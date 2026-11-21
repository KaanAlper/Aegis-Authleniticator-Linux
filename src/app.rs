use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use egui::{Color32, ColorImage, RichText, TextureHandle, TextureOptions, Vec2};
use uuid::Uuid;

use crate::config::{AppConfig, SortMode};
use crate::i18n::{strings, Lang};
use crate::otp::{
    current_unix_millis, current_unix_seconds, decode_qr_from_image, export_google_auth_migration,
    export_html, export_txt, format_code_display, generate_code_for_entry, parse_otpauth_uri,
};
use crate::tray::{spawn_tray, AegisTray, SharedTrayState, TrayCommand};
use crate::ui::widgets::{
    draw_countdown_ring, draw_issuer_avatar, draw_toast, filter_pill, primary_button,
    secondary_button, AEGIS_BLUE,
};
use crate::vault::{
    is_vault_file_encrypted, load_vault, EntryInfo, OtpType, UnlockedVault, VaultEntry,
    VaultGroup,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterMode {
    All,
    Favorites,
    Group(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Appearance,
    Security,
    Backups,
    ImportExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    AegisJson,
    WebHtml,
    TextTxt,
    GoogleAuth,
}

struct Toast {
    message: String,
    is_error: bool,
    expires_at: Instant,
}

struct EntryEditorState {
    editing_uuid: Option<String>,
    entry_type: OtpType,
    issuer: String,
    name: String,
    secret: String,
    show_secret: bool,
    algo: String,
    digits: String,
    period: String,
    counter: String,
    pin: String,
    note: String,
    favorite: bool,
    selected_groups: Vec<String>,
    qr_menu_open: bool,
    error: Option<String>,
}

impl EntryEditorState {
    fn new_empty() -> Self {
        Self {
            editing_uuid: None,
            entry_type: OtpType::Totp,
            issuer: String::new(),
            name: String::new(),
            secret: String::new(),
            show_secret: false,
            algo: "SHA1".to_string(),
            digits: "6".to_string(),
            period: "30".to_string(),
            counter: "0".to_string(),
            pin: String::new(),
            note: String::new(),
            favorite: false,
            selected_groups: Vec::new(),
            qr_menu_open: false,
            error: None,
        }
    }

    fn from_entry(e: &VaultEntry) -> Self {
        Self {
            editing_uuid: Some(e.uuid.clone()),
            entry_type: e.entry_type.clone(),
            issuer: e.issuer.clone(),
            name: e.name.clone(),
            secret: e.info.secret.clone(),
            show_secret: false,
            algo: e.info.algo.clone(),
            digits: e.info.digits.to_string(),
            period: e.info.period.unwrap_or(30).to_string(),
            counter: e.info.counter.unwrap_or(0).to_string(),
            pin: e.info.pin.clone().unwrap_or_default(),
            note: e.note.clone(),
            favorite: e.favorite,
            selected_groups: e.groups.clone(),
            qr_menu_open: false,
            error: None,
        }
    }

    fn apply_parsed_uri(&mut self, raw: &str) {
        match parse_otpauth_uri(raw) {
            Ok(parsed) => {
                self.entry_type = parsed.entry_type;
                self.issuer = parsed.issuer;
                self.name = parsed.name;
                self.secret = parsed.info.secret;
                self.algo = parsed.info.algo;
                self.digits = parsed.info.digits.to_string();
                self.period = parsed.info.period.unwrap_or(30).to_string();
                self.counter = parsed.info.counter.unwrap_or(0).to_string();
                self.pin = parsed.info.pin.unwrap_or_default();
                self.qr_menu_open = false;
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e.to_string());
            }
        }
    }

    fn to_entry(&self, existing: Option<&VaultEntry>) -> Result<VaultEntry, String> {
        let secret = self
            .secret
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        if secret.is_empty() {
            return Err("Secret cannot be empty".into());
        }
        crate::otp::decode_base32_secret(&secret).map_err(|e| e.to_string())?;

        let digits = self
            .digits
            .trim()
            .parse::<u32>()
            .map_err(|_| "Digits must be a valid number".to_string())?;
        if !(4..=10).contains(&digits) {
            return Err("Digits must be between 4 and 10".into());
        }

        let period = if self.entry_type == OtpType::Hotp {
            None
        } else {
            let p = self
                .period
                .trim()
                .parse::<u64>()
                .map_err(|_| "Period must be a valid number".to_string())?;
            Some(p.max(1))
        };

        let counter = if self.entry_type == OtpType::Hotp {
            let c = self
                .counter
                .trim()
                .parse::<u64>()
                .map_err(|_| "Counter must be a valid number".to_string())?;
            Some(c)
        } else {
            None
        };

        let pin = if matches!(self.entry_type, OtpType::Motp | OtpType::Yandex) {
            Some(self.pin.clone())
        } else {
            None
        };

        Ok(VaultEntry {
            entry_type: self.entry_type.clone(),
            uuid: self
                .editing_uuid
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            name: self.name.trim().to_string(),
            issuer: self.issuer.trim().to_string(),
            note: self.note.trim().to_string(),
            favorite: self.favorite,
            icon: existing.and_then(|x| x.icon.clone()),
            icon_mime: existing.and_then(|x| x.icon_mime.clone()),
            icon_hash: existing.and_then(|x| x.icon_hash.clone()),
            info: EntryInfo {
                secret,
                algo: self.algo.clone(),
                digits,
                period,
                counter,
                pin,
            },
            groups: self.selected_groups.clone(),
        })
    }
}

pub struct AegisApp {
    config: AppConfig,
    vault: Option<UnlockedVault>,
    vault_path: Option<PathBuf>,
    dirty: bool,

    // Unlock / create screen state
    pending_vault_path: Option<PathBuf>,
    pending_encrypted: bool,
    unlock_password: String,
    unlock_error: Option<String>,
    creating_new_vault: bool,
    new_vault_password: String,
    new_vault_confirm: String,

    // Main view state
    search_query: String,
    filter_mode: FilterMode,
    icon_cache: HashMap<String, TextureHandle>,
    toast: Option<Toast>,
    clipboard: Option<arboard::Clipboard>,

    // Modals
    entry_editor: Option<EntryEditorState>,
    import_modal: Option<String>,
    groups_modal_open: bool,
    new_group_name: String,
    security_modal_open: bool,
    sec_new_password: String,
    sec_confirm_password: String,
    delete_confirm_uuid: Option<String>,

    // Tray integration
    tray_state: Arc<Mutex<SharedTrayState>>,
    tray_handle: ksni::Handle<AegisTray>,
    tray_rx: Receiver<TrayCommand>,
    quitting: bool,
    last_tray_sync_sec: u64,
    app_logo: Option<TextureHandle>,
    lang: Lang,
    settings_open: bool,
    settings_tab: SettingsTab,
    export_format: ExportFormat,
    last_activity: Instant,
}

impl AegisApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        apply_theme(&cc.egui_ctx, config.dark_mode);

        let mut pending_vault_path = None;
        let mut pending_encrypted = false;
        let mut unlock_error = None;

        if let Some(last) = &config.last_vault_path {
            if last.exists() {
                match is_vault_file_encrypted(last) {
                    Ok(enc) => {
                        pending_vault_path = Some(last.clone());
                        pending_encrypted = enc;
                    }
                    Err(e) => {
                        unlock_error = Some(format!("Failed to inspect last vault: {e}"));
                    }
                }
            }
        }

        let lang = config
            .language
            .as_deref()
            .map(Lang::from_code)
            .unwrap_or_else(Lang::detect_system);

        let tray_state = Arc::new(Mutex::new(SharedTrayState {
            is_locked: true,
            entries: Vec::new(),
            icon_png_cache: HashMap::new(),
            lang,
        }));
        let (tray_tx, tray_rx) = mpsc::channel();
        let tray_handle = spawn_tray(Arc::clone(&tray_state), tray_tx, cc.egui_ctx.clone());

        let app_logo = image::load_from_memory(include_bytes!("../assets/icon.png"))
            .ok()
            .map(|img| {
                let rgba = img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let color_image = ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
                cc.egui_ctx
                    .load_texture("aegis_app_logo", color_image, TextureOptions::LINEAR)
            });

        let mut app = Self {
            config,
            vault: None,
            vault_path: None,
            dirty: false,
            pending_vault_path,
            pending_encrypted,
            unlock_password: String::new(),
            unlock_error,
            creating_new_vault: false,
            new_vault_password: String::new(),
            new_vault_confirm: String::new(),
            search_query: String::new(),
            filter_mode: FilterMode::All,
            icon_cache: HashMap::new(),
            toast: None,
            clipboard: arboard::Clipboard::new().ok(),
            entry_editor: None,
            import_modal: None,
            groups_modal_open: false,
            new_group_name: String::new(),
            security_modal_open: false,
            sec_new_password: String::new(),
            sec_confirm_password: String::new(),
            delete_confirm_uuid: None,
            tray_state,
            tray_handle,
            tray_rx,
            quitting: false,
            last_tray_sync_sec: 0,
            app_logo,
            lang,
            settings_open: false,
            settings_tab: SettingsTab::Appearance,
            export_format: ExportFormat::AegisJson,
            last_activity: Instant::now(),
        };

        // If last vault is plaintext, auto-open it
        if app.pending_vault_path.is_some() && !app.pending_encrypted {
            if let Some(p) = app.pending_vault_path.clone() {
                app.try_open_vault(p, None);
            }
        }

        app
    }

    fn sync_tray(&mut self) {
        {
            let mut guard = self.tray_state.lock().unwrap();
            guard.lang = self.lang;
            match &self.vault {
                Some(v) => {
                    guard.is_locked = false;
                    guard.entries = v.db.entries.clone();
                }
                None => {
                    guard.is_locked = true;
                    guard.entries.clear();
                }
            }
        }
        self.last_tray_sync_sec = current_unix_seconds();
        self.tray_handle.update(|_| {});
    }

    fn show_toast(&mut self, msg: impl Into<String>, is_error: bool) {
        self.toast = Some(Toast {
            message: msg.into(),
            is_error,
            expires_at: Instant::now() + Duration::from_secs(2),
        });
    }

    fn copy_to_clipboard(&mut self, text: &str, label: &str) {
        if let Some(cb) = &mut self.clipboard {
            match cb.set_text(text.to_string()) {
                Ok(()) => self.show_toast(format!("Copied {label} to clipboard"), false),
                Err(e) => self.show_toast(format!("Clipboard error: {e}"), true),
            }
        } else {
            self.show_toast("Clipboard unavailable", true);
        }
    }

    fn select_vault_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Aegis Vault JSON", &["json"])
            .pick_file()
        {
            self.inspect_and_prepare_vault(path);
        }
    }

    fn inspect_and_prepare_vault(&mut self, path: PathBuf) {
        match is_vault_file_encrypted(&path) {
            Ok(false) => {
                self.try_open_vault(path, None);
            }
            Ok(true) => {
                self.pending_vault_path = Some(path);
                self.pending_encrypted = true;
                self.unlock_password.clear();
                self.unlock_error = None;
                self.creating_new_vault = false;
            }
            Err(e) => {
                self.unlock_error = Some(format!("Invalid vault file: {e}"));
            }
        }
    }

    fn try_open_vault(&mut self, path: PathBuf, password: Option<&str>) {
        match load_vault(&path, password) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.vault_path = Some(path.clone());
                self.pending_vault_path = Some(path.clone());
                self.unlock_password.clear();
                self.unlock_error = None;
                self.dirty = false;
                self.icon_cache.clear();
                self.config.last_vault_path = Some(path);
                self.config.save();
                self.sync_tray();
            }
            Err(e) => {
                self.unlock_error = Some(e.to_string());
            }
        }
    }

    fn lock_vault(&mut self) {
        self.vault = None;
        self.icon_cache.clear();
        self.entry_editor = None;
        self.import_modal = None;
        self.groups_modal_open = false;
        self.security_modal_open = false;
        self.unlock_password.clear();
        self.unlock_error = None;
        if let Some(p) = &self.vault_path {
            self.pending_vault_path = Some(p.clone());
            self.pending_encrypted = is_vault_file_encrypted(p).unwrap_or(false);
        }
        self.sync_tray();
    }

    fn save_vault(&mut self) {
        let Some(vault) = &self.vault else {
            return;
        };
        let path = match &self.vault_path {
            Some(p) => p.clone(),
            None => {
                let Some(p) = rfd::FileDialog::new()
                    .add_filter("Aegis Vault JSON", &["json"])
                    .set_file_name("aegis-vault.json")
                    .save_file()
                else {
                    return;
                };
                self.vault_path = Some(p.clone());
                self.config.last_vault_path = Some(p.clone());
                self.config.save();
                p
            }
        };

        match vault.save_to_path(&path) {
            Ok(()) => {
                self.dirty = false;
                self.show_toast("Vault saved", false);
                self.maybe_run_auto_backup();
            }
            Err(e) => {
                self.show_toast(format!("Failed to save vault: {e}"), true);
            }
        }
    }

    fn run_backup_now(&mut self) -> Result<PathBuf, String> {
        let Some(vault) = &self.vault else {
            return Err("Vault is locked".into());
        };
        let dir = self
            .config
            .backup_dir
            .clone()
            .or_else(|| dirs::data_local_dir().map(|d| d.join("aegis-linux").join("backups")))
            .ok_or_else(|| "No backup directory configured".to_string())?;
        let ts = current_unix_seconds();
        let dest = dir.join(format!("aegis-backup-{ts}.json"));
        vault.save_to_path(&dest).map_err(|e| e.to_string())?;
        self.config.last_backup_epoch = ts;
        self.config.save();
        Ok(dest)
    }

    fn maybe_run_auto_backup(&mut self) {
        if !self.config.auto_backup_enabled || self.vault.is_none() {
            return;
        }
        let now = current_unix_seconds();
        let interval_secs = u64::from(self.config.backup_interval_days.max(1)) * 86_400;
        if now.saturating_sub(self.config.last_backup_epoch) >= interval_secs {
            let _ = self.run_backup_now();
        }
    }

    fn save_vault_as(&mut self) {
        if self.vault.is_none() {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Aegis Vault JSON", &["json"])
            .set_file_name("aegis-vault.json")
            .save_file()
        {
            self.vault_path = Some(path.clone());
            self.config.last_vault_path = Some(path);
            self.config.save();
            self.save_vault();
        }
    }

    fn get_or_load_icon(&mut self, ctx: &egui::Context, entry: &VaultEntry) -> Option<TextureHandle> {
        if let Some(tex) = self.icon_cache.get(&entry.uuid) {
            return Some(tex.clone());
        }
        let b64 = entry.icon.as_deref()?;
        let bytes = BASE64.decode(b64).ok()?;
        let dyn_img = image::load_from_memory(&bytes).ok()?;
        let rgba = dyn_img.to_rgba8();
        let size = [rgba.width() as usize, rgba.height() as usize];
        let color_image = ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
        let handle = ctx.load_texture(
            format!("icon_{}", entry.uuid),
            color_image,
            TextureOptions::LINEAR,
        );
        self.icon_cache.insert(entry.uuid.clone(), handle.clone());
        Some(handle)
    }

    fn render_unlock_screen(&mut self, ctx: &egui::Context) {
        let s = strings(self.lang);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if secondary_button(ui, self.lang.short_label()).clicked() {
                        self.lang = self.lang.toggle();
                        self.config.language = Some(self.lang.code().to_string());
                        self.config.save();
                        self.sync_tray();
                    }
                });
            });
            let top_pad = ((ui.available_height() - 390.0) * 0.38).max(16.0);
            ui.vertical_centered(|ui| {
                ui.add_space(top_pad);

                if let Some(logo) = &self.app_logo {
                    ui.add(egui::Image::new((logo.id(), Vec2::splat(72.0))));
                    ui.add_space(10.0);
                }

                ui.label(RichText::new("Aegis Authenticator").size(26.0).strong());
                ui.label(RichText::new(s.subtitle).size(13.0).weak());
                ui.add_space(24.0);

                let card_fill = if ui.visuals().dark_mode {
                    Color32::from_rgb(20, 24, 35)
                } else {
                    Color32::WHITE
                };
                let card_stroke = if ui.visuals().dark_mode {
                    egui::Stroke::new(1.0_f32, Color32::from_rgb(40, 46, 65))
                } else {
                    egui::Stroke::new(1.0_f32, Color32::from_rgb(220, 226, 236))
                };

                egui::Frame::NONE
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .inner_margin(egui::Margin::same(28))
                    .corner_radius(16.0)
                    .shadow(egui::Shadow {
                        offset: [0, 8],
                        blur: 24,
                        spread: 0,
                        color: Color32::from_black_alpha(60),
                    })
                    .show(ui, |ui| {
                        ui.set_width(380.0);

                        if self.creating_new_vault {
                            ui.label(RichText::new(s.create_vault_title).size(18.0).strong());
                            ui.add_space(14.0);
                            ui.label(s.password_opt);
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_vault_password)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(10.0);
                            ui.label(s.confirm_password);
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_vault_confirm)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                            if let Some(err) = &self.unlock_error {
                                ui.add_space(10.0);
                                ui.colored_label(Color32::from_rgb(239, 68, 68), err);
                            }
                            ui.add_space(18.0);
                            ui.horizontal(|ui| {
                                if secondary_button(ui, s.cancel).clicked() {
                                    self.creating_new_vault = false;
                                    self.unlock_error = None;
                                }
                                if primary_button(ui, s.create).clicked() {
                                    if self.new_vault_password != self.new_vault_confirm {
                                        self.unlock_error =
                                            Some(s.passwords_mismatch.to_string());
                                    } else {
                                        let created = if self.new_vault_password.is_empty() {
                                            Ok(UnlockedVault::new_plain())
                                        } else {
                                            UnlockedVault::new_encrypted(&self.new_vault_password)
                                        };
                                        match created {
                                            Ok(v) => {
                                                self.vault = Some(v);
                                                self.vault_path = None;
                                                self.dirty = true;
                                                self.creating_new_vault = false;
                                                self.new_vault_password.clear();
                                                self.new_vault_confirm.clear();
                                                self.unlock_error = None;
                                                self.sync_tray();
                                            }
                                            Err(e) => {
                                                self.unlock_error = Some(e.to_string());
                                            }
                                        }
                                    }
                                }
                            });
                        } else if let Some(path) = self.pending_vault_path.clone() {
                            ui.label(RichText::new(s.unlock_vault).size(18.0).strong());
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(path.display().to_string())
                                    .small()
                                    .weak(),
                            );
                            ui.add_space(14.0);

                            if self.pending_encrypted {
                                ui.label(s.master_password);
                                if !self.config.password_hint.trim().is_empty() {
                                    ui.label(
                                        RichText::new(format!(
                                            "Hint: {}",
                                            self.config.password_hint.trim()
                                        ))
                                        .small()
                                        .weak(),
                                    );
                                }
                                ui.add_space(4.0);
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut self.unlock_password)
                                        .password(true)
                                        .desired_width(f32::INFINITY),
                                );
                                if resp.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                {
                                    let pwd = self.unlock_password.clone();
                                    self.try_open_vault(path.clone(), Some(&pwd));
                                }
                            }

                            if let Some(err) = &self.unlock_error {
                                ui.add_space(10.0);
                                ui.colored_label(Color32::from_rgb(239, 68, 68), err);
                            }

                            ui.add_space(16.0);
                            ui.horizontal(|ui| {
                                if primary_button(ui, s.unlock_btn).clicked() {
                                    let pwd = self.unlock_password.clone();
                                    let pwd_opt = if self.pending_encrypted {
                                        Some(pwd.as_str())
                                    } else {
                                        None
                                    };
                                    self.try_open_vault(path, pwd_opt);
                                }
                                if secondary_button(ui, s.open_another).clicked() {
                                    self.select_vault_file();
                                }
                            });
                            ui.add_space(10.0);
                            if ui.link(s.create_instead).clicked() {
                                self.creating_new_vault = true;
                                self.unlock_error = None;
                            }
                        } else {
                            ui.label(RichText::new(s.welcome).size(18.0).strong());
                            ui.add_space(8.0);
                            ui.label(s.welcome_desc);
                            ui.add_space(2.0);
                            ui.label(RichText::new(s.welcome_tip).small().weak());
                            if let Some(err) = &self.unlock_error {
                                ui.add_space(10.0);
                                ui.colored_label(Color32::from_rgb(239, 68, 68), err);
                            }
                            ui.add_space(18.0);
                            ui.horizontal(|ui| {
                                if primary_button(ui, s.open_vault_file).clicked() {
                                    self.select_vault_file();
                                }
                                if secondary_button(ui, s.create_new_vault).clicked() {
                                    self.creating_new_vault = true;
                                    self.unlock_error = None;
                                }
                            });
                        }
                    });
            });
        });
    }

    fn render_main_view(&mut self, ctx: &egui::Context) {
        let s = strings(self.lang);
        ctx.request_repaint_after(Duration::from_millis(100));

        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S)) {
            self.save_vault();
        }

        let is_encrypted = self.vault.as_ref().is_some_and(|v| v.is_encrypted());
        let file_label = self
            .vault_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unsaved Vault".to_string());

        let top_bg = if ctx.style().visuals.dark_mode {
            Color32::from_rgb(18, 21, 30)
        } else {
            Color32::WHITE
        };

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::NONE
                    .fill(top_bg)
                    .inner_margin(egui::Margin::symmetric(20, 14)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.app_logo {
                        ui.add(egui::Image::new((logo.id(), Vec2::splat(26.0))));
                    }
                    ui.label(RichText::new("Aegis").size(19.0).strong());
                    let dirty_mark = if self.dirty { " *" } else { "" };
                    let badge_bg = if is_encrypted {
                        Color32::from_rgba_unmultiplied(32, 149, 242, 35)
                    } else {
                        Color32::from_rgba_unmultiplied(245, 158, 11, 35)
                    };
                    let badge_fg = if is_encrypted {
                        AEGIS_BLUE
                    } else {
                        Color32::from_rgb(245, 158, 11)
                    };
                    egui::Frame::NONE
                        .fill(badge_bg)
                        .corner_radius(10.0)
                        .inner_margin(egui::Margin::symmetric(8, 3))
                        .show(ui, |ui| {
                            let status = if is_encrypted { s.encrypted } else { s.plaintext };
                            ui.label(
                                RichText::new(format!("{file_label}{dirty_mark} • {status}"))
                                    .size(11.5)
                                    .color(badge_fg),
                            );
                        });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let theme_lbl = if self.config.dark_mode { "Light" } else { "Dark" };
                        if secondary_button(ui, theme_lbl).clicked() {
                            self.config.dark_mode = !self.config.dark_mode;
                            apply_theme(ctx, self.config.dark_mode);
                            self.config.save();
                        }
                        if secondary_button(ui, self.lang.short_label()).clicked() {
                            self.lang = self.lang.toggle();
                            self.config.language = Some(self.lang.code().to_string());
                            self.config.save();
                            self.sync_tray();
                        }
                        if secondary_button(ui, s.lock).clicked() {
                            self.lock_vault();
                            return;
                        }
                        if secondary_button(ui, s.settings).clicked() {
                            self.settings_open = !self.settings_open;
                        }
                        ui.menu_button(s.vault_menu, |ui| {
                            if ui.button(s.save_ctrl_s).clicked() {
                                self.save_vault();
                                ui.close_menu();
                            }
                            if ui.button(s.save_as).clicked() {
                                self.save_vault_as();
                                ui.close_menu();
                            }
                            if ui.button(s.open_another_vault).clicked() {
                                self.select_vault_file();
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button(s.encryption_pwd).clicked() {
                                self.security_modal_open = true;
                                self.sec_new_password.clear();
                                self.sec_confirm_password.clear();
                                ui.close_menu();
                            }
                            if ui.button(s.manage_groups).clicked() {
                                self.groups_modal_open = true;
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button(s.minimize_tray).clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                                ui.close_menu();
                            }
                            if ui.button(s.quit).clicked() {
                                self.quitting = true;
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                ui.close_menu();
                            }
                        });
                        if secondary_button(ui, s.import_uri).clicked() {
                            self.import_modal = Some(String::new());
                        }
                        if primary_button(ui, s.add_entry).clicked() {
                            self.entry_editor = Some(EntryEditorState::new_empty());
                        }
                    });
                });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .hint_text(s.search_hint)
                            .desired_width(280.0),
                    );
                    if !self.search_query.is_empty() && secondary_button(ui, s.clear).clicked() {
                        self.search_query.clear();
                    }

                    let sort_lbl = match self.config.sort_mode {
                        SortMode::Default => s.sort_default,
                        SortMode::IssuerAsc => s.sort_issuer_az,
                        SortMode::IssuerDesc => s.sort_issuer_za,
                        SortMode::NameAsc => s.sort_name_az,
                        SortMode::NameDesc => s.sort_name_za,
                        SortMode::FavoritesFirst => s.sort_fav_first,
                    };
                    egui::ComboBox::from_id_salt("sort_combo")
                        .selected_text(format!("{}: {}", s.sort_label, sort_lbl))
                        .show_ui(ui, |ui| {
                            for (mode, lbl) in [
                                (SortMode::Default, s.sort_default),
                                (SortMode::IssuerAsc, s.sort_issuer_az),
                                (SortMode::IssuerDesc, s.sort_issuer_za),
                                (SortMode::NameAsc, s.sort_name_az),
                                (SortMode::NameDesc, s.sort_name_za),
                                (SortMode::FavoritesFirst, s.sort_fav_first),
                            ] {
                                if ui
                                    .selectable_value(&mut self.config.sort_mode, mode, lbl)
                                    .clicked()
                                {
                                    self.config.save();
                                }
                            }
                        });

                    ui.add_space(6.0);
                    egui::ScrollArea::horizontal().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if filter_pill(ui, self.filter_mode == FilterMode::All, s.all).clicked()
                            {
                                self.filter_mode = FilterMode::All;
                            }
                            if filter_pill(
                                ui,
                                self.filter_mode == FilterMode::Favorites,
                                s.favorites,
                            )
                            .clicked()
                            {
                                self.filter_mode = FilterMode::Favorites;
                            }
                            if let Some(v) = &self.vault {
                                for g in &v.db.groups {
                                    let sel = self.filter_mode == FilterMode::Group(g.uuid.clone());
                                    if filter_pill(ui, sel, &g.name).clicked() {
                                        self.filter_mode = FilterMode::Group(g.uuid.clone());
                                    }
                                }
                            }
                        });
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::central_panel(&ctx.style())
                    .inner_margin(egui::Margin::symmetric(20, 16)),
            )
            .show(ctx, |ui| {
                let now_secs = current_unix_seconds();
                let now_millis = current_unix_millis();
                let query = self.search_query.trim().to_ascii_lowercase();

                let entries_snapshot: Vec<VaultEntry> = self
                    .vault
                    .as_ref()
                    .map(|v| v.db.entries.clone())
                    .unwrap_or_default();

                let mut filtered: Vec<VaultEntry> = entries_snapshot
                    .into_iter()
                    .filter(|e| match &self.filter_mode {
                        FilterMode::All => true,
                        FilterMode::Favorites => e.favorite,
                        FilterMode::Group(gid) => e.groups.contains(gid),
                    })
                    .filter(|e| {
                        if query.is_empty() {
                            return true;
                        }
                        e.issuer.to_ascii_lowercase().contains(&query)
                            || e.name.to_ascii_lowercase().contains(&query)
                            || e.note.to_ascii_lowercase().contains(&query)
                    })
                    .collect();

                match self.config.sort_mode {
                    SortMode::Default => {}
                    SortMode::IssuerAsc => filtered.sort_by(|a, b| {
                        a.issuer
                            .to_ascii_lowercase()
                            .cmp(&b.issuer.to_ascii_lowercase())
                            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
                    }),
                    SortMode::IssuerDesc => filtered.sort_by(|a, b| {
                        b.issuer
                            .to_ascii_lowercase()
                            .cmp(&a.issuer.to_ascii_lowercase())
                    }),
                    SortMode::NameAsc => filtered.sort_by(|a, b| {
                        a.name
                            .to_ascii_lowercase()
                            .cmp(&b.name.to_ascii_lowercase())
                    }),
                    SortMode::NameDesc => filtered.sort_by(|a, b| {
                        b.name
                            .to_ascii_lowercase()
                            .cmp(&a.name.to_ascii_lowercase())
                    }),
                    SortMode::FavoritesFirst => filtered.sort_by(|a, b| {
                        b.favorite.cmp(&a.favorite).then_with(|| {
                            a.issuer
                                .to_ascii_lowercase()
                                .cmp(&b.issuer.to_ascii_lowercase())
                        })
                    }),
                }

                if filtered.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(RichText::new(s.no_entries).size(17.0).weak());
                        ui.add_space(6.0);
                        ui.label(RichText::new(s.no_entries_tip).small().weak());
                    });
                    return;
                }

                let mut copy_req: Option<(String, String)> = None;
                let mut fav_toggle_uuid: Option<String> = None;
                let mut hotp_inc_uuid: Option<String> = None;
                let mut edit_entry: Option<VaultEntry> = None;
                let mut delete_uuid: Option<String> = None;

                let avail_w = ui.available_width();
                let cols = if avail_w >= 1460.0 {
                    4
                } else if avail_w >= 1040.0 {
                    3
                } else if avail_w >= 660.0 {
                    2
                } else {
                    1
                };
                let gap = 12.0_f32;
                let card_w = ((avail_w - (cols as f32 - 1.0) * gap) / cols as f32).max(260.0);

                let dark_mode = ui.visuals().dark_mode;
                let card_fill = if dark_mode {
                    Color32::from_rgb(22, 26, 38)
                } else {
                    Color32::WHITE
                };
                let card_stroke = if dark_mode {
                    egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 44, 62))
                } else {
                    egui::Stroke::new(1.0_f32, Color32::from_rgb(222, 228, 238))
                };

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for chunk in filtered.chunks(cols) {
                        ui.horizontal(|ui| {
                            for (idx, entry) in chunk.iter().enumerate() {
                                if idx > 0 {
                                    ui.add_space(gap - 8.0);
                                }
                                let texture = self.get_or_load_icon(ctx, entry);
                                let code_res = generate_code_for_entry(entry, now_secs);
                                let display_code = match &code_res {
                                    Ok(c) => format_code_display(c),
                                    Err(_) => "ERROR".to_string(),
                                };

                                egui::Frame::NONE
                                    .fill(card_fill)
                                    .stroke(card_stroke)
                                    .corner_radius(12.0)
                                    .inner_margin(egui::Margin::same(16))
                                    .show(ui, |ui| {
                                        ui.set_width(card_w - 34.0);

                                        // Card Top Row: Avatar + Title + Actions
                                        ui.horizontal(|ui| {
                                            if self.config.show_icons {
                                                draw_issuer_avatar(
                                                    ui,
                                                    &entry.issuer,
                                                    &entry.name,
                                                    texture.as_ref(),
                                                    38.0,
                                                );
                                                ui.add_space(6.0);
                                            }
                                            ui.vertical(|ui| {
                                                let title = if entry.issuer.is_empty() {
                                                    entry.name.as_str()
                                                } else {
                                                    entry.issuer.as_str()
                                                };
                                                ui.label(
                                                    RichText::new(title).size(15.0).strong(),
                                                );
                                                if !entry.issuer.is_empty()
                                                    && !entry.name.is_empty()
                                                {
                                                    ui.label(
                                                        RichText::new(&entry.name)
                                                            .size(12.0)
                                                            .weak(),
                                                    );
                                                } else {
                                                    ui.label(
                                                        RichText::new(entry.entry_type.label())
                                                            .size(11.0)
                                                            .weak(),
                                                    );
                                                }
                                            });

                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::TOP),
                                                |ui| {
                                                    if ui
                                                        .small_button("Del")
                                                        .on_hover_text("Delete")
                                                        .clicked()
                                                    {
                                                        delete_uuid = Some(entry.uuid.clone());
                                                    }
                                                    if ui
                                                        .small_button("Edit")
                                                        .on_hover_text("Edit")
                                                        .clicked()
                                                    {
                                                        edit_entry = Some(entry.clone());
                                                    }
                                                    let fav_txt = if entry.favorite {
                                                        RichText::new("★").color(
                                                            Color32::from_rgb(245, 158, 11),
                                                        )
                                                    } else {
                                                        RichText::new("☆").weak()
                                                    };
                                                    if ui
                                                        .add(egui::Button::new(fav_txt).frame(false))
                                                        .on_hover_text("Toggle favorite")
                                                        .clicked()
                                                    {
                                                        fav_toggle_uuid = Some(entry.uuid.clone());
                                                    }
                                                },
                                            );
                                        });

                                        if !entry.note.is_empty() {
                                            ui.add_space(4.0);
                                            ui.label(
                                                RichText::new(&entry.note)
                                                    .size(11.5)
                                                    .italics()
                                                    .weak(),
                                            );
                                        }

                                        ui.add_space(10.0);

                                        // Card Bottom Row: Big Code + Ring
                                        ui.horizontal(|ui| {
                                            let code_btn = ui.add(
                                                egui::Button::new(
                                                    RichText::new(&display_code)
                                                        .size(25.0)
                                                        .monospace()
                                                        .strong()
                                                        .color(AEGIS_BLUE),
                                                )
                                                .frame(false),
                                            );
                                            if code_btn
                                                .on_hover_text("Click to copy code")
                                                .clicked()
                                            {
                                                if let Ok(raw_code) = code_res {
                                                    let lbl = if entry.issuer.is_empty() {
                                                        entry.name.clone()
                                                    } else {
                                                        entry.issuer.clone()
                                                    };
                                                    copy_req = Some((raw_code, lbl));
                                                }
                                            }

                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if entry.entry_type == OtpType::Hotp {
                                                        if secondary_button(ui, "Next").clicked() {
                                                            hotp_inc_uuid =
                                                                Some(entry.uuid.clone());
                                                        }
                                                    } else {
                                                        let period =
                                                            entry.info.period.unwrap_or(30) as f64;
                                                        let elapsed_in_period =
                                                            ((now_millis as f64) / 1000.0) % period;
                                                        let remaining =
                                                            (period - elapsed_in_period) as f32;
                                                        draw_countdown_ring(
                                                            ui,
                                                            remaining,
                                                            period as f32,
                                                            32.0,
                                                        );
                                                    }
                                                },
                                            );
                                        });
                                    });
                            }
                        });
                        ui.add_space(gap - 4.0);
                    }
                });

                if let Some((code, lbl)) = copy_req {
                    self.copy_to_clipboard(&code, &lbl);
                }
                if let Some(uuid) = fav_toggle_uuid {
                    if let Some(v) = &mut self.vault {
                        if let Some(e) = v.db.entries.iter_mut().find(|x| x.uuid == uuid) {
                            e.favorite = !e.favorite;
                            self.dirty = true;
                        }
                    }
                }
                if let Some(uuid) = hotp_inc_uuid {
                    if let Some(v) = &mut self.vault {
                        if let Some(e) = v.db.entries.iter_mut().find(|x| x.uuid == uuid) {
                            let next = e.info.counter.unwrap_or(0).saturating_add(1);
                            e.info.counter = Some(next);
                            self.dirty = true;
                        }
                    }
                }
                if let Some(e) = edit_entry {
                    self.entry_editor = Some(EntryEditorState::from_entry(&e));
                }
                if let Some(uuid) = delete_uuid {
                    self.delete_confirm_uuid = Some(uuid);
                }
            });

        self.render_modals(ctx);
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        let s = strings(self.lang);
        // 1. Add / Edit Entry Modal
        if let Some(mut editor) = self.entry_editor.take() {
            let mut keep_open = true;
            let title = if editor.editing_uuid.is_some() {
                s.edit_entry
            } else {
                s.add_entry.trim_start_matches("+ ")
            };
            let groups = self
                .vault
                .as_ref()
                .map(|v| v.db.groups.clone())
                .unwrap_or_default();

            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.set_min_width(400.0);

                    if editor.editing_uuid.is_none() {
                        ui.horizontal(|ui| {
                            if primary_button(ui, s.scan_qr).clicked() {
                                editor.qr_menu_open = !editor.qr_menu_open;
                            }
                            if secondary_button(ui, s.enter_manually).clicked() {
                                editor.qr_menu_open = false;
                            }
                        });

                        if editor.qr_menu_open {
                            ui.add_space(6.0);
                            egui::Frame::group(ui.style())
                                .inner_margin(egui::Margin::same(10))
                                .corner_radius(8.0)
                                .show(ui, |ui| {
                                    ui.label(RichText::new(s.choose_qr_src).small().weak());
                                    ui.add_space(4.0);
                                    ui.horizontal(|ui| {
                                        if secondary_button(ui, s.image_file).clicked() {
                                            if let Some(path) = rfd::FileDialog::new()
                                                .add_filter(
                                                    "Images",
                                                    &["png", "jpg", "jpeg", "webp"],
                                                )
                                                .pick_file()
                                            {
                                                match decode_qr_from_image(&path) {
                                                    Ok(content) => {
                                                        editor.apply_parsed_uri(&content)
                                                    }
                                                    Err(e) => editor.error = Some(e),
                                                }
                                            }
                                        }
                                        if secondary_button(ui, s.camera_webcam).clicked() {
                                            match std::process::Command::new("zbarcam")
                                                .args(["--oneshot", "-q", "--raw"])
                                                .output()
                                            {
                                                Ok(out) if out.status.success() => {
                                                    let raw =
                                                        String::from_utf8_lossy(&out.stdout)
                                                            .trim()
                                                            .to_string();
                                                    if raw.is_empty() {
                                                        editor.error = Some(
                                                            "No QR code scanned from camera"
                                                                .into(),
                                                        );
                                                    } else {
                                                        editor.apply_parsed_uri(&raw);
                                                    }
                                                }
                                                Ok(_) => {
                                                    editor.error = Some(
                                                        "Camera scan cancelled or failed".into(),
                                                    );
                                                }
                                                Err(_) => {
                                                    editor.error = Some(
                                                        "Install 'zbar' (zbarcam) for webcam QR scanning, or use Image File."
                                                            .into(),
                                                    );
                                                }
                                            }
                                        }
                                    });
                                });
                        }
                        ui.add_space(10.0);
                    }

                    egui::Grid::new("entry_editor_grid")
                        .num_columns(2)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(s.issuer);
                            ui.add(
                                egui::TextEdit::singleline(&mut editor.issuer)
                                    .hint_text("e.g. Google, GitHub")
                                    .desired_width(240.0),
                            );
                            ui.end_row();

                            ui.label(s.account_name);
                            ui.add(
                                egui::TextEdit::singleline(&mut editor.name)
                                    .hint_text("e.g. user@example.com")
                                    .desired_width(240.0),
                            );
                            ui.end_row();

                            ui.label(s.secret_base32);
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut editor.secret)
                                        .password(!editor.show_secret)
                                        .desired_width(190.0),
                                );
                                let lbl = if editor.show_secret { "Hide" } else { "Show" };
                                if ui.small_button(lbl).clicked() {
                                    editor.show_secret = !editor.show_secret;
                                }
                            });
                            ui.end_row();

                            ui.label(s.note);
                            ui.add(
                                egui::TextEdit::singleline(&mut editor.note)
                                    .hint_text(s.optional)
                                    .desired_width(240.0),
                            );
                            ui.end_row();

                            ui.label(s.favorite);
                            ui.checkbox(&mut editor.favorite, "");
                            ui.end_row();
                        });

                    if !groups.is_empty() {
                        ui.add_space(6.0);
                        ui.label(s.groups);
                        ui.horizontal_wrapped(|ui| {
                            for g in &groups {
                                let mut checked = editor.selected_groups.contains(&g.uuid);
                                if ui.checkbox(&mut checked, &g.name).changed() {
                                    if checked {
                                        editor.selected_groups.push(g.uuid.clone());
                                    } else {
                                        editor.selected_groups.retain(|x| x != &g.uuid);
                                    }
                                }
                            }
                        });
                    }

                    ui.add_space(6.0);
                    let adv_title = format!(
                        "{} ({} • {} • {} • {}s)",
                        s.advanced,
                        editor.entry_type.label(),
                        editor.algo,
                        editor.digits,
                        editor.period
                    );
                    ui.collapsing(adv_title, |ui| {
                        egui::Grid::new("entry_advanced_grid")
                            .num_columns(2)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label(s.otp_type);
                                egui::ComboBox::from_id_salt("otp_type_combo")
                                    .selected_text(editor.entry_type.label())
                                    .show_ui(ui, |ui| {
                                        for t in OtpType::all() {
                                            if ui
                                                .selectable_value(
                                                    &mut editor.entry_type,
                                                    t.clone(),
                                                    t.label(),
                                                )
                                                .clicked()
                                            {
                                                if *t == OtpType::Steam {
                                                    editor.digits = "5".into();
                                                    editor.period = "30".into();
                                                    editor.algo = "SHA1".into();
                                                } else if *t == OtpType::Motp {
                                                    editor.digits = "6".into();
                                                    editor.period = "10".into();
                                                    editor.algo = "MD5".into();
                                                } else if *t == OtpType::Yandex {
                                                    editor.digits = "8".into();
                                                    editor.period = "30".into();
                                                    editor.algo = "SHA256".into();
                                                }
                                            }
                                        }
                                    });
                                ui.end_row();

                                ui.label(s.algorithm);
                                egui::ComboBox::from_id_salt("algo_combo")
                                    .selected_text(&editor.algo)
                                    .show_ui(ui, |ui| {
                                        for a in ["SHA1", "SHA256", "SHA512", "MD5"] {
                                            ui.selectable_value(
                                                &mut editor.algo,
                                                a.to_string(),
                                                a,
                                            );
                                        }
                                    });
                                ui.end_row();

                                ui.label(s.digits);
                                ui.text_edit_singleline(&mut editor.digits);
                                ui.end_row();

                                if editor.entry_type == OtpType::Hotp {
                                    ui.label(s.counter);
                                    ui.text_edit_singleline(&mut editor.counter);
                                    ui.end_row();
                                } else {
                                    ui.label(s.period_sec);
                                    ui.text_edit_singleline(&mut editor.period);
                                    ui.end_row();
                                }

                                if matches!(editor.entry_type, OtpType::Motp | OtpType::Yandex) {
                                    ui.label("PIN:");
                                    ui.text_edit_singleline(&mut editor.pin);
                                    ui.end_row();
                                }
                            });
                    });

                    if let Some(err) = &editor.error {
                        ui.add_space(6.0);
                        ui.colored_label(Color32::from_rgb(239, 68, 68), err);
                    }

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if secondary_button(ui, s.cancel).clicked() {
                            keep_open = false;
                        }
                        if primary_button(ui, s.save_entry).clicked() {
                            let existing = editor.editing_uuid.as_ref().and_then(|id| {
                                self.vault
                                    .as_ref()
                                    .and_then(|v| v.db.entries.iter().find(|e| &e.uuid == id))
                            });
                            match editor.to_entry(existing) {
                                Ok(new_entry) => {
                                    if let Some(v) = &mut self.vault {
                                        if let Some(pos) = v
                                            .db
                                            .entries
                                            .iter()
                                            .position(|e| e.uuid == new_entry.uuid)
                                        {
                                            v.db.entries[pos] = new_entry;
                                        } else {
                                            v.db.entries.push(new_entry);
                                        }
                                        self.dirty = true;
                                    }
                                    keep_open = false;
                                }
                                Err(e) => {
                                    editor.error = Some(e);
                                }
                            }
                        }
                    });
                });

            if keep_open {
                self.entry_editor = Some(editor);
            }
        }

        // 2. Import otpauth:// URI Modal
        if let Some(mut uri_text) = self.import_modal.take() {
            let mut keep_open = true;
            egui::Window::new("Import otpauth:// URIs")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.set_min_width(420.0);
                    ui.label("Paste one or more otpauth:// URIs (one per line):");
                    ui.add_space(6.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut uri_text)
                            .desired_rows(5)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            keep_open = false;
                        }
                        if ui.button(RichText::new("Import").strong()).clicked() {
                            let mut imported = 0usize;
                            let mut errors = Vec::new();
                            for line in uri_text.lines().filter(|l| !l.trim().is_empty()) {
                                match parse_otpauth_uri(line) {
                                    Ok(entry) => {
                                        if let Some(v) = &mut self.vault {
                                            v.db.entries.push(entry);
                                            imported += 1;
                                        }
                                    }
                                    Err(e) => errors.push(e.to_string()),
                                }
                            }
                            if imported > 0 {
                                self.dirty = true;
                                self.show_toast(format!("Imported {imported} entry(s)"), false);
                            }
                            if !errors.is_empty() {
                                self.show_toast(errors[0].clone(), true);
                            }
                            if errors.is_empty() {
                                keep_open = false;
                            }
                        }
                    });
                });
            if keep_open {
                self.import_modal = Some(uri_text);
            }
        }

        // 3. Manage Groups Modal
        if self.groups_modal_open {
            let mut open = true;
            egui::Window::new("Manage Groups")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.set_min_width(320.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_group_name)
                                .hint_text("New group name..."),
                        );
                        if ui.button("Add").clicked() && !self.new_group_name.trim().is_empty() {
                            if let Some(v) = &mut self.vault {
                                v.db.groups.push(VaultGroup {
                                    uuid: Uuid::new_v4().to_string(),
                                    name: self.new_group_name.trim().to_string(),
                                });
                                self.new_group_name.clear();
                                self.dirty = true;
                            }
                        }
                    });
                    ui.separator();
                    let mut remove_gid = None;
                    if let Some(v) = &self.vault {
                        for g in &v.db.groups {
                            ui.horizontal(|ui| {
                                ui.label(&g.name);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("Delete").clicked() {
                                            remove_gid = Some(g.uuid.clone());
                                        }
                                    },
                                );
                            });
                        }
                    }
                    if let Some(gid) = remove_gid {
                        if let Some(v) = &mut self.vault {
                            v.db.groups.retain(|g| g.uuid != gid);
                            for e in &mut v.db.entries {
                                e.groups.retain(|x| x != &gid);
                            }
                            if self.filter_mode == FilterMode::Group(gid) {
                                self.filter_mode = FilterMode::All;
                            }
                            self.dirty = true;
                        }
                    }
                });
            if !open {
                self.groups_modal_open = false;
            }
        }

        // 4. Vault Encryption / Password Modal
        if self.security_modal_open {
            let mut open = true;
            egui::Window::new(s.vault_encryption)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.set_min_width(340.0);
                    ui.label(s.new_pwd_hint);
                    ui.add_space(8.0);
                    ui.label(s.new_pwd);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sec_new_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    ui.label(s.confirm_password);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sec_confirm_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.button(s.apply).clicked() {
                            if self.sec_new_password != self.sec_confirm_password {
                                self.show_toast("Passwords do not match", true);
                            } else if let Some(v) = &mut self.vault {
                                let pwd_opt = if self.sec_new_password.is_empty() {
                                    None
                                } else {
                                    Some(self.sec_new_password.as_str())
                                };
                                match v.set_password(pwd_opt) {
                                    Ok(()) => {
                                        self.dirty = true;
                                        self.security_modal_open = false;
                                        self.sec_new_password.clear();
                                        self.sec_confirm_password.clear();
                                        self.show_toast(
                                            "Encryption updated (remember to Save)",
                                            false,
                                        );
                                    }
                                    Err(e) => self.show_toast(e.to_string(), true),
                                }
                            }
                        }
                    });
                });
            if !open {
                self.security_modal_open = false;
            }
        }

        // 5. Delete Confirmation Modal
        if let Some(uuid) = self.delete_confirm_uuid.clone() {
            egui::Window::new(s.delete_entry)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(s.delete_confirm);
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button(s.cancel).clicked() {
                            self.delete_confirm_uuid = None;
                        }
                        if ui
                            .button(
                                RichText::new(s.delete)
                                    .color(Color32::from_rgb(239, 68, 68))
                                    .strong(),
                            )
                            .clicked()
                        {
                            if let Some(v) = &mut self.vault {
                                v.db.entries.retain(|e| e.uuid != uuid);
                                self.dirty = true;
                            }
                            self.delete_confirm_uuid = None;
                        }
                    });
                });
        }

        // 6. Settings Modal (Appearance, Security, Backups, Import / Export)
        if self.settings_open {
            let mut open = true;
            let mut close_for_groups = false;
            let mut close_for_security = false;
            let mut do_backup_now = false;
            let mut do_import_json = false;
            let mut do_import_txt = false;
            let mut do_export = false;

            egui::Window::new(s.settings)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.set_min_width(470.0);
                    ui.horizontal(|ui| {
                        for (tab, lbl) in [
                            (SettingsTab::Appearance, s.tab_appearance),
                            (SettingsTab::Security, s.tab_security),
                            (SettingsTab::Backups, s.tab_backups),
                            (SettingsTab::ImportExport, s.tab_import_export),
                        ] {
                            if filter_pill(ui, self.settings_tab == tab, lbl).clicked() {
                                self.settings_tab = tab;
                            }
                        }
                    });
                    ui.separator();
                    ui.add_space(6.0);

                    match self.settings_tab {
                        SettingsTab::Appearance => {
                            egui::Grid::new("settings_app_grid")
                                .num_columns(2)
                                .spacing([16.0, 10.0])
                                .show(ui, |ui| {
                                    ui.label(s.theme_label);
                                    ui.horizontal(|ui| {
                                        if filter_pill(ui, self.config.dark_mode, "Dark").clicked()
                                        {
                                            self.config.dark_mode = true;
                                            apply_theme(ctx, true);
                                            self.config.save();
                                        }
                                        if filter_pill(ui, !self.config.dark_mode, "Light")
                                            .clicked()
                                        {
                                            self.config.dark_mode = false;
                                            apply_theme(ctx, false);
                                            self.config.save();
                                        }
                                    });
                                    ui.end_row();

                                    ui.label(s.language_label);
                                    ui.horizontal(|ui| {
                                        if filter_pill(ui, self.lang == Lang::En, "English")
                                            .clicked()
                                        {
                                            self.lang = Lang::En;
                                            self.config.language = Some("en".into());
                                            self.config.save();
                                            self.sync_tray();
                                        }
                                        if filter_pill(ui, self.lang == Lang::Tr, "Türkçe")
                                            .clicked()
                                        {
                                            self.lang = Lang::Tr;
                                            self.config.language = Some("tr".into());
                                            self.config.save();
                                            self.sync_tray();
                                        }
                                    });
                                    ui.end_row();
                                });

                            ui.add_space(8.0);
                            if ui
                                .checkbox(&mut self.config.show_icons, s.show_icons_label)
                                .changed()
                            {
                                self.config.save();
                            }
                            ui.add_space(10.0);
                            if secondary_button(ui, s.manage_groups).clicked() {
                                close_for_groups = true;
                            }
                        }
                        SettingsTab::Security => {
                            if secondary_button(ui, s.encryption_pwd).clicked() {
                                close_for_security = true;
                            }
                            ui.add_space(12.0);
                            ui.label(s.password_hint_label);
                            ui.add_space(4.0);
                            if ui
                                .add(
                                    egui::TextEdit::singleline(&mut self.config.password_hint)
                                        .desired_width(f32::INFINITY),
                                )
                                .changed()
                            {
                                self.config.save();
                            }
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.label(s.auto_lock_label);
                                let mut mins = self.config.auto_lock_mins as u32;
                                if ui
                                    .add(egui::DragValue::new(&mut mins).range(0..=240))
                                    .changed()
                                {
                                    self.config.auto_lock_mins = u64::from(mins);
                                    self.config.save();
                                }
                            });
                        }
                        SettingsTab::Backups => {
                            if ui
                                .checkbox(
                                    &mut self.config.auto_backup_enabled,
                                    s.auto_backup_label,
                                )
                                .changed()
                            {
                                self.config.save();
                            }
                            ui.add_space(8.0);
                            ui.label(s.backup_dir_label);
                            ui.horizontal(|ui| {
                                let dir_str = self
                                    .config
                                    .backup_dir
                                    .as_ref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default();
                                ui.label(RichText::new(dir_str).small().weak());
                                if secondary_button(ui, s.choose_folder).clicked() {
                                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                        self.config.backup_dir = Some(folder);
                                        self.config.save();
                                    }
                                }
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.label(s.backup_days_label);
                                if ui
                                    .add(
                                        egui::DragValue::new(&mut self.config.backup_interval_days)
                                            .range(1..=365),
                                    )
                                    .changed()
                                {
                                    self.config.save();
                                }
                            });
                            ui.add_space(12.0);
                            if primary_button(ui, s.backup_now).clicked() {
                                do_backup_now = true;
                            }
                        }
                        SettingsTab::ImportExport => {
                            ui.label(RichText::new(s.import_from_file).strong());
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if secondary_button(ui, s.import_aegis_json).clicked() {
                                    do_import_json = true;
                                }
                                if secondary_button(ui, s.import_txt_uris).clicked() {
                                    do_import_txt = true;
                                }
                            });
                            ui.add_space(14.0);
                            ui.separator();
                            ui.add_space(10.0);
                            ui.label(RichText::new(s.export_to).strong());
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label(s.export_format);
                                let fmt_label = match self.export_format {
                                    ExportFormat::AegisJson => "Aegis (.json)",
                                    ExportFormat::WebHtml => "Web (.html)",
                                    ExportFormat::TextTxt => "Text (.txt)",
                                    ExportFormat::GoogleAuth => "Google Authenticator",
                                };
                                egui::ComboBox::from_id_salt("export_fmt_combo")
                                    .selected_text(fmt_label)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(
                                            &mut self.export_format,
                                            ExportFormat::AegisJson,
                                            "Aegis (.json)",
                                        );
                                        ui.selectable_value(
                                            &mut self.export_format,
                                            ExportFormat::WebHtml,
                                            "Web (.html)",
                                        );
                                        ui.selectable_value(
                                            &mut self.export_format,
                                            ExportFormat::TextTxt,
                                            "Text (.txt)",
                                        );
                                        ui.selectable_value(
                                            &mut self.export_format,
                                            ExportFormat::GoogleAuth,
                                            "Google Authenticator",
                                        );
                                    });
                            });
                            ui.add_space(10.0);
                            if primary_button(ui, s.export_btn).clicked() {
                                do_export = true;
                            }
                        }
                    }
                });

            if !open {
                self.settings_open = false;
            }
            if close_for_groups {
                self.settings_open = false;
                self.groups_modal_open = true;
            }
            if close_for_security {
                self.settings_open = false;
                self.security_modal_open = true;
                self.sec_new_password.clear();
                self.sec_confirm_password.clear();
            }
            if do_backup_now {
                match self.run_backup_now() {
                    Ok(p) => self.show_toast(format!("Backup saved: {}", p.display()), false),
                    Err(e) => self.show_toast(e, true),
                }
            }
            if do_import_json {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Aegis JSON", &["json"])
                    .pick_file()
                {
                    match load_vault(&path, None) {
                        Ok(imported_v) => {
                            let mut count = 0usize;
                            if let Some(v) = &mut self.vault {
                                for e in imported_v.db.entries {
                                    if !v.db.entries.iter().any(|x| x.uuid == e.uuid) {
                                        v.db.entries.push(e);
                                        count += 1;
                                    }
                                }
                                self.dirty = count > 0;
                            }
                            self.sync_tray();
                            self.show_toast(format!("Imported {count} entry(s)"), false);
                        }
                        Err(e) => self.show_toast(e.to_string(), true),
                    }
                }
            }
            if do_import_txt {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Text / URI", &["txt"])
                    .pick_file()
                {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let mut count = 0usize;
                        for line in content.lines().filter(|l| !l.trim().is_empty()) {
                            if let Ok(entry) = parse_otpauth_uri(line) {
                                if let Some(v) = &mut self.vault {
                                    v.db.entries.push(entry);
                                    count += 1;
                                }
                            }
                        }
                        if count > 0 {
                            self.dirty = true;
                            self.sync_tray();
                        }
                        self.show_toast(format!("Imported {count} URI(s)"), false);
                    }
                }
            }
            if do_export {
                if let Some(v) = &self.vault {
                    let entries = v.db.entries.clone();
                    match self.export_format {
                        ExportFormat::AegisJson => {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Aegis JSON", &["json"])
                                .set_file_name("aegis-export.json")
                                .save_file()
                            {
                                match v.save_to_path(&path) {
                                    Ok(()) => self.show_toast("Exported Aegis JSON", false),
                                    Err(e) => self.show_toast(e.to_string(), true),
                                }
                            }
                        }
                        ExportFormat::WebHtml => {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("HTML", &["html"])
                                .set_file_name("aegis-export.html")
                                .save_file()
                            {
                                let html = export_html(&entries);
                                match std::fs::write(&path, html) {
                                    Ok(()) => self.show_toast("Exported Web HTML", false),
                                    Err(e) => self.show_toast(e.to_string(), true),
                                }
                            }
                        }
                        ExportFormat::TextTxt => {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Text", &["txt"])
                                .set_file_name("aegis-export.txt")
                                .save_file()
                            {
                                let txt = export_txt(&entries);
                                match std::fs::write(&path, txt) {
                                    Ok(()) => self.show_toast("Exported Text URIs", false),
                                    Err(e) => self.show_toast(e.to_string(), true),
                                }
                            }
                        }
                        ExportFormat::GoogleAuth => {
                            let migration_uri = export_google_auth_migration(&entries);
                            self.copy_to_clipboard(&migration_uri, "Google Auth Migration URI");
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Text", &["txt"])
                                .set_file_name("google-auth-migration.txt")
                                .save_file()
                            {
                                let _ = std::fs::write(&path, &migration_uri);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl eframe::App for AegisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process tray commands
        while let Ok(cmd) = self.tray_rx.try_recv() {
            match cmd {
                TrayCommand::ShowWindow => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayCommand::LockVault => {
                    self.lock_vault();
                }
                TrayCommand::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                TrayCommand::Copied(name) => {
                    self.show_toast(format!("Copied {name} from tray"), false);
                }
            }
        }

        // Minimize to tray instead of quitting when clicking X
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Track activity for auto-lock
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        if self.vault.is_some()
            && self.config.auto_lock_mins > 0
            && self.last_activity.elapsed() >= Duration::from_secs(self.config.auto_lock_mins * 60)
        {
            self.lock_vault();
        }

        // Periodically refresh tray menu OTP codes when unlocked
        let now = current_unix_seconds();
        if self.vault.is_some() && now.saturating_sub(self.last_tray_sync_sec) >= 5 {
            self.sync_tray();
        }

        // Handle drag-and-drop vault files
        let dropped_path = ctx.input(|i| {
            i.raw
                .dropped_files
                .first()
                .and_then(|f| f.path.clone())
        });
        if let Some(path) = dropped_path {
            if self.vault.is_none() {
                self.inspect_and_prepare_vault(path);
            }
        }

        if self.vault.is_none() {
            self.render_unlock_screen(ctx);
        } else {
            self.render_main_view(ctx);
        }

        if let Some(toast) = &self.toast {
            if Instant::now() < toast.expires_at {
                draw_toast(ctx, &toast.message, toast.is_error);
            } else {
                self.toast = None;
            }
        }
    }
}

fn apply_theme(ctx: &egui::Context, dark_mode: bool) {
    let mut style = (*ctx.style()).clone();
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.visuals = if dark_mode {
        let mut v = egui::Visuals::dark();
        v.panel_fill = Color32::from_rgb(13, 15, 22);
        v.window_fill = Color32::from_rgb(20, 24, 35);
        v.extreme_bg_color = Color32::from_rgb(18, 22, 32);
        v.faint_bg_color = Color32::from_rgb(24, 28, 40);
        v.widgets.noninteractive.bg_fill = Color32::from_rgb(24, 28, 40);
        v.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0_f32, Color32::from_rgb(40, 46, 65));
        v.widgets.inactive.bg_fill = Color32::from_rgb(30, 35, 50);
        v.widgets.hovered.bg_fill = Color32::from_rgb(40, 48, 68);
        v.selection.bg_fill = AEGIS_BLUE;
        v
    } else {
        let mut v = egui::Visuals::light();
        v.panel_fill = Color32::from_rgb(244, 246, 250);
        v.window_fill = Color32::WHITE;
        v.selection.bg_fill = AEGIS_BLUE;
        v
    };
    ctx.set_style(style);
}
