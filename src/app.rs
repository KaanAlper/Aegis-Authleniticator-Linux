use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use egui::{Color32, ColorImage, Pos2, Rect, RichText, Sense, TextureHandle, TextureOptions, Vec2};
use uuid::Uuid;

use crate::config::{adopt_vault_file, AppConfig, SortMode};
use crate::i18n::{strings, Lang};
use crate::otp::{
    current_unix_millis, current_unix_seconds, decode_qr_from_image, export_google_auth_migration,
    export_html, export_txt, format_code_display, generate_code_for_entry, parse_otpauth_uri,
};
use crate::tray::{spawn_tray, AegisTray, SharedTrayState, TrayCommand};
use crate::ui::widgets::{
    danger_button, draw_countdown_ring, draw_issuer_avatar, draw_toast, field_label, filter_pill,
    fit_text, icon_button, menu_item, menu_item_colored, modal, paint_icon, primary_button,
    secondary_button, segmented, tokens, Icon, AEGIS_AMBER, AEGIS_BLUE, AEGIS_RED,
};
use crate::vault::{
    is_vault_file_encrypted, load_vault, parse_vault_str, EntryInfo, OtpType, UnlockedVault, VaultEntry,
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

enum CardAction {
    Copy(String, String),
    ToggleFav(Vec<String>),
    SetFav(Vec<String>, bool),
    SetGroup(Vec<String>, String, bool),
    HotpNext(String),
    Edit(VaultEntry),
    Delete(Vec<String>),
    ToggleSelect(String),
    SelectAll,
    ClearSelection,
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
    delete_confirm_ids: Vec<String>,
    selected: std::collections::HashSet<String>,

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
    scale_save_pending: bool,
    sec_old_password: String,
    export_encrypt: bool,
    export_pwd: String,
    export_pwd_confirm: String,
    export_confirm_open: bool,
    export_go: bool,
}

impl AegisApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        install_fonts(&cc.egui_ctx);
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
            delete_confirm_ids: Vec::new(),
            selected: std::collections::HashSet::new(),
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
            scale_save_pending: false,
            sec_old_password: String::new(),
            export_encrypt: true,
            export_pwd: String::new(),
            export_pwd_confirm: String::new(),
            export_confirm_open: false,
            export_go: false,
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
        // On Wayland prefer wl-copy: it keeps serving the selection after we return.
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            use std::io::Write;
            use std::process::{Command, Stdio};
            if let Ok(mut child) = Command::new("wl-copy")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                let wrote = child
                    .stdin
                    .take()
                    .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
                if wrote && child.wait().map(|s| s.success()).unwrap_or(false) {
                    self.show_toast(format!("Copied {label} to clipboard"), false);
                    return;
                }
            }
        }
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
                // Embed the vault into app storage so it no longer depends on the original file.
                let path = match adopt_vault_file(&path) {
                    Ok(internal) => internal,
                    Err(e) => {
                        self.show_toast(format!("Could not copy vault into app storage: {e}"), true);
                        path
                    }
                };
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
          egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let top_pad = ((ui.available_height() - 360.0) * 0.38).max(16.0);
            ui.vertical_centered(|ui| {
                ui.add_space(top_pad);

                if let Some(logo) = &self.app_logo {
                    ui.add(egui::Image::new((logo.id(), Vec2::splat(72.0))));
                    ui.add_space(10.0);
                }

                ui.label(RichText::new("Aegis Authenticator").size(26.0).strong());
                ui.add_space(20.0);

                let ut = tokens(ui.visuals().dark_mode);
                let card_fill = ut.card;
                let card_stroke = egui::Stroke::new(1.0_f32, ut.border);

                egui::Frame::NONE
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .inner_margin(egui::Margin::same(28))
                    .corner_radius(22.0)
                    .shadow(egui::Shadow {
                        offset: [0, 8],
                        blur: 24,
                        spread: 0,
                        color: Color32::from_black_alpha(60),
                    })
                    .show(ui, |ui| {
                        ui.set_width(380.0_f32.min((ui.ctx().screen_rect().width() - 100.0).max(220.0)));

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
                            ui.horizontal_wrapped(|ui| {
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
                            ui.horizontal_wrapped(|ui| {
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
        });

        // Language: small translate icon in the bottom-left corner (no big drop-down).
        egui::Area::new(egui::Id::new("unlock_lang_area"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::LEFT_BOTTOM, Vec2::new(14.0, -14.0))
            .show(ctx, |ui| {
                let resp = icon_button(ui, Icon::Translate, 36.0, None);
                let pid = egui::Id::new("unlock_lang_popup");
                if resp.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(pid));
                }
                let mut chosen: Option<Option<Lang>> = None;
                egui::popup::popup_above_or_below_widget(
                    ui,
                    pid,
                    &resp,
                    egui::AboveOrBelow::Above,
                    egui::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(170.0);
                        if menu_item(ui, s.lang_system) {
                            chosen = Some(None);
                        }
                        for l in Lang::ALL {
                            if menu_item(ui, l.native_name()) {
                                chosen = Some(Some(l));
                            }
                        }
                    },
                );
                if let Some(c) = chosen {
                    match c {
                        None => {
                            self.config.language = None;
                            self.lang = Lang::detect_system();
                        }
                        Some(l) => {
                            self.config.language = Some(l.code().to_string());
                            self.lang = l;
                        }
                    }
                    self.config.save();
                    self.sync_tray();
                }
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

        let dark = ctx.style().visuals.dark_mode;
        let t = tokens(dark);
        let win_w = ctx.screen_rect().width();

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::NONE
                    .fill(t.bar)
                    .inner_margin(egui::Margin::symmetric(16, 12)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.app_logo {
                        ui.add(egui::Image::new((logo.id(), Vec2::splat(26.0))));
                    }
                    ui.label(RichText::new("Aegis").size(19.0).strong());
                    if win_w >= 640.0 {
                        let dirty_mark = if self.dirty { " •" } else { "" };
                        let (badge_bg, badge_fg) = if is_encrypted {
                            (Color32::from_rgba_unmultiplied(32, 149, 242, 32), AEGIS_BLUE)
                        } else {
                            (Color32::from_rgba_unmultiplied(245, 158, 11, 32), AEGIS_AMBER)
                        };
                        egui::Frame::NONE
                            .fill(badge_bg)
                            .corner_radius(10.0)
                            .inner_margin(egui::Margin::symmetric(9, 3))
                            .show(ui, |ui| {
                                let status = if is_encrypted { s.encrypted } else { s.plaintext };
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("{file_label}{dirty_mark}  ·  {status}"))
                                            .size(11.5)
                                            .color(badge_fg),
                                    )
                                    .truncate(),
                                );
                            });
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_button(ui, s.add_entry).clicked() {
                            self.entry_editor = Some(EntryEditorState::new_empty());
                        }

                        let more = icon_button(ui, Icon::More, 30.0, None);
                        let more_id = egui::Id::new("more_menu");
                        if more.clicked() {
                            ui.memory_mut(|m| m.toggle_popup(more_id));
                        }
                        egui::popup::popup_below_widget(
                            ui,
                            more_id,
                            &more,
                            egui::PopupCloseBehavior::CloseOnClick,
                            |ui| {
                                ui.set_min_width(210.0);
                                if menu_item(ui, s.import_uri) {
                                    self.import_modal = Some(String::new());
                                }
                                ui.separator();
                                if menu_item(ui, s.save_ctrl_s) {
                                    self.save_vault();
                                }
                                if menu_item(ui, s.save_as) {
                                    self.save_vault_as();
                                }
                                if menu_item(ui, s.open_another_vault) {
                                    self.select_vault_file();
                                }
                                ui.separator();
                                if menu_item(ui, s.encryption_pwd) {
                                    self.security_modal_open = true;
                                    self.sec_new_password.clear();
                                    self.sec_confirm_password.clear();
                self.sec_old_password.clear();
                                }
                                if menu_item(ui, s.manage_groups) {
                                    self.groups_modal_open = true;
                                }
                                ui.separator();
                                let theme_lbl = if self.config.dark_mode {
                                    s.theme_light
                                } else {
                                    s.theme_dark
                                };
                                if menu_item(ui, theme_lbl) {
                                    self.config.dark_mode = !self.config.dark_mode;
                                    apply_theme(ctx, self.config.dark_mode);
                                    self.config.save();
                                }
                                ui.separator();
                                if menu_item(ui, s.quit) {
                                    self.quitting = true;
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                            },
                        );

                        if icon_button(ui, Icon::Gear, 30.0, None)
                            .on_hover_text(s.settings)
                            .clicked()
                        {
                            self.settings_open = !self.settings_open;
                        }
                        if icon_button(ui, Icon::Lock, 30.0, None)
                            .on_hover_text(s.lock)
                            .clicked()
                        {
                            self.lock_vault();
                        }
                    });
                });

                // Search
                ui.horizontal(|ui| {
                    let w = ui.available_width();
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .hint_text(s.search_hint)
                            .margin(egui::Margin::symmetric(12, 8))
                            .desired_width(w),
                    );
                });

                // Sort + filters (wrap instead of overflowing)
                ui.horizontal_wrapped(|ui| {
                    let sort_lbl = match self.config.sort_mode {
                        SortMode::Default => s.sort_default,
                        SortMode::IssuerAsc => s.sort_issuer_az,
                        SortMode::IssuerDesc => s.sort_issuer_za,
                        SortMode::NameAsc => s.sort_name_az,
                        SortMode::NameDesc => s.sort_name_za,
                        SortMode::FavoritesFirst => s.sort_fav_first,
                    };
                    egui::ComboBox::from_id_salt("sort_combo")
                        .selected_text(sort_lbl)
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
                    if filter_pill(ui, self.filter_mode == FilterMode::All, s.all).clicked() {
                        self.filter_mode = FilterMode::All;
                    }
                    if filter_pill(ui, self.filter_mode == FilterMode::Favorites, s.favorites)
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

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(t.bg)
                    .inner_margin(egui::Margin::symmetric(16, 14)),
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
                let groups: Vec<VaultGroup> = self
                    .vault
                    .as_ref()
                    .map(|v| v.db.groups.clone())
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
                        b.issuer.to_ascii_lowercase().cmp(&a.issuer.to_ascii_lowercase())
                    }),
                    SortMode::NameAsc => filtered.sort_by(|a, b| {
                        a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase())
                    }),
                    SortMode::NameDesc => filtered.sort_by(|a, b| {
                        b.name.to_ascii_lowercase().cmp(&a.name.to_ascii_lowercase())
                    }),
                    SortMode::FavoritesFirst => filtered.sort_by(|a, b| {
                        b.favorite.cmp(&a.favorite).then_with(|| {
                            a.issuer.to_ascii_lowercase().cmp(&b.issuer.to_ascii_lowercase())
                        })
                    }),
                }

                // Drop selections that no longer exist
                let all_ids: std::collections::HashSet<String> =
                    filtered.iter().map(|e| e.uuid.clone()).collect();
                self.selected.retain(|id| all_ids.contains(id));

                if filtered.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(RichText::new(s.no_entries).size(17.0).color(t.muted));
                        ui.add_space(6.0);
                        ui.label(RichText::new(s.no_entries_tip).small().color(t.muted));
                    });
                    return;
                }

                let mut actions: Vec<CardAction> = Vec::new();

                // Selection bar
                if !self.selected.is_empty() {
                    egui::Frame::NONE
                        .fill(Color32::from_rgba_unmultiplied(32, 149, 242, 30))
                        .corner_radius(12.0)
                        .inner_margin(egui::Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "{} {}",
                                        self.selected.len(),
                                        s.selected_n
                                    ))
                                    .strong()
                                    .color(AEGIS_BLUE),
                                );
                                if secondary_button(ui, s.ctx_select_all).clicked() {
                                    actions.push(CardAction::SelectAll);
                                }
                                if secondary_button(ui, s.clear).clicked() {
                                    actions.push(CardAction::ClearSelection);
                                }
                                if danger_button(ui, s.delete).clicked() {
                                    actions.push(CardAction::Delete(
                                        self.selected.iter().cloned().collect(),
                                    ));
                                }
                            });
                        });
                    ui.add_space(10.0);
                }

                // Ctrl + scroll (or pinch) scales the cards; the grid re-flows automatically.
                // Only real Ctrl + mouse-wheel events count (egui's generic zoom_delta can
                // report phantom zooms and made the cards grow on their own).
                let wheel: f32 = ctx.input(|i| {
                    i.raw
                        .events
                        .iter()
                        .filter_map(|e| match e {
                            egui::Event::MouseWheel { unit, delta, modifiers, .. }
                                if modifiers.ctrl || modifiers.command =>
                            {
                                Some(match unit {
                                    egui::MouseWheelUnit::Line => delta.y * 0.06,
                                    egui::MouseWheelUnit::Page => delta.y * 0.3,
                                    egui::MouseWheelUnit::Point => delta.y * 0.002,
                                })
                            }
                            _ => None,
                        })
                        .sum()
                });
                if wheel.abs() > f32::EPSILON {
                    self.config.card_scale = (self.config.card_scale * (1.0 + wheel)).clamp(0.7, 1.8);
                    self.scale_save_pending = true;
                } else if self.scale_save_pending {
                    self.scale_save_pending = false;
                    self.config.save();
                }
                if ctx.input(|i| (i.modifiers.ctrl || i.modifiers.command) && i.key_pressed(egui::Key::Num0)) {
                    self.config.card_scale = 1.0;
                    self.config.save();
                }
                let z = self.config.card_scale;

                let avail_w = ui.available_width();
                let gap = 12.0_f32;
                let min_card = 290.0_f32 * z;
                let cols = (((avail_w + gap) / (min_card + gap)).floor() as usize).max(1);
                let card_w = (avail_w - gap * (cols as f32 - 1.0)) / cols as f32;
                let card_h = 104.0_f32 * z;
                let rows = filtered.len().div_ceil(cols);

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let total_h = rows as f32 * (card_h + gap) - gap;
                        let (area, _) = ui.allocate_exact_size(
                            Vec2::new(avail_w, total_h.max(0.0)),
                            Sense::hover(),
                        );
                        let ctrl_held = ui.input(|i| i.modifiers.command || i.modifiers.shift);
                        let selecting = !self.selected.is_empty();

                        for (i, entry) in filtered.iter().enumerate() {
                            let (row, col) = (i / cols, i % cols);
                            let rect = Rect::from_min_size(
                                area.min
                                    + Vec2::new(
                                        col as f32 * (card_w + gap),
                                        row as f32 * (card_h + gap),
                                    ),
                                Vec2::new(card_w, card_h),
                            );
                            if !ui.is_rect_visible(rect) {
                                continue;
                            }
                            let texture = self.get_or_load_icon(ctx, entry);
                            let code_res = generate_code_for_entry(entry, now_secs);
                            let display_code = match &code_res {
                                Ok(c) => format_code_display(c),
                                Err(_) => "ERROR".to_string(),
                            };
                            let is_selected = self.selected.contains(&entry.uuid);
                            let id = egui::Id::new(("card", &entry.uuid));
                            let resp = ui
                                .interact(rect, id, Sense::click())
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            let hovered = ui.rect_contains_pointer(rect) || resp.context_menu_opened();

                            // Card surface
                            let fill = if hovered { t.card_hover } else { t.card };
                            let stroke = if is_selected {
                                egui::Stroke::new(2.0_f32, AEGIS_BLUE)
                            } else {
                                egui::Stroke::new(1.0_f32, t.border)
                            };
                            ui.painter().rect(
                                rect,
                                16.0,
                                fill,
                                stroke,
                                egui::StrokeKind::Inside,
                            );

                            let pad = 14.0 * z;
                            let inner = rect.shrink(pad);

                            // Avatar
                            let av = 36.0 * z;
                            let av_rect = Rect::from_min_size(inner.min, Vec2::splat(av));
                            if self.config.show_icons {
                                let mut child = ui.new_child(
                                    egui::UiBuilder::new().max_rect(av_rect),
                                );
                                draw_issuer_avatar(
                                    &mut child,
                                    &entry.issuer,
                                    &entry.name,
                                    texture.as_ref(),
                                    av,
                                );
                            }
                            let text_x = if self.config.show_icons {
                                inner.min.x + av + 10.0
                            } else {
                                inner.min.x
                            };

                            // Title + subtitle (truncated, never overflow)
                            let right_reserved = 30.0 + if hovered { 84.0 } else { 0.0 };
                            let text_w = (inner.max.x - right_reserved - text_x).max(20.0);
                            let title = if entry.issuer.is_empty() {
                                entry.name.as_str()
                            } else {
                                entry.issuer.as_str()
                            };
                            let sub: String = if !entry.issuer.is_empty() && !entry.name.is_empty() {
                                entry.name.clone()
                            } else {
                                entry.entry_type.label().to_string()
                            };
                            let g1 = fit_text(ui, title, egui::FontId::proportional(15.0 * z), t.text, text_w);
                            let g2 = fit_text(ui, &sub, egui::FontId::proportional(12.0 * z), t.muted, text_w);
                            ui.painter().galley(Pos2::new(text_x, inner.min.y + 1.0), g1, t.text);
                            ui.painter().galley(Pos2::new(text_x, inner.min.y + 21.0 * z), g2, t.muted);

                            // Code (bottom-left)
                            let code_color = if entry.favorite { AEGIS_BLUE } else { AEGIS_BLUE };
                            ui.painter().text(
                                Pos2::new(inner.min.x, inner.max.y),
                                egui::Align2::LEFT_BOTTOM,
                                &display_code,
                                egui::FontId::monospace(27.0 * z),
                                code_color,
                            );

                            // Ring / next (bottom-right)
                            let ring_size = 32.0 * z;
                            let ring_rect = Rect::from_min_size(
                                Pos2::new(inner.max.x - ring_size, inner.max.y - ring_size),
                                Vec2::splat(ring_size),
                            );
                            if entry.entry_type == OtpType::Hotp {
                                let r = Rect::from_min_size(
                                    Pos2::new(inner.max.x - 56.0 * z, inner.max.y - 28.0 * z),
                                    Vec2::new(56.0 * z, 28.0 * z),
                                );
                                let rr = ui.interact(r, id.with("next"), Sense::click());
                                ui.painter().rect_filled(
                                    r,
                                    14.0,
                                    if rr.hovered() { t.chip_hover } else { t.chip },
                                );
                                ui.painter().text(
                                    r.center(),
                                    egui::Align2::CENTER_CENTER,
                                    "Next",
                                    egui::FontId::proportional(12.5),
                                    t.text,
                                );
                                if rr.clicked() {
                                    actions.push(CardAction::HotpNext(entry.uuid.clone()));
                                }
                            } else {
                                let period = entry.info.period.unwrap_or(30) as f64;
                                let elapsed = ((now_millis as f64) / 1000.0) % period;
                                let remaining = (period - elapsed) as f32;
                                let mut child = ui.new_child(egui::UiBuilder::new().max_rect(ring_rect));
                                draw_countdown_ring(&mut child, remaining, period as f32, ring_size);
                            }

                            // Star (always) + edit/delete (on hover)
                            let star_rect = Rect::from_min_size(
                                Pos2::new(inner.max.x - 26.0, inner.min.y - 3.0),
                                Vec2::splat(26.0),
                            );
                            let star_resp = ui.interact(star_rect, id.with("star"), Sense::click());
                            if entry.favorite {
                                paint_icon(ui.painter(), Icon::Star { filled: true }, star_rect.center(), 9.0, AEGIS_AMBER);
                            } else if hovered || star_resp.hovered() {
                                paint_icon(
                                    ui.painter(),
                                    Icon::Star { filled: false },
                                    star_rect.center(),
                                    9.0,
                                    if star_resp.hovered() { AEGIS_AMBER } else { t.muted },
                                );
                            }
                            if star_resp.clicked() {
                                actions.push(CardAction::ToggleFav(vec![entry.uuid.clone()]));
                            }

                            let mut sub_clicked = false;
                            if hovered {
                                for (k, icon) in [Icon::Copy, Icon::Pencil, Icon::Trash].into_iter().enumerate() {
                                    let r = Rect::from_min_size(
                                        Pos2::new(
                                            inner.max.x - 26.0 - 28.0 * (3 - k) as f32,
                                            inner.min.y - 3.0,
                                        ),
                                        Vec2::splat(26.0),
                                    );
                                    let rr = ui.interact(r, id.with(("act", k)), Sense::click());
                                    if rr.hovered() {
                                        ui.painter().circle_filled(r.center(), 13.0, t.chip_hover);
                                    }
                                    paint_icon(
                                        ui.painter(),
                                        icon,
                                        r.center(),
                                        8.0,
                                        if rr.hovered() { t.text } else { t.muted },
                                    );
                                    if rr.clicked() {
                                        sub_clicked = true;
                                        if k == 0 {
                                            if let Ok(raw) = &code_res {
                                                let lbl = if entry.issuer.is_empty() {
                                                    entry.name.clone()
                                                } else {
                                                    entry.issuer.clone()
                                                };
                                                actions.push(CardAction::Copy(raw.clone(), lbl));
                                            }
                                        } else if k == 1 {
                                            actions.push(CardAction::Edit(entry.clone()));
                                        } else {
                                            actions.push(CardAction::Delete(vec![entry.uuid.clone()]));
                                        }
                                    }
                                }
                            }

                            // Card click: copy (or toggle selection)
                            if resp.clicked() && !sub_clicked && !star_resp.hovered() {
                                if ctrl_held || selecting {
                                    actions.push(CardAction::ToggleSelect(entry.uuid.clone()));
                                } else if let Ok(raw) = &code_res {
                                    let lbl = if entry.issuer.is_empty() {
                                        entry.name.clone()
                                    } else {
                                        entry.issuer.clone()
                                    };
                                    actions.push(CardAction::Copy(raw.clone(), lbl));
                                }
                            }

                            // Right-click context menu
                            let targets: Vec<String> = if is_selected {
                                self.selected.iter().cloned().collect()
                            } else {
                                vec![entry.uuid.clone()]
                            };
                            let multi = targets.len() > 1;
                            resp.context_menu(|ui| {
                                ui.set_min_width(200.0);
                                if let Ok(raw) = &code_res {
                                    if menu_item(ui, s.ctx_copy) {
                                        let lbl = if entry.issuer.is_empty() {
                                            entry.name.clone()
                                        } else {
                                            entry.issuer.clone()
                                        };
                                        actions.push(CardAction::Copy(raw.clone(), lbl));
                                    }
                                }
                                let fav_lbl = if entry.favorite {
                                    s.ctx_fav_remove
                                } else {
                                    s.ctx_fav_add
                                };
                                if menu_item(ui, fav_lbl) {
                                    let make_fav = !entry.favorite;
                                    let ids = targets.clone();
                                    actions.push(CardAction::SetFav(ids, make_fav));
                                }
                                if !multi && menu_item(ui, s.ctx_edit) {
                                    actions.push(CardAction::Edit(entry.clone()));
                                }
                                if !groups.is_empty() {
                                    ui.menu_button(s.ctx_group, |ui| {
                                        for g in &groups {
                                            let in_all = self.vault.as_ref().is_some_and(|v| {
                                                targets.iter().all(|id| {
                                                    v.db.entries
                                                        .iter()
                                                        .find(|e| &e.uuid == id)
                                                        .is_some_and(|e| e.groups.contains(&g.uuid))
                                                })
                                            });
                                            let mut checked = in_all;
                                            if ui.checkbox(&mut checked, &g.name).changed() {
                                                actions.push(CardAction::SetGroup(
                                                    targets.clone(),
                                                    g.uuid.clone(),
                                                    checked,
                                                ));
                                                ui.close_menu();
                                            }
                                        }
                                    });
                                }
                                ui.separator();
                                if menu_item(ui, s.ctx_select_all) {
                                    actions.push(CardAction::SelectAll);
                                }
                                if menu_item(ui, if is_selected { s.ctx_deselect } else { s.ctx_select }) {
                                    actions.push(CardAction::ToggleSelect(entry.uuid.clone()));
                                }
                                ui.separator();
                                let del_lbl = if multi {
                                    format!("{} ({})", s.delete, targets.len())
                                } else {
                                    s.delete.to_string()
                                };
                                if menu_item_colored(ui, &del_lbl, AEGIS_RED) {
                                    actions.push(CardAction::Delete(targets.clone()));
                                }
                            });
                        }
                    });

                if ui.input(|i| i.key_pressed(egui::Key::Escape)) && !self.selected.is_empty() {
                    self.selected.clear();
                }
                if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::A))
                    && self.entry_editor.is_none()
                    && !ctx.wants_keyboard_input()
                {
                    actions.push(CardAction::SelectAll);
                }

                for a in actions {
                    match a {
                        CardAction::Copy(code, lbl) => self.copy_to_clipboard(&code, &lbl),
                        CardAction::ToggleFav(ids) => {
                            if let Some(v) = &mut self.vault {
                                for e in v.db.entries.iter_mut().filter(|e| ids.contains(&e.uuid)) {
                                    e.favorite = !e.favorite;
                                }
                                self.dirty = true;
                            }
                        }
                        CardAction::SetFav(ids, val) => {
                            if let Some(v) = &mut self.vault {
                                for e in v.db.entries.iter_mut().filter(|e| ids.contains(&e.uuid)) {
                                    e.favorite = val;
                                }
                                self.dirty = true;
                            }
                        }
                        CardAction::SetGroup(ids, gid, add) => {
                            if let Some(v) = &mut self.vault {
                                for e in v.db.entries.iter_mut().filter(|e| ids.contains(&e.uuid)) {
                                    e.groups.retain(|x| x != &gid);
                                    if add {
                                        e.groups.push(gid.clone());
                                    }
                                }
                                self.dirty = true;
                            }
                        }
                        CardAction::HotpNext(uuid) => {
                            if let Some(v) = &mut self.vault {
                                if let Some(e) = v.db.entries.iter_mut().find(|x| x.uuid == uuid) {
                                    e.info.counter = Some(e.info.counter.unwrap_or(0).saturating_add(1));
                                    self.dirty = true;
                                }
                            }
                        }
                        CardAction::Edit(e) => {
                            self.entry_editor = Some(EntryEditorState::from_entry(&e));
                        }
                        CardAction::Delete(ids) => self.delete_confirm_ids = ids,
                        CardAction::ToggleSelect(id) => {
                            if !self.selected.remove(&id) {
                                self.selected.insert(id);
                            }
                        }
                        CardAction::SelectAll => {
                            self.selected = filtered.iter().map(|e| e.uuid.clone()).collect();
                        }
                        CardAction::ClearSelection => self.selected.clear(),
                    }
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

            let editor_open = modal(ctx, "entry_editor", title, 440.0, |ui| {

                    if editor.editing_uuid.is_none() {
                        if secondary_button(ui, s.scan_qr).clicked() {
                            editor.qr_menu_open = !editor.qr_menu_open;
                        }

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

                    let full = ui.available_width();
                    field_label(ui, s.issuer);
                    ui.add(
                        egui::TextEdit::singleline(&mut editor.issuer)
                            .hint_text("e.g. Google, GitHub")
                            .margin(egui::Margin::symmetric(10, 7))
                            .desired_width(full),
                    );
                    field_label(ui, s.account_name);
                    ui.add(
                        egui::TextEdit::singleline(&mut editor.name)
                            .hint_text("e.g. user@example.com")
                            .margin(egui::Margin::symmetric(10, 7))
                            .desired_width(full),
                    );
                    field_label(ui, s.secret_base32);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut editor.secret)
                                .password(!editor.show_secret)
                                .margin(egui::Margin::symmetric(10, 7))
                                .desired_width((full - 80.0).max(60.0)),
                        );
                        let lbl = if editor.show_secret { "Hide" } else { "Show" };
                        if secondary_button(ui, lbl).clicked() {
                            editor.show_secret = !editor.show_secret;
                        }
                    });
                    field_label(ui, s.note);
                    ui.add(
                        egui::TextEdit::singleline(&mut editor.note)
                            .hint_text(s.optional)
                            .margin(egui::Margin::symmetric(10, 7))
                            .desired_width(full),
                    );
                    ui.add_space(4.0);
                    ui.checkbox(&mut editor.favorite, s.favorite.trim_end_matches(':'));

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
                            .spacing([12.0, 8.0]).min_col_width(80.0)
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
                    ui.horizontal_wrapped(|ui| {
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
                        if secondary_button(ui, s.cancel).clicked() {
                            keep_open = false;
                        }
                    });
                });

            if keep_open && editor_open {
                self.entry_editor = Some(editor);
            }
        }

        // 2. Import otpauth:// URI Modal
        if let Some(mut uri_text) = self.import_modal.take() {
            let mut keep_open = true;
            let still = modal(ctx, "import_modal", "Import otpauth:// URIs", 460.0, |ui| {
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
            if keep_open && still {
                self.import_modal = Some(uri_text);
            }
        }

        // 3. Manage Groups Modal
        if self.groups_modal_open {
            let open = modal(ctx, "m_ManageGroups", "Manage Groups", 360.0, |ui| {
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
            let open = modal(ctx, "m_svault_encryption", s.vault_encryption, 380.0, |ui| {
                    let needs_old = self.vault.as_ref().is_some_and(|v| v.is_encrypted());
                    if needs_old {
                        ui.label(s.current_pwd);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.sec_old_password)
                                .password(true)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(8.0);
                    }
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
                        if primary_button(ui, s.apply).clicked() {
                            // Verify the current password against the in-memory vault.
                            let old_ok = !needs_old
                                || self
                                    .vault
                                    .as_ref()
                                    .and_then(|v| v.to_vault_file().ok())
                                    .and_then(|f| serde_json::to_string(&f).ok())
                                    .is_some_and(|js| {
                                        parse_vault_str(&js, Some(&self.sec_old_password)).is_ok()
                                    });
                            if !old_ok {
                                self.show_toast(s.wrong_pwd, true);
                            } else if self.sec_new_password != self.sec_confirm_password {
                                self.show_toast(s.passwords_mismatch, true);
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
                self.sec_old_password.clear();
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
        if !self.delete_confirm_ids.is_empty() {
            let ids = self.delete_confirm_ids.clone();
            let msg = if ids.len() > 1 {
                s.delete_many.replace("{n}", &ids.len().to_string())
            } else {
                s.delete_confirm.to_string()
            };
            let mut do_delete = false;
            let mut cancel = false;
            let open = modal(ctx, "delete_modal", s.delete_entry, 380.0, |ui| {
                ui.label(msg);
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if danger_button(ui, s.delete).clicked() {
                        do_delete = true;
                    }
                    if secondary_button(ui, s.cancel).clicked() {
                        cancel = true;
                    }
                });
            });
            if do_delete {
                if let Some(v) = &mut self.vault {
                    v.db.entries.retain(|e| !ids.contains(&e.uuid));
                    self.dirty = true;
                }
                self.selected.clear();
                self.delete_confirm_ids.clear();
            } else if cancel || !open {
                self.delete_confirm_ids.clear();
            }
        }

        // Unencrypted export confirmation
        if self.export_confirm_open {
            let mut go = false;
            let mut cancel = false;
            let open = modal(ctx, "export_confirm", s.export_plain_title, 400.0, |ui| {
                ui.label(RichText::new(s.export_warn).color(AEGIS_RED));
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if danger_button(ui, s.export_anyway).clicked() {
                        go = true;
                    }
                    if secondary_button(ui, s.cancel).clicked() {
                        cancel = true;
                    }
                });
            });
            if go {
                self.export_confirm_open = false;
                self.export_go = true;
            } else if cancel || !open {
                self.export_confirm_open = false;
            }
        }

        // 6. Settings Modal (Appearance, Security, Backups, Import / Export)
        if self.settings_open {
            let mut close_for_groups = false;
            let mut close_for_security = false;
            let mut do_backup_now = false;
            let mut do_import_json = false;
            let mut do_import_txt = false;
            let mut do_export = false;

            let open = modal(ctx, "m_ssettings", s.settings, 510.0, |ui| {
                    ui.horizontal_wrapped(|ui| {
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
                                    let cur = if self.config.dark_mode { 0 } else { 1 };
                                    if let Some(i) = segmented(ui, cur, &["Dark", "Light"]) {
                                        self.config.dark_mode = i == 0;
                                        apply_theme(ctx, self.config.dark_mode);
                                        self.config.save();
                                    }
                                    ui.end_row();

                                    ui.label(s.language_label);
                                    if language_picker(ui, "settings_lang", &mut self.config, &mut self.lang, s.lang_system) {
                                        self.sync_tray();
                                    }
                                    ui.end_row();
                                });

                            ui.add_space(8.0);
                            if ui
                                .checkbox(&mut self.config.show_icons, s.show_icons_label)
                                .changed()
                            {
                                self.config.save();
                            }
                            ui.add_space(4.0);
                            if ui
                                .checkbox(&mut self.config.close_to_tray, s.close_to_tray)
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
                            let is_json = self.export_format == ExportFormat::AegisJson;
                            if is_json {
                                ui.add_space(8.0);
                                ui.checkbox(&mut self.export_encrypt, s.export_encrypt);
                                if self.export_encrypt {
                                    field_label(ui, s.export_pwd);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.export_pwd)
                                            .password(true)
                                            .desired_width(f32::INFINITY),
                                    );
                                    ui.add_space(4.0);
                                    ui.label(s.confirm_password);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.export_pwd_confirm)
                                            .password(true)
                                            .desired_width(f32::INFINITY),
                                    );
                                }
                            }
                            let plain_export = !is_json || !self.export_encrypt;
                            if plain_export {
                                ui.add_space(8.0);
                                egui::Frame::NONE
                                    .fill(Color32::from_rgba_unmultiplied(239, 68, 68, 30))
                                    .corner_radius(10.0)
                                    .inner_margin(egui::Margin::symmetric(12, 8))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(s.export_warn).color(AEGIS_RED));
                                    });
                            }
                            ui.add_space(10.0);
                            if primary_button(ui, s.export_btn).clicked() {
                                if is_json
                                    && self.export_encrypt
                                    && (self.export_pwd.is_empty()
                                        || self.export_pwd != self.export_pwd_confirm)
                                {
                                    self.show_toast(s.export_pwd_needed, true);
                                } else if plain_export {
                                    self.export_confirm_open = true;
                                } else {
                                    do_export = true;
                                }
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
                self.sec_old_password.clear();
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
            if self.export_go {
                self.export_go = false;
                do_export = true;
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
                                let mut ev = v.clone();
                                let pw = if self.export_encrypt {
                                    Some(self.export_pwd.clone())
                                } else {
                                    None
                                };
                                let res = ev
                                    .set_password(pw.as_deref())
                                    .and_then(|_| ev.save_to_path(&path));
                                match res {
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
        // Alt+F4 / Super+Q / the X button really close the window. With "keep in tray" on,
        // a tray-only background process is started first (works on Wayland, unlike hiding).
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.dirty && self.vault.is_some() {
                if self.vault_path.is_some() {
                    self.save_vault();
                }
                if self.dirty {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    self.quitting = false;
                    self.show_toast("Unsaved changes: save the vault first (Ctrl+S)", true);
                }
            }
            if !self.dirty && !self.quitting && self.config.close_to_tray {
                crate::tray::start_background_tray();
            }
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

        // The unlock screen scales with the window (small windows shrink it, big ones grow it).
        let target_zoom = if self.vault.is_none() {
            let base = ctx.screen_rect().size() * ctx.zoom_factor();
            (base.x / 520.0).min(base.y / 560.0).clamp(0.8, 1.8)
        } else {
            1.0
        };
        if (ctx.zoom_factor() - target_zoom).abs() > 0.03 {
            ctx.set_zoom_factor(target_zoom);
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

/// Language drop-down with a "system language" entry. Returns true if the language changed.
fn language_picker(
    ui: &mut egui::Ui,
    id: &str,
    config: &mut AppConfig,
    lang: &mut Lang,
    system_label: &str,
) -> bool {
    let current = match &config.language {
        None => system_label.to_string(),
        Some(code) => Lang::from_code(code).native_name().to_string(),
    };
    let mut choice: Option<Option<Lang>> = None;
    egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .show_ui(ui, |ui| {
            if ui.selectable_label(config.language.is_none(), system_label).clicked() {
                choice = Some(None);
            }
            for l in Lang::ALL {
                let sel = config.language.as_deref() == Some(l.code());
                if ui.selectable_label(sel, l.native_name()).clicked() {
                    choice = Some(Some(l));
                }
            }
        });
    if let Some(c) = choice {
        match c {
            None => {
                config.language = None;
                *lang = Lang::detect_system();
            }
            Some(l) => {
                config.language = Some(l.code().to_string());
                *lang = l;
            }
        }
        config.save();
        return true;
    }
    false
}

fn install_fonts(ctx: &egui::Context) {
    let candidates = [
        "/usr/share/fonts/inter/Inter-Regular.ttf",
        "/usr/share/fonts/TTF/Inter-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("ui_font".into(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "ui_font".into());
            ctx.set_fonts(fonts);
            return;
        }
    }
}

fn apply_theme(ctx: &egui::Context, dark_mode: bool) {
    let t = tokens(dark_mode);
    let mut style = (*ctx.style()).clone();
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.interact_size.y = 30.0;
    style.spacing.menu_margin = egui::Margin::same(6);
    style.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
    style.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(13.5));
    style.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(11.5));
    style.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
    let mut v = if dark_mode { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = t.bg;
    v.window_fill = t.card;
    v.extreme_bg_color = t.field;
    v.faint_bg_color = t.chip;
    v.window_corner_radius = egui::CornerRadius::same(16);
    v.menu_corner_radius = egui::CornerRadius::same(12);
    v.window_stroke = egui::Stroke::new(1.0_f32, t.border);
    v.override_text_color = Some(t.text);
    let r = egui::CornerRadius::same(10);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
        w.bg_stroke = egui::Stroke::NONE;
    }
    v.widgets.noninteractive.bg_fill = t.card;
    v.widgets.inactive.bg_fill = t.chip;
    v.widgets.inactive.weak_bg_fill = t.chip;
    v.widgets.hovered.bg_fill = t.chip_hover;
    v.widgets.hovered.weak_bg_fill = t.chip_hover;
    v.widgets.active.bg_fill = t.chip_hover;
    v.widgets.active.weak_bg_fill = t.chip_hover;
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(32, 149, 242, 120);
    v.selection.stroke = egui::Stroke::new(1.0_f32, AEGIS_BLUE);
    style.visuals = v;
    ctx.set_style(style);
}
