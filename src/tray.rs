use std::collections::HashMap;
use std::io::Cursor;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use image::{ImageFormat, Rgba, RgbaImage};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{Icon, MenuItem, Tray, TrayService};

use crate::i18n::{strings, Lang};
use crate::otp::{current_unix_seconds, format_code_display, generate_code_for_entry};
use crate::vault::VaultEntry;

#[derive(Debug, Clone)]
pub enum TrayCommand {
    ShowWindow,
    LockVault,
    Quit,
    Copied(String),
}

pub struct SharedTrayState {
    pub is_locked: bool,
    pub entries: Vec<VaultEntry>,
    pub icon_png_cache: HashMap<String, Vec<u8>>,
    pub lang: Lang,
}

impl Default for SharedTrayState {
    fn default() -> Self {
        Self {
            is_locked: true,
            entries: Vec::new(),
            icon_png_cache: HashMap::new(),
            lang: Lang::En,
        }
    }
}

/// Copies text to the clipboard; uses wl-copy on Wayland (reliable), arboard otherwise.
pub fn set_clipboard(text: &str) {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        use std::io::Write;
        use std::process::Stdio;
        if let Ok(mut child) = Command::new("wl-copy")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let wrote = child
                .stdin
                .take()
                .is_some_and(|mut i| i.write_all(text.as_bytes()).is_ok());
            if wrote && child.wait().map(|s| s.success()).unwrap_or(false) {
                return;
            }
        }
    }
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(text.to_string());
    }
}

pub struct AegisTray {
    pub state: Arc<Mutex<SharedTrayState>>,
    pub tx: Sender<TrayCommand>,
    pub egui_ctx: egui::Context,
    pub app_icon: Icon,
}

impl AegisTray {
    fn send_cmd(&self, cmd: TrayCommand) {
        let _ = self.tx.send(cmd);
        self.egui_ctx.request_repaint();
    }
}

impl Tray for AegisTray {
    fn id(&self) -> String {
        "aegis-linux".to_string()
    }

    fn title(&self) -> String {
        "Aegis Authenticator".to_string()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![self.app_icon.clone()]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send_cmd(TrayCommand::ShowWindow);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();
        let lang = self.state.lock().unwrap().lang;
        let s = strings(lang);

        items.push(MenuItem::Standard(StandardItem {
            label: s.tray_show.to_string(),
            activate: Box::new(|tray: &mut Self| {
                tray.send_cmd(TrayCommand::ShowWindow);
            }),
            ..Default::default()
        }));

        items.push(MenuItem::Separator);

        let get_key_submenu = {
            let mut guard = self.state.lock().unwrap();
            let is_locked = guard.is_locked;
            let entries = guard.entries.clone();

            let sub_items: Vec<MenuItem<Self>> = if is_locked {
                vec![MenuItem::Standard(StandardItem {
                    label: s.tray_locked.to_string(),
                    enabled: false,
                    ..Default::default()
                })]
            } else if entries.is_empty() {
                vec![MenuItem::Standard(StandardItem {
                    label: s.tray_empty.to_string(),
                    enabled: false,
                    ..Default::default()
                })]
            } else {
                let now = current_unix_seconds();
                let mut entries = entries;
                entries.sort_by_key(|e| {
                    if e.issuer.is_empty() { e.name.to_lowercase() } else { e.issuer.to_lowercase() }
                });
                let flat: Vec<MenuItem<Self>> = entries
                    .into_iter()
                    .map(|entry| {
                        let icon_png = get_or_build_entry_png(&mut guard.icon_png_cache, &entry);
                        let title = match (&entry.issuer.is_empty(), &entry.name.is_empty()) {
                            (false, false) => format!("{} ({})", entry.issuer, entry.name),
                            (false, true) => entry.issuer.clone(),
                            (true, false) => entry.name.clone(),
                            (true, true) => "Unnamed".to_string(),
                        };

                        let code_preview = generate_code_for_entry(&entry, now)
                            .map(|c| format_code_display(&c))
                            .unwrap_or_else(|_| "ERR".to_string());

                        let label = format!("{title}  —  {code_preview}");
                        let entry_clone = entry.clone();

                        MenuItem::Standard(StandardItem {
                            label,
                            icon_data: icon_png,
                            activate: Box::new(move |tray: &mut Self| {
                                let now = current_unix_seconds();
                                if let Ok(raw_code) = generate_code_for_entry(&entry_clone, now) {
                                    set_clipboard(&raw_code);
                                    let display_name = if entry_clone.issuer.is_empty() {
                                        entry_clone.name.clone()
                                    } else {
                                        entry_clone.issuer.clone()
                                    };
                                    let formatted = format_code_display(&raw_code);
                                    let _ = Command::new("notify-send")
                                        .args([
                                            "-a",
                                            "Aegis Authenticator",
                                            "-t",
                                            "2500",
                                            &format!("Copied: {display_name}"),
                                            &formatted,
                                        ])
                                        .spawn();
                                    tray.send_cmd(TrayCommand::Copied(display_name));
                                }
                            }),
                            ..Default::default()
                        })
                    })
                    .collect();

                // Long lists would run off the screen (the shell draws the menu), so
                // split them into alphabetical pages.
                const PAGE: usize = 12;
                if flat.len() <= PAGE {
                    flat
                } else {
                    let labels: Vec<char> = guard
                        .entries
                        .iter()
                        .map(|e| {
                            let t = if e.issuer.is_empty() { &e.name } else { &e.issuer };
                            t.chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('#')
                        })
                        .collect();
                    let mut sorted_labels = labels;
                    sorted_labels.sort();
                    let mut pages: Vec<MenuItem<Self>> = Vec::new();
                    let mut start = 0usize;
                    let mut iter = flat.into_iter().peekable();
                    while iter.peek().is_some() {
                        let chunk: Vec<MenuItem<Self>> = iter.by_ref().take(PAGE).collect();
                        let end = start + chunk.len() - 1;
                        let a = sorted_labels.get(start).copied().unwrap_or('#');
                        let b = sorted_labels.get(end).copied().unwrap_or('#');
                        pages.push(MenuItem::SubMenu(SubMenu {
                            label: format!("{a} – {b}"),
                            submenu: chunk,
                            ..Default::default()
                        }));
                        start = end + 1;
                    }
                    pages
                }
            };

            MenuItem::SubMenu(SubMenu {
                label: s.tray_get_key.to_string(),
                submenu: sub_items,
                ..Default::default()
            })
        };

        items.push(get_key_submenu);
        items.push(MenuItem::Separator);

        let is_locked = self.state.lock().unwrap().is_locked;
        if !is_locked {
            items.push(MenuItem::Standard(StandardItem {
                label: s.tray_lock.to_string(),
                activate: Box::new(|tray: &mut Self| {
                    tray.send_cmd(TrayCommand::LockVault);
                }),
                ..Default::default()
            }));
        }

        items.push(MenuItem::Standard(StandardItem {
            label: s.tray_quit.to_string(),
            activate: Box::new(|tray: &mut Self| {
                tray.send_cmd(TrayCommand::Quit);
            }),
            ..Default::default()
        }));

        items
    }
}

pub fn spawn_tray(
    state: Arc<Mutex<SharedTrayState>>,
    tx: Sender<TrayCommand>,
    egui_ctx: egui::Context,
) -> ksni::Handle<AegisTray> {
    let tray = AegisTray {
        state,
        tx,
        egui_ctx,
        app_icon: build_wolf_tray_icon(),
    };
    let service = TrayService::new(tray);
    let handle = service.handle();
    service.spawn();
    handle
}

fn get_or_build_entry_png(
    cache: &mut HashMap<String, Vec<u8>>,
    entry: &VaultEntry,
) -> Vec<u8> {
    if let Some(cached) = cache.get(&entry.uuid) {
        return cached.clone();
    }

    let png_bytes = entry
        .icon
        .as_deref()
        .and_then(|b64| BASE64.decode(b64).ok())
        .and_then(|bytes| image::load_from_memory(&bytes).ok())
        .and_then(|img| {
            let resized = img.resize_exact(24, 24, image::imageops::FilterType::Triangle);
            let mut buf = Cursor::new(Vec::new());
            resized.write_to(&mut buf, ImageFormat::Png).ok()?;
            Some(buf.into_inner())
        })
        .unwrap_or_else(|| {
            let label = if !entry.issuer.trim().is_empty() {
                entry.issuer.trim()
            } else {
                entry.name.trim()
            };
            build_badge_png(label)
        });

    cache.insert(entry.uuid.clone(), png_bytes.clone());
    png_bytes
}

fn build_badge_png(label: &str) -> Vec<u8> {
    const PALETTE: &[[u8; 3]] = &[
        [16, 185, 129],
        [59, 130, 246],
        [139, 92, 246],
        [236, 72, 153],
        [245, 158, 11],
        [20, 184, 166],
        [99, 102, 241],
        [244, 63, 94],
    ];
    let mut hash: u32 = 2166136261;
    for b in label.bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(16777619);
    }
    let rgb = PALETTE[(hash as usize) % PALETTE.len()];

    let size = 24u32;
    let center = (size as f32 - 1.0) / 2.0;
    let radius = 10.5_f32;
    let mut img = RgbaImage::new(size, size);

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= radius {
                // Simple white inner dot/keyhole motif
                if dist <= 3.5 {
                    img.put_pixel(x, y, Rgba([255, 255, 255, 230]));
                } else {
                    img.put_pixel(x, y, Rgba([rgb[0], rgb[1], rgb[2], 255]));
                }
            } else {
                img.put_pixel(x, y, Rgba([0, 0, 0, 0]));
            }
        }
    }

    let mut buf = Cursor::new(Vec::new());
    let _ = img.write_to(&mut buf, ImageFormat::Png);
    buf.into_inner()
}

fn build_wolf_tray_icon() -> Icon {
    let png_bytes = include_bytes!("../assets/icon.png");
    if let Ok(img) = image::load_from_memory(png_bytes) {
        let resized = img
            .resize_exact(32, 32, image::imageops::FilterType::Lanczos3)
            .to_rgba8();
        let mut data = Vec::with_capacity(32 * 32 * 4);
        for pixel in resized.pixels() {
            // ksni expects ARGB32 in big-endian byte order
            data.push(pixel[3]);
            data.push(pixel[0]);
            data.push(pixel[1]);
            data.push(pixel[2]);
        }
        return Icon {
            width: 32,
            height: 32,
            data,
        };
    }

    Icon {
        width: 1,
        height: 1,
        data: vec![255, 16, 185, 129],
    }
}

// ---------------------------------------------------------------------------
// Background tray mode
//
// Wayland has no way to hide a toplevel window, so "close to tray" works like
// GTK apps do: the window is really closed and a tiny tray-only process stays
// alive. "Show Aegis" starts a fresh window (the vault comes back locked).
// ---------------------------------------------------------------------------

fn pid_file() -> Option<std::path::PathBuf> {
    dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .map(|d| d.join("aegis-linux-tray.pid"))
}

fn spawn_detached(args: &[&str]) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    if let Ok(exe) = std::env::current_exe() {
        let _ = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
    }
}

/// Starts the tray-only background process.
pub fn start_background_tray() {
    spawn_detached(&["--tray-only"]);
}

/// Stops a running tray-only process (if any). Called when a window starts.
pub fn stop_background_tray() {
    let Some(path) = pid_file() else { return };
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(pid) = raw.trim().parse::<u32>() {
            let is_ours = std::fs::read(format!("/proc/{pid}/cmdline"))
                .map(|c| String::from_utf8_lossy(&c).contains("--tray-only"))
                .unwrap_or(false);
            if is_ours {
                let _ = Command::new("kill").arg(pid.to_string()).status();
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Runs the tray icon without any window until the user picks Show or Quit.
pub fn run_tray_only() {
    let config = crate::config::AppConfig::load();
    let lang = config
        .language
        .as_deref()
        .map(Lang::from_code)
        .unwrap_or_else(Lang::detect_system);

    if let Some(path) = pid_file() {
        let _ = std::fs::write(path, std::process::id().to_string());
    }

    let state = Arc::new(Mutex::new(SharedTrayState {
        is_locked: true,
        entries: Vec::new(),
        icon_png_cache: HashMap::new(),
        lang,
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let _handle = spawn_tray(state, tx, egui::Context::default());

    while let Ok(cmd) = rx.recv() {
        match cmd {
            TrayCommand::ShowWindow => {
                if let Some(path) = pid_file() {
                    let _ = std::fs::remove_file(path);
                }
                spawn_detached(&[]);
                return;
            }
            TrayCommand::Quit => break,
            _ => {}
        }
    }
    if let Some(path) = pid_file() {
        let _ = std::fs::remove_file(path);
    }
}
