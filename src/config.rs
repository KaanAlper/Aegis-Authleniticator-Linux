use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SortMode {
    #[default]
    Default,
    IssuerAsc,
    IssuerDesc,
    NameAsc,
    NameDesc,
    FavoritesFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub last_vault_path: Option<PathBuf>,
    #[serde(default = "default_dark_mode")]
    pub dark_mode: bool,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub sort_mode: SortMode,
    #[serde(default = "default_show_icons")]
    pub show_icons: bool,
    #[serde(default)]
    pub password_hint: String,
    #[serde(default)]
    pub auto_lock_mins: u64,
    #[serde(default)]
    pub auto_backup_enabled: bool,
    #[serde(default)]
    pub backup_dir: Option<PathBuf>,
    #[serde(default = "default_backup_days")]
    pub backup_interval_days: u32,
    #[serde(default)]
    pub last_backup_epoch: u64,
    /// Keep the app running in the tray when the window is closed (default: quit).
    #[serde(default)]
    pub close_to_tray: bool,
    /// Entry card scale (Ctrl + scroll).
    #[serde(default = "default_card_scale")]
    pub card_scale: f32,
}

fn default_card_scale() -> f32 {
    1.0
}

fn default_dark_mode() -> bool {
    true
}

fn default_show_icons() -> bool {
    true
}

fn default_backup_days() -> u32 {
    7
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            last_vault_path: None,
            dark_mode: true,
            language: None,
            sort_mode: SortMode::Default,
            show_icons: true,
            password_hint: String::new(),
            auto_lock_mins: 0,
            auto_backup_enabled: true,
            backup_dir: dirs::data_local_dir().map(|d| d.join("aegis-linux").join("backups")),
            backup_interval_days: 7,
            last_backup_epoch: 0,
            close_to_tray: false,
            card_scale: 1.0,
        }
    }
}

/// Directory where the app keeps its own copies of imported vaults.
pub fn managed_vault_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("aegis-linux").join("vaults"))
}

/// Copies an imported vault file into the app's private storage (owner-only permissions)
/// and returns the path of the internal copy. The original file is left untouched.
/// If the file already lives in the managed directory it is returned as-is.
pub fn adopt_vault_file(src: &std::path::Path) -> Result<PathBuf, String> {
    let dir = managed_vault_dir().ok_or("No data directory available")?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    if let (Ok(a), Ok(b)) = (src.canonicalize(), dir.canonicalize()) {
        if a.starts_with(&b) {
            return Ok(a);
        }
    }
    let stem = src
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault".into());
    let mut dest = dir.join(format!("{stem}.json"));
    let mut n = 1;
    while dest.exists() {
        // Never overwrite an existing internal vault
        if fs::read(&dest).ok() == fs::read(src).ok() {
            return Ok(dest);
        }
        dest = dir.join(format!("{stem}-{n}.json"));
        n += 1;
    }
    fs::copy(src, &dest).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o600));
        if let Some(parent) = dest.parent() {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dest)
}

impl AppConfig {
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aegis-linux").join("config.json"))
    }

    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        let Ok(raw) = fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self) {
        let Some(path) = Self::config_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}
