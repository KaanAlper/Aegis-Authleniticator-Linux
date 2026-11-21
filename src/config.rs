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
            auto_backup_enabled: false,
            backup_dir: dirs::data_local_dir().map(|d| d.join("aegis-linux").join("backups")),
            backup_interval_days: 7,
            last_backup_epoch: 0,
        }
    }
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
