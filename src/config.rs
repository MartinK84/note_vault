use std::error::Error;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

fn default_multithreading() -> bool {
    true
}

fn default_theme() -> String {
    "dark".to_string()
}

fn default_global_hotkey() -> String {
    "Shift+Space".to_string()
}

fn default_minimize_to_tray() -> bool {
    true
}

fn default_editor_show_line_numbers() -> bool {
    false
}

fn default_editor_line_wrap() -> bool {
    true
}

fn default_editor_highlight_current_line() -> bool {
    true
}

fn default_editor_font_size() -> u32 {
    14
}

/// Persistent configuration for NoteVault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub vault_path: String,

    #[serde(default)]
    pub keyfile_path: Option<String>,

    #[serde(default = "default_multithreading")]
    pub use_multithreading: bool,

    #[serde(default = "default_theme")]
    pub theme: String,

    #[serde(default = "default_global_hotkey")]
    pub global_hotkey: String,

    #[serde(default = "default_minimize_to_tray")]
    pub minimize_to_tray: bool,

    #[serde(default = "default_editor_show_line_numbers")]
    pub editor_show_line_numbers: bool,

    #[serde(default = "default_editor_line_wrap")]
    pub editor_line_wrap: bool,

    #[serde(default = "default_editor_highlight_current_line")]
    pub editor_highlight_current_line: bool,

    #[serde(default = "default_editor_font_size")]
    pub editor_font_size: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            vault_path: String::new(),
            keyfile_path: None,
            use_multithreading: true,
            theme: default_theme(),
            global_hotkey: default_global_hotkey(),
            minimize_to_tray: default_minimize_to_tray(),
            editor_show_line_numbers: default_editor_show_line_numbers(),
            editor_line_wrap: default_editor_line_wrap(),
            editor_highlight_current_line: default_editor_highlight_current_line(),
            editor_font_size: default_editor_font_size(),
        }
    }
}

impl AppConfig {
    pub const CONFIG_FILE: &'static str = "config.json";

    /// Loads the configuration from `config.json` in the current working directory.
    /// If the file does not exist or fails to parse, returns `AppConfig::default()`.
    pub fn load() -> Self {
        Self::load_from_path(Path::new(Self::CONFIG_FILE))
    }

    /// Loads configuration from a specific path.
    pub fn load_from_path(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str::<AppConfig>(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Saves the current configuration to `config.json` in the current working directory.
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        self.save_to_path(Path::new(Self::CONFIG_FILE))
    }

    /// Saves configuration to a specific path.
    pub fn save_to_path(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let json_data = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, json_data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.vault_path, "");
        assert_eq!(config.keyfile_path, None);
        assert!(config.use_multithreading);
        assert_eq!(config.theme, "dark");
        assert_eq!(config.global_hotkey, "Shift+Space");
        assert!(config.minimize_to_tray);
        assert!(!config.editor_show_line_numbers);
        assert!(config.editor_line_wrap);
        assert!(config.editor_highlight_current_line);
        assert_eq!(config.editor_font_size, 14);
    }

    #[test]
    fn test_config_save_and_load() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_config_{}", Uuid::new_v4()));
        let config_path = temp_dir.join("test_config.json");

        let config = AppConfig {
            vault_path: "D:/MyVault".to_string(),
            keyfile_path: Some("D:/MyVault/secret.key".to_string()),
            use_multithreading: false,
            theme: "light".to_string(),
            global_hotkey: "Control+Shift+N".to_string(),
            minimize_to_tray: false,
            editor_show_line_numbers: true,
            editor_line_wrap: false,
            editor_highlight_current_line: false,
            editor_font_size: 18,
        };

        config.save_to_path(&config_path).expect("Saving config should succeed");
        assert!(config_path.exists());

        let loaded = AppConfig::load_from_path(&config_path);
        assert_eq!(loaded, config);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_missing_fields_fallback_to_defaults() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_config_{}", Uuid::new_v4()));
        let config_path = temp_dir.join("partial_config.json");

        let partial_json = r#"{"vault_path": "D:/SomePath"}"#;
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(&config_path, partial_json).unwrap();

        let loaded = AppConfig::load_from_path(&config_path);
        assert_eq!(loaded.vault_path, "D:/SomePath");
        assert!(loaded.use_multithreading);
        assert_eq!(loaded.theme, "dark");
        assert_eq!(loaded.global_hotkey, "Shift+Space");
        assert!(loaded.minimize_to_tray);
        assert!(!loaded.editor_show_line_numbers);
        assert!(loaded.editor_line_wrap);
        assert!(loaded.editor_highlight_current_line);
        assert_eq!(loaded.editor_font_size, 14);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_theme_options_persistence() {
        for theme_name in &["dark", "blue", "light"] {
            let temp_dir = std::env::temp_dir().join(format!("note_vault_config_{}", Uuid::new_v4()));
            let config_path = temp_dir.join("theme_config.json");

            let mut config = AppConfig::default();
            config.theme = theme_name.to_string();

            config.save_to_path(&config_path).expect("Saving config should succeed");
            let loaded = AppConfig::load_from_path(&config_path);
            assert_eq!(loaded.theme, *theme_name);

            let _ = fs::remove_dir_all(&temp_dir);
        }
    }
}
