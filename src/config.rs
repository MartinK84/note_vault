use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Expands environment variables in `s` (both `%VAR%` on Windows and `$VAR`/`${VAR}` on
/// Unix-style syntax) and then resolves the result to an absolute path by joining it onto the
/// current working directory when it is relative.
pub fn expand_path(s: &str) -> PathBuf {
    // --- 1. Expand %VAR% placeholders (Windows style) ---
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Collect until the closing '%'
            let mut var_name = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '%' {
                    closed = true;
                    break;
                }
                var_name.push(inner);
            }
            if closed && !var_name.is_empty() {
                // Look up the env var; fall back to the original token if not set
                match std::env::var(&var_name) {
                    Ok(val) => result.push_str(&val),
                    Err(_) => {
                        result.push('%');
                        result.push_str(&var_name);
                        result.push('%');
                    }
                }
            } else {
                // Unmatched '%' – keep verbatim
                result.push('%');
                result.push_str(&var_name);
            }
        } else if ch == '$' {
            // --- 2. Expand $VAR and ${VAR} placeholders (Unix style) ---
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next(); // consume '{'
            }
            let mut var_name = String::new();
            if braced {
                for inner in chars.by_ref() {
                    if inner == '}' {
                        break;
                    }
                    var_name.push(inner);
                }
            } else {
                // Unbraced: collect alphanumerics and '_'
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        var_name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            if !var_name.is_empty() {
                match std::env::var(&var_name) {
                    Ok(val) => result.push_str(&val),
                    Err(_) => {
                        if braced {
                            result.push_str("${");
                            result.push_str(&var_name);
                            result.push('}');
                        } else {
                            result.push('$');
                            result.push_str(&var_name);
                        }
                    }
                }
            } else {
                result.push('$');
            }
        } else {
            result.push(ch);
        }
    }

    // --- 3. Resolve relative paths against CWD ---
    let p = PathBuf::from(&result);
    if p.is_absolute() {
        p
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(p)
    }
}

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

fn default_editor_markdown_mode() -> bool {
    false
}

fn default_folder_pane_width() -> u32 {
    210
}

fn default_notes_pane_width() -> u32 {
    300
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

    #[serde(default = "default_editor_markdown_mode")]
    pub editor_markdown_mode: bool,

    #[serde(default)]
    pub launch_at_startup: bool,

    #[serde(default = "default_folder_pane_width")]
    pub folder_pane_width: u32,

    #[serde(default = "default_notes_pane_width")]
    pub notes_pane_width: u32,
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
            editor_markdown_mode: default_editor_markdown_mode(),
            launch_at_startup: false,
            folder_pane_width: default_folder_pane_width(),
            notes_pane_width: default_notes_pane_width(),
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

    /// Returns the vault path with environment variables expanded and relative paths resolved
    /// to absolute paths based on the current working directory.
    pub fn resolved_vault_path(&self) -> PathBuf {
        expand_path(&self.vault_path)
    }

    /// Returns the keyfile path (if set) with environment variables expanded and relative paths
    /// resolved to absolute paths based on the current working directory.
    pub fn resolved_keyfile_path(&self) -> Option<PathBuf> {
        self.keyfile_path.as_deref().map(expand_path)
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
        assert!(!config.editor_markdown_mode);
        assert!(!config.launch_at_startup);
        assert_eq!(config.folder_pane_width, 210);
        assert_eq!(config.notes_pane_width, 300);
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
            editor_markdown_mode: true,
            launch_at_startup: true,
            folder_pane_width: 250,
            notes_pane_width: 350,
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
        assert!(!loaded.editor_markdown_mode);
        assert!(!loaded.launch_at_startup);
        assert_eq!(loaded.folder_pane_width, 210);
        assert_eq!(loaded.notes_pane_width, 300);

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

    #[test]
    fn test_expand_path_absolute_unchanged() {
        // An already-absolute path should come back unchanged (modulo platform separators).
        let abs = if cfg!(windows) { "C:\\Users\\test\\vault" } else { "/home/test/vault" };
        let result = expand_path(abs);
        assert!(result.is_absolute(), "Expected absolute path, got: {:?}", result);
        assert_eq!(result, PathBuf::from(abs));
    }

    #[test]
    fn test_expand_path_relative_becomes_absolute() {
        let result = expand_path("vault");
        assert!(result.is_absolute(), "Relative path should be made absolute, got: {:?}", result);
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(result, cwd.join("vault"));
    }

    #[test]
    fn test_expand_path_percent_var() {
        // Set a known env var and confirm %VAR% is expanded.
        unsafe { std::env::set_var("NV_TEST_VAR", "expanded_value"); }
        let result = expand_path("%NV_TEST_VAR%\\subdir");
        unsafe { std::env::remove_var("NV_TEST_VAR"); }
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("expanded_value"),
            "Expected expansion of %NV_TEST_VAR%, got: {}",
            result_str
        );
    }

    #[test]
    fn test_expand_path_dollar_var() {
        unsafe { std::env::set_var("NV_TEST_VAR2", "dollar_expanded"); }
        let result = expand_path("$NV_TEST_VAR2/subdir");
        unsafe { std::env::remove_var("NV_TEST_VAR2"); }
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("dollar_expanded"),
            "Expected expansion of $NV_TEST_VAR2, got: {}",
            result_str
        );
    }

    #[test]
    fn test_expand_path_dollar_braced_var() {
        unsafe { std::env::set_var("NV_TEST_VAR3", "braced_expanded"); }
        let result = expand_path("${NV_TEST_VAR3}/subdir");
        unsafe { std::env::remove_var("NV_TEST_VAR3"); }
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("braced_expanded"),
            "Expected expansion of ${{NV_TEST_VAR3}}, got: {}",
            result_str
        );
    }

    #[test]
    fn test_expand_path_unknown_var_kept_verbatim() {
        // An unknown %VAR% should be left as-is in the output.
        let result = expand_path("%DEFINITELY_NOT_SET_NV_VAR%\\subdir");
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("DEFINITELY_NOT_SET_NV_VAR"),
            "Unknown var should be kept verbatim, got: {}",
            result_str
        );
    }

    #[test]
    fn test_resolved_vault_path_relative() {
        let config = AppConfig {
            vault_path: "vault".to_string(),
            ..AppConfig::default()
        };
        let resolved = config.resolved_vault_path();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("vault"));
    }

    #[test]
    fn test_resolved_keyfile_path_none() {
        let config = AppConfig::default();
        assert_eq!(config.resolved_keyfile_path(), None);
    }
}
