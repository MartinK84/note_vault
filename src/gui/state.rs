use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::Parser;
use global_hotkey::hotkey::HotKey;
use global_hotkey::GlobalHotKeyManager;
use note_vault::config::AppConfig;
use note_vault::NoteType;
use zeroize::Zeroizing;

/// Command line arguments for the NoteVault GUI application.
#[derive(Parser, Debug)]
#[command(
    name = "note_vault_gui",
    version,
    about = "Secure Encrypted NoteVault GUI",
    long_about = "NoteVault securely encrypts and decrypts notes using Argon2id, AES-256-GCM + XChaCha20-Poly1305 cryptographic cascade, and Zeroize."
)]
pub struct Args {
    /// Path to the encrypted vault directory (optional, temporarily overrides config.json)
    #[arg(short, long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,

    /// Launch the application minimized to system tray (used for system startup)
    #[arg(long)]
    pub minimized: bool,

    /// Launch initiated by system auto-start
    #[arg(long)]
    pub autostart: bool,

    /// Set explicit working directory
    #[arg(short = 'w', long, value_name = "DIR")]
    pub working_dir: Option<PathBuf>,
}

/// Metadata extracted from a decrypted note, stored without plaintext content.
#[derive(Debug, Clone)]
pub struct NoteMetaSummary {
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
    pub updated_at: i64,
    pub file_path: PathBuf,
    pub note_type: NoteType,
}

/// Maximum number of canvas undo steps retained in memory.
pub const MAX_CANVAS_UNDO_STEPS: usize = 30;

/// Active in-memory state for canvas / drawing notes.
pub struct ActiveCanvasState {
    pub pixmap: Option<tiny_skia::Pixmap>,
    pub pixel_buffer: Option<slint::SharedPixelBuffer<slint::Rgba8Pixel>>,
    pub undo_stack: Vec<tiny_skia::Pixmap>,
    pub redo_stack: Vec<tiny_skia::Pixmap>,
    pub last_point: Option<(f32, f32)>,
    pub tool: String, // "pen" or "eraser"
    pub color: tiny_skia::Color,
    pub stroke_width: f32,
    pub line_style: String, // "solid", "dashed", "dotted"
    pub dash_offset: f32,
}

impl Default for ActiveCanvasState {
    fn default() -> Self {
        Self {
            pixmap: None,
            pixel_buffer: None,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            last_point: None,
            tool: "pen".to_string(),
            color: tiny_skia::Color::from_rgba8(30, 30, 30, 255),
            stroke_width: 3.0,
            line_style: "solid".to_string(),
            dash_offset: 0.0,
        }
    }
}

/// Shared GUI application state passed across callback handlers and background workers.
#[derive(Clone)]
pub struct AppState {
    pub app_config: Arc<Mutex<AppConfig>>,
    pub vault_path: Arc<Mutex<PathBuf>>,
    pub use_multithreading: Arc<AtomicBool>,
    pub session_password: Arc<Mutex<Option<Zeroizing<String>>>>,
    pub session_keyfile: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    pub metadata_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    pub active_folder: Arc<Mutex<String>>,
    pub search_query: Arc<Mutex<String>>,
    pub canvas_state: Arc<Mutex<ActiveCanvasState>>,
    pub is_quick_search_open: Arc<AtomicBool>,
    pub is_unlock_window_open: Arc<AtomicBool>,
    pub quick_search_shown_at: Arc<Mutex<Instant>>,
    pub hotkey_manager: Arc<Mutex<Option<GlobalHotKeyManager>>>,
    pub active_hotkey: Arc<Mutex<Option<HotKey>>>,
    pub active_main_hotkey: Arc<Mutex<Option<HotKey>>>,
    pub last_activity: Arc<Mutex<Instant>>,
    pub clipboard_clear: Arc<Mutex<Option<(Instant, Zeroizing<String>)>>>,
}

impl AppState {
    /// Creates a new `AppState` initialized from `config` and resolved `initial_vault_path`.
    pub fn new(
        config: AppConfig,
        initial_vault_path: PathBuf,
        initial_hotkey: Option<HotKey>,
        initial_main_hotkey: Option<HotKey>,
    ) -> Self {
        let multi = config.use_multithreading;
        Self {
            app_config: Arc::new(Mutex::new(config)),
            vault_path: Arc::new(Mutex::new(initial_vault_path)),
            use_multithreading: Arc::new(AtomicBool::new(multi)),
            session_password: Arc::new(Mutex::new(None)),
            session_keyfile: Arc::new(Mutex::new(None)),
            metadata_store: Arc::new(Mutex::new(HashMap::new())),
            active_folder: Arc::new(Mutex::new("*All Notes*".to_string())),
            search_query: Arc::new(Mutex::new(String::new())),
            canvas_state: Arc::new(Mutex::new(ActiveCanvasState::default())),
            is_quick_search_open: Arc::new(AtomicBool::new(false)),
            is_unlock_window_open: Arc::new(AtomicBool::new(false)),
            quick_search_shown_at: Arc::new(Mutex::new(Instant::now())),
            hotkey_manager: Arc::new(Mutex::new(GlobalHotKeyManager::new().ok())),
            active_hotkey: Arc::new(Mutex::new(initial_hotkey)),
            active_main_hotkey: Arc::new(Mutex::new(initial_main_hotkey)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            clipboard_clear: Arc::new(Mutex::new(None)),
        }
    }

    /// Records user activity for fallback idle-timeout tracking.
    pub fn touch_activity(&self) {
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
    }

    /// Schedules sensitive copied text for automatic clipboard clearing if configured.
    pub fn schedule_clipboard_clear(&self, text: &str) {
        let clear_secs = self.app_config.lock().unwrap().clipboard_clear_seconds;
        if clear_secs > 0 && !text.is_empty() {
            *self.clipboard_clear.lock().unwrap() =
                Some((Instant::now(), Zeroizing::new(text.to_string())));
        }
    }
}

/// Converts a UI auto-lock label (e.g. `"15 min"`) into minutes (`0` = disabled).
pub fn auto_lock_label_to_minutes(label: &str) -> u32 {
    match label.trim() {
        "5 min" => 5,
        "10 min" => 10,
        "15 min" => 15,
        "30 min" => 30,
        "60 min" => 60,
        _ => 0,
    }
}

/// Converts configured auto-lock minutes into the corresponding Settings ComboBox label.
pub fn minutes_to_auto_lock_label(minutes: u32) -> &'static str {
    match minutes {
        5 => "5 min",
        10 => "10 min",
        15 => "15 min",
        30 => "30 min",
        60 => "60 min",
        _ => "Disabled",
    }
}

/// Converts a UI clipboard-clear label (e.g. `"30 sec"`) into seconds (`0` = disabled).
pub fn clipboard_clear_label_to_seconds(label: &str) -> u32 {
    match label.trim() {
        "15 sec" => 15,
        "30 sec" => 30,
        "60 sec" => 60,
        "120 sec" => 120,
        _ => 0,
    }
}

/// Converts configured clipboard-clear seconds into the corresponding Settings ComboBox label.
pub fn seconds_to_clipboard_clear_label(seconds: u32) -> &'static str {
    match seconds {
        15 => "15 sec",
        30 => "30 sec",
        60 => "60 sec",
        120 => "120 sec",
        _ => "Disabled",
    }
}
