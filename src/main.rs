#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use arboard::Clipboard;
use clap::Parser;
use global_hotkey::hotkey::HotKey;
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use note_vault::config::AppConfig;
use note_vault::{
    format_decrypted_json_export, format_decrypted_txt_export, format_line_numbers,
    format_markdown_export, format_unix_date, format_unix_timestamp, load_note_decrypted,
    parse_markdown_into_blocks, render_markdown_styled, sanitize_filename, save_note_encrypted,
    validate_folder_name, Note, MainWindow, NoteMetadata, QuickSearchResult, QuickSearchWindow,
    QuickViewerWindow, TagSuggestion, Theme, UnlockWindow,
};
use rayon::prelude::*;
use slint::{ComponentHandle, Model};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

/// Command line arguments for the NoteVault GUI application.
#[derive(Parser, Debug)]
#[command(
    name = "note_vault_gui",
    version,
    about = "Secure Encrypted NoteVault GUI",
    long_about = "NoteVault securely encrypts and decrypts notes using Argon2id and XChaCha20-Poly1305."
)]
struct Args {
    /// Path to the encrypted vault directory (optional, temporarily overrides config.json)
    #[arg(short, long, value_name = "PATH")]
    vault_path: Option<PathBuf>,

    /// Launch the application minimized to system tray (used for system startup)
    #[arg(long)]
    minimized: bool,
}

/// Metadata extracted from a decrypted note, stored without plaintext content.
#[derive(Debug, Clone)]
struct NoteMetaSummary {
    title: String,
    category: String,
    tags: Vec<String>,
    date: String,
    updated_at: i64,
    file_path: PathBuf,
}

/// Builds a 32x32 RGBA icon for the system tray using the dark orange logo.svg.
fn create_tray_icon() -> Result<Icon, Box<dyn std::error::Error>> {
    const SVG_STR: &str = include_str!("../assets/icons/logo.svg");
    let width = 32u32;
    let height = 32u32;

    let opt = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_str(SVG_STR, &opt)?;

    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)
        .ok_or_else(|| "Failed to allocate icon pixmap".to_string())?;

    let svg_w = tree.size().width();
    let svg_h = tree.size().height();
    // Render the logo with a clean 2px margin inside 32x32 canvas
    let padding = 2.0f32;
    let draw_w = (width as f32) - 2.0 * padding;
    let draw_h = (height as f32) - 2.0 * padding;
    let scale_x = draw_w / svg_w;
    let scale_y = draw_h / svg_h;
    let scale = scale_x.min(scale_y);
    let offset_x = padding + (draw_w - svg_w * scale) / 2.0;
    let offset_y = padding + (draw_h - svg_h * scale) / 2.0;

    let transform = resvg::tiny_skia::Transform::from_row(scale, 0.0, 0.0, scale, offset_x, offset_y);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // Convert premultiplied RGBA from tiny_skia into straight RGBA for tray_icon
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for chunk in pixmap.data().chunks_exact(4) {
        let r = chunk[0];
        let g = chunk[1];
        let b = chunk[2];
        let a = chunk[3];
        if a == 0 {
            rgba.extend_from_slice(&[0, 0, 0, 0]);
        } else if a == 255 {
            rgba.extend_from_slice(&[r, g, b, 255]);
        } else {
            let r = ((r as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            let g = ((g as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            let b = ((b as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }

    Icon::from_rgba(rgba, width, height).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Filters notes in `metadata_store` by query (matching Title or Tags only),
/// sorts by `updated_at` descending (newest first), and returns a maximum of 5 items.
fn filter_quick_search_results(
    query: &str,
    metadata_store: &HashMap<String, NoteMetaSummary>,
) -> Vec<QuickSearchResult> {
    let q = query.trim().to_lowercase();
    let mut matching_notes: Vec<(&String, &NoteMetaSummary)> = metadata_store
        .iter()
        .filter(|(_id, meta)| {
            if q.is_empty() {
                true
            } else {
                meta.title.to_lowercase().contains(&q)
                    || meta.tags.iter().any(|t| t.to_lowercase().contains(&q))
            }
        })
        .collect();

    // Sort by date (updated_at) descending (newest first)
    matching_notes.sort_by(|a, b| b.1.updated_at.cmp(&a.1.updated_at));

    // Take top 5 results
    matching_notes
        .into_iter()
        .take(5)
        .map(|(id, meta)| QuickSearchResult {
            id: id.clone().into(),
            title: meta.title.clone().into(),
            tags: meta.tags.join(", ").into(),
            category: meta.category.clone().into(),
        })
        .collect()
}

/// Summary representation of a tag suggestion with note occurrence count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TagCount {
    pub name: String,
    pub count: usize,
}

/// Retrieves unique tags across all notes in `metadata_store`, excluding tags
/// already assigned to `current_note_tags` (case-insensitive).
/// Filters by `query` substring (case-insensitive), and sorts by frequency descending,
/// then alphabetically.
fn get_suggested_tags(
    metadata_store: &HashMap<String, NoteMetaSummary>,
    current_note_tags: &[String],
    query: &str,
) -> Vec<TagCount> {
    let current_tags_lower: std::collections::HashSet<String> = current_note_tags
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();

    let mut tag_counts: HashMap<String, (String, usize)> = HashMap::new();

    for meta in metadata_store.values() {
        let mut note_seen = std::collections::HashSet::new();
        for tag in &meta.tags {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if note_seen.insert(lower.clone()) {
                let entry = tag_counts
                    .entry(lower)
                    .or_insert_with(|| (trimmed.to_string(), 0));
                entry.1 += 1;
            }
        }
    }

    let q = query.trim().to_lowercase();
    let mut suggestions: Vec<TagCount> = tag_counts
        .into_iter()
        .filter(|(lower, _)| !current_tags_lower.contains(lower))
        .filter(|(lower, _)| q.is_empty() || lower.contains(&q))
        .map(|(_, (display_name, count))| TagCount {
            name: display_name,
            count,
        })
        .collect();

    suggestions.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    suggestions
}

/// Parses and normalizes a global hotkey string (e.g. "Shift + Space", "ctrl+shift+k", "Alt+Space").
pub fn parse_hotkey_string(s: &str) -> Result<(HotKey, String), String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("Hotkey cannot be empty".to_string());
    }

    // Split on '+' and normalize components
    let parts: Vec<&str> = trimmed.split('+').map(|p| p.trim()).collect();
    if parts.is_empty() {
        return Err("Invalid hotkey format".to_string());
    }

    let mut normalized_parts: Vec<String> = Vec::new();
    for part in parts {
        let p_lower = part.to_lowercase();
        let norm = match p_lower.as_str() {
            "ctrl" | "control" => "Control".to_string(),
            "shift" => "Shift".to_string(),
            "alt" => "Alt".to_string(),
            "super" | "win" | "windows" => "Super".to_string(),
            "cmd" | "command" => "Command".to_string(),
            "cmdorctrl" | "commandorcontrol" => "CmdOrCtrl".to_string(),
            "space" => "Space".to_string(),
            "enter" | "return" => "Return".to_string(),
            "esc" | "escape" => "Escape".to_string(),
            "tab" => "Tab".to_string(),
            "backspace" => "Backspace".to_string(),
            _ => {
                if part.len() == 1 {
                    part.to_ascii_uppercase()
                } else {
                    let mut c = part.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                }
            }
        };
        normalized_parts.push(norm);
    }

    let normalized_str = normalized_parts.join("+");
    match normalized_str.parse::<HotKey>() {
        Ok(hk) => Ok((hk, normalized_str)),
        Err(e) => {
            match trimmed.parse::<HotKey>() {
                Ok(hk) => Ok((hk, trimmed.to_string())),
                Err(_) => Err(format!("Could not parse hotkey '{}': {}", trimmed, e)),
            }
        }
    }
}

/// Retrieves primary screen dimensions (width, height) in physical pixels.
#[cfg(target_os = "windows")]
fn get_primary_screen_size() -> (f32, f32) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetSystemMetrics(nIndex: i32) -> i32;
    }
    unsafe {
        let w = GetSystemMetrics(0); // SM_CXSCREEN
        let h = GetSystemMetrics(1); // SM_CYSCREEN
        if w > 0 && h > 0 {
            (w as f32, h as f32)
        } else {
            (1920.0, 1080.0)
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_primary_screen_size() -> (f32, f32) {
    (1920.0, 1080.0)
}

/// Checks if the QuickSearchWindow currently has the foreground focus.
#[cfg(target_os = "windows")]
fn is_quick_search_active() -> bool {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetForegroundWindow() -> isize;
        fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
    }
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd == 0 {
            return false;
        }
        let mut buf = [0u16; 256];
        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 256);
        if len > 0 {
            let title = String::from_utf16_lossy(&buf[..len as usize]);
            title.contains("NoteVault Quick Search")
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn is_quick_search_active() -> bool {
    true
}

/// Activates and focuses the QuickSearchWindow on Windows.
#[cfg(target_os = "windows")]
fn activate_quick_search_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn SetForegroundWindow(hWnd: isize) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
    }
    unsafe {
        let title_wide: Vec<u16> = "NoteVault Quick Search"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd != 0 {
            ShowWindow(hwnd, 5); // SW_SHOW
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn activate_quick_search_window() {}

#[cfg(target_os = "windows")]
static MAIN_WINDOW_HWND: AtomicIsize = AtomicIsize::new(0);

#[cfg(target_os = "windows")]
static MAIN_WINDOW_HIDDEN_TO_TRAY: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
#[repr(C)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
const CLSID_TASKBAR_LIST: GUID = GUID {
    data1: 0x56FDF344,
    data2: 0xFD6D,
    data3: 0x11D0,
    data4: [0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90],
};

#[cfg(target_os = "windows")]
const IID_ITASKBAR_LIST: GUID = GUID {
    data1: 0x56FDF342,
    data2: 0xFD6D,
    data3: 0x11D0,
    data4: [0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90],
};

#[cfg(target_os = "windows")]
#[repr(C)]
struct ITaskbarListVtbl {
    query_interface: unsafe extern "system" fn(this: *mut ITaskbarList, riid: *const GUID, ppv: *mut *mut std::ffi::c_void) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut ITaskbarList) -> u32,
    release: unsafe extern "system" fn(this: *mut ITaskbarList) -> u32,
    hr_init: unsafe extern "system" fn(this: *mut ITaskbarList) -> i32,
    add_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    delete_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    activate_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    set_active_alt: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ITaskbarList {
    vtbl: *const ITaskbarListVtbl,
}

#[cfg(target_os = "windows")]
fn taskbar_delete_tab(hwnd: isize) {
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(pvReserved: *mut std::ffi::c_void, dwCoInit: u32) -> i32;
        fn CoCreateInstance(
            rclsid: *const GUID,
            pUnkOuter: *mut std::ffi::c_void,
            dwClsContext: u32,
            riid: *const GUID,
            ppv: *mut *mut std::ffi::c_void,
        ) -> i32;
    }
    unsafe {
        let _ = CoInitializeEx(std::ptr::null_mut(), 0);
        let mut obj: *mut std::ffi::c_void = std::ptr::null_mut();
        if CoCreateInstance(
            &CLSID_TASKBAR_LIST,
            std::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ITASKBAR_LIST,
            &mut obj,
        ) == 0 && !obj.is_null() {
            let taskbar = obj as *mut ITaskbarList;
            let vtbl = &*(*taskbar).vtbl;
            let _ = (vtbl.hr_init)(taskbar);
            let _ = (vtbl.delete_tab)(taskbar, hwnd);
            let _ = (vtbl.release)(taskbar);
        }
    }
}

#[cfg(target_os = "windows")]
fn taskbar_add_tab(hwnd: isize) {
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(pvReserved: *mut std::ffi::c_void, dwCoInit: u32) -> i32;
        fn CoCreateInstance(
            rclsid: *const GUID,
            pUnkOuter: *mut std::ffi::c_void,
            dwClsContext: u32,
            riid: *const GUID,
            ppv: *mut *mut std::ffi::c_void,
        ) -> i32;
    }
    unsafe {
        let _ = CoInitializeEx(std::ptr::null_mut(), 0);
        let mut obj: *mut std::ffi::c_void = std::ptr::null_mut();
        if CoCreateInstance(
            &CLSID_TASKBAR_LIST,
            std::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ITASKBAR_LIST,
            &mut obj,
        ) == 0 && !obj.is_null() {
            let taskbar = obj as *mut ITaskbarList;
            let vtbl = &*(*taskbar).vtbl;
            let _ = (vtbl.hr_init)(taskbar);
            let _ = (vtbl.add_tab)(taskbar, hwnd);
            let _ = (vtbl.release)(taskbar);
        }
    }
}

#[cfg(target_os = "windows")]
fn get_main_window_hwnd() -> isize {
    let cached = MAIN_WINDOW_HWND.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn EnumWindows(lpEnumFunc: unsafe extern "system" fn(isize, isize) -> i32, lParam: isize) -> i32;
        fn GetWindowThreadProcessId(hWnd: isize, lpdwProcessId: *mut u32) -> u32;
        fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
    }
    unsafe {
        let title_wide: Vec<u16> = "NoteVault - Secure Encrypted Notes"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd == 0 {
            unsafe extern "system" fn enum_proc(wnd: isize, lparam: isize) -> i32 {
                let mut pid = 0u32;
                unsafe {
                    GetWindowThreadProcessId(wnd, &mut pid);
                    if pid == std::process::id() {
                        let mut title_buf = [0u16; 256];
                        let len = GetWindowTextW(wnd, title_buf.as_mut_ptr(), 256);
                        let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                        if title.contains("NoteVault - Secure Encrypted Notes") {
                            *(lparam as *mut isize) = wnd;
                            return 0;
                        }
                    }
                }
                1
            }
            let mut found_hwnd: isize = 0;
            EnumWindows(enum_proc, &mut found_hwnd as *mut isize as isize);
            hwnd = found_hwnd;
        }
        if hwnd != 0 {
            MAIN_WINDOW_HWND.store(hwnd, Ordering::Relaxed);
        }
        hwnd
    }
}

/// Hides the main window completely from desktop and taskbar on Windows.
#[cfg(target_os = "windows")]
fn hide_main_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
    }
    unsafe {
        let hwnd = get_main_window_hwnd();
        if hwnd != 0 {
            const GWL_EXSTYLE: i32 = -20;
            const WS_EX_TOOLWINDOW: isize = 0x00000080;
            const WS_EX_APPWINDOW: isize = 0x00040000;
            let cur = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (cur & !WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW);
            taskbar_delete_tab(hwnd);
            ShowWindow(hwnd, 0); // 0 = SW_HIDE removes window completely from screen and taskbar
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn hide_main_window() {}

/// Restores and focuses the main NoteVault application window on Windows.
#[cfg(target_os = "windows")]
fn restore_main_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SetForegroundWindow(hWnd: isize) -> i32;
        fn BringWindowToTop(hWnd: isize) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
    }
    unsafe {
        let hwnd = get_main_window_hwnd();
        if hwnd != 0 {
            const GWL_EXSTYLE: i32 = -20;
            const WS_EX_TOOLWINDOW: isize = 0x00000080;
            const WS_EX_APPWINDOW: isize = 0x00040000;
            let cur = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (cur & !WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW);
            ShowWindow(hwnd, 9); // 9 = SW_RESTORE restores size, displays on screen and taskbar
            taskbar_add_tab(hwnd);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn restore_main_window() {}

/// Activates and brings the QuickViewerWindow to the foreground on Windows.
#[cfg(target_os = "windows")]
fn activate_quick_viewer_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn SetForegroundWindow(hWnd: isize) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
    }
    unsafe {
        let title_wide: Vec<u16> = "NoteVault Quick Viewer"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd != 0 {
            ShowWindow(hwnd, 5); // SW_SHOW
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn activate_quick_viewer_window() {}

/// Activates and brings the UnlockWindow to the foreground on Windows.
#[cfg(target_os = "windows")]
fn activate_unlock_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn SetForegroundWindow(hWnd: isize) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
    }
    unsafe {
        let title_wide: Vec<u16> = "NoteVault - Unlock Vault"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd != 0 {
            ShowWindow(hwnd, 5); // SW_SHOW
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn activate_unlock_window() {}

/// Sizes and centers the UnlockWindow on the primary display according to its content height.
fn center_and_resize_unlock_window(uw: &UnlockWindow) {
    let (screen_w, screen_h) = get_primary_screen_size();
    let scale = uw.window().scale_factor();
    let logical_w = if scale > 0.0 { screen_w / scale } else { screen_w };
    let logical_h = if scale > 0.0 { screen_h / scale } else { screen_h };

    let win_w = 460.0;
    let req_h = uw.get_requested_height();
    let win_h = if req_h > 50.0 { req_h } else { 180.0 };
    let pos_x = (logical_w - win_w) / 2.0;
    let pos_y = (logical_h - win_h) / 2.0;

    uw.window().set_size(slint::LogicalSize::new(win_w, win_h));
    uw.window().set_position(slint::LogicalPosition::new(pos_x, pos_y));
}

/// Formats a pressed key and active modifiers into a normalized hotkey string.
/// Returns Some("Shift+Space"), Some("Control+Shift+N"), etc. if valid; None if incomplete or only modifiers.
pub fn format_key_combination(
    key_text: &str,
    ctrl: bool,
    alt: bool,
    shift: bool,
    meta: bool,
) -> Option<String> {
    if key_text.is_empty() {
        return None;
    }

    // Ignore if only a modifier key was pressed
    let is_modifier_key = key_text.chars().any(|c| {
        c == '\u{0010}' || c == '\u{0011}' || c == '\u{0012}' || c == '\u{0013}' || c == '\u{0014}'
    });
    if is_modifier_key {
        return None;
    }

    // Determine the key name
    let key_name = if key_text == " " || key_text == "\u{0020}" {
        "Space"
    } else if key_text == "\n" || key_text == "\r" {
        "Return"
    } else if key_text == "\t" {
        "Tab"
    } else if key_text == "\u{001b}" {
        "Escape"
    } else if key_text == "\u{0008}" || key_text == "\u{007f}" {
        "Backspace"
    } else if key_text.len() == 1 {
        let c = key_text.chars().next().unwrap();
        if c.is_alphabetic() {
            let s = c.to_ascii_uppercase().to_string();
            return build_combo(ctrl, alt, shift, meta, &s);
        } else {
            return build_combo(ctrl, alt, shift, meta, key_text);
        }
    } else {
        key_text
    };

    build_combo(ctrl, alt, shift, meta, key_name)
}

fn build_combo(ctrl: bool, alt: bool, shift: bool, meta: bool, key_name: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    if ctrl {
        parts.push("Control");
    }
    if alt {
        parts.push("Alt");
    }
    if shift {
        parts.push("Shift");
    }
    if meta {
        parts.push("Super");
    }

    // Require at least one modifier unless it's a function key (F1-F12)
    let is_fkey = key_name.starts_with('F')
        && key_name.len() <= 3
        && key_name[1..].chars().all(|c| c.is_ascii_digit());
    if parts.is_empty() && !is_fkey {
        return None;
    }

    parts.push(key_name);
    let combo = parts.join("+");
    if parse_hotkey_string(&combo).is_ok() {
        Some(combo)
    } else {
        None
    }
}


/// Re-builds and updates the Slint `folders`, `available_categories`, and `current_notes` models
/// for the active 3-pane layout, filtering by `active_folder` and `search_query`.
fn refresh_models(
    ui: &MainWindow,
    vault_path: &Path,
    metadata_store: &Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    active_folder: &Arc<Mutex<String>>,
    search_query: &Arc<Mutex<String>>,
) {
    if !vault_path.exists() {
        return;
    }

    // 1. Scan for flat root directories under vault_path
    let mut folder_set = std::collections::BTreeSet::new();

    for entry in WalkDir::new(vault_path)
        .min_depth(1)
        .max_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_dir() && p != vault_path {
            if let Some(file_name) = p.file_name() {
                let name = file_name.to_string_lossy();
                if !name.is_empty() && !name.starts_with('.') {
                    folder_set.insert(name.to_string());
                }
            }
        }
    }

    // Include categories from in-memory metadata store
    {
        let store = metadata_store.lock().unwrap();
        for meta in store.values() {
            if !meta.category.is_empty() {
                folder_set.insert(meta.category.clone());
            }
        }
    }

    let folders_list: Vec<String> = folder_set.into_iter().collect();

    // 2. Validate and retrieve current active_folder
    let current_active_folder = {
        let mut active = active_folder.lock().unwrap();
        if *active != "*All Notes*"
            && (active.is_empty() || (!folders_list.is_empty() && !folders_list.contains(&*active)))
        {
            *active = folders_list.first().cloned().unwrap_or_else(|| "General".to_string());
        }
        active.clone()
    };

    // 3. Filter notes in metadata_store: note.category == active_folder AND matches search_query
    let store = metadata_store.lock().unwrap();
    let query = search_query.lock().unwrap().trim().to_lowercase();

    let mut filtered_notes: Vec<(String, NoteMetaSummary)> = Vec::new();

    for (id, meta) in store.iter() {
        if current_active_folder != "*All Notes*" && meta.category != current_active_folder {
            continue;
        }

        if !query.is_empty() {
            let matches_title = meta.title.to_lowercase().contains(&query);
            let matches_tags = meta.tags.iter().any(|t| t.to_lowercase().contains(&query));
            if !matches_title && !matches_tags {
                continue;
            }
        }

        filtered_notes.push((id.clone(), meta.clone()));
    }

    filtered_notes.sort_by(|a, b| b.1.updated_at.cmp(&a.1.updated_at));

    let note_models: Vec<NoteMetadata> = filtered_notes
        .into_iter()
        .map(|(id, meta)| NoteMetadata {
            id: id.into(),
            title: if meta.title.is_empty() {
                "Untitled".into()
            } else {
                meta.title.into()
            },
            category: meta.category.into(),
            tags: meta.tags.join(", ").into(),
            date: format_unix_date(meta.updated_at).into(),
        })
        .collect();

    let total_notes = store.len();
    drop(store);

    // 4. Update Slint models
    let folders_slint: Vec<slint::SharedString> = folders_list
        .iter()
        .cloned()
        .map(slint::SharedString::from)
        .collect();

    let folders_model: slint::ModelRc<slint::SharedString> =
        std::rc::Rc::new(slint::VecModel::from(folders_slint.clone())).into();

    let current_notes_model: slint::ModelRc<NoteMetadata> =
        std::rc::Rc::new(slint::VecModel::from(note_models)).into();

    ui.set_folders(folders_model.clone());
    ui.set_available_categories(folders_model);
    ui.set_active_folder(current_active_folder.into());
    ui.set_current_notes(current_notes_model);

    ui.set_vault_status_text(format!("{} note(s)", total_notes).into());
}

/// Loads a decrypted note into the UI editor pane and resets `has_unsaved_changes` to false.
fn load_note_into_ui(
    ui: &MainWindow,
    note_id: &str,
    metadata_store: &Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    session_password: &Arc<Mutex<Option<Zeroizing<String>>>>,
    session_keyfile: &Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
) {
    if note_id.is_empty() {
        return;
    }

    let (meta, password_opt, keyfile_opt) = {
        let store = metadata_store.lock().unwrap();
        let meta = store.get(note_id).cloned();
        let session = session_password.lock().unwrap();
        let keyfile = session_keyfile.lock().unwrap();
        (meta, session.clone(), keyfile.clone())
    };

    if let Some(meta) = meta {
        ui.set_editor_markdown_mode(false);
        ui.set_active_note_id(note_id.into());
        ui.set_note_title(meta.title.clone().into());
        ui.set_note_category(meta.category.clone().into());
        let tags_slint: Vec<slint::SharedString> = meta
            .tags
            .iter()
            .cloned()
            .map(slint::SharedString::from)
            .collect();
        let tags_model: slint::ModelRc<slint::SharedString> =
            std::rc::Rc::new(slint::VecModel::from(tags_slint)).into();
        ui.set_note_tags(tags_model);
        ui.set_note_date(meta.date.clone().into());

        if let Some(password) = password_opt {
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
            match load_note_decrypted(&password, kf_bytes, &meta.file_path) {
                Ok(mut note) => {
                    ui.set_line_numbers_text(format_line_numbers(&note.content).into());
                    let blocks = parse_markdown_into_blocks(&note.content);
                    ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
                    ui.set_note_markdown_rendered(render_markdown_styled(&note.content));
                    ui.set_note_content(note.content.as_str().into());
                    note.zeroize();
                }
                Err(e) => {
                    eprintln!("Error decrypting note at {:?}: {}", meta.file_path, e);
                    ui.set_line_numbers_text("1".into());
                    ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
                    ui.set_note_markdown_rendered(slint::StyledText::default());
                    ui.set_note_content(
                        format!("[Error: Failed to decrypt note: {}]", e).into(),
                    );
                }
            }
        } else {
            eprintln!("Error: Cannot decrypt note, vault session is locked.");
            ui.set_line_numbers_text("1".into());
            ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_markdown_rendered(slint::StyledText::default());
            ui.set_note_content("".into());
        }

        ui.set_has_unsaved_changes(false);
    }
}

/// Reloads and re-decrypts all notes in the vault,
/// respecting `use_multithreading` (parallel with Rayon or sequential).
fn trigger_vault_reload(
    password: Zeroizing<String>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
    window_weak: slint::Weak<MainWindow>,
    vault_dir: Arc<Mutex<PathBuf>>,
    meta_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    session_pass: Arc<Mutex<Option<Zeroizing<String>>>>,
    session_key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    a_folder: Arc<Mutex<String>>,
    s_query: Arc<Mutex<String>>,
    use_multi: Arc<AtomicBool>,
    is_initial_unlock: bool,
    on_complete: Option<Box<dyn FnOnce(bool) + Send + 'static>>,
) {
    let Some(ui) = window_weak.upgrade() else { return };

    ui.set_is_loading(true);
    ui.set_loading_progress(0.0);
    ui.set_loading_status_text("Discovering encrypted notes...".into());
    ui.set_active_note_id("".into());
    ui.set_note_title("".into());
    ui.set_note_content("".into());
    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_note_date("".into());
    ui.set_has_unsaved_changes(false);

    let weak = window_weak.clone();

    thread::spawn(move || {
        let current_vault_path = vault_dir.lock().unwrap().clone();

        let mut vault_files: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(&current_vault_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("vault") {
                vault_files.push(p.to_path_buf());
            }
        }

        let total_files = vault_files.len();

        if total_files == 0 {
            *session_pass.lock().unwrap() = Some(password);
            *session_key.lock().unwrap() = keyfile;
            meta_store.lock().unwrap().clear();

            let weak = weak.clone();
            let v_path = current_vault_path.clone();
            let m_store = Arc::clone(&meta_store);
            let af = Arc::clone(&a_folder);
            let sq = Arc::clone(&s_query);
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_is_loading(false);
                    ui.set_is_locked(false);
                    ui.set_unlock_error_message("".into());
                    refresh_models(&ui, &v_path, &m_store, &af, &sq);
                    ui.set_note_content("".into());
                }
            })
            .ok();
            if let Some(cb) = on_complete {
                cb(true);
            }
            return;
        }

        let completed_count = Arc::new(AtomicUsize::new(0));
        let decrypt_failed = Arc::new(AtomicBool::new(false));
        let kf_bytes = keyfile.as_deref().map(|b| b.as_slice());

        let process_file = |file_path: PathBuf| -> Option<(String, NoteMetaSummary)> {
            if decrypt_failed.load(Ordering::Relaxed) {
                return None;
            }

            let category_name = match file_path
                .parent()
                .and_then(|p| p.strip_prefix(&current_vault_path).ok())
            {
                Some(rel) if !rel.as_os_str().is_empty() => {
                    let rel_clean = rel.to_string_lossy().replace('\\', "/");
                    rel_clean.split('/').next().unwrap_or("General").to_string()
                }
                _ => "General".to_string(),
            };

            let item = match load_note_decrypted(&password, kf_bytes, &file_path) {
                Ok(mut note) => {
                    let note_id = note.id.to_string();
                    let title = if note.title.is_empty() {
                        file_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("Untitled")
                            .to_string()
                    } else {
                        note.title.clone()
                    };
                    let tags = note.tags.clone();
                    let date = format_unix_timestamp(note.updated_at);
                    let updated_at = note.updated_at;

                    let summary = NoteMetaSummary {
                        title,
                        category: category_name,
                        tags,
                        date,
                        updated_at,
                        file_path: file_path.clone(),
                    };

                    note.zeroize();
                    Some((note_id, summary))
                }
                Err(_) => {
                    decrypt_failed.store(true, Ordering::Relaxed);
                    None
                }
            };

            let done = completed_count.fetch_add(1, Ordering::Relaxed) + 1;
            let progress = (done as f32) / (total_files as f32);
            let status_msg = format!("Decrypting note {} of {}...", done, total_files);
            let weak_ui = weak.clone();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_ui.upgrade() {
                    ui.set_loading_progress(progress);
                    ui.set_loading_status_text(status_msg.into());
                }
            })
            .ok();

            item
        };

        let multithreaded = use_multi.load(Ordering::Relaxed);
        let decrypted_items: Vec<(String, NoteMetaSummary)> = if multithreaded {
            vault_files.into_par_iter().filter_map(process_file).collect()
        } else {
            vault_files.into_iter().filter_map(process_file).collect()
        };

        if decrypt_failed.load(Ordering::Relaxed) {
            if is_initial_unlock {
                *session_pass.lock().unwrap() = None;
                *session_key.lock().unwrap() = None;
            }
            let weak_ui = weak.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_ui.upgrade() {
                    ui.set_is_loading(false);
                    if is_initial_unlock {
                        ui.set_unlock_error_message(
                            "Decryption failed: invalid master password, keyfile mismatch, or corrupted note file.".into(),
                        );
                    } else {
                        ui.set_vault_status_text("Error: Decryption failed during refresh.".into());
                    }
                }
            })
            .ok();
            if let Some(cb) = on_complete {
                cb(false);
            }
            return;
        }

        {
            let mut store = meta_store.lock().unwrap();
            store.clear();
            store.extend(decrypted_items);
        }

        *session_pass.lock().unwrap() = Some(password);
        *session_key.lock().unwrap() = keyfile;

        let weak_ui = weak.clone();
        let v_path = current_vault_path;
        let m_store = Arc::clone(&meta_store);
        let af = Arc::clone(&a_folder);
        let sq = Arc::clone(&s_query);
        slint::invoke_from_event_loop(move || {
            let Some(ui) = weak_ui.upgrade() else { return };

            ui.set_loading_progress(1.0);
            ui.set_is_loading(false);
            ui.set_is_locked(false);
            ui.set_unlock_error_message("".into());
            refresh_models(&ui, &v_path, &m_store, &af, &sq);
            ui.set_note_content("".into());
        })
        .ok();
        if let Some(cb) = on_complete {
            cb(true);
        }
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = AppConfig::load();

    // Synchronize startup registration with the current executable path if enabled
    if config.launch_at_startup {
        let _ = note_vault::startup::set_launch_at_startup(true, config.minimize_to_tray);
    }
    let should_start_minimized = args.minimized && config.minimize_to_tray;
    if should_start_minimized {
        #[cfg(target_os = "windows")]
        MAIN_WINDOW_HIDDEN_TO_TRAY.store(true, Ordering::Relaxed);
    }

    // Determine vault path (CLI overrides config temporarily)
    let _is_cli_override = args.vault_path.is_some();
    let initial_vault_path_str = if let Some(ref cli_p) = args.vault_path {
        cli_p.to_string_lossy().to_string()
    } else {
        config.vault_path.clone()
    };

    // Resolve env vars and relative paths; keep the raw string for the UI display
    let initial_vault_path = if args.vault_path.is_some() {
        PathBuf::from(&initial_vault_path_str)
    } else {
        config.resolved_vault_path()
    };
    let initial_vault_path_display = initial_vault_path.to_string_lossy().to_string();

    // Shared state
    let app_config = Arc::new(Mutex::new(config.clone()));
    let vault_path = Arc::new(Mutex::new(initial_vault_path.clone()));
    let use_multithreading = Arc::new(AtomicBool::new(config.use_multithreading));
    let session_password: Arc<Mutex<Option<Zeroizing<String>>>> = Arc::new(Mutex::new(None));
    let session_keyfile: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let metadata_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_folder: Arc<Mutex<String>> = Arc::new(Mutex::new("*All Notes*".to_string()));
    let search_query: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Slint Windows: Main, QuickSearch, QuickViewer, UnlockWindow
    let main_window = MainWindow::new()?;
    main_window.window().set_size(slint::LogicalSize::new(1534.0, 740.0));
    let window_weak = main_window.as_weak();

    let quick_search = QuickSearchWindow::new()?;
    let quick_viewer = QuickViewerWindow::new()?;
    let unlock_window = UnlockWindow::new()?;
    let quick_search_weak = quick_search.as_weak();
    let quick_viewer_weak = quick_viewer.as_weak();
    let unlock_window_weak = unlock_window.as_weak();

    let is_unlock_window_open = Arc::new(AtomicBool::new(false));

    // Initialize Theme
    let theme_name = match config.theme.as_str() {
        "blue" => "blue",
        "light" => "light",
        _ => "dark",
    };
    let is_dark = theme_name != "light";
    main_window.global::<Theme>().set_theme(theme_name.into());
    main_window.global::<Theme>().set_is_dark(is_dark);
    quick_search.global::<Theme>().set_theme(theme_name.into());
    quick_search.global::<Theme>().set_is_dark(is_dark);
    quick_viewer.global::<Theme>().set_theme(theme_name.into());
    quick_viewer.global::<Theme>().set_is_dark(is_dark);
    unlock_window.global::<Theme>().set_theme(theme_name.into());
    unlock_window.global::<Theme>().set_is_dark(is_dark);
    main_window.set_settings_theme(theme_name.into());

    let theme_options_model: slint::ModelRc<slint::SharedString> =
        std::rc::Rc::new(slint::VecModel::from(vec!["dark".into(), "blue".into(), "light".into()])).into();
    main_window.set_theme_options(theme_options_model);

    // Initialize Settings state
    main_window.set_settings_vault_path(initial_vault_path_display.as_str().into());
    main_window.set_settings_use_multithreading(config.use_multithreading);
    main_window.set_settings_global_hotkey(config.global_hotkey.as_str().into());
    main_window.set_settings_minimize_to_tray(config.minimize_to_tray);
    main_window.set_settings_launch_at_startup(config.launch_at_startup);

    // Initialize Note Editor preferences
    main_window.set_editor_show_line_numbers(config.editor_show_line_numbers);
    main_window.set_editor_line_wrap(config.editor_line_wrap);
    main_window.set_editor_highlight_current_line(config.editor_highlight_current_line);
    main_window.set_editor_font_size(config.editor_font_size as i32);
    main_window.set_editor_markdown_mode(false);
    main_window.set_line_numbers_text("1".into());

    // Initialize column widths from config
    main_window.set_folder_pane_width(config.folder_pane_width as f32);
    main_window.set_notes_pane_width(config.notes_pane_width as f32);

    // Check keyfile on startup if configured
    if let Some(kpath) = config.resolved_keyfile_path() {
        if !kpath.exists() {
            main_window.set_unlock_error_message(
                format!("Keyfile missing at {}. Please locate it.", kpath.display()).into(),
            );
            main_window.set_show_keyfile_browse(true);
        }
    }

    // Close requests always quit the application cleanly (even if minimize to tray is enabled)
    main_window.window().on_close_requested({
        let window_weak = window_weak.clone();
        move || {
            if let Some(ui) = window_weak.upgrade() {
                let _ = ui.hide();
            }
            let _ = slint::quit_event_loop();
            std::process::exit(0);
        }
    });

    // Initialize System Tray
    let tray_menu = Menu::new();
    let show_item = MenuItem::new("Show NoteVault", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    let _ = tray_menu.append(&show_item);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&quit_item);

    let show_item_id = show_item.id().clone();
    let quit_item_id = quit_item.id().clone();

    let tray_icon_handle = create_tray_icon().ok().and_then(|icon| {
        TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_menu_on_left_click(false)
            .with_tooltip("NoteVault - Encrypted Notes")
            .with_icon(icon)
            .build()
            .ok()
    });

    let is_quick_search_open = Arc::new(AtomicBool::new(false));
    let quick_search_shown_at = Arc::new(Mutex::new(std::time::Instant::now()));

    let tray_timer = slint::Timer::default();
    let tray_window_weak = window_weak.clone();
    let tray_quick_search_weak = quick_search_weak.clone();
    let timer_is_qs_open = Arc::clone(&is_quick_search_open);
    let timer_qs_shown = Arc::clone(&quick_search_shown_at);
    let timer_app_config = Arc::clone(&app_config);

    tray_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(50),
        move || {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == show_item_id {
                    if let Some(ui) = tray_window_weak.upgrade() {
                        let _ = ui.show();
                        #[cfg(target_os = "windows")]
                        MAIN_WINDOW_HIDDEN_TO_TRAY.store(false, Ordering::Relaxed);
                        restore_main_window();
                    }
                } else if event.id == quit_item_id {
                    let _ = slint::quit_event_loop();
                    std::process::exit(0);
                }
            }
            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => {
                        if let Some(ui) = tray_window_weak.upgrade() {
                            let _ = ui.show();
                            #[cfg(target_os = "windows")]
                            MAIN_WINDOW_HIDDEN_TO_TRAY.store(false, Ordering::Relaxed);
                            restore_main_window();
                        }
                    }
                    _ => {}
                }
            }

            // Check if main window was minimized by user -> Hide completely from taskbar
            #[cfg(target_os = "windows")]
            {
                let minimize = timer_app_config.lock().unwrap().minimize_to_tray;
                if minimize {
                    let is_hidden = MAIN_WINDOW_HIDDEN_TO_TRAY.load(Ordering::Relaxed);
                    if !is_hidden {
                        #[link(name = "user32")]
                        unsafe extern "system" {
                            fn IsIconic(hWnd: isize) -> i32;
                        }
                        let hwnd = get_main_window_hwnd();
                        if hwnd != 0 {
                            unsafe {
                                if IsIconic(hwnd) != 0 {
                                    MAIN_WINDOW_HIDDEN_TO_TRAY.store(true, Ordering::Relaxed);
                                    hide_main_window();
                                    if let Some(ui) = tray_window_weak.upgrade() {
                                        let _ = ui.hide();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check if QuickSearchWindow lost focus -> Auto-close
            if timer_is_qs_open.load(Ordering::SeqCst) {
                let elapsed = timer_qs_shown.lock().unwrap().elapsed();
                if elapsed > std::time::Duration::from_millis(400) {
                    if !is_quick_search_active() {
                        if let Some(qs) = tray_quick_search_weak.upgrade() {
                            let _ = qs.hide();
                            timer_is_qs_open.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
        },
    );

    // Initialize Global Hotkey
    let initial_hotkey = parse_hotkey_string(&config.global_hotkey)
        .or_else(|_| parse_hotkey_string("Shift+Space"))
        .ok()
        .map(|(hk, _)| hk);

    let hotkey_manager = Arc::new(Mutex::new(GlobalHotKeyManager::new().ok()));
    let active_hotkey = Arc::new(Mutex::new(initial_hotkey));

    if let (Some(ref mut mgr), Some(ref hk)) = (
        hotkey_manager.lock().unwrap().as_mut(),
        active_hotkey.lock().unwrap().as_ref(),
    ) {
        if let Err(e) = mgr.register(**hk) {
            eprintln!("Failed to register initial global hotkey: {}", e);
        }
    }

    // Spawn background thread to listen for global hotkey events
    {
        let quick_search_weak = quick_search_weak.clone();
        let unlock_window_weak = unlock_window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let active_hotkey = Arc::clone(&active_hotkey);
        let is_qs_open = Arc::clone(&is_quick_search_open);
        let is_uw_open = Arc::clone(&is_unlock_window_open);
        let shown_at = Arc::clone(&quick_search_shown_at);
        let session_password = Arc::clone(&session_password);
        let app_config = Arc::clone(&app_config);

        thread::spawn(move || {
            let receiver = GlobalHotKeyEvent::receiver();
            while let Ok(event) = receiver.recv() {
                if event.state == HotKeyState::Pressed {
                    let current_hk_id = active_hotkey.lock().unwrap().map(|hk| hk.id());
                    if current_hk_id == Some(event.id) {
                        let is_locked = session_password.lock().unwrap().is_none();
                        if is_locked {
                            let uw_weak = unlock_window_weak.clone();
                            let is_open = Arc::clone(&is_uw_open);
                            let cfg_arc = Arc::clone(&app_config);

                            slint::invoke_from_event_loop(move || {
                                if let Some(uw) = uw_weak.upgrade() {
                                    if is_open.load(Ordering::SeqCst) {
                                        is_open.store(false, Ordering::SeqCst);
                                        uw.invoke_clear_fields();
                                        let _ = uw.hide();
                                    } else {
                                        uw.invoke_clear_fields();
                                        let cfg = cfg_arc.lock().unwrap();
                                        if let Some(kpath) = cfg.resolved_keyfile_path() {
                                            if !kpath.exists() {
                                                uw.set_error_message(
                                                    format!("Keyfile missing at {}. Please locate it.", kpath.display()).into(),
                                                );
                                                uw.set_show_keyfile_browse(true);
                                            } else {
                                                uw.set_show_keyfile_browse(false);
                                            }
                                        } else {
                                            uw.set_show_keyfile_browse(false);
                                        }

                                        center_and_resize_unlock_window(&uw);
                                        is_open.store(true, Ordering::SeqCst);
                                        let _ = uw.show();
                                        uw.invoke_focus_password();
                                        activate_unlock_window();
                                    }
                                }
                            })
                            .ok();
                        } else {
                            let weak = quick_search_weak.clone();
                            let m_store = Arc::clone(&metadata_store);
                            let is_open = Arc::clone(&is_qs_open);
                            let shown_at = Arc::clone(&shown_at);

                            slint::invoke_from_event_loop(move || {
                                if let Some(qs) = weak.upgrade() {
                                    if is_open.load(Ordering::SeqCst) {
                                        is_open.store(false, Ordering::SeqCst);
                                        let _ = qs.hide();
                                    } else {
                                        qs.set_search_text("".into());
                                        let initial_results = {
                                            let store = m_store.lock().unwrap();
                                            filter_quick_search_results("", &store)
                                        };
                                        let model = std::rc::Rc::new(slint::VecModel::from(initial_results));
                                        qs.set_results(model.into());
                                        qs.set_selected_index(0);

                                        // Position in the center of the primary screen
                                        let (screen_w, screen_h) = get_primary_screen_size();
                                        let scale = qs.window().scale_factor();
                                        let logical_w = if scale > 0.0 { screen_w / scale } else { screen_w };
                                        let logical_h = if scale > 0.0 { screen_h / scale } else { screen_h };

                                        let win_w = 650.0;
                                        let win_h = 360.0;
                                        let pos_x = (logical_w - win_w) / 2.0;
                                        let pos_y = (logical_h - win_h) / 2.0;

                                        qs.window().set_size(slint::LogicalSize::new(win_w, win_h));
                                        qs.window().set_position(slint::LogicalPosition::new(pos_x, pos_y));

                                        is_open.store(true, Ordering::SeqCst);
                                        *shown_at.lock().unwrap() = std::time::Instant::now();

                                        let _ = qs.show();
                                        qs.invoke_focus_search();
                                        activate_quick_search_window();
                                    }
                                }
                            })
                            .ok();
                        }
                    }
                }
            }
        });
    }

    // Quick Search: Query Changed
    quick_search.on_search_changed({
        let quick_search_weak = quick_search_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        move |text| {
            let Some(qs) = quick_search_weak.upgrade() else { return };
            if session_password.lock().unwrap().is_none() {
                is_quick_search_open.store(false, Ordering::SeqCst);
                let _ = qs.hide();
                return;
            }
            let results = {
                let store = metadata_store.lock().unwrap();
                filter_quick_search_results(text.as_str(), &store)
            };
            let model = std::rc::Rc::new(slint::VecModel::from(results));
            qs.set_results(model.into());
            qs.set_selected_index(0);
        }
    });

    // Quick Search: Enter key pressed -> Copy decrypted note to clipboard & zeroize
    quick_search.on_action_enter_pressed({
        let quick_search_weak = quick_search_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        move |note_id| {
            let note_id_str = note_id.as_str().to_string();
            let meta_opt = {
                let store = metadata_store.lock().unwrap();
                store.get(&note_id_str).cloned()
            };

            if let Some(meta) = meta_opt {
                let (pwd_opt, kf_opt) = {
                    let s_pwd = session_password.lock().unwrap();
                    let s_kf = session_keyfile.lock().unwrap();
                    (s_pwd.clone(), s_kf.clone())
                };
                if let Some(pwd) = pwd_opt {
                    let kf_bytes = kf_opt.as_deref().map(|b| b.as_slice());
                    match load_note_decrypted(pwd.as_str(), kf_bytes, &meta.file_path) {
                        Ok(mut note) => {
                            if let Ok(mut clipboard) = Clipboard::new() {
                                let _ = clipboard.set_text(&note.content);
                            }
                            note.zeroize();
                            is_quick_search_open.store(false, Ordering::SeqCst);
                            if let Some(qs) = quick_search_weak.upgrade() {
                                let _ = qs.hide();
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to decrypt note for clipboard: {}", e);
                        }
                    }
                } else {
                    is_quick_search_open.store(false, Ordering::SeqCst);
                    if let Some(qs) = quick_search_weak.upgrade() {
                        let _ = qs.hide();
                    }
                }
            }
        }
    });

    // Helper closure for previewing note in QuickViewerWindow & zeroizing buffer
    let handle_preview = {
        let quick_search_weak = quick_search_weak.clone();
        let quick_viewer_weak = quick_viewer_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let is_quick_search_open = Arc::clone(&is_quick_search_open);

        move |note_id: slint::SharedString| {
            let note_id_str = note_id.as_str().to_string();
            let meta_opt = {
                let store = metadata_store.lock().unwrap();
                store.get(&note_id_str).cloned()
            };

            if let Some(meta) = meta_opt {
                let (pwd_opt, kf_opt) = {
                    let s_pwd = session_password.lock().unwrap();
                    let s_kf = session_keyfile.lock().unwrap();
                    (s_pwd.clone(), s_kf.clone())
                };
                if let Some(pwd) = pwd_opt {
                    let kf_bytes = kf_opt.as_deref().map(|b| b.as_slice());
                    match load_note_decrypted(pwd.as_str(), kf_bytes, &meta.file_path) {
                        Ok(mut note) => {
                            if let Some(qv) = quick_viewer_weak.upgrade() {
                                qv.set_note_title(note.title.as_str().into());
                                qv.set_content(note.content.as_str().into());

                                // Center QuickViewerWindow on screen with enlarged dimensions
                                let (screen_w, screen_h) = get_primary_screen_size();
                                let scale = qv.window().scale_factor();
                                let logical_w = if scale > 0.0 { screen_w / scale } else { screen_w };
                                let logical_h = if scale > 0.0 { screen_h / scale } else { screen_h };

                                let win_w = 960.0f32.min(logical_w - 40.0);
                                let win_h = 680.0f32.min(logical_h - 60.0);
                                let pos_x = (logical_w - win_w) / 2.0;
                                let pos_y = (logical_h - win_h) / 2.0;

                                qv.window().set_size(slint::LogicalSize::new(win_w, win_h));
                                qv.window().set_position(slint::LogicalPosition::new(pos_x, pos_y));

                                let _ = qv.show();
                                activate_quick_viewer_window();
                            }
                            note.zeroize();
                            is_quick_search_open.store(false, Ordering::SeqCst);
                            if let Some(qs) = quick_search_weak.upgrade() {
                                let _ = qs.hide();
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to decrypt note for viewer: {}", e);
                        }
                    }
                } else {
                    is_quick_search_open.store(false, Ordering::SeqCst);
                    if let Some(qs) = quick_search_weak.upgrade() {
                        let _ = qs.hide();
                    }
                }
            }
        }
    };

    // Quick Search: Alt key pressed -> Preview note in QuickViewerWindow
    quick_search.on_action_alt_pressed({
        let handle = handle_preview.clone();
        move |note_id| handle(note_id)
    });

    // Quick Search: Space key pressed fallback
    quick_search.on_action_space_pressed({
        let handle = handle_preview;
        move |note_id| handle(note_id)
    });

    // Quick Search & Quick Viewer close handling
    quick_search.on_close_requested({
        let quick_search_weak = quick_search_weak.clone();
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        move || {
            is_quick_search_open.store(false, Ordering::SeqCst);
            if let Some(qs) = quick_search_weak.upgrade() {
                let _ = qs.hide();
            }
        }
    });

    quick_viewer.on_close_requested({
        let quick_viewer_weak = quick_viewer_weak.clone();
        move || {
            if let Some(qv) = quick_viewer_weak.upgrade() {
                qv.invoke_clear_data();
                qv.set_content("".into());
                qv.set_note_title("".into());
                let _ = qv.hide();
            }
        }
    });

    quick_viewer.window().on_close_requested({
        let quick_viewer_weak = quick_viewer_weak.clone();
        move || {
            if let Some(qv) = quick_viewer_weak.upgrade() {
                qv.invoke_clear_data();
                qv.set_content("".into());
                qv.set_note_title("".into());
                let _ = qv.hide();
            }
            slint::CloseRequestResponse::HideWindow
        }
    });

    quick_search.window().on_close_requested({
        let quick_search_weak = quick_search_weak.clone();
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        move || {
            is_quick_search_open.store(false, Ordering::SeqCst);
            if let Some(qs) = quick_search_weak.upgrade() {
                let _ = qs.hide();
            }
            slint::CloseRequestResponse::HideWindow
        }
    });

    // -------------------------------------------------------------
    // UnlockWindow Callbacks (for standalone quick search unlocking)
    // -------------------------------------------------------------
    unlock_window.on_close_requested({
        let unlock_window_weak = unlock_window_weak.clone();
        let is_unlock_window_open = Arc::clone(&is_unlock_window_open);
        move || {
            is_unlock_window_open.store(false, Ordering::SeqCst);
            if let Some(uw) = unlock_window_weak.upgrade() {
                uw.invoke_clear_fields();
                let _ = uw.hide();
            }
        }
    });

    unlock_window.window().on_close_requested({
        let unlock_window_weak = unlock_window_weak.clone();
        let is_unlock_window_open = Arc::clone(&is_unlock_window_open);
        move || {
            is_unlock_window_open.store(false, Ordering::SeqCst);
            if let Some(uw) = unlock_window_weak.upgrade() {
                uw.invoke_clear_fields();
                let _ = uw.hide();
            }
            slint::CloseRequestResponse::HideWindow
        }
    });

    unlock_window.on_browse_keyfile_requested({
        let unlock_window_weak = unlock_window_weak.clone();
        let window_weak = window_weak.clone();
        let app_config = Arc::clone(&app_config);
        move || {
            let picked_file = rfd::FileDialog::new()
                .set_title("Locate Keyfile")
                .pick_file();
            if let Some(path) = picked_file {
                let path_str = path.to_string_lossy().to_string();
                let mut cfg = app_config.lock().unwrap();
                cfg.keyfile_path = Some(path_str.clone());
                let _ = cfg.save();
                if let Some(uw) = unlock_window_weak.upgrade() {
                    uw.set_error_message("".into());
                    uw.set_show_keyfile_browse(false);
                    center_and_resize_unlock_window(&uw);
                }
                if let Some(ui) = window_weak.upgrade() {
                    ui.set_unlock_error_message("".into());
                    ui.set_show_keyfile_browse(false);
                    ui.set_vault_status_text(format!("Keyfile located: {}", path_str).into());
                }
            }
        }
    });

    unlock_window.on_unlock_requested({
        let unlock_window_weak = unlock_window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);
        let app_config = Arc::clone(&app_config);
        let is_unlock_window_open = Arc::clone(&is_unlock_window_open);
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        let quick_search_shown_at = Arc::clone(&quick_search_shown_at);

        move |raw_password| {
            let Some(uw) = unlock_window_weak.upgrade() else { return };
            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                uw.set_error_message("Please enter a master password.".into());
                center_and_resize_unlock_window(&uw);
                return;
            }

            let keyfile_data = {
                let cfg = app_config.lock().unwrap();
                if let Some(kpath) = cfg.resolved_keyfile_path() {
                    if !kpath.exists() {
                        uw.set_error_message(
                            format!("Keyfile missing at {}. Please locate it.", kpath.display()).into(),
                        );
                        uw.set_show_keyfile_browse(true);
                        center_and_resize_unlock_window(&uw);
                        return;
                    }
                    match std::fs::read(&kpath) {
                        Ok(data) => Some(Zeroizing::new(data)),
                        Err(e) => {
                            uw.set_error_message(
                                format!("Failed to read keyfile: {}", e).into(),
                            );
                            uw.set_show_keyfile_browse(true);
                            return;
                        }
                    }
                } else {
                    None
                }
            };

            uw.set_is_loading(true);
            uw.set_error_message("".into());

            let uw_weak = unlock_window_weak.clone();
            let qs_weak = quick_search_weak.clone();
            let m_store = Arc::clone(&metadata_store);
            let is_uw_open = Arc::clone(&is_unlock_window_open);
            let is_qs_open = Arc::clone(&is_quick_search_open);
            let qs_shown = Arc::clone(&quick_search_shown_at);

            trigger_vault_reload(
                password,
                keyfile_data,
                window_weak.clone(),
                Arc::clone(&vault_path),
                Arc::clone(&metadata_store),
                Arc::clone(&session_password),
                Arc::clone(&session_keyfile),
                Arc::clone(&active_folder),
                Arc::clone(&search_query),
                Arc::clone(&use_multithreading),
                true,
                Some(Box::new(move |success| {
                    slint::invoke_from_event_loop(move || {
                        if success {
                            // Hide UnlockWindow
                            if let Some(uw) = uw_weak.upgrade() {
                                uw.invoke_clear_fields();
                                let _ = uw.hide();
                                is_uw_open.store(false, Ordering::SeqCst);
                            }

                            // Show QuickSearchWindow
                            if let Some(qs) = qs_weak.upgrade() {
                                qs.set_search_text("".into());
                                let initial_results = {
                                    let store = m_store.lock().unwrap();
                                    filter_quick_search_results("", &store)
                                };
                                let model = std::rc::Rc::new(slint::VecModel::from(initial_results));
                                qs.set_results(model.into());
                                qs.set_selected_index(0);

                                let (screen_w, screen_h) = get_primary_screen_size();
                                let scale = qs.window().scale_factor();
                                let logical_w = if scale > 0.0 { screen_w / scale } else { screen_w };
                                let logical_h = if scale > 0.0 { screen_h / scale } else { screen_h };

                                let win_w = 650.0;
                                let win_h = 360.0;
                                let pos_x = (logical_w - win_w) / 2.0;
                                let pos_y = (logical_h - win_h) / 2.0;

                                qs.window().set_size(slint::LogicalSize::new(win_w, win_h));
                                qs.window().set_position(slint::LogicalPosition::new(pos_x, pos_y));

                                is_qs_open.store(true, Ordering::SeqCst);
                                *qs_shown.lock().unwrap() = std::time::Instant::now();

                                let _ = qs.show();
                                qs.invoke_focus_search();
                                activate_quick_search_window();
                            }
                        } else {
                            if let Some(uw) = uw_weak.upgrade() {
                                uw.set_is_loading(false);
                                uw.set_error_message(
                                    "Decryption failed: invalid master password, keyfile mismatch, or corrupted note file.".into(),
                                );
                                center_and_resize_unlock_window(&uw);
                                uw.invoke_focus_password();
                            }
                        }
                    })
                    .ok();
                })),
            );
        }
    });

    // Startup flow: Check if vault path is empty or does not exist
    let needs_onboarding = initial_vault_path_str.trim().is_empty();

    if needs_onboarding {
        main_window.set_show_welcome_modal(true);
        main_window.set_welcome_vault_path("".into());
        main_window.set_is_locked(false);
        main_window.set_vault_status_text("No vault folder selected".into());
    } else {
        // Ensure directory exists if path is provided
        if !initial_vault_path.exists() {
            let _ = std::fs::create_dir_all(&initial_vault_path);
        }
        main_window.set_show_welcome_modal(false);
        main_window.set_is_locked(true);
        main_window.set_vault_status_text("Vault locked".into());
    }

    main_window.set_active_folder("*All Notes*".into());
    main_window.set_note_category("General".into());

    // -------------------------------------------------------------
    // Callback: Browse Vault Path Requested (rfd Native Folder Picker)
    // -------------------------------------------------------------
    main_window.on_browse_vault_path_requested({
        let window_weak = window_weak.clone();

        move || {
            let weak = window_weak.clone();
            thread::spawn(move || {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    let path_str = folder.to_string_lossy().to_string();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_settings_vault_path(path_str.as_str().into());
                            ui.set_welcome_vault_path(path_str.into());
                            ui.set_welcome_error_message("".into());
                        }
                    })
                    .ok();
                }
            });
        }
    });

    // -------------------------------------------------------------
    // Callback: Browse Export Path Requested (rfd Native Folder Picker)
    // -------------------------------------------------------------
    main_window.on_browse_export_path_requested({
        let window_weak = window_weak.clone();

        move || {
            let weak = window_weak.clone();
            thread::spawn(move || {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    let path_str = folder.to_string_lossy().to_string();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_export_path(path_str.as_str().into());
                        }
                    })
                    .ok();
                }
            });
        }
    });

    // -------------------------------------------------------------
    // Callback: Start Vault Export Requested (Background Worker)
    // -------------------------------------------------------------
    main_window.on_start_export_requested({
        let window_weak = window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let export_dir_str = ui.get_export_path().trim().to_string();
            if export_dir_str.is_empty() {
                ui.set_export_status("Please select an export directory first.".into());
                return;
            }

            let export_dir = PathBuf::from(export_dir_str);

            // Safely acquire session password. If locked, abort.
            let password = match session_password.lock().unwrap().as_ref() {
                Some(p) => p.clone(),
                None => {
                    ui.set_export_status("Error: Vault is locked. Unlock vault before exporting.".into());
                    return;
                }
            };
            let keyfile_opt = session_keyfile.lock().unwrap().clone();

            // Clone metadata_store so we don't hold the mutex during the entire I/O process
            let notes_to_export: Vec<(String, NoteMetaSummary)> = {
                let store = metadata_store.lock().unwrap();
                store.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            };

            ui.set_is_exporting(true);
            ui.set_export_progress(0.0);
            ui.set_export_status("Starting export...".into());

            let weak = window_weak.clone();

            thread::spawn(move || {
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                let total_notes = notes_to_export.len();
                if total_notes == 0 {
                    let weak_ui = weak.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            ui.set_is_exporting(false);
                            ui.set_export_progress(1.0);
                            ui.set_show_export_modal(false);
                            ui.set_vault_status_text("Vault exported (0 notes)".into());
                        }
                    })
                    .ok();
                    return;
                }

                let mut exported_count = 0usize;
                let mut error_count = 0usize;

                for (idx, (note_id, meta)) in notes_to_export.into_iter().enumerate() {
                    let current_num = idx + 1;
                    let progress = (idx as f32) / (total_notes as f32);
                    let note_title_display = if meta.title.is_empty() {
                        "Untitled".to_string()
                    } else {
                        meta.title.clone()
                    };
                    let status_msg = format!(
                        "Exporting note {} of {}: \"{}\"",
                        current_num, total_notes, note_title_display
                    );

                    let weak_ui = weak.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            ui.set_export_progress(progress);
                            ui.set_export_status(status_msg.into());
                        }
                    })
                    .ok();

                    // Decrypt note payload
                    match load_note_decrypted(&password, kf_bytes, &meta.file_path) {
                        Ok(mut decrypted_note) => {
                            let category_name = if meta.category.trim().is_empty() {
                                "General".to_string()
                            } else {
                                meta.category.trim().to_string()
                            };

                            let category_dir = export_dir.join(&category_name);
                            if let Err(e) = std::fs::create_dir_all(&category_dir) {
                                eprintln!(
                                    "[Export] Failed to create folder {:?}: {}",
                                    category_dir, e
                                );
                                error_count += 1;
                                decrypted_note.zeroize();
                                continue;
                            }

                            let safe_filename = sanitize_filename(&decrypted_note.title, &note_id);
                            let mut target_file = category_dir.join(format!("{}.md", safe_filename));

                            // Collision check: if a file with this name already exists, disambiguate with short UUID
                            if target_file.exists() {
                                let short_id = if note_id.len() >= 8 {
                                    &note_id[..8]
                                } else {
                                    &note_id
                                };
                                target_file = category_dir.join(format!("{}_{}.md", safe_filename, short_id));
                            }

                            let date_str = format_unix_timestamp(decrypted_note.updated_at);
                            let mut md_content = format_markdown_export(
                                &decrypted_note,
                                &category_name,
                                &date_str,
                            );

                            if let Err(e) = std::fs::write(&target_file, md_content.as_bytes()) {
                                eprintln!(
                                    "[Export] Failed to write exported file {:?}: {}",
                                    target_file, e
                                );
                                error_count += 1;
                            } else {
                                exported_count += 1;
                            }

                            // Zeroize memory buffers immediately
                            decrypted_note.zeroize();
                            md_content.zeroize();
                        }
                        Err(e) => {
                            eprintln!(
                                "[Export] Failed to decrypt note at {:?}: {}",
                                meta.file_path, e
                            );
                            error_count += 1;
                        }
                    }
                }

                let weak_ui = weak.clone();
                let completion_msg = if error_count == 0 {
                    format!("Vault exported ({} note(s) saved)", exported_count)
                } else {
                    format!(
                        "Vault exported with {} error(s) ({} note(s) saved)",
                        error_count, exported_count
                    )
                };

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_ui.upgrade() {
                        ui.set_is_exporting(false);
                        ui.set_export_progress(1.0);
                        ui.set_show_export_modal(false);
                        ui.set_vault_status_text(completion_msg.into());
                    }
                })
                .ok();

                println!(
                    "[NoteVault] Export finished: {} exported, {} failed to {:?}",
                    exported_count, error_count, export_dir
                );
            });
        }
    });

    // -------------------------------------------------------------
    // Callback: Welcome Open Vault Requested
    // -------------------------------------------------------------
    main_window.on_welcome_open_vault_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let app_config = Arc::clone(&app_config);

        move |chosen_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            let chosen_path_clean = chosen_path_str.trim().to_string();

            if chosen_path_clean.is_empty() {
                ui.set_welcome_error_message("Please select a valid vault directory.".into());
                return;
            }

            let path = PathBuf::from(&chosen_path_clean);
            if let Err(e) = std::fs::create_dir_all(&path) {
                ui.set_welcome_error_message(format!("Failed to create folder: {}", e).into());
                return;
            }

            // Save to config
            {
                let mut cfg = app_config.lock().unwrap();
                cfg.vault_path = chosen_path_clean.clone();
                let _ = cfg.save();
            }

            *vault_path.lock().unwrap() = path;
            ui.set_settings_vault_path(chosen_path_clean.as_str().into());
            ui.set_show_welcome_modal(false);
            ui.set_is_locked(true);
            ui.set_vault_status_text("Vault locked".into());
        }
    });

    // -------------------------------------------------------------
    // Callback: Open Settings Requested
    // -------------------------------------------------------------
    main_window.on_open_settings_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let use_multithreading = Arc::clone(&use_multithreading);
        let app_config = Arc::clone(&app_config);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let cfg = app_config.lock().unwrap();
            let cur_path = vault_path.lock().unwrap().to_string_lossy().to_string();
            let cur_multi = use_multithreading.load(Ordering::Relaxed);
            let cur_hotkey = cfg.global_hotkey.clone();
            let cur_minimize = cfg.minimize_to_tray;
            let cur_theme_raw = cfg.theme.clone();
            let cur_theme = match cur_theme_raw.as_str() {
                "blue" => "blue",
                "light" => "light",
                _ => "dark",
            };
            let is_dark = cur_theme != "light";

            ui.set_settings_vault_path(cur_path.into());
            ui.set_settings_use_multithreading(cur_multi);
            ui.global::<Theme>().set_theme(cur_theme.into());
            ui.global::<Theme>().set_is_dark(is_dark);
            ui.set_settings_theme(cur_theme.into());
            ui.set_settings_global_hotkey(cur_hotkey.into());
            ui.set_settings_minimize_to_tray(cur_minimize);
            ui.set_settings_launch_at_startup(cfg.launch_at_startup);
            ui.set_settings_cur_pwd("".into());
            ui.set_settings_new_pwd("".into());
            ui.set_settings_confirm_pwd("".into());
            ui.set_password_change_status("".into());
            ui.set_password_change_success(false);
            ui.set_is_reencrypting(false);
            ui.set_settings_keyfile_cur_pwd("".into());
            ui.set_settings_new_keyfile_path("".into());
            ui.set_settings_remove_keyfile(false);
            ui.set_keyfile_status("".into());
            ui.set_keyfile_success(false);
            ui.set_is_keyfile_reencrypting(false);
            ui.set_keyfile_reencrypt_progress(0.0);
            ui.set_show_settings_modal(true);
        }
    });

    // -------------------------------------------------------------
    // Callback: Save Settings Requested
    // -------------------------------------------------------------
    main_window.on_save_settings_requested({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let quick_viewer_weak = quick_viewer_weak.clone();
        let unlock_window_weak = unlock_window_weak.clone();
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        let vault_path = Arc::clone(&vault_path);
        let use_multithreading = Arc::clone(&use_multithreading);
        let app_config = Arc::clone(&app_config);
        let hotkey_manager = Arc::clone(&hotkey_manager);
        let active_hotkey = Arc::clone(&active_hotkey);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |new_path_str, new_multi, new_theme_str, new_hotkey_str, new_min_tray, new_launch_startup| {
            let Some(ui) = window_weak.upgrade() else { return };
            let new_path_clean = new_path_str.trim().to_string();
            let new_theme_clean = new_theme_str.trim().to_string();
            let new_hotkey_clean = new_hotkey_str.trim().to_string();

            let parse_result = parse_hotkey_string(&new_hotkey_clean);
            let (new_hk_opt, clean_hotkey_str) = match parse_result {
                Ok((hk, norm)) => (Some(hk), norm),
                Err(e) => {
                    eprintln!("Invalid hotkey entered '{}': {}", new_hotkey_clean, e);
                    (None, new_hotkey_clean.clone())
                }
            };

            // 1. Update and save config.json
            let (old_hotkey, old_launch, old_min_tray) = {
                let mut cfg = app_config.lock().unwrap();
                let old_hk = cfg.global_hotkey.clone();
                let old_launch = cfg.launch_at_startup;
                let old_min_tray = cfg.minimize_to_tray;
                cfg.vault_path = new_path_clean.clone();
                cfg.use_multithreading = new_multi;
                let final_theme = match new_theme_clean.as_str() {
                    "blue" => "blue",
                    "light" => "light",
                    _ => "dark",
                };
                cfg.theme = final_theme.to_string();
                cfg.global_hotkey = clean_hotkey_str.clone();
                cfg.minimize_to_tray = new_min_tray;
                cfg.launch_at_startup = new_launch_startup;
                if let Err(e) = cfg.save() {
                    eprintln!("Failed to save config.json: {}", e);
                }
                (old_hk, old_launch, old_min_tray)
            };

            // 1b. If startup registration or minimize_to_tray changed, update startup registration
            if old_launch != new_launch_startup || (new_launch_startup && old_min_tray != new_min_tray) {
                if let Err(e) = note_vault::startup::set_launch_at_startup(new_launch_startup, new_min_tray) {
                    eprintln!("Failed to update startup registration: {}", e);
                }
            }

            // 1c. If hotkey changed, update global registration
            if let Some(new_hk) = new_hk_opt {
                if old_hotkey != clean_hotkey_str {
                    if let Some(ref mut mgr) = *hotkey_manager.lock().unwrap() {
                        let mut cur_hk_guard = active_hotkey.lock().unwrap();
                        if let Some(old_hk) = cur_hk_guard.take() {
                            let _ = mgr.unregister(old_hk);
                        }
                        if let Ok(()) = mgr.register(new_hk) {
                            *cur_hk_guard = Some(new_hk);
                        }
                    }
                }
            }

            ui.set_settings_global_hotkey(clean_hotkey_str.into());
            ui.set_settings_minimize_to_tray(new_min_tray);
            ui.set_settings_launch_at_startup(new_launch_startup);

            // 2. Apply theme dynamically
            let final_theme = match new_theme_clean.as_str() {
                "blue" => "blue",
                "light" => "light",
                _ => "dark",
            };
            let is_dark_mode = final_theme != "light";
            ui.global::<Theme>().set_theme(final_theme.into());
            ui.global::<Theme>().set_is_dark(is_dark_mode);
            if let Some(qs) = quick_search_weak.upgrade() {
                qs.global::<Theme>().set_theme(final_theme.into());
                qs.global::<Theme>().set_is_dark(is_dark_mode);
            }
            if let Some(qv) = quick_viewer_weak.upgrade() {
                qv.global::<Theme>().set_theme(final_theme.into());
                qv.global::<Theme>().set_is_dark(is_dark_mode);
            }
            if let Some(uw) = unlock_window_weak.upgrade() {
                uw.global::<Theme>().set_theme(final_theme.into());
                uw.global::<Theme>().set_is_dark(is_dark_mode);
            }

            // 3. Update multithreading state
            use_multithreading.store(new_multi, Ordering::Relaxed);

            // 4. Handle vault path changes
            let old_path = vault_path.lock().unwrap().clone();
            let new_path = PathBuf::from(&new_path_clean);

            if !new_path_clean.is_empty() && new_path != old_path {
                let _ = std::fs::create_dir_all(&new_path);
                *vault_path.lock().unwrap() = new_path.clone();

                // Lock vault on folder switch
                *session_password.lock().unwrap() = None;
                *session_keyfile.lock().unwrap() = None;
                metadata_store.lock().unwrap().clear();
                *active_folder.lock().unwrap() = "*All Notes*".to_string();
                *search_query.lock().unwrap() = String::new();

                is_quick_search_open.store(false, Ordering::SeqCst);
                if let Some(qs) = quick_search_weak.upgrade() {
                    let _ = qs.hide();
                    qs.set_results(std::rc::Rc::new(slint::VecModel::default()).into());
                }
                if let Some(qv) = quick_viewer_weak.upgrade() {
                    qv.invoke_clear_data();
                    qv.set_content("".into());
                    qv.set_note_title("".into());
                    let _ = qv.hide();
                }

                ui.set_folders(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_current_notes(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_active_note_id("".into());
                ui.set_note_title("".into());
                ui.set_active_folder("*All Notes*".into());
                ui.set_note_category("General".into());
                ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_note_date("".into());
                ui.set_note_content("".into());
                ui.set_search_query("".into());
                ui.set_unlock_password("".into());
                ui.set_vault_status_text("Vault locked (switched folder)".into());
                ui.set_has_unsaved_changes(false);
                ui.set_show_unsaved_warning(false);
                ui.set_is_locked(true);
            }

            ui.set_show_settings_modal(false);
        }
    });

    // -------------------------------------------------------------
    // Callback: Theme Changed from Settings ComboBox
    // -------------------------------------------------------------
    main_window.on_theme_changed({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let quick_viewer_weak = quick_viewer_weak.clone();
        move |theme_str| {
            let final_theme = match theme_str.trim() {
                "blue" => "blue",
                "light" => "light",
                _ => "dark",
            };
            let is_dark_mode = final_theme != "light";
            if let Some(ui) = window_weak.upgrade() {
                ui.global::<Theme>().set_theme(final_theme.into());
                ui.global::<Theme>().set_is_dark(is_dark_mode);
            }
            if let Some(qs) = quick_search_weak.upgrade() {
                qs.global::<Theme>().set_theme(final_theme.into());
                qs.global::<Theme>().set_is_dark(is_dark_mode);
            }
            if let Some(qv) = quick_viewer_weak.upgrade() {
                qv.global::<Theme>().set_theme(final_theme.into());
                qv.global::<Theme>().set_is_dark(is_dark_mode);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Record Hotkey Requested from Settings Shortcut Box
    // -------------------------------------------------------------
    main_window.on_record_hotkey_requested(|key_text, ctrl, alt, shift, meta| {
        if let Some(combo) = format_key_combination(key_text.as_str(), ctrl, alt, shift, meta) {
            combo.into()
        } else {
            "".into()
        }
    });

    // -------------------------------------------------------------
    // Callback: Exit Requested
    // -------------------------------------------------------------
    main_window.on_exit_requested({
        let window_weak = window_weak.clone();
        move || {
            if let Some(ui) = window_weak.upgrade() {
                let _ = ui.hide();
            }
            std::process::exit(0);
        }
    });

    // -------------------------------------------------------------
    // Callback: Change Master Password (SECURE & ATOMIC)
    // -------------------------------------------------------------
    main_window.on_change_password_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);

        move |raw_current, raw_new, raw_confirm| {
            let Some(ui) = window_weak.upgrade() else { return };

            let current_pwd = Zeroizing::new(raw_current.to_string());
            let new_pwd = Zeroizing::new(raw_new.to_string());
            let confirm_pwd = Zeroizing::new(raw_confirm.to_string());

            // 1. Verify active session is unlocked
            let session_opt = session_password.lock().unwrap().clone();
            let active_pwd = match session_opt {
                Some(p) => p,
                None => {
                    ui.set_password_change_status(
                        "Error: Vault must be unlocked to change password.".into(),
                    );
                    ui.set_password_change_success(false);
                    return;
                }
            };

            // 2. Verify current password matches active session
            if current_pwd.as_str() != active_pwd.as_str() {
                ui.set_password_change_status("Error: Current password does not match.".into());
                ui.set_password_change_success(false);
                return;
            }

            // 3. Verify new passwords match and are non-empty
            if new_pwd.as_str() != confirm_pwd.as_str() {
                ui.set_password_change_status(
                    "Error: New password and confirmation do not match.".into(),
                );
                ui.set_password_change_success(false);
                return;
            }

            if new_pwd.is_empty() {
                ui.set_password_change_status("Error: New password cannot be empty.".into());
                ui.set_password_change_success(false);
                return;
            }

            // Begin atomic re-encryption in background thread
            ui.set_is_reencrypting(true);
            ui.set_reencrypt_progress(0.0);
            ui.set_password_change_status("Starting atomic re-encryption...".into());
            ui.set_password_change_success(false);

            let weak = window_weak.clone();
            let v_dir = vault_path.lock().unwrap().clone();
            let s_pass = Arc::clone(&session_password);
            let keyfile_opt = session_keyfile.lock().unwrap().clone();

            thread::spawn(move || {
                let weak_progress = weak.clone();
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                let res = note_vault::reencrypt_vault_atomic(
                    &v_dir,
                    &current_pwd,
                    kf_bytes,
                    &new_pwd,
                    kf_bytes,
                    move |done, total| {
                        let progress = (done as f32) / (total as f32);
                        let status_msg = format!("Re-encrypting note {} of {}...", done, total);
                        let weak_ui = weak_progress.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_reencrypt_progress(progress);
                                ui.set_password_change_status(status_msg.into());
                            }
                        })
                        .ok();
                    },
                );

                match res {
                    Ok(total) => {
                        *s_pass.lock().unwrap() = Some(new_pwd);
                        let weak_ui = weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_is_reencrypting(false);
                                ui.set_reencrypt_progress(1.0);
                                ui.set_password_change_status(
                                    format!("Master password changed successfully ({} notes updated).", total).into(),
                                );
                                ui.set_password_change_success(true);
                                ui.set_settings_cur_pwd("".into());
                                ui.set_settings_new_pwd("".into());
                                ui.set_settings_confirm_pwd("".into());
                            }
                        })
                        .ok();
                    }
                    Err(err) => {
                        let err_msg = err.to_string();
                        let weak_ui = weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_is_reencrypting(false);
                                ui.set_password_change_status(
                                    format!("Re-encryption aborted: {}", err_msg).into(),
                                );
                                ui.set_password_change_success(false);
                            }
                        })
                        .ok();
                    }
                }
            });
        }
    });

    // -------------------------------------------------------------
    // Callback: Browse New Keyfile in Settings
    // -------------------------------------------------------------
    main_window.on_browse_new_keyfile_requested({
        let window_weak = window_weak.clone();
        let session_password = Arc::clone(&session_password);
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            if session_password.lock().unwrap().is_none() {
                return;
            }
            let picked_file = rfd::FileDialog::new()
                .set_title("Select New Keyfile")
                .pick_file();
            if let Some(path) = picked_file {
                ui.set_settings_new_keyfile_path(path.to_string_lossy().to_string().into());
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Unlock Browse Keyfile (from Unlock Modal)
    // -------------------------------------------------------------
    main_window.on_unlock_browse_keyfile_requested({
        let window_weak = window_weak.clone();
        let app_config = Arc::clone(&app_config);
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let picked_file = rfd::FileDialog::new()
                .set_title("Locate Keyfile")
                .pick_file();
            if let Some(path) = picked_file {
                let path_str = path.to_string_lossy().to_string();
                let mut cfg = app_config.lock().unwrap();
                cfg.keyfile_path = Some(path_str.clone());
                let _ = cfg.save();
                ui.set_unlock_error_message("".into());
                ui.set_show_keyfile_browse(false);
                ui.set_vault_status_text(format!("Keyfile located: {}", path_str).into());
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Update Keyfile (Add / Change / Remove Keyfile)
    // -------------------------------------------------------------
    main_window.on_update_keyfile_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let app_config = Arc::clone(&app_config);

        move |raw_current_pwd, raw_new_path, remove_keyfile| {
            let Some(ui) = window_weak.upgrade() else { return };

            let current_pwd = Zeroizing::new(raw_current_pwd.to_string());

            // 1. Verify active session is unlocked
            let session_opt = session_password.lock().unwrap().clone();
            let active_pwd = match session_opt {
                Some(p) => p,
                None => {
                    ui.set_keyfile_status("Error: Vault must be unlocked to update keyfile.".into());
                    ui.set_keyfile_success(false);
                    return;
                }
            };

            // 2. Verify current password matches active session
            if current_pwd.as_str() != active_pwd.as_str() {
                ui.set_keyfile_status("Error: Current password does not match.".into());
                ui.set_keyfile_success(false);
                return;
            }

            // 3. Determine target keyfile bytes and path
            let (target_keyfile_bytes, target_keyfile_path) = if remove_keyfile {
                (None, None)
            } else {
                let path_str = raw_new_path.trim().to_string();
                if path_str.is_empty() {
                    ui.set_keyfile_status("Error: Please select a keyfile or check Remove Keyfile.".into());
                    ui.set_keyfile_success(false);
                    return;
                }
                let kf_path = PathBuf::from(&path_str);
                if !kf_path.exists() {
                    ui.set_keyfile_status("Error: Selected keyfile does not exist.".into());
                    ui.set_keyfile_success(false);
                    return;
                }
                match std::fs::read(&kf_path) {
                    Ok(bytes) => (Some(Zeroizing::new(bytes)), Some(path_str)),
                    Err(e) => {
                        ui.set_keyfile_status(format!("Error reading keyfile: {}", e).into());
                        ui.set_keyfile_success(false);
                        return;
                    }
                }
            };

            let current_keyfile = session_keyfile.lock().unwrap().clone();

            // 4. Begin atomic re-encryption
            ui.set_is_keyfile_reencrypting(true);
            ui.set_keyfile_reencrypt_progress(0.0);
            ui.set_keyfile_status("Starting atomic re-encryption with new keyfile...".into());
            ui.set_keyfile_success(false);

            let weak = window_weak.clone();
            let v_dir = vault_path.lock().unwrap().clone();
            let s_kf = Arc::clone(&session_keyfile);
            let s_cfg = Arc::clone(&app_config);

            thread::spawn(move || {
                let weak_progress = weak.clone();
                let cur_kf_bytes = current_keyfile.as_deref().map(|b| b.as_slice());
                let tgt_kf_bytes = target_keyfile_bytes.as_deref().map(|b| b.as_slice());

                let res = note_vault::reencrypt_vault_atomic(
                    &v_dir,
                    &current_pwd,
                    cur_kf_bytes,
                    &current_pwd,
                    tgt_kf_bytes,
                    move |done, total| {
                        let progress = (done as f32) / (total as f32);
                        let status_msg = format!("Re-encrypting note {} of {}...", done, total);
                        let weak_ui = weak_progress.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_keyfile_reencrypt_progress(progress);
                                ui.set_keyfile_status(status_msg.into());
                            }
                        })
                        .ok();
                    },
                );

                match res {
                    Ok(total) => {
                        *s_kf.lock().unwrap() = target_keyfile_bytes;
                        {
                            let mut cfg = s_cfg.lock().unwrap();
                            cfg.keyfile_path = target_keyfile_path.clone();
                            let _ = cfg.save();
                        }

                        let weak_ui = weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_is_keyfile_reencrypting(false);
                                ui.set_keyfile_reencrypt_progress(1.0);
                                let msg = if target_keyfile_path.is_some() {
                                    format!("Keyfile updated successfully ({} notes re-encrypted).", total)
                                } else {
                                    format!("Keyfile removed successfully ({} notes re-encrypted).", total)
                                };
                                ui.set_keyfile_status(msg.into());
                                ui.set_keyfile_success(true);
                                ui.set_settings_keyfile_cur_pwd("".into());
                                ui.set_settings_new_keyfile_path("".into());
                                ui.set_settings_remove_keyfile(false);
                            }
                        })
                        .ok();
                    }
                    Err(err) => {
                        let err_msg = err.to_string();
                        let weak_ui = weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak_ui.upgrade() {
                                ui.set_is_keyfile_reencrypting(false);
                                ui.set_keyfile_status(
                                    format!("Keyfile update failed: {}", err_msg).into(),
                                );
                                ui.set_keyfile_success(false);
                            }
                        })
                        .ok();
                    }
                }
            });
        }
    });

    // -------------------------------------------------------------
    // Callback: Folder Selected in Pane 1
    // -------------------------------------------------------------
    main_window.on_folder_selected({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |folder| {
            let Some(ui) = window_weak.upgrade() else { return };
            let v_path = vault_path.lock().unwrap().clone();
            *active_folder.lock().unwrap() = folder.to_string();
            ui.set_active_folder(folder.clone());
            let note_cat = if folder == "*All Notes*" {
                "General".to_string()
            } else {
                folder.to_string()
            };
            ui.set_note_category(note_cat.into());
            ui.set_active_note_id("".into());
            ui.set_note_title("".into());
            ui.set_note_content("".into());
            ui.set_editor_markdown_mode(false);
            ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_date("".into());
            refresh_models(&ui, &v_path, &metadata_store, &active_folder, &search_query);
        }
    });

    // -------------------------------------------------------------
    // Callback: Search Query Changed in Pane 2 Header
    // -------------------------------------------------------------
    main_window.on_search_changed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |query| {
            let Some(ui) = window_weak.upgrade() else { return };
            let v_path = vault_path.lock().unwrap().clone();
            *search_query.lock().unwrap() = query.to_string();
            refresh_models(&ui, &v_path, &metadata_store, &active_folder, &search_query);
        }
    });

    // -------------------------------------------------------------
    // Callback: Unlock Vault
    // -------------------------------------------------------------
    main_window.on_unlock_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);
        let app_config = Arc::clone(&app_config);

        move |raw_password| {
            let Some(ui) = window_weak.upgrade() else { return };

            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                ui.set_unlock_error_message("Please enter a master password.".into());
                return;
            }

            let keyfile_data = {
                let cfg = app_config.lock().unwrap();
                if let Some(kpath) = cfg.resolved_keyfile_path() {
                    if !kpath.exists() {
                        ui.set_unlock_error_message(
                            format!("Keyfile missing at {}. Please locate it.", kpath.display()).into(),
                        );
                        ui.set_show_keyfile_browse(true);
                        return;
                    }
                    match std::fs::read(&kpath) {
                        Ok(data) => Some(Zeroizing::new(data)),
                        Err(e) => {
                            ui.set_unlock_error_message(
                                format!("Failed to read keyfile: {}", e).into(),
                            );
                            ui.set_show_keyfile_browse(true);
                            return;
                        }
                    }
                } else {
                    None
                }
            };

            ui.set_unlock_password("".into());
            ui.set_unlock_error_message("".into());
            ui.set_show_keyfile_browse(false);

            trigger_vault_reload(
                password,
                keyfile_data,
                window_weak.clone(),
                Arc::clone(&vault_path),
                Arc::clone(&metadata_store),
                Arc::clone(&session_password),
                Arc::clone(&session_keyfile),
                Arc::clone(&active_folder),
                Arc::clone(&search_query),
                Arc::clone(&use_multithreading),
                true,
                None,
            );
        }
    });

    // -------------------------------------------------------------
    // Callback: Note Selection in Pane 2
    // -------------------------------------------------------------
    main_window.on_select_note_requested({
        let window_weak = window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);

        move |note_id| {
            let Some(ui) = window_weak.upgrade() else { return };

            if ui.get_has_unsaved_changes() {
                ui.set_pending_action_type("select_note".into());
                ui.set_pending_action_payload(note_id);
                ui.set_show_unsaved_warning(true);
            } else {
                load_note_into_ui(&ui, note_id.as_str(), &metadata_store, &session_password, &session_keyfile);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Discard Changes Confirmed
    // -------------------------------------------------------------
    main_window.on_discard_changes_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let action_type = ui.get_pending_action_type().to_string();
            let payload = ui.get_pending_action_payload().to_string();

            ui.set_pending_action_type("".into());
            ui.set_pending_action_payload("".into());
            ui.set_has_unsaved_changes(false);
            ui.set_show_unsaved_warning(false);

            match action_type.as_str() {
                "select_note" => {
                    load_note_into_ui(
                        &ui,
                        payload.as_str(),
                        &metadata_store,
                        &session_password,
                        &session_keyfile,
                    );
                }
                "select_folder" => {
                    let v_path = vault_path.lock().unwrap().clone();
                    *active_folder.lock().unwrap() = payload.clone();
                    ui.set_active_folder(payload.clone().into());
                    let note_cat = if payload == "*All Notes*" {
                        "General".to_string()
                    } else {
                        payload.clone()
                    };
                    ui.set_note_category(note_cat.into());
                    ui.set_active_note_id("".into());
                    ui.set_note_title("".into());
                    ui.set_note_content("".into());
                    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                    ui.set_note_date("".into());
                    refresh_models(&ui, &v_path, &metadata_store, &active_folder, &search_query);
                }
                "new_note" => {
                    let cur_folder = active_folder.lock().unwrap().clone();
                    if cur_folder == "*All Notes*" {
                        return;
                    }
                    ui.set_active_note_id("new".into());
                    ui.set_note_title("Untitled Note".into());
                    ui.set_note_category(cur_folder.into());
                    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                    ui.set_note_date("Just now".into());
                    ui.set_note_content("".into());
                    ui.set_editor_markdown_mode(false);
                    ui.set_line_numbers_text("1".into());
                    ui.set_has_unsaved_changes(false);
                }
                "new_folder" => {
                    ui.set_new_folder_name("".into());
                    ui.set_folder_error_message("".into());
                    ui.set_show_folder_modal(true);
                }
                "rescan_vault" => {
                    let password_opt = session_password.lock().unwrap().clone();
                    let keyfile_opt = session_keyfile.lock().unwrap().clone();
                    if let Some(password) = password_opt {
                        trigger_vault_reload(
                            password,
                            keyfile_opt,
                            window_weak.clone(),
                            Arc::clone(&vault_path),
                            Arc::clone(&metadata_store),
                            Arc::clone(&session_password),
                            Arc::clone(&session_keyfile),
                            Arc::clone(&active_folder),
                            Arc::clone(&search_query),
                            Arc::clone(&use_multithreading),
                            false,
                            None,
                        );
                    }
                }
                _ => {}
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Rescan Vault Requested
    // -------------------------------------------------------------
    main_window.on_rescan_vault_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);

        move || {
            let password_opt = session_password.lock().unwrap().clone();
            let keyfile_opt = session_keyfile.lock().unwrap().clone();
            if let Some(password) = password_opt {
                trigger_vault_reload(
                    password,
                    keyfile_opt,
                    window_weak.clone(),
                    Arc::clone(&vault_path),
                    Arc::clone(&metadata_store),
                    Arc::clone(&session_password),
                    Arc::clone(&session_keyfile),
                    Arc::clone(&active_folder),
                    Arc::clone(&search_query),
                    Arc::clone(&use_multithreading),
                    false,
                    None,
                );
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Lock Vault
    // -------------------------------------------------------------
    main_window.on_lock_vault({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let quick_viewer_weak = quick_viewer_weak.clone();
        let is_quick_search_open = Arc::clone(&is_quick_search_open);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            println!("[NoteVault] Vault locked.");

            *session_password.lock().unwrap() = None;
            *session_keyfile.lock().unwrap() = None;
            metadata_store.lock().unwrap().clear();
            *active_folder.lock().unwrap() = "*All Notes*".to_string();
            *search_query.lock().unwrap() = String::new();

            is_quick_search_open.store(false, Ordering::SeqCst);
            if let Some(qs) = quick_search_weak.upgrade() {
                let _ = qs.hide();
                qs.set_results(std::rc::Rc::new(slint::VecModel::default()).into());
            }
            if let Some(qv) = quick_viewer_weak.upgrade() {
                qv.invoke_clear_data();
                qv.set_content("".into());
                qv.set_note_title("".into());
                let _ = qv.hide();
            }

            ui.set_folders(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_current_notes(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_active_note_id("".into());
            ui.set_note_title("".into());
            ui.set_active_folder("*All Notes*".into());
            ui.set_note_category("General".into());
            ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_date("".into());
            ui.set_note_content("".into());
            ui.set_search_query("".into());
            ui.set_unlock_password("".into());
            ui.set_show_keyfile_browse(false);
            ui.set_vault_status_text("Vault locked".into());
            ui.set_has_unsaved_changes(false);
            ui.set_show_unsaved_warning(false);
            ui.set_is_locked(true);
        }
    });

    // -------------------------------------------------------------
    // Callback: Save Note
    // -------------------------------------------------------------
    main_window.on_save_note_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let session_keyfile = Arc::clone(&session_keyfile);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |title, content, category| {
            let Some(ui) = window_weak.upgrade() else { return };

            let current_vault = vault_path.lock().unwrap().clone();

            let (password, keyfile_opt) = {
                let session = session_password.lock().unwrap();
                let keyfile = session_keyfile.lock().unwrap();
                match session.as_ref() {
                    Some(p) => (p.clone(), keyfile.clone()),
                    None => {
                        eprintln!("Error: Cannot save note, vault session is locked.");
                        return;
                    }
                }
            };
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());

            let active_id = ui.get_active_note_id().to_string();
            let is_new = active_id.is_empty() || active_id == "new";

            let mut target_category = category.trim().to_string();
            if target_category.is_empty() {
                target_category = active_folder.lock().unwrap().clone();
            }
            if target_category == "*All Notes*" || target_category.is_empty() {
                target_category = "General".to_string();
            }

            let clean_title = title.trim();
            let title_str = if clean_title.is_empty() {
                "Untitled Note".to_string()
            } else {
                clean_title.to_string()
            };

            // Check for note title collision in the target folder
            let has_duplicate = {
                let store = metadata_store.lock().unwrap();
                store.iter().any(|(id, meta)| {
                    id != &active_id
                        && meta.category == target_category
                        && meta.title.trim().eq_ignore_ascii_case(&title_str)
                })
            };

            if has_duplicate {
                ui.set_warning_modal_title("Duplicate Note Title".into());
                ui.set_warning_modal_message(
                    format!(
                        "A note titled \"{}\" already exists in folder \"{}\". Please choose a different title to prevent duplicate notes.",
                        title_str, target_category
                    )
                    .into(),
                );
                ui.set_show_warning_modal(true);
                ui.set_vault_status_text("Save blocked: Duplicate note title in folder".into());
                return;
            }

            let parsed_tags: Vec<String> = ui
                .get_note_tags()
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let category_dir = if target_category == "General" {
                current_vault.join("General")
            } else {
                current_vault.join(&target_category)
            };
            let _ = std::fs::create_dir_all(&category_dir);

            let (mut note, target_path, old_path_to_remove) = if is_new {
                let new_note = Note::new(
                    title_str.clone(),
                    parsed_tags.clone(),
                    content.to_string(),
                );

                let file_path = category_dir.join(format!("{}.vault", new_note.id));
                (new_note, file_path, None)
            } else {
                let (existing_file_path, _) = {
                    let store = metadata_store.lock().unwrap();
                    if let Some(m) = store.get(&active_id) {
                        (m.file_path.clone(), m.category.clone())
                    } else {
                        (
                            current_vault.join(&target_category).join(format!("{}.vault", active_id)),
                            target_category.clone(),
                        )
                    }
                };

                let new_target_path = category_dir.join(format!("{}.vault", active_id));
                let remove_old = if existing_file_path != new_target_path && existing_file_path.exists() {
                    Some(existing_file_path.clone())
                } else {
                    None
                };

                let loaded_note = if existing_file_path.exists() {
                    load_note_decrypted(&password, kf_bytes, &existing_file_path).ok()
                } else {
                    None
                };

                let note_to_save = match loaded_note {
                    Some(mut existing) => {
                        existing.title = title_str.clone();
                        existing.tags = parsed_tags.clone();
                        existing.content = content.to_string();
                        existing.updated_at = now;
                        existing
                    }
                    None => {
                        let parsed_uuid =
                            Uuid::parse_str(&active_id).unwrap_or_else(|_| Uuid::new_v4());
                        Note {
                            id: parsed_uuid,
                            title: title_str.clone(),
                            tags: parsed_tags.clone(),
                            content: content.to_string(),
                            created_at: now,
                            updated_at: now,
                        }
                    }
                };

                (note_to_save, new_target_path, remove_old)
            };

            let saved_id = note.id.to_string();
            let updated_ts = note.updated_at;

            if let Err(e) = save_note_encrypted(&note, &password, kf_bytes, &target_path) {
                eprintln!("Error saving encrypted note to {:?}: {}", target_path, e);
                return;
            }

            if let Some(old_file) = old_path_to_remove {
                let _ = std::fs::remove_file(&old_file);
            }

            note.zeroize();

            let formatted_date = format_unix_timestamp(updated_ts);

            // Update in-memory metadata store
            {
                let mut store = metadata_store.lock().unwrap();
                store.insert(
                    saved_id.clone(),
                    NoteMetaSummary {
                        title: title_str.clone(),
                        category: target_category.clone(),
                        tags: parsed_tags,
                        date: formatted_date.clone(),
                        updated_at: updated_ts,
                        file_path: target_path.clone(),
                    },
                );
            }

            let was_all_notes = active_folder.lock().unwrap().as_str() == "*All Notes*";
            if !was_all_notes {
                *active_folder.lock().unwrap() = target_category.clone();
                ui.set_active_folder(target_category.clone().into());
            }

            ui.set_active_note_id(saved_id.into());
            ui.set_note_title(title_str.as_str().into());
            ui.set_note_date(formatted_date.into());
            ui.set_note_category(target_category.clone().into());
            let blocks = parse_markdown_into_blocks(&content);
            ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
            ui.set_note_markdown_rendered(render_markdown_styled(&content));
            ui.set_has_unsaved_changes(false);

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Note saved successfully to {:?}", target_path);
        }
    });

    // -------------------------------------------------------------
    // Callback: New Note
    // -------------------------------------------------------------
    main_window.on_new_note_requested({
        let window_weak = window_weak.clone();
        let active_folder = Arc::clone(&active_folder);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            if ui.get_is_locked() {
                return;
            }
            let cur_folder = active_folder.lock().unwrap().clone();
            if cur_folder == "*All Notes*" {
                return;
            }
            ui.set_active_note_id("new".into());
            ui.set_note_title("Untitled Note".into());
            ui.set_note_category(cur_folder.into());
            ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_date("Just now".into());
            ui.set_note_content("".into());
            ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_markdown_rendered(slint::StyledText::default());
            ui.set_editor_markdown_mode(false);
            ui.set_line_numbers_text("1".into());
            ui.set_has_unsaved_changes(false);
        }
    });

    // -------------------------------------------------------------
    // Callback: New Folder Requested
    // -------------------------------------------------------------
    main_window.on_new_folder_requested({
        let window_weak = window_weak.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            if ui.get_is_locked() {
                return;
            }
            ui.set_new_folder_name("".into());
            ui.set_show_folder_modal(true);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Folder Creation
    // -------------------------------------------------------------
    main_window.on_create_folder_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |name| {
            let Some(ui) = window_weak.upgrade() else { return };
            if ui.get_is_locked() {
                return;
            }

            let valid_name = match validate_folder_name(&name) {
                Ok(n) => n,
                Err(err_msg) => {
                    ui.set_folder_error_message(err_msg.into());
                    return;
                }
            };

            let current_vault = vault_path.lock().unwrap().clone();
            let target_dir = current_vault.join(&valid_name);

            if target_dir.exists() {
                ui.set_folder_error_message(
                    format!("A folder named '{}' already exists.", valid_name).into(),
                );
                return;
            }

            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                ui.set_folder_error_message(format!("Failed to create folder: {}", e).into());
                eprintln!("Failed to create folder at {:?}: {}", target_dir, e);
                return;
            }

            ui.set_folder_error_message("".into());
            ui.set_show_folder_modal(false);

            println!("[NoteVault] Created folder: {:?}", target_dir);
            *active_folder.lock().unwrap() = valid_name.clone();
            ui.set_active_folder(valid_name.clone().into());
            ui.set_note_category(valid_name.into());

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Folder Rename
    // -------------------------------------------------------------
    main_window.on_rename_folder_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |old_name, new_name| {
            let Some(ui) = window_weak.upgrade() else { return };
            let old_name = old_name.trim().to_string();

            if old_name.is_empty() {
                ui.set_show_rename_folder_modal(false);
                return;
            }

            let valid_new = match validate_folder_name(&new_name) {
                Ok(n) => n,
                Err(err_msg) => {
                    ui.set_rename_folder_error_message(err_msg.into());
                    return;
                }
            };

            if old_name == valid_new {
                ui.set_rename_folder_error_message("".into());
                ui.set_show_rename_folder_modal(false);
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();
            let old_path = current_vault.join(&old_name);
            let new_path = current_vault.join(&valid_new);

            let is_case_only = old_name.eq_ignore_ascii_case(&valid_new);

            // Collision check: if new_path exists and is not just a case-only rename of the existing directory
            if new_path.exists() && !is_case_only {
                ui.set_rename_folder_error_message(
                    format!("A folder named '{}' already exists.", valid_new).into(),
                );
                return;
            }

            if old_path.exists() {
                if let Some(parent) = new_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                if is_case_only {
                    // Windows NTFS is case-insensitive. A direct rename to different case can fail.
                    // Rename via a temporary intermediate directory.
                    let temp_name = format!("{}_nv_temp_{}", old_name, Uuid::new_v4());
                    let temp_path = current_vault.join(&temp_name);
                    if let Err(e) = std::fs::rename(&old_path, &temp_path) {
                        ui.set_rename_folder_error_message(
                            format!("Failed to rename folder: {}", e).into(),
                        );
                        return;
                    }
                    if let Err(e) = std::fs::rename(&temp_path, &new_path) {
                        let _ = std::fs::rename(&temp_path, &old_path);
                        ui.set_rename_folder_error_message(
                            format!("Failed to rename folder: {}", e).into(),
                        );
                        return;
                    }
                } else {
                    if let Err(e) = std::fs::rename(&old_path, &new_path) {
                        ui.set_rename_folder_error_message(
                            format!("Failed to rename folder: {}", e).into(),
                        );
                        eprintln!(
                            "Failed to rename directory from {:?} to {:?}: {}",
                            old_path, new_path, e
                        );
                        return;
                    }
                }
            }

            ui.set_rename_folder_error_message("".into());
            ui.set_show_rename_folder_modal(false);

            // Update notes in metadata store
            {
                let mut store = metadata_store.lock().unwrap();
                for meta in store.values_mut() {
                    if meta.category == old_name {
                        meta.category = valid_new.clone();
                        if let Ok(rel) = meta.file_path.strip_prefix(&old_path) {
                            meta.file_path = new_path.join(rel);
                        }
                    } else if meta.category.starts_with(&format!("{}/", old_name)) {
                        let sub = &meta.category[old_name.len() + 1..];
                        meta.category = format!("{}/{}", valid_new, sub);
                        if let Ok(rel) = meta.file_path.strip_prefix(&old_path) {
                            meta.file_path = new_path.join(rel);
                        }
                    }
                }
            }

            // Update active_folder
            {
                let mut act = active_folder.lock().unwrap();
                if *act == old_name {
                    *act = valid_new.clone();
                } else if act.starts_with(&format!("{}/", old_name)) {
                    let sub = &act[old_name.len() + 1..];
                    *act = format!("{}/{}", valid_new, sub);
                }
            }

            if ui.get_note_category() == old_name {
                ui.set_note_category(valid_new.as_str().into());
            }
            if ui.get_active_folder() == old_name {
                ui.set_active_folder(valid_new.as_str().into());
            }

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Renamed folder from '{}' to '{}'", old_name, valid_new);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Folder Deletion
    // -------------------------------------------------------------
    main_window.on_delete_folder_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |folder_name| {
            let Some(ui) = window_weak.upgrade() else { return };
            let folder_name = folder_name.trim().to_string();

            if folder_name.is_empty() {
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();
            let target_dir = current_vault.join(&folder_name);
            if target_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&target_dir) {
                    eprintln!("Failed to recursively delete folder {:?}: {}", target_dir, e);
                }
            }

            let prefix = format!("{}/", folder_name);
            let active_id = ui.get_active_note_id().to_string();
            let mut active_note_deleted = false;

            {
                let mut store = metadata_store.lock().unwrap();
                store.retain(|id, meta| {
                    let in_folder = meta.category == folder_name || meta.category.starts_with(&prefix);
                    if in_folder && *id == active_id {
                        active_note_deleted = true;
                    }
                    !in_folder
                });
            }

            let is_active = {
                let act = active_folder.lock().unwrap();
                *act == folder_name || act.starts_with(&prefix)
            };

            if is_active {
                let mut remaining = std::collections::BTreeSet::new();
                for entry in WalkDir::new(&current_vault)
                    .min_depth(1)
                    .max_depth(1)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let p = entry.path();
                    if p.is_dir() && p != current_vault {
                        if let Some(file_name) = p.file_name() {
                            let name = file_name.to_string_lossy();
                            if !name.is_empty() && !name.starts_with('.') && name != folder_name {
                                remaining.insert(name.to_string());
                            }
                        }
                    }
                }
                {
                    let store = metadata_store.lock().unwrap();
                    for meta in store.values() {
                        if !meta.category.is_empty() && meta.category != folder_name && !meta.category.starts_with(&prefix) {
                            remaining.insert(meta.category.clone());
                        }
                    }
                }

                let next_folder = remaining.into_iter().next().unwrap_or_default();
                *active_folder.lock().unwrap() = next_folder.clone();
                ui.set_active_folder(next_folder.clone().into());
                ui.set_note_category(next_folder.into());
            }

            if active_note_deleted {
                ui.set_active_note_id("".into());
                ui.set_note_title("".into());
                ui.set_note_content("".into());
                ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_note_date("".into());
            }

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Deleted folder '{}' and its encrypted notes", folder_name);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Note Move to Another Folder
    // -------------------------------------------------------------
    main_window.on_move_note_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |note_id, target_folder| {
            let Some(ui) = window_weak.upgrade() else { return };
            let note_id = note_id.trim().to_string();
            let target_folder = target_folder.trim().to_string();

            if note_id.is_empty() || target_folder.is_empty() {
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();
            let target_dir = if target_folder == "General" {
                current_vault.join("General")
            } else {
                current_vault.join(&target_folder)
            };
            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                eprintln!("Failed to create folder {:?}: {}", target_dir, e);
                return;
            }

            let new_path = target_dir.join(format!("{}.vault", note_id));

            {
                let mut store = metadata_store.lock().unwrap();
                if let Some(meta) = store.get_mut(&note_id) {
                    let old_path = meta.file_path.clone();
                    if old_path != new_path && old_path.exists() {
                        if let Err(e) = std::fs::rename(&old_path, &new_path) {
                            eprintln!(
                                "Failed to move note file from {:?} to {:?}: {}",
                                old_path, new_path, e
                            );
                            if std::fs::copy(&old_path, &new_path).is_ok() {
                                let _ = std::fs::remove_file(&old_path);
                            } else {
                                return;
                            }
                        }
                    }
                    meta.category = target_folder.clone();
                    meta.file_path = new_path.clone();
                }
            }

            if ui.get_active_note_id() == note_id {
                ui.set_note_category(target_folder.as_str().into());
            }

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Moved note {} to folder '{}'", note_id, target_folder);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Note Deletion
    // -------------------------------------------------------------
    main_window.on_delete_note_confirmed({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |note_id| {
            let Some(ui) = window_weak.upgrade() else { return };
            let note_id = note_id.trim().to_string();

            if note_id.is_empty() {
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();

            let removed_meta = {
                let mut store = metadata_store.lock().unwrap();
                store.remove(&note_id)
            };

            if let Some(meta) = removed_meta {
                if meta.file_path.exists() {
                    if let Err(e) = std::fs::remove_file(&meta.file_path) {
                        eprintln!("Failed to delete note file at {:?}: {}", meta.file_path, e);
                    }
                }
            }

            if ui.get_active_note_id() == note_id {
                ui.set_active_note_id("".into());
                ui.set_note_title("".into());
                ui.set_note_content("".into());
                ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_note_date("".into());
            }

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Deleted note {}", note_id);
        }
    });

    // -------------------------------------------------------------
    // Callback: Remove Tag Requested from Chip
    // -------------------------------------------------------------
    main_window.on_remove_tag_requested({
        let window_weak = window_weak.clone();

        move |idx| {
            let Some(ui) = window_weak.upgrade() else { return };
            if idx < 0 {
                return;
            }
            let current_tags = ui.get_note_tags();
            let mut tags_vec: Vec<slint::SharedString> = current_tags.iter().collect();
            let index = idx as usize;
            if index < tags_vec.len() {
                tags_vec.remove(index);
                let new_model: slint::ModelRc<slint::SharedString> =
                    std::rc::Rc::new(slint::VecModel::from(tags_vec)).into();
                ui.set_note_tags(new_model);
                ui.set_has_unsaved_changes(true);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Open Add Tag Modal Requested
    // -------------------------------------------------------------
    main_window.on_open_add_tag_requested({
        let window_weak = window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let store = metadata_store.lock().unwrap();
            let current_tags: Vec<String> = ui
                .get_note_tags()
                .iter()
                .map(|s| s.to_string())
                .collect();
            let suggestions = get_suggested_tags(&store, &current_tags, "");
            let slint_suggestions: Vec<TagSuggestion> = suggestions
                .into_iter()
                .map(|s| TagSuggestion {
                    name: s.name.into(),
                    count: s.count as i32,
                })
                .collect();
            ui.set_suggested_tags(std::rc::Rc::new(slint::VecModel::from(slint_suggestions)).into());
            ui.set_new_tag_name("".into());
            ui.set_add_tag_selected_index(-1);
            ui.set_show_add_tag_modal(true);
        }
    });

    // -------------------------------------------------------------
    // Callback: Tag Search Changed while typing in Add Tag Modal
    // -------------------------------------------------------------
    main_window.on_tag_search_changed({
        let window_weak = window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);

        move |query| {
            let Some(ui) = window_weak.upgrade() else { return };
            let store = metadata_store.lock().unwrap();
            let current_tags: Vec<String> = ui
                .get_note_tags()
                .iter()
                .map(|s| s.to_string())
                .collect();
            let suggestions = get_suggested_tags(&store, &current_tags, query.as_str());
            let slint_suggestions: Vec<TagSuggestion> = suggestions
                .into_iter()
                .map(|s| TagSuggestion {
                    name: s.name.into(),
                    count: s.count as i32,
                })
                .collect();
            ui.set_suggested_tags(std::rc::Rc::new(slint::VecModel::from(slint_suggestions)).into());
            ui.set_add_tag_selected_index(-1);
        }
    });

    // -------------------------------------------------------------
    // Callback: Add Tag Confirmed
    // -------------------------------------------------------------
    main_window.on_add_tag_confirmed({
        let window_weak = window_weak.clone();

        move |new_tag| {
            let Some(ui) = window_weak.upgrade() else { return };
            let tag_str = new_tag.trim().to_string();
            if tag_str.is_empty() {
                return;
            }
            let current_tags = ui.get_note_tags();
            let mut tags_vec: Vec<slint::SharedString> = current_tags.iter().collect();
            if !tags_vec.iter().any(|t| t.as_str() == tag_str) {
                tags_vec.push(tag_str.into());
                let new_model: slint::ModelRc<slint::SharedString> =
                    std::rc::Rc::new(slint::VecModel::from(tags_vec)).into();
                ui.set_note_tags(new_model);
                ui.set_has_unsaved_changes(true);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Note Editor Setting Changed (Persist to config.json)
    // -------------------------------------------------------------
    main_window.on_editor_setting_changed({
        let app_config = Arc::clone(&app_config);
        move |key, value| {
            let mut cfg = app_config.lock().unwrap();
            match key.as_str() {
                "markdown_mode" => {
                    cfg.editor_markdown_mode = value == "true";
                }
                "line_numbers" => {
                    cfg.editor_show_line_numbers = value == "true";
                }
                "line_wrap" => {
                    cfg.editor_line_wrap = value == "true";
                }
                "highlight_line" => {
                    cfg.editor_highlight_current_line = value == "true";
                }
                "font_size" => {
                    if let Ok(fs) = value.parse::<u32>() {
                        cfg.editor_font_size = fs;
                    }
                }
                _ => {}
            }
            if let Err(e) = cfg.save() {
                eprintln!("[Config] Failed to save editor setting: {}", e);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Column Width Changed (Persist pane widths to config.json)
    // -------------------------------------------------------------
    main_window.on_column_width_changed({
        let app_config = Arc::clone(&app_config);
        move |pane, width_px| {
            let w = width_px.round() as u32;
            let mut cfg = app_config.lock().unwrap();
            match pane.as_str() {
                "folder" => cfg.folder_pane_width = w,
                "notes"  => cfg.notes_pane_width = w,
                _ => {}
            }
            if let Err(e) = cfg.save() {
                eprintln!("[Config] Failed to save column width: {}", e);
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Toggle Markdown Mode Requested
    // -------------------------------------------------------------
    main_window.on_toggle_markdown_mode_requested({
        let window_weak = window_weak.clone();
        move |is_markdown| {
            let Some(ui) = window_weak.upgrade() else { return };
            if is_markdown {
                let content = ui.get_note_content().to_string();
                let blocks = parse_markdown_into_blocks(&content);
                ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
                ui.set_note_markdown_rendered(render_markdown_styled(&content));
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Link Clicked in Markdown Preview
    // -------------------------------------------------------------
    main_window.on_link_clicked({
        move |url| {
            let url_str = url.to_string();
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                #[cfg(windows)]
                {
                    let _ = std::process::Command::new("cmd")
                        .args(["/C", "start", "", &url_str])
                        .spawn();
                }
                #[cfg(not(windows))]
                {
                    let _ = std::process::Command::new("xdg-open")
                        .arg(&url_str)
                        .spawn();
                }
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Note Content Edited (Update Line Numbers & Markdown)
    // -------------------------------------------------------------
    main_window.on_note_content_edited({
        let window_weak = window_weak.clone();
        move |content| {
            let Some(ui) = window_weak.upgrade() else { return };
            let count = if content.is_empty() {
                1
            } else {
                content.split('\n').count()
            };
            let current_text = ui.get_line_numbers_text();
            let current_count = if current_text.is_empty() {
                1
            } else {
                current_text.split('\n').count()
            };
            if count != current_count {
                ui.set_line_numbers_text(format_line_numbers(&content).into());
            }
            if ui.get_editor_markdown_mode() {
                let blocks = parse_markdown_into_blocks(&content);
                ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
                ui.set_note_markdown_rendered(render_markdown_styled(&content));
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Copy Text to Clipboard (Code blocks, note markdown)
    // -------------------------------------------------------------
    main_window.on_copy_text_to_clipboard({
        move |text| {
            let text_str = text.to_string();
            if !text_str.is_empty() {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let _ = clipboard.set_text(&text_str);
                }
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Export Decrypted Note as JSON
    // -------------------------------------------------------------
    main_window.on_export_note_json_requested({
        let window_weak = window_weak.clone();
        let session_password = Arc::clone(&session_password);
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let is_unlocked = session_password.lock().unwrap().is_some();
            if !is_unlocked {
                ui.set_vault_status_text("Error: Vault is locked. Unlock before exporting.".into());
                return;
            }

            let active_id = ui.get_active_note_id().to_string();
            if active_id.is_empty() || active_id == "new" {
                ui.set_vault_status_text("No active saved note to export.".into());
                return;
            }

            let title = ui.get_note_title().to_string();
            let content = ui.get_note_content().to_string();
            let category = ui.get_note_category().to_string();
            let tags: Vec<String> = ui
                .get_note_tags()
                .iter()
                .map(|s| s.to_string())
                .collect();
            let date = ui.get_note_date().to_string();

            let safe_name = sanitize_filename(&title, &active_id);
            let default_filename = format!("{}.json", safe_name);

            let picked_path = rfd::FileDialog::new()
                .set_title("Export Note as JSON")
                .set_file_name(&default_filename)
                .add_filter("JSON Files", &["json"])
                .save_file();

            if let Some(path) = picked_path {
                match format_decrypted_json_export(&active_id, &title, &category, &tags, &date, &content) {
                    Ok(json_str) => {
                        if let Err(e) = std::fs::write(&path, json_str) {
                            ui.set_vault_status_text(format!("Export failed: {}", e).into());
                        } else {
                            ui.set_vault_status_text(format!("Exported note as JSON to {}", path.display()).into());
                        }
                    }
                    Err(e) => {
                        ui.set_vault_status_text(format!("Export serialization error: {}", e).into());
                    }
                }
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Export Decrypted Note as TXT
    // -------------------------------------------------------------
    main_window.on_export_note_txt_requested({
        let window_weak = window_weak.clone();
        let session_password = Arc::clone(&session_password);
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            let is_unlocked = session_password.lock().unwrap().is_some();
            if !is_unlocked {
                ui.set_vault_status_text("Error: Vault is locked. Unlock before exporting.".into());
                return;
            }

            let active_id = ui.get_active_note_id().to_string();
            if active_id.is_empty() || active_id == "new" {
                ui.set_vault_status_text("No active saved note to export.".into());
                return;
            }

            let title = ui.get_note_title().to_string();
            let content = ui.get_note_content().to_string();
            let category = ui.get_note_category().to_string();
            let tags: Vec<String> = ui
                .get_note_tags()
                .iter()
                .map(|s| s.to_string())
                .collect();
            let date = ui.get_note_date().to_string();

            let safe_name = sanitize_filename(&title, &active_id);
            let default_filename = format!("{}.txt", safe_name);

            let picked_path = rfd::FileDialog::new()
                .set_title("Export Note as TXT")
                .set_file_name(&default_filename)
                .add_filter("Text Files", &["txt"])
                .save_file();

            if let Some(path) = picked_path {
                let txt_content = format_decrypted_txt_export(&title, &category, &tags, &date, &content);
                if let Err(e) = std::fs::write(&path, txt_content) {
                    ui.set_vault_status_text(format!("Export failed: {}", e).into());
                } else {
                    ui.set_vault_status_text(format!("Exported note as TXT to {}", path.display()).into());
                }
            }
        }
    });

    // Keep tray icon and timer alive alongside Slint event loop
    let _tray_icon = tray_icon_handle;
    let _tray_timer = tray_timer;

    // Run Slint GUI event loop until explicit quit (persists when windows are hidden to system tray)
    if !should_start_minimized {
        main_window.show()?;
    }
    slint::run_event_loop_until_quit()?;
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

