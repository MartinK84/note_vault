use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use note_vault::config::AppConfig;
use note_vault::{load_note_decrypted, save_note_encrypted, Note};
use rayon::prelude::*;
use slint::Model;
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

slint::include_modules!();

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

/// Helper to extract date components (year, month, day, hours, minutes, seconds) from Unix timestamp.
fn parse_unix_timestamp(ts: i64) -> (u32, u32, u32, u64, u64, u64) {
    if ts <= 0 {
        return (1970, 1, 1, 0, 0, 0);
    }
    let secs = ts as u64;
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let mut year = 1970;
    let mut day_count = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if day_count < days_in_year {
            break;
        }
        day_count -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for &d in &month_days {
        if day_count < d {
            break;
        }
        day_count -= d;
        month += 1;
    }
    let day = (day_count + 1) as u32;
    (year as u32, month, day, hours, minutes, seconds)
}

/// Formats a Unix timestamp (seconds) into a readable UTC date string.
fn format_unix_timestamp(ts: i64) -> String {
    if ts <= 0 {
        return "Unknown".to_string();
    }
    let (year, month, day, hours, minutes, seconds) = parse_unix_timestamp(ts);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", year, month, day, hours, minutes, seconds)
}

/// Formats a Unix timestamp (seconds) into a compact date string (YYYY-MM-DD) for note cards.
fn format_unix_date(ts: i64) -> String {
    if ts <= 0 {
        return "Unknown".to_string();
    }
    let (year, month, day, _, _, _) = parse_unix_timestamp(ts);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// Sanitizes a note title to produce a safe, filesystem-compatible filename.
/// Replaces illegal characters (`/`, `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`, and control characters) with `_`.
/// Trims whitespace and leading/trailing dots.
/// If the sanitized result is empty, falls back to `fallback_id`.
pub fn sanitize_filename(title: &str, fallback_id: &str) -> String {
    const ILLEGAL_CHARS: [char; 10] = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    let sanitized: String = title
        .chars()
        .map(|c| if ILLEGAL_CHARS.contains(&c) || c.is_control() { '_' } else { c })
        .collect();

    let trimmed = sanitized.trim().trim_matches('.');
    if trimmed.is_empty() {
        return fallback_id.to_string();
    }

    // Guard against Windows-reserved filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    let upper = trimmed.to_ascii_uppercase();
    const RESERVED_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED_NAMES.contains(&upper.as_str()) {
        format!("{}_{}", trimmed, fallback_id)
    } else {
        trimmed.to_string()
    }
}

/// Formats a note into a Markdown document with YAML frontmatter.
/// Contains `title`, `category`, `tags` (as a JSON/YAML array), and `date`.
pub fn format_markdown_export(note: &Note, category: &str, date_str: &str) -> String {
    let title_escaped = serde_json::to_string(&note.title).unwrap_or_else(|_| "\"\"".to_string());
    let category_escaped = serde_json::to_string(category).unwrap_or_else(|_| "\"\"".to_string());
    let tags_array = serde_json::to_string(&note.tags).unwrap_or_else(|_| "[]".to_string());
    let date_escaped = serde_json::to_string(date_str).unwrap_or_else(|_| "\"\"".to_string());

    format!(
        "---\ntitle: {}\ncategory: {}\ntags: {}\ndate: {}\n---\n\n{}",
        title_escaped, category_escaped, tags_array, date_escaped, note.content
    )
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
) {
    if note_id.is_empty() {
        return;
    }

    let (meta, password_opt) = {
        let store = metadata_store.lock().unwrap();
        let meta = store.get(note_id).cloned();
        let session = session_password.lock().unwrap();
        (meta, session.clone())
    };

    if let Some(meta) = meta {
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
            match load_note_decrypted(&password, &meta.file_path) {
                Ok(mut note) => {
                    ui.set_note_content(note.content.as_str().into());
                    note.zeroize();
                }
                Err(e) => {
                    eprintln!("Error decrypting note at {:?}: {}", meta.file_path, e);
                    ui.set_note_content(
                        format!("[Error: Failed to decrypt note: {}]", e).into(),
                    );
                }
            }
        } else {
            eprintln!("Error: Cannot decrypt note, vault session is locked.");
            ui.set_note_content("".into());
        }

        ui.set_has_unsaved_changes(false);
    }
}

/// Reloads and re-decrypts all notes in the vault,
/// respecting `use_multithreading` (parallel with Rayon or sequential).
fn trigger_vault_reload(
    password: Zeroizing<String>,
    window_weak: slint::Weak<MainWindow>,
    vault_dir: Arc<Mutex<PathBuf>>,
    meta_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    session_pass: Arc<Mutex<Option<Zeroizing<String>>>>,
    a_folder: Arc<Mutex<String>>,
    s_query: Arc<Mutex<String>>,
    use_multi: Arc<AtomicBool>,
    is_initial_unlock: bool,
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
            return;
        }

        let completed_count = Arc::new(AtomicUsize::new(0));
        let decrypt_failed = Arc::new(AtomicBool::new(false));

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

            let item = match load_note_decrypted(&password, &file_path) {
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
            }
            let weak_ui = weak.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_ui.upgrade() {
                    ui.set_is_loading(false);
                    if is_initial_unlock {
                        ui.set_unlock_error_message(
                            "Decryption failed: invalid master password or corrupted note file.".into(),
                        );
                    } else {
                        ui.set_vault_status_text("Error: Decryption failed during refresh.".into());
                    }
                }
            })
            .ok();
            return;
        }

        {
            let mut store = meta_store.lock().unwrap();
            store.clear();
            store.extend(decrypted_items);
        }

        *session_pass.lock().unwrap() = Some(password);

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
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = AppConfig::load();

    // Determine vault path (CLI overrides config temporarily)
    let _is_cli_override = args.vault_path.is_some();
    let initial_vault_path_str = if let Some(ref cli_p) = args.vault_path {
        cli_p.to_string_lossy().to_string()
    } else {
        config.vault_path.clone()
    };

    let initial_vault_path = PathBuf::from(&initial_vault_path_str);

    // Shared state
    let app_config = Arc::new(Mutex::new(config.clone()));
    let vault_path = Arc::new(Mutex::new(initial_vault_path.clone()));
    let use_multithreading = Arc::new(AtomicBool::new(config.use_multithreading));
    let session_password: Arc<Mutex<Option<Zeroizing<String>>>> = Arc::new(Mutex::new(None));
    let metadata_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_folder: Arc<Mutex<String>> = Arc::new(Mutex::new("General".to_string()));
    let search_query: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Slint Window
    let main_window = MainWindow::new()?;
    main_window.window().set_size(slint::LogicalSize::new(1534.0, 740.0));
    let window_weak = main_window.as_weak();

    // Initialize Theme
    let is_dark = config.theme == "dark";
    main_window.global::<Theme>().set_is_dark(is_dark);
    main_window.set_settings_theme(if is_dark { "dark".into() } else { "light".into() });

    let theme_options_model: slint::ModelRc<slint::SharedString> =
        std::rc::Rc::new(slint::VecModel::from(vec!["dark".into(), "light".into()])).into();
    main_window.set_theme_options(theme_options_model);

    // Initialize Settings state
    main_window.set_settings_vault_path(initial_vault_path_str.as_str().into());
    main_window.set_settings_use_multithreading(config.use_multithreading);

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

    main_window.set_active_folder("General".into());
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
                    match load_note_decrypted(&password, &meta.file_path) {
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
            let cur_path = vault_path.lock().unwrap().to_string_lossy().to_string();
            let cur_multi = use_multithreading.load(Ordering::Relaxed);
            let cur_theme = app_config.lock().unwrap().theme.clone();
            let is_dark = cur_theme == "dark";

            ui.set_settings_vault_path(cur_path.into());
            ui.set_settings_use_multithreading(cur_multi);
            ui.global::<Theme>().set_is_dark(is_dark);
            ui.set_settings_theme(cur_theme.into());
            ui.set_settings_cur_pwd("".into());
            ui.set_settings_new_pwd("".into());
            ui.set_settings_confirm_pwd("".into());
            ui.set_password_change_status("".into());
            ui.set_password_change_success(false);
            ui.set_is_reencrypting(false);
            ui.set_show_settings_modal(true);
        }
    });

    // -------------------------------------------------------------
    // Callback: Save Settings Requested
    // -------------------------------------------------------------
    main_window.on_save_settings_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let use_multithreading = Arc::clone(&use_multithreading);
        let app_config = Arc::clone(&app_config);
        let session_password = Arc::clone(&session_password);
        let metadata_store = Arc::clone(&metadata_store);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |new_path_str, new_multi, new_theme_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            let new_path_clean = new_path_str.trim().to_string();
            let new_theme_clean = new_theme_str.trim().to_string();

            // 1. Update and save config.json
            {
                let mut cfg = app_config.lock().unwrap();
                cfg.vault_path = new_path_clean.clone();
                cfg.use_multithreading = new_multi;
                cfg.theme = new_theme_clean.clone();
                if let Err(e) = cfg.save() {
                    eprintln!("Failed to save config.json: {}", e);
                }
            }

            // 2. Apply theme dynamically
            ui.global::<Theme>().set_is_dark(new_theme_clean == "dark");

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
                metadata_store.lock().unwrap().clear();
                *active_folder.lock().unwrap() = "General".to_string();
                *search_query.lock().unwrap() = String::new();

                ui.set_folders(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_current_notes(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_active_note_id("".into());
                ui.set_note_title("".into());
                ui.set_active_folder("General".into());
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
        move |theme_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            ui.global::<Theme>().set_is_dark(theme_str.trim() == "dark");
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

            thread::spawn(move || {
                let weak_progress = weak.clone();
                let res = note_vault::reencrypt_vault_atomic(
                    &v_dir,
                    &current_pwd,
                    &new_pwd,
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
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);

        move |raw_password| {
            let Some(ui) = window_weak.upgrade() else { return };

            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                ui.set_unlock_error_message("Please enter a master password.".into());
                return;
            }

            ui.set_unlock_password("".into());
            ui.set_unlock_error_message("".into());

            trigger_vault_reload(
                password,
                window_weak.clone(),
                Arc::clone(&vault_path),
                Arc::clone(&metadata_store),
                Arc::clone(&session_password),
                Arc::clone(&active_folder),
                Arc::clone(&search_query),
                Arc::clone(&use_multithreading),
                true,
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

        move |note_id| {
            let Some(ui) = window_weak.upgrade() else { return };

            if ui.get_has_unsaved_changes() {
                ui.set_pending_action_type("select_note".into());
                ui.set_pending_action_payload(note_id);
                ui.set_show_unsaved_warning(true);
            } else {
                load_note_into_ui(&ui, note_id.as_str(), &metadata_store, &session_password);
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
                    ui.set_has_unsaved_changes(false);
                }
                "new_folder" => {
                    ui.set_new_folder_name("".into());
                    ui.set_show_folder_modal(true);
                }
                "rescan_vault" => {
                    let password_opt = session_password.lock().unwrap().clone();
                    if let Some(password) = password_opt {
                        trigger_vault_reload(
                            password,
                            window_weak.clone(),
                            Arc::clone(&vault_path),
                            Arc::clone(&metadata_store),
                            Arc::clone(&session_password),
                            Arc::clone(&active_folder),
                            Arc::clone(&search_query),
                            Arc::clone(&use_multithreading),
                            false,
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
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);
        let use_multithreading = Arc::clone(&use_multithreading);

        move || {
            let password_opt = session_password.lock().unwrap().clone();
            if let Some(password) = password_opt {
                trigger_vault_reload(
                    password,
                    window_weak.clone(),
                    Arc::clone(&vault_path),
                    Arc::clone(&metadata_store),
                    Arc::clone(&session_password),
                    Arc::clone(&active_folder),
                    Arc::clone(&search_query),
                    Arc::clone(&use_multithreading),
                    false,
                );
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Lock Vault
    // -------------------------------------------------------------
    main_window.on_lock_vault({
        let window_weak = window_weak.clone();
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            println!("[NoteVault] Vault locked.");

            *session_password.lock().unwrap() = None;
            metadata_store.lock().unwrap().clear();
            *active_folder.lock().unwrap() = "General".to_string();
            *search_query.lock().unwrap() = String::new();

            ui.set_folders(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_current_notes(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_active_note_id("".into());
            ui.set_note_title("".into());
            ui.set_active_folder("General".into());
            ui.set_note_category("General".into());
            ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_date("".into());
            ui.set_note_content("".into());
            ui.set_search_query("".into());
            ui.set_unlock_password("".into());
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
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

        move |title, content, category| {
            let Some(ui) = window_weak.upgrade() else { return };

            let current_vault = vault_path.lock().unwrap().clone();

            let password = {
                let session = session_password.lock().unwrap();
                match session.as_ref() {
                    Some(p) => p.clone(),
                    None => {
                        eprintln!("Error: Cannot save note, vault session is locked.");
                        return;
                    }
                }
            };

            let active_id = ui.get_active_note_id().to_string();
            let is_new = active_id.is_empty() || active_id == "new";

            let mut target_category = category.trim().to_string();
            if target_category.is_empty() {
                target_category = active_folder.lock().unwrap().clone();
            }
            if target_category == "*All Notes*" || target_category.is_empty() {
                target_category = "General".to_string();
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
                    title.to_string(),
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
                    load_note_decrypted(&password, &existing_file_path).ok()
                } else {
                    None
                };

                let note_to_save = match loaded_note {
                    Some(mut existing) => {
                        existing.title = title.to_string();
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
                            title: title.to_string(),
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

            if let Err(e) = save_note_encrypted(&note, &password, &target_path) {
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
                        title: title.to_string(),
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
            ui.set_note_date(formatted_date.into());
            ui.set_note_category(target_category.clone().into());
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
            let name_clean = name.trim();

            if name_clean.is_empty() {
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();
            let target_dir = current_vault.join(name_clean);
            let full_folder_name = name_clean.to_string();

            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                eprintln!("Failed to create folder at {:?}: {}", target_dir, e);
                return;
            }

            println!("[NoteVault] Created folder: {:?}", target_dir);
            *active_folder.lock().unwrap() = full_folder_name.clone();
            ui.set_active_folder(full_folder_name.clone().into());
            ui.set_note_category(full_folder_name.into());

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
            let new_name = new_name.trim().to_string();

            if old_name.is_empty() || new_name.is_empty() || old_name == new_name {
                return;
            }

            let current_vault = vault_path.lock().unwrap().clone();
            let old_path = current_vault.join(&old_name);
            let new_path = current_vault.join(&new_name);

            if old_path.exists() {
                if let Some(parent) = new_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::rename(&old_path, &new_path) {
                    eprintln!(
                        "Failed to rename directory from {:?} to {:?}: {}",
                        old_path, new_path, e
                    );
                    return;
                }
            }

            // Update notes in metadata store
            {
                let mut store = metadata_store.lock().unwrap();
                for meta in store.values_mut() {
                    if meta.category == old_name {
                        meta.category = new_name.clone();
                        if let Ok(rel) = meta.file_path.strip_prefix(&old_path) {
                            meta.file_path = new_path.join(rel);
                        }
                    } else if meta.category.starts_with(&format!("{}/", old_name)) {
                        let sub = &meta.category[old_name.len() + 1..];
                        meta.category = format!("{}/{}", new_name, sub);
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
                    *act = new_name.clone();
                } else if act.starts_with(&format!("{}/", old_name)) {
                    let sub = &act[old_name.len() + 1..];
                    *act = format!("{}/{}", new_name, sub);
                }
            }

            if ui.get_note_category() == old_name {
                ui.set_note_category(new_name.as_str().into());
            }
            if ui.get_active_folder() == old_name {
                ui.set_active_folder(new_name.as_str().into());
            }

            refresh_models(&ui, &current_vault, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Renamed folder from '{}' to '{}'", old_name, new_name);
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

    // Run Slint GUI event loop
    main_window.run()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename_basic() {
        assert_eq!(sanitize_filename("Simple Note Title", "fallback-id"), "Simple Note Title");
    }

    #[test]
    fn test_sanitize_filename_illegal_characters() {
        assert_eq!(
            sanitize_filename("Note/With\\Illegal:Chars*?\"<>|Test", "fallback-id"),
            "Note_With_Illegal_Chars______Test"
        );
    }

    #[test]
    fn test_sanitize_filename_empty_fallback() {
        assert_eq!(sanitize_filename("", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("   ", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("....", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("/:*?", "fallback-uuid-1234"), "____");
    }

    #[test]
    fn test_sanitize_filename_windows_reserved() {
        assert_eq!(sanitize_filename("CON", "id123"), "CON_id123");
        assert_eq!(sanitize_filename("prn", "id123"), "prn_id123");
        assert_eq!(sanitize_filename("aux", "id123"), "aux_id123");
        assert_eq!(sanitize_filename("nul", "id123"), "nul_id123");
    }

    #[test]
    fn test_format_markdown_export() {
        let note = Note::new(
            "Project Ideas: 2026",
            vec!["work".to_string(), "rust".to_string()],
            "# Heading\n\nThis is a secret note.",
        );
        let category = "Projects";
        let date_str = "2026-09-13 14:00:00 UTC";

        let md = format_markdown_export(&note, category, date_str);

        assert!(md.starts_with("---\n"));
        assert!(md.contains("title: \"Project Ideas: 2026\"\n"));
        assert!(md.contains("category: \"Projects\"\n"));
        assert!(md.contains("tags: [\"work\",\"rust\"]\n"));
        assert!(md.contains("date: \"2026-09-13 14:00:00 UTC\"\n"));
        assert!(md.contains("---\n\n# Heading\n\nThis is a secret note."));
    }
}
