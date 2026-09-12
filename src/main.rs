use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
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
    /// Path to the encrypted vault directory (mandatory)
    #[arg(short, long, value_name = "PATH")]
    vault_path: PathBuf,
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

/// Formats a Unix timestamp (seconds) into a readable UTC date string without external dependencies.
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

/// Re-builds and updates the Slint `folders`, `available_categories`, and `current_notes` models
/// for the active 3-pane layout, filtering by `active_folder` and `search_query`.
fn refresh_models(
    ui: &MainWindow,
    vault_path: &Path,
    metadata_store: &Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    active_folder: &Arc<Mutex<String>>,
    search_query: &Arc<Mutex<String>>,
) {
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

    // Also include any categories found in the in-memory metadata store
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
        if active.is_empty() || !folders_list.contains(&*active) {
            *active = folders_list.first().cloned().unwrap_or_default();
        }
        active.clone()
    };

    // 3. Filter notes in metadata_store: note.category == active_folder AND matches search_query
    let store = metadata_store.lock().unwrap();
    let query = search_query.lock().unwrap().trim().to_lowercase();

    let mut filtered_notes: Vec<(String, NoteMetaSummary)> = Vec::new();

    for (id, meta) in store.iter() {
        if meta.category != current_active_folder {
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

    // Sort notes by updated date (newest first)
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

    ui.set_vault_status_text(format!("{} total note(s)", total_notes).into());
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

/// Reloads and re-decrypts all notes in the vault in parallel using Rayon,
/// displaying the progress modal popup and refreshing models upon completion.
fn trigger_vault_reload(
    password: Zeroizing<String>,
    window_weak: slint::Weak<MainWindow>,
    vault_dir: Arc<PathBuf>,
    meta_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    session_pass: Arc<Mutex<Option<Zeroizing<String>>>>,
    a_folder: Arc<Mutex<String>>,
    s_query: Arc<Mutex<String>>,
    is_initial_unlock: bool,
) {
    let Some(ui) = window_weak.upgrade() else { return };

    // Reset UI state and show loading progress popup
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
        let mut vault_files: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(&*vault_dir)
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
            // Empty vault: store password in session, clear meta store and unlock
            *session_pass.lock().unwrap() = Some(password);
            meta_store.lock().unwrap().clear();

            let weak = weak.clone();
            let v_path = Arc::clone(&vault_dir);
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

        let decrypted_items: Vec<(String, NoteMetaSummary)> = vault_files
            .into_par_iter()
            .filter_map(|file_path| {
                if decrypt_failed.load(Ordering::Relaxed) {
                    return None;
                }

                // Determine category from relative subdirectory path (root level folder only)
                let category_name = match file_path
                    .parent()
                    .and_then(|p| p.strip_prefix(&*vault_dir).ok())
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
            })
            .collect();

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

        // Update persistent metadata store by completely replacing with reloaded notes
        {
            let mut store = meta_store.lock().unwrap();
            store.clear();
            store.extend(decrypted_items);
        }

        // Store verified master password in the active vault session
        *session_pass.lock().unwrap() = Some(password);

        // Dispatch UI model population to main event loop thread
        let weak_ui = weak.clone();
        let v_path = Arc::clone(&vault_dir);
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
    // Parse command line arguments with clap
    let args = Args::parse();

    // Verify vault path existence and canonicalize
    let vault_path = match std::fs::canonicalize(&args.vault_path) {
        Ok(p) => p,
        Err(_) => args.vault_path,
    };

    if !vault_path.exists() {
        eprintln!("Error: Specified vault path does not exist: {:?}", vault_path);
        std::process::exit(1);
    }
    if !vault_path.is_dir() {
        eprintln!("Error: Specified vault path is not a directory: {:?}", vault_path);
        std::process::exit(1);
    }

    let vault_path = Arc::new(vault_path);

    // Instantiate Slint MainWindow
    let main_window = MainWindow::new()?;
    let window_weak = main_window.as_weak();

    // Thread-safe vault session state holding the master password while unlocked
    let session_password: Arc<Mutex<Option<Zeroizing<String>>>> = Arc::new(Mutex::new(None));

    // In-memory store for note metadata (indexed by note UUID string)
    let metadata_store: Arc<Mutex<HashMap<String, NoteMetaSummary>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Active folder tracker (defaults to "General")
    let active_folder: Arc<Mutex<String>> = Arc::new(Mutex::new("General".to_string()));

    // Active search query tracker
    let search_query: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Set initial vault status indicator
    main_window.set_vault_status_text("Vault locked".into());
    main_window.set_active_folder("General".into());
    main_window.set_note_category("General".into());

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
            *active_folder.lock().unwrap() = folder.to_string();
            ui.set_active_folder(folder.clone());
            ui.set_note_category(folder);
            ui.set_active_note_id("".into());
            ui.set_note_title("".into());
            ui.set_note_content("".into());
            ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_date("".into());
            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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
            *search_query.lock().unwrap() = query.to_string();
            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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

        move |raw_password| {
            let Some(ui) = window_weak.upgrade() else { return };

            // Wrap password immediately in Zeroizing for memory safety
            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                ui.set_unlock_error_message("Please enter a master password.".into());
                return;
            }

            // Clear password field in UI to avoid plaintext lingering in memory
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
                true,
            );
        }
    });

    // -------------------------------------------------------------
    // Callback: Note Selection in Pane 2 (On-Demand Loading with Unsaved Changes Guard)
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
                    *active_folder.lock().unwrap() = payload.clone();
                    ui.set_active_folder(payload.clone().into());
                    ui.set_note_category(payload.into());
                    ui.set_active_note_id("".into());
                    ui.set_note_title("".into());
                    ui.set_note_content("".into());
                    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                    ui.set_note_date("".into());
                    refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
                }
                "new_note" => {
                    let cur_folder = active_folder.lock().unwrap().clone();
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
                            false,
                        );
                    }
                }
                _ => {}
            }
        }
    });

    // -------------------------------------------------------------
    // Callback: Rescan Vault Requested (Resync UI with disk)
    // -------------------------------------------------------------
    main_window.on_rescan_vault_requested({
        let window_weak = window_weak.clone();
        let vault_path = Arc::clone(&vault_path);
        let metadata_store = Arc::clone(&metadata_store);
        let session_password = Arc::clone(&session_password);
        let active_folder = Arc::clone(&active_folder);
        let search_query = Arc::clone(&search_query);

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
    // Callback: Save Note (Encrypted Persistence with Category)
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
            if target_category.is_empty() {
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
                vault_path.join("General")
            } else {
                vault_path.join(&target_category)
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
                            vault_path.join(&target_category).join(format!("{}.vault", active_id)),
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

            *active_folder.lock().unwrap() = target_category.clone();

            ui.set_active_note_id(saved_id.into());
            ui.set_note_date(formatted_date.into());
            ui.set_note_category(target_category.clone().into());
            ui.set_active_folder(target_category.into());
            ui.set_has_unsaved_changes(false);

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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
    // Callback: New Folder Requested (Open Modal)
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
    // Callback: Confirm Folder Creation (Root Level Only)
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

            // All folders are strictly on the root level
            let target_dir = vault_path.join(name_clean);
            let full_folder_name = name_clean.to_string();

            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                eprintln!("Failed to create folder at {:?}: {}", target_dir, e);
                return;
            }

            println!("[NoteVault] Created folder: {:?}", target_dir);
            *active_folder.lock().unwrap() = full_folder_name.clone();
            ui.set_active_folder(full_folder_name.clone().into());
            ui.set_note_category(full_folder_name.into());

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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

            let old_path = vault_path.join(&old_name);
            let new_path = vault_path.join(&new_name);

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

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
            println!("[NoteVault] Renamed folder from '{}' to '{}'", old_name, new_name);
        }
    });

    // -------------------------------------------------------------
    // Callback: Confirm Folder Deletion (Recursive)
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

            let target_dir = vault_path.join(&folder_name);
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
                // Find remaining folders
                let mut remaining = std::collections::BTreeSet::new();
                for entry in WalkDir::new(&*vault_path)
                    .min_depth(1)
                    .max_depth(1)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let p = entry.path();
                    if p.is_dir() && p != &*vault_path {
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

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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

            let target_dir = if target_folder == "General" {
                vault_path.join("General")
            } else {
                vault_path.join(&target_folder)
            };
            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                eprintln!("Failed to create folder {:?}: {}", target_dir, e);
                return;
            }

            let new_path = target_dir.join(format!("{}.vault", note_id));

            // Move the file and update metadata_store
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

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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

            refresh_models(&ui, &vault_path, &metadata_store, &active_folder, &search_query);
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

    // Run GUI event loop
    main_window.run()?;
    Ok(())
}
