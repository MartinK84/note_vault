use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use note_vault::{
    format_file_size, format_line_numbers, format_unix_date, get_canvas_path,
    is_attachment_file, is_canvas_file, list_note_attachment_files, load_attachment_metadata,
    load_canvas_decrypted, load_note_decrypted, parse_markdown_into_blocks,
    render_markdown_styled, AttachmentItem, MainWindow, NoteMetadata, NoteType, QuickSearchResult,
    QuickSearchWindow, CANVAS_EXTEND_STEP, DEFAULT_CANVAS_BG_HEX, DEFAULT_CANVAS_HEIGHT,
    DEFAULT_CANVAS_WIDTH,
};
use rayon::prelude::*;
use slint::ComponentHandle;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

use crate::gui::canvas::{
    clear_canvas_history, parse_hex_rgb, sync_canvas_full, update_canvas_history_ui,
};
use crate::gui::state::{ActiveCanvasState, AppState, NoteMetaSummary};

/// Filters notes in `metadata_store` by query (matching Title or Tags only),
/// sorts by `updated_at` descending (newest first), and returns a maximum of 5 items.
pub fn filter_quick_search_results(
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

    matching_notes.sort_by(|a, b| b.1.updated_at.cmp(&a.1.updated_at));

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
pub struct TagCount {
    pub name: String,
    pub count: usize,
}

/// Retrieves unique tags across all notes in `metadata_store`, excluding tags
/// already assigned to `current_note_tags` (case-insensitive).
pub fn get_suggested_tags(
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

/// Re-builds and updates the Slint `folders`, `available_categories`, and `current_notes` models.
pub fn refresh_models(
    ui: &MainWindow,
    vault_path: &Path,
    metadata_store: &Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    active_folder: &Arc<Mutex<String>>,
    search_query: &Arc<Mutex<String>>,
) {
    if !vault_path.exists() {
        return;
    }

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

    {
        let store = metadata_store.lock().unwrap();
        for meta in store.values() {
            if !meta.category.is_empty() {
                folder_set.insert(meta.category.clone());
            }
        }
    }

    let folders_list: Vec<String> = folder_set.into_iter().collect();

    let current_active_folder = {
        let mut active = active_folder.lock().unwrap();
        if *active != "*All Notes*"
            && (active.is_empty() || (!folders_list.is_empty() && !folders_list.contains(&*active)))
        {
            *active = folders_list
                .first()
                .cloned()
                .unwrap_or_else(|| "General".to_string());
        }
        active.clone()
    };

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
            note_type: match meta.note_type {
                NoteType::Canvas => "canvas".into(),
                NoteType::Text => "text".into(),
            },
        })
        .collect();

    let total_notes = store.len();
    drop(store);

    let folders_slint: Vec<slint::SharedString> = folders_list
        .iter()
        .cloned()
        .map(slint::SharedString::from)
        .collect();

    let folders_model: slint::ModelRc<slint::SharedString> =
        std::rc::Rc::new(slint::VecModel::from(folders_slint)).into();

    let current_notes_model: slint::ModelRc<NoteMetadata> =
        std::rc::Rc::new(slint::VecModel::from(note_models)).into();

    ui.set_folders(folders_model.clone());
    ui.set_available_categories(folders_model);
    ui.set_active_folder(current_active_folder.into());
    ui.set_current_notes(current_notes_model);

    ui.set_vault_status_text(format!("{} note(s)", total_notes).into());
}

/// Loads and updates note attachments into the UI editor pane.
pub fn update_attachments_in_ui(
    ui: &MainWindow,
    note_path: &Path,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) {
    let att_files = list_note_attachment_files(note_path);
    let mut items: Vec<AttachmentItem> = Vec::new();
    for path in &att_files {
        if let Ok(meta) = load_attachment_metadata(password, keyfile_bytes, path) {
            let path_str = path.to_string_lossy().to_string();
            let size_str = format_file_size(meta.file_size);
            let date_str = format_unix_date(meta.created_at);
            items.push(AttachmentItem {
                id: path_str.into(),
                file_name: meta.file_name.into(),
                file_size_formatted: size_str.into(),
                created_at_formatted: date_str.into(),
            });
        }
    }
    ui.set_attachment_count(items.len() as i32);
    let model: slint::ModelRc<AttachmentItem> =
        std::rc::Rc::new(slint::VecModel::from(items)).into();
    ui.set_note_attachments(model);
}

/// Locks the active vault session, zeroizing/clearing decrypted state from UI and memory.
pub fn lock_vault_session(
    ui: &MainWindow,
    quick_search_weak: &slint::Weak<QuickSearchWindow>,
    state: &AppState,
    status_text: &str,
) {
    *state.session_password.lock().unwrap() = None;
    *state.session_keyfile.lock().unwrap() = None;
    state.metadata_store.lock().unwrap().clear();
    *state.active_folder.lock().unwrap() = "*All Notes*".to_string();
    *state.search_query.lock().unwrap() = String::new();

    state.is_quick_search_open.store(false, Ordering::SeqCst);
    if let Some(qs) = quick_search_weak.upgrade() {
        let _ = qs.hide();
        qs.set_results(std::rc::Rc::new(slint::VecModel::default()).into());
    }

    ui.set_folders(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_current_notes(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_active_note_id("".into());
    ui.set_active_note_type("text".into());
    ui.set_canvas_image(slint::Image::default());
    {
        let mut cstate = state.canvas_state.lock().unwrap();
        cstate.pixmap = None;
        cstate.last_point = None;
        clear_canvas_history(&mut cstate);
        update_canvas_history_ui(ui, &cstate);
    }
    ui.set_note_title("".into());
    ui.set_active_folder("*All Notes*".into());
    ui.set_note_category("General".into());
    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_note_date("".into());
    ui.set_note_content("".into());
    ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_attachment_count(0);
    ui.set_search_query("".into());
    ui.set_unlock_password("".into());
    ui.set_show_keyfile_browse(false);
    ui.set_vault_status_text(status_text.into());
    ui.set_has_unsaved_changes(false);
    ui.set_show_unsaved_warning(false);
    ui.set_show_attachment_preview_modal(false);
    ui.set_preview_image(slint::Image::default());
    ui.set_preview_text("".into());
    ui.set_preview_attachment_id("".into());
    ui.set_is_locked(true);
}

/// Loads a decrypted note into the UI editor pane and resets `has_unsaved_changes` to false.
pub fn load_note_into_ui(
    ui: &MainWindow,
    note_id: &str,
    metadata_store: &Arc<Mutex<HashMap<String, NoteMetaSummary>>>,
    session_password: &Arc<Mutex<Option<Zeroizing<String>>>>,
    session_keyfile: &Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    canvas_state: &Arc<Mutex<ActiveCanvasState>>,
) {
    ui.set_show_attachment_preview_modal(false);
    ui.set_preview_image(slint::Image::default());
    ui.set_preview_text("".into());
    ui.set_preview_attachment_id("".into());

    if note_id.is_empty() {
        ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
        ui.set_attachment_count(0);
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
        ui.set_active_note_type(meta.note_type.as_str().into());

        if meta.note_type == NoteType::Canvas {
            ui.set_line_numbers_text("1".into());
            ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
            ui.set_note_markdown_rendered(slint::StyledText::default());
            ui.set_note_content("".into());

            let canvas_path = get_canvas_path(&meta.file_path);
            let mut pixmap_opt = None;
            if canvas_path.exists() {
                if let Some(password) = password_opt.as_ref() {
                    let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                    match load_canvas_decrypted(password, kf_bytes, &canvas_path) {
                        Ok(png_bytes) => match tiny_skia::Pixmap::decode_png(&png_bytes) {
                            Ok(pix) => pixmap_opt = Some(pix),
                            Err(e) => {
                                eprintln!("Failed to decode canvas PNG from {:?}: {}", canvas_path, e)
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to decrypt canvas at {:?}: {}", canvas_path, e)
                        }
                    }
                }
            }

            let pixmap = pixmap_opt.unwrap_or_else(|| {
                tiny_skia::Pixmap::new(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT)
                    .expect("failed to allocate canvas pixmap")
            });
            ui.set_canvas_width(pixmap.width() as f32);
            ui.set_canvas_height(pixmap.height() as f32);
            ui.set_canvas_zoom_percent(100);
            ui.set_canvas_zoom_text("100%".into());
            ui.set_canvas_pan_x(0.0);
            ui.set_canvas_pan_y(0.0);

            let mut bg_loaded = false;
            if let Some(password) = password_opt.as_ref() {
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                if let Ok(note) = load_note_decrypted(password, kf_bytes, &meta.file_path) {
                    let content_trimmed = note.content.trim();
                    if let Some((r, g, b)) = parse_hex_rgb(content_trimmed) {
                        ui.set_canvas_bg_color_hex(content_trimmed.into());
                        ui.set_canvas_bg_color(slint::Color::from_argb_u8(255, r, g, b));
                        bg_loaded = true;
                    }
                }
            }

            if !bg_loaded {
                ui.set_canvas_bg_color_hex(DEFAULT_CANVAS_BG_HEX.into());
                ui.set_canvas_bg_color(slint::Color::from_argb_u8(255, 255, 255, 255));
            }

            ui.set_canvas_tool("pen".into());
            let c = ui.get_canvas_color();
            let sw = ui.get_canvas_stroke_width();
            let ls = ui.get_canvas_line_style().to_string();
            {
                let mut cstate = canvas_state.lock().unwrap();
                cstate.pixmap = Some(pixmap);
                cstate.last_point = None;
                cstate.dash_offset = 0.0;
                cstate.tool = "pen".to_string();
                cstate.color =
                    tiny_skia::Color::from_rgba8(c.red(), c.green(), c.blue(), c.alpha());
                cstate.stroke_width = sw;
                cstate.line_style = ls;
                clear_canvas_history(&mut cstate);
                if let Some(img) = sync_canvas_full(&mut cstate) {
                    ui.set_canvas_image(img);
                }
                update_canvas_history_ui(ui, &cstate);
            }

            if let Some(password) = password_opt.as_ref() {
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                update_attachments_in_ui(ui, &meta.file_path, password, kf_bytes);
            } else {
                ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_attachment_count(0);
            }
        } else {
            {
                let mut cstate = canvas_state.lock().unwrap();
                cstate.pixmap = None;
                cstate.last_point = None;
                clear_canvas_history(&mut cstate);
                update_canvas_history_ui(ui, &cstate);
            }
            ui.set_canvas_image(slint::Image::default());

            if let Some(password) = password_opt {
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                match load_note_decrypted(&password, kf_bytes, &meta.file_path) {
                    Ok(mut note) => {
                        ui.set_line_numbers_text(format_line_numbers(&note.content).into());
                        let blocks = parse_markdown_into_blocks(&note.content);
                        ui.set_note_markdown_blocks(
                            std::rc::Rc::new(slint::VecModel::from(blocks)).into(),
                        );
                        ui.set_note_markdown_rendered(render_markdown_styled(&note.content));
                        ui.set_note_content(note.content.as_str().into());
                        note.zeroize();
                        update_attachments_in_ui(ui, &meta.file_path, &password, kf_bytes);
                    }
                    Err(e) => {
                        eprintln!("Error decrypting note at {:?}: {}", meta.file_path, e);
                        ui.set_line_numbers_text("1".into());
                        ui.set_note_markdown_blocks(
                            std::rc::Rc::new(slint::VecModel::default()).into(),
                        );
                        ui.set_note_markdown_rendered(slint::StyledText::default());
                        ui.set_note_content(
                            format!("[Error: Failed to decrypt note: {}]", e).into(),
                        );
                        ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
                        ui.set_attachment_count(0);
                    }
                }
            } else {
                eprintln!("Error: Cannot decrypt note, vault session is locked.");
                ui.set_line_numbers_text("1".into());
                ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_note_markdown_rendered(slint::StyledText::default());
                ui.set_note_content("".into());
                ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_attachment_count(0);
            }
        }

        ui.set_has_unsaved_changes(false);
    }
}

/// Initializes the editor pane with a clean, unsaved `"new"` text or canvas note.
pub fn init_blank_new_note_in_ui(
    ui: &MainWindow,
    note_type_str: &str,
    folder_to_use: &str,
    canvas_state: &Arc<Mutex<ActiveCanvasState>>,
) {
    ui.set_active_note_id("new".into());
    ui.set_note_category(folder_to_use.into());
    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_note_date("Just now".into());
    ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_attachment_count(0);
    ui.set_has_unsaved_changes(false);

    if note_type_str.eq_ignore_ascii_case("canvas") {
        ui.set_active_note_type("canvas".into());
        ui.set_note_title("Untitled Drawing".into());
        ui.set_note_content("".into());
        ui.set_editor_markdown_mode(false);
        ui.set_canvas_tool("pen".into());
        ui.set_canvas_zoom_percent(100);
        ui.set_canvas_zoom_text("100%".into());
        ui.set_canvas_pan_x(0.0);
        ui.set_canvas_pan_y(0.0);
        ui.set_canvas_width(DEFAULT_CANVAS_WIDTH as f32);
        ui.set_canvas_height(DEFAULT_CANVAS_HEIGHT as f32);
        ui.set_canvas_bg_color_hex(DEFAULT_CANVAS_BG_HEX.into());
        ui.set_canvas_bg_color(slint::Color::from_argb_u8(255, 255, 255, 255));

        let mut pixmap = tiny_skia::Pixmap::new(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT)
            .expect("failed to allocate canvas pixmap");
        pixmap.fill(tiny_skia::Color::TRANSPARENT);

        let c = ui.get_canvas_color();
        let sw = ui.get_canvas_stroke_width();
        let ls = ui.get_canvas_line_style().to_string();
        let mut cstate = canvas_state.lock().unwrap();
        cstate.pixmap = Some(pixmap);
        cstate.last_point = None;
        cstate.dash_offset = 0.0;
        cstate.tool = "pen".to_string();
        cstate.color = tiny_skia::Color::from_rgba8(c.red(), c.green(), c.blue(), c.alpha());
        cstate.stroke_width = sw;
        cstate.line_style = ls;
        clear_canvas_history(&mut cstate);
        if let Some(img) = sync_canvas_full(&mut cstate) {
            ui.set_canvas_image(img);
        }
        update_canvas_history_ui(ui, &cstate);
    } else {
        ui.set_active_note_type("text".into());
        ui.set_note_title("Untitled Note".into());
        ui.set_note_content("".into());
        ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::default()).into());
        ui.set_note_markdown_rendered(slint::StyledText::default());
        ui.set_editor_markdown_mode(false);
        ui.set_line_numbers_text("1".into());

        let mut cstate = canvas_state.lock().unwrap();
        cstate.pixmap = None;
        cstate.last_point = None;
        clear_canvas_history(&mut cstate);
        update_canvas_history_ui(ui, &cstate);
        ui.set_canvas_image(slint::Image::default());
    }
}

/// Reloads and re-decrypts all notes in the vault,
/// respecting `use_multithreading` (parallel with Rayon or sequential).
#[allow(clippy::too_many_arguments)]
pub fn trigger_vault_reload(
    password: Zeroizing<String>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
    window_weak: slint::Weak<MainWindow>,
    state: &AppState,
    is_initial_unlock: bool,
    on_complete: Option<Box<dyn FnOnce(bool) + Send + 'static>>,
) {
    let Some(ui) = window_weak.upgrade() else { return };

    ui.set_is_loading(true);
    ui.set_loading_progress(0.0);
    ui.set_loading_status_text("Discovering encrypted notes...".into());
    ui.set_active_note_id("".into());
    ui.set_active_note_type("text".into());
    ui.set_canvas_image(slint::Image::default());
    ui.set_note_title("".into());
    ui.set_note_content("".into());
    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_note_date("".into());
    ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
    ui.set_attachment_count(0);
    ui.set_has_unsaved_changes(false);

    let weak = window_weak.clone();
    let vault_dir = Arc::clone(&state.vault_path);
    let meta_store = Arc::clone(&state.metadata_store);
    let session_pass = Arc::clone(&state.session_password);
    let session_key = Arc::clone(&state.session_keyfile);
    let a_folder = Arc::clone(&state.active_folder);
    let s_query = Arc::clone(&state.search_query);
    let use_multi = Arc::clone(&state.use_multithreading);
    let _ = CANVAS_EXTEND_STEP;

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
                if !is_attachment_file(p) && !is_canvas_file(p) {
                    vault_files.push(p.to_path_buf());
                }
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
                    let updated_at = note.updated_at;

                    let summary = NoteMetaSummary {
                        title,
                        category: category_name,
                        tags,
                        updated_at,
                        file_path: file_path.clone(),
                        note_type: note.note_type,
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
                        ui.invoke_focus_unlock_password();
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
