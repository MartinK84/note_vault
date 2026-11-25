use std::time::{SystemTime, UNIX_EPOCH};

use arboard::Clipboard;
use note_vault::{
    format_line_numbers, format_unix_timestamp, get_canvas_path, load_note_decrypted,
    move_note_attachments, parse_markdown_into_blocks, render_markdown_styled,
    save_canvas_encrypted, save_note_encrypted, delete_note_attachments, MainWindow, Note,
    NoteType, TagSuggestion,
};
use slint::{ComponentHandle, Model};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::gui::canvas::{clear_canvas_history, update_canvas_history_ui};
use crate::gui::state::{AppState, NoteMetaSummary};
use crate::gui::vault_ops::{
    get_suggested_tags, init_blank_new_note_in_ui, load_note_into_ui, refresh_models,
    trigger_vault_reload,
};
use crate::gui::win_interop::open_url_safely;

pub fn register(main_window: &MainWindow, state: &AppState) {
    let window_weak = main_window.as_weak();

    main_window.on_search_changed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |query| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let v_path = state.vault_path.lock().unwrap().clone();
            *state.search_query.lock().unwrap() = query.to_string();
            refresh_models(
                &ui,
                &v_path,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
        }
    });

    main_window.on_select_note_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |note_id| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            if ui.get_has_unsaved_changes() {
                ui.set_pending_action_type("select_note".into());
                ui.set_pending_action_payload(note_id);
                ui.set_show_unsaved_warning(true);
            } else {
                load_note_into_ui(
                    &ui,
                    note_id.as_str(),
                    &state.metadata_store,
                    &state.session_password,
                    &state.session_keyfile,
                    &state.canvas_state,
                );
            }
        }
    });

    main_window.on_discard_changes_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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
                        &state.metadata_store,
                        &state.session_password,
                        &state.session_keyfile,
                        &state.canvas_state,
                    );
                }
                "select_folder" => {
                    let v_path = state.vault_path.lock().unwrap().clone();
                    *state.active_folder.lock().unwrap() = payload.clone();
                    ui.set_active_folder(payload.clone().into());
                    let note_cat = if payload == "*All Notes*" {
                        "General".to_string()
                    } else {
                        payload.clone()
                    };
                    ui.set_note_category(note_cat.into());
                    ui.set_active_note_id("".into());
                    ui.set_active_note_type("text".into());
                    ui.set_canvas_image(slint::Image::default());
                    {
                        let mut cstate = state.canvas_state.lock().unwrap();
                        cstate.pixmap = None;
                        cstate.last_point = None;
                        clear_canvas_history(&mut cstate);
                        update_canvas_history_ui(&ui, &cstate);
                    }
                    ui.set_note_title("".into());
                    ui.set_note_content("".into());
                    ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                    ui.set_note_date("".into());
                    refresh_models(
                        &ui,
                        &v_path,
                        &state.metadata_store,
                        &state.active_folder,
                        &state.search_query,
                    );
                }
                "new_note" => {
                    let cur_folder = state.active_folder.lock().unwrap().clone();
                    if cur_folder == "*All Notes*" {
                        return;
                    }
                    ui.set_show_new_note_modal(true);
                }
                "new_folder" => {
                    ui.set_new_folder_name("".into());
                    ui.set_folder_error_message("".into());
                    ui.set_show_folder_modal(true);
                }
                "rescan_vault" => {
                    let password_opt = state.session_password.lock().unwrap().clone();
                    let keyfile_opt = state.session_keyfile.lock().unwrap().clone();
                    if let Some(password) = password_opt {
                        trigger_vault_reload(
                            password,
                            keyfile_opt,
                            window_weak.clone(),
                            &state,
                            false,
                            None,
                        );
                    }
                }
                _ => {}
            }
        }
    });

    main_window.on_save_note_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |title, content, category| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            let current_vault = state.vault_path.lock().unwrap().clone();

            let (password, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
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
            let note_type = NoteType::from(ui.get_active_note_type().as_str());

            let mut target_category = category.trim().to_string();
            if target_category.is_empty() {
                target_category = state.active_folder.lock().unwrap().clone();
            }
            if target_category == "*All Notes*" || target_category.is_empty() {
                target_category = "General".to_string();
            }

            let clean_title = title.trim();
            let title_str = if clean_title.is_empty() {
                if note_type == NoteType::Canvas {
                    "Untitled Drawing".to_string()
                } else {
                    "Untitled Note".to_string()
                }
            } else {
                clean_title.to_string()
            };

            let has_duplicate = {
                let store = state.metadata_store.lock().unwrap();
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

            let note_content_to_save = if note_type == NoteType::Canvas {
                ui.get_canvas_bg_color_hex().to_string()
            } else {
                content.to_string()
            };

            let (mut note, target_path, old_path_to_remove) = if is_new {
                let new_note = Note::new_with_type(
                    title_str.clone(),
                    parsed_tags.clone(),
                    note_content_to_save,
                    note_type,
                );

                let file_path = category_dir.join(format!("{}.vault", new_note.id));
                (new_note, file_path, None)
            } else {
                let existing_file_path = {
                    let store = state.metadata_store.lock().unwrap();
                    if let Some(m) = store.get(&active_id) {
                        m.file_path.clone()
                    } else {
                        current_vault
                            .join(&target_category)
                            .join(format!("{}.vault", active_id))
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
                        existing.content = note_content_to_save;
                        existing.updated_at = now;
                        existing.note_type = note_type;
                        existing
                    }
                    None => {
                        let parsed_uuid =
                            Uuid::parse_str(&active_id).unwrap_or_else(|_| Uuid::new_v4());
                        Note {
                            id: parsed_uuid,
                            title: title_str.clone(),
                            tags: parsed_tags.clone(),
                            content: note_content_to_save,
                            created_at: now,
                            updated_at: now,
                            note_type,
                        }
                    }
                };

                (note_to_save, new_target_path, remove_old)
            };

            let saved_id = note.id.to_string();
            let updated_ts = note.updated_at;
            let saved_note_type = note.note_type;

            if let Err(e) = save_note_encrypted(&note, &password, kf_bytes, &target_path) {
                eprintln!("Error saving encrypted note to {:?}: {}", target_path, e);
                return;
            }

            if saved_note_type == NoteType::Canvas {
                let png_bytes = {
                    let cstate = state.canvas_state.lock().unwrap();
                    cstate.pixmap.as_ref().and_then(|p| p.encode_png().ok())
                };
                if let Some(png_bytes) = png_bytes {
                    let canvas_path = get_canvas_path(&target_path);
                    if let Err(e) =
                        save_canvas_encrypted(&png_bytes, &password, kf_bytes, &canvas_path)
                    {
                        eprintln!("Error saving encrypted canvas to {:?}: {}", canvas_path, e);
                    }
                }
            }

            if let Some(old_file) = old_path_to_remove {
                move_note_attachments(&old_file, &target_path);
                let _ = std::fs::remove_file(&old_file);
            }

            note.zeroize();

            let formatted_date = format_unix_timestamp(updated_ts);

            {
                let mut store = state.metadata_store.lock().unwrap();
                store.insert(
                    saved_id.clone(),
                    NoteMetaSummary {
                        title: title_str.clone(),
                        category: target_category.clone(),
                        tags: parsed_tags,
                        updated_at: updated_ts,
                        file_path: target_path.clone(),
                        note_type: saved_note_type,
                    },
                );
            }

            let was_all_notes = state.active_folder.lock().unwrap().as_str() == "*All Notes*";
            if !was_all_notes {
                *state.active_folder.lock().unwrap() = target_category.clone();
                ui.set_active_folder(target_category.clone().into());
            }

            ui.set_active_note_id(saved_id.into());
            ui.set_note_title(title_str.as_str().into());
            ui.set_note_date(formatted_date.into());
            ui.set_note_category(target_category.into());
            let blocks = parse_markdown_into_blocks(&content);
            ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
            ui.set_note_markdown_rendered(render_markdown_styled(&content));
            ui.set_has_unsaved_changes(false);

            refresh_models(
                &ui,
                &current_vault,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
            println!("[NoteVault] Note saved successfully to {:?}", target_path);
        }
    });

    main_window.on_new_note_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }
            if ui.get_has_unsaved_changes() {
                ui.set_pending_action_type("new_note".into());
                ui.set_pending_action_payload("".into());
                ui.set_show_unsaved_warning(true);
            } else {
                ui.set_show_new_note_modal(true);
            }
        }
    });

    main_window.on_new_note_type_selected({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |note_type_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }
            let cur_folder = state.active_folder.lock().unwrap().clone();
            let folder_to_use = if cur_folder == "*All Notes*" {
                "General".to_string()
            } else {
                cur_folder
            };

            init_blank_new_note_in_ui(
                &ui,
                note_type_str.as_str(),
                &folder_to_use,
                &state.canvas_state,
            );
        }
    });

    main_window.on_cancel_note_edits_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() || !ui.get_has_unsaved_changes() {
                return;
            }
            let active_id = ui.get_active_note_id().to_string();
            if active_id.is_empty() {
                return;
            }

            if active_id == "new" {
                let cur_type = ui.get_active_note_type().to_string();
                let cur_cat = ui.get_note_category().to_string();
                let folder = if cur_cat.is_empty() {
                    "General"
                } else {
                    cur_cat.as_str()
                };
                init_blank_new_note_in_ui(&ui, &cur_type, folder, &state.canvas_state);
                ui.set_vault_status_text("Discarded unsaved edits".into());
            } else {
                load_note_into_ui(
                    &ui,
                    &active_id,
                    &state.metadata_store,
                    &state.session_password,
                    &state.session_keyfile,
                    &state.canvas_state,
                );
                ui.set_vault_status_text("Reverted unsaved edits".into());
            }
        }
    });

    main_window.on_move_note_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |note_id, target_folder| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let note_id = note_id.trim().to_string();
            let target_folder = target_folder.trim().to_string();

            if note_id.is_empty() || target_folder.is_empty() {
                return;
            }

            let current_vault = state.vault_path.lock().unwrap().clone();
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
                let mut store = state.metadata_store.lock().unwrap();
                if let Some(meta) = store.get_mut(&note_id) {
                    let old_path = meta.file_path.clone();
                    if old_path != new_path && old_path.exists() {
                        move_note_attachments(&old_path, &new_path);
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

            refresh_models(
                &ui,
                &current_vault,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
            println!("[NoteVault] Moved note {} to folder '{}'", note_id, target_folder);
        }
    });

    main_window.on_delete_note_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |note_id| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let note_id = note_id.trim().to_string();

            if note_id.is_empty() {
                return;
            }

            let current_vault = state.vault_path.lock().unwrap().clone();

            let removed_meta = {
                let mut store = state.metadata_store.lock().unwrap();
                store.remove(&note_id)
            };

            if let Some(meta) = removed_meta {
                delete_note_attachments(&meta.file_path);
                if meta.file_path.exists() {
                    if let Err(e) = std::fs::remove_file(&meta.file_path) {
                        eprintln!("Failed to delete note file at {:?}: {}", meta.file_path, e);
                    }
                }
            }

            if ui.get_active_note_id() == note_id {
                ui.set_active_note_id("".into());
                ui.set_active_note_type("text".into());
                ui.set_canvas_image(slint::Image::default());
                {
                    let mut cstate = state.canvas_state.lock().unwrap();
                    cstate.pixmap = None;
                    cstate.last_point = None;
                    clear_canvas_history(&mut cstate);
                    update_canvas_history_ui(&ui, &cstate);
                }
                ui.set_note_title("".into());
                ui.set_note_content("".into());
                ui.set_note_tags(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_note_date("".into());
                ui.set_note_attachments(std::rc::Rc::new(slint::VecModel::default()).into());
                ui.set_attachment_count(0);
            }

            refresh_models(
                &ui,
                &current_vault,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
            println!("[NoteVault] Deleted note {}", note_id);
        }
    });

    main_window.on_remove_tag_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |idx| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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

    main_window.on_open_add_tag_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let store = state.metadata_store.lock().unwrap();
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
            ui.set_suggested_tags(
                std::rc::Rc::new(slint::VecModel::from(slint_suggestions)).into(),
            );
            ui.set_new_tag_name("".into());
            ui.set_add_tag_selected_index(-1);
            ui.set_show_add_tag_modal(true);
        }
    });

    main_window.on_tag_search_changed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |query| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let store = state.metadata_store.lock().unwrap();
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
            ui.set_suggested_tags(
                std::rc::Rc::new(slint::VecModel::from(slint_suggestions)).into(),
            );
            ui.set_add_tag_selected_index(-1);
        }
    });

    main_window.on_add_tag_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |new_tag| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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

    main_window.on_editor_setting_changed({
        let state = state.clone();
        move |key, value| {
            state.touch_activity();
            let mut cfg = state.app_config.lock().unwrap();
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

    main_window.on_column_width_changed({
        let state = state.clone();
        move |pane, width_px| {
            state.touch_activity();
            let w = width_px.round() as u32;
            let mut cfg = state.app_config.lock().unwrap();
            match pane.as_str() {
                "folder" => cfg.folder_pane_width = w,
                "notes" => cfg.notes_pane_width = w,
                _ => {}
            }
            if let Err(e) = cfg.save() {
                eprintln!("[Config] Failed to save column width: {}", e);
            }
        }
    });

    main_window.on_toggle_markdown_mode_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();
        move |is_markdown| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if is_markdown {
                let content = ui.get_note_content().to_string();
                let blocks = parse_markdown_into_blocks(&content);
                ui.set_note_markdown_blocks(std::rc::Rc::new(slint::VecModel::from(blocks)).into());
                ui.set_note_markdown_rendered(render_markdown_styled(&content));
            }
        }
    });

    main_window.on_link_clicked({
        let state = state.clone();
        move |url| {
            state.touch_activity();
            open_url_safely(url.as_str());
        }
    });

    main_window.on_note_content_edited({
        let window_weak = window_weak.clone();
        let state = state.clone();
        move |content| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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

    main_window.on_copy_text_to_clipboard({
        let state = state.clone();
        move |text| {
            state.touch_activity();
            let text_str = text.to_string();
            if !text_str.is_empty() {
                if let Ok(mut clipboard) = Clipboard::new() {
                    if clipboard.set_text(&text_str).is_ok() {
                        state.schedule_clipboard_clear(&text_str);
                    }
                }
            }
        }
    });
}
