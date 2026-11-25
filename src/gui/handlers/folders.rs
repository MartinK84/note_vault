use note_vault::{validate_folder_name, MainWindow};
use slint::ComponentHandle;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::gui::canvas::{clear_canvas_history, update_canvas_history_ui};
use crate::gui::state::AppState;
use crate::gui::vault_ops::refresh_models;

pub fn register(main_window: &MainWindow, state: &AppState) {
    let window_weak = main_window.as_weak();

    main_window.on_folder_selected({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |folder| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let v_path = state.vault_path.lock().unwrap().clone();
            *state.active_folder.lock().unwrap() = folder.to_string();
            ui.set_active_folder(folder.clone());
            let note_cat = if folder == "*All Notes*" {
                "General".to_string()
            } else {
                folder.to_string()
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
            ui.set_editor_markdown_mode(false);
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
    });

    main_window.on_new_folder_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }
            ui.set_new_folder_name("".into());
            ui.set_show_folder_modal(true);
        }
    });

    main_window.on_create_folder_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |name| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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

            let current_vault = state.vault_path.lock().unwrap().clone();
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
            *state.active_folder.lock().unwrap() = valid_name.clone();
            ui.set_active_folder(valid_name.clone().into());
            ui.set_note_category(valid_name.into());

            refresh_models(
                &ui,
                &current_vault,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
        }
    });

    main_window.on_rename_folder_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |old_name, new_name| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
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

            let current_vault = state.vault_path.lock().unwrap().clone();
            let old_path = current_vault.join(&old_name);
            let new_path = current_vault.join(&valid_new);

            let is_case_only = old_name.eq_ignore_ascii_case(&valid_new);

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
                } else if let Err(e) = std::fs::rename(&old_path, &new_path) {
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

            ui.set_rename_folder_error_message("".into());
            ui.set_show_rename_folder_modal(false);

            {
                let mut store = state.metadata_store.lock().unwrap();
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

            {
                let mut act = state.active_folder.lock().unwrap();
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

            refresh_models(
                &ui,
                &current_vault,
                &state.metadata_store,
                &state.active_folder,
                &state.search_query,
            );
            println!(
                "[NoteVault] Renamed folder from '{}' to '{}'",
                old_name, valid_new
            );
        }
    });

    main_window.on_delete_folder_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |raw_folder_name| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            let folder_name = match validate_folder_name(&raw_folder_name) {
                Ok(n) => n,
                Err(err_msg) => {
                    eprintln!(
                        "[Security] Blocked invalid folder deletion request '{}': {}",
                        raw_folder_name, err_msg
                    );
                    return;
                }
            };

            let current_vault = state.vault_path.lock().unwrap().clone();
            let target_dir = current_vault.join(&folder_name);
            if target_dir.exists() {
                let is_inside_vault = match (
                    std::fs::canonicalize(&current_vault),
                    std::fs::canonicalize(&target_dir),
                ) {
                    (Ok(canon_vault), Ok(canon_target)) => {
                        canon_target.starts_with(&canon_vault) && canon_target != canon_vault
                    }
                    _ => false,
                };

                if !is_inside_vault {
                    eprintln!(
                        "[Security] Refusing to delete {:?}: path is outside vault {:?}",
                        target_dir, current_vault
                    );
                    return;
                }

                if let Err(e) = std::fs::remove_dir_all(&target_dir) {
                    eprintln!("Failed to recursively delete folder {:?}: {}", target_dir, e);
                }
            }

            let prefix = format!("{}/", folder_name);
            let active_id = ui.get_active_note_id().to_string();
            let mut active_note_deleted = false;

            {
                let mut store = state.metadata_store.lock().unwrap();
                store.retain(|id, meta| {
                    let in_folder =
                        meta.category == folder_name || meta.category.starts_with(&prefix);
                    if in_folder && *id == active_id {
                        active_note_deleted = true;
                    }
                    !in_folder
                });
            }

            let is_active = {
                let act = state.active_folder.lock().unwrap();
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
                    let store = state.metadata_store.lock().unwrap();
                    for meta in store.values() {
                        if !meta.category.is_empty()
                            && meta.category != folder_name
                            && !meta.category.starts_with(&prefix)
                        {
                            remaining.insert(meta.category.clone());
                        }
                    }
                }

                let next_folder = remaining.into_iter().next().unwrap_or_default();
                *state.active_folder.lock().unwrap() = next_folder.clone();
                ui.set_active_folder(next_folder.clone().into());
                ui.set_note_category(next_folder.into());
            }

            if active_note_deleted {
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
            println!(
                "[NoteVault] Deleted folder '{}' and its encrypted notes",
                folder_name
            );
        }
    });
}
