use std::fs;
use std::path::{Path, PathBuf};

use note_vault::{
    compact_note_attachments, format_file_size, format_unix_date, format_unix_timestamp,
    get_canvas_path, get_next_attachment_path, is_image_filename, is_text_data, is_text_filename,
    load_attachment_decrypted, load_attachment_metadata, save_attachment_encrypted,
    save_canvas_encrypted, save_note_encrypted, MainWindow, Note, NoteAttachment, NoteType,
};
use slint::{ComponentHandle, Model};
use uuid::Uuid;

use crate::gui::state::{AppState, NoteMetaSummary};
use crate::gui::vault_ops::{refresh_models, update_attachments_in_ui};

pub fn register(main_window: &MainWindow, state: &AppState) {
    let window_weak = main_window.as_weak();

    main_window.on_add_attachment_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }

            let mut active_id = ui.get_active_note_id().trim().to_string();
            if active_id.is_empty() {
                return;
            }

            let (password_opt, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
                (session.clone(), keyfile.clone())
            };
            let Some(password) = password_opt else { return };
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());

            let note_file_path = if active_id == "new" {
                let current_vault = state.vault_path.lock().unwrap().clone();
                let target_category = ui.get_note_category().trim().to_string();
                let cat = if target_category.is_empty() || target_category == "*All Notes*" {
                    "General".to_string()
                } else {
                    target_category
                };
                let category_dir = current_vault.join(&cat);
                let _ = std::fs::create_dir_all(&category_dir);

                let note_type = NoteType::from(ui.get_active_note_type().as_str());
                let title_str = ui.get_note_title().trim().to_string();
                let title = if title_str.is_empty() {
                    if note_type == NoteType::Canvas {
                        "Untitled Drawing".to_string()
                    } else {
                        "Untitled Note".to_string()
                    }
                } else {
                    title_str
                };
                let content = ui.get_note_content().to_string();
                let tags: Vec<String> = ui.get_note_tags().iter().map(|s| s.to_string()).collect();

                let new_note = Note::new_with_type(title.clone(), tags.clone(), content, note_type);
                let file_path = category_dir.join(format!("{}.vault", new_note.id));
                if let Err(e) = save_note_encrypted(&new_note, &password, kf_bytes, &file_path) {
                    eprintln!("Failed to save new note before adding attachment: {}", e);
                    return;
                }

                if new_note.note_type == NoteType::Canvas {
                    let png_bytes = {
                        let cstate = state.canvas_state.lock().unwrap();
                        cstate.pixmap.as_ref().and_then(|p| p.encode_png().ok())
                    };
                    if let Some(png_bytes) = png_bytes {
                        let canvas_path = get_canvas_path(&file_path);
                        if let Err(e) =
                            save_canvas_encrypted(&png_bytes, &password, kf_bytes, &canvas_path)
                        {
                            eprintln!("Error saving encrypted canvas to {:?}: {}", canvas_path, e);
                        }
                    }
                }

                let new_id_str = new_note.id.to_string();
                let now = new_note.updated_at;
                let formatted_date = format_unix_timestamp(now);

                state.metadata_store.lock().unwrap().insert(
                    new_id_str.clone(),
                    NoteMetaSummary {
                        title: title.clone(),
                        category: cat,
                        tags,
                        updated_at: now,
                        file_path: file_path.clone(),
                        note_type,
                    },
                );

                ui.set_active_note_id(new_id_str.clone().into());
                ui.set_note_date(formatted_date.into());
                ui.set_has_unsaved_changes(false);
                refresh_models(
                    &ui,
                    &current_vault,
                    &state.metadata_store,
                    &state.active_folder,
                    &state.search_query,
                );
                active_id = new_id_str;
                file_path
            } else {
                let store = state.metadata_store.lock().unwrap();
                match store.get(&active_id) {
                    Some(m) => m.file_path.clone(),
                    None => return,
                }
            };

            let selected_files = rfd::FileDialog::new()
                .set_title("Select Attachment(s)")
                .pick_files();

            let Some(files) = selected_files else { return };

            for file in files {
                let Ok(data) = fs::read(&file) else {
                    eprintln!("Failed to read attachment file: {:?}", file);
                    continue;
                };
                let file_name = file
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("attachment.bin")
                    .to_string();

                let att = NoteAttachment::new(file_name, data);
                let att_path = get_next_attachment_path(&note_file_path);

                if let Err(e) = save_attachment_encrypted(&att, &password, kf_bytes, &att_path) {
                    eprintln!("Failed to encrypt attachment at {:?}: {}", att_path, e);
                } else {
                    println!(
                        "[NoteVault] Attached {:?} to note {}",
                        att.file_name, active_id
                    );
                }
            }

            update_attachments_in_ui(&ui, &note_file_path, &password, kf_bytes);
        }
    });

    main_window.on_preview_attachment_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |att_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }

            let path = PathBuf::from(att_path_str.as_str());
            if !path.exists() {
                eprintln!("Attachment file does not exist: {:?}", path);
                return;
            }

            let (password_opt, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
                (session.clone(), keyfile.clone())
            };
            let Some(password) = password_opt else { return };
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());

            match load_attachment_decrypted(&password, kf_bytes, &path) {
                Ok(att) => {
                    let file_name = att.file_name.clone();
                    let file_size_str = format_file_size(att.file_size);
                    let date_str = format_unix_date(att.created_at);

                    let ext = Path::new(&file_name)
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_lowercase();

                    let is_image = is_image_filename(&file_name);
                    let is_text = is_text_filename(&file_name) || is_text_data(&att.data);

                    ui.set_preview_attachment_id(att_path_str);
                    ui.set_preview_file_name(file_name.into());
                    ui.set_preview_file_size(file_size_str.into());
                    ui.set_preview_created_at(date_str.into());

                    if is_image {
                        let temp_file = std::env::temp_dir().join(format!(
                            "nv_preview_{}.{}",
                            Uuid::new_v4(),
                            if ext.is_empty() { "png" } else { &ext }
                        ));

                        let load_res = fs::write(&temp_file, &att.data)
                            .map_err(|e| e.to_string())
                            .and_then(|_| {
                                slint::Image::load_from_path(&temp_file)
                                    .map_err(|e| format!("{:?}", e))
                            });

                        let _ = fs::remove_file(&temp_file);

                        match load_res {
                            Ok(img) => {
                                ui.set_preview_is_image(true);
                                ui.set_preview_image(img);
                                ui.set_preview_is_text(false);
                                ui.set_preview_text("".into());
                                ui.set_preview_error("".into());
                            }
                            Err(e) => {
                                eprintln!("Failed to load preview image: {}", e);
                                ui.set_preview_is_image(false);
                                ui.set_preview_image(slint::Image::default());
                                ui.set_preview_is_text(false);
                                ui.set_preview_text("".into());
                                ui.set_preview_error(format!("Could not decode image: {}", e).into());
                            }
                        }
                    } else if is_text {
                        let mut text = String::from_utf8_lossy(&att.data).to_string();
                        const MAX_CHARS: usize = 120_000;
                        if text.len() > MAX_CHARS {
                            text.truncate(MAX_CHARS);
                            text.push_str("\n\n--- [Preview truncated. File is too large to display completely. Please download to view full file.] ---");
                        }
                        ui.set_preview_is_image(false);
                        ui.set_preview_image(slint::Image::default());
                        ui.set_preview_is_text(true);
                        ui.set_preview_text(text.into());
                        ui.set_preview_error("".into());
                    } else {
                        ui.set_preview_is_image(false);
                        ui.set_preview_image(slint::Image::default());
                        ui.set_preview_is_text(false);
                        ui.set_preview_text("".into());
                        ui.set_preview_error("".into());
                    }

                    ui.set_show_attachment_preview_modal(true);
                }
                Err(e) => {
                    eprintln!(
                        "Failed to decrypt attachment for preview at {:?}: {}",
                        path, e
                    );
                }
            }
        }
    });

    main_window.on_extract_attachment_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |att_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }

            let path = PathBuf::from(att_path_str.as_str());
            if !path.exists() {
                eprintln!("Attachment file does not exist: {:?}", path);
                return;
            }

            let (password_opt, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
                (session.clone(), keyfile.clone())
            };
            let Some(password) = password_opt else { return };
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());

            match load_attachment_decrypted(&password, kf_bytes, &path) {
                Ok(att) => {
                    let dialog = rfd::FileDialog::new()
                        .set_title("Save Extracted Attachment")
                        .set_file_name(&att.file_name);

                    if let Some(dest) = dialog.save_file() {
                        if let Err(e) = fs::write(&dest, &att.data) {
                            eprintln!("Failed to save extracted attachment to {:?}: {}", dest, e);
                        } else {
                            println!("[NoteVault] Extracted attachment to {:?}", dest);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to decrypt attachment at {:?}: {}", path, e);
                }
            }
        }
    });

    main_window.on_replace_attachment_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |att_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            if ui.get_is_locked() {
                return;
            }

            let path = PathBuf::from(att_path_str.as_str());
            if !path.exists() {
                eprintln!("Attachment file does not exist: {:?}", path);
                return;
            }

            let active_id = ui.get_active_note_id().trim().to_string();
            let note_file_path = {
                let store = state.metadata_store.lock().unwrap();
                store.get(&active_id).map(|m| m.file_path.clone())
            };
            let Some(note_file_path) = note_file_path else { return };

            let (password_opt, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
                (session.clone(), keyfile.clone())
            };
            let Some(password) = password_opt else { return };
            let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());

            let selected_file = rfd::FileDialog::new()
                .set_title("Select Replacement File")
                .pick_file();

            let Some(new_file) = selected_file else { return };

            let Ok(data) = fs::read(&new_file) else {
                eprintln!("Failed to read replacement file: {:?}", new_file);
                return;
            };

            let file_name = new_file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("attachment.bin")
                .to_string();

            let att = NoteAttachment::new(file_name, data);
            if let Err(e) = save_attachment_encrypted(&att, &password, kf_bytes, &path) {
                eprintln!("Failed to save replaced attachment at {:?}: {}", path, e);
            } else {
                println!(
                    "[NoteVault] Replaced attachment {:?} at {:?}",
                    att.file_name, path
                );
            }

            update_attachments_in_ui(&ui, &note_file_path, &password, kf_bytes);
        }
    });

    main_window.on_delete_attachment_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |att_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let path = PathBuf::from(att_path_str.as_str());

            let (password_opt, keyfile_opt) = {
                let session = state.session_password.lock().unwrap();
                let keyfile = state.session_keyfile.lock().unwrap();
                (session.clone(), keyfile.clone())
            };
            let filename = if let Some(pwd) = password_opt {
                let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                load_attachment_metadata(&pwd, kf_bytes, &path)
                    .map(|m| m.file_name)
                    .unwrap_or_else(|_| "Attachment".to_string())
            } else {
                "Attachment".to_string()
            };

            ui.set_target_attachment_id(att_path_str);
            ui.set_target_attachment_name(filename.into());
            ui.set_show_delete_attachment_modal(true);
        }
    });

    main_window.on_delete_attachment_confirmed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |att_path_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let path = PathBuf::from(att_path_str.as_str());
            if path.exists() {
                let _ = fs::remove_file(&path);
            }

            let active_id = ui.get_active_note_id().trim().to_string();
            let note_file_path = {
                let store = state.metadata_store.lock().unwrap();
                store.get(&active_id).map(|m| m.file_path.clone())
            };

            if let Some(note_path) = note_file_path {
                compact_note_attachments(&note_path);

                let (password_opt, keyfile_opt) = {
                    let session = state.session_password.lock().unwrap();
                    let keyfile = state.session_keyfile.lock().unwrap();
                    (session.clone(), keyfile.clone())
                };
                if let Some(password) = password_opt {
                    let kf_bytes = keyfile_opt.as_deref().map(|b| b.as_slice());
                    update_attachments_in_ui(&ui, &note_path, &password, kf_bytes);
                }
            }
        }
    });
}
