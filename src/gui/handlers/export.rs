use std::path::PathBuf;
use std::thread;

use note_vault::{
    format_decrypted_json_export, format_decrypted_txt_export, format_markdown_export,
    format_unix_timestamp, load_note_decrypted, sanitize_filename, MainWindow,
};
use slint::{ComponentHandle, Model};
use zeroize::Zeroize;

use crate::gui::state::{AppState, NoteMetaSummary};

pub fn register(main_window: &MainWindow, state: &AppState) {
    let window_weak = main_window.as_weak();

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

    main_window.on_start_export_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let export_dir_str = ui.get_export_path().trim().to_string();
            if export_dir_str.is_empty() {
                ui.set_export_status("Please select an export directory first.".into());
                return;
            }

            let export_dir = PathBuf::from(export_dir_str);

            let password = match state.session_password.lock().unwrap().as_ref() {
                Some(p) => p.clone(),
                None => {
                    ui.set_export_status(
                        "Error: Vault is locked. Unlock vault before exporting.".into(),
                    );
                    return;
                }
            };
            let keyfile_opt = state.session_keyfile.lock().unwrap().clone();

            let notes_to_export: Vec<(String, NoteMetaSummary)> = {
                let store = state.metadata_store.lock().unwrap();
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
                            let mut target_file =
                                category_dir.join(format!("{}.md", safe_filename));

                            if target_file.exists() {
                                let short_id = if note_id.len() >= 8 {
                                    &note_id[..8]
                                } else {
                                    &note_id
                                };
                                target_file =
                                    category_dir.join(format!("{}_{}.md", safe_filename, short_id));
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

    main_window.on_export_note_json_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let is_unlocked = state.session_password.lock().unwrap().is_some();
            if !is_unlocked {
                ui.set_vault_status_text(
                    "Error: Vault is locked. Unlock before exporting.".into(),
                );
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
            let tags: Vec<String> = ui.get_note_tags().iter().map(|s| s.to_string()).collect();
            let date = ui.get_note_date().to_string();

            let safe_name = sanitize_filename(&title, &active_id);
            let default_filename = format!("{}.json", safe_name);

            let picked_path = rfd::FileDialog::new()
                .set_title("Export Note as JSON")
                .set_file_name(&default_filename)
                .add_filter("JSON Files", &["json"])
                .save_file();

            if let Some(path) = picked_path {
                match format_decrypted_json_export(
                    &active_id,
                    &title,
                    &category,
                    &tags,
                    &date,
                    &content,
                ) {
                    Ok(json_str) => {
                        if let Err(e) = std::fs::write(&path, json_str) {
                            ui.set_vault_status_text(format!("Export failed: {}", e).into());
                        } else {
                            ui.set_vault_status_text(
                                format!("Exported note as JSON to {}", path.display()).into(),
                            );
                        }
                    }
                    Err(e) => {
                        ui.set_vault_status_text(
                            format!("Export serialization error: {}", e).into(),
                        );
                    }
                }
            }
        }
    });

    main_window.on_export_note_txt_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let is_unlocked = state.session_password.lock().unwrap().is_some();
            if !is_unlocked {
                ui.set_vault_status_text(
                    "Error: Vault is locked. Unlock before exporting.".into(),
                );
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
            let tags: Vec<String> = ui.get_note_tags().iter().map(|s| s.to_string()).collect();
            let date = ui.get_note_date().to_string();

            let safe_name = sanitize_filename(&title, &active_id);
            let default_filename = format!("{}.txt", safe_name);

            let picked_path = rfd::FileDialog::new()
                .set_title("Export Note as TXT")
                .set_file_name(&default_filename)
                .add_filter("Text Files", &["txt"])
                .save_file();

            if let Some(path) = picked_path {
                let txt_content =
                    format_decrypted_txt_export(&title, &category, &tags, &date, &content);
                if let Err(e) = std::fs::write(&path, txt_content) {
                    ui.set_vault_status_text(format!("Export failed: {}", e).into());
                } else {
                    ui.set_vault_status_text(
                        format!("Exported note as TXT to {}", path.display()).into(),
                    );
                }
            }
        }
    });
}
