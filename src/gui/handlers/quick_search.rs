use std::sync::atomic::Ordering;
use std::sync::Arc;

use arboard::Clipboard;
use note_vault::{load_note_decrypted, MainWindow, QuickSearchWindow, UnlockWindow};
use slint::ComponentHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::gui::state::AppState;
use crate::gui::vault_ops::{
    filter_quick_search_results, load_note_into_ui, refresh_models, trigger_vault_reload,
};
use crate::gui::win_interop::{
    center_and_resize_unlock_window, get_primary_screen_size, schedule_quick_search_focus,
    show_and_focus_main_window,
};

pub fn register(
    main_window: &MainWindow,
    quick_search: &QuickSearchWindow,
    unlock_window: &UnlockWindow,
    state: &AppState,
) {
    let window_weak = main_window.as_weak();
    let quick_search_weak = quick_search.as_weak();
    let unlock_window_weak = unlock_window.as_weak();

    quick_search.on_search_changed({
        let quick_search_weak = quick_search_weak.clone();
        let state = state.clone();
        move |text| {
            let Some(qs) = quick_search_weak.upgrade() else { return };
            state.touch_activity();
            if state.session_password.lock().unwrap().is_none() {
                state.is_quick_search_open.store(false, Ordering::SeqCst);
                let _ = qs.hide();
                return;
            }
            let results = {
                let store = state.metadata_store.lock().unwrap();
                filter_quick_search_results(text.as_str(), &store)
            };
            let model = std::rc::Rc::new(slint::VecModel::from(results));
            qs.set_results(model.into());
            qs.set_selected_index(0);
        }
    });

    quick_search.on_action_enter_pressed({
        let quick_search_weak = quick_search_weak.clone();
        let state = state.clone();
        move |note_id| {
            state.touch_activity();
            let note_id_str = note_id.as_str().to_string();
            let meta_opt = {
                let store = state.metadata_store.lock().unwrap();
                store.get(&note_id_str).cloned()
            };

            if let Some(meta) = meta_opt {
                let (pwd_opt, kf_opt) = {
                    let s_pwd = state.session_password.lock().unwrap();
                    let s_kf = state.session_keyfile.lock().unwrap();
                    (s_pwd.clone(), s_kf.clone())
                };
                if let Some(pwd) = pwd_opt {
                    let kf_bytes = kf_opt.as_deref().map(|b| b.as_slice());
                    match load_note_decrypted(pwd.as_str(), kf_bytes, &meta.file_path) {
                        Ok(mut note) => {
                            if let Ok(mut clipboard) = Clipboard::new() {
                                if clipboard.set_text(&note.content).is_ok() {
                                    state.schedule_clipboard_clear(&note.content);
                                }
                            }
                            note.zeroize();
                            state.is_quick_search_open.store(false, Ordering::SeqCst);
                            if let Some(qs) = quick_search_weak.upgrade() {
                                let _ = qs.hide();
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to decrypt note for clipboard: {}", e);
                        }
                    }
                } else {
                    state.is_quick_search_open.store(false, Ordering::SeqCst);
                    if let Some(qs) = quick_search_weak.upgrade() {
                        let _ = qs.hide();
                    }
                }
            }
        }
    });

    let handle_open_note = {
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let state = state.clone();

        move |note_id: slint::SharedString| {
            state.touch_activity();
            let note_id_str = note_id.as_str().to_string();
            let meta_opt = {
                let store = state.metadata_store.lock().unwrap();
                store.get(&note_id_str).cloned()
            };

            if let Some(meta) = meta_opt {
                if let Some(ui) = window_weak.upgrade() {
                    ui.set_is_locked(false);
                    ui.set_show_welcome_modal(false);
                    ui.set_show_unlock_modal(false);
                    ui.set_show_unsaved_warning(false);

                    let target_folder = if meta.category.is_empty() {
                        "General".to_string()
                    } else {
                        meta.category.clone()
                    };
                    *state.active_folder.lock().unwrap() = target_folder.clone();
                    ui.set_active_folder(target_folder.into());

                    *state.search_query.lock().unwrap() = String::new();
                    ui.set_search_query("".into());

                    let v_path = state.vault_path.lock().unwrap().clone();
                    refresh_models(
                        &ui,
                        &v_path,
                        &state.metadata_store,
                        &state.active_folder,
                        &state.search_query,
                    );

                    load_note_into_ui(
                        &ui,
                        &note_id_str,
                        &state.metadata_store,
                        &state.session_password,
                        &state.session_keyfile,
                        &state.canvas_state,
                    );

                    show_and_focus_main_window(&ui);
                }

                state.is_quick_search_open.store(false, Ordering::SeqCst);
                if let Some(qs) = quick_search_weak.upgrade() {
                    let _ = qs.hide();
                }
            } else {
                state.is_quick_search_open.store(false, Ordering::SeqCst);
                if let Some(qs) = quick_search_weak.upgrade() {
                    let _ = qs.hide();
                }
            }
        }
    };

    quick_search.on_action_alt_pressed({
        let handle = handle_open_note.clone();
        move |note_id| handle(note_id)
    });

    quick_search.on_action_space_pressed({
        let handle = handle_open_note;
        move |note_id| handle(note_id)
    });

    quick_search.on_close_requested({
        let quick_search_weak = quick_search_weak.clone();
        let is_quick_search_open = Arc::clone(&state.is_quick_search_open);
        move || {
            is_quick_search_open.store(false, Ordering::SeqCst);
            if let Some(qs) = quick_search_weak.upgrade() {
                let _ = qs.hide();
            }
        }
    });

    quick_search.window().on_close_requested({
        let quick_search_weak = quick_search_weak.clone();
        let is_quick_search_open = Arc::clone(&state.is_quick_search_open);
        move || {
            is_quick_search_open.store(false, Ordering::SeqCst);
            if let Some(qs) = quick_search_weak.upgrade() {
                let _ = qs.hide();
            }
            slint::CloseRequestResponse::HideWindow
        }
    });

    unlock_window.on_close_requested({
        let unlock_window_weak = unlock_window_weak.clone();
        let is_unlock_window_open = Arc::clone(&state.is_unlock_window_open);
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
        let is_unlock_window_open = Arc::clone(&state.is_unlock_window_open);
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
        let app_config = Arc::clone(&state.app_config);
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
        let state = state.clone();

        move |raw_password| {
            let Some(uw) = unlock_window_weak.upgrade() else { return };
            state.touch_activity();
            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                uw.set_error_message("Please enter a master password.".into());
                center_and_resize_unlock_window(&uw);
                return;
            }

            let keyfile_data = {
                let cfg = state.app_config.lock().unwrap();
                if let Some(kpath) = cfg.resolved_keyfile_path() {
                    if !kpath.exists() {
                        uw.set_error_message(
                            format!("Keyfile missing at {}. Please locate it.", kpath.display())
                                .into(),
                        );
                        uw.set_show_keyfile_browse(true);
                        center_and_resize_unlock_window(&uw);
                        return;
                    }
                    match std::fs::read(&kpath) {
                        Ok(data) => Some(Zeroizing::new(data)),
                        Err(e) => {
                            uw.set_error_message(format!("Failed to read keyfile: {}", e).into());
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
            let m_store = Arc::clone(&state.metadata_store);
            let is_uw_open = Arc::clone(&state.is_unlock_window_open);
            let is_qs_open = Arc::clone(&state.is_quick_search_open);
            let qs_shown = Arc::clone(&state.quick_search_shown_at);

            trigger_vault_reload(
                password,
                keyfile_data,
                window_weak.clone(),
                &state,
                true,
                Some(Box::new(move |success| {
                    slint::invoke_from_event_loop(move || {
                        if success {
                            if let Some(uw) = uw_weak.upgrade() {
                                uw.invoke_clear_fields();
                                let _ = uw.hide();
                                is_uw_open.store(false, Ordering::SeqCst);
                            }

                            if let Some(qs) = qs_weak.upgrade() {
                                qs.set_search_text("".into());
                                let initial_results = {
                                    let store = m_store.lock().unwrap();
                                    filter_quick_search_results("", &store)
                                };
                                let model =
                                    std::rc::Rc::new(slint::VecModel::from(initial_results));
                                qs.set_results(model.into());
                                qs.set_selected_index(0);

                                let (screen_w, screen_h) = get_primary_screen_size();
                                let scale = qs.window().scale_factor();
                                let logical_w =
                                    if scale > 0.0 { screen_w / scale } else { screen_w };
                                let logical_h =
                                    if scale > 0.0 { screen_h / scale } else { screen_h };

                                let win_w = 650.0;
                                let win_h = 360.0;
                                let pos_x = (logical_w - win_w) / 2.0;
                                let pos_y = (logical_h - win_h) / 2.0;

                                qs.window()
                                    .set_size(slint::LogicalSize::new(win_w, win_h));
                                qs.window()
                                    .set_position(slint::LogicalPosition::new(pos_x, pos_y));

                                is_qs_open.store(true, Ordering::SeqCst);
                                *qs_shown.lock().unwrap() = std::time::Instant::now();

                                let _ = qs.show();
                                schedule_quick_search_focus(&qs, &is_qs_open);
                            }
                        } else if let Some(uw) = uw_weak.upgrade() {
                            uw.set_is_loading(false);
                            uw.set_error_message(
                                "Decryption failed: invalid master password, keyfile mismatch, or corrupted note file.".into(),
                            );
                            center_and_resize_unlock_window(&uw);
                            uw.invoke_focus_password();
                        }
                    })
                    .ok();
                })),
            );
        }
    });
}
