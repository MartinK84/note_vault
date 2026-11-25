use std::path::PathBuf;
use std::sync::Arc;

use note_vault::{MainWindow, QuickSearchWindow};
use slint::ComponentHandle;
use zeroize::Zeroizing;

use crate::gui::state::AppState;
use crate::gui::vault_ops::{lock_vault_session, trigger_vault_reload};

pub fn register(
    main_window: &MainWindow,
    quick_search: &QuickSearchWindow,
    state: &AppState,
) {
    let window_weak = main_window.as_weak();
    let quick_search_weak = quick_search.as_weak();

    main_window.on_welcome_open_vault_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

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

            {
                let mut cfg = state.app_config.lock().unwrap();
                cfg.vault_path = chosen_path_clean.clone();
                let _ = cfg.save();
            }

            *state.vault_path.lock().unwrap() = path;
            ui.set_settings_vault_path(chosen_path_clean.as_str().into());
            ui.set_show_welcome_modal(false);
            ui.set_is_locked(true);
            ui.set_vault_status_text("Vault locked".into());
        }
    });

    main_window.on_unlock_browse_keyfile_requested({
        let window_weak = window_weak.clone();
        let app_config = Arc::clone(&state.app_config);
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

    main_window.on_unlock_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |raw_password| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            let password = Zeroizing::new(raw_password.to_string());

            if password.is_empty() {
                ui.set_unlock_error_message("Please enter a master password.".into());
                return;
            }

            let keyfile_data = {
                let cfg = state.app_config.lock().unwrap();
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
                &state,
                true,
                None,
            );
        }
    });

    main_window.on_rescan_vault_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            state.touch_activity();
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
    });

    main_window.on_lock_vault({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            println!("[NoteVault] Vault locked.");
            lock_vault_session(&ui, &quick_search_weak, &state, "Vault locked");
        }
    });

    main_window.on_exit_requested({
        let window_weak = window_weak.clone();
        move || {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_show_exit_confirm_modal(true);
            }
        }
    });

    main_window.on_exit_confirmed({
        let window_weak = window_weak.clone();
        move || {
            if let Some(ui) = window_weak.upgrade() {
                let _ = ui.hide();
            }
            let _ = slint::quit_event_loop();
            std::process::exit(0);
        }
    });
}
