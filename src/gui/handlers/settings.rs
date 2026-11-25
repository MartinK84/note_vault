use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use note_vault::{MainWindow, QuickSearchWindow, Theme, UnlockWindow};
use slint::ComponentHandle;
use zeroize::Zeroizing;

use crate::gui::hotkey::{format_key_combination, parse_hotkey_string};
use crate::gui::state::{
    auto_lock_label_to_minutes, clipboard_clear_label_to_seconds, minutes_to_auto_lock_label,
    seconds_to_clipboard_clear_label, AppState,
};
use crate::gui::vault_ops::lock_vault_session;

pub fn register(
    main_window: &MainWindow,
    quick_search: &QuickSearchWindow,
    unlock_window: &UnlockWindow,
    state: &AppState,
) {
    let window_weak = main_window.as_weak();
    let quick_search_weak = quick_search.as_weak();
    let unlock_window_weak = unlock_window.as_weak();

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

    main_window.on_open_settings_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let cfg = state.app_config.lock().unwrap();
            let cur_path = cfg.vault_path.clone();
            let cur_multi = state.use_multithreading.load(Ordering::Relaxed);
            let cur_hotkey = cfg.global_hotkey.clone();
            let cur_minimize = cfg.minimize_to_tray;
            let cur_theme = match cfg.theme.as_str() {
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
            ui.set_settings_main_window_hotkey(cfg.main_window_hotkey.clone().into());
            ui.set_settings_minimize_to_tray(cur_minimize);
            ui.set_settings_launch_at_startup(cfg.launch_at_startup);
            ui.set_settings_auto_lock(minutes_to_auto_lock_label(cfg.auto_lock_minutes).into());
            ui.set_settings_clipboard_clear(
                seconds_to_clipboard_clear_label(cfg.clipboard_clear_seconds).into(),
            );
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

    main_window.on_save_settings_requested({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let unlock_window_weak = unlock_window_weak.clone();
        let state = state.clone();

        move |new_path_str,
              new_multi,
              new_theme_str,
              new_hotkey_str,
              new_main_hotkey_str,
              new_min_tray,
              new_launch_startup,
              new_auto_lock_str,
              new_clipboard_clear_str| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let new_path_clean = new_path_str.trim().to_string();
            let new_theme_clean = new_theme_str.trim().to_string();
            let new_hotkey_clean = new_hotkey_str.trim().to_string();
            let new_main_hotkey_clean = new_main_hotkey_str.trim().to_string();
            let new_auto_lock_mins = auto_lock_label_to_minutes(new_auto_lock_str.as_str());
            let new_clipboard_secs =
                clipboard_clear_label_to_seconds(new_clipboard_clear_str.as_str());

            let (new_hk_opt, clean_hotkey_str) = match parse_hotkey_string(&new_hotkey_clean) {
                Ok((hk, norm)) => (Some(hk), norm),
                Err(e) => {
                    eprintln!(
                        "Invalid quick search hotkey entered '{}': {}",
                        new_hotkey_clean, e
                    );
                    (None, new_hotkey_clean.clone())
                }
            };

            let (new_main_hk_opt, clean_main_hotkey_str) =
                match parse_hotkey_string(&new_main_hotkey_clean) {
                    Ok((hk, norm)) => (Some(hk), norm),
                    Err(e) => {
                        eprintln!(
                            "Invalid main window hotkey entered '{}': {}",
                            new_main_hotkey_clean, e
                        );
                        (None, new_main_hotkey_clean.clone())
                    }
                };

            let (old_hotkey, old_main_hotkey, old_launch, old_min_tray) = {
                let mut cfg = state.app_config.lock().unwrap();
                let old_hk = cfg.global_hotkey.clone();
                let old_main_hk = cfg.main_window_hotkey.clone();
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
                cfg.main_window_hotkey = clean_main_hotkey_str.clone();
                cfg.minimize_to_tray = new_min_tray;
                cfg.launch_at_startup = new_launch_startup;
                cfg.auto_lock_minutes = new_auto_lock_mins;
                cfg.clipboard_clear_seconds = new_clipboard_secs;
                if let Err(e) = cfg.save() {
                    eprintln!("Failed to save config.json: {}", e);
                }
                (old_hk, old_main_hk, old_launch, old_min_tray)
            };

            if old_launch != new_launch_startup
                || (new_launch_startup && old_min_tray != new_min_tray)
            {
                if let Err(e) =
                    note_vault::startup::set_launch_at_startup(new_launch_startup, new_min_tray)
                {
                    eprintln!("Failed to update startup registration: {}", e);
                }
            }

            if let Some(new_hk) = new_hk_opt {
                if old_hotkey != clean_hotkey_str {
                    if let Some(ref mut mgr) = *state.hotkey_manager.lock().unwrap() {
                        let mut cur_hk_guard = state.active_hotkey.lock().unwrap();
                        if let Some(old_hk) = cur_hk_guard.take() {
                            let _ = mgr.unregister(old_hk);
                        }
                        if let Ok(()) = mgr.register(new_hk) {
                            *cur_hk_guard = Some(new_hk);
                        }
                    }
                }
            }

            if let Some(new_main_hk) = new_main_hk_opt {
                if old_main_hotkey != clean_main_hotkey_str {
                    if let Some(ref mut mgr) = *state.hotkey_manager.lock().unwrap() {
                        let mut cur_main_hk_guard = state.active_main_hotkey.lock().unwrap();
                        if let Some(old_hk) = cur_main_hk_guard.take() {
                            let _ = mgr.unregister(old_hk);
                        }
                        if let Ok(()) = mgr.register(new_main_hk) {
                            *cur_main_hk_guard = Some(new_main_hk);
                        }
                    }
                }
            }

            ui.set_settings_global_hotkey(clean_hotkey_str.into());
            ui.set_settings_main_window_hotkey(clean_main_hotkey_str.into());
            ui.set_settings_minimize_to_tray(new_min_tray);
            ui.set_settings_launch_at_startup(new_launch_startup);
            ui.set_settings_auto_lock(minutes_to_auto_lock_label(new_auto_lock_mins).into());
            ui.set_settings_clipboard_clear(
                seconds_to_clipboard_clear_label(new_clipboard_secs).into(),
            );

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
            if let Some(uw) = unlock_window_weak.upgrade() {
                uw.global::<Theme>().set_theme(final_theme.into());
                uw.global::<Theme>().set_is_dark(is_dark_mode);
            }

            state.use_multithreading.store(new_multi, Ordering::Relaxed);

            let old_path = state.vault_path.lock().unwrap().clone();
            let resolved_new_path = note_vault::config::expand_path(&new_path_clean);

            if !new_path_clean.is_empty() && resolved_new_path != old_path {
                let _ = std::fs::create_dir_all(&resolved_new_path);
                *state.vault_path.lock().unwrap() = resolved_new_path;
                lock_vault_session(
                    &ui,
                    &quick_search_weak,
                    &state,
                    "Vault locked (switched folder)",
                );
            }

            ui.set_show_settings_modal(false);
        }
    });

    main_window.on_theme_changed({
        let window_weak = window_weak.clone();
        let quick_search_weak = quick_search_weak.clone();
        let unlock_window_weak = unlock_window_weak.clone();
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
            if let Some(uw) = unlock_window_weak.upgrade() {
                uw.global::<Theme>().set_theme(final_theme.into());
                uw.global::<Theme>().set_is_dark(is_dark_mode);
            }
        }
    });

    main_window.on_record_hotkey_requested(|key_text, ctrl, alt, shift, meta| {
        if let Some(combo) = format_key_combination(key_text.as_str(), ctrl, alt, shift, meta) {
            combo.into()
        } else {
            "".into()
        }
    });

    main_window.on_change_password_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |raw_current, raw_new, raw_confirm| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            let current_pwd = Zeroizing::new(raw_current.to_string());
            let new_pwd = Zeroizing::new(raw_new.to_string());
            let confirm_pwd = Zeroizing::new(raw_confirm.to_string());

            let session_opt = state.session_password.lock().unwrap().clone();
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

            if current_pwd.as_str() != active_pwd.as_str() {
                ui.set_password_change_status("Error: Current password does not match.".into());
                ui.set_password_change_success(false);
                return;
            }

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

            ui.set_is_reencrypting(true);
            ui.set_reencrypt_progress(0.0);
            ui.set_password_change_status("Starting atomic re-encryption...".into());
            ui.set_password_change_success(false);

            let weak = window_weak.clone();
            let v_dir = state.vault_path.lock().unwrap().clone();
            let s_pass = Arc::clone(&state.session_password);
            let keyfile_opt = state.session_keyfile.lock().unwrap().clone();

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
                        let status_msg = format!("Re-encrypting file {} of {}...", done, total);
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
                                    format!(
                                        "Master password changed successfully ({} files updated).",
                                        total
                                    )
                                    .into(),
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

    main_window.on_browse_new_keyfile_requested({
        let window_weak = window_weak.clone();
        let session_password = Arc::clone(&state.session_password);
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

    main_window.on_update_keyfile_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |raw_current_pwd, raw_new_path, remove_keyfile| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();

            let current_pwd = Zeroizing::new(raw_current_pwd.to_string());

            let session_opt = state.session_password.lock().unwrap().clone();
            let active_pwd = match session_opt {
                Some(p) => p,
                None => {
                    ui.set_keyfile_status("Error: Vault must be unlocked to update keyfile.".into());
                    ui.set_keyfile_success(false);
                    return;
                }
            };

            if current_pwd.as_str() != active_pwd.as_str() {
                ui.set_keyfile_status("Error: Current password does not match.".into());
                ui.set_keyfile_success(false);
                return;
            }

            let (target_keyfile_bytes, target_keyfile_path) = if remove_keyfile {
                (None, None)
            } else {
                let path_str = raw_new_path.trim().to_string();
                if path_str.is_empty() {
                    ui.set_keyfile_status(
                        "Error: Please select a keyfile or check Remove Keyfile.".into(),
                    );
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

            let current_keyfile = state.session_keyfile.lock().unwrap().clone();

            ui.set_is_keyfile_reencrypting(true);
            ui.set_keyfile_reencrypt_progress(0.0);
            ui.set_keyfile_status("Starting atomic re-encryption with new keyfile...".into());
            ui.set_keyfile_success(false);

            let weak = window_weak.clone();
            let v_dir = state.vault_path.lock().unwrap().clone();
            let s_kf = Arc::clone(&state.session_keyfile);
            let s_cfg = Arc::clone(&state.app_config);

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
                        let status_msg = format!("Re-encrypting file {} of {}...", done, total);
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
                                    format!(
                                        "Keyfile updated successfully ({} files re-encrypted).",
                                        total
                                    )
                                } else {
                                    format!(
                                        "Keyfile removed successfully ({} files re-encrypted).",
                                        total
                                    )
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
}
