#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use clap::Parser;
use global_hotkey::{GlobalHotKeyEvent, HotKeyState};
use note_vault::config::AppConfig;
use note_vault::{
    MainWindow, QuickSearchWindow, Theme, UnlockWindow, DEFAULT_CANVAS_BG_HEX,
    DEFAULT_CANVAS_HEIGHT, DEFAULT_CANVAS_WIDTH,
};
use slint::ComponentHandle;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

#[cfg(test)]
use note_vault::{parse_markdown_into_blocks, render_markdown_styled};

#[cfg(test)]
use gui::canvas::{
    draw_stroke_on_pixmap, push_canvas_undo, redo_canvas, sync_canvas_dirty_rect,
    sync_canvas_full, undo_canvas,
};
#[cfg(test)]
use gui::hotkey::{create_tray_icon as build_tray_icon, format_key_combination};
#[cfg(test)]
use gui::state::{
    auto_lock_label_to_minutes, clipboard_clear_label_to_seconds, minutes_to_auto_lock_label,
    seconds_to_clipboard_clear_label, ActiveCanvasState, NoteMetaSummary,
};
#[cfg(test)]
use gui::vault_ops::{filter_quick_search_results, get_suggested_tags, init_blank_new_note_in_ui};
#[cfg(test)]
use gui::win_interop::{
    handle_main_window_hotkey, is_main_window_visible, minimize_main_window,
    MAIN_WINDOW_HIDDEN_TO_TRAY,
};
#[cfg(test)]
use gui::win_pen::{
    build_mouse_wparam, determine_pen_button, pack_client_lparam, should_suppress_touch_for_pen,
    PenMouseButton, PEN_FLAG_BARREL_BIT, PEN_FLAG_ERASER_BIT, PEN_FLAG_INVERTED_BIT,
    PEN_POINTER_FLAG_SECONDBUTTON,
};
#[cfg(test)]
use note_vault::NoteType;

use gui::handlers;
use gui::hotkey::{create_tray_icon, parse_hotkey_string};
use gui::state::{
    minutes_to_auto_lock_label as format_auto_lock_label,
    seconds_to_clipboard_clear_label as format_clipboard_clear_label, AppState, Args,
};
use gui::vault_ops::{filter_quick_search_results as filter_qs_results, lock_vault_session};
use gui::win_interop::{
    center_and_resize_unlock_window, get_idle_duration, get_primary_screen_size,
    handle_main_window_hotkey as toggle_main_window_hotkey, hide_main_window,
    is_quick_search_active, restore_other_instance_window, schedule_quick_search_focus,
    schedule_unlock_window_focus, setup_working_directory, show_and_focus_main_window,
    MAIN_WINDOW_HIDDEN_TO_TRAY as HIDDEN_TO_TRAY_FLAG,
};

#[cfg(target_os = "windows")]
use gui::win_interop::get_main_window_hwnd;
#[cfg(target_os = "windows")]
use gui::win_pen::win_pen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 0. Limit to single instance running on this computer
    let single_instance =
        match note_vault::single_instance::SingleInstance::new("NoteVault_App_SingleInstance") {
            Ok(si) => si,
            Err(e) => {
                eprintln!(
                    "[SingleInstance] Warning: Failed to check single instance: {}",
                    e
                );
                return Err(e);
            }
        };

    if !single_instance.is_single() {
        eprintln!(
            "Another instance of NoteVault is already running. Activating existing instance and exiting."
        );
        restore_other_instance_window();
        return Ok(());
    }

    // 1. Ensure working directory is properly set, especially for autostart
    setup_working_directory(&args);

    let config = AppConfig::load();

    // Synchronize startup registration with the current executable path if enabled
    if config.launch_at_startup {
        let _ = note_vault::startup::set_launch_at_startup(true, config.minimize_to_tray);
    }
    let should_start_minimized = args.minimized && config.minimize_to_tray;
    if should_start_minimized {
        #[cfg(target_os = "windows")]
        HIDDEN_TO_TRAY_FLAG.store(true, Ordering::Relaxed);
    }

    // Determine vault path (CLI overrides config temporarily)
    let initial_vault_path_str = if let Some(ref cli_p) = args.vault_path {
        cli_p.to_string_lossy().to_string()
    } else {
        config.vault_path.clone()
    };

    let initial_vault_path = if args.vault_path.is_some() {
        PathBuf::from(&initial_vault_path_str)
    } else {
        config.resolved_vault_path()
    };
    let initial_vault_path_display = initial_vault_path_str.clone();

    // Keep single instance lock active for entire process lifetime
    let _single_instance_guard = single_instance;

    // Initialize Global Hotkeys
    let initial_hotkey = parse_hotkey_string(&config.global_hotkey)
        .or_else(|_| parse_hotkey_string("Shift+Space"))
        .ok()
        .map(|(hk, _)| hk);

    let initial_main_hotkey = parse_hotkey_string(&config.main_window_hotkey)
        .or_else(|_| parse_hotkey_string("Control+Shift+Space"))
        .ok()
        .map(|(hk, _)| hk);

    let state = AppState::new(
        config.clone(),
        initial_vault_path.clone(),
        initial_hotkey,
        initial_main_hotkey,
    );

    // Slint Windows: Main, QuickSearch, UnlockWindow
    let main_window = MainWindow::new()?;
    main_window
        .window()
        .set_size(slint::LogicalSize::new(1534.0, 740.0));
    let window_weak = main_window.as_weak();

    let quick_search = QuickSearchWindow::new()?;
    let unlock_window = UnlockWindow::new()?;
    let quick_search_weak = quick_search.as_weak();
    let unlock_window_weak = unlock_window.as_weak();

    // Initialize Theme
    let theme_name = match config.theme.as_str() {
        "blue" => "blue",
        "light" => "light",
        _ => "dark",
    };
    let is_dark = theme_name != "light";
    main_window.global::<Theme>().set_theme(theme_name.into());
    main_window.global::<Theme>().set_is_dark(is_dark);
    quick_search.global::<Theme>().set_theme(theme_name.into());
    quick_search.global::<Theme>().set_is_dark(is_dark);
    unlock_window.global::<Theme>().set_theme(theme_name.into());
    unlock_window.global::<Theme>().set_is_dark(is_dark);
    main_window.set_settings_theme(theme_name.into());

    let theme_options_model: slint::ModelRc<slint::SharedString> = std::rc::Rc::new(
        slint::VecModel::from(vec!["dark".into(), "blue".into(), "light".into()]),
    )
    .into();
    main_window.set_theme_options(theme_options_model);

    // Initialize Settings state
    main_window.set_settings_vault_path(initial_vault_path_display.as_str().into());
    main_window.set_settings_use_multithreading(config.use_multithreading);
    main_window.set_settings_global_hotkey(config.global_hotkey.as_str().into());
    main_window.set_settings_main_window_hotkey(config.main_window_hotkey.as_str().into());
    main_window.set_settings_minimize_to_tray(config.minimize_to_tray);
    main_window.set_settings_launch_at_startup(config.launch_at_startup);
    main_window.set_settings_auto_lock(format_auto_lock_label(config.auto_lock_minutes).into());
    main_window.set_settings_clipboard_clear(
        format_clipboard_clear_label(config.clipboard_clear_seconds).into(),
    );

    // Initialize Note Editor & Canvas preferences
    main_window.set_editor_show_line_numbers(config.editor_show_line_numbers);
    main_window.set_editor_line_wrap(config.editor_line_wrap);
    main_window.set_editor_highlight_current_line(config.editor_highlight_current_line);
    main_window.set_editor_font_size(config.editor_font_size as i32);
    main_window.set_editor_markdown_mode(false);
    main_window.set_line_numbers_text("1".into());
    main_window.set_active_note_type("text".into());
    main_window.set_canvas_tool("pen".into());
    main_window.set_canvas_stroke_width(3.0);
    main_window.set_canvas_zoom_percent(100);
    main_window.set_canvas_zoom_text("100%".into());
    main_window.set_canvas_pan_x(0.0);
    main_window.set_canvas_pan_y(0.0);
    main_window.set_canvas_width(DEFAULT_CANVAS_WIDTH as f32);
    main_window.set_canvas_height(DEFAULT_CANVAS_HEIGHT as f32);
    main_window.set_canvas_bg_color_hex(DEFAULT_CANVAS_BG_HEX.into());
    main_window.set_canvas_bg_color(slint::Color::from_argb_u8(255, 255, 255, 255));
    main_window.set_canvas_can_undo(false);
    main_window.set_canvas_can_redo(false);

    // Initialize column widths from config
    main_window.set_folder_pane_width(config.folder_pane_width as f32);
    main_window.set_notes_pane_width(config.notes_pane_width as f32);

    // Check keyfile on startup if configured
    if let Some(kpath) = config.resolved_keyfile_path() {
        if !kpath.exists() {
            main_window.set_unlock_error_message(
                format!("Keyfile missing at {}. Please locate it.", kpath.display()).into(),
            );
            main_window.set_show_keyfile_browse(true);
        }
    }

    // Close requests prompt user for confirmation before exiting
    main_window.window().on_close_requested({
        let window_weak = window_weak.clone();
        move || {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_show_exit_confirm_modal(true);
            }
            slint::CloseRequestResponse::KeepWindowShown
        }
    });

    // Initialize System Tray
    let tray_menu = Menu::new();
    let show_item = MenuItem::new("Show NoteVault", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    let _ = tray_menu.append(&show_item);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&quit_item);

    let show_item_id = show_item.id().clone();
    let quit_item_id = quit_item.id().clone();

    let tray_icon_handle = create_tray_icon().ok().and_then(|icon| {
        TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_menu_on_left_click(false)
            .with_tooltip("NoteVault - Encrypted Notes")
            .with_icon(icon)
            .build()
            .ok()
    });

    let tray_timer = slint::Timer::default();
    let tray_window_weak = window_weak.clone();
    let tray_quick_search_weak = quick_search_weak.clone();
    let timer_state = state.clone();

    tray_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(50),
        move || {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == show_item_id {
                    if let Some(ui) = tray_window_weak.upgrade() {
                        timer_state.touch_activity();
                        show_and_focus_main_window(&ui);
                    }
                } else if event.id == quit_item_id {
                    let _ = slint::quit_event_loop();
                    std::process::exit(0);
                }
            }
            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => {
                        if let Some(ui) = tray_window_weak.upgrade() {
                            timer_state.touch_activity();
                            show_and_focus_main_window(&ui);
                        }
                    }
                    _ => {}
                }
            }

            #[cfg(target_os = "windows")]
            {
                let hwnd = get_main_window_hwnd();
                if hwnd != 0 {
                    win_pen::install_for_hwnd(hwnd);
                }
                let minimize = timer_state.app_config.lock().unwrap().minimize_to_tray;
                if minimize {
                    let is_hidden = HIDDEN_TO_TRAY_FLAG.load(Ordering::Relaxed);
                    if !is_hidden && hwnd != 0 {
                        #[link(name = "user32")]
                        unsafe extern "system" {
                            fn IsIconic(hWnd: isize) -> i32;
                        }
                        unsafe {
                            if IsIconic(hwnd) != 0 {
                                HIDDEN_TO_TRAY_FLAG.store(true, Ordering::Relaxed);
                                hide_main_window();
                                if let Some(ui) = tray_window_weak.upgrade() {
                                    let _ = ui.hide();
                                }
                            }
                        }
                    }
                }
            }

            // Check if QuickSearchWindow lost focus -> Auto-close
            if timer_state.is_quick_search_open.load(Ordering::SeqCst) {
                let elapsed = timer_state.quick_search_shown_at.lock().unwrap().elapsed();
                if elapsed > Duration::from_millis(400) && !is_quick_search_active() {
                    if let Some(qs) = tray_quick_search_weak.upgrade() {
                        let _ = qs.hide();
                        timer_state
                            .is_quick_search_open
                            .store(false, Ordering::SeqCst);
                    }
                }
            }

            // Idle Auto-Lock check
            let auto_lock_mins = timer_state.app_config.lock().unwrap().auto_lock_minutes;
            if auto_lock_mins > 0 && timer_state.session_password.lock().unwrap().is_some() {
                let idle = get_idle_duration(&timer_state.last_activity);
                if idle >= Duration::from_secs(auto_lock_mins as u64 * 60) {
                    if let Some(ui) = tray_window_weak.upgrade() {
                        println!(
                            "[NoteVault] Auto-locking vault after {} min of inactivity.",
                            auto_lock_mins
                        );
                        lock_vault_session(
                            &ui,
                            &tray_quick_search_weak,
                            &timer_state,
                            "Vault auto-locked due to inactivity",
                        );
                    }
                }
            }

            // Clipboard Auto-Clear check (clears only if clipboard still contains the copied note text)
            let clear_secs = timer_state.app_config.lock().unwrap().clipboard_clear_seconds;
            if clear_secs > 0 {
                let expired_secret = {
                    let mut guard = timer_state.clipboard_clear.lock().unwrap();
                    if let Some((copied_at, _)) = guard.as_ref() {
                        if copied_at.elapsed() >= Duration::from_secs(clear_secs as u64) {
                            guard.take().map(|(_, text)| text)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(secret) = expired_secret {
                    if let Ok(mut cb) = Clipboard::new() {
                        if let Ok(current) = cb.get_text() {
                            if current == secret.as_str() {
                                let _ = cb.set_text("");
                            }
                        }
                    }
                }
            }
        },
    );

    // Register initial global hotkeys
    if let Some(ref mut mgr) = *state.hotkey_manager.lock().unwrap() {
        if let Some(ref hk) = *state.active_hotkey.lock().unwrap() {
            if let Err(e) = mgr.register(*hk) {
                eprintln!("Failed to register initial global hotkey: {}", e);
            }
        }
        if let Some(ref hk) = *state.active_main_hotkey.lock().unwrap() {
            if let Err(e) = mgr.register(*hk) {
                eprintln!("Failed to register initial main window hotkey: {}", e);
            }
        }
    }

    // Spawn background thread to listen for global hotkey events
    {
        let quick_search_weak = quick_search_weak.clone();
        let unlock_window_weak = unlock_window_weak.clone();
        let window_weak = window_weak.clone();
        let active_hotkey = Arc::clone(&state.active_hotkey);
        let active_main_hotkey = Arc::clone(&state.active_main_hotkey);
        let app_config = Arc::clone(&state.app_config);
        let session_password = Arc::clone(&state.session_password);
        let metadata_store = Arc::clone(&state.metadata_store);
        let is_unlock_window_open = Arc::clone(&state.is_unlock_window_open);
        let is_quick_search_open = Arc::clone(&state.is_quick_search_open);
        let quick_search_shown_at = Arc::clone(&state.quick_search_shown_at);
        let last_activity = Arc::clone(&state.last_activity);

        thread::spawn(move || {
            let receiver = GlobalHotKeyEvent::receiver();
            while let Ok(event) = receiver.recv() {
                if event.state == HotKeyState::Pressed {
                    let qs_hk_id = active_hotkey.lock().unwrap().map(|hk| hk.id());
                    let main_hk_id = active_main_hotkey.lock().unwrap().map(|hk| hk.id());

                    if main_hk_id == Some(event.id) {
                        if let Ok(mut guard) = last_activity.lock() {
                            *guard = std::time::Instant::now();
                        }
                        let weak = window_weak.clone();
                        let cfg_arc = Arc::clone(&app_config);
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = weak.upgrade() {
                                let min_to_tray = cfg_arc.lock().unwrap().minimize_to_tray;
                                toggle_main_window_hotkey(&ui, min_to_tray);
                            }
                        })
                        .ok();
                    } else if qs_hk_id == Some(event.id) {
                        if let Ok(mut guard) = last_activity.lock() {
                            *guard = std::time::Instant::now();
                        }
                        let is_locked = session_password.lock().unwrap().is_none();
                        if is_locked {
                            let uw_weak = unlock_window_weak.clone();
                            let is_open = Arc::clone(&is_unlock_window_open);
                            let cfg_arc = Arc::clone(&app_config);

                            slint::invoke_from_event_loop(move || {
                                if let Some(uw) = uw_weak.upgrade() {
                                    if is_open.load(Ordering::SeqCst) {
                                        is_open.store(false, Ordering::SeqCst);
                                        uw.invoke_clear_fields();
                                        let _ = uw.hide();
                                    } else {
                                        uw.invoke_clear_fields();
                                        let cfg = cfg_arc.lock().unwrap();
                                        if let Some(kpath) = cfg.resolved_keyfile_path() {
                                            if !kpath.exists() {
                                                uw.set_error_message(
                                                    format!(
                                                        "Keyfile missing at {}. Please locate it.",
                                                        kpath.display()
                                                    )
                                                    .into(),
                                                );
                                                uw.set_show_keyfile_browse(true);
                                            } else {
                                                uw.set_show_keyfile_browse(false);
                                            }
                                        } else {
                                            uw.set_show_keyfile_browse(false);
                                        }

                                        center_and_resize_unlock_window(&uw);
                                        is_open.store(true, Ordering::SeqCst);
                                        let _ = uw.show();
                                        schedule_unlock_window_focus(&uw, &is_open);
                                    }
                                }
                            })
                            .ok();
                        } else {
                            let weak = quick_search_weak.clone();
                            let m_store = Arc::clone(&metadata_store);
                            let is_open = Arc::clone(&is_quick_search_open);
                            let shown_at = Arc::clone(&quick_search_shown_at);

                            slint::invoke_from_event_loop(move || {
                                if let Some(qs) = weak.upgrade() {
                                    if is_open.load(Ordering::SeqCst) {
                                        is_open.store(false, Ordering::SeqCst);
                                        let _ = qs.hide();
                                    } else {
                                        qs.set_search_text("".into());
                                        let initial_results = {
                                            let store = m_store.lock().unwrap();
                                            filter_qs_results("", &store)
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

                                        is_open.store(true, Ordering::SeqCst);
                                        *shown_at.lock().unwrap() = std::time::Instant::now();

                                        let _ = qs.show();
                                        schedule_quick_search_focus(&qs, &is_open);
                                    }
                                }
                            })
                            .ok();
                        }
                    }
                }
            }
        });
    }

    // Startup flow: Check if vault path is empty
    let needs_onboarding = initial_vault_path_str.trim().is_empty();
    if needs_onboarding {
        main_window.set_show_welcome_modal(true);
        main_window.set_welcome_vault_path("".into());
        main_window.set_is_locked(false);
        main_window.set_vault_status_text("No vault folder selected".into());
    } else {
        if !initial_vault_path.exists() {
            let _ = std::fs::create_dir_all(&initial_vault_path);
        }
        main_window.set_show_welcome_modal(false);
        main_window.set_is_locked(true);
        main_window.set_vault_status_text("Vault locked".into());
    }

    main_window.set_active_folder("*All Notes*".into());
    main_window.set_note_category("General".into());

    // Register all Slint callbacks
    handlers::register_all(&main_window, &quick_search, &unlock_window, &state);

    let _tray_icon = tray_icon_handle;
    let _tray_timer = tray_timer;

    if !should_start_minimized {
        main_window.show()?;
    }
    slint::run_event_loop_until_quit()?;
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
