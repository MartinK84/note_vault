pub mod attachments;
pub mod auth;
pub mod canvas;
pub mod export;
pub mod folders;
pub mod notes;
pub mod quick_search;
pub mod settings;

use note_vault::{MainWindow, QuickSearchWindow, UnlockWindow};

use crate::gui::state::AppState;

/// Registers all Slint UI callbacks across all windows.
pub fn register_all(
    main_window: &MainWindow,
    quick_search: &QuickSearchWindow,
    unlock_window: &UnlockWindow,
    state: &AppState,
) {
    auth::register(main_window, quick_search, state);
    notes::register(main_window, state);
    folders::register(main_window, state);
    attachments::register(main_window, state);
    canvas::register(main_window, state);
    settings::register(main_window, quick_search, unlock_window, state);
    export::register(main_window, state);
    quick_search::register(main_window, quick_search, unlock_window, state);
}
