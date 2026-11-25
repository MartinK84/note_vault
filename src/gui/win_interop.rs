use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use note_vault::config::AppConfig;
use note_vault::{MainWindow, QuickSearchWindow, UnlockWindow};
use slint::ComponentHandle;

use crate::gui::state::Args;

#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicIsize;

#[cfg(target_os = "windows")]
use crate::gui::win_pen::win_pen;

/// Retrieves primary screen dimensions (width, height) in physical pixels.
#[cfg(target_os = "windows")]
pub fn get_primary_screen_size() -> (f32, f32) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetSystemMetrics(nIndex: i32) -> i32;
    }
    unsafe {
        let w = GetSystemMetrics(0); // SM_CXSCREEN
        let h = GetSystemMetrics(1); // SM_CYSCREEN
        if w > 0 && h > 0 {
            (w as f32, h as f32)
        } else {
            (1920.0, 1080.0)
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_primary_screen_size() -> (f32, f32) {
    (1920.0, 1080.0)
}

/// Checks if the QuickSearchWindow currently has the foreground focus.
#[cfg(target_os = "windows")]
pub fn is_quick_search_active() -> bool {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetForegroundWindow() -> isize;
        fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
    }
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd == 0 {
            return false;
        }
        let mut buf = [0u16; 256];
        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 256);
        if len > 0 {
            let title = String::from_utf16_lossy(&buf[..len as usize]);
            title.contains("NoteVault Quick Search")
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_quick_search_active() -> bool {
    true
}

/// Finds a top-level window belonging to this process whose title contains `title_substr`.
#[cfg(target_os = "windows")]
fn find_own_window_by_title(title_substr: &str) -> isize {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn EnumWindows(lpEnumFunc: unsafe extern "system" fn(isize, isize) -> i32, lParam: isize) -> i32;
        fn GetWindowThreadProcessId(hWnd: isize, lpdwProcessId: *mut u32) -> u32;
        fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
    }

    struct EnumSearch<'a> {
        pid: u32,
        needle: &'a str,
        found: isize,
    }

    unsafe extern "system" fn enum_proc(wnd: isize, lparam: isize) -> i32 {
        let search = unsafe { &mut *(lparam as *mut EnumSearch<'_>) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(wnd, &mut pid) };
        if pid == search.pid {
            let mut title_buf = [0u16; 256];
            let len = unsafe { GetWindowTextW(wnd, title_buf.as_mut_ptr(), 256) };
            if len > 0 {
                let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                if title.contains(search.needle) {
                    search.found = wnd;
                    return 0;
                }
            }
        }
        1
    }

    unsafe {
        let title_wide: Vec<u16> = title_substr
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd != 0 {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == std::process::id() {
                return hwnd;
            }
        }

        let mut search = EnumSearch {
            pid: std::process::id(),
            needle: title_substr,
            found: 0,
        };
        EnumWindows(enum_proc, &mut search as *mut EnumSearch<'_> as isize);
        search.found
    }
}

/// Reliably brings `hwnd` to the foreground and gives it Win32 keyboard focus,
/// working around Windows foreground lock restrictions via `AttachThreadInput`.
#[cfg(target_os = "windows")]
fn force_foreground_window(hwnd: isize) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn IsWindow(hWnd: isize) -> i32;
        fn IsIconic(hWnd: isize) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetForegroundWindow() -> isize;
        fn GetWindowThreadProcessId(hWnd: isize, lpdwProcessId: *mut u32) -> u32;
        fn AttachThreadInput(idAttach: u32, idAttachTo: u32, fAttach: i32) -> i32;
        fn AllowSetForegroundWindow(dwProcessId: u32) -> i32;
        fn BringWindowToTop(hWnd: isize) -> i32;
        fn SetForegroundWindow(hWnd: isize) -> i32;
        fn SetActiveWindow(hWnd: isize) -> isize;
        fn SetFocus(hWnd: isize) -> isize;
        fn SetWindowPos(
            hWnd: isize,
            hWndInsertAfter: isize,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            uFlags: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThreadId() -> u32;
    }

    if hwnd == 0 {
        return;
    }

    unsafe fn try_activate_with_attach(hwnd: isize, cur_tid: u32) {
        let fg_hwnd = unsafe { GetForegroundWindow() };
        let fg_tid = if fg_hwnd != 0 {
            unsafe { GetWindowThreadProcessId(fg_hwnd, std::ptr::null_mut()) }
        } else {
            0
        };
        let attached =
            fg_tid != 0 && fg_tid != cur_tid && unsafe { AttachThreadInput(cur_tid, fg_tid, 1) } != 0;
        unsafe {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetActiveWindow(hwnd);
            SetFocus(hwnd);
        }
        if attached {
            unsafe { AttachThreadInput(cur_tid, fg_tid, 0) };
        }
    }

    unsafe {
        if IsWindow(hwnd) == 0 {
            return;
        }
        const SW_SHOW: i32 = 5;
        const SW_RESTORE: i32 = 9;
        ShowWindow(hwnd, if IsIconic(hwnd) != 0 { SW_RESTORE } else { SW_SHOW });

        AllowSetForegroundWindow(u32::MAX);
        let cur_tid = GetCurrentThreadId();
        try_activate_with_attach(hwnd, cur_tid);

        if GetForegroundWindow() != hwnd {
            const HWND_TOPMOST: isize = -1;
            const HWND_NOTOPMOST: isize = -2;
            const SWP_NOSIZE: u32 = 0x0001;
            const SWP_NOMOVE: u32 = 0x0002;
            const SWP_SHOWWINDOW: u32 = 0x0040;
            let flags = SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW;
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags);
            SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, flags);
            try_activate_with_attach(hwnd, cur_tid);
        }
    }
}

#[cfg(target_os = "windows")]
fn activate_quick_search_window() {
    let hwnd = find_own_window_by_title("NoteVault Quick Search");
    if hwnd != 0 {
        force_foreground_window(hwnd);
    }
}

#[cfg(not(target_os = "windows"))]
fn activate_quick_search_window() {}

#[cfg(target_os = "windows")]
static MAIN_WINDOW_HWND: AtomicIsize = AtomicIsize::new(0);

pub static MAIN_WINDOW_HIDDEN_TO_TRAY: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
#[repr(C)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
const CLSID_TASKBAR_LIST: GUID = GUID {
    data1: 0x56FDF344,
    data2: 0xFD6D,
    data3: 0x11D0,
    data4: [0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90],
};

#[cfg(target_os = "windows")]
const IID_ITASKBAR_LIST: GUID = GUID {
    data1: 0x56FDF342,
    data2: 0xFD6D,
    data3: 0x11D0,
    data4: [0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90],
};

#[cfg(target_os = "windows")]
#[repr(C)]
struct ITaskbarListVtbl {
    query_interface: unsafe extern "system" fn(
        this: *mut ITaskbarList,
        riid: *const GUID,
        ppv: *mut *mut std::ffi::c_void,
    ) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut ITaskbarList) -> u32,
    release: unsafe extern "system" fn(this: *mut ITaskbarList) -> u32,
    hr_init: unsafe extern "system" fn(this: *mut ITaskbarList) -> i32,
    add_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    delete_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    activate_tab: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
    set_active_alt: unsafe extern "system" fn(this: *mut ITaskbarList, hwnd: isize) -> i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ITaskbarList {
    vtbl: *const ITaskbarListVtbl,
}

#[cfg(target_os = "windows")]
fn taskbar_update_tab(hwnd: isize, add: bool) {
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(pvReserved: *mut std::ffi::c_void, dwCoInit: u32) -> i32;
        fn CoCreateInstance(
            rclsid: *const GUID,
            pUnkOuter: *mut std::ffi::c_void,
            dwClsContext: u32,
            riid: *const GUID,
            ppv: *mut *mut std::ffi::c_void,
        ) -> i32;
    }
    unsafe {
        let _ = CoInitializeEx(std::ptr::null_mut(), 0);
        let mut obj: *mut std::ffi::c_void = std::ptr::null_mut();
        if CoCreateInstance(
            &CLSID_TASKBAR_LIST,
            std::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ITASKBAR_LIST,
            &mut obj,
        ) == 0
            && !obj.is_null()
        {
            let taskbar = obj as *mut ITaskbarList;
            let vtbl = &*(*taskbar).vtbl;
            let _ = (vtbl.hr_init)(taskbar);
            if add {
                let _ = (vtbl.add_tab)(taskbar, hwnd);
            } else {
                let _ = (vtbl.delete_tab)(taskbar, hwnd);
            }
            let _ = (vtbl.release)(taskbar);
        }
    }
}

#[cfg(target_os = "windows")]
pub fn get_main_window_hwnd() -> isize {
    let cached = MAIN_WINDOW_HWND.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let hwnd = find_own_window_by_title("NoteVault - Secure Encrypted Notes");
    if hwnd != 0 {
        MAIN_WINDOW_HWND.store(hwnd, Ordering::Relaxed);
    }
    hwnd
}

/// Hides the main window completely from desktop and taskbar on Windows.
#[cfg(target_os = "windows")]
pub fn hide_main_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
    }
    unsafe {
        let hwnd = get_main_window_hwnd();
        if hwnd != 0 {
            const GWL_EXSTYLE: i32 = -20;
            const WS_EX_TOOLWINDOW: isize = 0x00000080;
            const WS_EX_APPWINDOW: isize = 0x00040000;
            let cur = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (cur & !WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW);
            taskbar_update_tab(hwnd, false);
            ShowWindow(hwnd, 0); // SW_HIDE
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn hide_main_window() {}

/// Restores and focuses the main NoteVault application window on Windows.
#[cfg(target_os = "windows")]
pub fn restore_main_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
    }
    unsafe {
        let hwnd = get_main_window_hwnd();
        if hwnd != 0 {
            const GWL_EXSTYLE: i32 = -20;
            const WS_EX_TOOLWINDOW: isize = 0x00000080;
            const WS_EX_APPWINDOW: isize = 0x00040000;
            let cur = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (cur & !WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW);
            ShowWindow(hwnd, 9); // SW_RESTORE
            taskbar_update_tab(hwnd, true);
            force_foreground_window(hwnd);
            win_pen::install_for_hwnd(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn restore_main_window() {}

/// Minimizes the main NoteVault application window to the taskbar on Windows.
#[cfg(target_os = "windows")]
pub fn minimize_main_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
    }
    unsafe {
        let hwnd = get_main_window_hwnd();
        if hwnd != 0 {
            const SW_MINIMIZE: i32 = 6;
            ShowWindow(hwnd, SW_MINIMIZE);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn minimize_main_window() {}

/// Returns true if the main window is currently visible on screen (not hidden to tray and not minimized).
#[cfg(target_os = "windows")]
pub fn is_main_window_visible() -> bool {
    if MAIN_WINDOW_HIDDEN_TO_TRAY.load(Ordering::Relaxed) {
        return false;
    }
    let hwnd = get_main_window_hwnd();
    if hwnd != 0 {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn IsIconic(hWnd: isize) -> i32;
            fn IsWindowVisible(hWnd: isize) -> i32;
        }
        unsafe {
            if IsIconic(hwnd) != 0 {
                return false;
            }
            if IsWindowVisible(hwnd) == 0 {
                return false;
            }
            return true;
        }
    }
    !MAIN_WINDOW_HIDDEN_TO_TRAY.load(Ordering::Relaxed)
}

#[cfg(not(target_os = "windows"))]
pub fn is_main_window_visible() -> bool {
    !MAIN_WINDOW_HIDDEN_TO_TRAY.load(Ordering::Relaxed)
}

/// Shows, activates, and focuses the main window (and its unlock password field if locked).
pub fn show_and_focus_main_window(ui: &MainWindow) {
    let _ = ui.show();
    #[cfg(target_os = "windows")]
    MAIN_WINDOW_HIDDEN_TO_TRAY.store(false, Ordering::Relaxed);
    restore_main_window();
    if ui.get_is_locked() && ui.get_show_unlock_modal() {
        ui.invoke_focus_unlock_password();
    }

    for delay_ms in [25u64, 75u64] {
        let weak = ui.as_weak();
        slint::Timer::single_shot(Duration::from_millis(delay_ms), move || {
            if let Some(ui) = weak.upgrade() {
                if is_main_window_visible() {
                    restore_main_window();
                    if ui.get_is_locked() && ui.get_show_unlock_modal() {
                        ui.invoke_focus_unlock_password();
                    }
                }
            }
        });
    }
}

/// Handles toggling the main window state when its global hotkey is pressed.
pub fn handle_main_window_hotkey(ui: &MainWindow, min_to_tray: bool) {
    if is_main_window_visible() {
        if min_to_tray {
            MAIN_WINDOW_HIDDEN_TO_TRAY.store(true, Ordering::Relaxed);
            hide_main_window();
            let _ = ui.hide();
        } else {
            minimize_main_window();
        }
    } else {
        show_and_focus_main_window(ui);
    }
}

/// Restores and focuses the window of an already running instance of NoteVault on Windows.
#[cfg(target_os = "windows")]
pub fn restore_other_instance_window() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn EnumWindows(lpEnumFunc: unsafe extern "system" fn(isize, isize) -> i32, lParam: isize) -> i32;
        fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
    }

    unsafe extern "system" fn enum_proc(wnd: isize, lparam: isize) -> i32 {
        unsafe {
            let mut title_buf = [0u16; 256];
            let len = GetWindowTextW(wnd, title_buf.as_mut_ptr(), 256);
            if len > 0 {
                let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                if title.contains("NoteVault - Secure Encrypted Notes") {
                    *(lparam as *mut isize) = wnd;
                    return 0;
                }
            }
            1
        }
    }

    unsafe {
        let title_wide: Vec<u16> = "NoteVault - Secure Encrypted Notes"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd == 0 {
            let mut found_hwnd: isize = 0;
            EnumWindows(enum_proc, &mut found_hwnd as *mut isize as isize);
            hwnd = found_hwnd;
        }
        if hwnd != 0 {
            const GWL_EXSTYLE: i32 = -20;
            const WS_EX_TOOLWINDOW: isize = 0x00000080;
            const WS_EX_APPWINDOW: isize = 0x00040000;
            let cur = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (cur & !WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW);
            ShowWindow(hwnd, 9); // SW_RESTORE
            taskbar_update_tab(hwnd, true);
            force_foreground_window(hwnd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn restore_other_instance_window() {}

/// Ensures that the working directory is properly set to the application directory
/// when launched via autostart or from a system directory (such as C:\Windows\System32).
pub fn setup_working_directory(args: &Args) {
    if let Some(ref custom_dir) = args.working_dir {
        let _ = std::env::set_current_dir(custom_dir);
        return;
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let should_switch = if args.minimized || args.autostart {
                true
            } else if let Ok(cwd) = std::env::current_dir() {
                #[cfg(target_os = "windows")]
                let is_system_dir = {
                    let cwd_str = cwd.to_string_lossy().to_lowercase();
                    cwd_str.ends_with("\\system32")
                        || cwd_str.ends_with("\\syswow64")
                        || cwd_str == "c:\\windows"
                        || cwd_str.starts_with("c:\\windows\\")
                };
                #[cfg(not(target_os = "windows"))]
                let is_system_dir = false;

                is_system_dir
                    || (!cwd.join(AppConfig::CONFIG_FILE).exists()
                        && exe_dir.join(AppConfig::CONFIG_FILE).exists())
            } else {
                false
            };

            if should_switch {
                let _ = std::env::set_current_dir(exe_dir);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn activate_unlock_window() {
    let hwnd = find_own_window_by_title("NoteVault - Unlock Vault");
    if hwnd != 0 {
        force_foreground_window(hwnd);
    }
}

#[cfg(not(target_os = "windows"))]
fn activate_unlock_window() {}

/// Ensures UnlockWindow is brought to the foreground and its password input receives focus.
pub fn schedule_unlock_window_focus(uw: &UnlockWindow, is_open: &Arc<AtomicBool>) {
    activate_unlock_window();
    uw.invoke_focus_password();

    for delay_ms in [25u64, 75u64] {
        let uw_weak = uw.as_weak();
        let is_open_flag = Arc::clone(is_open);
        slint::Timer::single_shot(Duration::from_millis(delay_ms), move || {
            if is_open_flag.load(Ordering::SeqCst) {
                if let Some(uw) = uw_weak.upgrade() {
                    activate_unlock_window();
                    uw.invoke_focus_password();
                }
            }
        });
    }
}

/// Ensures QuickSearchWindow is brought to the foreground and its search input receives focus.
pub fn schedule_quick_search_focus(qs: &QuickSearchWindow, is_open: &Arc<AtomicBool>) {
    activate_quick_search_window();
    qs.invoke_focus_search();

    for delay_ms in [25u64, 75u64] {
        let qs_weak = qs.as_weak();
        let is_open_flag = Arc::clone(is_open);
        slint::Timer::single_shot(Duration::from_millis(delay_ms), move || {
            if is_open_flag.load(Ordering::SeqCst) {
                if let Some(qs) = qs_weak.upgrade() {
                    activate_quick_search_window();
                    qs.invoke_focus_search();
                }
            }
        });
    }
}

/// Sizes and centers the UnlockWindow on the primary display according to its content height.
pub fn center_and_resize_unlock_window(uw: &UnlockWindow) {
    let (screen_w, screen_h) = get_primary_screen_size();
    let scale = uw.window().scale_factor();
    let logical_w = if scale > 0.0 { screen_w / scale } else { screen_w };
    let logical_h = if scale > 0.0 { screen_h / scale } else { screen_h };

    let win_w = 460.0;
    let req_h = uw.get_requested_height();
    let win_h = if req_h > 50.0 { req_h } else { 180.0 };
    let pos_x = (logical_w - win_w) / 2.0;
    let pos_y = (logical_h - win_h) / 2.0;

    uw.window().set_size(slint::LogicalSize::new(win_w, win_h));
    uw.window().set_position(slint::LogicalPosition::new(pos_x, pos_y));
}

/// Opens an `http://` or `https://` URL without passing it through a command shell.
pub fn open_url_safely(url: &str) {
    let trimmed = url.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return;
    }

    #[cfg(target_os = "windows")]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                hwnd: isize,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> isize;
        }
        let op: Vec<u16> = "open\0".encode_utf16().collect();
        let file: Vec<u16> = trimmed.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let _ = ShellExecuteW(
                0,
                op.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1, // SW_SHOWNORMAL
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("xdg-open").arg(trimmed).spawn();
    }
}

/// Returns the elapsed idle duration since the last user input.
#[cfg(target_os = "windows")]
pub fn get_idle_duration(fallback_last_activity: &Mutex<Instant>) -> Duration {
    #[repr(C)]
    struct LastInputInfo {
        cb_size: u32,
        dw_time: u32,
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetLastInputInfo(plii: *mut LastInputInfo) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTickCount() -> u32;
    }
    let mut lii = LastInputInfo {
        cb_size: std::mem::size_of::<LastInputInfo>() as u32,
        dw_time: 0,
    };
    unsafe {
        if GetLastInputInfo(&mut lii) != 0 {
            let now_ticks = GetTickCount();
            let idle_ms = now_ticks.wrapping_sub(lii.dw_time);
            return Duration::from_millis(idle_ms as u64);
        }
    }
    fallback_last_activity.lock().unwrap().elapsed()
}

#[cfg(not(target_os = "windows"))]
pub fn get_idle_duration(fallback_last_activity: &Mutex<Instant>) -> Duration {
    fallback_last_activity.lock().unwrap().elapsed()
}
