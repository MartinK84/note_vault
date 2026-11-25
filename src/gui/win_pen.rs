#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenMouseButton {
    Left,
    Right,
}

pub const PEN_POINTER_FLAG_SECONDBUTTON: u32 = 0x0000_0020;
pub const PEN_FLAG_BARREL_BIT: u32 = 0x0000_0001;
pub const PEN_FLAG_INVERTED_BIT: u32 = 0x0000_0002;
pub const PEN_FLAG_ERASER_BIT: u32 = 0x0000_0004;

/// Packs signed 16-bit client coordinates `(x, y)` into a Win32 mouse message `LPARAM`.
pub fn pack_client_lparam(x: i32, y: i32) -> isize {
    let lx = (x as i16) as u16 as usize;
    let ly = (y as i16) as u16 as usize;
    ((ly << 16) | lx) as isize
}

/// Maps Windows pointer/pen flags to primary (pen draw) or secondary (eraser) button.
pub fn determine_pen_button(pointer_flags: u32, pen_flags: u32) -> PenMouseButton {
    if (pointer_flags & PEN_POINTER_FLAG_SECONDBUTTON) != 0
        || (pen_flags & (PEN_FLAG_BARREL_BIT | PEN_FLAG_ERASER_BIT | PEN_FLAG_INVERTED_BIT)) != 0
    {
        PenMouseButton::Right
    } else {
        PenMouseButton::Left
    }
}

/// Builds a Win32 mouse `WPARAM` bitmask from modifier keys and the active pen button.
pub fn build_mouse_wparam(ctrl: bool, shift: bool, pressed: Option<PenMouseButton>) -> usize {
    let mut flags = 0usize;
    if pressed == Some(PenMouseButton::Left) {
        flags |= 0x0001; // MK_LBUTTON
    }
    if pressed == Some(PenMouseButton::Right) {
        flags |= 0x0002; // MK_RBUTTON
    }
    if shift {
        flags |= 0x0004; // MK_SHIFT
    }
    if ctrl {
        flags |= 0x0008; // MK_CONTROL
    }
    flags
}

/// Suppresses touch/palm messages while a pen is in range or was active within the cooldown window.
pub fn should_suppress_touch_for_pen(
    in_range: bool,
    last_activity: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    in_range
        || last_activity
            .is_some_and(|t| now.saturating_duration_since(t) < std::time::Duration::from_millis(600))
}

#[cfg(target_os = "windows")]
pub mod win_pen {
    use super::{
        build_mouse_wparam, determine_pen_button, pack_client_lparam, should_suppress_touch_for_pen,
        PenMouseButton,
    };
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::OnceLock;
    use std::time::Instant;

    const GWLP_WNDPROC: i32 = -4;
    const SM_DIGITIZER: i32 = 94;
    const NID_READY: i32 = 0x80;

    const WM_NCDESTROY: u32 = 0x0082;
    const WM_MOUSEMOVE: u32 = 0x0200;
    const WM_LBUTTONDOWN: u32 = 0x0201;
    const WM_LBUTTONUP: u32 = 0x0202;
    const WM_RBUTTONDOWN: u32 = 0x0204;
    const WM_RBUTTONUP: u32 = 0x0205;
    const WM_TOUCH: u32 = 0x0240;
    const WM_POINTERUPDATE: u32 = 0x0245;
    const WM_POINTERDOWN: u32 = 0x0246;
    const WM_POINTERUP: u32 = 0x0247;
    const WM_POINTERENTER: u32 = 0x0249;
    const WM_POINTERLEAVE: u32 = 0x024A;
    const WM_POINTERACTIVATE: u32 = 0x024B;
    const WM_POINTERCAPTURECHANGED: u32 = 0x024C;
    const WM_TABLET_QUERYSYSTEMGESTURESTATUS: u32 = 0x02CC;

    const TABLET_DISABLE_PRESSANDHOLD: usize = 0x0000_0001;
    const TABLET_DISABLE_PENTAPFEEDBACK: usize = 0x0000_0008;
    const TABLET_DISABLE_PENBARRELFEEDBACK: usize = 0x0000_0010;
    const TABLET_DISABLE_TOUCHSWITCH: usize = 0x0000_8000;
    const TABLET_DISABLE_FLICKS: usize = 0x0001_0000;
    const TABLET_DISABLE_SMOOTHSCROLLING: usize = 0x0008_0000;

    const PT_TOUCH: i32 = 2;
    const PT_PEN: i32 = 3;

    const POINTER_FLAG_INCONTACT: u32 = 0x0000_0004;
    const POINTER_FLAG_CANCELED: u32 = 0x0000_8000;
    const POINTER_FLAG_DOWN: u32 = 0x0001_0000;
    const POINTER_FLAG_UP: u32 = 0x0004_0000;

    const VK_SHIFT: i32 = 0x10;
    const VK_CONTROL: i32 = 0x11;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct PointerInfo {
        pointer_type: i32,
        pointer_id: u32,
        frame_id: u32,
        pointer_flags: u32,
        source_device: isize,
        hwnd_target: isize,
        pt_pixel_location: Point,
        pt_himetric_location: Point,
        pt_pixel_location_raw: Point,
        pt_himetric_location_raw: Point,
        dw_time: u32,
        history_count: u32,
        input_data: i32,
        dw_key_states: u32,
        performance_count: u64,
        button_change_type: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct PointerPenInfo {
        pointer_info: PointerInfo,
        pen_flags: u32,
        pen_mask: u32,
        pressure: u32,
        rotation: u32,
        tilt_x: i32,
        tilt_y: i32,
    }

    type GetPointerTypeFn = unsafe extern "system" fn(u32, *mut i32) -> i32;
    type GetPointerInfoFn = unsafe extern "system" fn(u32, *mut PointerInfo) -> i32;
    type GetPointerFrameInfoHistoryFn =
        unsafe extern "system" fn(u32, *mut u32, *mut u32, *mut PointerInfo) -> i32;
    type GetPointerPenInfoFn = unsafe extern "system" fn(u32, *mut PointerPenInfo) -> i32;
    type SkipPointerFrameMessagesFn = unsafe extern "system" fn(u32) -> i32;
    type RegisterTouchWindowFn = unsafe extern "system" fn(isize, u32) -> i32;
    type UnregisterTouchWindowFn = unsafe extern "system" fn(isize) -> i32;
    type CloseTouchInputHandleFn = unsafe extern "system" fn(isize) -> i32;

    struct User32Apis {
        get_pointer_type: Option<GetPointerTypeFn>,
        get_pointer_info: Option<GetPointerInfoFn>,
        get_pointer_frame_info_history: Option<GetPointerFrameInfoHistoryFn>,
        get_pointer_pen_info: Option<GetPointerPenInfoFn>,
        skip_pointer_frame_messages: Option<SkipPointerFrameMessagesFn>,
        register_touch_window: Option<RegisterTouchWindowFn>,
        unregister_touch_window: Option<UnregisterTouchWindowFn>,
        close_touch_input_handle: Option<CloseTouchInputHandleFn>,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleA(lpModuleName: *const u8) -> isize;
        fn GetProcAddress(hModule: isize, lpProcName: *const u8) -> *const std::ffi::c_void;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn CallWindowProcW(
            lpPrevWndFunc: isize,
            hWnd: isize,
            msg: u32,
            wParam: usize,
            lParam: isize,
        ) -> isize;
        fn GetWindowLongPtrW(hWnd: isize, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(hWnd: isize, nIndex: i32, dwNewLong: isize) -> isize;
        fn ScreenToClient(hWnd: isize, lpPoint: *mut Point) -> i32;
        fn GetCursorPos(lpPoint: *mut Point) -> i32;
        fn GetKeyState(nVirtKey: i32) -> i16;
        fn GetSystemMetrics(nIndex: i32) -> i32;
    }

    unsafe fn resolve_proc<T>(module: isize, name: &[u8]) -> Option<T> {
        if module == 0 {
            return None;
        }
        let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy::<*const std::ffi::c_void, T>(&ptr) })
        }
    }

    fn apis() -> &'static User32Apis {
        static APIS: OnceLock<User32Apis> = OnceLock::new();
        APIS.get_or_init(|| unsafe {
            let user32 = GetModuleHandleA(b"user32.dll\0".as_ptr());
            User32Apis {
                get_pointer_type: resolve_proc(user32, b"GetPointerType\0"),
                get_pointer_info: resolve_proc(user32, b"GetPointerInfo\0"),
                get_pointer_frame_info_history: resolve_proc(user32, b"GetPointerFrameInfoHistory\0"),
                get_pointer_pen_info: resolve_proc(user32, b"GetPointerPenInfo\0"),
                skip_pointer_frame_messages: resolve_proc(user32, b"SkipPointerFrameMessages\0"),
                register_touch_window: resolve_proc(user32, b"RegisterTouchWindow\0"),
                unregister_touch_window: resolve_proc(user32, b"UnregisterTouchWindow\0"),
                close_touch_input_handle: resolve_proc(user32, b"CloseTouchInputHandle\0"),
            }
        })
    }

    #[derive(Default)]
    struct PenState {
        active_pointer_id: Option<u32>,
        pressed_button: Option<PenMouseButton>,
        in_range: bool,
        last_pen_activity: Option<Instant>,
    }

    thread_local! {
        static PEN_STATE: RefCell<PenState> = RefCell::new(PenState::default());
    }

    static SUBCLASSED_HWND: AtomicIsize = AtomicIsize::new(0);
    static PREV_WNDPROC: AtomicIsize = AtomicIsize::new(0);

    /// Installs the Win32 pen & palm-rejection subclass on `hwnd` if not already installed.
    pub fn install_for_hwnd(hwnd: isize) {
        if hwnd == 0 || SUBCLASSED_HWND.load(Ordering::Acquire) == hwnd {
            return;
        }

        let api = apis();
        unsafe {
            // Replace winit's TWF_WANTPALM touch registration so Windows enables hardware palm rejection.
            if (GetSystemMetrics(SM_DIGITIZER) & NID_READY) != 0 {
                if let (Some(unreg), Some(reg)) =
                    (api.unregister_touch_window, api.register_touch_window)
                {
                    let _ = unreg(hwnd);
                    let _ = reg(hwnd, 0);
                }
            }

            let our_proc = pen_wndproc as *const () as usize as isize;
            let current_proc = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
            if current_proc != 0 && current_proc != our_proc {
                PREV_WNDPROC.store(current_proc, Ordering::Release);
                let prev = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, our_proc);
                if prev != 0 {
                    PREV_WNDPROC.store(prev, Ordering::Release);
                    SUBCLASSED_HWND.store(hwnd, Ordering::Release);
                }
            }
        }
    }

    fn current_modifiers() -> (bool, bool) {
        unsafe {
            (
                (GetKeyState(VK_CONTROL) as u16 & 0x8000) != 0,
                (GetKeyState(VK_SHIFT) as u16 & 0x8000) != 0,
            )
        }
    }

    fn client_lparam_from_screen(hwnd: isize, mut pt: Point) -> isize {
        unsafe {
            let _ = ScreenToClient(hwnd, &mut pt);
        }
        pack_client_lparam(pt.x, pt.y)
    }

    fn client_lparam_from_cursor(hwnd: isize) -> isize {
        let mut pt = Point::default();
        unsafe {
            let _ = GetCursorPos(&mut pt);
            let _ = ScreenToClient(hwnd, &mut pt);
        }
        pack_client_lparam(pt.x, pt.y)
    }

    fn dispatch_mouse_to_prev(prev: isize, hwnd: isize, msg: u32, wparam: usize, lparam: isize) {
        if prev != 0 {
            unsafe {
                let _ = CallWindowProcW(prev, hwnd, msg, wparam, lparam);
            }
        }
    }

    fn release_active_pen_button(prev: isize, hwnd: isize, lparam: isize) {
        let released = PEN_STATE.with(|s| {
            let mut st = s.borrow_mut();
            st.active_pointer_id = None;
            st.pressed_button.take()
        });
        if let Some(btn) = released {
            let (ctrl, shift) = current_modifiers();
            let wparam = build_mouse_wparam(ctrl, shift, None);
            let up_msg = match btn {
                PenMouseButton::Left => WM_LBUTTONUP,
                PenMouseButton::Right => WM_RBUTTONUP,
            };
            dispatch_mouse_to_prev(prev, hwnd, up_msg, wparam, lparam);
        }
    }

    fn collect_pen_frame_infos(api: &User32Apis, pointer_id: u32) -> Vec<PointerInfo> {
        if let Some(get_history) = api.get_pointer_frame_info_history {
            let mut entries_count = 0u32;
            let mut pointers_count = 0u32;
            if unsafe {
                get_history(
                    pointer_id,
                    &mut entries_count,
                    &mut pointers_count,
                    std::ptr::null_mut(),
                )
            } != 0
                && entries_count > 0
                && pointers_count > 0
            {
                let total = (entries_count as usize).saturating_mul(pointers_count as usize);
                let mut buf = vec![PointerInfo::default(); total];
                if unsafe {
                    get_history(
                        pointer_id,
                        &mut entries_count,
                        &mut pointers_count,
                        buf.as_mut_ptr(),
                    )
                } != 0
                {
                    if let Some(skip) = api.skip_pointer_frame_messages {
                        unsafe {
                            let _ = skip(pointer_id);
                        }
                    }
                    let filtered: Vec<PointerInfo> = buf
                        .into_iter()
                        .rev()
                        .filter(|pi| pi.pointer_id == pointer_id || pi.pointer_type == PT_PEN)
                        .collect();
                    if !filtered.is_empty() {
                        return filtered;
                    }
                }
            }
        }

        if let Some(get_info) = api.get_pointer_info {
            let mut pi = PointerInfo::default();
            if unsafe { get_info(pointer_id, &mut pi) } != 0 {
                return vec![pi];
            }
        }
        Vec::new()
    }

    unsafe extern "system" fn pen_wndproc(
        hwnd: isize,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        let prev = PREV_WNDPROC.load(Ordering::Acquire);

        if msg == WM_NCDESTROY {
            if SUBCLASSED_HWND.load(Ordering::Acquire) == hwnd {
                SUBCLASSED_HWND.store(0, Ordering::Release);
                if prev != 0 {
                    unsafe {
                        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, prev);
                    }
                }
            }
            return if prev != 0 {
                unsafe { CallWindowProcW(prev, hwnd, msg, wparam, lparam) }
            } else {
                0
            };
        }

        if msg == WM_TABLET_QUERYSYSTEMGESTURESTATUS {
            return (TABLET_DISABLE_PRESSANDHOLD
                | TABLET_DISABLE_PENTAPFEEDBACK
                | TABLET_DISABLE_PENBARRELFEEDBACK
                | TABLET_DISABLE_TOUCHSWITCH
                | TABLET_DISABLE_FLICKS
                | TABLET_DISABLE_SMOOTHSCROLLING) as isize;
        }

        let api = apis();

        if msg == WM_TOUCH {
            let now = Instant::now();
            let suppress = PEN_STATE.with(|s| {
                let st = s.borrow();
                should_suppress_touch_for_pen(st.in_range, st.last_pen_activity, now)
            });
            if suppress {
                if let Some(close_touch) = api.close_touch_input_handle {
                    unsafe {
                        let _ = close_touch(lparam);
                    }
                }
                return 0;
            }
            return if prev != 0 {
                unsafe { CallWindowProcW(prev, hwnd, msg, wparam, lparam) }
            } else {
                0
            };
        }

        let is_pointer_msg = matches!(
            msg,
            WM_POINTERUPDATE
                | WM_POINTERDOWN
                | WM_POINTERUP
                | WM_POINTERENTER
                | WM_POINTERLEAVE
                | WM_POINTERACTIVATE
                | WM_POINTERCAPTURECHANGED
        );

        if is_pointer_msg {
            let pointer_id = (wparam as u32) & 0xFFFF;
            let mut pointer_type = 0i32;
            let has_type = api
                .get_pointer_type
                .is_some_and(|f| unsafe { f(pointer_id, &mut pointer_type) } != 0);

            let is_known_pen = PEN_STATE.with(|s| s.borrow().active_pointer_id == Some(pointer_id));
            let is_pen = (has_type && pointer_type == PT_PEN) || (!has_type && is_known_pen);

            if has_type && pointer_type == PT_TOUCH {
                let now = Instant::now();
                let suppress = PEN_STATE.with(|s| {
                    let st = s.borrow();
                    should_suppress_touch_for_pen(st.in_range, st.last_pen_activity, now)
                });
                if suppress {
                    return 0;
                }
            }

            if is_pen {
                let now = Instant::now();
                match msg {
                    WM_POINTERENTER | WM_POINTERACTIVATE => {
                        PEN_STATE.with(|s| {
                            let mut st = s.borrow_mut();
                            st.in_range = true;
                            st.active_pointer_id = Some(pointer_id);
                            st.last_pen_activity = Some(now);
                        });
                    }
                    WM_POINTERLEAVE => {
                        PEN_STATE.with(|s| {
                            let mut st = s.borrow_mut();
                            st.in_range = false;
                            st.last_pen_activity = Some(now);
                        });
                        let lp = client_lparam_from_cursor(hwnd);
                        release_active_pen_button(prev, hwnd, lp);
                    }
                    WM_POINTERCAPTURECHANGED => {
                        PEN_STATE.with(|s| {
                            s.borrow_mut().last_pen_activity = Some(now);
                        });
                        let lp = client_lparam_from_cursor(hwnd);
                        release_active_pen_button(prev, hwnd, lp);
                        return 0;
                    }
                    WM_POINTERDOWN | WM_POINTERUPDATE | WM_POINTERUP => {
                        PEN_STATE.with(|s| {
                            let mut st = s.borrow_mut();
                            st.in_range = true;
                            st.active_pointer_id = Some(pointer_id);
                            st.last_pen_activity = Some(now);
                        });

                        let infos = collect_pen_frame_infos(api, pointer_id);
                        for pi in infos {
                            let lp = client_lparam_from_screen(hwnd, pi.pt_pixel_location);
                            let mut pen_flags = 0u32;
                            if let Some(get_pen) = api.get_pointer_pen_info {
                                let mut pen_info = PointerPenInfo::default();
                                if unsafe { get_pen(pi.pointer_id, &mut pen_info) } != 0 {
                                    pen_flags = pen_info.pen_flags;
                                }
                            }

                            let target_btn = determine_pen_button(pi.pointer_flags, pen_flags);
                            let is_down = (pi.pointer_flags & POINTER_FLAG_DOWN) != 0;
                            let is_up =
                                (pi.pointer_flags & (POINTER_FLAG_UP | POINTER_FLAG_CANCELED)) != 0;
                            let in_contact = (pi.pointer_flags & POINTER_FLAG_INCONTACT) != 0;
                            let (ctrl, shift) = current_modifiers();

                            let current_pressed = PEN_STATE.with(|s| s.borrow().pressed_button);
                            dispatch_mouse_to_prev(
                                prev,
                                hwnd,
                                WM_MOUSEMOVE,
                                build_mouse_wparam(ctrl, shift, current_pressed),
                                lp,
                            );

                            if is_down || (in_contact && current_pressed.is_none() && !is_up) {
                                PEN_STATE.with(|s| {
                                    s.borrow_mut().pressed_button = Some(target_btn);
                                });
                                let down_msg = match target_btn {
                                    PenMouseButton::Left => WM_LBUTTONDOWN,
                                    PenMouseButton::Right => WM_RBUTTONDOWN,
                                };
                                dispatch_mouse_to_prev(
                                    prev,
                                    hwnd,
                                    down_msg,
                                    build_mouse_wparam(ctrl, shift, Some(target_btn)),
                                    lp,
                                );
                            } else if let Some(old_btn) = current_pressed {
                                if is_up || !in_contact {
                                    PEN_STATE.with(|s| {
                                        s.borrow_mut().pressed_button = None;
                                    });
                                    let up_msg = match old_btn {
                                        PenMouseButton::Left => WM_LBUTTONUP,
                                        PenMouseButton::Right => WM_RBUTTONUP,
                                    };
                                    dispatch_mouse_to_prev(
                                        prev,
                                        hwnd,
                                        up_msg,
                                        build_mouse_wparam(ctrl, shift, None),
                                        lp,
                                    );
                                } else if old_btn != target_btn {
                                    PEN_STATE.with(|s| {
                                        s.borrow_mut().pressed_button = Some(target_btn);
                                    });
                                    let up_msg = match old_btn {
                                        PenMouseButton::Left => WM_LBUTTONUP,
                                        PenMouseButton::Right => WM_RBUTTONUP,
                                    };
                                    let down_msg = match target_btn {
                                        PenMouseButton::Left => WM_LBUTTONDOWN,
                                        PenMouseButton::Right => WM_RBUTTONDOWN,
                                    };
                                    dispatch_mouse_to_prev(
                                        prev,
                                        hwnd,
                                        up_msg,
                                        build_mouse_wparam(ctrl, shift, None),
                                        lp,
                                    );
                                    dispatch_mouse_to_prev(
                                        prev,
                                        hwnd,
                                        down_msg,
                                        build_mouse_wparam(ctrl, shift, Some(target_btn)),
                                        lp,
                                    );
                                }
                            }
                        }

                        if msg == WM_POINTERUP {
                            let lp = client_lparam_from_cursor(hwnd);
                            release_active_pen_button(prev, hwnd, lp);
                        }
                        return 0;
                    }
                    _ => {}
                }
            }
        }

        if prev != 0 {
            unsafe { CallWindowProcW(prev, hwnd, msg, wparam, lparam) }
        } else {
            0
        }
    }
}
