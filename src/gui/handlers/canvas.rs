use note_vault::{
    extend_canvas_pixmap, fit_canvas_zoom_percent, hsl_to_rgb, parse_zoom_input, rgb_to_hsl,
    MainWindow, CANVAS_EXTEND_STEP,
};
use slint::ComponentHandle;

use crate::gui::canvas::{
    draw_stroke_on_pixmap, get_dash_cycle, parse_hex_color, parse_hex_rgb, push_canvas_undo,
    redo_canvas, sync_canvas_dirty_rect, sync_canvas_full, undo_canvas,
    update_canvas_history_ui,
};
use crate::gui::state::AppState;

pub fn register(main_window: &MainWindow, state: &AppState) {
    let window_weak = main_window.as_weak();

    main_window.on_canvas_pointer_down({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |x, y| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            push_canvas_undo(&mut cstate);
            cstate.last_point = Some((x, y));
            cstate.dash_offset = 0.0;

            let tool = cstate.tool.clone();
            let color = cstate.color;
            let stroke_width = cstate.stroke_width;
            let line_style = cstate.line_style.clone();

            if let Some(pixmap) = cstate.pixmap.as_mut() {
                draw_stroke_on_pixmap(
                    pixmap,
                    (x, y),
                    (x, y),
                    &tool,
                    color,
                    stroke_width,
                    &line_style,
                    0.0,
                );
                if let Some(img) = sync_canvas_dirty_rect(&mut cstate, (x, y), (x, y), stroke_width)
                {
                    ui.set_canvas_image(img);
                }
                ui.set_has_unsaved_changes(true);
                update_canvas_history_ui(&ui, &cstate);
            }
        }
    });

    main_window.on_canvas_pointer_move({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |x, y| {
            let Some(ui) = window_weak.upgrade() else { return };
            let mut cstate = state.canvas_state.lock().unwrap();
            let from = cstate.last_point.unwrap_or((x, y));
            cstate.last_point = Some((x, y));

            let tool = cstate.tool.clone();
            let color = cstate.color;
            let stroke_width = cstate.stroke_width;
            let line_style = cstate.line_style.clone();
            let current_dash_offset = cstate.dash_offset;

            let dist = ((x - from.0).powi(2) + (y - from.1).powi(2)).sqrt();
            let cycle = get_dash_cycle(&line_style, stroke_width);
            cstate.dash_offset = (current_dash_offset + dist) % cycle;

            if let Some(pixmap) = cstate.pixmap.as_mut() {
                draw_stroke_on_pixmap(
                    pixmap,
                    from,
                    (x, y),
                    &tool,
                    color,
                    stroke_width,
                    &line_style,
                    current_dash_offset,
                );
                if let Some(img) = sync_canvas_dirty_rect(&mut cstate, from, (x, y), stroke_width) {
                    ui.set_canvas_image(img);
                }
                ui.set_has_unsaved_changes(true);
            }
        }
    });

    main_window.on_canvas_pointer_up({
        let state = state.clone();

        move |_x, _y| {
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            cstate.last_point = None;
        }
    });

    main_window.on_canvas_tool_changed({
        let state = state.clone();

        move |tool_str| {
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            cstate.tool = tool_str.to_string();
        }
    });

    main_window.on_canvas_color_changed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |color_hex| {
            state.touch_activity();
            let color_str = color_hex.as_str();
            if let Some(ui) = window_weak.upgrade() {
                if let Some((r, g, b)) = parse_hex_rgb(color_str) {
                    ui.set_canvas_color(slint::Color::from_argb_u8(255, r, g, b));
                    ui.set_custom_color_preview(slint::Color::from_argb_u8(255, r, g, b));
                    ui.set_custom_color_hex(color_hex.clone());
                    let (h, s, l) = rgb_to_hsl(r, g, b);
                    ui.set_custom_color_hue(h);
                    ui.set_custom_color_sat(s);
                    ui.set_custom_color_light(l);
                }
            }
            let mut cstate = state.canvas_state.lock().unwrap();
            cstate.color = parse_hex_color(color_str);
        }
    });

    main_window.on_canvas_bg_color_changed({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |_hex| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            ui.set_has_unsaved_changes(true);
            ui.set_vault_status_text("Canvas background changed (unsaved)".into());
        }
    });

    main_window.on_canvas_stroke_width_changed({
        let state = state.clone();

        move |width| {
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            cstate.stroke_width = width.max(1.0);
        }
    });

    main_window.on_canvas_line_style_changed({
        let state = state.clone();

        move |style_str| {
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            cstate.line_style = style_str.to_string();
            cstate.dash_offset = 0.0;
        }
    });

    main_window.on_custom_color_preview_requested({
        let window_weak = window_weak.clone();

        move |hex| {
            if let Some(ui) = window_weak.upgrade() {
                if let Some((r, g, b)) = parse_hex_rgb(hex.as_str()) {
                    ui.set_custom_color_preview(slint::Color::from_argb_u8(255, r, g, b));
                    let (h, s, l) = rgb_to_hsl(r, g, b);
                    ui.set_custom_color_hue(h);
                    ui.set_custom_color_sat(s);
                    ui.set_custom_color_light(l);
                }
            }
        }
    });

    main_window.on_custom_color_hsl_changed({
        let window_weak = window_weak.clone();

        move |h, s, l| {
            let Some(ui) = window_weak.upgrade() else { return };
            let (r, g, b) = hsl_to_rgb(h, s, l);
            let hex = format!("#{:02x}{:02x}{:02x}", r, g, b);
            ui.set_custom_color_hex(hex.into());
            ui.set_custom_color_preview(slint::Color::from_argb_u8(255, r, g, b));
            ui.set_custom_color_hue(h);
            ui.set_custom_color_sat(s);
            ui.set_custom_color_light(l);
        }
    });

    main_window.on_canvas_zoom_submitted({
        let window_weak = window_weak.clone();

        move |zoom_text| {
            let Some(ui) = window_weak.upgrade() else { return };
            if let Some(clamped) = parse_zoom_input(&zoom_text) {
                ui.set_canvas_zoom_percent(clamped);
                ui.set_canvas_zoom_text(format!("{}%", clamped).into());
            } else {
                let cur = ui.get_canvas_zoom_percent();
                ui.set_canvas_zoom_text(format!("{}%", cur).into());
            }
        }
    });

    main_window.on_canvas_fit_requested({
        let window_weak = window_weak.clone();

        move |viewport_w, viewport_h| {
            let Some(ui) = window_weak.upgrade() else { return };
            let pct = fit_canvas_zoom_percent(
                viewport_w,
                viewport_h,
                ui.get_canvas_width(),
                ui.get_canvas_height(),
            );
            ui.set_canvas_zoom_percent(pct);
            ui.set_canvas_zoom_text(format!("{}%", pct).into());
            ui.set_canvas_pan_x(0.0);
            ui.set_canvas_pan_y(0.0);
        }
    });

    main_window.on_canvas_clear_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            if cstate.pixmap.is_some() {
                push_canvas_undo(&mut cstate);
                if let Some(pixmap) = cstate.pixmap.as_mut() {
                    pixmap.fill(tiny_skia::Color::TRANSPARENT);
                }
                if let Some(img) = sync_canvas_full(&mut cstate) {
                    ui.set_canvas_image(img);
                }
                ui.set_has_unsaved_changes(true);
                update_canvas_history_ui(&ui, &cstate);
            }
        }
    });

    main_window.on_canvas_extend_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move |direction| {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            let extended_opt = cstate
                .pixmap
                .as_ref()
                .and_then(|p| extend_canvas_pixmap(p, direction.as_str(), CANVAS_EXTEND_STEP));
            if let Some(extended) = extended_opt {
                push_canvas_undo(&mut cstate);
                let new_w = extended.width();
                let new_h = extended.height();
                cstate.pixmap = Some(extended);
                cstate.last_point = None;
                if let Some(img) = sync_canvas_full(&mut cstate) {
                    ui.set_canvas_image(img);
                }
                ui.set_canvas_width(new_w as f32);
                ui.set_canvas_height(new_h as f32);
                ui.set_has_unsaved_changes(true);
                update_canvas_history_ui(&ui, &cstate);
                ui.set_vault_status_text(
                    format!("Canvas extended to {}x{} (unsaved)", new_w, new_h).into(),
                );
            }
        }
    });

    main_window.on_canvas_undo_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            if undo_canvas(&mut cstate) {
                if let Some(ref pix) = cstate.pixmap {
                    ui.set_canvas_width(pix.width() as f32);
                    ui.set_canvas_height(pix.height() as f32);
                }
                if let Some(img) = sync_canvas_full(&mut cstate) {
                    ui.set_canvas_image(img);
                }
                ui.set_has_unsaved_changes(true);
                update_canvas_history_ui(&ui, &cstate);
            }
        }
    });

    main_window.on_canvas_redo_requested({
        let window_weak = window_weak.clone();
        let state = state.clone();

        move || {
            let Some(ui) = window_weak.upgrade() else { return };
            state.touch_activity();
            let mut cstate = state.canvas_state.lock().unwrap();
            if redo_canvas(&mut cstate) {
                if let Some(ref pix) = cstate.pixmap {
                    ui.set_canvas_width(pix.width() as f32);
                    ui.set_canvas_height(pix.height() as f32);
                }
                if let Some(img) = sync_canvas_full(&mut cstate) {
                    ui.set_canvas_image(img);
                }
                ui.set_has_unsaved_changes(true);
                update_canvas_history_ui(&ui, &cstate);
            }
        }
    });
}
