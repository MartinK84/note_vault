use crate::gui::state::{ActiveCanvasState, MAX_CANVAS_UNDO_STEPS};
use note_vault::MainWindow;

/// Computes the total period of the dash pattern for the given line style and width.
pub fn get_dash_cycle(line_style: &str, stroke_width: f32) -> f32 {
    match line_style {
        "dashed" => {
            let dash_len = (stroke_width * 3.0).max(10.0);
            let gap_len = (stroke_width * 2.0).max(8.0);
            dash_len + gap_len
        }
        "dotted" => {
            let dot_len = 0.1;
            let gap_len = (stroke_width * 2.2).max(8.0);
            dot_len + gap_len
        }
        _ => 1.0,
    }
}

#[inline]
fn unpremultiply_rgba(r: u8, g: u8, b: u8, a: u8) -> slint::Rgba8Pixel {
    if a == 0 {
        slint::Rgba8Pixel { r: 0, g: 0, b: 0, a: 0 }
    } else if a == 255 {
        slint::Rgba8Pixel { r, g, b, a: 255 }
    } else {
        let r = ((r as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
        let g = ((g as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
        let b = ((b as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
        slint::Rgba8Pixel { r, g, b, a }
    }
}

/// Rebuilds the cached `pixel_buffer` from `cstate.pixmap` and returns a Slint image.
pub fn sync_canvas_full(cstate: &mut ActiveCanvasState) -> Option<slint::Image> {
    let pixmap = cstate.pixmap.as_ref()?;
    let width = pixmap.width();
    let height = pixmap.height();
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(width, height);
    let slice = buffer.make_mut_slice();
    let data = pixmap.data();
    for (i, p) in slice.iter_mut().enumerate() {
        *p = unpremultiply_rgba(data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3]);
    }
    let img = slint::Image::from_rgba8(buffer.clone());
    cstate.pixel_buffer = Some(buffer);
    Some(img)
}

/// Updates only the dirty bounding rectangle around a stroke segment in the cached pixel buffer,
/// falling back to a full sync if the buffer has not been allocated or changed size.
pub fn sync_canvas_dirty_rect(
    cstate: &mut ActiveCanvasState,
    from: (f32, f32),
    to: (f32, f32),
    stroke_width: f32,
) -> Option<slint::Image> {
    let (width, height) = {
        let pixmap = cstate.pixmap.as_ref()?;
        (pixmap.width(), pixmap.height())
    };

    let needs_full = match cstate.pixel_buffer.as_ref() {
        Some(buf) => buf.width() != width || buf.height() != height,
        None => true,
    };
    if needs_full {
        return sync_canvas_full(cstate);
    }

    let pad = (stroke_width * 0.5).ceil() as i32 + 2;
    let min_x = (from.0.min(to.0).floor() as i32 - pad).max(0) as u32;
    let min_y = (from.1.min(to.1).floor() as i32 - pad).max(0) as u32;
    let max_x = ((from.0.max(to.0).ceil() as i32 + pad) + 1).min(width as i32).max(0) as u32;
    let max_y = ((from.1.max(to.1).ceil() as i32 + pad) + 1).min(height as i32).max(0) as u32;

    let data = cstate.pixmap.as_ref()?.data();
    let buf = cstate.pixel_buffer.as_mut()?;
    let slice = buf.make_mut_slice();
    let w_usize = width as usize;

    for y in min_y..max_y {
        let row_offset = (y as usize) * w_usize;
        for x in min_x..max_x {
            let idx = row_offset + (x as usize);
            let b = idx * 4;
            slice[idx] = unpremultiply_rgba(data[b], data[b + 1], data[b + 2], data[b + 3]);
        }
    }

    Some(slint::Image::from_rgba8(buf.clone()))
}

/// Saves a snapshot of the current canvas onto the undo stack and clears redo history.
pub fn push_canvas_undo(cstate: &mut ActiveCanvasState) {
    if let Some(ref pixmap) = cstate.pixmap {
        if cstate.undo_stack.len() >= MAX_CANVAS_UNDO_STEPS {
            cstate.undo_stack.remove(0);
        }
        cstate.undo_stack.push(pixmap.clone());
        cstate.redo_stack.clear();
    }
}

/// Restores the most recent canvas snapshot from the undo stack.
pub fn undo_canvas(cstate: &mut ActiveCanvasState) -> bool {
    let Some(prev) = cstate.undo_stack.pop() else {
        return false;
    };
    if let Some(current) = cstate.pixmap.take() {
        cstate.redo_stack.push(current);
    }
    cstate.pixmap = Some(prev);
    cstate.last_point = None;
    true
}

/// Reapplies the most recent undone canvas snapshot from the redo stack.
pub fn redo_canvas(cstate: &mut ActiveCanvasState) -> bool {
    let Some(next) = cstate.redo_stack.pop() else {
        return false;
    };
    if let Some(current) = cstate.pixmap.take() {
        cstate.undo_stack.push(current);
    }
    cstate.pixmap = Some(next);
    cstate.last_point = None;
    true
}

/// Clears canvas undo/redo history and cached pixel buffer.
pub fn clear_canvas_history(cstate: &mut ActiveCanvasState) {
    cstate.undo_stack.clear();
    cstate.redo_stack.clear();
    cstate.pixel_buffer = None;
}

/// Synchronizes undo/redo toolbar button enabled states in `MainWindow`.
pub fn update_canvas_history_ui(ui: &MainWindow, cstate: &ActiveCanvasState) {
    ui.set_canvas_can_undo(!cstate.undo_stack.is_empty());
    ui.set_canvas_can_redo(!cstate.redo_stack.is_empty());
}

/// Draws a smoothed stroke between two points on the Pixmap using tiny-skia.
#[allow(clippy::too_many_arguments)]
pub fn draw_stroke_on_pixmap(
    pixmap: &mut tiny_skia::Pixmap,
    from: (f32, f32),
    to: (f32, f32),
    tool: &str,
    color: tiny_skia::Color,
    stroke_width: f32,
    line_style: &str,
    dash_offset: f32,
) {
    let mut pb = tiny_skia::PathBuilder::new();
    pb.move_to(from.0, from.1);
    if (from.0 - to.0).abs() < 0.001 && (from.1 - to.1).abs() < 0.001 {
        pb.line_to(to.0 + 0.05, to.1);
    } else {
        pb.line_to(to.0, to.1);
    }
    let Some(path) = pb.finish() else { return };

    let mut stroke = tiny_skia::Stroke {
        width: stroke_width,
        line_cap: tiny_skia::LineCap::Round,
        line_join: tiny_skia::LineJoin::Round,
        ..Default::default()
    };

    if tool == "eraser" {
        stroke.dash = None;
    } else {
        match line_style {
            "dashed" => {
                let dash_len = (stroke_width * 3.0).max(10.0);
                let gap_len = (stroke_width * 2.0).max(8.0);
                stroke.dash = tiny_skia::StrokeDash::new(vec![dash_len, gap_len], dash_offset);
            }
            "dotted" => {
                let dot_len = 0.1;
                let gap_len = (stroke_width * 2.2).max(8.0);
                stroke.dash = tiny_skia::StrokeDash::new(vec![dot_len, gap_len], dash_offset);
            }
            _ => {
                stroke.dash = None;
            }
        }
    }

    let mut paint = tiny_skia::Paint {
        anti_alias: true,
        ..Default::default()
    };
    if tool == "eraser" {
        paint.blend_mode = tiny_skia::BlendMode::Clear;
    } else {
        paint.set_color(color);
        paint.blend_mode = tiny_skia::BlendMode::SourceOver;
    }

    pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);
}

/// Parses hex color string into (r, g, b) bytes if valid.
pub fn parse_hex_rgb(hex: &str) -> Option<(u8, u8, u8)> {
    let s = hex.trim().trim_start_matches('#');
    if s.len() == 6 {
        if let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&s[0..2], 16),
            u8::from_str_radix(&s[2..4], 16),
            u8::from_str_radix(&s[4..6], 16),
        ) {
            return Some((r, g, b));
        }
    }
    None
}

/// Parses hex color string into tiny_skia::Color.
pub fn parse_hex_color(hex: &str) -> tiny_skia::Color {
    if let Some((r, g, b)) = parse_hex_rgb(hex) {
        return tiny_skia::Color::from_rgba8(r, g, b, 255);
    }
    tiny_skia::Color::from_rgba8(30, 30, 30, 255)
}
