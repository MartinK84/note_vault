use global_hotkey::hotkey::HotKey;
use tray_icon::Icon;

/// Parses and normalizes a global hotkey string (e.g. "Shift + Space", "ctrl+shift+k", "Alt+Space").
pub fn parse_hotkey_string(s: &str) -> Result<(HotKey, String), String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("Hotkey cannot be empty".to_string());
    }

    // Split on '+' and normalize components
    let parts: Vec<&str> = trimmed.split('+').map(|p| p.trim()).collect();
    if parts.is_empty() {
        return Err("Invalid hotkey format".to_string());
    }

    let mut normalized_parts: Vec<String> = Vec::new();
    for part in parts {
        let p_lower = part.to_lowercase();
        let norm = match p_lower.as_str() {
            "ctrl" | "control" => "Control".to_string(),
            "shift" => "Shift".to_string(),
            "alt" => "Alt".to_string(),
            "super" | "win" | "windows" => "Super".to_string(),
            "cmd" | "command" => "Command".to_string(),
            "cmdorctrl" | "commandorcontrol" => "CmdOrCtrl".to_string(),
            "space" => "Space".to_string(),
            "enter" | "return" => "Return".to_string(),
            "esc" | "escape" => "Escape".to_string(),
            "tab" => "Tab".to_string(),
            "backspace" => "Backspace".to_string(),
            _ => {
                if part.len() == 1 {
                    part.to_ascii_uppercase()
                } else {
                    let mut c = part.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                }
            }
        };
        normalized_parts.push(norm);
    }

    let normalized_str = normalized_parts.join("+");
    match normalized_str.parse::<HotKey>() {
        Ok(hk) => Ok((hk, normalized_str)),
        Err(e) => match trimmed.parse::<HotKey>() {
            Ok(hk) => Ok((hk, trimmed.to_string())),
            Err(_) => Err(format!("Could not parse hotkey '{}': {}", trimmed, e)),
        },
    }
}

/// Formats a pressed key and active modifiers into a normalized hotkey string.
/// Returns Some("Shift+Space"), Some("Control+Shift+N"), etc. if valid; None if incomplete or only modifiers.
pub fn format_key_combination(
    key_text: &str,
    ctrl: bool,
    alt: bool,
    shift: bool,
    meta: bool,
) -> Option<String> {
    if key_text.is_empty() {
        return None;
    }

    // Ignore if only a modifier key was pressed
    let is_modifier_key = key_text.chars().any(|c| {
        c == '\u{0010}' || c == '\u{0011}' || c == '\u{0012}' || c == '\u{0013}' || c == '\u{0014}'
    });
    if is_modifier_key {
        return None;
    }

    // Determine the key name
    let key_name = if key_text == " " || key_text == "\u{0020}" {
        "Space"
    } else if key_text == "\n" || key_text == "\r" {
        "Return"
    } else if key_text == "\t" {
        "Tab"
    } else if key_text == "\u{001b}" {
        "Escape"
    } else if key_text == "\u{0008}" || key_text == "\u{007f}" {
        "Backspace"
    } else if key_text.len() == 1 {
        let c = key_text.chars().next().unwrap();
        if c.is_alphabetic() {
            let s = c.to_ascii_uppercase().to_string();
            return build_combo(ctrl, alt, shift, meta, &s);
        } else {
            return build_combo(ctrl, alt, shift, meta, key_text);
        }
    } else {
        key_text
    };

    build_combo(ctrl, alt, shift, meta, key_name)
}

fn build_combo(ctrl: bool, alt: bool, shift: bool, meta: bool, key_name: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    if ctrl {
        parts.push("Control");
    }
    if alt {
        parts.push("Alt");
    }
    if shift {
        parts.push("Shift");
    }
    if meta {
        parts.push("Super");
    }

    // Require at least one modifier unless it's a function key (F1-F12)
    let is_fkey = key_name.starts_with('F')
        && key_name.len() <= 3
        && key_name[1..].chars().all(|c| c.is_ascii_digit());
    if parts.is_empty() && !is_fkey {
        return None;
    }

    parts.push(key_name);
    let combo = parts.join("+");
    if parse_hotkey_string(&combo).is_ok() {
        Some(combo)
    } else {
        None
    }
}

/// Builds a 32x32 RGBA icon for the system tray using the dark orange logo.svg.
pub fn create_tray_icon() -> Result<Icon, Box<dyn std::error::Error>> {
    const SVG_STR: &str = include_str!("../../assets/icons/logo.svg");
    let width = 32u32;
    let height = 32u32;

    let opt = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_str(SVG_STR, &opt)?;

    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)
        .ok_or_else(|| "Failed to allocate icon pixmap".to_string())?;

    let svg_w = tree.size().width();
    let svg_h = tree.size().height();
    let padding = 2.0f32;
    let draw_w = (width as f32) - 2.0 * padding;
    let draw_h = (height as f32) - 2.0 * padding;
    let scale_x = draw_w / svg_w;
    let scale_y = draw_h / svg_h;
    let scale = scale_x.min(scale_y);
    let offset_x = padding + (draw_w - svg_w * scale) / 2.0;
    let offset_y = padding + (draw_h - svg_h * scale) / 2.0;

    let transform =
        resvg::tiny_skia::Transform::from_row(scale, 0.0, 0.0, scale, offset_x, offset_y);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // Convert premultiplied RGBA from tiny_skia into straight RGBA for tray_icon
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for chunk in pixmap.data().chunks_exact(4) {
        let r = chunk[0];
        let g = chunk[1];
        let b = chunk[2];
        let a = chunk[3];
        if a == 0 {
            rgba.extend_from_slice(&[0, 0, 0, 0]);
        } else if a == 255 {
            rgba.extend_from_slice(&[r, g, b, 255]);
        } else {
            let r = ((r as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            let g = ((g as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            let b = ((b as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }

    Icon::from_rgba(rgba, width, height).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
