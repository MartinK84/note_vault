use std::fs;
use note_vault::{
    get_canvas_path, is_canvas_file, load_canvas_decrypted, move_note_attachments,
    delete_note_attachments, reencrypt_vault_atomic, save_canvas_encrypted, save_note_encrypted,
    load_note_decrypted, Note, NoteType, hsl_to_rgb, rgb_to_hsl, clamp_zoom_percent,
    parse_zoom_input, scale_coordinate_to_canvas,
};
use uuid::Uuid;

#[test]
fn test_note_type_serde_and_backward_compatibility() {
    // 1. Text Note
    let text_note = Note::new(
        "Meeting Notes",
        vec!["work".into()],
        "Discussion summary...",
    );
    assert_eq!(text_note.note_type, NoteType::Text);
    let serialized_text = serde_json::to_string(&text_note).unwrap();
    assert!(serialized_text.contains("\"note_type\":\"text\""));
    let deserialized_text: Note = serde_json::from_str(&serialized_text).unwrap();
    assert_eq!(deserialized_text.note_type, NoteType::Text);

    // 2. Canvas Note
    let canvas_note = Note::new_canvas(
        "Design Sketch",
        vec!["ui".into(), "wireframe".into()],
    );
    assert_eq!(canvas_note.note_type, NoteType::Canvas);
    let serialized_canvas = serde_json::to_string(&canvas_note).unwrap();
    assert!(serialized_canvas.contains("\"note_type\":\"canvas\""));
    let deserialized_canvas: Note = serde_json::from_str(&serialized_canvas).unwrap();
    assert_eq!(deserialized_canvas.note_type, NoteType::Canvas);

    // 3. Backward Compatibility: Old note JSON without "note_type" field
    let legacy_json = r#"{
        "id": "67e55044-10b1-426f-9247-bb680e5fe0c8",
        "title": "Legacy Note",
        "tags": ["old"],
        "content": "Old plain text note without note_type field",
        "created_at": 1600000000,
        "updated_at": 1600000000
    }"#;
    let parsed_legacy: Note = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(parsed_legacy.note_type, NoteType::Text);
}

#[test]
fn test_canvas_drawing_eraser_and_encryption_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_canvas_integ_{}", Uuid::new_v4()));
    let category_dir = temp_dir.join("Sketches");
    fs::create_dir_all(&category_dir).unwrap();

    let password = "SuperSecretCanvasPassword#2026";
    let keyfile_bytes = b"canvas_hardware_keyfile_bytes_999";

    // 1. Create a canvas note
    let canvas_note = Note::new_with_type(
        "Architecture Diagram",
        vec!["diagram".into(), "arch".into()],
        "",
        NoteType::Canvas,
    );
    let note_path = category_dir.join(format!("{}.vault", canvas_note.id));
    save_note_encrypted(&canvas_note, password, Some(keyfile_bytes), &note_path)
        .expect("Saving canvas note metadata must succeed");

    // 2. Canvas path detection & naming
    let canvas_path = get_canvas_path(&note_path);
    assert!(canvas_path.to_string_lossy().ends_with("_canvas.vault"));
    assert!(is_canvas_file(&canvas_path));
    assert!(!is_canvas_file(&note_path));

    // 3. Draw on tiny_skia::Pixmap
    let width = 800u32;
    let height = 600u32;
    let mut pixmap = tiny_skia::Pixmap::new(width, height).expect("Failed to create Pixmap");
    pixmap.fill(tiny_skia::Color::TRANSPARENT);

    // Verify initial pixels are transparent (0, 0, 0, 0)
    let initial_px = pixmap.pixel(100, 100).unwrap();
    assert_eq!(initial_px.alpha(), 0);

    // 4. Draw with Pen (Blue stroke)
    {
        let mut pb = tiny_skia::PathBuilder::new();
        pb.move_to(50.0, 50.0);
        pb.line_to(150.0, 150.0);
        let path = pb.finish().unwrap();

        let mut stroke = tiny_skia::Stroke::default();
        stroke.width = 10.0;
        stroke.line_cap = tiny_skia::LineCap::Round;

        let mut paint = tiny_skia::Paint::default();
        paint.anti_alias = true;
        paint.set_color(tiny_skia::Color::from_rgba8(0, 0, 255, 255));
        paint.blend_mode = tiny_skia::BlendMode::SourceOver;

        pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);
    }

    // Verify (100, 100) is now non-transparent blue
    let drawn_px = pixmap.pixel(100, 100).unwrap();
    assert!(drawn_px.alpha() > 200);
    assert!(drawn_px.blue() > 200);

    // 5. Test Eraser tool: Draw with BlendMode::Clear over (100, 100)
    {
        let mut pb = tiny_skia::PathBuilder::new();
        pb.move_to(95.0, 95.0);
        pb.line_to(105.0, 105.0);
        let path = pb.finish().unwrap();

        let mut stroke = tiny_skia::Stroke::default();
        stroke.width = 16.0;
        stroke.line_cap = tiny_skia::LineCap::Round;

        let mut paint = tiny_skia::Paint::default();
        paint.anti_alias = true;
        // CRUCIAL REQUIREMENT: BlendMode::Clear makes pixels transparent again!
        paint.blend_mode = tiny_skia::BlendMode::Clear;

        pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);
    }

    // Verify (100, 100) has been erased to transparent (0, 0, 0, 0)
    let erased_px = pixmap.pixel(100, 100).unwrap();
    assert_eq!(erased_px.alpha(), 0, "Eraser with BlendMode::Clear must yield alpha == 0");
    assert_eq!(erased_px.red(), 0);
    assert_eq!(erased_px.green(), 0);
    assert_eq!(erased_px.blue(), 0);

    // 6. Encode to PNG
    let png_bytes = pixmap.encode_png().expect("PNG encoding must succeed");
    assert!(!png_bytes.is_empty());
    assert_eq!(&png_bytes[1..4], b"PNG");

    // 7. Save canvas encrypted
    save_canvas_encrypted(&png_bytes, password, Some(keyfile_bytes), &canvas_path)
        .expect("Saving encrypted canvas must succeed");
    assert!(canvas_path.exists());

    // 8. Decrypt and decode canvas
    let decrypted_png = load_canvas_decrypted(password, Some(keyfile_bytes), &canvas_path)
        .expect("Decrypting canvas must succeed");
    assert_eq!(decrypted_png, png_bytes);

    let decoded_pixmap = tiny_skia::Pixmap::decode_png(&decrypted_png)
        .expect("Decoding decrypted PNG must succeed");
    assert_eq!(decoded_pixmap.width(), width);
    assert_eq!(decoded_pixmap.height(), height);

    // Verify decoded pixels match
    assert_eq!(decoded_pixmap.pixel(100, 100).unwrap().alpha(), 0);
    assert_eq!(decoded_pixmap.data(), pixmap.data());

    // 9. Move note and verify canvas file moves along
    let new_category_dir = temp_dir.join("Archive");
    fs::create_dir_all(&new_category_dir).unwrap();
    let new_note_path = new_category_dir.join(format!("{}.vault", canvas_note.id));
    let new_canvas_path = get_canvas_path(&new_note_path);

    move_note_attachments(&note_path, &new_note_path);
    fs::rename(&note_path, &new_note_path).unwrap();

    assert!(!canvas_path.exists(), "Old canvas file must no longer exist after move");
    assert!(new_canvas_path.exists(), "New canvas file must exist after move");

    // 10. Re-encrypt vault and verify canvas file re-encryption
    let new_password = "UpdatedVaultPassword#2027";
    let new_keyfile = b"new_hardware_token_777";
    let count = reencrypt_vault_atomic(
        &temp_dir,
        password,
        Some(keyfile_bytes),
        new_password,
        Some(new_keyfile),
        |_curr, _total| {},
    )
    .expect("Re-encrypting vault must succeed");
    assert_eq!(count, 2, "Must re-encrypt both note file and canvas file");

    // Loading with old credentials must fail
    assert!(load_canvas_decrypted(password, Some(keyfile_bytes), &new_canvas_path).is_err());
    assert!(load_note_decrypted(password, Some(keyfile_bytes), &new_note_path).is_err());

    // Loading with new credentials must succeed
    let redecrypted_png = load_canvas_decrypted(new_password, Some(new_keyfile), &new_canvas_path)
        .expect("Decryption with new credentials must succeed");
    assert_eq!(redecrypted_png, png_bytes);

    // 11. Delete note attachments and verify canvas file is deleted
    delete_note_attachments(&new_note_path);
    assert!(!new_canvas_path.exists(), "Canvas file must be deleted by delete_note_attachments");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_note_type_case_insensitivity_and_loading() {
    // 1. Verify case-insensitive deserialization
    let json_capital = r#"{"id":"00000000-0000-0000-0000-000000000001","title":"Drawing 1","tags":[],"content":"","created_at":0,"updated_at":0,"note_type":"Canvas"}"#;
    let note_capital: Note = serde_json::from_str(json_capital).unwrap();
    assert_eq!(note_capital.note_type, NoteType::Canvas);
    assert_eq!(note_capital.note_type.as_str(), "canvas");
    assert_eq!(note_capital.note_type.to_string(), "canvas");

    let json_upper = r#"{"id":"00000000-0000-0000-0000-000000000002","title":"Drawing 2","tags":[],"content":"","created_at":0,"updated_at":0,"note_type":"CANVAS"}"#;
    let note_upper: Note = serde_json::from_str(json_upper).unwrap();
    assert_eq!(note_upper.note_type, NoteType::Canvas);

    let json_lower = r#"{"id":"00000000-0000-0000-0000-000000000003","title":"Drawing 3","tags":[],"content":"","created_at":0,"updated_at":0,"note_type":"canvas"}"#;
    let note_lower: Note = serde_json::from_str(json_lower).unwrap();
    assert_eq!(note_lower.note_type, NoteType::Canvas);

    // 2. From<&str>
    assert_eq!(NoteType::from("canvas"), NoteType::Canvas);
    assert_eq!(NoteType::from("Canvas"), NoteType::Canvas);
    assert_eq!(NoteType::from("CANVAS"), NoteType::Canvas);
    assert_eq!(NoteType::from("text"), NoteType::Text);
    assert_eq!(NoteType::from("Text"), NoteType::Text);

    // 3. Roundtrip file save and load test
    let temp_dir = std::env::temp_dir().join(format!("note_vault_case_test_{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let note_file = temp_dir.join("test_note.vault");
    let pass = "testpass";

    save_note_encrypted(&note_capital, pass, None, &note_file).unwrap();
    let loaded = load_note_decrypted(pass, None, &note_file).unwrap();
    assert_eq!(loaded.note_type, NoteType::Canvas);
    assert_eq!(loaded.note_type.as_str(), "canvas");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_canvas_line_styles_and_large_stroke_widths() {
    let mut pixmap = tiny_skia::Pixmap::new(500, 300).expect("allocate pixmap");
    pixmap.fill(tiny_skia::Color::TRANSPARENT);

    // 1. Draw solid line with large stroke width 48px
    {
        let mut pb = tiny_skia::PathBuilder::new();
        pb.move_to(50.0, 50.0);
        pb.line_to(450.0, 50.0);
        let path = pb.finish().unwrap();

        let mut stroke = tiny_skia::Stroke::default();
        stroke.width = 48.0;
        stroke.line_cap = tiny_skia::LineCap::Round;

        let mut paint = tiny_skia::Paint::default();
        paint.anti_alias = true;
        paint.set_color(tiny_skia::Color::from_rgba8(255, 0, 0, 255)); // Red

        pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);

        // Verify thickness: pixels 20px above and below center (50.0) should be colored
        assert!(pixmap.pixel(200, 50).unwrap().alpha() > 200);
        assert!(pixmap.pixel(200, 35).unwrap().alpha() > 200);
        assert!(pixmap.pixel(200, 65).unwrap().alpha() > 200);
    }

    // 2. Draw dashed line with stroke width 24px
    {
        let mut pb = tiny_skia::PathBuilder::new();
        pb.move_to(50.0, 150.0);
        pb.line_to(450.0, 150.0);
        let path = pb.finish().unwrap();

        let stroke_width = 24.0f32;
        let dash_len = (stroke_width * 3.0).max(10.0); // 72.0
        let gap_len = (stroke_width * 2.0).max(8.0);   // 48.0

        let mut stroke = tiny_skia::Stroke::default();
        stroke.width = stroke_width;
        stroke.line_cap = tiny_skia::LineCap::Round;
        stroke.dash = tiny_skia::StrokeDash::new(vec![dash_len, gap_len], 0.0);

        let mut paint = tiny_skia::Paint::default();
        paint.anti_alias = true;
        paint.set_color(tiny_skia::Color::from_rgba8(0, 255, 0, 255)); // Green

        pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);

        // Middle of first dash (around x=80): should be green
        assert!(pixmap.pixel(80, 150).unwrap().green() > 200);

        // Middle of first gap (dash ends ~122, gap is 48px, so around x=145): should be transparent
        assert_eq!(pixmap.pixel(145, 150).unwrap().alpha(), 0);
    }

    // 3. Draw dotted line with stroke width 32px
    {
        let mut pb = tiny_skia::PathBuilder::new();
        pb.move_to(50.0, 250.0);
        pb.line_to(450.0, 250.0);
        let path = pb.finish().unwrap();

        let stroke_width = 32.0f32;
        let dot_len = 0.1f32;
        let gap_len = (stroke_width * 2.2).max(8.0); // 70.4

        let mut stroke = tiny_skia::Stroke::default();
        stroke.width = stroke_width;
        stroke.line_cap = tiny_skia::LineCap::Round;
        stroke.dash = tiny_skia::StrokeDash::new(vec![dot_len, gap_len], 0.0);

        let mut paint = tiny_skia::Paint::default();
        paint.anti_alias = true;
        paint.set_color(tiny_skia::Color::from_rgba8(0, 0, 255, 255)); // Blue

        pixmap.stroke_path(&path, &paint, &stroke, tiny_skia::Transform::identity(), None);

        // First dot is centered at x=50, radius ~16
        assert!(pixmap.pixel(50, 250).unwrap().blue() > 200);

        // Between first and second dot (e.g. x=85): should be transparent
        assert_eq!(pixmap.pixel(85, 250).unwrap().alpha(), 0);

        // Second dot at around x=120: should be blue
        assert!(pixmap.pixel(120, 250).unwrap().blue() > 200);
    }
}

#[test]
fn test_hsl_to_rgb_and_rgb_to_hsl_conversions() {
    // 1. Primary Colors
    // Red: RGB(255, 0, 0) <-> HSL(0, 100%, 50%)
    assert_eq!(hsl_to_rgb(0.0, 100.0, 50.0), (255, 0, 0));
    assert_eq!(rgb_to_hsl(255, 0, 0), (0.0, 100.0, 50.0));

    // Green: RGB(0, 255, 0) <-> HSL(120, 100%, 50%)
    assert_eq!(hsl_to_rgb(120.0, 100.0, 50.0), (0, 255, 0));
    assert_eq!(rgb_to_hsl(0, 255, 0), (120.0, 100.0, 50.0));

    // Blue: RGB(0, 0, 255) <-> HSL(240, 100%, 50%)
    assert_eq!(hsl_to_rgb(240.0, 100.0, 50.0), (0, 0, 255));
    assert_eq!(rgb_to_hsl(0, 0, 255), (240.0, 100.0, 50.0));

    // 2. Secondary Colors
    // Yellow: RGB(255, 255, 0) <-> HSL(60, 100%, 50%)
    assert_eq!(hsl_to_rgb(60.0, 100.0, 50.0), (255, 255, 0));
    assert_eq!(rgb_to_hsl(255, 255, 0), (60.0, 100.0, 50.0));

    // Cyan: RGB(0, 255, 255) <-> HSL(180, 100%, 50%)
    assert_eq!(hsl_to_rgb(180.0, 100.0, 50.0), (0, 255, 255));
    assert_eq!(rgb_to_hsl(0, 255, 255), (180.0, 100.0, 50.0));

    // Magenta: RGB(255, 0, 255) <-> HSL(300, 100%, 50%)
    assert_eq!(hsl_to_rgb(300.0, 100.0, 50.0), (255, 0, 255));
    assert_eq!(rgb_to_hsl(255, 0, 255), (300.0, 100.0, 50.0));

    // 3. Neutrals
    // Pure Black: RGB(0, 0, 0) -> HSL(0, 0%, 0%)
    assert_eq!(hsl_to_rgb(0.0, 0.0, 0.0), (0, 0, 0));
    assert_eq!(rgb_to_hsl(0, 0, 0), (0.0, 0.0, 0.0));

    // Pure White: RGB(255, 255, 255) -> HSL(0, 0%, 100%)
    assert_eq!(hsl_to_rgb(0.0, 0.0, 100.0), (255, 255, 255));
    assert_eq!(rgb_to_hsl(255, 255, 255), (0.0, 0.0, 100.0));

    // Neutral Gray: RGB(128, 128, 128) -> HSL(0, 0%, 50%)
    assert_eq!(hsl_to_rgb(0.0, 0.0, 50.0), (128, 128, 128));
    assert_eq!(rgb_to_hsl(128, 128, 128), (0.0, 0.0, 50.0));

    // 4. Roundtrip consistency on sample vibrant palette colors
    let samples = [(30u8, 30u8, 30u8), (239, 68, 68), (59, 130, 246), (168, 85, 247), (34, 197, 94)];
    for &(r, g, b) in &samples {
        let (h, s, l) = rgb_to_hsl(r, g, b);
        let (r2, g2, b2) = hsl_to_rgb(h, s, l);
        assert!((r as i32 - r2 as i32).abs() <= 1, "R mismatch for ({}, {}, {}): got {}", r, g, b, r2);
        assert!((g as i32 - g2 as i32).abs() <= 1, "G mismatch for ({}, {}, {}): got {}", r, g, b, g2);
        assert!((b as i32 - b2 as i32).abs() <= 1, "B mismatch for ({}, {}, {}): got {}", r, g, b, b2);
    }
}

#[test]
fn test_canvas_zoom_clamping_and_parsing() {
    // 1. Zoom range clamping: min 25%, max 400%
    assert_eq!(clamp_zoom_percent(100), 100);
    assert_eq!(clamp_zoom_percent(25), 25);
    assert_eq!(clamp_zoom_percent(400), 400);
    assert_eq!(clamp_zoom_percent(10), 25);
    assert_eq!(clamp_zoom_percent(0), 25);
    assert_eq!(clamp_zoom_percent(-50), 25);
    assert_eq!(clamp_zoom_percent(500), 400);
    assert_eq!(clamp_zoom_percent(1000), 400);

    // 2. Zoom input parsing with % suffix and whitespaces
    assert_eq!(parse_zoom_input("100%"), Some(100));
    assert_eq!(parse_zoom_input("150"), Some(150));
    assert_eq!(parse_zoom_input("  75%  "), Some(75));
    assert_eq!(parse_zoom_input("200 %"), Some(200));
    assert_eq!(parse_zoom_input("10%"), Some(25)); // clamped to 25
    assert_eq!(parse_zoom_input("600%"), Some(400)); // clamped to 400

    // Invalid inputs return None
    assert_eq!(parse_zoom_input(""), None);
    assert_eq!(parse_zoom_input("abc"), None);
    assert_eq!(parse_zoom_input("%%"), None);

    // 3. Zoom step calculations by 25%
    let mut zoom = 100;
    zoom = clamp_zoom_percent(zoom + 25);
    assert_eq!(zoom, 125);
    zoom = clamp_zoom_percent(zoom - 50);
    assert_eq!(zoom, 75);

    // Stepping below min 25%
    let mut min_zoom = 25;
    min_zoom = clamp_zoom_percent(min_zoom - 25);
    assert_eq!(min_zoom, 25);

    // Stepping above max 400%
    let mut max_zoom = 400;
    max_zoom = clamp_zoom_percent(max_zoom + 25);
    assert_eq!(max_zoom, 400);
}

#[test]
fn test_canvas_coordinate_scaling_at_various_zoom_levels() {
    // Default 100% zoom (1.0 factor)
    assert_eq!(scale_coordinate_to_canvas(500.0, 1.0), 500.0);
    assert_eq!(scale_coordinate_to_canvas(300.0, 1.0), 300.0);

    // Zoom in 200% (2.0 factor): mouse at 1000px corresponds to 500px in the Pixmap
    assert_eq!(scale_coordinate_to_canvas(1000.0, 2.0), 500.0);
    assert_eq!(scale_coordinate_to_canvas(600.0, 2.0), 300.0);

    // Zoom out 50% (0.5 factor): mouse at 250px corresponds to 500px in the Pixmap
    assert_eq!(scale_coordinate_to_canvas(250.0, 0.5), 500.0);
    assert_eq!(scale_coordinate_to_canvas(150.0, 0.5), 300.0);

    // Max Zoom 400% (4.0 factor): mouse at 1600px corresponds to 400px in the Pixmap
    assert_eq!(scale_coordinate_to_canvas(1600.0, 4.0), 400.0);

    // Min Zoom 25% (0.25 factor): mouse at 400px corresponds to 1600px in the Pixmap
    assert_eq!(scale_coordinate_to_canvas(400.0, 0.25), 1600.0);
}

#[test]
fn test_canvas_background_color_persistence_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_canvas_bg_{}", Uuid::new_v4()));
    let category_dir = temp_dir.join("Designs");
    fs::create_dir_all(&category_dir).unwrap();

    let password = "CanvasBgPassword#2026";
    let keyfile_bytes = b"canvas_bg_keyfile_bytes";

    // 1. Create a canvas note with a custom background color stored in content
    let custom_bg_hex = "#2d3748";
    let canvas_note = Note::new_with_type(
        "Dark Mode Wireframe",
        vec!["ui".into(), "dark".into()],
        custom_bg_hex,
        NoteType::Canvas,
    );
    let note_path = category_dir.join(format!("{}.vault", canvas_note.id));

    save_note_encrypted(&canvas_note, password, Some(keyfile_bytes), &note_path)
        .expect("Saving canvas note with custom background color must succeed");

    // 2. Decrypt and load note
    let loaded = load_note_decrypted(password, Some(keyfile_bytes), &note_path)
        .expect("Loading encrypted canvas note must succeed");

    assert_eq!(loaded.note_type, NoteType::Canvas);
    assert_eq!(loaded.content, "#2d3748");
    assert_eq!(loaded.title, "Dark Mode Wireframe");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}


