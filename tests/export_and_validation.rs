use note_vault::{
    format_decrypted_json_export, format_decrypted_txt_export, format_line_numbers,
    format_markdown_export, sanitize_filename, validate_folder_name, Note,
};

#[test]
fn test_folder_validation_comprehensive() {
    // Valid folder names
    assert!(validate_folder_name("Personal").is_ok());
    assert!(validate_folder_name("Work 2026").is_ok());
    assert!(validate_folder_name("Sub-Folder_1").is_ok());
    assert!(validate_folder_name("Project & Ideas").is_ok());
    assert!(validate_folder_name("Notizen (Wichtig)").is_ok());
    assert!(validate_folder_name("  Trimmed Folder  ").is_ok());
    assert_eq!(validate_folder_name("  Trimmed Folder  ").unwrap(), "Trimmed Folder");

    // Invalid: Path traversal and separators
    assert!(validate_folder_name("..").is_err());
    assert!(validate_folder_name(".").is_err());
    assert!(validate_folder_name("../Secret").is_err());
    assert!(validate_folder_name("..\\Secret").is_err());
    assert!(validate_folder_name("Folder/Sub").is_err());
    assert!(validate_folder_name("Folder\\Sub").is_err());
    assert!(validate_folder_name("Folder/..").is_err());
    assert!(validate_folder_name("Folder\\..").is_err());

    // Invalid: Windows illegal characters
    for illegal in ['<', '>', ':', '"', '|', '?', '*'] {
        let name = format!("Folder{}Test", illegal);
        assert!(validate_folder_name(&name).is_err(), "Folder name with '{}' must be rejected", illegal);
    }

    // Invalid: Control characters
    assert!(validate_folder_name("Folder\x00Name").is_err());
    assert!(validate_folder_name("Folder\x1FName").is_err());

    // Invalid: Windows trailing period
    assert!(validate_folder_name("Trailing.").is_err());
    assert!(validate_folder_name("EndsWithDot.").is_err());

    // Invalid: Reserved system category
    assert!(validate_folder_name("*All Notes*").is_err());

    // Invalid: Windows reserved device names
    for dev in &["CON", "PRN", "AUX", "NUL", "COM1", "COM5", "COM9", "LPT1", "LPT9"] {
        assert!(validate_folder_name(dev).is_err(), "Device name '{}' must be rejected", dev);
        let lower = dev.to_lowercase();
        assert!(validate_folder_name(&lower).is_err(), "Lowercase device name '{}' must be rejected", lower);
        let with_ext = format!("{}.txt", dev);
        assert!(validate_folder_name(&with_ext).is_err(), "Device name with extension '{}' must be rejected", with_ext);
    }

    // Invalid: Empty or whitespace
    assert!(validate_folder_name("").is_err());
    assert!(validate_folder_name("    ").is_err());

    // Boundary: Maximum length (255 characters allowed, 256 rejected)
    let max_255 = "x".repeat(255);
    assert!(validate_folder_name(&max_255).is_ok());
    let over_255 = "x".repeat(256);
    assert!(validate_folder_name(&over_255).is_err());
}

#[test]
fn test_filename_sanitization_comprehensive() {
    let fallback = "fallback-uuid-1234";

    // Clean names unchanged
    assert_eq!(sanitize_filename("Clean Note Title", fallback), "Clean Note Title");

    // Illegal chars replaced with underscore
    assert_eq!(
        sanitize_filename("Title / With \\ Colon : Star * Question ? Quote \" Less < Greater > Pipe | Null \0", fallback),
        "Title _ With _ Colon _ Star _ Question _ Quote _ Less _ Greater _ Pipe _ Null _"
    );

    // Trimming leading and trailing dots/whitespace
    assert_eq!(sanitize_filename("   ...Note Title...   ", fallback), "Note Title");

    // Empty or pure illegal characters fallback to ID
    assert_eq!(sanitize_filename("", fallback), fallback);
    assert_eq!(sanitize_filename("     ", fallback), fallback);
    assert_eq!(sanitize_filename(".....", fallback), fallback);

    // Reserved Windows filenames get appended with fallback
    assert_eq!(sanitize_filename("CON", fallback), format!("CON_{}", fallback));
    assert_eq!(sanitize_filename("prn", fallback), format!("prn_{}", fallback));
    assert_eq!(sanitize_filename("AUX.txt", fallback), format!("AUX.txt_{}", fallback));
    assert_eq!(sanitize_filename("nul.vault", fallback), format!("nul.vault_{}", fallback));
    assert_eq!(sanitize_filename("COM1.json", fallback), format!("COM1.json_{}", fallback));
}

#[test]
fn test_export_markdown_with_yaml_frontmatter() {
    let note = Note::new(
        "Quarterly Report: \"Q3 / 2026\"",
        vec!["finance".into(), "confidential:high".into()],
        "# Financial Summary\n\n- Net Revenue: $5.2M\n- Profit: $1.1M\n",
    );

    let md = format_markdown_export(&note, "Executive Board", "2026-09-20 22:00:00 UTC");

    // Must have standard YAML delimiters
    assert!(md.starts_with("---\n"));
    assert!(md.contains("---\n\n# Financial Summary"));

    // Proper JSON-escaped YAML fields
    assert!(md.contains(r#"title: "Quarterly Report: \"Q3 / 2026\"""#));
    assert!(md.contains(r#"category: "Executive Board""#));
    assert!(md.contains(r#"tags: ["finance","confidential:high"]"#));
    assert!(md.contains(r#"date: "2026-09-20 22:00:00 UTC""#));
}

#[test]
fn test_export_json_and_txt() {
    let tags = vec!["tagA".to_string(), "tagB".to_string()];
    let json_res = format_decrypted_json_export(
        "note-uuid-999",
        "Export Test Note",
        "General",
        &tags,
        "2026-09-20",
        "Decrypted payload content",
    );
    assert!(json_res.is_ok());
    let json_str = json_res.unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["id"], "note-uuid-999");
    assert_eq!(parsed["title"], "Export Test Note");
    assert_eq!(parsed["category"], "General");
    assert_eq!(parsed["tags"][0], "tagA");
    assert_eq!(parsed["tags"][1], "tagB");
    assert_eq!(parsed["content"], "Decrypted payload content");

    let txt = format_decrypted_txt_export(
        "Export Test Note",
        "General",
        &tags,
        "2026-09-20",
        "Decrypted payload content",
    );
    assert!(txt.contains("Title: Export Test Note\n"));
    assert!(txt.contains("Category: General\n"));
    assert!(txt.contains("Tags: tagA, tagB\n"));
    assert!(txt.contains("Date: 2026-09-20\n"));
    assert!(txt.ends_with("Decrypted payload content"));
}

#[test]
fn test_line_numbers_formatter() {
    assert_eq!(format_line_numbers(""), "1");
    assert_eq!(format_line_numbers("single line"), "1");
    assert_eq!(format_line_numbers("line 1\nline 2"), "1\n2");
    assert_eq!(format_line_numbers("1\n2\n3\n4\n5"), "1\n2\n3\n4\n5");
    assert_eq!(format_line_numbers("\n\n"), "1\n2\n3");
}
