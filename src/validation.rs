/// Validation and sanitization utilities for folders and filenames.

/// Validates a user-supplied folder name to ensure it is valid, safe, and portable across OSes (especially Windows).
/// Returns `Ok(sanitized_trimmed_name)` or `Err(user_friendly_error_message)`.
pub fn validate_folder_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Folder name cannot be empty.".to_string());
    }

    if trimmed.len() > 255 {
        return Err("Folder name is too long (maximum 255 characters).".to_string());
    }

    // Disallow path separators and path traversal
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err("Folder name cannot contain path separators ('/' or '\\').".to_string());
    }

    if trimmed == "." || trimmed == ".." || trimmed.starts_with("../") || trimmed.starts_with("..\\") || trimmed.contains("/..") || trimmed.contains("\\..") {
        return Err("Folder name cannot contain relative path components ('..').".to_string());
    }

    // Windows illegal filename characters: < > : " | ? * and ASCII control characters (0-31)
    const ILLEGAL_CHARS: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];
    if trimmed.chars().any(|c| ILLEGAL_CHARS.contains(&c) || c.is_control() || (c as u32) < 32) {
        return Err("Folder name contains illegal characters (< > : \" | ? * or control characters).".to_string());
    }

    // Windows prohibits filenames ending with a period
    if trimmed.ends_with('.') {
        return Err("Folder name cannot end with a period ('.').".to_string());
    }

    // NoteVault internal reserved category
    if trimmed == "*All Notes*" {
        return Err("'*All Notes*' is a reserved system category name.".to_string());
    }

    // Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    // Windows rejects these even if an extension is added (e.g., CON.txt)
    let base_name = trimmed.split('.').next().unwrap_or(trimmed);
    let upper_base = base_name.to_ascii_uppercase();
    const RESERVED_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED_NAMES.contains(&upper_base.as_str()) {
        return Err(format!("'{}' is a system reserved device name on Windows.", base_name));
    }

    Ok(trimmed.to_string())
}

/// Sanitizes a note title to produce a safe, filesystem-compatible filename.
/// Replaces illegal characters (`/`, `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`, and control characters) with `_`.
/// Trims whitespace and leading/trailing dots.
/// If the sanitized result is empty, falls back to `fallback_id`.
pub fn sanitize_filename(title: &str, fallback_id: &str) -> String {
    const ILLEGAL_CHARS: [char; 10] = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    let sanitized: String = title
        .chars()
        .map(|c| if ILLEGAL_CHARS.contains(&c) || c.is_control() { '_' } else { c })
        .collect();

    let trimmed = sanitized.trim().trim_matches('.');
    if trimmed.is_empty() {
        return fallback_id.to_string();
    }

    // Guard against Windows-reserved filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    // Check base name before any extension, e.g. CON.txt or prn.json
    let base = trimmed.split('.').next().unwrap_or(trimmed);
    let upper_base = base.to_ascii_uppercase();
    const RESERVED_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED_NAMES.contains(&upper_base.as_str()) {
        format!("{}_{}", trimmed, fallback_id)
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename_basic() {
        assert_eq!(sanitize_filename("Simple Note Title", "fallback-id"), "Simple Note Title");
    }

    #[test]
    fn test_sanitize_filename_illegal_characters() {
        assert_eq!(
            sanitize_filename("Note/With\\Illegal:Chars*?\"<>|Test", "fallback-id"),
            "Note_With_Illegal_Chars______Test"
        );
    }

    #[test]
    fn test_sanitize_filename_empty_fallback() {
        assert_eq!(sanitize_filename("", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("   ", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("....", "fallback-uuid-1234"), "fallback-uuid-1234");
        assert_eq!(sanitize_filename("/:*?", "fallback-uuid-1234"), "____");
        assert_eq!(sanitize_filename(".....", "fallback-123"), "fallback-123");
    }

    #[test]
    fn test_sanitize_filename_windows_reserved() {
        assert_eq!(sanitize_filename("CON", "id123"), "CON_id123");
        assert_eq!(sanitize_filename("prn", "id123"), "prn_id123");
        assert_eq!(sanitize_filename("aux", "id123"), "aux_id123");
        assert_eq!(sanitize_filename("nul", "id123"), "nul_id123");
        assert_eq!(sanitize_filename("CON.txt", "id123"), "CON.txt_id123");
        assert_eq!(sanitize_filename("prn.json", "id123"), "prn.json_id123");
        assert_eq!(sanitize_filename("COM1", "abc"), "COM1_abc");
        assert_eq!(sanitize_filename("LPT9.vault", "xyz"), "LPT9.vault_xyz");
    }

    #[test]
    fn test_validate_folder_name_valid() {
        assert_eq!(validate_folder_name("Personal").unwrap(), "Personal");
        assert_eq!(validate_folder_name("  Work Notes  ").unwrap(), "Work Notes");
        assert_eq!(validate_folder_name("Project-2026_v2").unwrap(), "Project-2026_v2");
        assert_eq!(validate_folder_name("Projekte (2026)").unwrap(), "Projekte (2026)");
        assert_eq!(validate_folder_name("Notizen & Entwürfe").unwrap(), "Notizen & Entwürfe");
    }

    #[test]
    fn test_validate_folder_name_empty_or_too_long() {
        assert!(validate_folder_name("").is_err());
        assert!(validate_folder_name("   ").is_err());
        let exact_255 = "a".repeat(255);
        assert!(validate_folder_name(&exact_255).is_ok());
        let long_name = "a".repeat(256);
        assert!(validate_folder_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_folder_name_illegal_chars() {
        assert!(validate_folder_name("Folder/Sub").is_err());
        assert!(validate_folder_name("Folder\\Sub").is_err());
        assert!(validate_folder_name("Folder:Name").is_err());
        assert!(validate_folder_name("Folder*Name").is_err());
        assert!(validate_folder_name("Folder?Name").is_err());
        assert!(validate_folder_name("Folder\"Name").is_err());
        assert!(validate_folder_name("Folder<Name").is_err());
        assert!(validate_folder_name("Folder>Name").is_err());
        assert!(validate_folder_name("Folder|Name").is_err());
        assert!(validate_folder_name("Folder\x00Name").is_err());
        assert!(validate_folder_name("Folder\x1FName").is_err());
    }

    #[test]
    fn test_validate_folder_name_traversal_and_trailing() {
        assert!(validate_folder_name("..").is_err());
        assert!(validate_folder_name(".").is_err());
        assert!(validate_folder_name("../Secret").is_err());
        assert!(validate_folder_name("..\\Secret").is_err());
        assert!(validate_folder_name("TrailingPeriod.").is_err());
    }

    #[test]
    fn test_validate_folder_name_reserved_device_names() {
        assert!(validate_folder_name("CON").is_err());
        assert!(validate_folder_name("con").is_err());
        assert!(validate_folder_name("PRN").is_err());
        assert!(validate_folder_name("aux").is_err());
        assert!(validate_folder_name("NUL").is_err());
        assert!(validate_folder_name("COM1").is_err());
        assert!(validate_folder_name("lpt9").is_err());
        assert!(validate_folder_name("con.txt").is_err());
        assert!(validate_folder_name("*All Notes*").is_err());
    }
}
