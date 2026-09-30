use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{decrypt_bytes, encrypt_bytes, VaultError};

/// Metadata stored in the header of an encrypted attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMetadata {
    pub file_name: String,
    pub file_size: u64,
    pub created_at: i64,
}

/// In-memory representation of a decrypted note attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachment {
    pub file_name: String,
    pub file_size: u64,
    pub created_at: i64,
    pub data: Vec<u8>,
}

impl NoteAttachment {
    /// Creates a new NoteAttachment with current unix timestamp.
    pub fn new(file_name: impl Into<String>, data: Vec<u8>) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let file_name = file_name.into();
        let file_size = data.len() as u64;
        Self {
            file_name,
            file_size,
            created_at,
            data,
        }
    }
}

impl Zeroize for NoteAttachment {
    fn zeroize(&mut self) {
        self.file_name.zeroize();
        self.file_size.zeroize();
        self.created_at.zeroize();
        self.data.zeroize();
    }
}

/// Serializes an attachment into a compact binary payload:
/// `[Header Len (4B, big-endian u32)] + [JSON Header (AttachmentMetadata)] + [Raw Data Bytes]`
pub fn serialize_attachment(attachment: &NoteAttachment) -> Result<Vec<u8>, Box<dyn Error>> {
    let meta = AttachmentMetadata {
        file_name: attachment.file_name.clone(),
        file_size: attachment.data.len() as u64,
        created_at: attachment.created_at,
    };
    let meta_json = serde_json::to_vec(&meta)?;
    let meta_len = meta_json.len() as u32;
    let mut payload = Vec::with_capacity(4 + meta_json.len() + attachment.data.len());
    payload.extend_from_slice(&meta_len.to_be_bytes());
    payload.extend_from_slice(&meta_json);
    payload.extend_from_slice(&attachment.data);
    Ok(payload)
}

/// Deserializes a decrypted binary payload into a `NoteAttachment`.
pub fn deserialize_attachment(decrypted: &[u8]) -> Result<NoteAttachment, Box<dyn Error>> {
    if decrypted.len() < 4 {
        return Err(Box::new(VaultError::InvalidFileFormat(
            "Attachment data too short for header length".into(),
        )));
    }
    let meta_len = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;
    if decrypted.len() < 4 + meta_len {
        return Err(Box::new(VaultError::InvalidFileFormat(
            "Attachment data too short for metadata payload".into(),
        )));
    }
    let meta: AttachmentMetadata = serde_json::from_slice(&decrypted[4..4 + meta_len])?;
    let data = decrypted[4 + meta_len..].to_vec();
    Ok(NoteAttachment {
        file_name: meta.file_name,
        file_size: meta.file_size,
        created_at: meta.created_at,
        data,
    })
}

/// Deserializes only the metadata from a decrypted binary payload.
pub fn deserialize_attachment_metadata(decrypted: &[u8]) -> Result<AttachmentMetadata, Box<dyn Error>> {
    if decrypted.len() < 4 {
        return Err(Box::new(VaultError::InvalidFileFormat(
            "Attachment data too short for header length".into(),
        )));
    }
    let meta_len = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;
    if decrypted.len() < 4 + meta_len {
        return Err(Box::new(VaultError::InvalidFileFormat(
            "Attachment data too short for metadata payload".into(),
        )));
    }
    let meta: AttachmentMetadata = serde_json::from_slice(&decrypted[4..4 + meta_len])?;
    Ok(meta)
}

/// Encrypts and saves an attachment to disk using the cryptographic cascade (Version 0x02).
pub fn save_attachment_encrypted(
    attachment: &NoteAttachment,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let payload = serialize_attachment(attachment)?;
    let encrypted = encrypt_bytes(&payload, password, keyfile_bytes)?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, &encrypted)?;
    Ok(())
}

/// Reads and decrypts an attachment from disk.
pub fn load_attachment_decrypted(
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    input_path: &Path,
) -> Result<NoteAttachment, Box<dyn Error>> {
    let file_data = fs::read(input_path)?;
    let decrypted = decrypt_bytes(&file_data, password, keyfile_bytes)?;
    deserialize_attachment(decrypted.as_slice())
}

/// Reads and decrypts only the metadata of an attachment from disk.
pub fn load_attachment_metadata(
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    input_path: &Path,
) -> Result<AttachmentMetadata, Box<dyn Error>> {
    let file_data = fs::read(input_path)?;
    let decrypted = decrypt_bytes(&file_data, password, keyfile_bytes)?;
    deserialize_attachment_metadata(decrypted.as_slice())
}

/// Returns true if the file path has `.vault` extension and stem matches `<note_stem>_a<N>` with N >= 1.
pub fn is_attachment_file(path: &Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) != Some("vault") {
        return false;
    }
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        parse_attachment_stem(stem).is_some()
    } else {
        false
    }
}

/// Parses a stem like "note_123_a1" into ("note_123", 1).
pub fn parse_attachment_stem(stem: &str) -> Option<(&str, usize)> {
    if let Some(idx) = stem.rfind("_a") {
        let suffix = &stem[idx + 2..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(num) = suffix.parse::<usize>() {
                if num > 0 {
                    return Some((&stem[..idx], num));
                }
            }
        }
    }
    None
}

/// Gets the expected path for attachment `index` (1-based) of the given note.
pub fn get_attachment_path(note_path: &Path, index: usize) -> PathBuf {
    let parent = note_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = note_path.file_stem().and_then(|s| s.to_str()).unwrap_or("note");
    parent.join(format!("{}_a{}.vault", stem, index))
}

/// Lists all attachment paths for a given note path, sorted by index (1..N).
pub fn list_note_attachment_files(note_path: &Path) -> Vec<PathBuf> {
    let parent = match note_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let note_stem = match note_path.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let entries = match fs::read_dir(parent) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut indexed: Vec<(usize, PathBuf)> = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("vault") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Some((base, idx)) = parse_attachment_stem(stem) {
                    if base == note_stem {
                        indexed.push((idx, path));
                    }
                }
            }
        }
    }

    indexed.sort_by_key(|(idx, _)| *idx);
    indexed.into_iter().map(|(_, p)| p).collect()
}

/// Gets the next attachment path for a note (e.g. `_a1.vault`, `_a2.vault`, etc.).
pub fn get_next_attachment_path(note_path: &Path) -> PathBuf {
    let existing = list_note_attachment_files(note_path);
    let note_stem = note_path.file_stem().and_then(|s| s.to_str()).unwrap_or("note");
    let parent = note_path.parent().unwrap_or_else(|| Path::new(""));
    let mut max_idx = 0;
    for p in &existing {
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            if let Some((base, idx)) = parse_attachment_stem(stem) {
                if base == note_stem && idx > max_idx {
                    max_idx = idx;
                }
            }
        }
    }
    parent.join(format!("{}_a{}.vault", note_stem, max_idx + 1))
}

/// Compacts attachment files so that suffixes are consecutive: _a1, _a2, ...
pub fn compact_note_attachments(note_path: &Path) {
    let existing = list_note_attachment_files(note_path);
    for (i, current_path) in existing.iter().enumerate() {
        let expected = get_attachment_path(note_path, i + 1);
        if *current_path != expected {
            let _ = fs::rename(current_path, &expected);
        }
    }
}

/// Moves all attachment files of a note when the note itself is moved to a new path.
pub fn move_note_attachments(old_note_path: &Path, new_note_path: &Path) {
    let attachments = list_note_attachment_files(old_note_path);
    let new_stem = new_note_path.file_stem().and_then(|s| s.to_str()).unwrap_or("note");
    let new_parent = new_note_path.parent().unwrap_or_else(|| Path::new(""));
    for p in attachments {
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            if let Some((_, idx)) = parse_attachment_stem(stem) {
                let target = new_parent.join(format!("{}_a{}.vault", new_stem, idx));
                let _ = fs::rename(&p, &target);
            }
        }
    }
}

/// Deletes all attachment files of a note when the note itself is deleted.
pub fn delete_note_attachments(note_path: &Path) {
    let attachments = list_note_attachment_files(note_path);
    for p in attachments {
        let _ = fs::remove_file(p);
    }
}

/// Formats a file size into human-readable representation.
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        let kb = bytes as f64 / KB as f64;
        format!("{:.1} KB", kb)
    } else if bytes < GB {
        let mb = bytes as f64 / MB as f64;
        format!("{:.1} MB", mb)
    } else {
        let gb = bytes as f64 / GB as f64;
        format!("{:.2} GB", gb)
    }
}

/// Returns true if the file extension or file name indicates an image format.
pub fn is_image_filename(file_name: &str) -> bool {
    let ext = Path::new(file_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "ico" | "svg"
    )
}

/// Returns true if the file extension or file name indicates a text format.
pub fn is_text_filename(file_name: &str) -> bool {
    let ext = Path::new(file_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(
        ext.as_str(),
        "txt" | "md" | "markdown" | "json" | "csv" | "log" | "rs" | "toml"
            | "yaml" | "yml" | "xml" | "html" | "htm" | "css" | "scss" | "js"
            | "jsx" | "ts" | "tsx" | "py" | "sh" | "bat" | "cmd" | "ps1" | "ini"
            | "cfg" | "conf" | "env" | "sql" | "c" | "cpp" | "h" | "hpp" | "go"
            | "java" | "kt" | "swift" | "rb" | "php" | "lua"
    )
}

/// Returns true if bytes appear to be UTF-8 plain text without null bytes.
pub fn is_text_data(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let sample = if data.len() > 8192 { &data[..8192] } else { data };
    if sample.contains(&0) {
        return false;
    }
    std::str::from_utf8(sample).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_attachment_stem_parsing() {
        assert_eq!(parse_attachment_stem("note_123_a1"), Some(("note_123", 1)));
        assert_eq!(parse_attachment_stem("note_123_a42"), Some(("note_123", 42)));
        assert_eq!(
            parse_attachment_stem("550e8400-e29b-41d4-a716-446655440000_a2"),
            Some(("550e8400-e29b-41d4-a716-446655440000", 2))
        );
        assert_eq!(parse_attachment_stem("note_123"), None);
        assert_eq!(parse_attachment_stem("note_a_b"), None);
        assert_eq!(parse_attachment_stem("note_a0"), None); // 1-based index expected
        assert_eq!(parse_attachment_stem("note_a"), None);
    }

    #[test]
    fn test_is_attachment_file() {
        assert!(is_attachment_file(Path::new("C:/vault/General/note_123_a1.vault")));
        assert!(is_attachment_file(Path::new("note_123_a2.vault")));
        assert!(!is_attachment_file(Path::new("note_123.vault")));
        assert!(!is_attachment_file(Path::new("note_123_a1.txt")));
        assert!(!is_attachment_file(Path::new("note_123_a1.vault.new")));
    }

    #[test]
    fn test_attachment_roundtrip_encrypted() {
        let temp_dir = std::env::temp_dir().join(format!("vault_att_test_{}", Uuid::new_v4()));
        let _ = fs::create_dir_all(&temp_dir);
        let note_path = temp_dir.join("test_note.vault");
        let att_path = get_attachment_path(&note_path, 1);

        let sample_data = b"Hello, encrypted attachment world! \x00\x01\x02\xFF".to_vec();
        let att = NoteAttachment::new("document.pdf", sample_data.clone());
        let password = "TestPassword456!#";

        save_attachment_encrypted(&att, password, None, &att_path).expect("save should succeed");
        assert!(att_path.exists());

        // Test metadata loading
        let meta = load_attachment_metadata(password, None, &att_path).expect("load meta should succeed");
        assert_eq!(meta.file_name, "document.pdf");
        assert_eq!(meta.file_size, sample_data.len() as u64);

        // Test full attachment loading
        let loaded = load_attachment_decrypted(password, None, &att_path).expect("load should succeed");
        assert_eq!(loaded.file_name, "document.pdf");
        assert_eq!(loaded.data, sample_data);
        assert_eq!(loaded.file_size, sample_data.len() as u64);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_attachment_list_compact_move_delete() {
        let temp_dir = std::env::temp_dir().join(format!("vault_att_mgmt_{}", Uuid::new_v4()));
        let folder1 = temp_dir.join("Folder1");
        let folder2 = temp_dir.join("Folder2");
        let _ = fs::create_dir_all(&folder1);
        let _ = fs::create_dir_all(&folder2);

        let note1 = folder1.join("my_note.vault");
        let password = "SecretPass123!";

        let att1 = NoteAttachment::new("file1.txt", b"Content 1".to_vec());
        let att2 = NoteAttachment::new("file2.png", b"Content 2".to_vec());
        let att3 = NoteAttachment::new("file3.pdf", b"Content 3".to_vec());

        let p1 = get_attachment_path(&note1, 1);
        let p2 = get_attachment_path(&note1, 2);
        let p3 = get_attachment_path(&note1, 3);

        save_attachment_encrypted(&att1, password, None, &p1).unwrap();
        save_attachment_encrypted(&att2, password, None, &p2).unwrap();
        save_attachment_encrypted(&att3, password, None, &p3).unwrap();

        let list = list_note_attachment_files(&note1);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], p1);
        assert_eq!(list[1], p2);
        assert_eq!(list[2], p3);

        // Next attachment path should be _a4
        assert_eq!(get_next_attachment_path(&note1), get_attachment_path(&note1, 4));

        // Delete attachment 2 and compact
        let _ = fs::remove_file(&p2);
        compact_note_attachments(&note1);

        let compacted = list_note_attachment_files(&note1);
        assert_eq!(compacted.len(), 2);
        assert_eq!(compacted[0], p1);
        assert_eq!(compacted[1], p2); // Previously p3 was renamed to p2

        // Verify content of new p2 is att3
        let loaded_p2 = load_attachment_decrypted(password, None, &p2).unwrap();
        assert_eq!(loaded_p2.file_name, "file3.pdf");

        // Move note to folder2
        let note2 = folder2.join("my_note.vault");
        move_note_attachments(&note1, &note2);

        let list_f1 = list_note_attachment_files(&note1);
        assert_eq!(list_f1.len(), 0);

        let list_f2 = list_note_attachment_files(&note2);
        assert_eq!(list_f2.len(), 2);

        // Delete all attachments
        delete_note_attachments(&note2);
        assert_eq!(list_note_attachment_files(&note2).len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(500), "500 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(2048), "2.0 KB");
        assert_eq!(format_file_size(1024 * 1024 * 3 + 512 * 1024), "3.5 MB");
    }

    #[test]
    fn test_preview_type_detection() {
        assert!(is_image_filename("photo.PNG"));
        assert!(is_image_filename("diagram.jpg"));
        assert!(is_image_filename("graphic.svg"));
        assert!(is_image_filename("icon.webp"));
        assert!(!is_image_filename("notes.txt"));
        assert!(!is_image_filename("archive.zip"));

        assert!(is_text_filename("notes.TXT"));
        assert!(is_text_filename("README.md"));
        assert!(is_text_filename("config.json"));
        assert!(is_text_filename("data.csv"));
        assert!(is_text_filename("main.rs"));
        assert!(!is_text_filename("photo.png"));
        assert!(!is_text_filename("binary.bin"));

        assert!(is_text_data(b"Hello world, this is UTF-8 text!"));
        assert!(is_text_data(b""));
        assert!(!is_text_data(&[0x00, 0x01, 0x02, 0xFF]));
    }
}
