use std::fs;
use note_vault::{
    attachment::{
        compact_note_attachments, delete_note_attachments, format_file_size,
        get_next_attachment_path, is_attachment_file, is_image_filename, is_text_data,
        is_text_filename, list_note_attachment_files, load_attachment_decrypted,
        load_attachment_metadata, move_note_attachments, save_attachment_encrypted, NoteAttachment,
    },
    load_note_decrypted, reencrypt_vault_atomic, save_note_encrypted, Note,
};
use uuid::Uuid;

#[test]
fn test_attachment_full_lifecycle_and_reencrypt() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_att_integ_{}", Uuid::new_v4()));
    let category_dir = temp_dir.join("ConfidentialDocs");
    fs::create_dir_all(&category_dir).unwrap();

    let password = "PrimaryPassword2026!#";
    let keyfile_bytes = b"sample_usb_key_token_bytes_xyz987";

    // 1. Create a parent note
    let note = Note::new(
        "Project Blueprint",
        vec!["architecture".into(), "security".into()],
        "# Project Architecture\nSee attached diagrams and specifications.",
    );
    let note_path = category_dir.join("blueprint_123.vault");
    save_note_encrypted(&note, password, Some(keyfile_bytes), &note_path)
        .expect("Parent note saving must succeed");

    // 2. Add multiple arbitrary attachments
    let att1_data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03];
    let att1 = NoteAttachment::new("diagram.png", att1_data.clone());
    let att1_path = get_next_attachment_path(&note_path);
    assert_eq!(
        att1_path.file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a1.vault"
    );
    save_attachment_encrypted(&att1, password, Some(keyfile_bytes), &att1_path)
        .expect("Saving attachment 1 must succeed");

    let att2_data = b"%PDF-1.7\nSample confidential contract specifications\n%%EOF".to_vec();
    let att2 = NoteAttachment::new("specifications.pdf", att2_data.clone());
    let att2_path = get_next_attachment_path(&note_path);
    assert_eq!(
        att2_path.file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a2.vault"
    );
    save_attachment_encrypted(&att2, password, Some(keyfile_bytes), &att2_path)
        .expect("Saving attachment 2 must succeed");

    let att3_data = vec![0xAA; 1024 * 128]; // 128 KB binary payload
    let att3 = NoteAttachment::new("archive.bin", att3_data.clone());
    let att3_path = get_next_attachment_path(&note_path);
    assert_eq!(
        att3_path.file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a3.vault"
    );
    save_attachment_encrypted(&att3, password, Some(keyfile_bytes), &att3_path)
        .expect("Saving attachment 3 must succeed");

    // 3. Test listing and filtering
    let att_files = list_note_attachment_files(&note_path);
    assert_eq!(att_files.len(), 3);
    assert!(is_attachment_file(&att1_path));
    assert!(is_attachment_file(&att2_path));
    assert!(is_attachment_file(&att3_path));
    assert!(!is_attachment_file(&note_path));

    // 4. Test reading metadata only (without loading full payload)
    let meta1 = load_attachment_metadata(password, Some(keyfile_bytes), &att1_path)
        .expect("Metadata loading for att 1 must succeed");
    assert_eq!(meta1.file_name, "diagram.png");
    assert_eq!(meta1.file_size, att1_data.len() as u64);

    let meta3 = load_attachment_metadata(password, Some(keyfile_bytes), &att3_path)
        .expect("Metadata loading for att 3 must succeed");
    assert_eq!(meta3.file_name, "archive.bin");
    assert_eq!(meta3.file_size, 1024 * 128);
    assert_eq!(format_file_size(meta3.file_size), "128.0 KB");

    // 5. Test loading decrypted full attachment data
    let loaded_att2 = load_attachment_decrypted(password, Some(keyfile_bytes), &att2_path)
        .expect("Loading decrypted att 2 must succeed");
    assert_eq!(loaded_att2.file_name, "specifications.pdf");
    assert_eq!(loaded_att2.data, att2_data);

    // 6. Test replacing an attachment
    let replaced_att2_data = b"%PDF-1.7\nUpdated v2 contract specifications\n%%EOF".to_vec();
    let replaced_att2 = NoteAttachment::new("specifications_v2.pdf", replaced_att2_data.clone());
    save_attachment_encrypted(&replaced_att2, password, Some(keyfile_bytes), &att2_path)
        .expect("Replacing attachment 2 must succeed");

    let reloaded_att2 = load_attachment_decrypted(password, Some(keyfile_bytes), &att2_path)
        .expect("Reloading replaced att 2 must succeed");
    assert_eq!(reloaded_att2.file_name, "specifications_v2.pdf");
    assert_eq!(reloaded_att2.data, replaced_att2_data);

    // 7. Test deleting an attachment and compacting
    // Delete a2 (specifications_v2.pdf) -> leaving a1 and a3
    fs::remove_file(&att2_path).unwrap();
    let remaining_before_compact = list_note_attachment_files(&note_path);
    assert_eq!(remaining_before_compact.len(), 2);
    assert_eq!(
        remaining_before_compact[0].file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a1.vault"
    );
    assert_eq!(
        remaining_before_compact[1].file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a3.vault"
    );

    // Now compact -> a3 should be renamed to a2
    compact_note_attachments(&note_path);
    let remaining_after_compact = list_note_attachment_files(&note_path);
    assert_eq!(remaining_after_compact.len(), 2);
    assert_eq!(
        remaining_after_compact[0].file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a1.vault"
    );
    assert_eq!(
        remaining_after_compact[1].file_name().unwrap().to_str().unwrap(),
        "blueprint_123_a2.vault"
    );
    assert!(!att3_path.exists());

    // Verify the newly compacted a2 contains the archive.bin payload
    let compacted_a2 = load_attachment_decrypted(password, Some(keyfile_bytes), &remaining_after_compact[1])
        .expect("Compacted a2 must be decryptable");
    assert_eq!(compacted_a2.file_name, "archive.bin");
    assert_eq!(compacted_a2.data, att3_data);

    // 8. Test moving note to another category/name
    let dest_dir = temp_dir.join("ArchivedDocs");
    fs::create_dir_all(&dest_dir).unwrap();
    let new_note_path = dest_dir.join("archived_blueprint.vault");
    fs::rename(&note_path, &new_note_path).unwrap();
    move_note_attachments(&note_path, &new_note_path);

    let moved_atts = list_note_attachment_files(&new_note_path);
    assert_eq!(moved_atts.len(), 2);
    assert_eq!(
        moved_atts[0].file_name().unwrap().to_str().unwrap(),
        "archived_blueprint_a1.vault"
    );
    assert_eq!(
        moved_atts[1].file_name().unwrap().to_str().unwrap(),
        "archived_blueprint_a2.vault"
    );
    assert_eq!(list_note_attachment_files(&note_path).len(), 0);

    // 9. Test vault atomic re-encryption (both notes and attachments re-encrypted together)
    let new_password = "BrandNewMasterPassword999$$";
    let new_keyfile = b"new_device_keyfile_entropy_token";

    reencrypt_vault_atomic(
        &temp_dir,
        password,
        Some(keyfile_bytes),
        new_password,
        Some(new_keyfile),
        |_, _| {},
    )
    .expect("Vault atomic re-encryption must succeed for notes and attachments");

    // Parent note must be decryptable with new credentials
    let redecrypted_note = load_note_decrypted(new_password, Some(new_keyfile), &new_note_path)
        .expect("Parent note must be decryptable with new credentials");
    assert_eq!(redecrypted_note.title, "Project Blueprint");

    // Attachments must be decryptable with new credentials
    let redecrypted_att1 = load_attachment_decrypted(new_password, Some(new_keyfile), &moved_atts[0])
        .expect("Attachment 1 must be decryptable with new credentials");
    assert_eq!(redecrypted_att1.file_name, "diagram.png");
    assert_eq!(redecrypted_att1.data, att1_data);

    let redecrypted_att2 = load_attachment_decrypted(new_password, Some(new_keyfile), &moved_atts[1])
        .expect("Attachment 2 must be decryptable with new credentials");
    assert_eq!(redecrypted_att2.file_name, "archive.bin");
    assert_eq!(redecrypted_att2.data, att3_data);

    // Decryption with old credentials MUST fail
    assert!(load_note_decrypted(password, Some(keyfile_bytes), &new_note_path).is_err());
    assert!(load_attachment_decrypted(password, Some(keyfile_bytes), &moved_atts[0]).is_err());

    // 10. Test deleting all attachments
    delete_note_attachments(&new_note_path);
    assert_eq!(list_note_attachment_files(&new_note_path).len(), 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_attachment_preview_and_type_resolution() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_preview_test_{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let note_path = temp_dir.join("preview_note.vault");
    let password = "PreviewPassword2026!";

    // Text attachment
    let text_content = "fn main() {\n    println!(\"Hello encrypted preview!\");\n}";
    let text_att = NoteAttachment::new("code.rs", text_content.as_bytes().to_vec());
    let att1_path = get_next_attachment_path(&note_path);
    save_attachment_encrypted(&text_att, password, None, &att1_path).unwrap();

    // Image attachment
    let fake_png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let img_att = NoteAttachment::new("screenshot.PNG", fake_png.clone());
    let att2_path = get_next_attachment_path(&note_path);
    save_attachment_encrypted(&img_att, password, None, &att2_path).unwrap();

    // Binary / unsupported preview attachment
    let bin_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
    let bin_att = NoteAttachment::new("archive.zip", bin_data.clone());
    let att3_path = get_next_attachment_path(&note_path);
    save_attachment_encrypted(&bin_att, password, None, &att3_path).unwrap();

    // Load and test preview resolution
    let loaded1 = load_attachment_decrypted(password, None, &att1_path).unwrap();
    assert_eq!(loaded1.file_name, "code.rs");
    assert!(is_text_filename(&loaded1.file_name));
    assert!(is_text_data(&loaded1.data));
    assert!(!is_image_filename(&loaded1.file_name));
    let decoded_text = String::from_utf8(loaded1.data).unwrap();
    assert_eq!(decoded_text, text_content);

    let loaded2 = load_attachment_decrypted(password, None, &att2_path).unwrap();
    assert_eq!(loaded2.file_name, "screenshot.PNG");
    assert!(is_image_filename(&loaded2.file_name));
    assert!(!is_text_filename(&loaded2.file_name));

    let loaded3 = load_attachment_decrypted(password, None, &att3_path).unwrap();
    assert_eq!(loaded3.file_name, "archive.zip");
    assert!(!is_image_filename(&loaded3.file_name));
    assert!(!is_text_filename(&loaded3.file_name));
    assert!(!is_text_data(&loaded3.data));

    let _ = fs::remove_dir_all(&temp_dir);
}
