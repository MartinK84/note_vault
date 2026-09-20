use std::fs;
use note_vault::{
    load_note_decrypted, reencrypt_vault_atomic, save_note_encrypted, Note,
    CASCADE_HEADER_LEN, CASCADE_VERSION,
};
use uuid::Uuid;

#[test]
fn test_full_vault_lifecycle_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_integ_{}", Uuid::new_v4()));
    let work_dir = temp_dir.join("Work");
    let personal_dir = temp_dir.join("Personal");
    fs::create_dir_all(&work_dir).unwrap();
    fs::create_dir_all(&personal_dir).unwrap();

    let password = "VaultMasterPassword2026!#";
    let keyfile_bytes = b"quantum_resistant_entropy_token_bytes_abc123";

    // 1. Create and save Note A in Work category
    let note_a = Note::new(
        "Quarterly Strategic Plan",
        vec!["strategy".into(), "q3".into(), "confidential".into()],
        "# Strategy 2026\n\n- Expand local-first architecture\n- Zero-trust encryption cascade",
    );
    let path_a = work_dir.join("strategy.vault");
    save_note_encrypted(&note_a, password, Some(keyfile_bytes), &path_a)
        .expect("Saving note A should succeed");

    // 2. Create and save Note B in Personal category
    let note_b = Note::new(
        "Personal Health Record",
        vec!["health".into(), "private".into()],
        "Routine checkup scheduled for next Tuesday. All metrics normal.",
    );
    let path_b = personal_dir.join("health.vault");
    save_note_encrypted(&note_b, password, Some(keyfile_bytes), &path_b)
        .expect("Saving note B should succeed");

    // 3. Verify file headers on disk
    let raw_a = fs::read(&path_a).unwrap();
    assert_eq!(raw_a[0], CASCADE_VERSION);
    assert!(raw_a.len() > CASCADE_HEADER_LEN);

    let raw_b = fs::read(&path_b).unwrap();
    assert_eq!(raw_b[0], CASCADE_VERSION);
    assert!(raw_b.len() > CASCADE_HEADER_LEN);

    // 4. Decrypt and verify exact match
    let loaded_a = load_note_decrypted(password, Some(keyfile_bytes), &path_a)
        .expect("Decryption of note A should succeed");
    assert_eq!(loaded_a.id, note_a.id);
    assert_eq!(loaded_a.title, note_a.title);
    assert_eq!(loaded_a.tags, note_a.tags);
    assert_eq!(loaded_a.content, note_a.content);

    let loaded_b = load_note_decrypted(password, Some(keyfile_bytes), &path_b)
        .expect("Decryption of note B should succeed");
    assert_eq!(loaded_b.id, note_b.id);
    assert_eq!(loaded_b.title, note_b.title);
    assert_eq!(loaded_b.tags, note_b.tags);
    assert_eq!(loaded_b.content, note_b.content);

    // 5. Verify wrong password fails
    let wrong_pw_res = load_note_decrypted("WrongPassword", Some(keyfile_bytes), &path_a);
    assert!(wrong_pw_res.is_err());

    // 6. Verify missing keyfile fails
    let no_kf_res = load_note_decrypted(password, None, &path_a);
    assert!(no_kf_res.is_err());

    // 7. Verify altered keyfile fails
    let mut altered_kf = keyfile_bytes.to_vec();
    altered_kf[0] ^= 0x01;
    let altered_kf_res = load_note_decrypted(password, Some(&altered_kf), &path_a);
    assert!(altered_kf_res.is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_folder_reencrypt_atomic_workflow() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_reenc_integ_{}", Uuid::new_v4()));
    let cat1 = temp_dir.join("Finance");
    let cat2 = temp_dir.join("Research");
    fs::create_dir_all(&cat1).unwrap();
    fs::create_dir_all(&cat2).unwrap();

    let old_pw = "OldMasterPassword123!";
    let new_pw = "BrandNewMasterPassword456$";
    let old_keyfile = b"initial_usb_key_dongle_entropy";
    let new_keyfile = b"second_generation_usb_key_dongle_entropy";

    // Create 3 notes across 2 categories
    let n1 = Note::new("Budget 2026", vec!["finance".into()], "Revenue and costs");
    let n2 = Note::new("Taxes", vec!["finance".into(), "irs".into()], "Filing details");
    let n3 = Note::new("Algorithm Study", vec!["crypto".into()], "Argon2id + Cascade AEAD notes");

    let p1 = cat1.join("budget.vault");
    let p2 = cat1.join("taxes.vault");
    let p3 = cat2.join("algo.vault");

    save_note_encrypted(&n1, old_pw, Some(old_keyfile), &p1).unwrap();
    save_note_encrypted(&n2, old_pw, Some(old_keyfile), &p2).unwrap();
    save_note_encrypted(&n3, old_pw, Some(old_keyfile), &p3).unwrap();

    // Perform atomic re-encryption of the entire vault directory
    let total_reencrypted = reencrypt_vault_atomic(
        &temp_dir,
        old_pw,
        Some(old_keyfile),
        new_pw,
        Some(new_keyfile),
        |current, total| {
            assert!(current <= total);
        },
    ).expect("Atomic re-encryption across multi-folder vault must succeed");

    assert_eq!(total_reencrypted, 3);

    // Old credentials must fail on all files
    assert!(load_note_decrypted(old_pw, Some(old_keyfile), &p1).is_err());
    assert!(load_note_decrypted(old_pw, Some(old_keyfile), &p2).is_err());
    assert!(load_note_decrypted(old_pw, Some(old_keyfile), &p3).is_err());

    // New credentials must decrypt all files successfully
    let dec1 = load_note_decrypted(new_pw, Some(new_keyfile), &p1).unwrap();
    assert_eq!(dec1.title, "Budget 2026");
    assert_eq!(dec1.content, "Revenue and costs");

    let dec2 = load_note_decrypted(new_pw, Some(new_keyfile), &p2).unwrap();
    assert_eq!(dec2.title, "Taxes");

    let dec3 = load_note_decrypted(new_pw, Some(new_keyfile), &p3).unwrap();
    assert_eq!(dec3.title, "Algorithm Study");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_truncated_and_corrupt_files_resilience() {
    let temp_dir = std::env::temp_dir().join(format!("note_vault_resilience_{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let pw = "SecurePassword123!";

    // 0-byte file
    let f0 = temp_dir.join("zero_bytes.vault");
    fs::write(&f0, b"").unwrap();
    assert!(load_note_decrypted(pw, None, &f0).is_err());

    // 1-byte file
    let f1 = temp_dir.join("one_byte.vault");
    fs::write(&f1, &[CASCADE_VERSION]).unwrap();
    assert!(load_note_decrypted(pw, None, &f1).is_err());

    // 68-byte file (one byte short of CASCADE_HEADER_LEN = 69)
    let f68 = temp_dir.join("short_header.vault");
    let mut data68 = vec![0u8; 68];
    data68[0] = CASCADE_VERSION;
    fs::write(&f68, &data68).unwrap();
    assert!(load_note_decrypted(pw, None, &f68).is_err());

    // Random non-vault file
    let f_rand = temp_dir.join("random_garbage.vault");
    fs::write(&f_rand, b"THIS IS NOT A VALID VAULT FILE AT ALL").unwrap();
    assert!(load_note_decrypted(pw, None, &f_rand).is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}
