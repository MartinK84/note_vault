use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead as ChachaAead, KeyInit as ChachaKeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub mod config;
pub mod export;
pub mod validation;

pub use export::*;
pub use validation::*;

/// Cryptographic binary file header constants.
pub const CASCADE_VERSION: u8 = 0x02; // Version 2: AES-256-GCM + XChaCha20-Poly1305 cascade
pub const SALT_LEN: usize = 32;       // 256-bit salt for Argon2id
pub const AES_NONCE_LEN: usize = 12;  // 96-bit nonce for AES-256-GCM
pub const CHACHA_NONCE_LEN: usize = 24; // 192-bit nonce for XChaCha20
pub const TAG_LEN: usize = 16;        // 128-bit MAC tag (Poly1305 / GHASH)
pub const CASCADE_HEADER_LEN: usize = 1 + SALT_LEN + AES_NONCE_LEN + CHACHA_NONCE_LEN; // 69 bytes
pub const LEGACY_HEADER_LEN: usize = SALT_LEN + CHACHA_NONCE_LEN; // 56 bytes

// Aliases for backward compatibility
pub const NONCE_LEN: usize = CHACHA_NONCE_LEN;
pub const HEADER_LEN: usize = LEGACY_HEADER_LEN;

/// Domain-specific errors for encryption, decryption, and file I/O operations.
#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    KeyDerivation(String),
    EncryptionFailed,
    DecryptionFailed,
    InvalidFileFormat(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(err) => write!(f, "I/O error: {}", err),
            VaultError::Serialization(err) => write!(f, "JSON serialization error: {}", err),
            VaultError::KeyDerivation(msg) => write!(f, "Argon2 key derivation error: {}", msg),
            VaultError::EncryptionFailed => write!(f, "AEAD encryption failed"),
            VaultError::DecryptionFailed => {
                write!(f, "Decryption failed: invalid password, keyfile mismatch, or corrupted data")
            }
            VaultError::InvalidFileFormat(msg) => write!(f, "Invalid file format: {}", msg),
        }
    }
}

impl Error for VaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            VaultError::Io(err) => Some(err),
            VaultError::Serialization(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::Io(err)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(err: serde_json::Error) -> Self {
        VaultError::Serialization(err)
    }
}

/// Represents a single Note in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub content: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Note {
    /// Constructs a new Note with a randomly generated UUIDv4 and the current Unix timestamp (seconds).
    pub fn new(
        title: impl Into<String>,
        tags: Vec<String>,
        content: impl Into<String>,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            tags,
            content: content.into(),
            created_at,
            updated_at: created_at,
        }
    }
}

impl Zeroize for Note {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.tags.zeroize();
        self.content.zeroize();
        self.created_at.zeroize();
        self.updated_at.zeroize();
        self.id = Uuid::nil();
    }
}

/// Derives a 64-byte (512-bit) encryption key from a password, optional keyfile bytes, and salt using Argon2id.
///
/// If `keyfile_bytes` is `Some`, its BLAKE3 hash (32 bytes) is passed as the `secret` (pepper)
/// parameter in Argon2id. The first 32 bytes of the derived key are used for AES-256-GCM,
/// and the remaining 32 bytes are used for XChaCha20-Poly1305.
///
/// The resulting 64-byte key is wrapped in `Zeroizing` so that it is automatically erased from
/// memory upon drop.
pub fn derive_key(
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 64]>, VaultError> {
    let mut key = Zeroizing::new([0u8; 64]);

    if let Some(kf) = keyfile_bytes {
        let hash = blake3::hash(kf);
        let pepper = Zeroizing::new(*hash.as_bytes());
        let argon2 = Argon2::new_with_secret(
            pepper.as_ref(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        )
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    } else {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        );

        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    }

    Ok(key)
}

/// Derives a 32-byte (256-bit) encryption key using legacy Argon2id without pepper.
/// Strictly used for backward compatibility to decrypt legacy `.vault` files.
pub fn derive_key_legacy(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    );

    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Serializes, encrypts, and writes a `Note` to disk using the cryptographic cascade
/// (AES-256-GCM + XChaCha20-Poly1305).
///
/// Binary layout:
/// `[Version (1B, 0x02)] + [Argon2 Salt (32B)] + [AES Nonce (12B)] + [XChaCha Nonce (24B)] + [Final Ciphertext]`
///
/// Security properties:
/// - Salt and Nonces are cryptographically securely generated using `rand_core::OsRng`.
/// - 64-byte key derived with Argon2id, incorporating optional BLAKE3 keyfile hash as secret pepper.
/// - Double-layer authenticated encryption: AES-256-GCM inside XChaCha20-Poly1305.
/// - Plaintext serialized buffer, intermediate buffers, and derived keys are securely zeroized from RAM.
pub fn save_note_encrypted(
    note: &Note,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    // 1. Generate unique 32-byte salt using OsRng
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 2. Generate unique 12-byte nonce for AES-256-GCM using OsRng
    let mut aes_nonce_bytes = [0u8; AES_NONCE_LEN];
    OsRng.fill_bytes(&mut aes_nonce_bytes);
    let aes_nonce = AesNonce::from(aes_nonce_bytes);

    // 3. Generate unique 24-byte nonce for XChaCha20 using OsRng
    let mut chacha_nonce_bytes = [0u8; CHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut chacha_nonce_bytes);
    let chacha_nonce = XNonce::from_slice(&chacha_nonce_bytes);

    // 4. Derive 64-byte encryption key with Argon2id (wrapped in Zeroizing)
    let derived_key = derive_key(password, keyfile_bytes, &salt)?;
    let mut aes_key = Zeroizing::new([0u8; 32]);
    let mut chacha_key = Zeroizing::new([0u8; 32]);
    aes_key.copy_from_slice(&derived_key[..32]);
    chacha_key.copy_from_slice(&derived_key[32..]);
    drop(derived_key);

    // 5. Serialize note to JSON in a zeroizable buffer
    let plaintext_json = Zeroizing::new(serde_json::to_vec(note)?);

    // 6. Encrypt plaintext JSON with AES-256-GCM (inner encryption)
    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|_| VaultError::EncryptionFailed)?;
    let inner_ciphertext = Zeroizing::new(
        aes_cipher
            .encrypt(&aes_nonce, plaintext_json.as_slice())
            .map_err(|_| VaultError::EncryptionFailed)?,
    );

    // Immediately zeroize plaintext JSON buffer and AES key
    drop(plaintext_json);
    drop(aes_key);

    // 7. Encrypt resulting AES ciphertext with XChaCha20-Poly1305 (outer encryption)
    let chacha_cipher = XChaCha20Poly1305::new(Key::from_slice(chacha_key.as_ref()));
    let final_ciphertext = chacha_cipher
        .encrypt(chacha_nonce, inner_ciphertext.as_slice())
        .map_err(|_| VaultError::EncryptionFailed)?;

    drop(inner_ciphertext);
    drop(chacha_key);

    // 8. Assemble binary payload:
    // [Version (1B)] + [Salt (32B)] + [AES Nonce (12B)] + [XChaCha Nonce (24B)] + [Final Ciphertext]
    let total_len = CASCADE_HEADER_LEN + final_ciphertext.len();
    let mut binary_data = Vec::with_capacity(total_len);
    binary_data.push(CASCADE_VERSION);
    binary_data.extend_from_slice(&salt);
    binary_data.extend_from_slice(&aes_nonce_bytes);
    binary_data.extend_from_slice(&chacha_nonce_bytes);
    binary_data.extend_from_slice(&final_ciphertext);

    // 9. Ensure parent directory exists and write file to disk
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, &binary_data)?;

    Ok(())
}

/// Reads, decrypts, and deserializes a `Note` from disk.
///
/// Supports:
/// - Version `0x02` Cascade format: outer XChaCha20-Poly1305 + inner AES-256-GCM.
/// - Legacy format: 56-byte header with single-layer XChaCha20-Poly1305 (automatic backward compatibility).
/// - Plaintext buffers and derived keys are securely zeroized from RAM.
pub fn load_note_decrypted(
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    input_path: &Path,
) -> Result<Note, Box<dyn Error>> {
    // 1. Read encrypted file from disk
    let file_data = fs::read(input_path)?;

    if file_data.len() < LEGACY_HEADER_LEN + TAG_LEN {
        return Err(Box::new(VaultError::InvalidFileFormat(format!(
            "File size ({} bytes) is too small to contain valid header (expected at least {} bytes)",
            file_data.len(),
            LEGACY_HEADER_LEN + TAG_LEN
        ))));
    }

    // 2. Check for Cascade Version 0x02 layout
    if file_data[0] == CASCADE_VERSION && file_data.len() >= CASCADE_HEADER_LEN + TAG_LEN + TAG_LEN {
        let salt_end = 1 + SALT_LEN; // 33
        let aes_nonce_end = salt_end + AES_NONCE_LEN; // 45
        let chacha_nonce_end = aes_nonce_end + CHACHA_NONCE_LEN; // 69

        let salt: &[u8; SALT_LEN] = file_data[1..salt_end]
            .try_into()
            .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 32-byte salt".into()))?;
        let aes_nonce_slice: &[u8; AES_NONCE_LEN] = file_data[salt_end..aes_nonce_end]
            .try_into()
            .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 12-byte AES nonce".into()))?;
        let aes_nonce = AesNonce::from(*aes_nonce_slice);
        let chacha_nonce = XNonce::from_slice(&file_data[aes_nonce_end..chacha_nonce_end]);
        let outer_ciphertext = &file_data[chacha_nonce_end..];

        let cascade_res: Result<Note, VaultError> = (|| {
            let derived_key = derive_key(password, keyfile_bytes, salt)?;
            let mut aes_key = Zeroizing::new([0u8; 32]);
            let mut chacha_key = Zeroizing::new([0u8; 32]);
            aes_key.copy_from_slice(&derived_key[..32]);
            chacha_key.copy_from_slice(&derived_key[32..]);
            drop(derived_key);

            // Outer layer: XChaCha20-Poly1305
            let chacha_cipher = XChaCha20Poly1305::new(Key::from_slice(chacha_key.as_ref()));
            let inner_ciphertext = Zeroizing::new(
                chacha_cipher
                    .decrypt(chacha_nonce, outer_ciphertext)
                    .map_err(|_| VaultError::DecryptionFailed)?,
            );
            drop(chacha_key);

            // Inner layer: AES-256-GCM
            let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
                .map_err(|_| VaultError::DecryptionFailed)?;
            let decrypted_buffer = Zeroizing::new(
                aes_cipher
                    .decrypt(&aes_nonce, inner_ciphertext.as_slice())
                    .map_err(|_| VaultError::DecryptionFailed)?,
            );
            drop(inner_ciphertext);
            drop(aes_key);

            let note: Note = serde_json::from_slice(decrypted_buffer.as_slice())
                .map_err(VaultError::Serialization)?;
            drop(decrypted_buffer);

            Ok(note)
        })();

        match cascade_res {
            Ok(note) => return Ok(note),
            Err(e) => {
                // If cascade decryption failed, check if this could be a legacy file whose
                // first random salt byte happened to match 0x02.
                if keyfile_bytes.is_none() && file_data.len() >= LEGACY_HEADER_LEN + TAG_LEN {
                    if let Ok(legacy_note) = decrypt_legacy(&file_data, password) {
                        return Ok(legacy_note);
                    }
                }
                return Err(Box::new(e));
            }
        }
    }

    // 3. Fallback to Legacy layout (XChaCha20-Poly1305 with 32B key)
    let note = decrypt_legacy(&file_data, password)?;
    Ok(note)
}

fn decrypt_legacy(file_data: &[u8], password: &str) -> Result<Note, VaultError> {
    if file_data.len() < LEGACY_HEADER_LEN + TAG_LEN {
        return Err(VaultError::InvalidFileFormat(format!(
            "File size ({} bytes) is too small to contain valid legacy header",
            file_data.len()
        )));
    }

    let salt: &[u8; SALT_LEN] = file_data[..SALT_LEN]
        .try_into()
        .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 32-byte salt".into()))?;

    let nonce = XNonce::from_slice(&file_data[SALT_LEN..LEGACY_HEADER_LEN]);
    let ciphertext = &file_data[LEGACY_HEADER_LEN..];

    let key = derive_key_legacy(password, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let decrypted_buffer = Zeroizing::new(decrypted_bytes);
    let note: Note = serde_json::from_slice(decrypted_buffer.as_slice())
        .map_err(VaultError::Serialization)?;
    drop(decrypted_buffer);

    Ok(note)
}

/// Atomically re-encrypts all `.vault` files found recursively within `vault_dir`.
///
/// 1. Finds all files with `.vault` extension (excluding `.vault.new` and temporary files).
/// 2. Decrypts each file using `current_password` and `current_keyfile` into memory (`Note`),
///    then re-encrypts it using `new_password` and `new_keyfile` in the new Cascade (`0x02`)
///    format to `<filename>.vault.new`. The decrypted in-memory `Note` is zeroized.
/// 3. If any file fails during decryption or write, all created `.vault.new` files are removed
///    and an error is returned. The original `.vault` files remain untouched.
/// 4. Once all files have been safely staged as `.vault.new`, they are atomically renamed to `.vault`.
///
/// Returns the number of notes successfully re-encrypted.
pub fn reencrypt_vault_atomic<F>(
    vault_dir: &Path,
    current_password: &str,
    current_keyfile: Option<&[u8]>,
    new_password: &str,
    new_keyfile: Option<&[u8]>,
    mut progress_callback: F,
) -> Result<usize, Box<dyn Error>>
where
    F: FnMut(usize, usize),
{
    let mut vault_files: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(vault_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("vault") {
            vault_files.push(p.to_path_buf());
        }
    }

    let total = vault_files.len();
    if total == 0 {
        return Ok(0);
    }

    let staging_pairs: Vec<(PathBuf, PathBuf)> = vault_files
        .into_iter()
        .map(|p| {
            let new_path = PathBuf::from(format!("{}.new", p.display()));
            (p, new_path)
        })
        .collect();

    // Clean up any stale staging files
    for (_, new_path) in &staging_pairs {
        if new_path.exists() {
            let _ = fs::remove_file(new_path);
        }
    }

    let mut failure: Option<Box<dyn Error>> = None;

    // Step 1: Decrypt and stage each file to .vault.new
    for (idx, (orig_path, new_path)) in staging_pairs.iter().enumerate() {
        progress_callback(idx + 1, total);

        let mut note = match load_note_decrypted(current_password, current_keyfile, orig_path) {
            Ok(n) => n,
            Err(e) => {
                failure = Some(format!(
                    "Failed to decrypt note {:?}: {}",
                    orig_path.file_name().unwrap_or_default(),
                    e
                ).into());
                break;
            }
        };

        let save_res = save_note_encrypted(&note, new_password, new_keyfile, new_path);
        note.zeroize();

        if let Err(e) = save_res {
            failure = Some(format!(
                "Failed to write re-encrypted note {:?}: {}",
                new_path.file_name().unwrap_or_default(),
                e
            ).into());
            break;
        }
    }

    // If any failure occurred during staging, wipe staging files and return error
    if let Some(err) = failure {
        for (_, new_path) in &staging_pairs {
            if new_path.exists() {
                let _ = fs::remove_file(new_path);
            }
        }
        return Err(err);
    }

    // Step 2: Atomic commit - rename all .vault.new to .vault
    for (orig_path, new_path) in &staging_pairs {
        fs::rename(new_path, orig_path)?;
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_save_and_load_roundtrip_no_keyfile() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("test_note.vault");

        let original_note = Note::new(
            "Secret Master Key Document",
            vec!["cascade".into(), "v2".into()],
            "Sensitive payload: keep this secret and offline!",
        );
        let password = "SuperSecretPassword123!#";

        // Save encrypted note with cascade format
        save_note_encrypted(&original_note, password, None, &file_path)
            .expect("Saving encrypted note should succeed");

        // Verify version flag on disk is 0x02
        let raw_data = fs::read(&file_path).unwrap();
        assert_eq!(raw_data[0], CASCADE_VERSION);

        // Load decrypted note
        let decrypted_note = load_note_decrypted(password, None, &file_path)
            .expect("Loading decrypted note should succeed");

        assert_eq!(original_note, decrypted_note);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_and_load_roundtrip_with_keyfile() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("test_keyfile_note.vault");

        let original_note = Note::new(
            "Two Factor Protected Note",
            vec!["2fa".into(), "keyfile".into()],
            "Protected by both password and physical keyfile!",
        );
        let password = "SuperSecretPassword123!#";
        let keyfile_data = b"my_secure_physical_usb_dongle_entropy_data_bytes_1234567890";

        // Save encrypted note with keyfile
        save_note_encrypted(&original_note, password, Some(keyfile_data), &file_path)
            .expect("Saving encrypted note with keyfile should succeed");

        // Load decrypted note with correct keyfile
        let decrypted_note = load_note_decrypted(password, Some(keyfile_data), &file_path)
            .expect("Loading decrypted note with keyfile should succeed");

        assert_eq!(original_note, decrypted_note);

        // Decryption fails if keyfile is missing
        let no_keyfile_res = load_note_decrypted(password, None, &file_path);
        assert!(no_keyfile_res.is_err());

        // Decryption fails if wrong keyfile is used
        let wrong_keyfile = b"different_keyfile_content";
        let wrong_keyfile_res = load_note_decrypted(password, Some(wrong_keyfile), &file_path);
        assert!(wrong_keyfile_res.is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wrong_password_fails_decryption() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("test_note.vault");

        let original_note = Note::new("Confidential Note", Vec::new(), "Content...");
        let correct_password = "CorrectPassword123!";
        let wrong_password = "WrongPassword456?";

        save_note_encrypted(&original_note, correct_password, None, &file_path).unwrap();

        let result = load_note_decrypted(wrong_password, None, &file_path);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Decryption failed") || err_str.contains("corrupted"),
            "Expected decryption failure error, got: {}",
            err_str
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ciphertext_tampering_detected() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("tampered_note.vault");

        let note = Note::new(
            "Integrity Check",
            Vec::new(),
            "Verify AEAD MAC verification",
        );
        let password = "StrongPassword987*";

        save_note_encrypted(&note, password, None, &file_path).unwrap();

        // Tamper with one byte of the ciphertext on disk
        let mut file_data = fs::read(&file_path).unwrap();
        let last_byte_idx = file_data.len() - 1;
        file_data[last_byte_idx] ^= 0x01; // flip single bit
        fs::write(&file_path, &file_data).unwrap();

        let result = load_note_decrypted(password, None, &file_path);
        assert!(result.is_err(), "Decryption must fail when ciphertext is modified");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_legacy_format_backward_compatibility() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_legacy_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("legacy_note.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        let original_note = Note::new(
            "Legacy Note",
            vec!["legacy".into()],
            "Created before cascade encryption was introduced.",
        );
        let password = "LegacyPassword123!";

        // Manually write a legacy-format file (56-byte header: 32B Salt + 24B Nonce + XChaCha ciphertext)
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        // Ensure first byte is not 0x02 to test direct legacy path
        if salt[0] == CASCADE_VERSION {
            salt[0] = 0x00;
        }

        let mut nonce_bytes = [0u8; CHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let key = derive_key_legacy(password, &salt).unwrap();
        let plaintext_json = serde_json::to_vec(&original_note).unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher.encrypt(nonce, plaintext_json.as_slice()).unwrap();

        let mut legacy_data = Vec::new();
        legacy_data.extend_from_slice(&salt);
        legacy_data.extend_from_slice(&nonce_bytes);
        legacy_data.extend_from_slice(&ciphertext);
        fs::write(&file_path, &legacy_data).unwrap();

        // Load using load_note_decrypted (should automatically recognize legacy layout)
        let decrypted = load_note_decrypted(password, None, &file_path)
            .expect("Legacy note must be successfully decrypted");
        assert_eq!(decrypted, original_note);

        // Next save should automatically upgrade to cascade format
        save_note_encrypted(&decrypted, password, None, &file_path).unwrap();
        let upgraded_data = fs::read(&file_path).unwrap();
        assert_eq!(upgraded_data[0], CASCADE_VERSION);

        let re_loaded = load_note_decrypted(password, None, &file_path).unwrap();
        assert_eq!(re_loaded, original_note);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unique_salts_and_nonces_per_save() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path_1 = temp_dir.join("note1.vault");
        let file_path_2 = temp_dir.join("note2.vault");

        let note = Note::new("Identical Note", Vec::new(), "Identical Content");
        let password = "SamePasswordAcrossSaves";

        save_note_encrypted(&note, password, None, &file_path_1).unwrap();
        save_note_encrypted(&note, password, None, &file_path_2).unwrap();

        let data1 = fs::read(&file_path_1).unwrap();
        let data2 = fs::read(&file_path_2).unwrap();

        // Check Version byte
        assert_eq!(data1[0], CASCADE_VERSION);
        assert_eq!(data2[0], CASCADE_VERSION);

        // Check Salt
        let salt1 = &data1[1..1 + SALT_LEN];
        let salt2 = &data2[1..1 + SALT_LEN];
        assert_ne!(salt1, salt2, "Salts must be uniquely generated per file");

        // Check AES Nonce
        let aes_n1 = &data1[1 + SALT_LEN..1 + SALT_LEN + AES_NONCE_LEN];
        let aes_n2 = &data2[1 + SALT_LEN..1 + SALT_LEN + AES_NONCE_LEN];
        assert_ne!(aes_n1, aes_n2, "AES Nonces must be uniquely generated per file");

        // Check XChaCha Nonce
        let chacha_n1 = &data1[1 + SALT_LEN + AES_NONCE_LEN..CASCADE_HEADER_LEN];
        let chacha_n2 = &data2[1 + SALT_LEN + AES_NONCE_LEN..CASCADE_HEADER_LEN];
        assert_ne!(chacha_n1, chacha_n2, "XChaCha Nonces must be uniquely generated per file");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_reencrypt_vault_atomic_keyfile_management() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_reenc_{}", Uuid::new_v4()));
        let folder = temp_dir.join("Work");
        fs::create_dir_all(&folder).unwrap();

        let note = Note::new("Re-encryption Note", vec!["reenc".into()], "Top Secret Content");
        let path = folder.join("note.vault");

        let password = "MasterPassword123!";
        let keyfile_old = b"initial_usb_keyfile_entropy_content";
        let keyfile_new = b"updated_usb_keyfile_entropy_content";

        // 1. Initial save with keyfile_old
        save_note_encrypted(&note, password, Some(keyfile_old), &path).unwrap();

        // 2. Re-encrypt with new keyfile
        let count = reencrypt_vault_atomic(
            &temp_dir,
            password,
            Some(keyfile_old),
            password,
            Some(keyfile_new),
            |_, _| {},
        ).expect("Re-encryption with new keyfile should succeed");

        assert_eq!(count, 1);
        assert!(!folder.join("note.vault.new").exists());

        // Old keyfile should fail
        assert!(load_note_decrypted(password, Some(keyfile_old), &path).is_err());

        // New keyfile must succeed
        let loaded = load_note_decrypted(password, Some(keyfile_new), &path).unwrap();
        assert_eq!(loaded.title, "Re-encryption Note");
        assert_eq!(loaded.content, "Top Secret Content");

        // 3. Remove keyfile via atomic re-encryption
        let count_remove = reencrypt_vault_atomic(
            &temp_dir,
            password,
            Some(keyfile_new),
            password,
            None,
            |_, _| {},
        ).expect("Re-encryption removing keyfile should succeed");

        assert_eq!(count_remove, 1);

        // Keyfile is no longer required
        let loaded_no_kf = load_note_decrypted(password, None, &path).unwrap();
        assert_eq!(loaded_no_kf.title, "Re-encryption Note");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_empty_note_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_empty_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("empty.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        let note = Note::new("", Vec::new(), "");
        let password = "TestPasswordEmpty123!";

        save_note_encrypted(&note, password, None, &file_path).expect("Saving empty note should succeed");
        let loaded = load_note_decrypted(password, None, &file_path).expect("Loading empty note should succeed");

        assert_eq!(loaded.title, "");
        assert_eq!(loaded.content, "");
        assert!(loaded.tags.is_empty());
        assert_eq!(loaded.id, note.id);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_multilingual_unicode_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_unicode_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("unicode.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        let title = "🦀 Rust & 🔒 Crypto: 日本語テスト & العربية & Übergrößenträger";
        let tags = vec![
            "🏷️_tag1".to_string(),
            "кириллица".to_string(),
            "emoji_🎉".to_string(),
        ];
        let content = "Mathematics: ∑_{i=1}^n x_i = ∫_0^∞ f(t) dt\nSymbols: ⚡ 🚀 💻 🛡️\nMultibyte: 𠜎 𠜱 𠝹 𠱓";

        let note = Note::new(title, tags.clone(), content);
        let password = "UnicodePassword🔑_Über123!";

        save_note_encrypted(&note, password, None, &file_path).expect("Saving unicode note should succeed");
        let loaded = load_note_decrypted(password, None, &file_path).expect("Loading unicode note should succeed");

        assert_eq!(loaded.title, title);
        assert_eq!(loaded.tags, tags);
        assert_eq!(loaded.content, content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_large_payload_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_large_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("large.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        // 200 KB repetitive payload with newlines and structure
        let mut large_content = String::with_capacity(200 * 1024);
        for i in 0..5000 {
            large_content.push_str(&format!("Line {}: NoteVault cryptographic cascade payload stress test block.\n", i));
        }

        let note = Note::new("Large Payload Note", vec!["stress".into(), "large".into()], &large_content);
        let password = "LargePayloadPassword999#";

        save_note_encrypted(&note, password, None, &file_path).expect("Saving large note should succeed");
        let loaded = load_note_decrypted(password, None, &file_path).expect("Loading large note should succeed");

        assert_eq!(loaded.content.len(), large_content.len());
        assert_eq!(loaded.content, large_content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_corrupt_or_truncated_file_handling() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_trunc_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let password = "AnyPassword123!";

        // 1. Completely empty file (0 bytes)
        let empty_path = temp_dir.join("empty.vault");
        fs::write(&empty_path, b"").unwrap();
        let empty_res = load_note_decrypted(password, None, &empty_path);
        assert!(empty_res.is_err(), "Empty file must return error");

        // 2. Short header (10 bytes)
        let short_path = temp_dir.join("short.vault");
        fs::write(&short_path, &[CASCADE_VERSION; 10]).unwrap();
        let short_res = load_note_decrypted(password, None, &short_path);
        assert!(short_res.is_err(), "File shorter than cascade header must return error");

        // 3. Partial header (50 bytes - less than 69 bytes CASCADE_HEADER_LEN)
        let partial_path = temp_dir.join("partial.vault");
        let mut partial_data = vec![0u8; 50];
        partial_data[0] = CASCADE_VERSION;
        fs::write(&partial_path, &partial_data).unwrap();
        let partial_res = load_note_decrypted(password, None, &partial_path);
        assert!(partial_res.is_err(), "File shorter than 69 bytes must return error");

        // 4. Invalid version byte
        let invalid_ver_path = temp_dir.join("invalid_ver.vault");
        let inv_data = vec![0x99u8; 100];
        fs::write(&invalid_ver_path, &inv_data).unwrap();
        let inv_res = load_note_decrypted(password, None, &invalid_ver_path);
        assert!(inv_res.is_err(), "File with unknown version byte must fail gracefully");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_inner_aes_tampering_detected() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_tamper_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("tamper_inner.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        let note = Note::new("Tamper Inner Test", Vec::new(), "Super Secret Payload");
        let password = "CascadeTamperPassword!";

        save_note_encrypted(&note, password, None, &file_path).unwrap();

        let mut data = fs::read(&file_path).unwrap();
        // The data layout is: [1B Version] [32B Salt] [12B AES Nonce] [24B ChaCha Nonce] [Outer XChaCha Ciphertext...]
        // Tampering with byte in the middle of outer ciphertext
        let mid_idx = CASCADE_HEADER_LEN + (data.len() - CASCADE_HEADER_LEN) / 2;
        data[mid_idx] ^= 0xFF;
        fs::write(&file_path, &data).unwrap();

        let result = load_note_decrypted(password, None, &file_path);
        assert!(result.is_err(), "Tampered ciphertext must be detected by AEAD MAC verification");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_reencryption_rollback_on_corrupt_file() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_atomic_fail_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let password = "OriginalPassword123!";
        let new_password = "NewPassword456!";

        // Create 2 valid notes
        let note1 = Note::new("Note 1", Vec::new(), "Content 1");
        let note2 = Note::new("Note 2", Vec::new(), "Content 2");
        let path1 = temp_dir.join("note1.vault");
        let path2 = temp_dir.join("note2.vault");
        save_note_encrypted(&note1, password, None, &path1).unwrap();
        save_note_encrypted(&note2, password, None, &path2).unwrap();

        // Create 1 corrupted note file
        let corrupt_path = temp_dir.join("corrupt.vault");
        fs::write(&corrupt_path, b"corrupted garbage bytes").unwrap();

        // Attempt atomic re-encryption
        let result = reencrypt_vault_atomic(
            &temp_dir,
            password,
            None,
            new_password,
            None,
            |_, _| {},
        );

        // Must return Err because corrupt note cannot be decrypted
        assert!(result.is_err(), "Atomic re-encryption must abort if a file cannot be decrypted");

        // Verify staging files (.vault.new) are cleaned up
        assert!(!temp_dir.join("note1.vault.new").exists());
        assert!(!temp_dir.join("note2.vault.new").exists());
        assert!(!temp_dir.join("corrupt.vault.new").exists());

        // Verify original notes are intact and still decryptable with the original password
        let loaded1 = load_note_decrypted(password, None, &path1).expect("Original note 1 must still be intact");
        assert_eq!(loaded1.title, "Note 1");
        let loaded2 = load_note_decrypted(password, None, &path2).expect("Original note 2 must still be intact");
        assert_eq!(loaded2.title, "Note 2");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_note_zeroize_memory_hygiene() {
        let mut note = Note::new("Secret Document", vec!["financial".into()], "Account balance: $1,000,000");
        let original_id = note.id;
        assert_ne!(original_id, Uuid::nil());
        assert!(!note.title.is_empty());
        assert!(!note.content.is_empty());
        assert!(!note.tags.is_empty());

        note.zeroize();

        assert_eq!(note.id, Uuid::nil());
        assert!(note.title.is_empty());
        assert!(note.content.is_empty());
        assert!(note.tags.is_empty());
        assert_eq!(note.created_at, 0);
        assert_eq!(note.updated_at, 0);
    }
}


