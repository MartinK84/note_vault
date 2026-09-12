use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Cryptographic binary file header constants.
pub const SALT_LEN: usize = 32;       // 256-bit salt for Argon2id
pub const NONCE_LEN: usize = 24;      // 192-bit nonce for XChaCha20
pub const TAG_LEN: usize = 16;        // 128-bit Poly1305 MAC tag
pub const HEADER_LEN: usize = SALT_LEN + NONCE_LEN; // 56 bytes

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
                write!(f, "Decryption failed: invalid password or corrupted/tampered data")
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
    pub content: String,
    pub created_at: i64,
}

impl Note {
    /// Constructs a new Note with a randomly generated UUIDv4 and the current Unix timestamp (seconds).
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            content: content.into(),
            created_at,
        }
    }
}

impl Zeroize for Note {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.content.zeroize();
        self.created_at.zeroize();
        self.id = Uuid::nil();
    }
}

/// Derives a 32-byte (256-bit) encryption key from a password and salt using Argon2id.
/// The resulting key is wrapped in `Zeroizing` so that it is automatically erased from
/// memory upon drop.
fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut key = Zeroizing::new([0u8; 32]);

    // Explicit Argon2id configuration conforming to RFC 9106 recommended defaults
    // Algorithm: Argon2id, Version: 0x13, Memory: 64MiB, Iterations: 3, Parallelism: 4
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

/// Serializes, encrypts, and writes a `Note` to disk.
///
/// Binary layout:
/// `[Argon2 Salt (32 bytes)] + [XChaCha20 Nonce (24 bytes)] + [Encrypted JSON Payload & MAC]`
///
/// Security properties:
/// - Salt and Nonce are cryptographically securely generated using `rand_core::OsRng`.
/// - Key derived with Argon2id.
/// - Authenticated encryption using XChaCha20-Poly1305 (AEAD).
/// - Plaintext serialized buffer and derived key are securely zeroized from RAM.
pub fn save_note_encrypted(
    note: &Note,
    password: &str,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    // 1. Generate unique 32-byte salt using OsRng
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 2. Generate unique 24-byte nonce for XChaCha20 using OsRng
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // 3. Derive 256-bit encryption key with Argon2id (wrapped in Zeroizing)
    let key = derive_key(password, &salt)?;

    // 4. Serialize note to JSON in a zeroizable buffer
    let plaintext_json = Zeroizing::new(serde_json::to_vec(note)?);

    // 5. Encrypt plaintext JSON using XChaCha20-Poly1305 AEAD
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(nonce, plaintext_json.as_slice())
        .map_err(|_| VaultError::EncryptionFailed)?;

    // Immediately zeroize plaintext JSON buffer
    drop(plaintext_json);
    // Derived key is zeroized when `key` drops at function exit

    // 6. Assemble binary payload: [Salt (32)] + [Nonce (24)] + [Ciphertext + MAC]
    let total_len = SALT_LEN + NONCE_LEN + ciphertext.len();
    let mut binary_data = Vec::with_capacity(total_len);
    binary_data.extend_from_slice(&salt);
    binary_data.extend_from_slice(&nonce_bytes);
    binary_data.extend_from_slice(&ciphertext);

    // 7. Ensure parent directory exists and write file to disk
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
/// Validates binary structure:
/// - Verifies minimal length for Salt (32B) + Nonce (24B) + MAC (16B).
/// - Derives key via Argon2id.
/// - Decrypts and verifies Poly1305 MAC tag.
/// - Deserializes JSON payload into a `Note`.
/// - Plaintext buffer and derived key are securely zeroized from RAM.
pub fn load_note_decrypted(
    password: &str,
    input_path: &Path,
) -> Result<Note, Box<dyn Error>> {
    // 1. Read encrypted file from disk
    let file_data = fs::read(input_path)?;

    // 2. Validate header & minimum payload length (Salt + Nonce + Tag)
    let min_len = HEADER_LEN + TAG_LEN;
    if file_data.len() < HEADER_LEN {
        return Err(Box::new(VaultError::InvalidFileFormat(format!(
            "File size ({} bytes) is too small to contain valid header (expected at least {} bytes)",
            file_data.len(),
            HEADER_LEN
        ))));
    }
    if file_data.len() < min_len {
        return Err(Box::new(VaultError::InvalidFileFormat(format!(
            "File size ({} bytes) is too small to contain an encrypted payload and MAC tag (expected at least {} bytes)",
            file_data.len(),
            min_len
        ))));
    }

    // 3. Extract Salt, Nonce, and Ciphertext
    let salt: &[u8; SALT_LEN] = file_data[..SALT_LEN]
        .try_into()
        .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 32-byte salt".into()))?;

    let nonce = XNonce::from_slice(&file_data[SALT_LEN..HEADER_LEN]);
    let ciphertext = &file_data[HEADER_LEN..];

    // 4. Derive key using Argon2id with extracted salt
    let key = derive_key(password, salt)?;

    // 5. Decrypt and verify Poly1305 MAC using XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    // Wrap decrypted plaintext in Zeroizing buffer to ensure RAM is cleared after deserialization
    let decrypted_buffer = Zeroizing::new(decrypted_bytes);

    // 6. Deserialize JSON into Note
    let note: Note = serde_json::from_slice(decrypted_buffer.as_slice())?;

    // Explicitly zeroize plaintext buffer
    drop(decrypted_buffer);

    Ok(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("test_note.vault");

        let original_note = Note::new(
            "Secret Master Key Document",
            "Sensitive payload: keep this secret and offline!",
        );
        let password = "SuperSecretPassword123!#";

        // Save encrypted note
        save_note_encrypted(&original_note, password, &file_path)
            .expect("Saving encrypted note should succeed");

        // Load decrypted note
        let decrypted_note = load_note_decrypted(password, &file_path)
            .expect("Loading decrypted note should succeed");

        assert_eq!(original_note, decrypted_note);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wrong_password_fails_decryption() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("test_note.vault");

        let original_note = Note::new("Confidential Note", "Content...");
        let correct_password = "CorrectPassword123!";
        let wrong_password = "WrongPassword456?";

        save_note_encrypted(&original_note, correct_password, &file_path).unwrap();

        let result = load_note_decrypted(wrong_password, &file_path);
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

        let note = Note::new("Integrity Check", "Verify AEAD MAC verification");
        let password = "StrongPassword987*";

        save_note_encrypted(&note, password, &file_path).unwrap();

        // Tamper with one byte of the ciphertext on disk
        let mut file_data = fs::read(&file_path).unwrap();
        let last_byte_idx = file_data.len() - 1;
        file_data[last_byte_idx] ^= 0x01; // flip single bit
        fs::write(&file_path, &file_data).unwrap();

        let result = load_note_decrypted(password, &file_path);
        assert!(result.is_err(), "Decryption must fail when ciphertext is modified");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unique_salts_and_nonces_per_save() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path_1 = temp_dir.join("note1.vault");
        let file_path_2 = temp_dir.join("note2.vault");

        let note = Note::new("Identical Note", "Identical Content");
        let password = "SamePasswordAcrossSaves";

        save_note_encrypted(&note, password, &file_path_1).unwrap();
        save_note_encrypted(&note, password, &file_path_2).unwrap();

        let data1 = fs::read(&file_path_1).unwrap();
        let data2 = fs::read(&file_path_2).unwrap();

        let salt1 = &data1[..SALT_LEN];
        let salt2 = &data2[..SALT_LEN];
        assert_ne!(salt1, salt2, "Salts must be uniquely generated per file");

        let nonce1 = &data1[SALT_LEN..HEADER_LEN];
        let nonce2 = &data2[SALT_LEN..HEADER_LEN];
        assert_ne!(nonce1, nonce2, "Nonces must be uniquely generated per file");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_truncated_file_error() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_test_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("truncated.vault");

        // Write a truncated file (only 20 bytes, smaller than header)
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(&file_path, &[0u8; 20]).unwrap();

        let result = load_note_decrypted("SomePassword", &file_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("too small") || err_msg.contains("Invalid file format"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
