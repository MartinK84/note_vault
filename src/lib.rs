use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use rayon::prelude::*;
use walkdir::WalkDir;

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead as ChachaAead, KeyInit as ChachaKeyInit, Payload as ChachaPayload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod attachment;
pub mod config;
pub mod export;
pub mod markdown;
pub mod single_instance;
pub mod startup;
pub mod validation;

slint::include_modules!();

pub use attachment::*;
pub use export::*;
pub use markdown::*;
pub use single_instance::*;
pub use startup::*;
pub use validation::*;

/// Cryptographic binary file header constants.
pub const CASCADE_V2_VERSION: u8 = 0x02; // Version 2: AES-256-GCM + XChaCha20-Poly1305 cascade
pub const CASCADE_V3_VERSION: u8 = 0x03; // Version 3: v2 cascade + explicit Argon2id params + header AAD
pub const KDF_PARAMS_LEN: usize = 12;    // m_cost (4B BE) + t_cost (4B BE) + p_cost (4B BE)
pub const SALT_LEN: usize = 32;          // 256-bit salt for Argon2id
pub const AES_NONCE_LEN: usize = 12;     // 96-bit nonce for AES-256-GCM
pub const CHACHA_NONCE_LEN: usize = 24;  // 192-bit nonce for XChaCha20
pub const TAG_LEN: usize = 16;           // 128-bit MAC tag (Poly1305 / GHASH)
pub const CASCADE_V2_HEADER_LEN: usize = 1 + SALT_LEN + AES_NONCE_LEN + CHACHA_NONCE_LEN; // 69 bytes
pub const CASCADE_V3_HEADER_LEN: usize = 1 + KDF_PARAMS_LEN + SALT_LEN + AES_NONCE_LEN + CHACHA_NONCE_LEN; // 81 bytes
pub const CASCADE_VERSION: u8 = CASCADE_V3_VERSION;
pub const CASCADE_HEADER_LEN: usize = CASCADE_V3_HEADER_LEN;
pub const LEGACY_HEADER_LEN: usize = SALT_LEN + CHACHA_NONCE_LEN; // 56 bytes

pub const DEFAULT_ARGON2_M_COST: u32 = Params::DEFAULT_M_COST;
pub const DEFAULT_ARGON2_T_COST: u32 = Params::DEFAULT_T_COST;
pub const DEFAULT_ARGON2_P_COST: u32 = Params::DEFAULT_P_COST;

// Aliases for backward compatibility
pub const NONCE_LEN: usize = CHACHA_NONCE_LEN;
pub const HEADER_LEN: usize = LEGACY_HEADER_LEN;

/// Writes `data` atomically to `path` via a hidden sibling temporary file, fsync, and rename.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault_file");
    let tmp_name = format!(".{}.{}.tmp", file_name, Uuid::new_v4());
    let tmp_path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    };

    let write_result = (|| -> Result<(), std::io::Error> {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    Ok(())
}

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

/// Note type classification: standard markdown text or tiny-skia drawing canvas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoteType {
    #[default]
    Text,
    Canvas,
}

impl NoteType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NoteType::Text => "text",
            NoteType::Canvas => "canvas",
        }
    }
}

impl fmt::Display for NoteType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for NoteType {
    fn from(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "canvas" => NoteType::Canvas,
            _ => NoteType::Text,
        }
    }
}

impl Serialize for NoteType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NoteType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NoteTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for NoteTypeVisitor {
            type Value = NoteType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a note type ('text' or 'canvas')")
            }

            fn visit_str<E>(self, value: &str) -> Result<NoteType, E>
            where
                E: serde::de::Error,
            {
                Ok(NoteType::from(value))
            }
        }

        deserializer.deserialize_str(NoteTypeVisitor)
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
    #[serde(default)]
    pub note_type: NoteType,
}

impl Note {
    /// Constructs a new Note with a randomly generated UUIDv4 and the current Unix timestamp (seconds).
    pub fn new(
        title: impl Into<String>,
        tags: Vec<String>,
        content: impl Into<String>,
    ) -> Self {
        Self::new_with_type(title, tags, content, NoteType::Text)
    }

    /// Constructs a new Note with a specified NoteType.
    pub fn new_with_type(
        title: impl Into<String>,
        tags: Vec<String>,
        content: impl Into<String>,
        note_type: NoteType,
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
            note_type,
        }
    }

    /// Constructs a new Canvas note.
    pub fn new_canvas(
        title: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        Self::new_with_type(title, tags, "", NoteType::Canvas)
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
        self.note_type = NoteType::Text;
    }
}

impl Drop for Note {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Note {}

/// Derives a 64-byte (512-bit) encryption key from a password, optional keyfile bytes, salt,
/// and explicit Argon2id parameters.
pub fn derive_key_with_params(
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    salt: &[u8; SALT_LEN],
    params: Params,
) -> Result<Zeroizing<[u8; 64]>, VaultError> {
    let mut key = Zeroizing::new([0u8; 64]);

    if let Some(kf) = keyfile_bytes {
        let hash = blake3::hash(kf);
        let pepper = Zeroizing::new(*hash.as_bytes());
        let argon2 = Argon2::new_with_secret(
            pepper.as_ref(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    } else {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );

        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    }

    Ok(key)
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
    derive_key_with_params(password, keyfile_bytes, salt, Params::default())
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

/// Encrypts an arbitrary plaintext byte slice using the cryptographic cascade
/// (AES-256-GCM + XChaCha20-Poly1305) with version 0x03, explicit Argon2id parameters,
/// and authenticated header bytes (AAD).
///
/// Binary layout (81-byte header):
/// `[Version (1B, 0x03)] + [m_cost (4B BE)] + [t_cost (4B BE)] + [p_cost (4B BE)] + [Argon2 Salt (32B)] + [AES Nonce (12B)] + [XChaCha Nonce (24B)] + [Final Ciphertext]`
pub fn encrypt_bytes(
    plaintext: &[u8],
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
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

    // 4. Assemble authenticated 81-byte v3 header
    let m_cost = DEFAULT_ARGON2_M_COST;
    let t_cost = DEFAULT_ARGON2_T_COST;
    let p_cost = DEFAULT_ARGON2_P_COST;
    let params = Params::new(m_cost, t_cost, p_cost, Some(64))
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let mut header = [0u8; CASCADE_V3_HEADER_LEN];
    header[0] = CASCADE_V3_VERSION;
    header[1..5].copy_from_slice(&m_cost.to_be_bytes());
    header[5..9].copy_from_slice(&t_cost.to_be_bytes());
    header[9..13].copy_from_slice(&p_cost.to_be_bytes());
    header[13..13 + SALT_LEN].copy_from_slice(&salt);
    header[13 + SALT_LEN..13 + SALT_LEN + AES_NONCE_LEN].copy_from_slice(&aes_nonce_bytes);
    header[13 + SALT_LEN + AES_NONCE_LEN..CASCADE_V3_HEADER_LEN]
        .copy_from_slice(&chacha_nonce_bytes);

    // 5. Derive 64-byte encryption key with Argon2id (wrapped in Zeroizing)
    let derived_key = derive_key_with_params(password, keyfile_bytes, &salt, params)?;
    let mut aes_key = Zeroizing::new([0u8; 32]);
    let mut chacha_key = Zeroizing::new([0u8; 32]);
    aes_key.copy_from_slice(&derived_key[..32]);
    chacha_key.copy_from_slice(&derived_key[32..]);
    drop(derived_key);

    // 6. Encrypt plaintext with AES-256-GCM (inner encryption, header bound as AAD)
    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|_| VaultError::EncryptionFailed)?;
    let inner_ciphertext = Zeroizing::new(
        aes_cipher
            .encrypt(
                &aes_nonce,
                AesPayload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| VaultError::EncryptionFailed)?,
    );

    // Immediately zeroize AES key
    drop(aes_key);

    // 7. Encrypt resulting AES ciphertext with XChaCha20-Poly1305 (outer encryption, header bound as AAD)
    let chacha_cipher = XChaCha20Poly1305::new(Key::from_slice(chacha_key.as_ref()));
    let final_ciphertext = chacha_cipher
        .encrypt(
            chacha_nonce,
            ChachaPayload {
                msg: inner_ciphertext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| VaultError::EncryptionFailed)?;

    drop(inner_ciphertext);
    drop(chacha_key);

    // 8. Concatenate header + final ciphertext
    let mut binary_data = Vec::with_capacity(CASCADE_V3_HEADER_LEN + final_ciphertext.len());
    binary_data.extend_from_slice(&header);
    binary_data.extend_from_slice(&final_ciphertext);

    Ok(binary_data)
}

/// Serializes, encrypts, and atomically writes a `Note` to disk using the cryptographic cascade
/// (AES-256-GCM + XChaCha20-Poly1305).
pub fn save_note_encrypted(
    note: &Note,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let plaintext_json = Zeroizing::new(serde_json::to_vec(note)?);
    let binary_data = encrypt_bytes(plaintext_json.as_slice(), password, keyfile_bytes)?;
    drop(plaintext_json);

    atomic_write(output_path, &binary_data)?;

    Ok(())
}

/// Decrypts raw file bytes using Cascade Version 0x03, Cascade Version 0x02, or Legacy format.
/// Returns the decrypted plaintext wrapped in a `Zeroizing` buffer.
pub fn decrypt_bytes(
    file_data: &[u8],
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if file_data.len() < LEGACY_HEADER_LEN + TAG_LEN {
        return Err(VaultError::InvalidFileFormat(format!(
            "File size ({} bytes) is too small to contain valid header (expected at least {} bytes)",
            file_data.len(),
            LEGACY_HEADER_LEN + TAG_LEN
        )));
    }

    // 1. Check for Cascade Version 0x03 layout (81-byte authenticated header + explicit Argon2id params)
    if file_data[0] == CASCADE_V3_VERSION
        && file_data.len() >= CASCADE_V3_HEADER_LEN + TAG_LEN + TAG_LEN
    {
        let header = &file_data[..CASCADE_V3_HEADER_LEN];
        let outer_ciphertext = &file_data[CASCADE_V3_HEADER_LEN..];

        let m_cost = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let t_cost = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        let p_cost = u32::from_be_bytes([header[9], header[10], header[11], header[12]]);

        let cascade_v3_res: Result<Zeroizing<Vec<u8>>, VaultError> = (|| {
            // Bound Argon2id parameters to prevent memory/CPU DoS from untrusted or random bytes
            if m_cost == 0 || m_cost > 1_048_576 || t_cost == 0 || t_cost > 100 || p_cost == 0 || p_cost > 64 {
                return Err(VaultError::InvalidFileFormat(
                    "Invalid Argon2id parameters in v3 header".into(),
                ));
            }
            let params = Params::new(m_cost, t_cost, p_cost, Some(64))
                .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

            let salt_start = 1 + KDF_PARAMS_LEN;
            let aes_nonce_start = salt_start + SALT_LEN;
            let chacha_nonce_start = aes_nonce_start + AES_NONCE_LEN;

            let salt: &[u8; SALT_LEN] = header[salt_start..aes_nonce_start]
                .try_into()
                .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 32-byte salt".into()))?;
            let aes_nonce_slice: &[u8; AES_NONCE_LEN] = header[aes_nonce_start..chacha_nonce_start]
                .try_into()
                .map_err(|_| VaultError::InvalidFileFormat("Failed to parse 12-byte AES nonce".into()))?;
            let aes_nonce = AesNonce::from(*aes_nonce_slice);
            let chacha_nonce = XNonce::from_slice(&header[chacha_nonce_start..CASCADE_V3_HEADER_LEN]);

            let derived_key = derive_key_with_params(password, keyfile_bytes, salt, params)?;
            let mut aes_key = Zeroizing::new([0u8; 32]);
            let mut chacha_key = Zeroizing::new([0u8; 32]);
            aes_key.copy_from_slice(&derived_key[..32]);
            chacha_key.copy_from_slice(&derived_key[32..]);
            drop(derived_key);

            // Outer layer: XChaCha20-Poly1305 with header AAD
            let chacha_cipher = XChaCha20Poly1305::new(Key::from_slice(chacha_key.as_ref()));
            let inner_ciphertext = Zeroizing::new(
                chacha_cipher
                    .decrypt(
                        chacha_nonce,
                        ChachaPayload {
                            msg: outer_ciphertext,
                            aad: header,
                        },
                    )
                    .map_err(|_| VaultError::DecryptionFailed)?,
            );
            drop(chacha_key);

            // Inner layer: AES-256-GCM with header AAD
            let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
                .map_err(|_| VaultError::DecryptionFailed)?;
            let decrypted_buffer = Zeroizing::new(
                aes_cipher
                    .decrypt(
                        &aes_nonce,
                        AesPayload {
                            msg: inner_ciphertext.as_slice(),
                            aad: header,
                        },
                    )
                    .map_err(|_| VaultError::DecryptionFailed)?,
            );
            drop(inner_ciphertext);
            drop(aes_key);

            Ok(decrypted_buffer)
        })();

        match cascade_v3_res {
            Ok(buf) => return Ok(buf),
            Err(e) => {
                // Fallback if a legacy v1 file's first random salt byte happened to equal 0x03
                if keyfile_bytes.is_none() && file_data.len() >= LEGACY_HEADER_LEN + TAG_LEN {
                    if let Ok(legacy_buf) = decrypt_legacy_bytes(file_data, password) {
                        return Ok(legacy_buf);
                    }
                }
                return Err(e);
            }
        }
    }

    // 2. Check for Cascade Version 0x02 layout (69-byte header, no AAD)
    if file_data[0] == CASCADE_V2_VERSION
        && file_data.len() >= CASCADE_V2_HEADER_LEN + TAG_LEN + TAG_LEN
    {
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

        let cascade_res: Result<Zeroizing<Vec<u8>>, VaultError> = (|| {
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

            Ok(decrypted_buffer)
        })();

        match cascade_res {
            Ok(buf) => return Ok(buf),
            Err(e) => {
                // If cascade decryption failed, check if this could be a legacy file whose
                // first random salt byte happened to match 0x02.
                if keyfile_bytes.is_none() && file_data.len() >= LEGACY_HEADER_LEN + TAG_LEN {
                    if let Ok(legacy_buf) = decrypt_legacy_bytes(file_data, password) {
                        return Ok(legacy_buf);
                    }
                }
                return Err(e);
            }
        }
    }

    // 3. Fallback to Legacy layout (XChaCha20-Poly1305 with 32B key)
    decrypt_legacy_bytes(file_data, password)
}

fn decrypt_legacy_bytes(file_data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
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

    Ok(Zeroizing::new(decrypted_bytes))
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
    let file_data = fs::read(input_path)?;
    let decrypted_buffer = decrypt_bytes(&file_data, password, keyfile_bytes)?;
    let note: Note = serde_json::from_slice(decrypted_buffer.as_slice())
        .map_err(VaultError::Serialization)?;
    drop(decrypted_buffer);
    Ok(note)
}

/// Converts HSL (h in 0..360, s in 0..100, l in 0..100) to RGB bytes.
pub fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
    let s = (s / 100.0).clamp(0.0, 1.0);
    let l = (l / 100.0).clamp(0.0, 1.0);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let h_prime = (h % 360.0 + 360.0) % 360.0 / 60.0;
    let x = c * (1.0 - (h_prime % 2.0 - 1.0).abs());
    let (r1, g1, b1) = if h_prime < 1.0 {
        (c, x, 0.0)
    } else if h_prime < 2.0 {
        (x, c, 0.0)
    } else if h_prime < 3.0 {
        (0.0, c, x)
    } else if h_prime < 4.0 {
        (0.0, x, c)
    } else if h_prime < 5.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };
    let m = l - c / 2.0;
    let r = ((r1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    let g = ((g1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    let b = ((b1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    (r, g, b)
}

/// Converts RGB bytes to HSL (h in 0..360, s in 0..100, l in 0..100).
pub fn rgb_to_hsl(r: u8, g: u8, b: u8) -> (f32, f32, f32) {
    let r = r as f32 / 255.0;
    let g = g as f32 / 255.0;
    let b = b as f32 / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    let l = (max + min) / 2.0;

    if delta.abs() < 1e-5 {
        return (0.0, 0.0, (l * 100.0).round());
    }

    let s = if l > 0.5 {
        delta / (2.0 - max - min)
    } else {
        delta / (max + min)
    };

    let mut h = if (max - r).abs() < 1e-5 {
        (g - b) / delta + (if g < b { 6.0 } else { 0.0 })
    } else if (max - g).abs() < 1e-5 {
        (b - r) / delta + 2.0
    } else {
        (r - g) / delta + 4.0
    };
    h *= 60.0;

    (h.round(), (s * 100.0).round(), (l * 100.0).round())
}

/// Clamps zoom percentage to the allowed range [25, 400].
pub fn clamp_zoom_percent(percent: i32) -> i32 {
    percent.clamp(25, 400)
}

/// Parses a zoom percentage input string (e.g. "150%", "150", " 25% ").
pub fn parse_zoom_input(text: &str) -> Option<i32> {
    let cleaned = text.trim().trim_end_matches('%').trim();
    cleaned.parse::<i32>().ok().map(clamp_zoom_percent)
}

/// Default canvas dimensions, extend step, and default white background color.
pub const DEFAULT_CANVAS_WIDTH: u32 = 800;
pub const DEFAULT_CANVAS_HEIGHT: u32 = 400;
pub const CANVAS_EXTEND_STEP: u32 = 200;
pub const MAX_CANVAS_DIMENSION: u32 = 8000;
pub const DEFAULT_CANVAS_BG_HEX: &str = "#ffffff";

/// Extends a canvas `Pixmap` by `amount` pixels in the given direction ("top", "bottom", "left", or "right"),
/// preserving existing artwork at the appropriate offset. Returns `None` for invalid directions or
/// if the resulting dimensions exceed `MAX_CANVAS_DIMENSION`.
pub fn extend_canvas_pixmap(
    src: &tiny_skia::Pixmap,
    direction: &str,
    amount: u32,
) -> Option<tiny_skia::Pixmap> {
    if amount == 0 {
        return None;
    }
    let old_w = src.width();
    let old_h = src.height();
    let (new_w, new_h, offset_x, offset_y) = match direction {
        "top" => (old_w, old_h.checked_add(amount)?, 0i32, amount as i32),
        "bottom" => (old_w, old_h.checked_add(amount)?, 0i32, 0i32),
        "left" => (old_w.checked_add(amount)?, old_h, amount as i32, 0i32),
        "right" => (old_w.checked_add(amount)?, old_h, 0i32, 0i32),
        _ => return None,
    };

    if new_w > MAX_CANVAS_DIMENSION || new_h > MAX_CANVAS_DIMENSION {
        return None;
    }

    let mut dst = tiny_skia::Pixmap::new(new_w, new_h)?;
    let paint = tiny_skia::PixmapPaint {
        blend_mode: tiny_skia::BlendMode::Source,
        ..tiny_skia::PixmapPaint::default()
    };
    dst.draw_pixmap(
        offset_x,
        offset_y,
        src.as_ref(),
        &paint,
        tiny_skia::Transform::identity(),
        None,
    );
    Some(dst)
}

/// Converts on-screen mouse coordinates to pixmap coordinates given a zoom factor.
pub fn scale_coordinate_to_canvas(coord: f32, zoom: f32) -> f32 {
    if zoom <= 0.0 {
        coord
    } else {
        coord / zoom
    }
}

/// Computes the zoom percentage (clamped to [25, 100]) needed to fit the entire canvas
/// inside the given viewport dimensions with comfortable padding.
pub fn fit_canvas_zoom_percent(
    viewport_w: f32,
    viewport_h: f32,
    canvas_w: f32,
    canvas_h: f32,
) -> i32 {
    let pad = 48.0;
    let avail_w = (viewport_w - pad).max(100.0);
    let avail_h = (viewport_h - pad).max(100.0);
    let scale_x = avail_w / canvas_w.max(1.0);
    let scale_y = avail_h / canvas_h.max(1.0);
    let raw_pct = (scale_x.min(scale_y) * 100.0).floor() as i32;
    raw_pct.clamp(25, 100)
}

/// Atomically re-encrypts all `.vault` files found recursively within `vault_dir` in parallel using Rayon.
///
/// 1. Finds all files with `.vault` extension (excluding `.vault.new` and temporary files).
/// 2. Decrypts each file using `current_password` and `current_keyfile` into memory,
///    then re-encrypts it using `new_password` and `new_keyfile` in the latest Cascade (`0x03`)
///    format to `<filename>.vault.new`. The decrypted in-memory payload is zeroized.
/// 3. If any file fails during decryption or write, all created `.vault.new` files are removed
///    and an error is returned. The original `.vault` files remain untouched.
/// 4. Once all files have been safely staged as `.vault.new`, they are atomically renamed to `.vault`.
///
/// Returns the number of files successfully re-encrypted.
pub fn reencrypt_vault_atomic<F>(
    vault_dir: &Path,
    current_password: &str,
    current_keyfile: Option<&[u8]>,
    new_password: &str,
    new_keyfile: Option<&[u8]>,
    progress_callback: F,
) -> Result<usize, Box<dyn Error>>
where
    F: FnMut(usize, usize) + Send,
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

    let completed = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let first_error: Mutex<Option<String>> = Mutex::new(None);
    let cb_mutex = Mutex::new(progress_callback);

    // Step 1: Decrypt and stage each file to .vault.new in parallel
    staging_pairs.par_iter().for_each(|(orig_path, new_path)| {
        if failed.load(Ordering::Relaxed) {
            return;
        }

        let record_err = |msg: String| {
            failed.store(true, Ordering::Relaxed);
            let mut guard = first_error.lock().unwrap();
            if guard.is_none() {
                *guard = Some(msg);
            }
        };

        let file_data = match fs::read(orig_path) {
            Ok(d) => d,
            Err(e) => {
                record_err(format!(
                    "Failed to read file {:?}: {}",
                    orig_path.file_name().unwrap_or_default(),
                    e
                ));
                return;
            }
        };

        let decrypted_payload = match decrypt_bytes(&file_data, current_password, current_keyfile) {
            Ok(d) => d,
            Err(e) => {
                record_err(format!(
                    "Failed to decrypt {:?}: {}",
                    orig_path.file_name().unwrap_or_default(),
                    e
                ));
                return;
            }
        };

        let encrypted_payload = match encrypt_bytes(decrypted_payload.as_slice(), new_password, new_keyfile) {
            Ok(d) => d,
            Err(e) => {
                record_err(format!(
                    "Failed to encrypt {:?}: {}",
                    new_path.file_name().unwrap_or_default(),
                    e
                ));
                return;
            }
        };

        drop(decrypted_payload);

        if let Err(e) = fs::write(new_path, &encrypted_payload) {
            record_err(format!(
                "Failed to write re-encrypted file {:?}: {}",
                new_path.file_name().unwrap_or_default(),
                e
            ));
            return;
        }

        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut cb) = cb_mutex.lock() {
            cb(done, total);
        }
    });

    // If any failure occurred during staging, wipe staging files and return error
    if failed.load(Ordering::Relaxed) {
        for (_, new_path) in &staging_pairs {
            if new_path.exists() {
                let _ = fs::remove_file(new_path);
            }
        }
        let msg = first_error
            .into_inner()
            .unwrap_or(None)
            .unwrap_or_else(|| "Re-encryption failed".to_string());
        return Err(msg.into());
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

        // Check KDF params (m_cost, t_cost, p_cost)
        let m1 = u32::from_be_bytes(data1[1..5].try_into().unwrap());
        let t1 = u32::from_be_bytes(data1[5..9].try_into().unwrap());
        let p1 = u32::from_be_bytes(data1[9..13].try_into().unwrap());
        assert_eq!(m1, DEFAULT_ARGON2_M_COST);
        assert_eq!(t1, DEFAULT_ARGON2_T_COST);
        assert_eq!(p1, DEFAULT_ARGON2_P_COST);

        // Check Salt
        let salt_start = 1 + KDF_PARAMS_LEN;
        let salt1 = &data1[salt_start..salt_start + SALT_LEN];
        let salt2 = &data2[salt_start..salt_start + SALT_LEN];
        assert_ne!(salt1, salt2, "Salts must be uniquely generated per file");

        // Check AES Nonce
        let aes_start = salt_start + SALT_LEN;
        let aes_n1 = &data1[aes_start..aes_start + AES_NONCE_LEN];
        let aes_n2 = &data2[aes_start..aes_start + AES_NONCE_LEN];
        assert_ne!(aes_n1, aes_n2, "AES Nonces must be uniquely generated per file");

        // Check XChaCha Nonce
        let chacha_start = aes_start + AES_NONCE_LEN;
        let chacha_n1 = &data1[chacha_start..CASCADE_HEADER_LEN];
        let chacha_n2 = &data2[chacha_start..CASCADE_HEADER_LEN];
        assert_ne!(chacha_n1, chacha_n2, "XChaCha Nonces must be uniquely generated per file");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_v2_format_backward_compatibility() {
        let temp_dir = std::env::temp_dir().join(format!("note_vault_v2_compat_{}", Uuid::new_v4()));
        let file_path = temp_dir.join("v2_note.vault");
        fs::create_dir_all(&temp_dir).unwrap();

        let original_note = Note::new(
            "V2 Note",
            vec!["v2".into()],
            "Created with v0x02 cascade format without AAD.",
        );
        let password = "V2Password123!";
        let keyfile = b"v2_keyfile_entropy_bytes";

        // Manually construct a v0x02 file
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut aes_nonce_bytes = [0u8; AES_NONCE_LEN];
        OsRng.fill_bytes(&mut aes_nonce_bytes);
        let mut chacha_nonce_bytes = [0u8; CHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut chacha_nonce_bytes);

        let derived = derive_key(password, Some(keyfile), &salt).unwrap();
        let plaintext = serde_json::to_vec(&original_note).unwrap();
        let aes_cipher = Aes256Gcm::new_from_slice(&derived[..32]).unwrap();
        let inner = aes_cipher
            .encrypt(&AesNonce::from(aes_nonce_bytes), plaintext.as_slice())
            .unwrap();
        let chacha_cipher = XChaCha20Poly1305::new(Key::from_slice(&derived[32..]));
        let outer = chacha_cipher
            .encrypt(XNonce::from_slice(&chacha_nonce_bytes), inner.as_slice())
            .unwrap();

        let mut v2_data = Vec::new();
        v2_data.push(CASCADE_V2_VERSION);
        v2_data.extend_from_slice(&salt);
        v2_data.extend_from_slice(&aes_nonce_bytes);
        v2_data.extend_from_slice(&chacha_nonce_bytes);
        v2_data.extend_from_slice(&outer);
        fs::write(&file_path, &v2_data).unwrap();

        // Load with current decryptor
        let decrypted = load_note_decrypted(password, Some(keyfile), &file_path)
            .expect("v0x02 note must still decrypt cleanly");
        assert_eq!(decrypted, original_note);

        // Next save upgrades to v0x03
        save_note_encrypted(&decrypted, password, Some(keyfile), &file_path).unwrap();
        let upgraded = fs::read(&file_path).unwrap();
        assert_eq!(upgraded[0], CASCADE_V3_VERSION);
        let reloaded = load_note_decrypted(password, Some(keyfile), &file_path).unwrap();
        assert_eq!(reloaded, original_note);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_v3_header_aad_tampering_detected() {
        let note = Note::new("AAD Check", Vec::new(), "Verify header integrity");
        let password = "AadPassword123!";
        let plaintext = serde_json::to_vec(&note).unwrap();
        let encrypted = encrypt_bytes(&plaintext, password, None).unwrap();
        assert_eq!(encrypted[0], CASCADE_V3_VERSION);

        // Flip a bit in each region of the 81-byte header (m_cost, salt, aes_nonce, chacha_nonce)
        for offset in [4usize, 15, 1 + KDF_PARAMS_LEN + SALT_LEN + 2, CASCADE_V3_HEADER_LEN - 1] {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 0x01;
            assert!(
                decrypt_bytes(&tampered, password, None).is_err(),
                "Header tampering at offset {} must fail AEAD authentication",
                offset
            );
        }
    }

    #[test]
    fn test_legacy_salt_0x03_collision_fallback() {
        let note = Note::new("Legacy 0x03 Salt", Vec::new(), "Salt starts with 0x03");
        let password = "LegacyCollisionPassword!";

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt[0] = CASCADE_V3_VERSION; // Deliberately match v3 version byte

        let mut nonce_bytes = [0u8; CHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = derive_key_legacy(password, &salt).unwrap();
        let plaintext = serde_json::to_vec(&note).unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext.as_slice())
            .unwrap();

        let mut legacy_data = Vec::new();
        legacy_data.extend_from_slice(&salt);
        legacy_data.extend_from_slice(&nonce_bytes);
        legacy_data.extend_from_slice(&ciphertext);

        let decrypted = decrypt_bytes(&legacy_data, password, None)
            .expect("Legacy file with salt[0] == 0x03 must still decrypt");
        let parsed: Note = serde_json::from_slice(decrypted.as_slice()).unwrap();
        assert_eq!(parsed, note);
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


