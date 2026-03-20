//! AES-256-GCM seed encryption at rest with PBKDF2 key derivation.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Number of PBKDF2 iterations for key derivation.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// Salt length in bytes.
const SALT_LEN: usize = 32;
/// Nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: wrong password or corrupted data")]
    Decrypt,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encrypted seed stored on disk.
#[derive(Serialize, Deserialize)]
pub struct EncryptedSeed {
    /// PBKDF2 salt (hex).
    pub salt: String,
    /// AES-GCM nonce (hex).
    pub nonce: String,
    /// Ciphertext (hex).
    pub ciphertext: String,
}

/// Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a seed phrase with a password.
pub fn encrypt_seed(seed_phrase: &str, password: &str) -> Result<EncryptedSeed, EncryptionError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, seed_phrase.as_bytes())
        .map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    Ok(EncryptedSeed {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt a seed phrase with a password.
pub fn decrypt_seed(encrypted: &EncryptedSeed, password: &str) -> Result<String, EncryptionError> {
    let salt = hex::decode(&encrypted.salt).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce_bytes =
        hex::decode(&encrypted.nonce).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let ciphertext =
        hex::decode(&encrypted.ciphertext).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    let key = derive_key(password.as_bytes(), &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| EncryptionError::Decrypt)?;

    String::from_utf8(plaintext).map_err(|e| EncryptionError::Encrypt(e.to_string()))
}

/// Save encrypted seed to a file.
pub fn save_encrypted_seed(
    path: &std::path::Path,
    encrypted: &EncryptedSeed,
) -> Result<(), EncryptionError> {
    let json = serde_json::to_string_pretty(encrypted)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load encrypted seed from a file.
pub fn load_encrypted_seed(path: &std::path::Path) -> Result<EncryptedSeed, EncryptionError> {
    let json = std::fs::read_to_string(path)?;
    let encrypted: EncryptedSeed = serde_json::from_str(&json)?;
    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test-password-123";

        let encrypted = encrypt_seed(seed, password).unwrap();
        let decrypted = decrypt_seed(&encrypted, password).unwrap();
        assert_eq!(decrypted, seed);
    }

    #[test]
    fn test_wrong_password_fails() {
        let seed = "test seed phrase";
        let encrypted = encrypt_seed(seed, "correct").unwrap();
        let result = decrypt_seed(&encrypted, "wrong");
        assert!(result.is_err());
    }
}
