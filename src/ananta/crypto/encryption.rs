// Symmetric encryption for ANANTA's secure store.
//
// Uses AES-256-GCM (authenticated encryption).
// Key derivation uses PBKDF2.
//
// This is NOT for request-path encryption. It's for:
//   - Encrypting ANANTA's state file on disk
//   - Encrypting secrets in the Anchor vault
//   - Encrypting recovery keys

use serde::{Deserialize, Serialize};

/// An encrypted payload with authentication tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// AES-256-GCM nonce (96 bits).
    pub nonce: Vec<u8>,
    /// Ciphertext + GCM auth tag appended.
    pub ciphertext: Vec<u8>,
    /// Key derivation salt.
    pub salt: Vec<u8>,
    /// Algorithm identifier.
    pub algorithm: EncryptionAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
}

/// Encrypt data with a password-derived key.
pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    use rand::Rng;

    // Derive key using PBKDF2.
    let salt: [u8; 32] = rand::rng().random();
    let key = derive_key(password, &salt)?;

    // Generate random nonce.
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt.
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedPayload {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        salt: salt.to_vec(),
        algorithm: EncryptionAlgorithm::Aes256Gcm,
    })
}

/// Decrypt data with a password.
pub fn decrypt(password: &str, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let key = derive_key(password, &payload.salt)?;
    let nonce = Nonce::from_slice(&payload.nonce);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let plaintext = cipher.decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Derive a 256-bit key from password + salt using PBKDF2.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        100_000, // iterations (configurable)
        &mut key,
    );
    Ok(key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
    InvalidPayload,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed (wrong password or tampered data)"),
            CryptoError::KeyDerivationFailed => write!(f, "key derivation failed"),
            CryptoError::InvalidPayload => write!(f, "invalid encrypted payload"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encryptor holds a derived key for repeated operations.
#[derive(Debug, Clone)]
pub struct Encryptor {
    key: [u8; 32],
    salt: [u8; 32],
}

impl Encryptor {
    pub fn new(password: &str) -> Result<Self, CryptoError> {
        use rand::Rng;
        let salt: [u8; 32] = rand::rng().random();
        let key = derive_key(password, &salt)?;
        Ok(Self { key, salt })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;
        use rand::RngCore;

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedPayload {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            salt: self.salt.to_vec(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        })
    }

    pub fn salt(&self) -> &[u8] { &self.salt }
}

/// Decryptor holds a derived key for repeated operations.
#[derive(Debug)]
pub struct Decryptor {
    key: [u8; 32],
}

impl Decryptor {
    pub fn new(password: &str, salt: &[u8]) -> Result<Self, CryptoError> {
        let key = derive_key(password, salt)?;
        Ok(Self { key })
    }

    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        let nonce = Nonce::from_slice(&payload.nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        cipher.decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let password = "ananta-secret-key";
        let plaintext = b"trust proof data that must be protected";
        let encrypted = encrypt(password, plaintext).unwrap();
        let decrypted = decrypt(password, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let encrypted = encrypt("correct-password", b"secret data").unwrap();
        let result = decrypt("wrong-password", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let encrypted = encrypt("password", b"original").unwrap();
        let mut tampered = encrypted.clone();
        tampered.ciphertext[0] ^= 0xFF; // flip a byte
        let result = decrypt("password", &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn encryptor_reuse() {
        let enc = Encryptor::new("key").unwrap();
        let a = enc.encrypt(b"hello").unwrap();
        let b = enc.encrypt(b"world").unwrap();
        // Different nonces → different ciphertexts.
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn large_data() {
        let data = vec![0u8; 100_000]; // 100KB
        let encrypted = encrypt("key", &data).unwrap();
        let decrypted = decrypt("key", &encrypted).unwrap();
        assert_eq!(decrypted.len(), 100_000);
    }
}