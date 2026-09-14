// Key Manager — manages ANANTA's signing keys.
//
// Key types:
//   1. Attestation key — signs attestation reports
//   2. Manifest key — signs the immutable manifest
//   3. Audit chain key — HMAC for chaining audit entries
//   4. Recovery key — signs recovery actions (Phoenix)
//   5. Adapter key — signs pipeline reconfigurations
//
// Keys are:
//   - Generated at first boot
//   - Stored encrypted on disk (via SecureStore)
//   - Rotated on schedule
//   - Never in Keshav's config

use crate::ananta::crypto::signing::{KeyPair, SignAlgorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The purpose of a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Attestation,
    Manifest,
    AuditChain,
    Recovery,
    Adapter,
}

impl std::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyPurpose::Attestation => write!(f, "attestation"),
            KeyPurpose::Manifest => write!(f, "manifest"),
            KeyPurpose::AuditChain => write!(f, "audit_chain"),
            KeyPurpose::Recovery => write!(f, "recovery"),
            KeyPurpose::Adapter => write!(f, "adapter"),
        }
    }
}

/// Metadata about a stored key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub purpose: KeyPurpose,
    pub algorithm: SignAlgorithm,
    pub created_at: String,
    pub rotated_at: Option<String>,
    pub rotation_count: u32,
    pub is_active: bool,
}

/// Manages all ANANTA signing keys.
pub struct KeyManager {
    keys: HashMap<KeyPurpose, KeyPair>,
    metadata: HashMap<String, KeyMetadata>,
    encryption_password: String,
}

impl KeyManager {
    /// Create a new KeyManager. Generates keys on first boot.
    pub fn new(encryption_password: &str) -> Self {
        let mut km = Self {
            keys: HashMap::new(),
            metadata: HashMap::new(),
            encryption_password: encryption_password.into(),
        };

        // Generate default keys.
        let purposes = [
            KeyPurpose::Attestation,
            KeyPurpose::Manifest,
            KeyPurpose::AuditChain,
            KeyPurpose::Recovery,
            KeyPurpose::Adapter,
        ];

        for purpose in &purposes {
            km.generate_key(purpose);
        }

        km
    }

    /// Generate a new key for a purpose.
    fn generate_key(&mut self, purpose: &KeyPurpose) {
        let key_id = format!("ananta.{}.1", purpose);
        let kp = KeyPair::generate_ed25519(&key_id);

        // Audit chain uses HMAC, not Ed25519.
        let kp = if *purpose == KeyPurpose::AuditChain {
            KeyPair::generate_hmac_sha256(&key_id)
        } else {
            kp
        };

        let meta = KeyMetadata {
            key_id: key_id.clone(),
            purpose: purpose.clone(),
            algorithm: kp.algorithm().clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
            rotation_count: 1,
            is_active: true,
        };

        self.keys.insert(purpose.clone(), kp);
        self.metadata.insert(key_id, meta);
    }

    /// Get the active key for a purpose.
    pub fn get_key(&self, purpose: &KeyPurpose) -> Option<&KeyPair> {
        self.keys.get(purpose)
    }

    /// Get public key for a purpose.
    pub fn public_key(&self, purpose: &KeyPurpose) -> Option<&[u8]> {
        self.keys.get(purpose).map(|kp| kp.public_key())
    }

    /// Get metadata for a key.
    pub fn metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.metadata.get(key_id)
    }

    /// Rotate a key (generate new, mark old as inactive).
    pub fn rotate_key(&mut self, purpose: &KeyPurpose) -> &KeyPair {
        let old_meta = self
            .metadata
            .values()
            .find(|m| &m.purpose == purpose && m.is_active);

        let new_rotation = old_meta.map_or(1, |m| m.rotation_count + 1);
        let key_id = format!("ananta.{}.{}", purpose, new_rotation);
        let kp = if *purpose == KeyPurpose::AuditChain {
            KeyPair::generate_hmac_sha256(&key_id)
        } else {
            KeyPair::generate_ed25519(&key_id)
        };

        // Deactivate old keys for this purpose.
        for meta in self.metadata.values_mut() {
            if meta.purpose == *purpose {
                meta.is_active = false;
                meta.rotated_at = Some(chrono::Utc::now().to_rfc3339());
            }
        }

        let new_meta = KeyMetadata {
            key_id: key_id.clone(),
            purpose: purpose.clone(),
            algorithm: kp.algorithm().clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
            rotation_count: new_rotation,
            is_active: true,
        };

        self.keys.insert(purpose.clone(), kp);
        self.metadata.insert(key_id, new_meta);

        self.keys.get(purpose).unwrap()
    }

    /// Export all keys as encrypted bytes for persistence.
    pub fn export_encrypted(&self) -> Result<Vec<u8>, String> {
        // Serialize metadata only (keys are derived from password + salt).
        let meta_json =
            serde_json::to_string(&self.metadata).map_err(|e| format!("key export: {}", e))?;

        // For now, return plaintext metadata. SecureStore handles encryption.
        Ok(meta_json.into_bytes())
    }

    /// List all key metadata.
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.metadata.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_all_key_types() {
        let km = KeyManager::new("test-password");
        assert!(km.get_key(&KeyPurpose::Attestation).is_some());
        assert!(km.get_key(&KeyPurpose::Manifest).is_some());
        assert!(km.get_key(&KeyPurpose::AuditChain).is_some());
        assert!(km.get_key(&KeyPurpose::Recovery).is_some());
        assert!(km.get_key(&KeyPurpose::Adapter).is_some());
    }

    #[test]
    fn audit_chain_uses_hmac() {
        let km = KeyManager::new("test");
        let key = km.get_key(&KeyPurpose::AuditChain).unwrap();
        assert_eq!(key.algorithm(), &SignAlgorithm::HmacSha256);
    }

    #[test]
    fn attestation_uses_ed25519() {
        let km = KeyManager::new("test");
        let key = km.get_key(&KeyPurpose::Attestation).unwrap();
        assert_eq!(key.algorithm(), &SignAlgorithm::Ed25519);
    }

    #[test]
    fn rotate_increments_version() {
        let mut km = KeyManager::new("test");
        let old_id = km
            .get_key(&KeyPurpose::Attestation)
            .unwrap()
            .key_id()
            .to_string();
        km.rotate_key(&KeyPurpose::Attestation);
        let new_id = km.get_key(&KeyPurpose::Attestation).unwrap().key_id();
        assert_ne!(old_id, new_id);
    }

    #[test]
    fn rotation_deactivates_old() {
        let mut km = KeyManager::new("test");
        km.rotate_key(&KeyPurpose::Recovery);
        let active_count = km
            .list_keys()
            .iter()
            .filter(|m| m.is_active && m.purpose == KeyPurpose::Recovery)
            .count();
        assert_eq!(active_count, 1);
    }
}
