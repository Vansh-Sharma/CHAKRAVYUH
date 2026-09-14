// Immutable Manifest — records trusted hashes of all platform components.
//
// The manifest is the single source of truth for "what is trusted."
// It is:
//   - Created at build time or during initial setup
//   - Cryptographically signed
//   - Loaded by Anchor at startup
//   - Never modified at runtime (immutable)
//   - Can be audited to verify no tampering

use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::{hash, HashDigest};
use crate::ananta::crypto::signing::{self, KeyPair, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// The component identifier (e.g., "binary", "config", "policy", "ring:shield").
    pub component: String,
    /// The trusted hash.
    pub hash: HashDigest,
    /// When this entry was created.
    pub created_at: String,
    /// Who/what created this entry.
    pub source: String,
}

/// The immutable manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub algorithm: HashAlgorithm,
    pub version: String,
    pub created_at: String,
    /// component → hash
    entries: HashMap<String, HashDigest>,
    /// Optional signature over the entire manifest.
    pub signature: Option<Signature>,
}

impl Manifest {
    /// Create a new empty manifest.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            version: "1.0.0".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            entries: HashMap::new(),
            signature: None,
        }
    }

    /// Add a trusted hash for a component.
    pub fn insert(&mut self, component: String, hash: HashDigest) {
        self.entries.insert(component, hash);
    }

    /// Add a string-value component (hashes it automatically).
    pub fn insert_data(&mut self, component: &str, data: &str) {
        let hash = hash(data, &self.algorithm);
        self.entries.insert(component.into(), hash);
    }

    /// Add a bytes-value component.
    pub fn insert_bytes(&mut self, component: &str, data: &[u8]) {
        let hash = crate::ananta::crypto::hashing::hash_bytes(data, &self.algorithm);
        self.entries.insert(component.into(), hash);
    }

    /// Get the hash for a component.
    pub fn get(&self, component: &str) -> Option<&HashDigest> {
        self.entries.get(component)
    }

    /// Remove a component.
    pub fn remove(&mut self, component: &str) -> Option<HashDigest> {
        self.entries.remove(component)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &HashDigest)> {
        self.entries.iter()
    }

    /// Serialize the manifest to a canonical JSON string for signing.
    fn canonical_json(&self) -> String {
        // Sort by component name for deterministic output.
        let mut sorted: Vec<_> = self.entries.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);

        let map: serde_json::Map<String, serde_json::Value> = sorted
            .into_iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::json!({
                        "hash": v.hex,
                        "algorithm": format!("{:?}", v.algorithm).to_lowercase(),
                    }),
                )
            })
            .collect();

        serde_json::json!({
            "version": self.version,
            "created_at": self.created_at,
            "algorithm": format!("{:?}", self.algorithm).to_lowercase(),
            "entries": map,
        })
        .to_string()
    }

    /// Sign the manifest with a key pair.
    pub fn sign(&mut self, key_pair: &KeyPair) {
        let json = self.canonical_json();
        let sig = signing::sign(key_pair, json.as_bytes());
        self.signature = Some(sig);
    }

    /// Verify the manifest's signature.
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        match &self.signature {
            Some(sig) => {
                let json = self.canonical_json();
                signing::verify(public_key, &sig.algorithm, sig, json.as_bytes())
            }
            None => false, // No signature = not verified.
        }
    }

    /// Export as JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("manifest serialize: {}", e))
    }

    /// Import from JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("manifest parse: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert_data("config", "my config content");
        assert!(m.get("config").is_some());
        assert!(m.get("missing").is_none());
    }

    #[test]
    fn manifest_sign_verify() {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert_data("binary", "compiled binary content");
        m.insert_data("config", "config content");

        let kp = KeyPair::generate_ed25519("manifest-key");
        m.sign(&kp);

        assert!(m.verify_signature(kp.public_key()));
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert_data("config", "original");

        let kp = KeyPair::generate_ed25519("key");
        m.sign(&kp);

        // Tamper.
        m.insert_data("config", "tampered");

        assert!(!m.verify_signature(kp.public_key()));
    }

    #[test]
    fn json_roundtrip() {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert_data("a", "data_a");
        m.insert_data("b", "data_b");

        let json = m.to_json().unwrap();
        let m2 = Manifest::from_json(&json).unwrap();

        assert_eq!(m.get("a").unwrap().hex, m2.get("a").unwrap().hex);
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let mut m = Manifest::new(HashAlgorithm::Sha256);
        m.insert_data("z", "last");
        m.insert_data("a", "first");

        let j1 = m.canonical_json();
        let j2 = m.canonical_json();
        assert_eq!(j1, j2);
    }
}
