// Cryptographic signing and verification.
//
// Used by:
//   - Anchor: signing trust proofs and attestation reports
//   - Adapter: signing pipeline reconfiguration decisions
//   - Audit: chaining audit entries with HMAC
//   - Distributed: node-to-node signature verification

use serde::{Deserialize, Serialize};
use rand::Rng;

/// A digital signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: SignAlgorithm,
    pub bytes: Vec<u8>,
    pub public_key_id: Option<String>,
}

/// Supported signing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignAlgorithm {
    /// HMAC-SHA256 (symmetric, for internal chaining)
    HmacSha256,
    /// Ed25519 (asymmetric, for external attestation)
    Ed25519,
}

/// A key pair for signing.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_id: String,
    pub algorithm: SignAlgorithm,
    /// Secret key bytes (never serialized publicly).
    secret_key: Vec<u8>,
    /// Public key bytes.
    public_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a new Ed25519 key pair.
    pub fn generate_ed25519(key_id: &str) -> Self {
        use ed25519_dalek::SigningKey;
        let secret: [u8; 32] = rand::rng().random();
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            key_id: key_id.into(),
            algorithm: SignAlgorithm::Ed25519,
            secret_key: secret.to_vec(),
            public_key: public_key.to_vec(),
        }
    }

    /// Generate a new HMAC key pair (symmetric — secret = public).
    pub fn generate_hmac_sha256(key_id: &str) -> Self {
        let key: [u8; 32] = rand::rng().random();
        Self {
            key_id: key_id.into(),
            algorithm: SignAlgorithm::HmacSha256,
            secret_key: key.to_vec(),
            public_key: key.to_vec(),
        }
    }

    /// Create from existing key bytes (for loading from secure storage).
    pub fn from_bytes(
        key_id: &str,
        algorithm: SignAlgorithm,
        secret_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        Self { key_id: key_id.into(), algorithm, secret_key, public_key }
    }

    pub fn public_key(&self) -> &[u8] { &self.public_key }
    pub fn secret_key(&self) -> &[u8] { &self.secret_key }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub fn algorithm(&self) -> &SignAlgorithm { &self.algorithm }
}

/// Sign data with a key pair.
pub fn sign(key_pair: &KeyPair, data: &[u8]) -> Signature {
    match key_pair.algorithm {
        SignAlgorithm::Ed25519 => {
            use ed25519_dalek::{SigningKey, Signer};
            let secret: ed25519_dalek::SecretKey = key_pair.secret_key.clone().try_into()
                .expect("ed25519 secret key must be 32 bytes");
            let signing_key = SigningKey::from_bytes(&secret);
            let signature = signing_key.sign(data);
            Signature {
                algorithm: SignAlgorithm::Ed25519,
                bytes: signature.to_bytes().to_vec(),
                public_key_id: Some(key_pair.key_id.clone()),
            }
        }
        SignAlgorithm::HmacSha256 => {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(&key_pair.secret_key)
                .expect("HMAC key error");
            mac.update(data);
            let result = mac.finalize();
            Signature {
                algorithm: SignAlgorithm::HmacSha256,
                bytes: result.into_bytes().to_vec(),
                public_key_id: Some(key_pair.key_id.clone()),
            }
        }
    }
}

/// Verify a signature against data and a public key.
pub fn verify(
    public_key: &[u8],
    algorithm: &SignAlgorithm,
    signature: &Signature,
    data: &[u8],
) -> bool {
    match algorithm {
        SignAlgorithm::Ed25519 => {
            use ed25519_dalek::{VerifyingKey, Verifier, Signature as DalekSig};
            let vk_bytes: [u8; 32] = match public_key.try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let vk = match VerifyingKey::from_bytes(&vk_bytes) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let sig_bytes: [u8; 64] = match signature.bytes.clone().try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let sig = DalekSig::from_bytes(&sig_bytes);
            vk.verify(data, &sig).is_ok()
        }
        SignAlgorithm::HmacSha256 => {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = match HmacSha256::new_from_slice(public_key) {
                Ok(m) => m,
                Err(_) => return false,
            };
            mac.update(data);
            mac.verify_slice(&signature.bytes).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = KeyPair::generate_ed25519("test-key");
        let data = b"trust proof data";
        let sig = sign(&kp, data);
        assert!(verify(kp.public_key(), &kp.algorithm, &sig, data));
    }

    #[test]
    fn ed25519_detects_tampering() {
        let kp = KeyPair::generate_ed25519("test-key");
        let data = b"original data";
        let sig = sign(&kp, data);
        assert!(!verify(kp.public_key(), &kp.algorithm, &sig, b"tampered data"));
    }

    #[test]
    fn hmac_sign_verify_roundtrip() {
        let kp = KeyPair::generate_hmac_sha256("hmac-key");
        let data = b"audit chain entry";
        let sig = sign(&kp, data);
        assert!(verify(kp.public_key(), &kp.algorithm, &sig, data));
    }

    #[test]
    fn different_keys_different_signatures() {
        let kp1 = KeyPair::generate_ed25519("key-1");
        let kp2 = KeyPair::generate_ed25519("key-2");
        let data = b"same data";
        let sig1 = sign(&kp1, data);
        let sig2 = sign(&kp2, data);
        assert_ne!(sig1.bytes, sig2.bytes);
    }
}
