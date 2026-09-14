// Cryptographic hashing — the foundation of ANANTA's trust verification.
//
// Every integrity check, attestation, and trust proof depends on
// consistent, collision-resistant hashing.

use crate::ananta::config::HashAlgorithm;
use serde::{Deserialize, Serialize};

/// A cryptographic hash digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashDigest {
    pub algorithm: HashAlgorithm,
    pub bytes: Vec<u8>,
    /// Hex-encoded string for human-readable display.
    pub hex: String,
}

impl HashDigest {
    /// Size of the digest in bytes.
    pub fn size_bytes(&self) -> usize {
        match self.algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Blake3 => 32,
        }
    }

    /// Verify this digest matches raw bytes.
    pub fn matches(&self, data: &[u8]) -> bool {
        let computed = hash_bytes(data, &self.algorithm);
        computed.bytes == self.bytes
    }
}

impl std::fmt::Display for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            format!("{:?}", self.algorithm).to_lowercase(),
            &self.hex[..16]
        )
    }
}

/// Hash a string.
pub fn hash(data: &str, algorithm: &HashAlgorithm) -> HashDigest {
    hash_bytes(data.as_bytes(), algorithm)
}

/// Hash raw bytes.
pub fn hash_bytes(data: &[u8], algorithm: &HashAlgorithm) -> HashDigest {
    let digest = match algorithm {
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            use sha2::{Digest, Sha384};
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
    };

    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    HashDigest {
        algorithm: algorithm.clone(),
        bytes: digest,
        hex: hex.clone(),
    }
}

/// Hash multiple data blobs into a single combined digest.
/// Order matters — this is not commutative.
pub fn hash_combined(data: &[&[u8]], algorithm: &HashAlgorithm) -> HashDigest {
    // Create a domain-separated hash: H(0x01 || len || data1 || len || data2 || ...)
    let mut combined = Vec::new();
    combined.push(0x01); // domain separator
    for chunk in data {
        let len_bytes = (chunk.len() as u64).to_le_bytes();
        combined.extend_from_slice(&len_bytes);
        combined.extend_from_slice(chunk);
    }
    hash_bytes(&combined, algorithm)
}

/// Constant-time comparison of two byte slices.
/// Prevents timing attacks on hash comparisons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let a = hash("hello", &HashAlgorithm::Sha256);
        let b = hash("hello", &HashAlgorithm::Sha256);
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn sha256_different_inputs() {
        let a = hash("hello", &HashAlgorithm::Sha256);
        let b = hash("world", &HashAlgorithm::Sha256);
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn blake3_deterministic() {
        let a = hash("chakravyuh", &HashAlgorithm::Blake3);
        let b = hash("chakravyuh", &HashAlgorithm::Blake3);
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn digest_size_correct() {
        let sha256 = hash("test", &HashAlgorithm::Sha256);
        assert_eq!(sha256.size_bytes(), 32);
        let sha384 = hash("test", &HashAlgorithm::Sha384);
        assert_eq!(sha384.size_bytes(), 48);
        let sha512 = hash("test", &HashAlgorithm::Sha512);
        assert_eq!(sha512.size_bytes(), 64);
        let blake3 = hash("test", &HashAlgorithm::Blake3);
        assert_eq!(blake3.size_bytes(), 32);
    }

    #[test]
    fn matches_verification() {
        let digest = hash("verify me", &HashAlgorithm::Sha256);
        assert!(digest.matches(b"verify me"));
        assert!(!digest.matches(b"verify you"));
    }

    #[test]
    fn hash_combined_order_matters() {
        let algo = &HashAlgorithm::Sha256;
        let a = hash_combined(&[b"a", b"b"], algo);
        let b = hash_combined(&[b"b", b"a"], algo);
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn hash_combined_deterministic() {
        let algo = &HashAlgorithm::Sha256;
        let a = hash_combined(&[b"x", b"y", b"z"], algo);
        let b = hash_combined(&[b"x", b"y", b"z"], algo);
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn constant_time_eq_correct() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
