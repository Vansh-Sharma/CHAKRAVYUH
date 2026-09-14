// ANANTA Cryptographic Primitives
//
// Provides: hashing, signing, verification, Merkle trees, encryption.
// Uses the `ring` crate for production crypto. Falls back to
// software implementations when hardware acceleration unavailable.
//
// DESIGN: All crypto operations are pure functions (no state).
// Stateful key management lives in anchor/key_manager.rs.

pub mod encryption;
pub mod hashing;
pub mod merkle;
pub mod signing;
pub mod threshold;

pub use encryption::{Decryptor, EncryptedPayload, Encryptor};
pub use hashing::{hash, hash_bytes, HashDigest};
pub use merkle::MerkleTree;
pub use signing::{KeyPair, Signature};
pub use threshold::*;
