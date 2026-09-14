// ANANTA Cryptographic Primitives
//
// Provides: hashing, signing, verification, Merkle trees, encryption.
// Uses the `ring` crate for production crypto. Falls back to
// software implementations when hardware acceleration unavailable.
//
// DESIGN: All crypto operations are pure functions (no state).
// Stateful key management lives in anchor/key_manager.rs.

pub mod hashing;
pub mod threshold;
pub mod merkle;
pub mod signing;
pub mod encryption;

pub use hashing::{hash, hash_bytes, HashDigest};
pub use threshold::*;
pub use merkle::MerkleTree;
pub use signing::{Signature, KeyPair};
pub use encryption::{Encryptor, Decryptor, EncryptedPayload};
