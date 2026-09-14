// ANANTA Anchor — Root of Trust
//
// Anchor is the cryptographic foundation of ANANTA.
// It:
//   1. Verifies integrity of binaries, configs, policies at boot
//   2. Manages signing keys for trust proofs and attestations
//   3. Generates and stores the immutable manifest
//   4. Provides attestation reports
//   5. Securely stores secrets (encrypted)
//
// DESIGN CONSTRAINT: Anchor NEVER depends on Keshav.
// It loads its own config and uses its own storage.

pub mod attestation;
pub mod integrity;
pub mod key_manager;
pub mod manifest;
pub mod secure_enclave;
pub mod secure_store;
pub mod trust_chain;

pub use attestation::AttestationReport;
pub use integrity::IntegrityChecker;
pub use key_manager::{KeyManager, KeyPurpose};
pub use manifest::{Manifest, ManifestEntry};
pub use secure_enclave::*;
pub use secure_store::SecureStore;
pub use trust_chain::TrustChain;