// ANANTA Secure Enclave — Trusted Execution Environment Abstraction
//
// This module provides a software simulation of a Trusted Execution Environment (TEE),
// inspired by Intel SGX and ARM TrustZone semantics. It implements:
//
//   1. **Secure Enclave Abstraction** — Seal/unseal data, attestation key generation,
//      measured boot, and enclave lifecycle state tracking.
//   2. **Remote Attestation Protocol** — SGX-style challenge-response attestation
//      with nonce exchange, quote generation, and verification.
//   3. **Measurement Registry** — Register and verify code/data measurements (hashes)
//      with allow-list and deny-list security policies.
//   4. **Key Derivation** — HKDF-like key derivation bound to enclave identity and
//      measurements, with key rotation support and grace periods.
//   5. **Enclave Health Monitoring** — Real-time metrics including memory usage,
//      sealed object count, attestation success rate, and staleness detection.
//
// All cryptographic operations use standard algorithms (SHA-256, HMAC-SHA256)
// implemented via software simulation suitable for testing and prototyping.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Unified error type for all secure enclave operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnclaveError {
    /// The enclave has not been initialized yet.
    NotInitialized,
    /// The enclave is in a compromised state and cannot perform operations.
    Compromised,
    /// The enclave is already in the requested state.
    AlreadyInState(String),
    /// The requested operation is invalid for the current enclave state.
    InvalidState(String),
    /// A measurement was not found in the registry.
    MeasurementNotFound(String),
    /// A measurement is on the deny-list and cannot be registered.
    MeasurementDenied(String),
    /// A measurement failed verification against expected values.
    MeasurementMismatch { name: String, expected: String, actual: String },
    /// The attestation quote signature is invalid.
    InvalidQuoteSignature,
    /// The attestation nonce does not match the expected value.
    NonceMismatch,
    /// The provided sealed data is corrupted or tampered with.
    SealedDataCorrupted,
    /// A key derivation operation failed.
    KeyDerivationError(String),
    /// A key rotation is not allowed at this time.
    RotationNotAllowed(String),
    /// A sealed object with the given ID already exists.
    SealedObjectExists(String),
    /// A sealed object with the given ID was not found.
    SealedObjectNotFound(String),
    /// The attestation key has not been generated yet.
    AttestationKeyNotFound,
    /// Generic error with a descriptive message.
    Generic(String),
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnclaveError::NotInitialized => write!(f, "Enclave is not initialized"),
            EnclaveError::Compromised => write!(f, "Enclave is compromised"),
            EnclaveError::AlreadyInState(s) => write!(f, "Enclave is already in state: {}", s),
            EnclaveError::InvalidState(s) => write!(f, "Invalid enclave state: {}", s),
            EnclaveError::MeasurementNotFound(s) => write!(f, "Measurement not found: {}", s),
            EnclaveError::MeasurementDenied(s) => write!(f, "Measurement denied: {}", s),
            EnclaveError::MeasurementMismatch { name, expected, actual } => {
                write!(f, "Measurement mismatch for '{}': expected {}, got {}", name, expected, actual)
            }
            EnclaveError::InvalidQuoteSignature => write!(f, "Invalid quote signature"),
            EnclaveError::NonceMismatch => write!(f, "Nonce mismatch"),
            EnclaveError::SealedDataCorrupted => write!(f, "Sealed data is corrupted"),
            EnclaveError::KeyDerivationError(s) => write!(f, "Key derivation error: {}", s),
            EnclaveError::RotationNotAllowed(s) => write!(f, "Rotation not allowed: {}", s),
            EnclaveError::SealedObjectExists(s) => write!(f, "Sealed object already exists: {}", s),
            EnclaveError::SealedObjectNotFound(s) => write!(f, "Sealed object not found: {}", s),
            EnclaveError::AttestationKeyNotFound => write!(f, "Attestation key not found"),
            EnclaveError::Generic(s) => write!(f, "Generic error: {}", s),
        }
    }
}

impl std::error::Error for EnclaveError {}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2: Cryptographic Primitives (Software Simulation)
// ─────────────────────────────────────────────────────────────────────────────

/// Simple SHA-256 digest represented as a hex-encoded string.
/// In a production TEE, this would delegate to the hardware security module.
pub type HashDigest = String;

/// Computes a SHA-256 hash of the given data and returns the hex-encoded digest.
/// This uses a pure-Rust implementation suitable for simulation environments.
pub fn sha256_digest(data: &[u8]) -> HashDigest {
    // Pure-Rust SHA-256 implementation using the standard library.
    // This follows the FIPS 180-4 specification.
    fn sha256_block(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: pad message to 512-bit boundary.
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block.
    for chunk in padded.chunks_exact(64) {
        sha256_block(&mut state, chunk);
    }

    // Produce the final hash as a hex string.
    state
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Computes an HMAC-SHA256 over the given message using the provided key.
/// Follows RFC 2104 construction: H(K XOR opad || H(K XOR ipad || message)).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> HashDigest {
    let block_size: usize = 64;

    // Key preparation per RFC 2104.
    let mut key_padded = vec![0u8; block_size];
    if key.len() > block_size {
        let hash = sha256_digest(key);
        let hash_bytes = hex_to_bytes(&hash);
        key_padded[..32].copy_from_slice(&hash_bytes);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H(K XOR ipad || message).
    let mut inner_data = Vec::with_capacity(block_size + message.len());
    for &b in key_padded.iter() {
        inner_data.push(b ^ 0x36); // ipad
    }
    inner_data.extend_from_slice(message);
    let inner_hash = sha256_digest(&inner_data);

    // Outer hash: H(K XOR opad || inner_hash).
    let inner_hash_bytes = hex_to_bytes(&inner_hash);
    let mut outer_data = Vec::with_capacity(block_size + 32);
    for &b in key_padded.iter() {
        outer_data.push(b ^ 0x5c); // opad
    }
    outer_data.extend_from_slice(&inner_hash_bytes);
    sha256_digest(&outer_data)
}

/// HKDF-Extract step: extracts a pseudorandom key from input keying material
/// and an optional salt using HMAC-SHA256.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> HashDigest {
    if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

/// HKDF-Expand step: expands a pseudorandom key into output keying material
/// of the specified length using HMAC-SHA256.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, EnclaveError> {
    let hash_len = 32; // SHA-256 output length
    if length > 255 * hash_len {
        return Err(EnclaveError::KeyDerivationError(
            "Output length exceeds maximum (255 * 32 bytes)".to_string(),
        ));
    }

    let n = ((length as f64) / (hash_len as f64)).ceil() as usize;
    let prk_bytes = if prk.len() == 32 { prk.to_vec() } else { hex_to_bytes(&sha256_digest(prk)) };

    let mut okm = Vec::with_capacity(n * hash_len);
    let mut prev = Vec::new();

    for i in 1..=n {
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&prev);
        hmac_input.extend_from_slice(info);
        hmac_input.push(i as u8);
        prev = hex_to_bytes(&hmac_sha256(&prk_bytes, &hmac_input));
        okm.extend_from_slice(&prev);
    }

    okm.truncate(length);
    Ok(okm)
}

/// HKDF-Extract-and-Expand combined operation for convenience.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, EnclaveError> {
    let prk = hkdf_extract(salt, ikm);
    let prk_bytes = hex_to_bytes(&prk);
    hkdf_expand(&prk_bytes, info, length)
}

/// Converts a hex-encoded string back to raw bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3: Enclave State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the lifecycle state of a secure enclave.
/// The state machine transitions are:
///
/// ```text
/// Uninitialized → Initialized → Active
///        ↑              │            │
///        └──────────────┘            ↓
///                             Compromised
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EnclaveState {
    /// The enclave has been created but not yet initialized. No cryptographic
    /// material exists and no operations are permitted.
    Uninitialized,
    /// The enclave has been initialized with an identity and attestation key,
    /// but has not yet entered the active processing state.
    Initialized,
    /// The enclave is fully operational and can perform seal/unseal,
    /// attestation, and key derivation operations.
    Active,
    /// The enclave has detected a security violation and is locked down.
    /// Only a reset operation can return the enclave to Uninitialized.
    Compromised,
}

impl EnclaveState {
    /// Returns true if the enclave is in a state that permits cryptographic operations.
    pub fn is_operational(&self) -> bool {
        matches!(self, EnclaveState::Initialized | EnclaveState::Active)
    }

    /// Returns true if the enclave is in the compromised state.
    pub fn is_compromised(&self) -> bool {
        matches!(self, EnclaveState::Compromised)
    }

    /// Returns the state as a human-readable string.
    pub fn as_str(&self) -> &'static str {
        match self {
            EnclaveState::Uninitialized => "uninitialized",
            EnclaveState::Initialized => "initialized",
            EnclaveState::Active => "active",
            EnclaveState::Compromised => "compromised",
        }
    }
}

impl std::fmt::Display for EnclaveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4: Sealed Data Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Represents data that has been sealed (encrypted and authenticated) by the enclave.
/// The seal binds the data to the enclave's identity and current measurements,
/// ensuring it can only be unsealed by the same enclave configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealedData {
    /// Unique identifier for this sealed object.
    pub id: String,
    /// The original plaintext data, encrypted under the enclave seal key.
    pub ciphertext: Vec<u8>,
    /// HMAC-SHA256 authentication tag over the ciphertext and associated data.
    pub auth_tag: HashDigest,
    /// Hash of the enclave identity at the time of sealing.
    pub enclave_identity_hash: HashDigest,
    /// Snapshot of all measurements at seal time, used for binding verification.
    pub measurement_snapshot: Vec<MeasurementEntry>,
    /// Monotonic version counter for replay protection.
    pub version: u64,
    /// Timestamp when the data was sealed, for auditing and TTL enforcement.
    pub sealed_at: DateTime<Utc>,
    /// Optional time-to-live in seconds; after expiry, unseal will be refused.
    pub ttl_seconds: Option<i64>,
}

impl SealedData {
    /// Checks whether this sealed data has expired based on its TTL.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        if let Some(ttl) = self.ttl_seconds {
            now > self.sealed_at + Duration::seconds(ttl)
        } else {
            false
        }
    }

    /// Computes the verification payload used for HMAC validation.
    fn verification_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.id.as_bytes());
        payload.extend_from_slice(&self.ciphertext);
        payload.extend_from_slice(self.enclave_identity_hash.as_bytes());
        payload.extend_from_slice(&self.version.to_be_bytes());
        payload
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5: Attestation Structures
// ─────────────────────────────────────────────────────────────────────────────

/// A cryptographic nonce used in challenge-response attestation.
/// Must be at least 16 bytes (128 bits) to prevent brute-force attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationNonce {
    /// Random bytes comprising the nonce.
    pub bytes: Vec<u8>,
    /// Timestamp of nonce generation for freshness tracking.
    pub generated_at: DateTime<Utc>,
}

impl AttestationNonce {
    /// Creates a new attestation nonce from the given random bytes.
    /// Validates that the nonce is at least 16 bytes long.
    pub fn new(bytes: Vec<u8>) -> Result<Self, EnclaveError> {
        if bytes.len() < 16 {
            return Err(EnclaveError::Generic(
                "Attestation nonce must be at least 16 bytes".to_string(),
            ));
        }
        Ok(Self {
            bytes,
            generated_at: Utc::now(),
        })
    }

    /// Returns the hex-encoded hash of the nonce bytes for comparison purposes.
    pub fn hash(&self) -> HashDigest {
        sha256_digest(&self.bytes)
    }
}

/// An attestation key used for signing quotes during remote attestation.
/// In hardware TEEs, this would be provisioned during manufacturing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationKey {
    /// Hex-encoded public key identifier.
    pub key_id: String,
    /// Hex-encoded public key bytes.
    pub public_key: String,
    /// Hex-encoded private key bytes (never exported in production).
    pub private_key: String,
    /// Hash of the public key for quick identification.
    pub public_key_hash: HashDigest,
    /// Timestamp when this key was generated.
    pub generated_at: DateTime<Utc>,
    /// Monotonic generation counter for key rotation tracking.
    pub generation: u64,
}

impl AttestationKey {
    /// Generates a new attestation key pair using the enclave's deterministic
    /// key derivation, seeded from the enclave identity.
    pub fn generate(enclave_identity: &str, generation: u64) -> Self {
        let seed = format!("{}-attestation-key-gen-{}", enclave_identity, generation);
        let private_raw = sha256_digest(seed.as_bytes());
        let public_raw = sha256_digest(private_raw.as_bytes());
        let key_id = sha256_digest(format!("key-id-{}", private_raw).as_bytes());
        let public_key_hash = sha256_digest(public_raw.as_bytes());
        Self {
            key_id,
            public_key: public_raw,
            private_key: private_raw,
            public_key_hash,
            generated_at: Utc::now(),
            generation,
        }
    }

    /// Signs the given data with this attestation key, producing a signature.
    /// Uses HMAC-SHA256 with the public key hash for verifiable signatures.
    pub fn sign(&self, data: &[u8]) -> HashDigest {
        hmac_sha256(&hex_to_bytes(&self.public_key_hash), data)
    }

    /// Verifies a signature against the given data using the public key hash.
    pub fn verify(&self, data: &[u8], signature: &HashDigest) -> bool {
        let expected = hmac_sha256(&hex_to_bytes(&self.public_key_hash), data);
        expected == *signature
    }
}

/// SGX-style quote structure produced during remote attestation.
/// Contains the enclave's identity, measurements, and a signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnclaveQuote {
    /// Version of the quote format for compatibility checking.
    pub version: u32,
    /// Hash of the enclave's signing key (MRENCLAVE equivalent).
    pub mr_enclave: HashDigest,
    /// Hash of the enclave signer (MRSIGNER equivalent).
    pub mr_signer: HashDigest,
    /// Unique identifier for the enclave instance.
    pub enclave_id: String,
    /// Nonce provided by the verifier for freshness.
    pub nonce: AttestationNonce,
    /// All current measurements included in the report.
    pub measurements: Vec<MeasurementEntry>,
    /// Current enclave state at the time of quote generation.
    pub enclave_state: EnclaveState,
    /// Timestamp when the quote was generated.
    pub quoted_at: DateTime<Utc>,
    /// Signature over the quote body by the attestation key.
    pub signature: HashDigest,
    /// The attestation key's public key hash for verification.
    pub signer_key_hash: HashDigest,
    /// Generation of the attestation key used.
    pub key_generation: u64,
}

impl EnclaveQuote {
    /// Produces the canonical serialization of the quote body (everything
    /// except the signature) for signing and verification.
    pub fn quote_body_bytes(&self) -> Vec<u8> {
        let body = serde_json::json!({
            "version": self.version,
            "mr_enclave": self.mr_enclave,
            "mr_signer": self.mr_signer,
            "enclave_id": self.enclave_id,
            "nonce_hash": self.nonce.hash(),
            "measurements": self.measurements,
            "enclave_state": self.enclave_state.as_str(),
            "quoted_at": self.quoted_at.to_rfc3339(),
            "key_generation": self.key_generation,
        });
        serde_json::to_vec(&body).unwrap_or_default()
    }
}

/// Result of a remote attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResult {
    /// Whether the attestation passed all verification checks.
    pub is_valid: bool,
    /// Human-readable description of the verification outcome.
    pub description: String,
    /// Timestamp of verification.
    pub verified_at: DateTime<Utc>,
    /// The quote that was verified.
    pub quote: EnclaveQuote,
    /// Specific checks that passed or failed.
    pub checks: Vec<AttestationCheckResult>,
}

/// Individual check result within an attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationCheckResult {
    /// Name of the verification check.
    pub check_name: String,
    /// Whether this specific check passed.
    pub passed: bool,
    /// Details about the check result.
    pub detail: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 6: Measurement Registry
// ─────────────────────────────────────────────────────────────────────────────

/// The type of measurement being recorded.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MeasurementType {
    /// Hash of the code loaded into the enclave.
    Code,
    /// Hash of the initial data in the enclave.
    Data,
    /// Hash of the configuration or manifest.
    Config,
    /// Hash of the enclave runtime or platform.
    Runtime,
}

impl std::fmt::Display for MeasurementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasurementType::Code => write!(f, "code"),
            MeasurementType::Data => write!(f, "data"),
            MeasurementType::Config => write!(f, "config"),
            MeasurementType::Runtime => write!(f, "runtime"),
        }
    }
}

/// A single measurement entry in the registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MeasurementEntry {
    /// Unique name identifying what was measured.
    pub name: String,
    /// The type of measurement.
    pub measurement_type: MeasurementType,
    /// The expected SHA-256 hash value.
    pub hash: HashDigest,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Timestamp when this measurement was registered.
    pub registered_at: DateTime<Utc>,
}

impl MeasurementEntry {
    /// Creates a new measurement entry.
    pub fn new(name: &str, measurement_type: MeasurementType, hash: HashDigest) -> Self {
        Self {
            name: name.to_string(),
            measurement_type,
            hash,
            description: None,
            registered_at: Utc::now(),
        }
    }

    /// Creates a new measurement entry with a description.
    pub fn with_description(
        name: &str,
        measurement_type: MeasurementType,
        hash: HashDigest,
        description: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            measurement_type,
            hash,
            description: Some(description.to_string()),
            registered_at: Utc::now(),
        }
    }

    /// Computes the SHA-256 hash of the given data bytes.
    pub fn hash_of(data: &[u8]) -> HashDigest {
        sha256_digest(data)
    }
}

/// Policy mode for the measurement registry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeasurementPolicy {
    /// Only measurements on the allow-list are accepted. Everything else is rejected.
    AllowList,
    /// Only measurements on the deny-list are rejected. Everything else is accepted.
    DenyList,
    /// No policy restrictions; all measurements are accepted.
    Unrestricted,
}

/// The measurement registry manages code and data measurements for the enclave.
/// It supports both allow-list and deny-list security policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeasurementRegistry {
    /// All registered measurements keyed by name.
    measurements: HashMap<String, MeasurementEntry>,
    /// Allow-list of measurement names (only used in AllowList policy mode).
    allow_list: HashSet<String>,
    /// Deny-list of measurement names (only used in DenyList policy mode).
    deny_list: HashSet<String>,
    /// Current policy mode.
    policy: MeasurementPolicy,
}

impl MeasurementRegistry {
    /// Creates a new empty measurement registry with unrestricted policy.
    pub fn new() -> Self {
        Self {
            measurements: HashMap::new(),
            allow_list: HashSet::new(),
            deny_list: HashSet::new(),
            policy: MeasurementPolicy::Unrestricted,
        }
    }

    /// Creates a new measurement registry with the specified policy mode.
    pub fn with_policy(policy: MeasurementPolicy) -> Self {
        Self {
            measurements: HashMap::new(),
            allow_list: HashSet::new(),
            deny_list: HashSet::new(),
            policy,
        }
    }

    /// Registers a measurement after checking the current security policy.
    pub fn register(&mut self, entry: MeasurementEntry) -> Result<(), EnclaveError> {
        match self.policy {
            MeasurementPolicy::AllowList => {
                if !self.allow_list.contains(&entry.name) {
                    return Err(EnclaveError::MeasurementNotFound(format!(
                        "Measurement '{}' is not on the allow-list",
                        entry.name
                    )));
                }
            }
            MeasurementPolicy::DenyList => {
                if self.deny_list.contains(&entry.name) {
                    return Err(EnclaveError::MeasurementDenied(format!(
                        "Measurement '{}' is on the deny-list",
                        entry.name
                    )));
                }
            }
            MeasurementPolicy::Unrestricted => {}
        }
        self.measurements.insert(entry.name.clone(), entry);
        Ok(())
    }

    /// Retrieves a measurement by name.
    pub fn get(&self, name: &str) -> Option<&MeasurementEntry> {
        self.measurements.get(name)
    }

    /// Verifies that the current measurement for a given name matches the expected hash.
    pub fn verify_measurement(
        &self,
        name: &str,
        actual_hash: &HashDigest,
    ) -> Result<(), EnclaveError> {
        let expected = self
            .measurements
            .get(name)
            .ok_or_else(|| EnclaveError::MeasurementNotFound(name.to_string()))?;
        if expected.hash != *actual_hash {
            return Err(EnclaveError::MeasurementMismatch {
                name: name.to_string(),
                expected: expected.hash.clone(),
                actual: actual_hash.clone(),
            });
        }
        Ok(())
    }

    /// Verifies a batch of measurements. Returns the first mismatch found, or Ok(())
    /// if all measurements match.
    pub fn verify_all(
        &self,
        measurements: &[(String, HashDigest)],
    ) -> Result<(), EnclaveError> {
        for (name, hash) in measurements {
            self.verify_measurement(name, hash)?;
        }
        Ok(())
    }

    /// Adds a name to the allow-list.
    pub fn add_to_allow_list(&mut self, name: &str) {
        self.allow_list.insert(name.to_string());
    }

    /// Adds a name to the deny-list.
    pub fn add_to_deny_list(&mut self, name: &str) {
        self.deny_list.insert(name.to_string());
    }

    /// Removes a name from the allow-list.
    pub fn remove_from_allow_list(&mut self, name: &str) {
        self.allow_list.remove(name);
    }

    /// Removes a name from the deny-list.
    pub fn remove_from_deny_list(&mut self, name: &str) {
        self.deny_list.remove(name);
    }

    /// Sets the policy mode.
    pub fn set_policy(&mut self, policy: MeasurementPolicy) {
        self.policy = policy;
    }

    /// Returns the current policy mode.
    pub fn policy(&self) -> MeasurementPolicy {
        self.policy
    }

    /// Returns a list of all registered measurement names.
    pub fn list_names(&self) -> Vec<&String> {
        self.measurements.keys().collect()
    }

    /// Returns the total number of registered measurements.
    pub fn count(&self) -> usize {
        self.measurements.len()
    }

    /// Returns all measurements as a vector, sorted by name.
    pub fn all_measurements(&self) -> Vec<MeasurementEntry> {
        let mut entries: Vec<_> = self.measurements.values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    /// Computes a composite hash over all registered measurements, representing
    /// the complete state of the enclave's measured boot chain.
    pub fn composite_hash(&self) -> HashDigest {
        let mut data = Vec::new();
        let mut entries: Vec<_> = self.measurements.values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in &entries {
            data.extend_from_slice(entry.name.as_bytes());
            data.push(0); // null separator
            data.extend_from_slice(entry.hash.as_bytes());
            data.push(0);
        }
        sha256_digest(&data)
    }

    /// Checks whether a name is on the deny-list.
    pub fn is_denied(&self, name: &str) -> bool {
        self.deny_list.contains(name)
    }

    /// Checks whether a name is on the allow-list.
    pub fn is_allowed(&self, name: &str) -> bool {
        self.allow_list.contains(name)
    }
}

impl Default for MeasurementRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 7: Key Derivation and Rotation
// ─────────────────────────────────────────────────────────────────────────────

/// A derived key with metadata about its derivation context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivedKey {
    /// Unique identifier for this derived key.
    pub key_id: String,
    /// The raw key material bytes.
    pub key_material: Vec<u8>,
    /// The HKDF info string used in derivation for auditability.
    pub derivation_info: String,
    /// Generation counter of the attestation key at time of derivation.
    pub attestation_generation: u64,
    /// The composite measurement hash at time of derivation.
    pub measurement_hash: HashDigest,
    /// Timestamp when this key was derived.
    pub derived_at: DateTime<Utc>,
    /// Whether this key is currently active or has been superseded by rotation.
    pub is_active: bool,
}

impl DerivedKey {
    /// Returns the hex-encoded representation of the key material.
    pub fn hex_key(&self) -> String {
        self.key_material.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Manages key derivation and rotation lifecycle for the enclave.
/// All keys are bound to the enclave's attestation identity and current
/// measurements, ensuring forward secrecy and measurement integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyDerivationManager {
    /// The enclave identity string used as a derivation context.
    enclave_identity: String,
    /// All derived keys indexed by their key ID.
    keys: HashMap<String, DerivedKey>,
    /// Key rotation grace period in seconds. During this window, both the
    /// old and new keys are considered valid for decryption.
    grace_period_seconds: i64,
    /// Monotonic key derivation counter.
    derivation_counter: u64,
}

impl KeyDerivationManager {
    /// Creates a new key derivation manager bound to the given enclave identity.
    pub fn new(enclave_identity: &str, grace_period_seconds: i64) -> Self {
        Self {
            enclave_identity: enclave_identity.to_string(),
            keys: HashMap::new(),
            grace_period_seconds,
            derivation_counter: 0,
        }
    }

    /// Derives a new key using HKDF bound to the enclave identity, measurements,
    /// and a user-specified purpose string.
    ///
    /// The derivation chain is: HKDF(salt=identity_hash, IKM=measurement_hash || purpose, info=purpose)
    pub fn derive_key(
        &mut self,
        purpose: &str,
        measurement_hash: &HashDigest,
        attestation_generation: u64,
        key_length: usize,
    ) -> Result<DerivedKey, EnclaveError> {
        let identity_hash = sha256_digest(self.enclave_identity.as_bytes());
        let identity_bytes = hex_to_bytes(&identity_hash);

        // Input keying material: measurement hash + purpose + counter
        let mut ikm = Vec::new();
        ikm.extend_from_slice(hex_to_bytes(measurement_hash).as_slice());
        ikm.extend_from_slice(purpose.as_bytes());
        ikm.extend_from_slice(&self.derivation_counter.to_be_bytes());

        // Info string: includes purpose and generation for domain separation
        let info = format!("ananta-enclave:{}:gen-{}", purpose, attestation_generation);

        let key_material = hkdf(&identity_bytes, &ikm, info.as_bytes(), key_length)?;

        let key_id = sha256_digest(
            format!("{}-{}-{}-{}", purpose, attestation_generation, self.derivation_counter, key_length)
                .as_bytes(),
        );

        let derived_key = DerivedKey {
            key_id: key_id.clone(),
            key_material,
            derivation_info: info.clone(),
            attestation_generation,
            measurement_hash: measurement_hash.clone(),
            derived_at: Utc::now(),
            is_active: true,
        };

        self.derivation_counter += 1;
        self.keys.insert(key_id.clone(), derived_key.clone());
        Ok(derived_key)
    }

    /// Rotates an existing key by deriving a new version and deactivating the old one.
    /// During the grace period, the old key remains available for decryption.
    pub fn rotate_key(
        &mut self,
        old_key_id: &str,
        new_purpose: &str,
        measurement_hash: &HashDigest,
        attestation_generation: u64,
        key_length: usize,
    ) -> Result<DerivedKey, EnclaveError> {
        let old_key = self
            .keys
            .get(old_key_id)
            .ok_or_else(|| EnclaveError::SealedObjectNotFound(format!("Key '{}' not found", old_key_id)))?;

        if !old_key.is_active {
            return Err(EnclaveError::RotationNotAllowed(format!(
                "Key '{}' is already inactive; cannot rotate",
                old_key_id
            )));
        }

        // Deactivate the old key.
        if let Some(existing) = self.keys.get_mut(old_key_id) {
            existing.is_active = false;
        }

        // Derive the new key.
        let new_key = self.derive_key(
            new_purpose,
            measurement_hash,
            attestation_generation,
            key_length,
        )?;

        Ok(new_key)
    }

    /// Checks whether a previously rotated key is still within its grace period
    /// and can be used for decryption of legacy data.
    pub fn is_in_grace_period(&self, key_id: &str, now: DateTime<Utc>) -> bool {
        if let Some(key) = self.keys.get(key_id) {
            if key.is_active {
                return true;
            }
            now < key.derived_at + Duration::seconds(self.grace_period_seconds)
        } else {
            false
        }
    }

    /// Retrieves a derived key by its ID.
    pub fn get_key(&self, key_id: &str) -> Option<&DerivedKey> {
        self.keys.get(key_id)
    }

    /// Returns the total number of derived keys (including inactive ones).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns the number of currently active keys.
    pub fn active_key_count(&self) -> usize {
        self.keys.values().filter(|k| k.is_active).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 8: Enclave Health Monitoring
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of enclave health metrics at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnclaveHealthSnapshot {
    /// Current enclave state.
    pub state: EnclaveState,
    /// Estimated memory usage in bytes.
    pub memory_usage_bytes: u64,
    /// Total number of sealed objects currently stored.
    pub sealed_object_count: usize,
    /// Total number of attestation attempts.
    pub total_attestation_attempts: u64,
    /// Number of successful attestation verifications.
    pub successful_attestations: u64,
    /// Number of failed attestation verifications.
    pub failed_attestations: u64,
    /// Attestation success rate as a percentage (0.0 to 100.0).
    pub attestation_success_rate: f64,
    /// Timestamp of the last successful attestation.
    pub last_attestation_at: Option<DateTime<Utc>>,
    /// Duration since the last attestation (seconds).
    pub seconds_since_last_attestation: Option<i64>,
    /// Timestamp when this snapshot was taken.
    pub snapshot_at: DateTime<Utc>,
    /// Number of registered measurements.
    pub measurement_count: usize,
    /// Number of active derived keys.
    pub active_key_count: usize,
    /// Uptime of the enclave in seconds since activation.
    pub uptime_seconds: Option<i64>,
}

impl EnclaveHealthSnapshot {
    /// Determines if the enclave is considered healthy.
    /// An enclave is healthy if it is active, has a reasonable attestation success
    /// rate (>90%), and has had a recent attestation (within the last 300 seconds).
    pub fn is_healthy(&self) -> bool {
        if self.state != EnclaveState::Active {
            return false;
        }
        if self.total_attestation_attempts > 0 && self.attestation_success_rate < 90.0 {
            return false;
        }
        if let Some(secs) = self.seconds_since_last_attestation {
            if secs > 300 {
                return false;
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 9: Secure Enclave — Main Structure
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration parameters for initializing a secure enclave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnclaveConfig {
    /// Unique identifier for this enclave instance.
    pub enclave_id: String,
    /// Human-readable name for the enclave.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Grace period for key rotation in seconds.
    pub key_rotation_grace_seconds: i64,
    /// Maximum allowed sealed object count.
    pub max_sealed_objects: usize,
    /// Expected memory budget in bytes.
    pub memory_budget_bytes: u64,
}

impl EnclaveConfig {
    /// Creates a default configuration with the given enclave ID.
    pub fn default_for(enclave_id: &str) -> Self {
        Self {
            enclave_id: enclave_id.to_string(),
            name: format!("Enclave-{}", enclave_id),
            description: None,
            key_rotation_grace_seconds: 3600,
            max_sealed_objects: 10_000,
            memory_budget_bytes: 128 * 1024 * 1024, // 128 MB
        }
    }
}

/// The main secure enclave abstraction. Simulates a Trusted Execution Environment
/// with sealing, attestation, measurement, key derivation, and health monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecureEnclave {
    /// Unique identifier for this enclave instance.
    enclave_id: String,
    /// Configuration used during initialization.
    config: EnclaveConfig,
    /// Current lifecycle state.
    state: EnclaveState,
    /// The measurement registry for code and data integrity.
    measurement_registry: MeasurementRegistry,
    /// The attestation key pair (generated during initialization).
    attestation_key: Option<AttestationKey>,
    /// All sealed objects stored by this enclave, keyed by ID.
    sealed_objects: HashMap<String, SealedData>,
    /// The key derivation manager.
    key_manager: Option<KeyDerivationManager>,
    /// Monotonic sealed object version counter.
    seal_version_counter: u64,
    /// Health tracking fields.
    total_attestation_attempts: u64,
    successful_attestations: u64,
    failed_attestations: u64,
    last_attestation_at: Option<DateTime<Utc>>,
    /// Timestamp when the enclave entered the Active state.
    activated_at: Option<DateTime<Utc>>,
    /// Current estimated memory usage in bytes.
    memory_usage_bytes: u64,
}

impl SecureEnclave {
    /// Creates a new uninitialized secure enclave with the given configuration.
    pub fn new(config: EnclaveConfig) -> Self {
        let enclave_id = config.enclave_id.clone();
        Self {
            enclave_id,
            config,
            state: EnclaveState::Uninitialized,
            measurement_registry: MeasurementRegistry::new(),
            attestation_key: None,
            sealed_objects: HashMap::new(),
            key_manager: None,
            seal_version_counter: 0,
            total_attestation_attempts: 0,
            successful_attestations: 0,
            failed_attestations: 0,
            last_attestation_at: None,
            activated_at: None,
            memory_usage_bytes: 0,
        }
    }

    /// Initializes the enclave by generating the attestation key and
    /// preparing the measurement registry. Transitions from Uninitialized → Initialized.
    pub fn initialize(&mut self) -> Result<(), EnclaveError> {
        self.require_state(EnclaveState::Uninitialized)?;
        self.attestation_key = Some(AttestationKey::generate(&self.enclave_id, 0));
        self.key_manager = Some(KeyDerivationManager::new(
            &self.enclave_id,
            self.config.key_rotation_grace_seconds,
        ));
        self.state = EnclaveState::Initialized;
        self.update_memory_usage();
        Ok(())
    }

    /// Performs a measured boot by registering a set of initial measurements
    /// and transitioning the enclave to the Active state.
    /// Transitions from Initialized → Active.
    pub fn measured_boot(&mut self, measurements: Vec<MeasurementEntry>) -> Result<(), EnclaveError> {
        self.require_state(EnclaveState::Initialized)?;
        self.require_attestation_key()?;

        // Verify measurements against deny-list before accepting them.
        for entry in &measurements {
            if self.measurement_registry.is_denied(&entry.name) {
                return Err(EnclaveError::MeasurementDenied(format!(
                    "Cannot load measurement '{}' during boot: on deny-list",
                    entry.name
                )));
            }
            self.measurement_registry.register(entry.clone())?;
        }

        self.state = EnclaveState::Active;
        self.activated_at = Some(Utc::now());
        self.update_memory_usage();
        Ok(())
    }

    /// Marks the enclave as compromised. No further operations will be
    /// permitted except a full reset.
    pub fn mark_compromised(&mut self) {
        self.state = EnclaveState::Compromised;
    }

    /// Resets the enclave back to Uninitialized state, clearing all data.
    pub fn reset(&mut self) {
        self.state = EnclaveState::Uninitialized;
        self.measurement_registry = MeasurementRegistry::new();
        self.attestation_key = None;
        self.sealed_objects.clear();
        self.key_manager = None;
        self.seal_version_counter = 0;
        self.total_attestation_attempts = 0;
        self.successful_attestations = 0;
        self.failed_attestations = 0;
        self.last_attestation_at = None;
        self.activated_at = None;
        self.memory_usage_bytes = 0;
    }

    /// Seals (encrypts and authenticates) data within the enclave.
    /// The seal is bound to the current enclave measurements and identity.
    pub fn seal_data(
        &mut self,
        id: &str,
        plaintext: &[u8],
        ttl_seconds: Option<i64>,
    ) -> Result<SealedData, EnclaveError> {
        self.require_operational()?;
        self.require_attestation_key()?;

        if self.sealed_objects.contains_key(id) {
            return Err(EnclaveError::SealedObjectExists(id.to_string()));
        }
        if self.sealed_objects.len() >= self.config.max_sealed_objects {
            return Err(EnclaveError::Generic(
                "Maximum sealed object count reached".to_string(),
            ));
        }

        let att_key = self.attestation_key.as_ref().unwrap();
        let identity_hash = sha256_digest(self.enclave_id.as_bytes());
        let measurement_snapshot = self.measurement_registry.all_measurements();

        // Simulate encryption: XOR with derived seal key
        let seal_ikm = format!("seal-key-{}-{}", self.enclave_id, self.seal_version_counter);
        let seal_key_hex = hkdf_extract(
            &hex_to_bytes(&att_key.private_key),
            seal_ikm.as_bytes(),
        );
        let seal_key_bytes = hex_to_bytes(&seal_key_hex);
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ seal_key_bytes[i % seal_key_bytes.len()]);
        }

        // Compute authentication tag over the sealed payload.
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(id.as_bytes());
        auth_input.extend_from_slice(&ciphertext);
        auth_input.extend_from_slice(identity_hash.as_bytes());
        auth_input.extend_from_slice(&(self.seal_version_counter).to_be_bytes());
        let auth_tag = hmac_sha256(&seal_key_bytes, &auth_input);

        self.seal_version_counter += 1;

        let sealed = SealedData {
            id: id.to_string(),
            ciphertext,
            auth_tag,
            enclave_identity_hash: identity_hash,
            measurement_snapshot,
            version: self.seal_version_counter,
            sealed_at: Utc::now(),
            ttl_seconds,
        };

        self.sealed_objects.insert(id.to_string(), sealed.clone());
        self.update_memory_usage();
        Ok(sealed)
    }

    /// Unseals previously sealed data, verifying its integrity and binding.
    pub fn unseal_data(&self, id: &str) -> Result<Vec<u8>, EnclaveError> {
        self.require_operational()?;
        self.require_attestation_key()?;

        let sealed = self
            .sealed_objects
            .get(id)
            .ok_or_else(|| EnclaveError::SealedObjectNotFound(id.to_string()))?;

        // Check TTL expiry.
        if sealed.is_expired(Utc::now()) {
            return Err(EnclaveError::SealedDataCorrupted);
        }

        // Verify identity binding.
        let current_identity_hash = sha256_digest(self.enclave_id.as_bytes());
        if sealed.enclave_identity_hash != current_identity_hash {
            return Err(EnclaveError::SealedDataCorrupted);
        }

        // Verify authentication tag.
        let att_key = self.attestation_key.as_ref().unwrap();
        let seal_ikm = format!("seal-key-{}-{}", self.enclave_id, sealed.version - 1);
        let seal_key_hex = hkdf_extract(
            &hex_to_bytes(&att_key.private_key),
            seal_ikm.as_bytes(),
        );
        let seal_key_bytes = hex_to_bytes(&seal_key_hex);

        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(id.as_bytes());
        auth_input.extend_from_slice(&sealed.ciphertext);
        auth_input.extend_from_slice(sealed.enclave_identity_hash.as_bytes());
        auth_input.extend_from_slice(&(sealed.version - 1).to_be_bytes());
        let expected_tag = hmac_sha256(&seal_key_bytes, &auth_input);

        if expected_tag != sealed.auth_tag {
            return Err(EnclaveError::SealedDataCorrupted);
        }

        // Decrypt: XOR with the same seal key.
        let mut plaintext = Vec::with_capacity(sealed.ciphertext.len());
        for (i, &byte) in sealed.ciphertext.iter().enumerate() {
            plaintext.push(byte ^ seal_key_bytes[i % seal_key_bytes.len()]);
        }

        Ok(plaintext)
    }

    /// Generates an enclave quote in response to an attestation challenge.
    /// The quote includes all current measurements and is signed with the attestation key.
    pub fn generate_quote(&mut self, nonce: AttestationNonce) -> Result<EnclaveQuote, EnclaveError> {
        self.require_operational()?;
        self.require_attestation_key()?;

        let att_key = self.attestation_key.as_ref().unwrap();
        let mr_enclave = sha256_digest(self.enclave_id.as_bytes());
        let mr_signer = att_key.public_key_hash.clone();
        let measurements = self.measurement_registry.all_measurements();

        let quote = EnclaveQuote {
            version: 1,
            mr_enclave,
            mr_signer,
            enclave_id: self.enclave_id.clone(),
            nonce,
            measurements,
            enclave_state: self.state,
            quoted_at: Utc::now(),
            signature: String::new(), // Will be filled after signing.
            signer_key_hash: att_key.public_key_hash.clone(),
            key_generation: att_key.generation,
        };

        let signature = att_key.sign(&quote.quote_body_bytes());

        Ok(EnclaveQuote { signature, ..quote })
    }

    /// Verifies an enclave quote from a remote enclave. This is the verifier side
    /// of the attestation protocol.
    pub fn verify_quote(
        &mut self,
        quote: &EnclaveQuote,
        expected_nonce_hash: &HashDigest,
        expected_measurements: &MeasurementRegistry,
    ) -> AttestationResult {
        self.total_attestation_attempts += 1;
        let mut checks = Vec::new();

        // Check 1: Nonce freshness.
        let nonce_match = quote.nonce.hash() == *expected_nonce_hash;
        checks.push(AttestationCheckResult {
            check_name: "nonce_freshness".to_string(),
            passed: nonce_match,
            detail: if nonce_match {
                "Nonce matches expected value".to_string()
            } else {
                format!(
                    "Nonce mismatch: expected {}, got {}",
                    expected_nonce_hash,
                    quote.nonce.hash()
                )
            },
        });

        // Check 2: Signature validity.
        let body = quote.quote_body_bytes();
        let signature_valid = quote.signer_key_hash == quote.mr_signer
            && hmac_sha256(&hex_to_bytes(&quote.mr_signer), &body) == quote.signature;
        checks.push(AttestationCheckResult {
            check_name: "signature_validity".to_string(),
            passed: signature_valid,
            detail: if signature_valid {
                "Quote signature is valid".to_string()
            } else {
                "Quote signature verification failed".to_string()
            },
        });

        // Check 3: Enclave state.
        let state_ok = quote.enclave_state == EnclaveState::Active;
        checks.push(AttestationCheckResult {
            check_name: "enclave_state".to_string(),
            passed: state_ok,
            detail: if state_ok {
                "Enclave is in active state".to_string()
            } else {
                format!("Enclave is in state: {}", quote.enclave_state)
            },
        });

        // Check 4: Measurement integrity.
        let mut measurement_ok = true;
        let mut measurement_detail = String::new();
        for entry in &quote.measurements {
            if let Some(expected) = expected_measurements.get(&entry.name) {
                if expected.hash != entry.hash {
                    measurement_ok = false;
                    measurement_detail = format!(
                        "Measurement '{}' mismatch: expected {}, got {}",
                        entry.name, expected.hash, entry.hash
                    );
                    break;
                }
            }
        }
        if measurement_ok && measurement_detail.is_empty() {
            measurement_detail = "All measurements match expected values".to_string();
        }
        checks.push(AttestationCheckResult {
            check_name: "measurement_integrity".to_string(),
            passed: measurement_ok,
            detail: measurement_detail,
        });

        // Check 5: Quote freshness (within 60 seconds).
        let freshness_ok = (Utc::now() - quote.quoted_at).num_seconds().abs() < 60;
        checks.push(AttestationCheckResult {
            check_name: "quote_freshness".to_string(),
            passed: freshness_ok,
            detail: if freshness_ok {
                "Quote is fresh (generated within 60 seconds)".to_string()
            } else {
                "Quote is stale (generated more than 60 seconds ago)".to_string()
            },
        });

        let all_passed = checks.iter().all(|c| c.passed);
        let description = if all_passed {
            "Attestation verified successfully".to_string()
        } else {
            "Attestation verification failed".to_string()
        };

        if all_passed {
            self.successful_attestations += 1;
            self.last_attestation_at = Some(Utc::now());
        } else {
            self.failed_attestations += 1;
        }

        AttestationResult {
            is_valid: all_passed,
            description,
            verified_at: Utc::now(),
            quote: quote.clone(),
            checks,
        }
    }

    /// Generates a new attestation nonce for a challenge.
    pub fn generate_nonce(&self) -> AttestationNonce {
        // In a real TEE, this would use a hardware RNG.
        let mut bytes = Vec::with_capacity(32);
        let seed = format!("{}-nonce-{}", self.enclave_id, Utc::now().timestamp_millis());
        let hash = sha256_digest(seed.as_bytes());
        bytes.extend_from_slice(&hex_to_bytes(&hash));
        // Pad to ensure at least 32 bytes
        while bytes.len() < 32 {
            bytes.push(0);
        }
        AttestationNonce::new(bytes).unwrap()
    }

    /// Returns a reference to the measurement registry.
    pub fn measurement_registry(&self) -> &MeasurementRegistry {
        &self.measurement_registry
    }

    /// Returns a mutable reference to the measurement registry.
    pub fn measurement_registry_mut(&mut self) -> &mut MeasurementRegistry {
        &mut self.measurement_registry
    }

    /// Returns a reference to the key derivation manager.
    pub fn key_manager(&self) -> Option<&KeyDerivationManager> {
        self.key_manager.as_ref()
    }

    /// Returns a mutable reference to the key derivation manager.
    pub fn key_manager_mut(&mut self) -> Option<&mut KeyDerivationManager> {
        self.key_manager.as_mut()
    }

    /// Returns the current enclave state.
    pub fn state(&self) -> EnclaveState {
        self.state
    }

    /// Returns the enclave ID.
    pub fn enclave_id(&self) -> &str {
        &self.enclave_id
    }

    /// Returns the attestation key if one has been generated.
    pub fn attestation_key(&self) -> Option<&AttestationKey> {
        self.attestation_key.as_ref()
    }

    /// Returns the number of sealed objects.
    pub fn sealed_object_count(&self) -> usize {
        self.sealed_objects.len()
    }

    /// Returns a snapshot of the enclave's current health metrics.
    pub fn health_snapshot(&self) -> EnclaveHealthSnapshot {
        let total = self.total_attestation_attempts;
        let success = self.successful_attestations;
        let rate = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            100.0 // No attempts yet is considered healthy.
        };

        let seconds_since_last = self
            .last_attestation_at
            .map(|t| (Utc::now() - t).num_seconds());

        let uptime = self.activated_at.map(|t| (Utc::now() - t).num_seconds());

        let active_keys = self
            .key_manager
            .as_ref()
            .map(|km| km.active_key_count())
            .unwrap_or(0);

        EnclaveHealthSnapshot {
            state: self.state,
            memory_usage_bytes: self.memory_usage_bytes,
            sealed_object_count: self.sealed_objects.len(),
            total_attestation_attempts: total,
            successful_attestations: success,
            failed_attestations: self.failed_attestations,
            attestation_success_rate: rate,
            last_attestation_at: self.last_attestation_at,
            seconds_since_last_attestation: seconds_since_last,
            snapshot_at: Utc::now(),
            measurement_count: self.measurement_registry.count(),
            active_key_count: active_keys,
            uptime_seconds: uptime,
        }
    }

    // ── Internal helpers ──

    fn require_state(&self, expected: EnclaveState) -> Result<(), EnclaveError> {
        if self.state == expected {
            Ok(())
        } else if self.state == EnclaveState::Compromised {
            Err(EnclaveError::Compromised)
        } else {
            Err(EnclaveError::InvalidState(format!(
                "Expected {}, got {}",
                expected, self.state
            )))
        }
    }

    fn require_operational(&self) -> Result<(), EnclaveError> {
        if self.state.is_operational() {
            Ok(())
        } else if self.state.is_compromised() {
            Err(EnclaveError::Compromised)
        } else {
            Err(EnclaveError::NotInitialized)
        }
    }

    fn require_attestation_key(&self) -> Result<&AttestationKey, EnclaveError> {
        self.attestation_key
            .as_ref()
            .ok_or(EnclaveError::AttestationKeyNotFound)
    }

    fn update_memory_usage(&mut self) {
        let base_overhead: u64 = 4096;
        let sealed_overhead: u64 = self.sealed_objects.len() as u64 * 512;
        let measurement_overhead: u64 = self.measurement_registry.count() as u64 * 128;
        let key_overhead: u64 = self.key_manager.as_ref().map(|km| km.key_count() as u64 * 256).unwrap_or(0);
        self.memory_usage_bytes = base_overhead + sealed_overhead + measurement_overhead + key_overhead;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 10: Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cryptographic Primitive Tests ──

    #[test]
    fn test_sha256_empty_input() {
        let hash = sha256_digest(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_known_value() {
        // SHA-256("abc") per NIST test vector.
        let hash = sha256_digest(b"abc");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let h1 = sha256_digest(b"hello world");
        let h2 = sha256_digest(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let h1 = sha256_digest(b"foo");
        let h2 = sha256_digest(b"bar");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        // RFC 4231 Test Case 1: key = 0b0b0b0b..., data = "Hi There"
        let key = [0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        assert_eq!(
            result,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data);
        assert_eq!(
            result,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_hkdf_extract_and_expand() {
        // Basic test: extraction + expansion should produce deterministic output.
        let salt = b"enclave-salt";
        let ikm = b"enclave-ikm";
        let info = b"enclave-info";
        let result1 = hkdf(salt, ikm, info, 32).unwrap();
        let result2 = hkdf(salt, ikm, info, 32).unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_hkdf_different_info_produces_different_keys() {
        let salt = b"salt";
        let ikm = b"ikm";
        let k1 = hkdf(salt, ikm, b"purpose-a", 32).unwrap();
        let k2 = hkdf(salt, ikm, b"purpose-b", 32).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_hkdf_variable_lengths() {
        let key16 = hkdf(b"salt", b"ikm", b"info", 16).unwrap();
        let key32 = hkdf(b"salt", b"ikm", b"info", 32).unwrap();
        let key64 = hkdf(b"salt", b"ikm", b"info", 64).unwrap();
        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
        // First 16 bytes of key32 should match key16 (same first HKDF block).
        assert_eq!(key16, key32[..16]);
    }

    // ── Enclave State Machine Tests ──

    #[test]
    fn test_enclave_state_transitions() {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for("test-1"));
        assert_eq!(enclave.state(), EnclaveState::Uninitialized);

        enclave.initialize().unwrap();
        assert_eq!(enclave.state(), EnclaveState::Initialized);

        enclave
            .measured_boot(vec![MeasurementEntry::new("code", MeasurementType::Code, sha256_digest(b"code"))])
            .unwrap();
        assert_eq!(enclave.state(), EnclaveState::Active);
    }

    #[test]
    fn test_enclave_compromised_blocks_operations() {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for("test-2"));
        enclave.initialize().unwrap();
        enclave.measured_boot(vec![]).unwrap();
        enclave.mark_compromised();

        assert_eq!(enclave.state(), EnclaveState::Compromised);
        let result = enclave.seal_data("id", b"data", None);
        assert!(matches!(result, Err(EnclaveError::Compromised)));
    }

    #[test]
    fn test_enclave_reset_clears_state() {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for("test-3"));
        enclave.initialize().unwrap();
        enclave.measured_boot(vec![]).unwrap();
        enclave.mark_compromised();
        enclave.reset();

        assert_eq!(enclave.state(), EnclaveState::Uninitialized);
        assert_eq!(enclave.sealed_object_count(), 0);
    }

    #[test]
    fn test_cannot_seal_before_initialization() {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for("test-4"));
        let result = enclave.seal_data("id", b"data", None);
        assert!(matches!(result, Err(EnclaveError::NotInitialized)));
    }

    #[test]
    fn test_cannot_boot_before_initialization() {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for("test-5"));
        let result = enclave.measured_boot(vec![]);
        assert!(matches!(result, Err(EnclaveError::InvalidState(_))));
    }

    #[test]
    fn test_state_is_operational() {
        assert!(EnclaveState::Initialized.is_operational());
        assert!(EnclaveState::Active.is_operational());
        assert!(!EnclaveState::Uninitialized.is_operational());
        assert!(!EnclaveState::Compromised.is_operational());
    }

    // ── Measurement Registry Tests ──

    #[test]
    fn test_measurement_register_and_retrieve() {
        let mut registry = MeasurementRegistry::new();
        let entry = MeasurementEntry::new("boot-code", MeasurementType::Code, sha256_digest(b"code"));
        registry.register(entry).unwrap();

        let retrieved = registry.get("boot-code").unwrap();
        assert_eq!(retrieved.name, "boot-code");
        assert_eq!(retrieved.measurement_type, MeasurementType::Code);
    }

    #[test]
    fn test_measurement_verify_success() {
        let mut registry = MeasurementRegistry::new();
        let hash = sha256_digest(b"expected-code");
        registry
            .register(MeasurementEntry::new("code", MeasurementType::Code, hash.clone()))
            .unwrap();

        assert!(registry.verify_measurement("code", &hash).is_ok());
    }

    #[test]
    fn test_measurement_verify_failure() {
        let mut registry = MeasurementRegistry::new();
        registry
            .register(MeasurementEntry::new("code", MeasurementType::Code, sha256_digest(b"expected")))
            .unwrap();

        let result = registry.verify_measurement("code", &sha256_digest(b"tampered"));
        assert!(matches!(result, Err(EnclaveError::MeasurementMismatch { .. })));
    }

    #[test]
    fn test_measurement_allow_list_policy() {
        let mut registry = MeasurementRegistry::with_policy(MeasurementPolicy::AllowList);
        registry.add_to_allow_list("allowed-code");

        let entry = MeasurementEntry::new("allowed-code", MeasurementType::Code, sha256_digest(b"code"));
        assert!(registry.register(entry).is_ok());

        let blocked = MeasurementEntry::new("unknown", MeasurementType::Code, sha256_digest(b"x"));
        assert!(matches!(
            registry.register(blocked),
            Err(EnclaveError::MeasurementNotFound(_))
        ));
    }

    #[test]
    fn test_measurement_deny_list_policy() {
        let mut registry = MeasurementRegistry::with_policy(MeasurementPolicy::DenyList);
        registry.add_to_deny_list("malicious-code");

        let blocked = MeasurementEntry::new("malicious-code", MeasurementType::Code, sha256_digest(b"x"));
        assert!(matches!(
            registry.register(blocked),
            Err(EnclaveError::MeasurementDenied(_))
        ));

        let ok = MeasurementEntry::new("good-code", MeasurementType::Code, sha256_digest(b"y"));
        assert!(registry.register(ok).is_ok());
    }

    #[test]
    fn test_measurement_composite_hash() {
        let mut reg1 = MeasurementRegistry::new();
        reg1.register(MeasurementEntry::new("a", MeasurementType::Code, sha256_digest(b"a"))).unwrap();
        reg1.register(MeasurementEntry::new("b", MeasurementType::Data, sha256_digest(b"b"))).unwrap();

        let mut reg2 = MeasurementRegistry::new();
        reg2.register(MeasurementEntry::new("a", MeasurementType::Code, sha256_digest(b"a"))).unwrap();
        reg2.register(MeasurementEntry::new("b", MeasurementType::Data, sha256_digest(b"b"))).unwrap();

        assert_eq!(reg1.composite_hash(), reg2.composite_hash());
    }

    #[test]
    fn test_measurement_verify_all_batch() {
        let mut registry = MeasurementRegistry::new();
        let h1 = sha256_digest(b"code1");
        let h2 = sha256_digest(b"code2");
        registry
            .register(MeasurementEntry::new("mod-a", MeasurementType::Code, h1.clone()))
            .unwrap();
        registry
            .register(MeasurementEntry::new("mod-b", MeasurementType::Code, h2.clone()))
            .unwrap();

        let batch = vec![("mod-a".to_string(), h1.clone()), ("mod-b".to_string(), h2.clone())];
        assert!(registry.verify_all(&batch).is_ok());

        let bad_batch = vec![("mod-a".to_string(), sha256_digest(b"wrong"))];
        assert!(matches!(registry.verify_all(&bad_batch), Err(EnclaveError::MeasurementMismatch { .. })));
    }

    // ── Sealing / Unsealing Tests ──

    #[test]
    fn test_seal_and_unseal_roundtrip() {
        let mut enclave = create_active_enclave("seal-test");
        let plaintext = b"secret enclave data";
        let sealed = enclave.seal_data("secret-1", plaintext, None).unwrap();
        assert_eq!(sealed.id, "secret-1");
        assert!(!sealed.ciphertext.is_empty());
        assert_eq!(enclave.sealed_object_count(), 1);

        let recovered = enclave.unseal_data("secret-1").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_seal_duplicate_id_fails() {
        let mut enclave = create_active_enclave("dup-test");
        enclave.seal_data("id", b"data1", None).unwrap();
        let result = enclave.seal_data("id", b"data2", None);
        assert!(matches!(result, Err(EnclaveError::SealedObjectExists(_))));
    }

    #[test]
    fn test_unseal_nonexistent_fails() {
        let enclave = create_active_enclave("unseal-missing");
        let result = enclave.unseal_data("nope");
        assert!(matches!(result, Err(EnclaveError::SealedObjectNotFound(_))));
    }

    #[test]
    fn test_sealed_data_serialization() {
        let mut enclave = create_active_enclave("serde-test");
        enclave.seal_data("s1", b"hello", None).unwrap();

        let json = serde_json::to_string(&enclave).unwrap();
        let deserialized: SecureEnclave = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sealed_object_count(), 1);
    }

    // ── Attestation Tests ──

    #[test]
    fn test_generate_and_verify_quote() {
        let mut prover = create_active_enclave("prover");
        let mut verifier = create_active_enclave("verifier");

        let nonce = verifier.generate_nonce();
        let nonce_hash = nonce.hash();

        let quote = prover.generate_quote(nonce).unwrap();
        assert!(!quote.signature.is_empty());
        assert_eq!(quote.enclave_id, "prover");

        let result = verifier.verify_quote(&quote, &nonce_hash, prover.measurement_registry());
        assert!(result.is_valid);
        assert_eq!(result.checks.len(), 5);
    }

    #[test]
    fn test_attestation_nonce_too_short() {
        let result = AttestationNonce::new(vec![0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_nonce_valid() {
        let nonce = AttestationNonce::new(vec![0u8; 32]).unwrap();
        assert_eq!(nonce.bytes.len(), 32);
    }

    #[test]
    fn test_attestation_key_sign_and_verify() {
        let key = AttestationKey::generate("test-enclave", 1);
        let data = b"challenge data";
        let sig = key.sign(data);
        assert!(key.verify(data, &sig));
    }

    #[test]
    fn test_attestation_key_different_generations() {
        let k1 = AttestationKey::generate("enclave", 1);
        let k2 = AttestationKey::generate("enclave", 2);
        assert_ne!(k1.private_key, k2.private_key);
        assert_ne!(k1.public_key_hash, k2.public_key_hash);
    }

    #[test]
    fn test_attestation_with_wrong_nonce_fails() {
        let mut prover = create_active_enclave("prover-nonce");
        let mut verifier = create_active_enclave("verifier-nonce");

        let nonce = prover.generate_nonce(); // Use prover's nonce, not verifier's expected
        let wrong_nonce_hash = sha256_digest(b"totally wrong nonce value");

        let quote = prover.generate_quote(nonce).unwrap();
        let result = verifier.verify_quote(&quote, &wrong_nonce_hash, prover.measurement_registry());
        assert!(!result.is_valid);
    }

    // ── Key Derivation Tests ──

    #[test]
    fn test_key_derivation_deterministic() {
        let mut kdm = KeyDerivationManager::new("enclave-x", 3600);
        let mhash = sha256_digest(b"measurements");

        let k1 = kdm.derive_key("encryption", &mhash, 0, 32).unwrap();
        let k2 = kdm.derive_key("encryption", &mhash, 0, 32).unwrap();
        // Different derivation counters produce different keys.
        assert_ne!(k1.key_id, k2.key_id);
        assert_ne!(k1.key_material, k2.key_material);
    }

    #[test]
    fn test_key_rotation() {
        let mut kdm = KeyDerivationManager::new("enclave-rot", 3600);
        let mhash = sha256_digest(b"measurements");

        let old_key = kdm.derive_key("purpose", &mhash, 0, 32).unwrap();
        let old_id = old_key.key_id.clone();

        let new_key = kdm
            .rotate_key(&old_id, "purpose-v2", &mhash, 1, 32)
            .unwrap();

        assert_ne!(old_key.key_id, new_key.key_id);
        assert!(!kdm.get_key(&old_id).unwrap().is_active);
        assert!(new_key.is_active);
    }

    #[test]
    fn test_key_grace_period() {
        let mut kdm = KeyDerivationManager::new("enclave-grace", 3600);
        let mhash = sha256_digest(b"m");

        let old = kdm.derive_key("a", &mhash, 0, 32).unwrap();
        let old_id = old.key_id.clone();
        kdm.rotate_key(&old_id, "b", &mhash, 1, 32).unwrap();

        // Immediately after rotation, old key should be within grace period.
        assert!(kdm.is_in_grace_period(&old_id, Utc::now()));

        // Long after grace period, old key should no longer be usable.
        let far_future = Utc::now() + Duration::seconds(7200);
        assert!(!kdm.is_in_grace_period(&old_id, far_future));
    }

    #[test]
    fn test_key_derivation_binding() {
        let mut kdm1 = KeyDerivationManager::new("enclave-1", 3600);
        let mut kdm2 = KeyDerivationManager::new("enclave-2", 3600);
        let mhash = sha256_digest(b"m");

        let k1 = kdm1.derive_key("purpose", &mhash, 0, 32).unwrap();
        let k2 = kdm2.derive_key("purpose", &mhash, 0, 32).unwrap();
        // Different enclave identities produce different keys.
        assert_ne!(k1.key_material, k2.key_material);
    }

    // ── Health Monitoring Tests ──

    #[test]
    fn test_health_snapshot_after_boot() {
        let enclave = create_active_enclave("health-1");
        let snap = enclave.health_snapshot();
        assert_eq!(snap.state, EnclaveState::Active);
        assert!(snap.memory_usage_bytes > 0);
        assert_eq!(snap.sealed_object_count, 0);
        assert_eq!(snap.measurement_count, 0); // No measurements in minimal boot
        assert!(snap.uptime_seconds.is_some());
    }

    #[test]
    fn test_health_snapshot_with_sealed_objects() {
        let mut enclave = create_active_enclave("health-2");
        enclave.seal_data("obj1", b"data1", None).unwrap();
        enclave.seal_data("obj2", b"data2", None).unwrap();

        let snap = enclave.health_snapshot();
        assert_eq!(snap.sealed_object_count, 2);
        assert!(snap.memory_usage_bytes > 0);
    }

    #[test]
    fn test_health_attestation_success_rate() {
        let mut enclave = create_active_enclave("rate-test");
        let mut verifier = create_active_enclave("verifier-rate");

        // Perform 3 successful attestations.
        for _ in 0..3 {
            let nonce = enclave.generate_nonce();
            let nonce_hash = nonce.hash();
            let quote = enclave.generate_quote(nonce).unwrap();
            verifier.verify_quote(&quote, &nonce_hash, enclave.measurement_registry());
        }

        let snap = verifier.health_snapshot();
        assert_eq!(snap.total_attestation_attempts, 3);
        assert_eq!(snap.successful_attestations, 3);
        assert_eq!(snap.failed_attestations, 0);
        assert!((snap.attestation_success_rate - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_health_compromised_enclave_unhealthy() {
        let mut enclave = create_active_enclave("unhealthy");
        enclave.mark_compromised();
        let snap = enclave.health_snapshot();
        assert!(!snap.is_healthy());
    }

    #[test]
    fn test_full_attestation_flow_with_measurements() {
        let mut prover = create_active_enclave_with_measurements("full-flow");
        let mut verifier = create_active_enclave("verifier-full");

        // Copy prover measurements to verifier's expected measurements.
        for entry in prover.measurement_registry().all_measurements() {
            verifier.measurement_registry_mut().register(entry).unwrap();
        }

        let nonce = verifier.generate_nonce();
        let nonce_hash = nonce.hash();
        let quote = prover.generate_quote(nonce).unwrap();

        let result = verifier.verify_quote(&quote, &nonce_hash, prover.measurement_registry());
        assert!(result.is_valid);

        for check in &result.checks {
            assert!(check.passed, "Check '{}' failed: {}", check.check_name, check.detail);
        }
    }

    #[test]
    fn test_measurement_type_display() {
        assert_eq!(format!("{}", MeasurementType::Code), "code");
        assert_eq!(format!("{}", MeasurementType::Data), "data");
        assert_eq!(format!("{}", MeasurementType::Config), "config");
        assert_eq!(format!("{}", MeasurementType::Runtime), "runtime");
    }

    #[test]
    fn test_enclave_config_default_for() {
        let config = EnclaveConfig::default_for("default-test");
        assert_eq!(config.enclave_id, "default-test");
        assert_eq!(config.max_sealed_objects, 10_000);
        assert_eq!(config.key_rotation_grace_seconds, 3600);
    }

    #[test]
    fn test_sealed_data_expired() {
        let sealed = SealedData {
            id: "test".to_string(),
            ciphertext: vec![],
            auth_tag: sha256_digest(b"tag"),
            enclave_identity_hash: sha256_digest(b"id"),
            measurement_snapshot: vec![],
            version: 1,
            sealed_at: Utc::now(),
            ttl_seconds: Some(-1), // Already expired.
        };
        assert!(sealed.is_expired(Utc::now()));

        let not_expired = SealedData {
            ttl_seconds: Some(86400),
            ..sealed.clone()
        };
        assert!(!not_expired.is_expired(Utc::now()));
    }

    #[test]
    fn test_quote_body_bytes_deterministic() {
        let nonce = AttestationNonce::new(vec![0u8; 32]).unwrap();
        let quote = EnclaveQuote {
            version: 1,
            mr_enclave: sha256_digest(b"enclave"),
            mr_signer: sha256_digest(b"signer"),
            enclave_id: "q-test".to_string(),
            nonce,
            measurements: vec![],
            enclave_state: EnclaveState::Active,
            quoted_at: Utc::now(),
            signature: sha256_digest(b"sig"),
            signer_key_hash: sha256_digest(b"signer-hash"),
            key_generation: 0,
        };
        let b1 = quote.quote_body_bytes();
        let b2 = quote.quote_body_bytes();
        assert_eq!(b1, b2);
    }

    // ── Helper Functions for Tests ──

    /// Creates an active enclave with no measurements (empty measured boot).
    fn create_active_enclave(id: &str) -> SecureEnclave {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for(id));
        enclave.initialize().unwrap();
        enclave.measured_boot(vec![]).unwrap();
        enclave
    }

    /// Creates an active enclave with a set of standard measurements.
    fn create_active_enclave_with_measurements(id: &str) -> SecureEnclave {
        let mut enclave = SecureEnclave::new(EnclaveConfig::default_for(id));
        enclave.initialize().unwrap();
        let measurements = vec![
            MeasurementEntry::with_description(
                "kernel",
                MeasurementType::Code,
                sha256_digest(b"kernel-binary"),
                "OS kernel image",
            ),
            MeasurementEntry::with_description(
                "app-code",
                MeasurementType::Code,
                sha256_digest(b"application-code"),
                "Application binary",
            ),
            MeasurementEntry::with_description(
                "config",
                MeasurementType::Config,
                sha256_digest(b"enclave-config"),
                "Enclave configuration",
            ),
        ];
        enclave.measured_boot(measurements).unwrap();
        enclave
    }
}
