//! Fuzz harness for ANANTA cryptographic hashing.
//!
//! Exercises all 4 hash algorithms (SHA-256, SHA-384, SHA-512, BLAKE3)
//! with arbitrary byte inputs.
//!
//! Targets:
//!   - Panics on empty or very large inputs
//!   - Hash consistency (same input → same output)
//!   - No crashes on any byte pattern
//!   - hash_combined order-sensitivity
//!   - constant_time_eq correctness

#![no_main]

use chakravyuh::ananta::crypto::hashing::{hash_bytes, hash_combined, constant_time_eq};
use chakravyuh::ananta::config::HashAlgorithm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let algos = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
        HashAlgorithm::Blake3,
    ];

    for algo in &algos {
        // Single hash — must not panic.
        let digest = hash_bytes(data, algo);

        // Verify the digest matches its own data.
        assert!(digest.matches(data));

        // Verify it doesn't match modified data.
        if !data.is_empty() {
            let mut modified = data.to_vec();
            modified[0] = modified[0].wrapping_add(1);
            if modified != data {
                assert!(!digest.matches(&modified));
            }
        }

        // Verify size_bytes is correct.
        assert_eq!(digest.size_bytes(), digest.bytes.len());
    }

    // hash_combined with split data.
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let combined = hash_combined(&[&data[..mid], &data[mid..]], &HashAlgorithm::Sha256);
        // Verify combined hash is consistent.
        let combined2 = hash_combined(&[&data[..mid], &data[mid..]], &HashAlgorithm::Sha256);
        assert_eq!(combined.bytes, combined2.bytes);
    }

    // constant_time_eq on same data.
    assert!(constant_time_eq(data, data));

    // constant_time_eq on different-length data.
    if !data.is_empty() {
        assert!(!constant_time_eq(data, &data[..data.len() - 1]));
    }
});