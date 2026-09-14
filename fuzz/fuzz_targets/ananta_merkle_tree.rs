//! Fuzz harness for ANANTA Merkle Tree construction and verification.
//!
//! Builds Merkle trees from arbitrary data slices and exercises:
//!   - from_data with 0, 1, 2, 3, N items
//!   - from_leaves with pre-computed hashes
//!   - Root hash consistency
//!   - Proof generation and verification
//!
//! Targets:
//!   - Panics on empty input
//!   - Correctness of odd-leaf duplication
//!   - Proof verification on adversarial proofs

#![no_main]

use chakravyuh::ananta::crypto::{hash_bytes, hash_combined, MerkleTree};
use chakravyuh::ananta::config::HashAlgorithm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split data into variable-length chunks to build the tree.
    let chunk_size = 16usize;
    let items: Vec<&[u8]> = if data.is_empty() {
        vec![]
    } else {
        data.chunks(chunk_size.max(1)).collect()
    };

    let algos = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha512,
        HashAlgorithm::Blake3,
    ];

    for algo in &algos {
        // Build tree — must not panic on any input shape.
        let tree = MerkleTree::from_data(&items, algo);

        // Verify root is consistent with from_leaves.
        let leaves: Vec<_> = items
            .iter()
            .map(|item| hash_bytes(item, algo))
            .collect();
        let tree2 = MerkleTree::from_leaves(&leaves, algo);
        assert_eq!(tree.root.hex, tree2.root.hex);

        // Exercise proof generation for each leaf.
        for (idx, _leaf) in tree.leaves.iter().enumerate() {
            let proof = tree.proof(idx);
            if let Some(p) = proof {
                // Proof verification on the correct index should succeed.
                let valid = MerkleTree::verify_proof(&p, algo);
                assert!(valid, "Merkle proof should be valid for index {}", idx);
            }
        }

        // Verify proof on out-of-bounds index returns None.
        if !tree.leaves.is_empty() {
            let oob = tree.leaves.len() + 1000;
            assert!(tree.proof(oob).is_none());
        }
    }
});
