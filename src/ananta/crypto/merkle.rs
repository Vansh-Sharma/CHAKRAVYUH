// Merkle Tree — for efficient integrity verification of large data sets.
//
// Used by:
//   - Anchor: verifying the integrity manifest (all binaries, configs, policies)
//   - Trust Proof Engine: compact proof that N items are unchanged
//   - Audit: compact proof of log integrity

use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::{hash_bytes, hash_combined, HashDigest};
use serde::{Deserialize, Serialize};

/// A Merkle tree built from a list of data items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub algorithm: HashAlgorithm,
    /// Leaf hashes (one per item).
    pub leaves: Vec<HashDigest>,
    /// Internal node hashes (bottom-up, left to right).
    pub nodes: Vec<HashDigest>,
    /// The root hash — the single proof of integrity for all leaves.
    pub root: HashDigest,
}

impl MerkleTree {
    /// Build a Merkle tree from data items.
    /// Each item is hashed to produce a leaf.
    pub fn from_data(items: &[&[u8]], algorithm: &HashAlgorithm) -> Self {
        let leaves: Vec<HashDigest> = items
            .iter()
            .map(|item| hash_bytes(item, algorithm))
            .collect();
        Self::from_leaves(&leaves, algorithm)
    }

    /// Build from pre-computed leaf hashes.
    pub fn from_leaves(leaves: &[HashDigest], algorithm: &HashAlgorithm) -> Self {
        if leaves.is_empty() {
            let empty = hash_bytes(b"empty_merkle_tree", algorithm);
            return Self {
                algorithm: algorithm.clone(),
                leaves: vec![],
                nodes: vec![],
                root: empty,
            };
        }

        if leaves.len() == 1 {
            return Self {
                algorithm: algorithm.clone(),
                leaves: leaves.to_vec(),
                nodes: vec![],
                root: leaves[0].clone(),
            };
        }

        let mut current_level: Vec<HashDigest> = leaves.to_vec();
        let mut all_nodes: Vec<HashDigest> = vec![];

        while current_level.len() > 1 {
            let mut next_level: Vec<HashDigest> = vec![];
            let mut i = 0;

            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    // Hash(left || right)
                    let combined = hash_combined(
                        &[&current_level[i].bytes, &current_level[i + 1].bytes],
                        algorithm,
                    );
                    next_level.push(combined);
                    all_nodes.push(current_level[i].clone());
                    all_nodes.push(current_level[i + 1].clone());
                    i += 2;
                } else {
                    // Odd node: duplicate (standard Merkle tree approach)
                    let combined = hash_combined(
                        &[&current_level[i].bytes, &current_level[i].bytes],
                        algorithm,
                    );
                    next_level.push(combined);
                    all_nodes.push(current_level[i].clone());
                    i += 1;
                }
            }

            current_level = next_level;
        }

        let root = current_level.into_iter().next().unwrap();
        Self {
            algorithm: algorithm.clone(),
            leaves: leaves.to_vec(),
            nodes: all_nodes,
            root,
        }
    }

    /// Generate a Merkle proof for a specific leaf index.
    /// Returns the sibling hashes needed to reconstruct the root.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut path: Vec<(HashDigest, bool)> = vec![]; // (hash, is_right_sibling)

        // Rebuild the tree level by level, collecting siblings.
        // Owned hashes at each level to avoid lifetime issues.
        let mut current: Vec<HashDigest> = self.leaves.clone();
        let mut idx = index;

        while current.len() > 1 {
            let mut next: Vec<HashDigest> = vec![];
            let mut i = 0;
            let mut new_idx = 0;

            while i < current.len() {
                if i + 1 < current.len() {
                    if i == idx {
                        path.push((current[i + 1].clone(), true));
                        new_idx = next.len();
                    } else if i + 1 == idx {
                        path.push((current[i].clone(), false));
                        new_idx = next.len();
                    }
                    let combined =
                        hash_combined(&[&current[i].bytes, &current[i + 1].bytes], &self.algorithm);
                    next.push(combined);
                    i += 2;
                } else {
                    if i == idx {
                        path.push((current[i].clone(), true));
                        new_idx = next.len();
                    }
                    let combined =
                        hash_combined(&[&current[i].bytes, &current[i].bytes], &self.algorithm);
                    next.push(combined);
                    i += 1;
                }
            }

            current = next;
            idx = new_idx;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index].clone(),
            root_hash: self.root.clone(),
            path,
        })
    }

    /// Verify a Merkle proof returns the expected root.
    pub fn verify_proof(proof: &MerkleProof, algorithm: &HashAlgorithm) -> bool {
        let mut current = proof.leaf_hash.bytes.clone();

        for (sibling, is_right) in &proof.path {
            let combined = if *is_right {
                hash_combined(&[&current, &sibling.bytes], algorithm)
            } else {
                hash_combined(&[&sibling.bytes, &current], algorithm)
            };
            current = combined.bytes;
        }

        current == proof.root_hash.bytes
    }
}

/// A Merkle proof for a single leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: HashDigest,
    pub root_hash: HashDigest,
    /// Sibling hashes along the path to root.
    /// Each entry: (sibling_hash, is_right_sibling)
    pub path: Vec<(HashDigest, bool)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::from_data(&[b"only item"], &HashAlgorithm::Sha256);
        let expected = hash_bytes(b"only item", &HashAlgorithm::Sha256);
        assert_eq!(tree.root.bytes, expected.bytes);
    }

    #[test]
    fn two_leaf_tree() {
        let tree = MerkleTree::from_data(&[b"a", b"b"], &HashAlgorithm::Sha256);
        assert_eq!(tree.leaves.len(), 2);
        assert_ne!(tree.root.bytes, tree.leaves[0].bytes);
    }

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::from_data(&[], &HashAlgorithm::Sha256);
        // Empty tree has a deterministic root.
        let tree2 = MerkleTree::from_data(&[], &HashAlgorithm::Sha256);
        assert_eq!(tree.root.bytes, tree2.root.bytes);
    }

    #[test]
    fn tree_deterministic() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let t1 = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);
        let t2 = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);
        assert_eq!(t1.root.bytes, t2.root.bytes);
    }

    #[test]
    fn odd_number_of_leaves() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);
        assert_eq!(tree.leaves.len(), 3);
        // Should not panic.
        assert!(!tree.root.bytes.is_empty());
    }

    #[test]
    fn proof_verifies() {
        let data: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);

        for i in 0..4 {
            let proof = tree.proof(i).expect("proof exists");
            assert!(MerkleTree::verify_proof(&proof, &HashAlgorithm::Sha256));
        }
    }

    #[test]
    fn proof_detects_tampering() {
        let data: Vec<&[u8]> = vec![b"original1", b"original2", b"original3"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);

        let mut proof = tree.proof(1).expect("proof exists");
        // Tamper with the leaf hash.
        proof.leaf_hash = hash_bytes(b"tampered", &HashAlgorithm::Sha256);
        assert!(!MerkleTree::verify_proof(&proof, &HashAlgorithm::Sha256));
    }

    #[test]
    fn blake3_merkle() {
        let data: Vec<&[u8]> = vec![b"x", b"y", b"z", b"w"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Blake3);
        let proof = tree.proof(0).expect("proof exists");
        assert!(MerkleTree::verify_proof(&proof, &HashAlgorithm::Blake3));
    }
}
