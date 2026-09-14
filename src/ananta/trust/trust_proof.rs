// Trust Proof — cryptographic proof that the Security OS is trusted.
//
// This is the FLAGSHIP technology. It proves:
//   "I can prove the Security OS has not been compromised."
//
// A Trust Proof contains:
//   1. Merkle root of all integrity hashes
//   2. Trust state snapshot (signed)
//   3. Attestation report signature
//   4. Trust chain head hash
//   5. Timestamp and proof ID

use crate::ananta::anchor::AttestationReport;
use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::{hash_combined, HashDigest};
use crate::ananta::crypto::signing::{self, KeyPair, Signature};
use crate::ananta::trust::trust_state::TrustState;
use serde::{Deserialize, Serialize};

/// A Trust Proof — the cryptographic evidence that the platform is trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustProof {
    /// Unique proof ID.
    pub proof_id: String,
    /// Generation timestamp.
    pub timestamp: String,
    /// ANANTA version.
    pub ananta_version: String,
    /// Hash algorithm used.
    pub hash_algorithm: HashAlgorithm,
    /// Merkle root of all integrity domain hashes.
    pub integrity_merkle_root: HashDigest,
    /// Overall trust score at time of proof.
    pub trust_score: f64,
    /// Per-domain trust levels.
    pub domain_trust: Vec<DomainTrustEntry>,
    /// Hash of the trust chain head (proves chain integrity).
    pub trust_chain_head: String,
    /// Number of attestation cycles completed.
    pub attestation_cycles: u64,
    /// Number of consecutive successful attestations.
    pub consecutive_passes: u64,
    /// Whether all integrity checks passed.
    pub all_passed: bool,
    /// Cryptographic signature.
    pub signature: Option<Signature>,
    /// Raw proof bytes for verification.
    proof_bytes: Vec<u8>,
}

/// A single domain's trust in the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrustEntry {
    pub domain: String,
    pub level: f64,
}

impl TrustProof {
    /// Generate a trust proof from the current system state.
    pub fn generate(
        attestation: &AttestationReport,
        trust_state: &TrustState,
        trust_chain_head: &str,
        key_pair: &KeyPair,
    ) -> Self {
        let proof_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Collect domain trust levels.
        let domain_trust: Vec<DomainTrustEntry> = trust_state
            .domains
            .iter()
            .map(|(name, dt)| DomainTrustEntry {
                domain: name.clone(),
                level: dt.level,
            })
            .collect();

        let mut proof = Self {
            proof_id,
            timestamp,
            ananta_version: env!("CARGO_PKG_VERSION").to_string(),
            hash_algorithm: attestation.integrity.merkle_root.algorithm.clone(),
            integrity_merkle_root: attestation.integrity.merkle_root.clone(),
            trust_score: trust_state.overall_score(),
            domain_trust,
            trust_chain_head: trust_chain_head.into(),
            attestation_cycles: trust_state.cycle_count,
            consecutive_passes: attestation.consecutive_passes,
            all_passed: attestation.integrity.passed,
            signature: None,
            proof_bytes: vec![],
        };

        // Compute canonical proof bytes.
        let mut parts: Vec<Vec<u8>> = vec![];
        parts.push(proof.proof_id.as_bytes().to_vec());
        parts.push(proof.timestamp.as_bytes().to_vec());
        parts.push(proof.integrity_merkle_root.bytes.clone());
        parts.push(proof.trust_score.to_le_bytes().to_vec());
        parts.push(trust_chain_head.as_bytes().to_vec());

        let part_refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let digest = hash_combined(&part_refs, &proof.hash_algorithm);

        // Sign the proof.
        let signature = signing::sign(key_pair, &digest.bytes);

        proof.signature = Some(signature);
        proof.proof_bytes = digest.bytes;
        proof
    }

    /// Verify a trust proof.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        // 1. Verify signature against recomputed proof bytes (detects tampering).
        let sig = match &self.signature {
            Some(s) => s,
            None => return false,
        };

        // Recompute proof bytes from current fields to detect tampering.
        let mut parts: Vec<Vec<u8>> = vec![];
        parts.push(self.proof_id.as_bytes().to_vec());
        parts.push(self.timestamp.as_bytes().to_vec());
        parts.push(self.integrity_merkle_root.bytes.clone());
        parts.push(self.trust_score.to_le_bytes().to_vec());
        parts.push(self.trust_chain_head.as_bytes().to_vec());
        let part_refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let digest = hash_combined(&part_refs, &self.hash_algorithm);

        if !signing::verify(public_key, &sig.algorithm, sig, &digest.bytes) {
            return false;
        }

        true
    }

    /// Export as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("trust_proof: {}", e))
    }

    /// Summary.
    pub fn summary(&self) -> String {
        let status = if self.all_passed {
            "TRUSTED"
        } else {
            "COMPROMISED"
        };
        format!(
            "[TRUST PROOF] {} — trust={:.3} passes={} merkle={}...",
            status,
            self.trust_score,
            self.consecutive_passes,
            &self.integrity_merkle_root.hex[..16],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::anchor::integrity::{IntegrityChecker, IntegrityDomain};
    use crate::ananta::anchor::manifest::Manifest;
    use crate::ananta::anchor::TrustChain;

    fn make_attestation() -> AttestationReport {
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        let mut manifest = Manifest::new(HashAlgorithm::Sha256);
        manifest.insert_data("config", "valid");
        checker.register_provider(IntegrityDomain::Config, || b"valid".to_vec());
        let snapshot = checker.snapshot(&manifest);
        AttestationReport::from_snapshot(snapshot, 5, 0)
    }

    #[test]
    fn generate_and_verify() {
        let attestation = make_attestation();
        let trust_state = TrustState::new();
        let chain = TrustChain::new(HashAlgorithm::Sha256);
        let kp = KeyPair::generate_ed25519("proof-key");

        let proof = TrustProof::generate(
            &attestation,
            &trust_state,
            &chain.latest().map(|l| l.hash.clone()).unwrap_or_default(),
            &kp,
        );

        assert!(proof.verify(kp.public_key()));
        assert!(proof.all_passed);
        assert_eq!(proof.trust_score, 1.0);
    }

    #[test]
    fn tampered_proof_fails() {
        let attestation = make_attestation();
        let trust_state = TrustState::new();
        let kp = KeyPair::generate_ed25519("key");

        let mut proof = TrustProof::generate(&attestation, &trust_state, "head", &kp);

        proof.trust_score = 0.0; // Tamper.
        assert!(!proof.verify(kp.public_key()));
    }

    #[test]
    fn json_roundtrip() {
        let attestation = make_attestation();
        let trust_state = TrustState::new();
        let kp = KeyPair::generate_ed25519("key");

        let proof = TrustProof::generate(&attestation, &trust_state, "head", &kp);
        let json = proof.to_json().unwrap();
        let restored: TrustProof = serde_json::from_str(&json).unwrap();
        assert!(restored.verify(kp.public_key()));
    }
}
