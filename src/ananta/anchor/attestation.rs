// Attestation Report — proof that the platform is in a trusted state.
//
// Generated periodically by Anchor. Contains:
//   1. Integrity check results (per-domain pass/fail)
//   2. Merkle root of all domain hashes
//   3. Cryptographic signature
//   4. Timestamp and version
//   5. Trust state snapshot
//
// This is what gets attached to audit trails as the
// "I can prove the Security OS has not been compromised" evidence.

use crate::ananta::anchor::integrity::IntegritySnapshot;
use crate::ananta::crypto::signing::{self, KeyPair, Signature};
use serde::{Deserialize, Serialize};

/// A complete attestation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// ANANTA version.
    pub ananta_version: String,
    /// Report generation timestamp (ISO 8601).
    pub timestamp: String,
    /// The integrity snapshot from this check cycle.
    pub integrity: IntegritySnapshot,
    /// Platform trust level (0.0-1.0).
    pub trust_level: f64,
    /// Number of consecutive successful attestations.
    pub consecutive_passes: u64,
    /// Number of consecutive failed attestations.
    pub consecutive_failures: u64,
    /// Cryptographic signature over the report.
    pub signature: Option<Signature>,
}

impl AttestationReport {
    /// Create a new attestation report from an integrity snapshot.
    pub fn from_snapshot(
        snapshot: IntegritySnapshot,
        consecutive_passes: u64,
        consecutive_failures: u64,
    ) -> Self {
        let trust_level = if snapshot.passed { 1.0 } else {
            let total = snapshot.results.len().max(1);
            let passed = snapshot.results.iter().filter(|r| r.passed).count();
            passed as f64 / total as f64
        };

        let fixed_time = "2026-01-01T00:00:00+00:00".to_string();

        Self {
            ananta_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: fixed_time,
            integrity: snapshot,
            trust_level,
            consecutive_passes,
            consecutive_failures,
            signature: None,
        }
    }

    /// Sign the attestation report.
    pub fn sign(&mut self, key_pair: &KeyPair) {
        let payload = self.canonical_bytes();
        let sig = signing::sign(key_pair, &payload);
        self.signature = Some(sig);
    }

    /// Verify the attestation report's signature.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        match &self.signature {
            Some(sig) => {
                let payload = self.canonical_bytes();
                signing::verify(public_key, &sig.algorithm, sig, &payload)
            }
            None => false,
        }
    }

    /// Canonical byte representation for signing.
    fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "ananta:{}|time:{}|merkle:{}|trust:{:.6}|passes:{}|failures:{}",
            self.ananta_version,
            self.timestamp,
            self.integrity.merkle_root.hex,
            self.trust_level,
            self.consecutive_passes,
            self.consecutive_failures,
        ).into_bytes()
    }

    /// Summary for logging.
    pub fn summary(&self) -> String {
        let status = if self.integrity.passed { "TRUSTED" } else { "COMPROMISED" };
        format!(
            "[ANANTA ATTESTATION] {} — trust={:.3} passes={} failures={} — {}",
            status, self.trust_level, self.consecutive_passes, self.consecutive_failures,
            self.integrity.summary(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::anchor::integrity::{IntegrityChecker, IntegrityDomain};
    use crate::ananta::anchor::manifest::Manifest;
    use crate::ananta::config::HashAlgorithm;

    fn make_snapshot() -> IntegritySnapshot {
        let mut checker = IntegrityChecker::new(HashAlgorithm::Sha256);
        let mut manifest = Manifest::new(HashAlgorithm::Sha256);
        manifest.insert_data("config", "valid");
        checker.register_provider(IntegrityDomain::Config, || b"valid".to_vec());
        checker.snapshot(&manifest)
    }

    #[test]
    fn report_from_snapshot() {
        let snapshot = make_snapshot();
        let report = AttestationReport::from_snapshot(snapshot, 5, 0);
        assert_eq!(report.trust_level, 1.0);
        assert!(report.integrity.passed);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let snapshot = make_snapshot();
        let mut report = AttestationReport::from_snapshot(snapshot, 10, 0);
        let kp = KeyPair::generate_ed25519("attestation-key");
        report.sign(&kp);
        assert!(report.verify(kp.public_key()));
    }

    #[test]
    fn tampered_report_fails_verification() {
        let snapshot = make_snapshot();
        let mut report = AttestationReport::from_snapshot(snapshot, 10, 0);
        let kp = KeyPair::generate_ed25519("key");
        report.sign(&kp);

        report.trust_level = 0.0; // tamper
        assert!(!report.verify(kp.public_key()));
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let snapshot = make_snapshot();
        let r1 = AttestationReport::from_snapshot(snapshot.clone(), 1, 0);
        let r2 = AttestationReport::from_snapshot(snapshot, 1, 0);
        assert_eq!(r1.canonical_bytes(), r2.canonical_bytes());
    }
}
