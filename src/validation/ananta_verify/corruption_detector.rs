// D2 ANANTA Verification — Corruption Detector
//
// Detects and classifies corruption in ANANTA subsystems:
//   - Trust chain broken links
//   - Attestation tampering
//   - Audit log tampering
//   - Signature corruption

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing;

use crate::validation::verification::Severity;

// ────────────────────────────────────────────────────────────────
// CorruptionReport
// ────────────────────────────────────────────────────────────────

/// Report on corruption detected in an ANANTA subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionReport {
    /// Whether corruption was detected.
    pub corrupt: bool,
    /// Type of corruption (e.g. "trust_chain_broken", "attestation_tampered").
    pub corruption_type: String,
    /// Human-readable details about the corruption.
    pub details: String,
    /// Severity of the corruption.
    pub severity: Severity,
}

impl CorruptionReport {
    /// Create a clean (no corruption) report.
    pub fn clean() -> Self {
        Self {
            corrupt: false,
            corruption_type: "none".to_string(),
            details: "No corruption detected".to_string(),
            severity: Severity::Info,
        }
    }

    /// Create a corruption report.
    pub fn corrupted(corruption_type: &str, details: &str, severity: Severity) -> Self {
        Self {
            corrupt: true,
            corruption_type: corruption_type.to_string(),
            details: details.to_string(),
            severity,
        }
    }
}

impl Default for CorruptionReport {
    fn default() -> Self {
        Self::clean()
    }
}

// ────────────────────────────────────────────────────────────────
// CorruptionDetector
// ────────────────────────────────────────────────────────────────

/// Detects and classifies corruption in ANANTA subsystems.
///
/// All detection methods are deterministic — they examine structure
/// and field values to identify tampering or broken links.
pub struct CorruptionDetector;

impl CorruptionDetector {
    /// Check if a trust chain has broken links.
    ///
    /// Each link in the chain must have a `prev_hash` that matches the
    /// `hash` of the previous link. If any link is broken, corruption is reported.
    pub fn detect_trust_chain_corruption(chain: &[Value]) -> CorruptionReport {
        if chain.is_empty() {
            return CorruptionReport::clean();
        }

        for (i, window) in chain.windows(2).enumerate() {
            let current = &window[0];
            let next = &window[1];

            let current_hash = current.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            let next_prev = next.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("");

            if current_hash.is_empty() {
                tracing::warn!(index = i, "Trust chain link missing hash");
                return CorruptionReport::corrupted(
                    "trust_chain_broken",
                    &format!("Link {} missing 'hash' field", i),
                    Severity::Critical,
                );
            }

            if current_hash != next_prev {
                tracing::warn!(index = i, current_hash = %current_hash, next_prev = %next_prev, "Trust chain broken");
                return CorruptionReport::corrupted(
                    "trust_chain_broken",
                    &format!(
                        "Broken link at index {}: link {} hash='{}' does not match link {} prev_hash='{}'",
                        i, i, current_hash, i + 1, next_prev
                    ),
                    Severity::Critical,
                );
            }
        }

        // Also check the first link has no prev_hash or it's null/genesis.
        if let Some(first) = chain.first() {
            if let Some(prev) = first.get("prev_hash") {
                if !prev.is_null() {
                    let prev_str = prev.as_str().unwrap_or("");
                    if prev_str != "genesis" && !prev_str.is_empty() {
                        return CorruptionReport::corrupted(
                            "trust_chain_broken",
                            "First link has non-genesis prev_hash — chain may be partial or corrupted",
                            Severity::High,
                        );
                    }
                }
            }
        }

        tracing::debug!(chain_len = chain.len(), "Trust chain integrity verified");
        CorruptionReport::clean()
    }

    /// Check if an attestation has been tampered with.
    ///
    /// An attestation is considered valid if it contains:
    ///   - `valid` = true
    ///   - `signature` field (non-empty string)
    ///   - `timestamp` field (non-empty string)
    pub fn detect_attestation_tamper(attestation: &Value) -> CorruptionReport {
        let valid = attestation
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !valid {
            return CorruptionReport::corrupted(
                "attestation_tampered",
                "Attestation 'valid' field is false or missing",
                Severity::Critical,
            );
        }

        let sig = attestation
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if sig.is_empty() {
            return CorruptionReport::corrupted(
                "attestation_tampered",
                "Attestation 'signature' field is missing or empty",
                Severity::Critical,
            );
        }

        let ts = attestation
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if ts.is_empty() {
            return CorruptionReport::corrupted(
                "attestation_tampered",
                "Attestation 'timestamp' field is missing or empty",
                Severity::High,
            );
        }

        tracing::debug!("Attestation integrity verified");
        CorruptionReport::clean()
    }

    /// Check if audit log entries have been modified.
    ///
    /// Checks:
    ///   - Each entry must have a non-empty `entry_id`.
    ///   - Each entry must have a non-empty `hash` (integrity).
    ///   - Entries must be in chronological order by `timestamp`.
    pub fn detect_audit_log_tamper(entries: &[Value]) -> CorruptionReport {
        if entries.is_empty() {
            return CorruptionReport::clean();
        }

        let mut prev_ts: Option<&str> = None;

        for (i, entry) in entries.iter().enumerate() {
            let entry_id = entry.get("entry_id").and_then(|v| v.as_str()).unwrap_or("");
            if entry_id.is_empty() {
                return CorruptionReport::corrupted(
                    "audit_log_tampered",
                    &format!("Audit entry {} missing 'entry_id'", i),
                    Severity::High,
                );
            }

            let hash = entry.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            if hash.is_empty() {
                return CorruptionReport::corrupted(
                    "audit_log_tampered",
                    &format!("Audit entry {} missing 'hash'", i),
                    Severity::High,
                );
            }

            let ts = entry
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(prev) = prev_ts {
                if ts < prev {
                    return CorruptionReport::corrupted(
                        "audit_log_tampered",
                        &format!(
                            "Audit entries out of order at index {}: '{}' < '{}'",
                            i, ts, prev
                        ),
                        Severity::High,
                    );
                }
            }
            prev_ts = Some(ts);
        }

        tracing::debug!(entries_len = entries.len(), "Audit log integrity verified");
        CorruptionReport::clean()
    }

    /// Check if crypto signatures are invalid.
    ///
    /// Takes a list of (message, signature_hex) pairs and checks that:
    ///   - All messages are non-empty.
    ///   - All signatures are non-empty hex strings.
    ///   - Signature length is reasonable (>= 64 hex chars for typical schemes).
    pub fn detect_signature_corruption(signatures: &[(String, String)]) -> CorruptionReport {
        if signatures.is_empty() {
            return CorruptionReport::clean();
        }

        for (i, (msg, sig)) in signatures.iter().enumerate() {
            if msg.is_empty() {
                return CorruptionReport::corrupted(
                    "signature_corruption",
                    &format!("Signature pair {} has empty message", i),
                    Severity::High,
                );
            }

            if sig.is_empty() {
                return CorruptionReport::corrupted(
                    "signature_corruption",
                    &format!("Signature pair {} has empty signature", i),
                    Severity::Critical,
                );
            }

            // Check if signature is valid hex.
            if sig.len() < 64 {
                return CorruptionReport::corrupted(
                    "signature_corruption",
                    &format!(
                        "Signature pair {} has suspiciously short signature ({} chars, expected >= 64)",
                        i, sig.len()
                    ),
                    Severity::Critical,
                );
            }

            let is_hex = sig.chars().all(|c| c.is_ascii_hexdigit());
            if !is_hex {
                return CorruptionReport::corrupted(
                    "signature_corruption",
                    &format!("Signature pair {} contains non-hex characters", i),
                    Severity::Critical,
                );
            }
        }

        tracing::debug!(sig_count = signatures.len(), "Signature integrity verified");
        CorruptionReport::clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_chain_clean() {
        let chain = vec![
            serde_json::json!({"hash": "h1", "prev_hash": null}),
            serde_json::json!({"hash": "h2", "prev_hash": "h1"}),
            serde_json::json!({"hash": "h3", "prev_hash": "h2"}),
        ];
        let report = CorruptionDetector::detect_trust_chain_corruption(&chain);
        assert!(!report.corrupt);
    }

    #[test]
    fn trust_chain_broken_link() {
        let chain = vec![
            serde_json::json!({"hash": "h1", "prev_hash": null}),
            serde_json::json!({"hash": "h2", "prev_hash": "WRONG"}),
        ];
        let report = CorruptionDetector::detect_trust_chain_corruption(&chain);
        assert!(report.corrupt);
        assert_eq!(report.corruption_type, "trust_chain_broken");
        assert_eq!(report.severity, Severity::Critical);
    }

    #[test]
    fn attestation_clean() {
        let attestation = serde_json::json!({
            "valid": true,
            "signature": "abcdef1234567890",
            "timestamp": "2025-01-01T00:00:00Z"
        });
        let report = CorruptionDetector::detect_attestation_tamper(&attestation);
        assert!(!report.corrupt);
    }

    #[test]
    fn attestation_invalid() {
        let attestation = serde_json::json!({"valid": false, "signature": ""});
        let report = CorruptionDetector::detect_attestation_tamper(&attestation);
        assert!(report.corrupt);
    }

    #[test]
    fn audit_log_clean() {
        let entries = vec![
            serde_json::json!({"entry_id": "e1", "hash": "abc", "timestamp": "2025-01-01T00:00:00Z"}),
            serde_json::json!({"entry_id": "e2", "hash": "def", "timestamp": "2025-01-01T00:01:00Z"}),
        ];
        let report = CorruptionDetector::detect_audit_log_tamper(&entries);
        assert!(!report.corrupt);
    }

    #[test]
    fn audit_log_out_of_order() {
        let entries = vec![
            serde_json::json!({"entry_id": "e1", "hash": "abc", "timestamp": "2025-01-01T00:01:00Z"}),
            serde_json::json!({"entry_id": "e2", "hash": "def", "timestamp": "2025-01-01T00:00:00Z"}),
        ];
        let report = CorruptionDetector::detect_audit_log_tamper(&entries);
        assert!(report.corrupt);
        assert_eq!(report.corruption_type, "audit_log_tampered");
    }

    #[test]
    fn signatures_clean() {
        let sigs = vec![
            ("message1".to_string(), "a".repeat(128)),
            ("message2".to_string(), "b".repeat(128)),
        ];
        let report = CorruptionDetector::detect_signature_corruption(&sigs);
        assert!(!report.corrupt);
    }

    #[test]
    fn signatures_too_short() {
        let sigs = vec![("message".to_string(), "abc".to_string())];
        let report = CorruptionDetector::detect_signature_corruption(&sigs);
        assert!(report.corrupt);
        assert_eq!(report.corruption_type, "signature_corruption");
    }

    #[test]
    fn empty_inputs_are_clean() {
        assert!(!CorruptionDetector::detect_trust_chain_corruption(&[]).corrupt);
        assert!(!CorruptionDetector::detect_audit_log_tamper(&[]).corrupt);
        assert!(!CorruptionDetector::detect_signature_corruption(&[]).corrupt);
    }
}
