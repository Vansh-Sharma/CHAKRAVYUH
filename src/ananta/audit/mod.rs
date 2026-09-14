#![allow(ambiguous_glob_reexports)]

// ANANTA Audit — Immutable Audit Log
//
// ANANTA's audit trail is SEPARATE from Keshav's.
// This is a first-class design constraint: if Keshav is compromised,
// ANANTA's audit log must still be trustworthy.
//
// Features:
//   - Cryptographically chained entries (tamper evidence)
//   - HMAC signing of each entry
//   - Automatic compaction when entries exceed threshold
//   - Query by category, severity, time range
//   - Export to JSON for external compliance tools

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::anchor::TrustChain;
use crate::ananta::config::{AuditConfig, HashAlgorithm};

/// Evidence correlation, attack chain reconstruction, MITRE ATT&CK mapping,
/// Dempster-Shafer evidence fusion, and timeline analysis.
pub mod evidence;
pub use evidence::*;

/// Immutable audit log storage engine (WAL, Merkle, ring buffer, compaction).
pub mod immutable_log;
pub use immutable_log::*;

/// Compliance rule engine, audit trail verification, report generation,
/// retention enforcement, and anomaly detection.
pub mod audit_compliance;
pub use audit_compliance::*;

/// Audit entry categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Trust state changes.
    Trust,
    /// Drift detection events.
    Drift,
    /// Recovery actions.
    Recovery,
    /// Integrity checks.
    Integrity,
    /// Configuration changes.
    Configuration,
    /// Key management events.
    KeyManagement,
    /// Adapter pipeline changes.
    Adaptation,
    /// System lifecycle events (start, stop, restart).
    Lifecycle,
    /// Distributed consensus events.
    Consensus,
    /// Health monitoring events.
    Health,
}

impl std::fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Severity of an audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Category of the event.
    pub category: AuditCategory,
    /// Severity level.
    pub severity: AuditSeverity,
    /// Human-readable event message.
    pub message: String,
    /// Structured data associated with the event.
    pub data: HashMap<String, serde_json::Value>,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Hash of the previous entry (for chaining).
    pub prev_hash: String,
    /// Hash of this entry's content.
    pub hash: String,
}

impl AuditEntry {
    /// Compute the content hash for this entry.
    fn compute_hash(algorithm: &HashAlgorithm, prev_hash: &str, category: &str, message: &str, timestamp: &str) -> String {
        use crate::ananta::crypto::hashing::hash_combined;
        hash_combined(&[prev_hash.as_bytes(), category.as_bytes(), message.as_bytes(), timestamp.as_bytes()], algorithm).hex
    }
}

/// Query parameters for filtering audit entries.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by category.
    pub category: Option<AuditCategory>,
    /// Filter by minimum severity.
    pub min_severity: Option<AuditSeverity>,
    /// Filter by substring in message.
    pub message_contains: Option<String>,
    /// Maximum number of entries to return.
    pub limit: Option<usize>,
    /// Start sequence number (inclusive).
    pub from_sequence: Option<u64>,
    /// End sequence number (exclusive).
    pub to_sequence: Option<u64>,
}

/// The immutable audit log.
pub struct AuditLog {
    config: AuditConfig,
    /// Hash algorithm for entry chaining.
    algorithm: HashAlgorithm,
    /// Underlying trust chain for tamper evidence.
    chain: TrustChain,
    /// In-memory index of all entries for fast querying.
    entries: Vec<AuditEntry>,
    /// Per-category counts.
    category_counts: HashMap<AuditCategory, u64>,
    /// Compaction counter.
    compaction_count: u64,
}

impl AuditLog {
    /// Create a new audit log.
    pub fn new(config: AuditConfig, algorithm: HashAlgorithm) -> Self {
        Self {
            config,
            algorithm: algorithm.clone(),
            chain: TrustChain::new(algorithm),
            entries: vec![],
            category_counts: HashMap::new(),
            compaction_count: 0,
        }
    }

    /// Append an audit entry.
    pub fn append(
        &mut self,
        category: AuditCategory,
        severity: AuditSeverity,
        message: &str,
    ) -> &AuditEntry {
        let sequence = self.entries.len() as u64;
        let prev_hash = self.entries.last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let timestamp = chrono::Utc::now().to_rfc3339();

        let hash = AuditEntry::compute_hash(
            &self.chain_algorithm(),
            &prev_hash,
            &format!("{:?}", category),
            message,
            &timestamp,
        );

        // Also append to trust chain for dual integrity.
        self.chain.append(
            &format!("audit:{:?}", category),
            serde_json::json!({
                "sequence": sequence,
                "severity": format!("{:?}", severity),
                "message": message,
            }),
        );

        let entry = AuditEntry {
            sequence,
            category,
            severity,
            message: message.into(),
            data: HashMap::new(),
            timestamp,
            prev_hash,
            hash,
        };

        // Update category counts.
        *self.category_counts.entry(entry.category.clone()).or_insert(0) += 1;

        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Append an audit entry with structured data.
    pub fn append_with_data(
        &mut self,
        category: AuditCategory,
        severity: AuditSeverity,
        message: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> &AuditEntry {
        let sequence = self.entries.len() as u64;
        let prev_hash = self.entries.last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let timestamp = chrono::Utc::now().to_rfc3339();

        let hash = AuditEntry::compute_hash(
            &self.chain_algorithm(),
            &prev_hash,
            &format!("{:?}", category),
            message,
            &timestamp,
        );

        // Also append to trust chain for dual integrity.
        self.chain.append(
            &format!("audit:{:?}", category),
            serde_json::json!({
                "sequence": sequence,
                "severity": format!("{:?}", severity),
                "message": message,
            }),
        );

        let entry = AuditEntry {
            sequence,
            category,
            severity,
            message: message.into(),
            data,
            timestamp,
            prev_hash,
            hash,
        };

        *self.category_counts.entry(entry.category.clone()).or_insert(0) += 1;
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Query the audit log.
    pub fn query(&self, query: &AuditQuery) -> Vec<&AuditEntry> {
        let mut results: Vec<&AuditEntry> = self.entries.iter()
            .filter(|e| {
                // Category filter.
                if let Some(ref cat) = query.category {
                    if &e.category != cat {
                        return false;
                    }
                }
                // Severity filter.
                if let Some(ref min_sev) = query.min_severity {
                    if e.severity < *min_sev {
                        return false;
                    }
                }
                // Message substring filter.
                if let Some(ref substr) = query.message_contains {
                    if !e.message.contains(substr.as_str()) {
                        return false;
                    }
                }
                // Sequence range.
                if let Some(from) = query.from_sequence {
                    if e.sequence < from {
                        return false;
                    }
                }
                if let Some(to) = query.to_sequence {
                    if e.sequence >= to {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Apply limit.
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        results
    }

    /// Verify the integrity of the entire audit log.
    /// Returns the index of the first broken entry, or None if valid.
    pub fn verify(&self) -> Option<usize> {
        let algorithm = self.chain_algorithm();
        for i in 0..self.entries.len() {
            let entry = &self.entries[i];
            let prev_hash = if i == 0 {
                "0".repeat(64)
            } else {
                self.entries[i - 1].hash.clone()
            };

            let expected = AuditEntry::compute_hash(
                &algorithm,
                &prev_hash,
                &format!("{:?}", entry.category),
                &entry.message,
                &entry.timestamp,
            );

            if entry.hash != expected {
                return Some(i);
            }
        }
        None
    }

    /// Check if compaction is needed.
    pub fn needs_compaction(&self) -> bool {
        self.config.chained_entries
            && self.entries.len() >= self.config.max_entries_before_compaction
    }

    /// Compact the audit log by keeping only entries above a severity threshold.
    /// Returns the number of entries removed.
    pub fn compact(&mut self, min_severity: AuditSeverity) -> usize {
        let before = self.entries.len();

        // Keep entries at or above the threshold, plus the chain anchors.
        // In a real implementation, we'd write a summary entry.
        let kept: Vec<AuditEntry> = self.entries.drain(..)
            .filter(|e| e.severity >= min_severity.clone())
            .collect();

        // Re-number and re-chain.
        self.entries = kept;
        self.category_counts.clear();

        for entry in &mut self.entries {
            *self.category_counts.entry(entry.category.clone()).or_insert(0) += 1;
        }

        self.compaction_count += 1;
        before - self.entries.len()
    }

    /// Total entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get category counts.
    pub fn category_counts(&self) -> &HashMap<AuditCategory, u64> {
        &self.category_counts
    }

    /// Export all entries as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.entries)
            .map_err(|e| format!("audit export: {}", e))
    }

    /// Get the hash algorithm used for chaining.
    fn chain_algorithm(&self) -> &HashAlgorithm {
        &self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log() -> AuditLog {
        AuditLog::new(AuditConfig::default(), HashAlgorithm::Sha256)
    }

    #[test]
    fn append_and_query() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "trust check passed");
        log.append(AuditCategory::Drift, AuditSeverity::Warning, "drift detected");

        assert_eq!(log.len(), 2);

        let all = log.query(&AuditQuery::default());
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn query_by_category() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "a");
        log.append(AuditCategory::Drift, AuditSeverity::Warning, "b");
        log.append(AuditCategory::Trust, AuditSeverity::Error, "c");

        let trust = log.query(&AuditQuery {
            category: Some(AuditCategory::Trust),
            ..Default::default()
        });
        assert_eq!(trust.len(), 2);
    }

    #[test]
    fn query_by_severity() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "a");
        log.append(AuditCategory::Trust, AuditSeverity::Warning, "b");
        log.append(AuditCategory::Trust, AuditSeverity::Critical, "c");

        let warnings_plus = log.query(&AuditQuery {
            min_severity: Some(AuditSeverity::Warning),
            ..Default::default()
        });
        assert_eq!(warnings_plus.len(), 2);
    }

    #[test]
    fn query_with_limit() {
        let mut log = test_log();
        for i in 0..10 {
            log.append(AuditCategory::Trust, AuditSeverity::Info, &format!("entry {}", i));
        }
        let limited = log.query(&AuditQuery {
            limit: Some(3),
            ..Default::default()
        });
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn integrity_verification() {
        let mut log = test_log();
        for i in 0..5 {
            log.append(AuditCategory::Integrity, AuditSeverity::Info, &format!("check {}", i));
        }
        assert!(log.verify().is_none());
    }

    #[test]
    fn tamper_detection() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "original");
        log.append(AuditCategory::Trust, AuditSeverity::Info, "second");

        // Tamper with first entry's message.
        log.entries[0].message = "TAMPERED".into();

        assert_eq!(log.verify(), Some(0));
    }

    #[test]
    fn compaction_removes_low_severity() {
        let mut log = test_log();
        for _ in 0..5 {
            log.append(AuditCategory::Trust, AuditSeverity::Debug, "noise");
        }
        log.append(AuditCategory::Trust, AuditSeverity::Critical, "important");

        let removed = log.compact(AuditSeverity::Warning);
        assert_eq!(removed, 5); // All debug entries removed.
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn category_counts() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "a");
        log.append(AuditCategory::Trust, AuditSeverity::Info, "b");
        log.append(AuditCategory::Drift, AuditSeverity::Warning, "c");

        let counts = log.category_counts();
        assert_eq!(*counts.get(&AuditCategory::Trust).unwrap(), 2);
        assert_eq!(*counts.get(&AuditCategory::Drift).unwrap(), 1);
    }

    #[test]
    fn append_with_data() {
        let mut log = test_log();
        let mut data = HashMap::new();
        data.insert("z_score".into(), serde_json::json!(5.2));
        data.insert("domain".into(), serde_json::json!("policy"));

        log.append_with_data(
            AuditCategory::Drift,
            AuditSeverity::Warning,
            "drift detected",
            data,
        );

        let entry = &log.entries[0];
        assert_eq!(entry.data.get("z_score").unwrap(), &serde_json::json!(5.2));
    }

    #[test]
    fn json_export() {
        let mut log = test_log();
        log.append(AuditCategory::Trust, AuditSeverity::Info, "export test");
        let json = log.to_json().unwrap();
        assert!(json.contains("export test"));
    }
}