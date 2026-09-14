// Evidence Chain of Custody — Cryptographic integrity for forensic evidence.
//
// Implements a hash-chained evidence collection system where each piece
// of evidence links to the previous one via SHA-256. This creates an
// immutable audit trail suitable for legal and compliance purposes.
//
// Key features:
//   - SHA-256 hash chaining: chain_hash = SHA256(prev_hash + data_hash + metadata)
//   - Chain verification via full chain walk
//   - Chain of custody tracking (who accessed what, when, why)
//   - Tamper detection via hash recomputation
//   - JSON export for external audit

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

// ── Evidence Type ──

/// Type of evidence collected during incident response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Application or system log entry.
    LogEntry,
    /// Network traffic capture.
    NetworkCapture,
    /// Memory dump from a process.
    MemoryDump,
    /// Snapshot of system configuration.
    ConfigSnapshot,
    /// Version of a security policy at time of collection.
    PolicyVersion,
    /// Log of a conversation with the AI model.
    ConversationLog,
    /// Snapshot of overall system state.
    SystemState,
    /// Record of a user action.
    UserAction,
    /// Output produced by the AI model.
    ModelOutput,
}

impl EvidenceType {
    /// Returns a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::LogEntry => "Log Entry",
            Self::NetworkCapture => "Network Capture",
            Self::MemoryDump => "Memory Dump",
            Self::ConfigSnapshot => "Config Snapshot",
            Self::PolicyVersion => "Policy Version",
            Self::ConversationLog => "Conversation Log",
            Self::SystemState => "System State",
            Self::UserAction => "User Action",
            Self::ModelOutput => "Model Output",
        }
    }
}

// ── Evidence Item ──

/// A single piece of evidence in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Unique identifier for this evidence item.
    pub id: String,
    /// The incident this evidence belongs to.
    pub incident_id: String,
    /// Type of evidence.
    pub evidence_type: EvidenceType,
    /// Human-readable description.
    pub description: String,
    /// When this evidence was collected.
    pub collected_at: DateTime<Utc>,
    /// SHA-256 hash of the raw evidence data.
    pub data_hash: String,
    /// SHA-256 hash of the previous item in the chain.
    pub previous_hash: String,
    /// Computed chain hash: SHA256(previous_hash + data_hash + metadata).
    pub chain_hash: String,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl EvidenceItem {
    /// Compute the chain hash from components.
    pub fn compute_chain_hash(previous_hash: &str, data_hash: &str, metadata_str: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(data_hash.as_bytes());
        hasher.update(metadata_str.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute SHA-256 hash of raw data.
    pub fn hash_data(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Verify this item's chain hash against its components.
    pub fn verify_chain_hash(&self) -> bool {
        let metadata_str = self.serialize_metadata();
        let computed = Self::compute_chain_hash(
            &self.previous_hash,
            &self.data_hash,
            &metadata_str,
        );
        computed == self.chain_hash
    }

    /// Serialize metadata to a deterministic string for hashing.
    fn serialize_metadata(&self) -> String {
        let mut entries: Vec<_> = self.metadata.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        entries
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join("|")
    }
}

// ── Chain Verification Result ──

/// Result of verifying a complete evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    /// Whether the entire chain is valid.
    pub is_valid: bool,
    /// Total number of items checked.
    pub items_checked: usize,
    /// Index of the first invalid item (None if all valid).
    pub first_invalid_index: Option<usize>,
    /// Description of the first validation failure.
    pub failure_reason: Option<String>,
}

// ── Chain of Custody ──

/// Records who accessed evidence and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Evidence item ID.
    pub evidence_id: String,
    /// Who accessed the evidence.
    pub accessed_by: String,
    /// When the access occurred.
    pub accessed_at: DateTime<Utc>,
    /// Purpose of access.
    pub purpose: String,
}

/// Tracks chain of custody for evidence items.
#[derive(Debug, Default)]
pub struct ChainOfCustody {
    entries: Vec<CustodyEntry>,
}

impl ChainOfCustody {
    /// Create a new empty chain of custody tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an access event.
    pub fn record_access(
        &mut self,
        evidence_id: &str,
        accessed_by: &str,
        purpose: &str,
    ) {
        self.entries.push(CustodyEntry {
            evidence_id: evidence_id.to_string(),
            accessed_by: accessed_by.to_string(),
            accessed_at: Utc::now(),
            purpose: purpose.to_string(),
        });
    }

    /// Get the full access log.
    pub fn get_access_log(&self) -> &[CustodyEntry] {
        &self.entries
    }

    /// Get access log for a specific evidence item.
    pub fn get_access_log_for(&self, evidence_id: &str) -> Vec<&CustodyEntry> {
        self.entries
            .iter()
            .filter(|e| e.evidence_id == evidence_id)
            .collect()
    }
}

// ── Evidence Collector ──

/// Collects and manages evidence chains for incidents.
pub struct EvidenceCollector {
    /// Chains keyed by incident_id.
    chains: HashMap<String, Vec<EvidenceItem>>,
    /// Chain of custody tracker.
    custody: ChainOfCustody,
}

impl EvidenceCollector {
    /// Create a new evidence collector.
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            custody: ChainOfCustody::new(),
        }
    }

    /// Collect a new piece of evidence and append it to the chain.
    pub fn collect(
        &mut self,
        incident_id: &str,
        evidence_type: EvidenceType,
        description: &str,
        data: &[u8],
    ) -> Result<String> {
        let data_hash = EvidenceItem::hash_data(data);
        let chain = self.chains.entry(incident_id.to_string()).or_default();

        // Get previous hash
        let previous_hash = chain
            .last()
            .map(|item| item.chain_hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), evidence_type.label().to_string());
        metadata.insert("incident".to_string(), incident_id.to_string());

        // Build a temp item to get deterministic metadata serialization
        let temp_item = EvidenceItem {
            id: String::new(),
            incident_id: incident_id.to_string(),
            evidence_type: evidence_type.clone(),
            description: String::new(),
            collected_at: Utc::now(),
            data_hash: String::new(),
            previous_hash: String::new(),
            chain_hash: String::new(),
            metadata: metadata.clone(),
        };
        let metadata_str = temp_item.serialize_metadata();

        // Compute chain hash
        let chain_hash =
            EvidenceItem::compute_chain_hash(&previous_hash, &data_hash, &metadata_str);

        let item = EvidenceItem {
            id: uuid::Uuid::new_v4().to_string(),
            incident_id: incident_id.to_string(),
            evidence_type,
            description: description.to_string(),
            collected_at: Utc::now(),
            data_hash,
            previous_hash,
            chain_hash,
            metadata,
        };

        let item_id = item.id.clone();
        chain.push(item);
        Ok(item_id)
    }

    /// Verify the integrity of an entire evidence chain.
    pub fn verify_chain(&self, incident_id: &str) -> ChainVerificationResult {
        let chain = match self.chains.get(incident_id) {
            Some(c) => c,
            None => {
                return ChainVerificationResult {
                    is_valid: true,
                    items_checked: 0,
                    first_invalid_index: None,
                    failure_reason: None,
                }
            }
        };

        if chain.is_empty() {
            return ChainVerificationResult {
                is_valid: true,
                items_checked: 0,
                first_invalid_index: None,
                failure_reason: None,
            };
        }

        let mut items_checked = 0;
        for (i, item) in chain.iter().enumerate() {
            // Verify the item's own chain hash
            if !item.verify_chain_hash() {
                return ChainVerificationResult {
                    is_valid: false,
                    items_checked,
                    first_invalid_index: Some(i),
                    failure_reason: Some(format!(
                        "Chain hash mismatch at item {} (id={})",
                        i, item.id
                    )),
                };
            }

            // Verify linkage to previous item
            if i > 0 {
                let expected_prev = &chain[i - 1].chain_hash;
                if item.previous_hash != *expected_prev {
                    return ChainVerificationResult {
                        is_valid: false,
                        items_checked,
                        first_invalid_index: Some(i),
                        failure_reason: Some(format!(
                            "Previous hash mismatch at index {}: expected {}, got {}",
                            i, expected_prev, item.previous_hash
                        )),
                    };
                }
            } else {
                // First item should have GENESIS as previous hash
                if item.previous_hash != "GENESIS" {
                    return ChainVerificationResult {
                        is_valid: false,
                        items_checked,
                        first_invalid_index: Some(i),
                        failure_reason: Some(
                            "First item does not have GENESIS previous hash".to_string(),
                        ),
                    };
                }
            }

            items_checked += 1;
        }

        ChainVerificationResult {
            is_valid: true,
            items_checked,
            first_invalid_index: None,
            failure_reason: None,
        }
    }

    /// Get the evidence chain for an incident.
    pub fn get_chain(&self, incident_id: &str) -> Vec<&EvidenceItem> {
        self.chains
            .get(incident_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Export a chain as JSON.
    pub fn export_chain(&self, incident_id: &str) -> Result<String> {
        let chain = self.chains.get(incident_id).ok_or_else(|| {
            Error::Other(format!("No evidence chain for incident: {incident_id}"))
        })?;
        serde_json::to_string_pretty(chain)
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Compute a tamper-proof hash for the entire chain.
    /// This is the chain_hash of the last item, representing the
    /// cumulative hash of the entire chain.
    pub fn compute_tamper_proof(&self, incident_id: &str) -> Option<String> {
        self.chains
            .get(incident_id)
            .and_then(|chain| chain.last())
            .map(|item| item.chain_hash.clone())
    }

    /// Record a custody access event.
    pub fn record_access(&mut self, evidence_id: &str, accessed_by: &str, purpose: &str) {
        self.custody.record_access(evidence_id, accessed_by, purpose);
    }

    /// Get the chain of custody access log.
    pub fn get_access_log(&self) -> &[CustodyEntry] {
        self.custody.get_access_log()
    }

    /// Get the number of evidence items for an incident.
    pub fn chain_len(&self, incident_id: &str) -> usize {
        self.chains.get(incident_id).map_or(0, |c| c.len())
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    // ── EvidenceType tests ──

    #[test]
    fn test_evidence_type_labels() {
        assert_eq!(EvidenceType::LogEntry.label(), "Log Entry");
        assert_eq!(EvidenceType::NetworkCapture.label(), "Network Capture");
        assert_eq!(EvidenceType::ModelOutput.label(), "Model Output");
    }

    #[test]
    fn test_evidence_type_serialization() {
        let et = EvidenceType::ConversationLog;
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"conversation_log\"");
        let back: EvidenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }

    // ── EvidenceItem tests ──

    #[test]
    fn test_hash_data() {
        let hash1 = EvidenceItem::hash_data(b"hello");
        let hash2 = EvidenceItem::hash_data(b"hello");
        let hash3 = EvidenceItem::hash_data(b"world");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_compute_chain_hash_deterministic() {
        let h1 = EvidenceItem::compute_chain_hash("prev", "data", "meta");
        let h2 = EvidenceItem::compute_chain_hash("prev", "data", "meta");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_compute_chain_hash_different_inputs() {
        let h1 = EvidenceItem::compute_chain_hash("prev", "data", "meta");
        let h2 = EvidenceItem::compute_chain_hash("prev", "data", "different");
        let h3 = EvidenceItem::compute_chain_hash("different", "data", "meta");
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }
    
    #[test]
    fn test_verify_chain_hash_valid() {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "Log Entry".to_string());
        metadata.insert("incident".to_string(), "inc-123".to_string());

        let previous_hash = "GENESIS".to_string();
        let data_hash = EvidenceItem::hash_data(b"test data");
        let metadata_str = "incident:inc-123|type:Log Entry";
        let chain_hash = EvidenceItem::compute_chain_hash(&previous_hash, &data_hash, metadata_str);

        let item = EvidenceItem {
            id: "ev-1".to_string(),
            incident_id: "inc-123".to_string(),
            evidence_type: EvidenceType::LogEntry,
            description: "Test log".to_string(),
            collected_at: Utc::now(),
            data_hash,
            previous_hash,
            chain_hash,
            metadata,
        };

        assert!(item.verify_chain_hash());
    }

    #[test]
    fn test_verify_chain_hash_tampered() {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "Log Entry".to_string());

        let item = EvidenceItem {
            id: "ev-1".to_string(),
            incident_id: "inc-123".to_string(),
            evidence_type: EvidenceType::LogEntry,
            description: "Test".to_string(),
            collected_at: Utc::now(),
            data_hash: EvidenceItem::hash_data(b"original data"),
            previous_hash: "GENESIS".to_string(),
            chain_hash: "tampered_hash_value".to_string(), // Wrong hash
            metadata,
        };

        assert!(!item.verify_chain_hash());
    }

    // ── EvidenceCollector tests ──

    #[test]
    fn test_collect_single_item() {
        let mut collector = EvidenceCollector::new();
        let id = collector
            .collect("inc-1", EvidenceType::LogEntry, "First log", b"log data")
            .unwrap();

        assert!(!id.is_empty());
        assert_eq!(collector.chain_len("inc-1"), 1);
    }

    #[test]
    fn test_collect_multiple_items_chain() {
        let mut collector = EvidenceCollector::new();
        collector
            .collect("inc-1", EvidenceType::LogEntry, "Log 1", b"data1")
            .unwrap();
        collector
            .collect("inc-1", EvidenceType::NetworkCapture, "Capture", b"data2")
            .unwrap();
        collector
            .collect("inc-1", EvidenceType::ModelOutput, "Output", b"data3")
            .unwrap();

        assert_eq!(collector.chain_len("inc-1"), 3);

        let chain = collector.get_chain("inc-1");
        // First item has GENESIS as previous hash
        assert_eq!(chain[0].previous_hash, "GENESIS");
        // Second item's previous hash = first item's chain hash
        assert_eq!(chain[1].previous_hash, chain[0].chain_hash);
        // Third item's previous hash = second item's chain hash
        assert_eq!(chain[2].previous_hash, chain[1].chain_hash);
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut collector = EvidenceCollector::new();
        collector
            .collect("inc-1", EvidenceType::LogEntry, "Log", b"log")
            .unwrap();
        collector
            .collect("inc-1", EvidenceType::SystemState, "State", b"state")
            .unwrap();

        let result = collector.verify_chain("inc-1");
        assert!(result.is_valid);
        assert_eq!(result.items_checked, 2);
        assert!(result.first_invalid_index.is_none());
    }

    #[test]
    fn test_verify_chain_empty() {
        let collector = EvidenceCollector::new();
        let result = collector.verify_chain("nonexistent");
        assert!(result.is_valid);
        assert_eq!(result.items_checked, 0);
    }

    #[test]
    fn test_verify_chain_nonexistent() {
        let collector = EvidenceCollector::new();
        let result = collector.verify_chain("no-such-incident");
        assert!(result.is_valid);
    }

    #[test]
    fn test_export_chain() {
        let mut collector = EvidenceCollector::new();
        collector
            .collect("inc-1", EvidenceType::LogEntry, "Log", b"log data")
            .unwrap();

        let json = collector.export_chain("inc-1").unwrap();
        assert!(json.contains("Log Entry"));
        assert!(json.contains("inc-1"));
        // Should be valid JSON array
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_export_chain_nonexistent() {
        let collector = EvidenceCollector::new();
        let result = collector.export_chain("no-such-incident");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_tamper_proof() {
        let mut collector = EvidenceCollector::new();
        collector
            .collect("inc-1", EvidenceType::LogEntry, "Log", b"log")
            .unwrap();

        let proof = collector.compute_tamper_proof("inc-1");
        assert!(proof.is_some());
        assert_eq!(proof.unwrap().len(), 64);
    }

    #[test]
    fn test_compute_tamper_proof_nonexistent() {
        let collector = EvidenceCollector::new();
        let proof = collector.compute_tamper_proof("no-such-incident");
        assert!(proof.is_none());
    }

    // ── Chain of Custody tests ──

    #[test]
    fn test_custody_record_access() {
        let mut custody = ChainOfCustody::new();
        custody.record_access("ev-1", "analyst@example.com", "review");
        custody.record_access("ev-2", "admin@example.com", "investigation");
        custody.record_access("ev-1", "auditor@example.com", "audit");

        let log = custody.get_access_log();
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_custody_filter_by_evidence() {
        let mut custody = ChainOfCustody::new();
        custody.record_access("ev-1", "analyst", "review");
        custody.record_access("ev-2", "admin", "investigation");
        custody.record_access("ev-1", "auditor", "audit");

        let ev1_log = custody.get_access_log_for("ev-1");
        assert_eq!(ev1_log.len(), 2);

        let ev2_log = custody.get_access_log_for("ev-2");
        assert_eq!(ev2_log.len(), 1);

        let ev3_log = custody.get_access_log_for("ev-3");
        assert!(ev3_log.is_empty());
    }

    #[test]
    fn test_collector_custody_integration() {
        let mut collector = EvidenceCollector::new();
        let ev_id = collector
            .collect("inc-1", EvidenceType::LogEntry, "Log", b"log")
            .unwrap();

        collector.record_access(&ev_id, "analyst@example.com", "initial review");
        collector.record_access(&ev_id, "admin@example.com", "escalation review");

        let log = collector.get_access_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].evidence_id, ev_id);
        assert_eq!(log[1].accessed_by, "admin@example.com");
    }
}
