// ANANTA State — Shared State Management
//
// Provides:
//   1. State snapshots — point-in-time captures of all ANANTA state
//   2. State persistence — save/load state to disk
//   3. State diffing — detect what changed between snapshots
//   4. State versioning — track state evolution
//   5. State synchronization — distributed sync with vector clocks,
//      conflict resolution, incremental transfer, and OT
//
// All state access goes through this module to ensure
// consistency and auditability.

pub mod state_sync;
pub use state_sync::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::trust::trust_state::TrustState;
use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::hash_bytes;

/// A point-in-time snapshot of ANANTA's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot version (monotonically increasing).
    pub version: u64,
    /// Hash of the previous snapshot (for chaining).
    pub prev_hash: String,
    /// Hash of this snapshot's content.
    pub hash: String,
    /// The trust state at this point.
    pub trust_state: TrustState,
    /// Per-component state blobs.
    pub component_states: HashMap<String, serde_json::Value>,
    /// Metadata about this snapshot.
    pub metadata: SnapshotMetadata,
}

/// Metadata about a state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// When this snapshot was taken.
    pub timestamp: String,
    /// Why the snapshot was taken.
    pub reason: String,
    /// Whether this snapshot was triggered by an anomaly.
    pub anomaly_triggered: bool,
    /// ANANTA cycle count at snapshot time.
    pub cycle_count: u64,
    /// Overall trust score at snapshot time.
    pub trust_score: f64,
}

impl StateSnapshot {
    /// Create a new state snapshot.
    pub fn new(
        version: u64,
        prev_hash: &str,
        trust_state: TrustState,
        component_states: HashMap<String, serde_json::Value>,
        reason: &str,
    ) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let trust_score = trust_state.overall_score();
        let cycle_count = trust_state.cycle_count;

        // Compute hash of the snapshot content.
        let content = serde_json::json!({
            "version": version,
            "prev_hash": prev_hash,
            "trust_state": serde_json::to_value(&trust_state).unwrap_or_default(),
            "component_states": component_states,
            "timestamp": timestamp,
        });
        let content_str = serde_json::to_string(&content).unwrap_or_default();
        let digest = hash_bytes(content_str.as_bytes(), &HashAlgorithm::Sha256);

        Self {
            version,
            prev_hash: prev_hash.into(),
            hash: digest.hex,
            trust_state,
            component_states,
            metadata: SnapshotMetadata {
                timestamp,
                reason: reason.into(),
                anomaly_triggered: false,
                cycle_count,
                trust_score,
            },
        }
    }
}

/// A diff between two state snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    /// The version of the earlier snapshot.
    pub from_version: u64,
    /// The version of the later snapshot.
    pub to_version: u64,
    /// Trust score change.
    pub trust_score_delta: f64,
    /// Per-domain trust level changes.
    pub domain_changes: Vec<DomainChange>,
    /// New alerts that appeared.
    pub new_alerts: usize,
    /// Alerts that were cleared.
    pub cleared_alerts: usize,
    /// Duration between snapshots (ms).
    pub duration_ms: u64,
}

/// A change in a single domain's trust level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainChange {
    pub domain: String,
    pub old_level: f64,
    pub new_level: f64,
    pub delta: f64,
}

impl StateDiff {
    /// Compute the diff between two snapshots.
    pub fn compute(from: &StateSnapshot, to: &StateSnapshot) -> Self {
        let trust_score_delta = to.metadata.trust_score - from.metadata.trust_score;

        let mut domain_changes = vec![];

        // Check all domains in both snapshots.
        let all_domains: std::collections::HashSet<&str> = from.trust_state.domains.keys()
            .map(|s| s.as_str())
            .chain(to.trust_state.domains.keys().map(|s| s.as_str()))
            .collect();

        for domain in all_domains {
            let old_level = from.trust_state.domain_level(domain);
            let new_level = to.trust_state.domain_level(domain);
            let delta = new_level - old_level;

            if delta.abs() > 1e-10 {
                domain_changes.push(DomainChange {
                    domain: domain.into(),
                    old_level,
                    new_level,
                    delta,
                });
            }
        }

        // Sort by absolute delta (biggest changes first).
        domain_changes.sort_by(|a, b| b.delta.abs().partial_cmp(&a.delta.abs()).unwrap());

        let new_alerts = to.trust_state.alerts.len().saturating_sub(from.trust_state.alerts.len());
        // For cleared alerts, we can't easily compute without tracking individual alerts.
        let cleared_alerts = 0;

        // Approximate duration from timestamps.
        let duration_ms = 0; // Simplified.

        Self {
            from_version: from.version,
            to_version: to.version,
            trust_score_delta,
            domain_changes,
            new_alerts,
            cleared_alerts,
            duration_ms,
        }
    }
}

/// The state manager — handles persistence and versioning.
pub struct StateManager {
    /// All snapshots (in-memory, limited to max_snapshots).
    snapshots: Vec<StateSnapshot>,
    /// Current version number.
    current_version: u64,
    /// Maximum snapshots to keep in memory.
    max_snapshots: usize,
    /// Hash algorithm for snapshot chaining.
    hash_algorithm: HashAlgorithm,
}

impl StateManager {
    /// Create a new state manager.
    pub fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self {
            snapshots: vec![],
            current_version: 0,
            max_snapshots: 100,
            hash_algorithm,
        }
    }

    /// Create a new state manager with a specific max snapshots limit.
    pub fn with_max_snapshots(mut self, max: usize) -> Self {
        self.max_snapshots = max;
        self
    }

    /// Take a snapshot of the current state.
    pub fn snapshot(
        &mut self,
        trust_state: &TrustState,
        component_states: HashMap<String, serde_json::Value>,
        reason: &str,
    ) -> &StateSnapshot {
        self.current_version += 1;

        let prev_hash = self.snapshots.last()
            .map(|s| s.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let snapshot = StateSnapshot::new(
            self.current_version,
            &prev_hash,
            trust_state.clone(),
            component_states,
            reason,
        );

        self.snapshots.push(snapshot);

        // Evict old snapshots.
        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }

        self.snapshots.last().unwrap()
    }

    /// Take an anomaly-triggered snapshot.
    pub fn anomaly_snapshot(
        &mut self,
        trust_state: &TrustState,
        component_states: HashMap<String, serde_json::Value>,
        reason: &str,
    ) -> &StateSnapshot {
        let _snap = self.snapshot(trust_state, component_states, reason);
        // Mark as anomaly-triggered (mutate the last snapshot).
        if let Some(last) = self.snapshots.last_mut() {
            last.metadata.anomaly_triggered = true;
        }
        self.snapshots.last().unwrap()
    }

    /// Get the latest snapshot.
    pub fn latest(&self) -> Option<&StateSnapshot> {
        self.snapshots.last()
    }

    /// Get a snapshot by version.
    pub fn get_version(&self, version: u64) -> Option<&StateSnapshot> {
        self.snapshots.iter().find(|s| s.version == version)
    }

    /// Get the previous snapshot.
    pub fn previous(&self) -> Option<&StateSnapshot> {
        if self.snapshots.len() >= 2 {
            self.snapshots.get(self.snapshots.len() - 2)
        } else {
            None
        }
    }

    /// Compute the diff between the latest two snapshots.
    pub fn latest_diff(&self) -> Option<StateDiff> {
        if self.snapshots.len() < 2 {
            return None;
        }
        let len = self.snapshots.len();
        let from = &self.snapshots[len - 2];
        let to = &self.snapshots[len - 1];
        Some(StateDiff::compute(from, to))
    }

    /// Verify the integrity of the snapshot chain.
    /// Returns the version of the first broken snapshot, or None if valid.
    pub fn verify_chain(&self) -> Option<u64> {
        for i in 0..self.snapshots.len() {
            let snap = &self.snapshots[i];
            let expected_prev = if i == 0 {
                "0".repeat(64)
            } else {
                self.snapshots[i - 1].hash.clone()
            };

            if snap.prev_hash != expected_prev {
                return Some(snap.version);
            }
        }
        None
    }

    /// Total snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Find snapshots triggered by anomalies.
    pub fn anomaly_snapshots(&self) -> Vec<&StateSnapshot> {
        self.snapshots.iter()
            .filter(|s| s.metadata.anomaly_triggered)
            .collect()
    }

    /// Find snapshots where trust dropped significantly.
    pub fn trust_drop_snapshots(&self, threshold: f64) -> Vec<&StateSnapshot> {
        self.snapshots.windows(2)
            .filter(|w| {
                let delta = w[1].metadata.trust_score - w[0].metadata.trust_score;
                delta < -threshold
            })
            .map(|w| &w[1])
            .collect()
    }

    /// Export the latest snapshot as JSON.
    pub fn export_latest(&self) -> Result<String, String> {
        let snap = self.latest().ok_or("no snapshots")?;
        serde_json::to_string_pretty(snap)
            .map_err(|e| format!("state export: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_state() -> TrustState {
        TrustState::new()
    }

    fn degraded_state() -> TrustState {
        let mut state = TrustState::new();
        state.set_domain_level("decision", 0.4);
        state.set_domain_level("policy", 0.3);
        state
    }

    #[test]
    fn snapshot_creates_and_chains() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        let state = healthy_state();
        mgr.snapshot(&state, HashMap::new(), "initial");
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.latest().unwrap().version, 1);
    }

    #[test]
    fn snapshot_chain_hashes() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.snapshot(&healthy_state(), HashMap::new(), "v1");
        mgr.snapshot(&healthy_state(), HashMap::new(), "v2");

        let v2 = mgr.get_version(2).unwrap();
        let v1 = mgr.get_version(1).unwrap();
        assert_eq!(v2.prev_hash, v1.hash);
    }

    #[test]
    fn chain_verification() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        for i in 0..5 {
            let mut state = healthy_state();
            state.set_domain_level("decision", 1.0 - i as f64 * 0.1);
            mgr.snapshot(&state, HashMap::new(), &format!("v{}", i + 1));
        }
        assert!(mgr.verify_chain().is_none());
    }

    #[test]
    fn diff_detects_changes() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.snapshot(&healthy_state(), HashMap::new(), "before");
        mgr.snapshot(&degraded_state(), HashMap::new(), "after");

        let diff = mgr.latest_diff().unwrap();
        assert!(diff.trust_score_delta < 0.0); // Trust dropped.
        assert!(!diff.domain_changes.is_empty());
    }

    #[test]
    fn diff_domain_changes_sorted() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.snapshot(&healthy_state(), HashMap::new(), "before");

        let mut state = healthy_state();
        state.set_domain_level("decision", 0.5); // -0.5
        state.set_domain_level("plugin", 0.8);    // -0.2
        mgr.snapshot(&state, HashMap::new(), "after");

        let diff = mgr.latest_diff().unwrap();
        // Decision has the biggest change, should be first.
        assert_eq!(diff.domain_changes[0].domain, "decision");
    }

    #[test]
    fn anomaly_snapshot_marked() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.anomaly_snapshot(&degraded_state(), HashMap::new(), "drift detected");

        let anomaly_snaps = mgr.anomaly_snapshots();
        assert_eq!(anomaly_snaps.len(), 1);
        assert!(anomaly_snaps[0].metadata.anomaly_triggered);
    }

    #[test]
    fn trust_drop_detection() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.snapshot(&healthy_state(), HashMap::new(), "v1");
        mgr.snapshot(&degraded_state(), HashMap::new(), "v2");

        let drops = mgr.trust_drop_snapshots(0.1);
        assert_eq!(drops.len(), 1);
    }

    #[test]
    fn max_snapshots_eviction() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256).with_max_snapshots(3);
        for i in 0..5 {
            mgr.snapshot(&healthy_state(), HashMap::new(), &format!("v{}", i));
        }
        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.latest().unwrap().version, 5);
    }

    #[test]
    fn component_states_in_snapshot() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        let mut components = HashMap::new();
        components.insert("sentinel".into(), serde_json::json!({"cycles": 42}));
        components.insert("phoenix".into(), serde_json::json!({"recoveries": 1}));

        mgr.snapshot(&healthy_state(), components, "with components");
        let snap = mgr.latest().unwrap();
        assert_eq!(snap.component_states.len(), 2);
    }

    #[test]
    fn export_json() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        mgr.snapshot(&healthy_state(), HashMap::new(), "test");
        let json = mgr.export_latest().unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("trust_state"));
    }

    #[test]
    fn previous_snapshot() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        assert!(mgr.previous().is_none());
        mgr.snapshot(&healthy_state(), HashMap::new(), "v1");
        assert!(mgr.previous().is_none()); // Only 1 snapshot.
        mgr.snapshot(&healthy_state(), HashMap::new(), "v2");
        assert_eq!(mgr.previous().unwrap().version, 1);
    }

    #[test]
    fn empty_diff() {
        let mut mgr = StateManager::new(HashAlgorithm::Sha256);
        let state = healthy_state();
        mgr.snapshot(&state, HashMap::new(), "v1");
        mgr.snapshot(&state, HashMap::new(), "v2");

        let diff = mgr.latest_diff().unwrap();
        assert_eq!(diff.trust_score_delta, 0.0);
        assert!(diff.domain_changes.is_empty());
    }
}