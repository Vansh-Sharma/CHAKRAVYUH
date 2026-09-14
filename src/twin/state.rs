// Security Twin™ — TwinState: Snapshot/Restore of the security system state.
//
// TwinState manages point-in-time snapshots of ring configurations,
// policy settings, and trust levels. These snapshots are the digital
// replica that the Security Twin engine operates against.
//
// This module is independent of ANANTA — it is the external-facing
// operator interface for the Security Twin™ technology.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A point-in-time snapshot of the security system state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Unique snapshot ID.
    pub id: String,
    /// Human-readable snapshot name.
    pub name: String,
    /// RFC 3339 timestamp when captured.
    pub timestamp: String,
    /// Free-text description.
    pub description: String,
    /// Ring configurations keyed by ring name.
    /// Each value is arbitrary JSON representing that ring's config.
    pub ring_configs: HashMap<String, serde_json::Value>,
}

impl StateSnapshot {
    /// Create a new empty snapshot with the given name.
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            description: description.to_string(),
            ring_configs: HashMap::new(),
        }
    }
}

/// Manages a collection of state snapshots for the Security Twin.
///
/// The TwinState is the digital replica of the security system that
/// operators can snapshot, modify, restore, and compare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinState {
    /// All captured snapshots.
    snapshots: Vec<StateSnapshot>,
}

impl TwinState {
    /// Create an empty TwinState with no snapshots.
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    /// Capture a new snapshot with the given ring configurations.
    ///
    /// Returns the snapshot ID.
    pub fn capture(
        &mut self,
        name: &str,
        description: &str,
        ring_configs: HashMap<String, serde_json::Value>,
    ) -> Result<String, String> {
        let mut snapshot = StateSnapshot::new(name, description);
        snapshot.ring_configs = ring_configs;
        let id = snapshot.id.clone();
        self.snapshots.push(snapshot);
        tracing::info!(snapshot_id = %id, name, "twin state: snapshot captured");
        Ok(id)
    }

    /// List all snapshots.
    pub fn list(&self) -> &[StateSnapshot] {
        &self.snapshots
    }

    /// Restore a snapshot by ID, returning a cloned copy of its state.
    ///
    /// This does not modify the TwinState — it returns a mutable copy
    /// of the ring configs that the engine can modify without affecting
    /// the stored snapshot.
    pub fn restore(&self, snapshot_id: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let snapshot = self
            .snapshots
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| format!("snapshot '{}' not found", snapshot_id))?;
        tracing::info!(snapshot_id = %snapshot_id, name = %snapshot.name, "twin state: snapshot restored");
        Ok(snapshot.ring_configs.clone())
    }

    /// Compute a diff between two snapshots identified by their IDs.
    ///
    /// Returns a map of ring name → { field → { old, new } } for every
    /// ring that differs between the two snapshots.
    pub fn diff(
        &self,
        before_id: &str,
        after_id: &str,
    ) -> Result<HashMap<String, serde_json::Value>, String> {
        let before = self
            .snapshots
            .iter()
            .find(|s| s.id == before_id)
            .ok_or_else(|| format!("snapshot '{}' not found", before_id))?;
        let after = self
            .snapshots
            .iter()
            .find(|s| s.id == after_id)
            .ok_or_else(|| format!("snapshot '{}' not found", after_id))?;

        let mut diffs = HashMap::new();

        // Collect all ring names from both snapshots.
        let all_rings: std::collections::HashSet<&String> = before
            .ring_configs
            .keys()
            .chain(after.ring_configs.keys())
            .collect();

        for ring in all_rings {
            let old_val = before.ring_configs.get(ring);
            let new_val = after.ring_configs.get(ring);

            if old_val != new_val {
                diffs.insert(
                    ring.clone(),
                    serde_json::json!({
                        "old": old_val,
                        "new": new_val,
                    }),
                );
            }
        }

        tracing::info!(
            before_id = %before_id,
            after_id = %after_id,
            changed_rings = diffs.len(),
            "twin state: diff computed"
        );
        Ok(diffs)
    }

    /// Export the latest snapshot (or a specific one) as a JSON string.
    pub fn export_json(&self, snapshot_id: Option<&str>) -> Result<String, String> {
        let snapshot = match snapshot_id {
            Some(id) => self
                .snapshots
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| format!("snapshot '{}' not found", id))?,
            None => self
                .snapshots
                .last()
                .ok_or("no snapshots available to export")?,
        };
        serde_json::to_string_pretty(snapshot)
            .map_err(|e| format!("failed to serialize snapshot: {}", e))
    }

    /// Import a snapshot from a JSON string and add it to the state.
    ///
    /// Returns the imported snapshot ID.
    pub fn import_json(&mut self, json: &str) -> Result<String, String> {
        let snapshot: StateSnapshot =
            serde_json::from_str(json).map_err(|e| format!("failed to parse snapshot JSON: {}", e))?;
        let id = snapshot.id.clone();
        tracing::info!(snapshot_id = %id, name = %snapshot.name, "twin state: snapshot imported");
        self.snapshots.push(snapshot);
        Ok(id)
    }

    /// Get the number of stored snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Check if there are no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl Default for TwinState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ring_configs() -> HashMap<String, serde_json::Value> {
        let mut configs = HashMap::new();
        configs.insert(
            "shield".to_string(),
            serde_json::json!({"threshold": 0.8, "mode": "strict"}),
        );
        configs.insert(
            "threat".to_string(),
            serde_json::json!({"sensitivity": 0.7, "patterns_enabled": true}),
        );
        configs
    }

    #[test]
    fn capture_and_list() {
        let mut state = TwinState::new();
        let id = state
            .capture("baseline", "initial system state", sample_ring_configs())
            .unwrap();
        assert_eq!(state.list().len(), 1);
        assert_eq!(state.list()[0].id, id);
    }

    #[test]
    fn restore_snapshot() {
        let mut state = TwinState::new();
        let id = state
            .capture("baseline", "test", sample_ring_configs())
            .unwrap();
        let restored = state.restore(&id).unwrap();
        assert!(restored.contains_key("shield"));
        assert!(restored.contains_key("threat"));
    }

    #[test]
    fn diff_two_snapshots() {
        let mut state = TwinState::new();
        let id1 = state
            .capture("before", "before change", sample_ring_configs())
            .unwrap();

        let mut modified = sample_ring_configs();
        modified.insert(
            "shield".to_string(),
            serde_json::json!({"threshold": 0.5, "mode": "permissive"}),
        );
        let id2 = state
            .capture("after", "after change", modified)
            .unwrap();

        let diffs = state.diff(&id1, &id2).unwrap();
        assert!(diffs.contains_key("shield"));
        // Threat ring didn't change so it should not appear in the diff.
        assert!(!diffs.contains_key("threat"));
    }

    #[test]
    fn export_import_roundtrip() {
        let mut state = TwinState::new();
        state
            .capture("export-test", "round trip test", sample_ring_configs())
            .unwrap();

        let json = state.export_json(None).unwrap();
        assert!(json.contains("export-test"));

        let mut state2 = TwinState::new();
        let imported_id = state2.import_json(&json).unwrap();
        assert_eq!(state2.list().len(), 1);
        assert_eq!(state2.list()[0].id, imported_id);
    }

    #[test]
    fn restore_nonexistent_errors() {
        let state = TwinState::new();
        let result = state.restore("nonexistent-id");
        assert!(result.is_err());
    }
}
