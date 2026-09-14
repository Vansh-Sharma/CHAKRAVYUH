#![deny(unsafe_code)]

// ═══════════════════════════════════════════════════════════════════════════
// ANANTA Phoenix — Rollback Execution Engine
//
// Real rollback execution engine for Phoenix recovery.
// Provides state snapshotting, diffing, rollback planning, execution,
// verification, and automatic retry with full audit trail.
// ═══════════════════════════════════════════════════════════════════════════

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: StateSnapshot
// ═══════════════════════════════════════════════════════════════════════════

/// An immutable point-in-time capture of domain state.
/// Stores key-value pairs with SHA-256 integrity verification,
/// metadata, and optional tags for categorisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_id: String,
    pub domain: String,
    pub timestamp: String,
    pub data: HashMap<String, serde_json::Value>,
    pub checksum: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl StateSnapshot {
    /// Create a new snapshot for the given domain with the provided data.
    /// The checksum is computed automatically over the serialised data.
    pub fn new(domain: &str, data: HashMap<String, serde_json::Value>) -> Result<Self, String> {
        if domain.is_empty() {
            return Err("Domain must not be empty".to_string());
        }
        let snapshot_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let checksum = Self::compute_checksum(&data)?;
        Ok(Self {
            snapshot_id,
            domain: domain.to_string(),
            timestamp,
            data,
            checksum,
            metadata: HashMap::new(),
            tags: Vec::new(),
        })
    }

    /// Compute a SHA-256 checksum over the serialised data map.
    pub fn compute_checksum(data: &HashMap<String, serde_json::Value>) -> Result<String, String> {
        let sorted: BTreeMap<_, _> = data.iter().collect();
        let serialized = serde_json::to_string(&sorted)
            .map_err(|e| format!("Failed to serialize data for checksum: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Verify that the stored checksum still matches the current data.
    pub fn verify_checksum(&self) -> Result<bool, String> {
        let computed = Self::compute_checksum(&self.data)?;
        Ok(computed == self.checksum)
    }

    /// Serialize the snapshot to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize snapshot: {}", e))
    }

    /// Deserialize a snapshot from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to deserialize snapshot: {}", e))
    }

    /// Add a tag to this snapshot for categorisation and search.
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    /// Check whether the snapshot carries a specific tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Get a value by key from the snapshot data.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    /// Set a value in the snapshot data. Recomputes the checksum.
    pub fn set(&mut self, key: &str, value: serde_json::Value) -> Result<(), String> {
        self.data.insert(key.to_string(), value);
        self.checksum = Self::compute_checksum(&self.data)?;
        Ok(())
    }

    /// Merge another snapshot's data into this one.
    /// Keys present in `other` overwrite keys in `self`.
    pub fn merge(&mut self, other: &StateSnapshot) -> Result<(), String> {
        for (k, v) in &other.data {
            self.data.insert(k.clone(), v.clone());
        }
        self.checksum = Self::compute_checksum(&self.data)?;
        Ok(())
    }

    /// Compute the diff between this snapshot (as `from`) and another (as `to`).
    pub fn diff(&self, other: &StateSnapshot) -> Result<StateDiff, String> {
        StateDiff::compute(self, other)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: StateDiff
// ═══════════════════════════════════════════════════════════════════════════

/// Describes the nature of a field-level change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffType {
    Added,
    Removed,
    Modified,
    Unchanged,
}

impl std::fmt::Display for DiffType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffType::Added => write!(f, "Added"),
            DiffType::Removed => write!(f, "Removed"),
            DiffType::Modified => write!(f, "Modified"),
            DiffType::Unchanged => write!(f, "Unchanged"),
        }
    }
}

/// A single field-level difference between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiff {
    pub key: String,
    pub diff_type: DiffType,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    /// Heuristic impact score: Modified + type change = 1.0,
    /// Removed = 0.8, Added = 0.3, Modified = 0.5.
    pub impact_score: f64,
}

impl FieldDiff {
    fn new(
        key: &str,
        diff_type: DiffType,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
    ) -> Self {
        let impact_score = match &diff_type {
            DiffType::Added => 0.3,
            DiffType::Removed => 0.8,
            DiffType::Unchanged => 0.0,
            DiffType::Modified => {
                let type_changed = match (&old_value, &new_value) {
                    (Some(o), Some(n)) => o != n && value_type_name(o) != value_type_name(n),
                    _ => false,
                };
                if type_changed {
                    1.0
                } else {
                    0.5
                }
            }
        };
        Self {
            key: key.to_string(),
            diff_type,
            old_value,
            new_value,
            impact_score,
        }
    }

    fn is_breaking(&self) -> bool {
        self.impact_score >= 0.8
    }
}

/// A full diff between two snapshots, suitable for forward or reverse application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub domain: String,
    pub timestamp: String,
    pub fields: Vec<FieldDiff>,
    #[serde(default)]
    pub summary: String,
    pub has_breaking_changes: bool,
}

impl StateDiff {
    /// Compute the diff between `from` and `to` snapshots.
    pub fn compute(from: &StateSnapshot, to: &StateSnapshot) -> Result<Self, String> {
        let all_keys: std::collections::HashSet<&String> =
            from.data.keys().chain(to.data.keys()).collect();
        let mut fields: Vec<FieldDiff> = Vec::new();
        let mut breaking = false;

        for key in all_keys {
            let old_val = from.data.get(key).cloned();
            let new_val = to.data.get(key).cloned();
            let diff_type = match (&old_val, &new_val) {
                (None, Some(_)) => DiffType::Added,
                (Some(_), None) => DiffType::Removed,
                (Some(o), Some(n)) => {
                    if o == n {
                        DiffType::Unchanged
                    } else {
                        DiffType::Modified
                    }
                }
                (None, None) => DiffType::Unchanged,
            };
            let fd = FieldDiff::new(key, diff_type.clone(), old_val, new_val);
            if fd.is_breaking() {
                breaking = true;
            }
            fields.push(fd);
        }

        fields.sort_by(|a, b| a.key.cmp(&b.key));
        let added = fields.iter().filter(|f| f.diff_type == DiffType::Added).count();
        let removed = fields.iter().filter(|f| f.diff_type == DiffType::Removed).count();
        let modified = fields.iter().filter(|f| f.diff_type == DiffType::Modified).count();
        let summary = format!(
            "Diff: {} added, {} removed, {} modified, {} unchanged",
            added,
            removed,
            modified,
            fields.len().saturating_sub(added + removed + modified)
        );

        Ok(Self {
            from_snapshot_id: from.snapshot_id.clone(),
            to_snapshot_id: to.snapshot_id.clone(),
            domain: from.domain.clone(),
            timestamp: Utc::now().to_rfc3339(),
            fields,
            summary,
            has_breaking_changes: breaking,
        })
    }

    /// Total number of fields in the diff.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Count of fields that represent breaking changes.
    pub fn breaking_count(&self) -> usize {
        self.fields.iter().filter(|f| f.is_breaking()).count()
    }

    /// Serialize the diff to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize StateDiff: {}", e))
    }

    /// Deserialize a diff from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to deserialize StateDiff: {}", e))
    }

    /// Apply the reverse of this diff to the given snapshot (in-place mutation).
    /// This effectively reverts the changes described by this diff.
    pub fn apply_reverse(&self, snapshot: &mut StateSnapshot) -> Result<(), String> {
        for field in &self.fields {
            match &field.diff_type {
                DiffType::Added => {
                    // Reverse of Added is Removed
                    snapshot.data.remove(&field.key);
                }
                DiffType::Removed => {
                    // Reverse of Removed is Added
                    if let Some(old) = &field.old_value {
                        snapshot.data.insert(field.key.clone(), old.clone());
                    }
                }
                DiffType::Modified => {
                    // Reverse of Modified is to put back old value
                    if let Some(old) = &field.old_value {
                        snapshot.data.insert(field.key.clone(), old.clone());
                    } else {
                        snapshot.data.remove(&field.key);
                    }
                }
                DiffType::Unchanged => {
                    // No action needed
                }
            }
        }
        snapshot.checksum = StateSnapshot::compute_checksum(&snapshot.data)?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: RollbackConfig
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration knobs governing rollback behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackConfig {
    pub max_snapshots_per_domain: usize,
    pub snapshot_ttl_seconds: u64,
    pub auto_snapshot_before_recovery: bool,
    pub verify_after_rollback: bool,
    pub max_rollback_attempts: u32,
    pub rollback_timeout_ms: u64,
    pub enable_dry_run: bool,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            max_snapshots_per_domain: 10,
            snapshot_ttl_seconds: 86_400,
            auto_snapshot_before_recovery: true,
            verify_after_rollback: true,
            max_rollback_attempts: 3,
            rollback_timeout_ms: 5_000,
            enable_dry_run: false,
        }
    }
}

impl RollbackConfig {
    /// Create a new config with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style setter for max snapshots.
    pub fn with_max_snapshots(mut self, n: usize) -> Self {
        self.max_snapshots_per_domain = n;
        self
    }

    /// Builder-style setter for TTL.
    pub fn with_ttl(mut self, seconds: u64) -> Self {
        self.snapshot_ttl_seconds = seconds;
        self
    }

    /// Builder-style setter for dry-run mode.
    pub fn with_dry_run(mut self, enabled: bool) -> Self {
        self.enable_dry_run = enabled;
        self
    }

    /// Builder-style setter for max rollback attempts.
    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_rollback_attempts = n;
        self
    }

    /// Builder-style setter for rollback timeout.
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.rollback_timeout_ms = ms;
        self
    }

    /// Builder-style setter for auto-snapshot.
    pub fn with_auto_snapshot(mut self, enabled: bool) -> Self {
        self.auto_snapshot_before_recovery = enabled;
        self
    }

    /// Builder-style setter for verify after rollback.
    pub fn with_verify(mut self, enabled: bool) -> Self {
        self.verify_after_rollback = enabled;
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: SnapshotStore
// ═══════════════════════════════════════════════════════════════════════════

/// In-memory store for domain-scoped state snapshots.
/// Snapshots are stored in FIFO order per domain, subject to
/// configurable retention limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotStore {
    pub snapshots: HashMap<String, VecDeque<StateSnapshot>>,
    pub config: RollbackConfig,
}

impl SnapshotStore {
    /// Create a new empty store with the given config.
    pub fn new(config: RollbackConfig) -> Self {
        Self {
            snapshots: HashMap::new(),
            config,
        }
    }

    /// Create a new store with default config.
    pub fn with_defaults() -> Self {
        Self::new(RollbackConfig::default())
    }

    /// Store a snapshot. Evicts oldest snapshots if the per-domain
    /// limit is exceeded.
    pub fn store(&mut self, snapshot: StateSnapshot) -> Result<(), String> {
        let domain = snapshot.domain.clone();
        let entry = self
            .snapshots
            .entry(domain.clone())
            .or_insert_with(VecDeque::new);
        entry.push_back(snapshot);
        // Evict oldest when over capacity
        while entry.len() > self.config.max_snapshots_per_domain {
            if let Some(evicted) = entry.pop_front() {
                debug!(
                    domain = %domain,
                    snapshot_id = %evicted.snapshot_id,
                    "Evicted oldest snapshot due to capacity limit"
                );
            }
        }
        Ok(())
    }

    /// Retrieve the most recent snapshot for a domain, if any.
    pub fn latest(&self, domain: &str) -> Option<&StateSnapshot> {
        self.snapshots
            .get(domain)
            .and_then(|q| q.back())
    }

    /// Retrieve a specific snapshot by domain and ID.
    pub fn get(&self, domain: &str, snapshot_id: &str) -> Option<&StateSnapshot> {
        self.snapshots.get(domain).and_then(|q| {
            q.iter().find(|s| s.snapshot_id == snapshot_id)
        })
    }

    /// List all snapshots for a domain.
    pub fn list(&self, domain: &str) -> Vec<&StateSnapshot> {
        self.snapshots
            .get(domain)
            .map(|q| q.iter().collect())
            .unwrap_or_default()
    }

    /// Remove expired snapshots based on TTL.
    /// Returns the number of pruned snapshots.
    pub fn prune(&mut self) -> Result<usize, String> {
        let ttl = self.config.snapshot_ttl_seconds;
        let cutoff = Utc::now().timestamp() - (ttl as i64);
        let mut total_pruned = 0usize;

        for (domain, queue) in self.snapshots.iter_mut() {
            let before = queue.len();
            queue.retain(|s| {
                let ts = chrono::DateTime::parse_from_rfc3339(&s.timestamp)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(i64::MAX);
                ts > cutoff
            });
            let pruned = before - queue.len();
            if pruned > 0 {
                info!(
                    domain = %domain,
                    pruned = pruned,
                    "Pruned expired snapshots"
                );
            }
            total_pruned += pruned;
        }
        Ok(total_pruned)
    }

    /// Convenience: create a snapshot from data and store it.
    pub fn create_snapshot(
        &mut self,
        domain: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<StateSnapshot, String> {
        let snapshot = StateSnapshot::new(domain, data)?;
        let id = snapshot.snapshot_id.clone();
        self.store(snapshot.clone())?;
        debug!(domain = %domain, snapshot_id = %id, "Created and stored snapshot");
        Ok(snapshot)
    }

    /// Create a snapshot tagged as "last-known-good" and store it.
    pub fn create_last_known_good(
        &mut self,
        domain: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<StateSnapshot, String> {
        let mut snapshot = StateSnapshot::new(domain, data)?;
        snapshot.add_tag("last-known-good");
        snapshot.metadata.insert(
            "source".to_string(),
            "last-known-good".to_string(),
        );
        let id = snapshot.snapshot_id.clone();
        self.store(snapshot.clone())?;
        info!(
            domain = %domain,
            snapshot_id = %id,
            "Created and stored last-known-good snapshot"
        );
        Ok(snapshot)
    }

    /// Get the last-known-good snapshot for a domain.
    pub fn get_last_known_good(&self, domain: &str) -> Option<&StateSnapshot> {
        self.snapshots
            .get(domain)
            .and_then(|q| q.iter().rev().find(|s| s.has_tag("last-known-good")))
    }

    /// Count of snapshots for a given domain.
    pub fn count(&self, domain: &str) -> usize {
        self.snapshots
            .get(domain)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Total count of all snapshots across all domains.
    pub fn total_count(&self) -> usize {
        self.snapshots.values().map(|q| q.len()).sum()
    }

    /// List all known domains.
    pub fn domains(&self) -> Vec<&String> {
        self.snapshots.keys().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: RollbackExecutor
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RollbackOutcome {
    Success,
    PartialSuccess,
    Failed,
    VerificationFailed,
    Timeout,
    Aborted,
    DryRun,
}

impl std::fmt::Display for RollbackOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollbackOutcome::Success => write!(f, "Success"),
            RollbackOutcome::PartialSuccess => write!(f, "PartialSuccess"),
            RollbackOutcome::Failed => write!(f, "Failed"),
            RollbackOutcome::VerificationFailed => write!(f, "VerificationFailed"),
            RollbackOutcome::Timeout => write!(f, "Timeout"),
            RollbackOutcome::Aborted => write!(f, "Aborted"),
            RollbackOutcome::DryRun => write!(f, "DryRun"),
        }
    }
}

/// Detailed result of a single rollback execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    pub rollback_id: String,
    pub domain: String,
    pub source_snapshot_id: String,
    pub target_snapshot_id: String,
    pub outcome: RollbackOutcome,
    pub duration_ms: u64,
    pub diff_applied: Option<StateDiff>,
    pub pre_trust: f64,
    pub post_trust: f64,
    pub verification: Option<VerificationResult>,
    pub error: Option<String>,
    pub attempts: u32,
    pub dry_run: bool,
}

impl RollbackResult {
    fn success(rollback_id: &str, domain: &str, source_id: &str, target_id: &str, duration_ms: u64) -> Self {
        Self {
            rollback_id: rollback_id.to_string(),
            domain: domain.to_string(),
            source_snapshot_id: source_id.to_string(),
            target_snapshot_id: target_id.to_string(),
            outcome: RollbackOutcome::Success,
            duration_ms,
            diff_applied: None,
            pre_trust: 0.0,
            post_trust: 0.0,
            verification: None,
            error: None,
            attempts: 1,
            dry_run: false,
        }
    }

    fn failed(rollback_id: &str, domain: &str, source_id: &str, target_id: &str, err: &str, duration_ms: u64) -> Self {
        Self {
            rollback_id: rollback_id.to_string(),
            domain: domain.to_string(),
            source_snapshot_id: source_id.to_string(),
            target_snapshot_id: target_id.to_string(),
            outcome: RollbackOutcome::Failed,
            duration_ms,
            diff_applied: None,
            pre_trust: 0.0,
            post_trust: 0.0,
            verification: None,
            error: Some(err.to_string()),
            attempts: 1,
            dry_run: false,
        }
    }
}

/// Executes rollbacks against a snapshot store.
/// Thread-safe via Arc<Mutex<SnapshotStore>>.
#[derive(Debug, Clone)]
pub struct RollbackExecutor {
    pub store: Arc<Mutex<SnapshotStore>>,
    pub config: RollbackConfig,
    #[allow(dead_code)]
    pub history: Vec<RollbackResult>,
}

impl RollbackExecutor {
    /// Create a new executor with the given store and config.
    pub fn new(store: Arc<Mutex<SnapshotStore>>, config: RollbackConfig) -> Self {
        Self {
            store,
            config,
            history: Vec::new(),
        }
    }

    /// Execute a rollback from the current latest snapshot to the specified target.
    pub fn execute_rollback(
        &mut self,
        domain: &str,
        target_snapshot_id: &str,
    ) -> Result<RollbackResult, String> {
        self.execute_rollback_inner(domain, target_snapshot_id, false)
    }

    /// Execute a rollback to the last-known-good snapshot for the domain.
    pub fn execute_rollback_to_last_good(
        &mut self,
        domain: &str,
    ) -> Result<RollbackResult, String> {
        let target_id = {
            let store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let lkg = store
                .get_last_known_good(domain)
                .ok_or_else(|| {
                    format!("No last-known-good snapshot found for domain '{}'", domain)
                })?;
            lkg.snapshot_id.clone()
        };
        self.execute_rollback_inner(domain, &target_id, false)
    }

    /// Perform a dry-run: compute the diff and simulate the rollback without
    /// persisting any state changes.
    pub fn dry_run(
        &mut self,
        domain: &str,
        target_snapshot_id: &str,
    ) -> Result<RollbackResult, String> {
        self.execute_rollback_inner(domain, target_snapshot_id, true)
    }

    /// Internal rollback logic shared by execute, last-good, and dry-run.
    fn execute_rollback_inner(
        &mut self,
        domain: &str,
        target_snapshot_id: &str,
        is_dry_run: bool,
    ) -> Result<RollbackResult, String> {
        let rollback_id = Uuid::new_v4().to_string();
        let start = Instant::now();
        info!(
            rollback_id = %rollback_id,
            domain = %domain,
            target = %target_snapshot_id,
            dry_run = is_dry_run,
            "Starting rollback"
        );

        if is_dry_run || self.config.enable_dry_run {
            return self.perform_dry_run(domain, target_snapshot_id, &rollback_id, start);
        }

        // Extract source and target snapshots from the store
        let (source_snapshot, target_snapshot) = {
            let store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let source = store
                .latest(domain)
                .ok_or_else(|| format!("No snapshots found for domain '{}'", domain))?
                .clone();
            let target = store
                .get(domain, target_snapshot_id)
                .ok_or_else(|| {
                    format!(
                        "Target snapshot '{}' not found in domain '{}'",
                        target_snapshot_id, domain
                    )
                })?
                .clone();
            (source, target)
        };

        let source_id = source_snapshot.snapshot_id.clone();
        let pre_trust = 0.5; // Placeholder trust score

        // Auto-snapshot current state before recovery
        if self.config.auto_snapshot_before_recovery {
            let mut store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let auto_snap = store.create_snapshot(
                domain,
                source_snapshot.data.clone(),
            )?;
            info!(
                auto_snapshot_id = %auto_snap.snapshot_id,
                "Auto-snapshot created before rollback"
            );
        }

        // Compute the diff from target → source, then apply_reverse on source to produce target state
        let diff = StateDiff::compute(&target_snapshot, &source_snapshot)?;
        let diff_applied = diff.clone();

        // Create a new snapshot that represents the rolled-back state
        let mut rolled_back = source_snapshot.clone();
        diff.apply_reverse(&mut rolled_back)?;
        rolled_back.snapshot_id = Uuid::new_v4().to_string();
        rolled_back.timestamp = Utc::now().to_rfc3339();
        rolled_back.add_tag("rolled-back");

        // Store the rolled-back snapshot
        {
            let mut store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            store.store(rolled_back)?;
        }

        // Verification
        let verification = if self.config.verify_after_rollback {
            Some(self.verify_rollback(domain, &source_id, target_snapshot_id)?)
        } else {
            None
        };

        let duration_ms = std::cmp::max(1, start.elapsed().as_millis() as u64);
        let outcome = match &verification {
            Some(v) if !v.verified => RollbackOutcome::VerificationFailed,
            _ => RollbackOutcome::Success,
        };

        let post_trust = match &verification {
            Some(v) => v.match_percentage / 100.0,
            None => 1.0,
        };

        let result = RollbackResult {
            rollback_id: rollback_id.clone(),
            domain: domain.to_string(),
            source_snapshot_id: source_id,
            target_snapshot_id: target_snapshot_id.to_string(),
            outcome: outcome.clone(),
            duration_ms,
            diff_applied: Some(diff_applied),
            pre_trust,
            post_trust,
            verification,
            error: if outcome == RollbackOutcome::VerificationFailed {
                Some("Post-rollback verification failed".to_string())
            } else {
                None
            },
            attempts: 1,
            dry_run: false,
        };

        info!(
            rollback_id = %rollback_id,
            outcome = %outcome,
            duration_ms = duration_ms,
            "Rollback completed"
        );

        self.history.push(result.clone());
        Ok(result)
    }

    /// Perform a dry-run rollback.
    fn perform_dry_run(
        &mut self,
        domain: &str,
        target_snapshot_id: &str,
        rollback_id: &str,
        start: Instant,
    ) -> Result<RollbackResult, String> {
        let (source_snapshot, target_snapshot) = {
            let store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let source = store
                .latest(domain)
                .ok_or_else(|| format!("No snapshots found for domain '{}'", domain))?
                .clone();
            let target = store
                .get(domain, target_snapshot_id)
                .ok_or_else(|| {
                    format!(
                        "Target snapshot '{}' not found in domain '{}'",
                        target_snapshot_id, domain
                    )
                })?
                .clone();
            (source, target)
        };

        let source_id = source_snapshot.snapshot_id.clone();
        let diff = StateDiff::compute(&source_snapshot, &target_snapshot)?;
        let duration_ms = std::cmp::max(1, start.elapsed().as_millis() as u64);

        let result = RollbackResult {
            rollback_id: rollback_id.to_string(),
            domain: domain.to_string(),
            source_snapshot_id: source_id,
            target_snapshot_id: target_snapshot_id.to_string(),
            outcome: RollbackOutcome::DryRun,
            duration_ms,
            diff_applied: Some(diff),
            pre_trust: 0.0,
            post_trust: 0.0,
            verification: None,
            error: None,
            attempts: 1,
            dry_run: true,
        };

        info!(rollback_id = %rollback_id, "Dry-run rollback completed");
        self.history.push(result.clone());
        Ok(result)
    }

    /// Verify a rollback by comparing the current latest snapshot's data
    /// against the target snapshot's data.
    pub fn verify_rollback(
        &self,
        domain: &str,
        _source_snapshot_id: &str,
        target_snapshot_id: &str,
    ) -> Result<VerificationResult, String> {
        let start = Instant::now();
        let (latest, target) = {
            let store = self
                .store
                .lock()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let latest = store
                .latest(domain)
                .ok_or_else(|| format!("No latest snapshot for domain '{}'", domain))?
                .clone();
            let target = store
                .get(domain, target_snapshot_id)
                .ok_or_else(|| {
                    format!(
                        "Target snapshot '{}' not found in domain '{}'",
                        target_snapshot_id, domain
                    )
                })?
                .clone();
            (latest, target)
        };

        let total_fields = target
            .data
            .keys()
            .chain(latest.data.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();

        let mut mismatches: Vec<String> = Vec::new();
        let mut matching = 0usize;

        for key in target.data.keys().chain(latest.data.keys()) {
            let tv = target.data.get(key);
            let lv = latest.data.get(key);
            match (tv, lv) {
                (Some(t), Some(l)) if t == l => matching += 1,
                (Some(t), Some(l)) => {
                    mismatches.push(format!("key '{}': expected {}, got {}", key, t, l));
                }
                (Some(_), None) => {
                    mismatches.push(format!("key '{}': missing in latest", key));
                }
                (None, Some(_)) => {
                    mismatches.push(format!("key '{}': unexpected in latest", key));
                }
                (None, None) => matching += 1,
            }
        }

        let match_percentage = if total_fields > 0 {
            (matching as f64 / total_fields as f64) * 100.0
        } else {
            100.0
        };

        let duration_ms = std::cmp::max(1, start.elapsed().as_millis() as u64);
        let verified = mismatches.is_empty();

        Ok(VerificationResult {
            verified,
            mismatches,
            match_percentage,
            duration_ms,
        })
    }

    /// Retry the last failed rollback operation.
    pub fn retry_last_failed(&mut self) -> Result<Option<RollbackResult>, String> {
        let last = self
            .history
            .iter()
            .rev()
            .find(|r| r.outcome == RollbackOutcome::Failed);

        let last = match last {
            Some(r) => r.clone(),
            None => return Ok(None),
        };

        warn!(
            rollback_id = %last.rollback_id,
            domain = %last.domain,
            "Retrying last failed rollback"
        );

        let mut result = match self.execute_rollback_inner(
            &last.domain,
            &last.target_snapshot_id,
            false,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Retry execution failed");
                RollbackResult::failed(
                    &Uuid::new_v4().to_string(),
                    &last.domain,
                    &last.source_snapshot_id,
                    &last.target_snapshot_id,
                    &e,
                    0,
                )
            }
        };
        result.attempts = last.attempts + 1;

        if result.attempts > self.config.max_rollback_attempts {
            result.outcome = RollbackOutcome::Aborted;
            result.error = Some(format!(
                "Exceeded max rollback attempts ({})",
                self.config.max_rollback_attempts
            ));
            error!(
                rollback_id = %result.rollback_id,
                attempts = result.attempts,
                "Rollback aborted: max attempts exceeded"
            );
        }

        self.history.push(result.clone());
        Ok(Some(result))
    }

    /// Get the history of all rollback operations.
    pub fn history(&self) -> &[RollbackResult] {
        &self.history
    }

    /// Get the number of recorded rollback operations.
    pub fn history_count(&self) -> usize {
        self.history.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: VerificationResult
// ═══════════════════════════════════════════════════════════════════════════

/// Result of post-rollback verification comparing actual vs expected state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub mismatches: Vec<String>,
    pub match_percentage: f64,
    pub duration_ms: u64,
}

impl VerificationResult {
    /// Create a passing verification result.
    pub fn pass(duration_ms: u64) -> Self {
        Self {
            verified: true,
            mismatches: Vec::new(),
            match_percentage: 100.0,
            duration_ms,
        }
    }

    /// Create a failing verification result.
    pub fn fail(mismatches: Vec<String>, match_percentage: f64, duration_ms: u64) -> Self {
        Self {
            verified: false,
            mismatches,
            match_percentage,
            duration_ms,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self)
            .map_err(|e| format!("Failed to serialize VerificationResult: {}", e))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to deserialize VerificationResult: {}", e))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: RollbackPlanner
// ═══════════════════════════════════════════════════════════════════════════

/// A candidate snapshot for rollback, scored by suitability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackCandidate {
    pub snapshot: StateSnapshot,
    pub score: f64,
    pub rationale: String,
    pub estimated_risk: f64,
}

/// Plans and recommends optimal rollback targets.
#[derive(Debug, Clone)]
pub struct RollbackPlanner;

impl RollbackPlanner {
    /// Analyse available snapshots for a domain and recommend the best
    /// rollback target. Scoring considers: recency, last-known-good tag,
    /// data completeness, and diff risk.
    pub fn plan_rollback(
        store: &SnapshotStore,
        domain: &str,
        current_data: &HashMap<String, serde_json::Value>,
    ) -> Result<Vec<RollbackCandidate>, String> {
        let snapshots = store.list(domain);
        if snapshots.is_empty() {
            return Err(format!("No snapshots available for domain '{}'", domain));
        }

        let current_snapshot = StateSnapshot::new(domain, current_data.clone())?;
        let mut candidates: Vec<RollbackCandidate> = Vec::new();

        for snap in snapshots {
            let diff = match current_snapshot.diff(snap) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let score = Self::score_candidate(snap, &diff);
            let risk = Self::estimate_risk(&diff);
            let rationale = Self::build_rationale(snap, &diff, score, risk);

            candidates.push(RollbackCandidate {
                snapshot: snap.clone(),
                score,
                rationale,
                estimated_risk: risk,
            });
        }

        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(candidates)
    }

    /// Pick the single best rollback candidate.
    pub fn best_candidate(
        store: &SnapshotStore,
        domain: &str,
        current_data: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<RollbackCandidate>, String> {
        let candidates = Self::plan_rollback(store, domain, current_data)?;
        Ok(candidates.into_iter().next())
    }

    fn score_candidate(snap: &StateSnapshot, diff: &StateDiff) -> f64 {
        let mut score = 50.0;

        // Prefer last-known-good snapshots
        if snap.has_tag("last-known-good") {
            score += 30.0;
        }

        // Penalise breaking changes in the diff
        if diff.has_breaking_changes {
            score -= 20.0;
        }

        // Fewer changes is better
        let change_count = diff
            .fields
            .iter()
            .filter(|f| f.diff_type != DiffType::Unchanged)
            .count();
        score -= (change_count as f64 * 2.0).min(30.0);

        // Reward data completeness
        if snap.data.is_empty() {
            score -= 40.0;
        }

        // Reward checksum validity
        if snap.verify_checksum().unwrap_or(false) {
            score += 10.0;
        } else {
            score -= 50.0;
        }

        score.max(0.0).min(100.0)
    }

    fn estimate_risk(diff: &StateDiff) -> f64 {
        let total = diff.fields.len();
        if total == 0 {
            return 0.0;
        }
        let breaking = diff.breaking_count();
        let removed = diff
            .fields
            .iter()
            .filter(|f| f.diff_type == DiffType::Removed)
            .count();
        let type_changes = diff
            .fields
            .iter()
            .filter(|f| {
                f.diff_type == DiffType::Modified
                    && match (&f.old_value, &f.new_value) {
                        (Some(o), Some(n)) => value_type_name(o) != value_type_name(n),
                        _ => false,
                    }
            })
            .count();

        let risk = breaking as f64 * 25.0
            + removed as f64 * 10.0
            + type_changes as f64 * 15.0
            + diff.fields.iter().map(|f| f.impact_score).sum::<f64>();
        (risk / (total as f64 * 25.0)).min(100.0)
    }

    fn build_rationale(
        snap: &StateSnapshot,
        diff: &StateDiff,
        score: f64,
        risk: f64,
    ) -> String {
        let mut parts: Vec<String> = Vec::new();
        if snap.has_tag("last-known-good") {
            parts.push("marked as last-known-good".to_string());
        }
        parts.push(format!("score={:.1}", score));
        parts.push(format!("risk={:.1}%", risk));
        parts.push(diff.summary.clone());
        parts.join(", ")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Return a short type name for a JSON value.
fn value_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_data(pairs: Vec<(&str, serde_json::Value)>) -> HashMap<String, serde_json::Value> {
        pairs.into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    fn make_store_with_config(max: usize) -> Arc<Mutex<SnapshotStore>> {
        let config = RollbackConfig::new().with_max_snapshots(max);
        Arc::new(Mutex::new(SnapshotStore::new(config)))
    }

    fn make_store() -> Arc<Mutex<SnapshotStore>> {
        make_store_with_config(10)
    }

    // ─── StateSnapshot Tests ───────────────────────────────────────────

    #[test]
    fn test_snapshot_new_basic() {
        let data = make_data(vec![
            ("key1", serde_json::json!("value1")),
            ("key2", serde_json::json!(42)),
        ]);
        let snap = StateSnapshot::new("test-domain", data).unwrap();
        assert_eq!(snap.domain, "test-domain");
        assert_eq!(snap.data.len(), 2);
        assert!(!snap.snapshot_id.is_empty());
        assert!(!snap.timestamp.is_empty());
        assert!(!snap.checksum.is_empty());
    }

    #[test]
    fn test_snapshot_new_empty_domain_fails() {
        let data = make_data(vec![("k", serde_json::json!(1))]);
        let result = StateSnapshot::new("", data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_snapshot_compute_checksum_deterministic() {
        let data = make_data(vec![("a", serde_json::json!(1))]);
        let c1 = StateSnapshot::compute_checksum(&data).unwrap();
        let c2 = StateSnapshot::compute_checksum(&data).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_snapshot_compute_checksum_differs_for_different_data() {
        let d1 = make_data(vec![("a", serde_json::json!(1))]);
        let d2 = make_data(vec![("a", serde_json::json!(2))]);
        let c1 = StateSnapshot::compute_checksum(&d1).unwrap();
        let c2 = StateSnapshot::compute_checksum(&d2).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_snapshot_verify_checksum_valid() {
        let data = make_data(vec![("x", serde_json::json!(true))]);
        let snap = StateSnapshot::new("d", data).unwrap();
        assert!(snap.verify_checksum().unwrap());
    }

    #[test]
    fn test_snapshot_verify_checksum_tampered() {
        let data = make_data(vec![("x", serde_json::json!(true))]);
        let mut snap = StateSnapshot::new("d", data).unwrap();
        snap.data.insert("x".to_string(), serde_json::json!(false));
        assert!(!snap.verify_checksum().unwrap());
    }

    #[test]
    fn test_snapshot_to_json_roundtrip() {
        let data = make_data(vec![
            ("k", serde_json::json!("v")),
            ("n", serde_json::json!(99)),
        ]);
        let snap = StateSnapshot::new("domain", data).unwrap();
        let json = snap.to_json().unwrap();
        let restored = StateSnapshot::from_json(&json).unwrap();
        assert_eq!(restored.snapshot_id, snap.snapshot_id);
        assert_eq!(restored.domain, snap.domain);
        assert_eq!(restored.checksum, snap.checksum);
    }

    #[test]
    fn test_snapshot_add_tag() {
        let data = make_data(vec![]);
        let mut snap = StateSnapshot::new("d", data).unwrap();
        snap.add_tag("important");
        snap.add_tag("important"); // duplicate — should not add again
        assert_eq!(snap.tags.len(), 1);
        assert!(snap.has_tag("important"));
        assert!(!snap.has_tag("other"));
    }

    #[test]
    fn test_snapshot_get_set() {
        let data = make_data(vec![("a", serde_json::json!(1))]);
        let mut snap = StateSnapshot::new("d", data).unwrap();
        assert_eq!(snap.get("a"), Some(&serde_json::json!(1)));
        assert_eq!(snap.get("z"), None);
        snap.set("b", serde_json::json!("hello")).unwrap();
        assert_eq!(snap.get("b"), Some(&serde_json::json!("hello")));
        // Checksum should be recomputed
        assert!(snap.verify_checksum().unwrap());
    }

    #[test]
    fn test_snapshot_merge() {
        let d1 = make_data(vec![("a", serde_json::json!(1)), ("b", serde_json::json!(2))]);
        let d2 = make_data(vec![("b", serde_json::json!(20)), ("c", serde_json::json!(3))]);
        let mut snap1 = StateSnapshot::new("d", d1).unwrap();
        let snap2 = StateSnapshot::new("d", d2).unwrap();
        snap1.merge(&snap2).unwrap();
        assert_eq!(snap1.get("a"), Some(&serde_json::json!(1)));
        assert_eq!(snap1.get("b"), Some(&serde_json::json!(20))); // overwritten
        assert_eq!(snap1.get("c"), Some(&serde_json::json!(3)));
        assert!(snap1.verify_checksum().unwrap());
    }

    #[test]
    fn test_snapshot_diff_identical() {
        let data = make_data(vec![("x", serde_json::json!(10))]);
        let s1 = StateSnapshot::new("d", data.clone()).unwrap();
        let s2 = StateSnapshot::new("d", data).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.field_count(), 1);
        assert_eq!(diff.breaking_count(), 0);
        assert!(!diff.has_breaking_changes);
    }

    #[test]
    fn test_snapshot_diff_with_changes() {
        let d1 = make_data(vec![("a", serde_json::json!(1))]);
        let d2 = make_data(vec![("a", serde_json::json!(2)), ("b", serde_json::json!("new"))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.field_count(), 2);
        assert!(diff.fields.iter().any(|f| f.key == "b" && f.diff_type == DiffType::Added));
        assert!(diff.fields.iter().any(|f| f.key == "a" && f.diff_type == DiffType::Modified));
    }

    #[test]
    fn test_snapshot_metadata() {
        let data = make_data(vec![]);
        let mut snap = StateSnapshot::new("d", data).unwrap();
        snap.metadata.insert("reason".to_string(), "test".to_string());
        assert_eq!(snap.metadata.get("reason"), Some(&"test".to_string()));
    }

    #[test]
    fn test_snapshot_empty_data() {
        let snap = StateSnapshot::new("d", HashMap::new()).unwrap();
        assert!(snap.data.is_empty());
        assert!(snap.verify_checksum().unwrap());
    }

    // ─── StateDiff Tests ───────────────────────────────────────────────

    #[test]
    fn test_diff_added_field() {
        let d1 = make_data(vec![]);
        let d2 = make_data(vec![("new_key", serde_json::json!(42))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.fields.len(), 1);
        assert_eq!(diff.fields[0].diff_type, DiffType::Added);
        assert_eq!(diff.fields[0].impact_score, 0.3);
    }

    #[test]
    fn test_diff_removed_field() {
        let d1 = make_data(vec![("old_key", serde_json::json!("gone"))]);
        let d2 = make_data(vec![]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.fields.len(), 1);
        assert_eq!(diff.fields[0].diff_type, DiffType::Removed);
        assert_eq!(diff.fields[0].impact_score, 0.8);
        assert!(diff.fields[0].is_breaking());
    }

    #[test]
    fn test_diff_modified_same_type() {
        let d1 = make_data(vec![("v", serde_json::json!(10))]);
        let d2 = make_data(vec![("v", serde_json::json!(20))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.fields[0].diff_type, DiffType::Modified);
        assert_eq!(diff.fields[0].impact_score, 0.5);
        assert!(!diff.fields[0].is_breaking());
    }

    #[test]
    fn test_diff_modified_type_change() {
        let d1 = make_data(vec![("v", serde_json::json!(42))]);
        let d2 = make_data(vec![("v", serde_json::json!("now a string"))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.fields[0].diff_type, DiffType::Modified);
        assert_eq!(diff.fields[0].impact_score, 1.0);
        assert!(diff.fields[0].is_breaking());
        assert!(diff.has_breaking_changes);
    }

    #[test]
    fn test_diff_field_count_and_breaking_count() {
        let d1 = make_data(vec![
            ("a", serde_json::json!(1)),
            ("b", serde_json::json!("str")),
        ]);
        let d2 = make_data(vec![
            ("a", serde_json::json!("changed type")),
            ("c", serde_json::json!("new")),
        ]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert_eq!(diff.field_count(), 3);
        assert!(diff.breaking_count() >= 2); // removed b, type change on a
    }

    #[test]
    fn test_diff_to_json_roundtrip() {
        let d1 = make_data(vec![("a", serde_json::json!(1))]);
        let d2 = make_data(vec![("a", serde_json::json!(2))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        let json = diff.to_json().unwrap();
        let restored = StateDiff::from_json(&json).unwrap();
        assert_eq!(restored.field_count(), diff.field_count());
        assert_eq!(restored.has_breaking_changes, diff.has_breaking_changes);
    }

    #[test]
    fn test_diff_apply_reverse_added() {
        // Forward: empty → {a: 1}. Reverse: {a: 1} → empty
        let d1 = make_data(vec![]);
        let d2 = make_data(vec![("a", serde_json::json!(1))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        let mut target = s2.clone();
        diff.apply_reverse(&mut target).unwrap();
        assert!(target.data.is_empty());
    }

    #[test]
    fn test_diff_apply_reverse_removed() {
        // Forward: {a: 1} → empty. Reverse: empty → {a: 1}
        let d1 = make_data(vec![("a", serde_json::json!(1))]);
        let d2 = make_data(vec![]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        let mut target = s2.clone();
        diff.apply_reverse(&mut target).unwrap();
        assert_eq!(target.get("a"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn test_diff_apply_reverse_modified() {
        let d1 = make_data(vec![("x", serde_json::json!("old"))]);
        let d2 = make_data(vec![("x", serde_json::json!("new"))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        let mut target = s2.clone();
        diff.apply_reverse(&mut target).unwrap();
        assert_eq!(target.get("x"), Some(&serde_json::json!("old")));
    }

    #[test]
    fn test_diff_apply_reverse_recomputes_checksum() {
        let d1 = make_data(vec![("k", serde_json::json!(1))]);
        let d2 = make_data(vec![("k", serde_json::json!(2))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        let mut target = s2.clone();
        diff.apply_reverse(&mut target).unwrap();
        assert!(target.verify_checksum().unwrap());
    }

    #[test]
    fn test_diff_summary() {
        let d1 = make_data(vec![("a", serde_json::json!(1))]);
        let d2 = make_data(vec![("a", serde_json::json!(2)), ("b", serde_json::json!(3))]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();
        assert!(diff.summary.contains("1 added"));
        assert!(diff.summary.contains("1 modified"));
    }

    // ─── RollbackConfig Tests ──────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = RollbackConfig::default();
        assert_eq!(cfg.max_snapshots_per_domain, 10);
        assert_eq!(cfg.snapshot_ttl_seconds, 86_400);
        assert!(cfg.auto_snapshot_before_recovery);
        assert!(cfg.verify_after_rollback);
        assert_eq!(cfg.max_rollback_attempts, 3);
        assert_eq!(cfg.rollback_timeout_ms, 5_000);
        assert!(!cfg.enable_dry_run);
    }

    #[test]
    fn test_config_builder_pattern() {
        let cfg = RollbackConfig::new()
            .with_max_snapshots(5)
            .with_ttl(3600)
            .with_dry_run(true)
            .with_max_attempts(5)
            .with_timeout(10_000)
            .with_auto_snapshot(false)
            .with_verify(false);
        assert_eq!(cfg.max_snapshots_per_domain, 5);
        assert_eq!(cfg.snapshot_ttl_seconds, 3600);
        assert!(cfg.enable_dry_run);
        assert_eq!(cfg.max_rollback_attempts, 5);
        assert_eq!(cfg.rollback_timeout_ms, 10_000);
        assert!(!cfg.auto_snapshot_before_recovery);
        assert!(!cfg.verify_after_rollback);
    }

    // ─── SnapshotStore Tests ───────────────────────────────────────────

    #[test]
    fn test_store_create_and_retrieve() {
        let mut store = SnapshotStore::with_defaults();
        let data = make_data(vec![("k", serde_json::json!("v"))]);
        let snap = store.create_snapshot("test", data).unwrap();
        let retrieved = store.get("test", &snap.snapshot_id).unwrap();
        assert_eq!(retrieved.snapshot_id, snap.snapshot_id);
        assert_eq!(retrieved.domain, "test");
    }

    #[test]
    fn test_store_latest() {
        let mut store = SnapshotStore::with_defaults();
        let _s1 = store.create_snapshot("d", make_data(vec![("v", serde_json::json!(1))])).unwrap();
        let s2 = store.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))])).unwrap();
        let latest = store.latest("d").unwrap();
        assert_eq!(latest.snapshot_id, s2.snapshot_id);
    }

    #[test]
    fn test_store_latest_empty_domain() {
        let store = SnapshotStore::with_defaults();
        assert!(store.latest("nonexistent").is_none());
    }

    #[test]
    fn test_store_list() {
        let mut store = SnapshotStore::with_defaults();
        store.create_snapshot("d", make_data(vec![("a", serde_json::json!(1))])).unwrap();
        store.create_snapshot("d", make_data(vec![("b", serde_json::json!(2))])).unwrap();
        let list = store.list("d");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_store_eviction() {
        let store_arc = make_store_with_config(3);
        let mut store = store_arc.lock().unwrap();
        for i in 0..5 {
            store
                .create_snapshot("d", make_data(vec![("v", serde_json::json!(i))]))
                .unwrap();
        }
        assert_eq!(store.count("d"), 3);
    }

    #[test]
    fn test_store_prune_expired() {
        let config = RollbackConfig::new().with_ttl(0); // immediate expiry
        let mut store = SnapshotStore::new(config);
        store
            .create_snapshot("d", make_data(vec![("k", serde_json::json!(1))]))
            .unwrap();
        // Give a tiny moment then prune
        let pruned = store.prune().unwrap();
        assert!(pruned >= 1);
    }

    #[test]
    fn test_store_prune_retains_fresh() {
        let config = RollbackConfig::new().with_ttl(86400);
        let mut store = SnapshotStore::new(config);
        store
            .create_snapshot("d", make_data(vec![("k", serde_json::json!(1))]))
            .unwrap();
        let pruned = store.prune().unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_store_create_last_known_good() {
        let mut store = SnapshotStore::with_defaults();
        let snap = store
            .create_last_known_good("d", make_data(vec![("k", serde_json::json!(1))]))
            .unwrap();
        assert!(snap.has_tag("last-known-good"));
        let retrieved = store.get_last_known_good("d").unwrap();
        assert_eq!(retrieved.snapshot_id, snap.snapshot_id);
    }

    #[test]
    fn test_store_get_nonexistent() {
        let store = SnapshotStore::with_defaults();
        assert!(store.get("d", "no-such-id").is_none());
    }

    #[test]
    fn test_store_count_and_total() {
        let mut store = SnapshotStore::with_defaults();
        store.create_snapshot("d1", make_data(vec![])).unwrap();
        store.create_snapshot("d1", make_data(vec![])).unwrap();
        store.create_snapshot("d2", make_data(vec![])).unwrap();
        assert_eq!(store.count("d1"), 2);
        assert_eq!(store.count("d2"), 1);
        assert_eq!(store.total_count(), 3);
    }

    #[test]
    fn test_store_domains() {
        let mut store = SnapshotStore::with_defaults();
        store.create_snapshot("alpha", make_data(vec![])).unwrap();
        store.create_snapshot("beta", make_data(vec![])).unwrap();
        let mut domains = store.domains();
        domains.sort();
        assert_eq!(domains, vec!["alpha", "beta"]);
    }

    // ─── RollbackExecutor Tests ────────────────────────────────────────

    #[test]
    fn test_executor_dry_run() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(1))]))
                .unwrap();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))]))
                .unwrap();
        }
        let mut executor = RollbackExecutor::new(
            store.clone(),
            RollbackConfig::new(),
        );
        // Target the first snapshot
        let target_id = {
            let s = store.lock().unwrap();
            s.list("d")[0].snapshot_id.clone()
        };
        let result = executor.dry_run("d", &target_id).unwrap();
        assert_eq!(result.outcome, RollbackOutcome::DryRun);
        assert!(result.dry_run);
        assert!(result.diff_applied.is_some());
    }

    #[test]
    fn test_executor_rollback_success() {
        let store = make_store();
        let target_id = {
            let mut s = store.lock().unwrap();
            let snap = s
                .create_snapshot("d", make_data(vec![("v", serde_json::json!(1))]))
                .unwrap();
            let id = snap.snapshot_id.clone();
            // Push a second (current) snapshot
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))]))
                .unwrap();
            id
        };
        let config = RollbackConfig::new()
            .with_auto_snapshot(false)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store.clone(), config);
        let result = executor.execute_rollback("d", &target_id).unwrap();
        assert_eq!(result.outcome, RollbackOutcome::Success);
        assert!(!result.dry_run);
        assert!(result.diff_applied.is_some());
        assert_eq!(executor.history_count(), 1);
    }

    #[test]
    fn test_executor_rollback_nonexistent_domain() {
        let store = make_store();
        let mut executor = RollbackExecutor::new(store, RollbackConfig::new());
        let result = executor.execute_rollback("nope", "fake-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_rollback_nonexistent_target() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("d", make_data(vec![])).unwrap();
        }
        let mut executor = RollbackExecutor::new(store, RollbackConfig::new());
        let result = executor.execute_rollback("d", "no-such-snapshot");
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_rollback_to_last_good() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_last_known_good("d", make_data(vec![("v", serde_json::json!(1))]))
                .unwrap();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))]))
                .unwrap();
        }
        let config = RollbackConfig::new()
            .with_auto_snapshot(false)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store, config);
        let result = executor.execute_rollback_to_last_good("d").unwrap();
        assert_eq!(result.outcome, RollbackOutcome::Success);
    }

    #[test]
    fn test_executor_rollback_to_last_good_not_found() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("d", make_data(vec![])).unwrap(); // no LKG tag
        }
        let mut executor = RollbackExecutor::new(store, RollbackConfig::new());
        let result = executor.execute_rollback_to_last_good("d");
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_verify_rollback() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("d", make_data(vec![("a", serde_json::json!(1))]))
                .unwrap();
            s.create_snapshot("d", make_data(vec![("a", serde_json::json!(2))]))
                .unwrap();
        }
        let target_id = {
            let s = store.lock().unwrap();
            s.list("d")[0].snapshot_id.clone()
        };
        let config = RollbackConfig::new()
            .with_auto_snapshot(false)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store.clone(), config);
        executor.execute_rollback("d", &target_id).unwrap();
        // After rollback, the latest should have the rolled-back data
        let vr = executor.verify_rollback("d", "", &target_id).unwrap();
        // Since we reverse-applied, the latest should match the target
        assert!(vr.match_percentage > 0.0);
    }

    #[test]
    fn test_executor_retry_last_failed() {
        let store = make_store();
        let mut executor = RollbackExecutor::new(
            store,
            RollbackConfig::new().with_verify(false).with_auto_snapshot(false),
        );
        // Manually inject a failed result into history
        executor.history.push(RollbackResult::failed(
            "rb-1",
            "d",
            "src",
            "tgt",
            "simulated failure",
            10,
        ));
        let result = executor.retry_last_failed().unwrap();
        // The retry will fail because domain has no snapshots, but the
        // point is that it attempted
        assert!(result.is_some());
    }

    #[test]
    fn test_executor_retry_no_failed() {
        let store = make_store();
        let mut executor = RollbackExecutor::new(store, RollbackConfig::new());
        let result = executor.retry_last_failed().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_executor_history_tracking() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(1))]))
                .unwrap();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))]))
                .unwrap();
        }
        let target_id = {
            let s = store.lock().unwrap();
            s.list("d")[0].snapshot_id.clone()
        };
        let config = RollbackConfig::new()
            .with_auto_snapshot(false)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store, config);
        executor.dry_run("d", &target_id).unwrap();
        executor.execute_rollback("d", &target_id).unwrap();
        assert_eq!(executor.history_count(), 2);
    }

    #[test]
    fn test_executor_auto_snapshot_before_recovery() {
        let store = make_store();
        let target_id = {
            let mut s = store.lock().unwrap();
            let snap = s
                .create_snapshot("d", make_data(vec![("v", serde_json::json!(1))]))
                .unwrap();
            let id = snap.snapshot_id.clone();
            s.create_snapshot("d", make_data(vec![("v", serde_json::json!(2))]))
                .unwrap();
            id
        };
        let count_before = store.lock().unwrap().count("d");
        let config = RollbackConfig::new()
            .with_auto_snapshot(true)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store.clone(), config);
        executor.execute_rollback("d", &target_id).unwrap();
        let count_after = store.lock().unwrap().count("d");
        // Should have an extra auto-snapshot
        assert!(count_after > count_before);
    }

    // ─── VerificationResult Tests ──────────────────────────────────────

    #[test]
    fn test_verification_pass() {
        let vr = VerificationResult::pass(5);
        assert!(vr.verified);
        assert!(vr.mismatches.is_empty());
        assert_eq!(vr.match_percentage, 100.0);
        assert_eq!(vr.duration_ms, 5);
    }

    #[test]
    fn test_verification_fail() {
        let vr = VerificationResult::fail(
            vec!["key mismatch".to_string()],
            75.0,
            10,
        );
        assert!(!vr.verified);
        assert_eq!(vr.mismatches.len(), 1);
        assert_eq!(vr.match_percentage, 75.0);
    }

    #[test]
    fn test_verification_json_roundtrip() {
        let vr = VerificationResult::pass(42);
        let json = vr.to_json().unwrap();
        let restored = VerificationResult::from_json(&json).unwrap();
        assert_eq!(restored.verified, vr.verified);
        assert_eq!(restored.match_percentage, vr.match_percentage);
        assert_eq!(restored.duration_ms, vr.duration_ms);
    }

    // ─── RollbackPlanner Tests ─────────────────────────────────────────

    #[test]
    fn test_planner_returns_candidates() {
        let mut store = SnapshotStore::with_defaults();
        store
            .create_snapshot("d", make_data(vec![("a", serde_json::json!(1))]))
            .unwrap();
        store
            .create_snapshot("d", make_data(vec![("a", serde_json::json!(2))]))
            .unwrap();
        let current = make_data(vec![("a", serde_json::json!(3))]);
        let candidates = RollbackPlanner::plan_rollback(&store, "d", &current).unwrap();
        assert_eq!(candidates.len(), 2);
        // First candidate should have highest score
        assert!(candidates[0].score >= candidates[1].score);
    }

    #[test]
    fn test_planner_empty_domain() {
        let store = SnapshotStore::with_defaults();
        let current = make_data(vec![]);
        let result = RollbackPlanner::plan_rollback(&store, "d", &current);
        assert!(result.is_err());
    }

    #[test]
    fn test_planner_best_candidate() {
        let mut store = SnapshotStore::with_defaults();
        store
            .create_last_known_good("d", make_data(vec![("a", serde_json::json!(1))]))
            .unwrap();
        store
            .create_snapshot("d", make_data(vec![("a", serde_json::json!(2))]))
            .unwrap();
        let current = make_data(vec![("a", serde_json::json!(3))]);
        let best = RollbackPlanner::best_candidate(&store, "d", &current).unwrap();
        assert!(best.is_some());
        // LKG should be preferred
        assert!(best.as_ref().unwrap().snapshot.has_tag("last-known-good"));
    }

    #[test]
    fn test_planner_rationale_nonempty() {
        let mut store = SnapshotStore::with_defaults();
        store
            .create_snapshot("d", make_data(vec![("x", serde_json::json!(1))]))
            .unwrap();
        let current = make_data(vec![("x", serde_json::json!(2))]);
        let candidates = RollbackPlanner::plan_rollback(&store, "d", &current).unwrap();
        assert!(!candidates[0].rationale.is_empty());
    }

    #[test]
    fn test_planner_risk_bounds() {
        let mut store = SnapshotStore::with_defaults();
        store
            .create_snapshot("d", make_data(vec![("x", serde_json::json!(1))]))
            .unwrap();
        let current = make_data(vec![("x", serde_json::json!(1))]);
        let candidates = RollbackPlanner::plan_rollback(&store, "d", &current).unwrap();
        let risk = candidates[0].estimated_risk;
        assert!(risk >= 0.0 && risk <= 100.0);
    }

    #[test]
    fn test_planner_score_bounds() {
        let mut store = SnapshotStore::with_defaults();
        store
            .create_snapshot("d", make_data(vec![("a", serde_json::json!(1))]))
            .unwrap();
        let current = make_data(vec![("a", serde_json::json!(99))]);
        let candidates = RollbackPlanner::plan_rollback(&store, "d", &current).unwrap();
        for c in &candidates {
            assert!(c.score >= 0.0 && c.score <= 100.0);
        }
    }

    // ─── RollbackOutcome Tests ─────────────────────────────────────────

    #[test]
    fn test_outcome_display() {
        assert_eq!(format!("{}", RollbackOutcome::Success), "Success");
        assert_eq!(format!("{}", RollbackOutcome::DryRun), "DryRun");
        assert_eq!(format!("{}", RollbackOutcome::Aborted), "Aborted");
    }

    #[test]
    fn test_outcome_serialization() {
        let outcomes = vec![
            RollbackOutcome::Success,
            RollbackOutcome::PartialSuccess,
            RollbackOutcome::Failed,
            RollbackOutcome::VerificationFailed,
            RollbackOutcome::Timeout,
            RollbackOutcome::Aborted,
            RollbackOutcome::DryRun,
        ];
        for o in outcomes {
            let json = serde_json::to_string(&o).unwrap();
            let restored: RollbackOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, restored);
        }
    }

    // ─── DiffType Tests ────────────────────────────────────────────────

    #[test]
    fn test_diff_type_display() {
        assert_eq!(format!("{}", DiffType::Added), "Added");
        assert_eq!(format!("{}", DiffType::Removed), "Removed");
        assert_eq!(format!("{}", DiffType::Modified), "Modified");
        assert_eq!(format!("{}", DiffType::Unchanged), "Unchanged");
    }

    #[test]
    fn test_diff_type_serialization() {
        let types = vec![
            DiffType::Added,
            DiffType::Removed,
            DiffType::Modified,
            DiffType::Unchanged,
        ];
        for dt in types {
            let json = serde_json::to_string(&dt).unwrap();
            let restored: DiffType = serde_json::from_str(&json).unwrap();
            assert_eq!(dt, restored);
        }
    }

    // ─── Integration Tests ─────────────────────────────────────────────

    #[test]
    fn test_integration_full_rollback_lifecycle() {
        // 1. Create store, push LKG + current
        let store = make_store();
        let lkg_id = {
            let mut s = store.lock().unwrap();
            let lkg = s
                .create_last_known_good("app", make_data(vec![
                    ("port", serde_json::json!(8080)),
                    ("log_level", serde_json::json!("info")),
                    ("workers", serde_json::json!(4)),
                ]))
                .unwrap();
            let id = lkg.snapshot_id.clone();
            // Current (broken) state
            s.create_snapshot("app", make_data(vec![
                ("port", serde_json::json!(9090)),
                ("log_level", serde_json::json!("debug")),
                ("workers", serde_json::json!(1)),
            ]))
            .unwrap();
            id
        };

        // 2. Plan rollback
        let current = make_data(vec![
            ("port", serde_json::json!(9090)),
            ("log_level", serde_json::json!("debug")),
            ("workers", serde_json::json!(1)),
        ]);
        let candidates = {
            let s = store.lock().unwrap();
            RollbackPlanner::plan_rollback(&s, "app", &current).unwrap()
        };
        assert!(!candidates.is_empty());

        // 3. Dry run
        let config = RollbackConfig::new()
            .with_auto_snapshot(false)
            .with_verify(false);
        let mut executor = RollbackExecutor::new(store.clone(), config);
        let dry = executor.dry_run("app", &lkg_id).unwrap();
        assert_eq!(dry.outcome, RollbackOutcome::DryRun);

        // 4. Execute actual rollback
        let result = executor.execute_rollback("app", &lkg_id).unwrap();
        assert_eq!(result.outcome, RollbackOutcome::Success);
    }

    #[test]
    fn test_integration_multi_domain_isolation() {
        let store = make_store();
        {
            let mut s = store.lock().unwrap();
            s.create_snapshot("domain-a", make_data(vec![("k", serde_json::json!("a"))]))
                .unwrap();
            s.create_snapshot("domain-b", make_data(vec![("k", serde_json::json!("b"))]))
                .unwrap();
        }
        let s = store.lock().unwrap();
        assert_eq!(s.count("domain-a"), 1);
        assert_eq!(s.count("domain-b"), 1);
        assert_eq!(s.total_count(), 2);
    }

    #[test]
    fn test_integration_snapshot_serialization_across_boundary() {
        let data = make_data(vec![
            ("config", serde_json::json!({"key": "value"})),
            ("count", serde_json::json!(42)),
            ("enabled", serde_json::json!(true)),
        ]);
        let snap = StateSnapshot::new("boundary-test", data).unwrap();
        let json = snap.to_json().unwrap();
        let restored = StateSnapshot::from_json(&json).unwrap();
        assert_eq!(snap.domain, restored.domain);
        assert_eq!(snap.data.len(), restored.data.len());
        assert!(restored.verify_checksum().unwrap());
    }

    #[test]
    fn test_integration_complex_diff_reverse() {
        let d1 = make_data(vec![
            ("a", serde_json::json!(1)),
            ("b", serde_json::json!("hello")),
            ("c", serde_json::json!(true)),
            ("d", serde_json::json!(null)),
        ]);
        let d2 = make_data(vec![
            ("a", serde_json::json!("changed")), // type change
            ("b", serde_json::json!("world")),  // same type
            ("e", serde_json::json!(3.14)),     // added
            // c and d removed
        ]);
        let s1 = StateSnapshot::new("d", d1).unwrap();
        let s2 = StateSnapshot::new("d", d2).unwrap();
        let diff = s1.diff(&s2).unwrap();

        // Apply reverse to s2, should get back s1's data
        let mut reversed = s2.clone();
        diff.apply_reverse(&mut reversed).unwrap();
        assert_eq!(reversed.get("a"), s1.get("a"));
        assert_eq!(reversed.get("b"), s1.get("b"));
        assert_eq!(reversed.get("c"), s1.get("c"));
        assert_eq!(reversed.get("d"), s1.get("d"));
        assert_eq!(reversed.get("e"), None); // removed during reverse
    }

    #[test]
    fn test_integration_rollback_result_serialization() {
        let result = RollbackResult::success("rb-1", "dom", "src-1", "tgt-1", 123);
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.rollback_id, "rb-1");
        assert_eq!(restored.outcome, RollbackOutcome::Success);
        assert_eq!(restored.duration_ms, 123);
    }
}
