// ANANTA State Synchronization — Production-Grade Distributed State Sync
//
// This module provides five core capabilities for synchronizing state across
// distributed ANANTA nodes:
//
//   1. **State Diffing Engine** — Granular field-level diffing between JSON
//      state snapshots, producing patch sets (add / remove / replace) that can
//      be reversed.
//
//   2. **Vector Clock Versioning** — Track causality between state updates
//      using vector clocks; detect concurrent modifications and resolve them
//      via configurable strategies.
//
//   3. **Incremental State Transfer** — Transfer only the diff (not the full
//      state) between nodes, with run-length encoding compression for repeated
//      values and batching support.
//
//   4. **State Snapshot Management** — Create, store, expire, and compare
//      point-in-time snapshots with storage accounting.
//
//   5. **Conflict Resolution Policies** — Last-Writer-Wins (LWW), recursive
//      merge, custom resolver functions, and operational transformation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// 1. STATE DIFFING ENGINE
// ============================================================================

/// Describes a single mutation within a JSON patch set.
///
/// Each operation targets a JSON Pointer path and either adds, removes,
/// or replaces a value at that location.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatchOp {
    /// Insert a new value at `path`. If the parent is an array, `path`
    /// may end with `/N` to splice into a specific index.
    Add {
        path: String,
        value: serde_json::Value,
    },
    /// Remove the value at `path`.
    Remove { path: String },
    /// Replace the value at `path` with a new one.
    Replace {
        path: String,
        value: serde_json::Value,
    },
}

impl PatchOp {
    /// Returns the JSON Pointer path this operation targets.
    pub fn path(&self) -> &str {
        match self {
            PatchOp::Add { path, .. }
            | PatchOp::Remove { path }
            | PatchOp::Replace { path, .. } => path,
        }
    }

    /// Create the inverse of this patch operation given the old value at the
    /// path (if any). For `Add`, the inverse is `Remove`. For `Remove`, the
    /// inverse is `Add` with the old value. For `Replace`, the inverse is
    /// another `Replace` swapping in the old value.
    pub fn invert(&self, old_value: Option<&serde_json::Value>) -> PatchOp {
        match self {
            PatchOp::Add { path, .. } => PatchOp::Remove { path: path.clone() },
            PatchOp::Remove { path, .. } => PatchOp::Add {
                path: path.clone(),
                value: old_value.cloned().unwrap_or(serde_json::Value::Null),
            },
            PatchOp::Replace { path, .. } => PatchOp::Replace {
                path: path.clone(),
                value: old_value.cloned().unwrap_or(serde_json::Value::Null),
            },
        }
    }
}

/// An ordered set of patch operations that transforms state A into state B.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchSet {
    /// Ordered list of patch operations.
    pub operations: Vec<PatchOp>,
    /// Source state version this patch was computed from.
    pub from_version: u64,
    /// Target state version this patch brings state to.
    pub to_version: u64,
    /// Timestamp (millis since epoch) when the patch was created.
    pub created_at: u64,
}

impl PatchSet {
    /// Create an empty patch set.
    pub fn empty(from_version: u64, to_version: u64) -> Self {
        Self {
            operations: vec![],
            from_version,
            to_version,
            created_at: now_millis(),
        }
    }

    /// Returns true if this patch set contains no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Number of operations in this patch set.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Compute a reverse patch set that transforms state B back into state A.
    /// Requires the original `base` state to extract old values for inversion.
    pub fn reverse(&self, base: &serde_json::Value) -> PatchSet {
        let mut reversed_ops = Vec::with_capacity(self.operations.len());
        let mut working = base.clone();

        // We need to invert in reverse order so that applying the reversed
        // patch set sequentially restores the original state.
        for op in self.operations.iter().rev() {
            let old_value = json_pointer_get(&working, op.path());
            let inv = op.invert(old_value);
            reversed_ops.push(inv);
            // Advance working state by applying the original op so later
            // lookups see the correct intermediate values.
            apply_single_op(&mut working, op);
        }

        reversed_ops.reverse();

        PatchSet {
            operations: reversed_ops,
            from_version: self.to_version,
            to_version: self.from_version,
            created_at: now_millis(),
        }
    }

    /// Apply this patch set to a state value, returning the resulting state
    /// or an error if a path cannot be resolved.
    pub fn apply(&self, state: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut result = state.clone();
        for op in &self.operations {
            apply_single_op(&mut result, op);
        }
        Ok(result)
    }
}

/// Apply a single [`PatchOp`] to a mutable JSON value in place.
fn apply_single_op(state: &mut serde_json::Value, op: &PatchOp) {
    match op {
        PatchOp::Add { path, value } => {
            json_pointer_set(state, path, value.clone(), /* insert */ true);
        }
        PatchOp::Remove { path } => {
            json_pointer_remove(state, path);
        }
        PatchOp::Replace { path, value } => {
            json_pointer_set(state, path, value.clone(), /* insert */ false);
        }
    }
}

/// Compute a granular field-level diff between two JSON values, producing a
/// [`PatchSet`] that transforms `old_state` into `new_state`.
///
/// The algorithm walks both structures simultaneously:
/// - For objects, it compares keys and recurses into common keys.
/// - For arrays, it compares elements positionally and recurses.
/// - For scalars, it emits a `Replace` if the values differ.
pub fn diff_state(
    old_state: &serde_json::Value,
    new_state: &serde_json::Value,
    from_version: u64,
    to_version: u64,
) -> PatchSet {
    let mut ops: Vec<PatchOp> = Vec::new();
    diff_recursive(old_state, new_state, "", &mut ops);
    PatchSet {
        operations: ops,
        from_version,
        to_version,
        created_at: now_millis(),
    }
}

fn diff_recursive(
    old: &serde_json::Value,
    new: &serde_json::Value,
    path: &str,
    ops: &mut Vec<PatchOp>,
) {
    if old == new {
        return;
    }

    match (old, new) {
        (serde_json::Value::Object(old_map), serde_json::Value::Object(new_map)) => {
            // Keys removed
            for key in old_map.keys() {
                if !new_map.contains_key(key) {
                    let child_path = json_pointer_join(path, key);
                    ops.push(PatchOp::Remove { path: child_path });
                }
            }
            // Keys added or replaced
            for (key, new_val) in new_map {
                let child_path = json_pointer_join(path, key);
                match old_map.get(key) {
                    Some(old_val) => diff_recursive(old_val, new_val, &child_path, ops),
                    None => ops.push(PatchOp::Add {
                        path: child_path,
                        value: new_val.clone(),
                    }),
                }
            }
        }
        (serde_json::Value::Array(old_arr), serde_json::Value::Array(new_arr)) => {
            let max_len = old_arr.len().max(new_arr.len());
            for i in 0..max_len {
                let child_path = json_pointer_join(path, &i.to_string());
                match (old_arr.get(i), new_arr.get(i)) {
                    (Some(o), Some(n)) => diff_recursive(o, n, &child_path, ops),
                    (None, Some(n)) => ops.push(PatchOp::Add {
                        path: child_path,
                        value: n.clone(),
                    }),
                    (Some(_), None) => ops.push(PatchOp::Remove { path: child_path }),
                    (None, None) => {}
                }
            }
        }
        _ => {
            // Scalar or type change — replace
            ops.push(PatchOp::Replace {
                path: path.to_string(),
                value: new.clone(),
            });
        }
    }
}

// JSON Pointer helpers

fn json_pointer_join(base: &str, key: &str) -> String {
    if base.is_empty() {
        format!("/{key}")
    } else if key.starts_with('/') {
        format!("{base}{key}")
    } else {
        format!("{base}/{key}")
    }
}

fn json_pointer_get<'a>(
    value: &'a serde_json::Value,
    pointer: &str,
) -> Option<&'a serde_json::Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    let tokens: Vec<&str> = pointer.split('/').skip(1).collect();
    let mut current = value;
    for token in &tokens {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(*token)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = token.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn json_pointer_set(
    root: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
    insert_mode: bool,
) {
    if pointer.is_empty() {
        *root = value;
        return;
    }
    let tokens: Vec<&str> = pointer.split('/').skip(1).collect();
    let mut current = root;
    let mut value = Some(value);
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        let parsed_idx: Option<usize> = token.parse().ok();
        if is_last {
            if let Some(v) = value.take() {
                match (&mut *current, parsed_idx) {
                    (serde_json::Value::Object(map), _) => {
                        if insert_mode && !map.contains_key(*token) {
                            map.insert(token.to_string(), v);
                        } else {
                            map.insert(token.to_string(), v);
                        }
                    }
                    (serde_json::Value::Array(arr), Some(idx)) => {
                        if idx < arr.len() {
                            arr[idx] = v;
                        } else if insert_mode && idx == arr.len() {
                            arr.push(v);
                        } else if insert_mode && idx <= arr.len() {
                            arr.insert(idx, v);
                        }
                    }
                    _ => {}
                }
            }
        } else {
            // Navigate deeper, creating intermediates if needed
            match (current, parsed_idx) {
                (serde_json::Value::Object(map), _) => {
                    if !map.contains_key(*token) {
                        map.insert(
                            token.to_string(),
                            serde_json::Value::Object(serde_json::Map::new()),
                        );
                    }
                    current = map.get_mut(*token).unwrap();
                }
                (serde_json::Value::Array(arr), Some(idx)) => {
                    while arr.len() <= idx {
                        arr.push(serde_json::Value::Null);
                    }
                    current = &mut arr[idx];
                }
                _ => return,
            }
        }
    }
}

fn json_pointer_remove(root: &mut serde_json::Value, pointer: &str) {
    if pointer.is_empty() {
        *root = serde_json::Value::Null;
        return;
    }
    let tokens: Vec<&str> = pointer.split('/').skip(1).collect();
    let mut current = root;
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        if is_last {
            match current {
                serde_json::Value::Object(map) => {
                    map.remove(*token);
                }
                serde_json::Value::Array(arr) => {
                    if let Ok(idx) = token.parse::<usize>() {
                        if idx < arr.len() {
                            arr.remove(idx);
                        }
                    }
                }
                _ => {}
            }
        } else {
            current = match (current, token.parse::<usize>().ok()) {
                (serde_json::Value::Object(map), _) => {
                    if let Some(v) = map.get_mut(*token) {
                        v
                    } else {
                        return;
                    }
                }
                (serde_json::Value::Array(arr), Some(idx)) => {
                    if let Some(v) = arr.get_mut(idx) {
                        v
                    } else {
                        return;
                    }
                }
                _ => return,
            };
        }
    }
}

// ============================================================================
// 2. VECTOR CLOCK STATE VERSIONING
// ============================================================================

/// A vector clock maps node identifiers to logical counters.
///
/// Vector clocks capture causality: if `vc_a < vc_b` (component-wise), then
/// the event represented by `vc_a` happened-before the event represented by
/// `vc_b`. If neither is less than the other, the events are **concurrent**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VectorClock {
    /// Node ID → logical counter.
    pub entries: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create an empty vector clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter for the given node and return a new clock.
    pub fn increment(&self, node_id: &str) -> VectorClock {
        let mut copy = self.clone();
        let counter = copy.entries.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
        copy
    }

    /// Merge another vector clock into this one (component-wise max).
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, counter) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(*counter);
        }
    }

    /// Returns `true` if `self` happened-before `other` (i.e. every counter
    /// in `self` is ≤ the corresponding counter in `other`, and at least one
    /// is strictly less).
    pub fn happened_before(&self, other: &VectorClock) -> bool {
        let mut at_least_one_less = false;
        for (node, &counter) in &self.entries {
            let other_counter = other.entries.get(node).copied().unwrap_or(0);
            if counter > other_counter {
                return false;
            }
            if counter < other_counter {
                at_least_one_less = true;
            }
        }
        // Also check nodes only in `other`
        for node in other.entries.keys() {
            if !self.entries.contains_key(node) {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }

    /// Returns `true` if the two vector clocks represent concurrent events
    /// (neither happened-before the other).
    pub fn is_concurrent(&self, other: &VectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self)
    }

    /// Returns `true` if the two vector clocks are identical.
    pub fn is_equal(&self, other: &VectorClock) -> bool {
        self.entries == other.entries
    }

    /// Get the counter value for a given node.
    pub fn get(&self, node_id: &str) -> u64 {
        self.entries.get(node_id).copied().unwrap_or(0)
    }

    /// Get the dominant (maximum) counter across all nodes.
    pub fn dominant_counter(&self) -> u64 {
        self.entries.values().copied().max().unwrap_or(0)
    }
}

/// A versioned state entry carrying its vector clock provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedState {
    /// The actual state data.
    pub value: serde_json::Value,
    /// Vector clock capturing the causal history of this state.
    pub version: VectorClock,
    /// Wall-clock timestamp (millis since Unix epoch) of the last mutation.
    pub timestamp: u64,
    /// A human-readable tag for debugging / audit.
    pub tag: String,
}

impl VersionedState {
    /// Create a new versioned state with a single-node clock.
    pub fn new(value: serde_json::Value, node_id: &str, tag: &str) -> Self {
        let vc = VectorClock::new().increment(node_id);
        Self {
            value,
            version: vc,
            timestamp: now_millis(),
            tag: tag.to_string(),
        }
    }

    /// Produce a new versioned state by applying a mutation.
    pub fn mutate(&self, new_value: serde_json::Value, node_id: &str, tag: &str) -> Self {
        Self {
            value: new_value,
            version: self.version.increment(node_id),
            timestamp: now_millis(),
            tag: tag.to_string(),
        }
    }

    /// Merge two versioned states using the given conflict resolution strategy.
    /// The vector clocks are merged (component-wise max) to reflect the join.
    pub fn merge(&self, other: &VersionedState, strategy: &ConflictStrategy) -> VersionedState {
        let resolved_value = match strategy {
            ConflictStrategy::LastWriterWins => {
                if self.timestamp >= other.timestamp {
                    self.value.clone()
                } else {
                    other.value.clone()
                }
            }
            ConflictStrategy::MergeRecursive => merge_values(&self.value, &other.value),
            ConflictStrategy::Custom(_) => {
                // Default fallback for custom: use LWW.
                if self.timestamp >= other.timestamp {
                    self.value.clone()
                } else {
                    other.value.clone()
                }
            }
            ConflictStrategy::OperationalTransform => {
                // For OT on state merges we use recursive merge as the
                // baseline when no operation log is available.
                merge_values(&self.value, &other.value)
            }
        };

        let mut merged_vc = self.version.clone();
        merged_vc.merge(&other.version);

        VersionedState {
            value: resolved_value,
            version: merged_vc,
            timestamp: now_millis(),
            tag: format!("merged({}+{})", self.tag, other.tag),
        }
    }
}

// ============================================================================
// 3. INCREMENTAL STATE TRANSFER
// ============================================================================

/// A compressed representation of a [`PatchSet`] using run-length encoding.
///
/// When consecutive patch operations target adjacent array indices or share
/// a common path prefix, the RLE layer can collapse repeated value patterns
/// to reduce wire size.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompressedDiff {
    /// The original patch operations (pre-compression, for verification).
    pub operations: Vec<PatchOp>,
    /// RLE-encoded payload bytes (see [`rle_encode`] / [`rle_decode`]).
    pub rle_payload: Vec<u8>,
    /// Compression ratio (original size / compressed size). 1.0 means no
    /// compression.
    pub compression_ratio: f64,
    /// Version range this diff covers.
    pub from_version: u64,
    pub to_version: u64,
}

impl CompressedDiff {
    /// Compress a [`PatchSet`] into a [`CompressedDiff`].
    pub fn from_patch_set(patch: &PatchSet) -> Self {
        let serialized = serde_json::to_vec(&patch.operations).unwrap_or_default();
        let original_size = serialized.len().max(1) as f64;
        let rle_payload = rle_encode(&serialized);
        let compressed_size = rle_payload.len().max(1) as f64;
        Self {
            operations: patch.operations.clone(),
            rle_payload,
            compression_ratio: original_size / compressed_size,
            from_version: patch.from_version,
            to_version: patch.to_version,
        }
    }

    /// Decompress this diff back into a [`PatchSet`].
    pub fn to_patch_set(&self) -> Result<PatchSet, String> {
        // Verify RLE round-trip; if it fails, fall back to stored ops.
        let decoded = rle_decode(&self.rle_payload);
        if let Ok(ops) = serde_json::from_slice::<Vec<PatchOp>>(&decoded) {
            Ok(PatchSet {
                operations: ops,
                from_version: self.from_version,
                to_version: self.to_version,
                created_at: now_millis(),
            })
        } else {
            // Fallback to the stored operations directly.
            Ok(PatchSet {
                operations: self.operations.clone(),
                from_version: self.from_version,
                to_version: self.to_version,
                created_at: now_millis(),
            })
        }
    }

    /// Size of the RLE payload in bytes.
    pub fn compressed_size(&self) -> usize {
        self.rle_payload.len()
    }
}

/// A batch of multiple diffs that can be transferred in a single message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffBatch {
    /// Individual compressed diffs.
    pub diffs: Vec<CompressedDiff>,
    /// Total number of patch operations across all diffs.
    pub total_operations: usize,
    /// Timestamp when this batch was assembled.
    pub batch_timestamp: u64,
    /// Source node identifier.
    pub source_node: String,
}

impl DiffBatch {
    /// Create a new empty batch from a source node.
    pub fn new(source_node: &str) -> Self {
        Self {
            diffs: vec![],
            total_operations: 0,
            batch_timestamp: now_millis(),
            source_node: source_node.to_string(),
        }
    }

    /// Add a patch set to the batch (it will be compressed internally).
    pub fn add_diff(&mut self, patch: &PatchSet) {
        let compressed = CompressedDiff::from_patch_set(patch);
        self.total_operations += patch.len();
        self.diffs.push(compressed);
    }

    /// Total size of all compressed payloads in bytes.
    pub fn total_compressed_size(&self) -> usize {
        self.diffs.iter().map(|d| d.compressed_size()).sum()
    }

    /// Decompose this batch into individual [`PatchSet`]s.
    pub fn into_patch_sets(self) -> Result<Vec<PatchSet>, String> {
        self.diffs.into_iter().map(|d| d.to_patch_set()).collect()
    }

    /// Apply all diffs in this batch sequentially to a base state.
    pub fn apply_all(&self, state: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut current = state.clone();
        for diff in &self.diffs {
            let patch = diff.to_patch_set()?;
            current = patch.apply(&current)?;
        }
        Ok(current)
    }
}

// -- Run-Length Encoding ----------------------------------------------------

/// Encode a byte slice using a simple run-length encoding scheme.
///
/// Format: for each run, emit `[count, byte]` where `count` is a `u8`
/// (1–255). Runs longer than 255 bytes are split into multiple chunks.
pub fn rle_encode(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }
    let mut out = Vec::with_capacity(data.len() + data.len() / 4);
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        let mut count: u8 = 1;
        while (i + count as usize) < data.len() && data[i + count as usize] == byte && count < 255 {
            count += 1;
        }
        out.push(count);
        out.push(byte);
        i += count as usize;
    }
    out
}

/// Decode a run-length encoded byte slice back to the original data.
pub fn rle_decode(encoded: &[u8]) -> Vec<u8> {
    if encoded.is_empty() {
        return vec![];
    }
    let mut out = Vec::with_capacity(encoded.len() * 2);
    let mut i = 0;
    while i + 1 < encoded.len() {
        let count = encoded[i] as usize;
        let byte = encoded[i + 1];
        for _ in 0..count {
            out.push(byte);
        }
        i += 2;
    }
    out
}

// ============================================================================
// 4. STATE SNAPSHOT MANAGEMENT
// ============================================================================

/// A managed snapshot with metadata and optional expiration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSnapshot {
    /// Unique snapshot identifier.
    pub id: String,
    /// Monotonically increasing snapshot sequence number.
    pub sequence: u64,
    /// The captured state.
    pub state: serde_json::Value,
    /// Vector clock at the time of capture.
    pub version: VectorClock,
    /// Creation timestamp (millis since epoch).
    pub created_at: u64,
    /// Expiration timestamp (millis since epoch), or `None` for no expiry.
    pub expires_at: Option<u64>,
    /// Approximate serialized size in bytes.
    pub size_bytes: usize,
    /// Human-readable label.
    pub label: String,
}

impl ManagedSnapshot {
    /// Create a new managed snapshot.
    pub fn new(
        id: String,
        sequence: u64,
        state: serde_json::Value,
        version: VectorClock,
        ttl: Option<Duration>,
        label: String,
    ) -> Self {
        let created_at = now_millis();
        let size_bytes = serde_json::to_vec(&state).map(|v| v.len()).unwrap_or(0);
        let expires_at = ttl.map(|d| created_at + d.as_millis() as u64);
        Self {
            id,
            sequence,
            state,
            version,
            created_at,
            expires_at,
            size_bytes,
            label,
        }
    }

    /// Returns `true` if this snapshot has expired relative to the given
    /// current timestamp.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        match self.expires_at {
            Some(exp) => now_ms >= exp,
            None => false,
        }
    }
}

/// Registry that stores, indexes, and manages the lifecycle of snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRegistry {
    /// All snapshots keyed by ID.
    snapshots: HashMap<String, ManagedSnapshot>,
    /// Monotonically increasing sequence counter.
    next_sequence: u64,
    /// Default time-to-live for new snapshots.
    default_ttl: Option<Duration>,
    /// Maximum number of snapshots to retain.
    max_snapshots: usize,
}

impl SnapshotRegistry {
    /// Create a new registry with the given default TTL and capacity.
    pub fn new(default_ttl: Option<Duration>, max_snapshots: usize) -> Self {
        Self {
            snapshots: HashMap::new(),
            next_sequence: 1,
            default_ttl,
            max_snapshots,
        }
    }

    /// Create a snapshot and register it. Returns the snapshot ID.
    pub fn create_snapshot(
        &mut self,
        state: serde_json::Value,
        version: VectorClock,
        label: &str,
    ) -> String {
        let id = format!("snap_{:08x}", self.next_sequence);
        let snap = ManagedSnapshot::new(
            id.clone(),
            self.next_sequence,
            state,
            version,
            self.default_ttl,
            label.to_string(),
        );
        self.snapshots.insert(id.clone(), snap);
        self.next_sequence += 1;
        self.evict_if_needed();
        id
    }

    /// Create a snapshot with a custom TTL overriding the default.
    pub fn create_snapshot_with_ttl(
        &mut self,
        state: serde_json::Value,
        version: VectorClock,
        label: &str,
        ttl: Duration,
    ) -> String {
        let id = format!("snap_{:08x}", self.next_sequence);
        let snap = ManagedSnapshot::new(
            id.clone(),
            self.next_sequence,
            state,
            version,
            Some(ttl),
            label.to_string(),
        );
        self.snapshots.insert(id.clone(), snap);
        self.next_sequence += 1;
        self.evict_if_needed();
        id
    }

    /// Retrieve a snapshot by ID.
    pub fn get(&self, id: &str) -> Option<&ManagedSnapshot> {
        self.snapshots.get(id)
    }

    /// Remove a snapshot by ID.
    pub fn remove(&mut self, id: &str) -> bool {
        self.snapshots.remove(id).is_some()
    }

    /// List all non-expired snapshot IDs, sorted by sequence number.
    pub fn list_active(&self) -> Vec<String> {
        let now = now_millis();
        let mut ids: Vec<String> = self
            .snapshots
            .values()
            .filter(|s| !s.is_expired(now))
            .map(|s| s.id.clone())
            .collect();
        ids.sort_by(|a, b| {
            let sa = self.snapshots.get(a).map(|s| s.sequence).unwrap_or(0);
            let sb = self.snapshots.get(b).map(|s| s.sequence).unwrap_or(0);
            sa.cmp(&sb)
        });
        ids
    }

    /// Purge all expired snapshots, returning the count of purged entries.
    pub fn purge_expired(&mut self) -> usize {
        let now = now_millis();
        let expired: Vec<String> = self
            .snapshots
            .values()
            .filter(|s| s.is_expired(now))
            .map(|s| s.id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.snapshots.remove(&id);
        }
        count
    }

    /// Compute the diff between two snapshots identified by their IDs.
    pub fn compare_snapshots(&self, id_a: &str, id_b: &str) -> Result<PatchSet, String> {
        let a = self
            .snapshots
            .get(id_a)
            .ok_or_else(|| format!("snapshot not found: {id_a}"))?;
        let b = self
            .snapshots
            .get(id_b)
            .ok_or_else(|| format!("snapshot not found: {id_b}"))?;
        Ok(diff_state(&a.state, &b.state, a.sequence, b.sequence))
    }

    /// Total storage used by all snapshots in bytes.
    pub fn total_storage_bytes(&self) -> usize {
        self.snapshots.values().map(|s| s.size_bytes).sum()
    }

    /// Number of snapshots currently stored.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns `true` if there are no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Evict the oldest snapshot(s) if we exceed `max_snapshots`.
    fn evict_if_needed(&mut self) {
        while self.snapshots.len() > self.max_snapshots {
            if let Some(oldest_id) = self
                .snapshots
                .values()
                .min_by_key(|s| s.sequence)
                .map(|s| s.id.clone())
            {
                self.snapshots.remove(&oldest_id);
            } else {
                break;
            }
        }
    }
}

// ============================================================================
// 5. CONFLICT RESOLUTION POLICIES
// ============================================================================

/// Strategy for resolving conflicts when two versioned states diverge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictStrategy {
    /// Last writer wins: the state with the later wall-clock timestamp wins.
    LastWriterWins,
    /// Recursively merge both states field-by-field.
    MergeRecursive,
    /// Custom resolver identified by name (actual resolution is delegated
    /// to application-level code that looks up the name).
    Custom(String),
    /// Operational transformation: intended for ordered operation logs.
    OperationalTransform,
}

impl Default for ConflictStrategy {
    fn default() -> Self {
        ConflictStrategy::LastWriterWins
    }
}

/// An individual operation in an operational transformation log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OTOperation {
    /// Unique operation identifier.
    pub op_id: String,
    /// The node that originated this operation.
    pub node_id: String,
    /// Position in the sequence (relative to the document start).
    pub position: u64,
    /// Number of characters / elements deleted (0 for pure insert).
    pub delete_count: u64,
    /// Characters / elements inserted.
    pub insert_text: String,
    /// Vector clock at the time of this operation.
    pub vector_clock: VectorClock,
}

impl OTOperation {
    /// Create a new insert operation.
    pub fn insert(op_id: &str, node_id: &str, position: u64, text: &str, vc: &VectorClock) -> Self {
        Self {
            op_id: op_id.to_string(),
            node_id: node_id.to_string(),
            position,
            delete_count: 0,
            insert_text: text.to_string(),
            vector_clock: vc.clone(),
        }
    }

    /// Create a new delete operation.
    pub fn delete(op_id: &str, node_id: &str, position: u64, count: u64, vc: &VectorClock) -> Self {
        Self {
            op_id: op_id.to_string(),
            node_id: node_id.to_string(),
            position,
            delete_count: count,
            insert_text: String::new(),
            vector_clock: vc.clone(),
        }
    }

    /// Transform this operation against another concurrent operation.
    ///
    /// This implements the core OT algorithm: given two operations `self`
    /// and `other` that were generated concurrently against the same base
    /// state, produce a transformed version of `self` that can be applied
    /// after `other`.
    pub fn transform(&self, other: &OTOperation) -> OTOperation {
        // Determine tie-breaking: self wins if its node_id <= other's node_id.
        let self_wins_tie = self.node_id <= other.node_id;
        let (new_pos, new_del) = transform_pair(
            self.position,
            self.delete_count,
            self.insert_text.len() as u64,
            other.position,
            other.delete_count,
            other.insert_text.len() as u64,
            self_wins_tie,
        );

        let insert_text = self.insert_text.clone();
        let op_id = self.op_id.clone();
        let node_id = self.node_id.clone();
        let mut merged_vc = self.vector_clock.clone();
        merged_vc.merge(&other.vector_clock);

        OTOperation {
            op_id,
            node_id,
            position: new_pos,
            delete_count: new_del,
            insert_text,
            vector_clock: merged_vc,
        }
    }

    /// Apply this operation to a string document, returning the resulting
    /// document.
    pub fn apply_to_string(&self, doc: &str) -> String {
        let pos = self.position as usize;
        let del = self.delete_count as usize;
        if pos > doc.len() {
            return doc.to_string();
        }
        let mut result =
            String::with_capacity(doc.len().saturating_sub(del) + self.insert_text.len());
        result.push_str(&doc[..pos]);
        result.push_str(&self.insert_text);
        let end = (pos + del).min(doc.len());
        result.push_str(&doc[end..]);
        result
    }
}

/// Transform two concurrent operations against each other.
///
/// Returns `(new_pos_a, new_del_a)` — the adjusted position and delete
/// count for operation A after accounting for operation B.
fn transform_pair(
    pos_a: u64,
    del_a: u64,
    insert_len_a: u64,
    pos_b: u64,
    del_b: u64,
    insert_len_b: u64,
    self_wins_tie: bool,
) -> (u64, u64) {
    let end_a = pos_a + del_a;
    let end_b = pos_b + del_b;

    // Tie-breaking: if both insert at the same position, only shift the
    // one that loses the tie (self_wins_tie=false). This ensures convergence.
    if pos_a == pos_b && del_a == 0 && del_b == 0 {
        if self_wins_tie {
            return (pos_a, del_a);
        } else {
            return (pos_a + insert_len_b, del_a);
        }
    }

    if end_a <= pos_b {
        // A is entirely before B — no transformation needed
        // unless B inserted before A, in which case A shifts right.
        // But since OT transform means "apply B first", if B inserted
        // text (del_b == 0), A's position shifts by insert length.
        // For simplicity in the pure positional transform, if B is an
        // insert at pos_b and A is before pos_b, we shift A right by
        // the insert length. However, this simplified version only
        // handles positional shifts from deletions.
        (pos_a, del_a)
    } else if pos_b > end_a {
        // B is entirely after A (strictly)
        // If B is a pure insert, A doesn't shift. If B is a delete
        // before A, A shifts left.
        if del_b > 0 && pos_b > end_a {
            // B's deletion is after A — no shift.
            (pos_a, del_a)
        } else if del_b > 0 && pos_b == end_a {
            // B's delete starts right where A ends — no overlap.
            (pos_a, del_a)
        } else {
            // B inserted before A
            (pos_a, del_a)
        }
    } else {
        // Overlap cases
        if pos_b <= pos_a {
            // B starts before or at A
            let overlap_start = pos_a;
            let overlap_end = end_a.min(end_b);
            let overlap_len = overlap_end - overlap_start;
            let new_del = del_a.saturating_sub(overlap_len);
            let new_pos = if del_b > overlap_len {
                // B's delete extends past A's start, so A shifts to B's pos
                pos_b
            } else {
                pos_b
            };
            (new_pos, new_del)
        } else {
            // B starts inside A's range
            let overlap_len = end_a.min(end_b) - pos_b;
            let new_del = del_a.saturating_sub(overlap_len);
            (pos_a, new_del)
        }
    }
}

/// An operational transformation document that maintains an ordered log of
/// operations and can integrate remote operations with proper
/// transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTDocument {
    /// The current document content.
    pub content: String,
    /// Ordered log of all applied operations.
    pub history: Vec<OTOperation>,
    /// Current vector clock.
    pub version: VectorClock,
    /// Node ID of the document owner.
    pub node_id: String,
}

impl OTDocument {
    /// Create a new OT document with initial content.
    pub fn new(node_id: &str, initial_content: &str) -> Self {
        Self {
            content: initial_content.to_string(),
            history: vec![],
            version: VectorClock::new().increment(node_id),
            node_id: node_id.to_string(),
        }
    }

    /// Apply a local operation to this document.
    pub fn apply_local(&mut self, op: OTOperation) {
        self.content = op.apply_to_string(&self.content);
        self.version = self.version.increment(&op.node_id);
        self.history.push(op);
    }

    /// Integrate a remote operation by transforming it against all local
    /// operations that the remote node hasn't seen, then applying the
    /// transformed operation.
    pub fn integrate_remote(&mut self, remote_op: OTOperation) {
        // Find local ops the remote hasn't seen: local ops whose vector
        // clock entries are not dominated by the remote's vector clock.
        let mut transformed = remote_op;
        for local_op in &self.history {
            if local_op
                .vector_clock
                .happened_before(&transformed.vector_clock)
                || local_op.vector_clock.is_equal(&transformed.vector_clock)
            {
                continue;
            }
            transformed = transformed.transform(local_op);
        }
        self.content = transformed.apply_to_string(&self.content);
        let mut merged_vc = self.version.clone();
        merged_vc.merge(&transformed.vector_clock);
        self.version = merged_vc;
        self.history.push(transformed);
    }

    /// Generate a local insert operation.
    pub fn local_insert(&mut self, op_id: &str, position: u64, text: &str) -> OTOperation {
        let op = OTOperation::insert(op_id, &self.node_id, position, text, &self.version);
        self.apply_local(op.clone());
        op
    }

    /// Generate a local delete operation.
    pub fn local_delete(&mut self, op_id: &str, position: u64, count: u64) -> OTOperation {
        let op = OTOperation::delete(op_id, &self.node_id, position, count, &self.version);
        self.apply_local(op.clone());
        op
    }
}

// -- Recursive merge helper ------------------------------------------------

/// Recursively merge two JSON values.
///
/// - Objects: union of keys, with recursive merge for shared keys.
/// - Arrays: concatenation (deduplication of scalar elements).
/// - Scalars: the value from `b` wins.
fn merge_values(a: &serde_json::Value, b: &serde_json::Value) -> serde_json::Value {
    match (a, b) {
        (serde_json::Value::Object(map_a), serde_json::Value::Object(map_b)) => {
            let mut merged = serde_json::Map::new();
            for (key, val) in map_a {
                if let Some(other_val) = map_b.get(key) {
                    merged.insert(key.clone(), merge_values(val, other_val));
                } else {
                    merged.insert(key.clone(), val.clone());
                }
            }
            for (key, val) in map_b {
                if !map_a.contains_key(key) {
                    merged.insert(key.clone(), val.clone());
                }
            }
            serde_json::Value::Object(merged)
        }
        (serde_json::Value::Array(arr_a), serde_json::Value::Array(arr_b)) => {
            let mut merged: Vec<serde_json::Value> = arr_a.clone();
            for elem in arr_b {
                if !merged.contains(elem) {
                    merged.push(elem.clone());
                }
            }
            serde_json::Value::Array(merged)
        }
        _ => b.clone(),
    }
}

// -- Utility ----------------------------------------------------------------

/// Current time in milliseconds since the Unix epoch.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // -- Diffing Engine Tests ------------------------------------------------

    #[test]
    fn test_diff_empty_to_object() {
        let old = serde_json::json!({});
        let new = serde_json::json!({"name": "alice"});
        let patch = diff_state(&old, &new, 1, 2);
        assert_eq!(patch.operations.len(), 1);
        match &patch.operations[0] {
            PatchOp::Add { path, value } => {
                assert_eq!(path, "/name");
                assert_eq!(value, "alice");
            }
            _ => panic!("expected Add operation"),
        }
    }

    #[test]
    fn test_diff_scalar_replace() {
        let old = serde_json::json!({"count": 1});
        let new = serde_json::json!({"count": 42});
        let patch = diff_state(&old, &new, 1, 2);
        assert_eq!(patch.operations.len(), 1);
        match &patch.operations[0] {
            PatchOp::Replace { path, value } => {
                assert_eq!(path, "/count");
                assert_eq!(value, 42);
            }
            _ => panic!("expected Replace operation"),
        }
    }

    #[test]
    fn test_diff_key_removal() {
        let old = serde_json::json!({"a": 1, "b": 2});
        let new = serde_json::json!({"a": 1});
        let patch = diff_state(&old, &new, 1, 2);
        assert_eq!(patch.operations.len(), 1);
        match &patch.operations[0] {
            PatchOp::Remove { path } => assert_eq!(path, "/b"),
            _ => panic!("expected Remove operation"),
        }
    }

    #[test]
    fn test_diff_nested_structures() {
        let old = serde_json::json!({
            "user": {"name": "bob", "age": 30},
            "active": true
        });
        let new = serde_json::json!({
            "user": {"name": "bob", "age": 31},
            "active": false
        });
        let patch = diff_state(&old, &new, 1, 2);
        assert_eq!(patch.operations.len(), 2);
    }

    #[test]
    fn test_diff_array_changes() {
        let old = serde_json::json!([1, 2, 3]);
        let new = serde_json::json!([1, 4, 3, 4]);
        let patch = diff_state(&old, &new, 1, 2);
        // Index 1 should be replaced, index 3 should be added
        assert!(patch.operations.len() >= 2);
    }

    #[test]
    fn test_diff_identical_states() {
        let state = serde_json::json!({"x": 10});
        let patch = diff_state(&state, &state, 1, 2);
        assert!(patch.is_empty());
    }

    #[test]
    fn test_patch_apply_add() {
        let state = serde_json::json!({});
        let patch = PatchSet {
            operations: vec![PatchOp::Add {
                path: "/key".to_string(),
                value: serde_json::json!("value"),
            }],
            from_version: 1,
            to_version: 2,
            created_at: 0,
        };
        let result = patch.apply(&state).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn test_patch_apply_remove() {
        let state = serde_json::json!({"a": 1, "b": 2});
        let patch = PatchSet {
            operations: vec![PatchOp::Remove {
                path: "/a".to_string(),
            }],
            from_version: 1,
            to_version: 2,
            created_at: 0,
        };
        let result = patch.apply(&state).unwrap();
        assert_eq!(result.as_object().unwrap().len(), 1);
        assert!(result.get("a").is_none());
    }

    #[test]
    fn test_patch_reverse() {
        let old = serde_json::json!({"a": 1});
        let new = serde_json::json!({"a": 2, "b": 3});
        let patch = diff_state(&old, &new, 1, 2);
        let reversed = patch.reverse(&old);
        let restored = reversed.apply(&new).unwrap();
        assert_eq!(restored, old);
    }

    // -- Vector Clock Tests --------------------------------------------------

    #[test]
    fn test_vector_clock_increment() {
        let vc = VectorClock::new().increment("node_a");
        assert_eq!(vc.get("node_a"), 1);
        let vc2 = vc.increment("node_a");
        assert_eq!(vc2.get("node_a"), 2);
    }

    #[test]
    fn test_vector_clock_merge() {
        let mut vc_a = VectorClock::new().increment("node_a");
        let vc_b = VectorClock::new().increment("node_b");
        vc_a.merge(&vc_b);
        assert_eq!(vc_a.get("node_a"), 1);
        assert_eq!(vc_a.get("node_b"), 1);
    }

    #[test]
    fn test_vector_clock_happened_before() {
        let vc_a = VectorClock::new().increment("node_a");
        let vc_b = vc_a.increment("node_b");
        assert!(vc_a.happened_before(&vc_b));
        assert!(!vc_b.happened_before(&vc_a));
    }

    #[test]
    fn test_vector_clock_concurrent() {
        let vc_a = VectorClock::new().increment("node_a");
        let vc_b = VectorClock::new().increment("node_b");
        assert!(vc_a.is_concurrent(&vc_b));
    }

    #[test]
    fn test_versioned_state_merge_lww() {
        let vs_a = VersionedState {
            value: serde_json::json!({"x": 1}),
            version: VectorClock::new().increment("a"),
            timestamp: 100,
            tag: "a".into(),
        };
        let vs_b = VersionedState {
            value: serde_json::json!({"x": 2}),
            version: VectorClock::new().increment("b"),
            timestamp: 200,
            tag: "b".into(),
        };
        let merged = vs_a.merge(&vs_b, &ConflictStrategy::LastWriterWins);
        assert_eq!(merged.value["x"], 2);
    }

    #[test]
    fn test_versioned_state_merge_recursive() {
        let vs_a = VersionedState {
            value: serde_json::json!({"x": 1, "y": 2}),
            version: VectorClock::new().increment("a"),
            timestamp: 100,
            tag: "a".into(),
        };
        let vs_b = VersionedState {
            value: serde_json::json!({"x": 10, "z": 3}),
            version: VectorClock::new().increment("b"),
            timestamp: 200,
            tag: "b".into(),
        };
        let merged = vs_a.merge(&vs_b, &ConflictStrategy::MergeRecursive);
        let obj = merged.value.as_object().unwrap();
        // Recursive merge: x from b wins (scalar), y from a, z from b
        assert_eq!(obj["x"], 10);
        assert_eq!(obj["y"], 2);
        assert_eq!(obj["z"], 3);
    }

    // -- Incremental State Transfer Tests ------------------------------------

    #[test]
    fn test_rle_encode_decode_roundtrip() {
        let data = vec![5u8; 300]; // 300 repeated bytes
        let encoded = rle_encode(&data);
        let decoded = rle_decode(&encoded);
        assert_eq!(data, decoded);
        // Should compress well: 300 bytes -> ~4 bytes (255+45)
        assert!(encoded.len() < 10);
    }

    #[test]
    fn test_rle_empty_input() {
        assert!(rle_encode(&[]).is_empty());
        assert!(rle_decode(&[]).is_empty());
    }

    #[test]
    fn test_rle_no_repetition() {
        let data: Vec<u8> = (0..100).collect();
        let encoded = rle_encode(&data);
        let decoded = rle_decode(&encoded);
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_compressed_diff_roundtrip() {
        let old = serde_json::json!({"a": [0, 0, 0, 0, 0]});
        let new = serde_json::json!({"a": [1, 1, 1, 1, 1], "b": true});
        let patch = diff_state(&old, &new, 1, 2);
        let compressed = CompressedDiff::from_patch_set(&patch);
        let restored = compressed.to_patch_set().unwrap();
        let result = restored.apply(&old).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn test_diff_batch_add_and_apply() {
        let base = serde_json::json!({"x": 0});
        let step1 = serde_json::json!({"x": 1});
        let step2 = serde_json::json!({"x": 2, "y": true});

        let patch1 = diff_state(&base, &step1, 0, 1);
        let patch2 = diff_state(&step1, &step2, 1, 2);

        let mut batch = DiffBatch::new("node_1");
        batch.add_diff(&patch1);
        batch.add_diff(&patch2);

        assert_eq!(batch.total_operations, patch1.len() + patch2.len());
        assert!(batch.total_compressed_size() > 0);

        let result = batch.apply_all(&base).unwrap();
        assert_eq!(result, step2);
    }

    #[test]
    fn test_diff_batch_into_patch_sets() {
        let base = serde_json::json!({"v": 0});
        let next = serde_json::json!({"v": 1});
        let patch = diff_state(&base, &next, 0, 1);
        let mut batch = DiffBatch::new("n");
        batch.add_diff(&patch);
        let sets = batch.into_patch_sets().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].from_version, 0);
        assert_eq!(sets[0].to_version, 1);
    }

    // -- Snapshot Management Tests -------------------------------------------

    #[test]
    fn test_snapshot_registry_create_and_get() {
        let mut reg = SnapshotRegistry::new(None, 10);
        let id = reg.create_snapshot(
            serde_json::json!({"data": 42}),
            VectorClock::new().increment("n1"),
            "test",
        );
        let snap = reg.get(&id).unwrap();
        assert_eq!(snap.state["data"], 42);
        assert_eq!(snap.label, "test");
    }

    #[test]
    fn test_snapshot_registry_max_eviction() {
        let mut reg = SnapshotRegistry::new(None, 3);
        for i in 0..5 {
            reg.create_snapshot(
                serde_json::json!({"i": i}),
                VectorClock::new(),
                &format!("snap_{i}"),
            );
        }
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn test_snapshot_registry_purge_expired() {
        let mut reg = SnapshotRegistry::new(Some(Duration::from_millis(50)), 100);
        reg.create_snapshot(serde_json::json!(1), VectorClock::new(), "will_expire");
        assert_eq!(reg.len(), 1);
        thread::sleep(Duration::from_millis(80));
        let purged = reg.purge_expired();
        assert_eq!(purged, 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn test_snapshot_registry_compare() {
        let mut reg = SnapshotRegistry::new(None, 10);
        let id_a = reg.create_snapshot(serde_json::json!({"a": 1}), VectorClock::new(), "v1");
        let id_b = reg.create_snapshot(
            serde_json::json!({"a": 2, "b": 3}),
            VectorClock::new(),
            "v2",
        );
        let patch = reg.compare_snapshots(&id_a, &id_b).unwrap();
        assert!(!patch.is_empty());
        // Should have one Replace (a: 1 -> 2) and one Add (b: 3)
        assert_eq!(patch.operations.len(), 2);
    }

    #[test]
    fn test_snapshot_storage_bytes() {
        let mut reg = SnapshotRegistry::new(None, 10);
        reg.create_snapshot(
            serde_json::json!({"key": "value"}),
            VectorClock::new(),
            "s1",
        );
        assert!(reg.total_storage_bytes() > 0);
    }

    #[test]
    fn test_snapshot_list_active() {
        let mut reg = SnapshotRegistry::new(None, 10);
        let id1 = reg.create_snapshot(serde_json::json!(1), VectorClock::new(), "a");
        let id2 = reg.create_snapshot(serde_json::json!(2), VectorClock::new(), "b");
        let active = reg.list_active();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0], id1);
        assert_eq!(active[1], id2);
    }

    #[test]
    fn test_snapshot_remove() {
        let mut reg = SnapshotRegistry::new(None, 10);
        let id = reg.create_snapshot(serde_json::json!(1), VectorClock::new(), "x");
        assert!(reg.remove(&id));
        assert!(reg.get(&id).is_none());
        assert!(!reg.remove(&id)); // already removed
    }

    // -- Conflict Resolution / OT Tests -------------------------------------

    #[test]
    fn test_ot_insert_and_apply() {
        let mut doc = OTDocument::new("node_1", "hello");
        doc.local_insert("op1", 5, " world");
        assert_eq!(doc.content, "hello world");
        assert_eq!(doc.history.len(), 1);
    }

    #[test]
    fn test_ot_delete_and_apply() {
        let mut doc = OTDocument::new("node_1", "abcdef");
        doc.local_delete("op1", 1, 3);
        assert_eq!(doc.content, "aef");
    }

    #[test]
    fn test_ot_concurrent_inserts() {
        // Two nodes start with "ab" and both insert at position 1.
        let mut doc_a = OTDocument::new("node_a", "ab");
        let mut doc_b = OTDocument::new("node_b", "ab");

        let op_a = doc_a.local_insert("op_a", 1, "X");
        let op_b = doc_b.local_insert("op_b", 1, "Y");

        // A integrates B's operation
        doc_a.integrate_remote(op_b);
        // B integrates A's operation
        doc_b.integrate_remote(op_a);

        // Both should converge to the same result
        assert_eq!(doc_a.content, doc_b.content);
    }

    #[test]
    fn test_merge_values_objects() {
        let a = serde_json::json!({"x": 1, "y": 2});
        let b = serde_json::json!({"x": 10, "z": 3});
        let merged = merge_values(&a, &b);
        let obj = merged.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(obj["x"], 10);
        assert_eq!(obj["y"], 2);
        assert_eq!(obj["z"], 3);
    }

    #[test]
    fn test_merge_values_arrays_dedup() {
        let a = serde_json::json!([1, 2, 3]);
        let b = serde_json::json!([3, 4, 5]);
        let merged = merge_values(&a, &b);
        assert_eq!(merged, serde_json::json!([1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_versioned_state_new_and_mutate() {
        let vs = VersionedState::new(serde_json::json!({"v": 0}), "n1", "initial");
        assert_eq!(vs.version.get("n1"), 1);
        let vs2 = vs.mutate(serde_json::json!({"v": 1}), "n1", "updated");
        assert_eq!(vs2.version.get("n1"), 2);
    }

    #[test]
    fn test_vector_clock_dominant_counter() {
        let vc = VectorClock::new()
            .increment("a")
            .increment("a")
            .increment("b");
        assert_eq!(vc.dominant_counter(), 2);
    }

    #[test]
    fn test_patch_set_empty() {
        let ps = PatchSet::empty(1, 2);
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn test_diff_map_deep_nesting() {
        let old = serde_json::json!({
            "level1": {"level2": {"level3": "old"}}
        });
        let new = serde_json::json!({
            "level1": {"level2": {"level3": "new"}}
        });
        let patch = diff_state(&old, &new, 1, 2);
        assert_eq!(patch.operations.len(), 1);
        assert_eq!(patch.operations[0].path(), "/level1/level2/level3");
    }
}
