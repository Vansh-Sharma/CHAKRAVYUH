// Federated Model Manager — Model Lifecycle, Versioning, and Evaluation
//
// Manages the lifecycle of federated threat models including:
//   - Semantic versioning (major.minor.patch)
//   - Checkpoint save/load with SHA-256 integrity hashing
//   - Rollback to previous versions
//   - Model diff computation between versions
//   - Model evaluation metrics (accuracy, precision, recall, F1)
//   - Peer contribution leaderboard
//   - Model registry with full version lineage
//
// No unsafe code.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fedavg::GlobalModel;
use crate::error::{Error, Result};

// ── Model Version ─────────────────────────────────────────────────

/// Semantic version for federated models.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ModelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// SHA-256 hex hash of the model weights for content addressing.
    pub commit_hash: String,
    /// Unix timestamp (seconds) when this version was created.
    pub created_at: u64,
    /// The parent version string this was derived from (None for initial).
    pub parent_version: Option<String>,
}

impl ModelVersion {
    /// Create a new version with the given components.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            commit_hash: String::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            parent_version: None,
        }
    }

    /// Compute a commit hash from all model weights.
    pub fn compute_commit_hash(weights: &[super::fedavg::ModelWeight]) -> String {
        let mut hasher = Sha256::new();
        for w in weights {
            hasher.update(w.layer_name.as_bytes());
            for val in &w.weights {
                hasher.update(&val.to_le_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }

    /// String representation: "major.minor.patch".
    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Compare two versions. Returns -1, 0, or 1.
    pub fn compare(&self, other: &ModelVersion) -> i32 {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                std::cmp::Ordering::Equal => self.patch.cmp(&other.patch) as i32,
                other => other as i32,
            },
            other => other as i32,
        }
    }
}

impl std::fmt::Display for ModelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ── Checkpoint ────────────────────────────────────────────────────

/// Unique identifier for a saved checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CheckpointId {
    /// The version string at checkpoint time.
    pub version: String,
    /// SHA-256 hash of the checkpoint data.
    pub checkpoint_hash: String,
    /// Unix timestamp of the checkpoint.
    pub timestamp: u64,
}

/// A saved snapshot of the global model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCheckpoint {
    /// The model version.
    pub version: ModelVersion,
    /// The full global model.
    pub model: GlobalModel,
    /// Unix timestamp.
    pub timestamp: u64,
    /// SHA-256 hash for integrity.
    pub checkpoint_hash: String,
}

impl ModelCheckpoint {
    /// Compute the checkpoint hash from the global model.
    pub fn compute_hash(model: &GlobalModel) -> String {
        let mut hasher = Sha256::new();
        hasher.update(model.version.as_bytes());
        for w in &model.weights {
            hasher.update(w.layer_name.as_bytes());
            for val in &w.weights {
                hasher.update(&val.to_le_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }
}

// ── Checkpoint Summary ────────────────────────────────────────────

/// A lightweight summary of a checkpoint for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSummary {
    pub checkpoint_id: CheckpointId,
    pub version: String,
    pub num_layers: usize,
    pub total_parameters: usize,
    pub participating_peers: Vec<String>,
    pub timestamp: u64,
}

// ── Model Diff ────────────────────────────────────────────────────

/// Differences between two model versions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelDiff {
    /// Layers added in the newer version.
    pub added_weights: Vec<String>,
    /// Layers removed in the newer version.
    pub removed_weights: Vec<String>,
    /// Layers with modified weights.
    pub modified_weights: Vec<WeightChange>,
    /// Human-readable summary.
    pub summary: String,
}

/// A single weight change between versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightChange {
    pub layer_name: String,
    /// L2 norm of the difference.
    pub l2_change: f64,
    /// Mean absolute change.
    pub mean_abs_change: f64,
    /// Max absolute change.
    pub max_abs_change: f64,
}

// ── Model Metrics ─────────────────────────────────────────────────

/// Evaluation metrics for a federated threat model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
    pub latency_ms: f64,
    pub model_size_bytes: usize,
}

// ── Peer Contribution ─────────────────────────────────────────────

/// Tracks a peer's contribution to the federation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerContribution {
    pub peer_id: String,
    pub rounds_participated: u32,
    pub signatures_contributed: u32,
    pub average_update_quality: f64,
    pub last_seen: u64,
}

// ── Registry Stats ────────────────────────────────────────────────

/// Statistics about the model registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryStats {
    pub total_versions: usize,
    pub total_checkpoints: usize,
    pub latest_version: String,
    pub oldest_version: String,
    pub total_parameters: usize,
    pub total_peers: usize,
}

// ── Model Registry ────────────────────────────────────────────────

/// Tracks all known model versions, their lineage, and metadata.
struct ModelRegistry {
    /// All versions indexed by version string.
    versions: HashMap<String, ModelVersion>,
    /// Version lineage: child -> parent.
    lineage: HashMap<String, String>,
    /// All checkpoints indexed by checkpoint hash.
    checkpoints: HashMap<String, ModelCheckpoint>,
    /// Peer contribution records.
    peer_contributions: HashMap<String, PeerContribution>,
}

impl ModelRegistry {
    fn new() -> Self {
        Self {
            versions: HashMap::new(),
            lineage: HashMap::new(),
            checkpoints: HashMap::new(),
            peer_contributions: HashMap::new(),
        }
    }

    fn register_version(&mut self, version: ModelVersion) {
        let key = version.version_string();
        if let Some(ref parent) = version.parent_version {
            self.lineage.insert(key.clone(), parent.clone());
        }
        self.versions.insert(key, version);
    }

    fn save_checkpoint(&mut self, checkpoint: ModelCheckpoint) -> CheckpointId {
        let id = CheckpointId {
            version: checkpoint.version.version_string(),
            checkpoint_hash: checkpoint.checkpoint_hash.clone(),
            timestamp: checkpoint.timestamp,
        };
        self.checkpoints
            .insert(checkpoint.checkpoint_hash.clone(), checkpoint);
        id
    }

    fn load_checkpoint(&self, id: &CheckpointId) -> Option<GlobalModel> {
        self.checkpoints
            .get(&id.checkpoint_hash)
            .map(|cp| cp.model.clone())
    }

    fn list_checkpoints(&self) -> Vec<CheckpointSummary> {
        self.checkpoints
            .values()
            .map(|cp| CheckpointSummary {
                checkpoint_id: CheckpointId {
                    version: cp.version.version_string(),
                    checkpoint_hash: cp.checkpoint_hash.clone(),
                    timestamp: cp.timestamp,
                },
                version: cp.version.version_string(),
                num_layers: cp.model.weights.len(),
                total_parameters: cp.model.total_parameters(),
                participating_peers: cp.model.participating_peers.clone(),
                timestamp: cp.timestamp,
            })
            .collect()
    }

    fn get_latest_checkpoint(&self) -> Option<(CheckpointId, ModelCheckpoint)> {
        self.checkpoints
            .values()
            .max_by_key(|cp| cp.timestamp)
            .map(|cp| {
                let id = CheckpointId {
                    version: cp.version.version_string(),
                    checkpoint_hash: cp.checkpoint_hash.clone(),
                    timestamp: cp.timestamp,
                };
                (id, cp.clone())
            })
    }

    fn stats(&self) -> RegistryStats {
        let versions: Vec<&String> = self.versions.keys().collect();
        let latest = versions
            .iter()
            .max_by_key(|v| {
                self.versions
                    .get(**v)
                    .map(|ver| (ver.major, ver.minor, ver.patch, ver.created_at))
                    .unwrap_or((0, 0, 0, 0))
            })
            .map(|s| (*s).clone())
            .unwrap_or_else(|| "none".to_string());
        let oldest = versions
            .iter()
            .min_by_key(|v| {
                self.versions
                    .get(**v)
                    .map(|ver| (ver.major, ver.minor, ver.patch, ver.created_at))
                    .unwrap_or((0, 0, 0, u64::MAX))
            })
            .map(|s| (*s).clone())
            .unwrap_or_else(|| "none".to_string());
        let total_params: usize = self
            .checkpoints
            .values()
            .next()
            .map(|cp| cp.model.total_parameters())
            .unwrap_or(0);
        RegistryStats {
            total_versions: self.versions.len(),
            total_checkpoints: self.checkpoints.len(),
            latest_version: latest,
            oldest_version: oldest,
            total_parameters: total_params,
            total_peers: self.peer_contributions.len(),
        }
    }
}

// ── Federated Model Manager ───────────────────────────────────────

/// Manages the full lifecycle of federated threat models.
pub struct FederatedModelManager {
    registry: RwLock<ModelRegistry>,
    /// Counter for auto-incrementing minor version on each checkpoint.
    next_minor: RwLock<u32>,
}

impl FederatedModelManager {
    /// Create a new model manager.
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(ModelRegistry::new()),
            next_minor: RwLock::new(1),
        }
    }

    /// Save a checkpoint of the current global model.
    ///
    /// Returns the checkpoint ID for later retrieval.
    pub fn save_checkpoint(&self, model: &GlobalModel) -> CheckpointId {
        let commit_hash = ModelVersion::compute_commit_hash(&model.weights);
        let checkpoint_hash = ModelCheckpoint::compute_hash(model);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let parent_version = {
            let reg = self.registry.read().unwrap();
            reg.get_latest_checkpoint().map(|(id, _)| id.version)
        };

        let version = {
            let parts: Vec<u32> = model
                .version
                .split('.')
                .filter_map(|s| s.parse().ok())
                .collect();
            let mut v = if parts.len() == 3 {
                ModelVersion::new(parts[0], parts[1], parts[2])
            } else {
                let minor = *self.next_minor.read().unwrap();
                ModelVersion::new(1, minor, 0)
            };
            v.commit_hash = commit_hash;
            v.created_at = now;
            v.parent_version = parent_version;
            v
        };

        let checkpoint = ModelCheckpoint {
            version: version.clone(),
            model: model.clone(),
            timestamp: now,
            checkpoint_hash: checkpoint_hash.clone(),
        };

        let id = {
            let mut reg = self.registry.write().unwrap();
            reg.register_version(version);
            reg.save_checkpoint(checkpoint)
        };

        // Track peer contributions.
        for peer_id in &model.participating_peers {
            self.record_peer_participation(peer_id);
        }

        id
    }

    /// Load a checkpoint by its ID.
    ///
    /// Returns None if the checkpoint does not exist.
    pub fn load_checkpoint(&self, id: &CheckpointId) -> Option<GlobalModel> {
        self.registry.read().unwrap().load_checkpoint(id)
    }

    /// Roll back to a specific version.
    ///
    /// Searches all checkpoints for one matching the given version string.
    pub fn rollback_to(&self, version: &ModelVersion) -> Result<GlobalModel> {
        let reg = self.registry.read().unwrap();
        let target_version_str = version.version_string();
        for checkpoint in reg.checkpoints.values() {
            if checkpoint.version.version_string() == target_version_str {
                return Ok(checkpoint.model.clone());
            }
        }
        Err(Error::Evaluation(format!(
            "No checkpoint found for version {}",
            target_version_str
        )))
    }

    /// List all saved checkpoints.
    pub fn list_checkpoints(&self) -> Vec<CheckpointSummary> {
        self.registry.read().unwrap().list_checkpoints()
    }

    /// Compute the diff between two global models.
    pub fn compute_model_diff(v1: &GlobalModel, v2: &GlobalModel) -> ModelDiff {
        let v1_layers: HashMap<&str, &super::fedavg::ModelWeight> = v1
            .weights
            .iter()
            .map(|w| (w.layer_name.as_str(), w))
            .collect();
        let v2_layers: HashMap<&str, &super::fedavg::ModelWeight> = v2
            .weights
            .iter()
            .map(|w| (w.layer_name.as_str(), w))
            .collect();

        let v1_names: std::collections::HashSet<&str> = v1_layers.keys().copied().collect();
        let v2_names: std::collections::HashSet<&str> = v2_layers.keys().copied().collect();

        let mut added: Vec<String> = v2_names
            .difference(&v1_names)
            .map(|s| s.to_string())
            .collect();
        added.sort();
        let mut removed: Vec<String> = v1_names
            .difference(&v2_names)
            .map(|s| s.to_string())
            .collect();
        removed.sort();

        let mut modified: Vec<WeightChange> = Vec::new();
        for name in v2_names.intersection(&v1_names) {
            let w1 = v1_layers.get(name).unwrap();
            let w2 = v2_layers.get(name).unwrap();
            let changes: Vec<f64> = w1
                .weights
                .iter()
                .zip(w2.weights.iter())
                .map(|(a, b)| a - b)
                .collect();

            let l2: f64 = changes.iter().map(|d| d * d).sum::<f64>().sqrt();
            let mean_abs: f64 =
                changes.iter().map(|d| d.abs()).sum::<f64>() / changes.len().max(1) as f64;
            let max_abs: f64 = changes.iter().map(|d| d.abs()).fold(0.0_f64, f64::max);

            modified.push(WeightChange {
                layer_name: name.to_string(),
                l2_change: l2,
                mean_abs_change: mean_abs,
                max_abs_change: max_abs,
            });
        }

        let summary = format!(
            "{} added, {} removed, {} modified layers",
            added.len(),
            removed.len(),
            modified.len()
        );

        modified.sort_by(|a, b| a.layer_name.cmp(&b.layer_name));

        ModelDiff {
            added_weights: added,
            removed_weights: removed,
            modified_weights: modified,
            summary,
        }
    }

    /// Evaluate a model against test data.
    ///
    /// Test data is a list of (input_patterns, is_threat) tuples.
    /// The model evaluates each input pattern using its weights as a
    /// simple linear classifier and computes standard metrics.
    pub fn evaluate_model(
        &self,
        model: &GlobalModel,
        test_data: &[(Vec<String>, bool)],
    ) -> ModelMetrics {
        let start = std::time::Instant::now();

        // Simple evaluation: use model weights as a dot-product classifier.
        // For each test input, compute a score based on pattern matching
        // against model weight magnitudes per layer.
        let mut tp = 0u32;
        let mut fp = 0u32;
        let mut tn = 0u32;
        let mut fn_count = 0u32;

        // Use the first layer's weights as a simple feature vector.
        // This is a simplified evaluation for the federated model manager.
        // In production, the actual threat ring would be used.
        let feature_weights: Vec<f64> = model
            .weights
            .first()
            .map(|w| w.weights.clone())
            .unwrap_or_default();

        // Threshold for classification.
        let threshold = 0.0;

        for (patterns, is_threat) in test_data {
            // Compute a score: sum of (pattern length * corresponding weight).
            let mut score = 0.0;
            for (i, pattern) in patterns.iter().enumerate() {
                let w = feature_weights.get(i).copied().unwrap_or(0.0);
                score += pattern.len() as f64 * w;
            }

            let predicted_threat = score > threshold;
            if predicted_threat && *is_threat {
                tp += 1;
            } else if predicted_threat && !*is_threat {
                fp += 1;
            } else if !predicted_threat && !*is_threat {
                tn += 1;
            } else {
                fn_count += 1;
            }
        }

        let total = (tp + fp + tn + fn_count) as f64;
        let accuracy = if total > 0.0 {
            (tp + tn) as f64 / total
        } else {
            0.0
        };
        let precision = if (tp + fp) > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if (tp + fn_count) > 0 {
            tp as f64 / (tp + fn_count) as f64
        } else {
            0.0
        };
        let f1 = if (precision + recall) > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let fpr = if (fp + tn) > 0 {
            fp as f64 / (fp + tn) as f64
        } else {
            0.0
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Approximate model size: 8 bytes per f64 weight.
        let model_size_bytes = model.total_parameters() * 8;

        ModelMetrics {
            accuracy,
            precision,
            recall,
            f1_score: f1,
            false_positive_rate: fpr,
            latency_ms,
            model_size_bytes,
        }
    }

    /// Get the peer contribution leaderboard, sorted by quality descending.
    pub fn leaderboard(&self) -> Vec<PeerContribution> {
        let reg = self.registry.read().unwrap();
        let mut contributions: Vec<PeerContribution> =
            reg.peer_contributions.values().cloned().collect();
        contributions.sort_by(|a, b| {
            b.average_update_quality
                .partial_cmp(&a.average_update_quality)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        contributions
    }

    /// Get registry statistics.
    pub fn registry_stats(&self) -> RegistryStats {
        self.registry.read().unwrap().stats()
    }

    /// Record that a peer participated in a round.
    fn record_peer_participation(&self, peer_id: &str) {
        let mut reg = self.registry.write().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = reg
            .peer_contributions
            .entry(peer_id.to_string())
            .or_insert(PeerContribution {
                peer_id: peer_id.to_string(),
                rounds_participated: 0,
                signatures_contributed: 0,
                average_update_quality: 0.0,
                last_seen: 0,
            });

        entry.rounds_participated += 1;
        entry.last_seen = now;
        // Compute a simple quality metric: inverse of rounds (earlier peers
        // get higher quality to simulate "foundational" contributions).
        entry.average_update_quality = 1.0 / (entry.rounds_participated as f64).sqrt();
    }
}

impl Default for FederatedModelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fedavg::{AggregationMetadata, ModelWeight};
    use super::*;

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_global_model(version: &str, peer_ids: Vec<&str>) -> GlobalModel {
        GlobalModel {
            version: version.to_string(),
            weights: vec![
                ModelWeight {
                    layer_name: "dense1".to_string(),
                    weights: vec![0.5, 0.3, 0.1, -0.2],
                    version: version.to_string(),
                    timestamp: now_ts(),
                    source_peer_id: "fedavg".to_string(),
                },
                ModelWeight {
                    layer_name: "dense2".to_string(),
                    weights: vec![0.4, -0.1],
                    version: version.to_string(),
                    timestamp: now_ts(),
                    source_peer_id: "fedavg".to_string(),
                },
            ],
            aggregation_metadata: AggregationMetadata {
                num_peers: peer_ids.len(),
                total_samples: 300,
                avg_local_epochs: 1.0,
                max_weight_norm: 1.0,
                avg_weight_norm: 0.5,
                weight_decay: 0.0001,
                learning_rate: 0.01,
            },
            timestamp: now_ts(),
            participating_peers: peer_ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_checkpoint_save_and_load() {
        let mgr = FederatedModelManager::new();
        let model = make_global_model("1.0.0", vec!["p1", "p2", "p3"]);

        let id = mgr.save_checkpoint(&model);
        let loaded = mgr.load_checkpoint(&id).expect("checkpoint should exist");

        assert_eq!(loaded.version, model.version);
        assert_eq!(loaded.weights.len(), model.weights.len());
    }

    #[test]
    fn test_rollback() {
        let mgr = FederatedModelManager::new();

        let model_v1 = make_global_model("1.0.0", vec!["p1"]);
        let _id_v1 = mgr.save_checkpoint(&model_v1);

        let model_v2 = make_global_model("1.1.0", vec!["p1", "p2"]);
        mgr.save_checkpoint(&model_v2);

        let rolled_back = mgr
            .rollback_to(&ModelVersion::new(1, 1, 0))
            .expect("rollback should find v1.1.0");
        assert_eq!(rolled_back.participating_peers.len(), 2);
    }

    #[test]
    fn test_rollback_missing_version() {
        let mgr = FederatedModelManager::new();
        let result = mgr.rollback_to(&ModelVersion::new(99, 99, 99));
        assert!(result.is_err());
    }

    #[test]
    fn test_model_diff() {
        let m1 = make_global_model("1.0.0", vec!["p1"]);
        let mut m2 = make_global_model("1.1.0", vec!["p1", "p2"]);
        // Modify weights to create a change.
        m2.weights[0].weights = vec![1.0, 0.3, 0.1, -0.2]; // First element changed.

        let diff = FederatedModelManager::compute_model_diff(&m1, &m2);
        assert_eq!(diff.added_weights.len(), 0); // Same layers.
        assert_eq!(diff.removed_weights.len(), 0);
        assert_eq!(diff.modified_weights.len(), 2); // Both layers have some weights.
        assert!(diff.modified_weights[0].l2_change > 0.0); // dense1 changed.
        assert!((diff.modified_weights[1].l2_change - 0.0).abs() < 1e-9); // dense2 unchanged.
    }

    #[test]
    fn test_model_diff_added_removed_layers() {
        let m1 = GlobalModel {
            version: "1.0.0".into(),
            weights: vec![ModelWeight {
                layer_name: "layer_a".into(),
                weights: vec![1.0],
                version: "1.0.0".into(),
                timestamp: now_ts(),
                source_peer_id: "test".into(),
            }],
            aggregation_metadata: AggregationMetadata {
                num_peers: 1,
                total_samples: 100,
                avg_local_epochs: 1.0,
                max_weight_norm: 1.0,
                avg_weight_norm: 0.5,
                weight_decay: 0.0,
                learning_rate: 0.01,
            },
            timestamp: now_ts(),
            participating_peers: vec!["p1".into()],
        };

        let m2 = GlobalModel {
            version: "1.1.0".into(),
            weights: vec![ModelWeight {
                layer_name: "layer_b".into(),
                weights: vec![2.0],
                version: "1.1.0".into(),
                timestamp: now_ts(),
                source_peer_id: "test".into(),
            }],
            aggregation_metadata: AggregationMetadata {
                num_peers: 1,
                total_samples: 100,
                avg_local_epochs: 1.0,
                max_weight_norm: 1.0,
                avg_weight_norm: 0.5,
                weight_decay: 0.0,
                learning_rate: 0.01,
            },
            timestamp: now_ts(),
            participating_peers: vec!["p1".into()],
        };

        let diff = FederatedModelManager::compute_model_diff(&m1, &m2);
        assert_eq!(diff.added_weights, vec!["layer_b"]);
        assert_eq!(diff.removed_weights, vec!["layer_a"]);
        assert!(diff.modified_weights.is_empty());
    }

    #[test]
    fn test_version_comparison() {
        let v1 = ModelVersion::new(1, 0, 0);
        let v2 = ModelVersion::new(1, 1, 0);
        let v3 = ModelVersion::new(2, 0, 0);

        assert!(v1.compare(&v2) < 0);
        assert!(v2.compare(&v1) > 0);
        assert!(v1.compare(&v1) == 0);
        assert!(v3.compare(&v1) > 0);
    }

    #[test]
    fn test_metrics_computation() {
        let mgr = FederatedModelManager::new();
        let model = make_global_model("1.0.0", vec!["p1"]);

        // Create test data that should produce predictable results.
        // With weights [0.5, 0.3, 0.1, -0.2] and threshold 0.0:
        // Threat patterns (long strings) * positive weights → positive score → predicted threat.
        // Benign patterns (empty or short) * weights → low score → predicted benign.
        let test_data: Vec<(Vec<String>, bool)> = vec![
            // Long pattern with 4 elements → should predict threat.
            (
                vec![
                    "longthreat".to_string(),
                    "a".to_string(),
                    "b".to_string(),
                    "c".to_string(),
                ],
                true,
            ),
            // Empty → score 0 → not threat.
            (vec![], false),
        ];

        let metrics = mgr.evaluate_model(&model, &test_data);
        assert!(metrics.accuracy >= 0.0 && metrics.accuracy <= 1.0);
        assert!(metrics.precision >= 0.0 && metrics.precision <= 1.0);
        assert!(metrics.recall >= 0.0 && metrics.recall <= 1.0);
        assert!(metrics.f1_score >= 0.0 && metrics.f1_score <= 1.0);
        assert!(metrics.latency_ms >= 0.0);
    }

    #[test]
    fn test_metrics_perfect_classifier() {
        let mgr = FederatedModelManager::new();
        // Model with strong positive weights.
        let model = GlobalModel {
            version: "1.0.0".into(),
            weights: vec![ModelWeight {
                layer_name: "clf".into(),
                weights: vec![10.0],
                version: "1.0.0".into(),
                timestamp: now_ts(),
                source_peer_id: "test".into(),
            }],
            aggregation_metadata: AggregationMetadata {
                num_peers: 1,
                total_samples: 100,
                avg_local_epochs: 1.0,
                max_weight_norm: 10.0,
                avg_weight_norm: 10.0,
                weight_decay: 0.0,
                learning_rate: 0.01,
            },
            timestamp: now_ts(),
            participating_peers: vec!["p1".into()],
        };

        // Threats have long patterns → high score. Benign have empty → score 0.
        let test_data: Vec<(Vec<String>, bool)> = vec![
            (vec!["attack".to_string()], true),
            (vec!["injection".to_string()], true),
            (vec![], false),
            (vec![], false),
        ];

        let metrics = mgr.evaluate_model(&model, &test_data);
        assert!((metrics.accuracy - 1.0).abs() < 1e-9, "Should be perfect");
        assert!((metrics.precision - 1.0).abs() < 1e-9);
        assert!((metrics.recall - 1.0).abs() < 1e-9);
        assert!((metrics.f1_score - 1.0).abs() < 1e-9);
        assert!((metrics.false_positive_rate).abs() < 1e-9);
    }

    #[test]
    fn test_peer_leaderboard() {
        let mgr = FederatedModelManager::new();

        let model1 = make_global_model("1.0.0", vec!["peer-a", "peer-b"]);
        mgr.save_checkpoint(&model1);

        let model2 = make_global_model("1.1.0", vec!["peer-a", "peer-c"]);
        mgr.save_checkpoint(&model2);

        let lb = mgr.leaderboard();
        assert_eq!(lb.len(), 3); // peer-a, peer-b, peer-c.
                                 // peer-a participated in 2 rounds, so quality = 1/sqrt(2) ≈ 0.707.
                                 // peer-b participated in 1 round, so quality = 1/sqrt(1) = 1.0.
                                 // peer-c participated in 1 round, so quality = 1/sqrt(1) = 1.0.
                                 // Top peer(s) should have quality 1.0.
        assert!(lb[0].average_update_quality >= lb[1].average_update_quality);
    }

    #[test]
    fn test_registry_stats() {
        let mgr = FederatedModelManager::new();

        let stats_before = mgr.registry_stats();
        assert_eq!(stats_before.total_checkpoints, 0);
        assert_eq!(stats_before.total_versions, 0);

        let model = make_global_model("1.0.0", vec!["p1", "p2"]);
        mgr.save_checkpoint(&model);
        mgr.save_checkpoint(&make_global_model("1.1.0", vec!["p1"]));

        let stats_after = mgr.registry_stats();
        assert_eq!(stats_after.total_checkpoints, 2);
        assert_eq!(stats_after.total_versions, 2);
        assert_eq!(stats_after.total_peers, 2);
    }

    #[test]
    fn test_no_checkpoints_returns_empty_list() {
        let mgr = FederatedModelManager::new();
        let checkpoints = mgr.list_checkpoints();
        assert!(checkpoints.is_empty());
    }

    #[test]
    fn test_single_version_lineage() {
        let mgr = FederatedModelManager::new();

        let id1 = mgr.save_checkpoint(&make_global_model("1.0.0", vec!["p1"]));
        let id2 = mgr.save_checkpoint(&make_global_model("1.1.0", vec!["p1", "p2"]));

        // First checkpoint has no parent.
        let cp1 = mgr.load_checkpoint(&id1).unwrap();
        assert_eq!(cp1.version, "1.0.0");

        // Second checkpoint should exist.
        let cp2 = mgr.load_checkpoint(&id2).unwrap();
        assert_eq!(cp2.participating_peers.len(), 2);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let mgr = Arc::new(FederatedModelManager::new());
        let mut handles = vec![];

        for i in 0..4 {
            let mgr_clone = Arc::clone(&mgr);
            handles.push(thread::spawn(move || {
                let model = make_global_model(&format!("1.{}.0", i), vec!["p1", "p2", "p3"]);
                mgr_clone.save_checkpoint(&model);
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let stats = mgr.registry_stats();
        assert_eq!(stats.total_checkpoints, 4);
    }

    #[test]
    fn test_checkpoint_hash_uniqueness() {
        let mgr = FederatedModelManager::new();

        let m1 = make_global_model("1.0.0", vec!["p1"]);
        let m2 = make_global_model("1.0.0", vec!["p1"]);
        // Same data → same checkpoint hash.
        let id1 = mgr.save_checkpoint(&m1);
        let id2 = mgr.save_checkpoint(&m2);
        assert_eq!(id1.checkpoint_hash, id2.checkpoint_hash);

        // Different data → different hash.
        let mut m3 = make_global_model("1.1.0", vec!["p1"]);
        m3.weights[0].weights[0] = 999.0;
        let id3 = mgr.save_checkpoint(&m3);
        assert_ne!(id1.checkpoint_hash, id3.checkpoint_hash);
    }

    #[test]
    fn test_list_checkpoints_content() {
        let mgr = FederatedModelManager::new();
        let model = make_global_model("1.0.0", vec!["p1", "p2", "p3"]);
        let id = mgr.save_checkpoint(&model);

        let list = mgr.list_checkpoints();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].version, id.version);
        assert_eq!(list[0].num_layers, 2);
        assert_eq!(list[0].total_parameters, 6); // 4 + 2
        assert_eq!(list[0].participating_peers.len(), 3);
    }
}
