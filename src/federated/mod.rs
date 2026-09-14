// Federated Learning for Threat Detection
//
// This module adds collaborative intelligence to the CHAKRAVYUH Threat Ring (Ring 3).
// Multiple peers jointly train threat detection models without sharing raw data.
//
// Sub-modules:
//   - fedavg: Federated Averaging aggregation algorithm
//   - differential_privacy: Privacy-preserving noise injection & budget tracking
//   - threat_sync: Cross-peer threat signature synchronization
//   - model_manager: Model lifecycle, versioning, checkpointing, evaluation
//
// Architecture:
//   FederatedOrchestrator coordinates the round lifecycle. Each round:
//     1. Collects local model updates from peers
//     2. Applies differential privacy (noise, clipping)
//     3. Aggregates via FedAvg into a global model
//     4. Synchronizes threat signatures across the federation
//     5. Stores a checkpoint of the new global model
//
// No unsafe code. All algorithmic implementations are real.

pub mod differential_privacy;
pub mod fedavg;
pub mod model_manager;
pub mod threat_sync;

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, Verdict};
use crate::error::{Error, Result};

use differential_privacy::{DifferentialPrivacyConfig, DifferentialPrivacyEngine, PrivacyReport};
use fedavg::{AggregationConfig, FedAvgAggregator, GlobalModel, ModelUpdate};
use model_manager::FederatedModelManager;
use threat_sync::{ThreatSignatureSync, ThreatSyncConfig};

pub use differential_privacy::{
    DifferentialPrivacyEngine as DPEngine, PrivacyAccountant, PrivacyReport as DPReport,
};
pub use fedavg::{
    FedAvgAggregator as Aggregator, GlobalModel as FedGlobalModel,
    ModelUpdate as FedModelUpdate,
};
pub use model_manager::{
    CheckpointId, FederatedModelManager as ModelManager, ModelDiff,
    ModelMetrics as FedModelMetrics, ModelVersion, PeerContribution,
};
pub use threat_sync::{
    GlobalThreatModel as SyncedThreatModel, SignatureDiff as SigDiff,
    ThreatSignature as FedThreatSignature, ThreatSignatureSync as SignatureSync,
};

// ── Configuration ───────────────────────────────────────────────────

/// Peer configuration for federated learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Unique identifier for this peer.
    pub peer_id: String,
    /// Network address of the peer (host:port).
    #[serde(default)]
    pub address: Option<String>,
    /// Whether this peer is currently active.
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

/// Aggregation sub-configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationSubConfig {
    /// Minimum peers required to start a round.
    #[serde(default = "default_min_peers")]
    pub min_peers: usize,
    /// Maximum peers per round.
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// Server-side learning rate for global model update.
    #[serde(default = "default_learning_rate")]
    pub learning_rate: f64,
}

fn default_min_peers() -> usize {
    3
}
fn default_max_peers() -> usize {
    100
}
fn default_learning_rate() -> f64 {
    0.01
}

impl Default for AggregationSubConfig {
    fn default() -> Self {
        Self {
            min_peers: default_min_peers(),
            max_peers: default_max_peers(),
            learning_rate: default_learning_rate(),
        }
    }
}

/// Privacy sub-configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySubConfig {
    /// Privacy budget epsilon per round.
    #[serde(default = "default_epsilon")]
    pub epsilon: f64,
    /// Privacy failure probability delta per round.
    #[serde(default = "default_delta")]
    pub delta: f64,
    /// Gradient clipping norm.
    #[serde(default = "default_clip_norm")]
    pub clip_norm: f64,
    /// Whether secure aggregation (masking) is enabled.
    #[serde(default = "default_true")]
    pub secure_aggregation: bool,
}

fn default_epsilon() -> f64 {
    1.0
}
fn default_delta() -> f64 {
    1e-5
}
fn default_clip_norm() -> f64 {
    1.0
}

impl Default for PrivacySubConfig {
    fn default() -> Self {
        Self {
            epsilon: default_epsilon(),
            delta: default_delta(),
            clip_norm: default_clip_norm(),
            secure_aggregation: true,
        }
    }
}

/// Sync sub-configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSubConfig {
    /// Interval between sync rounds in milliseconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_ms: u64,
    /// Maximum signatures per sync exchange.
    #[serde(default = "default_max_sigs")]
    pub max_signatures_per_sync: usize,
    /// Whether signature verification is required.
    #[serde(default = "default_true")]
    pub verification_required: bool,
}

fn default_sync_interval() -> u64 {
    60_000
}
fn default_max_sigs() -> usize {
    1000
}

impl Default for SyncSubConfig {
    fn default() -> Self {
        Self {
            sync_interval_ms: default_sync_interval(),
            max_signatures_per_sync: default_max_sigs(),
            verification_required: true,
        }
    }
}

/// Top-level configuration for the federated learning module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedConfig {
    /// Master switch for federated learning.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// This peer's own identifier.
    #[serde(default = "default_peer_id")]
    pub peer_id: String,
    /// Known federation peers.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Aggregation settings.
    #[serde(default)]
    pub aggregation: AggregationSubConfig,
    /// Privacy settings.
    #[serde(default)]
    pub privacy: PrivacySubConfig,
    /// Threat signature sync settings.
    #[serde(default)]
    pub sync: SyncSubConfig,
}

fn default_peer_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Default for FederatedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            peer_id: default_peer_id(),
            peers: vec![],
            aggregation: AggregationSubConfig::default(),
            privacy: PrivacySubConfig::default(),
            sync: SyncSubConfig::default(),
        }
    }
}

// ── Federated Verdict ──────────────────────────────────────────────

/// A verdict produced by federated threat intelligence.
/// Implements the `Verdict` trait so Keshav can integrate it like any ring verdict.
#[derive(Debug, Clone, Serialize)]
pub struct FederatedVerdict {
    /// The decision reached by the federated model.
    pub decision: Decision,
    /// Composite threat score from the federated global model (0.0–1.0).
    pub federated_score: f64,
    /// Number of peers that contributed to this model version.
    pub contributing_peers: usize,
    /// The global model version used for this evaluation.
    pub model_version: String,
    /// How long the federated evaluation took in milliseconds.
    pub latency_ms: f64,
    /// Reason for the decision, including peer consensus info.
    pub reasoning: String,
}

impl FederatedVerdict {
    /// Create a new federated verdict.
    pub fn new(
        decision: Decision,
        federated_score: f64,
        contributing_peers: usize,
        model_version: String,
        latency_ms: f64,
        reasoning: String,
    ) -> Self {
        Self {
            decision,
            federated_score,
            contributing_peers,
            model_version,
            latency_ms,
            reasoning,
        }
    }

    /// Build an allow verdict from a low federated score.
    pub fn allow(score: f64, peers: usize, version: String, latency_ms: f64) -> Self {
        let reasoning = format!(
            "Federated model v{} ({} peers) scored {:.4} — below threat threshold",
            version, peers, score
        );
        Self::new(
            Decision::Allow,
            score,
            peers,
            version,
            latency_ms,
            reasoning,
        )
    }

    /// Build a deny verdict from a high federated score.
    pub fn deny(score: f64, peers: usize, version: String, latency_ms: f64) -> Self {
        let reasoning = format!(
            "Federated model v{} ({} peers) scored {:.4} — above deny threshold",
            version, peers, score
        );
        Self::new(
            Decision::Deny {
                code: "FEDERATED_THREAT".into(),
                retry_after: None,
            },
            score,
            peers,
            version,
            latency_ms,
            reasoning,
        )
    }
}

impl Verdict for FederatedVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }

    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

// ── Model Statistics ───────────────────────────────────────────────

/// Aggregated statistics about the current federated model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedModelStats {
    /// Current global model version string.
    pub model_version: String,
    /// Number of completed federation rounds.
    pub round_number: u32,
    /// Number of peers that participated in the latest round.
    pub peers_in_last_round: usize,
    /// Total unique peers ever participated.
    pub total_peers: usize,
    /// Cumulative privacy budget spent (epsilon).
    pub cumulative_epsilon: f64,
    /// Cumulative privacy budget spent (delta).
    pub cumulative_delta: f64,
    /// Number of threat signatures in the global model.
    pub signature_count: usize,
    /// Timestamp of the last aggregation.
    pub last_aggregation_ts: u64,
}

// ── Federated Orchestrator ─────────────────────────────────────────

/// The main coordinator that ties all federated sub-engines together.
///
/// The orchestrator manages the round lifecycle: collect updates,
/// apply privacy, aggregate, sync signatures, and checkpoint.
pub struct FederatedOrchestrator {
    config: FederatedConfig,
    aggregator: FedAvgAggregator,
    dp_engine: DifferentialPrivacyEngine,
    sync_engine: ThreatSignatureSync,
    model_manager: Arc<RwLock<FederatedModelManager>>,

    /// Current round number (increments on each completed round).
    round_number: Arc<RwLock<u32>>,
    /// Peer IDs that participated in the latest round.
    last_round_peers: Arc<RwLock<Vec<String>>>,
    /// All peer IDs that have ever contributed.
    all_known_peers: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Timestamp of the last completed aggregation.
    last_aggregation_ts: Arc<RwLock<u64>>,
    /// The current global model, if any round has completed.
    current_global_model: Arc<RwLock<Option<GlobalModel>>>,
}

impl FederatedOrchestrator {
    /// Create a new federated orchestrator from configuration.
    pub fn new(config: FederatedConfig) -> Result<Self> {
        let agg_config = AggregationConfig {
            min_peers: config.aggregation.min_peers,
            max_peers: config.aggregation.max_peers,
            learning_rate: config.aggregation.learning_rate,
            weight_decay: 0.0001,
            clipping_norm: config.privacy.clip_norm,
        };

        let dp_config = DifferentialPrivacyConfig {
            epsilon: config.privacy.epsilon,
            delta: config.privacy.delta,
            noise_mechanism: differential_privacy::NoiseMechanism::Gaussian,
            clip_norm: config.privacy.clip_norm,
            secure_aggregation: config.privacy.secure_aggregation,
        };

        let sync_config = ThreatSyncConfig {
            sync_interval_ms: config.sync.sync_interval_ms,
            max_signatures_per_sync: config.sync.max_signatures_per_sync,
            signature_ttl: 86400,
            verification_required: config.sync.verification_required,
        };

        let aggregator = FedAvgAggregator::new(agg_config);
        let dp_engine = DifferentialPrivacyEngine::new(dp_config);
        let sync_engine = ThreatSignatureSync::new(sync_config);
        let model_manager = Arc::new(RwLock::new(FederatedModelManager::new()));

        Ok(Self {
            config,
            aggregator,
            dp_engine,
            sync_engine,
            model_manager,
            round_number: Arc::new(RwLock::new(0)),
            last_round_peers: Arc::new(RwLock::new(vec![])),
            all_known_peers: Arc::new(RwLock::new(std::collections::HashSet::new())),
            last_aggregation_ts: Arc::new(RwLock::new(0)),
            current_global_model: Arc::new(RwLock::new(None)),
        })
    }

    /// Execute one federated learning round.
    ///
    /// Steps:
    ///   1. Validate that enough peers have submitted updates.
    ///   2. Apply differential privacy (gradient clipping + noise).
    ///   3. Aggregate via FedAvg.
    ///   4. Update the global model and record a checkpoint.
    ///   5. Increment the round counter.
    pub fn start_round(&self, updates: Vec<ModelUpdate>) -> Result<GlobalModel> {
        if !self.config.enabled {
            return Err(Error::EngineInit(
                "Federated learning is disabled in configuration".into(),
            ));
        }

        if updates.len() < self.config.aggregation.min_peers {
            return Err(Error::Evaluation(format!(
                "Not enough peers for aggregation: got {}, need at least {}",
                updates.len(),
                self.config.aggregation.min_peers
            )));
        }

        // Apply differential privacy to each update's weights.
        let mut sanitized_updates = updates;
        for update in &mut sanitized_updates {
            for weight in &mut update.weights {
                self.dp_engine.clip_gradients(&mut weight.weights, self.config.privacy.clip_norm);
            }
            for weight in &mut update.weights {
                self.dp_engine.apply_noise(&mut weight.weights);
            }
        }

        // Aggregate using FedAvg.
        let global_model = self.aggregator.aggregate(sanitized_updates)?;

        // Record participating peers.
        let peer_ids: Vec<String> = global_model.participating_peers.clone();
        {
            let mut last = self.last_round_peers.write().unwrap();
            *last = peer_ids.clone();
        }
        {
            let mut all = self.all_known_peers.write().unwrap();
            for pid in &peer_ids {
                all.insert(pid.clone());
            }
        }

        // Store the global model and checkpoint.
        {
            let mut current = self.current_global_model.write().unwrap();
            *current = Some(global_model.clone());
        }
        {
            let mgr = self.model_manager.write().unwrap();
            let _checkpoint_id = mgr.save_checkpoint(&global_model);
        }

        // Advance round counter and record timestamp.
        {
            let mut rn = self.round_number.write().unwrap();
            *rn += 1;
        }
        {
            let mut ts = self.last_aggregation_ts.write().unwrap();
            *ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }

        Ok(global_model)
    }

    /// Get a clone of the current global model, if available.
    pub fn get_global_model(&self) -> Option<GlobalModel> {
        self.current_global_model.read().unwrap().clone()
    }

    /// Register a local model update from a peer.
    ///
    /// This is a convenience method that wraps update creation.
    /// In production, updates would arrive over the network.
    pub fn register_local_update(
        &self,
        peer_id: String,
        weights: Vec<fedavg::ModelWeight>,
        num_samples: u64,
        local_epochs: u32,
    ) -> ModelUpdate {
        let current_version = self
            .current_global_model
            .read()
            .unwrap()
            .as_ref()
            .map(|m| m.version.clone())
            .unwrap_or_else(|| "0.0.0".to_string());

        ModelUpdate {
            peer_id,
            weights,
            num_samples,
            local_epochs,
            update_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            model_version: current_version,
        }
    }

    /// Get statistics about the current federated model state.
    pub fn get_model_stats(&self) -> FederatedModelStats {
        let round = *self.round_number.read().unwrap();
        let peers_last = self.last_round_peers.read().unwrap().len();
        let total_peers = self.all_known_peers.read().unwrap().len();
        let last_ts = *self.last_aggregation_ts.read().unwrap();
        let model_version = self
            .current_global_model
            .read()
            .unwrap()
            .as_ref()
            .map(|m| m.version.clone())
            .unwrap_or_else(|| "none".to_string());

        let privacy_report = self.dp_engine.privacy_report();
        let signature_count = self.sync_engine.global_model().signatures.len();

        FederatedModelStats {
            model_version,
            round_number: round,
            peers_in_last_round: peers_last,
            total_peers,
            cumulative_epsilon: privacy_report.current_epsilon,
            cumulative_delta: privacy_report.current_delta,
            signature_count,
            last_aggregation_ts: last_ts,
        }
    }

    /// Get the current round number.
    pub fn round_number(&self) -> u32 {
        *self.round_number.read().unwrap()
    }

    /// Get the privacy report from the differential privacy engine.
    pub fn privacy_report(&self) -> PrivacyReport {
        self.dp_engine.privacy_report()
    }

    /// Get the differential privacy engine for direct budget queries.
    pub fn dp_engine(&self) -> &DifferentialPrivacyEngine {
        &self.dp_engine
    }

    /// Get the threat sync engine for signature exchange.
    pub fn sync_engine(&self) -> &ThreatSignatureSync {
        &self.sync_engine
    }

    /// Get the model manager for checkpoint and version operations.
    pub fn model_manager(&self) -> &Arc<RwLock<FederatedModelManager>> {
        &self.model_manager
    }

    /// Get the aggregator for direct access to FedAvg.
    pub fn aggregator(&self) -> &FedAvgAggregator {
        &self.aggregator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fedavg::ModelWeight;

    fn make_default_config() -> FederatedConfig {
        FederatedConfig {
            enabled: true,
            peer_id: "test-peer-0".into(),
            peers: vec![
                PeerConfig {
                    peer_id: "peer-1".into(),
                    address: Some("127.0.0.1:9001".into()),
                    active: true,
                },
                PeerConfig {
                    peer_id: "peer-2".into(),
                    address: Some("127.0.0.1:9002".into()),
                    active: true,
                },
                PeerConfig {
                    peer_id: "peer-3".into(),
                    address: Some("127.0.0.1:9003".into()),
                    active: true,
                },
            ],
            aggregation: AggregationSubConfig {
                min_peers: 2,
                max_peers: 100,
                learning_rate: 0.01,
            },
            privacy: PrivacySubConfig {
                epsilon: 1.0,
                delta: 1e-5,
                clip_norm: 1.0,
                secure_aggregation: false,
            },
            sync: SyncSubConfig::default(),
        }
    }

    fn make_weight(layer: &str, values: Vec<f64>) -> ModelWeight {
        ModelWeight {
            layer_name: layer.to_string(),
            weights: values,
            version: "0.0.0".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source_peer_id: "test".to_string(),
        }
    }

    fn make_updates(n_peers: usize) -> Vec<ModelUpdate> {
        (0..n_peers)
            .map(|i| ModelUpdate {
                peer_id: format!("peer-{}", i + 1),
                weights: vec![
                    make_weight("dense1", vec![0.1 * (i as f64 + 1.0); 4]),
                    make_weight("dense2", vec![0.2 * (i as f64 + 1.0); 2]),
                ],
                num_samples: 100,
                local_epochs: 1,
                update_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                model_version: "0.0.0".to_string(),
            })
            .collect()
    }

    #[test]
    fn test_config_defaults() {
        let config = FederatedConfig::default();
        assert!(config.enabled);
        assert_eq!(config.aggregation.min_peers, 3);
        assert_eq!(config.privacy.epsilon, 1.0);
        assert_eq!(config.privacy.delta, 1e-5);
        assert!(config.privacy.secure_aggregation);
        assert_eq!(config.sync.sync_interval_ms, 60_000);
    }

    #[test]
    fn test_orchestrator_creation() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).expect("should create orchestrator");
        assert_eq!(orch.round_number(), 0);
        let stats = orch.get_model_stats();
        assert_eq!(stats.round_number, 0);
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.model_version, "none");
    }

    #[test]
    fn test_round_lifecycle() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).unwrap();
        let updates = make_updates(3);

        let model = orch.start_round(updates).expect("round should succeed");
        assert_eq!(orch.round_number(), 1);
        assert_eq!(model.participating_peers.len(), 3);

        // Second round.
        let updates2 = make_updates(3);
        let model2 = orch.start_round(updates2).expect("round 2 should succeed");
        assert_eq!(orch.round_number(), 2);
        assert_eq!(model2.version, model.version); // Same version since we use update model_version
    }

    #[test]
    fn test_get_global_model() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).unwrap();
        assert!(orch.get_global_model().is_none());

        let updates = make_updates(3);
        orch.start_round(updates).unwrap();
        assert!(orch.get_global_model().is_some());
    }

    #[test]
    fn test_model_stats_after_round() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).unwrap();
        orch.start_round(make_updates(3)).unwrap();

        let stats = orch.get_model_stats();
        assert_eq!(stats.round_number, 1);
        assert_eq!(stats.peers_in_last_round, 3);
        assert_eq!(stats.total_peers, 3);
        assert_ne!(stats.last_aggregation_ts, 0);
        assert_ne!(stats.model_version, "none");
    }

    #[test]
    fn test_verdict_integration() {
        let v = FederatedVerdict::allow(0.15, 5, "1.0.0".into(), 2.5);
        assert!(v.decision().is_allow());
        assert_eq!(v.latency_ms(), 2.5);
        assert_eq!(v.federated_score, 0.15);

        let v2 = FederatedVerdict::deny(0.85, 5, "1.0.0".into(), 1.2);
        assert!(v2.decision().is_deny());
        assert_eq!(v2.contributing_peers, 5);
    }

    #[test]
    fn test_peer_registration() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).unwrap();

        let update = orch.register_local_update(
            "peer-1".into(),
            vec![make_weight("layer1", vec![0.5, 0.3, 0.1])],
            200,
            2,
        );
        assert_eq!(update.peer_id, "peer-1");
        assert_eq!(update.num_samples, 200);
        assert_eq!(update.local_epochs, 2);
        assert_eq!(update.weights.len(), 1);
    }

    #[test]
    fn test_error_handling_insufficient_peers() {
        let config = make_default_config();
        let orch = FederatedOrchestrator::new(config).unwrap();
        // Only 1 peer, but min_peers is 2.
        let result = orch.start_round(make_updates(1));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Not enough peers"));
    }

    #[test]
    fn test_disabled_orchestrator_rejects_round() {
        let mut config = make_default_config();
        config.enabled = false;
        let orch = FederatedOrchestrator::new(config).unwrap();
        let result = orch.start_round(make_updates(3));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("disabled"));
    }
}
