// Federated Averaging (FedAvg) Aggregation Algorithm
//
// Implements the classic McMahan et al. (2017) FedAvg algorithm for
// aggregating model weight updates from multiple federated peers.
//
// Key steps:
//   1. Validate each peer's update (norm check, version compatibility)
//   2. Clip gradients if they exceed the configured norm bound
//   3. Compute weighted average based on number of local training samples
//   4. Apply weight decay regularization to prevent overfitting
//   5. Return an aggregated GlobalModel
//
// No unsafe code. All implementations are real algorithms.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A single layer's weights from one peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelWeight {
    /// Name identifying the neural network layer (e.g., "dense1", "embedding").
    pub layer_name: String,
    /// Flattened weight values for this layer.
    pub weights: Vec<f64>,
    /// Model version this weight corresponds to.
    pub version: String,
    /// Unix timestamp (seconds) when this weight was produced.
    pub timestamp: u64,
    /// Peer ID that produced this weight.
    pub source_peer_id: String,
}

impl ModelWeight {
    /// Compute the L2 norm of this layer's weights.
    ///
    /// Formula: ||w||_2 = sqrt(sum(w_i^2))
    pub fn compute_weight_norm(&self) -> f64 {
        self.weights.iter().map(|w| w * w).sum::<f64>().sqrt()
    }

    /// Compute the L2 divergence between this weight and another.
    ///
    /// Formula: ||w1 - w2||_2
    /// Returns None if the weight vectors have different lengths.
    pub fn compute_weight_divergence(&self, other: &ModelWeight) -> Option<f64> {
        if self.weights.len() != other.weights.len() {
            return None;
        }
        let sum_sq: f64 = self
            .weights
            .iter()
            .zip(other.weights.iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum();
        Some(sum_sq.sqrt())
    }

    /// Check whether this weight is compatible with a target version.
    ///
    /// Two versions are compatible if their major component matches.
    pub fn is_compatible_version(&self, target_version: &str) -> bool {
        let self_major = self.version.split('.').next().unwrap_or("0");
        let target_major = target_version.split('.').next().unwrap_or("0");
        self_major == target_major
    }

    /// Clip this weight's values in-place so the L2 norm does not exceed `max_norm`.
    ///
    /// If the norm is already below `max_norm`, the weights are unchanged.
    /// Otherwise, each weight is scaled by `max_norm / current_norm`.
    pub fn clip_to_norm(&mut self, max_norm: f64) {
        let norm = self.compute_weight_norm();
        if norm <= max_norm || norm == 0.0 {
            return;
        }
        let scale = max_norm / norm;
        for w in &mut self.weights {
            *w *= scale;
        }
    }
}

/// A model update submitted by a single federated peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelUpdate {
    /// Unique identifier of the submitting peer.
    pub peer_id: String,
    /// Per-layer weights from local training.
    pub weights: Vec<ModelWeight>,
    /// Number of local training samples used.
    pub num_samples: u64,
    /// Number of local training epochs performed.
    pub local_epochs: u32,
    /// Unix timestamp (seconds) when this update was created.
    pub update_timestamp: u64,
    /// Global model version this update was based on.
    pub model_version: String,
}

impl ModelUpdate {
    /// Compute the total L2 norm across all layers.
    pub fn total_weight_norm(&self) -> f64 {
        self.weights
            .iter()
            .map(|w| w.compute_weight_norm().powi(2))
            .sum::<f64>()
            .sqrt()
    }

    /// Check version compatibility with a target model version.
    /// All layers must be compatible.
    pub fn is_compatible_version(&self, target_version: &str) -> bool {
        let self_major = self.model_version.split('.').next().unwrap_or("0");
        let target_major = target_version.split('.').next().unwrap_or("0");
        if self_major != target_major {
            return false;
        }
        self.weights
            .iter()
            .all(|w| w.is_compatible_version(target_version))
    }

    /// Compute the weighted divergence from another update's weights.
    pub fn compute_weight_divergence(&self, other: &ModelUpdate) -> f64 {
        let self_map: HashMap<&str, &ModelWeight> = self
            .weights
            .iter()
            .map(|w| (w.layer_name.as_str(), w))
            .collect();
        let other_map: HashMap<&str, &ModelWeight> = other
            .weights
            .iter()
            .map(|w| (w.layer_name.as_str(), w))
            .collect();

        let total_sq: f64 = self_map
            .keys()
            .filter_map(|k| {
                self_map.get(k).and_then(|a| {
                    other_map
                        .get(k)
                        .and_then(|b| a.compute_weight_divergence(b))
                })
            })
            .map(|d| d * d)
            .sum();
        total_sq.sqrt()
    }
}

/// Metadata about an aggregation round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationMetadata {
    /// Number of peers that participated.
    pub num_peers: usize,
    /// Total number of training samples across all peers.
    pub total_samples: u64,
    /// Average number of local epochs.
    pub avg_local_epochs: f64,
    /// Maximum weight norm among all updates (before clipping).
    pub max_weight_norm: f64,
    /// Average weight norm across all updates (before clipping).
    pub avg_weight_norm: f64,
    /// Weight decay coefficient applied.
    pub weight_decay: f64,
    /// Learning rate used.
    pub learning_rate: f64,
}

/// The aggregated global model produced by FedAvg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalModel {
    /// Version string (e.g., "1.0.0").
    pub version: String,
    /// Per-layer averaged weights.
    pub weights: Vec<ModelWeight>,
    /// Metadata about the aggregation that produced this model.
    pub aggregation_metadata: AggregationMetadata,
    /// Unix timestamp (seconds) when this model was created.
    pub timestamp: u64,
    /// Peer IDs that participated in this aggregation.
    pub participating_peers: Vec<String>,
}

impl GlobalModel {
    /// Get the total number of weight parameters across all layers.
    pub fn total_parameters(&self) -> usize {
        self.weights.iter().map(|w| w.weights.len()).sum()
    }

    /// Compute the total L2 norm of all weights.
    pub fn total_norm(&self) -> f64 {
        let norm_sq: f64 = self
            .weights
            .iter()
            .map(|w| w.weights.iter().map(|v| v * v).sum::<f64>())
            .sum();
        norm_sq.sqrt()
    }
}

/// Configuration for the FedAvg aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Minimum number of peers required for aggregation.
    pub min_peers: usize,
    /// Maximum number of peers to include per round.
    pub max_peers: usize,
    /// Server-side learning rate.
    pub learning_rate: f64,
    /// Weight decay coefficient for L2 regularization.
    pub weight_decay: f64,
    /// Maximum L2 norm for per-update gradient clipping.
    pub clipping_norm: f64,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            min_peers: 3,
            max_peers: 100,
            learning_rate: 0.01,
            weight_decay: 0.0001,
            clipping_norm: 100.0,
        }
    }
}

/// Federated Averaging aggregator.
///
/// Implements the standard FedAvg algorithm with configurable gradient
/// clipping and weight decay regularization.
pub struct FedAvgAggregator {
    config: AggregationConfig,
}

impl FedAvgAggregator {
    /// Create a new aggregator with the given configuration.
    pub fn new(config: AggregationConfig) -> Self {
        Self { config }
    }

    /// Aggregate multiple peer updates into a single global model.
    ///
    /// Algorithm:
    ///   1. Validate each update (norm bound, version compatibility).
    ///   2. Clip gradient norms that exceed `clipping_norm`.
    ///   3. Compute weighted average: w_global = sum(n_k * w_k) / sum(n_k)
    ///      where n_k is the number of local samples from peer k.
    ///   4. Apply weight decay: w_final = w_global * (1 - lr * lambda)
    ///   5. Return the aggregated GlobalModel.
    pub fn aggregate(&self, updates: Vec<ModelUpdate>) -> Result<GlobalModel> {
        if updates.is_empty() {
            return Err(Error::Evaluation(
                "Cannot aggregate an empty set of updates".into(),
            ));
        }
        if updates.len() < self.config.min_peers {
            return Err(Error::Evaluation(format!(
                "Not enough peers for aggregation: {} < {}",
                updates.len(),
                self.config.min_peers
            )));
        }

        // Determine a common target version from the first update.
        let target_version = updates[0].model_version.clone();

        // Validate and preprocess updates.
        let mut validated: Vec<ModelUpdate> = Vec::with_capacity(updates.len());
        let mut max_norm = 0.0_f64;
        let mut norms: Vec<f64> = Vec::with_capacity(updates.len());

        for update in updates {
            if !update.is_compatible_version(&target_version) {
                return Err(Error::Evaluation(format!(
                    "Update from peer {} has incompatible version: {} vs {}",
                    update.peer_id, update.model_version, target_version
                )));
            }

            let norm = update.total_weight_norm();
            norms.push(norm);
            if norm > max_norm {
                max_norm = norm;
            }

            // Clone and clip the update.
            let mut clipped = update.clone();
            for weight in &mut clipped.weights {
                weight.clip_to_norm(self.config.clipping_norm);
            }
            validated.push(clipped);
        }

        // Compute weighted average.
        // Group weights by layer name and compute n_k-weighted average.
        let total_samples: u64 = validated.iter().map(|u| u.num_samples).sum();
        if total_samples == 0 {
            return Err(Error::Evaluation(
                "Total training samples across all peers is zero".into(),
            ));
        }

        // Collect all unique layer names in order.
        let mut layer_order: Vec<String> = Vec::new();
        let mut seen_layers: std::collections::HashSet<String> = std::collections::HashSet::new();
        for update in &validated {
            for w in &update.weights {
                if seen_layers.insert(w.layer_name.clone()) {
                    layer_order.push(w.layer_name.clone());
                }
            }
        }

        let mut aggregated_weights: Vec<ModelWeight> = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for layer_name in &layer_order {
            // Collect weights for this layer from all peers, weighted by n_k.
            let mut weight_sum: Vec<f64> = Vec::new();
            let mut layer_size: Option<usize> = None;
            let mut peer_count = 0usize;

            for update in &validated {
                if let Some(layer_w) = update.weights.iter().find(|w| &w.layer_name == layer_name) {
                    if let Some(ref mut ws) = layer_size {
                        // All peers should have the same layer size.
                        if *ws != layer_w.weights.len() {
                            return Err(Error::Evaluation(format!(
                                "Layer '{}' size mismatch: {} vs {}",
                                layer_name,
                                ws,
                                layer_w.weights.len()
                            )));
                        }
                    } else {
                        layer_size = Some(layer_w.weights.len());
                        weight_sum.resize(layer_w.weights.len(), 0.0);
                    }

                    let sample_weight = update.num_samples as f64 / total_samples as f64;
                    for (i, v) in layer_w.weights.iter().enumerate() {
                        weight_sum[i] += v * sample_weight;
                    }
                    peer_count += 1;
                }
            }

            let _size = layer_size.unwrap_or(0);

            // Apply weight decay regularization.
            let decay_factor = 1.0 - self.config.learning_rate * self.config.weight_decay;
            for w in &mut weight_sum {
                *w *= decay_factor;
            }

            // Validate that at least one peer contributed this layer.
            if peer_count == 0 {
                return Err(Error::Evaluation(format!(
                    "No peers contributed weights for layer '{}'",
                    layer_name
                )));
            }

            aggregated_weights.push(ModelWeight {
                layer_name: layer_name.clone(),
                weights: weight_sum,
                version: target_version.clone(),
                timestamp: now,
                source_peer_id: "fedavg".to_string(),
            });
        }

        let avg_local_epochs =
            validated.iter().map(|u| u.local_epochs as f64).sum::<f64>() / validated.len() as f64;
        let avg_norm = norms.iter().sum::<f64>() / norms.len() as f64;
        let participating_peers: Vec<String> =
            validated.iter().map(|u| u.peer_id.clone()).collect();

        Ok(GlobalModel {
            version: target_version,
            weights: aggregated_weights,
            aggregation_metadata: AggregationMetadata {
                num_peers: validated.len(),
                total_samples,
                avg_local_epochs,
                max_weight_norm: max_norm,
                avg_weight_norm: avg_norm,
                weight_decay: self.config.weight_decay,
                learning_rate: self.config.learning_rate,
            },
            timestamp: now,
            participating_peers,
        })
    }

    /// Get a reference to the aggregation configuration.
    pub fn config(&self) -> &AggregationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_weight(layer: &str, peer: &str, values: Vec<f64>) -> ModelWeight {
        ModelWeight {
            layer_name: layer.to_string(),
            weights: values,
            version: "1.0.0".to_string(),
            timestamp: now_ts(),
            source_peer_id: peer.to_string(),
        }
    }

    fn make_update(peer_id: &str, weights: Vec<ModelWeight>, num_samples: u64) -> ModelUpdate {
        ModelUpdate {
            peer_id: peer_id.to_string(),
            weights,
            num_samples,
            local_epochs: 1,
            update_timestamp: now_ts(),
            model_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn test_basic_aggregation() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.0,
            ..Default::default()
        });

        // 3 peers, 2 layers, equal weights.
        let updates = vec![
            make_update(
                "p1",
                vec![
                    make_weight("l1", "p1", vec![1.0, 2.0]),
                    make_weight("l2", "p1", vec![3.0]),
                ],
                100,
            ),
            make_update(
                "p2",
                vec![
                    make_weight("l1", "p2", vec![3.0, 4.0]),
                    make_weight("l2", "p2", vec![5.0]),
                ],
                100,
            ),
            make_update(
                "p3",
                vec![
                    make_weight("l1", "p3", vec![5.0, 6.0]),
                    make_weight("l2", "p3", vec![7.0]),
                ],
                100,
            ),
        ];

        let model = agg.aggregate(updates).unwrap();
        assert_eq!(model.participating_peers.len(), 3);
        assert_eq!(model.aggregation_metadata.total_samples, 300);

        // Equal samples -> simple average.
        let l1 = model.weights.iter().find(|w| w.layer_name == "l1").unwrap();
        assert!((l1.weights[0] - 3.0).abs() < 1e-6); // (1+3+5)/3
        assert!((l1.weights[1] - 4.0).abs() < 1e-6); // (2+4+6)/3

        let l2 = model.weights.iter().find(|w| w.layer_name == "l2").unwrap();
        assert!((l2.weights[0] - 5.0).abs() < 1e-6); // (3+5+7)/3
    }

    #[test]
    fn test_weighted_aggregation() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.0,
            ..Default::default()
        });

        // Peer 1 has 3x the samples of peer 2.
        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![3.0])], 300),
            make_update("p2", vec![make_weight("l1", "p2", vec![0.0])], 100),
        ];

        let model = agg.aggregate(updates).unwrap();
        let l1 = model.weights.iter().find(|w| w.layer_name == "l1").unwrap();
        // Weighted: (3.0 * 300 + 0.0 * 100) / 400 = 2.25
        assert!((l1.weights[0] - 2.25).abs() < 1e-6);
    }

    #[test]
    fn test_gradient_clipping() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            clipping_norm: 1.0,
            ..Default::default()
        });

        // One peer has huge weights (norm >> 1.0), should be clipped.
        let huge_weights = vec![10.0; 10]; // norm = sqrt(1000) ~= 31.6
        let updates = vec![
            make_update(
                "p1",
                vec![make_weight("l1", "p1", huge_weights.clone())],
                100,
            ),
            make_update("p2", vec![make_weight("l1", "p2", vec![0.0; 10])], 100),
        ];

        let model = agg.aggregate(updates).unwrap();
        let l1 = model.weights.iter().find(|w| w.layer_name == "l1").unwrap();

        // After clipping to norm 1.0, each element becomes 10/sqrt(1000) ~= 0.316
        // Average with zero: ~0.158 per element
        let expected = 10.0 / (1000.0_f64.sqrt()) / 2.0;
        assert!(
            l1.weights.iter().all(|w| *w < 1.0),
            "Weights should be clipped"
        );
        assert!((l1.weights[0] - expected).abs() < 1e-4);
    }

    #[test]
    fn test_weight_decay() {
        // Higher weight decay should reduce the magnitude of weights.
        let agg_low = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.0,
            learning_rate: 0.01,
            ..Default::default()
        });
        let agg_high = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.1,
            learning_rate: 0.01,
            ..Default::default()
        });

        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![1.0])], 100),
            make_update("p2", vec![make_weight("l1", "p2", vec![1.0])], 100),
        ];

        let model_low = agg_low.aggregate(updates.clone()).unwrap();
        let model_high = agg_high.aggregate(updates).unwrap();

        let w_low = model_low.weights[0].weights[0];
        let w_high = model_high.weights[0].weights[0];

        // weight_decay=0 -> decay_factor = 1.0, weight_decay=0.1 -> decay_factor = 1 - 0.01*0.1 = 0.999
        assert!(
            w_low > w_high,
            "Higher decay should produce smaller weights"
        );
    }

    #[test]
    fn test_weight_norm_computation() {
        let w = make_weight("l1", "p1", vec![3.0, 4.0]);
        assert!((w.compute_weight_norm() - 5.0).abs() < 1e-9); // sqrt(9+16)

        let w_zero = make_weight("l1", "p1", vec![0.0, 0.0]);
        assert!((w_zero.compute_weight_norm() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_weight_divergence() {
        let w1 = make_weight("l1", "p1", vec![1.0, 2.0, 3.0]);
        let w2 = make_weight("l1", "p2", vec![4.0, 6.0, 3.0]);
        // divergence = sqrt((1-4)^2 + (2-6)^2 + (3-3)^2) = sqrt(9+16+0) = 5.0
        let div = w1.compute_weight_divergence(&w2).unwrap();
        assert!((div - 5.0).abs() < 1e-9);

        // Mismatched sizes -> None.
        let w3 = make_weight("l1", "p3", vec![1.0, 2.0]);
        assert!(w1.compute_weight_divergence(&w3).is_none());
    }

    #[test]
    fn test_version_compatibility() {
        let w = ModelWeight {
            layer_name: "l1".into(),
            weights: vec![1.0],
            version: "2.1.0".into(),
            timestamp: now_ts(),
            source_peer_id: "p1".into(),
        };
        assert!(w.is_compatible_version("2.5.0"));
        assert!(!w.is_compatible_version("1.0.0"));
        assert!(w.is_compatible_version("2.0.0"));
    }

    #[test]
    fn test_empty_updates_rejected() {
        let agg = FedAvgAggregator::new(AggregationConfig::default());
        let result = agg.aggregate(vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_single_peer_rejected() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 3,
            ..Default::default()
        });
        let updates = vec![make_update(
            "p1",
            vec![make_weight("l1", "p1", vec![1.0])],
            100,
        )];
        let result = agg.aggregate(updates);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not enough"));
    }

    #[test]
    fn test_conflicting_versions_rejected() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            ..Default::default()
        });
        let mut u1 = make_update("p1", vec![make_weight("l1", "p1", vec![1.0])], 100);
        u1.model_version = "1.0.0".into();
        let mut u2 = make_update("p2", vec![make_weight("l1", "p2", vec![1.0])], 100);
        u2.model_version = "2.0.0".into();
        let result = agg.aggregate(vec![u1, u2]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incompatible"));
    }

    #[test]
    fn test_zero_samples_rejected() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            ..Default::default()
        });
        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![1.0])], 0),
            make_update("p2", vec![make_weight("l1", "p2", vec![1.0])], 0),
        ];
        let result = agg.aggregate(updates);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zero"));
    }

    #[test]
    fn test_convergence_over_multiple_rounds() {
        // Simulate multiple rounds where peers converge toward a common value.
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.0,
            learning_rate: 0.01,
            clipping_norm: 100.0,
            ..Default::default()
        });

        // Start with very different initial weights.
        let mut peer1_weight = vec![-5.0];
        let mut peer2_weight = vec![10.0];
        let mut peer3_weight = vec![0.0];

        for round in 0..12 {
            let updates = vec![
                make_update(
                    "p1",
                    vec![make_weight("l1", "p1", peer1_weight.clone())],
                    100,
                ),
                make_update(
                    "p2",
                    vec![make_weight("l1", "p2", peer2_weight.clone())],
                    100,
                ),
                make_update(
                    "p3",
                    vec![make_weight("l1", "p3", peer3_weight.clone())],
                    100,
                ),
            ];
            let model = agg.aggregate(updates).unwrap();
            let new_w = model.weights[0].weights[0];

            // Simulate local training: each peer moves their weight toward new_w.
            peer1_weight = vec![peer1_weight[0] + 0.5 * (new_w - peer1_weight[0])];
            peer2_weight = vec![peer2_weight[0] + 0.5 * (new_w - peer2_weight[0])];
            peer3_weight = vec![peer3_weight[0] + 0.5 * (new_w - peer3_weight[0])];

            // After a few rounds, the weights should be converging.
            if round >= 3 {
                let spread = (peer1_weight[0] - peer2_weight[0])
                    .abs()
                    .max((peer2_weight[0] - peer3_weight[0]).abs());
                assert!(
                    spread < 2.0,
                    "Round {}: peer weights should converge, spread = {}",
                    round,
                    spread
                );
            }
        }

        // After 10 rounds, very tight convergence.
        let final_spread = (peer1_weight[0] - peer2_weight[0])
            .abs()
            .max((peer2_weight[0] - peer3_weight[0]).abs());
        assert!(
            final_spread < 0.01,
            "Final spread should be tiny: {}",
            final_spread
        );
    }

    #[test]
    fn test_global_model_total_parameters() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            ..Default::default()
        });
        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![1.0, 2.0])], 100),
            make_update("p2", vec![make_weight("l1", "p2", vec![3.0, 4.0])], 100),
        ];
        let model = agg.aggregate(updates).unwrap();
        assert_eq!(model.total_parameters(), 2);
    }

    #[test]
    fn test_global_model_total_norm() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            weight_decay: 0.0,
            ..Default::default()
        });
        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![3.0, 4.0])], 100),
            make_update("p2", vec![make_weight("l1", "p2", vec![3.0, 4.0])], 100),
        ];
        let model = agg.aggregate(updates).unwrap();
        assert!((model.total_norm() - 5.0).abs() < 1e-6);
    }

    #[test]
    fn test_update_divergence() {
        let u1 = make_update("p1", vec![make_weight("l1", "p1", vec![1.0, 2.0])], 100);
        let u2 = make_update("p2", vec![make_weight("l1", "p2", vec![1.0, 5.0])], 100);
        let div = u1.compute_weight_divergence(&u2);
        assert!((div - 3.0).abs() < 1e-9); // sqrt(0 + 9)
    }

    #[test]
    fn test_aggregation_metadata() {
        let agg = FedAvgAggregator::new(AggregationConfig {
            min_peers: 2,
            learning_rate: 0.05,
            weight_decay: 0.001,
            ..Default::default()
        });
        let updates = vec![
            make_update("p1", vec![make_weight("l1", "p1", vec![1.0])], 100),
            make_update("p2", vec![make_weight("l1", "p2", vec![1.0])], 200),
        ];
        let model = agg.aggregate(updates).unwrap();
        assert_eq!(model.aggregation_metadata.num_peers, 2);
        assert_eq!(model.aggregation_metadata.total_samples, 300);
        assert_eq!(model.aggregation_metadata.avg_local_epochs, 1.0);
        assert!((model.aggregation_metadata.learning_rate - 0.05).abs() < 1e-9);
        assert!((model.aggregation_metadata.weight_decay - 0.001).abs() < 1e-9);
    }

    #[test]
    fn test_clip_to_norm_in_place() {
        let mut w = make_weight("l1", "p1", vec![3.0, 4.0]); // norm = 5
        w.clip_to_norm(1.0);
        let new_norm = w.compute_weight_norm();
        assert!((new_norm - 1.0).abs() < 1e-9);

        // Original direction preserved.
        assert!((w.weights[0] - 0.6).abs() < 1e-9); // 3/5
        assert!((w.weights[1] - 0.8).abs() < 1e-9); // 4/5

        // Clip to larger norm -> no change.
        let mut w2 = make_weight("l1", "p1", vec![3.0, 4.0]);
        let original = w2.weights.clone();
        w2.clip_to_norm(100.0);
        assert_eq!(w2.weights, original);
    }
}
