// Keshav-Learn — Threshold Optimizer
//
// Adjusts ring deny/challenge thresholds based on operational feedback.
//
// Architecture Principle: Learn can NEVER override Fallback Rules.
// ThresholdOptimizer can only adjust Policy Engine thresholds, not the
// hard deny-on-any-ring-deny fallback. This is the architectural
// boundary that ensures the system never fails open.
//
// Adjustment strategy:
//   - Excessive false positives (deny was wrong) → raise threshold
//   - Excessive false negatives (allow was wrong) → lower threshold
//   - Graduated adjustment with bounded limits to prevent oscillation
//   - Confidence weighting: more feedback = larger adjustments
//
// Thread Safety: RwLock-protected for concurrent read/write.
// Latency Budget: <0.05ms per read (thresholds are cached in memory)

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::feedback_collector::{FeedbackEntry, FeedbackType};

/// Per-ring threshold state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdState {
    /// Current deny threshold (0.0-10.0).
    pub deny_threshold: f64,
    /// Current challenge threshold (0.0-10.0).
    pub challenge_threshold: f64,
    /// Default deny threshold (from config).
    pub default_deny_threshold: f64,
    /// Default challenge threshold (from config).
    pub default_challenge_threshold: f64,
    /// Number of adjustments made.
    pub adjustment_count: u64,
    /// Cumulative adjustment applied.
    pub total_adjustment: f64,
    /// Feedback entries that influenced this ring's thresholds.
    pub feedback_count: u64,
}

impl ThresholdState {
    pub fn new(default_deny: f64, default_challenge: f64) -> Self {
        Self {
            deny_threshold: default_deny,
            challenge_threshold: default_challenge,
            default_deny_threshold: default_deny,
            default_challenge_threshold: default_challenge,
            adjustment_count: 0,
            total_adjustment: 0.0,
            feedback_count: 0,
        }
    }

    /// Maximum deviation from default (prevents runaway adjustment).
    const MAX_DEVIATION: f64 = 2.0;
    /// Minimum step size to avoid negligible changes.
    const MIN_STEP: f64 = 0.05;
}

/// Threshold Optimizer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdOptimizerConfig {
    /// Adjustment step size (0.0-1.0). Higher = more aggressive.
    #[serde(default = "default_step_size")]
    pub step_size: f64,
    /// Minimum number of feedback entries before optimization activates.
    #[serde(default = "default_min_feedback")]
    pub min_feedback_for_adjustment: usize,
    /// Maximum number of adjustments per optimization pass.
    #[serde(default = "default_max_adjustments_per_pass")]
    pub max_adjustments_per_pass: usize,
}

fn default_step_size() -> f64 { 0.25 }
fn default_min_feedback() -> usize { 5 }
fn default_max_adjustments_per_pass() -> usize { 3 }

impl Default for ThresholdOptimizerConfig {
    fn default() -> Self {
        Self {
            step_size: default_step_size(),
            min_feedback_for_adjustment: default_min_feedback(),
            max_adjustments_per_pass: default_max_adjustments_per_pass(),
        }
    }
}

/// An optimization result — what was adjusted and why.
#[derive(Debug, Clone, Serialize)]
pub struct OptimizationResult {
    pub ring_name: String,
    pub old_deny: f64,
    pub new_deny: f64,
    pub old_challenge: f64,
    pub new_challenge: f64,
    pub direction: OptimizationDirection,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationDirection {
    /// Threshold raised (less sensitive — fewer denies).
    Raised,
    /// Threshold lowered (more sensitive — more denies).
    Lowered,
    /// No change made.
    Unchanged,
}

/// The Threshold Optimizer — adjusts ring thresholds from feedback.
pub struct ThresholdOptimizer {
    config: ThresholdOptimizerConfig,
    /// Per-ring threshold state (ring_name -> ThresholdState).
    thresholds: RwLock<HashMap<String, ThresholdState>>,
}

impl ThresholdOptimizer {
    pub fn new(config: ThresholdOptimizerConfig) -> Self {
        Self {
            config,
            thresholds: RwLock::new(HashMap::new()),
        }
    }

    /// Register a ring with its default thresholds.
    pub fn register_ring(&self, ring_name: &str, default_deny: f64, default_challenge: f64) {
        let mut thresholds = self.thresholds.write().unwrap();
        thresholds.entry(ring_name.to_string())
            .or_insert_with(|| ThresholdState::new(default_deny, default_challenge));
    }

    /// Get the current deny threshold for a ring.
    pub fn deny_threshold(&self, ring_name: &str) -> f64 {
        let thresholds = self.thresholds.read().unwrap();
        thresholds.get(ring_name)
            .map(|t| t.deny_threshold)
            .unwrap_or(9.0) // default if unregistered
    }

    /// Get the current challenge threshold for a ring.
    pub fn challenge_threshold(&self, ring_name: &str) -> f64 {
        let thresholds = self.thresholds.read().unwrap();
        thresholds.get(ring_name)
            .map(|t| t.challenge_threshold)
            .unwrap_or(6.0) // default if unregistered
    }

    /// Get all threshold states.
    pub fn all_thresholds(&self) -> HashMap<String, ThresholdState> {
        self.thresholds.read().unwrap().clone()
    }

    /// Run an optimization pass on feedback entries.
    ///
    /// Returns a list of adjustments made. The ThresholdOptimizer analyzes
    /// false positive/negative patterns per ring and adjusts thresholds
    /// with bounded graduated steps.
    pub fn optimize(&self, feedback: &[FeedbackEntry]) -> Vec<OptimizationResult> {
        if feedback.len() < self.config.min_feedback_for_adjustment {
            return vec![];
        }

        let mut results = Vec::new();
        let mut adjustments = 0;

        // Group feedback by target ring.
        let mut by_ring: HashMap<String, Vec<&FeedbackEntry>> = HashMap::new();
        for entry in feedback {
            for ring in &entry.target_rings {
                by_ring.entry(ring.clone()).or_default().push(entry);
            }
            // If no target rings specified, apply to all registered rings.
            if entry.target_rings.is_empty() {
                let thresholds = self.thresholds.read().unwrap();
                for ring_name in thresholds.keys() {
                    by_ring.entry(ring_name.clone()).or_default().push(entry);
                }
            }
        }

        for (ring_name, ring_feedback) in &by_ring {
            if adjustments >= self.config.max_adjustments_per_pass {
                break;
            }

            let mut false_positives = 0;
            let mut false_negatives = 0;

            for entry in ring_feedback {
                match entry.feedback_type {
                    FeedbackType::FalsePositive | FeedbackType::Approve => {
                        if entry.original_decision.starts_with("deny") {
                            false_positives += 1;
                        }
                    }
                    FeedbackType::FalseNegative | FeedbackType::Reject => {
                        if entry.original_decision.starts_with("allow") {
                            false_negatives += 1;
                        }
                    }
                    _ => {}
                }
            }

            let fp_rate = false_positives as f64 / ring_feedback.len() as f64;
            let fn_rate = false_negatives as f64 / ring_feedback.len() as f64;
            let total = ring_feedback.len();

            // Determine direction.
            let direction = if fp_rate > fn_rate && fp_rate > 0.3 {
                OptimizationDirection::Raised // too many false positives
            } else if fn_rate > fp_rate && fn_rate > 0.3 {
                OptimizationDirection::Lowered // too many false negatives
            } else {
                OptimizationDirection::Unchanged
            };

            let mut thresholds = self.thresholds.write().unwrap();
            let state = thresholds.entry(ring_name.clone())
                .or_insert_with(|| ThresholdState::new(9.0, 6.0));

            let old_deny = state.deny_threshold;
            let old_challenge = state.challenge_threshold;

            match direction {
                OptimizationDirection::Raised => {
                    let step = self.config.step_size * fp_rate.clamp(0.1, 1.0);
                    let step = step.max(ThresholdState::MIN_STEP);
                    let max_allowed = state.default_deny_threshold + ThresholdState::MAX_DEVIATION;
                    state.deny_threshold = (state.deny_threshold + step).min(max_allowed);
                    let max_challenge = state.default_challenge_threshold + ThresholdState::MAX_DEVIATION;
                    state.challenge_threshold = (state.challenge_threshold + step * 0.5).min(max_challenge);
                }
                OptimizationDirection::Lowered => {
                    let step = self.config.step_size * fn_rate.clamp(0.1, 1.0);
                    let step = step.max(ThresholdState::MIN_STEP);
                    let min_allowed = state.default_deny_threshold - ThresholdState::MAX_DEVIATION;
                    state.deny_threshold = (state.deny_threshold - step).max(min_allowed);
                    let min_challenge = state.default_challenge_threshold - ThresholdState::MAX_DEVIATION;
                    state.challenge_threshold = (state.challenge_threshold - step * 0.5).max(min_challenge);
                }
                OptimizationDirection::Unchanged => continue,
            }

            state.adjustment_count += 1;
            state.total_adjustment += state.deny_threshold - old_deny;
            state.feedback_count += total as u64;

            results.push(OptimizationResult {
                ring_name: ring_name.clone(),
                old_deny,
                new_deny: state.deny_threshold,
                old_challenge,
                new_challenge: state.challenge_threshold,
                direction,
                reason: format!(
                    "fp_rate={:.2}, fn_rate={:.2}, feedback_count={}, step={:.3}",
                    fp_rate, fn_rate, total,
                    self.config.step_size
                ),
                confidence: (total as f64 / self.config.min_feedback_for_adjustment as f64).clamp(0.0, 1.0),
            });

            adjustments += 1;
        }

        if !results.is_empty() {
            tracing::info!(
                adjustments = results.len(),
                "Keshav-Learn: threshold optimization applied"
            );
        }

        results
    }

    /// Reset a ring's thresholds to defaults.
    pub fn reset(&self, ring_name: &str) -> bool {
        let mut thresholds = self.thresholds.write().unwrap();
        if let Some(state) = thresholds.get_mut(ring_name) {
            state.deny_threshold = state.default_deny_threshold;
            state.challenge_threshold = state.default_challenge_threshold;
            true
        } else {
            false
        }
    }

    /// Reset all thresholds to defaults.
    pub fn reset_all(&self) {
        let mut thresholds = self.thresholds.write().unwrap();
        for state in thresholds.values_mut() {
            state.deny_threshold = state.default_deny_threshold;
            state.challenge_threshold = state.default_challenge_threshold;
        }
    }
}

impl Clone for ThresholdOptimizer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            thresholds: RwLock::new(self.thresholds.read().unwrap().clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keshav::feedback_collector::FeedbackSeverity;

    fn make_optimizer() -> ThresholdOptimizer {
        let opt = ThresholdOptimizer::new(ThresholdOptimizerConfig::default());
        opt.register_ring("shield", 9.0, 6.0);
        opt.register_ring("threat", 8.0, 5.0);
        opt.register_ring("identity", 6.0, 4.0);
        opt
    }

    fn make_fp_feedback(ring: &str, count: usize) -> Vec<FeedbackEntry> {
        (0..count).map(|i| FeedbackEntry {
            feedback_id: format!("fb-fp-{}", i),
            request_id: format!("req-fp-{}", i),
            feedback_type: FeedbackType::FalsePositive,
            severity: FeedbackSeverity::High,
            target_rings: vec![ring.to_string()],
            original_decision: "deny:WAF_PATTERN_MATCH".to_string(),
            explanation: "benign request was blocked".to_string(),
            submitted_by: "admin".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        }).collect()
    }

    fn make_fn_feedback(ring: &str, count: usize) -> Vec<FeedbackEntry> {
        (0..count).map(|i| FeedbackEntry {
            feedback_id: format!("fb-fn-{}", i),
            request_id: format!("req-fn-{}", i),
            feedback_type: FeedbackType::FalseNegative,
            severity: FeedbackSeverity::Critical,
            target_rings: vec![ring.to_string()],
            original_decision: "allow".to_string(),
            explanation: "malicious request was allowed".to_string(),
            submitted_by: "admin".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        }).collect()
    }

    #[test]
    fn register_and_read_defaults() {
        let opt = make_optimizer();
        assert_eq!(opt.deny_threshold("shield"), 9.0);
        assert_eq!(opt.challenge_threshold("shield"), 6.0);
        assert_eq!(opt.deny_threshold("threat"), 8.0);
        assert_eq!(opt.deny_threshold("unregistered"), 9.0); // fallback
    }

    #[test]
    fn too_few_feedback_no_change() {
        let opt = make_optimizer();
        let results = opt.optimize(&make_fp_feedback("shield", 2));
        assert!(results.is_empty());
    }

    #[test]
    fn false_positives_raise_threshold() {
        let opt = make_optimizer();
        let feedback = make_fp_feedback("shield", 10);
        let results = opt.optimize(&feedback);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].direction, OptimizationDirection::Raised);
        assert!(results[0].new_deny > results[0].old_deny);
    }

    #[test]
    fn false_negatives_lower_threshold() {
        let opt = make_optimizer();
        let feedback = make_fn_feedback("threat", 10);
        let results = opt.optimize(&feedback);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].direction, OptimizationDirection::Lowered);
        assert!(results[0].new_deny < results[0].old_deny);
    }

    #[test]
    fn max_deviation_boundary() {
        let opt = make_optimizer();
        // Repeatedly optimize with false positives — should cap at MAX_DEVIATION.
        for _ in 0..50 {
            let feedback = make_fp_feedback("shield", 10);
            opt.optimize(&feedback);
        }
        let deny = opt.deny_threshold("shield");
        assert!(deny <= 9.0 + ThresholdState::MAX_DEVIATION + 0.01);
    }

    #[test]
    fn reset_to_defaults() {
        let opt = make_optimizer();
        opt.optimize(&make_fp_feedback("shield", 10));
        assert!(opt.deny_threshold("shield") > 9.0);
        opt.reset("shield");
        assert_eq!(opt.deny_threshold("shield"), 9.0);
    }

    #[test]
    fn reset_all() {
        let opt = make_optimizer();
        opt.optimize(&make_fp_feedback("shield", 10));
        opt.optimize(&make_fn_feedback("threat", 10));
        opt.reset_all();
        assert_eq!(opt.deny_threshold("shield"), 9.0);
        assert_eq!(opt.deny_threshold("threat"), 8.0);
    }

    #[test]
    fn all_thresholds_snapshot() {
        let opt = make_optimizer();
        let all = opt.all_thresholds();
        assert!(all.contains_key("shield"));
        assert!(all.contains_key("threat"));
        assert!(all.contains_key("identity"));
    }
}
