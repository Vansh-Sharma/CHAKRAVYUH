// Chaos Framework — Recovery Metrics (D4)
//
// Tracks per-fault recovery outcomes and produces aggregate summaries.
// Supports both overall and per-target breakdowns.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Recovery outcome for a single fault injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    /// The fault injection ID.
    pub fault_id: String,
    /// Human-readable fault type name (e.g. "ring_crash", "state_corruption").
    pub fault_type: String,
    /// The target that was faulted.
    pub target: String,
    /// Whether the system recovered from this fault.
    pub recovered: bool,
    /// Time from fault injection to recovery, in milliseconds.
    pub recovery_time_ms: Option<u64>,
    /// Whether this fault caused cascading failures.
    pub cascaded: bool,
    /// Which targets were affected by the cascade.
    pub cascade_targets: Vec<String>,
    /// Whether the system auto-healed (vs. manual recovery).
    pub auto_healed: bool,
    /// Whether data was lost during this fault.
    pub data_loss: bool,
}

impl RecoveryMetrics {
    /// Create a new recovery metric.
    pub fn new(fault_id: &str, fault_type: &str, target: &str) -> Self {
        Self {
            fault_id: fault_id.to_string(),
            fault_type: fault_type.to_string(),
            target: target.to_string(),
            recovered: false,
            recovery_time_ms: None,
            cascaded: false,
            cascade_targets: Vec::new(),
            auto_healed: false,
            data_loss: false,
        }
    }

    /// Builder: mark as recovered with a recovery time.
    pub fn recovered(mut self, time_ms: u64) -> Self {
        self.recovered = true;
        self.recovery_time_ms = Some(time_ms);
        self
    }

    /// Builder: mark as auto-healed.
    pub fn auto_healed(mut self) -> Self {
        self.auto_healed = true;
        self
    }

    /// Builder: mark as cascaded with affected targets.
    pub fn cascaded(mut self, targets: Vec<String>) -> Self {
        self.cascaded = true;
        self.cascade_targets = targets;
        self
    }

    /// Builder: mark data loss.
    pub fn data_loss(mut self) -> Self {
        self.data_loss = true;
        self
    }
}

/// Aggregate recovery summary across multiple faults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySummary {
    /// Total number of faults.
    pub total_faults: u64,
    /// Number of faults that recovered.
    pub recovered: u64,
    /// Recovery rate (0.0–1.0).
    pub recovery_rate: f64,
    /// Average recovery time in ms (only for recovered faults).
    pub avg_recovery_ms: f64,
    /// Number of faults that caused cascading failures.
    pub cascading_faults: u64,
    /// Auto-heal rate (0.0–1.0).
    pub auto_heal_rate: f64,
    /// Number of data loss events.
    pub data_loss_events: u64,
}

impl RecoverySummary {
    /// Compute aggregate summary from a list of recovery metrics.
    pub fn from_metrics(metrics: &[RecoveryMetrics]) -> Self {
        let total = metrics.len() as u64;
        if total == 0 {
            return Self {
                total_faults: 0,
                recovered: 0,
                recovery_rate: 0.0,
                avg_recovery_ms: 0.0,
                cascading_faults: 0,
                auto_heal_rate: 0.0,
                data_loss_events: 0,
            };
        }

        let recovered = metrics.iter().filter(|m| m.recovered).count() as u64;
        let cascading = metrics.iter().filter(|m| m.cascaded).count() as u64;
        let data_loss = metrics.iter().filter(|m| m.data_loss).count() as u64;
        let auto_healed = metrics.iter().filter(|m| m.auto_healed).count() as u64;

        let recovery_sum: u64 = metrics
            .iter()
            .filter_map(|m| m.recovery_time_ms)
            .sum();
        let recovery_count = metrics.iter().filter(|m| m.recovery_time_ms.is_some()).count();
        let avg_recovery = if recovery_count > 0 {
            recovery_sum as f64 / recovery_count as f64
        } else {
            0.0
        };

        Self {
            total_faults: total,
            recovered,
            recovery_rate: if total > 0 {
                recovered as f64 / total as f64
            } else {
                0.0
            },
            avg_recovery_ms: avg_recovery,
            cascading_faults: cascading,
            auto_heal_rate: if total > 0 {
                auto_healed as f64 / total as f64
            } else {
                0.0
            },
            data_loss_events: data_loss,
        }
    }

    /// Compute per-target recovery summaries.
    ///
    /// Groups metrics by the `target` field and computes a `RecoverySummary`
    /// for each group.
    pub fn per_target_summary(
        metrics: &[RecoveryMetrics],
    ) -> HashMap<String, RecoverySummary> {
        let mut by_target: HashMap<String, Vec<&RecoveryMetrics>> = HashMap::new();
        for m in metrics {
            by_target
                .entry(m.target.clone())
                .or_default()
                .push(m);
        }

        let mut result = HashMap::new();
        for (target, group) in by_target {
            let owned: Vec<RecoveryMetrics> = group.into_iter().cloned().collect();
            result.insert(target, RecoverySummary::from_metrics(&owned));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metric(id: &str, fault_type: &str, target: &str) -> RecoveryMetrics {
        RecoveryMetrics::new(id, fault_type, target)
    }

    #[test]
    fn empty_metrics_yields_zero_summary() {
        let summary = RecoverySummary::from_metrics(&[]);
        assert_eq!(summary.total_faults, 0);
        assert_eq!(summary.recovery_rate, 0.0);
        assert_eq!(summary.avg_recovery_ms, 0.0);
    }

    #[test]
    fn full_recovery_summary() {
        let metrics = vec![
            make_metric("f1", "ring_crash", "shield").recovered(100).auto_healed(),
            make_metric("f2", "ring_crash", "shield").recovered(200),
            make_metric("f3", "state_loss", "memory")
                .recovered(500)
                .cascaded(vec!["agent".to_string()])
                .data_loss(),
            make_metric("f4", "network_partition", "shield"),
        ];

        let summary = RecoverySummary::from_metrics(&metrics);
        assert_eq!(summary.total_faults, 4);
        assert_eq!(summary.recovered, 3);
        assert!((summary.recovery_rate - 0.75).abs() < f64::EPSILON);
        assert!((summary.avg_recovery_ms - 266.666_7).abs() < 0.01);
        assert_eq!(summary.cascading_faults, 1);
        assert!((summary.auto_heal_rate - 0.25).abs() < f64::EPSILON);
        assert_eq!(summary.data_loss_events, 1);
    }

    #[test]
    fn per_target_summary_groups_correctly() {
        let metrics = vec![
            make_metric("a", "crash", "shield").recovered(100),
            make_metric("b", "crash", "shield").recovered(200),
            make_metric("c", "hang", "threat").recovered(300),
        ];

        let by_target = RecoverySummary::per_target_summary(&metrics);
        assert_eq!(by_target.len(), 2);

        let shield = by_target.get("shield").unwrap();
        assert_eq!(shield.total_faults, 2);
        assert_eq!(shield.recovered, 2);
        assert!((shield.avg_recovery_ms - 150.0).abs() < f64::EPSILON);

        let threat = by_target.get("threat").unwrap();
        assert_eq!(threat.total_faults, 1);
    }
}
