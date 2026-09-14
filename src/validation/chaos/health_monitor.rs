// Chaos Framework — Health Monitor (D4)
//
// Tracks health samples across all subsystems over time.
// Provides cascade detection (secondary failures from a primary fault)
// and recovery time measurement.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use super::fault_types::FaultTarget;

/// A single health sample for a target at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSample {
    /// RFC 3339 timestamp of the sample.
    pub timestamp: String,
    /// Which target this sample is for.
    pub target: FaultTarget,
    /// Whether the target is healthy at this point.
    pub healthy: bool,
    /// Response time in milliseconds (if available).
    pub response_time_ms: Option<u64>,
    /// Current error rate (0.0–1.0).
    pub error_rate: f64,
    /// Arbitrary custom metrics.
    pub custom_metrics: HashMap<String, f64>,
}

impl HealthSample {
    /// Create a new health sample.
    pub fn new(
        target: FaultTarget,
        healthy: bool,
        response_time_ms: Option<u64>,
        error_rate: f64,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target,
            healthy,
            response_time_ms,
            error_rate,
            custom_metrics: HashMap::new(),
        }
    }

    /// Builder: add a custom metric.
    pub fn with_metric(mut self, key: &str, value: f64) -> Self {
        self.custom_metrics.insert(key.to_string(), value);
        self
    }

    /// Builder: set the timestamp (useful for testing/replay).
    pub fn with_timestamp(mut self, ts: &str) -> Self {
        self.timestamp = ts.to_string();
        self
    }
}

/// Monitors health across all targets over time.
///
/// Accumulates health samples and provides analysis:
/// - Latest health per target
/// - Recovery time measurement
/// - Cascade detection (which other targets became unhealthy)
pub struct HealthMonitor {
    samples: Vec<HealthSample>,
}

impl HealthMonitor {
    /// Create a new health monitor.
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    /// Record a health sample.
    pub fn sample(
        &mut self,
        target: FaultTarget,
        healthy: bool,
        response_time_ms: Option<u64>,
        error_rate: f64,
    ) {
        let s = HealthSample::new(target, healthy, response_time_ms, error_rate);
        info!(
            target = %s.target.label(),
            healthy = s.healthy,
            "Health sample recorded"
        );
        self.samples.push(s);
    }

    /// Record a pre-built health sample.
    pub fn record_sample(&mut self, sample: HealthSample) {
        self.samples.push(sample);
    }

    /// Check if a target is currently healthy based on the latest sample.
    /// Returns `true` if no samples exist for the target (assume healthy).
    pub fn is_healthy(&self, target: FaultTarget) -> bool {
        self.samples
            .iter()
            .rev()
            .find(|s| s.target == target)
            .map(|s| s.healthy)
            .unwrap_or(true)
    }

    /// Get the latest sample for a target.
    pub fn latest_sample(&self, target: FaultTarget) -> Option<&HealthSample> {
        self.samples.iter().rev().find(|s| s.target == target)
    }

    /// Calculate recovery time for a target after a fault was injected.
    ///
    /// Scans from the injection time forward. Recovery is the first sample
    /// after `injection_time` where the target is healthy again.
    /// Returns `None` if recovery was not observed.
    pub fn recovery_time(&self, target: FaultTarget, injection_time: &str) -> Option<u64> {
        // Parse injection time.
        let inj_dt = chrono::DateTime::parse_from_rfc3339(injection_time).ok()?;
        let inj_ms = inj_dt.timestamp_millis() as u64;

        let mut found_unhealthy = false;

        for s in &self.samples {
            if s.target != target {
                continue;
            }
            let sample_dt = chrono::DateTime::parse_from_rfc3339(&s.timestamp).ok()?;
            let sample_ms = sample_dt.timestamp_millis() as u64;

            if sample_ms < inj_ms {
                continue;
            }

            if !s.healthy {
                found_unhealthy = true;
            } else if found_unhealthy {
                // First healthy sample after being unhealthy = recovery.
                return Some(sample_ms.saturating_sub(inj_ms));
            }
        }

        None
    }

    /// Detect cascade failures caused by a fault injected into `injection_target`.
    ///
    /// Returns a list of targets that became unhealthy *after* the injection time
    /// and were healthy *before* the injection time. The injection target itself
    /// is excluded from the cascade list.
    pub fn detect_cascade(
        &self,
        injection_target: FaultTarget,
        injection_time: &str,
    ) -> Vec<FaultTarget> {
        let inj_dt = match chrono::DateTime::parse_from_rfc3339(injection_time) {
            Ok(dt) => dt.timestamp_millis() as u64,
            Err(_) => return Vec::new(),
        };

        // Collect per-target health status before injection.
        let mut healthy_before: HashMap<FaultTarget, bool> = HashMap::new();
        for s in &self.samples {
            let sample_dt = match chrono::DateTime::parse_from_rfc3339(&s.timestamp) {
                Ok(dt) => dt.timestamp_millis() as u64,
                Err(_) => continue,
            };
            if sample_dt < inj_dt {
                healthy_before.insert(s.target.clone(), s.healthy);
            }
        }

        // Collect per-target health status after injection.
        let mut unhealthy_after: HashMap<FaultTarget, bool> = HashMap::new();
        for s in &self.samples {
            let sample_dt = match chrono::DateTime::parse_from_rfc3339(&s.timestamp) {
                Ok(dt) => dt.timestamp_millis() as u64,
                Err(_) => continue,
            };
            if sample_dt >= inj_dt && !s.healthy {
                unhealthy_after.insert(s.target.clone(), true);
            }
        }

        // A cascade target was healthy before but unhealthy after, and is
        // NOT the injection target itself.
        let mut cascaded = Vec::new();
        for (target, _was_unhealthy) in &unhealthy_after {
            if *target == injection_target {
                continue;
            }
            let was_healthy_before = healthy_before.get(target).copied().unwrap_or(true);
            if was_healthy_before {
                cascaded.push(target.clone());
            }
        }

        cascaded
    }

    /// Get all recorded health samples (read-only).
    pub fn health_history(&self) -> &[HealthSample] {
        &self.samples
    }

    /// Get the total number of samples recorded.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get the number of samples for a specific target.
    pub fn sample_count_for(&self, target: FaultTarget) -> usize {
        self.samples.iter().filter(|s| s.target == target).count()
    }

    /// Get all unique targets that have been sampled.
    pub fn sampled_targets(&self) -> Vec<FaultTarget> {
        let mut targets: Vec<FaultTarget> = self
            .samples
            .iter()
            .map(|s| s.target.clone())
            .collect();
        targets.sort_by(|a, b| a.label().cmp(b.label()));
        targets.dedup();
        targets
    }

    /// Clear all samples.
    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_healthy_defaults_to_true() {
        let monitor = HealthMonitor::new();
        assert!(monitor.is_healthy(FaultTarget::Shield));
    }

    #[test]
    fn is_healthy_tracks_latest() {
        let mut monitor = HealthMonitor::new();
        monitor.sample(FaultTarget::Shield, true, Some(10), 0.0);
        assert!(monitor.is_healthy(FaultTarget::Shield));

        monitor.sample(FaultTarget::Shield, false, None, 1.0);
        assert!(!monitor.is_healthy(FaultTarget::Shield));

        monitor.sample(FaultTarget::Shield, true, Some(15), 0.0);
        assert!(monitor.is_healthy(FaultTarget::Shield));
    }

    #[test]
    fn recovery_time_measurement() {
        let mut monitor = HealthMonitor::new();
        let base = "2025-01-01T00:00:00+00:00";

        // Healthy before injection.
        monitor.record_sample(
            HealthSample::new(FaultTarget::Agent, true, Some(5), 0.0)
                .with_timestamp("2024-12-31T23:59:59+00:00"),
        );

        // Unhealthy after injection.
        monitor.record_sample(
            HealthSample::new(FaultTarget::Agent, false, None, 1.0)
                .with_timestamp("2025-01-01T00:00:01+00:00"),
        );

        // Recovered.
        monitor.record_sample(
            HealthSample::new(FaultTarget::Agent, true, Some(8), 0.0)
                .with_timestamp("2025-01-01T00:00:05+00:00"),
        );

        let rt = monitor.recovery_time(FaultTarget::Agent, base);
        assert_eq!(rt, Some(5000)); // 5 seconds in ms.
    }

    #[test]
    fn recovery_time_none_if_no_recovery() {
        let mut monitor = HealthMonitor::new();
        let base = "2025-01-01T00:00:00+00:00";

        monitor.record_sample(
            HealthSample::new(FaultTarget::Agent, false, None, 1.0)
                .with_timestamp("2025-01-01T00:00:01+00:00"),
        );

        assert_eq!(monitor.recovery_time(FaultTarget::Agent, base), None);
    }

    #[test]
    fn cascade_detection() {
        let mut monitor = HealthMonitor::new();
        let inj_time = "2025-01-01T00:00:00+00:00";

        // Before injection: all healthy.
        monitor.record_sample(
            HealthSample::new(FaultTarget::Shield, true, Some(5), 0.0)
                .with_timestamp("2024-12-31T23:59:59+00:00"),
        );
        monitor.record_sample(
            HealthSample::new(FaultTarget::Threat, true, Some(5), 0.0)
                .with_timestamp("2024-12-31T23:59:59+00:00"),
        );
        monitor.record_sample(
            HealthSample::new(FaultTarget::Execution, true, Some(5), 0.0)
                .with_timestamp("2024-12-31T23:59:59+00:00"),
        );

        // After injection: shield (injection target) and threat become unhealthy.
        monitor.record_sample(
            HealthSample::new(FaultTarget::Shield, false, None, 1.0)
                .with_timestamp("2025-01-01T00:00:01+00:00"),
        );
        monitor.record_sample(
            HealthSample::new(FaultTarget::Threat, false, None, 0.8)
                .with_timestamp("2025-01-01T00:00:02+00:00"),
        );

        let cascade = monitor.detect_cascade(FaultTarget::Shield, inj_time);
        // Threat cascaded, Execution did not.
        assert_eq!(cascade.len(), 1);
        assert!(cascade.contains(&FaultTarget::Threat));
    }

    #[test]
    fn sampled_targets_deduplication() {
        let mut monitor = HealthMonitor::new();
        monitor.sample(FaultTarget::Shield, true, None, 0.0);
        monitor.sample(FaultTarget::Shield, true, None, 0.0);
        monitor.sample(FaultTarget::Threat, true, None, 0.0);

        let targets = monitor.sampled_targets();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn clear_resets_all_samples() {
        let mut monitor = HealthMonitor::new();
        monitor.sample(FaultTarget::Shield, false, None, 1.0);
        assert_eq!(monitor.sample_count(), 1);

        monitor.clear();
        assert_eq!(monitor.sample_count(), 0);
        // Defaults to healthy when empty.
        assert!(monitor.is_healthy(FaultTarget::Shield));
    }
}
