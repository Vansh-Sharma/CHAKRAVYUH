// Soak Framework — Drift Detector (D6)
//
// Detects behavioral drift over long-running soaks by comparing
// time-windowed metric distributions using z-score analysis.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::validation::verification::Severity;

/// Configuration for the drift detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftConfig {
    /// Number of samples per time window.
    pub window_size_samples: usize,
    /// Sensitivity threshold (0.0–1.0). Higher means less sensitive.
    pub sensitivity_threshold: f64,
    /// Names of metrics to track for drift.
    pub metrics_to_track: Vec<String>,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            window_size_samples: 100,
            sensitivity_threshold: 0.5,
            metrics_to_track: vec![
                "latency_us".to_string(),
                "error_rate".to_string(),
                "cpu_percent".to_string(),
            ],
        }
    }
}

/// A time window containing computed metric statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftWindow {
    /// Index of this window (0-based).
    pub window_index: usize,
    /// RFC 3339 start time of the window.
    pub start_time: String,
    /// RFC 3339 end time of the window.
    pub end_time: String,
    /// Computed metrics for this window.
    pub metrics: HashMap<String, WindowMetric>,
}

/// Statistical summary of a metric within a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowMetric {
    /// Name of the metric.
    pub name: String,
    /// Mean value.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// 50th percentile.
    pub p50: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Number of data points.
    pub count: u64,
}

/// A report describing behavioral drift between two consecutive windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    /// Name of the drifting metric.
    pub metric: String,
    /// Index of the baseline (previous) window.
    pub from_window: usize,
    /// Index of the drifted (current) window.
    pub to_window: usize,
    /// Drift score (z-score based, higher = more drift).
    pub drift_score: f64,
    /// Absolute shift in mean between windows.
    pub mean_shift: f64,
    /// Change in standard deviation between windows.
    pub stddev_change: f64,
    /// Whether the drift is significant given the sensitivity threshold.
    pub significant: bool,
    /// Severity of the drift.
    pub severity: Severity,
}

/// Detects behavioral drift by comparing metric distributions
/// across consecutive time windows.
///
/// Each window is characterized by mean, stddev, and percentiles.
/// Drift between consecutive windows is measured using a z-score
/// derived from the combined variance of both windows.
pub struct DriftDetector {
    windows: Vec<DriftWindow>,
    config: DriftConfig,
}

impl DriftDetector {
    /// Create a new drift detector with the given configuration.
    pub fn new(config: DriftConfig) -> Self {
        info!(
            window_size = config.window_size_samples,
            sensitivity = config.sensitivity_threshold,
            metrics = ?config.metrics_to_track,
            "DriftDetector initialized"
        );
        Self {
            windows: Vec::new(),
            config,
        }
    }

    /// Add a completed time window's raw metric samples.
    ///
    /// The `samples` parameter is a slice of (metric_name, value) pairs
    /// collected during this time window. The detector computes statistics
    /// for each tracked metric.
    pub fn add_window(&mut self, samples: &[(String, f64)]) {
        let window_index = self.windows.len();
        let start_time = chrono::Utc::now().to_rfc3339();

        // Group samples by metric name.
        let mut by_metric: HashMap<String, Vec<f64>> = HashMap::new();
        for (name, value) in samples {
            by_metric.entry(name.clone()).or_default().push(*value);
        }

        // Compute window metrics for all tracked metrics that have data.
        let mut metrics = HashMap::new();
        for metric_name in &self.config.metrics_to_track {
            if let Some(values) = by_metric.get(metric_name) {
                if !values.is_empty() {
                    let wm = compute_window_metric(metric_name, values);
                    metrics.insert(metric_name.clone(), wm);
                }
            }
        }

        let end_time = chrono::Utc::now().to_rfc3339();

        info!(
            window_index,
            metrics_count = metrics.len(),
            "Drift window added"
        );

        self.windows.push(DriftWindow {
            window_index,
            start_time,
            end_time,
            metrics,
        });
    }

    /// Detect drift by comparing consecutive windows.
    ///
    /// For each tracked metric, computes the z-score between adjacent windows.
    /// A drift is considered significant if the z-score exceeds the sensitivity
    /// threshold (mapped to a z-score cutoff).
    pub fn detect_drift(&self) -> Vec<DriftReport> {
        let mut reports = Vec::new();

        if self.windows.len() < 2 {
            return reports;
        }

        for i in 0..self.windows.len() - 1 {
            let prev = &self.windows[i];
            let curr = &self.windows[i + 1];

            for metric_name in &self.config.metrics_to_track {
                let prev_metric = match prev.metrics.get(metric_name) {
                    Some(m) => m,
                    None => continue,
                };
                let curr_metric = match curr.metrics.get(metric_name) {
                    Some(m) => m,
                    None => continue,
                };

                let drift_score = self.compute_drift_score(prev_metric, curr_metric);
                let mean_shift = curr_metric.mean - prev_metric.mean;
                let stddev_change = curr_metric.stddev - prev_metric.stddev;

                // Map sensitivity_threshold to a z-score cutoff.
                // Lower sensitivity → higher cutoff (less likely to flag).
                // sensitivity 0.0 → cutoff 1.0 (very sensitive)
                // sensitivity 0.5 → cutoff 2.0 (moderate)
                // sensitivity 1.0 → cutoff 5.0 (almost never flags)
                let cutoff = 1.0 + self.config.sensitivity_threshold * 4.0;
                let significant = drift_score > cutoff;

                let severity = if drift_score > cutoff * 3.0 {
                    Severity::Critical
                } else if drift_score > cutoff * 2.0 {
                    Severity::High
                } else if drift_score > cutoff {
                    Severity::Medium
                } else if drift_score > cutoff * 0.5 {
                    Severity::Low
                } else {
                    continue; // Not worth reporting if below half the cutoff.
                };

                if significant {
                    warn!(
                        metric = metric_name,
                        from = prev.window_index,
                        to = curr.window_index,
                        drift_score = drift_score,
                        "Significant drift detected"
                    );
                }

                reports.push(DriftReport {
                    metric: metric_name.clone(),
                    from_window: prev.window_index,
                    to_window: curr.window_index,
                    drift_score,
                    mean_shift,
                    stddev_change,
                    significant,
                    severity,
                });
            }
        }

        reports
    }

    /// Compute a z-score based drift score between two window metrics.
    ///
    /// The z-score measures how many standard deviations the current mean
    /// has shifted from the previous mean, accounting for the combined
    /// variance of both windows.
    fn compute_drift_score(&self, prev: &WindowMetric, curr: &WindowMetric) -> f64 {
        let prev_stddev = if prev.stddev < 1e-10 {
            1.0
        } else {
            prev.stddev
        };
        let curr_stddev = if curr.stddev < 1e-10 {
            1.0
        } else {
            curr.stddev
        };

        // Pooled standard deviation using the smaller sample count to be conservative.
        let prev_n = prev.count as f64;
        let curr_n = curr.count as f64;
        let pooled_n = prev_n.min(curr_n).max(1.0);

        let pooled_stddev = ((prev_stddev.powi(2) + curr_stddev.powi(2)) / 2.0).sqrt();

        if pooled_stddev < 1e-10 {
            return 0.0;
        }

        let mean_diff = (curr.mean - prev.mean).abs();

        // z-score: how many pooled stddevs away is the mean shift?
        (mean_diff / pooled_stddev) * (pooled_n.sqrt())
    }

    /// Get the number of windows collected.
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// Get all collected windows (read-only).
    pub fn windows(&self) -> &[DriftWindow] {
        &self.windows
    }
}

/// Compute window statistics from a slice of values.
fn compute_window_metric(name: &str, values: &[f64]) -> WindowMetric {
    let count = values.len() as u64;

    let sum: f64 = values.iter().sum();
    let mean = sum / values.len() as f64;

    let variance = if values.len() > 1 {
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64
    } else {
        0.0
    };
    let stddev = variance.sqrt();

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let percentile = |p: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        if sorted.len() == 1 {
            return sorted[0];
        }
        let rank = (p / 100.0) * (sorted.len() - 1) as f64;
        let lower = rank.floor() as usize;
        let upper = (lower + 1).min(sorted.len() - 1);
        let frac = rank - lower as f64;
        sorted[lower] + frac * (sorted[upper] - sorted[lower])
    };

    WindowMetric {
        name: name.to_string(),
        mean,
        stddev,
        p50: percentile(50.0),
        p99: percentile(99.0),
        count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> DriftConfig {
        DriftConfig {
            window_size_samples: 10,
            sensitivity_threshold: 0.5,
            metrics_to_track: vec!["latency_us".to_string()],
        }
    }

    #[test]
    fn no_drift_with_stable_metrics() {
        let config = default_config();
        let mut detector = DriftDetector::new(config);

        // Two windows with similar distributions.
        let samples1: Vec<(String, f64)> = (0..20)
            .map(|i| ("latency_us".to_string(), 100.0 + (i as f64 * 0.5)))
            .collect();
        let samples2: Vec<(String, f64)> = (0..20)
            .map(|i| ("latency_us".to_string(), 101.0 + (i as f64 * 0.5)))
            .collect();

        detector.add_window(&samples1);
        detector.add_window(&samples2);

        let drift = detector.detect_drift();
        // With similar windows, no significant drift should be found.
        let significant: Vec<_> = drift.iter().filter(|d| d.significant).collect();
        assert!(
            significant.is_empty(),
            "Expected no significant drift but found: {:?}",
            significant
        );
    }

    #[test]
    fn drift_detected_with_large_shift() {
        let config = DriftConfig {
            window_size_samples: 10,
            sensitivity_threshold: 0.1, // Very sensitive.
            metrics_to_track: vec!["latency_us".to_string()],
        };
        let mut detector = DriftDetector::new(config);

        // First window: low latency.
        let samples1: Vec<(String, f64)> = (0..20)
            .map(|i| ("latency_us".to_string(), 100.0 + (i as f64 * 0.1)))
            .collect();
        // Second window: much higher latency.
        let samples2: Vec<(String, f64)> = (0..20)
            .map(|i| ("latency_us".to_string(), 10000.0 + (i as f64 * 10.0)))
            .collect();

        detector.add_window(&samples1);
        detector.add_window(&samples2);

        let drift = detector.detect_drift();
        assert!(!drift.is_empty());
        // At least one report should be significant.
        assert!(drift.iter().any(|d| d.significant));
    }

    #[test]
    fn single_window_no_drift() {
        let config = default_config();
        let mut detector = DriftDetector::new(config);

        let samples: Vec<(String, f64)> = (0..20)
            .map(|i| ("latency_us".to_string(), 100.0 + i as f64))
            .collect();
        detector.add_window(&samples);

        let drift = detector.detect_drift();
        assert!(drift.is_empty());
    }

    #[test]
    fn window_metric_statistics() {
        let values: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let wm = compute_window_metric("test", &values);
        assert_eq!(wm.count, 100);
        assert!((wm.mean - 50.5).abs() < 0.1);
        assert!(wm.stddev > 25.0);
        assert!((wm.p50 - 50.5).abs() < 0.01);
        assert!((wm.p99 - 99.0).abs() < 1.0);
    }

    #[test]
    fn multiple_metrics_tracked() {
        let config = DriftConfig {
            window_size_samples: 10,
            sensitivity_threshold: 0.5,
            metrics_to_track: vec!["latency_us".to_string(), "error_rate".to_string()],
        };
        let mut detector = DriftDetector::new(config);

        let samples1: Vec<(String, f64)> = (0..20)
            .flat_map(|i| {
                vec![
                    ("latency_us".to_string(), 100.0 + i as f64),
                    ("error_rate".to_string(), 0.01),
                ]
            })
            .collect();
        let samples2: Vec<(String, f64)> = (0..20)
            .flat_map(|i| {
                vec![
                    ("latency_us".to_string(), 105.0 + i as f64),
                    ("error_rate".to_string(), 0.01),
                ]
            })
            .collect();

        detector.add_window(&samples1);
        detector.add_window(&samples2);

        assert_eq!(detector.window_count(), 2);

        // Both windows should have both metrics.
        for w in detector.windows() {
            assert!(w.metrics.contains_key("latency_us"));
            assert!(w.metrics.contains_key("error_rate"));
        }
    }
}
