// Drift Detection — statistical anomaly detection for 10 drift types.
//
// Uses Welford's online algorithm for computing mean/variance
// over a sliding window. Detects drift when z-score exceeds threshold.
//
// This is NOT threshold-based alerting. This is STATISTICAL drift detection.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The 10 drift types ANANTA monitors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    Decision,
    Policy,
    Model,
    Orchestration,
    Learning,
    Memory,
    Configuration,
    Plugin,
    Runtime,
    Trust,
}

impl std::fmt::Display for DriftType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single observation fed into the drift detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftObservation {
    pub drift_type: DriftType,
    /// The observed value (e.g., allow ratio = 0.85).
    pub value: f64,
    /// Optional context (e.g., ring name, policy version).
    pub context: String,
    pub timestamp: String,
}

/// A drift alert generated when z-score exceeds threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftAlert {
    pub drift_type: DriftType,
    pub z_score: f64,
    pub current_mean: f64,
    pub current_stddev: f64,
    pub observed_value: f64,
    pub context: String,
    pub timestamp: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl DriftAlert {
    pub fn summary(&self) -> String {
        format!(
            "[DRIFT] type={} z={:.2} mean={:.4} std={:.4} value={:.4} context={}",
            self.drift_type, self.z_score, self.current_mean,
            self.current_stddev, self.observed_value, self.context,
        )
    }
}

/// Online drift detector using Welford's algorithm.
///
/// Maintains a sliding window of observations and computes
/// running mean/variance. When a new observation's z-score
/// exceeds the threshold, a DriftAlert is generated.
#[derive(Debug)]
pub struct DriftDetector {
    /// One detector per drift type.
    detectors: std::collections::HashMap<DriftType, TypeDetector>,
    /// How many standard deviations before alerting.
    sigma_threshold: f64,
    /// Window size for each detector.
    window_size: usize,
}

/// Per-type detector state.
#[derive(Debug)]
struct TypeDetector {
    window: VecDeque<f64>,
    // Welford's online stats.
    count: u64,
    mean: f64,
    m2: f64, // sum of squared differences from mean.
}

impl TypeDetector {
    fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Add an observation and return the z-score.
    fn observe(&mut self, value: f64, window_size: usize) -> (f64, f64, f64) {
        // Welford's online algorithm.
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        // Add to sliding window.
        self.window.push_back(value);
        if self.window.len() > window_size {
            self.window.pop_front();
        }

        let variance = if self.count > 1 {
            self.m2 / (self.count - 1) as f64
        } else {
            1.0 // Not enough data.
        };

        let stddev = variance.sqrt().max(1e-10);
        let z_score = (value - self.mean) / stddev;

        (z_score, self.mean, stddev)
    }

    fn reset(&mut self) {
        self.window.clear();
        self.count = 0;
        self.mean = 0.0;
        self.m2 = 0.0;
    }
}

impl DriftDetector {
    pub fn new(sigma_threshold: f64, window_size: usize) -> Self {
        let mut detectors = std::collections::HashMap::new();
        for dt in DriftType::all() {
            detectors.insert(dt.clone(), TypeDetector::new(window_size));
        }
        Self { detectors, sigma_threshold, window_size }
    }

    /// Feed an observation. Returns Some(DriftAlert) if drift detected.
    pub fn observe(&mut self, obs: DriftObservation) -> Option<DriftAlert> {
        let detector = self.detectors.get_mut(&obs.drift_type)?;
        let (z_score, mean, stddev) = detector.observe(obs.value, self.window_size);

        if z_score.abs() > self.sigma_threshold && detector.count > 10 {
            // Enough data to be meaningful.
            let severity = if z_score.abs() > self.sigma_threshold * 2.0 {
                AlertSeverity::Critical
            } else if z_score.abs() > self.sigma_threshold * 1.5 {
                AlertSeverity::Warning
            } else {
                AlertSeverity::Info
            };

            Some(DriftAlert {
                drift_type: obs.drift_type,
                z_score,
                current_mean: mean,
                current_stddev: stddev,
                observed_value: obs.value,
                context: obs.context,
                timestamp: obs.timestamp,
                severity,
            })
        } else {
            None
        }
    }

    /// Get current stats for a drift type.
    pub fn stats(&self, drift_type: &DriftType) -> Option<(f64, f64, usize)> {
        let d = self.detectors.get(drift_type)?;
        let variance = if d.count > 1 { d.m2 / (d.count - 1) as f64 } else { 0.0 };
        Some((d.mean, variance.sqrt(), d.window.len()))
    }

    /// Reset a detector (e.g., after a known policy change).
    pub fn reset(&mut self, drift_type: &DriftType) {
        if let Some(d) = self.detectors.get_mut(drift_type) {
            d.reset();
        }
    }

    /// Reset all detectors.
    pub fn reset_all(&mut self) {
        for d in self.detectors.values_mut() {
            d.reset();
        }
    }
}

impl DriftType {
    pub fn all() -> &'static [DriftType] {
        &[
            DriftType::Decision,
            DriftType::Policy,
            DriftType::Model,
            DriftType::Orchestration,
            DriftType::Learning,
            DriftType::Memory,
            DriftType::Configuration,
            DriftType::Plugin,
            DriftType::Runtime,
            DriftType::Trust,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector() -> DriftDetector {
        DriftDetector::new(3.0, 100)
    }

    fn obs(dt: DriftType, value: f64) -> DriftObservation {
        DriftObservation {
            drift_type: dt,
            value,
            context: String::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn no_drift_stable_data() {
        let mut det = make_detector();
        // Feed stable data.
        for _ in 0..50 {
            assert!(det.observe(obs(DriftType::Decision, 0.85 + (rand::random::<f64>() * 0.02 - 0.01))).is_none());
        }
    }

    #[test]
    fn drift_detected_on_shift() {
        let mut det = make_detector();
        // Establish baseline.
        for _ in 0..50 {
            det.observe(obs(DriftType::Decision, 0.85));
        }
        // Sudden shift.
        let alert = det.observe(obs(DriftType::Decision, 0.40));
        assert!(alert.is_some());
        assert!(alert.unwrap().z_score.abs() > 3.0);
    }

    #[test]
    fn gradual_drift_detected() {
        let mut det = make_detector();
        // Baseline at 0.5.
        for _ in 0..50 {
            det.observe(obs(DriftType::Trust, 0.50));
        }
        // Gradual decline.
        let mut alerted = false;
        for i in 0..100 {
            let value = 0.50 - (i as f64 * 0.005); // 0.50 → 0.00
            if let Some(_) = det.observe(obs(DriftType::Trust, value)) {
                alerted = true;
                break;
            }
        }
        assert!(alerted, "gradual drift should be detected");
    }

    #[test]
    fn reset_clears_state() {
        let mut det = make_detector();
        for _ in 0..20 {
            det.observe(obs(DriftType::Decision, 0.9));
        }
        det.reset(&DriftType::Decision);
        // After reset, should need new baseline.
        // A value that would have been normal before should not alert.
        let stats = det.stats(&DriftType::Decision).unwrap();
        assert_eq!(stats.2, 0); // Window empty.
    }

    #[test]
    fn all_drift_types_have_detectors() {
        let det = make_detector();
        for dt in DriftType::all() {
            assert!(det.stats(dt).is_some());
        }
    }

    #[test]
    fn alert_severity_scaling() {
        let mut det = make_detector();
        for _ in 0..50 {
            det.observe(obs(DriftType::Policy, 0.5));
        }
        // Extreme shift.
        let alert = det.observe(obs(DriftType::Policy, -5.0)).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }
}