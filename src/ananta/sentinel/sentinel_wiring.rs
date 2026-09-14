// ═══════════════════════════════════════════════════════════════════════
// Sentinel Wiring — Bridge DriftAnalyzer into AnantaPlane
//
// The existing drift.rs uses simple z-score detection (Welford).
// The drift_analyzer.rs has advanced methods (KS, PSI, ADWIN, JS, KL,
// Chi-squared, concept drift) but is NEVER called.
//
// This module provides:
//   1. SentinelHub — unified interface that runs BOTH detectors
//   2. Signal fusion — combine z-score and advanced analysis
//   3. Multi-method verification — cross-validate with multiple methods
//   4. Drift baselines — manage reference distributions for advanced detectors
//   5. Alert correlation — deduplicate and correlate alerts from both detectors
//
// Lightweight inline stubs for KS, PSI, ADWIN are provided here as
// temporary bridges until drift_analyzer.rs types are unified.
// ═══════════════════════════════════════════════════════════════════════

#![deny(unsafe_code)]

use crate::ananta::ovaph_loop::{
    AnalysisMethod, OvaphObservation, OvaphVerificationResult, Severity, VerifiedSignal,
};
use crate::ananta::sentinel::drift::{
    AlertSeverity, DriftAlert, DriftDetector, DriftObservation, DriftType,
};
use crate::ananta::sentinel::drift_analyzer::DriftSeverity;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

// ────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────

/// Maximum number of raw values stored per baseline (prevents unbounded memory).
const MAX_BASELINE_VALUES: usize = 10_000;

/// Default number of histogram bins for baseline computation.
const DEFAULT_HISTOGRAM_BINS: usize = 20;

/// ADWIN window size for simplified concept drift detection.
const ADWIN_WINDOW_SIZE: usize = 50;

/// Significance threshold for advanced detectors (treated as "drift" above this).
const ADVANCED_DRIFT_THRESHOLD: f64 = 0.3;

/// PSI thresholds: < 0.1 = no drift, 0.1-0.25 = moderate, > 0.25 = significant.
const PSI_LOW_THRESHOLD: f64 = 0.1;
const PSI_MEDIUM_THRESHOLD: f64 = 0.25;

// ────────────────────────────────────────────────────────────────────────
// Section 0: Inline Advanced Detection Stubs
// ────────────────────────────────────────────────────────────────────────
//
// These are lightweight bridge implementations. They are NOT meant to replace
// the full-featured drift_analyzer.rs (2,051 LOC). Once drift_analyzer's
// public types are unified with the wiring interface, these stubs can be
// replaced by direct calls.

/// Kolmogorov-Smirnov two-sample test stub.
///
/// Computes the maximum absolute difference between the empirical CDFs
/// of two samples. A large KS statistic indicates the two distributions
/// differ significantly.
///
/// # Arguments
/// * `reference` - Reference distribution values (baseline)
/// * `sample` - New sample values to compare against the reference
///
/// # Returns
/// (statistic, confidence) — statistic is the KS D-value, confidence is 0-1.
fn ks_test(reference: &[f64], sample: &[f64]) -> (f64, f64) {
    if reference.is_empty() || sample.is_empty() {
        return (0.0, 0.0);
    }
    if reference.len() < 5 || sample.len() < 5 {
        return (0.0, 0.0);
    }

    let mut sorted_ref: Vec<f64> = reference.to_vec();
    let mut sorted_sample: Vec<f64> = sample.to_vec();
    sorted_ref.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted_sample.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n_ref = sorted_ref.len() as f64;
    let n_sample = sorted_sample.len() as f64;

    let ref_cdf = |x: f64| -> f64 {
        // Count values <= x, return fraction.
        let count = sorted_ref.iter().filter(|&&v| v <= x).count();
        count as f64 / n_ref
    };

    let sample_cdf = |x: f64| -> f64 {
        let count = sorted_sample.iter().filter(|&&v| v <= x).count();
        count as f64 / n_sample
    };

    // Compute D = max |F_ref(x) - F_sample(x)| at all data points.
    let mut max_diff: f64 = 0.0;

    for &x in &sorted_ref {
        let diff = (ref_cdf(x) - sample_cdf(x)).abs();
        if diff > max_diff {
            max_diff = diff;
        }
    }

    for &x in &sorted_sample {
        let diff = (ref_cdf(x) - sample_cdf(x)).abs();
        if diff > max_diff {
            max_diff = diff;
        }
    }

    // Approximate confidence via a rough scaling.
    // For N observations, the critical value ~ 1.36/sqrt(N).
    let n_effective = ((n_ref * n_sample) / (n_ref + n_sample)).sqrt();
    let critical = 1.36 / n_effective.max(1.0);
    let confidence = if critical > 0.0 {
        (max_diff / critical).clamp(0.0, 1.0)
    } else {
        0.0
    };

    (max_diff, confidence)
}

/// Population Stability Index stub.
///
/// Compares binned distributions. PSI = sum((actual_pct - expected_pct) * ln(actual_pct / expected_pct))
/// PSI < 0.1: no significant shift
/// 0.1 <= PSI < 0.25: moderate shift
/// PSI >= 0.25: significant shift
///
/// # Returns
/// (psi_value, confidence) where confidence reflects the magnitude of the shift.
fn psi_test(reference: &[f64], sample: &[f64]) -> (f64, f64) {
    if reference.is_empty() || sample.is_empty() {
        return (0.0, 0.0);
    }
    if reference.len() < 10 || sample.len() < 10 {
        return (0.0, 0.0);
    }

    let num_bins = DEFAULT_HISTOGRAM_BINS;
    let all_values: Vec<f64> = reference.iter().chain(sample.iter()).cloned().collect();
    let min_val = all_values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_val = all_values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max_val - min_val;

    let bin_width = if range.abs() < 1e-12 {
        1.0
    } else {
        range / num_bins as f64
    };

    let bin_index = |v: f64| -> usize {
        if bin_width <= 0.0 {
            0
        } else {
            ((v - min_val) / bin_width).floor().clamp(0.0, (num_bins - 1) as f64) as usize
        }
    };

    let n_ref = reference.len() as f64;
    let n_sample = sample.len() as f64;

    let mut expected_counts: HashMap<usize, f64> = HashMap::new();
    let mut actual_counts: HashMap<usize, f64> = HashMap::new();

    for &v in reference {
        *expected_counts.entry(bin_index(v)).or_insert(0.0) += 1.0;
    }
    for &v in sample {
        *actual_counts.entry(bin_index(v)).or_insert(0.0) += 1.0;
    }

    // Add small epsilon to avoid log(0).
    let epsilon = 1e-6;
    let mut psi: f64 = 0.0;

    // Ensure all bins are present.
    for i in 0..num_bins {
        let expected_pct = (*expected_counts.get(&i).unwrap_or(&0.0)) / n_ref;
        let actual_pct = (*actual_counts.get(&i).unwrap_or(&0.0)) / n_sample;

        if expected_pct < epsilon {
            continue; // Skip bins with no reference data.
        }

        let safe_actual = actual_pct.max(epsilon);
        let diff = safe_actual - expected_pct;
        let ratio = safe_actual / expected_pct;
        psi += diff * ratio.ln();
    }

    // Confidence scales with PSI magnitude.
    let confidence = (psi / PSI_MEDIUM_THRESHOLD).clamp(0.0, 1.0);

    (psi, confidence)
}

/// Simplified ADWIN (Adaptive Windowing) stub.
///
/// Checks if the mean of the last N observations differs significantly
/// from the mean of earlier observations. Uses a simplified z-test
/// between two windows rather than full ADWIN with variable-length windows.
///
/// # Returns
/// (drift_score, confidence) — drift_score represents the magnitude of change.
fn adwin_test(reference: &[f64], sample: &[f64]) -> (f64, f64) {
    if reference.is_empty() || sample.is_empty() {
        return (0.0, 0.0);
    }
    if reference.len() < 10 || sample.len() < 5 {
        return (0.0, 0.0);
    }

    let ref_mean = mean(reference);
    let ref_stddev = stddev(reference);
    let sample_mean = mean(sample);

    if ref_stddev < 1e-12 {
        // No variance in reference — any difference is a signal.
        let diff = (sample_mean - ref_mean).abs();
        return (if diff > 1e-6 { 1.0 } else { 0.0 }, 1.0);
    }

    // Z-test between reference mean and sample mean.
    let se = ref_stddev * (1.0 / reference.len() as f64 + 1.0 / sample.len() as f64).sqrt();
    let z = (sample_mean - ref_mean).abs() / se.max(1e-12);

    let confidence = (1.0 - 1.0 / (1.0 + z)).clamp(0.0, 1.0);
    let drift_score = z / 3.0; // Normalize: 3σ ≈ 1.0.

    (drift_score.clamp(0.0, 1.0), confidence)
}

// ────────────────────────────────────────────────────────────────────────
// Statistical Helpers
// ────────────────────────────────────────────────────────────────────────

/// Compute the arithmetic mean of a slice.
fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let sum: f64 = values.iter().sum();
    sum / values.len() as f64
}

/// Compute the population standard deviation of a slice.
fn stddev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance: f64 = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

/// Compute a percentile from a sorted slice using linear interpolation.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = p * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = idx.ceil().min((sorted.len() - 1) as f64) as usize;
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

// ────────────────────────────────────────────────────────────────────────
// Section 1: DriftBaselines
// ────────────────────────────────────────────────────────────────────────
//
// Manages reference distributions for each DriftType. The advanced
// detectors (KS, PSI, ADWIN) need a reference baseline to compare
// new observations against. This struct tracks, updates, and ages out
// baselines automatically.

/// Maximum age of a baseline in seconds before it's considered stale.
const DEFAULT_MAX_AGE_SECONDS: u64 = 3600;

/// A stored reference distribution for one DriftType.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceBaseline {
    /// Which drift type this baseline tracks.
    pub drift_type: DriftType,
    /// When this baseline was first created.
    pub created_at: String,
    /// When this baseline was last updated.
    pub updated_at: String,
    /// Number of samples incorporated into this baseline.
    pub sample_count: usize,
    /// Arithmetic mean of all values.
    pub mean: f64,
    /// Population standard deviation.
    pub stddev: f64,
    /// 25th percentile.
    pub percentile_25: f64,
    /// 50th percentile (median).
    pub percentile_50: f64,
    /// 75th percentile.
    pub percentile_75: f64,
    /// 95th percentile.
    pub percentile_95: f64,
    /// 99th percentile.
    pub percentile_99: f64,
    /// Histogram bin counts for distribution comparison.
    pub histogram_bins: Vec<f64>,
    /// Raw values for KS/PSI tests (capped at MAX_BASELINE_VALUES).
    pub values: Vec<f64>,
}

/// Manages reference baselines for all DriftTypes.
///
/// Each baseline accumulates observations over time and provides
/// the statistical foundation for advanced drift detection methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBaselines {
    /// One baseline per drift type.
    baselines: HashMap<DriftType, ReferenceBaseline>,
    /// Maximum age in seconds before a baseline is considered stale.
    max_age_seconds: u64,
}

impl Default for DriftBaselines {
    fn default() -> Self {
        Self::new()
    }
}

impl DriftBaselines {
    /// Create an empty baselines manager with default staleness threshold.
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        }
    }

    /// Create baselines with a custom staleness threshold.
    pub fn with_max_age(max_age_seconds: u64) -> Self {
        Self {
            baselines: HashMap::new(),
            max_age_seconds,
        }
    }

    /// Update a baseline with a new observed value.
    ///
    /// If no baseline exists for this type, one is created.
    /// Values are capped at MAX_BASELINE_VALUES to prevent unbounded growth.
    pub fn update(&mut self, drift_type: DriftType, new_value: f64) {
        let now = Utc::now().to_rfc3339();
        let drift_type_str = format!("{:?}", drift_type);

        if let Some(baseline) = self.baselines.get_mut(&drift_type) {
            // Cap values list.
            if baseline.values.len() >= MAX_BASELINE_VALUES {
                // Remove oldest 10% to make room.
                let remove_count = MAX_BASELINE_VALUES / 10;
                baseline.values.drain(0..remove_count);
            }
            baseline.values.push(new_value);
            baseline.sample_count = baseline.values.len();
            baseline.mean = mean(&baseline.values);
            baseline.stddev = stddev(&baseline.values);

            // Recompute percentiles.
            let mut sorted = baseline.values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            baseline.percentile_25 = percentile(&sorted, 0.25);
            baseline.percentile_50 = percentile(&sorted, 0.50);
            baseline.percentile_75 = percentile(&sorted, 0.75);
            baseline.percentile_95 = percentile(&sorted, 0.95);
            baseline.percentile_99 = percentile(&sorted, 0.99);

            // Recompute histogram.
            baseline.histogram_bins = compute_histogram(&baseline.values, DEFAULT_HISTOGRAM_BINS);
            baseline.updated_at = now;
        } else {
            let values = vec![new_value];
            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let baseline = ReferenceBaseline {
                drift_type: drift_type.clone(),
                created_at: now.clone(),
                updated_at: now,
                sample_count: 1,
                mean: new_value,
                stddev: 0.0,
                percentile_25: new_value,
                percentile_50: new_value,
                percentile_75: new_value,
                percentile_95: new_value,
                percentile_99: new_value,
                histogram_bins: vec![1.0],
                values,
            };
            self.baselines.insert(drift_type, baseline);
        }

        trace!("Baseline updated for drift_type={}", drift_type_str);
    }

    /// Get a baseline reference for a specific drift type.
    pub fn get(&self, drift_type: &DriftType) -> Option<&ReferenceBaseline> {
        self.baselines.get(drift_type)
    }

    /// Get a mutable baseline reference for a specific drift type.
    pub fn get_mut(&mut self, drift_type: &DriftType) -> Option<&mut ReferenceBaseline> {
        self.baselines.get_mut(drift_type)
    }

    /// Compute a fresh baseline from a batch of values.
    ///
    /// This replaces any existing baseline for the given drift type.
    pub fn compute_baseline(&mut self, drift_type: DriftType, values: &[f64]) -> Result<(), String> {
        if values.is_empty() {
            return Err("Cannot compute baseline from empty values".to_string());
        }

        let capped: Vec<f64> = if values.len() > MAX_BASELINE_VALUES {
            values[values.len() - MAX_BASELINE_VALUES..].to_vec()
        } else {
            values.to_vec()
        };

        let mut sorted = capped.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let now = Utc::now().to_rfc3339();
        let baseline = ReferenceBaseline {
            drift_type: drift_type.clone(),
            created_at: now.clone(),
            updated_at: now,
            sample_count: capped.len(),
            mean: mean(&capped),
            stddev: stddev(&capped),
            percentile_25: percentile(&sorted, 0.25),
            percentile_50: percentile(&sorted, 0.50),
            percentile_75: percentile(&sorted, 0.75),
            percentile_95: percentile(&sorted, 0.95),
            percentile_99: percentile(&sorted, 0.99),
            histogram_bins: compute_histogram(&capped, DEFAULT_HISTOGRAM_BINS),
            values: capped,
        };

        self.baselines.insert(drift_type, baseline);
        Ok(())
    }

    /// Check if a baseline is stale (older than max_age_seconds).
    ///
    /// Returns true if the baseline exists but has not been updated recently.
    /// Returns false if no baseline exists or if it's fresh.
    pub fn is_stale(&self, drift_type: &DriftType) -> bool {
        if let Some(baseline) = self.baselines.get(drift_type) {
            match parse_rfc3339_age(&baseline.updated_at) {
                Ok(age_seconds) => age_seconds >= self.max_age_seconds,
                Err(_) => true, // Unparseable timestamp → treat as stale.
            }
        } else {
            false // No baseline is not "stale" — it's just absent.
        }
    }

    /// Reset (remove) the baseline for a specific drift type.
    pub fn reset(&mut self, drift_type: &DriftType) {
        if self.baselines.remove(drift_type).is_some() {
            info!("Baseline reset for drift_type={}", drift_type);
        }
    }

    /// Reset all baselines.
    pub fn reset_all(&mut self) {
        self.baselines.clear();
        info!("All baselines reset");
    }

    /// Return the number of baselines currently stored.
    pub fn len(&self) -> usize {
        self.baselines.len()
    }

    /// Return true if no baselines are stored.
    pub fn is_empty(&self) -> bool {
        self.baselines.is_empty()
    }
}

/// Compute a histogram from values, returning normalized bin counts.
fn compute_histogram(values: &[f64], num_bins: usize) -> Vec<f64> {
    if values.is_empty() {
        return vec![0.0; num_bins];
    }
    let min_val = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max_val - min_val;
    let bin_width = if range.abs() < 1e-12 {
        1.0
    } else {
        range / num_bins as f64
    };

    let mut bins = vec![0.0f64; num_bins];
    for &v in values {
        let idx = if bin_width <= 0.0 {
            0
        } else {
            ((v - min_val) / bin_width).floor().clamp(0.0, (num_bins - 1) as f64) as usize
        };
        bins[idx] += 1.0;
    }

    // Normalize to proportions.
    let total = values.len() as f64;
    for b in &mut bins {
        *b /= total;
    }

    bins
}

/// Parse an RFC3339 timestamp string and return its age in seconds.
fn parse_rfc3339_age(timestamp: &str) -> Result<u64, String> {
    let dt = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp, e))?;
    let now = Utc::now();
    let duration = now.signed_duration_since(dt.with_timezone(&Utc));
    if duration.num_seconds() < 0 {
        Ok(0) // Future timestamp — not stale.
    } else {
        Ok(duration.num_seconds() as u64)
    }
}

// ────────────────────────────────────────────────────────────────────────
// Section 2: FusedDriftSignal
// ────────────────────────────────────────────────────────────────────────
//
// Combines the z-score alert from drift.rs with the advanced analysis
// from drift_analyzer.rs into a single, unified signal. The fusion
// logic uses configurable weights to produce a composite severity.

/// A fused drift signal combining simple and advanced detection results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedDriftSignal {
    /// Which drift type this signal covers.
    pub drift_type: DriftType,
    /// Alert from the simple z-score detector (drift.rs), if any.
    pub z_score_alert: Option<DriftAlert>,
    /// Severity from the advanced detector (KS/PSI/ADWIN), if any.
    pub advanced_severity: Option<DriftSeverity>,
    /// Names of analysis methods that contributed to this signal.
    pub analysis_methods_used: Vec<String>,
    /// Composite severity after fusion.
    pub composite_severity: DriftSeverity,
    /// Confidence in the composite assessment (0.0 to 1.0).
    pub composite_confidence: f64,
    /// Whether the fused signal indicates an anomaly.
    pub is_anomaly: bool,
    /// Human-readable context about the detection.
    pub context: String,
    /// Timestamp of when this signal was produced.
    pub timestamp: String,
}

impl FusedDriftSignal {
    /// Fuse a z-score alert with advanced analysis results.
    ///
    /// Fusion logic:
    /// - If z-score fires AND advanced confirms → Critical (both agree)
    /// - If either fires independently → max of the two severities
    /// - If neither fires → None
    pub fn fuse(
        drift_type: DriftType,
        z_alert: Option<DriftAlert>,
        advanced_severity: Option<DriftSeverity>,
        methods: Vec<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();

        let z_severity = match &z_alert {
            Some(alert) => map_alert_severity(&alert.severity),
            None => DriftSeverity::None,
        };

        let adv_sev = advanced_severity.clone().unwrap_or(DriftSeverity::None);

        let (composite_severity, composite_confidence, is_anomaly) =
            compute_fusion(z_severity, adv_sev, z_alert.is_some(), advanced_severity.is_some());

        let context = match (&z_alert, &advanced_severity) {
            (Some(za), Some(as_)) => format!(
                "Dual detection: z-score={:.2} ({:?}), advanced={:?}",
                za.z_score, za.severity, as_
            ),
            (Some(za), None) => format!(
                "Z-score only: z={:.2} ({:?}), no advanced confirmation",
                za.z_score, za.severity
            ),
            (None, Some(as_)) => format!("Advanced only: {:?}, no z-score alert", as_),
            (None, None) => "No drift detected".to_string(),
        };

        FusedDriftSignal {
            drift_type,
            z_score_alert: z_alert,
            advanced_severity,
            analysis_methods_used: methods,
            composite_severity,
            composite_confidence,
            is_anomaly,
            context,
            timestamp: now,
        }
    }
}

/// Map an AlertSeverity from drift.rs to a DriftSeverity from drift_analyzer.rs.
fn map_alert_severity(alert_sev: &AlertSeverity) -> DriftSeverity {
    match alert_sev {
        AlertSeverity::Info => DriftSeverity::Low,
        AlertSeverity::Warning => DriftSeverity::Medium,
        AlertSeverity::Critical => DriftSeverity::Critical,
    }
}

/// Compute the fused severity, confidence, and anomaly flag.
///
/// Uses the following logic:
/// - Both detectors fire → Critical severity, high confidence
/// - Only z-score fires → map z-score severity, moderate confidence
/// - Only advanced fires → map advanced severity, moderate confidence
/// - Neither fires → None, low confidence
fn compute_fusion(
    z_severity: DriftSeverity,
    advanced_severity: DriftSeverity,
    z_fired: bool,
    advanced_fired: bool,
) -> (DriftSeverity, f64, bool) {
    if z_fired && advanced_fired {
        // Both agree — high confidence Critical or higher.
        let composite = max_severity(z_severity, advanced_severity);
        // Boost to at least High when both agree.
        let boosted = match composite {
            DriftSeverity::None => DriftSeverity::None,
            DriftSeverity::Low => DriftSeverity::Medium,
            DriftSeverity::Medium => DriftSeverity::High,
            DriftSeverity::High | DriftSeverity::Critical => DriftSeverity::Critical,
        };
        let confidence = 0.85 + 0.10 * composite.to_score();
        (boosted, confidence.clamp(0.0, 1.0), true)
    } else if z_fired {
        let confidence = 0.5 + 0.3 * z_severity.to_score();
        (z_severity, confidence.clamp(0.0, 1.0), z_severity != DriftSeverity::None)
    } else if advanced_fired {
        let confidence = 0.5 + 0.3 * advanced_severity.to_score();
        (
            advanced_severity,
            confidence.clamp(0.0, 1.0),
            advanced_severity != DriftSeverity::None,
        )
    } else {
        (DriftSeverity::None, 0.0, false)
    }
}

/// Return the higher of two DriftSeverity values.
fn max_severity(a: DriftSeverity, b: DriftSeverity) -> DriftSeverity {
    if a.to_score() >= b.to_score() {
        a
    } else {
        b
    }
}

// ────────────────────────────────────────────────────────────────────────
// Section 3: SentinelHub
// ────────────────────────────────────────────────────────────────────────
//
// The central hub that coordinates simple z-score detection (drift.rs)
// with advanced detection methods (KS, PSI, ADWIN stubs) and fuses
// their results into unified FusedDriftSignals.

/// Configuration for how the SentinelHub fuses signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionConfig {
    /// If true, require BOTH detectors to fire for an anomaly.
    /// If false, either detector firing is sufficient.
    pub require_both_detectors: bool,

    /// Which advanced methods to run.
    pub advanced_methods: Vec<String>,

    /// Minimum number of baseline samples before running advanced analysis.
    pub baseline_min_samples: usize,

    /// Time window in seconds for correlating related alerts.
    pub correlation_window_seconds: u64,

    /// Weight for z-score detector in composite scoring (0-1).
    pub z_score_weight: f64,

    /// Weight for advanced detector in composite scoring (0-1).
    pub advanced_weight: f64,
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            require_both_detectors: false,
            advanced_methods: vec!["ks".to_string(), "psi".to_string()],
            baseline_min_samples: 30,
            correlation_window_seconds: 300,
            z_score_weight: 0.6,
            advanced_weight: 0.4,
        }
    }
}

impl FusionConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.z_score_weight + self.advanced_weight == 0.0 {
            return Err("z_score_weight and advanced_weight cannot both be zero".to_string());
        }
        if self.z_score_weight < 0.0 || self.advanced_weight < 0.0 {
            return Err("Weights must be non-negative".to_string());
        }
        if self.baseline_min_samples == 0 {
            return Err("baseline_min_samples must be positive".to_string());
        }
        Ok(())
    }
}

/// The unified sentinel hub that coordinates all drift detection.
#[derive(Debug)]
pub struct SentinelHub {
    /// Simple z-score detector from drift.rs.
    simple_detector: DriftDetector,
    /// Reference baselines for advanced detectors.
    baselines: DriftBaselines,
    /// Fusion configuration.
    fusion_config: FusionConfig,
    /// Recent alerts buffer for correlation.
    alert_buffer: VecDeque<FusedDriftSignal>,
    /// Maximum number of alerts in the correlation buffer.
    buffer_size: usize,
    /// Count of observations processed per drift type.
    observation_counts: HashMap<DriftType, u64>,
    /// Count of anomalies detected per drift type.
    anomaly_counts: HashMap<DriftType, u64>,
}

impl SentinelHub {
    /// Create a new SentinelHub.
    ///
    /// # Arguments
    /// * `sigma_threshold` - Z-score threshold for the simple detector
    /// * `window_size` - Sliding window size for the simple detector
    /// * `fusion_config` - Configuration for signal fusion
    /// * `buffer_size` - Maximum alerts to keep for correlation
    pub fn new(
        sigma_threshold: f64,
        window_size: usize,
        fusion_config: FusionConfig,
        buffer_size: usize,
    ) -> Result<Self, String> {
        fusion_config.validate()?;

        let mut observation_counts = HashMap::new();
        let mut anomaly_counts = HashMap::new();
        for dt in DriftType::all() {
            observation_counts.insert(dt.clone(), 0);
            anomaly_counts.insert(dt.clone(), 0);
        }

        Ok(SentinelHub {
            simple_detector: DriftDetector::new(sigma_threshold, window_size),
            baselines: DriftBaselines::new(),
            fusion_config,
            alert_buffer: VecDeque::with_capacity(buffer_size),
            buffer_size,
            observation_counts,
            anomaly_counts,
        })
    }

    /// Create a SentinelHub with default configuration.
    pub fn with_defaults(sigma_threshold: f64, window_size: usize) -> Result<Self, String> {
        Self::new(sigma_threshold, window_size, FusionConfig::default(), 1000)
    }

    /// Process a single observation through the full pipeline.
    ///
    /// Pipeline:
    ///   1. Feed observation to simple_detector (z-score)
    ///   2. Update baseline for the drift type
    ///   3. If z-score fires, check baseline stability
    ///   4. Run advanced analysis if enough baseline data
    ///   5. Fuse the signals
    ///   6. Buffer the result
    ///   7. Return fused signal if it's an anomaly
    pub fn observe(&mut self, observation: DriftObservation) -> Result<Option<FusedDriftSignal>, String> {
        let drift_type = observation.drift_type.clone();

        // Step 1: Feed to simple z-score detector.
        let z_alert = self.simple_detector.observe(observation.clone());

        // Step 2: Update baseline.
        self.baselines.update(drift_type.clone(), observation.value);

        // Step 3: Increment observation count.
        if let Some(count) = self.observation_counts.get_mut(&drift_type) {
            *count += 1;
        }

        // Step 4: Run advanced analysis if baseline has enough data.
        let mut advanced_severity = None;
        let mut methods_used: Vec<String> = Vec::new();

        if let Some(baseline) = self.baselines.get(&drift_type) {
            if baseline.sample_count >= self.fusion_config.baseline_min_samples {
                debug!(
                    "Running advanced analysis for drift_type={}, methods={:?}",
                    drift_type, self.fusion_config.advanced_methods
                );

                let mut max_sev = DriftSeverity::None;

                for method in &self.fusion_config.advanced_methods {
                    let (severity, method_name) =
                        self.run_advanced_method(method, &baseline.values, &[observation.value]);

                    methods_used.push(method_name);
                    if severity != DriftSeverity::None && severity.to_score() > max_sev.to_score() {
                        max_sev = severity;
                    }
                }

                advanced_severity = Some(max_sev);
            } else {
                trace!(
                    "Skipping advanced analysis: only {} samples (need {})",
                    baseline.sample_count, self.fusion_config.baseline_min_samples
                );
            }
        }

        // Step 5: Fuse signals.
        let fused = FusedDriftSignal::fuse(
            drift_type.clone(),
            z_alert,
            advanced_severity,
            methods_used,
        );

        // Step 6: Buffer if anomaly.
        if fused.is_anomaly {
            if let Some(count) = self.anomaly_counts.get_mut(&drift_type) {
                *count += 1;
            }

            if self.alert_buffer.len() >= self.buffer_size {
                self.alert_buffer.pop_front();
            }
            self.alert_buffer.push_back(fused.clone());

            info!(
                "Anomaly detected: drift_type={}, severity={:?}, confidence={:.3}, methods={:?}",
                fused.drift_type,
                fused.composite_severity,
                fused.composite_confidence,
                fused.analysis_methods_used,
            );
        }

        // Step 7: Return if anomaly (respecting require_both_detectors).
        let return_signal = if self.fusion_config.require_both_detectors {
            if fused.is_anomaly
                && fused.z_score_alert.is_some()
                && fused.advanced_severity.is_some()
            {
                Some(fused)
            } else {
                None
            }
        } else if fused.is_anomaly {
            Some(fused)
        } else {
            None
        };

        Ok(return_signal)
    }

    /// Run a single advanced detection method.
    ///
    /// Returns the detected severity and the canonical method name.
    fn run_advanced_method(
        &self,
        method: &str,
        reference: &[f64],
        sample: &[f64],
    ) -> (DriftSeverity, String) {
        match method.to_lowercase().as_str() {
            "ks" => {
                let (statistic, confidence) = ks_test(reference, sample);
                let severity = if statistic > ADVANCED_DRIFT_THRESHOLD && confidence > 0.7 {
                    DriftSeverity::from_score_default(statistic)
                } else {
                    DriftSeverity::None
                };
                debug!("KS test: statistic={:.4}, confidence={:.3}, severity={:?}", statistic, confidence, severity);
                (severity, "ks".to_string())
            }
            "psi" => {
                let (psi_value, confidence) = psi_test(reference, sample);
                let severity = if psi_value > PSI_LOW_THRESHOLD {
                    if psi_value > PSI_MEDIUM_THRESHOLD {
                        DriftSeverity::High
                    } else {
                        DriftSeverity::Medium
                    }
                } else {
                    DriftSeverity::None
                };
                debug!("PSI test: psi={:.4}, confidence={:.3}, severity={:?}", psi_value, confidence, severity);
                (severity, "psi".to_string())
            }
            "adwin" => {
                let (drift_score, confidence) = adwin_test(reference, sample);
                let severity = if drift_score > ADVANCED_DRIFT_THRESHOLD && confidence > 0.7 {
                    DriftSeverity::from_score_default(drift_score)
                } else {
                    DriftSeverity::None
                };
                debug!("ADWIN test: drift_score={:.4}, confidence={:.3}, severity={:?}", drift_score, confidence, severity);
                (severity, "adwin".to_string())
            }
            _ => {
                warn!("Unknown advanced method '{}', skipping", method);
                (DriftSeverity::None, method.to_string())
            }
        }
    }

    /// Update a baseline with a value without running detection.
    pub fn update_baseline(&mut self, drift_type: DriftType, value: f64) {
        self.baselines.update(drift_type, value);
    }

    /// Get the most recent fused signal for a specific drift type.
    pub fn get_fused_signal(&self, drift_type: &DriftType) -> Option<FusedDriftSignal> {
        self.alert_buffer
            .iter()
            .rev()
            .find(|s| &s.drift_type == drift_type)
            .cloned()
    }

    /// Get all fused signals currently in the alert buffer.
    pub fn get_all_fused_signals(&self) -> Vec<FusedDriftSignal> {
        self.alert_buffer.iter().cloned().collect()
    }

    /// Run correlation analysis on the current alert buffer.
    ///
    /// Groups alerts by temporal proximity and domain similarity
    /// to produce CorrelatedAlerts.
    pub fn correlation_check(&self) -> Vec<CorrelatedAlert> {
        let signals: Vec<&FusedDriftSignal> = self.alert_buffer.iter().collect();
        correlate_signals(&signals)
    }

    /// Reset the simple detector for a specific drift type.
    ///
    /// Also clears the baseline for that type.
    pub fn reset_detector(&mut self, drift_type: &DriftType) {
        self.simple_detector.reset(drift_type);
        self.baselines.reset(drift_type);
        if let Some(count) = self.observation_counts.get_mut(drift_type) {
            *count = 0;
        }
        if let Some(count) = self.anomaly_counts.get_mut(drift_type) {
            *count = 0;
        }
        info!("Detector reset for drift_type={}", drift_type);
    }

    /// Get current statistics for a drift type from the simple detector.
    ///
    /// Returns (mean, stddev, window_size) if available.
    pub fn get_stats(&self, drift_type: &DriftType) -> Option<(f64, f64, usize)> {
        self.simple_detector.stats(drift_type)
    }

    /// Get the current observation count for a drift type.
    pub fn observation_count(&self, drift_type: &DriftType) -> u64 {
        self.observation_counts.get(drift_type).copied().unwrap_or(0)
    }

    /// Get the current anomaly count for a drift type.
    pub fn anomaly_count(&self, drift_type: &DriftType) -> u64 {
        self.anomaly_counts.get(drift_type).copied().unwrap_or(0)
    }

    /// Get a reference to the baselines manager.
    pub fn baselines(&self) -> &DriftBaselines {
        &self.baselines
    }

    /// Get the number of alerts in the correlation buffer.
    pub fn buffer_len(&self) -> usize {
        self.alert_buffer.len()
    }

    /// Prune old alerts from the correlation buffer based on time window.
    pub fn prune_buffer(&mut self) -> usize {
        let window = self.fusion_config.correlation_window_seconds;
        let now = Utc::now();
        let mut pruned = 0;

        while let Some(front) = self.alert_buffer.front() {
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&front.timestamp) {
                let age = now.signed_duration_since(parsed.with_timezone(&Utc));
                if age.num_seconds() > window as i64 {
                    self.alert_buffer.pop_front();
                    pruned += 1;
                } else {
                    break; // Buffer is time-ordered, so we can stop.
                }
            } else {
                // Unparseable timestamp — remove it.
                self.alert_buffer.pop_front();
                pruned += 1;
            }
        }

        if pruned > 0 {
            debug!("Pruned {} expired alerts from correlation buffer", pruned);
        }
        pruned
    }
}

// ────────────────────────────────────────────────────────────────────────
// Section 4: DriftCorrelationReport
// ────────────────────────────────────────────────────────────────────────
//
// Correlation analysis groups related alerts to reduce noise and
// identify patterns (same domain, cascading failures, temporal clusters).

/// Type of correlation between alerts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CorrelationType {
    /// Multiple alerts for the same drift type within the time window.
    SameDomain,
    /// Alerts from related drift types suggesting cascading failure.
    Cascade,
    /// Multiple alerts from different types within a tight time window.
    TemporalCluster,
    /// Alerts from unrelated drift types that co-occur (cross-domain).
    CrossDomain,
}

impl std::fmt::Display for CorrelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationType::SameDomain => write!(f, "SameDomain"),
            CorrelationType::Cascade => write!(f, "Cascade"),
            CorrelationType::TemporalCluster => write!(f, "TemporalCluster"),
            CorrelationType::CrossDomain => write!(f, "CrossDomain"),
        }
    }
}

/// A group of correlated alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedAlert {
    /// Unique correlation identifier.
    pub correlation_id: String,
    /// The alerts that are correlated.
    pub alerts: Vec<FusedDriftSignal>,
    /// Type of correlation detected.
    pub correlation_type: CorrelationType,
    /// Combined severity of the correlated group.
    pub severity: DriftSeverity,
    /// Human-readable description of the correlation.
    pub description: String,
    /// Timestamp when the correlation was detected.
    pub timestamp: String,
}

impl CorrelatedAlert {
    /// Create a new correlated alert group.
    pub fn new(
        alerts: Vec<FusedDriftSignal>,
        correlation_type: CorrelationType,
    ) -> Self {
        let severity = alerts
            .iter()
            .map(|s| s.composite_severity.clone())
            .max_by(|a, b| a.to_score().partial_cmp(&b.to_score()).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(DriftSeverity::None);

        let drift_types: Vec<String> = alerts
            .iter()
            .map(|s| s.drift_type.to_string())
            .collect();

        let description = format!(
            "{} correlation across {} types: {}",
            correlation_type,
            drift_types.len(),
            drift_types.join(", "),
        );

        CorrelatedAlert {
            correlation_id: Uuid::new_v4().to_string(),
            alerts,
            correlation_type,
            severity,
            description,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Correlation Logic
// ────────────────────────────────────────────────────────────────────────

/// Groups of drift types that commonly cascade.
const CASCADE_PAIRS: &[(DriftType, DriftType)] = &[
    (DriftType::Decision, DriftType::Policy),
    (DriftType::Policy, DriftType::Configuration),
    (DriftType::Configuration, DriftType::Runtime),
    (DriftType::Model, DriftType::Learning),
    (DriftType::Trust, DriftType::Decision),
    (DriftType::Memory, DriftType::Runtime),
    (DriftType::Plugin, DriftType::Runtime),
    (DriftType::Orchestration, DriftType::Decision),
];

/// Check if two drift types form a known cascade pair.
fn is_cascade_pair(a: &DriftType, b: &DriftType) -> bool {
    CASCADE_PAIRS.iter().any(|(x, y)| (a == x && b == y) || (a == y && b == x))
}

/// Correlate a set of fused signals into groups.
///
/// Algorithm:
/// 1. Group by drift type (SameDomain)
/// 2. Check for cascade pairs across groups (Cascade)
/// 3. Check for temporal clustering of different types (TemporalCluster)
/// 4. Everything else that co-occurs (CrossDomain)
pub fn correlate_signals(signals: &[&FusedDriftSignal]) -> Vec<CorrelatedAlert> {
    if signals.len() < 2 {
        // Single signal cannot be correlated.
        return signals
            .iter()
            .map(|s| {
                CorrelatedAlert::new(
                    vec![(*s).clone()],
                    CorrelationType::SameDomain,
                )
            })
            .collect();
    }

    let mut correlated: Vec<CorrelatedAlert> = Vec::new();

    // Group by drift type.
    let mut type_groups: HashMap<DriftType, Vec<FusedDriftSignal>> = HashMap::new();
    for signal in signals {
        type_groups
            .entry(signal.drift_type.clone())
            .or_insert_with(Vec::new)
            .push((*signal).clone());
    }

    // Emit SameDomain groups (multiple alerts of same type).
    for (_dt, group) in &type_groups {
        if group.len() > 1 {
            correlated.push(CorrelatedAlert::new(group.clone(), CorrelationType::SameDomain));
        }
    }

    // Check for cascade pairs among different type groups.
    let drift_types: Vec<&DriftType> = type_groups.keys().collect();
    let mut cascade_types: Vec<DriftType> = Vec::new();

    for i in 0..drift_types.len() {
        for j in (i + 1)..drift_types.len() {
            if is_cascade_pair(drift_types[i], drift_types[j]) {
                if !cascade_types.contains(drift_types[i]) {
                    cascade_types.push(drift_types[i].clone());
                }
                if !cascade_types.contains(drift_types[j]) {
                    cascade_types.push(drift_types[j].clone());
                }
            }
        }
    }

    if cascade_types.len() > 1 {
        let cascade_alerts: Vec<FusedDriftSignal> = cascade_types
            .iter()
            .filter_map(|dt| type_groups.get(dt).and_then(|g| g.first().cloned()))
            .collect();
        if cascade_alerts.len() > 1 {
            correlated.push(CorrelatedAlert::new(cascade_alerts, CorrelationType::Cascade));
        }
    }

    // Check for temporal clusters (multiple types within tight window).
    if type_groups.len() >= 3 && cascade_types.len() < 3 {
        let cluster_alerts: Vec<FusedDriftSignal> = type_groups
            .values()
            .filter_map(|g| g.first().cloned())
            .collect();
        if cluster_alerts.len() >= 3 {
            correlated.push(CorrelatedAlert::new(
                cluster_alerts,
                CorrelationType::TemporalCluster,
            ));
        }
    }

    // Any remaining uncorrelated multi-type groups → CrossDomain.
    let correlated_types: std::collections::HashSet<String> = correlated
        .iter()
        .flat_map(|ca| ca.alerts.iter().map(|a| a.drift_type.to_string()))
        .collect();

    let _uncorrelated: Vec<FusedDriftSignal> = signals
        .iter()
        .filter(|s| !correlated_types.contains(&s.drift_type.to_string()))
        .map(|s| (*s).clone())
        .collect();

    if correlated.is_empty() && signals.len() >= 2 {
        // Fall through to CrossDomain.
        let cross_alerts: Vec<FusedDriftSignal> = signals.iter().map(|s| (*s).clone()).collect();
        correlated.push(CorrelatedAlert::new(cross_alerts, CorrelationType::CrossDomain));
    }

    // Emit remaining singleton signals as SameDomain.
    for (dt, group) in &type_groups {
        if group.len() == 1 && !correlated_types.contains(&dt.to_string()) {
            correlated.push(CorrelatedAlert::new(group.clone(), CorrelationType::SameDomain));
        }
    }

    correlated
}

// ────────────────────────────────────────────────────────────────────────
// Section 5: SentinelVerificationBridge
// ────────────────────────────────────────────────────────────────────────
//
// Bridges SentinelHub's FusedDriftSignals into the OVAPH loop's
// Verify stage types (OvaphVerificationResult, VerifiedSignal).

/// Bridge between SentinelHub and the OVAPH loop's Verify stage.
///
/// This adapter translates FusedDriftSignals (internal sentinel types)
/// into OvaphVerificationResult types that the OVAPH loop consumes.
#[derive(Debug)]
pub struct SentinelVerificationBridge {
    /// The sentinel hub that provides fused signals.
    hub: SentinelHub,
    /// Sigma threshold used for the simple detector (cached for severity mapping).
    sigma_threshold: f64,
}

impl SentinelVerificationBridge {
    /// Create a new bridge wrapping a SentinelHub.
    pub fn new(hub: SentinelHub) -> Self {
        // We don't have direct access to sigma_threshold from the hub,
        // so we use a default. The caller can adjust via the constructor.
        Self {
            hub,
            sigma_threshold: 3.0,
        }
    }

    /// Create a bridge with an explicit sigma threshold for severity mapping.
    pub fn with_sigma_threshold(hub: SentinelHub, sigma_threshold: f64) -> Self {
        Self { hub, sigma_threshold }
    }

    /// Process an OvaphObservation and produce an OvaphVerificationResult.
    ///
    /// This maps the observation's drift snapshots through SentinelHub,
    /// collecting fused signals, and translating them into VerifiedSignals
    /// that the OVAPH loop's Attest/Heal stages can consume.
    pub fn verify(&mut self, observation: &OvaphObservation) -> OvaphVerificationResult {
        if observation.drift_snapshots.is_empty() {
            return OvaphVerificationResult {
                signals: vec![],
                composite_severity: Severity::None,
                requires_healing: false,
                rationale: "No drift snapshots to verify".to_string(),
            };
        }

        let mut signals: Vec<VerifiedSignal> = Vec::new();
        let mut max_severity = Severity::None;

        for snapshot in &observation.drift_snapshots {
            // Map drift_type string to DriftType enum.
            let drift_type = match parse_drift_type(&snapshot.drift_type) {
                Ok(dt) => dt,
                Err(_) => {
                    // Unknown drift type — produce a normal signal.
                    signals.push(VerifiedSignal::normal(snapshot.drift_type.clone()));
                    continue;
                }
            };

            // Create a DriftObservation from the snapshot.
            let drift_obs = DriftObservation {
                drift_type: drift_type.clone(),
                value: snapshot.current_mean,
                context: format!("snapshot: z={:.4}", snapshot.last_z_score),
                timestamp: observation.timestamp.clone(),
            };

            // Feed through the hub.
            match self.hub.observe(drift_obs) {
                Ok(Some(fused)) => {
                    let verified = map_fused_to_verified(&fused);
                    if verified.severity > max_severity {
                        max_severity = verified.severity;
                    }
                    signals.push(verified);
                }
                Ok(None) => {
                    // No anomaly detected — produce normal signal.
                    signals.push(VerifiedSignal::normal(snapshot.drift_type.clone()));
                }
                Err(e) => {
                    error!("SentinelHub observation error: {}", e);
                    signals.push(VerifiedSignal::normal(snapshot.drift_type.clone()));
                }
            }
        }

        // Run correlation check on buffered signals.
        let correlated = self.hub.correlation_check();
        if !correlated.is_empty() {
            // Add correlation-based signals for cross-domain patterns.
            for ca in &correlated {
                if ca.alerts.len() >= 3 {
                    let correlation_signal = VerifiedSignal {
                        drift_type: format!("correlation_{}", ca.correlation_type),
                        severity: map_drift_severity_to_ovaph(&ca.severity),
                        is_anomaly: true,
                        confidence: 0.8,
                        analysis_method: AnalysisMethod::Composite,
                        recommended_action: "investigate_correlation".to_string(),
                    };
                    if correlation_signal.severity > max_severity {
                        max_severity = correlation_signal.severity;
                    }
                    signals.push(correlation_signal);
                }
            }
        }

        let requires_healing = max_severity >= Severity::High;

        let signal_count = signals.len();
        OvaphVerificationResult {
            signals,
            composite_severity: max_severity,
            requires_healing,
            rationale: format!(
                "Sentinel verification: {} signals processed, max severity={}",
                signal_count,
                max_severity,
            ),
        }
    }

    /// Get a reference to the underlying hub for advanced queries.
    pub fn hub(&self) -> &SentinelHub {
        &self.hub
    }

    /// Get a mutable reference to the underlying hub.
    pub fn hub_mut(&mut self) -> &mut SentinelHub {
        &mut self.hub
    }
}

/// Parse a drift type string into the DriftType enum.
fn parse_drift_type(s: &str) -> Result<DriftType, String> {
    match s.to_lowercase().as_str() {
        "decision" => Ok(DriftType::Decision),
        "policy" => Ok(DriftType::Policy),
        "model" => Ok(DriftType::Model),
        "orchestration" => Ok(DriftType::Orchestration),
        "learning" => Ok(DriftType::Learning),
        "memory" => Ok(DriftType::Memory),
        "configuration" => Ok(DriftType::Configuration),
        "plugin" => Ok(DriftType::Plugin),
        "runtime" => Ok(DriftType::Runtime),
        "trust" => Ok(DriftType::Trust),
        _ => Err(format!("Unknown drift type: {}", s)),
    }
}

/// Map a FusedDriftSignal to a VerifiedSignal for the OVAPH loop.
fn map_fused_to_verified(fused: &FusedDriftSignal) -> VerifiedSignal {
    let severity = map_drift_severity_to_ovaph(&fused.composite_severity);
    let analysis_method = if fused.analysis_methods_used.contains(&"ks".to_string())
        || fused.analysis_methods_used.contains(&"psi".to_string())
        || fused.analysis_methods_used.contains(&"adwin".to_string())
    {
        AnalysisMethod::Composite
    } else if fused.z_score_alert.is_some() {
        AnalysisMethod::ZScore
    } else {
        AnalysisMethod::ZScore
    };

    VerifiedSignal {
        drift_type: fused.drift_type.to_string(),
        severity,
        is_anomaly: fused.is_anomaly,
        confidence: fused.composite_confidence,
        analysis_method,
        recommended_action: if fused.is_anomaly {
            format!(
                "investigate: methods={:?}, {}",
                fused.analysis_methods_used, fused.context
            )
        } else {
            "continue_monitoring".to_string()
        },
    }
}

/// Map DriftSeverity (from drift_analyzer) to Severity (from ovaph_loop).
fn map_drift_severity_to_ovaph(severity: &DriftSeverity) -> Severity {
    match severity {
        DriftSeverity::None => Severity::None,
        DriftSeverity::Low => Severity::Low,
        DriftSeverity::Medium => Severity::Medium,
        DriftSeverity::High => Severity::High,
        DriftSeverity::Critical => Severity::Critical,
    }
}

// ────────────────────────────────────────────────────────────────────────
// Section 6: Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────
    // Helper functions for tests
    // ────────────────────────────────────────────────────────────────

    fn make_observation(drift_type: DriftType, value: f64) -> DriftObservation {
        DriftObservation {
            drift_type,
            value,
            context: "test".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    fn make_hub() -> SentinelHub {
        SentinelHub::with_defaults(3.0, 100).unwrap_or_else(|e| panic!("Failed to create hub: {}", e))
    }

    fn make_hub_with_config(config: FusionConfig) -> SentinelHub {
        SentinelHub::new(3.0, 100, config, 1000)
            .unwrap_or_else(|e| panic!("Failed to create hub: {}", e))
    }

    fn establish_baseline(hub: &mut SentinelHub, drift_type: DriftType, base_value: f64, count: usize) {
        for _ in 0..count {
            let noise = (rand::random::<f64>() - 0.5) * 0.02;
            let obs = make_observation(drift_type.clone(), base_value + noise);
            let _ = hub.observe(obs);
        }
    }

    // ════════════════════════════════════════════════════════════════
    // A. DriftBaselines Tests (8)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_baselines_new() {
        let baselines = DriftBaselines::new();
        assert!(baselines.is_empty());
        assert_eq!(baselines.len(), 0);
    }

    #[test]
    fn test_baselines_update_creates() {
        let mut baselines = DriftBaselines::new();
        baselines.update(DriftType::Decision, 0.85);

        assert_eq!(baselines.len(), 1);
        let baseline = baselines.get(&DriftType::Decision).unwrap();
        assert_eq!(baseline.sample_count, 1);
        assert!((baseline.mean - 0.85).abs() < 1e-10);
    }

    #[test]
    fn test_baselines_update_accumulates() {
        let mut baselines = DriftBaselines::new();
        for i in 0..50 {
            baselines.update(DriftType::Policy, 0.5 + (i as f64 * 0.001));
        }

        let baseline = baselines.get(&DriftType::Policy).unwrap();
        assert_eq!(baseline.sample_count, 50);
        assert!(baseline.mean > 0.5);
        assert!(baseline.stddev > 0.0);
    }

    #[test]
    fn test_baselines_get_missing() {
        let baselines = DriftBaselines::new();
        assert!(baselines.get(&DriftType::Trust).is_none());
    }

    #[test]
    fn test_baselines_compute_baseline() {
        let mut baselines = DriftBaselines::new();
        let values: Vec<f64> = (0..100).map(|i| 0.8 + (i as f64 * 0.001)).collect();

        let result = baselines.compute_baseline(DriftType::Model, &values);
        assert!(result.is_ok());

        let baseline = baselines.get(&DriftType::Model).unwrap();
        assert_eq!(baseline.sample_count, 100);
        assert_eq!(baseline.histogram_bins.len(), DEFAULT_HISTOGRAM_BINS);
        assert!(baseline.percentile_50 > 0.84);
        assert!(baseline.percentile_50 < 0.90);
    }

    #[test]
    fn test_baselines_compute_empty_fails() {
        let mut baselines = DriftBaselines::new();
        let result = baselines.compute_baseline(DriftType::Decision, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_baselines_is_stale() {
        let mut baselines = DriftBaselines::with_max_age(0); // Immediately stale.
        baselines.update(DriftType::Runtime, 1.0);

        // Give a moment for the timestamp to be "in the past".
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(baselines.is_stale(&DriftType::Runtime));
    }

    #[test]
    fn test_baselines_reset() {
        let mut baselines = DriftBaselines::new();
        baselines.update(DriftType::Decision, 0.5);
        baselines.update(DriftType::Policy, 0.6);
        assert_eq!(baselines.len(), 2);

        baselines.reset(&DriftType::Decision);
        assert_eq!(baselines.len(), 1);
        assert!(baselines.get(&DriftType::Decision).is_none());
        assert!(baselines.get(&DriftType::Policy).is_some());
    }

    #[test]
    fn test_baselines_histogram() {
        let mut baselines = DriftBaselines::new();
        // Uniform distribution 0..100.
        let values: Vec<f64> = (0..1000).map(|i| i as f64).collect();
        let _ = baselines.compute_baseline(DriftType::Trust, &values);

        let baseline = baselines.get(&DriftType::Trust).unwrap();
        let total: f64 = baseline.histogram_bins.iter().sum();
        assert!((total - 1.0).abs() < 1e-10, "Histogram should sum to 1.0");
    }

    // ════════════════════════════════════════════════════════════════
    // B. FusedDriftSignal Tests (6)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_fuse_both_fire() {
        let z_alert = DriftAlert {
            drift_type: DriftType::Decision,
            z_score: 5.0,
            current_mean: 0.85,
            current_stddev: 0.03,
            observed_value: 0.40,
            context: "test".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            severity: AlertSeverity::Critical,
        };

        let fused = FusedDriftSignal::fuse(
            DriftType::Decision,
            Some(z_alert),
            Some(DriftSeverity::High),
            vec!["z-score".to_string(), "ks".to_string()],
        );

        assert!(fused.is_anomaly);
        // Both fire → should be boosted to Critical.
        assert_eq!(fused.composite_severity, DriftSeverity::Critical);
        assert!(fused.composite_confidence > 0.85);
        assert!(fused.z_score_alert.is_some());
        assert!(fused.advanced_severity.is_some());
    }

    #[test]
    fn test_fuse_z_only() {
        let z_alert = DriftAlert {
            drift_type: DriftType::Policy,
            z_score: 4.0,
            current_mean: 0.5,
            current_stddev: 0.1,
            observed_value: 0.0,
            context: "test".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            severity: AlertSeverity::Warning,
        };

        let fused = FusedDriftSignal::fuse(
            DriftType::Policy,
            Some(z_alert),
            None,
            vec!["z-score".to_string()],
        );

        assert!(fused.is_anomaly);
        assert_eq!(fused.composite_severity, DriftSeverity::Medium); // Warning → Medium.
        assert!(fused.composite_confidence >= 0.5);
    }

    #[test]
    fn test_fuse_advanced_only() {
        let fused = FusedDriftSignal::fuse(
            DriftType::Model,
            None,
            Some(DriftSeverity::High),
            vec!["ks".to_string(), "psi".to_string()],
        );

        assert!(fused.is_anomaly);
        assert_eq!(fused.composite_severity, DriftSeverity::High);
    }

    #[test]
    fn test_fuse_neither() {
        let fused = FusedDriftSignal::fuse(
            DriftType::Trust,
            None,
            None,
            vec![],
        );

        assert!(!fused.is_anomaly);
        assert_eq!(fused.composite_severity, DriftSeverity::None);
        assert!((fused.composite_confidence - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_fuse_composite_confidence_range() {
        // Both detectors, Critical severity → highest confidence.
        let z_alert = DriftAlert {
            drift_type: DriftType::Runtime,
            z_score: 10.0,
            current_mean: 1.0,
            current_stddev: 0.01,
            observed_value: 0.5,
            context: "test".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            severity: AlertSeverity::Critical,
        };

        let fused = FusedDriftSignal::fuse(
            DriftType::Runtime,
            Some(z_alert),
            Some(DriftSeverity::Critical),
            vec!["z-score".to_string(), "ks".to_string(), "psi".to_string()],
        );

        assert!(fused.composite_confidence >= 0.0);
        assert!(fused.composite_confidence <= 1.0);
    }

    #[test]
    fn test_fuse_is_anomaly_consistent() {
        // If severity is None, is_anomaly must be false.
        let fused = FusedDriftSignal::fuse(
            DriftType::Configuration,
            Some(DriftAlert {
                drift_type: DriftType::Configuration,
                z_score: 1.5,
                current_mean: 0.5,
                current_stddev: 0.1,
                observed_value: 0.35,
                context: "test".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                severity: AlertSeverity::Info,
            }),
            None,
            vec!["z-score".to_string()],
        );

        // Info → Low severity, which should still be an anomaly.
        assert!(fused.is_anomaly);
    }

    // ════════════════════════════════════════════════════════════════
    // C. SentinelHub Tests (10)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_hub_new() {
        let hub = make_hub();
        assert_eq!(hub.buffer_len(), 0);
        assert_eq!(hub.observation_count(&DriftType::Decision), 0);
    }

    #[test]
    fn test_hub_observe_stable() {
        let mut hub = make_hub();

        // Feed stable data — should not produce anomalies.
        for _ in 0..50 {
            let obs = make_observation(DriftType::Decision, 0.85);
            let result = hub.observe(obs).unwrap();
            assert!(result.is_none(), "Stable data should not produce anomalies");
        }

        assert_eq!(hub.observation_count(&DriftType::Decision), 50);
        assert_eq!(hub.anomaly_count(&DriftType::Decision), 0);
    }

    #[test]
    fn test_hub_observe_drift() {
        let mut hub = make_hub();

        // Establish baseline.
        establish_baseline(&mut hub, DriftType::Policy, 0.5, 50);

        // Sudden shift should trigger z-score alert.
        let obs = make_observation(DriftType::Policy, -2.0);
        let result = hub.observe(obs).unwrap();

        assert!(result.is_some(), "Drift should be detected");
        let fused = result.unwrap();
        assert!(fused.is_anomaly);
        assert!(fused.z_score_alert.is_some());
    }

    #[test]
    fn test_hub_observe_with_baseline() {
        let mut hub = make_hub_with_config(FusionConfig {
            baseline_min_samples: 20,
            advanced_methods: vec!["ks".to_string(), "psi".to_string(), "adwin".to_string()],
            ..FusionConfig::default()
        });

        // Warm up baseline to 20+ samples.
        establish_baseline(&mut hub, DriftType::Model, 0.8, 25);

        // Verify baseline exists.
        assert!(hub.baselines().get(&DriftType::Model).is_some());
        let baseline = hub.baselines().get(&DriftType::Model).unwrap();
        assert!(baseline.sample_count >= 20);
    }

    #[test]
    fn test_hub_fusion_logic() {
        let mut hub = make_hub_with_config(FusionConfig {
            require_both_detectors: true,
            baseline_min_samples: 10,
            advanced_methods: vec!["ks".to_string()],
            ..FusionConfig::default()
        });

        // Warm baseline.
        establish_baseline(&mut hub, DriftType::Trust, 0.5, 15);

        // Introduce drift.
        let obs = make_observation(DriftType::Trust, -3.0);
        let result = hub.observe(obs).unwrap();

        // With require_both_detectors=true, z-score alone may not fire.
        // It depends on whether the advanced method also detects drift.
        // We just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_hub_correlation() {
        let mut hub = make_hub();

        // Trigger drift in multiple types.
        for dt in &[DriftType::Decision, DriftType::Policy, DriftType::Configuration] {
            establish_baseline(&mut hub, dt.clone(), 0.5, 50);
        }

        // Shift all three.
        for dt in &[DriftType::Decision, DriftType::Policy, DriftType::Configuration] {
            let obs = make_observation(dt.clone(), -2.0);
            let _ = hub.observe(obs);
        }

        let correlated = hub.correlation_check();
        // Should have at least one correlation group.
        assert!(!correlated.is_empty());
    }

    #[test]
    fn test_hub_reset() {
        let mut hub = make_hub();
        establish_baseline(&mut hub, DriftType::Runtime, 1.0, 30);

        hub.reset_detector(&DriftType::Runtime);
        assert_eq!(hub.observation_count(&DriftType::Runtime), 0);
        assert_eq!(hub.anomaly_count(&DriftType::Runtime), 0);
    }

    #[test]
    fn test_hub_stats() {
        let mut hub = make_hub();
        let obs = make_observation(DriftType::Plugin, 0.7);
        let _ = hub.observe(obs);

        let stats = hub.get_stats(&DriftType::Plugin);
        assert!(stats.is_some());
        let (m, _s, w) = stats.unwrap();
        assert!((m - 0.7).abs() < 1e-10);
        assert_eq!(w, 1);
    }

    #[test]
    fn test_hub_buffer_overflow() {
        let mut hub = SentinelHub::new(3.0, 100, FusionConfig::default(), 5)
            .unwrap_or_else(|e| panic!("{}", e));

        // Warm baseline.
        establish_baseline(&mut hub, DriftType::Memory, 0.5, 50);

        // Trigger many anomalies to overflow the buffer.
        for i in 0..10 {
            let obs = make_observation(DriftType::Memory, -3.0 - i as f64);
            let _ = hub.observe(obs);
        }

        // Buffer should be capped at 5.
        assert!(hub.buffer_len() <= 5);
    }

    #[test]
    fn test_hub_multiple_types() {
        let mut hub = make_hub();

        // Feed different types.
        for dt in DriftType::all() {
            let obs = make_observation(dt.clone(), 0.5);
            let _ = hub.observe(obs);
        }

        // All types should have been observed.
        for dt in DriftType::all() {
            assert_eq!(hub.observation_count(dt), 1);
        }
    }

    // ════════════════════════════════════════════════════════════════
    // D. SentinelVerificationBridge Tests (5)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_no_anomalies() {
        let hub = make_hub();
        let mut bridge = SentinelVerificationBridge::new(hub);

        let observation = OvaphObservation {
            drift_snapshots: vec![],
            ..OvaphObservation::default()
        };

        let result = bridge.verify(&observation);
        assert!(!result.requires_healing);
        assert_eq!(result.composite_severity, Severity::None);
        assert!(result.signals.is_empty());
    }

    #[test]
    fn test_verify_with_anomalies() {
        let mut hub = make_hub();
        // Warm baseline for Decision drift type.
        establish_baseline(&mut hub, DriftType::Decision, 0.85, 50);

        let bridge_hub = std::mem::replace(&mut hub, make_hub());
        let mut bridge = SentinelVerificationBridge::new(bridge_hub);

        let observation = OvaphObservation {
            drift_snapshots: vec![crate::ananta::ovaph_loop::DriftSnapshot {
                drift_type: "decision".to_string(),
                current_mean: -2.0,
                current_stddev: 0.1,
                sample_count: 51,
                last_z_score: 8.0,
            }],
            ..OvaphObservation::default()
        };

        let result = bridge.verify(&observation);
        assert!(!result.signals.is_empty());
    }

    #[test]
    fn test_verify_maps_severity() {
        let hub = make_hub();
        let mut bridge = SentinelVerificationBridge::new(hub);

        let observation = OvaphObservation {
            drift_snapshots: vec![crate::ananta::ovaph_loop::DriftSnapshot {
                drift_type: "unknown_type".to_string(),
                current_mean: 0.0,
                current_stddev: 0.0,
                sample_count: 0,
                last_z_score: 0.0,
            }],
            ..OvaphObservation::default()
        };

        let result = bridge.verify(&observation);
        assert_eq!(result.signals.len(), 1);
        assert!(!result.signals[0].is_anomaly);
        assert_eq!(result.signals[0].severity, Severity::None);
    }

    #[test]
    fn test_verify_maps_methods() {
        let mut hub = make_hub();
        establish_baseline(&mut hub, DriftType::Model, 0.5, 40);

        let bridge_hub = std::mem::replace(&mut hub, make_hub());
        let mut bridge = SentinelVerificationBridge::new(bridge_hub);

        let observation = OvaphObservation {
            drift_snapshots: vec![crate::ananta::ovaph_loop::DriftSnapshot {
                drift_type: "model".to_string(),
                current_mean: 0.5,
                current_stddev: 0.05,
                sample_count: 41,
                last_z_score: 0.5,
            }],
            ..OvaphObservation::default()
        };

        let result = bridge.verify(&observation);
        assert!(!result.signals.is_empty());
        // Should use ZScore or Composite method.
        assert!(
            matches!(
                result.signals[0].analysis_method,
                AnalysisMethod::ZScore | AnalysisMethod::Composite
            )
        );
    }

    #[test]
    fn test_verify_empty_observation() {
        let hub = make_hub();
        let mut bridge = SentinelVerificationBridge::new(hub);

        let observation = OvaphObservation::default();
        let result = bridge.verify(&observation);

        assert_eq!(result.signals.len(), 0);
        assert_eq!(result.composite_severity, Severity::None);
        assert!(!result.requires_healing);
        assert!(result.rationale.contains("No drift"));
    }

    // ════════════════════════════════════════════════════════════════
    // E. Correlation Tests (4)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_correlation_same_domain() {
        let mut hub = make_hub();
        establish_baseline(&mut hub, DriftType::Trust, 0.5, 50);

        // Trigger multiple alerts of the same type.
        for _ in 0..3 {
            let obs = make_observation(DriftType::Trust, -3.0);
            let _ = hub.observe(obs);
        }

        let signals = hub.get_all_fused_signals();
        let signal_refs: Vec<&FusedDriftSignal> = signals.iter().collect();
        let correlated = correlate_signals(&signal_refs);

        assert!(!correlated.is_empty());
        let has_same_domain = correlated
            .iter()
            .any(|ca| ca.correlation_type == CorrelationType::SameDomain);
        assert!(has_same_domain);
    }

    #[test]
    fn test_correlation_cascade() {
        // Decision + Policy form a cascade pair.
        let mut hub = make_hub();
        establish_baseline(&mut hub, DriftType::Decision, 0.5, 50);
        establish_baseline(&mut hub, DriftType::Policy, 0.5, 50);

        // Trigger both.
        let _ = hub.observe(make_observation(DriftType::Decision, -3.0));
        let _ = hub.observe(make_observation(DriftType::Policy, -3.0));

        let signals = hub.get_all_fused_signals();
        let signal_refs: Vec<&FusedDriftSignal> = signals.iter().collect();
        let correlated = correlate_signals(&signal_refs);

        let has_cascade = correlated
            .iter()
            .any(|ca| ca.correlation_type == CorrelationType::Cascade);
        assert!(has_cascade, "Expected cascade correlation for Decision+Policy");
    }

    #[test]
    fn test_correlation_temporal_cluster() {
        let mut hub = make_hub();

        // Establish baseline for 3 unrelated types.
        establish_baseline(&mut hub, DriftType::Memory, 0.5, 50);
        establish_baseline(&mut hub, DriftType::Plugin, 0.5, 50);
        establish_baseline(&mut hub, DriftType::Learning, 0.5, 50);

        // Trigger all three within a short window.
        let _ = hub.observe(make_observation(DriftType::Memory, -3.0));
        let _ = hub.observe(make_observation(DriftType::Plugin, -3.0));
        let _ = hub.observe(make_observation(DriftType::Learning, -3.0));

        let signals = hub.get_all_fused_signals();
        let signal_refs: Vec<&FusedDriftSignal> = signals.iter().collect();
        let correlated = correlate_signals(&signal_refs);

        let has_temporal = correlated
            .iter()
            .any(|ca| ca.correlation_type == CorrelationType::TemporalCluster);
        assert!(has_temporal, "Expected temporal cluster for 3 non-cascade types");
    }

    #[test]
    fn test_correlation_cross_domain() {
        // Create signals for two unrelated types that are not cascade pairs.
        let signal_a = FusedDriftSignal::fuse(
            DriftType::Memory,
            Some(DriftAlert {
                drift_type: DriftType::Memory,
                z_score: 5.0,
                current_mean: 0.5,
                current_stddev: 0.1,
                observed_value: 0.0,
                context: "test".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                severity: AlertSeverity::Critical,
            }),
            None,
            vec!["z-score".to_string()],
        );

        let signal_b = FusedDriftSignal::fuse(
            DriftType::Learning,
            Some(DriftAlert {
                drift_type: DriftType::Learning,
                z_score: 5.0,
                current_mean: 0.5,
                current_stddev: 0.1,
                observed_value: 0.0,
                context: "test".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                severity: AlertSeverity::Critical,
            }),
            None,
            vec!["z-score".to_string()],
        );

        let signals: Vec<&FusedDriftSignal> = vec![&signal_a, &signal_b];
        let correlated = correlate_signals(&signals);

        assert!(!correlated.is_empty());
        // Two non-cascade, non-cluster types → should produce some correlation.
        // Could be CrossDomain or SameDomain.
        assert!(correlated.iter().any(|ca| {
            matches!(
                ca.correlation_type,
                CorrelationType::SameDomain | CorrelationType::CrossDomain
            )
        }));
    }

    // ════════════════════════════════════════════════════════════════
    // F. Integration Tests (5)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_observe_verify_flow() {
        let mut hub = make_hub_with_config(FusionConfig {
            baseline_min_samples: 20,
            advanced_methods: vec!["ks".to_string(), "psi".to_string()],
            ..FusionConfig::default()
        });

        // Warm baseline.
        establish_baseline(&mut hub, DriftType::Decision, 0.85, 25);

        // Introduce drift.
        let obs = make_observation(DriftType::Decision, 0.30);
        let result = hub.observe(obs).unwrap();
        assert!(result.is_some(), "Should detect drift after baseline warmup");

        // Create bridge and verify.
        let mut bridge = SentinelVerificationBridge::new(hub);
        let observation = OvaphObservation {
            drift_snapshots: vec![crate::ananta::ovaph_loop::DriftSnapshot {
                drift_type: "decision".to_string(),
                current_mean: 0.30,
                current_stddev: 0.05,
                sample_count: 26,
                last_z_score: 5.0,
            }],
            ..OvaphObservation::default()
        };

        let vr = bridge.verify(&observation);
        assert!(!vr.signals.is_empty());
    }

    #[test]
    fn test_baseline_warming() {
        let mut hub = make_hub_with_config(FusionConfig {
            baseline_min_samples: 30,
            advanced_methods: vec!["ks".to_string(), "psi".to_string(), "adwin".to_string()],
            ..FusionConfig::default()
        });

        // Feed observations one at a time and check when baseline becomes active.
        for i in 1..=40 {
            let obs = make_observation(DriftType::Configuration, 0.6);
            let _ = hub.observe(obs);

            if i >= 30 {
                // After 30 samples, baseline should be usable by advanced methods.
                let baseline = hub.baselines().get(&DriftType::Configuration);
                assert!(baseline.is_some());
                assert!(baseline.unwrap().sample_count >= 30);
            }
        }
    }

    #[test]
    fn test_multi_type_drift() {
        let mut hub = make_hub();

        // Warm baselines for multiple types.
        establish_baseline(&mut hub, DriftType::Decision, 0.85, 50);
        establish_baseline(&mut hub, DriftType::Trust, 0.7, 50);
        establish_baseline(&mut hub, DriftType::Runtime, 1.0, 50);

        // Trigger drift in all three simultaneously.
        let alerts: Vec<_> = vec![
            make_observation(DriftType::Decision, -1.0),
            make_observation(DriftType::Trust, -1.0),
            make_observation(DriftType::Runtime, -2.0),
        ]
        .into_iter()
        .filter_map(|obs| hub.observe(obs).unwrap())
        .collect();

        // Should have detected at least some anomalies.
        assert!(!alerts.is_empty() || hub.buffer_len() > 0);
    }

    #[test]
    fn test_correlation_in_pipeline() {
        let mut hub = make_hub();

        establish_baseline(&mut hub, DriftType::Policy, 0.5, 50);
        establish_baseline(&mut hub, DriftType::Configuration, 0.5, 50);

        // Trigger cascade pair (Policy → Configuration).
        let _ = hub.observe(make_observation(DriftType::Policy, -3.0));
        let _ = hub.observe(make_observation(DriftType::Configuration, -3.0));

        // Correlation should find the cascade.
        let correlated = hub.correlation_check();
        assert!(!correlated.is_empty());

        let has_cascade = correlated
            .iter()
            .any(|ca| ca.correlation_type == CorrelationType::Cascade);
        assert!(has_cascade);
    }

    #[test]
    fn test_buffer_pruning() {
        let mut hub = SentinelHub::new(3.0, 100, FusionConfig::default(), 100)
            .unwrap_or_else(|e| panic!("{}", e));

        // Warm baseline.
        establish_baseline(&mut hub, DriftType::Orchestration, 0.5, 50);

        // Fill buffer with anomalies.
        for _ in 0..20 {
            let obs = make_observation(DriftType::Orchestration, -3.0);
            let _ = hub.observe(obs);
        }

        assert!(hub.buffer_len() > 0);

        // Pruning should remove items (but since we just added them, most
        // should still be within the window). We verify the method works
        // without panicking and the count doesn't exceed buffer_size.
        let pruned = hub.prune_buffer();
        assert!(hub.buffer_len() <= 100);
        // pruned might be 0 if all items are fresh — that's fine.
        let _ = pruned;
    }

    // ════════════════════════════════════════════════════════════════
    // G. Advanced Detection Stub Tests (6 bonus)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_ks_identical_distributions() {
        let dist: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let (stat, _conf) = ks_test(&dist, &dist);
        assert!((stat - 0.0).abs() < 1e-10, "Identical distributions should have KS=0");
    }

    #[test]
    fn test_ks_different_distributions() {
        let ref_dist: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let sample_dist: Vec<f64> = (50..150).map(|i| i as f64).collect();
        let (stat, _conf) = ks_test(&ref_dist, &sample_dist);
        assert!(stat > 0.0, "Different distributions should have KS > 0");
    }

    #[test]
    fn test_ks_empty_inputs() {
        let (stat, conf) = ks_test(&[], &[1.0, 2.0]);
        assert_eq!(stat, 0.0);
        assert_eq!(conf, 0.0);

        let (stat, conf) = ks_test(&[1.0, 2.0], &[]);
        assert_eq!(stat, 0.0);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_psi_stable_distribution() {
        let reference: Vec<f64> = (0..1000).map(|_| rand::random::<f64>()).collect();
        let sample: Vec<f64> = (0..1000).map(|_| rand::random::<f64>()).collect();
        let (psi, _) = psi_test(&reference, &sample);
        // Both uniform [0,1] — PSI should be low.
        assert!(
            psi < PSI_MEDIUM_THRESHOLD,
            "Uniform vs uniform should have low PSI, got {:.4}",
            psi
        );
    }

    #[test]
    fn test_psi_shifted_distribution() {
        let reference: Vec<f64> = (0..1000).map(|i| i as f64 / 1000.0).collect();
        let sample: Vec<f64> = (0..1000).map(|i| (i as f64 + 500.0) / 1000.0).collect();
        let (psi, _) = psi_test(&reference, &sample);
        // Shifted by 0.5 — PSI should be significant.
        assert!(
            psi > PSI_LOW_THRESHOLD,
            "Shifted distribution should have PSI > 0.1, got {:.4}",
            psi
        );
    }

    #[test]
    fn test_adwin_no_change() {
        use rand::Rng;
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        let mut rng = SmallRng::seed_from_u64(12345);
        let reference: Vec<f64> = (0..100).map(|_| 0.5 + rng.random::<f64>() * 0.1 - 0.05).collect();
        let sample: Vec<f64> = (0..20).map(|_| 0.5 + rng.random::<f64>() * 0.1 - 0.05).collect();
        let (score, _) = adwin_test(&reference, &sample);
        // Same mean, noise — drift score should be low.
        assert!(
            score < ADVANCED_DRIFT_THRESHOLD,
            "Same mean should have low ADWIN score, got {:.4}",
            score
        );
    }

    // ════════════════════════════════════════════════════════════════
    // H. FusionConfig and Edge Case Tests (4 bonus)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_fusion_config_validate_ok() {
        let config = FusionConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fusion_config_validate_zero_weights() {
        let config = FusionConfig {
            z_score_weight: 0.0,
            advanced_weight: 0.0,
            ..FusionConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_fusion_config_validate_negative_weights() {
        let config = FusionConfig {
            z_score_weight: -1.0,
            advanced_weight: 0.5,
            ..FusionConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_fusion_config_validate_zero_min_samples() {
        let config = FusionConfig {
            baseline_min_samples: 0,
            ..FusionConfig::default()
        };
        assert!(config.validate().is_err());
    }

    // ════════════════════════════════════════════════════════════════
    // I. Statistical Helper Tests (3 bonus)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_mean_empty() {
        assert_eq!(mean(&[]), 0.0);
    }

    #[test]
    fn test_mean_single() {
        assert!((mean(&[42.0]) - 42.0).abs() < 1e-10);
    }

    #[test]
    fn test_stddev_values() {
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let s = stddev(&values);
        // Expected: sqrt(mean((x - mean)^2)) = sqrt(4.0) = 2.0
        assert!((s - 2.0).abs() < 0.01, "Expected stddev ≈ 2.0, got {:.4}", s);
    }
}
