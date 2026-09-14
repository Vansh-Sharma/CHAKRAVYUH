// ANANTA Sentinel — Production-Grade Drift Analyzer
//
// Provides advanced statistical methods for detecting, classifying, and
// assessing data and concept drift. Designed for continuous monitoring of
// trust distributions, decision patterns, and model behavior.
//
// Capabilities:
//   - Statistical drift detection (KS, PSI, JS, KL, Chi-squared)
//   - Concept drift detection via ADWIN (Adaptive Windowing)
//   - Drift pattern classification (Sudden, Gradual, Recurring, Incremental)
//   - Multi-dimensional drift with weighted aggregation
//   - Drift impact assessment on trust scores
//   - Baseline management with multiple reference periods

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

use crate::ananta::TrendDirection;
use crate::ananta::distributed::partition_detector::ln_gamma;

// ────────────────────────────────────────────────────────────────────────
// Core types shared across modules
// ────────────────────────────────────────────────────────────────────────

/// Severity level for detected drift.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// No meaningful drift detected.
    None,
    /// Minor statistical deviation; likely noise.
    Low,
    /// Moderate drift that warrants monitoring.
    Medium,
    /// Significant drift requiring investigation.
    High,
    /// Severe drift; system behavior has fundamentally changed.
    Critical,
}

impl DriftSeverity {
    /// Convert severity to a numeric score in [0.0, 1.0].
    pub fn to_score(&self) -> f64 {
        match self {
            DriftSeverity::None => 0.0,
            DriftSeverity::Low => 0.25,
            DriftSeverity::Medium => 0.5,
            DriftSeverity::High => 0.75,
            DriftSeverity::Critical => 1.0,
        }
    }

    /// Classify a raw drift score into a severity level.
    pub fn from_score(score: f64, low: f64, medium: f64, high: f64) -> Self {
        if score < low {
            DriftSeverity::None
        } else if score < medium {
            DriftSeverity::Low
        } else if score < high {
            DriftSeverity::Medium
        } else if score < 1.0 {
            DriftSeverity::High
        } else {
            DriftSeverity::Critical
        }
    }

    /// Default thresholds: low=0.1, medium=0.25, high=0.5.
    pub fn from_score_default(score: f64) -> Self {
        Self::from_score(score, 0.1, 0.25, 0.5)
    }
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Result of a statistical drift test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResult {
    /// The computed drift statistic/score.
    pub score: f64,
    /// The p-value or significance measure (where applicable).
    pub p_value: f64,
    /// Qualitative severity classification.
    pub severity: DriftSeverity,
    /// Human-readable description of the finding.
    pub description: String,
    /// Timestamp of the analysis.
    pub timestamp: DateTime<Utc>,
}

impl DriftResult {
    pub fn new(score: f64, p_value: f64, severity: DriftSeverity, description: String) -> Self {
        Self {
            score,
            p_value,
            severity,
            description,
            timestamp: Utc::now(),
        }
    }

    /// Returns true if drift is considered statistically significant.
    pub fn is_significant(&self, alpha: f64) -> bool {
        self.p_value < alpha
    }
}

// ────────────────────────────────────────────────────────────────────────
// 1. Statistical Drift Detection
// ────────────────────────────────────────────────────────────────────────

/// Histogram representation of a distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Distribution {
    /// Bin index → probability mass.
    pub bins: HashMap<usize, f64>,
    /// Number of original data points.
    pub count: usize,
    /// Minimum observed value.
    pub min: f64,
    /// Maximum observed value.
    pub max: f64,
    /// Number of bins used.
    pub num_bins: usize,
}

impl Distribution {
    /// Build a histogram distribution from raw observations.
    pub fn from_values(values: &[f64], num_bins: usize) -> Self {
        if values.is_empty() {
            return Self {
                bins: HashMap::new(),
                count: 0,
                min: 0.0,
                max: 0.0,
                num_bins,
            };
        }
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = max - min;
        let bin_width = if range.abs() < 1e-12 { 1.0 } else { range / num_bins as f64 };

        let mut bins: HashMap<usize, f64> = HashMap::new();
        for &v in values {
            let idx = if bin_width > 0.0 {
                ((v - min) / bin_width).floor() as usize
            } else {
                0
            };
            let idx = idx.min(num_bins - 1);
            *bins.entry(idx).or_insert(0.0) += 1.0;
        }
        let total = values.len() as f64;
        for prob in bins.values_mut() {
            *prob /= total;
        }
        Self { bins, count: values.len(), min, max, num_bins }
    }

    /// Build a histogram distribution from raw observations using shared bounds.
    /// This ensures two distributions are binned on the same scale for fair comparison.
    pub fn from_values_with_bounds(values: &[f64], num_bins: usize, shared_min: f64, shared_max: f64) -> Self {
        if values.is_empty() {
            return Self { bins: HashMap::new(), count: 0, min: shared_min, max: shared_max, num_bins };
        }
        let range = shared_max - shared_min;
        let bin_width = if range.abs() < 1e-12 { 1.0 } else { range / num_bins as f64 };
        let mut bins: HashMap<usize, f64> = HashMap::new();
        for &v in values {
            let idx = if bin_width > 0.0 {
                ((v - shared_min) / bin_width).floor() as usize
            } else { 0 };
            let idx = idx.min(num_bins - 1);
            *bins.entry(idx).or_insert(0.0) += 1.0;
        }
        let total = values.len() as f64;
        for prob in bins.values_mut() {
            *prob /= total;
        }
        Self { bins, count: values.len(), min: shared_min, max: shared_max, num_bins }
    }

    /// Get the probability for a bin, defaulting to 0.0.
    pub fn prob(&self, bin: usize) -> f64 {
        self.bins.get(&bin).copied().unwrap_or(0.0)
    }

    /// Compute the empirical CDF value at a given point.
    pub fn cdf_at(&self, x: f64) -> f64 {
        if x <= self.min { return 0.0; }
        if x >= self.max { return 1.0; }
        let range = self.max - self.min;
        let bin_width = if range.abs() < 1e-12 { 1.0 } else { range / self.num_bins as f64 };
        let target_bin = if bin_width > 0.0 {
            ((x - self.min) / bin_width).floor() as usize
        } else {
            0
        };
        let mut cumulative = 0.0;
        for (&bin_idx, &prob) in &self.bins {
            if bin_idx < target_bin {
                cumulative += prob;
            } else if bin_idx == target_bin {
                cumulative += prob * 0.5;
            }
        }
        cumulative
    }
}

/// Statistical drift detector providing multiple test methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalDriftDetector {
    /// Number of histogram bins for distribution comparisons.
    pub num_bins: usize,
    /// Small constant added to probabilities to avoid log(0).
    pub epsilon: f64,
    /// Significance level (alpha) for hypothesis tests.
    pub alpha: f64,
}

impl StatisticalDriftDetector {
    /// Create a new detector with default settings.
    pub fn new() -> Self {
        Self { num_bins: 10, epsilon: 1e-10, alpha: 0.05 }
    }

    /// Create with custom parameters.
    pub fn with_params(num_bins: usize, epsilon: f64, alpha: f64) -> Self {
        Self { num_bins, epsilon, alpha }
    }

    // ── Kolmogorov-Smirnov Test ──────────────────────────────────────

    /// Two-sample Kolmogorov-Smirnov test.
    ///
    /// Compares the empirical CDFs of two samples. Returns the
    /// KS statistic (maximum absolute CDF difference) and an
    /// approximate p-value using the Kolmogorov asymptotic formula.
    ///
    /// D = sup|F1(x) - F2(x)|
    /// p ≈ 2 * Σ_{k=1}^{∞} (-1)^{k+1} * exp(-2 * k² * λ²)
    /// where λ = D * sqrt(n_eff)
    pub fn ks_test(&self, reference: &[f64], current: &[f64]) -> DriftResult {
        if reference.is_empty() || current.is_empty() {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "Insufficient data for KS test".into());
        }

        let mut sorted_ref = reference.to_vec();
        let mut sorted_cur = current.to_vec();
        sorted_ref.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted_cur.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n_ref = sorted_ref.len() as f64;
        let n_cur = sorted_cur.len() as f64;
        let all_values = merge_sorted(&sorted_ref, &sorted_cur);

        let mut d_statistic: f64 = 0.0;
        let mut ref_idx: usize = 0;
        let mut cur_idx: usize = 0;

        for &val in &all_values {
            while ref_idx < sorted_ref.len() && sorted_ref[ref_idx] <= val {
                ref_idx += 1;
            }
            while cur_idx < sorted_cur.len() && sorted_cur[cur_idx] <= val {
                cur_idx += 1;
            }
            let cdf_ref = ref_idx as f64 / n_ref;
            let cdf_cur = cur_idx as f64 / n_cur;
            d_statistic = d_statistic.max((cdf_ref - cdf_cur).abs());
        }

        let n_eff = (n_ref * n_cur) / (n_ref + n_cur);
        let lambda = d_statistic * n_eff.sqrt();
        let p_value = kolmogorov_p_value(lambda);

        let severity = if p_value < self.alpha {
            DriftSeverity::from_score_default(d_statistic)
        } else {
            DriftSeverity::None
        };

        let desc = if p_value < self.alpha {
            format!("KS test: D={:.6}, p={:.6} < alpha={:.2} — distributions differ",
                d_statistic, p_value, self.alpha)
        } else {
            format!("KS test: D={:.6}, p={:.6} — no significant drift",
                d_statistic, p_value)
        };

        DriftResult::new(d_statistic, p_value, severity, desc)
    }

    // ── Population Stability Index (PSI) ─────────────────────────────

    /// Population Stability Index between reference and current.
    ///
    /// PSI = Σ (P_curr - P_ref) * ln(P_curr / P_ref)
    ///
    /// Interpretation:
    ///   PSI < 0.1    → No significant change
    ///   0.1 ≤ PSI < 0.25 → Moderate change
    ///   PSI ≥ 0.25   → Significant change
    pub fn psi(&self, reference: &[f64], current: &[f64]) -> DriftResult {
        if reference.is_empty() || current.is_empty() {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "Insufficient data for PSI".into());
        }

        let all_min = reference.iter().chain(current.iter())
            .cloned().fold(f64::INFINITY, f64::min);
        let all_max = reference.iter().chain(current.iter())
            .cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = all_max - all_min;
        let bin_width = if range.abs() < 1e-12 { 1.0 } else { range / self.num_bins as f64 };

        let ref_dist = histogram_probs(reference, all_min, bin_width, self.num_bins);
        let cur_dist = histogram_probs(current, all_min, bin_width, self.num_bins);

        let mut psi_value = 0.0;
        for i in 0..self.num_bins {
            let p_ref = ref_dist.get(&i).copied().unwrap_or(0.0).max(self.epsilon);
            let p_cur = cur_dist.get(&i).copied().unwrap_or(0.0).max(self.epsilon);
            psi_value += (p_cur - p_ref) * (p_cur / p_ref).ln();
        }

        let severity = if psi_value < 0.1 {
            DriftSeverity::None
        } else if psi_value < 0.25 {
            DriftSeverity::Low
        } else if psi_value < 0.5 {
            DriftSeverity::Medium
        } else if psi_value < 1.0 {
            DriftSeverity::High
        } else {
            DriftSeverity::Critical
        };

        let p_value = (1.0 - psi_value.min(1.0)).max(0.0);
        let desc = format!("PSI={:.6} — {}", psi_value,
            match &severity {
                DriftSeverity::None => "stable population",
                DriftSeverity::Low => "minor shift",
                DriftSeverity::Medium => "moderate shift, investigate",
                DriftSeverity::High => "significant shift, action recommended",
                DriftSeverity::Critical => "severe population change",
            });
        DriftResult::new(psi_value, p_value, severity, desc)
    }

    // ── Jensen-Shannon Divergence ────────────────────────────────────

    /// Jensen-Shannon divergence between two distributions.
    ///
    /// JSD(P||Q) = 0.5 * KL(P||M) + 0.5 * KL(Q||M) where M = 0.5*(P+Q)
    /// Bounded in [0, ln(2)]; normalized via sqrt(JSD/ln(2)) → [0,1].
    pub fn jensen_shannon(&self, reference: &[f64], current: &[f64]) -> DriftResult {
        if reference.is_empty() || current.is_empty() {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "Insufficient data for JSD".into());
        }

        // Compute shared bounds so both distributions use the same bin edges.
        let shared_min = reference.iter().cloned().fold(f64::INFINITY, f64::min)
            .min(current.iter().cloned().fold(f64::INFINITY, f64::min));
        let shared_max = reference.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
            .max(current.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
        let ref_dist = Distribution::from_values_with_bounds(reference, self.num_bins, shared_min, shared_max);
        let cur_dist = Distribution::from_values_with_bounds(current, self.num_bins, shared_min, shared_max);

        let mut jsd = 0.0;
        for i in 0..self.num_bins {
            let p = ref_dist.prob(i).max(self.epsilon);
            let q = cur_dist.prob(i).max(self.epsilon);
            let m = 0.5 * (p + q);
            jsd += 0.5 * (p * (p / m).ln() + q * (q / m).ln());
        }
        jsd = jsd.max(0.0);
        let ln2 = 2.0_f64.ln();
        let jsd_normalized = if ln2 > 0.0 { (jsd / ln2).sqrt().min(1.0) } else { 0.0 };

        let severity = DriftSeverity::from_score_default(jsd_normalized);
        let p_value = 1.0 - jsd_normalized;
        let desc = format!("JSD={:.6} (normalized={:.4}) — {} divergence",
            jsd, jsd_normalized,
            if jsd_normalized < 0.1 { "negligible" }
            else if jsd_normalized < 0.25 { "small" }
            else if jsd_normalized < 0.5 { "moderate" }
            else { "large" });
        DriftResult::new(jsd_normalized, p_value, severity, desc)
    }

    // ── Kullback-Leibler Divergence ───────────────────────────────────

    /// KL divergence KL(P || Q) where P=reference, Q=current.
    ///
    /// KL(P||Q) = Σ P(i) * ln(P(i) / Q(i))
    /// Asymmetric and unbounded; normalized via 1 - exp(-KL).
    pub fn kl_divergence(&self, reference: &[f64], current: &[f64]) -> DriftResult {
        if reference.is_empty() || current.is_empty() {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "Insufficient data for KL divergence".into());
        }

        // Compute shared bounds so both distributions use the same bin edges.
        let shared_min = reference.iter().cloned().fold(f64::INFINITY, f64::min)
            .min(current.iter().cloned().fold(f64::INFINITY, f64::min));
        let shared_max = reference.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
            .max(current.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
        let ref_dist = Distribution::from_values_with_bounds(reference, self.num_bins, shared_min, shared_max);
        let cur_dist = Distribution::from_values_with_bounds(current, self.num_bins, shared_min, shared_max);

        let mut kl = 0.0;
        for i in 0..self.num_bins {
            let p = ref_dist.prob(i);
            let q = cur_dist.prob(i).max(self.epsilon);
            if p > 0.0 {
                kl += p * (p / q).ln();
            }
        }
        let kl_normalized = (1.0 - (-kl).exp()).min(1.0);
        let severity = DriftSeverity::from_score_default(kl_normalized);
        let p_value = 1.0 - kl_normalized;
        let desc = format!("KL(P||Q)={:.6} (normalized={:.4}) — divergence from reference to current",
            kl, kl_normalized);
        DriftResult::new(kl_normalized, p_value, severity, desc)
    }

    // ── Chi-Squared Test ─────────────────────────────────────────────

    /// Chi-squared test for categorical/binned distributions.
    ///
    /// χ² = Σ (O_i - E_i)² / E_i
    pub fn chi_squared_test(&self, reference: &[f64], current: &[f64]) -> DriftResult {
        if reference.is_empty() || current.is_empty() {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "Insufficient data for chi-squared test".into());
        }

        let all_min = reference.iter().chain(current.iter())
            .cloned().fold(f64::INFINITY, f64::min);
        let all_max = reference.iter().chain(current.iter())
            .cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = all_max - all_min;
        let bin_width = if range.abs() < 1e-12 { 1.0 } else { range / self.num_bins as f64 };

        let ref_counts = raw_histogram_counts(reference, all_min, bin_width, self.num_bins);
        let cur_counts = raw_histogram_counts(current, all_min, bin_width, self.num_bins);

        let n_ref = reference.len() as f64;
        let n_cur = current.len() as f64;
        let mut chi_sq = 0.0;
        let mut df = 0;

        for i in 0..self.num_bins {
            let expected = (ref_counts.get(&i).copied().unwrap_or(0.0) / n_ref) * n_cur;
            if expected < 1.0 {
                continue;
            }
            let observed = cur_counts.get(&i).copied().unwrap_or(0.0);
            chi_sq += (observed - expected).powi(2) / expected;
            df += 1;
        }

        if df == 0 {
            return DriftResult::new(0.0, 1.0, DriftSeverity::None,
                "No valid bins for chi-squared test".into());
        }

        let p_value = chi_squared_p_value_approx(chi_sq, df as f64);
        let severity = if p_value < self.alpha {
            DriftSeverity::from_score_default(chi_sq / (df as f64))
        } else {
            DriftSeverity::None
        };

        let desc = if p_value < self.alpha {
            format!("Chi-squared: χ²={:.4}, df={}, p={:.6} — significant change",
                chi_sq, df, p_value)
        } else {
            format!("Chi-squared: χ²={:.4}, df={}, p={:.6} — no significant change",
                chi_sq, df, p_value)
        };
        DriftResult::new(chi_sq, p_value, severity, desc)
    }

    /// Run all five statistical tests and return a summary.
    pub fn run_all_tests(&self, reference: &[f64], current: &[f64]) -> AllTestsResult {
        AllTestsResult {
            ks: self.ks_test(reference, current),
            psi: self.psi(reference, current),
            jsd: self.jensen_shannon(reference, current),
            kl: self.kl_divergence(reference, current),
            chi_squared: self.chi_squared_test(reference, current),
        }
    }
}

impl Default for StatisticalDriftDetector {
    fn default() -> Self { Self::new() }
}

/// Aggregate result of all five statistical drift tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllTestsResult {
    pub ks: DriftResult,
    pub psi: DriftResult,
    pub jsd: DriftResult,
    pub kl: DriftResult,
    pub chi_squared: DriftResult,
}

impl AllTestsResult {
    /// Count how many tests indicate significant drift.
    pub fn significant_count(&self, alpha: f64) -> usize {
        [&self.ks, &self.psi, &self.jsd, &self.kl, &self.chi_squared]
            .iter()
            .filter(|r| r.is_significant(alpha))
            .count()
    }

    /// Compute the average drift severity score across all tests.
    pub fn aggregate_severity(&self) -> DriftSeverity {
        let avg = (self.ks.severity.to_score()
            + self.psi.severity.to_score()
            + self.jsd.severity.to_score()
            + self.kl.severity.to_score()
            + self.chi_squared.severity.to_score()) / 5.0;
        DriftSeverity::from_score_default(avg)
    }
}

// ────────────────────────────────────────────────────────────────────────
// 2. Concept Drift Detection — ADWIN
// ────────────────────────────────────────────────────────────────────────

/// ADWIN (ADaptive WINdowing) for concept drift detection in streams.
///
/// Maintains a variable-length window and detects statistically
/// significant changes in the mean using the Hoeffding bound.
/// When drift is detected, the oldest portion of the window is dropped.
///
/// Reference: Bifet & Gavaldà (2007), SDM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdwinDetector {
    /// The sliding window of observations.
    window: VecDeque<f64>,
    /// Running sum of all elements in the window.
    total_sum: f64,
    /// Running sum of squares for variance computation.
    total_sum_sq: f64,
    /// Delta confidence parameter (default 0.002).
    delta: f64,
    /// Minimum observations before checking for drift.
    min_window_size: usize,
    /// History of detected drift points.
    drift_history: Vec<AdwinDriftEvent>,
    /// Maximum window capacity.
    max_window_size: usize,
}

/// Event recorded when ADWIN detects concept drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdwinDriftEvent {
    /// Index in the stream when drift was detected.
    pub stream_index: usize,
    /// Cutpoint in the window where drift was found.
    pub cutpoint: usize,
    /// Mean of the discarded window portion.
    pub old_mean: f64,
    /// Mean of the retained window portion.
    pub new_mean: f64,
    /// Size of the discarded portion.
    pub old_size: usize,
    /// Size of the retained portion.
    pub new_size: usize,
    /// Magnitude of the mean shift.
    pub shift_magnitude: f64,
    /// Timestamp of detection.
    pub timestamp: DateTime<Utc>,
}

impl AdwinDetector {
    /// Create a new ADWIN detector with default parameters.
    pub fn new() -> Self {
        Self {
            window: VecDeque::new(),
            total_sum: 0.0,
            total_sum_sq: 0.0,
            delta: 0.002,
            min_window_size: 5,
            drift_history: Vec::new(),
            max_window_size: 10_000,
        }
    }

    /// Create with custom parameters.
    pub fn with_params(delta: f64, min_window: usize, max_window: usize) -> Self {
        Self {
            window: VecDeque::new(),
            total_sum: 0.0,
            total_sum_sq: 0.0,
            delta,
            min_window_size: min_window,
            drift_history: Vec::new(),
            max_window_size: max_window,
        }
    }

    /// Current window size.
    pub fn window_size(&self) -> usize { self.window.len() }

    /// Current mean of the window.
    pub fn window_mean(&self) -> f64 {
        if self.window.is_empty() { 0.0 } else { self.total_sum / self.window.len() as f64 }
    }

    /// Current variance of the window.
    pub fn window_variance(&self) -> f64 {
        let n = self.window.len();
        if n < 2 { return 0.0; }
        let mean = self.window_mean();
        self.total_sum_sq / n as f64 - mean * mean
    }

    /// Get a reference to the drift history.
    pub fn drift_history(&self) -> &[AdwinDriftEvent] { &self.drift_history }

    /// Process a new observation. Returns the drift event if drift was detected.
    pub fn update(&mut self, value: f64, stream_index: usize) -> Option<AdwinDriftEvent> {
        if self.window.len() >= self.max_window_size {
            if let Some(old) = self.window.pop_front() {
                self.total_sum -= old;
                self.total_sum_sq -= old * old;
            }
        }

        self.window.push_back(value);
        self.total_sum += value;
        self.total_sum_sq += value * value;

        if self.window.len() < self.min_window_size * 2 {
            return None;
        }

        let window_vec: Vec<f64> = self.window.iter().copied().collect();
        let n = window_vec.len();

        // Precompute prefix sums for O(1) sub-window variance.
        let mut prefix_sum = Vec::with_capacity(n + 1);
        let mut prefix_sq = Vec::with_capacity(n + 1);
        prefix_sum.push(0.0);
        prefix_sq.push(0.0);
        for &v in &window_vec {
            let last_s = *prefix_sum.last().unwrap();
            let last_sq = *prefix_sq.last().unwrap();
            prefix_sum.push(last_s + v);
            prefix_sq.push(last_sq + v * v);
        }

        let ln_term = (2.0 * (n as f64).ln() / self.delta).ln();
        let ln_term = if ln_term > 0.0 { ln_term } else { 0.001 };
        let delta_log = (2.0 / self.delta).ln(); // confidence factor

        let mut best_cut = None;
        let mut best_diff = 0.0;

        // Test cutpoints at linear then exponential spacing.
        let mut pos = self.min_window_size;
        while pos <= n - self.min_window_size {
            let left_mean = mean_slice(&window_vec[..pos]);
            let right_mean = mean_slice(&window_vec[pos..]);
            let diff = (left_mean - right_mean).abs();

            let n0 = pos as f64;
            let n1 = (n - pos) as f64;
            let m = 1.0 / (2.0 * n0) + 1.0 / (2.0 * n1);

            // Hoeffding bound (distribution-free, worst-case variance)
            let hoeffding_eps = (2.0 * m * ln_term).sqrt().max(0.001);

            // Variance-aware bound: uses actual sub-window variances.
            // When a sub-window mixes two distributions, its variance is
            // high, producing a larger epsilon that prevents false positives.
            let left_var = (prefix_sq[pos] / n0 - (prefix_sum[pos] / n0).powi(2)).max(0.0);
            let right_var = ((prefix_sq[n] - prefix_sq[pos]) / n1
                - ((prefix_sum[n] - prefix_sum[pos]) / n1).powi(2)).max(0.0);
            let se = (left_var / n0 + right_var / n1).sqrt();
            let variance_eps = se * delta_log.sqrt().max(0.001);

            let epsilon = hoeffding_eps.max(variance_eps);

            if diff >= epsilon && diff > best_diff {
                best_diff = diff;
                best_cut = Some(pos);
            }
            pos = if pos < 100 { pos + 1 } else { pos + (pos / 10).max(1) };
        }

        if let Some(cutpoint) = best_cut {
            let old_portion: Vec<f64> = window_vec[..cutpoint].to_vec();
            let new_portion: Vec<f64> = window_vec[cutpoint..].to_vec();
            let old_mean = mean_slice(&old_portion);
            let new_mean = mean_slice(&new_portion);

            let event = AdwinDriftEvent {
                stream_index,
                cutpoint,
                old_mean,
                new_mean,
                old_size: old_portion.len(),
                new_size: new_portion.len(),
                shift_magnitude: (old_mean - new_mean).abs(),
                timestamp: Utc::now(),
            };

            self.window = new_portion.into_iter().collect();
            self.recompute_sums();
            self.drift_history.push(event.clone());
            Some(event)
        } else {
            None
        }
    }

    /// Reset the detector state completely.
    pub fn reset(&mut self) {
        self.window.clear();
        self.total_sum = 0.0;
        self.total_sum_sq = 0.0;
        self.drift_history.clear();
    }

    /// Recompute running sums from the window contents.
    fn recompute_sums(&mut self) {
        self.total_sum = 0.0;
        self.total_sum_sq = 0.0;
        for &v in &self.window {
            self.total_sum += v;
            self.total_sum_sq += v * v;
        }
    }

    /// Classify recent drift pattern from history.
    pub fn classify_recent_drift(&self) -> DriftPattern {
        if self.drift_history.is_empty() {
            return DriftPattern::Stable;
        }
        let recent: Vec<&AdwinDriftEvent> =
            self.drift_history.iter().rev().take(10).collect();
        let recent_rev: Vec<&AdwinDriftEvent> = recent.into_iter().rev().collect();

        if recent_rev.len() == 1 {
            return DriftPattern::Sudden;
        }

        let means: Vec<f64> = recent_rev.iter().map(|e| e.new_mean).collect();
        let shifts: Vec<f64> = recent_rev.iter().map(|e| e.shift_magnitude).collect();

        // Check for recurring: alternating means with many transitions.
        let mut transitions = 0;
        let avg_mean = mean_f64(&means);
        for w in means.windows(2) {
            if (w[0] > avg_mean) != (w[1] > avg_mean) {
                transitions += 1;
            }
        }
        if transitions > means.len() / 2 && recent_rev.len() >= 4 {
            return DriftPattern::Recurring;
        }

        // Gradual: consistent direction of change.
        let signs: Vec<f64> = recent_rev.windows(2)
            .map(|w| w[1].new_mean - w[0].new_mean).collect();
        if signs.is_empty() {
            return DriftPattern::Sudden;
        }
        let first_sign = signs[0].signum();
        let same_dir = signs.iter().all(|s| s.signum() == first_sign || s.abs() < 1e-9);
        if same_dir && recent_rev.len() >= 3 {
            return DriftPattern::Gradual;
        }

        // Incremental: many small shifts of similar magnitude.
        let avg_shift = mean_f64(&shifts);
        let max_shift = shifts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        if avg_shift > 0.0 && max_shift < avg_shift * 3.0 && recent_rev.len() >= 3 {
            return DriftPattern::Incremental;
        }

        DriftPattern::Sudden
    }
}

impl Default for AdwinDetector {
    fn default() -> Self { Self::new() }
}

// ────────────────────────────────────────────────────────────────────────
// 3. Drift Pattern Classification
// ────────────────────────────────────────────────────────────────────────

/// Classification of drift patterns observed in a data stream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DriftPattern {
    /// No drift detected; system is stable.
    Stable,
    /// Abrupt, sudden shift in the data distribution.
    Sudden,
    /// Slow, continuous trend in one direction.
    Gradual,
    /// Cyclical/periodic drift that recurs over time.
    Recurring,
    /// Step-wise drift with small incremental shifts.
    Incremental,
}

impl std::fmt::Display for DriftPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftPattern::Stable => write!(f, "stable"),
            DriftPattern::Sudden => write!(f, "sudden"),
            DriftPattern::Gradual => write!(f, "gradual"),
            DriftPattern::Recurring => write!(f, "recurring"),
            DriftPattern::Incremental => write!(f, "incremental"),
        }
    }
}

/// A detected change-point in a time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    /// Index in the series where the change was detected.
    pub index: usize,
    /// Mean before the change-point.
    pub mean_before: f64,
    /// Mean after the change-point.
    pub mean_after: f64,
    /// Magnitude of the change.
    pub magnitude: f64,
    /// Confidence score for this change-point (0-1).
    pub confidence: f64,
}

/// Trend analysis result for a segment of data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    /// Estimated slope (change per observation).
    pub slope: f64,
    /// Direction of the trend.
    pub direction: TrendDirection,
    /// R-squared goodness of fit for the linear trend.
    pub r_squared: f64,
    /// Whether the trend is statistically significant.
    pub significant: bool,
}

/// Classifier for drift patterns using change-point detection and trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftPatternClassifier {
    /// Minimum segment size for change-point detection.
    pub min_segment_size: usize,
    /// Threshold for considering a slope as non-flat.
    pub slope_threshold: f64,
    /// Significance level for trend tests.
    pub trend_alpha: f64,
}

impl DriftPatternClassifier {
    pub fn new() -> Self {
        Self { min_segment_size: 5, slope_threshold: 0.01, trend_alpha: 0.05 }
    }

    pub fn with_params(min_segment: usize, slope_thresh: f64, alpha: f64) -> Self {
        Self { min_segment_size: min_segment, slope_threshold: slope_thresh, trend_alpha: alpha }
    }

    /// Detect change-points via recursive binary segmentation.
    /// For each candidate split, compute the reduction in total sum of
    /// squares. The split with the greatest reduction above 20% threshold
    /// becomes a change-point. Recurse on each sub-segment.
    pub fn detect_change_points(&self, data: &[f64]) -> Vec<ChangePoint> {
        if data.len() < self.min_segment_size * 2 {
            return Vec::new();
        }
        let mut change_points = Vec::new();
        self.find_cps_recursive(data, &mut change_points);
        change_points
    }

    fn find_cps_recursive(&self, data: &[f64], results: &mut Vec<ChangePoint>) {
        if data.len() < self.min_segment_size * 2 {
            return;
        }
        let data_mean = mean_slice(data);
        let total_ss: f64 = data.iter().map(|x| (x - data_mean).powi(2)).sum();
        if total_ss < 1e-12 {
            return;
        }

        let mut best_idx = 0;
        let mut best_reduction = 0.0;

        for i in self.min_segment_size..=(data.len() - self.min_segment_size) {
            let left = &data[..i];
            let right = &data[i..];
            let left_mean = mean_slice(left);
            let right_mean = mean_slice(right);
            let left_ss: f64 = left.iter().map(|x| (x - left_mean).powi(2)).sum();
            let right_ss: f64 = right.iter().map(|x| (x - right_mean).powi(2)).sum();
            let reduction = total_ss - left_ss - right_ss;
            if reduction > best_reduction {
                best_reduction = reduction;
                best_idx = i;
            }
        }

        if best_reduction > total_ss * 0.2 {
            let left_mean = mean_slice(&data[..best_idx]);
            let right_mean = mean_slice(&data[best_idx..]);
            results.push(ChangePoint {
                index: best_idx,
                mean_before: left_mean,
                mean_after: right_mean,
                magnitude: (right_mean - left_mean).abs(),
                confidence: (best_reduction / total_ss).min(1.0),
            });
            self.find_cps_recursive(&data[..best_idx], results);
            self.find_cps_recursive(&data[best_idx..], results);
        }
    }

    /// Analyze the linear trend via least-squares regression.
    pub fn analyze_trend(&self, data: &[f64]) -> TrendAnalysis {
        if data.len() < 2 {
            return TrendAnalysis { slope: 0.0, direction: TrendDirection::Stable,
                r_squared: 0.0, significant: false };
        }
        let n = data.len() as f64;
        let x_mean = (n - 1.0) / 2.0;
        let y_mean = mean_slice(data);
        let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
        for (i, &y) in data.iter().enumerate() {
            let dx = i as f64 - x_mean;
            let dy = y - y_mean;
            sxy += dx * dy;
            sxx += dx * dx;
            syy += dy * dy;
        }
        let slope = if sxx > 1e-12 { sxy / sxx } else { 0.0 };
        let r_squared = if syy > 1e-12 && sxx > 1e-12 {
            (sxy * sxy) / (sxx * syy)
        } else { 0.0 };
        let direction = if slope.abs() < self.slope_threshold {
            TrendDirection::Stable
        } else if slope > 0.0 { TrendDirection::Improving } else { TrendDirection::Degrading };

        let ss_res = syy - sxy * sxy / sxx.max(1e-12);
        let residual_se = if n > 2.0 && ss_res > 0.0 { (ss_res / (n - 2.0)).sqrt() } else { f64::INFINITY };
        let slope_se = residual_se / sxx.sqrt().max(1e-12);
        let t_stat = if slope_se > 0.0 && slope_se.is_finite() {
            slope.abs() / slope_se
        } else if slope.abs() > 1e-12 {
            1e6 // Perfect fit: non-zero slope with zero residuals
        } else {
            0.0
        };
        let significant = t_stat > 2.0 && r_squared > 0.1;

        TrendAnalysis { slope, direction, r_squared, significant }
    }

    /// Classify the drift pattern in a data series.
    pub fn classify(&self, data: &[f64]) -> DriftPattern {
        if data.len() < self.min_segment_size * 2 {
            return DriftPattern::Stable;
        }
        let change_points = self.detect_change_points(data);

        // Check for strong linear trend (gradual drift).
        // But: a single large change point always wins over a trend.
        let trend = self.analyze_trend(data);

        if change_points.len() == 1 {
            let avg_abs = data.iter().map(|x| x.abs()).sum::<f64>() / data.len() as f64;
            if change_points[0].magnitude > avg_abs {
                return DriftPattern::Sudden;
            }
        }

        if change_points.is_empty() {
            return if trend.significant { DriftPattern::Gradual } else { DriftPattern::Stable };
        }
        if trend.significant && trend.r_squared > 0.7 {
            return DriftPattern::Gradual;
        }
        // Check for recurring pattern.
        let segments = self.extract_segments(data, &change_points);
        if segments.len() >= 4 {
            let means: Vec<f64> = segments.iter().map(|s| mean_slice(s)).collect();
            if is_recurring_pattern(&means) {
                return DriftPattern::Recurring;
            }
        }

        // Incremental: many small changes in same direction.
        if change_points.len() >= 3 {
            let magnitudes: Vec<f64> = change_points.iter().map(|cp| cp.magnitude).collect();
            let avg_mag = mean_f64(&magnitudes);
            let max_mag = magnitudes.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            if max_mag < avg_mag * 4.0 {
                let directions: Vec<f64> = change_points.iter()
                    .map(|cp| cp.mean_after - cp.mean_before).collect();
                let pos_count = directions.iter().filter(|&&d| d > 0.0).count();
                if pos_count == 0 || pos_count == directions.len() {
                    return DriftPattern::Incremental;
                }
            }
        }

        if change_points.len() >= 2 { DriftPattern::Gradual } else { DriftPattern::Sudden }
    }

    fn extract_segments<'a>(&self, data: &'a [f64], cps: &[ChangePoint]) -> Vec<&'a [f64]> {
        let mut segments = Vec::new();
        let mut prev = 0;
        for cp in cps {
            if cp.index > prev && cp.index < data.len() {
                segments.push(&data[prev..cp.index]);
                prev = cp.index;
            }
        }
        if prev < data.len() { segments.push(&data[prev..]); }
        segments
    }
}

impl Default for DriftPatternClassifier {
    fn default() -> Self { Self::new() }
}

/// Check if a sequence of means shows a recurring (cyclical) pattern.
fn is_recurring_pattern(means: &[f64]) -> bool {
    if means.len() < 4 { return false; }
    let overall_mean = mean_f64(means);
    let above = means.iter().filter(|&&m| m > overall_mean).count();
    let below = means.len() - above;
    if above == 0 || below == 0 { return false; }
    let mut transitions = 0;
    for w in means.windows(2) {
        let a_above = w[0] > overall_mean;
        let b_above = w[1] > overall_mean;
        if a_above != b_above { transitions += 1; }
    }
    transitions > means.len() / 2
}

// ────────────────────────────────────────────────────────────────────────
// 4. Multi-Dimensional Drift
// ────────────────────────────────────────────────────────────────────────

/// Drift analysis result for a single dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionDriftResult {
    /// Name/identifier of this dimension.
    pub dimension: String,
    /// Per-test results from the statistical detector.
    pub tests: AllTestsResult,
    /// Aggregated severity for this dimension.
    pub severity: DriftSeverity,
    /// Weight assigned in aggregation.
    pub weight: f64,
    /// Weighted severity contribution.
    pub weighted_score: f64,
}

/// Multi-dimensional drift analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDimDriftResult {
    /// Per-dimension drift results.
    pub dimensions: Vec<DimensionDriftResult>,
    /// Overall aggregated drift severity.
    pub overall_severity: DriftSeverity,
    /// Overall aggregated drift score (weighted average).
    pub overall_score: f64,
    /// Dimensions ranked by drift severity (most drifting first).
    pub ranked_dimensions: Vec<(String, f64)>,
    /// Number of dimensions with significant drift.
    pub significant_count: usize,
    /// Total number of dimensions analyzed.
    pub total_dimensions: usize,
    /// Timestamp of analysis.
    pub timestamp: DateTime<Utc>,
}

/// Multi-dimensional drift detector.
///
/// Analyzes drift across multiple named dimensions simultaneously,
/// computes per-dimension scores, and aggregates with configurable weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDimDriftDetector {
    /// The underlying statistical detector.
    pub statistical_detector: StatisticalDriftDetector,
    /// Per-dimension weights (dimension name → weight).
    pub dimension_weights: HashMap<String, f64>,
    /// Default weight for unregistered dimensions.
    pub default_weight: f64,
    /// Significance level.
    pub alpha: f64,
}

impl MultiDimDriftDetector {
    /// Create a new multi-dimensional detector with equal weights.
    pub fn new() -> Self {
        Self {
            statistical_detector: StatisticalDriftDetector::new(),
            dimension_weights: HashMap::new(),
            default_weight: 1.0,
            alpha: 0.05,
        }
    }

    /// Set the weight for a specific dimension.
    pub fn set_weight(&mut self, dimension: &str, weight: f64) {
        self.dimension_weights.insert(dimension.to_string(), weight);
    }

    /// Remove a dimension's custom weight.
    pub fn remove_weight(&mut self, dimension: &str) {
        self.dimension_weights.remove(dimension);
    }

    /// Analyze drift across multiple dimensions.
    pub fn analyze(
        &self,
        reference_data: &HashMap<String, Vec<f64>>,
        current_data: &HashMap<String, Vec<f64>>,
    ) -> MultiDimDriftResult {
        let mut dim_results = Vec::new();
        let all_dims: std::collections::HashSet<&String> =
            reference_data.keys().chain(current_data.keys()).collect();

        for dim in &all_dims {
            let ref_vals = reference_data.get(*dim).cloned().unwrap_or_default();
            let cur_vals = current_data.get(*dim).cloned().unwrap_or_default();
            if ref_vals.is_empty() || cur_vals.is_empty() { continue; }

            let tests = self.statistical_detector.run_all_tests(&ref_vals, &cur_vals);
            let severity = tests.aggregate_severity();
            let weight = self.dimension_weights.get(*dim).copied().unwrap_or(self.default_weight);
            dim_results.push(DimensionDriftResult {
                dimension: (*dim).clone(), tests, severity, weight,
                weighted_score: severity.to_score() * weight,
            });
        }

        let total_weight: f64 = dim_results.iter().map(|d| d.weight).sum::<f64>().max(1e-12);
        let overall_score: f64 = dim_results.iter()
            .map(|d| (d.severity.to_score() * d.weight) / total_weight).sum();
        let overall_severity = DriftSeverity::from_score_default(overall_score);
        let significant_count = dim_results.iter()
            .filter(|d| d.tests.significant_count(self.alpha) >= 3).count();

        let mut ranked: Vec<(String, f64)> = dim_results.iter()
            .map(|d| (d.dimension.clone(), d.severity.to_score())).collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let total_dimensions = ranked.len();
        MultiDimDriftResult {
            dimensions: dim_results, overall_severity, overall_score,
            ranked_dimensions: ranked, significant_count,
            total_dimensions, timestamp: Utc::now(),
        }
    }

    /// Identify the top-N most drifting dimensions.
    pub fn top_drifting(
        &self, result: &MultiDimDriftResult, n: usize,
    ) -> Vec<(String, f64, DriftSeverity)> {
        result.dimensions.iter()
            .filter(|d| d.severity != DriftSeverity::None)
            .map(|d| (d.dimension.clone(), d.severity.to_score(), d.severity.clone()))
            .take(n).collect()
    }
}

impl Default for MultiDimDriftDetector {
    fn default() -> Self { Self::new() }
}

// ────────────────────────────────────────────────────────────────────────
// 5. Drift Impact Assessment
// ────────────────────────────────────────────────────────────────────────

/// Trust impact resulting from detected drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftTrustImpact {
    /// The drift result that caused this impact.
    pub drift_result: DriftResult,
    /// Recommended trust score adjustment (negative = decrease).
    pub trust_adjustment: f64,
    /// The trust score after adjustment.
    pub adjusted_trust: f64,
    /// Criticality of the drifting component (0.0 - 1.0).
    pub component_criticality: f64,
    /// Explanation of the impact.
    pub explanation: String,
}

/// Assesses the impact of drift on trust scores.
///
/// Maps drift severity to trust impact, considering the criticality
/// of the drifting component. Higher-criticality components cause
/// larger trust adjustments for the same drift level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftImpactAssessor {
    pub low_impact_factor: f64,
    pub medium_impact_factor: f64,
    pub high_impact_factor: f64,
    pub critical_impact_factor: f64,
    /// Maximum single-event trust reduction (absolute value).
    pub max_trust_reduction: f64,
    /// Minimum trust floor — trust cannot drop below this.
    pub trust_floor: f64,
}

impl DriftImpactAssessor {
    pub fn new() -> Self {
        Self {
            low_impact_factor: 0.02, medium_impact_factor: 0.08,
            high_impact_factor: 0.20, critical_impact_factor: 0.40,
            max_trust_reduction: 0.5, trust_floor: 0.05,
        }
    }

    pub fn with_params(
        low: f64, medium: f64, high: f64, critical: f64,
        max_reduction: f64, floor: f64,
    ) -> Self {
        Self { low_impact_factor: low, medium_impact_factor: medium,
            high_impact_factor: high, critical_impact_factor: critical,
            max_trust_reduction: max_reduction, trust_floor: floor }
    }

    /// Assess the impact of a drift event on a trust score.
    ///
    /// base_adjustment = severity_factor * (1 + component_criticality)
    /// trust_adjustment = -min(base_adjustment, max_trust_reduction)
    /// adjusted_trust = max(current_trust + trust_adjustment, trust_floor)
    pub fn assess(
        &self, drift_result: &DriftResult, current_trust: f64,
        component_criticality: f64,
    ) -> DriftTrustImpact {
        let base_factor = match &drift_result.severity {
            DriftSeverity::None => 0.0,
            DriftSeverity::Low => self.low_impact_factor,
            DriftSeverity::Medium => self.medium_impact_factor,
            DriftSeverity::High => self.high_impact_factor,
            DriftSeverity::Critical => self.critical_impact_factor,
        };
        let criticality_scale = 1.0 + component_criticality;
        let raw_adj = base_factor * criticality_scale;
        let capped_adj = raw_adj.min(self.max_trust_reduction);
        let trust_adjustment = -capped_adj;
        let adjusted_trust = (current_trust + trust_adjustment).max(self.trust_floor);

        let explanation = format!(
            "Drift severity={:?}, score={:.4}, criticality={:.2} → adjustment={:.4} ({:.4} → {:.4})",
            drift_result.severity, drift_result.score, component_criticality,
            trust_adjustment, current_trust, adjusted_trust);

        DriftTrustImpact { drift_result: drift_result.clone(), trust_adjustment,
            adjusted_trust, component_criticality, explanation }
    }

    /// Assess multi-dimensional drift impact on trust using worst dimension.
    pub fn assess_multi_dim(
        &self, multi_result: &MultiDimDriftResult, current_trust: f64,
        component_criticalities: &HashMap<String, f64>,
    ) -> DriftTrustImpact {
        let worst_dim = multi_result.dimensions.iter().max_by(|a, b| {
            a.severity.to_score().partial_cmp(&b.severity.to_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let (drift_result, criticality) = match worst_dim {
            Some(dim) => {
                let candidates = [&dim.tests.ks, &dim.tests.psi, &dim.tests.jsd,
                    &dim.tests.kl, &dim.tests.chi_squared];
                let best = candidates.iter().max_by(|a, b| {
                    a.severity.to_score().partial_cmp(&b.severity.to_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                }).unwrap();
                let crit = component_criticalities.get(&dim.dimension).copied().unwrap_or(0.5);
                ((*best).clone(), crit)
            }
            None => (DriftResult::new(0.0, 1.0, DriftSeverity::None, "No drift".into()), 0.0),
        };
        self.assess(&drift_result, current_trust, criticality)
    }
}

impl Default for DriftImpactAssessor {
    fn default() -> Self { Self::new() }
}

// ────────────────────────────────────────────────────────────────────────
// 6. Baseline Management
// ────────────────────────────────────────────────────────────────────────

/// A named baseline capturing a reference distribution at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    /// Unique identifier for this baseline.
    pub id: String,
    /// Human-readable label (e.g., "v2.1 release").
    pub label: String,
    /// The reference distribution data (dimension → values).
    pub reference_data: HashMap<String, Vec<f64>>,
    /// When this baseline was established.
    pub created_at: DateTime<Utc>,
    /// Number of observations used to build this baseline.
    pub observation_count: usize,
    /// Summary statistics per dimension for quick comparison.
    pub summaries: HashMap<String, BaselineSummary>,
}

/// Summary statistics for a single dimension's baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineSummary {
    /// Number of observations.
    pub count: usize,
    /// Mean value.
    pub mean: f64,
    /// Standard deviation.
    pub std_dev: f64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
    /// Median (approximate from sorted data).
    pub median: f64,
    /// 25th percentile.
    pub p25: f64,
    /// 75th percentile.
    pub p75: f64,
}

impl BaselineSummary {
    /// Compute summary statistics from a slice of observations.
    pub fn from_values(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self { count: 0, mean: 0.0, std_dev: 0.0,
                min: 0.0, max: 0.0, median: 0.0, p25: 0.0, p75: 0.0 };
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let mean = mean_slice(&sorted);
        let variance = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n.max(1) as f64;
        let min = sorted[0];
        let max = sorted[n - 1];
        let median = percentile(&sorted, 0.5);
        let p25 = percentile(&sorted, 0.25);
        let p75 = percentile(&sorted, 0.75);
        Self { count: n, mean, std_dev: variance.sqrt(), min, max, median, p25, p75 }
    }
}

/// Manages multiple baselines and determines when a new one should be created.
///
/// A new baseline is established when:
///   - A legitimate, authorized change is confirmed (e.g., new deployment)
///   - The accumulated drift from the current baseline exceeds a threshold
///     AND a domain expert confirms the change is permanent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManager {
    /// All registered baselines, keyed by ID.
    baselines: HashMap<String, Baseline>,
    /// ID of the currently active baseline.
    active_baseline_id: Option<String>,
    /// Statistical detector used for baseline comparisons.
    detector: StatisticalDriftDetector,
    /// Threshold score above which a baseline refresh is recommended.
    refresh_threshold: f64,
    /// Maximum number of historical baselines to retain.
    max_baselines: usize,
    /// Counter for generating unique baseline IDs.
    next_id: u64,
}

/// Recommendation from the baseline manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRecommendation {
    /// Whether a new baseline should be created.
    pub should_create: bool,
    /// Reason for the recommendation.
    pub reason: String,
    /// Drift score that triggered the recommendation.
    pub drift_score: f64,
    /// Severity of drift from the active baseline.
    pub severity: DriftSeverity,
}

impl BaselineManager {
    /// Create a new baseline manager with default settings.
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            active_baseline_id: None,
            detector: StatisticalDriftDetector::new(),
            refresh_threshold: 0.5,
            max_baselines: 20,
            next_id: 1,
        }
    }

    /// Create with custom parameters.
    pub fn with_params(refresh_threshold: f64, max_baselines: usize) -> Self {
        Self { refresh_threshold, max_baselines, ..Self::new() }
    }

    /// Register a new baseline from observed data.
    pub fn create_baseline(
        &mut self, label: String,
        data: HashMap<String, Vec<f64>>,
    ) -> String {
        let id = format!("baseline_{}", self.next_id);
        self.next_id += 1;

        let total_obs: usize = data.values().map(|v| v.len()).max().unwrap_or(0);
        let mut summaries = HashMap::new();
        for (dim, values) in &data {
            summaries.insert(dim.clone(), BaselineSummary::from_values(values));
        }

        let baseline = Baseline {
            id: id.clone(), label, reference_data: data,
            created_at: Utc::now(), observation_count: total_obs, summaries,
        };
        self.baselines.insert(id.clone(), baseline);
        self.active_baseline_id = Some(id.clone());

        // Enforce max baselines by removing the oldest.
        while self.baselines.len() > self.max_baselines {
            if let Some(oldest_id) = self.baselines.iter()
                .min_by_key(|(_, b)| b.created_at).map(|(k, _)| k.clone()) {
                self.baselines.remove(&oldest_id);
                if self.active_baseline_id.as_deref() == Some(&oldest_id) {
                    self.active_baseline_id = None;
                }
            } else { break; }
        }
        id
    }

    /// Get the currently active baseline.
    pub fn active_baseline(&self) -> Option<&Baseline> {
        self.active_baseline_id.as_ref().and_then(|id| self.baselines.get(id))
    }

    /// Set the active baseline by ID.
    pub fn set_active(&mut self, id: &str) -> bool {
        if self.baselines.contains_key(id) {
            self.active_baseline_id = Some(id.to_string());
            true
        } else { false }
    }

    /// List all baseline IDs and labels.
    pub fn list_baselines(&self) -> Vec<(String, String, DateTime<Utc>)> {
        let mut list: Vec<_> = self.baselines.values()
            .map(|b| (b.id.clone(), b.label.clone(), b.created_at)).collect();
        list.sort_by(|a, b| a.2.cmp(&b.2));
        list
    }

    /// Compare current data against the active baseline.
    /// Returns per-dimension drift results.
    pub fn compare_against_active(
        &self, current_data: &HashMap<String, Vec<f64>>,
    ) -> HashMap<String, AllTestsResult> {
        let mut results = HashMap::new();
        if let Some(baseline) = self.active_baseline() {
            for (dim, cur_vals) in current_data {
                if let Some(ref_vals) = baseline.reference_data.get(dim) {
                    results.insert(dim.clone(), self.detector.run_all_tests(ref_vals, cur_vals));
                }
            }
        }
        results
    }

    /// Determine whether a new baseline should be established.
    pub fn recommend_baseline_refresh(
        &self, current_data: &HashMap<String, Vec<f64>>,
    ) -> BaselineRecommendation {
        let comparisons = self.compare_against_active(current_data);
        if comparisons.is_empty() {
            return BaselineRecommendation {
                should_create: true,
                reason: "No active baseline exists".into(),
                drift_score: 1.0, severity: DriftSeverity::Critical,
            };
        }

        let total_severity: f64 = comparisons.values()
            .map(|r| r.aggregate_severity().to_score()).sum::<f64>()
            / comparisons.len().max(1) as f64;
        let severity = DriftSeverity::from_score_default(total_severity);
        let should_create = total_severity > self.refresh_threshold;

        let reason = if should_create {
            format!("Drift score {:.4} exceeds refresh threshold {:.4}; new baseline recommended",
                total_severity, self.refresh_threshold)
        } else {
            format!("Drift score {:.4} within acceptable range", total_severity)
        };

        BaselineRecommendation { should_create, reason, drift_score: total_severity, severity }
    }

    /// Remove a baseline by ID.
    pub fn remove_baseline(&mut self, id: &str) -> bool {
        let removed = self.baselines.remove(id).is_some();
        if removed && self.active_baseline_id.as_deref() == Some(id) {
            self.active_baseline_id = None;
        }
        removed
    }

    /// Number of registered baselines.
    pub fn baseline_count(&self) -> usize { self.baselines.len() }
}

impl Default for BaselineManager {
    fn default() -> Self { Self::new() }
}

// ────────────────────────────────────────────────────────────────────────
// Helper functions
// ────────────────────────────────────────────────────────────────────────

/// Merge two sorted vectors into one sorted vector.
fn merge_sorted(a: &[f64], b: &[f64]) -> Vec<f64> {
    let mut result = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] <= b[j] { result.push(a[i]); i += 1; }
        else { result.push(b[j]); j += 1; }
    }
    while i < a.len() { result.push(a[i]); i += 1; }
    while j < b.len() { result.push(b[j]); j += 1; }
    result
}

/// Kolmogorov asymptotic p-value.
/// p ≈ 2 * Σ_{k=1}^{∞} (-1)^{k+1} * exp(-2 * k² * λ²)
fn kolmogorov_p_value(lambda: f64) -> f64 {
    if lambda <= 0.0 { return 1.0; }
    let mut sum = 0.0;
    let mut sign = 1.0;
    for k in 1..=100 {
        let term = 2.0 * (k as f64).powi(2) * lambda * lambda;
        if term > 700.0 { break; } // exp overflow guard
        let contribution = sign * (-term).exp();
        if contribution.abs() < 1e-15 { break; }
        sum += contribution;
        sign *= -1.0;
    }
    (2.0 * sum).max(0.0).min(1.0)
}

/// Build a probability histogram with shared binning.
fn histogram_probs(
    values: &[f64], min: f64, bin_width: f64, num_bins: usize,
) -> HashMap<usize, f64> {
    let mut counts: HashMap<usize, f64> = HashMap::new();
    for &v in values {
        let idx = if bin_width > 0.0 {
            ((v - min) / bin_width).floor() as usize
        } else { 0 };
        let idx = idx.min(num_bins - 1);
        *counts.entry(idx).or_insert(0.0) += 1.0;
    }
    let total = values.len() as f64;
    for prob in counts.values_mut() { *prob /= total; }
    counts
}

/// Build a raw count histogram.
fn raw_histogram_counts(
    values: &[f64], min: f64, bin_width: f64, num_bins: usize,
) -> HashMap<usize, f64> {
    let mut counts: HashMap<usize, f64> = HashMap::new();
    for &v in values {
        let idx = if bin_width > 0.0 {
            ((v - min) / bin_width).floor() as usize
        } else { 0 };
        let idx = idx.min(num_bins - 1);
        *counts.entry(idx).or_insert(0.0) += 1.0;
    }
    counts
}

/// Approximate p-value for chi-squared distribution.
/// Uses the regularized lower incomplete gamma function for small x/df,
/// and the continued fraction (Legendre) for the upper tail when x/df is large.
fn chi_squared_p_value_approx(chi_sq: f64, df: f64) -> f64 {
    if chi_sq <= 0.0 { return 1.0; }
    if df <= 0.0 { return 0.0; }
    let half_df = df / 2.0;
    let half_chi = chi_sq / 2.0;

    // For large chi_sq relative to df, use the continued fraction for
    // the upper tail Q(a, x) directly. This converges quickly for large x.
    if half_chi > half_df + 1.0 {
        return chi_squared_cf_upper(half_df, half_chi);
    }

    // Compute prefix: e^(-x) * x^a / Gamma(a) using log-space to avoid overflow.
    // ln(prefix) = -x + a*ln(x) - ln(Gamma(a))
    let ln_prefix = -half_chi + half_df * half_chi.ln() - ln_gamma(half_df);
    let prefix = ln_prefix.exp();
    // Series: sum_{k=0} x^k / (a*(a+1)*...*(a+k))
    let mut sum = 1.0;
    let mut term = 1.0;
    for k in 1..=10000 {
        term *= half_chi / (half_df + k as f64);
        sum += term;
        if term.abs() < sum * 1e-15 { break; }
    }
    let p_lower = (prefix * sum).min(1.0);
    // p_value = upper tail probability (1 - CDF).
    (1.0 - p_lower).max(0.0).min(1.0)
}

/// Compute the upper tail Q(a, x) of the regularized incomplete gamma function
/// using the continued fraction representation (Lentz's method).
/// This converges quickly when x > a.
fn chi_squared_cf_upper(a: f64, x: f64) -> f64 {
    // Compute prefix: e^(-x) * x^a / Gamma(a) in log-space.
    let ln_prefix = -x + a * x.ln() - ln_gamma(a);
    let prefix = ln_prefix.exp();

    // Continued fraction: 1/(x + 1-a + 1/(1 + 1/(x + 2-a + 2/(1 + ...))))
    // Using modified Lentz's method with b_0 = x+1-a, a_n = -n*(n-a), b_n = x + 2n + 1 - a.
    let tiny = 1e-30;
    let mut b = x + 1.0 - a;
    if b.abs() < tiny { b = tiny; }
    let mut c = b;
    let mut d = 0.0;
    let mut f = 1.0 / b;

    for n in 1..=500 {
        let an = -(n as f64) * (n as f64 - a);
        let bn = x + 2.0 * n as f64 + 1.0 - a;
        d = bn + an * d;
        if d.abs() < tiny { d = tiny; }
        d = 1.0 / d;
        c = bn + an / c;
        if c.abs() < tiny { c = tiny; }
        let delta = d * c;
        f *= delta;
        if (delta - 1.0).abs() < 1e-15 { break; }
    }

    let q = (f * prefix).min(1.0);
    q.max(0.0).min(1.0)
}

/// Mean of a slice.
fn mean_slice(data: &[f64]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<f64>() / data.len() as f64
}

/// Mean of a Vec<f64>.
fn mean_f64(data: &[f64]) -> f64 { mean_slice(data) }

/// Approximate percentile from sorted data (linear interpolation).
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    if sorted.len() == 1 { return sorted[0]; }
    let idx = p * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate n values from a normal-like distribution using Box-Muller.
    fn normal_samples(mean: f64, std: f64, n: usize) -> Vec<f64> {
        let mut samples = Vec::with_capacity(n);
        let mut seed = 42u64;
        for _ in 0..n {
            // Simple LCG pseudo-random for deterministic tests.
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let u1 = ((seed >> 33) as f64) / ((1u64 << 31) as f64);
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let u2 = ((seed >> 33) as f64) / ((1u64 << 31) as f64);
            let z0 = (-2.0 * u1.max(1e-10).ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            samples.push(mean + z0 * std);
        }
        samples
    }

    // ── DriftSeverity tests ───────────────────────────────────────────

    #[test]
    fn test_severity_to_score_roundtrip() {
        assert_eq!(DriftSeverity::None.to_score(), 0.0);
        assert_eq!(DriftSeverity::Low.to_score(), 0.25);
        assert_eq!(DriftSeverity::Medium.to_score(), 0.5);
        assert_eq!(DriftSeverity::High.to_score(), 0.75);
        assert_eq!(DriftSeverity::Critical.to_score(), 1.0);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(DriftSeverity::from_score(0.05, 0.1, 0.25, 0.5), DriftSeverity::None);
        assert_eq!(DriftSeverity::from_score(0.15, 0.1, 0.25, 0.5), DriftSeverity::Low);
        assert_eq!(DriftSeverity::from_score(0.3, 0.1, 0.25, 0.5), DriftSeverity::Medium);
        assert_eq!(DriftSeverity::from_score(0.6, 0.1, 0.25, 0.5), DriftSeverity::High);
        assert_eq!(DriftSeverity::from_score(1.0, 0.1, 0.25, 0.5), DriftSeverity::Critical);
    }

    // ── KS test tests ─────────────────────────────────────────────────

    #[test]
    fn test_ks_same_distribution() {
        let det = StatisticalDriftDetector::new();
        let data = normal_samples(0.0, 1.0, 200);
        let result = det.ks_test(&data[..100], &data[100..]);
        assert!(result.p_value > 0.01, "Same dist should have high p-value, got {}", result.p_value);
        assert_eq!(result.severity, DriftSeverity::None);
    }

    #[test]
    fn test_ks_different_distributions() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 1.0, 200);
        let cur_data = normal_samples(5.0, 1.0, 200);
        let result = det.ks_test(&ref_data, &cur_data);
        assert!(result.score > 0.3, "Different dists should have large D, got {}", result.score);
        assert!(result.p_value < 0.05, "p-value should be small, got {}", result.p_value);
    }

    #[test]
    fn test_ks_empty_data() {
        let det = StatisticalDriftDetector::new();
        let result = det.ks_test(&[], &[1.0, 2.0]);
        assert_eq!(result.severity, DriftSeverity::None);
    }

    // ── PSI test tests ────────────────────────────────────────────────

    #[test]
    fn test_psi_stable() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 1.0, 500);
        let cur_data = normal_samples(0.0, 1.0, 500);
        let result = det.psi(&ref_data, &cur_data);
        assert!(result.score < 0.2, "PSI should be low for stable data, got {}", result.score);
    }

    #[test]
    fn test_psi_drifted() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 1.0, 500);
        let cur_data = normal_samples(3.0, 1.0, 500);
        let result = det.psi(&ref_data, &cur_data);
        assert!(result.score > 0.25, "PSI should be high for drifted data, got {}", result.score);
    }

    // ── JSD test tests ────────────────────────────────────────────────

    #[test]
    fn test_jsd_same_distribution() {
        let det = StatisticalDriftDetector::new();
        let data = normal_samples(0.0, 1.0, 200);
        let result = det.jensen_shannon(&data[..100], &data[100..]);
        assert!(result.score < 0.3, "JSD should be low for same dist, got {}", result.score);
    }

    #[test]
    fn test_jsd_different_distributions() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 0.5, 200);
        let cur_data = normal_samples(4.0, 0.5, 200);
        let result = det.jensen_shannon(&ref_data, &cur_data);
        assert!(result.score > 0.3, "JSD should be high for different dists, got {}", result.score);
    }

    // ── KL divergence tests ───────────────────────────────────────────

    #[test]
    fn test_kl_same_distribution() {
        let det = StatisticalDriftDetector::new();
        let data = normal_samples(0.0, 1.0, 200);
        let result = det.kl_divergence(&data[..100], &data[100..]);
        assert!(result.score < 0.3, "KL should be low for same dist, got {}", result.score);
    }

    #[test]
    fn test_kl_different_distributions() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 1.0, 300);
        let cur_data = normal_samples(5.0, 1.0, 300);
        let result = det.kl_divergence(&ref_data, &cur_data);
        assert!(result.score > 0.3, "KL should be high for different dists, got {}", result.score);
    }

    // ── Chi-squared tests ─────────────────────────────────────────────

    #[test]
    fn test_chi_sq_same_distribution() {
        let det = StatisticalDriftDetector::new();
        let data = normal_samples(0.0, 1.0, 300);
        let result = det.chi_squared_test(&data[..150], &data[150..]);
        assert!(result.p_value > 0.01, "Same dist p-value should be high, got {}", result.p_value);
    }

    #[test]
    fn test_chi_sq_different_distributions() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 0.5, 300);
        let cur_data = normal_samples(4.0, 0.5, 300);
        let result = det.chi_squared_test(&ref_data, &cur_data);
        assert!(result.p_value < 0.05, "p-value should be small, got {}", result.p_value);
    }

    // ── All tests aggregate ───────────────────────────────────────────

    #[test]
    fn test_run_all_tests() {
        let det = StatisticalDriftDetector::new();
        let ref_data = normal_samples(0.0, 1.0, 200);
        let cur_data = normal_samples(3.0, 1.0, 200);
        let results = det.run_all_tests(&ref_data, &cur_data);
        assert!(results.significant_count(0.05) >= 2,
            "Expected at least 2 significant tests, got {}", results.significant_count(0.05));
    }

    // ── ADWIN tests ───────────────────────────────────────────────────

    #[test]
    fn test_adwin_stable_stream() {
        let mut det = AdwinDetector::new();
        let data = normal_samples(5.0, 0.5, 200);
        let mut drift_count = 0;
        for (i, &v) in data.iter().enumerate() {
            if det.update(v, i).is_some() { drift_count += 1; }
        }
        assert!(drift_count <= 1, "Stable stream should have ≤ 1 drift, got {}", drift_count);
    }

    #[test]
    fn test_adwin_abrupt_drift() {
        let mut det = AdwinDetector::new();
        let stable = normal_samples(0.0, 0.5, 100);
        let shifted = normal_samples(5.0, 0.5, 100);
        let mut drift_found = false;
        let mut idx = 0;
        for &v in &stable { det.update(v, idx); idx += 1; }
        for &v in &shifted {
            if let Some(event) = det.update(v, idx) {
                drift_found = true;
                assert!(event.shift_magnitude > 2.0,
                    "Shift magnitude should be large, got {}", event.shift_magnitude);
                break;
            }
            idx += 1;
        }
        assert!(drift_found, "Should detect abrupt drift");
    }

    #[test]
    fn test_adwin_window_mean_variance() {
        let mut det = AdwinDetector::new();
        for v in &[1.0, 2.0, 3.0, 4.0, 5.0] { det.update(*v, 0); }
        assert!((det.window_mean() - 3.0).abs() < 0.01);
        assert!(det.window_variance() > 0.0);
    }

    #[test]
    fn test_adwin_reset() {
        let mut det = AdwinDetector::new();
        for v in &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0] {
            det.update(*v, 0);
        }
        det.reset();
        assert_eq!(det.window_size(), 0);
        assert_eq!(det.drift_history().len(), 0);
    }

    #[test]
    fn test_adwin_classify_recent_drift_stable() {
        let det = AdwinDetector::new();
        assert_eq!(det.classify_recent_drift(), DriftPattern::Stable);
    }

    // ── DriftPatternClassifier tests ──────────────────────────────────

    #[test]
    fn test_classify_stable() {
        let cls = DriftPatternClassifier::new();
        let data = normal_samples(5.0, 0.1, 100);
        assert_eq!(cls.classify(&data), DriftPattern::Stable);
    }

    #[test]
    fn test_classify_sudden() {
        let cls = DriftPatternClassifier::with_params(10, 0.001, 0.05);
        let mut data = normal_samples(0.0, 0.1, 50);
        data.extend(normal_samples(10.0, 0.1, 50));
        let pattern = cls.classify(&data);
        assert_eq!(pattern, DriftPattern::Sudden);
    }

    #[test]
    fn test_classify_gradual() {
        let cls = DriftPatternClassifier::with_params(5, 0.001, 0.05);
        let data: Vec<f64> = (0..100).map(|i| 0.0 + i as f64 * 0.1).collect();
        let pattern = cls.classify(&data);
        assert_eq!(pattern, DriftPattern::Gradual);
    }

    #[test]
    fn test_detect_change_points() {
        let cls = DriftPatternClassifier::new();
        let mut data = vec![0.0; 50];
        data.extend(vec![10.0; 50]);
        let cps = cls.detect_change_points(&data);
        assert!(!cps.is_empty(), "Should detect at least one change-point");
        assert!(cps[0].index > 40 && cps[0].index <= 55,
            "Change-point should be near index 50, got {}", cps[0].index);
    }

    #[test]
    fn test_analyze_trend_increasing() {
        let cls = DriftPatternClassifier::new();
        let data: Vec<f64> = (0..50).map(|i| i as f64 * 0.5).collect();
        let trend = cls.analyze_trend(&data);
        assert_eq!(trend.direction, TrendDirection::Improving);
        assert!(trend.significant);
        assert!(trend.r_squared > 0.9);
    }

    #[test]
    fn test_analyze_trend_flat() {
        let cls = DriftPatternClassifier::new();
        let data = vec![5.0; 50];
        let trend = cls.analyze_trend(&data);
        assert_eq!(trend.direction, TrendDirection::Stable);
    }

    // ── Multi-dimensional drift tests ─────────────────────────────────

    #[test]
    fn test_multi_dim_no_drift() {
        let det = MultiDimDriftDetector::new();
        let mut ref_data = HashMap::new();
        let mut cur_data = HashMap::new();
        ref_data.insert("a".to_string(), normal_samples(0.0, 1.0, 200));
        ref_data.insert("b".to_string(), normal_samples(5.0, 1.0, 200));
        cur_data.insert("a".to_string(), normal_samples(0.0, 1.0, 200));
        cur_data.insert("b".to_string(), normal_samples(5.0, 1.0, 200));
        let result = det.analyze(&ref_data, &cur_data);
        assert_eq!(result.total_dimensions, 2);
        assert!(result.overall_score < 0.5, "Overall score should be low, got {}", result.overall_score);
    }

    #[test]
    fn test_multi_dim_with_drift() {
        let det = MultiDimDriftDetector::new();
        let mut ref_data = HashMap::new();
        let mut cur_data = HashMap::new();
        ref_data.insert("x".to_string(), normal_samples(0.0, 1.0, 300));
        cur_data.insert("x".to_string(), normal_samples(6.0, 1.0, 300));
        let result = det.analyze(&ref_data, &cur_data);
        assert!(result.overall_score > 0.25, "Score should be high with drift, got {}", result.overall_score);
    }

    #[test]
    fn test_multi_dim_weighted() {
        let mut det = MultiDimDriftDetector::new();
        det.set_weight("critical_dim", 10.0);
        det.set_weight("minor_dim", 1.0);
        let mut ref_data = HashMap::new();
        let mut cur_data = HashMap::new();
        ref_data.insert("critical_dim".to_string(), normal_samples(0.0, 1.0, 200));
        ref_data.insert("minor_dim".to_string(), normal_samples(0.0, 1.0, 200));
        cur_data.insert("critical_dim".to_string(), normal_samples(3.0, 1.0, 200));
        cur_data.insert("minor_dim".to_string(), normal_samples(0.0, 1.0, 200));
        let result = det.analyze(&ref_data, &cur_data);
        assert!(result.overall_score > 0.1);
    }

    // ── DriftImpactAssessor tests ─────────────────────────────────────

    #[test]
    fn test_impact_none_severity() {
        let assessor = DriftImpactAssessor::new();
        let result = DriftResult::new(0.0, 0.5, DriftSeverity::None, "ok".into());
        let impact = assessor.assess(&result, 0.9, 0.5);
        assert_eq!(impact.trust_adjustment, 0.0);
        assert!((impact.adjusted_trust - 0.9).abs() < 1e-9);
    }

    #[test]
    fn test_impact_critical_severity() {
        let assessor = DriftImpactAssessor::new();
        let result = DriftResult::new(0.9, 0.001, DriftSeverity::Critical, "severe".into());
        let impact = assessor.assess(&result, 0.9, 0.8);
        assert!(impact.trust_adjustment < 0.0, "Trust should decrease");
        assert!(impact.adjusted_trust < 0.9);
        assert!(impact.adjusted_trust >= 0.05); // Trust floor.
    }

    #[test]
    fn test_impact_trust_floor() {
        let assessor = DriftImpactAssessor::new();
        let result = DriftResult::new(1.0, 0.0, DriftSeverity::Critical, "max".into());
        let impact = assessor.assess(&result, 0.01, 1.0);
        assert!(impact.adjusted_trust >= 0.05, "Should not go below floor");
    }

    #[test]
    fn test_impact_criticality_scaling() {
        let assessor = DriftImpactAssessor::new();
        let result = DriftResult::new(0.5, 0.01, DriftSeverity::High, "high".into());
        let low_crit = assessor.assess(&result, 0.9, 0.0);
        let high_crit = assessor.assess(&result, 0.9, 1.0);
        assert!(low_crit.trust_adjustment > high_crit.trust_adjustment,
            "Higher criticality → larger negative adjustment");
        assert!(high_crit.adjusted_trust < low_crit.adjusted_trust);
    }

    // ── Baseline management tests ─────────────────────────────────────

    #[test]
    fn test_baseline_create_and_retrieve() {
        let mut mgr = BaselineManager::new();
        let mut data = HashMap::new();
        data.insert("dim1".to_string(), normal_samples(0.0, 1.0, 100));
        let id = mgr.create_baseline("v1.0".into(), data);
        let baseline = mgr.active_baseline().unwrap();
        assert_eq!(baseline.id, id);
        assert_eq!(baseline.label, "v1.0");
        assert!(baseline.summaries.contains_key("dim1"));
    }

    #[test]
    fn test_baseline_compare() {
        let mut mgr = BaselineManager::new();
        let mut ref_data = HashMap::new();
        ref_data.insert("d".to_string(), normal_samples(0.0, 1.0, 200));
        mgr.create_baseline("ref".into(), ref_data);

        let mut cur_data = HashMap::new();
        cur_data.insert("d".to_string(), normal_samples(0.0, 1.0, 200));
        let comparisons = mgr.compare_against_active(&cur_data);
        assert!(comparisons.contains_key("d"));
    }

    #[test]
    fn test_baseline_recommendation_no_baseline() {
        let mgr = BaselineManager::new();
        let cur_data = HashMap::new();
        let rec = mgr.recommend_baseline_refresh(&cur_data);
        assert!(rec.should_create);
    }

    #[test]
    fn test_baseline_max_limit() {
        let mut mgr = BaselineManager::with_params(0.5, 3);
        for i in 0..5 {
            let mut data = HashMap::new();
            data.insert("d".to_string(), vec![i as f64]);
            mgr.create_baseline(format!("b{}", i), data);
        }
        assert!(mgr.baseline_count() <= 3);
    }

    #[test]
    fn test_baseline_remove() {
        let mut mgr = BaselineManager::new();
        let id = mgr.create_baseline("temp".into(), HashMap::new());
        assert!(mgr.remove_baseline(&id));
        assert_eq!(mgr.active_baseline(), None);
    }

    #[test]
    fn test_baseline_summary_statistics() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let summary = BaselineSummary::from_values(&values);
        assert!((summary.mean - 5.5).abs() < 0.01);
        assert_eq!(summary.min, 1.0);
        assert_eq!(summary.max, 10.0);
        assert_eq!(summary.count, 10);
        assert!(summary.std_dev > 0.0);
        assert!(summary.p25 < summary.median);
        assert!(summary.median < summary.p75);
    }

    // ── Helper function tests ─────────────────────────────────────────

    #[test]
    fn test_merge_sorted() {
        let a = vec![1.0, 3.0, 5.0];
        let b = vec![2.0, 4.0, 6.0];
        let merged = merge_sorted(&a, &b);
        assert_eq!(merged, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    }

    #[test]
    fn test_kolmogorov_p_value_bounds() {
        assert!((kolmogorov_p_value(0.0) - 1.0).abs() < 1e-9);
        assert!(kolmogorov_p_value(10.0) < 0.01);
        assert!(kolmogorov_p_value(0.5) > 0.5);
    }

    #[test]
    fn test_percentile() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&sorted, 0.5) - 3.0).abs() < 0.01);
        assert_eq!(percentile(&sorted, 0.0), 1.0);
        assert_eq!(percentile(&sorted, 1.0), 5.0);
    }

    #[test]
    fn test_distribution_cdf() {
        let dist = Distribution::from_values(&vec![1.0, 2.0, 3.0, 4.0, 5.0], 5);
        assert!(dist.cdf_at(0.0) <= 0.0);
        assert!(dist.cdf_at(6.0) >= 0.9);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let det = StatisticalDriftDetector::with_params(20, 1e-12, 0.01);
        let json = serde_json::to_string(&det).unwrap();
        let deserialized: StatisticalDriftDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(det.num_bins, deserialized.num_bins);
        assert_eq!(det.alpha, deserialized.alpha);
    }
}
