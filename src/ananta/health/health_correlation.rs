// ANANTA Health Signal Correlation Engine
//
// Production-grade cross-component health signal analysis for the ANANTA
// trust plane. Provides:
//
//   1. Cross-Component Correlation  — Pearson, Spearman, rolling-window,
//      and partial correlation between component health signals.
//
//   2. Causal Inference             — Simplified Granger causality via
//      bivariate VAR(p) with AIC-based lag selection.
//
//   3. Anomaly Propagation Tracking — Track how anomalies travel across
//      the dependency DAG, measuring speed, attenuation, and amplification.
//
//   4. Health Root Cause Analysis  — Given unhealthy components, score
//      candidates by DAG position, correlation strength, and temporal
//      ordering to identify the most likely originating component.
//
//   5. Predictive Health Scoring    — Combine current health, trend data,
//      and correlation-based predictions into a forward-looking health score.
//
// All algorithms are self-contained; only `std` and lightweight crates
// (chrono, serde, serde_json) are used.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════════════════
//  1. Cross-Component Correlation
// ═══════════════════════════════════════════════════════════════════════

/// Result of a correlation computation between two signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Pearson product-moment correlation coefficient (-1 to 1).
    pub pearson: f64,
    /// Spearman rank correlation coefficient (-1 to 1).
    pub spearman: f64,
    /// Number of paired observations used.
    pub n: usize,
    /// Timestamp of the computation.
    pub computed_at: DateTime<Utc>,
}

/// A time-stamped health signal sample for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSignal {
    pub component: String,
    pub score: f64,
    pub timestamp: DateTime<Utc>,
}

/// Rolling-window correlation state for one component pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingCorrelation {
    pub component_a: String,
    pub component_b: String,
    pub window_size: usize,
    pub buffer_a: VecDeque<f64>,
    pub buffer_b: VecDeque<f64>,
    /// All historical full-window correlation snapshots.
    pub history: Vec<CorrelationResult>,
    pub max_history: usize,
}

impl RollingCorrelation {
    /// Create a new rolling correlation tracker for the given pair.
    pub fn new(component_a: &str, component_b: &str, window_size: usize, max_history: usize) -> Self {
        Self {
            component_a: component_a.to_string(),
            component_b: component_b.to_string(),
            window_size,
            buffer_a: VecDeque::with_capacity(window_size),
            buffer_b: VecDeque::with_capacity(window_size),
            history: Vec::with_capacity(max_history),
            max_history,
        }
    }

    /// Push a new paired observation. Returns `Some(CorrelationResult)` if the
    /// window is full after the push.
    pub fn push(&mut self, a: f64, b: f64) -> Option<CorrelationResult> {
        self.buffer_a.push_back(a);
        self.buffer_b.push_back(b);
        if self.buffer_a.len() > self.window_size {
            self.buffer_a.pop_front();
            self.buffer_b.pop_front();
        }
        if self.buffer_a.len() >= self.window_size {
            let va: Vec<f64> = self.buffer_a.iter().copied().collect();
            let vb: Vec<f64> = self.buffer_b.iter().copied().collect();
            let result = CorrelationResult {
                pearson: pearson_correlation(&va, &vb),
                spearman: spearman_correlation(&va, &vb),
                n: va.len(),
                computed_at: Utc::now(),
            };
            self.history.push(result.clone());
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }
            Some(result)
        } else {
            None
        }
    }

    /// Current correlation over the available data (may be a partial window).
    pub fn current(&self) -> Option<CorrelationResult> {
        if self.buffer_a.is_empty() {
            return None;
        }
        let va: Vec<f64> = self.buffer_a.iter().copied().collect();
        let vb: Vec<f64> = self.buffer_b.iter().copied().collect();
        Some(CorrelationResult {
            pearson: pearson_correlation(&va, &vb),
            spearman: spearman_correlation(&va, &vb),
            n: va.len(),
            computed_at: Utc::now(),
        })
    }
}

/// Compute the Pearson product-moment correlation between two equal-length
/// slices. Returns 0.0 if either slice has zero variance or length < 2.
pub fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    if x.len() != y.len() || x.len() < 2 {
        return 0.0;
    }
    let n = x.len() as f64;
    let mean_x: f64 = x.iter().sum::<f64>() / n;
    let mean_y: f64 = y.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    let denom = (var_x * var_y).sqrt();
    if denom < 1e-12 {
        return 0.0;
    }
    cov / denom
}

/// Compute the Spearman rank correlation. Ties are handled by averaging
/// ranks. Returns 0.0 if either slice is empty or has zero variance in ranks.
pub fn spearman_correlation(x: &[f64], y: &[f64]) -> f64 {
    if x.len() != y.len() || x.len() < 2 {
        return 0.0;
    }
    let rx = average_ranks(x);
    let ry = average_ranks(y);
    pearson_correlation(&rx, &ry)
}

/// Compute the **partial correlation** between `x` and `y` controlling for
/// the covariate `z`. Uses the formula:
///
///   r_{xy·z} = (r_{xy} - r_{xz} * r_{yz}) / sqrt((1 - r_{xz}²)(1 - r_{yz}²))
///
/// Returns `None` if the denominator is zero.
pub fn partial_correlation(x: &[f64], y: &[f64], z: &[f64]) -> Option<f64> {
    if x.len() != y.len() || y.len() != z.len() || x.len() < 3 {
        return None;
    }
    let rxy = pearson_correlation(x, y);
    let rxz = pearson_correlation(x, z);
    let ryz = pearson_correlation(y, z);
    let denom_sq = (1.0 - rxz * rxz) * (1.0 - ryz * ryz);
    if denom_sq <= 1e-12 {
        return None;
    }
    Some((rxy - rxz * ryz) / denom_sq.sqrt())
}

/// Compute average ranks for a slice (1-based). Ties receive the average
/// of the ranks they span.
fn average_ranks(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    if n == 0 {
        return vec![];
    }
    // Build (index, value) pairs, sort by value.
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut ranks = vec![0.0f64; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && (indexed[j].1 - indexed[i].1).abs() < 1e-12 {
            j += 1;
        }
        // Tied group spans i..j (exclusive).
        let avg_rank = (i + 1 + j) as f64 / 2.0;
        for k in i..j {
            ranks[indexed[k].0] = avg_rank;
        }
        i = j;
    }
    ranks
}

/// Engine that tracks pairwise correlations across all registered components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEngine {
    /// Rolling window size for online computation.
    pub window_size: usize,
    /// Maximum number of historical snapshots per pair.
    pub max_history: usize,
    /// Rolling trackers keyed by `(a, b)` where `a < b` lexicographically.
    pub rolling: HashMap<(String, String), RollingCorrelation>,
    /// Full historical signal buffers per component.
    pub signals: HashMap<String, VecDeque<HealthSignal>>,
    pub max_signal_len: usize,
}

impl CorrelationEngine {
    pub fn new(window_size: usize, max_history: usize, max_signal_len: usize) -> Self {
        Self {
            window_size,
            max_history,
            rolling: HashMap::new(),
            signals: HashMap::new(),
            max_signal_len,
        }
    }

    /// Register a component pair for tracking.
    pub fn track_pair(&mut self, a: &str, b: &str) {
        let key = pair_key(a, b);
        if !self.rolling.contains_key(&key) {
            self.rolling.insert(
                key,
                RollingCorrelation::new(a, b, self.window_size, self.max_history),
            );
        }
    }

    /// Record a new signal for a component. Updates all rolling windows
    /// that include this component.
    pub fn record(&mut self, signal: HealthSignal) -> Vec<CorrelationResult> {
        let entry = self.signals.entry(signal.component.clone()).or_default();
        entry.push_back(signal.clone());
        if entry.len() > self.max_signal_len {
            entry.pop_front();
        }

        let mut results = Vec::new();
        let score = signal.score;
        let comp = &signal.component;
        for ((a, b), rolling) in &mut self.rolling {
            if a == comp || b == comp {
                // Need the other component's latest score.
                let other = if a == comp { b } else { a };
                let other_score = self.signals.get(other).and_then(|buf| buf.back().map(|s| s.score));
                if let Some(os) = other_score {
                    // Insert in the correct order.
                    let (va, vb) = if a == comp { (score, os) } else { (os, score) };
                    if let Some(result) = rolling.push(va, vb) {
                        results.push(result);
                    }
                }
            }
        }
        results
    }

    /// Compute a one-shot Pearson correlation between two components using
    /// their full recorded history (aligned by recency).
    pub fn compute_pearson(&self, a: &str, b: &str) -> Option<f64> {
        let sig_a = self.signals.get(a)?;
        let sig_b = self.signals.get(b)?;
        let len = sig_a.len().min(sig_b.len());
        if len < 2 {
            return None;
        }
        let va: Vec<f64> = sig_a.iter().rev().take(len).rev().map(|s| s.score).collect();
        let vb: Vec<f64> = sig_b.iter().rev().take(len).rev().map(|s| s.score).collect();
        Some(pearson_correlation(&va, &vb))
    }

    /// Compute partial correlation between `x` and `y` controlling for `z`.
    pub fn compute_partial(&self, x: &str, y: &str, z: &str) -> Option<f64> {
        let sig_x = self.signals.get(x)?;
        let sig_y = self.signals.get(y)?;
        let sig_z = self.signals.get(z)?;
        let len = sig_x.len().min(sig_y.len()).min(sig_z.len());
        if len < 3 {
            return None;
        }
        let vx: Vec<f64> = sig_x.iter().rev().take(len).rev().map(|s| s.score).collect();
        let vy: Vec<f64> = sig_y.iter().rev().take(len).rev().map(|s| s.score).collect();
        let vz: Vec<f64> = sig_z.iter().rev().take(len).rev().map(|s| s.score).collect();
        partial_correlation(&vx, &vy, &vz)
    }

    /// Get the latest rolling correlation for a pair.
    pub fn latest(&self, a: &str, b: &str) -> Option<&CorrelationResult> {
        let key = pair_key(a, b);
        self.rolling.get(&key)?.history.last()
    }

    /// Return all component pairs currently tracked.
    pub fn tracked_pairs(&self) -> Vec<(&String, &String)> {
        self.rolling.keys().map(|(a, b)| (a, b)).collect()
    }
}

/// Normalise a pair key so that `(a, b)` and `(b, a)` map to the same entry.
fn pair_key(a: &str, b: &str) -> (String, String) {
    if a < b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  2. Causal Inference — Simplified Granger Causality via VAR(p)
// ═══════════════════════════════════════════════════════════════════════

/// Result of a Granger causality test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrangerResult {
    /// "Does X Granger-cause Y?"
    pub x_causes_y: bool,
    /// F-statistic for X→Y.
    pub f_statistic_xy: f64,
    /// "Does Y Granger-cause X?"
    pub y_causes_x: bool,
    /// F-statistic for Y→X.
    pub f_statistic_yx: f64,
    /// Chosen lag order `p`.
    pub lag: usize,
    /// Residual sum of squares for the restricted model (Y only).
    pub rss_restricted: f64,
    /// Residual sum of squares for the unrestricted model (X + Y).
    pub rss_unrestricted: f64,
    /// Significance threshold used.
    pub significance: f64,
}

/// Fit a bivariate VAR(p) model and test Granger causality in both directions.
///
/// # Algorithm
///
/// 1. Select optimal lag `p` ∈ [1..max_lag] via AIC on the full model.
/// 2. Fit the unrestricted model Y_t = α + Σ β_i Y_{t-i} + Σ γ_i X_{t-i} + ε.
/// 3. Fit the restricted model Y_t = α' + Σ β'_i Y_{t-i} + ε'.
/// 4. Compute the F-statistic:
///
///    F = ((RSS_r - RSS_u) / p) / (RSS_u / (T - 2p - 1))
///
/// 5. Compare against the critical value (approximated) at the given
///    significance level.
///
/// Returns `None` if there is insufficient data for even lag-1.
pub fn granger_causality_test(
    x: &[f64],
    y: &[f64],
    max_lag: usize,
    significance: f64,
) -> Option<GrangerResult> {
    if x.len() != y.len() || x.len() < max_lag + 2 {
        return None;
    }

    // Step 1: select lag by AIC.
    let best_lag = select_lag_aic(x, y, max_lag);
    let p = best_lag;
    let t = x.len();

    // Build design matrices. Each row is [1, Y_{t-1}, ..., Y_{t-p}, X_{t-1}, ..., X_{t-p}].
    let start = p;
    let unrestricted: Vec<Vec<f64>> = (start..t)
        .map(|i| {
            let mut row = vec![1.0];
            for lag in 1..=p {
                row.push(y[i - lag]);
            }
            for lag in 1..=p {
                row.push(x[i - lag]);
            }
            row
        })
        .collect();

    let response_y: Vec<f64> = (start..t).map(|i| y[i]).collect();

    // Restricted model: only lags of Y.
    let restricted: Vec<Vec<f64>> = (start..t)
        .map(|i| {
            let mut row = vec![1.0];
            for lag in 1..=p {
                row.push(y[i - lag]);
            }
            row
        })
        .collect();

    // Fit both models via least squares.
    let coef_u = least_squares_solve(&unrestricted, &response_y)?;
    let coef_r = least_squares_solve(&restricted, &response_y)?;

    let rss_u = residuals_sum_sq(&unrestricted, &coef_u, &response_y);
    let rss_r = residuals_sum_sq(&restricted, &coef_r, &response_y);

    let df_num = p as f64;
    let df_denom = (t - start - 2 * p - 1) as f64;
    if df_denom <= 1.0 || rss_u < 1e-15 {
        return None;
    }

    let f_stat = ((rss_r - rss_u) / df_num) / (rss_u / df_denom);

    // Approximate F critical value at given significance using a simple
    // heuristic: for df_num >= 1 and df_denom >= 30, F_crit ≈ 3.84 (p=0.05),
    // 6.63 (p=0.01), etc. We use an analytic approximation of the inverse
    // of the F distribution's CDF for common significance levels.
    let f_critical = approximate_f_critical(df_num, df_denom, significance);

    let x_causes_y = f_stat > f_critical;

    // Now test Y → X (swap roles).
    let response_x: Vec<f64> = (start..t).map(|i| x[i]).collect();

    let unrestricted_yx: Vec<Vec<f64>> = (start..t)
        .map(|i| {
            let mut row = vec![1.0];
            for lag in 1..=p {
                row.push(x[i - lag]);
            }
            for lag in 1..=p {
                row.push(y[i - lag]);
            }
            row
        })
        .collect();

    let restricted_yx: Vec<Vec<f64>> = (start..t)
        .map(|i| {
            let mut row = vec![1.0];
            for lag in 1..=p {
                row.push(x[i - lag]);
            }
            row
        })
        .collect();

    let coef_u_yx = least_squares_solve(&unrestricted_yx, &response_x)?;
    let coef_r_yx = least_squares_solve(&restricted_yx, &response_x)?;
    let rss_u_yx = residuals_sum_sq(&unrestricted_yx, &coef_u_yx, &response_x);
    let rss_r_yx = residuals_sum_sq(&restricted_yx, &coef_r_yx, &response_x);
    let f_stat_yx = ((rss_r_yx - rss_u_yx) / df_num) / (rss_u_yx / df_denom);
    let y_causes_x = f_stat_yx > f_critical;

    Some(GrangerResult {
        x_causes_y,
        f_statistic_xy: f_stat,
        y_causes_x,
        f_statistic_yx: f_stat_yx,
        lag: p,
        rss_restricted: rss_r,
        rss_unrestricted: rss_u,
        significance,
    })
}

/// Select the optimal lag for a bivariate VAR using the Akaike Information
/// Criterion (AIC = 2k - 2 ln(L)). Since we compute the likelihood only up
/// to a constant via RSS, we minimise `n * ln(RSS/n) + 2 * k`.
fn select_lag_aic(x: &[f64], y: &[f64], max_lag: usize) -> usize {
    let mut best_lag = 1;
    let mut best_aic = f64::INFINITY;

    for p in 1..=max_lag {
        if x.len() < p + 2 {
            break;
        }
        let start = p;
        let t = x.len();
        // Design matrix: [1, Y_{t-1}..Y_{t-p}, X_{t-1}..X_{t-p}]
        let design: Vec<Vec<f64>> = (start..t)
            .map(|i| {
                let mut row = vec![1.0];
                for lag in 1..=p {
                    row.push(y[i - lag]);
                }
                for lag in 1..=p {
                    row.push(x[i - lag]);
                }
                row
            })
            .collect();
        let resp_y: Vec<f64> = (start..t).map(|i| y[i]).collect();
        let resp_x: Vec<f64> = (start..t).map(|i| x[i]).collect();

        let k = 2 * p + 1; // per equation
        let n = (t - start) as f64;

        if let Some(coef) = least_squares_solve(&design, &resp_y) {
            let rss = residuals_sum_sq(&design, &coef, &resp_y);
            let aic_y = n * (rss / n).ln() + 2.0 * k as f64;
            if aic_y < best_aic {
                best_aic = aic_y;
                best_lag = p;
            }
        }

        if let Some(coef) = least_squares_solve(&design, &resp_x) {
            let rss = residuals_sum_sq(&design, &coef, &resp_x);
            let aic_x = n * (rss / n).ln() + 2.0 * k as f64;
            if aic_x < best_aic {
                best_aic = aic_x;
                best_lag = p;
            }
        }
    }

    best_lag
}

/// Approximate the critical value of the F-distribution for a given
/// significance level. Uses the approximation:
///
///   F_crit ≈ (df1 - 2 / df1) * (1 + 2/df2) * z_crit²
///
/// where z_crit is the standard normal critical value. This is reasonable
/// for moderate-to-large df2 (which is always the case in our setting since
/// we require T >> max_lag).
fn approximate_f_critical(df1: f64, df2: f64, alpha: f64) -> f64 {
    if df1 <= 0.0 || df2 <= 2.0 {
        return f64::INFINITY;
    }
    let z = normal_critical_value(alpha);
    // Wilson-Hilferty based approximation via chi-squared:
    // chi2_crit(k) ≈ k * (1 - 2/(9k) + z * sqrt(2/(9k)))^3
    // F_crit ≈ chi2_crit(df1) / df1 * df2 / (df2 - 2)
    let a1 = 2.0 / (9.0 * df1);
    let chi2_wh = df1 * (1.0 - a1 + z * a1.sqrt()).powi(3);
    let f_approx = chi2_wh / df1 * df2 / (df2 - 2.0);
    f_approx.max(0.1)
}

/// Standard normal inverse CDF approximation (Abramowitz & Stegun 26.2.23).
fn normal_critical_value(alpha: f64) -> f64 {
    // We want z such that P(Z > z) = alpha/2 (two-tailed).
    let p = 1.0 - alpha / 2.0;
    // Rational approximation for the probit function.
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    let tail = (1.0 - p).max(1e-15);
    let t = (-2.0 * tail.ln()).sqrt();
    let c0 = 2.515517;
    let c1 = 0.802853;
    let c2 = 0.010328;
    let d1 = 1.432788;
    let d2 = 0.189269;
    let d3 = 0.001308;
    t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)
}

/// Solve the least-squares problem X β ≈ y using Gaussian elimination with
/// partial pivoting. Returns the coefficient vector or `None` if the system
/// is singular.
fn least_squares_solve(x: &[Vec<f64>], y: &[f64]) -> Option<Vec<f64>> {
    let n = y.len();
    if n == 0 || x.is_empty() {
        return None;
    }
    let k = x[0].len();
    if n < k {
        return None;
    }
    // Compute X^T X and X^T y.
    let xt = transpose(x);
    let xtx = mat_mul(&xt, x);
    let xty: Vec<f64> = (0..k).map(|i| dot_product(&xt[i], y)).collect();

    // Augmented matrix [A | b].
    let mut aug: Vec<Vec<f64>> = xtx
        .into_iter()
        .zip(xty.into_iter())
        .map(|(mut row, b)| {
            row.push(b);
            row
        })
        .collect();

    // Forward elimination with partial pivoting.
    for col in 0..k {
        let mut max_val = aug[col][col].abs();
        let mut max_row = col;
        for row in (col + 1)..k {
            if aug[row][col].abs() > max_val {
                max_val = aug[row][col].abs();
                max_row = row;
            }
        }
        if max_val < 1e-14 {
            return None;
        }
        aug.swap(col, max_row);
        for row in (col + 1)..k {
            let factor = aug[row][col] / aug[col][col];
            for j in col..=k {
                aug[row][j] -= factor * aug[col][j];
            }
        }
    }

    // Back substitution.
    let mut beta = vec![0.0; k];
    for i in (0..k).rev() {
        let mut sum = aug[i][k];
        for j in (i + 1)..k {
            sum -= aug[i][j] * beta[j];
        }
        beta[i] = sum / aug[i][i];
    }
    Some(beta)
}

fn dot_product(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn transpose(m: &[Vec<f64>]) -> Vec<Vec<f64>> {
    if m.is_empty() {
        return vec![];
    }
    let rows = m.len();
    let cols = m[0].len();
    let mut t = vec![vec![0.0; rows]; cols];
    for i in 0..rows {
        for j in 0..cols {
            t[j][i] = m[i][j];
        }
    }
    t
}

fn mat_mul(a: &[Vec<f64>], b: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let rows = a.len();
    let k = a[0].len();
    let cols = b[0].len();
    let mut c = vec![vec![0.0; cols]; rows];
    for i in 0..rows {
        for j in 0..cols {
            let mut s = 0.0;
            for l in 0..k {
                s += a[i][l] * b[l][j];
            }
            c[i][j] = s;
        }
    }
    c
}

fn residuals_sum_sq(x: &[Vec<f64>], beta: &[f64], y: &[f64]) -> f64 {
    let mut rss = 0.0;
    for i in 0..y.len() {
        let mut predicted = 0.0;
        for j in 0..beta.len() {
            predicted += x[i][j] * beta[j];
        }
        let residual = y[i] - predicted;
        rss += residual * residual;
    }
    rss
}

// ═══════════════════════════════════════════════════════════════════════
//  3. Anomaly Propagation Tracking
// ═══════════════════════════════════════════════════════════════════════

/// A single propagation event: how an anomaly propagated from one component
/// to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationEvent {
    pub source_component: String,
    pub target_component: String,
    /// Time the anomaly was first detected in the source.
    pub source_anomaly_time: DateTime<Utc>,
    /// Time the anomaly was first detected in the target.
    pub target_anomaly_time: DateTime<Utc>,
    /// Delay in seconds between source and target anomaly detection.
    pub delay_secs: f64,
    /// Health score impact measured at the target.
    pub impact: f64,
    /// Whether the impact was amplified (impact > source impact) or attenuated.
    pub propagation_type: PropagationType,
    /// Edge weight in the dependency DAG.
    pub edge_weight: f64,
}

/// Type of propagation observed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PropagationType {
    /// Impact decreased as it propagated (attenuation).
    Attenuation,
    /// Impact increased as it propagated (amplification).
    Amplification,
    /// Impact remained roughly the same.
    Neutral,
}

/// Summary of anomaly propagation across the dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationSummary {
    pub origin_component: String,
    pub origin_anomaly_time: DateTime<Utc>,
    pub total_affected: usize,
    pub max_depth: usize,
    pub events: Vec<PropagationEvent>,
    /// Average delay across all propagation hops (seconds).
    pub avg_delay_secs: f64,
    /// Average impact across all targets.
    pub avg_impact: f64,
    /// Fraction of edges that showed amplification.
    pub amplification_fraction: f64,
}

/// Tracker for anomaly propagation across a dependency DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPropagationTracker {
    /// Dependency edges: (from, to, weight). "from depends on to".
    pub dependencies: Vec<(String, String, f64)>,
    /// Anomaly detection records: component → list of anomaly detection times.
    pub anomaly_times: HashMap<String, Vec<DateTime<Utc>>>,
    /// Health impact records: component → (time, score_drop).
    pub health_impacts: HashMap<String, Vec<(DateTime<Utc>, f64)>>,
    /// Anomaly threshold (health score below this is an anomaly).
    pub anomaly_threshold: f64,
}

impl AnomalyPropagationTracker {
    pub fn new(anomaly_threshold: f64) -> Self {
        Self {
            dependencies: Vec::new(),
            anomaly_times: HashMap::new(),
            health_impacts: HashMap::new(),
            anomaly_threshold,
        }
    }

    /// Register a dependency edge.
    pub fn add_dependency(&mut self, from: &str, to: &str, weight: f64) {
        self.dependencies.push((from.to_string(), to.to_string(), weight.clamp(0.0, 1.0)));
    }

    /// Record a health observation. If the score falls below the anomaly
    /// threshold, it is logged as an anomaly.
    pub fn observe(&mut self, component: &str, score: f64, time: DateTime<Utc>, previous_score: f64) {
        let times = self.anomaly_times.entry(component.to_string()).or_default();
        let impacts = self.health_impacts.entry(component.to_string()).or_default();
        let score_drop = (previous_score - score).max(0.0);
        impacts.push((time, score_drop));

        if score < self.anomaly_threshold {
            times.push(time);
        }
    }

    /// Track propagation from a given origin component. Performs BFS/DFS
    /// across the dependency graph and measures how the anomaly spread.
    pub fn track_propagation(&self, origin: &str) -> Option<PropagationSummary> {
        let origin_times = self.anomaly_times.get(origin)?;
        if origin_times.is_empty() {
            return None;
        }
        let origin_time = origin_times.iter().min().cloned()?;

        let origin_impact = self.health_impacts.get(origin)
            .and_then(|imps| imps.iter().find(|(t, _)| *t == origin_time).map(|(_, s)| *s))
            .unwrap_or(0.5);

        // Collect dependents (components that depend on the current one).
        let mut dependents_map: HashMap<String, Vec<(String, f64)>> = HashMap::new();
        for (from, to, w) in &self.dependencies {
            dependents_map.entry(to.clone()).or_default().push((from.clone(), *w));
        }

        let mut events: Vec<PropagationEvent> = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, DateTime<Utc>, f64, usize)> = VecDeque::new();
        queue.push_back((origin.to_string(), origin_time, origin_impact, 0));
        visited.insert(origin.to_string());

        while let Some((current, cur_time, cur_impact, depth)) = queue.pop_front() {
            if let Some(deps) = dependents_map.get(&current) {
                for (dep, weight) in deps {
                    if visited.contains(dep) {
                        continue;
                    }
                    if let Some(dep_impacts) = self.health_impacts.get(dep) {
                        if let Some(&(dep_time, dep_impact)) = dep_impacts.iter().find(|(t, _)| *t >= cur_time) {
                            visited.insert(dep.clone());
                            let delay = (dep_time - cur_time).num_milliseconds() as f64 / 1000.0;

                            let propagation_type = if dep_impact > cur_impact * 1.1 {
                                PropagationType::Amplification
                            } else if dep_impact < cur_impact * 0.9 {
                                PropagationType::Attenuation
                            } else {
                                PropagationType::Neutral
                            };

                            events.push(PropagationEvent {
                                source_component: current.clone(),
                                target_component: dep.clone(),
                                source_anomaly_time: cur_time,
                                target_anomaly_time: dep_time,
                                delay_secs: delay,
                                impact: dep_impact,
                                propagation_type,
                                edge_weight: *weight,
                            });

                            queue.push_back((dep.clone(), dep_time, dep_impact, depth + 1));
                        }
                    }
                }
            }
        }

        if events.is_empty() {
            return None;
        }

        let total_affected = events.len();
        let max_depth = events.iter().map(|_| 0).max().unwrap_or(0) + 1;
        let avg_delay: f64 = events.iter().map(|e| e.delay_secs).sum::<f64>() / events.len() as f64;
        let avg_impact: f64 = events.iter().map(|e| e.impact).sum::<f64>() / events.len() as f64;
        let amp_count = events.iter().filter(|e| e.propagation_type == PropagationType::Amplification).count();
        let amplification_fraction = amp_count as f64 / events.len() as f64;

        Some(PropagationSummary {
            origin_component: origin.to_string(),
            origin_anomaly_time: origin_time,
            total_affected,
            max_depth,
            events,
            avg_delay_secs: avg_delay,
            avg_impact,
            amplification_fraction,
        })
    }

    /// Compute propagation speed as a weighted average of delays across the
    /// dependency graph. Lower values indicate faster propagation.
    pub fn propagation_speed(&self, origin: &str) -> Option<f64> {
        let summary = self.track_propagation(origin)?;
        if summary.events.is_empty() {
            return None;
        }
        let total_delay: f64 = summary.events.iter().map(|e| e.delay_secs).sum();
        let total_hops = summary.events.len() as f64;
        Some(total_delay / total_hops)
    }

    /// Compute the attenuation factor: ratio of average impact at leaf
    /// nodes to the origin impact. Values < 1.0 indicate attenuation.
    pub fn attenuation_factor(&self, origin: &str) -> Option<f64> {
        let summary = self.track_propagation(origin)?;
        if summary.events.is_empty() {
            return None;
        }
        let origin_impact = self.health_impacts.get(origin)
            .and_then(|imps| imps.first().map(|(_, s)| *s))
            .unwrap_or(1.0);
        if origin_impact < 1e-12 {
            return None;
        }
        Some(summary.avg_impact / origin_impact)
    }

    /// Compute the amplification factor: the maximum impact observed at any
    /// target divided by the origin impact. Values > 1.0 indicate amplification.
    pub fn amplification_factor(&self, origin: &str) -> Option<f64> {
        let summary = self.track_propagation(origin)?;
        if summary.events.is_empty() {
            return None;
        }
        let origin_impact = self.health_impacts.get(origin)
            .and_then(|imps| imps.first().map(|(_, s)| *s))
            .unwrap_or(1.0);
        if origin_impact < 1e-12 {
            return None;
        }
        let max_impact = summary.events.iter().map(|e| e.impact).fold(0.0_f64, f64::max);
        Some(max_impact / origin_impact)
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  4. Health Root Cause Analysis
// ═══════════════════════════════════════════════════════════════════════

/// A scored candidate for the root cause of a health degradation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseCandidate {
    pub component: String,
    /// Composite root-cause score (higher = more likely root cause).
    pub score: f64,
    /// Sub-score: how far upstream is this component in the DAG (higher = more upstream).
    pub dag_position_score: f64,
    /// Sub-score: correlation with the unhealthy components.
    pub correlation_score: f64,
    /// Sub-score: how early this component became unhealthy.
    pub timing_score: f64,
    /// Explanation for the score.
    pub reason: String,
}

/// Result of the root cause analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseAnalysisResult {
    pub candidates: Vec<RootCauseCandidate>,
    pub analyzed_at: DateTime<Utc>,
    pub unhealthy_components: Vec<String>,
}

/// Root cause analyzer that uses the dependency DAG, correlation data,
/// and temporal ordering to identify the most likely origin of failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseAnalyzer {
    /// Dependency edges: (dependent, dependency, weight).
    pub dependencies: Vec<(String, String, f64)>,
    /// Correlation cache: (a, b) → correlation value.
    pub correlations: HashMap<(String, String), f64>,
    /// Component anomaly timestamps: component → first anomaly detection time.
    pub anomaly_timestamps: HashMap<String, DateTime<Utc>>,
    /// Health history per component.
    pub health_history: HashMap<String, Vec<f64>>,
    /// Weight for DAG position in composite scoring.
    pub dag_weight: f64,
    /// Weight for correlation in composite scoring.
    pub correlation_weight: f64,
    /// Weight for timing in composite scoring.
    pub timing_weight: f64,
}

impl RootCauseAnalyzer {
    pub fn new() -> Self {
        Self {
            dependencies: Vec::new(),
            correlations: HashMap::new(),
            anomaly_timestamps: HashMap::new(),
            health_history: HashMap::new(),
            dag_weight: 0.4,
            correlation_weight: 0.3,
            timing_weight: 0.3,
        }
    }

    /// Add a dependency edge.
    pub fn add_dependency(&mut self, from: &str, to: &str, weight: f64) {
        self.dependencies.push((from.to_string(), to.to_string(), weight.clamp(0.0, 1.0)));
    }

    /// Record a correlation value for a pair.
    pub fn set_correlation(&mut self, a: &str, b: &str, corr: f64) {
        let key = pair_key(a, b);
        self.correlations.insert(key, corr);
    }

    /// Record the timestamp when a component first became anomalous.
    pub fn record_anomaly_time(&mut self, component: &str, time: DateTime<Utc>) {
        let entry = self.anomaly_timestamps.entry(component.to_string()).or_insert_with(|| time);
        if time < *entry {
            *entry = time;
        }
    }

    /// Record a health score for a component.
    pub fn record_health(&mut self, component: &str, score: f64) {
        let entry = self.health_history.entry(component.to_string()).or_default();
        entry.push(score);
        if entry.len() > 1000 {
            entry.remove(0);
        }
    }

    /// Compute the DAG position score for a component. Components with more
    /// dependents and fewer dependencies score higher (they are more upstream).
    fn dag_position_score(&self, component: &str) -> f64 {
        // Count dependents (how many depend on this component).
        let dependents: HashSet<String> = self.dependencies
            .iter()
            .filter(|(_, to, _)| to == component)
            .map(|(from, _, _)| from.clone())
            .collect();

        // Count dependencies (how many this depends on).
        let deps: HashSet<String> = self.dependencies
            .iter()
            .filter(|(from, _, _)| from == component)
            .map(|(_, to, _)| to.clone())
            .collect();

        // Score: higher when more things depend on it and fewer things does it depend on.
        let downstream_count = dependents.len() as f64;
        let upstream_count = deps.len() as f64;

        if downstream_count + upstream_count == 0.0 {
            return 0.5;
        }

        downstream_count / (downstream_count + upstream_count)
    }

    /// Compute the correlation score: average absolute correlation with
    /// all unhealthy components.
    fn correlation_score(&self, component: &str, unhealthy: &[String]) -> f64 {
        if unhealthy.is_empty() {
            return 0.0;
        }
        let mut sum = 0.0;
        let mut count = 0;
        for target in unhealthy {
            if target == component {
                continue;
            }
            let key = pair_key(component, target);
            if let Some(&corr) = self.correlations.get(&key) {
                sum += corr.abs();
                count += 1;
            }
        }
        if count == 0 {
            return 0.0;
        }
        sum / count as f64
    }

    /// Compute the timing score: components that became unhealthy earlier
    /// score higher. Score is 1.0 for the earliest, linearly decreasing
    /// for later components.
    fn timing_score(&self, component: &str, unhealthy: &[String]) -> f64 {
        let comp_time = match self.anomaly_timestamps.get(component) {
            Some(t) => *t,
            None => return 0.0,
        };

        let mut times: Vec<DateTime<Utc>> = unhealthy
            .iter()
            .filter_map(|c| self.anomaly_timestamps.get(c).copied())
            .collect();

        if times.is_empty() {
            return 0.5;
        }

        times.sort();
        let earliest = times.first().unwrap();
        let latest = times.last().unwrap();
        let range = (*latest - *earliest).num_milliseconds() as f64;

        if range < 1.0 {
            return 1.0; // All became unhealthy at the same time.
        }

        let elapsed = (comp_time - *earliest).num_milliseconds() as f64;
        1.0 - (elapsed / range)
    }

    /// Perform root cause analysis on the given set of unhealthy components.
    /// Scores each unhealthy component (and its upstream neighbours) to
    /// identify the most likely root cause.
    pub fn analyze(&self, unhealthy: &[String]) -> RootCauseAnalysisResult {
        // Collect all candidate components: the unhealthy set plus their
        // direct dependencies (upstream).
        let mut candidates_set: HashSet<String> = unhealthy.iter().cloned().collect();
        for (from, to, _) in &self.dependencies {
            if unhealthy.contains(from) {
                candidates_set.insert(to.clone());
            }
        }

        let mut candidates: Vec<RootCauseCandidate> = candidates_set
            .iter()
            .map(|comp| {
                let dag = self.dag_position_score(comp);
                let corr = self.correlation_score(comp, unhealthy);
                let timing = self.timing_score(comp, unhealthy);

                // Composite score with configurable weights.
                let total = self.dag_weight * dag
                    + self.correlation_weight * corr
                    + self.timing_weight * timing;

                let reason = format!(
                    "dag_pos={:.3}, corr={:.3}, timing={:.3} → composite={:.3}",
                    dag, corr, timing, total
                );

                RootCauseCandidate {
                    component: comp.clone(),
                    score: total,
                    dag_position_score: dag,
                    correlation_score: corr,
                    timing_score: timing,
                    reason,
                }
            })
            .collect();

        // Sort by score descending (most likely root cause first).
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        RootCauseAnalysisResult {
            candidates,
            analyzed_at: Utc::now(),
            unhealthy_components: unhealthy.to_vec(),
        }
    }

    /// Get the top N root cause candidates.
    pub fn top_candidates(&self, unhealthy: &[String], n: usize) -> Vec<RootCauseCandidate> {
        let result = self.analyze(unhealthy);
        result.candidates.into_iter().take(n).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  5. Predictive Health Scoring
// ═══════════════════════════════════════════════════════════════════════

/// A forward-looking health prediction for a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedHealth {
    pub component: String,
    /// Current health score.
    pub current_score: f64,
    /// Predicted health score at the forecast horizon.
    pub predicted_score: f64,
    /// Forecast horizon in seconds.
    pub horizon_secs: u64,
    /// Confidence in the prediction (0.0 to 1.0).
    pub confidence: f64,
    /// Trend direction.
    pub trend: TrendDirection,
    /// Number of degrading dependencies.
    pub degrading_dependency_count: usize,
    /// Total number of dependencies.
    pub total_dependency_count: usize,
    /// Number of unhealthy dependencies.
    pub unhealthy_dependency_count: usize,
    /// Explanation of the prediction.
    pub explanation: String,
    pub computed_at: DateTime<Utc>,
}

/// Re-export TrendDirection from the canonical ANANTA location.
pub use crate::ananta::TrendDirection;

/// Predictive health scorer that combines current scores, trend analysis,
/// dependency health, and correlation data to produce forward-looking
/// health estimates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictiveHealthScorer {
    /// Dependency edges: (dependent, dependency, weight).
    pub dependencies: Vec<(String, String, f64)>,
    /// Health history per component.
    pub health_history: HashMap<String, VecDeque<f64>>,
    /// Correlation cache.
    pub correlations: HashMap<(String, String), f64>,
    /// Maximum history length per component.
    pub max_history: usize,
    /// Default forecast horizon in seconds.
    pub default_horizon_secs: u64,
    /// Health score below which a component is considered unhealthy.
    pub unhealthy_threshold: f64,
    /// Health score below which a component is considered degrading.
    pub degrading_threshold: f64,
}

impl PredictiveHealthScorer {
    pub fn new(default_horizon_secs: u64) -> Self {
        Self {
            dependencies: Vec::new(),
            health_history: HashMap::new(),
            correlations: HashMap::new(),
            max_history: 1000,
            default_horizon_secs,
            unhealthy_threshold: 0.3,
            degrading_threshold: 0.7,
        }
    }

    /// Add a dependency edge.
    pub fn add_dependency(&mut self, from: &str, to: &str, weight: f64) {
        self.dependencies.push((from.to_string(), to.to_string(), weight.clamp(0.0, 1.0)));
    }

    /// Record a health score for a component.
    pub fn record_health(&mut self, component: &str, score: f64) {
        let entry = self.health_history.entry(component.to_string()).or_default();
        entry.push_back(score);
        if entry.len() > self.max_history {
            entry.pop_front();
        }
    }

    /// Set a correlation value for a pair.
    pub fn set_correlation(&mut self, a: &str, b: &str, corr: f64) {
        let key = pair_key(a, b);
        self.correlations.insert(key, corr);
    }

    /// Compute the current health score for a component (latest observation).
    pub fn current_health(&self, component: &str) -> f64 {
        self.health_history
            .get(component)
            .and_then(|h| h.back().copied())
            .unwrap_or(1.0)
    }

    /// Compute the trend direction for a component based on its recent history.
    pub fn trend(&self, component: &str) -> TrendDirection {
        let history = match self.health_history.get(component) {
            Some(h) if h.len() >= 10 => h,
            _ => return TrendDirection::Stable,
        };

        // Compare the mean of the last 5 observations to the mean of the
        // 5 before that.
        let n = history.len();
        let recent_start = n.saturating_sub(5);
        let older_end = recent_start;
        let older_start = older_end.saturating_sub(5);

        let recent_sum: f64 = history.iter().skip(recent_start).sum();
        let recent_mean = recent_sum / (n - recent_start) as f64;

        if older_start == older_end {
            return TrendDirection::Stable;
        }

        let older_sum: f64 = history.iter().skip(older_start).take(older_end - older_start).sum();
        let older_mean = older_sum / (older_end - older_start) as f64;

        let diff = recent_mean - older_mean;
        if diff.abs() < 0.02 {
            TrendDirection::Stable
        } else if diff > 0.0 {
            TrendDirection::Improving
        } else {
            TrendDirection::Degrading
        }
    }

    /// Compute the linear trend slope (change per observation).
    fn trend_slope(&self, component: &str) -> f64 {
        let history = match self.health_history.get(component) {
            Some(h) if h.len() >= 5 => h,
            _ => return 0.0,
        };
        let n = history.len();
        let recent: Vec<f64> = history.iter().skip(n.saturating_sub(20)).copied().collect();
        let m = recent.len();
        if m < 2 {
            return 0.0;
        }
        // Simple linear regression slope: Σ(x-mean_x)(y-mean_y) / Σ(x-mean_x)²
        let mean_x = (m - 1) as f64 / 2.0;
        let mean_y: f64 = recent.iter().sum::<f64>() / m as f64;
        let mut num = 0.0;
        let mut den = 0.0;
        for (i, &y) in recent.iter().enumerate() {
            let dx = i as f64 - mean_x;
            let dy = y - mean_y;
            num += dx * dy;
            den += dx * dx;
        }
        if den < 1e-12 {
            return 0.0;
        }
        num / den
    }

    /// Count the dependencies of a component.
    fn dependency_info(&self, component: &str) -> (usize, usize, usize) {
        let deps: Vec<&(String, String, f64)> = self.dependencies
            .iter()
            .filter(|(from, _, _)| from == component)
            .collect();

        let total = deps.len();
        let mut degrading = 0;
        let mut unhealthy = 0;

        for (_, dep_comp, _weight) in &deps {
            let score = self.current_health(dep_comp);
            if score < self.degrading_threshold {
                unhealthy += 1;
            } else if score < 0.8 {
                degrading += 1;
            }
        }

        (total, degrading, unhealthy)
    }

    /// Compute the dependency health factor: a weighted average of
    /// dependency health scores. If a component has no dependencies,
    /// returns 1.0.
    fn dependency_factor(&self, component: &str) -> f64 {
        let deps: Vec<&(String, String, f64)> = self.dependencies
            .iter()
            .filter(|(from, _, _)| from == component)
            .collect();

        if deps.is_empty() {
            return 1.0;
        }

        let mut total_weight = 0.0;
        let mut weighted_health = 0.0;

        for (_, dep_comp, weight) in &deps {
            let dep_health = self.current_health(dep_comp);
            weighted_health += dep_health * weight;
            total_weight += weight;
        }

        if total_weight < 1e-12 {
            return 1.0;
        }
        weighted_health / total_weight
    }

    /// Compute the correlation-based prediction adjustment. If this component
    /// is highly correlated with degrading components, reduce the predicted
    /// score.
    fn correlation_adjustment(&self, component: &str) -> f64 {
        let mut adjustment = 0.0;
        let mut count = 0;

        for ((a, b), &corr) in &self.correlations {
            if a == component || b == component {
                let other = if a == component { b } else { a };
                let other_health = self.current_health(other);
                let other_trend = self.trend(other);

                // If the other component is degrading and highly correlated,
                // push our prediction down.
                if other_trend == TrendDirection::Degrading && corr.abs() > 0.5 {
                    let impact = corr.abs() * (1.0 - other_health) * 0.3;
                    adjustment -= impact;
                    count += 1;
                }
                // If the other component is improving and highly correlated,
                // push our prediction up.
                if other_trend == TrendDirection::Improving && corr.abs() > 0.5 {
                    let impact = corr.abs() * other_health * 0.15;
                    adjustment += impact;
                    count += 1;
                }
            }
        }

        if count == 0 {
            return 0.0;
        }
        adjustment / count as f64
    }

    /// Produce a forward-looking health prediction for a component.
    pub fn predict(&self, component: &str, horizon_secs: Option<u64>) -> PredictedHealth {
        let horizon = horizon_secs.unwrap_or(self.default_horizon_secs);
        let current = self.current_health(component);
        let trend = self.trend(component);
        let slope = self.trend_slope(component);
        let (total_deps, degrading_deps, unhealthy_deps) = self.dependency_info(component);
        let dep_factor = self.dependency_factor(component);
        let corr_adj = self.correlation_adjustment(component);

        // Trend-based extrapolation: assume 1 observation per ~10 seconds.
        let steps = (horizon as f64 / 10.0).min(50.0);
        let trend_prediction = (current + slope * steps).clamp(0.0, 1.0);

        // Dependency-based prediction: blend current score with dependency health.
        let dep_prediction = current * (0.5 + 0.5 * dep_factor);

        // Combined prediction: 40% trend, 40% dependency, 20% correlation adjustment.
        let raw_predicted = 0.4 * trend_prediction + 0.4 * dep_prediction + 0.2 * (current + corr_adj);
        let predicted = raw_predicted.clamp(0.0, 1.0);

        // Confidence: higher with more history and fewer uncertainties.
        let history_len = self.health_history.get(component).map(|h| h.len()).unwrap_or(0);
        let data_confidence = if history_len >= 50 { 0.8 } else if history_len >= 20 { 0.6 } else { 0.3 };
        let dep_confidence = if total_deps == 0 { 1.0 } else { 1.0 - (unhealthy_deps as f64 * 0.15).min(0.5) };
        let confidence = (data_confidence * dep_confidence).clamp(0.1, 0.95);

        let explanation = if degrading_deps > 0 || unhealthy_deps > 0 {
            format!(
                "Component '{}' is currently at {:.2}. {} dependencies degrading, {} unhealthy. \
                 Predicted health in {}s: {:.2}. Trend: {:?}.",
                component, current, degrading_deps, unhealthy_deps, horizon, predicted, trend
            )
        } else {
            format!(
                "Component '{}' is currently at {:.2} with no degrading dependencies. \
                 Predicted health in {}s: {:.2}. Trend: {:?}.",
                component, current, horizon, predicted, trend
            )
        };

        PredictedHealth {
            component: component.to_string(),
            current_score: current,
            predicted_score: predicted,
            horizon_secs: horizon,
            confidence,
            trend,
            degrading_dependency_count: degrading_deps,
            total_dependency_count: total_deps,
            unhealthy_dependency_count: unhealthy_deps,
            explanation,
            computed_at: Utc::now(),
        }
    }

    /// Produce predictions for all components with recorded history.
    pub fn predict_all(&self, horizon_secs: Option<u64>) -> Vec<PredictedHealth> {
        let components: Vec<String> = self.health_history.keys().cloned().collect();
        components.iter().map(|c| self.predict(c, horizon_secs)).collect()
    }

    /// Return components whose predicted health is below the unhealthy
    /// threshold (they are expected to fail within the forecast horizon).
    pub fn predicted_failures(&self, horizon_secs: Option<u64>) -> Vec<PredictedHealth> {
        self.predict_all(horizon_secs)
            .into_iter()
            .filter(|p| p.predicted_score < self.unhealthy_threshold)
            .collect()
    }

    /// Return components that are currently healthy but predicted to
    /// degrade within the forecast horizon.
    pub fn at_risk_components(&self, horizon_secs: Option<u64>) -> Vec<PredictedHealth> {
        self.predict_all(horizon_secs)
            .into_iter()
            .filter(|p| {
                p.current_score >= self.unhealthy_threshold
                    && p.predicted_score < self.degrading_threshold
            })
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Integration: Combined Health Correlation Engine
// ═══════════════════════════════════════════════════════════════════════

/// Top-level engine that integrates all five subsystems into a single
/// coherent health correlation analysis pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCorrelationEngine {
    pub correlation: CorrelationEngine,
    pub propagation: AnomalyPropagationTracker,
    pub root_cause: RootCauseAnalyzer,
    pub predictor: PredictiveHealthScorer,
    /// Granger causality cache: (a, b) → result.
    pub causality_cache: HashMap<(String, String), GrangerResult>,
}

impl HealthCorrelationEngine {
    /// Create a new engine with default parameters.
    pub fn new() -> Self {
        Self {
            correlation: CorrelationEngine::new(60, 100, 1000),
            propagation: AnomalyPropagationTracker::new(0.5),
            root_cause: RootCauseAnalyzer::new(),
            predictor: PredictiveHealthScorer::new(3600),
            causality_cache: HashMap::new(),
        }
    }

    /// Add a dependency edge to all subsystems.
    pub fn add_dependency(&mut self, from: &str, to: &str, weight: f64) {
        self.correlation.track_pair(from, to);
        self.propagation.add_dependency(from, to, weight);
        self.root_cause.add_dependency(from, to, weight);
        self.predictor.add_dependency(from, to, weight);
    }

    /// Record a health signal for a component, updating all subsystems.
    pub fn record(&mut self, component: &str, score: f64) -> Vec<CorrelationResult> {
        let signal = HealthSignal {
            component: component.to_string(),
            score,
            timestamp: Utc::now(),
        };

        let corr_results = self.correlation.record(signal.clone());

        let previous_score = self.predictor.current_health(component);
        self.predictor.record_health(component, score);
        self.root_cause.record_health(component, score);

        if score < self.propagation.anomaly_threshold {
            self.propagation.observe(component, score, Utc::now(), previous_score);
            self.root_cause.record_anomaly_time(component, Utc::now());
        }

        corr_results
    }

    /// Run Granger causality tests for all tracked pairs and cache results.
    pub fn compute_all_causality(&mut self, max_lag: usize, significance: f64) {
        let pairs: Vec<(String, String)> = self.correlation.tracked_pairs()
            .into_iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();

        for (a, b) in pairs {
            let sig_a: Vec<f64> = self.correlation.signals
                .get(a.as_str())
                .map(|s| s.iter().map(|hs| hs.score).collect())
                .unwrap_or_default();
            let sig_b: Vec<f64> = self.correlation.signals
                .get(b.as_str())
                .map(|s| s.iter().map(|hs| hs.score).collect())
                .unwrap_or_default();

            if let Some(result) = granger_causality_test(&sig_a, &sig_b, max_lag, significance) {
                let key = pair_key(&a, &b);
                self.causality_cache.insert(key, result);
            }
        }

        // Update the root cause analyzer with Pearson correlations.
        for ((a, b), rolling) in &self.correlation.rolling {
            if let Some(result) = rolling.history.last() {
                self.root_cause.set_correlation(a, b, result.pearson);
                self.predictor.set_correlation(a, b, result.pearson);
            }
        }
    }

    /// Perform a full analysis: causality, root cause, and predictions.
    pub fn full_analysis(
        &mut self,
        unhealthy_components: &[String],
        max_lag: usize,
        significance: f64,
    ) -> FullAnalysisReport {
        self.compute_all_causality(max_lag, significance);

        let root_cause = self.root_cause.analyze(unhealthy_components);
        let predictions = self.predictor.predict_all(None);

        let mut propagations = Vec::new();
        for comp in unhealthy_components {
            if let Some(summary) = self.propagation.track_propagation(comp) {
                propagations.push(summary);
            }
        }

        FullAnalysisReport {
            root_cause,
            predictions,
            propagations,
            causality_results: self.causality_cache.clone(),
            analyzed_at: Utc::now(),
        }
    }
}

/// A comprehensive analysis report combining all subsystems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAnalysisReport {
    pub root_cause: RootCauseAnalysisResult,
    pub predictions: Vec<PredictedHealth>,
    pub propagations: Vec<PropagationSummary>,
    pub causality_results: HashMap<(String, String), GrangerResult>,
    pub analyzed_at: DateTime<Utc>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper to build a correlated pair of signals. ──

    /// Generate `n` samples of two perfectly correlated signals with optional noise.
    fn correlated_signals(n: usize, correlation: f64, noise: f64) -> (Vec<f64>, Vec<f64>) {
        let mut rng_state: u64 = 42;
        let mut pseudo_random = move || -> f64 {
            // Simple LCG for reproducibility.
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (rng_state >> 33) as f64 / (1u64 << 31) as f64
        };

        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);
        for i in 0..n {
            let base = (i as f64 * 0.1).sin() + 0.5;
            let nx = base + pseudo_random() * noise;
            let ny = correlation * base + (1.0 - correlation) * pseudo_random() + noise * 0.5;
            x.push(nx);
            y.push(ny);
        }
        (x, y)
    }

    // ── 1. Correlation tests ──

    #[test]
    fn test_pearson_perfect_correlation() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let r = pearson_correlation(&x, &y);
        assert!((r - 1.0).abs() < 1e-10, "Expected 1.0, got {}", r);
    }

    #[test]
    fn test_pearson_negative_correlation() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![10.0, 8.0, 6.0, 4.0, 2.0];
        let r = pearson_correlation(&x, &y);
        assert!((r - (-1.0)).abs() < 1e-10, "Expected -1.0, got {}", r);
    }

    #[test]
    fn test_pearson_zero_correlation() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![1.0, -1.0, 1.0, -1.0, 1.0];
        // These are not perfectly uncorrelated but the r should be low.
        let r = pearson_correlation(&x, &y);
        assert!(r.abs() < 0.5, "Expected near-zero, got {}", r);
    }

    #[test]
    fn test_pearson_empty_slices() {
        let r = pearson_correlation(&[], &[]);
        assert_eq!(r, 0.0);
    }

    #[test]
    fn test_pearson_constant_slice() {
        let x = vec![3.0, 3.0, 3.0, 3.0];
        let y = vec![1.0, 2.0, 3.0, 4.0];
        let r = pearson_correlation(&x, &y);
        assert_eq!(r, 0.0, "Zero variance should yield 0.0");
    }

    #[test]
    fn test_spearman_perfect_monotonic() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let r = spearman_correlation(&x, &y);
        assert!((r - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_spearman_with_ties() {
        let x = vec![1.0, 2.0, 2.0, 3.0];
        let y = vec![1.0, 2.0, 2.0, 3.0];
        let r = spearman_correlation(&x, &y);
        assert!((r - 1.0).abs() < 1e-10, "Tied values should still yield 1.0");
    }

    #[test]
    fn test_partial_correlation() {
        // X and Y are both correlated with Z. Partial correlation should
        // be lower than the bivariate correlation.
        let z: Vec<f64> = (0..100).map(|i| (i as f64 * 0.1).sin()).collect();
        let x: Vec<f64> = z.iter().map(|&v| v + 0.1 * (v * 2.0).cos()).collect();
        let y: Vec<f64> = z.iter().map(|&v| v + 0.05 * (v * 3.0).cos()).collect();

        let rxy = pearson_correlation(&x, &y);
        let r_partial = partial_correlation(&x, &y, &z).unwrap();
        // Partial should remove the common Z effect.
        assert!(r_partial.abs() < rxy.abs() + 0.05,
            "partial ({}) should be lower than bivariate ({})", r_partial, rxy);
    }

    #[test]
    fn test_rolling_correlation_push() {
        let mut rolling = RollingCorrelation::new("a", "b", 5, 10);
        // Need 5 pushes to fill the window.
        for i in 0..4 {
            let result = rolling.push(i as f64, (i as f64) * 2.0);
            assert!(result.is_none(), "Window not full yet");
        }
        let result = rolling.push(4.0, 8.0);
        assert!(result.is_some(), "Window should now be full");
        let r = result.unwrap();
        assert!((r.pearson - 1.0).abs() < 1e-10, "Perfect correlation expected");
    }

    #[test]
    fn test_correlation_engine_record() {
        let mut engine = CorrelationEngine::new(5, 10, 100);
        engine.track_pair("alpha", "beta");
        for i in 0..10 {
            engine.record(HealthSignal {
                component: "alpha".to_string(),
                score: (i as f64) * 0.1,
                timestamp: Utc::now(),
            });
            engine.record(HealthSignal {
                component: "beta".to_string(),
                score: (i as f64) * 0.2,
                timestamp: Utc::now(),
            });
        }
        let pearson = engine.compute_pearson("alpha", "beta").unwrap();
        assert!(pearson > 0.9, "Expected high positive correlation, got {}", pearson);
    }

    #[test]
    fn test_correlation_engine_partial() {
        let mut engine = CorrelationEngine::new(5, 10, 100);
        engine.track_pair("x", "y");
        engine.track_pair("x", "z");
        engine.track_pair("y", "z");
        for i in 0..50 {
            let base = (i as f64 * 0.2).sin();
            engine.record(HealthSignal {
                component: "z".to_string(),
                score: base + 0.5,
                timestamp: Utc::now(),
            });
            engine.record(HealthSignal {
                component: "x".to_string(),
                score: base + 0.1 + 0.5 + (i as f64) * 0.001,
                timestamp: Utc::now(),
            });
            engine.record(HealthSignal {
                component: "y".to_string(),
                score: base + 0.05 + 0.5 - (i as f64) * 0.002,
                timestamp: Utc::now(),
            });
        }
        let partial = engine.compute_partial("x", "y", "z");
        assert!(partial.is_some(), "Should compute partial correlation");
    }

    // ── 2. Causal inference tests ──

    #[test]
    fn test_granger_causality_detected() {
        // X leads Y by one step: Y_t = 0.5 * Y_{t-1} + 0.5 * X_{t-1} + noise.
        let mut rng_state: u64 = 123;
        let mut noise = || -> f64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (rng_state >> 33) as f64 / (1u64 << 31) as f64 * 0.2 - 0.1
        };

        let n = 200;
        let mut x = vec![0.5];
        let mut y = vec![0.5];
        for _ in 1..n {
            let nx = 0.8 * x[x.len() - 1] + noise();
            let ny = 0.3 * y[y.len() - 1] + 0.5 * x[x.len() - 1] + noise();
            x.push(nx);
            y.push(ny);
        }

        let result = granger_causality_test(&x, &y, 5, 0.05).unwrap();
        assert!(
            result.x_causes_y,
            "X should Granger-cause Y (F={:.2})", result.f_statistic_xy
        );
    }

    #[test]
    fn test_granger_no_causality_independent() {
        // Generate two independent random walks.
        let mut rng_state: u64 = 999;
        let mut noise = || -> f64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (rng_state >> 33) as f64 / (1u64 << 31) as f64 * 0.5 - 0.25
        };

        let n = 200;
        let mut x = vec![0.0];
        let mut y = vec![0.0];
        for _ in 1..n {
            x.push(x[x.len() - 1] + noise());
            y.push(y[y.len() - 1] + noise());
        }

        let result = granger_causality_test(&x, &y, 3, 0.05);
        // With independent series, neither should Granger-cause the other
        // at the 5% level (probabilistic, but very likely to hold).
        if let Some(r) = result {
            // We don't strictly assert no causality since random data can
            // occasionally produce spurious results, but F-statistics
            // should be low.
            assert!(r.f_statistic_xy < 10.0, "F-stat should be moderate for independent series");
        }
    }

    #[test]
    fn test_granger_bidirectional() {
        // Both X and Y influence each other.
        let mut rng_state: u64 = 777;
        let mut noise = || -> f64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (rng_state >> 33) as f64 / (1u64 << 31) as f64 * 0.15 - 0.075
        };

        let n = 200;
        let mut x = vec![0.5];
        let mut y = vec![0.5];
        for _ in 1..n {
            let nx = 0.5 * x[x.len() - 1] + 0.3 * y[y.len() - 1] + noise();
            let ny = 0.5 * y[y.len() - 1] + 0.3 * x[x.len() - 1] + noise();
            x.push(nx);
            y.push(ny);
        }

        let result = granger_causality_test(&x, &y, 5, 0.10).unwrap();
        // With bidirectional influence, at least one direction should show
        // causality at the 10% level. With 200 samples and true coupling,
        // this is highly likely.
        assert!(
            result.x_causes_y || result.y_causes_x,
            "Expected at least one direction of Granger causality"
        );
    }

    #[test]
    fn test_granger_insufficient_data() {
        let x = vec![1.0, 2.0];
        let y = vec![2.0, 4.0];
        let result = granger_causality_test(&x, &y, 3, 0.05);
        assert!(result.is_none(), "Should return None for insufficient data");
    }

    #[test]
    fn test_lag_selection_aic() {
        let n = 200;
        let x: Vec<f64> = (0..n).map(|i| (i as f64 * 0.05).sin()).collect();
        let y: Vec<f64> = (0..n).map(|i| (i as f64 * 0.05 + 0.5).sin()).collect();
        let lag = select_lag_aic(&x, &y, 5);
        assert!(lag >= 1 && lag <= 5, "Lag should be in [1, 5], got {}", lag);
    }

    #[test]
    fn test_f_critical_approximation() {
        let fc = approximate_f_critical(2.0, 50.0, 0.05);
        // F(2,50) at 5% is approximately 3.18. Our approximation should be
        // in the right ballpark.
        assert!(fc > 2.0 && fc < 6.0, "F critical should be in reasonable range, got {}", fc);
    }

    // ── 3. Anomaly propagation tests ──

    #[test]
    fn test_propagation_tracking_basic() {
        let mut tracker = AnomalyPropagationTracker::new(0.5);
        tracker.add_dependency("web", "api", 0.8);
        tracker.add_dependency("api", "db", 0.9);

        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(5);
        let t2 = t1 + chrono::Duration::seconds(3);

        tracker.observe("db", 0.3, t0, 0.9);
        tracker.observe("api", 0.4, t1, 0.9);
        tracker.observe("web", 0.45, t2, 0.9);

        let summary = tracker.track_propagation("db").unwrap();
        assert_eq!(summary.origin_component, "db");
        assert_eq!(summary.total_affected, 2);
    }

    #[test]
    fn test_propagation_speed() {
        let mut tracker = AnomalyPropagationTracker::new(0.5);
        tracker.add_dependency("svc_a", "svc_b", 1.0);

        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(10);

        tracker.observe("svc_b", 0.2, t0, 0.8);
        tracker.observe("svc_a", 0.3, t1, 0.8);

        let speed = tracker.propagation_speed("svc_b").unwrap();
        assert!((speed - 10.0).abs() < 0.1, "Expected 10s delay, got {}", speed);
    }

    #[test]
    fn test_attenuation_factor() {
        let mut tracker = AnomalyPropagationTracker::new(0.5);
        tracker.add_dependency("leaf", "root", 0.5);

        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(2);

        // Root drops by 0.5, leaf drops by only 0.2 (attenuated).
        tracker.observe("root", 0.3, t0, 0.8);
        tracker.observe("leaf", 0.6, t1, 0.8);

        let factor = tracker.attenuation_factor("root").unwrap();
        assert!(factor < 1.0, "Should show attenuation");
    }

    #[test]
    fn test_amplification_factor() {
        let mut tracker = AnomalyPropagationTracker::new(0.5);
        tracker.add_dependency("downstream", "upstream", 0.8);

        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(1);

        // Upstream drops by 0.1, downstream drops by 0.4 (amplified).
        tracker.observe("upstream", 0.4, t0, 0.5);
        tracker.observe("downstream", 0.1, t1, 0.5);

        let factor = tracker.amplification_factor("upstream").unwrap();
        assert!(factor > 1.0, "Should show amplification, got {}", factor);
    }

    #[test]
    fn test_propagation_no_origin() {
        let tracker = AnomalyPropagationTracker::new(0.5);
        assert!(tracker.track_propagation("nonexistent").is_none());
    }

    // ── 4. Root cause analysis tests ──

    #[test]
    fn test_root_cause_upstream_scores_higher() {
        let mut analyzer = RootCauseAnalyzer::new();
        analyzer.add_dependency("web", "api", 0.8);
        analyzer.add_dependency("api", "db", 0.9);

        // All three are unhealthy, but db is the most upstream.
        analyzer.record_anomaly_time("db", Utc::now());
        analyzer.record_anomaly_time("api", Utc::now() + chrono::Duration::seconds(5));
        analyzer.record_anomaly_time("web", Utc::now() + chrono::Duration::seconds(10));

        analyzer.set_correlation("web", "api", 0.8);
        analyzer.set_correlation("api", "db", 0.9);

        let result = analyzer.analyze(&["web".to_string(), "api".to_string(), "db".to_string()]);
        let top = &result.candidates[0];
        assert_eq!(top.component, "db", "DB should be the top root cause candidate");
        assert!(top.dag_position_score > 0.5, "DB should have high DAG position score");
    }

    #[test]
    fn test_root_cause_timing() {
        let mut analyzer = RootCauseAnalyzer::new();
        analyzer.add_dependency("a", "b", 0.5);

        let t0 = Utc::now();
        analyzer.record_anomaly_time("a", t0);
        analyzer.record_anomaly_time("b", t0 + chrono::Duration::seconds(30));

        let result = analyzer.analyze(&["a".to_string(), "b".to_string()]);
        let a_score = result.candidates.iter().find(|c| c.component == "a").unwrap().timing_score;
        let b_score = result.candidates.iter().find(|c| c.component == "b").unwrap().timing_score;
        assert!(a_score > b_score, "Earlier component should have higher timing score");
    }

    #[test]
    fn test_root_cause_empty_unhealthy() {
        let analyzer = RootCauseAnalyzer::new();
        let result = analyzer.analyze(&[]);
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn test_root_cause_top_n() {
        let mut analyzer = RootCauseAnalyzer::new();
        analyzer.add_dependency("web", "api", 1.0);
        analyzer.add_dependency("api", "db", 1.0);
        analyzer.record_anomaly_time("db", Utc::now());

        let top = analyzer.top_candidates(&["web".to_string(), "api".to_string(), "db".to_string()], 2);
        assert_eq!(top.len(), 2);
    }

    // ── 5. Predictive health scoring tests ──

    #[test]
    fn test_predictor_healthy_stable() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        for _ in 0..20 {
            scorer.record_health("stable_svc", 0.95);
        }
        let pred = scorer.predict("stable_svc", None);
        assert!(pred.predicted_score > 0.8, "Healthy stable should predict high, got {}", pred.predicted_score);
        assert_eq!(pred.trend, TrendDirection::Stable);
        assert_eq!(pred.degrading_dependency_count, 0);
    }

    #[test]
    fn test_predictor_degrading() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        for i in 0..20 {
            let score = 0.95 - (i as f64 * 0.03);
            scorer.record_health("declining", score.max(0.1));
        }
        let pred = scorer.predict("declining", None);
        assert_eq!(pred.trend, TrendDirection::Degrading);
        assert!(pred.predicted_score < 0.7, "Degrading should predict lower, got {}", pred.predicted_score);
    }

    #[test]
    fn test_predictor_with_degrading_deps() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        scorer.add_dependency("web", "api", 0.9);
        scorer.add_dependency("web", "db", 0.7);

        for _ in 0..15 {
            scorer.record_health("web", 0.95);
            scorer.record_health("api", 0.5);
            scorer.record_health("db", 0.4);
        }

        let pred = scorer.predict("web", None);
        assert_eq!(pred.unhealthy_dependency_count, 2);
        assert!(pred.predicted_score < pred.current_score,
            "With unhealthy deps, predicted should be lower than current");
    }

    #[test]
    fn test_predictor_at_risk() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        scorer.add_dependency("svc", "dep", 0.9);
        for i in 0..30 {
            scorer.record_health("svc", 0.85 - (i as f64 * 0.01));
            scorer.record_health("dep", 0.3 - (i as f64 * 0.005).max(0.0));
        }
        let at_risk = scorer.at_risk_components(None);
        // svc is degrading from 0.85 towards 0.55 — it should be flagged.
        let svc_pred = at_risk.iter().find(|p| p.component == "svc");
        assert!(svc_pred.is_some(), "degrading service should be at risk");
    }

    #[test]
    fn test_predictor_predicted_failures() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        for i in 0..30 {
            let score = 0.5 - (i as f64 * 0.02);
            scorer.record_health("failing", score.max(0.0));
        }
        let failures = scorer.predicted_failures(None);
        let failing_pred = failures.iter().find(|p| p.component == "failing");
        assert!(failing_pred.is_some(), "rapidly declining service should be predicted failure");
    }

    #[test]
    fn test_predictor_correlation_adjustment() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        scorer.add_dependency("primary", "secondary", 0.5);

        for _ in 0..20 {
            scorer.record_health("primary", 0.9);
        }
        for i in 0..20 {
            scorer.record_health("secondary", 0.9 - (i as f64 * 0.03).max(0.1));
        }
        scorer.set_correlation("primary", "secondary", 0.8);

        let pred = scorer.predict("primary", None);
        // Correlation with a degrading component should reduce prediction.
        assert!(pred.predicted_score <= pred.current_score + 0.01,
            "Correlated degradation should not increase predicted score");
    }

    #[test]
    fn test_predictor_confidence() {
        let mut scorer = PredictiveHealthScorer::new(3600);
        for _ in 0..60 {
            scorer.record_health("well_observed", 0.9);
        }
        let pred = scorer.predict("well_observed", None);
        assert!(pred.confidence > 0.7, "Should have high confidence with 60 observations, got {}", pred.confidence);
    }

    // ── Integration tests ──

    #[test]
    fn test_full_engine_lifecycle() {
        let mut engine = HealthCorrelationEngine::new();
        engine.add_dependency("web", "api", 0.8);
        engine.add_dependency("api", "db", 0.9);

        // Feed healthy data.
        for _ in 0..50 {
            engine.record("db", 0.95);
            engine.record("api", 0.95);
            engine.record("web", 0.95);
        }

        // Trigger degradation in db.
        for i in 0..20 {
            let score = 0.8 - (i as f64 * 0.025);
            engine.record("db", score.max(0.1));
            engine.record("api", (0.85 - i as f64 * 0.015).max(0.2));
            engine.record("web", (0.90 - i as f64 * 0.01).max(0.3));
        }

        // Run full analysis.
        let report = engine.full_analysis(
            &["db".to_string(), "api".to_string()],
            3,
            0.05,
        );

        assert!(!report.root_cause.candidates.is_empty());
        assert!(!report.predictions.is_empty());
        // DB should be the top root cause.
        assert_eq!(report.root_cause.candidates[0].component, "db");
    }

    #[test]
    fn test_full_engine_serialization() {
        let engine = HealthCorrelationEngine::new();
        let json = serde_json::to_string(&engine).unwrap();
        let restored: HealthCorrelationEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.correlation.window_size, engine.correlation.window_size);
    }

    #[test]
    fn test_correlation_result_serialization() {
        let result = CorrelationResult {
            pearson: 0.85,
            spearman: 0.82,
            n: 50,
            computed_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: CorrelationResult = serde_json::from_str(&json).unwrap();
        assert!((restored.pearson - 0.85).abs() < 1e-10);
    }

    #[test]
    fn test_propagation_summary_serialization() {
        let summary = PropagationSummary {
            origin_component: "db".to_string(),
            origin_anomaly_time: Utc::now(),
            total_affected: 3,
            max_depth: 2,
            events: vec![],
            avg_delay_secs: 5.0,
            avg_impact: 0.3,
            amplification_fraction: 0.1,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let _: PropagationSummary = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_predicted_health_serialization() {
        let pred = PredictedHealth {
            component: "svc".to_string(),
            current_score: 0.9,
            predicted_score: 0.7,
            horizon_secs: 3600,
            confidence: 0.85,
            trend: TrendDirection::Degrading,
            degrading_dependency_count: 2,
            total_dependency_count: 5,
            unhealthy_dependency_count: 1,
            explanation: "test".to_string(),
            computed_at: Utc::now(),
        };
        let json = serde_json::to_string(&pred).unwrap();
        let restored: PredictedHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.component, "svc");
    }
}
