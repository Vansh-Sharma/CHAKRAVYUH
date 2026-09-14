// ANANTA Anomaly Prediction Engine
//
// Production-grade time-series anomaly prediction for the health trust plane.
// Provides:
//   - ARIMA(p,d,q) for univariate forecasting
//   - Holt-Winters triple exponential smoothing
//   - Classical seasonal decomposition (additive model)
//   - Multi-method anomaly scoring (Z-score, IQR, prediction intervals)
//   - CUSUM change-point detection
//
// All mathematical operations are self-contained — no external numeric
// libraries are required. Matrix algebra is implemented inline for
// the small systems (up to ~10×10) encountered in coefficient
// estimation.

use serde::{Deserialize, Serialize};
use super::HealthStatus;

// ────────────────────────────────────────────────────────────────────
// Linear-algebra helpers
// ────────────────────────────────────────────────────────────────────

/// Dot product of two equal-length slices.
///
/// # Panics
/// Panics if `a` and `b` have different lengths.
#[inline]
fn dot(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len(), "dot: length mismatch");
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Multiply matrix `a` (rows × k) by matrix `b` (k × cols),
/// returning a new matrix of shape (rows × cols).
///
/// # Panics
/// Panics if the inner dimensions do not match.
fn mat_mul(a: &[Vec<f64>], b: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let rows = a.len();
    let k = a[0].len();
    let cols = b[0].len();
    assert_eq!(b.len(), k, "mat_mul: inner dim mismatch");
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

/// Transpose a matrix.
fn mat_transpose(m: &[Vec<f64>]) -> Vec<Vec<f64>> {
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

/// Solve the normal equations `X^T X β = X^T y` via Gaussian
/// elimination with partial pivoting.
///
/// Returns `Some(β)` on success, `None` if the system is singular.
fn least_squares(x: &[Vec<f64>], y: &[f64]) -> Option<Vec<f64>> {
    let n = y.len();
    let p = x[0].len();
    if n < p {
        return None;
    }
    let xt = mat_transpose(x);
    let xtx = mat_mul(&xt, x);
    let xty: Vec<f64> = (0..p).map(|i| dot(&xt[i], y)).collect();

    // Augmented matrix [ A | b ]
    let mut aug: Vec<Vec<f64>> = xtx
        .into_iter()
        .zip(xty.into_iter())
        .map(|(mut row, b)| {
            row.push(b);
            row
        })
        .collect();

    // Gaussian elimination with partial pivoting
    for col in 0..p {
        // Find pivot
        let mut max_val = aug[col][col].abs();
        let mut max_row = col;
        for row in (col + 1)..p {
            if aug[row][col].abs() > max_val {
                max_val = aug[row][col].abs();
                max_row = row;
            }
        }
        if max_val < 1e-12 {
            return None; // singular
        }
        aug.swap(col, max_row);
        // Eliminate below
        for row in (col + 1)..p {
            let factor = aug[row][col] / aug[col][col];
            for j in col..=p {
                aug[row][j] -= factor * aug[col][j];
            }
        }
    }

    // Back-substitution
    let mut beta = vec![0.0; p];
    for i in (0..p).rev() {
        let mut s = aug[i][p];
        for j in (i + 1)..p {
            s -= aug[i][j] * beta[j];
        }
        beta[i] = s / aug[i][i];
    }
    Some(beta)
}

/// Compute the mean of a slice.
#[inline]
fn mean(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f64>() / data.len() as f64
}

/// Compute the population variance (divides by N).
#[inline]
fn variance(data: &[f64]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let m = mean(data);
    let ss: f64 = data.iter().map(|x| (x - m).powi(2)).sum();
    ss / data.len() as f64
}

/// Compute the sample standard deviation.
#[inline]
fn std_dev(data: &[f64]) -> f64 {
    variance(data).sqrt()
}

/// Compute the p-th percentile using linear interpolation.
/// `p` must be in [0, 100].
fn percentile(data: &mut [f64], p: f64) -> f64 {
    assert!(data.len() >= 2, "percentile needs at least 2 points");
    assert!((0.0..=100.0).contains(&p), "p out of [0,100]");
    data.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = data.len() as f64;
    let k = (p / 100.0) * (n - 1.0);
    let lo = k.floor() as usize;
    let hi = k.ceil() as usize;
    if lo == hi {
        data[lo]
    } else {
        let frac = k - lo as f64;
        data[lo] * (1.0 - frac) + data[hi] * frac
    }
}

// ────────────────────────────────────────────────────────────────────
// ARIMA Model
// ────────────────────────────────────────────────────────────────────

/// Configuration for an ARIMA(p, d, q) model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArimaConfig {
    /// Autoregressive order.
    pub p: usize,
    /// Differencing order (0, 1, or 2).
    pub d: usize,
    /// Moving-average order.
    pub q: usize,
}

impl Default for ArimaConfig {
    fn default() -> Self {
        Self { p: 2, d: 1, q: 1 }
    }
}

impl ArimaConfig {
    /// Create a new ARIMA configuration.
    ///
    /// # Panics
    /// Panics if `d` > 2.
    pub fn new(p: usize, d: usize, q: usize) -> Self {
        assert!(d <= 2, "ArimaConfig: d must be 0, 1, or 2");
        Self { p, d, q }
    }
}

/// A fitted ARIMA model ready for forecasting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArimaModel {
    /// Model configuration.
    pub config: ArimaConfig,
    /// AR coefficients φ₁ … φₚ.
    pub ar_coeffs: Vec<f64>,
    /// MA coefficients θ₁ … θ_q.
    pub ma_coeffs: Vec<f64>,
    /// Residual standard error σ.
    pub sigma: f64,
    /// The differenced series used during fitting.
    pub differenced: Vec<f64>,
    /// Residuals from fitting.
    pub residuals: Vec<f64>,
    /// Pre-differencing values needed for inversion.
    pub pre_diff: Vec<f64>,
}

impl ArimaModel {
    /// Fit an ARIMA(p, d, q) model to the observed series `y`
    /// using least-squares on the lag matrix.
    ///
    /// # Errors
    /// Returns `Err` if the series is too short for the requested
    /// order or if the least-squares system is singular.
    pub fn fit(y: &[f64], config: ArimaConfig) -> Result<Self, String> {
        let min_len = config.p.max(config.q) + config.d + 2;
        if y.len() < min_len {
            return Err(format!(
                "ARIMA fit requires at least {} observations, got {}",
                min_len,
                y.len()
            ));
        }

        // --- differencing ---
        let (differenced, pre_diff) = Self::difference(y, config.d);
        let d_len = differenced.len();

        // --- Build design matrix for regression ---
        // For AR(p): regress y_t on y_{t-1}, …, y_{t-p}
        // For MA(q): regress y_t on ε_{t-1}, …, ε_{t-q}
        //
        // Strategy: iterative procedure.
        //   1. Fit pure AR(p) via OLS.
        //   2. Compute residuals ε_t = y_t - Σ φ_i y_{t-i}.
        //   3. Re-fit with both AR lags and MA(lag of ε) as regressors.
        //
        // This is the Hannan-Rissanen style initialisation.

        let max_lag = config.p.max(config.q);
        let n_eff = d_len.saturating_sub(max_lag);
        if n_eff < 1 {
            return Err("Not enough differenced observations for the lag matrix".into());
        }

        // Step 1: pure AR fit
        let mut design: Vec<Vec<f64>> = Vec::with_capacity(n_eff);
        let mut target: Vec<f64> = Vec::with_capacity(n_eff);

        for t in max_lag..d_len {
            let mut row = Vec::with_capacity(config.p + config.q);
            for k in 1..=config.p {
                row.push(differenced[t - k]);
            }
            // MA lags are zero for the first pass
            for _ in 0..config.q {
                row.push(0.0);
            }
            design.push(row);
            target.push(differenced[t]);
        }

        let ar_only: Vec<Vec<f64>> = design
            .iter()
            .map(|row| row[..config.p].to_vec())
            .collect();

        let ar_coeffs = if config.p > 0 {
            least_squares(&ar_only, &target).ok_or("AR coefficient estimation failed (singular matrix)")?
        } else {
            vec![]
        };

        // Step 2: compute residuals from AR-only model
        let mut ar_residuals: Vec<f64> = vec![0.0; d_len];
        for t in max_lag..d_len {
            let mut pred = 0.0;
            for (k, phi) in ar_coeffs.iter().enumerate() {
                pred += phi * differenced[t - 1 - k];
            }
            ar_residuals[t] = differenced[t] - pred;
        }

        // Step 3: re-fit with MA lags
        for (i, row) in design.iter_mut().enumerate() {
            let t = max_lag + i;
            for k in 1..=config.q {
                row[config.p + k - 1] = ar_residuals[t - k];
            }
        }

        let total_params = config.p + config.q;
        let full_coeffs = if total_params > 0 {
            least_squares(&design, &target).ok_or("Full ARMA coefficient estimation failed")?
        } else {
            vec![]
        };

        let ar_coeffs_final = full_coeffs[..config.p].to_vec();
        let ma_coeffs_final = if config.q > 0 {
            full_coeffs[config.p..].to_vec()
        } else {
            vec![]
        };

        // Step 4: compute final residuals
        let mut residuals = vec![0.0; d_len];
        for t in max_lag..d_len {
            let mut pred = 0.0;
            for (k, phi) in ar_coeffs_final.iter().enumerate() {
                pred += phi * differenced[t - 1 - k];
            }
            for (k, theta) in ma_coeffs_final.iter().enumerate() {
                let res_idx = t - 1 - k;
                pred += theta * residuals.get(res_idx).copied().unwrap_or(0.0);
            }
            residuals[t] = differenced[t] - pred;
        }

        // Only count residuals where we had full lags
        let fitted_residuals: Vec<f64> = residuals[max_lag..].to_vec();
        let sigma = std_dev(&fitted_residuals);

        Ok(Self {
            config,
            ar_coeffs: ar_coeffs_final,
            ma_coeffs: ma_coeffs_final,
            sigma,
            differenced,
            residuals: fitted_residuals,
            pre_diff,
        })
    }

    /// Difference the series `y` `d` times.
    /// Returns (differenced_series, pre-differencing values for inversion).
    fn difference(y: &[f64], d: usize) -> (Vec<f64>, Vec<f64>) {
        if d == 0 {
            return (y.to_vec(), vec![]);
        }
        let mut current = y.to_vec();
        // Store the values we'll need for inversion: the last `d` values
        // before each differencing step.
        let mut pre = Vec::new();
        for _ in 0..d {
            let last_val = current.last().copied().unwrap_or(0.0);
            pre.push(last_val);
            let mut diff = Vec::with_capacity(current.len() - 1);
            for i in 1..current.len() {
                diff.push(current[i] - current[i - 1]);
            }
            current = diff;
        }
        (current, pre)
    }

    /// Invert differencing: given the last `d` original-level values
    /// and a forecast of the differenced series, return the level forecast.
    fn invert_difference(
        pre_diff: &[f64],
        diff_forecast: &[f64],
        d: usize,
    ) -> Vec<f64> {
        if d == 0 {
            return diff_forecast.to_vec();
        }
        // We need the last `d` actual values before differencing
        // stored in reverse order: pre_diff[0] is the last value before
        // the first difference, etc.
        let mut current = diff_forecast.to_vec();
        for dd in (0..d).rev() {
            let base = pre_diff[dd];
            let mut restored = Vec::with_capacity(current.len() + 1);
            restored.push(base);
            for v in &current {
                restored.push(*restored.last().unwrap() + v);
            }
            current = restored;
        }
        // Drop the initial seed value
        current[1..].to_vec()
    }

    /// Produce `steps`-ahead point forecasts.
    ///
    /// For multi-step forecasts beyond the MA window, residuals are
    /// assumed zero.
    pub fn forecast(&self, steps: usize) -> Vec<f64> {
        if steps == 0 {
            return vec![];
        }

        let p = self.config.p;
        let q = self.config.q;
        let _max_lag = p.max(q);

        // Build an extended differenced series: original + forecast
        let mut ext = self.differenced.clone();
        let d_len = ext.len();

        // We also need extended residuals (zero for future)
        let mut ext_res = vec![0.0; d_len];
        for (i, r) in self.residuals.iter().enumerate() {
            ext_res[d_len - self.residuals.len() + i] = *r;
        }

        for _ in 0..steps {
            let t = ext.len();
            let mut pred = 0.0;
            // AR component: use actual or forecast values
            for (k, phi) in self.ar_coeffs.iter().enumerate() {
                let lag_idx = t - 1 - k;
                pred += phi * ext.get(lag_idx).copied().unwrap_or(0.0);
            }
            // MA component: use actual residuals or zero
            for (k, theta) in self.ma_coeffs.iter().enumerate() {
                let lag_idx = t - 1 - k;
                pred += theta * ext_res.get(lag_idx).copied().unwrap_or(0.0);
            }
            ext.push(pred);
            ext_res.push(0.0); // future residual assumed 0
        }

        let diff_forecast: Vec<f64> = ext[d_len..].to_vec();
        Self::invert_difference(&self.pre_diff, &diff_forecast, self.config.d)
    }

    /// Produce prediction intervals for `steps` ahead at the given
    /// z-critical value (e.g. 1.96 for 95%).
    ///
    /// Returns `(lower, point, upper)` triples.
    pub fn forecast_intervals(
        &self,
        steps: usize,
        z_crit: f64,
    ) -> Vec<PredictionInterval> {
        let points = self.forecast(steps);
        let p = self.config.p;
        let q = self.config.q;
        let _max_lag = p.max(q);
        let d_len = self.differenced.len();

        // Build the ψ-weights (infinite MA representation coefficients)
        // ψ_0 = 1, and for j >= 1:
        //   ψ_j = φ_1 ψ_{j-1} + … + φ_p ψ_{j-p} + θ_j  (θ_j=0 for j>q)
        let max_psi = steps + d_len + 20;
        let mut psi = vec![0.0; max_psi];
        psi[0] = 1.0;
        for j in 1..max_psi {
            let mut s = 0.0;
            for (k, phi) in self.ar_coeffs.iter().enumerate() {
                if j > k {
                    s += phi * psi[j - 1 - k];
                }
            }
            if j <= q {
                s += self.ma_coeffs.get(j - 1).copied().unwrap_or(0.0);
            }
            psi[j] = s;
        }

        // The h-step forecast error variance (on the differenced scale)
        // σ²_h = σ² Σ_{j=0}^{h-1} ψ_j²
        let mut result = Vec::with_capacity(steps);
        for h in 1..=steps {
            let psi_sum_sq: f64 = (0..h).map(|j| psi[j].powi(2)).sum();
            let se_diff = self.sigma * psi_sum_sq.sqrt();
            // Approximate: same SE after inversion (simplification)
            let se = se_diff;
            let pt = points[h - 1];
            result.push(PredictionInterval {
                lower: pt - z_crit * se,
                point: pt,
                upper: pt + z_crit * se,
            });
        }
        result
    }
}

/// A single prediction interval (lower, point, upper).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionInterval {
    pub lower: f64,
    pub point: f64,
    pub upper: f64,
}

// ────────────────────────────────────────────────────────────────────
// Holt-Winters Triple Exponential Smoothing
// ────────────────────────────────────────────────────────────────────

/// Configuration for Holt-Winters (triple exponential smoothing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoltWintersConfig {
    /// Level smoothing parameter α ∈ (0, 1).
    pub alpha: f64,
    /// Trend smoothing parameter β ∈ (0, 1).
    pub beta: f64,
    /// Seasonal smoothing parameter γ ∈ (0, 1).
    pub gamma: f64,
    /// Season length (number of observations per cycle).
    pub season_length: usize,
    /// Damping factor for the trend (1.0 = no damping).
    pub phi: f64,
}

impl Default for HoltWintersConfig {
    fn default() -> Self {
        Self {
            alpha: 0.2,
            beta: 0.1,
            gamma: 0.1,
            season_length: 12,
            phi: 1.0,
        }
    }
}

impl HoltWintersConfig {
    /// Create a new Holt-Winters configuration.
    ///
    /// # Panics
    /// Panics if `season_length` < 2.
    pub fn new(alpha: f64, beta: f64, gamma: f64, season_length: usize) -> Self {
        assert!(season_length >= 2, "season_length must be >= 2");
        Self {
            alpha: alpha.clamp(1e-6, 1.0 - 1e-6),
            beta: beta.clamp(1e-6, 1.0 - 1e-6),
            gamma: gamma.clamp(1e-6, 1.0 - 1e-6),
            season_length,
            phi: 1.0,
        }
    }

    /// Builder: set the trend damping factor.
    pub fn with_damping(mut self, phi: f64) -> Self {
        self.phi = phi.clamp(0.8, 1.0);
        self
    }
}

/// A fitted Holt-Winters model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoltWintersModel {
    /// Model configuration.
    pub config: HoltWintersConfig,
    /// Final level component ℓ_T.
    pub level: f64,
    /// Final trend component b_T.
    pub trend: f64,
    /// Seasonal components s_{T-m+1}, …, s_T.
    pub seasonal: Vec<f64>,
    /// In-sample residuals.
    pub residuals: Vec<f64>,
    /// In-sample fitted values.
    pub fitted: Vec<f64>,
}

impl HoltWintersModel {
    /// Fit a Holt-Winters model with additive seasonality.
    ///
    /// Initialisation:
    ///   - Level: mean of the first season.
    ///   - Trend: average slope across the first two seasons.
    ///   - Seasonal: average deviation from level per season position.
    ///
    /// # Errors
    /// Returns `Err` if the series is shorter than 2 × season_length.
    pub fn fit(y: &[f64], config: HoltWintersConfig) -> Result<Self, String> {
        let m = config.season_length;
        if y.len() < 2 * m {
            return Err(format!(
                "Holt-Winters needs at least 2*season_length={} observations, got {}",
                2 * m,
                y.len()
            ));
        }

        // --- Initialisation ---
        // Level: mean of first season
        let level_init: f64 = y[..m].iter().sum::<f64>() / m as f64;

        // Trend: (mean of second season - mean of first season) / m
        let level2: f64 = y[m..2 * m].iter().sum::<f64>() / m as f64;
        let trend_init = (level2 - level_init) / m as f64;

        // Seasonal indices from the first two seasons
        let mut season_init = vec![0.0; m];
        for s in 0..m {
            let avg = (y[s] + y[m + s]) / 2.0;
            season_init[s] = avg - level_init;
        }
        // Normalise so they sum to zero (additive)
        let s_avg: f64 = season_init.iter().sum::<f64>() / m as f64;
        for s in season_init.iter_mut() {
            *s -= s_avg;
        }

        // --- Smoothing recursion ---
        let mut level = level_init;
        let mut trend = trend_init;
        let mut seasonal = season_init;
        let mut residuals = Vec::with_capacity(y.len());
        let mut fitted_vals = Vec::with_capacity(y.len());

        for t in 0..y.len() {
            let s_idx = t % m;
            // One-step-ahead forecast
            let forecast = level + config.phi * trend + seasonal[s_idx];
            let res = y[t] - forecast;
            residuals.push(res);
            fitted_vals.push(forecast);

            // Update components
            let new_level = config.alpha * (y[t] - seasonal[s_idx])
                + (1.0 - config.alpha) * (level + config.phi * trend);
            let new_trend = config.beta * (new_level - level)
                + (1.0 - config.beta) * config.phi * trend;
            let new_seasonal = config.gamma * (y[t] - new_level)
                + (1.0 - config.gamma) * seasonal[s_idx];

            level = new_level;
            trend = new_trend;
            seasonal[s_idx] = new_seasonal;
        }

        Ok(Self {
            config,
            level,
            trend,
            seasonal,
            residuals,
            fitted: fitted_vals,
        })
    }

    /// Produce `h`-step-ahead point forecasts.
    pub fn forecast(&self, h: usize) -> Vec<f64> {
        let m = self.config.season_length;
        let mut result = Vec::with_capacity(h);
        for i in 1..=h {
            // Trend accumulates with damping: b_T Σ_{j=0}^{h-1} φ^j
            let phi_pow_sum: f64 = (0..i)
                .map(|j| self.config.phi.powi(j as i32))
                .sum();
            let s_idx = (self.seasonal.len() - m + (i - 1) % m) % m;
            let pt = self.level + self.trend * phi_pow_sum + self.seasonal[s_idx];
            result.push(pt);
        }
        result
    }

    /// Produce prediction intervals at the given z-critical value.
    ///
    /// Uses a simplified variance model:
    ///   σ²_h = σ² [1 + α² Σ_{j=0}^{h-2} (Σ_{k=0}^{j} ψ_k)²]
    /// where ψ_k are the recursive MA weights.
    pub fn forecast_intervals(
        &self,
        h: usize,
        z_crit: f64,
    ) -> Vec<PredictionInterval> {
        let sigma = std_dev(&self.residuals);
        let points = self.forecast(h);
        let alpha = self.config.alpha;
        let beta = self.config.beta;
        let phi = self.config.phi;

        // Recursive ψ-weights
        // ψ_0 = 1, ψ_1 = α + φβ - αφ, ψ_j = αφψ_{j-1} + φβψ_{j-1} ... simplified
        let max_psi = h + 10;
        let mut psi = vec![0.0; max_psi];
        psi[0] = 1.0;
        if max_psi > 1 {
            psi[1] = alpha + phi * beta - alpha * phi;
        }
        for j in 2..max_psi {
            psi[j] = alpha * phi * psi[j - 1] + phi * beta * psi[j - 1] - alpha * phi * beta * psi[j - 2];
            // Simplified: for additive Holt-Winters without seasonal correction
            // in the error variance
        }

        let mut result = Vec::with_capacity(h);
        for i in 1..=h {
            // Cumulative sum of psi weights
            let cum_psi: f64 = (0..i).map(|j| psi[j]).sum();
            let se = sigma * (1.0 + alpha * alpha * cum_psi * cum_psi).sqrt();
            let pt = points[i - 1];
            result.push(PredictionInterval {
                lower: pt - z_crit * se,
                point: pt,
                upper: pt + z_crit * se,
            });
        }
        result
    }

    /// Residual standard error.
    pub fn sigma(&self) -> f64 {
        std_dev(&self.residuals)
    }
}

// ────────────────────────────────────────────────────────────────────
// Classical Seasonal Decomposition (Additive)
// ────────────────────────────────────────────────────────────────────

/// Result of classical additive seasonal decomposition.
///
/// Model:  Y_t = T_t + S_t + R_t
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalDecomposition {
    /// Original observed series.
    pub observed: Vec<f64>,
    /// Trend component T_t (from centred moving average).
    pub trend: Vec<f64>,
    /// Seasonal component S_t.
    pub seasonal: Vec<f64>,
    /// Residual / irregular component R_t.
    pub residual: Vec<f64>,
    /// Season length used.
    pub season_length: usize,
}

impl SeasonalDecomposition {
    /// Perform classical additive decomposition.
    ///
    /// 1. Compute a centred moving average of window `season_length`
    ///    to extract the trend.
    /// 2. Detrend: D_t = Y_t − T_t.
    /// 3. Average detrended values for each seasonal position to get
    ///    seasonal indices. Normalise them to sum to zero.
    /// 4. Residual = Observed − Trend − Seasonal.
    ///
    /// # Errors
    /// Returns `Err` if the series is shorter than `2 * season_length`.
    pub fn decompose(y: &[f64], season_length: usize) -> Result<Self, String> {
        if y.len() < 2 * season_length {
            return Err(format!(
                "Seasonal decomposition needs >= 2*season_length={} points, got {}",
                2 * season_length,
                y.len()
            ));
        }
        let n = y.len();
        let m = season_length;

        // Step 1: Trend via centred moving average
        let trend = Self::centred_ma(y, m);

        // Step 2: Detrend
        let mut detrended = vec![0.0; n];
        for i in 0..n {
            detrended[i] = y[i] - trend[i];
        }

        // Step 3: Seasonal indices — average detrended values per position
        let mut season_sum = vec![0.0; m];
        let mut season_count = vec![0usize; m];
        for i in 0..n {
            if !trend[i].is_nan() {
                let pos = i % m;
                season_sum[pos] += detrended[i];
                season_count[pos] += 1;
            }
        }
        let mut seasonal_indices = vec![0.0; m];
        for s in 0..m {
            if season_count[s] > 0 {
                seasonal_indices[s] = season_sum[s] / season_count[s] as f64;
            }
        }
        // Normalise: sum of indices must be 0
        let s_mean: f64 = seasonal_indices.iter().sum::<f64>() / m as f64;
        for s in seasonal_indices.iter_mut() {
            *s -= s_mean;
        }

        // Tile seasonal indices across the full series
        let mut seasonal = vec![0.0; n];
        for i in 0..n {
            seasonal[i] = seasonal_indices[i % m];
        }

        // Step 4: Residual
        let mut residual = vec![0.0; n];
        for i in 0..n {
            residual[i] = y[i] - trend[i] - seasonal[i];
        }

        Ok(Self {
            observed: y.to_vec(),
            trend,
            seasonal,
            residual,
            season_length: m,
        })
    }

    /// Compute a centred moving average of window `m`.
    ///
    /// For even `m`, uses a 2×m centred MA (moving average of a
    /// moving average) to properly centre the window.
    /// Points near the boundaries that cannot be centred are set to NaN.
    fn centred_ma(y: &[f64], m: usize) -> Vec<f64> {
        let n = y.len();
        let mut trend = vec![f64::NAN; n];

        if m % 2 == 1 {
            // Odd window: straightforward centred MA
            let half = m / 2;
            for i in half..n.saturating_sub(half) {
                let start = i - half;
                let end = i + half + 1;
                let s: f64 = y[start..end].iter().sum();
                trend[i] = s / m as f64;
            }
        } else {
            // Even window: 2×m centred MA
            // First pass: 2-period MA
            let ma2: Vec<f64> = (0..n - 1)
                .map(|i| (y[i] + y[i + 1]) / 2.0)
                .collect();
            // Second pass: m-period MA on the 2-period MA
            let half = (m / 2) - 1;
            for i in half..ma2.len().saturating_sub(half) {
                let start = i - half;
                let end = i + half + 1;
                let s: f64 = ma2[start..end].iter().sum();
                // Original index mapping: i in ma2 corresponds to i+0.5 in y
                let y_idx = i + 1; // centre of 2-period MA
                if y_idx < n {
                    trend[y_idx] = s / (m - 1) as f64;
                }
            }
        }
        trend
    }

    /// Return the seasonal indices (one per season position).
    pub fn seasonal_indices(&self) -> Vec<f64> {
        let mut indices = vec![0.0; self.season_length];
        for s in 0..self.season_length {
            indices[s] = self.seasonal[s];
        }
        indices
    }

    /// Strength of seasonality: 1 − Var(residual) / Var(detrended).
    /// Values closer to 1 indicate stronger seasonality.
    pub fn seasonality_strength(&self) -> f64 {
        let detrended: Vec<f64> = self
            .observed
            .iter()
            .zip(self.trend.iter())
            .map(|(o, t)| o - t)
            .filter(|v| !v.is_nan())
            .collect();
        let residuals: Vec<f64> = self.residual.iter().filter(|v| !v.is_nan()).copied().collect();
        if detrended.len() < 2 || residuals.len() < 2 {
            return 0.0;
        }
        let var_det = variance(&detrended);
        let var_res = variance(&residuals);
        if var_det < 1e-15 {
            return 0.0;
        }
        (1.0 - var_res / var_det).clamp(0.0, 1.0)
    }
}

// ────────────────────────────────────────────────────────────────────
// Anomaly Scoring
// ────────────────────────────────────────────────────────────────────

/// Anomaly detection method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyMethod {
    /// Standardised Z-score: |z| > threshold.
    ZScore,
    /// Inter-Quartile Range based.
    Iqr,
    /// Point outside model prediction interval.
    PredictionInterval,
}

/// A single anomaly detected at a specific time index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPoint {
    /// Index in the original series.
    pub index: usize,
    /// Observed value.
    pub value: f64,
    /// Anomaly score (higher = more anomalous).
    pub score: f64,
    /// Which method(s) flagged this point.
    pub methods: Vec<AnomalyMethod>,
    /// Direction of the anomaly.
    pub direction: AnomalyDirection,
}

/// Direction of the anomaly relative to expected value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyDirection {
    /// Value is above expected.
    High,
    /// Value is below expected.
    Low,
    /// Value is above or below expected.
    Both,
}

/// Configuration for the multi-method anomaly detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectorConfig {
    /// Z-score threshold (default 3.0).
    pub z_threshold: f64,
    /// IQR multiplier k (default 1.5). Points outside
    /// [Q1 − k·IQR, Q3 + k·IQR] are flagged.
    pub iqr_k: f64,
    /// Z-critical value for prediction intervals (default 2.576 ≈ 99%).
    pub pi_z_crit: f64,
    /// Minimum number of observations to start scoring.
    pub min_obs: usize,
    /// ARIMA config (used if prediction-interval method is enabled).
    pub arima_config: Option<ArimaConfig>,
    /// Holt-Winters config (alternative model for prediction intervals).
    pub hw_config: Option<HoltWintersConfig>,
}

impl Default for AnomalyDetectorConfig {
    fn default() -> Self {
        Self {
            z_threshold: 3.0,
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 10,
            arima_config: Some(ArimaConfig::default()),
            hw_config: None,
        }
    }
}

/// Combined anomaly detector using multiple methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetector {
    pub config: AnomalyDetectorConfig,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with the given config.
    pub fn new(config: AnomalyDetectorConfig) -> Self {
        Self { config }
    }

    /// Detect anomalies in the series using all enabled methods.
    ///
    /// Returns a sorted list of `AnomalyPoint`s (by index), each
    /// annotated with which methods flagged it and a combined score.
    pub fn detect(&self, y: &[f64]) -> Vec<AnomalyPoint> {
        if y.len() < self.config.min_obs {
            return vec![];
        }

        let mut score_map: Vec<AnomalyCandidate> = vec![];

        // Z-score method
        let z_flags = self.zscore_flags(y);
        for (idx, (z_val, _dir)) in z_flags.iter().enumerate() {
            if let Some((z, d)) = z_val {
                score_map.push(AnomalyCandidate {
                    index: idx,
                    value: y[idx],
                    score: z.abs(),
                    method: AnomalyMethod::ZScore,
                    direction: d.clone(),
                });
            }
        }

        // IQR method
        let iqr_flags = self.iqr_flags(y);
        for (idx, (flag, dir)) in iqr_flags.iter().enumerate() {
            if *flag {
                // Score = normalised distance from nearest fence
                let q1 = self.quartile(y, 25.0);
                let q3 = self.quartile(y, 75.0);
                let iqr = q3 - q1;
                let fence_lo = q1 - self.config.iqr_k * iqr;
                let fence_hi = q3 + self.config.iqr_k * iqr;
                let dist = if y[idx] < fence_lo {
                    (fence_lo - y[idx]) / iqr.max(1e-12)
                } else {
                    (y[idx] - fence_hi) / iqr.max(1e-12)
                };
                score_map.push(AnomalyCandidate {
                    index: idx,
                    value: y[idx],
                    score: dist.max(0.0),
                    method: AnomalyMethod::Iqr,
                    direction: dir.clone(),
                });
            }
        }

        // Prediction interval method
        if self.config.arima_config.is_some() || self.config.hw_config.is_some() {
            let pi_flags = self.prediction_interval_flags(y);
            for (idx, (flag, dir)) in pi_flags.iter().enumerate() {
                if *flag {
                    score_map.push(AnomalyCandidate {
                        index: idx,
                        value: y[idx],
                        score: self.config.pi_z_crit, // at least z_crit
                        method: AnomalyMethod::PredictionInterval,
                        direction: dir.clone(),
                    });
                }
            }
        }

        // Aggregate by index
        let mut by_index: std::collections::HashMap<usize, AggAnomaly> = std::collections::HashMap::new();
        for c in score_map {
            let entry = by_index.entry(c.index).or_insert_with(|| AggAnomaly {
                index: c.index,
                value: c.value,
                methods: vec![],
                max_score: 0.0,
                direction: AnomalyDirection::Both,
            });
            if !entry.methods.contains(&c.method) {
                entry.methods.push(c.method);
            }
            entry.max_score = entry.max_score.max(c.score);
            // Combine directions
            entry.direction = match (&entry.direction, &c.direction) {
                (AnomalyDirection::Both, other) => other.clone(),
                (_, AnomalyDirection::Both) => entry.direction.clone(),
                (a, b) if a == b => a.clone(),
                _ => AnomalyDirection::Both,
            };
        }

        let mut result: Vec<AnomalyPoint> = by_index
            .into_values()
            .map(|a| AnomalyPoint {
                index: a.index,
                value: a.value,
                score: a.max_score,
                methods: a.methods,
                direction: a.direction,
            })
            .collect();
        result.sort_by_key(|a| a.index);
        result
    }

    /// Z-score flags: returns Option<(z_value, direction)> per point.
    /// None means not anomalous.
    fn zscore_flags(&self, y: &[f64]) -> Vec<(Option<(f64, AnomalyDirection)>, AnomalyDirection)> {
        let m = mean(y);
        let sd = std_dev(y);
        if sd < 1e-15 {
            return vec![(None, AnomalyDirection::Both); y.len()];
        }
        y.iter()
            .map(|v| {
                let z = (v - m) / sd;
                if z.abs() > self.config.z_threshold {
                    let dir = if z > 0.0 {
                        AnomalyDirection::High
                    } else {
                        AnomalyDirection::Low
                    };
                    (Some((z, dir.clone())), dir)
                } else {
                    (None, AnomalyDirection::Both)
                }
            })
            .collect()
    }

    /// IQR flags: returns (is_anomaly, direction) per point.
    fn iqr_flags(&self, y: &[f64]) -> Vec<(bool, AnomalyDirection)> {
        let q1 = self.quartile(y, 25.0);
        let q3 = self.quartile(y, 75.0);
        let iqr = q3 - q1;
        let lo = q1 - self.config.iqr_k * iqr;
        let hi = q3 + self.config.iqr_k * iqr;
        y.iter()
            .map(|v| {
                if *v < lo {
                    (true, AnomalyDirection::Low)
                } else if *v > hi {
                    (true, AnomalyDirection::High)
                } else {
                    (false, AnomalyDirection::Both)
                }
            })
            .collect()
    }

    /// Prediction-interval flags using the best available model.
    fn prediction_interval_flags(&self, y: &[f64]) -> Vec<(bool, AnomalyDirection)> {
        let intervals = if let Some(ref hw_cfg) = self.config.hw_config {
            match HoltWintersModel::fit(y, hw_cfg.clone()) {
                Ok(model) => model
                    .forecast_intervals(y.len(), self.config.pi_z_crit)
                    .into_iter()
                    .map(|pi| (pi.lower, pi.point, pi.upper))
                    .collect::<Vec<_>>(),
                Err(_) => {
                    // Fall back to ARIMA
                    self.arima_intervals(y)
                }
            }
        } else {
            self.arima_intervals(y)
        };

        y.iter()
            .zip(intervals.iter())
            .map(|(v, (lo, _pt, hi))| {
                if *v < *lo {
                    (true, AnomalyDirection::Low)
                } else if *v > *hi {
                    (true, AnomalyDirection::High)
                } else {
                    (false, AnomalyDirection::Both)
                }
            })
            .collect()
    }

    /// Get prediction intervals from ARIMA.
    fn arima_intervals(&self, y: &[f64]) -> Vec<(f64, f64, f64)> {
        let cfg = self.config.arima_config.as_ref().unwrap();
        match ArimaModel::fit(y, cfg.clone()) {
            Ok(_model) => {
                // For in-sample prediction intervals, we do a rolling
                // one-step forecast.
                let n = y.len();
                let max_lag = cfg.p.max(cfg.q);
                let mut result = vec![(f64::NEG_INFINITY, 0.0, f64::INFINITY); n];
                // For the first max_lag points we can't forecast
                for t in (max_lag + cfg.d)..n {
                    let train = &y[..t];
                    if let Ok(m) = ArimaModel::fit(train, cfg.clone()) {
                        if let Some(pi) = m.forecast_intervals(1, self.config.pi_z_crit).first() {
                            result[t] = (pi.lower, pi.point, pi.upper);
                        }
                    }
                }
                result
            }
            Err(_) => vec![(f64::NEG_INFINITY, 0.0, f64::INFINITY); y.len()],
        }
    }

    /// Compute the p-th quartile (p in 0..100) of the data.
    fn quartile(&self, y: &[f64], p: f64) -> f64 {
        let mut buf = y.to_vec();
        percentile(&mut buf, p)
    }
}

/// Internal helper for aggregating anomaly candidates.
struct AnomalyCandidate {
    index: usize,
    value: f64,
    score: f64,
    method: AnomalyMethod,
    direction: AnomalyDirection,
}

/// Internal aggregation struct.
struct AggAnomaly {
    index: usize,
    value: f64,
    methods: Vec<AnomalyMethod>,
    max_score: f64,
    direction: AnomalyDirection,
}

// ────────────────────────────────────────────────────────────────────
// CUSUM Change-Point Detection
// ────────────────────────────────────────────────────────────────────

/// Configuration for the CUSUM change-point detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CusumConfig {
    /// The target mean (or pre-change mean estimate).
    /// If `None`, it is estimated from the first `warmup` points.
    pub target_mean: Option<f64>,
    /// The allowable slack / drift parameter k.
    /// Typically set to 0.5 * expected shift magnitude.
    pub k: f64,
    /// Decision threshold h. CUSUM signals when S > h.
    pub h: f64,
    /// Number of initial observations used to estimate the mean
    /// and variance when `target_mean` is `None`.
    pub warmup: usize,
}

impl Default for CusumConfig {
    fn default() -> Self {
        Self {
            target_mean: None,
            k: 0.5,
            h: 4.0,
            warmup: 20,
        }
    }
}

impl CusumConfig {
    /// Create a new CUSUM configuration.
    pub fn new(k: f64, h: f64, warmup: usize) -> Self {
        Self {
            target_mean: None,
            k,
            h,
            warmup,
        }
    }

    /// Set the target mean explicitly.
    pub fn with_target_mean(mut self, mu: f64) -> Self {
        self.target_mean = Some(mu);
        self
    }
}

/// A detected change point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    /// Index in the original series where the change was detected.
    pub index: usize,
    /// Value at the change point.
    pub value: f64,
    /// Estimated post-change mean (up to this point).
    pub post_change_mean: f64,
    /// CUSUM statistic at detection.
    pub statistic: f64,
}

/// CUSUM (Cumulative Sum) change-point detector.
///
/// Maintains two one-sided statistics:
///   S⁺_t = max(0, S⁺_{t-1} + (x_t − μ₀ − k))
///   S⁻_t = max(0, S⁻_{t-1} + (μ₀ − k − x_t))
///
/// A change is signalled when either S⁺ or S⁻ exceeds `h`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CusumDetector {
    pub config: CusumConfig,
}

impl CusumDetector {
    /// Create a new CUSUM detector.
    pub fn new(config: CusumConfig) -> Self {
        Self { config }
    }

    /// Run CUSUM on the series and return all detected change points.
    ///
    /// After a detection, the CUSUM statistics reset and the target
    /// mean is updated to the post-change mean (adaptive CUSUM).
    pub fn detect(&self, y: &[f64]) -> Vec<ChangePoint> {
        if y.len() < self.config.warmup + 2 {
            return vec![];
        }

        let mu0 = self.config.target_mean.unwrap_or_else(|| mean(&y[..self.config.warmup]));
        let k = self.config.k;
        let h = self.config.h;

        let mut s_plus: f64 = 0.0;
        let mut s_minus: f64 = 0.0;
        let mut current_mu = mu0;
        let mut change_points = Vec::new();
        let mut run_start = 0;

        for t in 0..y.len() {
            s_plus = (s_plus + (y[t] - current_mu - k)).max(0.0);
            s_minus = (s_minus + (current_mu - k - y[t])).max(0.0);

            if s_plus > h || s_minus > h {
                // Estimate post-change mean from the current run
                let run_data = &y[run_start..=t];
                let post_mean = mean(run_data);
                change_points.push(ChangePoint {
                    index: t,
                    value: y[t],
                    post_change_mean: post_mean,
                    statistic: s_plus.max(s_minus),
                });
                // Reset
                s_plus = 0.0;
                s_minus = 0.0;
                current_mu = post_mean;
                run_start = t + 1;
            }
        }
        change_points
    }

    /// Return the full CUSUM statistic series (S⁺, S⁻) for plotting.
    pub fn statistics(&self, y: &[f64]) -> Vec<(f64, f64)> {
        if y.len() < self.config.warmup {
            return vec![];
        }
        let mu0 = self.config.target_mean.unwrap_or_else(|| mean(&y[..self.config.warmup]));
        let k = self.config.k;

        let mut s_plus: f64 = 0.0;
        let mut s_minus: f64 = 0.0;
        let mut result = Vec::with_capacity(y.len());

        for &v in y {
            s_plus = (s_plus + (v - mu0 - k)).max(0.0);
            s_minus = (s_minus + (mu0 - k - v)).max(0.0);
            result.push((s_plus, s_minus));
        }
        result
    }
}

// ────────────────────────────────────────────────────────────────────
// High-Level Anomaly Prediction Engine
// ────────────────────────────────────────────────────────────────────

/// The result of running the full anomaly prediction pipeline
/// on a single component's health-score time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPredictionResult {
    /// Component name.
    pub component: String,
    /// ARIMA point forecast (next `forecast_horizon` steps).
    pub arima_forecast: Option<Vec<f64>>,
    /// ARIMA prediction intervals.
    pub arima_intervals: Option<Vec<PredictionInterval>>,
    /// Holt-Winters point forecast.
    pub hw_forecast: Option<Vec<f64>>,
    /// Holt-Winters prediction intervals.
    pub hw_intervals: Option<Vec<PredictionInterval>>,
    /// Detected anomaly points in the historical data.
    pub anomalies: Vec<AnomalyPoint>,
    /// Detected change points.
    pub change_points: Vec<ChangePoint>,
    /// Seasonal decomposition result.
    pub decomposition: Option<SeasonalDecomposition>,
    /// Overall predicted status.
    pub predicted_status: HealthStatus,
    /// Confidence in the prediction.
    pub confidence: f64,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Configuration for the full anomaly prediction pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionEngineConfig {
    /// ARIMA configuration.
    pub arima: ArimaConfig,
    /// Holt-Winters configuration.
    pub holt_winters: Option<HoltWintersConfig>,
    /// Anomaly detector configuration.
    pub anomaly: AnomalyDetectorConfig,
    /// CUSUM configuration.
    pub cusum: CusumConfig,
    /// How many steps ahead to forecast.
    pub forecast_horizon: usize,
    /// Season length for decomposition (0 = skip).
    pub season_length: usize,
    /// Z-critical for prediction intervals.
    pub z_crit: f64,
}

impl Default for PredictionEngineConfig {
    fn default() -> Self {
        Self {
            arima: ArimaConfig::default(),
            holt_winters: Some(HoltWintersConfig::default()),
            anomaly: AnomalyDetectorConfig::default(),
            cusum: CusumConfig::default(),
            forecast_horizon: 10,
            season_length: 0, // skip decomposition by default
            z_crit: 2.576,
        }
    }
}

/// The main anomaly prediction engine that orchestrates all
/// statistical models and anomaly detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPredictionEngine {
    pub config: PredictionEngineConfig,
}

impl AnomalyPredictionEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: PredictionEngineConfig) -> Self {
        Self { config }
    }

    /// Run the full prediction pipeline on a component's score history.
    pub fn predict(&self, component: &str, scores: &[f64]) -> AnomalyPredictionResult {
        let mut result = AnomalyPredictionResult {
            component: component.to_string(),
            arima_forecast: None,
            arima_intervals: None,
            hw_forecast: None,
            hw_intervals: None,
            anomalies: vec![],
            change_points: vec![],
            decomposition: None,
            predicted_status: HealthStatus::Unknown,
            confidence: 0.0,
            explanation: String::new(),
        };

        // --- ARIMA ---
        let arima_ok = if scores.len() >= self.config.arima.p.max(self.config.arima.q) + self.config.arima.d + 5 {
            match ArimaModel::fit(scores, self.config.arima.clone()) {
                Ok(model) => {
                    let fc = model.forecast(self.config.forecast_horizon);
                    let pi = model.forecast_intervals(self.config.forecast_horizon, self.config.z_crit);
                    result.arima_forecast = Some(fc.clone());
                    result.arima_intervals = Some(pi);
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        };

        // --- Holt-Winters ---
        let hw_ok = if let Some(ref hw_cfg) = self.config.holt_winters {
            if scores.len() >= 2 * hw_cfg.season_length {
                match HoltWintersModel::fit(scores, hw_cfg.clone()) {
                    Ok(model) => {
                        let fc = model.forecast(self.config.forecast_horizon);
                        let pi = model.forecast_intervals(self.config.forecast_horizon, self.config.z_crit);
                        result.hw_forecast = Some(fc.clone());
                        result.hw_intervals = Some(pi);
                        true
                    }
                    Err(_) => false,
                }
            } else {
                false
            }
        } else {
            false
        };

        // --- Seasonal Decomposition ---
        if self.config.season_length >= 2 {
            if let Ok(dec) = SeasonalDecomposition::decompose(scores, self.config.season_length) {
                result.decomposition = Some(dec);
            }
        }

        // --- Anomaly Detection ---
        let detector = AnomalyDetector::new(self.config.anomaly.clone());
        result.anomalies = detector.detect(scores);

        // --- Change Point Detection ---
        let cusum = CusumDetector::new(self.config.cusum.clone());
        result.change_points = cusum.detect(scores);

        // --- Synthesise prediction ---
        self.synthesise(scores, &mut result, arima_ok, hw_ok);
        result
    }

    /// Combine model outputs into a status prediction and explanation.
    fn synthesise(
        &self,
        scores: &[f64],
        result: &mut AnomalyPredictionResult,
        arima_ok: bool,
        hw_ok: bool,
    ) {
        let current = *scores.last().unwrap_or(&1.0);
        let mut reasons: Vec<String> = vec![];
        let mut predicted_value = current;
        let mut confidence = 0.5;

        // Use the best available forecast
        if arima_ok {
            if let Some(ref fc) = result.arima_forecast {
                if let Some(&last) = fc.last() {
                    predicted_value = last;
                    confidence = 0.7;
                    reasons.push(format!(
                        "ARIMA forecast: {:.3} → {:.3}",
                        current, last
                    ));
                }
            }
        }
        if hw_ok {
            if let Some(ref fc) = result.hw_forecast {
                if let Some(&last) = fc.last() {
                    // If both models agree, boost confidence
                    if (predicted_value - last).abs() < 0.1 {
                        confidence = (confidence + 0.8) / 2.0;
                        reasons.push(format!(
                            "Holt-Winters confirms: {:.3}",
                            last
                        ));
                    } else {
                        predicted_value = (predicted_value + last) / 2.0;
                        reasons.push(format!(
                            "Holt-Winters diverges: {:.3}",
                            last
                        ));
                    }
                }
            }
        }

        // Factor in recent anomalies
        let n_anomalies = result.anomalies.len();
        if n_anomalies > 0 {
            let recent_anom = result
                .anomalies
                .iter()
                .filter(|a| a.index + 5 >= scores.len())
                .count();
            if recent_anom > 0 {
                confidence = (confidence + 0.15 * recent_anom as f64).min(0.98);
                reasons.push(format!(
                    "{} recent anomaly signal(s)",
                    recent_anom
                ));
            }
        }

        // Factor in change points
        if !result.change_points.is_empty() {
            let last_cp = result.change_points.last().unwrap();
            if last_cp.index + 10 >= scores.len() {
                reasons.push(format!(
                    "recent change point at t={} (stat={:.2})",
                    last_cp.index, last_cp.statistic
                ));
                confidence = (confidence + 0.1).min(0.98);
            }
        }

        // Determine predicted status
        result.predicted_status = if predicted_value >= 0.8 {
            HealthStatus::Healthy
        } else if predicted_value >= 0.6 {
            HealthStatus::Degraded
        } else if predicted_value >= 0.2 {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Failed
        };

        result.confidence = confidence;
        result.explanation = if reasons.is_empty() {
            "insufficient model agreement".to_string()
        } else {
            reasons.join("; ")
        };
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: generate a simple AR(1) series: y_t = 0.7 * y_{t-1} + noise
    fn ar1_series(n: usize, phi: f64, seed: f64) -> Vec<f64> {
        let mut y = vec![0.0; n];
        // Simple LCG for reproducibility
        let mut rng = seed as u64;
        let next_rand = |rng: &mut u64| -> f64 {
            *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((*rng >> 33) as f64) / 2147483648.0 - 0.5
        };
        for t in 1..n {
            y[t] = phi * y[t - 1] + next_rand(&mut rng) * 0.3;
        }
        y
    }

    // Helper: generate seasonal data + trend
    fn seasonal_series(n: usize, m: usize, trend_slope: f64) -> Vec<f64> {
        (0..n)
            .map(|t| {
                50.0 + trend_slope * t as f64 + 10.0 * (2.0 * std::f64::consts::PI * t as f64 / m as f64).sin()
            })
            .collect()
    }

    // ── Linear algebra ──

    #[test]
    fn test_dot_product() {
        assert_eq!(dot(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]), 32.0);
    }

    #[test]
    fn test_mat_mul_identity() {
        let id = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
        let a = vec![vec![3.0, 4.0], vec![5.0, 6.0]];
        let c = mat_mul(&id, &a);
        assert!((c[0][0] - 3.0).abs() < 1e-10);
        assert!((c[1][1] - 6.0).abs() < 1e-10);
    }

    #[test]
    fn test_least_squares_perfect_fit() {
        // y = 2x + 1 exactly (with intercept column)
        let x: Vec<Vec<f64>> = (0..5).map(|i| vec![1.0, i as f64]).collect();
        let y: Vec<f64> = (0..5).map(|i| 2.0 * i as f64 + 1.0).collect();
        let beta = least_squares(&x, &y).unwrap();
        // beta[0] = intercept = 1.0, beta[1] = slope = 2.0
        assert!((beta[0] - 1.0).abs() < 1e-8);
        assert!((beta[1] - 2.0).abs() < 1e-8);
    }

    #[test]
    fn test_least_squares_overdetermined() {
        // y = 3 (constant) with some noise
        let x: Vec<Vec<f64>> = (0..20).map(|_| vec![1.0]).collect();
        let y: Vec<f64> = vec![3.1, 2.9, 3.0, 3.2, 2.8, 3.0, 3.1, 2.9, 3.0, 3.0,
                               3.1, 2.9, 3.0, 3.2, 2.8, 3.0, 3.1, 2.9, 3.0, 3.0];
        let beta = least_squares(&x, &y).unwrap();
        assert!((beta[0] - 3.0).abs() < 0.1);
    }

    #[test]
    fn test_mean_variance() {
        let d = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert!((mean(&d) - 5.0).abs() < 1e-10);
        let v = variance(&d);
        assert!((v - 4.0).abs() < 1e-10); // pop-variance=4, sample-var=4.571
    }

    #[test]
    fn test_percentile() {
        let mut d = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&mut d, 50.0) - 3.0).abs() < 1e-10);
        let mut d2 = vec![1.0, 2.0, 3.0, 4.0];
        let p25 = percentile(&mut d2, 25.0);
        assert!((p25 - 1.75).abs() < 1e-10);
    }

    // ── ARIMA ──

    #[test]
    fn test_arima_fit_ar1() {
        let y = ar1_series(100, 0.7, 42.0);
        let cfg = ArimaConfig::new(1, 0, 0);
        let model = ArimaModel::fit(&y, cfg).unwrap();
        assert!((model.ar_coeffs[0] - 0.7).abs() < 0.2);
    }

    #[test]
    fn test_arima_fit_with_differencing() {
        let y: Vec<f64> = (0..100).map(|i| i as f64 * 0.5 + (i as f64 * 0.1).sin() * 2.0).collect();
        let cfg = ArimaConfig::new(1, 1, 0);
        let model = ArimaModel::fit(&y, cfg).unwrap();
        assert!(model.sigma >= 0.0);
        assert_eq!(model.differenced.len(), y.len() - 1);
    }

    #[test]
    fn test_arima_forecast_length() {
        let y = ar1_series(80, 0.5, 123.0);
        let model = ArimaModel::fit(&y, ArimaConfig::default()).unwrap();
        let fc = model.forecast(10);
        assert_eq!(fc.len(), 10);
    }

    #[test]
    fn test_arima_forecast_intervals_structure() {
        let y = ar1_series(80, 0.5, 99.0);
        let model = ArimaModel::fit(&y, ArimaConfig::default()).unwrap();
        let pi = model.forecast_intervals(5, 1.96);
        assert_eq!(pi.len(), 5);
        for interval in &pi {
            assert!(interval.lower < interval.point);
            assert!(interval.point < interval.upper);
        }
    }

    #[test]
    fn test_arima_intervals_widen() {
        let y = ar1_series(100, 0.6, 7.0);
        let model = ArimaModel::fit(&y, ArimaConfig::new(1, 0, 1)).unwrap();
        let pi = model.forecast_intervals(10, 1.96);
        let width_1 = pi[0].upper - pi[0].lower;
        let width_10 = pi[9].upper - pi[9].lower;
        assert!(width_10 > width_1, "intervals should widen with horizon");
    }

    #[test]
    fn test_arima_too_short() {
        let y = vec![1.0, 2.0, 3.0];
        let cfg = ArimaConfig::new(3, 1, 2);
        let res = ArimaModel::fit(&y, cfg);
        assert!(res.is_err());
    }

    // ── Holt-Winters ──

    #[test]
    fn test_holt_winters_fit() {
        let y = seasonal_series(60, 12, 0.1);
        let cfg = HoltWintersConfig::new(0.3, 0.1, 0.1, 12);
        let model = HoltWintersModel::fit(&y, cfg).unwrap();
        assert_eq!(model.seasonal.len(), 12);
        assert!(model.sigma() >= 0.0);
    }

    #[test]
    fn test_holt_winters_forecast() {
        let y = seasonal_series(60, 12, 0.1);
        let model = HoltWintersModel::fit(&y, HoltWintersConfig::new(0.3, 0.1, 0.1, 12)).unwrap();
        let fc = model.forecast(12);
        assert_eq!(fc.len(), 12);
    }

    #[test]
    fn test_holt_winters_forecast_intervals() {
        let y = seasonal_series(60, 12, 0.1);
        let model = HoltWintersModel::fit(&y, HoltWintersConfig::new(0.3, 0.1, 0.1, 12)).unwrap();
        let pi = model.forecast_intervals(5, 1.96);
        assert_eq!(pi.len(), 5);
        for interval in &pi {
            assert!(interval.lower < interval.upper);
        }
    }

    #[test]
    fn test_holt_winters_too_short() {
        let y = vec![1.0, 2.0, 3.0];
        let cfg = HoltWintersConfig::new(0.2, 0.1, 0.1, 12);
        let res = HoltWintersModel::fit(&y, cfg);
        assert!(res.is_err());
    }

    #[test]
    fn test_holt_winters_with_damping() {
        let y = seasonal_series(80, 12, 0.05);
        let cfg = HoltWintersConfig::new(0.2, 0.1, 0.1, 12).with_damping(0.95);
        let model = HoltWintersModel::fit(&y, cfg).unwrap();
        let fc = model.forecast(24);
        assert_eq!(fc.len(), 24);
    }

    // ── Seasonal Decomposition ──

    #[test]
    fn test_decomposition_basic() {
        let y = seasonal_series(48, 12, 0.1);
        let dec = SeasonalDecomposition::decompose(&y, 12).unwrap();
        assert_eq!(dec.observed.len(), 48);
        assert_eq!(dec.trend.len(), 48);
        assert_eq!(dec.seasonal.len(), 48);
        assert_eq!(dec.residual.len(), 48);
    }

    #[test]
    fn test_decomposition_reconstruction() {
        let y = seasonal_series(48, 12, 0.2);
        let dec = SeasonalDecomposition::decompose(&y, 12).unwrap();
        for i in 0..y.len() {
            if !dec.trend[i].is_nan() {
                let reconstructed = dec.trend[i] + dec.seasonal[i] + dec.residual[i];
                assert!(
                    (reconstructed - y[i]).abs() < 1e-8,
                    "reconstruction failed at index {}: got {}, expected {}",
                    i, reconstructed, y[i]
                );
            }
        }
    }

    #[test]
    fn test_decomposition_seasonal_indices_sum_zero() {
        let y = seasonal_series(60, 12, 0.1);
        let dec = SeasonalDecomposition::decompose(&y, 12).unwrap();
        let indices = dec.seasonal_indices();
        let sum: f64 = indices.iter().sum();
        assert!(sum.abs() < 1e-8, "seasonal indices should sum to 0, got {}", sum);
    }

    #[test]
    fn test_decomposition_too_short() {
        let y = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let res = SeasonalDecomposition::decompose(&y, 12);
        assert!(res.is_err());
    }

    // ── Anomaly Detection ──

    #[test]
    fn test_zscore_detects_outlier() {
        let mut y = vec![10.0; 50];
        y[25] = 100.0; // clear outlier
        let detector = AnomalyDetector::new(AnomalyDetectorConfig {
            z_threshold: 3.0,
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 5,
            arima_config: None,
            hw_config: None,
        });
        let anomalies = detector.detect(&y);
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| a.index == 25));
    }

    #[test]
    fn test_iqr_detects_outlier() {
        let mut y: Vec<f64> = (1..=20).map(|i| i as f64).collect();
        y.push(100.0); // extreme outlier
        let detector = AnomalyDetector::new(AnomalyDetectorConfig {
            z_threshold: 10.0, // disable z-score
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 5,
            arima_config: None,
            hw_config: None,
        });
        let anomalies = detector.detect(&y);
        assert!(anomalies.iter().any(|a| a.value == 100.0));
    }

    #[test]
    fn test_no_anomalies_uniform() {
        let y = vec![5.0; 50];
        let detector = AnomalyDetector::new(AnomalyDetectorConfig {
            z_threshold: 3.0,
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 5,
            arima_config: None,
            hw_config: None,
        });
        let anomalies = detector.detect(&y);
        assert!(anomalies.is_empty(), "uniform series should have no anomalies");
    }

    #[test]
    fn test_anomaly_direction_high() {
        let mut y = vec![10.0; 50];
        y[10] = 50.0;
        let detector = AnomalyDetector::new(AnomalyDetectorConfig {
            z_threshold: 3.0,
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 5,
            arima_config: None,
            hw_config: None,
        });
        let anomalies = detector.detect(&y);
        let high_anom = anomalies.iter().find(|a| a.index == 10);
        assert!(high_anom.is_some());
        assert_eq!(high_anom.unwrap().direction, AnomalyDirection::High);
    }

    #[test]
    fn test_anomaly_direction_low() {
        let mut y = vec![10.0; 50];
        y[10] = -50.0;
        let detector = AnomalyDetector::new(AnomalyDetectorConfig {
            z_threshold: 3.0,
            iqr_k: 1.5,
            pi_z_crit: 2.576,
            min_obs: 5,
            arima_config: None,
            hw_config: None,
        });
        let anomalies = detector.detect(&y);
        let low_anom = anomalies.iter().find(|a| a.index == 10);
        assert!(low_anom.is_some());
        assert_eq!(low_anom.unwrap().direction, AnomalyDirection::Low);
    }

    #[test]
    fn test_anomaly_too_few_observations() {
        let y = vec![1.0, 2.0, 3.0];
        let detector = AnomalyDetector::new(AnomalyDetectorConfig::default());
        let anomalies = detector.detect(&y);
        assert!(anomalies.is_empty());
    }

    // ── CUSUM ──

    #[test]
    fn test_cusum_detects_shift_up() {
        let mut y = vec![10.0; 30];
        y.extend(vec![20.0; 30]);
        let detector = CusumDetector::new(CusumConfig::new(0.5, 4.0, 20));
        let cps = detector.detect(&y);
        assert!(!cps.is_empty(), "CUSUM should detect the mean shift");
        // The change should be detected after the shift point
        let first_cp = &cps[0];
        assert!(first_cp.index >= 30, "change point should be at or after index 30, got {}", first_cp.index);
    }

    #[test]
    fn test_cusum_detects_shift_down() {
        let mut y = vec![20.0; 30];
        y.extend(vec![5.0; 30]);
        let detector = CusumDetector::new(CusumConfig::new(0.5, 4.0, 20));
        let cps = detector.detect(&y);
        assert!(!cps.is_empty());
    }

    #[test]
    fn test_cusum_no_false_positive_stable() {
        let y: Vec<f64> = (0..100).map(|_| 10.0).collect();
        let detector = CusumDetector::new(CusumConfig::new(0.5, 10.0, 20));
        let cps = detector.detect(&y);
        assert!(cps.is_empty(), "stable series should have no change points");
    }

    #[test]
    fn test_cusum_too_short() {
        let y = vec![1.0, 2.0, 3.0];
        let detector = CusumDetector::new(CusumConfig::default());
        let cps = detector.detect(&y);
        assert!(cps.is_empty());
    }

    #[test]
    fn test_cusum_statistics_length() {
        let y = vec![5.0; 50];
        let detector = CusumDetector::new(CusumConfig::default());
        let stats = detector.statistics(&y);
        // warmup=20, but we still compute for all points
        assert_eq!(stats.len(), 50);
    }

    // ── End-to-End Prediction Engine ──

    #[test]
    fn test_prediction_engine_basic() {
        let scores: Vec<f64> = (0..100).map(|i| 1.0 - i as f64 * 0.005).collect();
        let engine = AnomalyPredictionEngine::new(PredictionEngineConfig {
            arima: ArimaConfig::new(1, 1, 0),
            holt_winters: None,
            anomaly: AnomalyDetectorConfig {
                arima_config: None,
                hw_config: None,
                min_obs: 10,
                ..Default::default()
            },
            cusum: CusumConfig::new(0.5, 5.0, 20),
            forecast_horizon: 5,
            season_length: 0,
            z_crit: 1.96,
        });
        let result = engine.predict("test_component", &scores);
        assert_eq!(result.component, "test_component");
        // Declining scores → should predict Unhealthy or worse
        assert_ne!(result.predicted_status, HealthStatus::Healthy);
    }

    #[test]
    fn test_prediction_engine_healthy() {
        let scores = vec![1.0; 100];
        let engine = AnomalyPredictionEngine::new(PredictionEngineConfig {
            arima: ArimaConfig::new(1, 0, 0),
            holt_winters: None,
            anomaly: AnomalyDetectorConfig {
                arima_config: None,
                hw_config: None,
                min_obs: 10,
                ..Default::default()
            },
            cusum: CusumConfig::new(1.0, 10.0, 20),
            forecast_horizon: 5,
            season_length: 0,
            z_crit: 1.96,
        });
        let result = engine.predict("stable", &scores);
        assert_eq!(result.predicted_status, HealthStatus::Healthy);
    }

    #[test]
    fn test_prediction_engine_with_seasonal_decomposition() {
        let y = seasonal_series(60, 12, 0.1);
        let engine = AnomalyPredictionEngine::new(PredictionEngineConfig {
            arima: ArimaConfig::new(1, 0, 0),
            holt_winters: None,
            anomaly: AnomalyDetectorConfig {
                arima_config: None,
                hw_config: None,
                min_obs: 10,
                ..Default::default()
            },
            cusum: CusumConfig::default(),
            forecast_horizon: 5,
            season_length: 12,
            z_crit: 1.96,
        });
        let result = engine.predict("seasonal_comp", &y);
        assert!(result.decomposition.is_some());
        let dec = result.decomposition.unwrap();
        let indices = dec.seasonal_indices();
        let sum: f64 = indices.iter().sum();
        assert!(sum.abs() < 1e-6);
    }

    #[test]
    fn test_centred_ma_odd_window() {
        let y = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let ma = SeasonalDecomposition::centred_ma(&y, 3);
        // Centred MA with window 3: i=2 uses [2,3,4]->3.0, i=3 uses [3,4,5]->4.0, i=4 uses [4,5,6]->5.0
        assert!((ma[2] - 3.0).abs() < 1e-10);
        assert!((ma[3] - 4.0).abs() < 1e-10);
        assert!((ma[4] - 5.0).abs() < 1e-10);
        assert!(ma[0].is_nan());
        assert!(ma[6].is_nan());
    }

    #[test]
    fn test_centred_ma_even_window() {
        let y = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let ma = SeasonalDecomposition::centred_ma(&y, 4);
        // With even window, use 2×4 centred MA
        // Boundaries should be NaN
        assert!(ma[0].is_nan());
        assert!(ma[1].is_nan());
        // Central values should be finite
        let finite_count = ma.iter().filter(|v| !v.is_nan()).count();
        assert!(finite_count > 0);
    }

    #[test]
    fn test_seasonality_strength() {
        let y = seasonal_series(60, 12, 0.0); // pure seasonal, no trend
        let dec = SeasonalDecomposition::decompose(&y, 12).unwrap();
        let strength = dec.seasonality_strength();
        assert!(strength > 0.5, "seasonality strength should be high for pure seasonal data, got {}", strength);
    }

    #[test]
    fn test_arima_difference_inversion_roundtrip() {
        let y = vec![10.0, 12.0, 15.0, 14.0, 18.0, 20.0, 22.0];
        let (diffed, pre) = ArimaModel::difference(&y, 1);
        let restored = ArimaModel::invert_difference(&pre, &diffed, 1);
        // pre stores the last value; inversion continues forward from it
        let last = *y.last().unwrap();
        let mut cum = last;
        for (i, &d) in diffed.iter().enumerate() {
            cum += d;
            assert!((restored[i] - cum).abs() < 1e-10, "mismatch at index {}", i);
        }
    }

    #[test]
    fn test_arima_second_difference() {
        let y: Vec<f64> = (0..20).map(|i| (i as f64).powi(2)).collect();
        let (diffed, pre) = ArimaModel::difference(&y, 2);
        // Second difference of quadratic should be constant (2)
        for d in &diffed {
            assert!((d - 2.0).abs() < 1e-8, "expected ~2.0, got {}", d);
        }
        assert_eq!(pre.len(), 2);
    }

    #[test]
    fn test_serialisation_roundtrip() {
        let cfg = ArimaConfig::new(2, 1, 1);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ArimaConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.p, 2);
        assert_eq!(restored.d, 1);
        assert_eq!(restored.q, 1);
    }

    #[test]
    fn test_holt_winters_config_serialisation() {
        let cfg = HoltWintersConfig::new(0.3, 0.2, 0.1, 24).with_damping(0.9);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: HoltWintersConfig = serde_json::from_str(&json).unwrap();
        assert!((restored.alpha - 0.3).abs() < 1e-10);
        assert_eq!(restored.season_length, 24);
        assert!((restored.phi - 0.9).abs() < 1e-10);
    }

    #[test]
    fn test_anomaly_point_serialisation() {
        let ap = AnomalyPoint {
            index: 42,
            value: 99.9,
            score: 5.0,
            methods: vec![AnomalyMethod::ZScore, AnomalyMethod::Iqr],
            direction: AnomalyDirection::High,
        };
        let json = serde_json::to_string(&ap).unwrap();
        let restored: AnomalyPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.index, 42);
        assert_eq!(restored.methods.len(), 2);
    }

    #[test]
    fn test_cusum_config_serialisation() {
        let cfg = CusumConfig::new(0.5, 5.0, 30).with_target_mean(10.0);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: CusumConfig = serde_json::from_str(&json).unwrap();
        assert!((restored.target_mean.unwrap() - 10.0).abs() < 1e-10);
    }

    #[test]
    fn test_engine_result_serialisation() {
        let result = AnomalyPredictionResult {
            component: "test".to_string(),
            arima_forecast: Some(vec![1.0, 2.0]),
            arima_intervals: Some(vec![
                PredictionInterval { lower: 0.5, point: 1.0, upper: 1.5 },
                PredictionInterval { lower: 1.0, point: 2.0, upper: 3.0 },
            ]),
            hw_forecast: None,
            hw_intervals: None,
            anomalies: vec![],
            change_points: vec![],
            decomposition: None,
            predicted_status: HealthStatus::Degraded,
            confidence: 0.8,
            explanation: "test".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: AnomalyPredictionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.component, "test");
        assert_eq!(restored.predicted_status, HealthStatus::Degraded);
    }
}
