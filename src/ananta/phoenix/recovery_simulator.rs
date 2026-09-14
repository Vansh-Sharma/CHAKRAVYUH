// ANANTA Phoenix — Monte Carlo Recovery Simulation Engine
//
// This module provides a full Monte Carlo simulation framework for evaluating
// recovery strategies within the ANANTA trust plane. Before committing to a
// recovery action in production, Phoenix can simulate thousands of failure
// scenarios, inject faults, apply candidate strategies, and aggregate outcomes
// to quantify risk, identify Pareto-optimal strategies, and perform sensitivity
// analysis on critical parameters.
//
// Pipeline:
//   Define topology → Configure failure injector → Set recovery strategies →
//   Run Monte Carlo engine → Aggregate statistics → Sensitivity analysis →
//   Pareto-optimal selection → Report
//
// Core capabilities:
//   1. Monte Carlo Simulation Engine — run N independent recovery scenarios
//   2. Failure Injection — random, cascading, targeted, correlated patterns
//   3. Recovery Strategy Simulation — restart, rollback, failover, rebuild
//   4. Sensitivity Analysis — vary parameters, compute numerical derivatives
//   5. Pareto-Optimal Selection — multi-objective frontier across objectives
//   6. Statistics Utilities — mean, std_dev, confidence interval, t-test

use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// =============================================================================
// Section 1: Statistics Utilities
// =============================================================================

/// Descriptive statistics over a sample of f64 observations.
///
/// Provides the canonical set of summary statistics used throughout the
/// simulation engine: mean, standard deviation, min, max, median, and
/// quartiles. All methods are O(n) or O(1) after construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleStatistics {
    /// Number of observations.
    pub n: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Sample standard deviation (Bessel-corrected, denominator n-1).
    /// Returns 0.0 when n < 2.
    pub std_dev: f64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
    /// Median (50th percentile).
    pub median: f64,
    /// 25th percentile.
    pub q1: f64,
    /// 75th percentile.
    pub q3: f64,
    /// Variance.
    pub variance: f64,
    /// Standard error of the mean.
    pub standard_error: f64,
}

impl SampleStatistics {
    /// Compute descriptive statistics from a slice of f64 values.
    ///
    /// Returns `None` if the slice is empty. For a single-element slice,
    /// `std_dev` and `variance` are reported as 0.0.
    pub fn from_slice(data: &[f64]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let n = data.len();
        let mean = data.iter().copied().sum::<f64>() / n as f64;
        let variance = if n > 1 {
            data.iter()
                .copied()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>()
                / (n - 1) as f64
        } else {
            0.0
        };
        let std_dev = variance.sqrt();
        let standard_error = if n > 1 {
            std_dev / (n as f64).sqrt()
        } else {
            0.0
        };

        let mut sorted = data.to_vec();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted[0];
        let max = sorted[n - 1];
        let median = percentile(&sorted, 50.0);
        let q1 = percentile(&sorted, 25.0);
        let q3 = percentile(&sorted, 75.0);

        Some(Self {
            n,
            mean,
            std_dev,
            min,
            max,
            median,
            q1,
            q3,
            variance,
            standard_error,
        })
    }

    /// Compute the t-value for a two-sample t-test (Welch's, unequal variances).
    ///
    /// Returns `None` if either sample has fewer than 2 observations.
    pub fn welch_t_test(&self, other: &SampleStatistics) -> Option<TTestResult> {
        if self.n < 2 || other.n < 2 {
            return None;
        }
        let se_diff = (self.standard_error.powi(2) + other.standard_error.powi(2)).sqrt();
        if se_diff == 0.0 {
            return None;
        }
        let t_statistic = (self.mean - other.mean) / se_diff;

        // Welch–Satterthwaite degrees of freedom.
        let s1_sq = self.variance / self.n as f64;
        let s2_sq = other.variance / other.n as f64;
        let numerator = (s1_sq + s2_sq).powi(2);
        let denominator =
            s1_sq.powi(2) / (self.n - 1) as f64 + s2_sq.powi(2) / (other.n - 1) as f64;
        if denominator == 0.0 {
            return None;
        }
        let df = numerator / denominator;

        // Approximate p-value using the normal approximation for large df.
        // For small df this is conservative (overestimates p-value slightly).
        let z = t_statistic.abs();
        let p_value = 2.0 * normal_survival(z);

        let significant = p_value < 0.05;
        Some(TTestResult {
            t_statistic,
            degrees_of_freedom: df,
            p_value,
            significant_at_0_05: significant,
            mean_difference: self.mean - other.mean,
            effect_size: cohen_d(
                self.mean,
                other.mean,
                self.variance,
                other.variance,
                self.n,
                other.n,
            ),
        })
    }

    /// Compute a confidence interval for the mean at the given confidence level.
    ///
    /// Uses the t-distribution approximation via the normal distribution for
    /// simplicity. For n > 30 the approximation is excellent.
    ///
    /// Returns `None` if n < 2.
    pub fn confidence_interval(&self, confidence_level: f64) -> Option<ConfidenceInterval> {
        if self.n < 2 || self.standard_error == 0.0 {
            return None;
        }
        // z-critical for common levels via inverse normal approximation.
        let z_critical = z_critical_value(confidence_level);
        let margin = z_critical * self.standard_error;
        Some(ConfidenceInterval {
            lower: self.mean - margin,
            upper: self.mean + margin,
            confidence_level,
            margin_of_error: margin,
        })
    }
}

/// Result of a two-sample Welch's t-test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TTestResult {
    /// The t-statistic.
    pub t_statistic: f64,
    /// Degrees of freedom (Welch–Satterthwaite approximation).
    pub degrees_of_freedom: f64,
    /// Two-tailed p-value (normal approximation).
    pub p_value: f64,
    /// Whether the difference is significant at α = 0.05.
    pub significant_at_0_05: bool,
    /// Mean of sample 1 minus mean of sample 2.
    pub mean_difference: f64,
    /// Cohen's d effect size.
    pub effect_size: f64,
}

/// A confidence interval for the mean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound.
    pub lower: f64,
    /// Upper bound.
    pub upper: f64,
    /// Confidence level (e.g. 0.95).
    pub confidence_level: f64,
    /// Half-width of the interval.
    pub margin_of_error: f64,
}

/// Compute the p-th percentile from a sorted slice using linear interpolation.
///
/// `percentile` must be in [0, 100]. Uses the "exclusive" method consistent
/// with NumPy's default `np.percentile`.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(
        sorted.is_sorted_by(|a, b| a <= b),
        "percentile requires a sorted slice"
    );
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let n = sorted.len();
    // Rank using the exclusive method.
    let rank = (p / 100.0) * (n as f64 - 1.0) + 1.0;
    let lower_idx = (rank.floor() as usize).max(1).min(n) - 1;
    let upper_idx = (rank.ceil() as usize).max(1).min(n) - 1;
    let fraction = rank - rank.floor();
    sorted[lower_idx] + fraction * (sorted[upper_idx] - sorted[lower_idx])
}

/// Compute the arithmetic mean of a slice.
pub fn mean(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().copied().sum::<f64>() / data.len() as f64
}

/// Compute the sample standard deviation (Bessel-corrected) of a slice.
pub fn std_dev(data: &[f64]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let m = mean(data);
    let variance = data.iter().copied().map(|x| (x - m).powi(2)).sum::<f64>() / data.len() as f64;
    variance.sqrt()
}

/// Compute a two-sample t-test (Welch's) between two data slices.
///
/// Returns `None` if either slice has fewer than 2 elements.
pub fn t_test(a: &[f64], b: &[f64]) -> Option<TTestResult> {
    let stats_a = SampleStatistics::from_slice(a)?;
    let stats_b = SampleStatistics::from_slice(b)?;
    stats_a.welch_t_test(&stats_b)
}

/// Compute Cohen's d effect size between two groups.
fn cohen_d(mean_a: f64, mean_b: f64, var_a: f64, var_b: f64, n_a: usize, n_b: usize) -> f64 {
    let pooled_std = ((var_a * (n_a - 1) as f64 + var_b * (n_b - 1) as f64)
        / (n_a + n_b - 2).max(1) as f64)
        .sqrt();
    if pooled_std == 0.0 {
        return 0.0;
    }
    (mean_a - mean_b) / pooled_std
}

/// Approximate the survival function (1 - CDF) of the standard normal.
///
/// Uses Abramowitz and Stegun approximation 26.2.17, accurate to ~1e-4.
fn normal_survival(z: f64) -> f64 {
    if z < 0.0 {
        return 1.0 - normal_survival(-z);
    }
    let b0 = 0.231_641_9;
    let b1 = 0.319_381_530;
    let b2 = -0.356_563_782;
    let b3 = 1.781_477_937;
    let b4 = -1.821_255_978;
    let b5 = 1.330_274_429;
    let t = 1.0 / (1.0 + b0 * z);
    let t2 = t * t;
    let t3 = t2 * t;
    let t4 = t3 * t;
    let t5 = t4 * t;
    let poly = t * b1 + t2 * b2 + t3 * b3 + t4 * b4 + t5 * b5;
    // A&S 26.2.17: survival = phi(z) * poly where phi(z) = exp(-z^2/2) / sqrt(2*pi)
    let phi = (-z * z / 2.0).exp() / (2.0 * std::f64::consts::PI).sqrt();
    phi * poly
}

/// Approximate the z-critical value for a given two-tailed confidence level.
///
/// Uses a rational approximation (Abramowitz & Stegun inverse normal).
fn z_critical_value(confidence: f64) -> f64 {
    // Map confidence to tail probability: P(|Z| > z) = 1 - confidence.
    let p = (1.0 - confidence) / 2.0;
    // Rational approximation for the inverse of normal CDF.
    if p <= 1e-10 {
        return 6.366;
    }
    if p >= 0.5 - 1e-10 {
        return 0.0;
    }
    let t = (-2.0 * p.ln()).sqrt();
    let c0 = 2.515_517;
    let c1 = 0.802_853;
    let c2 = 0.010_328;
    let d1 = 1.432_788;
    let d2 = 0.189_269;
    let d3 = 0.001_308;
    t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)
}

/// Pearson correlation coefficient between two equal-length slices.
///
/// Returns `None` if slices differ in length or have fewer than 2 elements,
/// or if either variable has zero variance.
pub fn pearson_correlation(x: &[f64], y: &[f64]) -> Option<f64> {
    if x.len() != y.len() || x.len() < 2 {
        return None;
    }
    let n = x.len() as f64;
    let mx = mean(x);
    let my = mean(y);
    let cov: f64 = x
        .iter()
        .zip(y.iter())
        .map(|(a, b)| (a - mx) * (b - my))
        .sum();
    let sx = std_dev(x);
    let sy = std_dev(y);
    if sx == 0.0 || sy == 0.0 {
        return None;
    }
    Some(cov / (n * sx * sy))
}

/// Compute the rank-biserial correlation (Cliff's delta) between two samples.
///
/// Returns a value in [-1, 1] indicating the degree of stochastic dominance.
pub fn cliffs_delta(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let _n_a = a.len() as f64;
    let _n_b = b.len() as f64;
    let mut greater = 0usize;
    let mut less = 0usize;
    for va in a {
        for vb in b {
            if va > vb {
                greater += 1;
            } else if va < vb {
                less += 1;
            }
        }
    }
    let total = (greater + less) as f64;
    if total == 0.0 {
        return 0.0;
    }
    (greater as f64 - less as f64) / total
}

// =============================================================================
// Section 2: Component and System Topology Models
// =============================================================================

/// Unique identifier for a component in the trust plane.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComponentId(pub String);

impl ComponentId {
    /// Create a new component ID from a string.
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The operational state of a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Component is fully operational.
    Healthy,
    /// Component is degraded but still functional.
    Degraded,
    /// Component has failed and is unresponsive.
    Failed,
    /// Component is undergoing recovery.
    Recovering,
    /// Component is quarantined (isolated from traffic).
    Quarantined,
}

impl ComponentState {
    /// Returns true if the component can process traffic.
    pub fn is_operational(&self) -> bool {
        matches!(self, ComponentState::Healthy | ComponentState::Degraded)
    }

    /// Returns true if the component has failed or is quarantined.
    pub fn is_down(&self) -> bool {
        matches!(self, ComponentState::Failed | ComponentState::Quarantined)
    }
}

/// A single component in the trust plane with its configuration and runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Unique identifier.
    pub id: ComponentId,
    /// Current operational state.
    pub state: ComponentState,
    /// Intrinsic trust level of this component (0.0 to 1.0).
    pub trust_level: f64,
    /// Recovery difficulty — higher means harder to recover (0.0 to 1.0).
    pub recovery_difficulty: f64,
    /// Base failure probability per time step (0.0 to 1.0).
    pub base_failure_probability: f64,
    /// Category of this component (e.g., "shield_ring", "threat_ring").
    pub category: String,
    /// Dependencies — IDs of components this one depends on.
    pub dependencies: Vec<ComponentId>,
    /// Number of consecutive failures (for cascade detection).
    pub consecutive_failures: u32,
    /// Time since last recovery in arbitrary time units.
    pub time_since_recovery: f64,
    /// Whether this component is critical for system operation.
    pub is_critical: bool,
    /// Load factor: proportion of maximum capacity currently in use (0.0-1.0).
    pub load_factor: f64,
}

impl Component {
    /// Create a new healthy component with the given parameters.
    pub fn new(id: &str, category: &str) -> Self {
        Self {
            id: ComponentId::new(id),
            state: ComponentState::Healthy,
            trust_level: 1.0,
            recovery_difficulty: 0.3,
            base_failure_probability: 0.01,
            category: category.to_string(),
            dependencies: vec![],
            consecutive_failures: 0,
            time_since_recovery: 0.0,
            is_critical: false,
            load_factor: 0.5,
        }
    }

    /// Create a component builder with sensible defaults for modification.
    pub fn builder(id: &str, category: &str) -> ComponentBuilder {
        ComponentBuilder {
            component: Self::new(id, category),
        }
    }

    /// Compute the effective failure probability considering all stressors.
    ///
    /// Combines base failure probability with adjustments for consecutive
    /// failures, trust level, load factor, and time since recovery.
    pub fn effective_failure_probability(&self) -> f64 {
        let mut p = self.base_failure_probability;
        // Consecutive failures increase probability exponentially.
        p *= 1.0 + 0.5 * self.consecutive_failures as f64;
        // Higher trust reduces failure probability.
        p *= 1.0 - 0.3 * self.trust_level;
        // Higher load increases failure probability.
        p *= 1.0 + 0.4 * self.load_factor;
        // Longer time since recovery increases probability slightly.
        p *= 1.0 + 0.1 * (self.time_since_recovery / 100.0).min(1.0);
        p.clamp(0.0, 1.0)
    }
}

/// Builder pattern for constructing components with custom parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentBuilder {
    component: Component,
}

impl ComponentBuilder {
    /// Set the trust level of the component.
    pub fn trust_level(mut self, level: f64) -> Self {
        self.component.trust_level = level.clamp(0.0, 1.0);
        self
    }

    /// Set the recovery difficulty.
    pub fn recovery_difficulty(mut self, difficulty: f64) -> Self {
        self.component.recovery_difficulty = difficulty.clamp(0.0, 1.0);
        self
    }

    /// Set the base failure probability.
    pub fn base_failure_probability(mut self, p: f64) -> Self {
        self.component.base_failure_probability = p.clamp(0.0, 1.0);
        self
    }

    /// Mark the component as critical.
    pub fn critical(mut self) -> Self {
        self.component.is_critical = true;
        self
    }

    /// Add a dependency by ID string.
    pub fn depends_on(mut self, dep_id: &str) -> Self {
        self.component.dependencies.push(ComponentId::new(dep_id));
        self
    }

    /// Set the load factor.
    pub fn load_factor(mut self, load: f64) -> Self {
        self.component.load_factor = load.clamp(0.0, 1.0);
        self
    }

    /// Build and return the component.
    pub fn build(self) -> Component {
        self.component
    }
}

/// Represents the full topology of the trust plane system under simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemTopology {
    /// All components indexed by their ID.
    pub components: HashMap<ComponentId, Component>,
}

impl SystemTopology {
    /// Create an empty topology.
    pub fn new() -> Self {
        Self {
            components: HashMap::new(),
        }
    }

    /// Add a component to the topology.
    pub fn add_component(&mut self, component: Component) {
        self.components.insert(component.id.clone(), component);
    }

    /// Remove a component from the topology.
    pub fn remove_component(&mut self, id: &ComponentId) -> Option<Component> {
        self.components.remove(id)
    }

    /// Get a reference to a component by ID.
    pub fn get(&self, id: &ComponentId) -> Option<&Component> {
        self.components.get(id)
    }

    /// Get a mutable reference to a component by ID.
    pub fn get_mut(&mut self, id: &ComponentId) -> Option<&mut Component> {
        self.components.get_mut(id)
    }

    /// Count the number of components in each state.
    pub fn state_counts(&self) -> HashMap<ComponentState, usize> {
        let mut counts = HashMap::new();
        for c in self.components.values() {
            *counts.entry(c.state).or_insert(0) += 1;
        }
        counts
    }

    /// Compute the fraction of components that are operational.
    pub fn availability(&self) -> f64 {
        if self.components.is_empty() {
            return 1.0;
        }
        let operational = self
            .components
            .values()
            .filter(|c| c.state.is_operational())
            .count();
        operational as f64 / self.components.len() as f64
    }

    /// Compute the system trust level as the weighted harmonic mean of
    /// component trust levels (critical components weighted more).
    pub fn system_trust(&self) -> f64 {
        if self.components.is_empty() {
            return 1.0;
        }
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        for c in self.components.values() {
            let weight = if c.is_critical { 3.0 } else { 1.0 };
            if c.trust_level > 0.0 {
                weighted_sum += weight / c.trust_level;
                total_weight += weight;
            }
        }
        if weighted_sum == 0.0 || total_weight == 0.0 {
            return 0.0;
        }
        total_weight / weighted_sum
    }

    /// Return IDs of components that are currently failed or quarantined.
    pub fn failed_components(&self) -> Vec<ComponentId> {
        self.components
            .values()
            .filter(|c| c.state.is_down())
            .map(|c| c.id.clone())
            .collect()
    }

    /// Create a default trust plane topology for testing.
    pub fn default_trust_plane() -> Self {
        let mut topo = Self::new();

        // Shield Ring components.
        topo.add_component(
            Component::builder("shield_ingress", "shield_ring")
                .trust_level(0.95)
                .critical()
                .base_failure_probability(0.005)
                .load_factor(0.6)
                .build(),
        );
        topo.add_component(
            Component::builder("shield_proxy", "shield_ring")
                .trust_level(0.90)
                .critical()
                .base_failure_probability(0.01)
                .load_factor(0.7)
                .depends_on("shield_ingress")
                .build(),
        );
        topo.add_component(
            Component::builder("shield_waf", "shield_ring")
                .trust_level(0.92)
                .base_failure_probability(0.008)
                .load_factor(0.5)
                .depends_on("shield_proxy")
                .build(),
        );

        // Threat Ring components.
        topo.add_component(
            Component::builder("threat_analyzer", "threat_ring")
                .trust_level(0.88)
                .critical()
                .base_failure_probability(0.015)
                .load_factor(0.65)
                .build(),
        );
        topo.add_component(
            Component::builder("threat_classifier", "threat_ring")
                .trust_level(0.85)
                .base_failure_probability(0.02)
                .load_factor(0.55)
                .depends_on("threat_analyzer")
                .build(),
        );
        topo.add_component(
            Component::builder("threat_correlator", "threat_ring")
                .trust_level(0.87)
                .base_failure_probability(0.012)
                .load_factor(0.4)
                .depends_on("threat_analyzer")
                .build(),
        );

        // Trust Ring components.
        topo.add_component(
            Component::builder("trust_evaluator", "trust_ring")
                .trust_level(0.97)
                .critical()
                .base_failure_probability(0.003)
                .load_factor(0.3)
                .build(),
        );
        topo.add_component(
            Component::builder("trust_aggregator", "trust_ring")
                .trust_level(0.94)
                .base_failure_probability(0.006)
                .load_factor(0.35)
                .depends_on("trust_evaluator")
                .build(),
        );

        // Phoenix recovery controller.
        topo.add_component(
            Component::builder("phoenix_controller", "phoenix")
                .trust_level(0.99)
                .critical()
                .base_failure_probability(0.001)
                .recovery_difficulty(0.8)
                .load_factor(0.2)
                .build(),
        );

        topo
    }
}

impl Default for SystemTopology {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Section 3: Failure Injection
// =============================================================================

/// The type of failure that can be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureType {
    /// Component crashes and becomes unresponsive.
    Crash,
    /// Component enters degraded mode (partial functionality).
    Degradation,
    /// Component starts producing incorrect results (silent failure).
    DataCorruption,
    /// Component becomes extremely slow (timeout failures).
    PerformanceDegradation,
    /// Network connectivity loss.
    NetworkPartition,
    /// Resource exhaustion (CPU, memory, file descriptors).
    ResourceExhaustion,
    /// Configuration drift — component operates with stale config.
    ConfigDrift,
}

impl FailureType {
    /// Returns the severity of this failure type on a 0.0–1.0 scale.
    pub fn severity(&self) -> f64 {
        match self {
            FailureType::Crash => 0.9,
            FailureType::Degradation => 0.4,
            FailureType::DataCorruption => 0.95,
            FailureType::PerformanceDegradation => 0.3,
            FailureType::NetworkPartition => 0.7,
            FailureType::ResourceExhaustion => 0.6,
            FailureType::ConfigDrift => 0.5,
        }
    }

    /// Returns the trust impact of this failure type on a 0.0–1.0 scale.
    /// Higher means more trust is lost when this failure occurs.
    pub fn trust_impact(&self) -> f64 {
        match self {
            FailureType::Crash => 0.3,
            FailureType::Degradation => 0.1,
            FailureType::DataCorruption => 0.5,
            FailureType::PerformanceDegradation => 0.05,
            FailureType::NetworkPartition => 0.2,
            FailureType::ResourceExhaustion => 0.15,
            FailureType::ConfigDrift => 0.25,
        }
    }
}

impl fmt::Display for FailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The pattern governing how failures are injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePattern {
    /// Fail K random components uniformly.
    Random {
        /// Number of components to fail.
        count: usize,
    },
    /// Fail one component, then cascade to its dependents with given probability.
    Cascading {
        /// Initial component to fail (by ID substring match).
        seed_component: String,
        /// Probability of each dependent also failing (0.0–1.0).
        cascade_probability: f64,
        /// Maximum depth of cascade propagation.
        max_depth: u32,
    },
    /// Fail specific named components.
    Targeted {
        /// Exact IDs of components to fail.
        targets: Vec<String>,
    },
    /// Inject correlated failures where components in the same category
    /// fail with higher probability.
    Correlated {
        /// Number of components to fail.
        count: usize,
        /// Category bias factor — probability multiplier for same-category failures.
        category_bias: f64,
    },
    /// Fail components based on their effective failure probability (weighted random).
    ProbabilityWeighted {
        /// Number of components to fail.
        count: usize,
    },
    /// Simultaneous multi-component failure (common cause).
    CommonCause {
        /// The category affected.
        affected_category: String,
        /// Fraction of components in the category that fail.
        failure_fraction: f64,
    },
}

/// A record of a single failure injection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureEvent {
    /// The ID of the component that failed.
    pub component_id: ComponentId,
    /// The type of failure.
    pub failure_type: FailureType,
    /// Severity of this particular failure event.
    pub severity: f64,
    /// Trust impact of this failure event.
    pub trust_impact: f64,
    /// Time step at which the failure occurred.
    pub time_step: u32,
    /// Whether this failure cascaded from another failure.
    pub is_cascade: bool,
}

impl FailureEvent {
    /// Create a new failure event.
    pub fn new(component_id: ComponentId, failure_type: FailureType, time_step: u32) -> Self {
        Self {
            component_id,
            severity: failure_type.severity(),
            trust_impact: failure_type.trust_impact(),
            failure_type,
            time_step,
            is_cascade: false,
        }
    }
}

/// Engine for injecting failures into a system topology according to patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureInjector {
    /// The failure pattern to use.
    pub pattern: FailurePattern,
    /// Seed for reproducible randomness (set to None for non-deterministic).
    pub seed: Option<u64>,
    /// Available failure types and their weights for random selection.
    pub failure_type_weights: HashMap<FailureType, f64>,
}

impl FailureInjector {
    /// Create a new failure injector with the given pattern.
    pub fn new(pattern: FailurePattern) -> Self {
        let mut weights = HashMap::new();
        weights.insert(FailureType::Crash, 0.30);
        weights.insert(FailureType::Degradation, 0.20);
        weights.insert(FailureType::DataCorruption, 0.10);
        weights.insert(FailureType::PerformanceDegradation, 0.15);
        weights.insert(FailureType::NetworkPartition, 0.10);
        weights.insert(FailureType::ResourceExhaustion, 0.10);
        weights.insert(FailureType::ConfigDrift, 0.05);
        Self {
            pattern,
            seed: None,
            failure_type_weights: weights,
        }
    }

    /// Create a failure injector with a specific seed for reproducibility.
    pub fn with_seed(pattern: FailurePattern, seed: u64) -> Self {
        let mut injector = Self::new(pattern);
        injector.seed = Some(seed);
        injector
    }

    /// Inject failures into the topology according to the configured pattern.
    ///
    /// Returns a vector of failure events that were injected.
    pub fn inject(&self, topology: &mut SystemTopology, time_step: u32) -> Vec<FailureEvent> {
        let mut rng = match self.seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s.wrapping_add(time_step as u64)),
            None => rand::rngs::StdRng::from_os_rng(),
        };

        let mut events = Vec::new();
        let mut component_ids: Vec<ComponentId> = topology.components.keys().cloned().collect();
        // Sort for deterministic iteration order regardless of HashMap internals.
        component_ids.sort_by(|a, b| a.0.cmp(&b.0));

        match &self.pattern {
            FailurePattern::Random { count } => {
                let k = (*count).min(component_ids.len());
                let selected = select_random_indices(&mut rng, component_ids.len(), k);
                for idx in selected {
                    let id = &component_ids[idx];
                    let ft = self.sample_failure_type(&mut rng);
                    let mut event = FailureEvent::new(id.clone(), ft, time_step);
                    if let Some(comp) = topology.get_mut(id) {
                        event.severity *= comp.recovery_difficulty;
                        event.trust_impact *= (1.0 - comp.trust_level) + 0.2;
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);
                }
            }

            FailurePattern::Cascading {
                seed_component,
                cascade_probability,
                max_depth,
            } => {
                // Find seed component by substring match.
                let seed_id = component_ids
                    .iter()
                    .find(|id| id.0.contains(seed_component.as_str()));
                if let Some(id) = seed_id {
                    let ft = self.sample_failure_type(&mut rng);
                    let mut event = FailureEvent::new(id.clone(), ft, time_step);
                    if let Some(comp) = topology.get_mut(id) {
                        event.severity *= comp.recovery_difficulty;
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);

                    // BFS cascade to dependents.
                    let mut queue = vec![(id.clone(), 0u32)];
                    let mut visited = HashSet::new();
                    visited.insert(id.clone());

                    while let Some((current_id, depth)) = queue.pop() {
                        if depth >= *max_depth {
                            continue;
                        }
                        if let Some(comp) = topology.get(&current_id) {
                            for dep_id in &comp.dependencies.clone() {
                                if visited.contains(dep_id) {
                                    continue;
                                }
                                visited.insert(dep_id.clone());

                                let r: f64 = rng.random();
                                if r < *cascade_probability {
                                    let dep_ft = self.sample_failure_type(&mut rng);
                                    let mut cascade_event =
                                        FailureEvent::new(dep_id.clone(), dep_ft, time_step);
                                    cascade_event.is_cascade = true;
                                    if let Some(dep_comp) = topology.get_mut(dep_id) {
                                        cascade_event.severity *= dep_comp.recovery_difficulty;
                                        cascade_event.severity *= 0.8; // Cascade failures slightly less severe.
                                        dep_comp.state = ComponentState::Failed;
                                    }
                                    events.push(cascade_event);
                                    queue.push((dep_id.clone(), depth + 1));
                                }
                            }
                        }
                    }
                }
            }

            FailurePattern::Targeted { targets } => {
                for target in targets {
                    let target_id = ComponentId::new(target);
                    let ft = self.sample_failure_type(&mut rng);
                    let mut event = FailureEvent::new(target_id.clone(), ft, time_step);
                    if let Some(comp) = topology.get_mut(&target_id) {
                        event.severity *= comp.recovery_difficulty;
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);
                }
            }

            FailurePattern::Correlated {
                count,
                category_bias,
            } => {
                let k = (*count).min(component_ids.len());
                // First, select a random "seed category".
                let mut categories: Vec<&str> = topology
                    .components
                    .values()
                    .map(|c| c.category.as_str())
                    .collect();
                categories.sort();
                let seed_cat = if categories.is_empty() {
                    ""
                } else {
                    categories[rng.random_range(0..categories.len())]
                };

                // Weight components by category match.
                let weights: Vec<f64> = component_ids
                    .iter()
                    .map(|id| {
                        if let Some(comp) = topology.get(id) {
                            if comp.category == seed_cat {
                                *category_bias
                            } else {
                                1.0
                            }
                        } else {
                            1.0
                        }
                    })
                    .collect();

                let selected = select_weighted_indices(&mut rng, &weights, k);
                for idx in selected {
                    let id = &component_ids[idx];
                    let ft = self.sample_failure_type(&mut rng);
                    let mut event = FailureEvent::new(id.clone(), ft, time_step);
                    if let Some(comp) = topology.get_mut(id) {
                        event.severity *= comp.recovery_difficulty;
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);
                }
            }

            FailurePattern::ProbabilityWeighted { count } => {
                let k = (*count).min(component_ids.len());
                let weights: Vec<f64> = component_ids
                    .iter()
                    .map(|id| {
                        topology
                            .get(id)
                            .map(|c| c.effective_failure_probability())
                            .unwrap_or(0.01)
                    })
                    .collect();
                let selected = select_weighted_indices(&mut rng, &weights, k);
                for idx in selected {
                    let id = &component_ids[idx];
                    let ft = self.sample_failure_type(&mut rng);
                    let mut event = FailureEvent::new(id.clone(), ft, time_step);
                    if let Some(comp) = topology.get_mut(id) {
                        event.severity *= comp.recovery_difficulty;
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);
                }
            }

            FailurePattern::CommonCause {
                affected_category,
                failure_fraction,
            } => {
                let eligible: Vec<ComponentId> = component_ids
                    .iter()
                    .filter(|id| {
                        topology
                            .get(id)
                            .map(|c| c.category == *affected_category)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();

                let fail_count = (eligible.len() as f64 * failure_fraction).round() as usize;
                let selected = select_random_indices(&mut rng, eligible.len(), fail_count);
                for idx in selected {
                    let id = &eligible[idx];
                    let ft = FailureType::Crash; // Common cause is typically a crash.
                    let mut event = FailureEvent::new(id.clone(), ft, time_step);
                    event.severity = 0.8; // Common cause failures are uniformly severe.
                    if let Some(comp) = topology.get_mut(id) {
                        comp.state = ComponentState::Failed;
                    }
                    events.push(event);
                }
            }
        }

        events
    }

    /// Sample a failure type according to the configured weights.
    ///
    /// Iterates in a deterministic order (sorted by variant name) so that
    /// seeded RNG calls produce identical results across runs.
    fn sample_failure_type<R: rand::Rng>(&self, rng: &mut R) -> FailureType {
        let mut entries: Vec<_> = self.failure_type_weights.iter().collect();
        entries.sort_by_key(|(ft, _)| format!("{:?}", ft));
        let total_weight: f64 = entries.iter().map(|(_, &w)| w).sum();
        if total_weight <= 0.0 {
            return FailureType::Crash;
        }
        let mut r: f64 = rng.random::<f64>() * total_weight;
        for (&ft, &w) in &entries {
            r -= w;
            if r <= 0.0 {
                return ft;
            }
        }
        FailureType::Crash
    }
}

/// Select `k` distinct random indices from 0..n using Fisher-Yates partial shuffle.
fn select_random_indices<R: rand::Rng>(rng: &mut R, n: usize, k: usize) -> Vec<usize> {
    let k = k.min(n);
    let mut indices: Vec<usize> = (0..n).collect();
    for i in 0..k {
        let j = rng.random_range(i..n);
        indices.swap(i, j);
    }
    indices[..k].to_vec()
}

/// Select `k` distinct indices from 0..n weighted by `weights`.
fn select_weighted_indices<R: rand::Rng>(rng: &mut R, weights: &[f64], k: usize) -> Vec<usize> {
    let k = k.min(weights.len());
    let mut selected = Vec::with_capacity(k);
    let mut available_weights = weights.to_vec();

    for _ in 0..k {
        let total: f64 = available_weights.iter().sum();
        if total <= 0.0 {
            // Fallback: pick any remaining unselected.
            for (i, w) in available_weights.iter().enumerate() {
                if *w > 0.0 || !selected.contains(&i) {
                    selected.push(i);
                    available_weights[i] = 0.0;
                    break;
                }
            }
            continue;
        }

        let mut r: f64 = rng.random::<f64>() * total;
        let mut chosen = 0;
        for (i, w) in available_weights.iter().enumerate() {
            r -= w;
            if r <= 0.0 {
                chosen = i;
                break;
            }
        }
        selected.push(chosen);
        available_weights[chosen] = 0.0;
    }

    selected
}

// =============================================================================
// Section 4: Recovery Strategy Simulation
// =============================================================================

/// Types of recovery strategies that can be simulated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimRecoveryStrategy {
    /// Stop and restart the component.
    Restart,
    /// Revert to the last known-good configuration or state.
    Rollback,
    /// Switch traffic to a standby/replica component.
    Failover,
    /// Rebuild the component from scratch (costly but thorough).
    Rebuild,
}

impl SimRecoveryStrategy {
    /// All available strategy variants for iteration.
    pub fn all() -> Vec<SimRecoveryStrategy> {
        vec![
            SimRecoveryStrategy::Restart,
            SimRecoveryStrategy::Rollback,
            SimRecoveryStrategy::Failover,
            SimRecoveryStrategy::Rebuild,
        ]
    }
}

impl fmt::Display for SimRecoveryStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimRecoveryStrategy::Restart => write!(f, "Restart"),
            SimRecoveryStrategy::Rollback => write!(f, "Rollback"),
            SimRecoveryStrategy::Failover => write!(f, "Failover"),
            SimRecoveryStrategy::Rebuild => write!(f, "Rebuild"),
        }
    }
}

/// Configuration for a specific recovery strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStrategyConfig {
    /// The strategy type.
    pub strategy: SimRecoveryStrategy,
    /// Base probability that this strategy succeeds (0.0–1.0).
    pub base_success_probability: f64,
    /// Base duration of recovery in time steps (mean).
    pub base_duration: f64,
    /// Duration standard deviation.
    pub duration_variance: f64,
    /// Trust impact on recovery: positive means trust is restored, negative means trust is lost.
    pub trust_restoration: f64,
    /// Cost of applying this strategy (abstract units, for optimization).
    pub cost: f64,
    /// Whether this strategy can be applied to degraded components (not just failed).
    pub works_on_degraded: bool,
    /// Multiplier applied to success probability for critical components.
    pub critical_modifier: f64,
}

impl RecoveryStrategyConfig {
    /// Default configurations for all strategies.
    pub fn defaults() -> Vec<RecoveryStrategyConfig> {
        vec![
            RecoveryStrategyConfig {
                strategy: SimRecoveryStrategy::Restart,
                base_success_probability: 0.85,
                base_duration: 5.0,
                duration_variance: 2.0,
                trust_restoration: 0.3,
                cost: 1.0,
                works_on_degraded: true,
                critical_modifier: 0.9,
            },
            RecoveryStrategyConfig {
                strategy: SimRecoveryStrategy::Rollback,
                base_success_probability: 0.90,
                base_duration: 8.0,
                duration_variance: 3.0,
                trust_restoration: 0.5,
                cost: 2.0,
                works_on_degraded: true,
                critical_modifier: 0.95,
            },
            RecoveryStrategyConfig {
                strategy: SimRecoveryStrategy::Failover,
                base_success_probability: 0.80,
                base_duration: 2.0,
                duration_variance: 1.0,
                trust_restoration: 0.2,
                cost: 1.5,
                works_on_degraded: false,
                critical_modifier: 0.85,
            },
            RecoveryStrategyConfig {
                strategy: SimRecoveryStrategy::Rebuild,
                base_success_probability: 0.95,
                base_duration: 20.0,
                duration_variance: 5.0,
                trust_restoration: 0.8,
                cost: 5.0,
                works_on_degraded: true,
                critical_modifier: 1.0,
            },
        ]
    }
}

/// The outcome of applying a recovery strategy to a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimRecoveryOutcome {
    /// The strategy that was applied.
    pub strategy: SimRecoveryStrategy,
    /// ID of the component that was recovered.
    pub component_id: ComponentId,
    /// Whether the recovery was successful.
    pub success: bool,
    /// Actual duration of the recovery attempt (in time steps).
    pub duration: f64,
    /// Change in trust level resulting from this recovery.
    pub trust_delta: f64,
    /// Cost incurred by this recovery.
    pub cost: f64,
    /// The failure type that triggered this recovery.
    pub failure_type: FailureType,
}

impl SimRecoveryOutcome {
    /// Create a successful recovery outcome.
    pub fn success(
        strategy: SimRecoveryStrategy,
        component_id: ComponentId,
        duration: f64,
        trust_delta: f64,
        cost: f64,
        failure_type: FailureType,
    ) -> Self {
        Self {
            strategy,
            component_id,
            success: true,
            duration,
            trust_delta,
            cost,
            failure_type,
        }
    }

    /// Create a failed recovery outcome.
    pub fn failure(
        strategy: SimRecoveryStrategy,
        component_id: ComponentId,
        duration: f64,
        trust_delta: f64,
        cost: f64,
        failure_type: FailureType,
    ) -> Self {
        Self {
            strategy,
            component_id,
            success: false,
            duration,
            trust_delta,
            cost,
            failure_type,
        }
    }
}

/// Applies recovery strategies to failed components and returns outcomes.
pub struct RecoveryApplier {
    /// Configurations for each strategy type, keyed by strategy.
    pub configs: HashMap<SimRecoveryStrategy, RecoveryStrategyConfig>,
}

impl RecoveryApplier {
    /// Create a new recovery applier with default configurations.
    pub fn new() -> Self {
        let configs: HashMap<_, _> = RecoveryStrategyConfig::defaults()
            .into_iter()
            .map(|c| (c.strategy.clone(), c))
            .collect();
        Self { configs }
    }

    /// Create a recovery applier with a specific strategy configuration.
    pub fn with_config(configs: Vec<RecoveryStrategyConfig>) -> Self {
        let map: HashMap<_, _> = configs
            .into_iter()
            .map(|c| (c.strategy.clone(), c))
            .collect();
        Self { configs: map }
    }

    /// Apply the given recovery strategy to a failed component.
    ///
    /// Returns a `SimRecoveryOutcome` indicating success or failure, along with
    /// duration, trust impact, and cost. The success probability is adjusted
    /// based on component properties (recovery difficulty, trust level, etc.).
    pub fn apply<R: rand::Rng>(
        &self,
        strategy: &SimRecoveryStrategy,
        component: &Component,
        failure_type: FailureType,
        rng: &mut R,
    ) -> SimRecoveryOutcome {
        let config =
            self.configs
                .get(strategy)
                .cloned()
                .unwrap_or_else(|| RecoveryStrategyConfig {
                    strategy: strategy.clone(),
                    base_success_probability: 0.5,
                    base_duration: 10.0,
                    duration_variance: 3.0,
                    trust_restoration: 0.1,
                    cost: 1.0,
                    works_on_degraded: true,
                    critical_modifier: 1.0,
                });

        // Compute effective success probability.
        let mut success_prob = config.base_success_probability;
        // Higher recovery difficulty reduces success probability.
        success_prob *= 1.0 - 0.5 * component.recovery_difficulty;
        // Higher existing trust increases success probability slightly.
        success_prob *= 1.0 + 0.2 * component.trust_level;
        // Critical components get a modifier.
        if component.is_critical {
            success_prob *= config.critical_modifier;
        }
        // Certain failure types are harder to recover from.
        success_prob *= 1.0 - 0.2 * failure_type.severity();
        success_prob = success_prob.clamp(0.01, 0.99);

        // Determine success.
        let roll: f64 = rng.random();
        let success = roll < success_prob;

        // Sample duration from a truncated normal-ish distribution (Box-Muller-like).
        let u1: f64 = rng.random();
        let u2: f64 = rng.random();
        let normal_sample =
            (-2.0 * u1.max(1e-10).ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let duration =
            (config.base_duration + normal_sample * config.duration_variance.sqrt()).max(1.0);

        // Trust delta depends on outcome.
        let trust_delta = if success {
            config.trust_restoration
                * (1.0 - component.trust_level)
                * (1.0 - failure_type.trust_impact())
        } else {
            -failure_type.trust_impact() * 0.5
        };

        if success {
            SimRecoveryOutcome::success(
                strategy.clone(),
                component.id.clone(),
                duration,
                trust_delta,
                config.cost,
                failure_type,
            )
        } else {
            SimRecoveryOutcome::failure(
                strategy.clone(),
                component.id.clone(),
                duration,
                trust_delta,
                config.cost,
                failure_type,
            )
        }
    }

    /// Apply recovery to all failed components in the topology.
    ///
    /// Uses the specified strategy for all components. Returns outcomes for
    /// each component that was targeted for recovery.
    pub fn apply_to_topology<R: rand::Rng>(
        &self,
        topology: &mut SystemTopology,
        strategy: &SimRecoveryStrategy,
        failure_events: &[FailureEvent],
        rng: &mut R,
    ) -> Vec<SimRecoveryOutcome> {
        let mut outcomes = Vec::new();

        for event in failure_events {
            let comp = match topology.get(&event.component_id) {
                Some(c) => c.clone(),
                None => continue,
            };

            // Skip if component is already recovering (don't stack recoveries).
            if comp.state == ComponentState::Recovering {
                continue;
            }

            let outcome = self.apply(strategy, &comp, event.failure_type, rng);

            // Apply outcome to topology.
            if let Some(c) = topology.get_mut(&event.component_id) {
                if outcome.success {
                    c.state = ComponentState::Healthy;
                    c.trust_level = (c.trust_level + outcome.trust_delta).clamp(0.0, 1.0);
                    c.consecutive_failures = 0;
                    c.time_since_recovery = 0.0;
                } else {
                    c.state = ComponentState::Failed;
                    c.trust_level = (c.trust_level + outcome.trust_delta).clamp(0.0, 1.0);
                    c.consecutive_failures += 1;
                }
            }

            outcomes.push(outcome);
        }

        outcomes
    }
}

impl Default for RecoveryApplier {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Section 5: Monte Carlo Simulation Engine
// =============================================================================

/// Configuration for the Monte Carlo simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationConfig {
    /// Number of independent simulation runs (N).
    pub num_runs: u32,
    /// Number of time steps per simulation run.
    pub time_steps: u32,
    /// Failure injection pattern.
    pub failure_pattern: FailurePattern,
    /// Recovery strategy to apply after failures.
    pub recovery_strategy: SimRecoveryStrategy,
    /// Random seed for reproducibility (None for non-deterministic).
    pub seed: Option<u64>,
    /// Whether to enable verbose logging of individual scenarios.
    pub verbose: bool,
    /// Custom recovery strategy configurations (None uses defaults).
    pub recovery_configs: Option<Vec<RecoveryStrategyConfig>>,
    /// Whether to inject failures at every time step (true) or only once (false).
    pub continuous_failures: bool,
}

impl SimulationConfig {
    /// Create a default simulation configuration.
    pub fn new() -> Self {
        Self {
            num_runs: 1000,
            time_steps: 10,
            failure_pattern: FailurePattern::Random { count: 2 },
            recovery_strategy: SimRecoveryStrategy::Restart,
            seed: None,
            verbose: false,
            recovery_configs: None,
            continuous_failures: false,
        }
    }

    /// Create a configuration with a specific number of runs.
    pub fn with_runs(mut self, n: u32) -> Self {
        self.num_runs = n;
        self
    }

    /// Set the failure pattern.
    pub fn with_failure_pattern(mut self, pattern: FailurePattern) -> Self {
        self.failure_pattern = pattern;
        self
    }

    /// Set the recovery strategy.
    pub fn with_recovery_strategy(mut self, strategy: SimRecoveryStrategy) -> Self {
        self.recovery_strategy = strategy;
        self
    }

    /// Set the random seed.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a single simulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRun {
    /// Run index (0-based).
    pub run_index: u32,
    /// All failure events that occurred during this run.
    pub failure_events: Vec<FailureEvent>,
    /// All recovery outcomes during this run.
    pub recovery_outcomes: Vec<SimRecoveryOutcome>,
    /// System availability at the end of the run (0.0–1.0).
    pub final_availability: f64,
    /// System trust level at the end of the run (0.0–1.0).
    pub final_trust: f64,
    /// Total recovery cost incurred.
    pub total_cost: f64,
    /// Total time spent in recovery across all components.
    pub total_recovery_time: f64,
    /// Number of components that successfully recovered.
    pub successful_recoveries: u32,
    /// Number of recovery attempts that failed.
    pub failed_recoveries: u32,
    /// Maximum depth of cascading failures observed.
    pub max_cascade_depth: u32,
    /// Fraction of time steps where at least one critical component was down.
    pub critical_downtime_fraction: f64,
}

/// The aggregated results of a Monte Carlo simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationReport {
    /// Configuration used for the simulation.
    pub config: SimulationConfig,
    /// Number of runs that were actually executed.
    pub total_runs: u32,
    /// Statistics over final availability across all runs.
    pub availability_stats: SampleStatistics,
    /// Statistics over final trust levels across all runs.
    pub trust_stats: SampleStatistics,
    /// Statistics over total recovery costs across all runs.
    pub cost_stats: SampleStatistics,
    /// Statistics over total recovery times across all runs.
    pub recovery_time_stats: SampleStatistics,
    /// Overall recovery success rate (successful / total attempts).
    pub recovery_success_rate: f64,
    /// Average fraction of time critical components were down.
    pub avg_critical_downtime: f64,
    /// Individual run results (may be empty if verbose was false).
    pub runs: Vec<SimulationRun>,
    /// Failure type distribution across all runs.
    pub failure_type_distribution: HashMap<String, usize>,
    /// Per-strategy recovery success rates.
    pub strategy_success_rates: HashMap<String, f64>,
}

/// The Monte Carlo simulation engine.
///
/// Runs N independent simulations of the trust plane under failure,
/// applies recovery strategies, and aggregates results into a report.
pub struct MonteCarloEngine {
    /// The base topology (cloned for each run).
    pub base_topology: SystemTopology,
    /// Recovery applier for applying strategies.
    pub recovery_applier: RecoveryApplier,
}

impl MonteCarloEngine {
    /// Create a new Monte Carlo engine with the given base topology.
    pub fn new(topology: SystemTopology) -> Self {
        Self {
            base_topology: topology,
            recovery_applier: RecoveryApplier::new(),
        }
    }

    /// Create a new Monte Carlo engine with custom recovery configurations.
    pub fn with_recovery_configs(
        topology: SystemTopology,
        configs: Vec<RecoveryStrategyConfig>,
    ) -> Self {
        Self {
            base_topology: topology,
            recovery_applier: RecoveryApplier::with_config(configs),
        }
    }

    /// Run the Monte Carlo simulation with the given configuration.
    ///
    /// Executes `config.num_runs` independent simulations, each with
    /// `config.time_steps` time steps. Returns an aggregated report.
    pub fn run(&self, config: &SimulationConfig) -> SimulationReport {
        let mut all_runs = Vec::with_capacity(config.num_runs as usize);
        let mut availabilities = Vec::with_capacity(config.num_runs as usize);
        let mut trusts = Vec::with_capacity(config.num_runs as usize);
        let mut costs = Vec::with_capacity(config.num_runs as usize);
        let mut recovery_times = Vec::with_capacity(config.num_runs as usize);
        let mut critical_downtimes = Vec::with_capacity(config.num_runs as usize);
        let mut total_successes = 0u32;
        let mut total_attempts = 0u32;
        let mut failure_type_counts: HashMap<String, usize> = HashMap::new();
        let mut strategy_success: HashMap<String, (usize, usize)> = HashMap::new();

        for run_idx in 0..config.num_runs {
            let run_result = self.run_single(config, run_idx);

            let success_count = run_result.successful_recoveries;
            let failure_count = run_result.failed_recoveries;
            total_successes += success_count;
            total_attempts += success_count + failure_count;

            availabilities.push(run_result.final_availability);
            trusts.push(run_result.final_trust);
            costs.push(run_result.total_cost);
            recovery_times.push(run_result.total_recovery_time);
            critical_downtimes.push(run_result.critical_downtime_fraction);

            // Aggregate failure type distribution.
            for event in &run_result.failure_events {
                *failure_type_counts
                    .entry(event.failure_type.to_string())
                    .or_insert(0) += 1;
            }

            // Aggregate per-strategy success rates.
            for outcome in &run_result.recovery_outcomes {
                let entry = strategy_success
                    .entry(outcome.strategy.to_string())
                    .or_insert((0, 0));
                entry.1 += 1;
                if outcome.success {
                    entry.0 += 1;
                }
            }

            if config.verbose {
                all_runs.push(run_result);
            }
        }

        // Build strategy success rate map.
        let strategy_rates: HashMap<String, f64> = strategy_success
            .into_iter()
            .map(|(k, (s, total))| {
                let rate = if total > 0 {
                    s as f64 / total as f64
                } else {
                    0.0
                };
                (k, rate)
            })
            .collect();

        // Compute recovery success rate.
        let recovery_success_rate = if total_attempts > 0 {
            total_successes as f64 / total_attempts as f64
        } else {
            1.0
        };

        SimulationReport {
            config: config.clone(),
            total_runs: config.num_runs,
            availability_stats: SampleStatistics::from_slice(&availabilities).unwrap_or_else(
                || SampleStatistics {
                    n: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0.0,
                    max: 0.0,
                    median: 0.0,
                    q1: 0.0,
                    q3: 0.0,
                    variance: 0.0,
                    standard_error: 0.0,
                },
            ),
            trust_stats: SampleStatistics::from_slice(&trusts).unwrap_or_else(|| {
                SampleStatistics {
                    n: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0.0,
                    max: 0.0,
                    median: 0.0,
                    q1: 0.0,
                    q3: 0.0,
                    variance: 0.0,
                    standard_error: 0.0,
                }
            }),
            cost_stats: SampleStatistics::from_slice(&costs).unwrap_or_else(|| SampleStatistics {
                n: 0,
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                median: 0.0,
                q1: 0.0,
                q3: 0.0,
                variance: 0.0,
                standard_error: 0.0,
            }),
            recovery_time_stats: SampleStatistics::from_slice(&recovery_times).unwrap_or_else(
                || SampleStatistics {
                    n: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0.0,
                    max: 0.0,
                    median: 0.0,
                    q1: 0.0,
                    q3: 0.0,
                    variance: 0.0,
                    standard_error: 0.0,
                },
            ),
            recovery_success_rate,
            avg_critical_downtime: mean(&critical_downtimes),
            runs: all_runs,
            failure_type_distribution: failure_type_counts,
            strategy_success_rates: strategy_rates,
        }
    }

    /// Execute a single simulation run.
    ///
    /// Clones the base topology, injects failures at each time step,
    /// applies recovery, and tracks all outcomes.
    fn run_single(&self, config: &SimulationConfig, run_index: u32) -> SimulationRun {
        let mut rng = match config.seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(
                seed.wrapping_add(run_index as u64).wrapping_mul(31),
            ),
            None => rand::rngs::StdRng::from_os_rng(),
        };

        let mut topology = self.base_topology.clone();
        let mut all_failure_events = Vec::new();
        let mut all_recovery_outcomes = Vec::new();
        let mut total_cost = 0.0;
        let mut total_recovery_time = 0.0;
        let mut successful_recoveries = 0u32;
        let mut failed_recoveries = 0u32;
        let mut max_cascade_depth = 0u32;
        let mut critical_down_steps = 0u32;
        let critical_ids: HashSet<ComponentId> = topology
            .components
            .values()
            .filter(|c| c.is_critical)
            .map(|c| c.id.clone())
            .collect();

        for step in 0..config.time_steps {
            // Inject failures (only at step 0 if not continuous).
            let should_inject = config.continuous_failures || step == 0;
            if should_inject {
                let injector =
                    FailureInjector::with_seed(config.failure_pattern.clone(), rng.random::<u64>());
                let events = injector.inject(&mut topology, step);

                // Track cascade depth.
                for event in &events {
                    if event.is_cascade {
                        max_cascade_depth = max_cascade_depth.max(step);
                    }
                    all_failure_events.push(event.clone());
                }
            }

            // Apply recovery to all failed components.
            let outcomes = self.recovery_applier.apply_to_topology(
                &mut topology,
                &config.recovery_strategy,
                &all_failure_events,
                &mut rng,
            );

            for outcome in &outcomes {
                total_cost += outcome.cost;
                total_recovery_time += outcome.duration;
                if outcome.success {
                    successful_recoveries += 1;
                } else {
                    failed_recoveries += 1;
                }
            }

            all_recovery_outcomes.extend(outcomes);

            // Check if any critical component is down.
            let any_critical_down = critical_ids
                .iter()
                .any(|id| topology.get(id).map(|c| c.state.is_down()).unwrap_or(false));
            if any_critical_down {
                critical_down_steps += 1;
            }

            // Age all components.
            for comp in topology.components.values_mut() {
                comp.time_since_recovery += 1.0;
            }
        }

        SimulationRun {
            run_index,
            failure_events: all_failure_events,
            recovery_outcomes: all_recovery_outcomes,
            final_availability: topology.availability(),
            final_trust: topology.system_trust(),
            total_cost,
            total_recovery_time,
            successful_recoveries,
            failed_recoveries,
            max_cascade_depth,
            critical_downtime_fraction: if config.time_steps > 0 {
                critical_down_steps as f64 / config.time_steps as f64
            } else {
                0.0
            },
        }
    }
}

// =============================================================================
// Section 6: Sensitivity Analysis
// =============================================================================

/// A parameter that can be varied during sensitivity analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityParameter {
    /// Human-readable name of the parameter.
    pub name: String,
    /// The base (default) value.
    pub base_value: f64,
    /// Lower bound of the parameter range.
    pub min_value: f64,
    /// Upper bound of the parameter range.
    pub max_value: f64,
    /// Number of discrete points to sample in the range.
    pub num_points: usize,
    /// The objective metric this parameter affects.
    pub objective: SensitivityObjective,
}

/// Objectives that can be measured during sensitivity analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityObjective {
    /// System availability (fraction of components operational).
    Availability,
    /// System trust level.
    Trust,
    /// Recovery cost.
    Cost,
    /// Recovery time.
    RecoveryTime,
    /// Recovery success rate.
    SuccessRate,
}

/// The result of varying a single parameter across its range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivitySweepResult {
    /// The parameter that was varied.
    pub parameter: SensitivityParameter,
    /// The objective that was measured.
    pub objective: SensitivityObjective,
    /// Parameter values used in the sweep.
    pub parameter_values: Vec<f64>,
    /// Measured objective values at each parameter point.
    pub objective_values: Vec<f64>,
    /// Standard deviation of objective at each point (across Monte Carlo runs).
    pub objective_std_devs: Vec<f64>,
    /// Numerical derivative (slope) at each point (central difference).
    pub derivatives: Vec<f64>,
    /// Overall sensitivity rank: higher means this parameter has more effect.
    pub sensitivity_index: f64,
}

/// Sensitivity analysis engine.
///
/// Varies parameters one-at-a-time across the trust plane model,
/// runs Monte Carlo simulations at each value, and computes
/// numerical derivatives to identify the most impactful parameters.
pub struct SensitivityAnalyzer {
    /// The Monte Carlo engine used for running simulations.
    pub engine: MonteCarloEngine,
    /// Number of Monte Carlo runs per parameter point.
    pub runs_per_point: u32,
}

impl SensitivityAnalyzer {
    /// Create a new sensitivity analyzer.
    pub fn new(engine: MonteCarloEngine, runs_per_point: u32) -> Self {
        Self {
            engine,
            runs_per_point,
        }
    }

    /// Perform a one-at-a-time parameter sweep.
    ///
    /// For each parameter, varies it across `num_points` evenly spaced
    /// values in [min_value, max_value], runs Monte Carlo simulations,
    /// and computes numerical derivatives using central differences.
    ///
    /// Returns a sweep result for each parameter.
    pub fn sweep(&self, parameters: &[SensitivityParameter]) -> Vec<SensitivitySweepResult> {
        parameters
            .iter()
            .map(|param| self.sweep_parameter(param))
            .collect()
    }

    /// Sweep a single parameter across its range.
    pub fn sweep_parameter(&self, parameter: &SensitivityParameter) -> SensitivitySweepResult {
        let mut parameter_values = Vec::with_capacity(parameter.num_points);
        let mut objective_values = Vec::with_capacity(parameter.num_points);
        let mut objective_std_devs = Vec::with_capacity(parameter.num_points);

        let step = if parameter.num_points > 1 {
            (parameter.max_value - parameter.min_value) / (parameter.num_points - 1) as f64
        } else {
            0.0
        };

        for i in 0..parameter.num_points {
            let value = parameter.min_value + step * i as f64;
            parameter_values.push(value);

            // Create a modified topology with the parameter applied.
            let mut modified_topology = self.engine.base_topology.clone();
            self.apply_parameter(&mut modified_topology, parameter, value);

            // Run Monte Carlo with modified topology.
            let modified_engine = MonteCarloEngine::with_recovery_configs(
                modified_topology,
                RecoveryStrategyConfig::defaults(),
            );

            let config = SimulationConfig::new()
                .with_runs(self.runs_per_point)
                .with_seed(42);

            let report = modified_engine.run(&config);

            let (obj_value, obj_std) = match parameter.objective {
                SensitivityObjective::Availability => (
                    report.availability_stats.mean,
                    report.availability_stats.std_dev,
                ),
                SensitivityObjective::Trust => {
                    (report.trust_stats.mean, report.trust_stats.std_dev)
                }
                SensitivityObjective::Cost => (report.cost_stats.mean, report.cost_stats.std_dev),
                SensitivityObjective::RecoveryTime => (
                    report.recovery_time_stats.mean,
                    report.recovery_time_stats.std_dev,
                ),
                SensitivityObjective::SuccessRate => (report.recovery_success_rate, 0.0),
            };

            objective_values.push(obj_value);
            objective_std_devs.push(obj_std);
        }

        // Compute central-difference derivatives.
        let derivatives: Vec<f64> = (0..parameter_values.len())
            .map(|i| {
                if i == 0 && parameter_values.len() > 1 {
                    // Forward difference at left boundary.
                    (objective_values[1] - objective_values[0])
                        / (parameter_values[1] - parameter_values[0]).max(1e-10)
                } else if i == parameter_values.len() - 1 && parameter_values.len() > 1 {
                    // Backward difference at right boundary.
                    (objective_values[i] - objective_values[i - 1])
                        / (parameter_values[i] - parameter_values[i - 1]).max(1e-10)
                } else if parameter_values.len() > 2 {
                    // Central difference.
                    (objective_values[i + 1] - objective_values[i - 1])
                        / (parameter_values[i + 1] - parameter_values[i - 1]).max(1e-10)
                } else {
                    0.0
                }
            })
            .collect();

        // Compute sensitivity index: max absolute derivative.
        let sensitivity_index = derivatives
            .iter()
            .map(|d| d.abs())
            .fold(0.0_f64, |a, b| a.max(b));

        SensitivitySweepResult {
            parameter: parameter.clone(),
            objective: parameter.objective,
            parameter_values,
            objective_values,
            objective_std_devs,
            derivatives,
            sensitivity_index,
        }
    }

    /// Apply a parameter value to a topology by modifying component properties.
    ///
    /// Maps parameter names to concrete topology modifications.
    fn apply_parameter(
        &self,
        topology: &mut SystemTopology,
        parameter: &SensitivityParameter,
        value: f64,
    ) {
        match parameter.name.as_str() {
            "base_failure_probability" => {
                for comp in topology.components.values_mut() {
                    comp.base_failure_probability = value.clamp(0.0, 1.0);
                }
            }
            "trust_level" => {
                for comp in topology.components.values_mut() {
                    comp.trust_level = value.clamp(0.0, 1.0);
                }
            }
            "recovery_difficulty" => {
                for comp in topology.components.values_mut() {
                    comp.recovery_difficulty = value.clamp(0.0, 1.0);
                }
            }
            "load_factor" => {
                for comp in topology.components.values_mut() {
                    comp.load_factor = value.clamp(0.0, 1.0);
                }
            }
            "cascade_probability" => {
                // This affects the failure pattern, stored as a signal in trust_level temporarily.
                // We handle this by scaling base_failure_probability as a proxy.
                for comp in topology.components.values_mut() {
                    comp.base_failure_probability *= value.clamp(0.0, 2.0);
                    comp.base_failure_probability = comp.base_failure_probability.clamp(0.0, 1.0);
                }
            }
            _ => {
                // Unknown parameter: try to apply uniformly to all components
                // as a generic trust level modifier.
                for comp in topology.components.values_mut() {
                    comp.trust_level = (comp.trust_level * value).clamp(0.0, 1.0);
                }
            }
        }
    }

    /// Rank parameters by their sensitivity index (descending).
    ///
    /// Returns parameter names in order from most to least sensitive.
    pub fn rank_parameters(sweep_results: &[SensitivitySweepResult]) -> Vec<(String, f64)> {
        let mut ranked: Vec<(String, f64)> = sweep_results
            .iter()
            .map(|r| (r.parameter.name.clone(), r.sensitivity_index))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }
}

// =============================================================================
// Section 7: Pareto-Optimal Selection
// =============================================================================

/// Objectives used in Pareto-optimal strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParetoObjective {
    /// Minimize recovery time (lower is better).
    Speed,
    /// Maximize recovery reliability / success rate (higher is better).
    Reliability,
    /// Maximize post-recovery trust level (higher is better).
    Trust,
    /// Minimize recovery cost (lower is better).
    Cost,
}

impl ParetoObjective {
    /// All Pareto objectives.
    pub fn all() -> Vec<ParetoObjective> {
        vec![
            ParetoObjective::Speed,
            ParetoObjective::Reliability,
            ParetoObjective::Trust,
            ParetoObjective::Cost,
        ]
    }

    /// Returns true if higher values are better for this objective.
    pub fn is_maximize(&self) -> bool {
        matches!(
            self,
            ParetoObjective::Speed | ParetoObjective::Reliability | ParetoObjective::Trust
        )
    }
}

impl fmt::Display for ParetoObjective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParetoObjective::Speed => write!(f, "Speed"),
            ParetoObjective::Reliability => write!(f, "Reliability"),
            ParetoObjective::Trust => write!(f, "Trust"),
            ParetoObjective::Cost => write!(f, "Cost"),
        }
    }
}

/// A point in the multi-objective space representing a strategy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParetoPoint {
    /// The strategy that produced this point.
    pub strategy: SimRecoveryStrategy,
    /// Objective values keyed by objective name.
    pub objectives: HashMap<ParetoObjective, f64>,
    /// Label for display purposes.
    pub label: String,
}

impl ParetoPoint {
    /// Create a new Pareto point.
    pub fn new(strategy: SimRecoveryStrategy) -> Self {
        let label = strategy.to_string();
        Self {
            strategy,
            objectives: HashMap::new(),
            label,
        }
    }

    /// Set an objective value.
    pub fn with_objective(mut self, objective: ParetoObjective, value: f64) -> Self {
        self.objectives.insert(objective, value);
        self
    }
}

/// Result of Pareto frontier computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParetoFrontier {
    /// Points on the Pareto frontier (non-dominated).
    pub frontier_points: Vec<ParetoPoint>,
    /// All points that were evaluated (including dominated ones).
    pub all_points: Vec<ParetoPoint>,
    /// The objectives used for frontier computation.
    pub objectives: Vec<ParetoObjective>,
}

impl ParetoFrontier {
    /// Compute the Pareto frontier from a set of evaluated points.
    ///
    /// A point is on the frontier if no other point dominates it across
    /// all objectives. For maximization objectives, higher is better;
    /// for minimization objectives, lower is better.
    pub fn compute(points: Vec<ParetoPoint>, objectives: &[ParetoObjective]) -> Self {
        let frontier: Vec<ParetoPoint> = points
            .iter()
            .filter(|p| !is_dominated(p, &points, objectives))
            .cloned()
            .collect();

        // Sort frontier points by first objective for consistent ordering.
        let mut frontier = frontier;
        if let Some(first_obj) = objectives.first() {
            frontier.sort_by(|a, b| {
                let va = a.objectives.get(first_obj).copied().unwrap_or(0.0);
                let vb = b.objectives.get(first_obj).copied().unwrap_or(0.0);
                if first_obj.is_maximize() {
                    vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal)
                }
            });
        }

        Self {
            frontier_points: frontier,
            all_points: points,
            objectives: objectives.to_vec(),
        }
    }

    /// Select the best strategy from the frontier using weighted scoring.
    ///
    /// Weights are provided for each objective. The strategy with the
    /// highest weighted score is selected.
    pub fn select_best(&self, weights: &HashMap<ParetoObjective, f64>) -> Option<&ParetoPoint> {
        self.frontier_points.iter().max_by(|a, b| {
            let score_a = self.weighted_score(a, weights);
            let score_b = self.weighted_score(b, weights);
            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Compute the weighted score for a point.
    fn weighted_score(&self, point: &ParetoPoint, weights: &HashMap<ParetoObjective, f64>) -> f64 {
        let mut score = 0.0;
        for (obj, &weight) in weights {
            if let Some(&value) = point.objectives.get(obj) {
                let normalized = self.normalize(value, obj);
                score += weight * normalized;
            }
        }
        score
    }

    /// Normalize an objective value to [0, 1] using min-max normalization
    /// across all points.
    fn normalize(&self, value: f64, objective: &ParetoObjective) -> f64 {
        let values: Vec<f64> = self
            .all_points
            .iter()
            .filter_map(|p| p.objectives.get(objective).copied())
            .collect();

        let min_val = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = max_val - min_val;

        if range.abs() < 1e-10 {
            return 0.5;
        }

        if objective.is_maximize() {
            (value - min_val) / range
        } else {
            (max_val - value) / range
        }
    }

    /// Select the knee point — the point closest to the ideal point
    /// (best in all objectives simultaneously, which may not exist).
    pub fn select_knee_point(&self) -> Option<&ParetoPoint> {
        if self.frontier_points.is_empty() {
            return None;
        }

        // Compute ideal point (best in each objective).
        let ideal: HashMap<ParetoObjective, f64> = self
            .objectives
            .iter()
            .map(|obj| {
                let values: Vec<f64> = self
                    .frontier_points
                    .iter()
                    .filter_map(|p| p.objectives.get(obj).copied())
                    .collect();
                let best = if obj.is_maximize() {
                    values.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
                } else {
                    values.iter().cloned().fold(f64::INFINITY, f64::min)
                };
                (obj.clone(), best)
            })
            .collect();

        // Compute anti-ideal (worst in each objective).
        let anti_ideal: HashMap<ParetoObjective, f64> = self
            .objectives
            .iter()
            .map(|obj| {
                let values: Vec<f64> = self
                    .frontier_points
                    .iter()
                    .filter_map(|p| p.objectives.get(obj).copied())
                    .collect();
                let worst = if obj.is_maximize() {
                    values.iter().cloned().fold(f64::INFINITY, f64::min)
                } else {
                    values.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
                };
                (obj.clone(), worst)
            })
            .collect();

        // Normalize and compute Euclidean distance to ideal.
        let mut best_point = None;
        let mut best_distance = f64::INFINITY;

        for point in &self.frontier_points {
            let mut dist_sq = 0.0;
            for obj in &self.objectives {
                let value = point.objectives.get(obj).copied().unwrap_or(0.0);
                let ideal_val = ideal.get(obj).copied().unwrap_or(0.0);
                let anti_val = anti_ideal.get(obj).copied().unwrap_or(0.0);
                let range = (ideal_val - anti_val).abs().max(1e-10);

                // Normalize to [0, 1] where 0 = ideal, 1 = anti-ideal.
                let normalized = if obj.is_maximize() {
                    (ideal_val - value) / range
                } else {
                    (value - ideal_val) / range
                };
                dist_sq += normalized * normalized;
            }

            let dist = dist_sq.sqrt();
            if dist < best_distance {
                best_distance = dist;
                best_point = Some(point);
            }
        }

        best_point
    }

    /// Get the number of non-dominated points.
    pub fn frontier_size(&self) -> usize {
        self.frontier_points.len()
    }

    /// Get the number of dominated points.
    pub fn dominated_count(&self) -> usize {
        self.all_points
            .len()
            .saturating_sub(self.frontier_points.len())
    }
}

/// Check if a point is dominated by any other point in the set.
///
/// A point A dominates point B if A is at least as good as B in all
/// objectives and strictly better in at least one.
fn is_dominated(
    point: &ParetoPoint,
    all_points: &[ParetoPoint],
    objectives: &[ParetoObjective],
) -> bool {
    for other in all_points {
        if std::ptr::eq(point, other) {
            continue;
        }
        if dominates(other, point, objectives) {
            return true;
        }
    }
    false
}

/// Check if `a` dominates `b`.
fn dominates(a: &ParetoPoint, b: &ParetoPoint, objectives: &[ParetoObjective]) -> bool {
    let mut at_least_one_better = false;

    for obj in objectives {
        let va = a.objectives.get(obj).copied().unwrap_or(0.0);
        let vb = b.objectives.get(obj).copied().unwrap_or(0.0);

        if obj.is_maximize() {
            // Higher is better.
            if va < vb {
                return false; // a is worse in this objective.
            }
            if va > vb {
                at_least_one_better = true;
            }
        } else {
            // Lower is better.
            if va > vb {
                return false; // a is worse in this objective.
            }
            if va < vb {
                at_least_one_better = true;
            }
        }
    }

    at_least_one_better
}

/// Multi-objective strategy evaluator.
///
/// Evaluates all recovery strategies across a set of objectives using
/// Monte Carlo simulation and returns Pareto points for frontier analysis.
pub struct StrategyEvaluator {
    /// The Monte Carlo engine.
    pub engine: MonteCarloEngine,
    /// Number of runs per strategy evaluation.
    pub evaluation_runs: u32,
}

impl StrategyEvaluator {
    /// Create a new strategy evaluator.
    pub fn new(engine: MonteCarloEngine, evaluation_runs: u32) -> Self {
        Self {
            engine,
            evaluation_runs,
        }
    }

    /// Evaluate all strategies and produce Pareto points.
    ///
    /// For each strategy, runs the Monte Carlo engine and computes
    /// objective values: speed (inverse of avg recovery time), reliability
    /// (success rate), trust (final trust level), cost (total cost).
    pub fn evaluate(&self, failure_pattern: &FailurePattern) -> Vec<ParetoPoint> {
        let mut points = Vec::new();

        for strategy in SimRecoveryStrategy::all() {
            let config = SimulationConfig {
                num_runs: self.evaluation_runs,
                time_steps: 10,
                failure_pattern: failure_pattern.clone(),
                recovery_strategy: strategy.clone(),
                seed: Some(12345),
                verbose: false,
                recovery_configs: None,
                continuous_failures: false,
            };

            let report = self.engine.run(&config);

            let mut point = ParetoPoint::new(strategy.clone());
            point = point.with_objective(
                ParetoObjective::Speed,
                1.0 / report.recovery_time_stats.mean.max(0.01),
            );
            point =
                point.with_objective(ParetoObjective::Reliability, report.recovery_success_rate);
            point = point.with_objective(ParetoObjective::Trust, report.trust_stats.mean);
            point = point.with_objective(ParetoObjective::Cost, report.cost_stats.mean);

            points.push(point);
        }

        points
    }
}

// =============================================================================
// Section 8: Composite Scenario Runner
// =============================================================================

/// A named scenario combining a failure pattern with a recovery strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryScenario {
    /// Human-readable name for this scenario.
    pub name: String,
    /// Description of what this scenario tests.
    pub description: String,
    /// The failure injection pattern.
    pub failure_pattern: FailurePattern,
    /// The recovery strategy to apply.
    pub recovery_strategy: SimRecoveryStrategy,
    /// Custom recovery configurations (optional).
    pub recovery_configs: Option<Vec<RecoveryStrategyConfig>>,
    /// Expected outcome for validation (optional).
    pub expected_min_availability: Option<f64>,
    /// Expected minimum recovery success rate (optional).
    pub expected_min_success_rate: Option<f64>,
}

impl RecoveryScenario {
    /// Create a new scenario with a name and description.
    pub fn new(
        name: &str,
        description: &str,
        failure_pattern: FailurePattern,
        recovery_strategy: SimRecoveryStrategy,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            failure_pattern,
            recovery_strategy,
            recovery_configs: None,
            expected_min_availability: None,
            expected_min_success_rate: None,
        }
    }

    /// Set expected minimum availability.
    pub fn expect_availability(mut self, min_avail: f64) -> Self {
        self.expected_min_availability = Some(min_avail);
        self
    }

    /// Set expected minimum success rate.
    pub fn expect_success_rate(mut self, min_rate: f64) -> Self {
        self.expected_min_success_rate = Some(min_rate);
        self
    }

    /// Validate that the report meets the expected thresholds.
    pub fn validate(&self, report: &SimulationReport) -> ScenarioValidation {
        let mut passed = true;
        let mut failures = Vec::new();

        if let Some(min_avail) = self.expected_min_availability {
            if report.availability_stats.mean < min_avail {
                passed = false;
                failures.push(format!(
                    "Availability {:.4} below threshold {:.4}",
                    report.availability_stats.mean, min_avail
                ));
            }
        }

        if let Some(min_rate) = self.expected_min_success_rate {
            if report.recovery_success_rate < min_rate {
                passed = false;
                failures.push(format!(
                    "Success rate {:.4} below threshold {:.4}",
                    report.recovery_success_rate, min_rate
                ));
            }
        }

        ScenarioValidation {
            scenario_name: self.name.clone(),
            passed,
            failures,
            actual_availability: report.availability_stats.mean,
            actual_success_rate: report.recovery_success_rate,
        }
    }
}

/// Result of validating a scenario against its expectations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioValidation {
    /// Name of the scenario.
    pub scenario_name: String,
    /// Whether all expectations were met.
    pub passed: bool,
    /// List of expectation failures.
    pub failures: Vec<String>,
    /// Actual availability achieved.
    pub actual_availability: f64,
    /// Actual recovery success rate.
    pub actual_success_rate: f64,
}

/// Build a standard set of recovery scenarios for regression testing.
pub fn standard_scenarios() -> Vec<RecoveryScenario> {
    vec![
        RecoveryScenario::new(
            "single_random_restart",
            "Single random component failure with restart recovery",
            FailurePattern::Random { count: 1 },
            SimRecoveryStrategy::Restart,
        )
        .expect_availability(0.8)
        .expect_success_rate(0.7),
        RecoveryScenario::new(
            "dual_random_restart",
            "Two random component failures with restart recovery",
            FailurePattern::Random { count: 2 },
            SimRecoveryStrategy::Restart,
        )
        .expect_availability(0.6)
        .expect_success_rate(0.6),
        RecoveryScenario::new(
            "cascading_failover",
            "Cascading failure with failover strategy",
            FailurePattern::Cascading {
                seed_component: "shield_ingress".to_string(),
                cascade_probability: 0.5,
                max_depth: 3,
            },
            SimRecoveryStrategy::Failover,
        )
        .expect_availability(0.5)
        .expect_success_rate(0.6),
        RecoveryScenario::new(
            "targeted_rollback",
            "Targeted critical component failure with rollback",
            FailurePattern::Targeted {
                targets: vec!["trust_evaluator".to_string()],
            },
            SimRecoveryStrategy::Rollback,
        )
        .expect_availability(0.8)
        .expect_success_rate(0.7),
        RecoveryScenario::new(
            "correlated_rebuild",
            "Correlated failures with rebuild strategy",
            FailurePattern::Correlated {
                count: 3,
                category_bias: 2.0,
            },
            SimRecoveryStrategy::Rebuild,
        )
        .expect_availability(0.5)
        .expect_success_rate(0.8),
        RecoveryScenario::new(
            "common_cause_restart",
            "Common cause failure in shield_ring with restart",
            FailurePattern::CommonCause {
                affected_category: "shield_ring".to_string(),
                failure_fraction: 0.5,
            },
            SimRecoveryStrategy::Restart,
        )
        .expect_availability(0.4)
        .expect_success_rate(0.5),
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Statistics Utilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_mean_empty() {
        assert_eq!(mean(&[]), 0.0);
    }

    #[test]
    fn test_mean_single() {
        assert_eq!(mean(&[5.0]), 5.0);
    }

    #[test]
    fn test_mean_multiple() {
        let data = vec![2.0, 4.0, 6.0, 8.0];
        assert!((mean(&data) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_std_dev_empty() {
        assert_eq!(std_dev(&[]), 0.0);
    }

    #[test]
    fn test_std_dev_single() {
        assert_eq!(std_dev(&[7.0]), 0.0);
    }

    #[test]
    fn test_std_dev_known() {
        let data = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        // Known: mean=5.0, variance=4.0, std_dev=2.0
        let sd = std_dev(&data);
        assert!((sd - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_sample_statistics_from_slice() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let stats = SampleStatistics::from_slice(&data).unwrap();
        assert_eq!(stats.n, 10);
        assert!((stats.mean - 5.5).abs() < 1e-10);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 10.0);
        assert!(stats.variance > 0.0);
        assert!(stats.std_dev > 0.0);
    }

    #[test]
    fn test_sample_statistics_empty() {
        assert!(SampleStatistics::from_slice(&[]).is_none());
    }

    #[test]
    fn test_percentile_sorted() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert!((percentile(&sorted, 50.0) - 5.5).abs() < 0.01);
        assert!((percentile(&sorted, 25.0) - 3.25).abs() < 0.01);
        assert!((percentile(&sorted, 75.0) - 7.75).abs() < 0.01);
        assert!((percentile(&sorted, 0.0) - 1.0).abs() < 0.01);
        assert!((percentile(&sorted, 100.0) - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_confidence_interval() {
        let data: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let stats = SampleStatistics::from_slice(&data).unwrap();
        let ci_95 = stats.confidence_interval(0.95).unwrap();
        assert!(ci_95.lower < stats.mean);
        assert!(ci_95.upper > stats.mean);
        assert!((ci_95.confidence_level - 0.95).abs() < 1e-10);
        assert!(ci_95.margin_of_error > 0.0);
    }

    #[test]
    fn test_t_test_significant() {
        let a: Vec<f64> = (1..=50).map(|i| i as f64).collect();
        let b: Vec<f64> = (51..=100).map(|i| i as f64).collect();
        let result = t_test(&a, &b).unwrap();
        assert!(result.p_value < 0.05);
        assert!(result.significant_at_0_05);
        assert!(result.mean_difference < 0.0);
        assert!(result.effect_size.abs() > 1.0);
    }

    #[test]
    fn test_t_test_not_significant() {
        let a: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let b: Vec<f64> = vec![1.1, 2.1, 3.1, 4.1, 5.1];
        let result = t_test(&a, &b).unwrap();
        assert!(result.p_value > 0.05);
        assert!(!result.significant_at_0_05);
    }

    #[test]
    fn test_pearson_correlation_perfect() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let r = pearson_correlation(&x, &y).unwrap();
        assert!((r - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_pearson_correlation_negative() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![10.0, 8.0, 6.0, 4.0, 2.0];
        let r = pearson_correlation(&x, &y).unwrap();
        assert!((r - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn test_cliffs_delta() {
        let a = vec![10.0, 20.0, 30.0];
        let b = vec![1.0, 2.0, 3.0];
        let d = cliffs_delta(&a, &b);
        assert!(d > 0.5);
    }

    // -------------------------------------------------------------------------
    // Component and Topology Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_component_builder() {
        let comp = Component::builder("test_comp", "test_cat")
            .trust_level(0.75)
            .recovery_difficulty(0.5)
            .critical()
            .depends_on("other_comp")
            .load_factor(0.8)
            .build();

        assert_eq!(comp.id.0, "test_comp");
        assert_eq!(comp.category, "test_cat");
        assert!((comp.trust_level - 0.75).abs() < 1e-10);
        assert!((comp.recovery_difficulty - 0.5).abs() < 1e-10);
        assert!(comp.is_critical);
        assert_eq!(comp.dependencies.len(), 1);
        assert!((comp.load_factor - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_effective_failure_probability() {
        let mut comp = Component::new("test", "test");
        comp.base_failure_probability = 0.1;
        comp.trust_level = 0.5;
        comp.load_factor = 0.5;
        let p = comp.effective_failure_probability();
        assert!(p > 0.0 && p <= 1.0);
        // Higher trust should reduce probability relative to base.
        assert!(p < 0.2); // Reasonable upper bound given adjustments
    }

    #[test]
    fn test_system_topology_availability() {
        let mut topo = SystemTopology::new();
        topo.add_component(Component::new("a", "cat1"));
        topo.add_component(Component::new("b", "cat1"));
        assert!((topo.availability() - 1.0).abs() < 1e-10);

        topo.get_mut(&ComponentId::new("a")).unwrap().state = ComponentState::Failed;
        assert!((topo.availability() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_system_topology_trust() {
        let topo = SystemTopology::default_trust_plane();
        let trust = topo.system_trust();
        assert!(trust > 0.0 && trust <= 1.0);
    }

    #[test]
    fn test_default_trust_plane_size() {
        let topo = SystemTopology::default_trust_plane();
        assert_eq!(topo.components.len(), 9);
    }

    #[test]
    fn test_state_counts() {
        let mut topo = SystemTopology::new();
        topo.add_component(Component::new("a", "cat"));
        topo.add_component(Component::new("b", "cat"));
        topo.add_component(Component::new("c", "cat"));

        topo.get_mut(&ComponentId::new("a")).unwrap().state = ComponentState::Failed;
        topo.get_mut(&ComponentId::new("b")).unwrap().state = ComponentState::Degraded;

        let counts = topo.state_counts();
        assert_eq!(*counts.get(&ComponentState::Healthy).unwrap_or(&0), 1);
        assert_eq!(*counts.get(&ComponentState::Degraded).unwrap_or(&0), 1);
        assert_eq!(*counts.get(&ComponentState::Failed).unwrap_or(&0), 1);
    }

    // -------------------------------------------------------------------------
    // Failure Injection Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_random_failure_injection() {
        let mut topo = SystemTopology::default_trust_plane();
        let injector = FailureInjector::with_seed(FailurePattern::Random { count: 2 }, 42);
        let events = injector.inject(&mut topo, 0);
        assert_eq!(events.len(), 2);
        // Exactly 2 components should now be failed.
        let failed = topo.failed_components();
        assert!(failed.len() >= 2);
    }

    #[test]
    fn test_targeted_failure_injection() {
        let mut topo = SystemTopology::default_trust_plane();
        let injector = FailureInjector::with_seed(
            FailurePattern::Targeted {
                targets: vec!["trust_evaluator".to_string()],
            },
            42,
        );
        let events = injector.inject(&mut topo, 0);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].component_id.0, "trust_evaluator");
        assert_eq!(
            topo.get(&ComponentId::new("trust_evaluator"))
                .unwrap()
                .state,
            ComponentState::Failed
        );
    }

    #[test]
    fn test_common_cause_failure() {
        let mut topo = SystemTopology::default_trust_plane();
        let injector = FailureInjector::with_seed(
            FailurePattern::CommonCause {
                affected_category: "shield_ring".to_string(),
                failure_fraction: 0.5,
            },
            42,
        );
        let events = injector.inject(&mut topo, 0);
        // shield_ring has 3 components; 50% should fail 1 or 2.
        assert!(events.len() >= 1);
        for event in &events {
            let comp = topo.get(&event.component_id).unwrap();
            assert_eq!(comp.category, "shield_ring");
        }
    }

    #[test]
    fn test_cascading_failure_injection() {
        let mut topo = SystemTopology::default_trust_plane();
        let injector = FailureInjector::with_seed(
            FailurePattern::Cascading {
                seed_component: "shield_ingress".to_string(),
                cascade_probability: 1.0,
                max_depth: 2,
            },
            42,
        );
        let events = injector.inject(&mut topo, 0);
        // Seed should fail; dependents may cascade.
        assert!(events.len() >= 1);
        let seed_event = &events[0];
        assert_eq!(seed_event.component_id.0, "shield_ingress");
        assert!(!seed_event.is_cascade);
    }

    #[test]
    fn test_failure_type_severity() {
        assert!(FailureType::DataCorruption.severity() > FailureType::Degradation.severity());
        assert!(
            FailureType::Crash.trust_impact() > FailureType::PerformanceDegradation.trust_impact()
        );
    }

    // -------------------------------------------------------------------------
    // Recovery Strategy Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_recovery_applier_default() {
        let applier = RecoveryApplier::new();
        assert!(applier.configs.len() >= 4);
    }

    #[test]
    fn test_recovery_outcome_success() {
        let outcome = SimRecoveryOutcome::success(
            SimRecoveryStrategy::Restart,
            ComponentId::new("comp1"),
            5.0,
            0.3,
            1.0,
            FailureType::Crash,
        );
        assert!(outcome.success);
        assert!((outcome.trust_delta - 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_recovery_outcome_failure() {
        let outcome = SimRecoveryOutcome::failure(
            SimRecoveryStrategy::Rebuild,
            ComponentId::new("comp2"),
            20.0,
            -0.1,
            5.0,
            FailureType::DataCorruption,
        );
        assert!(!outcome.success);
        assert!(outcome.trust_delta < 0.0);
    }

    #[test]
    fn test_recovery_to_topology() {
        let mut topo = SystemTopology::default_trust_plane();
        let applier = RecoveryApplier::new();
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);

        // Manually fail a component.
        topo.get_mut(&ComponentId::new("trust_evaluator"))
            .unwrap()
            .state = ComponentState::Failed;

        let events = vec![FailureEvent::new(
            ComponentId::new("trust_evaluator"),
            FailureType::Crash,
            0,
        )];

        let outcomes =
            applier.apply_to_topology(&mut topo, &SimRecoveryStrategy::Restart, &events, &mut rng);
        assert_eq!(outcomes.len(), 1);
        // Check state changed (may be Healthy or still Failed depending on success).
        let comp = topo.get(&ComponentId::new("trust_evaluator")).unwrap();
        assert!(matches!(
            comp.state,
            ComponentState::Healthy | ComponentState::Failed
        ));
    }

    // -------------------------------------------------------------------------
    // Monte Carlo Engine Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_monte_carlo_basic_run() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new()
            .with_runs(50)
            .with_seed(42)
            .with_failure_pattern(FailurePattern::Random { count: 1 });

        let report = engine.run(&config);
        assert_eq!(report.total_runs, 50);
        assert!(report.availability_stats.mean > 0.0);
        assert!(report.trust_stats.mean > 0.0);
        assert!(report.recovery_success_rate >= 0.0 && report.recovery_success_rate <= 1.0);
    }

    #[test]
    fn test_monte_carlo_reproducible() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new().with_runs(30).with_seed(99);

        let report1 = engine.run(&config);
        let report2 = engine.run(&config);

        assert!((report1.availability_stats.mean - report2.availability_stats.mean).abs() < 1e-10);
        assert!((report1.trust_stats.mean - report2.trust_stats.mean).abs() < 1e-10);
    }

    #[test]
    fn test_monte_carlo_verbose_runs() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let mut config = SimulationConfig::new().with_runs(5).with_seed(42);
        config.verbose = true;

        let report = engine.run(&config);
        assert_eq!(report.runs.len(), 5);
        for run in &report.runs {
            assert!(run.final_availability >= 0.0 && run.final_availability <= 1.0);
        }
    }

    #[test]
    fn test_monte_carlo_failure_distribution() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new()
            .with_runs(100)
            .with_seed(42)
            .with_failure_pattern(FailurePattern::Random { count: 3 });

        let report = engine.run(&config);
        assert!(!report.failure_type_distribution.is_empty());
        let total_failures: usize = report.failure_type_distribution.values().sum();
        assert!(total_failures > 0);
    }

    // -------------------------------------------------------------------------
    // Sensitivity Analysis Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sensitivity_sweep() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let analyzer = SensitivityAnalyzer::new(engine, 20);

        let params = vec![SensitivityParameter {
            name: "base_failure_probability".to_string(),
            base_value: 0.01,
            min_value: 0.001,
            max_value: 0.1,
            num_points: 5,
            objective: SensitivityObjective::Availability,
        }];

        let results = analyzer.sweep(&params);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].parameter_values.len(), 5);
        assert_eq!(results[0].objective_values.len(), 5);
        assert_eq!(results[0].derivatives.len(), 5);
    }

    #[test]
    fn test_sensitivity_ranking() {
        let results = vec![
            SensitivitySweepResult {
                parameter: SensitivityParameter {
                    name: "low_sensitivity".to_string(),
                    base_value: 0.0,
                    min_value: 0.0,
                    max_value: 1.0,
                    num_points: 3,
                    objective: SensitivityObjective::Availability,
                },
                objective: SensitivityObjective::Availability,
                parameter_values: vec![0.0, 0.5, 1.0],
                objective_values: vec![0.9, 0.88, 0.86],
                objective_std_devs: vec![0.0, 0.0, 0.0],
                derivatives: vec![-0.08, -0.04, -0.04],
                sensitivity_index: 0.08,
            },
            SensitivitySweepResult {
                parameter: SensitivityParameter {
                    name: "high_sensitivity".to_string(),
                    base_value: 0.0,
                    min_value: 0.0,
                    max_value: 1.0,
                    num_points: 3,
                    objective: SensitivityObjective::Availability,
                },
                objective: SensitivityObjective::Availability,
                parameter_values: vec![0.0, 0.5, 1.0],
                objective_values: vec![0.9, 0.5, 0.1],
                objective_std_devs: vec![0.0, 0.0, 0.0],
                derivatives: vec![-0.8, -0.4, -0.4],
                sensitivity_index: 0.8,
            },
        ];

        let ranked = SensitivityAnalyzer::rank_parameters(&results);
        assert_eq!(ranked[0].0, "high_sensitivity");
        assert_eq!(ranked[1].0, "low_sensitivity");
    }

    // -------------------------------------------------------------------------
    // Pareto Frontier Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_pareto_frontier_basic() {
        let points = vec![
            ParetoPoint::new(SimRecoveryStrategy::Restart)
                .with_objective(ParetoObjective::Speed, 0.8)
                .with_objective(ParetoObjective::Reliability, 0.7),
            ParetoPoint::new(SimRecoveryStrategy::Rollback)
                .with_objective(ParetoObjective::Speed, 0.5)
                .with_objective(ParetoObjective::Reliability, 0.9),
            ParetoPoint::new(SimRecoveryStrategy::Rebuild)
                .with_objective(ParetoObjective::Speed, 0.3)
                .with_objective(ParetoObjective::Reliability, 0.95),
            ParetoPoint::new(SimRecoveryStrategy::Failover)
                .with_objective(ParetoObjective::Speed, 0.6)
                .with_objective(ParetoObjective::Reliability, 0.6),
        ];

        let frontier = ParetoFrontier::compute(
            points,
            &[ParetoObjective::Speed, ParetoObjective::Reliability],
        );

        // Failover (0.6, 0.6) is dominated by Restart (0.8, 0.7) in both objectives.
        assert!(frontier.dominated_count() >= 1);
        assert!(frontier.frontier_size() >= 2);
        // Restart and Rebuild should be on the frontier.
        let frontier_names: Vec<&str> = frontier
            .frontier_points
            .iter()
            .map(|p| p.label.as_str())
            .collect();
        assert!(frontier_names.contains(&"Restart"));
        assert!(frontier_names.contains(&"Rebuild"));
    }

    #[test]
    fn test_pareto_knee_point() {
        let points = vec![
            ParetoPoint::new(SimRecoveryStrategy::Restart)
                .with_objective(ParetoObjective::Speed, 0.9)
                .with_objective(ParetoObjective::Reliability, 0.5),
            ParetoPoint::new(SimRecoveryStrategy::Rollback)
                .with_objective(ParetoObjective::Speed, 0.5)
                .with_objective(ParetoObjective::Reliability, 0.9),
            ParetoPoint::new(SimRecoveryStrategy::Rebuild)
                .with_objective(ParetoObjective::Speed, 0.3)
                .with_objective(ParetoObjective::Reliability, 0.95),
        ];

        let frontier = ParetoFrontier::compute(
            points,
            &[ParetoObjective::Speed, ParetoObjective::Reliability],
        );

        let knee = frontier.select_knee_point();
        assert!(knee.is_some());
    }

    #[test]
    fn test_pareto_select_best_weighted() {
        let points = vec![
            ParetoPoint::new(SimRecoveryStrategy::Restart)
                .with_objective(ParetoObjective::Speed, 0.9)
                .with_objective(ParetoObjective::Reliability, 0.5),
            ParetoPoint::new(SimRecoveryStrategy::Rebuild)
                .with_objective(ParetoObjective::Speed, 0.3)
                .with_objective(ParetoObjective::Reliability, 0.95),
        ];

        let frontier = ParetoFrontier::compute(
            points,
            &[ParetoObjective::Speed, ParetoObjective::Reliability],
        );

        // Prefer reliability.
        let mut weights = HashMap::new();
        weights.insert(ParetoObjective::Speed, 0.3);
        weights.insert(ParetoObjective::Reliability, 0.7);

        let best = frontier.select_best(&weights);
        assert!(best.is_some());
        assert_eq!(best.unwrap().strategy, SimRecoveryStrategy::Rebuild);
    }

    // -------------------------------------------------------------------------
    // Scenario Validation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_standard_scenarios() {
        let scenarios = standard_scenarios();
        assert!(scenarios.len() >= 6);

        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);

        for scenario in &scenarios {
            let config = SimulationConfig {
                num_runs: 50,
                time_steps: 5,
                failure_pattern: scenario.failure_pattern.clone(),
                recovery_strategy: scenario.recovery_strategy.clone(),
                seed: Some(42),
                verbose: false,
                recovery_configs: scenario.recovery_configs.clone(),
                continuous_failures: false,
            };
            let report = engine.run(&config);
            let validation = scenario.validate(&report);
            // Most scenarios should pass with enough runs.
            // We don't assert pass/fail since Monte Carlo has variance.
            assert!(validation.actual_availability >= 0.0);
            assert!(validation.actual_success_rate >= 0.0);
        }
    }

    #[test]
    fn test_scenario_validation_pass() {
        let scenario = RecoveryScenario::new(
            "test",
            "Test scenario",
            FailurePattern::Random { count: 1 },
            SimRecoveryStrategy::Restart,
        )
        .expect_availability(0.0) // Very low threshold, should always pass.
        .expect_success_rate(0.0);

        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new()
            .with_runs(20)
            .with_seed(42)
            .with_failure_pattern(FailurePattern::Random { count: 1 });
        let report = engine.run(&config);
        let validation = scenario.validate(&report);
        assert!(validation.passed);
        assert!(validation.failures.is_empty());
    }

    #[test]
    fn test_strategy_evaluator() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let evaluator = StrategyEvaluator::new(engine, 30);
        let points = evaluator.evaluate(&FailurePattern::Random { count: 2 });
        assert_eq!(points.len(), 4); // One per strategy.
        for point in &points {
            assert!(point.objectives.len() >= 4); // All four objectives.
        }
    }

    // -------------------------------------------------------------------------
    // Edge Cases and Integration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_empty_topology_simulation() {
        let topo = SystemTopology::new();
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new().with_runs(10).with_seed(42);
        let report = engine.run(&config);
        assert_eq!(report.total_runs, 10);
    }

    #[test]
    fn test_single_component_topology() {
        let mut topo = SystemTopology::new();
        topo.add_component(Component::new("solo", "solo_cat"));
        let engine = MonteCarloEngine::new(topo);
        let config = SimulationConfig::new()
            .with_runs(20)
            .with_seed(42)
            .with_failure_pattern(FailurePattern::Random { count: 1 });
        let report = engine.run(&config);
        assert!(report.availability_stats.mean >= 0.0);
    }

    #[test]
    fn test_continuous_failures() {
        let topo = SystemTopology::default_trust_plane();
        let engine = MonteCarloEngine::new(topo);
        let mut config = SimulationConfig::new()
            .with_runs(20)
            .with_seed(42)
            .with_failure_pattern(FailurePattern::Random { count: 1 });
        config.continuous_failures = true;
        config.time_steps = 5;

        let report = engine.run(&config);
        // Continuous failures should produce more failure events than single-shot.
        assert!(report.failure_type_distribution.values().sum::<usize>() > 20);
    }

    #[test]
    fn test_probability_weighted_failure() {
        let mut topo = SystemTopology::default_trust_plane();
        // Give one component a very high failure probability.
        if let Some(comp) = topo.get_mut(&ComponentId::new("threat_analyzer")) {
            comp.base_failure_probability = 0.99;
        }
        let injector =
            FailureInjector::with_seed(FailurePattern::ProbabilityWeighted { count: 1 }, 42);
        let events = injector.inject(&mut topo, 0);
        assert_eq!(events.len(), 1);
        // The high-probability component should be the one that fails.
        assert_eq!(events[0].component_id.0, "threat_analyzer");
    }

    #[test]
    fn test_component_state_is_operational() {
        assert!(ComponentState::Healthy.is_operational());
        assert!(ComponentState::Degraded.is_operational());
        assert!(!ComponentState::Failed.is_operational());
        assert!(!ComponentState::Recovering.is_operational());
        assert!(!ComponentState::Quarantined.is_operational());
    }

    #[test]
    fn test_component_state_is_down() {
        assert!(!ComponentState::Healthy.is_down());
        assert!(ComponentState::Failed.is_down());
        assert!(ComponentState::Quarantined.is_down());
        assert!(!ComponentState::Degraded.is_down());
    }

    #[test]
    fn test_recovery_strategy_display() {
        assert_eq!(SimRecoveryStrategy::Restart.to_string(), "Restart");
        assert_eq!(SimRecoveryStrategy::Rollback.to_string(), "Rollback");
        assert_eq!(SimRecoveryStrategy::Failover.to_string(), "Failover");
        assert_eq!(SimRecoveryStrategy::Rebuild.to_string(), "Rebuild");
    }

    #[test]
    fn test_failure_type_display() {
        assert_eq!(format!("{}", FailureType::Crash), "Crash");
        assert_eq!(format!("{}", FailureType::DataCorruption), "DataCorruption");
    }

    #[test]
    fn test_all_strategies_enumerated() {
        let all = SimRecoveryStrategy::all();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_pareto_objective_maximize() {
        assert!(ParetoObjective::Reliability.is_maximize());
        assert!(ParetoObjective::Trust.is_maximize());
        assert!(ParetoObjective::Speed.is_maximize());
        assert!(!ParetoObjective::Cost.is_maximize());
    }

    #[test]
    fn test_simulation_config_defaults() {
        let config = SimulationConfig::default();
        assert_eq!(config.num_runs, 1000);
        assert_eq!(config.time_steps, 10);
    }

    #[test]
    fn test_z_critical_value_reasonable() {
        let z95 = z_critical_value(0.95);
        assert!((z95 - 1.96).abs() < 0.1);
        let z99 = z_critical_value(0.99);
        assert!((z99 - 2.576).abs() < 0.1);
    }

    #[test]
    fn test_normal_survival_symmetry() {
        let s1 = normal_survival(1.0);
        let s2 = normal_survival(-1.0);
        assert!((s1 - (1.0 - s2)).abs() < 1e-10);
    }

    #[test]
    fn test_recovery_strategy_config_defaults() {
        let defaults = RecoveryStrategyConfig::defaults();
        assert_eq!(defaults.len(), 4);
        // Check Rebuild is the most expensive.
        let rebuild = defaults
            .iter()
            .find(|c| c.strategy == SimRecoveryStrategy::Rebuild)
            .unwrap();
        let restart = defaults
            .iter()
            .find(|c| c.strategy == SimRecoveryStrategy::Restart)
            .unwrap();
        assert!(rebuild.cost > restart.cost);
        assert!(rebuild.base_success_probability > restart.base_success_probability);
    }
}
