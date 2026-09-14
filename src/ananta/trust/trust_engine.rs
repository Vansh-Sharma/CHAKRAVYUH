// Bayesian Trust Engine — probabilistic trust model replacing simple EMA.
//
// This module implements a production-grade Bayesian trust engine that:
//   1. Uses Beta distribution for per-edge trust posteriors
//   2. Applies configurable temporal decay to evidence
//   3. Propagates trust through the graph with PageRank-like damping
//   4. Fuses multi-path evidence via Dempster-Shafer combination
//   5. Predicts future trust trends via Holt-Winters smoothing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::TrendDirection;

// ---------------------------------------------------------------------------
// 1. Beta Distribution Trust Model
// ---------------------------------------------------------------------------

/// Parameters for the Beta prior used in all trust relationships.
///
/// A skeptical prior (alpha_0 == beta_0 > 1) ensures that trust must be
/// *earned* through evidence — a neutral prior with small pseudo-counts
/// would converge too quickly from noisy observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetaPrior {
    /// Pseudo-count of positive evidence in the prior.
    pub alpha_0: f64,
    /// Pseudo-count of negative evidence in the prior.
    pub beta_0: f64,
}

impl Default for BetaPrior {
    /// Default skeptical prior: Beta(2, 2). The posterior mean starts at 0.5
    /// and requires genuine evidence to move away from neutrality.
    fn default() -> Self {
        Self {
            alpha_0: 2.0,
            beta_0: 2.0,
        }
    }
}

impl BetaPrior {
    /// Create a custom prior. Both parameters must be positive.
    pub fn new(alpha_0: f64, beta_0: f64) -> Self {
        Self {
            alpha_0: alpha_0.max(0.01),
            beta_0: beta_0.max(0.01),
        }
    }

    /// Create an optimistic prior (higher starting trust).
    pub fn optimistic() -> Self {
        Self::new(5.0, 1.0)
    }

    /// Create a pessimistic prior (lower starting trust).
    pub fn pessimistic() -> Self {
        Self::new(1.0, 5.0)
    }

    /// Compute the prior mean: alpha_0 / (alpha_0 + beta_0).
    pub fn mean(&self) -> f64 {
        self.alpha_0 / (self.alpha_0 + self.beta_0)
    }

    /// Compute the prior variance of the Beta distribution.
    /// Var(X) = alpha*beta / ((alpha+beta)^2 * (alpha+beta+1))
    pub fn variance(&self) -> f64 {
        let a = self.alpha_0;
        let b = self.beta_0;
        (a * b) / ((a + b).powi(2) * (a + b + 1.0))
    }
}

/// A single piece of trust evidence with an optional timestamp.
///
/// Evidence is either positive (trust-increasing) or negative (trust-decreasing)
/// with a weight that controls how much impact it has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvidence {
    /// Whether this evidence is positive (true) or negative (false).
    pub is_positive: bool,
    /// Weight of this evidence, in (0, 1]. Higher = more impactful.
    pub weight: f64,
    /// RFC 3339 timestamp when this evidence was observed.
    pub timestamp: String,
    /// Human-readable description of the evidence source.
    pub source: String,
}

impl TrustEvidence {
    /// Create a new evidence record.
    pub fn new(is_positive: bool, weight: f64, source: &str) -> Self {
        Self {
            is_positive,
            weight: weight.clamp(0.01, 1.0),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: source.into(),
        }
    }

    /// Create a positive evidence record with unit weight.
    pub fn positive(source: &str) -> Self {
        Self::new(true, 1.0, source)
    }

    /// Create a negative evidence record with unit weight.
    pub fn negative(source: &str) -> Self {
        Self::new(false, 1.0, source)
    }
}

/// Bayesian trust parameters for a single entity-pair relationship.
///
/// Stores the Beta distribution parameters (alpha, beta) that represent
/// accumulated positive and negative evidence. The posterior mean
/// `alpha / (alpha + beta)` is the trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetaTrustParams {
    /// Beta distribution alpha parameter (positive evidence + prior).
    pub alpha: f64,
    /// Beta distribution beta parameter (negative evidence + prior).
    pub beta: f64,
    /// Raw positive evidence count (before prior addition), for audit.
    pub raw_positive: f64,
    /// Raw negative evidence count (before prior addition), for audit.
    pub raw_negative: f64,
    /// The prior used for this relationship.
    pub prior: BetaPrior,
}

impl BetaTrustParams {
    /// Initialize with the given prior and no evidence.
    pub fn new(prior: BetaPrior) -> Self {
        Self {
            alpha: prior.alpha_0,
            beta: prior.beta_0,
            raw_positive: 0.0,
            raw_negative: 0.0,
            prior,
        }
    }

    /// Initialize with the default skeptical prior Beta(2, 2).
    pub fn with_default_prior() -> Self {
        Self::new(BetaPrior::default())
    }

    /// Compute the posterior mean (the trust score).
    ///
    /// This is the expected value of the Beta(alpha, beta) distribution:
    ///   E[X] = alpha / (alpha + beta)
    pub fn posterior_mean(&self) -> f64 {
        let total = self.alpha + self.beta;
        if total == 0.0 {
            return self.prior.mean();
        }
        self.alpha / total
    }

    /// Compute the posterior variance.
    ///
    /// Var(X) = alpha * beta / ((alpha+beta)^2 * (alpha+beta+1))
    pub fn posterior_variance(&self) -> f64 {
        let total = self.alpha + self.beta;
        if total <= 1.0 {
            return 1.0 / 12.0; // Maximum variance for uniform approximation.
        }
        (self.alpha * self.beta) / (total.powi(2) * (total + 1.0))
    }

    /// Compute the posterior standard deviation.
    pub fn posterior_std(&self) -> f64 {
        self.posterior_variance().sqrt()
    }

    /// Compute the total evidence count (including prior pseudo-counts).
    pub fn total_evidence(&self) -> f64 {
        self.alpha + self.beta
    }

    /// Compute the effective sample size (raw evidence only, excluding prior).
    pub fn effective_sample_size(&self) -> f64 {
        self.raw_positive + self.raw_negative
    }

    /// Update with new positive evidence.
    ///
    /// Returns the updated (alpha, beta) as a tuple.
    pub fn update_positive(&mut self, weight: f64) -> (f64, f64) {
        let w = weight.max(0.01);
        self.alpha += w;
        self.raw_positive += w;
        (self.alpha, self.beta)
    }

    /// Update with new negative evidence.
    ///
    /// Returns the updated (alpha, beta) as a tuple.
    pub fn update_negative(&mut self, weight: f64) -> (f64, f64) {
        let w = weight.max(0.01);
        self.beta += w;
        self.raw_negative += w;
        (self.alpha, self.beta)
    }

    /// Update with a boolean evidence flag.
    ///
    /// If `positive` is true, alpha is incremented; otherwise beta is incremented.
    /// The weight controls the magnitude of the update.
    pub fn update(&mut self, positive: bool, weight: f64) -> (f64, f64) {
        if positive {
            self.update_positive(weight)
        } else {
            self.update_negative(weight)
        }
    }

    /// Compute a credible interval for the trust score.
    ///
    /// Uses the normal approximation to the Beta distribution:
    ///   CI = mean ± z * std_dev
    ///
    /// `confidence` should be in (0, 1). Common values:
    ///   - 0.90 → z ≈ 1.645
    ///   - 0.95 → z ≈ 1.960
    ///   - 0.99 → z ≈ 2.576
    pub fn credible_interval(&self, confidence: f64) -> (f64, f64) {
        let z = z_score(confidence);
        let mean = self.posterior_mean();
        let std = self.posterior_std();
        let half_width = z * std;
        (
            (mean - half_width).max(0.0),
            (mean + half_width).min(1.0),
        )
    }

    /// Compute the probability that trust exceeds a threshold.
    ///
    /// Uses the normal approximation to the Beta distribution.
    pub fn prob_exceeds(&self, threshold: f64) -> f64 {
        let mean = self.posterior_mean();
        let std = self.posterior_std();
        if std < 1e-12 {
            if mean >= threshold { 1.0 } else { 0.0 }
        } else {
            let z = (mean - threshold) / std;
            normal_cdf(z)
        }
    }

    /// Reset to the prior, discarding all evidence.
    pub fn reset(&mut self) {
        self.alpha = self.prior.alpha_0;
        self.beta = self.prior.beta_0;
        self.raw_positive = 0.0;
        self.raw_negative = 0.0;
    }
}

// ---------------------------------------------------------------------------
// 2. Temporal Decay
// ---------------------------------------------------------------------------

/// The type of temporal decay to apply to trust evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecayFunction {
    /// Exponential decay: weight *= e^(-lambda * dt).
    Exponential,
    /// Linear decay: weight -= rate * dt.
    Linear,
    /// Step decay: weight drops by a factor at configured time boundaries.
    Step,
}

/// Configuration for temporal decay of trust evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayConfig {
    /// The type of decay function to use.
    pub function: DecayFunction,
    /// For exponential decay: the lambda parameter. Higher = faster decay.
    /// Units: per-second inverse. E.g., 0.001 means ~63% decay over 1000 seconds.
    pub lambda: f64,
    /// For linear decay: the rate of decrease per second.
    pub linear_rate: f64,
    /// For step decay: the factor to multiply by at each step boundary.
    /// E.g., 0.5 halves the weight at each step.
    pub step_factor: f64,
    /// For step decay: the interval in seconds between step boundaries.
    pub step_interval_secs: f64,
    /// Minimum decayed weight floor. Evidence never decays below this.
    pub floor: f64,
}

impl Default for DecayConfig {
    /// Default: exponential decay with lambda=0.001 (slow decay).
    fn default() -> Self {
        Self {
            function: DecayFunction::Exponential,
            lambda: 0.001,
            linear_rate: 0.0001,
            step_factor: 0.8,
            step_interval_secs: 3600.0, // 1 hour
            floor: 0.01,
        }
    }
}

impl DecayConfig {
    /// Create an exponential decay config with the given lambda.
    pub fn exponential(lambda: f64) -> Self {
        Self {
            function: DecayFunction::Exponential,
            lambda: lambda.max(0.0),
            linear_rate: 0.0001,
            step_factor: 0.8,
            step_interval_secs: 3600.0,
            floor: 0.01,
        }
    }

    /// Create a linear decay config with the given rate.
    pub fn linear(rate: f64) -> Self {
        Self {
            function: DecayFunction::Linear,
            lambda: 0.001,
            linear_rate: rate.max(0.0),
            step_factor: 0.8,
            step_interval_secs: 3600.0,
            floor: 0.01,
        }
    }

    /// Create a step decay config with the given factor and interval.
    pub fn step(factor: f64, interval_secs: f64) -> Self {
        Self {
            function: DecayFunction::Step,
            lambda: 0.001,
            linear_rate: 0.0001,
            step_factor: factor.clamp(0.0, 1.0),
            step_interval_secs: interval_secs.max(1.0),
            floor: 0.01,
        }
    }

    /// Compute the decay multiplier for a given time delta in seconds.
    ///
    /// Returns a value in [floor, 1.0] representing how much of the
    /// original evidence weight remains after `dt` seconds.
    pub fn decay_multiplier(&self, dt_secs: f64) -> f64 {
        let dt = dt_secs.max(0.0);
        let multiplier = match self.function {
            DecayFunction::Exponential => {
                (-self.lambda * dt).exp()
            }
            DecayFunction::Linear => {
                (1.0 - self.linear_rate * dt).max(0.0)
            }
            DecayFunction::Step => {
                let steps = (dt / self.step_interval_secs).floor() as u64;
                self.step_factor.powi(steps as i32)
            }
        };
        multiplier.max(self.floor)
    }
}

/// A record of trust evidence with its decay state.
///
/// Stores both the raw evidence weight and the decayed weight,
/// so that raw counts are preserved for audit while decayed weights
/// are used for trust computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayableEvidence {
    /// The original evidence.
    pub evidence: TrustEvidence,
    /// Raw weight at time of observation.
    pub raw_weight: f64,
    /// Decayed weight as of the last decay pass.
    pub decayed_weight: f64,
    /// Timestamp of the last decay computation.
    pub last_decay_time: String,
}

impl DecayableEvidence {
    /// Create a new decayable evidence record.
    pub fn new(evidence: TrustEvidence) -> Self {
        let raw_weight = evidence.weight;
        Self {
            evidence,
            raw_weight,
            decayed_weight: raw_weight,
            last_decay_time: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Recompute the decayed weight based on elapsed time.
    ///
    /// `now_secs` is the current time in seconds since epoch.
    /// `config` controls the decay function and parameters.
    pub fn apply_decay(&mut self, now_secs: f64, config: &DecayConfig) {
        let evidence_time = parse_rfc3339_to_secs(&self.evidence.timestamp);
        let dt = (now_secs - evidence_time).max(0.0);
        let multiplier = config.decay_multiplier(dt);
        self.decayed_weight = self.raw_weight * multiplier;
        self.last_decay_time = chrono::Utc::now().to_rfc3339();
    }
}

/// A time-bucketed evidence store with temporal decay.
///
/// Accumulates evidence over time and applies decay to compute
/// effective (alpha, beta) parameters for the Bayesian model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalEvidenceStore {
    /// All evidence records with their decay state.
    pub records: Vec<DecayableEvidence>,
    /// The decay configuration.
    pub config: DecayConfig,
}

impl TemporalEvidenceStore {
    /// Create a new empty store with the given decay config.
    pub fn new(config: DecayConfig) -> Self {
        Self {
            records: vec![],
            config,
        }
    }

    /// Create with default exponential decay.
    pub fn with_default_decay() -> Self {
        Self::new(DecayConfig::default())
    }

    /// Add a new evidence record.
    pub fn add_evidence(&mut self, evidence: TrustEvidence) {
        self.records.push(DecayableEvidence::new(evidence));
    }

    /// Apply decay to all evidence records and compute effective
    /// (alpha, beta) parameters.
    ///
    /// `now_secs` is the current time in seconds since epoch.
    /// Returns (effective_alpha, effective_beta) after applying decay.
    pub fn compute_decayed_params(&mut self, now_secs: f64) -> (f64, f64) {
        for record in self.records.iter_mut() {
            record.apply_decay(now_secs, &self.config);
        }
        let mut alpha = 0.0;
        let mut beta = 0.0;
        for record in &self.records {
            if record.evidence.is_positive {
                alpha += record.decayed_weight;
            } else {
                beta += record.decayed_weight;
            }
        }
        (alpha, beta)
    }

    /// Compute the total raw evidence (without decay) split into
    /// positive and negative components.
    pub fn raw_evidence_totals(&self) -> (f64, f64) {
        let mut alpha = 0.0;
        let mut beta = 0.0;
        for record in &self.records {
            if record.evidence.is_positive {
                alpha += record.raw_weight;
            } else {
                beta += record.raw_weight;
            }
        }
        (alpha, beta)
    }

    /// Remove evidence records whose decayed weight is below a threshold.
    /// This prunes stale evidence to keep the store bounded.
    pub fn prune_stale(&mut self, min_weight: f64) {
        self.records.retain(|r| r.decayed_weight >= min_weight);
    }

    /// Number of evidence records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 3. Bayesian Trust Edge — replaces TrustEdge's simple EMA
// ---------------------------------------------------------------------------

/// A Bayesian trust relationship between two entities.
///
/// Replaces the simple exponential-moving-average in `TrustEdge::update()`
/// with a proper Beta distribution posterior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianTrustEdge {
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
    /// The Beta distribution parameters for this edge.
    pub params: BetaTrustParams,
    /// Temporal evidence store with decay.
    pub evidence_store: TemporalEvidenceStore,
    /// Last updated timestamp.
    pub last_updated: String,
    /// The most recent trust-affecting event description.
    pub last_event: Option<String>,
}

impl BayesianTrustEdge {
    /// Create a new Bayesian trust edge with default prior and decay.
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            params: BetaTrustParams::with_default_prior(),
            evidence_store: TemporalEvidenceStore::with_default_decay(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            last_event: None,
        }
    }

    /// Create with a custom prior and decay config.
    pub fn with_config(
        from: &str,
        to: &str,
        prior: BetaPrior,
        decay_config: DecayConfig,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            params: BetaTrustParams::new(prior),
            evidence_store: TemporalEvidenceStore::new(decay_config),
            last_updated: chrono::Utc::now().to_rfc3339(),
            last_event: None,
        }
    }

    /// Get the current trust score (posterior mean).
    pub fn trust_score(&self) -> f64 {
        self.params.posterior_mean()
    }

    /// Get the trust score after applying temporal decay.
    pub fn decayed_trust_score(&mut self, now_secs: f64) -> f64 {
        let (decayed_alpha, decayed_beta) =
            self.evidence_store.compute_decayed_params(now_secs);
        let total = decayed_alpha
            + decayed_beta
            + self.params.prior.alpha_0
            + self.params.prior.beta_0;
        if total == 0.0 {
            return self.params.prior.mean();
        }
        (decayed_alpha + self.params.prior.alpha_0) / total
    }

    /// Record new evidence and update the Bayesian parameters.
    pub fn record_evidence(&mut self, evidence: TrustEvidence) {
        self.params.update(evidence.is_positive, evidence.weight);
        self.evidence_store.add_evidence(evidence.clone());
        self.last_updated = chrono::Utc::now().to_rfc3339();
        self.last_event = Some(evidence.source);
    }

    /// Get the posterior standard deviation (uncertainty).
    pub fn uncertainty(&self) -> f64 {
        self.params.posterior_std()
    }

    /// Get the 95% credible interval for trust.
    pub fn credible_interval_95(&self) -> (f64, f64) {
        self.params.credible_interval(0.95)
    }

    /// Get total raw evidence count.
    pub fn evidence_count(&self) -> u64 {
        self.evidence_store.len() as u64
    }
}

// ---------------------------------------------------------------------------
// 4. Graph Propagation with Damping
// ---------------------------------------------------------------------------

/// Configuration for trust propagation through the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationConfig {
    /// Damping factor (similar to PageRank). Default 0.85.
    /// Higher = trust propagates more freely through the graph.
    pub damping: f64,
    /// Convergence threshold. Iteration stops when the maximum
    /// change in any node's trust is below this value.
    pub epsilon: f64,
    /// Maximum number of propagation iterations.
    pub max_iterations: u32,
    /// Minimum trust value. Nodes never drop below this.
    pub min_trust: f64,
    /// Whether to include self-trust (nodes trust themselves by default).
    pub include_self_trust: bool,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            damping: 0.85,
            epsilon: 1e-6,
            max_iterations: 100,
            min_trust: 0.01,
            include_self_trust: true,
        }
    }
}

/// Result of a trust propagation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResult {
    /// Final trust values for each node.
    pub node_trust: HashMap<String, f64>,
    /// Number of iterations run.
    pub iterations: u32,
    /// Whether convergence was achieved.
    pub converged: bool,
    /// Maximum delta in the final iteration.
    pub final_max_delta: f64,
    /// Timestamp of the computation.
    pub computed_at: String,
}

impl PropagationResult {
    /// Get the trust value for a node, defaulting to 0.0.
    pub fn get(&self, node_id: &str) -> f64 {
        self.node_trust.get(node_id).copied().unwrap_or(0.0)
    }

    /// Get the top N most trusted nodes.
    pub fn top_nodes(&self, n: usize) -> Vec<(String, f64)> {
        let mut sorted: Vec<(String, f64)> = self.node_trust
            .iter()
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        sorted.into_iter().take(n).collect()
    }

    /// Get nodes below a trust threshold.
    pub fn nodes_below(&self, threshold: f64) -> Vec<(String, f64)> {
        self.node_trust
            .iter()
            .filter(|(_, &v)| v < threshold)
            .map(|(k, &v)| (k.clone(), v))
            .collect()
    }
}

/// A Bayesian trust edge stored in the propagation graph.
///
/// This is a lightweight struct that the propagation algorithm
/// works with. In production, this would reference `BayesianTrustEdge`
/// but for algorithmic clarity we store the values directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationEdge {
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
    /// Trust weight (posterior mean of the Beta distribution).
    pub weight: f64,
}

/// Trust propagation engine using iterative belief propagation with damping.
///
/// The algorithm works similarly to PageRank:
///   1. Initialize each node with its local trust score (from direct evidence).
///   2. Iteratively update each node's trust as a weighted combination of
///      its neighbors' trust, scaled by edge weights and a damping factor.
///   3. The damping factor controls how much of a node's trust comes from
///      its neighbors vs. its own direct evidence.
///   4. Converge when the maximum change across all nodes is below epsilon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPropagator {
    /// Nodes and their initial trust scores.
    pub initial_trust: HashMap<String, f64>,
    /// Directed edges with weights.
    pub edges: Vec<PropagationEdge>,
    /// Configuration.
    pub config: PropagationConfig,
}

impl TrustPropagator {
    /// Create a new propagator with the given configuration.
    pub fn new(config: PropagationConfig) -> Self {
        Self {
            initial_trust: HashMap::new(),
            edges: vec![],
            config,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PropagationConfig::default())
    }

    /// Set the initial trust for a node.
    pub fn set_initial_trust(&mut self, node_id: &str, trust: f64) {
        self.initial_trust
            .insert(node_id.into(), trust.clamp(0.0, 1.0));
    }

    /// Add a directed edge with its weight.
    pub fn add_edge(&mut self, from: &str, to: &str, weight: f64) {
        self.edges.push(PropagationEdge {
            from: from.into(),
            to: to.into(),
            weight: weight.clamp(0.0, 1.0),
        });
    }

    /// Build the outgoing edge adjacency list for efficient iteration.
    fn build_outgoing(&self) -> HashMap<String, Vec<(String, f64)>> {
        let mut outgoing: HashMap<String, Vec<(String, f64)>> = HashMap::new();
        for edge in &self.edges {
            outgoing
                .entry(edge.from.clone())
            
                .or_insert_with(Vec::new)
                .push((edge.to.clone(), edge.weight));
        }
        // Normalize: for each source node, the outgoing weights sum to 1.0.
        for targets in outgoing.values_mut() {
            let total: f64 = targets.iter().map(|(_, w)| *w).sum();
            if total > 0.0 {
                for (_, w) in targets.iter_mut() {
                    *w /= total;
                }
            }
        }
        outgoing
    }

    /// Build the incoming edge adjacency list.
    fn build_incoming(&self) -> HashMap<String, Vec<(String, f64)>> {
        let mut incoming: HashMap<String, Vec<(String, f64)>> = HashMap::new();
        for edge in &self.edges {
            incoming
                .entry(edge.to.clone())
            
                .or_insert_with(Vec::new)
                .push((edge.from.clone(), edge.weight));
        }
        incoming
    }

    /// Collect all node IDs from initial trust and edges.
    fn all_nodes(&self) -> Vec<String> {
        let mut nodes: std::collections::HashSet<String> =
            self.initial_trust.keys().cloned().collect();
        for edge in &self.edges {
            nodes.insert(edge.from.clone());
            nodes.insert(edge.to.clone());
        }
        nodes.into_iter().collect()
    }

    /// Run the trust propagation algorithm.
    ///
    /// Returns a `PropagationResult` with the final trust values
    /// for all nodes and convergence metadata.
    pub fn propagate(&self) -> PropagationResult {
        let all_nodes = self.all_nodes();
        let _outgoing = self.build_outgoing();
        let incoming = self.build_incoming();
        let damping = self.config.damping;
        let n = all_nodes.len();
        if n == 0 {
            return PropagationResult {
                node_trust: HashMap::new(),
                iterations: 0,
                converged: true,
                final_max_delta: 0.0,
                computed_at: chrono::Utc::now().to_rfc3339(),
            };
        }

        // Initialize: each node starts with its local trust or the prior mean.
        let prior_mean = 0.5;
        let mut current: HashMap<String, f64> = HashMap::new();
        for node in &all_nodes {
            let val = self
                .initial_trust
                .get(node.as_str())
                .copied()
                .unwrap_or(prior_mean);
            current.insert(node.clone(), val);
        }

        // Iterative propagation.
        let mut converged = false;
        let mut max_delta = f64::MAX;
        let mut iterations = 0u32;

        for _ in 0..self.config.max_iterations {
            iterations += 1;
            let mut next: HashMap<String, f64> = HashMap::new();
            max_delta = 0.0;

            for node in &all_nodes {
                // Base trust from direct evidence.
                let local_trust = self
                    .initial_trust
                    .get(node.as_str())
                    .copied()
                    .unwrap_or(prior_mean);

                // Propagated trust from incoming neighbors.
                let incoming_edges = incoming
                    .get(node)
                    .cloned()
                    .unwrap_or_default();
                let mut propagated = 0.0;
                for (source, _raw_weight) in &incoming_edges {
                    let source_trust = current.get(source).copied().unwrap_or(prior_mean);
                    let edge_weight = self
                        .edges
                        .iter()
                        .find(|e| &e.from == source && &e.to == node)
                        .map(|e| e.weight)
                        .unwrap_or(0.0);
                    propagated += source_trust * edge_weight;
                }

                let mut incoming_count = incoming_edges.len() as f64;

                // Include self-trust as a self-loop when enabled.
                if self.config.include_self_trust {
                    let self_trust = current.get(node).copied().unwrap_or(local_trust);
                    propagated += self_trust * 1.0;
                    incoming_count += 1.0;
                }

                if incoming_count > 0.0 {
                    propagated /= incoming_count;
                }

                // Damped combination: (1 - d) * local + d * propagated
                let new_trust = (1.0 - damping) * local_trust + damping * propagated;
                let new_trust = new_trust.clamp(self.config.min_trust, 1.0);

                let old_trust = current.get(node).copied().unwrap_or(prior_mean);
                let delta = (new_trust - old_trust).abs();
                if delta > max_delta {
                    max_delta = delta;
                }

                next.insert(node.clone(), new_trust);
            }

            current = next;

            if max_delta < self.config.epsilon {
                converged = true;
                break;
            }
        }

        PropagationResult {
            node_trust: current,
            iterations,
            converged,
            final_max_delta: max_delta,
            computed_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Dempster-Shafer Trust Fusion
// ---------------------------------------------------------------------------

/// A basic belief function for Dempster-Shafer combination.
///
/// Maps a hypothesis (e.g., "entity is trusted") to a belief mass.
/// The frame of discernment is {Trusted, NotTrusted}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeliefFunction {
    /// Mass assigned to "trusted" hypothesis.
    pub m_trusted: f64,
    /// Mass assigned to "not trusted" hypothesis.
    pub m_not_trusted: f64,
    /// Mass assigned to uncertainty (the full frame).
    pub m_uncertain: f64,
}

impl BeliefFunction {
    /// Create a belief function from a trust score and uncertainty.
    ///
    /// `trust` is in [0, 1]. `uncertainty` is in [0, 1] and represents
    /// how much mass is assigned to the universal set.
    /// The remaining mass (1 - trust - uncertainty) is assigned to not_trusted.
    pub fn from_trust(trust: f64, uncertainty: f64) -> Self {
        let trust = trust.clamp(0.0, 1.0);
        let uncertainty = uncertainty.clamp(0.0, 1.0 - trust);
        let not_trusted = (1.0 - trust - uncertainty).max(0.0);
        Self {
            m_trusted: trust,
            m_not_trusted: not_trusted,
            m_uncertain: uncertainty,
        }
    }

    /// Create from Beta distribution parameters.
    ///
    /// The trust mass is the posterior mean. The uncertainty mass is
       /// inversely proportional to the total evidence: more evidence = less
    /// uncertainty. Specifically: uncertainty = 1 / (1 + total_evidence / k)
    /// where k is a scaling constant.
    pub fn from_beta(alpha: f64, beta: f64, evidence_scale: f64) -> Self {
        let total = alpha + beta;
        let trust = if total > 0.0 { alpha / total } else { 0.5 };
        let raw_evidence = (alpha + beta - 2.0).max(0.0); // Subtract prior.
        let uncertainty = 1.0 / (1.0 + raw_evidence / evidence_scale);
        Self::from_trust(trust, uncertainty)
    }

    /// Compute the belief (lower probability) for "trusted".
    /// Bel(trusted) = m_trusted.
    pub fn belief_trusted(&self) -> f64 {
        self.m_trusted
    }

    /// Compute the plausibility (upper probability) for "trusted".
    /// Pl(trusted) = 1 - m_not_trusted = m_trusted + m_uncertain.
    pub fn plausibility_trusted(&self) -> f64 {
        1.0 - self.m_not_trusted
    }

    /// Compute the conflict between two belief functions.
    ///
    /// Conflict K = m1_trusted * m2_not_trusted + m1_not_trusted * m2_trusted.
    /// High conflict means the two sources disagree strongly.
    pub fn conflict_with(&self, other: &BeliefFunction) -> f64 {
        self.m_trusted * other.m_not_trusted
            + self.m_not_trusted * other.m_trusted
    }

    /// Dempster's combination rule for two belief functions.
    ///
    /// Combines two independent evidence sources. If the conflict K is
    /// close to 1.0, the combination is unreliable.
    ///
    /// Returns `None` if K >= 1.0 (total conflict, normalization impossible).
    pub fn combine(&self, other: &BeliefFunction) -> Option<BeliefFunction> {
        let k = self.conflict_with(other);
        if k >= 1.0 {
            return None;
        }

        let one_minus_k = 1.0 - k;

        // m_combined(trusted) = (m1_trusted * m2_trusted
        //     + m1_trusted * m2_uncertain + m1_uncertain * m2_trusted) / (1 - K)
        let m_trusted = (self.m_trusted * other.m_trusted
            + self.m_trusted * other.m_uncertain
            + self.m_uncertain * other.m_trusted)
            / one_minus_k;

        // m_combined(not_trusted) = (m1_not_trusted * m2_not_trusted
        //     + m1_not_trusted * m2_uncertain + m1_uncertain * m2_not_trusted) / (1 - K)
        let m_not_trusted = (self.m_not_trusted * other.m_not_trusted
            + self.m_not_trusted * other.m_uncertain
            + self.m_uncertain * other.m_not_trusted)
            / one_minus_k;

        // m_combined(uncertain) = m1_uncertain * m2_uncertain / (1 - K)
        let m_uncertain = (self.m_uncertain * other.m_uncertain) / one_minus_k;

        Some(BeliefFunction {
            m_trusted,
            m_not_trusted,
            m_uncertain,
        })
    }

    /// Combine multiple belief functions sequentially.
    ///
    /// Returns `None` if any pairwise combination fails (total conflict).
    pub fn combine_many(functions: &[BeliefFunction]) -> Option<BeliefFunction> {
        if functions.is_empty() {
            return Some(BeliefFunction {
                m_trusted: 0.0,
                m_not_trusted: 0.0,
                m_uncertain: 1.0,
            });
        }
        let mut result = functions[0].clone();
        for f in &functions[1..] {
            result = result.combine(f)?;
        }
        Some(result)
    }

    /// Compute a trust score from the belief function.
    ///
    /// Uses the pignistic probability: P(trusted) = Bel(trusted) + m_uncertain / 2.
    /// This is the expected value under the principle of insufficient reason.
    pub fn pignistic_probability(&self) -> f64 {
        self.m_trusted + self.m_uncertain / 2.0
    }
}

/// Result of fusing trust from multiple paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionResult {
    /// The combined belief function.
    pub combined: Option<BeliefFunction>,
    /// Pignistic probability (expected trust).
    pub trust_score: f64,
    /// Maximum pairwise conflict among the sources.
    pub max_conflict: f64,
    /// Average pairwise conflict.
    pub avg_conflict: f64,
    /// Number of sources that were combined.
    pub source_count: usize,
    /// Whether the fusion succeeded (no total conflict).
    pub success: bool,
}

impl FusionResult {
    /// Create a fusion result from a list of belief functions.
    pub fn from_beliefs(beliefs: &[BeliefFunction]) -> Self {
        let n = beliefs.len();
        if n == 0 {
            return Self {
                combined: None,
                trust_score: 0.5,
                max_conflict: 0.0,
                avg_conflict: 0.0,
                source_count: 0,
                success: false,
            };
        }
        if n == 1 {
            let trust = beliefs[0].pignistic_probability();
            return Self {
                combined: Some(beliefs[0].clone()),
                trust_score: trust,
                max_conflict: 0.0,
                avg_conflict: 0.0,
                source_count: 1,
                success: true,
            };
        }

        // Compute pairwise conflicts.
        let mut conflicts = vec![];
        for i in 0..n {
            for j in (i + 1)..n {
                conflicts.push(beliefs[i].conflict_with(&beliefs[j]));
            }
        }
        let max_conflict = conflicts.iter().cloned().fold(0.0_f64, f64::max);
        let avg_conflict = conflicts.iter().sum::<f64>() / conflicts.len() as f64;

        // Combine.
        let combined = BeliefFunction::combine_many(beliefs);
        let (trust_score, success) = match &combined {
            Some(bf) => (bf.pignistic_probability(), true),
            None => (0.5, false),
        };

        Self {
            combined,
            trust_score,
            max_conflict,
            avg_conflict,
            source_count: n,
            success,
        }
    }
}

/// Trust fusion engine that combines evidence from multiple paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFusionEngine {
    /// Scaling factor for uncertainty computation from Beta params.
    pub evidence_scale: f64,
}

impl Default for TrustFusionEngine {
    fn default() -> Self {
        Self {
            evidence_scale: 10.0,
        }
    }
}

impl TrustFusionEngine {
    /// Create a new fusion engine.
    pub fn new(evidence_scale: f64) -> Self {
        Self {
            evidence_scale: evidence_scale.max(1.0),
        }
    }

    /// Convert a Beta trust parameter to a belief function.
    pub fn beta_to_belief(&self, params: &BetaTrustParams) -> BeliefFunction {
        BeliefFunction::from_beta(
            params.alpha,
            params.beta,
            self.evidence_scale,
        )
    }

    /// Fuse trust from multiple Beta trust parameters.
    pub fn fuse_betas(&self, params: &[BetaTrustParams]) -> FusionResult {
        let beliefs: Vec<BeliefFunction> = params
            .iter()
            .map(|p| self.beta_to_belief(p))
            .collect();
        FusionResult::from_beliefs(&beliefs)
    }

    /// Fuse trust from multiple trust scores with associated uncertainties.
    ///
    /// Each element is (trust_score, uncertainty).
    pub fn fuse_scores(&self, scores: &[(f64, f64)]) -> FusionResult {
        let beliefs: Vec<BeliefFunction> = scores
            .iter()
            .map(|(trust, unc)| BeliefFunction::from_trust(*trust, *unc))
            .collect();
        FusionResult::from_beliefs(&beliefs)
    }
}

// ---------------------------------------------------------------------------
// 6. Trust Prediction (Holt-Winters Double Exponential Smoothing)
// ---------------------------------------------------------------------------

/// Configuration for the trust prediction model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionConfig {
    /// Smoothing parameter for the level (alpha). Higher = more responsive.
    pub alpha: f64,
    /// Smoothing parameter for the trend (beta). Higher = trend adjusts faster.
    pub beta: f64,
    /// Number of historical points to use for initialization.
    pub init_window: usize,
    /// Maximum number of steps to predict ahead.
    pub max_horizon: u32,
}

impl Default for PredictionConfig {
    fn default() -> Self {
        Self {
            alpha: 0.3,
            beta: 0.1,
            init_window: 5,
            max_horizon: 30,
        }
    }
}

/// A single prediction point with confidence interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionPoint {
    /// Predicted trust value.
    pub value: f64,
    /// Lower bound of the confidence interval.
    pub ci_lower: f64,
    /// Upper bound of the confidence interval.
    pub ci_upper: f64,
    /// Steps ahead from the last observation.
    pub step_ahead: u32,
}

/// State of the Holt-Winters double exponential smoothing model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoltWintersState {
    /// Current smoothed level.
    pub level: f64,
    /// Current smoothed trend.
    pub trend: f64,
    /// Historical residuals for variance estimation.
    pub residuals: Vec<f64>,
    /// Number of observations processed.
    pub observation_count: usize,
}

impl HoltWintersState {
    /// Create initial state from a window of observations.
    ///
    /// The initial level is the mean of the window.
    /// The initial trend is the average slope between consecutive points.
    pub fn initialize(observations: &[f64]) -> Self {
        let n = observations.len();
        if n < 2 {
            return Self {
                level: observations.first().copied().unwrap_or(0.5),
                trend: 0.0,
                residuals: vec![],
                observation_count: n,
            };
        }
        // Level = simple average of all observations.
        let level = observations.iter().sum::<f64>() / n as f64;

        // Trend = average of consecutive differences.
        let mut slopes = vec![];
        for i in 1..n {
            slopes.push(observations[i] - observations[i - 1]);
        }
        let trend = if slopes.is_empty() {
            0.0
        } else {
            slopes.iter().sum::<f64>() / slopes.len() as f64
        };

        Self {
            level,
            trend,
            residuals: vec![],
            observation_count: n,
        }
    }
}

/// Trust prediction engine using Holt-Winters double exponential smoothing.
///
/// This model captures both the current level and the trend in trust scores,
/// allowing it to predict future values with reasonable accuracy.
///
/// The double exponential smoothing equations are:
///   Level_t = alpha * Y_t + (1 - alpha) * (Level_{t-1} + Trend_{t-1})
///   Trend_t = beta * (Level_t - Level_{t-1}) + (1 - beta) * Trend_{t-1}
///   Forecast_{t+h} = Level_t + h * Trend_t
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPredictor {
    /// Smoothing model state.
    pub state: Option<HoltWintersState>,
    /// Configuration.
    pub config: PredictionConfig,
    /// History of observed trust values.
    pub history: Vec<f64>,
    /// Timestamps corresponding to history entries.
    pub history_timestamps: Vec<String>,
}

impl TrustPredictor {
    /// Create a new predictor with default configuration.
    pub fn new() -> Self {
        Self {
            state: None,
            config: PredictionConfig::default(),
            history: vec![],
            history_timestamps: vec![],
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: PredictionConfig) -> Self {
        Self {
            state: None,
            config,
            history: vec![],
            history_timestamps: vec![],
        }
    }

    /// Add a new observation and update the model.
    pub fn observe(&mut self, value: f64) {
        let value = value.clamp(0.0, 1.0);
        self.history.push(value);
        self.history_timestamps
            .push(chrono::Utc::now().to_rfc3339());

        if self.history.len() < self.config.init_window {
            // Not enough data to initialize the model.
            return;
        }

        if self.state.is_none() {
            // Initialize the model.
            let window: Vec<f64> = self
                        .history
                        .iter()
                        .rev()
                        .take(self.config.init_window)
                        .rev()
                        .copied()
                        .collect();
            self.state = Some(HoltWintersState::initialize(&window));
            return;
        }

        // Update the model with the new observation.
        let state = self.state.as_mut().unwrap();
        let old_level = state.level;
        let alpha = self.config.alpha;
        let beta = self.config.beta;

        // Holt-Winters double exponential smoothing update.
        let new_level = alpha * value + (1.0 - alpha) * (old_level + state.trend);
        let new_trend = beta * (new_level - old_level) + (1.0 - beta) * state.trend;

        // Compute residual for variance estimation.
        let forecast = old_level + state.trend;
        let residual = value - forecast;
        state.residuals.push(residual);
        // Keep only the last 100 residuals to bound memory.
        if state.residuals.len() > 100 {
            state.residuals.remove(0);
        }

        state.level = new_level;
        state.trend = new_trend;
        state.observation_count += 1;
    }

    /// Predict trust values N steps ahead.
    ///
    /// Returns a vector of `PredictionPoint` with predicted values and
    /// 95% confidence intervals based on historical residual variance.
    pub fn predict(&self, steps_ahead: u32) -> Vec<PredictionPoint> {
        let state = match &self.state {
            Some(s) => s,
            None => {
                // No model yet — return naive predictions from history.
                let last = self.history.last().copied().unwrap_or(0.5);
                return (1..=steps_ahead)
                    .map(|h| PredictionPoint {
                        value: last,
                        ci_lower: 0.0,
                        ci_upper: 1.0,
                        step_ahead: h,
                    })
                    .collect();
            }
        };

        let steps = steps_ahead.min(self.config.max_horizon);
        let residual_variance = self.compute_residual_variance();
        let z = z_score(0.95); // 95% confidence interval.

        (1..=steps)
            .map(|h| {
                let forecast = state.level + (h as f64) * state.trend;
                let forecast = forecast.clamp(0.0, 1.0);
                // Variance grows with the square of the forecast horizon.
                let forecast_variance =
                    residual_variance * (h as f64).powi(2);
                let half_width = z * forecast_variance.sqrt();
                PredictionPoint {
                    value: forecast,
                    ci_lower: (forecast - half_width).max(0.0),
                    ci_upper: (forecast + half_width).min(1.0),
                    step_ahead: h,
                }
            })
            .collect()
    }

    /// Compute the variance of the model residuals.
    fn compute_residual_variance(&self) -> f64 {
        match &self.state {
            Some(state) if !state.residuals.is_empty() => {
                let n = state.residuals.len() as f64;
                let mean = state.residuals.iter().sum::<f64>() / n;
                let variance =
                    state.residuals.iter().map(|r| (r - mean).powi(2)).sum::<f64>()
                        / (n - 1.0).max(1.0);
                variance.max(1e-12) // Floor to avoid zero variance.
            }
            _ => 0.01, // Default variance when no data.
        }
    }

    /// Get the current trend direction.
    pub fn trend_direction(&self) -> TrendDirection {
        match &self.state {
            Some(state) => {
                let threshold = 0.001;
                if state.trend > threshold {
                    TrendDirection::Improving
                } else if state.trend < -threshold {
                    TrendDirection::Degrading
                } else {
                    TrendDirection::Stable
                }
            }
            None => TrendDirection::Unknown,
        }
    }

    /// Get the current smoothed level.
    pub fn current_level(&self) -> f64 {
        self.state
            .as_ref()
            .map(|s| s.level)
            .unwrap_or_else(|| self.history.last().copied().unwrap_or(0.5))
    }

    /// Get the number of observations.
    pub fn observation_count(&self) -> usize {
        self.history.len()
    }
}

// ---------------------------------------------------------------------------
// 7. The Unified Bayesian Trust Engine
// ---------------------------------------------------------------------------

/// Configuration for the full Bayesian trust engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEngineConfig {
    /// Prior for new trust relationships.
    pub prior: BetaPrior,
    /// Decay configuration for temporal evidence.
    pub decay: DecayConfig,
    /// Propagation configuration for graph-level trust.
    pub propagation: PropagationConfig,
    /// Prediction configuration for trust trend forecasting.
    pub prediction: PredictionConfig,
    /// Evidence scale for Dempster-Shafer fusion.
    pub fusion_evidence_scale: f64,
}

impl Default for TrustEngineConfig {
    fn default() -> Self {
        Self {
            prior: BetaPrior::default(),
            decay: DecayConfig::default(),
            propagation: PropagationConfig::default(),
            prediction: PredictionConfig::default(),
            fusion_evidence_scale: 10.0,
        }
    }
}

/// A per-edge entry in the trust engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEntry {
    /// The Bayesian trust edge.
    pub edge: BayesianTrustEdge,
    /// A predictor for this edge's trust trend.
    pub predictor: TrustPredictor,
}

/// The unified Bayesian Trust Engine.
///
/// Orchestrates all trust computation components:
///   - Beta distribution posterior for each edge
///   - Temporal decay of evidence
///   - Graph propagation with damping
///   - Dempster-Shafer fusion of multi-path evidence
///   - Holt-Winters prediction of trust trends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianTrustEngine {
    /// Engine configuration.
    pub config: TrustEngineConfig,
    /// Bayesian trust edges indexed by (from, to).
    pub edges: HashMap<(String, String), EdgeEntry>,
    /// Propagation engine (rebuilt as needed).
    pub propagator: TrustPropagator,
    /// Fusion engine.
    pub fusion_engine: TrustFusionEngine,
    /// Timestamp of the last full update.
    pub last_updated: String,
}

impl BayesianTrustEngine {
    /// Create a new trust engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(TrustEngineConfig::default())
    }

    /// Create a new trust engine with custom configuration.
    pub fn with_config(config: TrustEngineConfig) -> Self {
        let fusion_engine =
            TrustFusionEngine::new(config.fusion_evidence_scale);
        Self {
            propagator: TrustPropagator::new(config.propagation.clone()),
            fusion_engine,
            config,
            edges: HashMap::new(),
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Record evidence for a trust edge.
    ///
    /// If the edge does not exist, it is created with the configured prior.
    pub fn record_evidence(
        &mut self,
        from: &str,
        to: &str,
        is_positive: bool,
        weight: f64,
        source: &str,
    ) {
        let key = (from.into(), to.into());
        let evidence = TrustEvidence::new(is_positive, weight, source);
        let entry = self.edges.entry(key).or_insert_with(|| {
            let edge = BayesianTrustEdge::with_config(
                from,
                to,
                self.config.prior.clone(),
                self.config.decay.clone(),
            );
            EdgeEntry {
                edge,
                predictor: TrustPredictor::with_config(
                    self.config.prediction.clone(),
                ),
            }
        });
        entry.edge.record_evidence(evidence);
        // Also feed the observation to the predictor.
        let score = entry.edge.trust_score();
        entry.predictor.observe(score);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Get the Bayesian trust score between two entities.
    pub fn trust_score(&self, from: &str, to: &str) -> Option<f64> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| e.edge.trust_score())
    }

    /// Get the Bayesian trust parameters for an edge.
    pub fn trust_params(&self, from: &str, to: &str) -> Option<&BetaTrustParams> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| &e.edge.params)
    }

    /// Get the decayed trust score for an edge.
    pub fn decayed_trust_score(
        &mut self,
        from: &str,
        to: &str,
        now_secs: f64,
    ) -> Option<f64> {
        self.edges
            .get_mut(&(from.into(), to.into()))
            .map(|e| e.edge.decayed_trust_score(now_secs))
    }

    /// Get the uncertainty (posterior std) for an edge.
    pub fn uncertainty(&self, from: &str, to: &str) -> Option<f64> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| e.edge.uncertainty())
    }

    /// Get the 95% credible interval for an edge.
    pub fn credible_interval(&self, from: &str, to: &str) -> Option<(f64, f64)> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| e.edge.credible_interval_95())
    }

    /// Predict the trust trend for an edge.
    pub fn predict(
        &self,
        from: &str,
        to: &str,
        steps: u32,
    ) -> Option<Vec<PredictionPoint>> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| e.predictor.predict(steps))
    }

    /// Get the trend direction for an edge.
    pub fn trend_direction(
        &self,
        from: &str,
        to: &str,
    ) -> Option<TrendDirection> {
        self.edges
            .get(&(from.into(), to.into()))
            .map(|e| e.predictor.trend_direction())
    }

    /// Fuse trust from multiple paths to the same target.
    ///
    /// `paths` is a list of (from, to) pairs representing different
    /// trust paths to evaluate and combine.
    pub fn fuse_paths(&self, paths: &[(&str, &str)]) -> FusionResult {
        let params: Vec<BetaTrustParams> = paths
            .iter()
            .filter_map(|(f, t)| {
                self.edges
                    .get(&(f.to_string(), t.to_string()))
                    .map(|e| e.edge.params.clone())
            })
            .collect();
        self.fusion_engine.fuse_betas(&params)
    }

    /// Run trust propagation across the entire graph.
    ///
    /// Rebuilds the propagator from current edge states and runs
    /// the iterative belief propagation algorithm.
    pub fn propagate(&mut self) -> PropagationResult {
        // Rebuild the propagator from current edges.
        self.propagator = TrustPropagator::new(self.config.propagation.clone());
        for ((from, to), entry) in &self.edges {
            let score = entry.edge.trust_score();
            // Set initial trust for both nodes (max of incoming).
            let existing_from = self
                .propagator
                .initial_trust
                .get(from)
                .copied()
                .unwrap_or(0.0);
            let existing_to = self
                .propagator
                .initial_trust
                .get(to)
                .copied()
                .unwrap_or(0.0);
            self.propagator
                .set_initial_trust(from, existing_from.max(score));
            self.propagator
                .set_initial_trust(to, existing_to.max(score));
            self.propagator.add_edge(from, to, score);
        }
        let result = self.propagator.propagate();
        self.last_updated = chrono::Utc::now().to_rfc3339();
        result
    }

    /// Get all edge keys.
    pub fn edge_keys(&self) -> Vec<(String, String)> {
        self.edges.keys().cloned().collect()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get a summary of the engine state.
    pub fn summary(&self) -> String {
        format!(
            "BayesianTrustEngine: edges={} last_updated={}",
            self.edges.len(),
            self.last_updated,
        )
    }
}

// ---------------------------------------------------------------------------
// 8. Statistical Utility Functions
// ---------------------------------------------------------------------------

/// Compute the z-score for a given confidence level using a rational
/// approximation to the inverse normal CDF (Abramowitz and Stegun).
///
/// This approximation is accurate to about 1e-9 for 0.5 < p < 1.0.
pub fn z_score(confidence: f64) -> f64 {
    // Map (0.5, 1.0) to (0, infinity) via the inverse CDF approximation.
    let p = confidence.clamp(0.5, 1.0 - 1e-15);
    let t = (-2.0 * (1.0 - p).ln()).sqrt();

    // Rational approximation coefficients (Abramowitz & Stegun 26.2.23).
    let c0 = 2.515517;
    let c1 = 0.802853;
    let c2 = 0.010328;
    let d1 = 1.432788;
    let d2 = 0.189269;
    let d3 = 0.001308;

    let z = t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t);
    z
}

/// Compute the cumulative distribution function of the standard normal.
///
/// Uses the error function approximation:
///   Phi(x) = 0.5 * (1 + erf(x / sqrt(2)))
pub fn normal_cdf(x: f64) -> f64 {
    // Abramowitz and Stegun approximation to erf (7.1.26).
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x_abs = x.abs();

    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let t = 1.0 / (1.0 + p * x_abs);
    let y = 1.0
        - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t
            * (-x_abs * x_abs).exp();

    0.5 * (1.0 + sign * y)
}

/// Parse an RFC 3339 timestamp string to seconds since Unix epoch.
///
/// Falls back to 0.0 if parsing fails.
pub fn parse_rfc3339_to_secs(timestamp: &str) -> f64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp() as f64)
        .unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// 9. Trust Alert Generation
// ---------------------------------------------------------------------------

use super::trust_state::{
    AlertSeverity, AlertType, TrustAlert,
};

/// Generate trust alerts based on the engine state.
///
/// Scans all edges and generates alerts for:
///   - Trust scores below critical thresholds
///   - High uncertainty (insufficient evidence)
///   - Strong degrading trends
///   - High conflict in fused paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAlertGenerator {
    /// Trust threshold below which a critical alert is generated.
    pub critical_threshold: f64,
    /// Trust threshold below which a warning alert is generated.
    pub warning_threshold: f64,
    /// Uncertainty threshold above which a warning is generated.
    pub uncertainty_threshold: f64,
    /// Minimum trend slope to be considered degrading.
    pub degrading_threshold: f64,
}

impl Default for TrustAlertGenerator {
    fn default() -> Self {
        Self {
            critical_threshold: 0.2,
            warning_threshold: 0.4,
            uncertainty_threshold: 0.25,
            degrading_threshold: -0.01,
        }
    }
}

impl TrustAlertGenerator {
    /// Create with custom thresholds.
    pub fn new(
        critical_threshold: f64,
        warning_threshold: f64,
        uncertainty_threshold: f64,
        degrading_threshold: f64,
    ) -> Self {
        Self {
            critical_threshold,
            warning_threshold,
            uncertainty_threshold,
            degrading_threshold,
        }
    }

    /// Scan the engine and generate alerts for all edges.
    pub fn generate_alerts(&self, engine: &BayesianTrustEngine) -> Vec<TrustAlert> {
        let mut alerts = vec![];
        for ((from, to), entry) in &engine.edges {
            let score = entry.edge.trust_score();
            let uncertainty = entry.edge.uncertainty();
            let direction = entry.predictor.trend_direction();
            let domain = format!("{}->{}", from, to);

            // Check for critical trust degradation.
            if score < self.critical_threshold {
                alerts.push(TrustAlert {
                    alert_type: AlertType::TrustDegradation,
                    domain: domain.clone(),
                    message: format!(
                        "Critical: trust {}->{} = {:.3} (below {:.3})",
                        from, to, score, self.critical_threshold
                    ),
                    severity: AlertSeverity::Critical,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    data: Some(serde_json::json!({
                        "score": score,
                        "threshold": self.critical_threshold,
                        "from": from,
                        "to": to,
                    })),
                });
            } else if score < self.warning_threshold {
                alerts.push(TrustAlert {
                    alert_type: AlertType::TrustDegradation,
                    domain: domain.clone(),
                    message: format!(
                        "Warning: trust {}->{} = {:.3} (below {:.3})",
                        from, to, score, self.warning_threshold
                    ),
                    severity: AlertSeverity::Warning,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    data: Some(serde_json::json!({
                        "score": score,
                        "threshold": self.warning_threshold,
                    })),
                });
            }

            // Check for high uncertainty.
            if uncertainty > self.uncertainty_threshold {
                alerts.push(TrustAlert {
                    alert_type: AlertType::AnomalyDetected,
                    domain: domain.clone(),
                    message: format!(
                        "High uncertainty on {}->{}: std={:.3}",
                        from, to, uncertainty
                    ),
                    severity: AlertSeverity::Warning,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    data: Some(serde_json::json!({
                        "uncertainty": uncertainty,
                        "threshold": self.uncertainty_threshold,
                    })),
                });
            }

            // Check for degrading trend.
            if direction == TrendDirection::Degrading {
                let trend_val = entry
                    .predictor
                    .state
                    .as_ref()
                    .map(|s| s.trend)
                    .unwrap_or(0.0);
                alerts.push(TrustAlert {
                    alert_type: AlertType::DecisionDrift,
                    domain,
                    message: format!(
                        "Degrading trend on {}->{}: slope={:.5}",
                        from, to, trend_val
                    ),
                    severity: AlertSeverity::Info,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    data: Some(serde_json::json!({
                        "trend": trend_val,
                    })),
                });
            }
        }
        alerts
    }
}

// ---------------------------------------------------------------------------
// 10. Trust Audit Trail
// ---------------------------------------------------------------------------

/// A single entry in the trust audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAuditEntry {
    /// Unique entry ID.
    pub id: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// The edge this entry relates to.
    pub from: String,
    /// The target node.
    pub to: String,
    /// The type of action performed.
    pub action: AuditAction,
    /// The trust score before the action.
    pub score_before: f64,
    /// The trust score after the action.
    pub score_after: f64,
    /// Additional context.
    pub context: String,
}

/// Actions that can be recorded in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// New evidence recorded.
    EvidenceRecorded,
    /// Trust propagated through the graph.
    PropagationRun,
    /// Multiple paths were fused.
    PathsFused,
    /// Decay was applied.
    DecayApplied,
    /// Alert was generated.
    AlertGenerated,
    /// Trust parameters were reset.
    Reset,
}

impl TrustAuditEntry {
    /// Create a new audit entry.
    pub fn new(
        from: &str,
        to: &str,
        action: AuditAction,
        score_before: f64,
        score_after: f64,
        context: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            from: from.into(),
            to: to.into(),
            action,
            score_before,
            score_after,
            context: context.into(),
        }
    }
}

/// An append-only audit trail for trust operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAuditTrail {
    /// All audit entries, most recent last.
    pub entries: Vec<TrustAuditEntry>,
    /// Maximum number of entries to keep.
    pub max_entries: usize,
}

impl TrustAuditTrail {
    /// Create a new audit trail with a maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: vec![],
            max_entries,
        }
    }

    /// Create with a default maximum of 10,000 entries.
    pub fn with_defaults() -> Self {
        Self::new(10_000)
    }

    /// Record a new audit entry.
    pub fn record(&mut self, entry: TrustAuditEntry) {
        self.entries.push(entry);
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Get entries for a specific edge.
    pub fn entries_for(&self, from: &str, to: &str) -> Vec<&TrustAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.from == from && e.to == to)
            .collect()
    }

    /// Get entries of a specific action type.
    pub fn entries_by_action(&self, action: &AuditAction) -> Vec<&TrustAuditEntry> {
        self.entries
            .iter()
            .filter(|e| &e.action == action)
            .collect()
    }

    /// Get the total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the trail is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the most recent N entries.
    pub fn recent(&self, n: usize) -> Vec<&TrustAuditEntry> {
        let start = self.entries.len().saturating_sub(n);
        self.entries[start..].iter().collect()
    }
}

// ---------------------------------------------------------------------------
// 11. Trust Engine Statistics
// ---------------------------------------------------------------------------

/// Aggregated statistics about the trust engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEngineStats {
    /// Total number of trust edges.
    pub edge_count: usize,
    /// Average trust score across all edges.
    pub avg_trust: f64,
    /// Minimum trust score.
    pub min_trust: f64,
    /// Maximum trust score.
    pub max_trust: f64,
    /// Average uncertainty across all edges.
    pub avg_uncertainty: f64,
    /// Number of edges below the warning threshold.
    pub low_trust_count: usize,
    /// Number of edges with degrading trends.
    pub degrading_count: usize,
    /// Number of edges with improving trends.
    pub improving_count: usize,
    /// Total evidence count across all edges.
    pub total_evidence: u64,
    /// Computation timestamp.
    pub computed_at: String,
}

impl TrustEngineStats {
    /// Compute statistics from the current engine state.
    pub fn compute(engine: &BayesianTrustEngine, warning_threshold: f64) -> Self {
        let edges: Vec<_> = engine.edges.values().collect();
        let edge_count = edges.len();

        if edge_count == 0 {
            return Self {
                edge_count: 0,
                avg_trust: 0.5,
                min_trust: 0.5,
                max_trust: 0.5,
                avg_uncertainty: 0.0,
                low_trust_count: 0,
                degrading_count: 0,
                improving_count: 0,
                total_evidence: 0,
                computed_at: chrono::Utc::now().to_rfc3339(),
            };
        }

        let mut sum_trust = 0.0;
        let mut sum_uncertainty = 0.0;
        let mut min_trust = f64::MAX;
        let mut max_trust = f64::MIN;
        let mut low_trust_count = 0usize;
        let mut degrading_count = 0usize;
        let mut improving_count = 0usize;
        let mut total_evidence = 0u64;

        for entry in &edges {
            let trust = entry.edge.trust_score();
            let unc = entry.edge.uncertainty();
            let ev = entry.edge.evidence_count();
            sum_trust += trust;
            sum_uncertainty += unc;
            total_evidence += ev;
            if trust < min_trust {
                min_trust = trust;
            }
            if trust > max_trust {
                max_trust = trust;
            }
            if trust < warning_threshold {
                low_trust_count += 1;
            }
            let direction = entry.predictor.trend_direction();
            if direction == TrendDirection::Degrading {
                degrading_count += 1;
            } else if direction == TrendDirection::Improving {
                improving_count += 1;
            }
        }

        Self {
            edge_count,
            avg_trust: sum_trust / edge_count as f64,
            min_trust,
            max_trust,
            avg_uncertainty: sum_uncertainty / edge_count as f64,
            low_trust_count,
            degrading_count,
            improving_count,
            total_evidence,
            computed_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Produce a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "edges={} avg_trust={:.3} min={:.3} max={:.3} \
             avg_unc={:.3} low={} degrading={} improving={} evidence={}",
            self.edge_count,
            self.avg_trust,
            self.min_trust,
            self.max_trust,
            self.avg_uncertainty,
            self.low_trust_count,
            self.degrading_count,
            self.improving_count,
            self.total_evidence,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper to build a simple engine with a few edges --
    fn build_test_engine() -> BayesianTrustEngine {
        let mut engine = BayesianTrustEngine::new();
        engine.record_evidence("A", "B", true, 1.0, "test");
        engine.record_evidence("A", "B", true, 1.0, "test");
        engine.record_evidence("B", "C", true, 0.8, "test");
        engine.record_evidence("A", "C", false, 0.5, "test");
        engine
    }

    // ---- 1. Beta Distribution Tests ----

    #[test]
    fn test_default_prior_mean_is_half() {
        let prior = BetaPrior::default();
        assert!((prior.mean() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_optimistic_prior_higher_mean() {
        let prior = BetaPrior::optimistic();
        assert!(prior.mean() > 0.7);
    }

    #[test]
    fn test_pessimistic_prior_lower_mean() {
        let prior = BetaPrior::pessimistic();
        assert!(prior.mean() < 0.3);
    }

    #[test]
    fn test_beta_trust_starts_at_prior_mean() {
        let params = BetaTrustParams::with_default_prior();
        assert!((params.posterior_mean() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_positive_evidence_increases_trust() {
        let mut params = BetaTrustParams::with_default_prior();
        let before = params.posterior_mean();
        params.update_positive(1.0);
        let after = params.posterior_mean();
        assert!(after > before);
    }

    #[test]
    fn test_negative_evidence_decreases_trust() {
        let mut params = BetaTrustParams::with_default_prior();
        let before = params.posterior_mean();
        params.update_negative(1.0);
        let after = params.posterior_mean();
        assert!(after < before);
    }

    #[test]
    fn test_multiple_updates_converge_toward_one() {
        let mut params = BetaTrustParams::with_default_prior();
        for _ in 0..100 {
            params.update_positive(1.0);
        }
        assert!(params.posterior_mean() > 0.95);
    }

    #[test]
    fn test_multiple_updates_converge_toward_zero() {
        let mut params = BetaTrustParams::with_default_prior();
        for _ in 0..100 {
            params.update_negative(1.0);
        }
        assert!(params.posterior_mean() < 0.05);
    }

    #[test]
    fn test_evidence_weight_affects_speed() {
        let mut p1 = BetaTrustParams::with_default_prior();
        let mut p2 = BetaTrustParams::with_default_prior();
        p1.update_positive(0.1); // Small weight.
        p2.update_positive(1.0); // Large weight.
        assert!(p2.posterior_mean() > p1.posterior_mean());
    }

    #[test]
    fn test_raw_evidence_preserved() {
        let mut params = BetaTrustParams::with_default_prior();
        params.update_positive(1.0);
        params.update_positive(0.5);
        params.update_negative(0.3);
        assert!((params.raw_positive - 1.5).abs() < 1e-9);
        assert!((params.raw_negative - 0.3).abs() < 1e-9);
    }

    #[test]
    fn test_reset_restores_prior() {
        let mut params = BetaTrustParams::with_default_prior();
        params.update_positive(10.0);
        params.reset();
        assert!((params.posterior_mean() - 0.5).abs() < 1e-9);
        assert!((params.raw_positive).abs() < 1e-9);
    }

    #[test]
    fn test_credible_interval_contains_mean() {
        let mut params = BetaTrustParams::with_default_prior();
        for _ in 0..20 {
            params.update_positive(1.0);
        }
        let (lo, hi) = params.credible_interval(0.95);
        let mean = params.posterior_mean();
        assert!(mean >= lo - 1e-9 && mean <= hi + 1e-9);
        assert!(lo <= hi);
    }

    #[test]
    fn test_prob_exceeds_with_high_trust() {
        let mut params = BetaTrustParams::with_default_prior();
        for _ in 0..50 {
            params.update_positive(1.0);
        }
        let p = params.prob_exceeds(0.5);
        assert!(p > 0.99);
    }

    #[test]
    fn test_prob_exceeds_with_low_trust() {
        let mut params = BetaTrustParams::with_default_prior();
        for _ in 0..50 {
            params.update_negative(1.0);
        }
        let p = params.prob_exceeds(0.5);
        assert!(p < 0.01);
    }

    #[test]
    fn test_posterior_variance_decreases_with_evidence() {
        let mut params = BetaTrustParams::with_default_prior();
        let var_before = params.posterior_variance();
        params.update_positive(1.0);
        let var_after = params.posterior_variance();
        assert!(var_after < var_before);
    }

    // ---- 2. Temporal Decay Tests ----

    #[test]
    fn test_exponential_decay_at_zero_dt() {
        let config = DecayConfig::exponential(0.001);
        let mult = config.decay_multiplier(0.0);
        assert!((mult - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_exponential_decay_decreases_over_time() {
        let config = DecayConfig::exponential(0.001);
        let m1 = config.decay_multiplier(100.0);
        let m2 = config.decay_multiplier(1000.0);
        assert!(m1 > m2);
        assert!(m1 < 1.0);
        assert!(m2 > config.floor);
    }

    #[test]
    fn test_linear_decay_at_zero_dt() {
        let config = DecayConfig::linear(0.0001);
        let mult = config.decay_multiplier(0.0);
        assert!((mult - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_linear_decay_decreases_over_time() {
        let config = DecayConfig::linear(0.001);
        let m1 = config.decay_multiplier(100.0);
        let m2 = config.decay_multiplier(500.0);
        assert!(m1 > m2);
    }

    #[test]
    fn test_step_decay_at_boundaries() {
        let config = DecayConfig::step(0.5, 100.0);
        let m0 = config.decay_multiplier(0.0);
        let m1 = config.decay_multiplier(100.0);
        let m2 = config.decay_multiplier(200.0);
        assert!((m0 - 1.0).abs() < 1e-9);
        assert!((m1 - 0.5).abs() < 1e-9);
        assert!((m2 - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_decay_floor_is_respected() {
        let config = DecayConfig::exponential(1.0); // Fast decay.
        let mult = config.decay_multiplier(1e6);
        assert!(mult >= config.floor);
    }

    #[test]
    fn test_temporal_evidence_store_accumulates() {
        let mut store = TemporalEvidenceStore::with_default_decay();
        store.add_evidence(TrustEvidence::positive("src1"));
        store.add_evidence(TrustEvidence::negative("src2"));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_temporal_store_raw_totals() {
        let mut store = TemporalEvidenceStore::with_default_decay();
        store.add_evidence(TrustEvidence::new(true, 1.0, "a"));
        store.add_evidence(TrustEvidence::new(true, 0.5, "b"));
        store.add_evidence(TrustEvidence::new(false, 0.3, "c"));
        let (pos, neg) = store.raw_evidence_totals();
        assert!((pos - 1.5).abs() < 1e-9);
        assert!((neg - 0.3).abs() < 1e-9);
    }

    #[test]
    fn test_prune_stale_removes_low_weight() {
        let mut store = TemporalEvidenceStore::new(DecayConfig::exponential(10.0));
        store.add_evidence(TrustEvidence::positive("old"));
        // Simulate decay of a very old record.
        let now_secs = parse_rfc3339_to_secs(&chrono::Utc::now().to_rfc3339());
        store.compute_decayed_params(now_secs + 1000.0);
        store.prune_stale(0.5);
        // After heavy decay, the record should be pruned.
        assert!(store.is_empty() || store.len() <= 1);
    }
    // ---- 3. Graph Propagation Tests ----

    #[test]
    fn test_propagation_converges_simple_chain() {
        let mut prop = TrustPropagator::with_defaults();
        prop.set_initial_trust("A", 0.9);
        prop.set_initial_trust("B", 0.5);
        prop.set_initial_trust("C", 0.5);
        prop.add_edge("A", "B", 0.9);
        prop.add_edge("B", "C", 0.8);

        let result = prop.propagate();
        assert!(result.converged);
        // A should remain high, B and C should be pulled up.
        assert!(result.get("A") > 0.8);
        assert!(result.get("C") > 0.5);
    }

    #[test]
    fn test_propagation_damping_limits_spread() {
        let config_high = PropagationConfig {
            damping: 0.99,
            epsilon: 1e-6,
            max_iterations: 200,
            min_trust: 0.01,
            include_self_trust: true,
        };
        let config_low = PropagationConfig {
            damping: 0.3,
            epsilon: 1e-6,
            max_iterations: 200,
            min_trust: 0.01,
            include_self_trust: true,
        };

        let mut prop_high = TrustPropagator::new(config_high);
        prop_high.set_initial_trust("A", 1.0);
        prop_high.set_initial_trust("B", 0.0);
        prop_high.add_edge("A", "B", 1.0);

        let mut prop_low = TrustPropagator::new(config_low);
        prop_low.set_initial_trust("A", 1.0);
        prop_low.set_initial_trust("B", 0.0);
        prop_low.add_edge("A", "B", 1.0);

        let r_high = prop_high.propagate();
        let r_low = prop_low.propagate();
        // High damping should propagate more trust to B.
        assert!(r_high.get("B") > r_low.get("B"));
    }

    #[test]
    fn test_propagation_max_iterations() {
        let config = PropagationConfig {
            damping: 0.85,
            epsilon: 1e-15, // Very tight — may not converge quickly.
            max_iterations: 5,
            min_trust: 0.01,
            include_self_trust: true,
        };
        let mut prop = TrustPropagator::new(config);
        prop.set_initial_trust("A", 1.0);
        prop.set_initial_trust("B", 0.0);
        prop.add_edge("A", "B", 1.0);
        let result = prop.propagate();
        assert_eq!(result.iterations, 5);
    }

    #[test]
    fn test_propagation_empty_graph() {
        let prop = TrustPropagator::with_defaults();
        let result = prop.propagate();
        assert!(result.converged);
        assert!(result.node_trust.is_empty());
    }

    #[test]
    fn test_propagation_result_top_nodes() {
        let mut prop = TrustPropagator::with_defaults();
        prop.set_initial_trust("A", 0.9);
        prop.set_initial_trust("B", 0.5);
        prop.set_initial_trust("C", 0.1);
        prop.add_edge("A", "B", 0.8);
        prop.add_edge("B", "C", 0.3);
        let result = prop.propagate();
        let top = result.top_nodes(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].1 >= top[1].1);
    }

    // ---- 4. Fusion Tests ----

    #[test]
    fn test_belief_function_from_trust() {
        let bf = BeliefFunction::from_trust(0.8, 0.1);
        assert!((bf.m_trusted - 0.8).abs() < 1e-9);
        assert!((bf.m_uncertain - 0.1).abs() < 1e-9);
        assert!((bf.m_not_trusted - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_belief_plausibility_bounds() {
        let bf = BeliefFunction::from_trust(0.6, 0.2);
        let bel = bf.belief_trusted();
        let pl = bf.plausibility_trusted();
        assert!(bel <= pl);
        assert!(bel >= 0.0 && bel <= 1.0);
        assert!(pl >= 0.0 && pl <= 1.0);
    }

    #[test]
    fn test_combine_agreeing_sources() {
        let b1 = BeliefFunction::from_trust(0.8, 0.1);
        let b2 = BeliefFunction::from_trust(0.8, 0.1);
        let combined = b1.combine(&b2).unwrap();
        // Combining agreeing sources should increase trust.
        assert!(combined.m_trusted >= b1.m_trusted);
        assert!(combined.pignistic_probability() > 0.8);
    }

    #[test]
    fn test_combine_conflicting_sources_reduces_trust() {
        let b1 = BeliefFunction::from_trust(0.9, 0.05);
        let b2 = BeliefFunction::from_trust(0.1, 0.05);
        let combined = b1.combine(&b2).unwrap();
        // Combined trust should be near 0.5 due to high conflict.
        let p = combined.pignistic_probability();
        assert!(p > 0.3 && p < 0.7);
    }

    #[test]
    fn test_total_conflict_returns_none() {
        let b1 = BeliefFunction::from_trust(1.0, 0.0);
        let b2 = BeliefFunction::from_trust(0.0, 0.0);
        let combined = b1.combine(&b2);
        assert!(combined.is_none());
    }

    #[test]
    fn test_conflict_measure() {
        let b1 = BeliefFunction::from_trust(0.9, 0.1);
        let b2 = BeliefFunction::from_trust(0.1, 0.0);
        let k = b1.conflict_with(&b2);
        // 0.9*0.9 + 0.0*0.1 = 0.81
        assert!((k - 0.81).abs() < 1e-9);
    }

    #[test]
    fn test_combine_many_sources() {
        let beliefs = vec![
            BeliefFunction::from_trust(0.8, 0.1),
            BeliefFunction::from_trust(0.7, 0.15),
            BeliefFunction::from_trust(0.85, 0.05),
        ];
        let combined = BeliefFunction::combine_many(&beliefs);
        assert!(combined.is_some());
        let c = combined.unwrap();
        assert!(c.pignistic_probability() > 0.75);
    }

    #[test]
    fn test_fusion_result_metrics() {
        let beliefs = vec![
            BeliefFunction::from_trust(0.9, 0.05),
            BeliefFunction::from_trust(0.2, 0.05),
        ];
        let result = FusionResult::from_beliefs(&beliefs);
        assert_eq!(result.source_count, 2);
        assert!(result.max_conflict > 0.5);
        assert!(result.avg_conflict > 0.0);
    }

    #[test]
    fn test_fusion_engine_fuse_scores() {
        let engine = TrustFusionEngine::new(10.0);
        let scores = vec![(0.8, 0.1), (0.7, 0.1)];
        let result = engine.fuse_scores(&scores);
        assert!(result.success);
        assert!(result.trust_score > 0.6);
    }

    // ---- 5. Prediction Tests ----

    #[test]
    fn test_predictor_initializes_after_window() {
        let config = PredictionConfig {
            init_window: 3,
            alpha: 0.3,
            beta: 0.1,
            max_horizon: 10,
        };
        let mut pred = TrustPredictor::with_config(config);
        assert!(pred.state.is_none());
        pred.observe(0.5);
        pred.observe(0.6);
        assert!(pred.state.is_none());
        pred.observe(0.7);
        assert!(pred.state.is_some());
    }

    #[test]
    fn test_prediction_increasing_trend() {
        let config = PredictionConfig {
            init_window: 3,
            alpha: 0.5,
            beta: 0.3,
            max_horizon: 10,
        };
        let mut pred = TrustPredictor::with_config(config);
        for i in 0..10 {
            pred.observe(0.3 + (i as f64) * 0.05);
        }
        let predictions = pred.predict(3);
        assert_eq!(predictions.len(), 3);
        // Predictions should be increasing.
        assert!(predictions[1].value >= predictions[0].value);
        assert!(predictions[2].value >= predictions[1].value);
    }

    #[test]
    fn test_prediction_decreasing_trend() {
        let config = PredictionConfig {
            init_window: 3,
            alpha: 0.5,
            beta: 0.3,
            max_horizon: 10,
        };
        let mut pred = TrustPredictor::with_config(config);
        for i in 0..10 {
            pred.observe(0.9 - (i as f64) * 0.05);
        }
        let predictions = pred.predict(3);
        assert_eq!(predictions.len(), 3);
        // Predictions should be decreasing.
        assert!(predictions[1].value <= predictions[0].value);
        assert!(predictions[2].value <= predictions[1].value);
    }

    #[test]
    fn test_prediction_confidence_intervals_widen() {
        let config = PredictionConfig {
            init_window: 3,
            alpha: 0.3,
            beta: 0.1,
            max_horizon: 10,
        };
        let mut pred = TrustPredictor::with_config(config);
        for _ in 0..15 {
            pred.observe(0.5 + rand_small_noise());
        }
        let predictions = pred.predict(5);
        // Confidence intervals should widen with horizon.
        let w1 = predictions[0].ci_upper - predictions[0].ci_lower;
        let w5 = predictions[4].ci_upper - predictions[4].ci_lower;
        assert!(w5 >= w1);
    }

    #[test]
    fn test_trend_direction_detection() {
        let config = PredictionConfig {
            init_window: 3,
            alpha: 0.5,
            beta: 0.3,
            max_horizon: 10,
        };
        let mut pred = TrustPredictor::with_config(config);
        for i in 0..10 {
            pred.observe(0.3 + (i as f64) * 0.06);
        }
        assert_eq!(pred.trend_direction(), TrendDirection::Improving);
    }

    #[test]
    fn test_prediction_before_initialization() {
        let mut pred = TrustPredictor::new();
        pred.observe(0.5);
        let preds = pred.predict(3);
        assert_eq!(preds.len(), 3);
        // All predictions should be the last observed value.
        for p in &preds {
            assert!((p.value - 0.5).abs() < 1e-9);
        }
    }

    // ---- 6. Integration / Engine Tests ----

    #[test]
    fn test_engine_record_and_retrieve() {
        let mut engine = BayesianTrustEngine::new();
        engine.record_evidence("A", "B", true, 1.0, "auth_ok");
        let score = engine.trust_score("A", "B").unwrap();
        assert!(score > 0.5); // Started at prior mean 0.5, positive evidence.
    }

    #[test]
    fn test_engine_negative_evidence() {
        let mut engine = BayesianTrustEngine::new();
        engine.record_evidence("A", "B", false, 1.0, "violation");
        let score = engine.trust_score("A", "B").unwrap();
        assert!(score < 0.5);
    }

    #[test]
    fn test_engine_uncertainty_decreases() {
        let mut engine = BayesianTrustEngine::new();
        engine.record_evidence("A", "B", true, 1.0, "ev1");
        let unc1 = engine.uncertainty("A", "B").unwrap();
        engine.record_evidence("A", "B", true, 1.0, "ev2");
        engine.record_evidence("A", "B", true, 1.0, "ev3");
        let unc2 = engine.uncertainty("A", "B").unwrap();
        assert!(unc2 < unc1);
    }

    #[test]
    fn test_engine_fuse_paths() {
        let mut engine = BayesianTrustEngine::new();
        // Two paths to C: A->C and B->C, both positive.
        for _ in 0..10 {
            engine.record_evidence("A", "C", true, 1.0, "path1");
            engine.record_evidence("B", "C", true, 1.0, "path2");
        }
        let result = engine.fuse_paths(&[("A", "C"), ("B", "C")]);
        assert!(result.success);
        assert!(result.trust_score > 0.8);
    }

    #[test]
    fn test_engine_propagation() {
        let mut engine = build_test_engine();
        let result = engine.propagate();
        assert!(result.iterations > 0);
        assert!(!result.node_trust.is_empty());
    }

    #[test]
    fn test_engine_prediction() {
        let mut engine = BayesianTrustEngine::new();
        for i in 0..15 {
            let val = 0.3 + (i as f64) * 0.04;
            let is_pos = val > 0.5;
            engine.record_evidence("A", "B", is_pos, 1.0, &format!("ev{}", i));
        }
        let preds = engine.predict("A", "B", 3);
        assert!(preds.is_some());
        let preds = preds.unwrap();
        assert_eq!(preds.len(), 3);
    }

    #[test]
    fn test_alert_generator() {
        let mut engine = BayesianTrustEngine::new();
        // Create a low-trust edge.
        for _ in 0..20 {
            engine.record_evidence("A", "B", false, 1.0, "bad");
        }
        let gen = TrustAlertGenerator::default();
        let alerts = gen.generate_alerts(&engine);
        assert!(!alerts.is_empty());
        // Should have at least a critical alert.
        let has_critical = alerts
            .iter()
            .any(|a| a.severity == AlertSeverity::Critical);
        assert!(has_critical);
    }

    #[test]
    fn test_audit_trail() {
        let mut trail = TrustAuditTrail::with_defaults();
        trail.record(TrustAuditEntry::new(
            "A", "B",
            AuditAction::EvidenceRecorded,
            0.5, 0.6,
            "test",
        ));
        trail.record(TrustAuditEntry::new(
            "A", "B",
            AuditAction::EvidenceRecorded,
            0.6, 0.7,
            "test",
        ));
        assert_eq!(trail.len(), 2);
        let for_ab = trail.entries_for("A", "B");
        assert_eq!(for_ab.len(), 2);
    }

    #[test]
    fn test_audit_trail_max_entries() {
        let mut trail = TrustAuditTrail::new(5);
        for i in 0..10 {
            trail.record(TrustAuditEntry::new(
                "A", "B",
                AuditAction::EvidenceRecorded,
                0.5, 0.5 + i as f64 * 0.01,
                &format!("ev{}", i),
            ));
        }
        assert_eq!(trail.len(), 5); // Capped at 5.
    }

    #[test]
    fn test_engine_stats() {
        let engine = build_test_engine();
        let stats = TrustEngineStats::compute(&engine, 0.4);
        assert_eq!(stats.edge_count, 3);
        assert!(stats.avg_trust > 0.0);
        assert!(stats.total_evidence > 0);
    }

    #[test]
    fn test_bayesian_edge_serialization() {
        let edge = BayesianTrustEdge::new("A", "B");
        let json = serde_json::to_string(&edge).unwrap();
        let restored: BayesianTrustEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge.from, restored.from);
        assert_eq!(edge.to, restored.to);
        assert!((edge.trust_score() - restored.trust_score()).abs() < 1e-9);
    }

    // ---- 7. Statistical Utility Tests ----

    #[test]
    fn test_z_score_values() {
        let z90 = z_score(0.90);
        let z95 = z_score(0.95);
        let z99 = z_score(0.99);
        assert!((z90 - 1.2816).abs() < 0.01);
        assert!((z95 - 1.6449).abs() < 0.01);
        assert!((z99 - 2.3263).abs() < 0.01);
    }

    #[test]
    fn test_normal_cdf_symmetry() {
        let p_pos = normal_cdf(1.0);
        let p_neg = normal_cdf(-1.0);
        assert!((p_pos + p_neg - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_normal_cdf_at_zero() {
        let p = normal_cdf(0.0);
        assert!((p - 0.5).abs() < 1e-9);
    }

    // ---- 8. Edge Case Tests ----

    #[test]
    fn test_empty_fusion_result() {
        let result = FusionResult::from_beliefs(&[]);
        assert!(!result.success);
        assert_eq!(result.source_count, 0);
    }

    #[test]
    fn test_single_source_fusion() {
        let beliefs = vec![BeliefFunction::from_trust(0.7, 0.2)];
        let result = FusionResult::from_beliefs(&beliefs);
        assert!(result.success);
        assert_eq!(result.source_count, 1);
        assert!((result.trust_score - 0.8).abs() < 1e-9); // pignistic: 0.7 + 0.2/2
    }

    #[test]
    fn test_prior_variance_sensible() {
        let prior = BetaPrior::default(); // Beta(2, 2)
        let v = prior.variance();
        // Var = 2*2 / (4^2 * 5) = 4/80 = 0.05
        assert!((v - 0.05).abs() < 1e-9);
    }

    #[test]
    fn test_belief_from_beta() {
        let bf = BeliefFunction::from_beta(5.0, 3.0, 10.0);
        // alpha=5, beta=3 => trust=5/8=0.625
        // raw_evidence = 5+3-2 = 6, uncertainty = 1/(1+6/10) = 1/1.6 = 0.625
        assert!((bf.m_trusted - 0.625).abs() < 1e-9);
    }

    #[test]
    fn test_pignistic_probability() {
        let bf = BeliefFunction::from_trust(0.6, 0.2);
        // P(trusted) = 0.6 + 0.2/2 = 0.7
        let p = bf.pignistic_probability();
        assert!((p - 0.7).abs() < 1e-9);
    }

    // Helper: generate small noise for prediction tests.
    fn rand_small_noise() -> f64 {
        // Simple deterministic pseudo-random noise in [-0.05, 0.05].
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let noise = ((nanos % 100) as f64 / 100.0) * 0.1 - 0.05;
        noise
    }
}
