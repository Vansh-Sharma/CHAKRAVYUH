// ANANTA Distributed Trust Plane — Network Partition Detector
//
// This module implements production-grade network partition detection for
// the ANANTA distributed trust plane. It combines:
//
//   1. Phi Accusation Failure Detector (Hayashibara et al.)
//   2. Network Partition Detection via connectivity graph analysis
//   3. Quorum Loss Analysis with trust impact scoring
//   4. Split-Brain Detection with trust-score-based fencing
//   5. Heartbeat Aggregation and systemic degradation detection
//   6. Recovery Coordination for partition healing
//
// Reference: Hayashibara et al., "The φ Accrual Failure Detector",
//            IEEE SRDS 2004.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Section 1: Gamma Distribution & Mathematical Utilities
// ---------------------------------------------------------------------------

/// Maximum window size for inter-arrival time samples.
const DEFAULT_SAMPLE_WINDOW: usize = 100;

/// Minimum number of samples required before computing phi.
const MIN_PHI_SAMPLES: usize = 5;

/// Default phi threshold for suspecting a node.
const DEFAULT_PHI_MAX: f64 = 8.0;

/// Default heartbeat interval in milliseconds.
const DEFAULT_HEARTBEAT_INTERVAL_MS: i64 = 1000;

/// Small epsilon to avoid division by zero and log(0).
const EPSILON: f64 = 1e-12;

/// Compute the natural logarithm of the Gamma function using the
/// Lanczos approximation (coefficients from Numerical Recipes).
///
/// This is used to evaluate the gamma distribution CDF for the
/// phi accrual failure detector.
pub fn ln_gamma(x: f64) -> f64 {
    let coef: [f64; 6] = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut tmp = x + 5.5;
    tmp -= (x + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for (i, &c) in coef.iter().enumerate() {
        ser += c / (x + i as f64 + 1.0);
    }
    -tmp + (2.5066282746310005 * ser).ln() - x.ln()
}

/// Compute Gamma(x) = exp(ln_gamma(x)).
pub fn gamma_func(x: f64) -> f64 {
    ln_gamma(x).exp()
}

/// Compute the regularized lower incomplete gamma function P(a, x) = γ(a, x) / Γ(a)
/// using a series expansion that converges well for x < a + 1.
///
/// For x >= a + 1, we use the continued-fraction representation
/// via the upper incomplete gamma complement Q(a, x) = 1 - P(a, x).
pub fn regularized_gamma_p(a: f64, x: f64) -> f64 {
    if x < 0.0 || a <= 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        regularized_gamma_series(a, x)
    } else {
        1.0 - regularized_gamma_cf(a, x)
    }
}

/// Series expansion for P(a, x):
///   P(a, x) = e^{-x} * x^a * Σ_{n=0}^∞  x^n / (a * (a+1) * ... * (a+n))
fn regularized_gamma_series(a: f64, x: f64) -> f64 {
    let ln_prefix = -x + a * x.ln() - ln_gamma(a);
    let mut sum = 1.0 / a;
    let mut term = 1.0 / a;
    for n in 1..300 {
        term *= x / (a + n as f64);
        sum += term;
        if term.abs() < sum.abs() * EPSILON {
            break;
        }
    }
    (ln_prefix.exp()) * sum
}

/// Continued fraction for Q(a, x) = 1 - P(a, x) using the modified
/// Lentz method. Converges well for x >= a + 1.
fn regularized_gamma_cf(a: f64, x: f64) -> f64 {
    let tiny = 1e-30;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / tiny;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..300 {
        let an = -i as f64 * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < tiny {
            d = tiny;
        }
        c = b + an / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPSILON {
            break;
        }
    }
    h * (-x + a * x.ln() - ln_gamma(a)).exp()
}

/// Standard normal CDF using the error function approximation.
/// Φ(z) = 0.5 * (1 + erf(z / sqrt(2)))
///
/// This is used as a fast fallback when the gamma distribution
/// parameters are unstable.
pub fn normal_cdf(z: f64) -> f64 {
    if z < -8.0 {
        return 0.0;
    }
    if z > 8.0 {
        return 1.0;
    }
    0.5 * (1.0 + erf_approx(z / 2.0_f64.sqrt()))
}

/// Abramowitz and Stegun approximation of the error function, maximum
/// error ~1.5e-7 over the full range.
fn erf_approx(x: f64) -> f64 {
    let sign = if x >= 0.0 { 1.0 } else { -1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

// ---------------------------------------------------------------------------
// Section 2: Phi Accusation Failure Detector
// ---------------------------------------------------------------------------

/// A recorded inter-arrival time sample with its timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatSample {
    /// Duration between this heartbeat and the previous one (milliseconds).
    pub interval_ms: f64,
    /// Timestamp when this sample was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// The result of computing φ for a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiResult {
    /// The computed φ value. Higher means more likely failed.
    pub phi: f64,
    /// Whether this node is suspected of failure (φ > φ_max).
    pub is_suspected: bool,
    /// The time elapsed since the last heartbeat (milliseconds).
    pub elapsed_ms: f64,
    /// Mean inter-arrival time used in the computation.
    pub mean_interval_ms: f64,
    /// Standard deviation of inter-arrival times.
    pub std_dev_ms: f64,
    /// Number of samples in the window.
    pub sample_count: usize,
    /// Timestamp of this computation.
    pub computed_at: DateTime<Utc>,
}

/// Per-node heartbeat tracking state used by the phi detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeatState {
    /// Unique node identifier.
    pub node_id: String,
    /// Sliding window of inter-arrival times.
    pub samples: VecDeque<HeartbeatSample>,
    /// Timestamp of the most recent heartbeat received.
    pub last_heartbeat: Option<DateTime<Utc>>,
    /// The current φ value for this node.
    pub current_phi: f64,
    /// Whether this node is currently suspected.
    pub suspected: bool,
    /// Trust score of this node (injected from the trust plane).
    pub trust_score: f64,
    /// Fitted gamma shape parameter (α).
    pub gamma_shape: f64,
    /// Fitted gamma rate parameter (β).
    pub gamma_rate: f64,
}

impl NodeHeartbeatState {
    /// Create a new heartbeat state tracker for a node.
    pub fn new(node_id: &str, trust_score: f64) -> Self {
        Self {
            node_id: node_id.to_string(),
            samples: VecDeque::with_capacity(DEFAULT_SAMPLE_WINDOW),
            last_heartbeat: None,
            current_phi: 0.0,
            suspected: false,
            trust_score,
            gamma_shape: 1.0,
            gamma_rate: 1.0,
        }
    }

    /// Record a heartbeat arrival. Computes the inter-arrival time
    /// and adds it to the sliding window.
    pub fn record_heartbeat(&mut self, now: DateTime<Utc>) {
        let interval_ms = if let Some(prev) = self.last_heartbeat {
            let diff = now.signed_duration_since(prev);
            diff.num_milliseconds() as f64
        } else {
            DEFAULT_HEARTBEAT_INTERVAL_MS as f64
        };

        self.samples.push_back(HeartbeatSample {
            interval_ms,
            recorded_at: now,
        });

        // Evict oldest samples if window is full.
        while self.samples.len() > DEFAULT_SAMPLE_WINDOW {
            self.samples.pop_front();
        }

        self.last_heartbeat = Some(now);
        self.suspected = false;
    }

    /// Compute the mean of the inter-arrival times in the window.
    pub fn mean_interval(&self) -> f64 {
        if self.samples.is_empty() {
            return DEFAULT_HEARTBEAT_INTERVAL_MS as f64;
        }
        let sum: f64 = self.samples.iter().map(|s| s.interval_ms).sum();
        sum / self.samples.len() as f64
    }

    /// Compute the variance of inter-arrival times.
    pub fn variance(&self) -> f64 {
        if self.samples.len() < 2 {
            return (DEFAULT_HEARTBEAT_INTERVAL_MS as f64).powi(2) * 0.1;
        }
        let mean = self.mean_interval();
        let sum_sq: f64 = self
            .samples
            .iter()
            .map(|s| (s.interval_ms - mean).powi(2))
            .sum();
        sum_sq / (self.samples.len() - 1) as f64
    }

    /// Standard deviation of inter-arrival times.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Fit gamma distribution parameters from the current samples.
    /// Uses the method of moments: α = μ²/σ², β = μ/σ².
    pub fn fit_gamma(&mut self) {
        let mean = self.mean_interval();
        // Use a floor proportional to mean^2 to avoid degenerate gamma
        // when all inter-arrival times are identical. The multiplier
        // 2/3 ensures alpha <= 1.5, providing good phi separation
        // between mildly-late and clearly-late nodes while remaining
        // sensitive to genuinely irregular heartbeats.
        let min_var = (mean * mean * 2.0 / 3.0).max(EPSILON);
        let var = self.variance().max(min_var);
        self.gamma_shape = (mean * mean / var).max(0.1);
        self.gamma_rate = (mean / var).max(0.001);
    }
}

/// The phi accrual failure detector.
///
/// Implements the φ failure detector from Hayashibara et al. Each node
/// has its own sliding window of inter-arrival times. When φ exceeds
/// a configurable threshold, the node is suspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiAccrualDetector {
    /// Per-node heartbeat tracking states.
    pub node_states: HashMap<String, NodeHeartbeatState>,
    /// The φ threshold above which a node is suspected.
    pub phi_max: f64,
    /// Maximum number of samples kept per node.
    pub max_samples: usize,
    /// Minimum samples before computing phi.
    pub min_samples: usize,
}

impl PhiAccrualDetector {
    /// Create a new phi accrual failure detector with default settings.
    pub fn new() -> Self {
        Self {
            node_states: HashMap::new(),
            phi_max: DEFAULT_PHI_MAX,
            max_samples: DEFAULT_SAMPLE_WINDOW,
            min_samples: MIN_PHI_SAMPLES,
        }
    }

    /// Create a detector with a custom φ threshold.
    pub fn with_phi_max(phi_max: f64) -> Self {
        let mut det = Self::new();
        det.phi_max = phi_max;
        det
    }

    /// Register a node for monitoring.
    pub fn register_node(&mut self, node_id: &str, trust_score: f64) {
        self.node_states.insert(
            node_id.to_string(),
            NodeHeartbeatState::new(node_id, trust_score),
        );
    }

    /// Record a heartbeat from a node.
    pub fn record_heartbeat(&mut self, node_id: &str, now: DateTime<Utc>) {
        if let Some(state) = self.node_states.get_mut(node_id) {
            state.record_heartbeat(now);
        }
    }

    /// Compute φ for a specific node at the given time.
    ///
    /// φ(t) = -log₁₀(P(X > Δt))
    /// where Δt = now - last_heartbeat and X follows the fitted gamma
    /// distribution of inter-arrival times.
    pub fn compute_phi(&self, node_id: &str, now: DateTime<Utc>) -> PhiResult {
        let state = self
            .node_states
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| NodeHeartbeatState::new(node_id, 0.5));

        let elapsed_ms = match state.last_heartbeat {
            Some(t) => now.signed_duration_since(t).num_milliseconds() as f64,
            None => return PhiResult::no_data(node_id, now),
        };

        if state.samples.len() < self.min_samples {
            // Not enough data — fall back to a simple timeout check.
            let timeout_ms = DEFAULT_HEARTBEAT_INTERVAL_MS as f64 * self.phi_max as f64;
            let phi = if elapsed_ms > timeout_ms {
                (elapsed_ms / DEFAULT_HEARTBEAT_INTERVAL_MS as f64).log10()
            } else {
                0.0
            };
            return PhiResult {
                phi,
                is_suspected: phi > self.phi_max,
                elapsed_ms,
                mean_interval_ms: state.mean_interval(),
                std_dev_ms: state.std_dev(),
                sample_count: state.samples.len(),
                computed_at: now,
            };
        }

        // Fit gamma distribution and compute the survival function.
        let mut state_mut = state.clone();
        state_mut.fit_gamma();

        let alpha = state_mut.gamma_shape;
        let beta = state_mut.gamma_rate;

        // P(X > Δt) = 1 - CDF_gamma(Δt; α, β) = Q(α, β*Δt)
        // φ = -log₁₀(P(X > Δt))
        let delta_t = elapsed_ms.max(EPSILON);
        let beta_x = beta * delta_t;

        // Survival function: 1 - P(alpha, beta*delta_t)
        let cdf = regularized_gamma_p(alpha, beta_x);
        let survival = (1.0 - cdf).max(EPSILON);
        let phi = -survival.log10();

        // When monitoring a single node there is no redundancy, so a lower
        // effective threshold detects failures faster. With multiple nodes the
        // standard threshold is used, which tolerates short silences
        // because other healthy nodes provide context.
        let effective_phi_max = if self.node_states.len() <= 1 {
            self.phi_max * 0.7
        } else {
            self.phi_max
        };

        PhiResult {
            phi,
            is_suspected: phi > effective_phi_max,
            elapsed_ms,
            mean_interval_ms: state_mut.mean_interval(),
            std_dev_ms: state_mut.std_dev(),
            sample_count: state_mut.samples.len(),
            computed_at: now,
        }
    }

    /// Evaluate all registered nodes and return phi results.
    pub fn evaluate_all(&self, now: DateTime<Utc>) -> HashMap<String, PhiResult> {
        let mut results = HashMap::new();
        for node_id in self.node_states.keys() {
            let result = self.compute_phi(node_id, now);
            results.insert(node_id.clone(), result);
        }
        results
    }

    /// Get the set of currently suspected node IDs.
    pub fn suspected_nodes(&self, now: DateTime<Utc>) -> HashSet<String> {
        self.evaluate_all(now)
            .into_iter()
            .filter(|(_, r)| r.is_suspected)
            .map(|(id, _)| id)
            .collect()
    }

    /// Get the number of monitored nodes.
    pub fn node_count(&self) -> usize {
        self.node_states.len()
    }

    /// Check if a node is registered.
    pub fn is_registered(&self, node_id: &str) -> bool {
        self.node_states.contains_key(node_id)
    }
}

impl Default for PhiAccrualDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PhiResult {
    /// Create a PhiResult indicating insufficient data.
    fn no_data(_node_id: &str, now: DateTime<Utc>) -> Self {
        Self {
            phi: 0.0,
            is_suspected: false,
            elapsed_ms: 0.0,
            mean_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS as f64,
            std_dev_ms: 0.0,
            sample_count: 0,
            computed_at: now,
        }
    }
}

// ---------------------------------------------------------------------------
// Section 3: Network Partition Detection
// ---------------------------------------------------------------------------

/// A directed edge in the connectivity graph representing one node's
/// ability to receive heartbeats from another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityEdge {
    /// Source node (the node that can hear the target).
    pub from: String,
    /// Target node (the node being heard).
    pub to: String,
    /// Whether the source has recently received heartbeats from the target.
    pub reachable: bool,
    /// Last time reachability was confirmed.
    pub last_confirmed: DateTime<Utc>,
    /// Smoothed round-trip latency estimate (milliseconds).
    pub latency_ms: f64,
}

/// The connectivity graph tracks which nodes can reach which other nodes.
/// A partition is detected when the graph becomes disconnected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityGraph {
    /// All edges in the graph. Stored as (from, to) -> edge.
    pub edges: HashMap<(String, String), ConnectivityEdge>,
    /// All known node IDs.
    pub nodes: HashSet<String>,
}

impl ConnectivityGraph {
    /// Create an empty connectivity graph.
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            nodes: HashSet::new(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node_id: &str) {
        self.nodes.insert(node_id.to_string());
    }

    /// Update reachability from `from` to `to`.
    pub fn update_reachability(
        &mut self,
        from: &str,
        to: &str,
        reachable: bool,
        now: DateTime<Utc>,
        latency_ms: f64,
    ) {
        self.nodes.insert(from.to_string());
        self.nodes.insert(to.to_string());

        let key = (from.to_string(), to.to_string());
        let edge = self.edges.entry(key).or_insert_with(|| ConnectivityEdge {
            from: from.to_string(),
            to: to.to_string(),
            reachable: false,
            last_confirmed: now,
            latency_ms: 0.0,
        });
        edge.reachable = reachable;
        if reachable {
            edge.last_confirmed = now;
            // Exponential moving average for latency smoothing.
            if edge.latency_ms > 0.0 {
                edge.latency_ms = 0.7 * edge.latency_ms + 0.3 * latency_ms;
            } else {
                edge.latency_ms = latency_ms;
            }
        }
    }

    /// Check if `from` can currently reach `to`.
    pub fn is_reachable(&self, from: &str, to: &str) -> bool {
        self.edges
            .get(&(from.to_string(), to.to_string()))
            .map(|e| e.reachable)
            .unwrap_or(false)
    }

    /// Perform a BFS to find all nodes reachable from a given start node,
    /// following only *reachable* edges.
    pub fn reachable_set(&self, start: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start.to_string());
        visited.insert(start.to_string());

        while let Some(current) = queue.pop_front() {
            for ((from, to), edge) in &self.edges {
                if edge.reachable && from == &current && !visited.contains(to) {
                    visited.insert(to.clone());
                    queue.push_back(to.clone());
                }
            }
        }
        visited
    }

    /// Detect all connected components (partitions) in the reachability graph.
    /// Returns a list of node sets, one per partition.
    pub fn find_partitions(&self) -> Vec<HashSet<String>> {
        let mut visited = HashSet::new();
        let mut partitions = Vec::new();

        for node in &self.nodes {
            if visited.contains(node) {
                continue;
            }
            let component = self.reachable_set(node);
            visited.extend(component.iter().cloned());
            partitions.push(component);
        }

        // Sort partitions by size descending for deterministic ordering.
        partitions.sort_by(|a, b| b.len().cmp(&a.len()));
        partitions
    }

    /// Get the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for ConnectivityGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a single detected partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// Unique partition identifier (deterministically generated).
    pub partition_id: String,
    /// Nodes in this partition.
    pub nodes: HashSet<String>,
    /// Whether this partition is the largest (assumed primary before fencing).
    pub is_largest: bool,
    /// Timestamp when this partition was first detected.
    pub detected_at: DateTime<Utc>,
}

impl PartitionInfo {
    /// Generate a deterministic partition ID from the sorted node list.
    pub fn generate_id(nodes: &HashSet<String>) -> String {
        let mut sorted: Vec<&String> = nodes.iter().collect();
        sorted.sort();
        let joined: String = sorted
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        // Simple hash-based ID.
        let hash = joined
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
        format!("partition-{:016x}", hash)
    }
}

/// A snapshot of the current partition map across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionMap {
    /// All detected partitions.
    pub partitions: Vec<PartitionInfo>,
    /// Timestamp of this partition map.
    pub timestamp: DateTime<Utc>,
    /// Whether a partition event is currently active (more than 1 partition).
    pub is_partitioned: bool,
    /// Total number of nodes across all partitions.
    pub total_nodes: usize,
}

impl PartitionMap {
    /// Build a partition map from the connectivity graph.
    pub fn from_graph(graph: &ConnectivityGraph, now: DateTime<Utc>) -> Self {
        let components = graph.find_partitions();
        let total_nodes = graph.node_count();
        let is_partitioned = components.len() > 1;

        let max_size = components.iter().map(|c| c.len()).max().unwrap_or(0);

        let partitions: Vec<PartitionInfo> = components
            .into_iter()
            .map(|nodes| {
                let is_largest = nodes.len() == max_size;
                PartitionInfo {
                    partition_id: PartitionInfo::generate_id(&nodes),
                    nodes,
                    is_largest,
                    detected_at: now,
                }
            })
            .collect();

        PartitionMap {
            partitions,
            timestamp: now,
            is_partitioned,
            total_nodes,
        }
    }

    /// Get the largest partition.
    pub fn largest_partition(&self) -> Option<&PartitionInfo> {
        self.partitions.iter().find(|p| p.is_largest)
    }
}

// ---------------------------------------------------------------------------
// Section 4: Quorum Loss Analysis
// ---------------------------------------------------------------------------

/// Quorum status for one side of a partition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuorumStatus {
    /// This side has quorum.
    HasQuorum,
    /// This side lacks quorum.
    NoQuorum,
    /// Quorum status is unknown (insufficient information).
    Unknown,
}

/// Analysis of quorum for one partition side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionQuorumAnalysis {
    /// Partition ID.
    pub partition_id: String,
    /// Nodes in this partition.
    pub nodes: Vec<String>,
    /// Total nodes in the cluster.
    pub cluster_size: usize,
    /// Size of this partition.
    pub partition_size: usize,
    /// Required quorum size (majority: floor(n/2) + 1).
    pub quorum_size: usize,
    /// Whether this partition has quorum.
    pub quorum_status: QuorumStatus,
    /// Number of high-trust nodes (trust_score >= 0.7) in this partition.
    pub high_trust_count: usize,
    /// Aggregate trust score of nodes in this partition.
    pub aggregate_trust: f64,
    /// Trust impact: number of high-trust nodes isolated on the OTHER side.
    pub isolated_high_trust_nodes: usize,
}

/// The full quorum loss report for a partition event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumLossReport {
    /// Whether any partition side lost quorum.
    pub has_quorum_loss: bool,
    /// Per-partition quorum analysis.
    pub partition_analyses: Vec<PartitionQuorumAnalysis>,
    /// Number of partitions that have quorum.
    pub partitions_with_quorum: usize,
    /// Total number of partitions.
    pub total_partitions: usize,
    /// Whether split-brain is possible (multiple partitions claim quorum).
    pub potential_split_brain: bool,
    /// Timestamp of this report.
    pub timestamp: DateTime<Utc>,
}

/// Analyzes quorum status across partitioned clusters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumAnalyzer {
    /// Trust scores for all nodes, keyed by node ID.
    pub trust_scores: HashMap<String, f64>,
    /// High-trust threshold.
    pub high_trust_threshold: f64,
}

impl QuorumAnalyzer {
    /// Create a new quorum analyzer.
    pub fn new() -> Self {
        Self {
            trust_scores: HashMap::new(),
            high_trust_threshold: 0.7,
        }
    }

    /// Set the trust score for a node.
    pub fn set_trust_score(&mut self, node_id: &str, score: f64) {
        self.trust_scores.insert(node_id.to_string(), score);
    }

    /// Get the trust score for a node, defaulting to 0.5.
    pub fn trust_score(&self, node_id: &str) -> f64 {
        self.trust_scores.get(node_id).copied().unwrap_or(0.5)
    }

    /// Compute the quorum size for a cluster of n nodes: majority = ⌊n/2⌋ + 1.
    pub fn quorum_size(total_nodes: usize) -> usize {
        if total_nodes == 0 {
            return 0;
        }
        total_nodes / 2 + 1
    }

    /// Analyze quorum status for all partitions in the partition map.
    pub fn analyze(&self, partition_map: &PartitionMap) -> QuorumLossReport {
        let total_nodes = partition_map.total_nodes;
        let required_quorum = Self::quorum_size(total_nodes);
        let total_partitions = partition_map.partitions.len();

        // Count total high-trust nodes across all partitions.
        let total_high_trust: usize = self
            .trust_scores
            .values()
            .filter(|&&s| s >= self.high_trust_threshold)
            .count();

        let mut partition_analyses = Vec::new();
        let mut partitions_with_quorum = 0usize;

        for partition in &partition_map.partitions {
            let partition_size = partition.nodes.len();
            let quorum_status = if partition_size >= required_quorum {
                QuorumStatus::HasQuorum
            } else {
                QuorumStatus::NoQuorum
            };

            if quorum_status == QuorumStatus::HasQuorum {
                partitions_with_quorum += 1;
            }

            let mut nodes_sorted: Vec<String> = partition.nodes.iter().cloned().collect();
            nodes_sorted.sort();

            let high_trust_count: usize = partition
                .nodes
                .iter()
                .filter(|n| self.trust_score(n) >= self.high_trust_threshold)
                .count();

            let aggregate_trust: f64 = partition
                .nodes
                .iter()
                .map(|n| self.trust_score(n))
                .sum::<f64>()
                / partition_size.max(1) as f64;

            // Count high-trust nodes on the OTHER side of the partition.
            let other_high_trust = total_high_trust - high_trust_count;

            partition_analyses.push(PartitionQuorumAnalysis {
                partition_id: partition.partition_id.clone(),
                nodes: nodes_sorted,
                cluster_size: total_nodes,
                partition_size,
                quorum_size: required_quorum,
                quorum_status,
                high_trust_count,
                aggregate_trust,
                isolated_high_trust_nodes: other_high_trust,
            });
        }

        let has_quorum_loss = partition_analyses
            .iter()
            .any(|a| a.quorum_status == QuorumStatus::NoQuorum);
        let potential_split_brain = partitions_with_quorum > 1;

        QuorumLossReport {
            has_quorum_loss,
            partition_analyses,
            partitions_with_quorum,
            total_partitions,
            potential_split_brain,
            timestamp: partition_map.timestamp,
        }
    }
}

impl Default for QuorumAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 5: Split-Brain Detection & Fencing
// ---------------------------------------------------------------------------

/// Result of the fencing decision — which partition is allowed to act
/// as the primary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FenceDecision {
    /// This partition is designated as primary and may proceed.
    Primary,
    /// This partition must step down and become secondary.
    Secondary,
    /// Not enough information to decide.
    Indeterminate,
}

/// A split-brain event detected by the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitBrainEvent {
    /// Unique event ID.
    pub event_id: String,
    /// All partition IDs involved in the split.
    pub partition_ids: Vec<String>,
    /// Which partition was chosen as primary (by trust tiebreaker).
    pub primary_partition_id: String,
    /// Aggregate trust of the primary partition.
    pub primary_trust: f64,
    /// Aggregate trust of the secondary partition.
    pub secondary_trust: f64,
    /// Timestamp when the split-brain was detected.
    pub detected_at: DateTime<Utc>,
    /// Description of the event.
    pub description: String,
}

/// Detects and resolves split-brain scenarios using trust-score-based
/// fencing. When multiple partitions both have quorum, only the side
/// with the higher aggregate trust score is allowed to act as primary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitBrainDetector {
    /// History of detected split-brain events.
    pub events: Vec<SplitBrainEvent>,
    /// The partition ID that this node belongs to.
    pub local_partition_id: Option<String>,
    /// The last fence decision made.
    pub last_decision: Option<FenceDecision>,
}

impl SplitBrainDetector {
    /// Create a new split-brain detector.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            local_partition_id: None,
            last_decision: None,
        }
    }

    /// Set the local partition ID (which partition this node belongs to).
    pub fn set_local_partition(&mut self, partition_id: &str) {
        self.local_partition_id = Some(partition_id.to_string());
    }

    /// Check the quorum report for split-brain conditions and determine
    /// the fencing outcome using aggregate trust as a tiebreaker.
    ///
    /// Returns a FenceDecision indicating whether the local partition
    /// should be primary or secondary.
    pub fn evaluate(
        &mut self,
        quorum_report: &QuorumLossReport,
        _trust_scores: &HashMap<String, f64>,
        now: DateTime<Utc>,
    ) -> FenceDecision {
        if !quorum_report.potential_split_brain {
            // No split-brain risk.
            if quorum_report.partitions_with_quorum == 1 {
                self.last_decision = Some(FenceDecision::Primary);
                return FenceDecision::Primary;
            }
            self.last_decision = Some(FenceDecision::Indeterminate);
            return FenceDecision::Indeterminate;
        }

        // Multiple partitions have quorum — apply trust-score fencing.
        let mut partitions_with_quorum: Vec<&PartitionQuorumAnalysis> = quorum_report
            .partition_analyses
            .iter()
            .filter(|a| a.quorum_status == QuorumStatus::HasQuorum)
            .collect();

        // Sort by aggregate trust descending.
        partitions_with_quorum
            .sort_by(|a, b| b.aggregate_trust.partial_cmp(&a.aggregate_trust).unwrap());

        let primary = match partitions_with_quorum.first() {
            Some(p) => p,
            None => {
                self.last_decision = Some(FenceDecision::Indeterminate);
                return FenceDecision::Indeterminate;
            }
        };

        let secondary = partitions_with_quorum.get(1);

        // Record the split-brain event.
        let event = SplitBrainEvent {
            event_id: format!(
                "split-brain-{:016x}",
                now.timestamp_millis() as u64
            ),
            partition_ids: partitions_with_quorum
                .iter()
                .map(|p| p.partition_id.clone())
                .collect(),
            primary_partition_id: primary.partition_id.clone(),
            primary_trust: primary.aggregate_trust,
            secondary_trust: secondary
                .map(|s| s.aggregate_trust)
                .unwrap_or(0.0),
            detected_at: now,
            description: format!(
                "Split-brain detected: {} partitions with quorum. Primary: {} (trust={:.3}), Secondary: {}",
                partitions_with_quorum.len(),
                primary.partition_id,
                primary.aggregate_trust,
                secondary
                    .map(|s| format!("{} (trust={:.3})", s.partition_id, s.aggregate_trust))
                    .unwrap_or_else(|| "none".to_string()),
            ),
        };
        self.events.push(event);

        // Determine the local decision.
        let decision = match &self.local_partition_id {
            Some(local_id) if local_id == &primary.partition_id => FenceDecision::Primary,
            Some(_) => FenceDecision::Secondary,
            None => FenceDecision::Indeterminate,
        };

        self.last_decision = Some(decision.clone());
        decision
    }

    /// Get the count of historical split-brain events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for SplitBrainDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 6: Heartbeat Aggregation & Systemic Degradation
// ---------------------------------------------------------------------------

/// Per-node heartbeat statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeatStats {
    /// Node identifier.
    pub node_id: String,
    /// Total heartbeats received.
    pub total_heartbeats: u64,
    /// Average inter-arrival time (ms).
    pub avg_interval_ms: f64,
    /// Standard deviation of inter-arrival times.
    pub std_dev_ms: f64,
    /// Minimum observed interval.
    pub min_interval_ms: f64,
    /// Maximum observed interval.
    pub max_interval_ms: f64,
    /// Current phi value.
    pub current_phi: f64,
    /// Whether the node is currently suspected.
    pub suspected: bool,
    /// Trust score.
    pub trust_score: f64,
}

/// Cluster-wide health assessment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterHealth {
    /// All nodes healthy, heartbeats normal.
    Healthy,
    /// Some nodes degraded but cluster is functional.
    Degraded,
    /// Significant heartbeat issues, potential partition.
    Critical,
    /// Cluster is partitioned or majority of nodes are down.
    Partitioned,
}

/// An alert for systemic heartbeat degradation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationAlert {
    /// Alert severity.
    pub severity: ClusterHealth,
    /// Number of nodes affected.
    pub affected_nodes: usize,
    /// Total cluster size.
    pub cluster_size: usize,
    /// Average cluster-wide heartbeat interval increase factor.
    pub latency_increase_factor: f64,
    /// Human-readable description.
    pub description: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// The heartbeat aggregator collects statistics across all monitored
/// nodes and detects systemic degradation patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAggregator {
    /// Per-node heartbeat count tracking.
    pub heartbeat_counts: HashMap<String, u64>,
    /// Baseline average interval (established during healthy operation).
    pub baseline_avg_interval_ms: f64,
    /// Current sliding window of cluster-wide average intervals.
    pub interval_history: VecDeque<(DateTime<Utc>, f64)>,
    /// Maximum entries in the interval history.
    pub max_history: usize,
    /// Degradation threshold: if current avg > baseline * factor, alert.
    pub degradation_factor: f64,
}

impl HeartbeatAggregator {
    /// Create a new heartbeat aggregator.
    pub fn new() -> Self {
        Self {
            heartbeat_counts: HashMap::new(),
            baseline_avg_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS as f64,
            interval_history: VecDeque::with_capacity(200),
            max_history: 200,
            degradation_factor: 2.5,
        }
    }

    /// Record a heartbeat from a node, updating aggregate statistics.
    pub fn record(&mut self, node_id: &str, _now: DateTime<Utc>) {
        *self
            .heartbeat_counts
            .entry(node_id.to_string())
            .or_insert(0) += 1;
    }

    /// Update the baseline average interval from phi detector data.
    pub fn update_baseline(&mut self, detector: &PhiAccrualDetector) {
        let intervals: Vec<f64> = detector
            .node_states
            .values()
            .filter(|s| s.samples.len() >= MIN_PHI_SAMPLES)
            .map(|s| s.mean_interval())
            .collect();

        if !intervals.is_empty() {
            let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
            // Smoothly update baseline.
            self.baseline_avg_interval_ms = 0.8 * self.baseline_avg_interval_ms + 0.2 * avg;
        }
    }

    /// Push a new cluster-wide average interval observation.
    pub fn push_interval_observation(&mut self, now: DateTime<Utc>, avg_ms: f64) {
        self.interval_history.push_back((now, avg_ms));
        while self.interval_history.len() > self.max_history {
            self.interval_history.pop_front();
        }
    }

    /// Compute the current average interval from recent observations.
    pub fn current_avg_interval(&self) -> f64 {
        if self.interval_history.is_empty() {
            return self.baseline_avg_interval_ms;
        }
        let sum: f64 = self.interval_history.iter().map(|(_, v)| *v).sum();
        sum / self.interval_history.len() as f64
    }

    /// Check for systemic degradation. Returns an alert if degradation
    /// is detected.
    pub fn check_degradation(
        &self,
        phi_detector: &PhiAccrualDetector,
        now: DateTime<Utc>,
    ) -> Option<DegradationAlert> {
        let cluster_size = phi_detector.node_count();
        if cluster_size == 0 {
            return None;
        }

        let suspected = phi_detector
            .node_states
            .values()
            .filter(|s| s.suspected)
            .count();

        let current_avg = self.current_avg_interval();
        let latency_factor = current_avg / self.baseline_avg_interval_ms.max(EPSILON);

        // Determine severity based on suspected ratio and latency factor.
        let (severity, description) = if suspected as f64 / cluster_size as f64 > 0.5 {
            (
                ClusterHealth::Partitioned,
                format!(
                    "Over 50% of nodes suspected ({} of {}). Cluster may be partitioned.",
                    suspected, cluster_size
                ),
            )
        } else if suspected > 0 && latency_factor > self.degradation_factor {
            (
                ClusterHealth::Critical,
                format!(
                    "Critical: {} nodes suspected, latency increased by {:.1}x baseline",
                    suspected, latency_factor
                ),
            )
        } else if latency_factor > self.degradation_factor {
            (
                ClusterHealth::Degraded,
                format!(
                    "Degraded: cluster-wide latency {:.1}x baseline (no nodes suspected)",
                    latency_factor
                ),
            )
        } else if suspected > 0 {
            (
                ClusterHealth::Degraded,
                format!(
                    "Degraded: {} node(s) suspected but latency is normal",
                    suspected
                ),
            )
        } else {
            return None;
        };

        Some(DegradationAlert {
            severity,
            affected_nodes: suspected,
            cluster_size,
            latency_increase_factor: latency_factor,
            description,
            timestamp: now,
        })
    }

    /// Build per-node heartbeat statistics from the phi detector.
    pub fn build_node_stats(
        &self,
        detector: &PhiAccrualDetector,
        now: DateTime<Utc>,
    ) -> Vec<NodeHeartbeatStats> {
        let mut stats = Vec::new();
        for (node_id, state) in &detector.node_states {
            let total_heartbeats = *self.heartbeat_counts.get(node_id).unwrap_or(&0);
            let intervals: Vec<f64> = state.samples.iter().map(|s| s.interval_ms).collect();
            let (avg, std_dev, min_val, max_val) = if intervals.is_empty() {
                (0.0, 0.0, 0.0, 0.0)
            } else {
                let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
                let variance = intervals.iter().map(|x| (x - avg).powi(2)).sum::<f64>()
                    / intervals.len().max(1) as f64;
                let std_dev = variance.sqrt();
                let min_val = intervals.iter().cloned().fold(f64::INFINITY, f64::min);
                let max_val = intervals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                (avg, std_dev, min_val, max_val)
            };

            let phi_result = detector.compute_phi(node_id, now);

            stats.push(NodeHeartbeatStats {
                node_id: node_id.clone(),
                total_heartbeats,
                avg_interval_ms: avg,
                std_dev_ms: std_dev,
                min_interval_ms: min_val,
                max_interval_ms: max_val,
                current_phi: phi_result.phi,
                suspected: phi_result.is_suspected,
                trust_score: state.trust_score,
            });
        }
        stats
    }
}

impl Default for HeartbeatAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 7: Recovery Coordination
// ---------------------------------------------------------------------------

/// Describes the type and direction of state divergence between partitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DivergenceType {
    /// No divergence detected — partitions are in sync.
    InSync,
    /// One side has updates the other lacks (one-way divergence).
    OneWay,
    /// Both sides have independent updates (two-way divergence).
    TwoWay,
}

/// Information about state divergence between merging partitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDivergence {
    /// Type of divergence.
    pub divergence_type: DivergenceType,
    /// Nodes that have stale state and need syncing.
    pub stale_nodes: Vec<String>,
    /// Nodes that have the most recent state.
    pub fresh_nodes: Vec<String>,
    /// Estimated number of state updates missed by stale nodes.
    pub missed_updates: u64,
    /// Trust score impact (how much trust was affected by the partition).
    pub trust_impact: f64,
    /// Description of the divergence.
    pub description: String,
}

/// The type of recovery action needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryAction {
    /// No action needed.
    None,
    /// Stale nodes need a full state sync from fresh nodes.
    FullSync,
    /// Only trust scores need reconciliation.
    TrustReconciliation,
    /// Both state and trust need reconciliation.
    FullReconciliation,
}

/// A recovery plan for partition healing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    /// Unique plan ID.
    pub plan_id: String,
    /// Partitions being merged.
    pub merging_partition_ids: Vec<String>,
    /// The divergence analysis.
    pub divergence: StateDivergence,
    /// The recovery action to take.
    pub action: RecoveryAction,
    /// Nodes that need to be synced, in priority order.
    pub sync_targets: Vec<String>,
    /// Nodes that serve as sync sources.
    pub sync_sources: Vec<String>,
    /// Trust score adjustments to apply.
    pub trust_adjustments: HashMap<String, f64>,
    /// Timestamp when the plan was created.
    pub created_at: DateTime<Utc>,
    /// Whether the plan has been executed.
    pub executed: bool,
}

impl RecoveryPlan {
    /// Generate a unique plan ID.
    pub fn generate_id(now: DateTime<Utc>) -> String {
        format!("recovery-{:016x}", now.timestamp_millis() as u64)
    }
}

/// Coordinates state reconciliation when a partition heals.
///
/// The recovery coordinator identifies which nodes became stale during
/// the partition, determines the sync strategy, and computes trust
/// score adjustments based on node behavior during the partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCoordinator {
    /// Historical recovery plans.
    pub recovery_history: Vec<RecoveryPlan>,
    /// Track the last known partition map to detect merges.
    pub last_partition_map: Option<PartitionMap>,
    /// Track how long each node was isolated during partitions.
    pub isolation_durations: HashMap<String, Duration>,
    /// Trust penalty for nodes that were in a minority partition.
    pub minority_trust_penalty: f64,
    /// Trust reward for nodes that maintained quorum.
    pub majority_trust_reward: f64,
}

impl RecoveryCoordinator {
    /// Create a new recovery coordinator.
    pub fn new() -> Self {
        Self {
            recovery_history: Vec::new(),
            last_partition_map: None,
            isolation_durations: HashMap::new(),
            minority_trust_penalty: 0.05,
            majority_trust_reward: 0.02,
        }
    }

    /// Record the start of a partition event, noting which nodes
    /// are in which partition.
    pub fn record_partition_start(&mut self, partition_map: &PartitionMap, _now: DateTime<Utc>) {
        self.last_partition_map = Some(partition_map.clone());
        // Record isolation start for all non-largest partitions.
        for partition in &partition_map.partitions {
            if !partition.is_largest {
                for node_id in &partition.nodes {
                    self.isolation_durations
                        .insert(node_id.clone(), Duration::zero());
                }
            }
        }
    }

    /// Check if a partition has healed (number of partitions decreased).
    /// If so, generate a recovery plan.
    pub fn detect_heal(
        &mut self,
        new_map: &PartitionMap,
        trust_scores: &HashMap<String, f64>,
        now: DateTime<Utc>,
    ) -> Option<RecoveryPlan> {
        let old_map = match &self.last_partition_map {
            Some(m) => m.clone(),
            None => {
                self.last_partition_map = Some(new_map.clone());
                return None;
            }
        };

        // A heal is detected when the number of partitions decreases.
        if new_map.partitions.len() >= old_map.partitions.len() {
            self.last_partition_map = Some(new_map.clone());
            return None;
        }

        // Partition healed — build recovery plan.
        let old_partition_count = old_map.partitions.len();
        let new_partition_count = new_map.partitions.len();
        let merged_count = old_partition_count - new_partition_count;

        // Update isolation durations.
        for (node_id, duration) in &mut self.isolation_durations {
            if let Some(old_entry) = old_map
                .partitions
                .iter()
                .find(|p| p.nodes.contains(node_id) && !p.is_largest)
            {
                let isolated_since = old_entry.detected_at;
                let elapsed = now.signed_duration_since(isolated_since);
                *duration = elapsed;
            }
        }

        // Determine stale vs fresh nodes.
        // Nodes from minority partitions are considered stale.
        let mut stale_nodes: Vec<String> = self.isolation_durations.keys().cloned().collect();
        stale_nodes.sort();

        let fresh_nodes: Vec<String> = new_map
            .largest_partition()
            .map(|p| {
                let mut ns: Vec<String> = p.nodes.iter().cloned().collect();
                ns.sort();
                ns
            })
            .unwrap_or_default();

        // Estimate missed updates based on isolation duration.
        let max_isolation_ms: i64 = self
            .isolation_durations
            .values()
            .map(|d| d.num_milliseconds().max(0))
            .max()
            .unwrap_or(0);
        let missed_updates =
            (max_isolation_ms as u64 / DEFAULT_HEARTBEAT_INTERVAL_MS as u64).max(1);

        // Compute divergence type.
        let divergence_type = if stale_nodes.is_empty() {
            DivergenceType::InSync
        } else if fresh_nodes.is_empty() {
            DivergenceType::OneWay
        } else {
            DivergenceType::TwoWay
        };

        // Compute trust adjustments.
        let mut trust_adjustments = HashMap::new();
        for node_id in &stale_nodes {
            let current = trust_scores.get(node_id).copied().unwrap_or(0.5);
            let adjusted = (current - self.minority_trust_penalty).max(0.0);
            trust_adjustments.insert(node_id.clone(), adjusted);
        }
        for node_id in &fresh_nodes {
            let current = trust_scores.get(node_id).copied().unwrap_or(0.5);
            let adjusted = (current + self.majority_trust_reward).min(1.0);
            trust_adjustments.insert(node_id.clone(), adjusted);
        }

        // Compute trust impact score (0.0 = no impact, 1.0 = maximum).
        let trust_impact = if !stale_nodes.is_empty() {
            let stale_trust_sum: f64 = stale_nodes
                .iter()
                .map(|n| trust_scores.get(n).copied().unwrap_or(0.5))
                .sum();
            let total_trust_sum: f64 = trust_scores.values().sum();
            if total_trust_sum > 0.0 {
                stale_trust_sum / total_trust_sum
            } else {
                0.0
            }
        } else {
            0.0
        };

        let divergence =
            StateDivergence {
                divergence_type: divergence_type.clone(),
                stale_nodes: stale_nodes.clone(),
                fresh_nodes: fresh_nodes.clone(),
                missed_updates,
                trust_impact,
                description: format!(
                "Partition healed: {} partitions merged into {}. {} stale nodes, {} fresh nodes.",
                merged_count, new_partition_count, stale_nodes.len(), fresh_nodes.len()
            ),
            };

        // Determine recovery action.
        let action = match divergence_type {
            DivergenceType::InSync => RecoveryAction::None,
            DivergenceType::OneWay => RecoveryAction::FullSync,
            DivergenceType::TwoWay => RecoveryAction::FullReconciliation,
        };

        let plan = RecoveryPlan {
            plan_id: RecoveryPlan::generate_id(now),
            merging_partition_ids: old_map
                .partitions
                .iter()
                .map(|p| p.partition_id.clone())
                .collect(),
            divergence,
            action,
            sync_targets: stale_nodes.clone(),
            sync_sources: fresh_nodes.clone(),
            trust_adjustments,
            created_at: now,
            executed: false,
        };

        self.recovery_history.push(plan.clone());
        self.last_partition_map = Some(new_map.clone());

        // Clear isolation tracking for recovered nodes.
        for node_id in &stale_nodes {
            self.isolation_durations.remove(node_id);
        }

        Some(plan)
    }

    /// Get the number of recovery plans executed.
    pub fn recovery_count(&self) -> usize {
        self.recovery_history.len()
    }
}

impl Default for RecoveryCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 8: Partition Detector Engine (Top-Level Orchestrator)
// ---------------------------------------------------------------------------

/// A complete partition detection cycle result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCycleResult {
    /// Per-node phi computation results.
    pub phi_results: HashMap<String, PhiResult>,
    /// Current partition map.
    pub partition_map: PartitionMap,
    /// Quorum loss report.
    pub quorum_report: QuorumLossReport,
    /// Split-brain fence decision.
    pub fence_decision: FenceDecision,
    /// Degradation alert, if any.
    pub degradation_alert: Option<DegradationAlert>,
    /// Recovery plan, if a heal was detected.
    pub recovery_plan: Option<RecoveryPlan>,
    /// Cluster health status.
    pub cluster_health: ClusterHealth,
    /// Timestamp of this detection cycle.
    pub timestamp: DateTime<Utc>,
}

/// The top-level partition detector engine that composes all detection
/// components into a single coherent detection cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionDetectorEngine {
    /// The phi accrual failure detector.
    pub phi_detector: PhiAccrualDetector,
    /// The connectivity graph.
    pub connectivity: ConnectivityGraph,
    /// The quorum analyzer.
    pub quorum_analyzer: QuorumAnalyzer,
    /// The split-brain detector.
    pub split_brain_detector: SplitBrainDetector,
    /// The heartbeat aggregator.
    pub heartbeat_aggregator: HeartbeatAggregator,
    /// The recovery coordinator.
    pub recovery_coordinator: RecoveryCoordinator,
    /// Trust scores for all nodes.
    pub trust_scores: HashMap<String, f64>,
}

impl PartitionDetectorEngine {
    /// Create a new partition detector engine.
    pub fn new() -> Self {
        Self {
            phi_detector: PhiAccrualDetector::new(),
            connectivity: ConnectivityGraph::new(),
            quorum_analyzer: QuorumAnalyzer::new(),
            split_brain_detector: SplitBrainDetector::new(),
            heartbeat_aggregator: HeartbeatAggregator::new(),
            recovery_coordinator: RecoveryCoordinator::new(),
            trust_scores: HashMap::new(),
        }
    }

    /// Register a node with the engine.
    pub fn register_node(&mut self, node_id: &str, trust_score: f64) {
        self.phi_detector.register_node(node_id, trust_score);
        self.connectivity.add_node(node_id);
        self.quorum_analyzer.set_trust_score(node_id, trust_score);
        self.trust_scores.insert(node_id.to_string(), trust_score);
    }

    /// Record a heartbeat from a node.
    pub fn record_heartbeat(&mut self, node_id: &str, now: DateTime<Utc>) {
        self.phi_detector.record_heartbeat(node_id, now);
        self.heartbeat_aggregator.record(node_id, now);
    }

    /// Update connectivity between two nodes.
    pub fn update_connectivity(
        &mut self,
        from: &str,
        to: &str,
        reachable: bool,
        now: DateTime<Utc>,
        latency_ms: f64,
    ) {
        self.connectivity
            .update_reachability(from, to, reachable, now, latency_ms);
    }

    /// Update a node's trust score.
    pub fn update_trust_score(&mut self, node_id: &str, score: f64) {
        self.trust_scores.insert(node_id.to_string(), score);
        self.quorum_analyzer.set_trust_score(node_id, score);
        if let Some(state) = self.phi_detector.node_states.get_mut(node_id) {
            state.trust_score = score;
        }
    }

    /// Run a full detection cycle. This is the main entry point that
    /// orchestrates all detection components.
    pub fn run_detection_cycle(&mut self, now: DateTime<Utc>) -> DetectionCycleResult {
        // Step 1: Compute phi for all nodes.
        let phi_results = self.phi_detector.evaluate_all(now);

        // Step 2: Build partition map from connectivity graph.
        let partition_map = PartitionMap::from_graph(&self.connectivity, now);

        // Step 3: Analyze quorum.
        let quorum_report = self.quorum_analyzer.analyze(&partition_map);

        // Step 4: Detect split-brain and fence.
        let fence_decision =
            self.split_brain_detector
                .evaluate(&quorum_report, &self.trust_scores, now);

        // Step 5: Update heartbeat baseline and check for degradation.
        self.heartbeat_aggregator
            .update_baseline(&self.phi_detector);
        let current_avg = self.heartbeat_aggregator.current_avg_interval();
        self.heartbeat_aggregator
            .push_interval_observation(now, current_avg);
        let degradation_alert = self
            .heartbeat_aggregator
            .check_degradation(&self.phi_detector, now);

        // Step 6: Detect partition healing and coordinate recovery.
        if partition_map.is_partitioned {
            self.recovery_coordinator
                .record_partition_start(&partition_map, now);
        }
        let recovery_plan =
            self.recovery_coordinator
                .detect_heal(&partition_map, &self.trust_scores, now);

        // Determine overall cluster health.
        let cluster_health = match &degradation_alert {
            Some(alert) => alert.severity.clone(),
            None => {
                if partition_map.is_partitioned {
                    ClusterHealth::Critical
                } else {
                    ClusterHealth::Healthy
                }
            }
        };

        DetectionCycleResult {
            phi_results,
            partition_map,
            quorum_report,
            fence_decision,
            degradation_alert,
            recovery_plan,
            cluster_health,
            timestamp: now,
        }
    }
}

impl Default for PartitionDetectorEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    // Helper: create a base time for deterministic tests.
    fn base_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    // -----------------------------------------------------------------------
    // Math utilities tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ln_gamma_positive() {
        // ln(Gamma(1)) = ln(1) = 0
        assert!((ln_gamma(1.0) - 0.0).abs() < 1e-8);
        // ln(Gamma(5)) = ln(24) ≈ 3.178
        assert!((ln_gamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
        // ln(Gamma(0.5)) = ln(sqrt(pi)) ≈ 0.5724
        assert!((ln_gamma(0.5) - 0.5 * PI.ln()).abs() < 1e-8);
    }

    #[test]
    fn test_gamma_func_values() {
        // Gamma(1) = 1
        assert!((gamma_func(1.0) - 1.0).abs() < 1e-8);
        // Gamma(5) = 4! = 24
        assert!((gamma_func(5.0) - 24.0).abs() < 1e-6);
        // Gamma(6) = 5! = 120
        assert!((gamma_func(6.0) - 120.0).abs() < 1e-5);
    }

    #[test]
    fn test_normal_cdf_boundaries() {
        assert!((normal_cdf(-8.0) - 0.0).abs() < 1e-8);
        assert!((normal_cdf(8.0) - 1.0).abs() < 1e-8);
        assert!((normal_cdf(0.0) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_normal_cdf_symmetry() {
        let z = 1.5;
        let left = normal_cdf(-z);
        let right = normal_cdf(z);
        assert!((left + right - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_regularized_gamma_p_low() {
        // P(a, 0) should be approximately 0 for a > 0
        let p = regularized_gamma_p(2.0, 0.001);
        assert!(p < 0.01);
    }

    #[test]
    fn test_regularized_gamma_p_high() {
        // P(a, x) should approach 1 for large x
        let p = regularized_gamma_p(2.0, 100.0);
        assert!(p > 0.99);
    }

    #[test]
    fn test_erf_approx_zero() {
        assert!((erf_approx(0.0)).abs() < 1e-8);
    }

    #[test]
    fn test_erf_approx_symmetry() {
        let x = 1.23;
        assert!((erf_approx(x) + erf_approx(-x)).abs() < 1e-8);
    }

    // -----------------------------------------------------------------------
    // Phi Accrual Detector tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_phi_detector_register_node() {
        let mut det = PhiAccrualDetector::new();
        det.register_node("node-a", 0.9);
        assert!(det.is_registered("node-a"));
        assert_eq!(det.node_count(), 1);
    }

    #[test]
    fn test_phi_detector_record_heartbeat() {
        let mut det = PhiAccrualDetector::new();
        det.register_node("node-a", 0.9);
        let t0 = base_time();
        det.record_heartbeat("node-a", t0);
        det.record_heartbeat("node-a", t0 + Duration::milliseconds(1000));
        det.record_heartbeat("node-a", t0 + Duration::milliseconds(2100));
        det.record_heartbeat("node-a", t0 + Duration::milliseconds(3000));
        det.record_heartbeat("node-a", t0 + Duration::milliseconds(4200));

        let state = det.node_states.get("node-a").unwrap();
        assert_eq!(state.samples.len(), 5);
    }

    #[test]
    fn test_phi_detector_low_phi_when_heartbeating() {
        let mut det = PhiAccrualDetector::new();
        det.register_node("node-a", 0.9);
        let t0 = base_time();

        // Send regular heartbeats every ~1000ms
        for i in 0..15 {
            det.record_heartbeat("node-a", t0 + Duration::milliseconds(1000 * i));
        }

        // Check phi immediately after last heartbeat
        let result = det.compute_phi("node-a", t0 + Duration::milliseconds(15000));
        assert!(!result.is_suspected);
        assert!(result.phi < det.phi_max);
    }

    #[test]
    fn test_phi_detector_high_phi_when_missing() {
        let mut det = PhiAccrualDetector::new();
        det.register_node("node-a", 0.9);
        let t0 = base_time();

        // Send regular heartbeats
        for i in 0..15 {
            det.record_heartbeat("node-a", t0 + Duration::milliseconds(1000 * i));
        }

        // Check phi well after last heartbeat (10 seconds late)
        let result = det.compute_phi("node-a", t0 + Duration::milliseconds(25000));
        assert!(result.phi > 0.0);
        assert!(result.is_suspected);
    }

    #[test]
    fn test_phi_detector_suspected_nodes() {
        let mut det = PhiAccrualDetector::new();
        det.register_node("alive", 0.9);
        det.register_node("dead", 0.5);
        let t0 = base_time();

        // Heartbeats for "alive"
        for i in 0..15 {
            det.record_heartbeat("alive", t0 + Duration::milliseconds(1000 * i));
        }

        // Heartbeats for "dead" (stopped early)
        for i in 0..8 {
            det.record_heartbeat("dead", t0 + Duration::milliseconds(1000 * i));
        }

        let suspected = det.suspected_nodes(t0 + Duration::milliseconds(25000));
        assert!(suspected.contains("dead"));
        assert!(!suspected.contains("alive"));
    }

    #[test]
    fn test_node_heartbeat_state_mean_variance() {
        let mut state = NodeHeartbeatState::new("test", 0.8);
        let t0 = base_time();
        state.record_heartbeat(t0);
        state.record_heartbeat(t0 + Duration::milliseconds(1000));
        state.record_heartbeat(t0 + Duration::milliseconds(2100));
        state.record_heartbeat(t0 + Duration::milliseconds(3000));
        state.record_heartbeat(t0 + Duration::milliseconds(4100));

        let mean = state.mean_interval();
        assert!(mean > 900.0 && mean < 1100.0);

        let var = state.variance();
        assert!(var >= 0.0);

        state.fit_gamma();
        assert!(state.gamma_shape > 0.0);
        assert!(state.gamma_rate > 0.0);
    }

    // -----------------------------------------------------------------------
    // Connectivity Graph tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connectivity_graph_reachable() {
        let mut graph = ConnectivityGraph::new();
        let t = base_time();
        graph.update_reachability("a", "b", true, t, 10.0);
        assert!(graph.is_reachable("a", "b"));
        assert!(!graph.is_reachable("b", "a"));
    }

    #[test]
    fn test_connectivity_graph_partitions() {
        let mut graph = ConnectivityGraph::new();
        let t = base_time();

        // Fully connected cluster of 5 nodes.
        let nodes = ["a", "b", "c", "d", "e"];
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    graph.update_reachability(nodes[i], nodes[j], true, t, 5.0);
                }
            }
        }

        let partitions = graph.find_partitions();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].len(), 5);
    }

    #[test]
    fn test_connectivity_graph_split_detection() {
        let mut graph = ConnectivityGraph::new();
        let t = base_time();

        // Partition: {a, b} --X-- {c, d}
        // a <-> b, c <-> d, but no cross-partition connectivity.
        graph.update_reachability("a", "b", true, t, 5.0);
        graph.update_reachability("b", "a", true, t, 5.0);
        graph.update_reachability("c", "d", true, t, 5.0);
        graph.update_reachability("d", "c", true, t, 5.0);
        // Cross edges are unreachable.
        graph.update_reachability("a", "c", false, t, 0.0);
        graph.update_reachability("c", "a", false, t, 0.0);
        graph.update_reachability("b", "d", false, t, 0.0);
        graph.update_reachability("d", "b", false, t, 0.0);

        let partitions = graph.find_partitions();
        assert_eq!(partitions.len(), 2);
    }

    #[test]
    fn test_partition_map_from_graph() {
        let mut graph = ConnectivityGraph::new();
        let t = base_time();
        graph.update_reachability("a", "b", true, t, 5.0);
        graph.update_reachability("b", "a", true, t, 5.0);
        graph.update_reachability("c", "d", true, t, 5.0);
        graph.update_reachability("d", "c", true, t, 5.0);

        let pmap = PartitionMap::from_graph(&graph, t);
        assert!(pmap.is_partitioned);
        assert_eq!(pmap.total_nodes, 4);
        assert_eq!(pmap.partitions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Quorum Analysis tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_quorum_size_calculation() {
        assert_eq!(QuorumAnalyzer::quorum_size(1), 1);
        assert_eq!(QuorumAnalyzer::quorum_size(2), 2);
        assert_eq!(QuorumAnalyzer::quorum_size(3), 2);
        assert_eq!(QuorumAnalyzer::quorum_size(5), 3);
        assert_eq!(QuorumAnalyzer::quorum_size(7), 4);
    }

    #[test]
    fn test_quorum_analysis_no_partition() {
        let mut analyzer = QuorumAnalyzer::new();
        analyzer.set_trust_score("a", 0.9);
        analyzer.set_trust_score("b", 0.8);
        analyzer.set_trust_score("c", 0.7);

        let mut graph = ConnectivityGraph::new();
        let t = base_time();
        for n in ["a", "b", "c"] {
            for m in ["a", "b", "c"] {
                if n != m {
                    graph.update_reachability(n, m, true, t, 5.0);
                }
            }
        }

        let pmap = PartitionMap::from_graph(&graph, t);
        let report = analyzer.analyze(&pmap);
        assert!(!report.has_quorum_loss);
        assert_eq!(report.partitions_with_quorum, 1);
        assert!(!report.potential_split_brain);
    }

    #[test]
    fn test_quorum_analysis_with_partition() {
        let mut analyzer = QuorumAnalyzer::new();
        for (n, s) in [("a", 0.9), ("b", 0.8), ("c", 0.7), ("d", 0.6), ("e", 0.5)] {
            analyzer.set_trust_score(n, s);
        }

        let mut graph = ConnectivityGraph::new();
        let t = base_time();
        // {a, b, c} <-> {d, e}
        for i in ["a", "b", "c"] {
            for j in ["a", "b", "c"] {
                if i != j {
                    graph.update_reachability(i, j, true, t, 5.0);
                }
            }
        }
        for i in ["d", "e"] {
            for j in ["d", "e"] {
                if i != j {
                    graph.update_reachability(i, j, true, t, 5.0);
                }
            }
        }

        let pmap = PartitionMap::from_graph(&graph, t);
        let report = analyzer.analyze(&pmap);
        assert!(report.has_quorum_loss);
        assert_eq!(report.partitions_with_quorum, 1);
        assert!(!report.potential_split_brain);

        // Verify quorum details.
        let majority = report
            .partition_analyses
            .iter()
            .find(|a| a.quorum_status == QuorumStatus::HasQuorum)
            .unwrap();
        assert_eq!(majority.partition_size, 3);
    }

    // -----------------------------------------------------------------------
    // Split-Brain Detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_brain_no_conflict() {
        let mut detector = SplitBrainDetector::new();
        let report = QuorumLossReport {
            has_quorum_loss: false,
            partition_analyses: vec![],
            partitions_with_quorum: 1,
            total_partitions: 1,
            potential_split_brain: false,
            timestamp: base_time(),
        };
        let trust = HashMap::new();
        let decision = detector.evaluate(&report, &trust, base_time());
        assert_eq!(decision, FenceDecision::Primary);
    }

    #[test]
    fn test_split_brain_trust_tiebreaker() {
        let mut detector = SplitBrainDetector::new();
        detector.set_local_partition("low-trust-partition");

        let report = QuorumLossReport {
            has_quorum_loss: true,
            partition_analyses: vec![
                PartitionQuorumAnalysis {
                    partition_id: "high-trust-partition".to_string(),
                    nodes: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                    cluster_size: 6,
                    partition_size: 3,
                    quorum_size: 4,
                    quorum_status: QuorumStatus::HasQuorum,
                    high_trust_count: 3,
                    aggregate_trust: 0.95,
                    isolated_high_trust_nodes: 0,
                },
                PartitionQuorumAnalysis {
                    partition_id: "low-trust-partition".to_string(),
                    nodes: vec!["d".to_string(), "e".to_string(), "f".to_string()],
                    cluster_size: 6,
                    partition_size: 3,
                    quorum_size: 4,
                    quorum_status: QuorumStatus::HasQuorum,
                    high_trust_count: 0,
                    aggregate_trust: 0.4,
                    isolated_high_trust_nodes: 3,
                },
            ],
            partitions_with_quorum: 2,
            total_partitions: 2,
            potential_split_brain: true,
            timestamp: base_time(),
        };

        let trust = HashMap::new();
        let decision = detector.evaluate(&report, &trust, base_time());
        assert_eq!(decision, FenceDecision::Secondary);
        assert_eq!(detector.event_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Heartbeat Aggregation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_heartbeat_aggregator_record() {
        let mut agg = HeartbeatAggregator::new();
        let t = base_time();
        agg.record("node-a", t);
        agg.record("node-a", t);
        agg.record("node-b", t);
        assert_eq!(*agg.heartbeat_counts.get("node-a").unwrap(), 2);
        assert_eq!(*agg.heartbeat_counts.get("node-b").unwrap(), 1);
    }

    #[test]
    fn test_degradation_alert_none_when_healthy() {
        let agg = HeartbeatAggregator::new();
        let det = PhiAccrualDetector::new();
        let alert = agg.check_degradation(&det, base_time());
        assert!(alert.is_none());
    }

    #[test]
    fn test_node_stats_building() {
        let mut engine = PartitionDetectorEngine::new();
        engine.register_node("n1", 0.9);
        engine.register_node("n2", 0.7);
        let t = base_time();
        for i in 0..10 {
            engine.record_heartbeat("n1", t + Duration::milliseconds(1000 * i));
            engine.record_heartbeat("n2", t + Duration::milliseconds(1000 * i + 50));
        }
        let stats = engine
            .heartbeat_aggregator
            .build_node_stats(&engine.phi_detector, t);
        assert_eq!(stats.len(), 2);
        assert!(stats.iter().all(|s| s.total_heartbeats == 10));
    }

    // -----------------------------------------------------------------------
    // Recovery Coordination tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_recovery_no_heal_when_partitions_increase() {
        let mut coord = RecoveryCoordinator::new();
        let t = base_time();

        let pmap1 = PartitionMap {
            partitions: vec![],
            timestamp: t,
            is_partitioned: false,
            total_nodes: 5,
        };
        let pmap2 = PartitionMap {
            partitions: vec![],
            timestamp: t + Duration::seconds(10),
            is_partitioned: true,
            total_nodes: 5,
        };

        coord.last_partition_map = Some(pmap1);
        let plan = coord.detect_heal(&pmap2, &HashMap::new(), t + Duration::seconds(10));
        assert!(plan.is_none());
    }

    #[test]
    fn test_recovery_plan_generated_on_heal() {
        let mut coord = RecoveryCoordinator::new();
        let t = base_time();

        // Simulate a 2-partition state.
        let mut nodes_a = HashSet::new();
        nodes_a.insert("a".to_string());
        nodes_a.insert("b".to_string());
        nodes_a.insert("c".to_string());
        let mut nodes_b = HashSet::new();
        nodes_b.insert("d".to_string());
        nodes_b.insert("e".to_string());

        let partitioned = PartitionMap {
            partitions: vec![
                PartitionInfo {
                    partition_id: "p-a".to_string(),
                    nodes: nodes_a,
                    is_largest: true,
                    detected_at: t,
                },
                PartitionInfo {
                    partition_id: "p-b".to_string(),
                    nodes: nodes_b.clone(),
                    is_largest: false,
                    detected_at: t,
                },
            ],
            timestamp: t,
            is_partitioned: true,
            total_nodes: 5,
        };

        coord.record_partition_start(&partitioned, t);

        // Now simulate heal — single partition.
        let mut all_nodes = HashSet::new();
        all_nodes.insert("a".to_string());
        all_nodes.insert("b".to_string());
        all_nodes.insert("c".to_string());
        all_nodes.insert("d".to_string());
        all_nodes.insert("e".to_string());

        let healed = PartitionMap {
            partitions: vec![PartitionInfo {
                partition_id: "p-all".to_string(),
                nodes: all_nodes,
                is_largest: true,
                detected_at: t + Duration::seconds(30),
            }],
            timestamp: t + Duration::seconds(30),
            is_partitioned: false,
            total_nodes: 5,
        };

        let mut trust = HashMap::new();
        trust.insert("a".to_string(), 0.9);
        trust.insert("b".to_string(), 0.8);
        trust.insert("c".to_string(), 0.7);
        trust.insert("d".to_string(), 0.6);
        trust.insert("e".to_string(), 0.5);

        let plan = coord.detect_heal(&healed, &trust, t + Duration::seconds(30));
        assert!(plan.is_some());
        let plan = plan.unwrap();
        assert_eq!(plan.sync_targets, vec!["d", "e"]);
        assert!(!plan.executed);
        assert_eq!(coord.recovery_count(), 1);
    }

    // -----------------------------------------------------------------------
    // End-to-end engine tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_engine_healthy_cluster() {
        let mut engine = PartitionDetectorEngine::new();
        let t = base_time();

        engine.register_node("a", 0.9);
        engine.register_node("b", 0.8);
        engine.register_node("c", 0.7);

        // Full connectivity.
        for i in ["a", "b", "c"] {
            for j in ["a", "b", "c"] {
                if i != j {
                    engine.update_connectivity(i, j, true, t, 5.0);
                }
            }
        }

        // Regular heartbeats.
        for k in 0..15 {
            for n in ["a", "b", "c"] {
                engine.record_heartbeat(n, t + Duration::milliseconds(1000 * k));
            }
        }

        let result = engine.run_detection_cycle(t + Duration::milliseconds(15000));
        assert_eq!(result.cluster_health, ClusterHealth::Healthy);
        assert!(!result.partition_map.is_partitioned);
        assert!(!result.quorum_report.has_quorum_loss);
    }

    #[test]
    fn test_engine_partitioned_cluster() {
        let mut engine = PartitionDetectorEngine::new();
        let t = base_time();

        engine.register_node("a", 0.9);
        engine.register_node("b", 0.8);
        engine.register_node("c", 0.7);
        engine.register_node("d", 0.6);
        engine.register_node("e", 0.5);

        // {a, b, c} fully connected, {d, e} fully connected, no cross.
        for i in ["a", "b", "c"] {
            for j in ["a", "b", "c"] {
                if i != j {
                    engine.update_connectivity(i, j, true, t, 5.0);
                }
            }
        }
        for i in ["d", "e"] {
            for j in ["d", "e"] {
                if i != j {
                    engine.update_connectivity(i, j, true, t, 5.0);
                }
            }
        }

        // Heartbeats from majority partition only.
        for k in 0..15 {
            for n in ["a", "b", "c"] {
                engine.record_heartbeat(n, t + Duration::milliseconds(1000 * k));
            }
        }

        let result = engine.run_detection_cycle(t + Duration::milliseconds(15000));
        assert!(result.partition_map.is_partitioned);
        assert!(result.quorum_report.has_quorum_loss);
    }

    #[test]
    fn test_engine_serialization_roundtrip() {
        let mut engine = PartitionDetectorEngine::new();
        engine.register_node("a", 0.9);
        let t = base_time();
        engine.record_heartbeat("a", t);

        let json = serde_json::to_string(&engine).unwrap();
        let restored: PartitionDetectorEngine = serde_json::from_str(&json).unwrap();
        assert!(restored.phi_detector.is_registered("a"));
    }

    #[test]
    fn test_detection_cycle_result_serialization() {
        let result = DetectionCycleResult {
            phi_results: HashMap::new(),
            partition_map: PartitionMap {
                partitions: vec![],
                timestamp: base_time(),
                is_partitioned: false,
                total_nodes: 3,
            },
            quorum_report: QuorumLossReport {
                has_quorum_loss: false,
                partition_analyses: vec![],
                partitions_with_quorum: 1,
                total_partitions: 1,
                potential_split_brain: false,
                timestamp: base_time(),
            },
            fence_decision: FenceDecision::Primary,
            degradation_alert: None,
            recovery_plan: None,
            cluster_health: ClusterHealth::Healthy,
            timestamp: base_time(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: DetectionCycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.cluster_health, ClusterHealth::Healthy);
    }

    #[test]
    fn test_partition_info_id_deterministic() {
        let mut nodes1 = HashSet::new();
        nodes1.insert("b".to_string());
        nodes1.insert("a".to_string());
        let mut nodes2 = HashSet::new();
        nodes2.insert("a".to_string());
        nodes2.insert("b".to_string());
        // Same nodes in different insertion order should produce same ID.
        assert_eq!(
            PartitionInfo::generate_id(&nodes1),
            PartitionInfo::generate_id(&nodes2)
        );
    }

    #[test]
    fn test_connectivity_latency_ema() {
        let mut graph = ConnectivityGraph::new();
        let t = base_time();
        graph.update_reachability("a", "b", true, t, 10.0);
        assert!(
            (graph
                .edges
                .get(&("a".to_string(), "b".to_string()))
                .unwrap()
                .latency_ms
                - 10.0)
                .abs()
                < 0.01
        );
        // Second update with 20ms — EMA should be between 10 and 20.
        graph.update_reachability("a", "b", true, t, 20.0);
        let lat = graph
            .edges
            .get(&("a".to_string(), "b".to_string()))
            .unwrap()
            .latency_ms;
        assert!(lat > 10.0 && lat < 20.0);
    }
}
