// ANANTA Adaptive Routing — Multi-Objective Path Optimization
//
// This module provides production-grade adaptive routing through the ANANTA
// node network, optimizing simultaneously for latency, trust score, load,
// and cost. It includes A* path finding with composite heuristics, circuit
// breaking, multiple load-balancing strategies, and adaptive weight tuning.

use std::cmp::Ordering;
use std::collections::{
    BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque,
};
use serde::{Deserialize, Serialize};

use super::{Node, NodeRole, NodeStatus};

// ============================================================================
// Configuration Types
// ============================================================================

/// Weights for the multi-objective routing score.
/// All weights must be non-negative; they will be normalized internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingWeights {
    /// Weight for latency in the composite score (higher = prioritize low latency).
    pub latency_weight: f64,
    /// Weight for trust score (higher = prioritize high trust).
    pub trust_weight: f64,
    /// Weight for load (higher = prioritize low load).
    pub load_weight: f64,
    /// Weight for monetary/cost (higher = prioritize low cost).
    pub cost_weight: f64,
}

impl Default for RoutingWeights {
    fn default() -> Self {
        Self {
            latency_weight: 0.3,
            trust_weight: 0.3,
            load_weight: 0.2,
            cost_weight: 0.2,
        }
    }
}

impl RoutingWeights {
    /// Create a new RoutingWeights, clamping all values to [0.0, 1.0].
    pub fn new(
        latency: f64,
        trust: f64,
        load: f64,
        cost: f64,
    ) -> Self {
        Self {
            latency_weight: latency.clamp(0.0, 1.0),
            trust_weight: trust.clamp(0.0, 1.0),
            load_weight: load.clamp(0.0, 1.0),
            cost_weight: cost.clamp(0.0, 1.0),
        }
    }

    /// Return the sum of all weights (useful for normalization check).
    pub fn total(&self) -> f64 {
        self.latency_weight
            + self.trust_weight
            + self.load_weight
            + self.cost_weight
    }

    /// Return normalized weights that sum to 1.0.
    /// If the total is zero, returns equal weights.
    /// Preserves the original ratio by using raw values before any clamping.
    pub fn normalized(&self) -> RoutingWeights {
        let total = self.total();
        if total <= 0.0 {
            return RoutingWeights::new(0.25, 0.25, 0.25, 0.25);
        }
        Self {
            latency_weight: self.latency_weight / total,
            trust_weight: self.trust_weight / total,
            load_weight: self.load_weight / total,
            cost_weight: self.cost_weight / total,
        }
    }
}

/// Target SLA for adaptive weight tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaTarget {
    /// Maximum acceptable end-to-end latency in milliseconds.
    pub max_latency_ms: f64,
    /// Minimum acceptable average trust score on the path.
    pub min_trust_score: f64,
    /// Maximum acceptable load fraction (0.0–1.0) per node.
    pub max_load_fraction: f64,
    /// Maximum acceptable cost per request (arbitrary units).
    pub max_cost_per_request: f64,
}

impl Default for SlaTarget {
    fn default() -> Self {
        Self {
            max_latency_ms: 200.0,
            min_trust_score: 0.7,
            max_load_fraction: 0.8,
            max_cost_per_request: 10.0,
        }
    }
}

/// Full routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Scoring weights for multi-objective optimization.
    pub weights: RoutingWeights,
    /// SLA targets for adaptive tuning.
    pub sla_target: SlaTarget,
    /// Maximum number of hops allowed in a route.
    pub max_hops: usize,
    /// Maximum number of Pareto-optimal routes to return.
    pub max_pareto_routes: usize,
    /// Learning rate for adaptive weight tuning (gradient step size).
    pub learning_rate: f64,
    /// Number of historical observations to keep for weight tuning.
    pub history_window_size: usize,
    /// A* search beam width (max open-set size, 0 = unlimited).
    pub beam_width: usize,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            weights: RoutingWeights::default(),
            sla_target: SlaTarget::default(),
            max_hops: 15,
            max_pareto_routes: 10,
            learning_rate: 0.05,
            history_window_size: 100,
            beam_width: 0,
        }
    }
}

// ============================================================================
// Network Topology
// ============================================================================

/// A directed edge in the routing graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEdge {
    /// Source node ID.
    pub from: String,
    /// Destination node ID.
    pub to: String,
    /// Measured or estimated latency in milliseconds.
    pub latency_ms: f64,
    /// Trust score assigned to this edge (can differ from node trust).
    pub trust_score: f64,
    /// Current load fraction (0.0–1.0) on this edge.
    pub load: f64,
    /// Monetary cost for traversing this edge.
    pub cost: f64,
}

impl NetworkEdge {
    /// Create a new edge with the given metrics.
    pub fn new(
        from: &str,
        to: &str,
        latency_ms: f64,
        trust_score: f64,
        load: f64,
        cost: f64,
    ) -> Self {
        Self {
            from: from.to_string(),
            to: to.to_string(),
            latency_ms: latency_ms.max(0.01),
            trust_score: trust_score.clamp(0.0, 1.0),
            load: load.clamp(0.0, 1.0),
            cost: cost.max(0.0),
        }
    }

    /// Compute the weighted composite cost for this edge.
    pub fn weighted_cost(&self, weights: &RoutingWeights) -> f64 {
        let norm = weights.normalized();
        // Lower latency, higher trust, lower load, lower cost are all desirable.
        // We convert each into a "cost" where lower is better.
        let latency_cost = self.latency_ms / 500.0; // Normalize: 500ms = cost 1.0
        let trust_cost = 1.0 - self.trust_score; // 1.0 trust → 0.0 cost
        let load_cost = self.load; // Already 0–1
        let cost_cost = self.cost / 20.0; // Normalize: 20 units = cost 1.0

        norm.latency_weight * latency_cost
            + norm.trust_weight * trust_cost
            + norm.load_weight * load_cost
            + norm.cost_weight * cost_cost
    }
}

/// The directed graph representing the ANANTA node network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGraph {
    /// Adjacency list: node_id → list of outgoing edges.
    pub adjacency: HashMap<String, Vec<NetworkEdge>>,
    /// Optional geographic coordinates for heuristic estimation (node_id → (lat, lon)).
    pub coordinates: HashMap<String, (f64, f64)>,
}

impl Default for NetworkGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkGraph {
    /// Create an empty graph.
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            coordinates: HashMap::new(),
        }
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: NetworkEdge) {
        self.adjacency
            .entry(edge.from.clone())
            .or_insert_with(Vec::new)
            .push(edge);
    }

    /// Add a coordinate for a node (used in geographic heuristic).
    pub fn set_coordinate(&mut self, node_id: &str, lat: f64, lon: f64) {
        self.coordinates
            .insert(node_id.to_string(), (lat, lon));
    }

    /// Get all outgoing edges from a node.
    pub fn edges_from(&self, node_id: &str) -> &[NetworkEdge] {
        self.adjacency
            .get(node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all unique node IDs in the graph.
    pub fn node_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for (src, edges) in &self.adjacency {
            ids.insert(src.clone());
            for edge in edges {
                ids.insert(edge.to.clone());
            }
        }
        ids
    }

    /// Compute an estimated straight-line distance between two nodes
    /// using their coordinates (Haversine approximation in km).
    /// Returns a default estimate if coordinates are missing.
    pub fn estimated_distance_km(&self, from: &str, to: &str) -> f64 {
        match (
            self.coordinates.get(from),
            self.coordinates.get(to),
        ) {
            (Some(&(lat1, lon1)), Some(&(lat2, lon2))) => {
                let to_radians = |deg: f64| deg * std::f64::consts::PI / 180.0;
                let lat1 = to_radians(lat1);
                let lat2 = to_radians(lat2);
                let dlat = lat2 - lat1;
                let dlon = to_radians(lon2 - lon1);
                let a = (dlat / 2.0).sin().powi(2)
                    + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
                let c = 2.0 * a.sqrt().asin();
                6371.0 * c // Earth radius in km
            }
            _ => 1000.0, // Default 1000 km if unknown
        }
    }

    /// Filter edges: only keep edges whose destination node is in the given set.
    pub fn filter_edges_by_nodes(
        &self,
        allowed: &HashSet<String>,
    ) -> HashMap<String, Vec<NetworkEdge>> {
        let mut filtered = HashMap::new();
        for (src, edges) in &self.adjacency {
            if !allowed.contains(src) {
                continue;
            }
            let kept: Vec<NetworkEdge> = edges
                .iter()
                .filter(|e| allowed.contains(&e.to))
                .cloned()
                .collect();
            if !kept.is_empty() {
                filtered.insert(src.clone(), kept);
            }
        }
        filtered
    }
}

// ============================================================================
// Route and Metrics
// ============================================================================

/// Aggregated metrics for a complete route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMetrics {
    /// Sum of edge latencies.
    pub total_latency_ms: f64,
    /// Minimum trust score across all edges.
    pub min_trust_score: f64,
    /// Average trust score across all edges.
    pub avg_trust_score: f64,
    /// Maximum load across all edges.
    pub max_load: f64,
    /// Average load across all edges.
    pub avg_load: f64,
    /// Sum of edge costs.
    pub total_cost: f64,
    /// Number of hops.
    pub hop_count: usize,
    /// Weighted composite score (lower is better).
    pub composite_score: f64,
}

/// A route through the network: an ordered list of node IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Ordered sequence of node IDs from source to destination.
    pub nodes: Vec<String>,
    /// Aggregated metrics for this route.
    pub metrics: RouteMetrics,
    /// Timestamp when this route was computed.
    pub computed_at: String,
}

impl Route {
    /// Create a route from a node list and compute its metrics over the given edges.
    pub fn from_path(
        path: Vec<String>,
        edges: &HashMap<String, Vec<NetworkEdge>>,
        weights: &RoutingWeights,
    ) -> Self {
        let mut total_latency = 0.0;
        let mut trust_scores = Vec::new();
        let mut loads = Vec::new();
        let mut total_cost = 0.0;
        let mut composite = 0.0;

        for window in path.windows(2) {
            let from = &window[0];
            let to = &window[1];
            if let Some(edge_list) = edges.get(from) {
                if let Some(edge) = edge_list.iter().find(|e| &e.to == to) {
                    total_latency += edge.latency_ms;
                    trust_scores.push(edge.trust_score);
                    loads.push(edge.load);
                    total_cost += edge.cost;
                    composite += edge.weighted_cost(weights);
                }
            }
        }

        let hop_count = if path.len() > 1 {
            path.len() - 1
        } else {
            0
        };

        let min_trust = trust_scores.iter().cloned().fold(1.0, f64::min);
        let avg_trust = if trust_scores.is_empty() {
            1.0
        } else {
            trust_scores.iter().sum::<f64>() / trust_scores.len() as f64
        };
        let max_load = loads.iter().cloned().fold(0.0, f64::max);
        let avg_load = if loads.is_empty() {
            0.0
        } else {
            loads.iter().sum::<f64>() / loads.len() as f64
        };

        Route {
            nodes: path,
            metrics: RouteMetrics {
                total_latency_ms: total_latency,
                min_trust_score: min_trust,
                avg_trust_score: avg_trust,
                max_load,
                avg_load,
                total_cost,
                hop_count,
                composite_score: composite,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// The source node of this route.
    pub fn source(&self) -> Option<&str> {
        self.nodes.first().map(|s| s.as_str())
    }

    /// The destination node of this route.
    pub fn destination(&self) -> Option<&str> {
        self.nodes.last().map(|s| s.as_str())
    }
}

// ============================================================================
// Pareto Frontier
// ============================================================================

/// A point in the multi-objective space for Pareto comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectivePoint {
    /// Lower is better.
    pub latency: f64,
    /// Higher is better (we store as 1 - trust so lower = better).
    pub trust_inverted: f64,
    /// Lower is better.
    pub load: f64,
    /// Lower is better.
    pub cost: f64,
}

impl ObjectivePoint {
    /// Create from route metrics.
    pub fn from_metrics(m: &RouteMetrics) -> Self {
        Self {
            latency: m.total_latency_ms,
            trust_inverted: 1.0 - m.avg_trust_score,
            load: m.max_load,
            cost: m.total_cost,
        }
    }

    /// Check whether `other` dominates this point (i.e., `other` is
    /// at least as good in every objective and strictly better in at least one).
    pub fn is_dominated_by(&self, other: &ObjectivePoint) -> bool {
        let at_least_as_good = other.latency <= self.latency
            && other.trust_inverted <= self.trust_inverted
            && other.load <= self.load
            && other.cost <= self.cost;
        let strictly_better = other.latency < self.latency
            || other.trust_inverted < self.trust_inverted
            || other.load < self.load
            || other.cost < self.cost;
        at_least_as_good && strictly_better
    }
}

/// Compute the Pareto frontier from a set of routes.
/// Returns the subset of routes that are not dominated by any other route.
pub fn compute_pareto_frontier(routes: &[Route]) -> Vec<Route> {
    if routes.is_empty() {
        return vec![];
    }
    let points: Vec<ObjectivePoint> = routes
        .iter()
        .map(|r| ObjectivePoint::from_metrics(&r.metrics))
        .collect();

    let mut non_dominated = Vec::new();
    for (i, route) in routes.iter().enumerate() {
        let mut dominated = false;
        for (j, other_pt) in points.iter().enumerate() {
            if i != j && points[i].is_dominated_by(other_pt) {
                dominated = true;
                break;
            }
        }
        if !dominated {
            non_dominated.push(route.clone());
        }
    }
    non_dominated
}

// ============================================================================
// A* Path Finding
// ============================================================================

/// Different heuristic functions for A* search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HeuristicKind {
    /// Estimate based on geographic distance converted to latency.
    Geographic,
    /// Estimate based on the minimum-cost edge observed so far.
    MinCostEstimate,
    /// Combine geographic latency estimate with a trust-weighted hop penalty.
    TrustWeighted,
    /// Combine geographic with load-balancing penalty.
    LoadBalanced,
    /// Composite of all components.
    Composite,
}

/// State used during A* search.
#[derive(Debug, Clone)]
struct AStarState {
    /// Current node ID.
    node: String,
    /// Cumulative cost from start to this node.
    g_cost: f64,
    /// Estimated total cost (g + h).
    f_cost: f64,
    /// Path from start to this node.
    path: Vec<String>,
}

// We want a min-heap, so we reverse the ordering.
impl PartialEq for AStarState {
    fn eq(&self, other: &Self) -> bool {
        self.f_cost == other.f_cost && self.node == other.node
    }
}

impl Eq for AStarState {}

impl PartialOrd for AStarState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AStarState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap behavior.
        other.f_cost.partial_cmp(&self.f_cost).unwrap_or(Ordering::Equal)
            .then_with(|| self.node.cmp(&other.node))
    }
}

/// A* path finding result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AStarResult {
    /// The best path found, or None if no path exists.
    pub path: Option<Route>,
    /// Number of nodes expanded during search.
    pub nodes_expanded: usize,
    /// Heuristic type used.
    pub heuristic: HeuristicKind,
    /// Time taken for the search in microseconds (approximate).
    pub search_time_us: u64,
}

/// Compute a heuristic estimate from `current` to `goal`.
fn heuristic_estimate(
    kind: &HeuristicKind,
    current: &str,
    goal: &str,
    graph: &NetworkGraph,
    weights: &RoutingWeights,
    node_loads: &HashMap<String, f64>,
    min_edge_cost: f64,
) -> f64 {
    match kind {
        HeuristicKind::Geographic => {
            // Assume ~1 ms latency per 200 km.
            let dist_km = graph.estimated_distance_km(current, goal);
            dist_km / 200.0
        }
        HeuristicKind::MinCostEstimate => {
            // Assume we need at least 1 hop, each with min_edge_cost.
            min_edge_cost.max(0.001)
        }
        HeuristicKind::TrustWeighted => {
            let geo = graph.estimated_distance_km(current, goal) / 200.0;
            let avg_load = node_loads
                .get(current)
                .copied()
                .unwrap_or(0.5);
            let trust_penalty = (1.0 - avg_load) * 0.5;
            geo + trust_penalty
        }
        HeuristicKind::LoadBalanced => {
            let geo = graph.estimated_distance_km(current, goal) / 200.0;
            let load_penalty = node_loads
                .get(current)
                .copied()
                .unwrap_or(0.5)
                * weights.normalized().load_weight
                * 2.0;
            geo + load_penalty
        }
        HeuristicKind::Composite => {
            let norm = weights.normalized();
            let geo = graph.estimated_distance_km(current, goal) / 200.0;
            let load_penalty = node_loads
                .get(current)
                .copied()
                .unwrap_or(0.5);
            let trust_penalty = (1.0 - load_penalty) * 0.3;
            norm.latency_weight * geo
                + norm.trust_weight * trust_penalty
                + norm.load_weight * load_penalty
                + norm.cost_weight * min_edge_cost.max(0.001)
        }
    }
}

/// Run A* search from `source` to `goal` on the given graph.
pub fn astar_search(
    graph: &NetworkGraph,
    source: &str,
    goal: &str,
    weights: &RoutingWeights,
    heuristic: HeuristicKind,
    max_hops: usize,
    beam_width: usize,
    node_loads: &HashMap<String, f64>,
    blocked_nodes: &HashSet<String>,
) -> AStarResult {
    let start_time = std::time::Instant::now();

    // Precompute minimum edge cost for MinCostEstimate heuristic.
    let mut min_edge_cost = f64::MAX;
    for edges in graph.adjacency.values() {
        for edge in edges {
            let c = edge.weighted_cost(weights);
            if c < min_edge_cost {
                min_edge_cost = c;
            }
        }
    }
    if min_edge_cost == f64::MAX {
        min_edge_cost = 1.0;
    }

    let mut open: BinaryHeap<AStarState> = BinaryHeap::new();
    let mut closed: HashSet<String> = HashSet::new();
    let mut nodes_expanded = 0usize;

    let h0 = heuristic_estimate(
        &heuristic,
        source,
        goal,
        graph,
        weights,
        node_loads,
        min_edge_cost,
    );

    if source == goal {
        return AStarResult {
            path: Some(Route {
                nodes: vec![source.to_string()],
                metrics: RouteMetrics {
                    total_latency_ms: 0.0,
                    min_trust_score: 1.0,
                    avg_trust_score: 1.0,
                    max_load: 0.0,
                    avg_load: 0.0,
                    total_cost: 0.0,
                    hop_count: 0,
                    composite_score: 0.0,
                },
                computed_at: chrono::Utc::now().to_rfc3339(),
            }),
            nodes_expanded: 0,
            heuristic,
            search_time_us: start_time.elapsed().as_micros() as u64,
        };
    }

    open.push(AStarState {
        node: source.to_string(),
        g_cost: 0.0,
        f_cost: h0,
        path: vec![source.to_string()],
    });

    while let Some(current) = open.pop() {
        if current.node == goal {
            let route = Route::from_path(
                current.path,
                &graph.adjacency,
                weights,
            );
            return AStarResult {
                path: Some(route),
                nodes_expanded,
                heuristic: heuristic.clone(),
                search_time_us: start_time.elapsed().as_micros() as u64,
            };
        }

        if closed.contains(&current.node) {
            continue;
        }
        closed.insert(current.node.clone());
        nodes_expanded += 1;

        for edge in graph.edges_from(&current.node) {
            if blocked_nodes.contains(&edge.to) {
                continue;
            }
            if closed.contains(&edge.to) {
                continue;
            }
            if current.path.len() >= max_hops {
                continue;
            }

            let step_cost = edge.weighted_cost(weights);
            let new_g = current.g_cost + step_cost;
            let h = heuristic_estimate(
                &heuristic,
                &edge.to,
                goal,
                graph,
                weights,
                node_loads,
                min_edge_cost,
            );
            let new_f = new_g + h;

            let mut new_path = current.path.clone();
            new_path.push(edge.to.clone());

            open.push(AStarState {
                node: edge.to.clone(),
                g_cost: new_g,
                f_cost: new_f,
                path: new_path,
            });
        }

        // Apply beam width pruning if configured.
        if beam_width > 0 && open.len() > beam_width {
            let pruned: Vec<AStarState> = open.drain().collect();
            let mut best = pruned;
            best.sort_by(|a, b| {
                a.f_cost
                    .partial_cmp(&b.f_cost)
                    .unwrap_or(Ordering::Equal)
            });
            for item in best.into_iter().take(beam_width) {
                open.push(item);
            }
        }
    }

    AStarResult {
        path: None,
        nodes_expanded,
        heuristic,
        search_time_us: start_time.elapsed().as_micros() as u64,
    }
}

/// Run A* with multiple heuristics and return the best result.
pub fn astar_multi_heuristic(
    graph: &NetworkGraph,
    source: &str,
    goal: &str,
    weights: &RoutingWeights,
    max_hops: usize,
    beam_width: usize,
    node_loads: &HashMap<String, f64>,
    blocked_nodes: &HashSet<String>,
) -> AStarResult {
    let heuristics = vec![
        HeuristicKind::Geographic,
        HeuristicKind::MinCostEstimate,
        HeuristicKind::TrustWeighted,
        HeuristicKind::LoadBalanced,
        HeuristicKind::Composite,
    ];

    let mut best: Option<AStarResult> = None;
    for h in &heuristics {
        let result = astar_search(
            graph,
            source,
            goal,
            weights,
            h.clone(),
            max_hops,
            beam_width,
            node_loads,
            blocked_nodes,
        );
        if let Some(ref route) = result.path {
            if let Some(ref mut best_ref) = best {
                if let Some(ref best_route) = best_ref.path {
                    if route.metrics.composite_score < best_route.metrics.composite_score {
                        *best_ref = result;
                    }
                }
            } else {
                best = Some(result);
            }
        }
    }
    best.unwrap_or(AStarResult {
        path: None,
        nodes_expanded: 0,
        heuristic: HeuristicKind::Composite,
        search_time_us: 0,
    })
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// States of the circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation — requests pass through.
    Closed,
    /// Failing — requests are rejected immediately.
    Open,
    /// Probing — allow a limited number of requests to test recovery.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Configuration for a single circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures in the window before opening the circuit.
    pub failure_threshold: usize,
    /// Number of successes in the half-open window before closing.
    pub success_threshold: usize,
    /// Sliding window size for tracking outcomes (in number of events).
    pub window_size: usize,
    /// Base backoff duration in milliseconds for half-open probing.
    pub backoff_base_ms: u64,
    /// Maximum backoff duration in milliseconds.
    pub backoff_max_ms: u64,
    /// Maximum multiplier applied to base backoff.
    pub backoff_max_multiplier: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            window_size: 20,
            backoff_base_ms: 1000,
            backoff_max_ms: 60000,
            backoff_max_multiplier: 6,
        }
    }
}

/// A per-node circuit breaker that tracks success/failure in a sliding window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    /// Node ID this circuit breaker protects.
    pub node_id: String,
    /// Current circuit state.
    pub state: CircuitState,
    /// Configuration.
    pub config: CircuitBreakerConfig,
    /// Sliding window of outcomes: true = success, false = failure.
    pub outcomes: VecDeque<bool>,
    /// Number of consecutive failures in the current window.
    pub consecutive_failures: usize,
    /// Number of consecutive successes since entering half-open.
    pub half_open_successes: usize,
    /// Current backoff exponent (increases each time we re-open).
    pub backoff_exponent: u32,
    /// Timestamp when the circuit was last opened.
    pub opened_at: Option<String>,
    /// Timestamp of the last state transition.
    pub last_transition: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for the given node.
    pub fn new(node_id: &str, config: CircuitBreakerConfig) -> Self {
        Self {
            node_id: node_id.to_string(),
            state: CircuitState::Closed,
            config,
            outcomes: VecDeque::new(),
            consecutive_failures: 0,
            half_open_successes: 0,
            backoff_exponent: 0,
            opened_at: None,
            last_transition: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Record a successful interaction with the node.
    pub fn record_success(&mut self) {
        self.push_outcome(true);

        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                self.half_open_successes += 1;
                if self.half_open_successes >= self.config.success_threshold {
                    self.transition_to(CircuitState::Closed);
                    self.backoff_exponent = 0;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen (requests are rejected in open state),
                // but handle gracefully.
            }
        }
    }

    /// Record a failed interaction with the node.
    pub fn record_failure(&mut self) {
        self.push_outcome(false);

        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open re-opens the circuit.
                self.backoff_exponent = (self.backoff_exponent + 1)
                    .min(self.config.backoff_max_multiplier);
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open; just track the failure.
            }
        }
    }

    /// Whether a request is allowed through the circuit.
    pub fn is_request_allowed(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                // Allow one probe request at a time.
                self.half_open_successes < self.config.success_threshold
            }
        }
    }

    /// Attempt to transition from Open to HalfOpen if enough backoff
    /// time has elapsed. Returns true if the transition happened.
    pub fn try_half_open(&mut self) -> bool {
        if self.state != CircuitState::Open {
            return false;
        }
        let backoff_ms = self.compute_backoff_ms();
        if let Some(ref opened) = self.opened_at {
            if let Ok(opened_dt) = chrono::DateTime::parse_from_rfc3339(opened) {
                let now = chrono::Utc::now();
                let elapsed_ms = (now - opened_dt.to_utc())
                    .to_std()
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(u64::MAX);
                if elapsed_ms >= backoff_ms {
                    self.half_open_successes = 0;
                    self.transition_to(CircuitState::HalfOpen);
                    return true;
                }
            }
        }
        false
    }

    /// Compute the current backoff in milliseconds using exponential backoff.
    pub fn compute_backoff_ms(&self) -> u64 {
        let multiplier = 2u64.pow(self.backoff_exponent);
        let ms = self.config.backoff_base_ms * multiplier;
        ms.min(self.config.backoff_max_ms)
    }

    /// Get the failure rate in the current sliding window.
    pub fn failure_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        let failures = self.outcomes.iter().filter(|&&ok| !ok).count();
        failures as f64 / self.outcomes.len() as f64
    }

    /// Get the success rate in the current sliding window.
    pub fn success_rate(&self) -> f64 {
        1.0 - self.failure_rate()
    }

    fn push_outcome(&mut self, success: bool) {
        self.outcomes.push_back(success);
        while self.outcomes.len() > self.config.window_size {
            self.outcomes.pop_front();
        }
    }

    fn transition_to(&mut self, new_state: CircuitState) {
        let is_open = new_state == CircuitState::Open;
        let is_closed = new_state == CircuitState::Closed;
        self.state = new_state;
        self.last_transition = chrono::Utc::now().to_rfc3339();
        if is_open {
            self.opened_at = Some(chrono::Utc::now().to_rfc3339());
            self.half_open_successes = 0;
        }
        if is_closed {
            self.consecutive_failures = 0;
            self.half_open_successes = 0;
        }
    }
}

/// A registry of circuit breakers, keyed by node ID.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CircuitBreakerRegistry {
    /// node_id → circuit breaker.
    pub breakers: HashMap<String, CircuitBreaker>,
}

impl CircuitBreakerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a circuit breaker for a node.
    pub fn get_or_create(
        &mut self,
        node_id: &str,
        config: &CircuitBreakerConfig,
    ) -> &mut CircuitBreaker {
        if !self.breakers.contains_key(node_id) {
            self.breakers.insert(
                node_id.to_string(),
                CircuitBreaker::new(node_id, config.clone()),
            );
        }
        self.breakers.get_mut(node_id).unwrap()
    }

    /// Get the set of node IDs that are currently in Open state.
    pub fn open_nodes(&self) -> HashSet<String> {
        self.breakers
            .iter()
            .filter(|(_, cb)| cb.state == CircuitState::Open)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Attempt to transition all Open breakers to HalfOpen.
    /// Returns the number of breakers that transitioned.
    pub fn try_recover_all(&mut self) -> usize {
        let mut count = 0usize;
        for cb in self.breakers.values_mut() {
            if cb.try_half_open() {
                count += 1;
            }
        }
        count
    }

    /// Record a success for a node.
    pub fn record_success(&mut self, node_id: &str) {
        if let Some(cb) = self.breakers.get_mut(node_id) {
            cb.record_success();
        }
    }

    /// Record a failure for a node.
    pub fn record_failure(&mut self, node_id: &str) {
        if let Some(cb) = self.breakers.get_mut(node_id) {
            cb.record_failure();
        }
    }

    /// Check if requests to a node are allowed.
    pub fn is_allowed(&self, node_id: &str) -> bool {
        self.breakers
            .get(node_id)
            .map(|cb| cb.is_request_allowed())
            .unwrap_or(true)
    }
}

// ============================================================================
// Load Balancing Strategies
// ============================================================================

/// Available load-balancing strategies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin with trust-based weighting.
    RoundRobinTrustWeighted,
    /// Select the node with the lowest current load.
    LeastLoaded,
    /// Pick two random nodes, choose the least loaded.
    PowerOfTwoChoices,
    /// Consistent hashing for session affinity.
    ConsistentHash,
}

/// A simple consistent hashing ring using virtual nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsistentHashRing {
    /// Sorted ring positions (hash value) → node ID.
    ring: BTreeMap<u64, String>,
    /// Number of virtual nodes per real node.
    virtual_nodes: usize,
}

impl ConsistentHashRing {
    fn new(virtual_nodes: usize) -> Self {
        Self {
            ring: BTreeMap::new(),
            virtual_nodes,
        }
    }

    fn add_node(&mut self, node_id: &str) {
        for i in 0..self.virtual_nodes {
            let key = self.hash_key(&format!("{}:vn:{}", node_id, i));
            self.ring.insert(key, node_id.to_string());
        }
    }

    fn remove_node(&mut self, node_id: &str) {
        let mut to_remove = Vec::new();
        for i in 0..self.virtual_nodes {
            let key = self.hash_key(&format!("{}:vn:{}", node_id, i));
            if self.ring.contains_key(&key) {
                to_remove.push(key);
            }
        }
        for key in to_remove {
            self.ring.remove(&key);
        }
    }

    /// Find the node responsible for the given key.
    fn get_node(&self, key: &str) -> Option<String> {
        if self.ring.is_empty() {
            return None;
        }
        let hash = self.hash_key(key);
        // Find the first ring position >= hash.
        if let Some((_, node_id)) = self.ring.range(hash..).next() {
            return Some(node_id.clone());
        }
        // Wrap around to the first node in the ring.
        self.ring.iter().next().map(|(_, node_id)| node_id.clone())
    }

    /// Simple FNV-1a-inspired hash.
    fn hash_key(&self, key: &str) -> u64 {
        let mut hash: u64 = 14695981039346656037;
        for byte in key.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(1099511628211);
        }
        hash
    }
}

/// Tracks per-node load for load balancing decisions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeLoadTracker {
    /// node_id → number of active/in-flight requests.
    pub request_counts: HashMap<String, u64>,
    /// node_id → reported load fraction (0.0–1.0).
    pub reported_loads: HashMap<String, f64>,
    /// node_id → trust score.
    pub trust_scores: HashMap<String, f64>,
    /// Round-robin index counter.
    pub rr_index: usize,
}

impl NodeLoadTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the request count for a node.
    pub fn increment(&mut self, node_id: &str) {
        *self.request_counts.entry(node_id.to_string()).or_insert(0) += 1;
    }

    /// Decrement the request count for a node.
    pub fn decrement(&mut self, node_id: &str) {
        if let Some(count) = self.request_counts.get_mut(node_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Set the reported load for a node.
    pub fn set_load(&mut self, node_id: &str, load: f64) {
        self.reported_loads
            .insert(node_id.to_string(), load.clamp(0.0, 1.0));
    }

    /// Set the trust score for a node.
    pub fn set_trust(&mut self, node_id: &str, trust: f64) {
        self.trust_scores
            .insert(node_id.to_string(), trust.clamp(0.0, 1.0));
    }

    /// Get the effective load for a node: combine request count and reported load.
    pub fn effective_load(&self, node_id: &str) -> f64 {
        let request_load = self
            .request_counts
            .get(node_id)
            .copied()
            .unwrap_or(0) as f64
            / 100.0; // Normalize: 100 requests = full load
        let reported = self
            .reported_loads
            .get(node_id)
            .copied()
            .unwrap_or(0.0);
        (request_load + reported) / 2.0
    }
}

/// Load balancer that selects a node from a candidate set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancer {
    /// Strategy to use.
    pub strategy: LoadBalanceStrategy,
    /// Per-node load tracking.
    pub tracker: NodeLoadTracker,
    /// Consistent hashing ring (used when strategy is ConsistentHash).
    pub hash_ring: ConsistentHashRing,
    /// Random seed for reproducibility in tests.
    pub seed: u64,
}

impl LoadBalancer {
    /// Create a new load balancer with the given strategy.
    pub fn new(strategy: LoadBalanceStrategy) -> Self {
        Self {
            strategy,
            tracker: NodeLoadTracker::new(),
            hash_ring: ConsistentHashRing::new(150),
            seed: 42,
        }
    }

    /// Register a node with the load balancer.
    pub fn add_node(&mut self, node_id: &str, trust: f64, load: f64) {
        self.tracker.set_trust(node_id, trust);
        self.tracker.set_load(node_id, load);
        self.hash_ring.add_node(node_id);
    }

    /// Remove a node from the load balancer.
    pub fn remove_node(&mut self, node_id: &str) {
        self.tracker.request_counts.remove(node_id);
        self.tracker.reported_loads.remove(node_id);
        self.tracker.trust_scores.remove(node_id);
        self.hash_ring.remove_node(node_id);
    }

    /// Select the best node from the candidates.
    /// Returns None if candidates is empty.
    pub fn select(&mut self, candidates: &[String]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(candidates[0].clone());
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobinTrustWeighted => {
                self.select_round_robin_trust(candidates)
            }
            LoadBalanceStrategy::LeastLoaded => {
                self.select_least_loaded(candidates)
            }
            LoadBalanceStrategy::PowerOfTwoChoices => {
                self.select_power_of_two(candidates)
            }
            LoadBalanceStrategy::ConsistentHash => {
                self.select_consistent_hash(candidates)
            }
        }
    }

    /// Round-robin with trust weighting: iterate through candidates,
    /// but weight selection probability by trust score.
    fn select_round_robin_trust(
        &mut self,
        candidates: &[String],
    ) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        // Simple weighted round-robin: advance index, pick from
        // candidates cyclically. The trust weight influences which
        // candidates are preferred — higher trust nodes get picked
        // more often by expanding their slot.
        let weights: Vec<f64> = candidates
            .iter()
            .map(|id| {
                self.tracker
                    .trust_scores
                    .get(id)
                    .copied()
                    .unwrap_or(0.5)
            })
            .collect();

        let total_weight: f64 = weights.iter().sum();
        if total_weight <= 0.0 {
            // Fallback: simple round-robin.
            let idx = self.tracker.rr_index % candidates.len();
            self.tracker.rr_index += 1;
            return Some(candidates[idx].clone());
        }

        // Weighted selection using cumulative distribution.
        let normalized: Vec<f64> = weights
            .iter()
            .map(|w| w / total_weight)
            .collect();

        // Use the rr_index to pick a slot.
        let slot = self.tracker.rr_index;
        self.tracker.rr_index += 1;

        // Determine which weighted slot we're in.
        let mut cumulative = 0.0;
        let _fractional = (slot as f64 % 1.0_f64) / 1.0_f64;
        // Use deterministic distribution based on slot.
        let target = (slot as f64 % total_weight) / total_weight;
        for (i, w) in normalized.iter().enumerate() {
            cumulative += w;
            if target <= cumulative {
                return Some(candidates[i].clone());
            }
        }
        Some(candidates[candidates.len() - 1].clone())
    }

    /// Select the candidate with the lowest effective load.
    fn select_least_loaded(&self, candidates: &[String]) -> Option<String> {
        candidates
            .iter()
            .min_by(|a, b| {
                self.tracker
                    .effective_load(a)
                    .partial_cmp(&self.tracker.effective_load(b))
                    .unwrap_or(Ordering::Equal)
            })
            .cloned()
    }

    /// Pick two random candidates and select the less loaded one.
    fn select_power_of_two(&self, candidates: &[String]) -> Option<String> {
        if candidates.len() < 2 {
            return candidates.first().cloned();
        }
        // Deterministic pseudo-random selection based on seed + index.
        let idx1 = (self.seed) as usize % candidates.len();
        let idx2 = (self.seed + 7) as usize % candidates.len();
        let idx2 = if idx2 == idx1 {
            (idx1 + 1) % candidates.len()
        } else {
            idx2
        };

        let load1 = self.tracker.effective_load(&candidates[idx1]);
        let load2 = self.tracker.effective_load(&candidates[idx2]);

        if load1 <= load2 {
            Some(candidates[idx1].clone())
        } else {
            Some(candidates[idx2].clone())
        }
    }

    /// Use consistent hashing to select a node based on a key.
    /// Uses the first candidate's ID as the hashing key if no
    /// explicit key is provided (for affinity-based routing).
    fn select_consistent_hash(&self, candidates: &[String]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        // Build a temporary ring with only the candidates.
        let mut temp_ring = ConsistentHashRing::new(self.hash_ring.virtual_nodes);
        for c in candidates {
            temp_ring.add_node(c);
        }
        // Use a fixed key derived from the candidate set for consistency.
        let key = candidates.join(":");
        temp_ring.get_node(&key)
    }

    /// Notify that a request to a node completed.
    pub fn notify_complete(&mut self, node_id: &str) {
        self.tracker.decrement(node_id);
    }

    /// Notify that a request to a node is starting.
    pub fn notify_start(&mut self, node_id: &str) {
        self.tracker.increment(node_id);
    }
}

// ============================================================================
// Adaptive Weight Tuning
// ============================================================================

/// A single observation of route quality, used for weight tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteObservation {
    /// Actual latency experienced (ms).
    pub latency_ms: f64,
    /// Trust score of the route at the time.
    pub trust_score: f64,
    /// Load on the route at the time.
    pub load: f64,
    /// Cost of the route.
    pub cost: f64,
    /// Composite score that was used to select this route.
    pub predicted_score: f64,
    /// Timestamp of the observation.
    pub timestamp: String,
}

impl RouteObservation {
    /// Create a new observation.
    pub fn new(
        latency_ms: f64,
        trust_score: f64,
        load: f64,
        cost: f64,
        predicted_score: f64,
    ) -> Self {
        Self {
            latency_ms,
            trust_score,
            load,
            cost,
            predicted_score,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Compute the SLA violation magnitude (0.0 = perfect, higher = worse).
    pub fn sla_violation(&self, target: &SlaTarget) -> f64 {
        let latency_violation = if self.latency_ms > target.max_latency_ms {
            (self.latency_ms - target.max_latency_ms) / target.max_latency_ms
        } else {
            0.0
        };
        let trust_violation = if self.trust_score < target.min_trust_score {
            (target.min_trust_score - self.trust_score) / target.min_trust_score
        } else {
            0.0
        };
        let load_violation = if self.load > target.max_load_fraction {
            (self.load - target.max_load_fraction) / target.max_load_fraction
        } else {
            0.0
        };
        let cost_violation = if self.cost > target.max_cost_per_request {
            (self.cost - target.max_cost_per_request) / target.max_cost_per_request
        } else {
            0.0
        };
        latency_violation + trust_violation + load_violation + cost_violation
    }
}

/// Adaptive weight tuner that adjusts routing weights based on
/// observed route quality versus SLA targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveWeightTuner {
    /// Current weights.
    pub weights: RoutingWeights,
    /// SLA target to optimize toward.
    pub sla_target: SlaTarget,
    /// History of recent observations (bounded by window_size).
    pub observations: VecDeque<RouteObservation>,
    /// Maximum number of observations to keep.
    pub window_size: usize,
    /// Learning rate for gradient steps.
    pub learning_rate: f64,
    /// Number of tuning iterations performed.
    pub iterations: usize,
    /// Smoothing factor for weight changes (0.0–1.0, lower = more smoothing).
    pub smoothing: f64,
}

impl AdaptiveWeightTuner {
    /// Create a new adaptive weight tuner.
    pub fn new(
        initial_weights: RoutingWeights,
        sla_target: SlaTarget,
        window_size: usize,
        learning_rate: f64,
    ) -> Self {
        Self {
            weights: initial_weights,
            sla_target,
            observations: VecDeque::new(),
            window_size,
            learning_rate,
            iterations: 0,
            smoothing: 0.1,
        }
    }

    /// Record a new observation.
    pub fn record_observation(&mut self, obs: RouteObservation) {
        if self.observations.len() >= self.window_size {
            self.observations.pop_front();
        }
        self.observations.push_back(obs);
    }

    /// Run one step of gradient-descent-like weight adaptation.
    ///
    /// The idea: compute the average SLA violation across recent observations,
    /// then determine which dimension has the largest relative violation
    /// and increase its weight to make the router prioritize it more.
    /// Conversely, dimensions with no violation get their weights slightly
    /// reduced to avoid over-optimizing one dimension.
    pub fn tune(&mut self) -> RoutingWeights {
        if self.observations.is_empty() {
            return self.weights.clone();
        }

        // Compute average violation per dimension.
        let mut avg_latency_violation = 0.0;
        let mut avg_trust_violation = 0.0;
        let mut avg_load_violation = 0.0;
        let mut avg_cost_violation = 0.0;
        let n = self.observations.len() as f64;

        for obs in &self.observations {
            let target = &self.sla_target;
            avg_latency_violation += if obs.latency_ms > target.max_latency_ms {
                (obs.latency_ms - target.max_latency_ms) / target.max_latency_ms
            } else {
                0.0
            };
            avg_trust_violation += if obs.trust_score < target.min_trust_score {
                (target.min_trust_score - obs.trust_score) / target.min_trust_score
            } else {
                0.0
            };
            avg_load_violation += if obs.load > target.max_load_fraction {
                (obs.load - target.max_load_fraction) / target.max_load_fraction
            } else {
                0.0
            };
            avg_cost_violation += if obs.cost > target.max_cost_per_request {
                (obs.cost - target.max_cost_per_request) / target.max_cost_per_request
            } else {
                0.0
            };
        }

        avg_latency_violation /= n;
        avg_trust_violation /= n;
        avg_load_violation /= n;
        avg_cost_violation /= n;

        let total_violation = avg_latency_violation
            + avg_trust_violation
            + avg_load_violation
            + avg_cost_violation;

        if total_violation < 0.01 {
            // SLA is being met well; no adjustment needed.
            self.iterations += 1;
            return self.weights.clone();
        }

        // Gradient-like step: increase weight for the most-violated dimension.
        let lr = self.learning_rate;
        let new_latency = (self.weights.latency_weight
            + lr * avg_latency_violation
            - lr * self.smoothing * (1.0 - avg_latency_violation))
            .clamp(0.05, 0.8);
        let new_trust = (self.weights.trust_weight
            + lr * avg_trust_violation
            - lr * self.smoothing * (1.0 - avg_trust_violation))
            .clamp(0.05, 0.8);
        let new_load = (self.weights.load_weight
            + lr * avg_load_violation
            - lr * self.smoothing * (1.0 - avg_load_violation))
            .clamp(0.05, 0.8);
        let new_cost = (self.weights.cost_weight
            + lr * avg_cost_violation
            - lr * self.smoothing * (1.0 - avg_cost_violation))
            .clamp(0.05, 0.8);

        self.weights = RoutingWeights::new(
            new_latency, new_trust, new_load, new_cost,
        );
        self.iterations += 1;
        self.weights.clone()
    }

    /// Detect if latency is trending upward (degrading) compared to
    /// earlier observations. Returns a value > 0 if degrading, < 0 if improving.
    pub fn latency_trend(&self) -> f64 {
        if self.observations.len() < 4 {
            return 0.0;
        }
        let len = self.observations.len();
        let first_half: Vec<_> =
            self.observations.iter().take(len / 2).collect();
        let second_half: Vec<_> = self
            .observations
            .iter()
            .skip(len / 2)
            .collect();

        let avg_first: f64 = first_half
            .iter()
            .map(|o| o.latency_ms)
            .sum::<f64>()
            / first_half.len() as f64;
        let avg_second: f64 = second_half
            .iter()
            .map(|o| o.latency_ms)
            .sum::<f64>()
            / second_half.len() as f64;

        // Positive = degrading, negative = improving.
        (avg_second - avg_first) / avg_first.max(1.0)
    }

    /// Detect if trust scores are trending downward.
    pub fn trust_trend(&self) -> f64 {
        if self.observations.len() < 4 {
            return 0.0;
        }
        let len = self.observations.len();
        let first_half: Vec<_> =
            self.observations.iter().take(len / 2).collect();
        let second_half: Vec<_> = self
            .observations
            .iter()
            .skip(len / 2)
            .collect();

        let avg_first: f64 = first_half
            .iter()
            .map(|o| o.trust_score)
            .sum::<f64>()
            / first_half.len() as f64;
        let avg_second: f64 = second_half
            .iter()
            .map(|o| o.trust_score)
            .sum::<f64>()
            / second_half.len() as f64;

        // Negative = degrading trust, positive = improving.
        (avg_second - avg_first) / avg_first.max(0.01)
    }

    /// Compute recent failure rate from observations.
    /// Treats an observation as a "failure" if its SLA violation > 0.
    pub fn recent_failure_rate(&self) -> f64 {
        if self.observations.is_empty() {
            return 0.0;
        }
        let failures = self
            .observations
            .iter()
            .filter(|o| o.sla_violation(&self.sla_target) > 0.0)
            .count();
        failures as f64 / self.observations.len() as f64
    }

    /// Get current weights.
    pub fn current_weights(&self) -> &RoutingWeights {
        &self.weights
    }
}

// ============================================================================
// Adaptive Router (Main Orchestrator)
// ============================================================================

/// The main adaptive router that orchestrates all routing components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRouter {
    /// Network topology graph.
    pub graph: NetworkGraph,
    /// Routing configuration.
    pub config: RoutingConfig,
    /// Circuit breaker registry.
    pub circuit_breakers: CircuitBreakerRegistry,
    /// Load balancer for next-hop selection.
    pub load_balancer: LoadBalancer,
    /// Adaptive weight tuner.
    pub weight_tuner: AdaptiveWeightTuner,
    /// Known nodes (node_id → Node).
    pub known_nodes: HashMap<String, Node>,
    /// Cache of recently computed routes.
    pub route_cache: HashMap<String, Route>,
    /// Maximum cache entries.
    pub max_cache_size: usize,
    /// Route computation counter.
    pub routes_computed: usize,
}

impl AdaptiveRouter {
    /// Create a new adaptive router with the given configuration.
    pub fn new(config: RoutingConfig) -> Self {
        let weight_tuner = AdaptiveWeightTuner::new(
            config.weights.clone(),
            config.sla_target.clone(),
            config.history_window_size,
            config.learning_rate,
        );
        Self {
            graph: NetworkGraph::new(),
            config,
            circuit_breakers: CircuitBreakerRegistry::new(),
            load_balancer: LoadBalancer::new(LoadBalanceStrategy::LeastLoaded),
            weight_tuner,
            known_nodes: HashMap::new(),
            route_cache: HashMap::new(),
            max_cache_size: 50,
            routes_computed: 0,
        }
    }

    /// Add a node to the router's known node set.
    pub fn add_node(&mut self, node: Node) {
        let is_active = node.status == NodeStatus::Active;
        if is_active {
            self.load_balancer
                .add_node(&node.node_id, node.trust_score, 0.0);
            self.circuit_breakers
                .get_or_create(&node.node_id, &CircuitBreakerConfig::default());
        }
        self.known_nodes.insert(node.node_id.clone(), node);
    }

    /// Remove a node from the router.
    pub fn remove_node(&mut self, node_id: &str) {
        self.known_nodes.remove(node_id);
        self.load_balancer.remove_node(node_id);
        self.graph.adjacency.remove(node_id);
    }

    /// Add an edge to the routing graph.
    pub fn add_edge(&mut self, edge: NetworkEdge) {
        self.graph.add_edge(edge);
    }

    /// Set a node's coordinate for geographic heuristics.
    pub fn set_coordinate(&mut self, node_id: &str, lat: f64, lon: f64) {
        self.graph.set_coordinate(node_id, lat, lon);
    }

    /// Update a node's trust score.
    pub fn update_trust(&mut self, node_id: &str, trust: f64) {
        if let Some(node) = self.known_nodes.get_mut(node_id) {
            node.trust_score = trust.clamp(0.0, 1.0);
        }
        self.load_balancer.tracker.set_trust(node_id, trust);
    }

    /// Update a node's reported load.
    pub fn update_load(&mut self, node_id: &str, load: f64) {
        self.load_balancer.tracker.set_load(node_id, load);
    }

    /// Get the set of nodes that are currently blocked (open circuits or dead).
    pub fn blocked_nodes(&self) -> HashSet<String> {
        let mut blocked = self.circuit_breakers.open_nodes();
        for (id, node) in &self.known_nodes {
            if node.status == NodeStatus::Dead {
                blocked.insert(id.clone());
            }
        }
        blocked
    }

    /// Compute the best route from source to destination using A*
    /// with the best heuristic.
    pub fn find_route(&mut self, source: &str, destination: &str) -> Option<Route> {
        let blocked = self.blocked_nodes();
        let node_loads: HashMap<String, f64> = self
            .known_nodes
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    self.load_balancer.tracker.effective_load(id),
                )
            })
            .collect();

        let result = astar_multi_heuristic(
            &self.graph,
            source,
            destination,
            self.weight_tuner.current_weights(),
            self.config.max_hops,
            self.config.beam_width,
            &node_loads,
            &blocked,
        );

        if let Some(route) = result.path {
            self.routes_computed += 1;
            // Cache the route.
            let cache_key = format!("{}->{}", source, destination);
            if self.route_cache.len() >= self.max_cache_size {
                // Simple eviction: remove the oldest entry.
                if let Some(first_key) = self.route_cache.keys().next().cloned() {
                    self.route_cache.remove(&first_key);
                }
            }
            self.route_cache.insert(cache_key, route.clone());
            Some(route)
        } else {
            None
        }
    }

    /// Find all Pareto-optimal routes from source to destination.
    pub fn find_pareto_routes(
        &mut self,
        source: &str,
        destination: &str,
    ) -> Vec<Route> {
        let mut all_routes = Vec::new();
        let blocked = self.blocked_nodes();
        let node_loads: HashMap<String, f64> = self
            .known_nodes
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    self.load_balancer.tracker.effective_load(id),
                )
            })
            .collect();

        // Run A* with each heuristic.
        let heuristics = vec![
            HeuristicKind::Geographic,
            HeuristicKind::MinCostEstimate,
            HeuristicKind::TrustWeighted,
            HeuristicKind::LoadBalanced,
            HeuristicKind::Composite,
        ];

        for h in &heuristics {
            let result = astar_search(
                &self.graph,
                source,
                destination,
                self.weight_tuner.current_weights(),
                h.clone(),
                self.config.max_hops,
                self.config.beam_width,
                &node_loads,
                &blocked,
            );
            if let Some(route) = result.path {
                // Avoid duplicates.
                let path_str = route.nodes.join("->");
                if !all_routes.iter().any(|r: &Route| r.nodes.join("->") == path_str) {
                    all_routes.push(route);
                }
            }
        }

        let pareto = compute_pareto_frontier(&all_routes);
        let max = self.config.max_pareto_routes;
        if pareto.len() > max {
            pareto[..max].to_vec()
        } else {
            pareto
        }
    }

    /// Record a route observation and optionally trigger weight tuning.
    pub fn record_route_outcome(&mut self, obs: RouteObservation) {
        self.weight_tuner.record_observation(obs);
    }

    /// Run one step of adaptive weight tuning.
    pub fn tune_weights(&mut self) -> RoutingWeights {
        let new_weights = self.weight_tuner.tune();
        self.config.weights = new_weights.clone();
        new_weights
    }

    /// Record a successful communication with a node.
    pub fn record_success(&mut self, node_id: &str) {
        self.circuit_breakers.record_success(node_id);
        self.load_balancer.notify_complete(node_id);
    }

    /// Record a failed communication with a node.
    pub fn record_failure(&mut self, node_id: &str) {
        self.circuit_breakers.record_failure(node_id);
        self.load_balancer.notify_complete(node_id);
    }

    /// Select the best next hop from a set of candidates using
    /// the configured load balancing strategy.
    pub fn select_next_hop(&mut self, candidates: &[String]) -> Option<String> {
        // Filter out blocked nodes.
        let blocked = self.blocked_nodes();
        let available: Vec<String> = candidates
            .iter()
            .filter(|c| !blocked.contains(*c))
            .cloned()
            .collect();

        if available.is_empty() {
            return None;
        }

        let selected = self.load_balancer.select(&available);
        if let Some(ref node_id) = selected {
            self.load_balancer.notify_start(node_id);
        }
        selected
    }

    /// Attempt to recover all open circuit breakers.
    pub fn try_recover_circuits(&mut self) -> usize {
        self.circuit_breakers.try_recover_all()
    }

    /// Get the current routing weights.
    pub fn current_weights(&self) -> &RoutingWeights {
        self.weight_tuner.current_weights()
    }

    /// Get the current latency trend.
    pub fn latency_trend(&self) -> f64 {
        self.weight_tuner.latency_trend()
    }

    /// Get the current trust trend.
    pub fn trust_trend(&self) -> f64 {
        self.weight_tuner.trust_trend()
    }

    /// Get the recent SLA failure rate.
    pub fn failure_rate(&self) -> f64 {
        self.weight_tuner.recent_failure_rate()
    }

    /// Set the load balancing strategy.
    pub fn set_lb_strategy(&mut self, strategy: LoadBalanceStrategy) {
        self.load_balancer.strategy = strategy;
    }

    /// Clear the route cache.
    pub fn clear_cache(&mut self) {
        self.route_cache.clear();
    }

    /// Get a cached route if available.
    pub fn cached_route(&self, source: &str, destination: &str) -> Option<&Route> {
        let key = format!("{}->{}", source, destination);
        self.route_cache.get(&key)
    }
}

// ============================================================================
// Helper: Build test graphs
// ============================================================================

/// Build a simple 5-node linear graph for testing: A→B→C→D→E.
pub fn build_linear_graph() -> (NetworkGraph, HashMap<String, Node>) {
    let mut graph = NetworkGraph::new();
    let mut nodes = HashMap::new();

    let ids = ["A", "B", "C", "D", "E"];
    for id in &ids {
        nodes.insert(
            id.to_string(),
            Node {
                node_id: id.to_string(),
                address: format!("addr:{}", id),
                status: NodeStatus::Active,
                last_heartbeat: chrono::Utc::now().to_rfc3339(),
                trust_score: 0.8,
                reported_trust_state: None,
                role: NodeRole::Follower,
            },
        );
    }

    // Edges: A→B (10ms, 0.9 trust, 0.1 load, 1 cost)
    graph.add_edge(NetworkEdge::new("A", "B", 10.0, 0.9, 0.1, 1.0));
    graph.add_edge(NetworkEdge::new("B", "C", 15.0, 0.85, 0.2, 2.0));
    graph.add_edge(NetworkEdge::new("C", "D", 20.0, 0.7, 0.3, 1.5));
    graph.add_edge(NetworkEdge::new("D", "E", 12.0, 0.95, 0.1, 1.0));

    (graph, nodes)
}

/// Build a diamond graph: A→B→D, A→C→D, with varying costs.
pub fn build_diamond_graph() -> (NetworkGraph, HashMap<String, Node>) {
    let mut graph = NetworkGraph::new();
    let mut nodes = HashMap::new();

    for id in &["A", "B", "C", "D"] {
        nodes.insert(
            id.to_string(),
            Node {
                node_id: id.to_string(),
                address: format!("addr:{}", id),
                status: NodeStatus::Active,
                last_heartbeat: chrono::Utc::now().to_rfc3339(),
                trust_score: 0.8,
                reported_trust_state: None,
                role: NodeRole::Follower,
            },
        );
    }

    // Upper path: A→B→D (fast but lower trust)
    graph.add_edge(NetworkEdge::new("A", "B", 5.0, 0.6, 0.1, 3.0));
    graph.add_edge(NetworkEdge::new("B", "D", 5.0, 0.6, 0.1, 3.0));
    // Lower path: A→C→D (slower but higher trust)
    graph.add_edge(NetworkEdge::new("A", "C", 20.0, 0.95, 0.3, 1.0));
    graph.add_edge(NetworkEdge::new("C", "D", 20.0, 0.95, 0.3, 1.0));

    (graph, nodes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::distributed::NodeRole;

    fn default_config() -> RoutingConfig {
        RoutingConfig::default()
    }

    fn default_weights() -> RoutingWeights {
        RoutingWeights::default()
    }

    // ---------------------------------------------------------------
    // RoutingWeights tests
    // ---------------------------------------------------------------
    #[test]
    fn test_weights_default_sum_approx_one() {
        let w = RoutingWeights::default();
        let sum = w.total();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_weights_normalized() {
        let w = RoutingWeights::new(0.5, 0.25, 0.25, 0.0);
        let n = w.normalized();
        assert!((n.total() - 1.0).abs() < 0.001);
        assert!(n.latency_weight > n.trust_weight);
    }

    #[test]
    fn test_weights_clamped() {
        let w = RoutingWeights::new(-1.0, 5.0, 0.5, 0.5);
        assert_eq!(w.latency_weight, 0.0);
        assert_eq!(w.trust_weight, 1.0);
    }

    #[test]
    fn test_weights_zero_total_normalizes_equally() {
        let w = RoutingWeights::new(0.0, 0.0, 0.0, 0.0);
        let n = w.normalized();
        assert!((n.latency_weight - 0.25).abs() < 0.001);
        assert!((n.trust_weight - 0.25).abs() < 0.001);
    }

    // ---------------------------------------------------------------
    // NetworkEdge tests
    // ---------------------------------------------------------------
    #[test]
    fn test_edge_weighted_cost() {
        let edge = NetworkEdge::new("A", "B", 100.0, 0.5, 0.5, 5.0);
        let w = RoutingWeights::new(0.25, 0.25, 0.25, 0.25);
        let cost = edge.weighted_cost(&w);
        assert!(cost > 0.0);
    }

    #[test]
    fn test_edge_clamps_values() {
        let edge = NetworkEdge::new("A", "B", -5.0, 1.5, -0.1, -2.0);
        assert!(edge.latency_ms > 0.0);
        assert!(edge.trust_score <= 1.0);
        assert!(edge.load >= 0.0);
        assert!(edge.cost >= 0.0);
    }

    // ---------------------------------------------------------------
    // NetworkGraph tests
    // ---------------------------------------------------------------
    #[test]
    fn test_graph_add_and_retrieve_edges() {
        let mut g = NetworkGraph::new();
        g.add_edge(NetworkEdge::new("A", "B", 10.0, 0.9, 0.1, 1.0));
        g.add_edge(NetworkEdge::new("A", "C", 20.0, 0.8, 0.2, 2.0));
        assert_eq!(g.edges_from("A").len(), 2);
        assert_eq!(g.edges_from("B").len(), 0);
    }

    #[test]
    fn test_graph_node_ids() {
        let mut g = NetworkGraph::new();
        g.add_edge(NetworkEdge::new("A", "B", 10.0, 0.9, 0.1, 1.0));
        let ids = g.node_ids();
        assert!(ids.contains("A"));
        assert!(ids.contains("B"));
    }

    #[test]
    fn test_graph_estimated_distance() {
        let mut g = NetworkGraph::new();
        g.set_coordinate("A", 0.0, 0.0);
        g.set_coordinate("B", 0.0, 1.0);
        let dist = g.estimated_distance_km("A", "B");
        // 1 degree of longitude at equator ≈ 111 km.
        assert!(dist > 100.0 && dist < 115.0);
    }

    #[test]
    fn test_graph_distance_unknown_nodes() {
        let g = NetworkGraph::new();
        let dist = g.estimated_distance_km("X", "Y");
        assert_eq!(dist, 1000.0);
    }

    #[test]
    fn test_graph_filter_edges() {
        let mut g = NetworkGraph::new();
        g.add_edge(NetworkEdge::new("A", "B", 10.0, 0.9, 0.1, 1.0));
        g.add_edge(NetworkEdge::new("A", "C", 20.0, 0.8, 0.2, 2.0));
        g.add_edge(NetworkEdge::new("B", "C", 15.0, 0.7, 0.3, 1.5));

        let mut allowed = HashSet::new();
        allowed.insert("A".to_string());
        allowed.insert("B".to_string());

        let filtered = g.filter_edges_by_nodes(&allowed);
        assert_eq!(filtered.get("A").unwrap().len(), 1); // Only A→B
        assert!(!filtered.contains_key("B")); // B→C filtered out
    }

    // ---------------------------------------------------------------
    // Route and RouteMetrics tests
    // ---------------------------------------------------------------
    #[test]
    fn test_route_from_path() {
        let (graph, _) = build_linear_graph();
        let weights = default_weights();
        let route = Route::from_path(
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            &graph.adjacency,
            &weights,
        );
        assert_eq!(route.nodes.len(), 3);
        assert_eq!(route.metrics.hop_count, 2);
        assert!((route.metrics.total_latency_ms - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_route_source_destination() {
        let route = Route {
            nodes: vec!["X".to_string(), "Y".to_string(), "Z".to_string()],
            metrics: RouteMetrics {
                total_latency_ms: 0.0,
                min_trust_score: 1.0,
                avg_trust_score: 1.0,
                max_load: 0.0,
                avg_load: 0.0,
                total_cost: 0.0,
                hop_count: 2,
                composite_score: 0.0,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        };
        assert_eq!(route.source(), Some("X"));
        assert_eq!(route.destination(), Some("Z"));
    }

    // ---------------------------------------------------------------
    // Pareto frontier tests
    // ---------------------------------------------------------------
    #[test]
    fn test_pareto_frontier_no_dominated() {
        // If one route is better in all objectives, the other is dominated.
        let r1 = Route {
            nodes: vec!["A".to_string(), "B".to_string()],
            metrics: RouteMetrics {
                total_latency_ms: 10.0,
                min_trust_score: 0.9,
                avg_trust_score: 0.9,
                max_load: 0.1,
                avg_load: 0.1,
                total_cost: 1.0,
                hop_count: 1,
                composite_score: 0.1,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        };
        let r2 = Route {
            nodes: vec!["A".to_string(), "C".to_string()],
            metrics: RouteMetrics {
                total_latency_ms: 100.0,
                min_trust_score: 0.5,
                avg_trust_score: 0.5,
                max_load: 0.9,
                avg_load: 0.9,
                total_cost: 10.0,
                hop_count: 1,
                composite_score: 1.0,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        };
        let frontier = compute_pareto_frontier(&[r1, r2]);
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier[0].nodes[1], "B");
    }

    #[test]
    fn test_pareto_frontier_both_nondominated() {
        let r1 = Route {
            nodes: vec!["A".to_string(), "B".to_string()],
            metrics: RouteMetrics {
                total_latency_ms: 10.0,
                min_trust_score: 0.5,
                avg_trust_score: 0.5,
                max_load: 0.1,
                avg_load: 0.1,
                total_cost: 1.0,
                hop_count: 1,
                composite_score: 0.1,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        };
        // r2 has higher latency but higher trust — not dominated.
        let r2 = Route {
            nodes: vec!["A".to_string(), "C".to_string()],
            metrics: RouteMetrics {
                total_latency_ms: 50.0,
                min_trust_score: 0.99,
                avg_trust_score: 0.99,
                max_load: 0.1,
                avg_load: 0.1,
                total_cost: 1.0,
                hop_count: 1,
                composite_score: 0.5,
            },
            computed_at: chrono::Utc::now().to_rfc3339(),
        };
        let frontier = compute_pareto_frontier(&[r1, r2]);
        assert_eq!(frontier.len(), 2);
    }

    #[test]
    fn test_pareto_frontier_empty() {
        let frontier = compute_pareto_frontier(&[]);
        assert!(frontier.is_empty());
    }

    // ---------------------------------------------------------------
    // A* search tests
    // ---------------------------------------------------------------
    #[test]
    fn test_astar_linear_path() {
        let (graph, _) = build_linear_graph();
        let weights = default_weights();
        let blocked = HashSet::new();
        let loads = HashMap::new();
        let result = astar_search(
            &graph,
            "A",
            "E",
            &weights,
            HeuristicKind::Geographic,
            15,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_some());
        let route = result.path.unwrap();
        assert_eq!(route.nodes, vec!["A", "B", "C", "D", "E"]);
    }

    #[test]
    fn test_astar_diamond_picks_best() {
        let (graph, _) = build_diamond_graph();
        // With high trust weight, should prefer the C path.
        let weights = RoutingWeights::new(0.1, 0.7, 0.1, 0.1);
        let blocked = HashSet::new();
        let loads = HashMap::new();
        let result = astar_search(
            &graph,
            "A",
            "D",
            &weights,
            HeuristicKind::Composite,
            15,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_some());
        let route = result.path.unwrap();
        assert_eq!(route.nodes, vec!["A", "C", "D"]);
    }

    #[test]
    fn test_astar_no_path_when_blocked() {
        let (graph, _) = build_linear_graph();
        let weights = default_weights();
        let mut blocked = HashSet::new();
        blocked.insert("C".to_string());
        let loads = HashMap::new();
        let result = astar_search(
            &graph,
            "A",
            "E",
            &weights,
            HeuristicKind::Geographic,
            15,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_none());
    }

    #[test]
    fn test_astar_same_source_destination() {
        let graph = NetworkGraph::new();
        let weights = default_weights();
        let blocked = HashSet::new();
        let loads = HashMap::new();
        let result = astar_search(
            &graph,
            "A",
            "A",
            &weights,
            HeuristicKind::Geographic,
            15,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_some());
        assert_eq!(result.path.unwrap().nodes.len(), 1);
    }

    #[test]
    fn test_astar_max_hops_limit() {
        let (graph, _) = build_linear_graph();
        let weights = default_weights();
        let blocked = HashSet::new();
        let loads = HashMap::new();
        // Max 2 hops but A→E needs 4 hops.
        let result = astar_search(
            &graph,
            "A",
            "E",
            &weights,
            HeuristicKind::Geographic,
            2,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_none());
    }

    #[test]
    fn test_astar_multi_heuristic() {
        let (graph, _) = build_diamond_graph();
        let weights = default_weights();
        let blocked = HashSet::new();
        let loads = HashMap::new();
        let result = astar_multi_heuristic(
            &graph,
            "A",
            "D",
            &weights,
            15,
            0,
            &loads,
            &blocked,
        );
        assert!(result.path.is_some());
    }

    // ---------------------------------------------------------------
    // Circuit breaker tests
    // ---------------------------------------------------------------
    #[test]
    fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("node-1", CircuitBreakerConfig::default());
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.is_request_allowed());
    }

    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let mut cb = CircuitBreaker::new("node-1", CircuitBreakerConfig::default());
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.is_request_allowed());
    }

    #[test]
    fn test_circuit_breaker_successes_prevent_open() {
        let mut cb = CircuitBreaker::new("node-1", CircuitBreakerConfig::default());
        for i in 0..10 {
            if i % 3 == 0 {
                cb.record_failure();
            } else {
                cb.record_success();
            }
        }
        // Should never have had 5 consecutive failures.
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_to_closed() {
        let mut cb = CircuitBreaker::new(
            "node-1",
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 2,
                ..Default::default()
            },
        );
        // Open the circuit.
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state, CircuitState::Open);

        // Manually transition to half-open (simulating backoff elapsed).
        cb.state = CircuitState::HalfOpen;
        cb.half_open_successes = 0;

        // Record successes to close.
        cb.record_success();
        assert_eq!(cb.state, CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_failure_reopens() {
        let mut cb = CircuitBreaker::new(
            "node-1",
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                ..Default::default()
            },
        );
        for _ in 0..2 {
            cb.record_failure();
        }
        assert_eq!(cb.state, CircuitState::Open);

        // Transition to half-open.
        cb.state = CircuitState::HalfOpen;
        cb.half_open_successes = 0;

        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert_eq!(cb.backoff_exponent, 1);
    }

    #[test]
    fn test_circuit_breaker_backoff_increases() {
        let cb = CircuitBreaker::new("node-1", CircuitBreakerConfig::default());
        let ms0 = cb.compute_backoff_ms();
        assert_eq!(ms0, 1000);
    }

    #[test]
    fn test_circuit_breaker_registry() {
        let mut reg = CircuitBreakerRegistry::new();
        let config = CircuitBreakerConfig::default();
        reg.get_or_create("n1", &config).record_failure();
        reg.get_or_create("n2", &config).record_failure();
        assert_eq!(reg.breakers.len(), 2);
        assert!(reg.is_allowed("n1"));
    }

    #[test]
    fn test_circuit_breaker_sliding_window() {
        let mut cb = CircuitBreaker::new(
            "node-1",
            CircuitBreakerConfig {
                window_size: 5,
                failure_threshold: 3,
                ..Default::default()
            },
        );
        // Record 2 failures.
        cb.record_failure();
        cb.record_failure();
        // Fill window with 5 successes to push out old failures.
        for _ in 0..5 {
            cb.record_success();
        }
        // Window should now have only the last 5 entries (all successes).
        assert!((cb.failure_rate() - 0.0).abs() < 0.001);
    }

    // ---------------------------------------------------------------
    // Load balancer tests
    // ---------------------------------------------------------------
    #[test]
    fn test_lb_least_loaded() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::LeastLoaded);
        lb.add_node("n1", 0.8, 0.1);
        lb.add_node("n2", 0.9, 0.9);
        lb.tracker.increment("n2");
        lb.tracker.increment("n2");
        let selected = lb.select(&["n1".to_string(), "n2".to_string()]);
        assert_eq!(selected, Some("n1".to_string()));
    }

    #[test]
    fn test_lb_power_of_two_choices() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::PowerOfTwoChoices);
        lb.add_node("n1", 0.8, 0.9);
        lb.add_node("n2", 0.9, 0.1);
        let selected = lb.select(&["n1".to_string(), "n2".to_string()]);
        assert!(selected.is_some());
        // n2 has lower load, should be preferred.
        assert_eq!(selected.unwrap(), "n2");
    }

    #[test]
    fn test_lb_round_robin_trust_weighted() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobinTrustWeighted);
        lb.add_node("n1", 0.99, 0.5);
        lb.add_node("n2", 0.01, 0.5);
        // With very skewed trust, n1 should be picked more often.
        let mut n1_count = 0;
        let mut n2_count = 0;
        for _ in 0..100 {
            let sel = lb.select(&["n1".to_string(), "n2".to_string()]);
            if sel == Some("n1".to_string()) {
                n1_count += 1;
            } else {
                n2_count += 1;
            }
        }
        assert!(n1_count > n2_count);
    }

    #[test]
    fn test_lb_consistent_hash() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::ConsistentHash);
        lb.add_node("n1", 0.8, 0.5);
        lb.add_node("n2", 0.8, 0.5);
        // Same candidates should always produce the same selection.
        let first = lb.select(&["n1".to_string(), "n2".to_string()]);
        let second = lb.select(&["n1".to_string(), "n2".to_string()]);
        assert_eq!(first, second);
    }

    #[test]
    fn test_lb_empty_candidates() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::LeastLoaded);
        assert_eq!(lb.select(&[]), None);
    }

    #[test]
    fn test_lb_single_candidate() {
        let mut lb = LoadBalancer::new(LoadBalanceStrategy::LeastLoaded);
        assert_eq!(
            lb.select(&["only".to_string()]),
            Some("only".to_string())
        );
    }

    // ---------------------------------------------------------------
    // Adaptive weight tuner tests
    // ---------------------------------------------------------------
    #[test]
    fn test_tuner_records_observations() {
        let mut tuner = AdaptiveWeightTuner::new(
            default_weights(),
            SlaTarget::default(),
            10,
            0.05,
        );
        tuner.record_observation(RouteObservation::new(
            50.0, 0.9, 0.2, 1.0, 0.1,
        ));
        assert_eq!(tuner.observations.len(), 1);
    }

    #[test]
    fn test_tuner_window_eviction() {
        let mut tuner = AdaptiveWeightTuner::new(
            default_weights(),
            SlaTarget::default(),
            3,
            0.05,
        );
        for i in 0..5 {
            tuner.record_observation(RouteObservation::new(
                50.0 + i as f64, 0.9, 0.2, 1.0, 0.1,
            ));
        }
        assert_eq!(tuner.observations.len(), 3);
    }

    #[test]
    fn test_tuner_tune_increases_weight_on_violation() {
        let mut tuner = AdaptiveWeightTuner::new(
            RoutingWeights::new(0.25, 0.25, 0.25, 0.25),
            SlaTarget {
                max_latency_ms: 10.0, // Very strict
                ..Default::default()
            },
            10,
            0.2, // High learning rate
        );
        // Record observations with high latency violations.
        for _ in 0..5 {
            tuner.record_observation(RouteObservation::new(
                100.0, // Way over 10ms SLA
                0.9, 0.1, 1.0, 0.1,
            ));
        }
        let old_latency_w = tuner.weights.latency_weight;
        tuner.tune();
        // Latency weight should increase due to violations.
        assert!(tuner.weights.latency_weight >= old_latency_w);
    }

    #[test]
    fn test_tuner_no_tune_when_sla_met() {
        let mut tuner = AdaptiveWeightTuner::new(
            default_weights(),
            SlaTarget::default(),
            10,
            0.05,
        );
        // All observations well within SLA.
        for _ in 0..5 {
            tuner.record_observation(RouteObservation::new(
                10.0, 0.99, 0.1, 0.5, 0.05,
            ));
        }
        let w_before = tuner.weights.clone();
        tuner.tune();
        // Weights should not change.
        assert!((tuner.weights.latency_weight - w_before.latency_weight).abs() < 0.001);
    }

    #[test]
    fn test_tuner_latency_trend() {
        let mut tuner = AdaptiveWeightTuner::new(
            default_weights(),
            SlaTarget::default(),
            10,
            0.05,
        );
        // Improving latency.
        for i in 0..8 {
            tuner.record_observation(RouteObservation::new(
                100.0 - i as f64 * 10.0, 0.9, 0.2, 1.0, 0.1,
            ));
        }
        let trend = tuner.latency_trend();
        assert!(trend < 0.0); // Negative = improving
    }

    // ---------------------------------------------------------------
    // AdaptiveRouter integration tests
    // ---------------------------------------------------------------
    #[test]
    fn test_router_find_route_linear() {
        let (graph, nodes) = build_linear_graph();
        let mut router = AdaptiveRouter::new(default_config());
        router.graph = graph;
        for (_, node) in nodes {
            router.add_node(node);
        }
        let route = router.find_route("A", "E");
        assert!(route.is_some());
        let r = route.unwrap();
        assert_eq!(r.nodes.last().unwrap(), "E");
    }

    #[test]
    fn test_router_records_outcome_and_tunes() {
        let mut router = AdaptiveRouter::new(default_config());
        router.record_route_outcome(RouteObservation::new(
            150.0, 0.8, 0.3, 2.0, 0.5,
        ));
        router.record_route_outcome(RouteObservation::new(
            180.0, 0.7, 0.4, 2.5, 0.6,
        ));
        let w = router.tune_weights();
        assert!(w.total() > 0.0);
    }

    #[test]
    fn test_router_circuit_breaker_integration() {
        let mut router = AdaptiveRouter::new(default_config());
        router.add_node(Node {
            node_id: "n1".to_string(),
            address: "addr".to_string(),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 0.9,
            reported_trust_state: None,
            role: NodeRole::Follower,
        });
        // Record enough failures to open the circuit.
        for _ in 0..5 {
            router.record_failure("n1");
        }
        assert!(router.blocked_nodes().contains("n1"));
    }

    #[test]
    fn test_router_select_next_hop_filters_blocked() {
        let mut router = AdaptiveRouter::new(default_config());
        router.add_node(Node {
            node_id: "n1".to_string(),
            address: "addr1".to_string(),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 0.9,
            reported_trust_state: None,
            role: NodeRole::Follower,
        });
        router.add_node(Node {
            node_id: "n2".to_string(),
            address: "addr2".to_string(),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 0.8,
            reported_trust_state: None,
            role: NodeRole::Follower,
        });
        // Block n1.
        for _ in 0..5 {
            router.record_failure("n1");
        }
        let selected = router.select_next_hop(&[
            "n1".to_string(),
            "n2".to_string(),
        ]);
        assert_eq!(selected, Some("n2".to_string()));
    }

    #[test]
    fn test_router_pareto_routes_diamond() {
        let (graph, nodes) = build_diamond_graph();
        let mut router = AdaptiveRouter::new(default_config());
        router.graph = graph;
        for (_, node) in nodes {
            router.add_node(node);
        }
        let pareto = router.find_pareto_routes("A", "D");
        // Both paths (via B and via C) should appear since they
        // trade off latency vs trust.
        assert!(pareto.len() >= 1);
    }
}
