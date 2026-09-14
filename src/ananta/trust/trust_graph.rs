// Trust Graph — entity-to-entity trust relationships.
//
// Not a simple trust score. A LIVING trust network.
//
// Nodes: User, Agent, Model, Tool, Memory, Ring, Keshav, ANANTA
// Edges: directional trust relationships with weight and evidence.
//
// Every interaction updates edge weights.
// The graph is the foundation of Trust Fabric™.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// A node in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustNode {
    pub id: String,
    pub node_type: NodeType,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    User,
    Agent,
    Model,
    Tool,
    Memory,
    Ring(String),
    Keshav,
    Ananta,
    Policy,
    Infra,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Ring(name) => write!(f, "ring:{}", name),
            other => write!(f, "{:?}", other),
        }
    }
}

/// A directed trust edge between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from: String,
    pub to: String,
    /// Trust weight 0.0 (no trust) to 1.0 (full trust).
    pub weight: f64,
    /// Evidence count supporting this trust level.
    pub evidence_count: u64,
    /// Last updated.
    pub last_updated: String,
    /// The most recent trust-affecting event.
    pub last_event: Option<String>,
}

impl TrustEdge {
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            weight: 0.5, // Start neutral.
            evidence_count: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
            last_event: None,
        }
    }

    /// Update trust based on new evidence.
    /// positive=true means good event (increase trust).
    /// positive=false means bad event (decrease trust).
    pub fn update(&mut self, positive: bool, magnitude: f64, event: &str) {
        let delta = if positive { magnitude } else { -magnitude };
        // Exponential moving average.
        let alpha = 0.1;
        self.weight = (self.weight + alpha * delta).clamp(0.0, 1.0);
        self.evidence_count += 1;
        self.last_updated = chrono::Utc::now().to_rfc3339();
        self.last_event = Some(event.into());
    }
}

/// The trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraph {
    nodes: HashMap<String, TrustNode>,
    edges: HashMap<(String, String), TrustEdge>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
        }
    }

    /// Add a node.
    pub fn add_node(&mut self, node: TrustNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Get a node.
    pub fn get_node(&self, id: &str) -> Option<&TrustNode> {
        self.nodes.get(id)
    }

    /// Add or update a trust edge.
    pub fn update_edge(
        &mut self,
        from: &str,
        to: &str,
        positive: bool,
        magnitude: f64,
        event: &str,
    ) {
        let key = (from.into(), to.into());
        let edge = self
            .edges
            .entry(key)
            .or_insert_with(|| TrustEdge::new(from, to));
        edge.update(positive, magnitude, event);
    }

    /// Get trust weight between two nodes.
    pub fn trust_weight(&self, from: &str, to: &str) -> Option<f64> {
        self.edges.get(&(from.into(), to.into())).map(|e| e.weight)
    }

    /// Get all edges for a node (outgoing).
    pub fn outgoing_edges(&self, from: &str) -> Vec<&TrustEdge> {
        self.edges.values().filter(|e| e.from == from).collect()
    }

    /// Get all edges for a node (incoming).
    pub fn incoming_edges(&self, to: &str) -> Vec<&TrustEdge> {
        self.edges.values().filter(|e| e.to == to).collect()
    }

    /// Compute aggregate trust for a node (average of all incoming trust).
    pub fn node_trust(&self, node_id: &str) -> f64 {
        let incoming = self.incoming_edges(node_id);
        if incoming.is_empty() {
            return 0.5; // No evidence = neutral.
        }
        let sum: f64 = incoming.iter().map(|e| e.weight).sum();
        sum / incoming.len() as f64
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Find weak links (trust < threshold).
    pub fn weak_links(&self, threshold: f64) -> Vec<&TrustEdge> {
        self.edges
            .values()
            .filter(|e| e.weight < threshold)
            .collect()
    }

    /// Find the minimum trust path between two nodes (Dijkstra-like).
    /// Returns the path cost (lower = more trusted). None if no path.
    pub fn trust_path_cost(&self, from: &str, to: &str) -> Option<f64> {
        if from == to {
            return Some(0.0);
        }
        if !self.nodes.contains_key(from) || !self.nodes.contains_key(to) {
            return None;
        }

        // Dijkstra with trust as inverse cost.
        let mut dist: HashMap<String, f64> = HashMap::new();
        let mut visited: HashMap<String, bool> = HashMap::new();
        dist.insert(from.into(), 0.0);

        loop {
            // Find unvisited node with minimum distance.
            let current = dist
                .iter()
                .filter(|(k, _)| !visited.contains_key(*k))
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(k, _)| k.clone());

            let current = match current {
                Some(c) => c,
                None => break, // All reachable nodes visited.
            };

            if current == to {
                return dist.get(&current).copied();
            }

            visited.insert(current.clone(), true);
            let current_dist = dist[&current];

            for edge in self.outgoing_edges(&current) {
                if visited.contains_key(&edge.to) {
                    continue;
                }
                let cost = 1.0 - edge.weight; // Invert trust to get cost.
                let new_dist = current_dist + cost;
                let entry = dist.entry(edge.to.clone()).or_insert(f64::MAX);
                if new_dist < *entry {
                    *entry = new_dist;
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_graph() -> TrustGraph {
        let mut g = TrustGraph::new();
        g.add_node(TrustNode {
            id: "user-1".into(),
            node_type: NodeType::User,
            labels: BTreeMap::new(),
        });
        g.add_node(TrustNode {
            id: "agent-1".into(),
            node_type: NodeType::Agent,
            labels: BTreeMap::new(),
        });
        g.add_node(TrustNode {
            id: "shield".into(),
            node_type: NodeType::Ring("shield".into()),
            labels: BTreeMap::new(),
        });
        g
    }

    #[test]
    fn add_and_get_nodes() {
        let g = test_graph();
        assert!(g.get_node("user-1").is_some());
        assert!(g.get_node("nonexistent").is_none());
    }

    #[test]
    fn update_edge_changes_weight() {
        let mut g = test_graph();
        g.update_edge("user-1", "agent-1", true, 0.3, "successful_auth");
        let w = g.trust_weight("user-1", "agent-1").unwrap();
        assert!(w > 0.5); // Started at 0.5, positive event.
    }

    #[test]
    fn negative_event_decreases_trust() {
        let mut g = test_graph();
        g.update_edge("agent-1", "shield", false, 0.5, "policy_violation");
        let w = g.trust_weight("agent-1", "shield").unwrap();
        assert!(w < 0.5);
    }

    #[test]
    fn weak_links() {
        let mut g = test_graph();
        g.update_edge("a", "b", false, 0.9, "major_violation");
        // Re-add nodes.
        g.add_node(TrustNode {
            id: "a".into(),
            node_type: NodeType::Agent,
            labels: BTreeMap::new(),
        });
        g.add_node(TrustNode {
            id: "b".into(),
            node_type: NodeType::Agent,
            labels: BTreeMap::new(),
        });
        let weak = g.weak_links(0.5);
        assert!(!weak.is_empty());
    }

    #[test]
    fn trust_path_cost() {
        let mut g = test_graph();
        g.update_edge("user-1", "agent-1", true, 0.5, "ok");
        let cost = g.trust_path_cost("user-1", "agent-1").unwrap();
        assert!(cost < 0.5); // High trust = low cost.
    }

    #[test]
    fn no_path_returns_none() {
        let g = test_graph();
        assert!(g.trust_path_cost("user-1", "nonexistent").is_none());
    }
}
