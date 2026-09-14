// ANANTA Distributed — Consensus, Quorum, Federation
//
// When ANANTA runs in distributed mode, multiple nodes
// must agree on trust decisions. This module provides:
//   1. Quorum voting for trust state decisions
//   2. Simple consensus protocol (majority vote)
//   3. Node registry and health tracking
//   4. Federation support (multiple ANANTA clusters)
//
// DESIGN NOTE: This is a simplified consensus for ANANTA's
// specific use case. It is NOT a general-purpose consensus
// algorithm like Raft or PBFT. ANANTA only needs agreement
// on trust state snapshots — not arbitrary state machines.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::config::DistributedConfig;
use crate::ananta::trust::trust_state::TrustState;

pub mod consensus;
pub use consensus::*;

pub mod adaptive_routing;
pub use adaptive_routing::*;

pub mod gossip;
pub use gossip::*;

pub mod partition_detector;
pub use partition_detector::*;

/// A node in the ANANTA distributed cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Unique node identifier.
    pub node_id: String,
    /// Network address.
    pub address: String,
    /// Current node status.
    pub status: NodeStatus,
    /// Last heartbeat timestamp.
    pub last_heartbeat: String,
    /// Trust score of this node (how much we trust it).
    pub trust_score: f64,
    /// The node's reported trust state (latest snapshot).
    pub reported_trust_state: Option<serde_json::Value>,
    /// Node role.
    pub role: NodeRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Node is alive and participating.
    Active,
    /// Node is suspected of being down.
    Suspect,
    /// Node has been confirmed down.
    Dead,
    /// Node is joining the cluster.
    Joining,
    /// Node is leaving the cluster.
    Leaving,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Regular participant.
    Follower,
    /// Leads consensus rounds.
    Leader,
    /// Read-only observer.
    Observer,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A vote in a consensus round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter_id: String,
    pub round_id: String,
    pub decision: VoteDecision,
    pub trust_level: f64,
    pub timestamp: String,
    /// Optional justification.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoteDecision {
    Approve,
    Reject,
    Abstain,
}

impl std::fmt::Display for VoteDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The outcome of a consensus round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub round_id: String,
    pub decision: ConsensusDecision,
    pub approve_count: usize,
    pub reject_count: usize,
    pub abstain_count: usize,
    pub total_voters: usize,
    pub quorum_reached: bool,
    pub aggregated_trust: f64,
    pub timestamp: String,
    pub votes: Vec<Vote>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusDecision {
    Approved,
    Rejected,
    NoQuorum,
    Pending,
}

impl std::fmt::Display for ConsensusDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A federation connection between ANANTA clusters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationLink {
    pub cluster_id: String,
    pub endpoint: String,
    pub trust_level: f64,
    pub last_sync: String,
    pub status: FederationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FederationStatus {
    Connected,
    Disconnected,
    Syncing,
}

/// The distributed ANANTA manager.
pub struct DistributedManager {
    config: DistributedConfig,
    /// Registered nodes.
    nodes: HashMap<String, Node>,
    /// Active consensus rounds.
    rounds: HashMap<String, ConsensusRound>,
    /// Federation links.
    federation: HashMap<String, FederationLink>,
    /// This node's ID.
    self_node_id: String,
}

/// An in-progress consensus round.
struct ConsensusRound {
    round_id: String,
    proposal: String,
    votes: Vec<Vote>,
    required_quorum: u8,
    created_at: String,
}

impl DistributedManager {
    /// Create a new distributed manager.
    pub fn new(config: DistributedConfig) -> Self {
        let self_node_id = config.node_id.clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Register self as a node.
        let mut nodes = HashMap::new();
        nodes.insert(self_node_id.clone(), Node {
            node_id: self_node_id.clone(),
            address: "self".into(),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 1.0,
            reported_trust_state: None,
            role: NodeRole::Leader,
        });

        Self {
            config,
            nodes,
            rounds: HashMap::new(),
            federation: HashMap::new(),
            self_node_id,
        }
    }

    /// Register a peer node.
    pub fn register_node(&mut self, node_id: &str, address: &str, role: NodeRole) {
        self.nodes.insert(node_id.into(), Node {
            node_id: node_id.into(),
            address: address.into(),
            status: NodeStatus::Joining,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 0.5, // New nodes start with partial trust.
            reported_trust_state: None,
            role,
        });
    }

    /// Record a heartbeat from a node.
    pub fn heartbeat(&mut self, node_id: &str, trust_state: Option<&TrustState>) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.last_heartbeat = chrono::Utc::now().to_rfc3339();
            if node.status == NodeStatus::Suspect || node.status == NodeStatus::Joining {
                node.status = NodeStatus::Active;
            }
            if let Some(ts) = trust_state {
                node.reported_trust_state = Some(serde_json::to_value(ts).unwrap_or_default());
            }
        }
    }

    /// Mark a node as suspect.
    pub fn mark_suspect(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Suspect;
        }
    }

    /// Mark a node as dead.
    pub fn mark_dead(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Dead;
            node.trust_score = 0.0;
        }
    }

    /// Start a new consensus round.
    ///
    /// Returns the round ID for collecting votes.
    pub fn start_round(&mut self, proposal: &str) -> String {
        let round_id = uuid::Uuid::new_v4().to_string();

        let round = ConsensusRound {
            round_id: round_id.clone(),
            proposal: proposal.into(),
            votes: vec![],
            required_quorum: self.config.quorum_size,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        self.rounds.insert(round_id.clone(), round);
        round_id
    }

    /// Cast a vote in an existing round.
    pub fn cast_vote(&mut self, round_id: &str, vote: Vote) -> bool {
        if let Some(round) = self.rounds.get_mut(round_id) {
            // Prevent double voting.
            if round.votes.iter().any(|v| v.voter_id == vote.voter_id) {
                return false;
            }
            round.votes.push(vote);
            true
        } else {
            false
        }
    }

    /// Tally votes and determine consensus.
    ///
    /// Returns the consensus result.
    pub fn tally(&self, round_id: &str) -> Result<ConsensusResult, String> {
        let round = self.rounds.get(round_id)
            .ok_or_else(|| format!("round '{}' not found", round_id))?;

        let approve_count = round.votes.iter().filter(|v| v.decision == VoteDecision::Approve).count();
        let reject_count = round.votes.iter().filter(|v| v.decision == VoteDecision::Reject).count();
        let abstain_count = round.votes.iter().filter(|v| v.decision == VoteDecision::Abstain).count();
        let total_voters = round.votes.len();

        let quorum_reached = (approve_count as u8) >= round.required_quorum;

        // Aggregate trust from approvers.
        let approver_trust: f64 = round.votes.iter()
            .filter(|v| v.decision == VoteDecision::Approve)
            .map(|v| v.trust_level)
            .sum();
        let aggregated_trust = if approve_count > 0 {
            approver_trust / approve_count as f64
        } else {
            0.0
        };

        let decision = if quorum_reached {
            ConsensusDecision::Approved
        } else if reject_count as u8 >= round.required_quorum {
            ConsensusDecision::Rejected
        } else {
            ConsensusDecision::NoQuorum
        };

        Ok(ConsensusResult {
            round_id: round_id.into(),
            decision,
            approve_count,
            reject_count,
            abstain_count,
            total_voters,
            quorum_reached,
            aggregated_trust,
            timestamp: chrono::Utc::now().to_rfc3339(),
            votes: round.votes.clone(),
        })
    }

    /// Get all nodes.
    pub fn nodes(&self) -> &HashMap<String, Node> {
        &self.nodes
    }

    /// Get active node count.
    pub fn active_count(&self) -> usize {
        self.nodes.values().filter(|n| n.status == NodeStatus::Active).count()
    }

    /// Add a federation link.
    pub fn add_federation(&mut self, cluster_id: &str, endpoint: &str) {
        self.federation.insert(cluster_id.into(), FederationLink {
            cluster_id: cluster_id.into(),
            endpoint: endpoint.into(),
            trust_level: 0.5,
            last_sync: chrono::Utc::now().to_rfc3339(),
            status: FederationStatus::Connected,
        });
    }

    /// Get federation links.
    pub fn federation(&self) -> &HashMap<String, FederationLink> {
        &self.federation
    }

    /// Get this node's ID.
    pub fn self_node_id(&self) -> &str {
        &self.self_node_id
    }

    /// Compute aggregate trust across all active nodes.
    pub fn aggregate_trust(&self) -> f64 {
        let active: Vec<&Node> = self.nodes.values()
            .filter(|n| n.status == NodeStatus::Active)
            .collect();

        if active.is_empty() {
            return 0.0;
        }

        let total: f64 = active.iter().map(|n| n.trust_score).sum();
        total / active.len() as f64
    }

    /// Remove a finished consensus round.
    pub fn finish_round(&mut self, round_id: &str) {
        self.rounds.remove(round_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DistributedConfig {
        DistributedConfig {
            enabled: true,
            quorum_size: 2,
            node_id: Some("node-1".into()),
            peers: vec!["node-2".into(), "node-3".into()],
        }
    }

    #[test]
    fn new_manager_has_self() {
        let mgr = DistributedManager::new(test_config());
        assert_eq!(mgr.self_node_id(), "node-1");
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn register_and_heartbeat() {
        let mut mgr = DistributedManager::new(test_config());
        mgr.register_node("node-2", "addr-2", NodeRole::Follower);
        assert_eq!(mgr.active_count(), 1); // Still joining.

        mgr.heartbeat("node-2", None);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn suspect_and_dead() {
        let mut mgr = DistributedManager::new(test_config());
        mgr.register_node("node-2", "addr-2", NodeRole::Follower);
        mgr.heartbeat("node-2", None);

        mgr.mark_suspect("node-2");
        assert_eq!(mgr.nodes["node-2"].status, NodeStatus::Suspect);

        mgr.mark_dead("node-2");
        assert_eq!(mgr.nodes["node-2"].status, NodeStatus::Dead);
        assert_eq!(mgr.nodes["node-2"].trust_score, 0.0);
    }

    #[test]
    fn consensus_approved() {
        let mut mgr = DistributedManager::new(test_config());
        let round_id = mgr.start_round("trust_level_ok");

        mgr.cast_vote(&round_id, Vote {
            voter_id: "node-1".into(),
            round_id: round_id.clone(),
            decision: VoteDecision::Approve,
            trust_level: 0.9,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: Some("trust is good".into()),
        });
        mgr.cast_vote(&round_id, Vote {
            voter_id: "node-2".into(),
            round_id: round_id.clone(),
            decision: VoteDecision::Approve,
            trust_level: 0.85,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: None,
        });

        let result = mgr.tally(&round_id).unwrap();
        assert_eq!(result.decision, ConsensusDecision::Approved);
        assert!(result.quorum_reached);
        assert!((result.aggregated_trust - 0.875).abs() < 0.01);
    }

    #[test]
    fn consensus_no_quorum() {
        let mut mgr = DistributedManager::new(test_config());
        let round_id = mgr.start_round("test");

        mgr.cast_vote(&round_id, Vote {
            voter_id: "node-1".into(),
            round_id: round_id.clone(),
            decision: VoteDecision::Approve,
            trust_level: 0.9,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: None,
        });

        let result = mgr.tally(&round_id).unwrap();
        assert_eq!(result.decision, ConsensusDecision::NoQuorum);
        assert!(!result.quorum_reached);
    }

    #[test]
    fn double_vote_prevented() {
        let mut mgr = DistributedManager::new(test_config());
        let round_id = mgr.start_round("test");

        let vote = Vote {
            voter_id: "node-1".into(),
            round_id: round_id.clone(),
            decision: VoteDecision::Approve,
            trust_level: 0.9,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: None,
        };

        assert!(mgr.cast_vote(&round_id, vote.clone()));
        assert!(!mgr.cast_vote(&round_id, vote)); // Same voter, same round.
    }

    #[test]
    fn aggregate_trust() {
        let mut mgr = DistributedManager::new(test_config());
        mgr.register_node("node-2", "addr-2", NodeRole::Follower);
        mgr.heartbeat("node-2", None);
        mgr.nodes.get_mut("node-2").unwrap().trust_score = 0.8;

        let agg = mgr.aggregate_trust();
        assert!((agg - 0.9).abs() < 0.01); // (1.0 + 0.8) / 2
    }

    #[test]
    fn federation_link() {
        let mut mgr = DistributedManager::new(test_config());
        mgr.add_federation("cluster-b", "https://cluster-b.example.com");
        assert!(mgr.federation().contains_key("cluster-b"));
        assert_eq!(mgr.federation()["cluster-b"].status, FederationStatus::Connected);
    }

    #[test]
    fn node_serialization() {
        let node = Node {
            node_id: "test".into(),
            address: "addr".into(),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: 0.9,
            reported_trust_state: None,
            role: NodeRole::Follower,
        };
        let json = serde_json::to_string(&node).unwrap();
        let restored: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.node_id, "test");
        assert_eq!(restored.status, NodeStatus::Active);
    }

    #[test]
    fn finish_round_removes() {
        let mut mgr = DistributedManager::new(test_config());
        let round_id = mgr.start_round("test");
        assert!(mgr.rounds.contains_key(&round_id));
        mgr.finish_round(&round_id);
        assert!(!mgr.rounds.contains_key(&round_id));
    }
}
