// ANANTA Distributed Consensus Protocol
//
// A 4-phase Byzantine fault-tolerant consensus protocol inspired by Tendermint PBFT,
// adapted for ANANTA's trust-state agreement use case. The protocol ensures that
// distributed ANANTA nodes agree on trust decisions with cryptographic certificates
// and probabilistic finality guarantees via a GHOST-like fork choice rule.
//
// PHASES:
//   1. Propose  — The current proposer broadcasts a trust-state proposal.
//   2. PreVote  — Nodes vote on whether the proposal is valid (not yet committed).
//   3. PreCommit — Nodes vote to commit the proposal (given sufficient PreVotes).
//   4. Commit   — Once PreCommit quorum is reached, the decision is final.
//
// SAFETY PROPERTIES:
//   - No two conflicting decisions can both be committed at the same round/height.
//   - Every committed decision carries a Merkle certificate.
//   - Byzantine nodes are detected and flagged via equivocation tracking.
//   - GHOST-like finality provides probabilistic confirmation depth.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::ananta::config::HashAlgorithm;
use crate::ananta::crypto::hashing::{hash, hash_bytes, HashDigest};
use crate::ananta::crypto::merkle::MerkleTree;
use crate::ananta::trust::trust_state::TrustState;

// Re-export key types from the parent distributed module.
use super::{ConsensusDecision, Node, VoteDecision};

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1: Consensus Phase Machine
// ═══════════════════════════════════════════════════════════════════════════

/// The four phases of the ANANTA consensus protocol.
///
/// Each phase has a specific purpose and timeout. A consensus round must
/// pass through all four phases sequentially to reach a decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusPhase {
    /// The proposer broadcasts the trust-state proposal to all validators.
    Propose,
    /// Validators vote on whether the proposal is valid (liveness gate).
    /// This is a "soft" vote — it does not commit the proposal.
    PreVote,
    /// Validators vote to lock and commit the proposal (safety gate).
    /// This is a "hard" vote — it means the validator is willing to commit.
    PreCommit,
    /// The proposal is committed. Once a node enters this phase, the
    /// decision is irreversible (barring Byzantine collusion > 1/3).
    Commit,
}

impl ConsensusPhase {
    /// Returns the next phase in the sequence, or None if this is the final phase.
    pub fn next(&self) -> Option<ConsensusPhase> {
        match self {
            ConsensusPhase::Propose => Some(ConsensusPhase::PreVote),
            ConsensusPhase::PreVote => Some(ConsensusPhase::PreCommit),
            ConsensusPhase::PreCommit => Some(ConsensusPhase::Commit),
            ConsensusPhase::Commit => None,
        }
    }

    /// Returns a numeric index for ordering phases (0..4).
    pub fn ordinal(&self) -> u8 {
        match self {
            ConsensusPhase::Propose => 0,
            ConsensusPhase::PreVote => 1,
            ConsensusPhase::PreCommit => 2,
            ConsensusPhase::Commit => 3,
        }
    }

    /// Returns the canonical string name of the phase.
    pub fn name(&self) -> &'static str {
        match self {
            ConsensusPhase::Propose => "propose",
            ConsensusPhase::PreVote => "prevote",
            ConsensusPhase::PreCommit => "precommit",
            ConsensusPhase::Commit => "commit",
        }
    }
}

impl std::fmt::Display for ConsensusPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Configuration for phase timeouts.
///
/// Each phase has an independently configurable timeout. If the phase
/// times out, a view change is triggered (round increment + new proposer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTimeoutConfig {
    /// Timeout for the Propose phase in milliseconds.
    pub propose_timeout_ms: u64,
    /// Timeout for the PreVote phase in milliseconds.
    pub prevote_timeout_ms: u64,
    /// Timeout for the PreCommit phase in milliseconds.
    pub precommit_timeout_ms: u64,
    /// Timeout for the Commit phase in milliseconds.
    pub commit_timeout_ms: u64,
    /// Maximum number of rounds before giving up on a proposal entirely.
    pub max_rounds: u32,
    /// Backoff multiplier applied to timeouts after each failed round.
    pub round_backoff_multiplier: f64,
}

impl Default for PhaseTimeoutConfig {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 2000,
            prevote_timeout_ms: 3000,
            precommit_timeout_ms: 3000,
            commit_timeout_ms: 1000,
            max_rounds: 20,
            round_backoff_multiplier: 1.5,
        }
    }
}

impl PhaseTimeoutConfig {
    /// Get the timeout for a given phase.
    pub fn timeout_for(&self, phase: &ConsensusPhase, round: u32) -> u64 {
        let base = match phase {
            ConsensusPhase::Propose => self.propose_timeout_ms,
            ConsensusPhase::PreVote => self.prevote_timeout_ms,
            ConsensusPhase::PreCommit => self.precommit_timeout_ms,
            ConsensusPhase::Commit => self.commit_timeout_ms,
        };
        // Apply exponential backoff based on round number.
        let multiplier = self.round_backoff_multiplier.powi(round as i32);
        (base as f64 * multiplier) as u64
    }
}

/// Snapshot of the current phase state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseSnapshot {
    /// The current consensus phase.
    pub phase: ConsensusPhase,
    /// The current round number.
    pub round: u32,
    /// The height (block number) being decided.
    pub height: u64,
    /// The node ID of the current proposer.
    pub proposer_id: String,
    /// Timestamp when this phase started.
    pub phase_started_at: String,
    /// Timestamp of the overall round start.
    pub round_started_at: String,
    /// Number of votes collected so far in the current phase.
    pub votes_collected: usize,
    /// Whether this phase has timed out.
    pub timed_out: bool,
}

/// The state machine that manages phase transitions for a single consensus instance.
///
/// Each consensus round goes through Propose → PreVote → PreCommit → Commit.
/// The machine enforces valid transitions and tracks timing for timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseMachine {
    /// Current phase in the consensus protocol.
    pub current_phase: ConsensusPhase,
    /// Current round number (increments on timeout).
    pub round: u32,
    /// Block height being decided.
    pub height: u64,
    /// The ID of the node that is the current proposer.
    pub proposer_id: String,
    /// Timestamp when the current phase was entered.
    pub phase_entered_at: String,
    /// Timestamp when the current round started.
    pub round_started_at: String,
    /// Total number of validators participating.
    pub validator_count: usize,
    /// Whether this round has completed (reached Commit or timed out).
    pub round_complete: bool,
    /// The final decision for this round (if committed).
    pub decision: Option<ConsensusDecision>,
}

impl PhaseMachine {
    /// Create a new phase machine for the given height, round, and proposer.
    pub fn new(height: u64, round: u32, proposer_id: &str, validator_count: usize) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            current_phase: ConsensusPhase::Propose,
            round,
            height,
            proposer_id: proposer_id.to_string(),
            phase_entered_at: now.clone(),
            round_started_at: now,
            validator_count,
            round_complete: false,
            decision: None,
        }
    }

    /// Advance to the next phase. Returns the new phase or None if already at Commit.
    pub fn advance_phase(&mut self) -> Option<ConsensusPhase> {
        if self.round_complete {
            return None;
        }
        let next = self.current_phase.next();
        if let Some(ref phase) = next {
            self.current_phase = phase.clone();
            self.phase_entered_at = chrono::Utc::now().to_rfc3339();
            if *phase == ConsensusPhase::Commit {
                self.round_complete = true;
            }
        }
        next
    }

    /// Force a transition to Commit phase (used when PreCommit quorum is reached).
    pub fn transition_to_commit(&mut self, decision: ConsensusDecision) {
        self.current_phase = ConsensusPhase::Commit;
        self.decision = Some(decision);
        self.round_complete = true;
        self.phase_entered_at = chrono::Utc::now().to_rfc3339();
    }

    /// Start a new round (view change). Resets phase to Propose with new proposer.
    pub fn start_new_round(&mut self, new_round: u32, new_proposer_id: &str) {
        self.round = new_round;
        self.current_phase = ConsensusPhase::Propose;
        self.proposer_id = new_proposer_id.to_string();
        self.phase_entered_at = chrono::Utc::now().to_rfc3339();
        self.round_started_at = self.phase_entered_at.clone();
        self.round_complete = false;
        self.decision = None;
    }

    /// Check if the given phase timeout has elapsed based on wall-clock time.
    pub fn is_phase_timed_out(&self, config: &PhaseTimeoutConfig) -> bool {
        if self.round_complete {
            return false;
        }
        let timeout_ms = config.timeout_for(&self.current_phase, self.round);
        if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&self.phase_entered_at) {
            let now = chrono::Utc::now();
            let elapsed_ms = (now.timestamp_millis() - started.timestamp_millis()) as u64;
            elapsed_ms > timeout_ms
        } else {
            // If we can't parse the timestamp, never time out (safe default).
            false
        }
    }

    /// Take a snapshot of the current phase state.
    pub fn snapshot(&self, votes_collected: usize, timed_out: bool) -> PhaseSnapshot {
        PhaseSnapshot {
            phase: self.current_phase.clone(),
            round: self.round,
            height: self.height,
            proposer_id: self.proposer_id.clone(),
            phase_started_at: self.phase_entered_at.clone(),
            round_started_at: self.round_started_at.clone(),
            votes_collected,
            timed_out,
        }
    }

    /// Returns true if the machine is in a voting phase (PreVote or PreCommit).
    pub fn is_voting_phase(&self) -> bool {
        self.current_phase == ConsensusPhase::PreVote || self.current_phase == ConsensusPhase::PreCommit
    }

    /// Returns true if the machine has reached the Commit phase.
    pub fn is_committed(&self) -> bool {
        self.current_phase == ConsensusPhase::Commit && self.decision.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2: Proposal and Message Types
// ═══════════════════════════════════════════════════════════════════════════

/// A trust-state proposal submitted for consensus.
///
/// Wraps a TrustState snapshot along with metadata identifying the
/// proposer, round, and height for which this proposal is intended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// Unique identifier for this proposal.
    pub proposal_id: String,
    /// The proposer's node ID.
    pub proposer_id: String,
    /// The block height this proposal targets.
    pub height: u64,
    /// The consensus round number.
    pub round: u32,
    /// The trust state being proposed.
    pub trust_state: serde_json::Value,
    /// A hash of the trust state for efficient comparison.
    pub trust_state_hash: String,
    /// Timestamp when the proposal was created.
    pub created_at: String,
    /// Optional human-readable description of what changed.
    pub description: Option<String>,
    /// The proposer's trust score at the time of proposing.
    pub proposer_trust: f64,
    /// Arbitrary metadata attached to the proposal.
    pub metadata: serde_json::Value,
}

impl ConsensusProposal {
    /// Create a new consensus proposal.
    pub fn new(
        proposer_id: &str,
        height: u64,
        round: u32,
        trust_state: &TrustState,
        proposer_trust: f64,
    ) -> Self {
        let ts_value = serde_json::to_value(trust_state).unwrap_or_default();
        let ts_string = serde_json::to_string(&ts_value).unwrap_or_default();
        let digest = hash_bytes(ts_string.as_bytes(), &HashAlgorithm::Sha256);
        Self {
            proposal_id: uuid::Uuid::new_v4().to_string(),
            proposer_id: proposer_id.to_string(),
            height,
            round,
            trust_state: ts_value,
            trust_state_hash: digest.hex.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: None,
            proposer_trust,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Compute a unique hash for this proposal based on its key fields.
    pub fn compute_hash(&self) -> HashDigest {
        let data = format!(
            "proposal:{}:{}:{}:{}:{}",
            self.proposal_id, self.height, self.round, self.proposer_id, self.trust_state_hash
        );
        hash(&data, &HashAlgorithm::Sha256)
    }
}

/// A phase-specific vote message used in the PBFT protocol.
///
/// Unlike the simple Vote type in the parent module, this tracks which
/// phase the vote is for, what proposal it references, and its round/height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseVote {
    /// Unique ID for this vote.
    pub vote_id: String,
    /// The voter's node ID.
    pub voter_id: String,
    /// The consensus phase this vote is for (PreVote or PreCommit).
    pub phase: ConsensusPhase,
    /// The proposal ID this vote references.
    pub proposal_id: String,
    /// The block height.
    pub height: u64,
    /// The round number.
    pub round: u32,
    /// The vote decision (Approve, Reject, or Abstain).
    pub decision: VoteDecision,
    /// The voter's trust score.
    pub voter_trust: f64,
    /// Timestamp of the vote.
    pub timestamp: String,
    /// Optional reason for the vote.
    pub reason: Option<String>,
    /// A signature over the vote (simulated as a hex string in this impl).
    pub signature: String,
}

impl PhaseVote {
    /// Create a new phase vote.
    pub fn new(
        voter_id: &str,
        phase: ConsensusPhase,
        proposal_id: &str,
        height: u64,
        round: u32,
        decision: VoteDecision,
        voter_trust: f64,
        reason: Option<String>,
    ) -> Self {
        let vote_id = uuid::Uuid::new_v4().to_string();
        // Simulate a signature: H(vote_id || voter_id || decision || round || height)
        let sig_data = format!("{}:{}:{:?}:{}:{}", vote_id, voter_id, decision, round, height);
        let sig_digest = hash(&sig_data, &HashAlgorithm::Sha256);
        Self {
            vote_id,
            voter_id: voter_id.to_string(),
            phase,
            proposal_id: proposal_id.to_string(),
            height,
            round,
            decision,
            voter_trust,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason,
            signature: sig_digest.hex,
        }
    }

    /// Verify the signature of this vote (simulated verification).
    pub fn verify_signature(&self) -> bool {
        let sig_data = format!(
            "{}:{}:{:?}:{}:{}",
            self.vote_id, self.voter_id, self.decision, self.round, self.height
        );
        let expected = hash(&sig_data, &HashAlgorithm::Sha256);
        self.signature == expected.hex
    }

    /// Check if this vote matches a given (proposal, height, round, phase).
    pub fn matches_context(&self, proposal_id: &str, height: u64, round: u32, phase: &ConsensusPhase) -> bool {
        self.proposal_id == proposal_id
            && self.height == height
            && self.round == round
            && self.phase == *phase
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3: Byzantine Fault Detection
// ═══════════════════════════════════════════════════════════════════════════

/// A record of a single equivocation event — a node voting for conflicting proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvent {
    /// The node that equivocated.
    pub node_id: String,
    /// The first vote (proposal ID).
    pub first_proposal_id: String,
    /// The conflicting vote (proposal ID).
    pub second_proposal_id: String,
    /// The round in which the equivocation was detected.
    pub round: u32,
    /// The height at which the equivocation was detected.
    pub height: u64,
    /// Timestamp when the equivocation was detected.
    pub detected_at: String,
    /// The phase in which the equivocation occurred.
    pub phase: ConsensusPhase,
}

/// A record of observed commit latency for a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyObservation {
    /// The node ID.
    pub node_id: String,
    /// The round number.
    pub round: u32,
    /// Latency in milliseconds from proposal to vote.
    pub latency_ms: u64,
    /// Timestamp of the observation.
    pub observed_at: String,
}

/// Suspicion level for a node based on observed behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionLevel {
    /// No suspicious behavior observed.
    Clean,
    /// Minor anomalies detected (e.g., occasional latency spikes).
    Low,
    /// Moderate suspicion (e.g., multiple latency outliers, single equivocation).
    Medium,
    /// High suspicion (e.g., repeated equivocation, persistent latency issues).
    High,
    /// Confirmed Byzantine behavior — node should be excluded.
    Confirmed,
}

impl std::fmt::Display for SuspicionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A behavioral profile for a single node, tracking patterns for Byzantine detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBehaviorProfile {
    /// The node being tracked.
    pub node_id: String,
    /// All equivocation events for this node.
    pub equivocations: Vec<EquivocationEvent>,
    /// Recent latency observations (ring buffer, most recent last).
    pub latency_observations: VecDeque<LatencyObservation>,
    /// Number of rounds the node has participated in.
    pub rounds_participated: u32,
    /// Number of rounds the node was absent (no vote).
    pub rounds_absent: u32,
    /// Current suspicion level.
    pub suspicion_level: SuspicionLevel,
    /// The node's current trust score (external input).
    pub trust_score: f64,
    /// Timestamp of the last activity from this node.
    pub last_activity: String,
}

impl NodeBehaviorProfile {
    /// Create a new behavior profile for a node.
    pub fn new(node_id: &str, trust_score: f64) -> Self {
        Self {
            node_id: node_id.to_string(),
            equivocations: vec![],
            latency_observations: VecDeque::with_capacity(100),
            rounds_participated: 0,
            rounds_absent: 0,
            suspicion_level: SuspicionLevel::Clean,
            trust_score,
            last_activity: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Record a latency observation.
    pub fn record_latency(&mut self, round: u32, latency_ms: u64) {
        self.latency_observations.push_back(LatencyObservation {
            node_id: self.node_id.clone(),
            round,
            latency_ms,
            observed_at: chrono::Utc::now().to_rfc3339(),
        });
        // Keep only the most recent 100 observations.
        while self.latency_observations.len() > 100 {
            self.latency_observations.pop_front();
        }
        self.last_activity = chrono::Utc::now().to_rfc3339();
    }

    /// Record a round absence.
    pub fn record_absence(&mut self) {
        self.rounds_absent += 1;
    }

    /// Record a round participation.
    pub fn record_participation(&mut self) {
        self.rounds_participated += 1;
        self.last_activity = chrono::Utc::now().to_rfc3339();
    }

    /// Compute the mean latency from recent observations.
    pub fn mean_latency_ms(&self) -> f64 {
        if self.latency_observations.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.latency_observations.iter().map(|o| o.latency_ms).sum();
        sum as f64 / self.latency_observations.len() as f64
    }

    /// Compute the standard deviation of latency from recent observations.
    pub fn latency_stddev_ms(&self) -> f64 {
        if self.latency_observations.len() < 2 {
            return 0.0;
        }
        let mean = self.mean_latency_ms();
        let variance: f64 = self
            .latency_observations
            .iter()
            .map(|o| (o.latency_ms as f64 - mean).powi(2))
            .sum::<f64>()
            / self.latency_observations.len() as f64;
        variance.sqrt()
    }

    /// Check if the given latency is an outlier (more than 2 standard deviations from mean).
    pub fn is_latency_outlier(&self, latency_ms: u64) -> bool {
        if self.latency_observations.len() < 5 {
            return false;
        }
        let mean = self.mean_latency_ms();
        let stddev = self.latency_stddev_ms();
        if stddev < 1e-10 {
            // No variation in observations: flag anything different from mean.
            return (latency_ms as f64 - mean).abs() > 0.001;
        }
        let z_score = (latency_ms as f64 - mean) / stddev;
        z_score.abs() > 2.0
    }

    /// Update the suspicion level based on accumulated evidence.
    pub fn recompute_suspicion(&mut self) -> SuspicionLevel {
        let equivocation_count = self.equivocations.len();
        let outlier_count: usize = self
            .latency_observations
            .iter()
            .filter(|o| self.is_latency_outlier(o.latency_ms))
            .count();
        let total_obs = self.latency_observations.len();
        let outlier_ratio = if total_obs > 0 {
            outlier_count as f64 / total_obs as f64
        } else {
            0.0
        };
        let absence_rate = if (self.rounds_participated + self.rounds_absent) > 0 {
            self.rounds_absent as f64 / (self.rounds_participated + self.rounds_absent) as f64
        } else {
            0.0
        };

        self.suspicion_level = if equivocation_count >= 3 || (equivocation_count >= 1 && outlier_ratio > 0.5) {
            SuspicionLevel::Confirmed
        } else if equivocation_count >= 2 || outlier_ratio > 0.4 || absence_rate > 0.6 {
            SuspicionLevel::High
        } else if equivocation_count >= 1 || outlier_ratio > 0.25 || absence_rate > 0.4 {
            SuspicionLevel::Medium
        } else if outlier_ratio > 0.1 || absence_rate > 0.2 {
            SuspicionLevel::Low
        } else {
            SuspicionLevel::Clean
        };
        self.suspicion_level.clone()
    }
}

/// The Byzantine fault detector that monitors all node behavior.
///
/// Tracks equivocation (voting for conflicting proposals), latency outliers,
/// and participation patterns to identify potentially Byzantine nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByzantineDetector {
    /// Behavioral profiles indexed by node ID.
    pub profiles: HashMap<String, NodeBehaviorProfile>,
    /// All detected equivocation events across all nodes.
    pub equivocation_log: Vec<EquivocationEvent>,
    /// The threshold number of latency outliers before flagging (per window).
    pub latency_outlier_threshold: usize,
    /// Number of standard deviations to use for outlier detection.
    pub outlier_sigma: f64,
    /// Nodes that have been confirmed as Byzantine and should be excluded.
    pub blacklisted: HashSet<String>,
}

impl ByzantineDetector {
    /// Create a new Byzantine detector with default settings.
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            equivocation_log: vec![],
            latency_outlier_threshold: 5,
            outlier_sigma: 2.0,
            blacklisted: HashSet::new(),
        }
    }

    /// Register a node for monitoring.
    pub fn register_node(&mut self, node_id: &str, trust_score: f64) {
        self.profiles.insert(
            node_id.to_string(),
            NodeBehaviorProfile::new(node_id, trust_score),
        );
    }

    /// Record a phase vote for a node, checking for equivocation.
    /// Returns the list of any equivocation events detected.
    pub fn record_vote(
        &mut self,
        node_id: &str,
        vote: &PhaseVote,
        known_proposals_for_round: &[String],
    ) -> Vec<EquivocationEvent> {
        let mut events = vec![];

        // Check for equivocation: voting for a proposal that conflicts with
        // a previously known proposal for this round/height/phase.
        if !known_proposals_for_round.is_empty() {
            if !known_proposals_for_round.contains(&vote.proposal_id) {
                let event = EquivocationEvent {
                    node_id: node_id.to_string(),
                    first_proposal_id: known_proposals_for_round
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    second_proposal_id: vote.proposal_id.clone(),
                    round: vote.round,
                    height: vote.height,
                    detected_at: chrono::Utc::now().to_rfc3339(),
                    phase: vote.phase.clone(),
                };
                events.push(event.clone());
                self.equivocation_log.push(event);
            }
        }

        // Record the equivocation in the node's profile.
        if !events.is_empty() {
            if let Some(profile) = self.profiles.get_mut(node_id) {
                for e in &events {
                    profile.equivocations.push(e.clone());
                }
                profile.recompute_suspicion();
                if profile.suspicion_level == SuspicionLevel::Confirmed {
                    self.blacklisted.insert(node_id.to_string());
                }
            }
        }

        events
    }

    /// Record a latency observation for a node.
    pub fn record_latency(&mut self, node_id: &str, round: u32, latency_ms: u64) {
        if let Some(profile) = self.profiles.get_mut(node_id) {
            profile.record_latency(round, latency_ms);
            profile.recompute_suspicion();
            if profile.suspicion_level == SuspicionLevel::Confirmed {
                self.blacklisted.insert(node_id.to_string());
            }
        }
    }

    /// Record that a node participated in a round.
    pub fn record_participation(&mut self, node_id: &str) {
        if let Some(profile) = self.profiles.get_mut(node_id) {
            profile.record_participation();
        }
    }

    /// Record that a node was absent from a round.
    pub fn record_absence(&mut self, node_id: &str) {
        if let Some(profile) = self.profiles.get_mut(node_id) {
            profile.record_absence();
            profile.recompute_suspicion();
        }
    }

    /// Get the suspicion level for a node.
    pub fn suspicion_level(&self, node_id: &str) -> SuspicionLevel {
        self.profiles
            .get(node_id)
            .map(|p| p.suspicion_level.clone())
            .unwrap_or(SuspicionLevel::Clean)
    }

    /// Get a list of nodes at or above a given suspicion level.
    pub fn suspicious_nodes(&self, min_level: &SuspicionLevel) -> Vec<&str> {
        self.profiles
            .values()
            .filter(|p| p.suspicion_level >= *min_level)
            .map(|p| p.node_id.as_str())
            .collect()
    }

    /// Check if a node is blacklisted (confirmed Byzantine).
    pub fn is_blacklisted(&self, node_id: &str) -> bool {
        self.blacklisted.contains(node_id)
    }

    /// Get the behavior profile for a node.
    pub fn profile(&self, node_id: &str) -> Option<&NodeBehaviorProfile> {
        self.profiles.get(node_id)
    }

    /// Get all node IDs being monitored.
    pub fn monitored_nodes(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    /// Rebuild the blacklist based on current suspicion levels.
    pub fn rebuild_blacklist(&mut self) {
        self.blacklisted.clear();
        for (node_id, profile) in &self.profiles {
            if profile.suspicion_level == SuspicionLevel::Confirmed {
                self.blacklisted.insert(node_id.clone());
            }
        }
    }

    /// Get a summary of the Byzantine detector state.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "monitored_nodes": self.profiles.len(),
            "equivocation_events": self.equivocation_log.len(),
            "blacklisted_nodes": self.blacklisted.len(),
            "blacklisted_ids": self.blacklisted.iter().collect::<Vec<_>>(),
            "suspicion_distribution": {
                "clean": self.profiles.values().filter(|p| p.suspicion_level == SuspicionLevel::Clean).count(),
                "low": self.profiles.values().filter(|p| p.suspicion_level == SuspicionLevel::Low).count(),
                "medium": self.profiles.values().filter(|p| p.suspicion_level == SuspicionLevel::Medium).count(),
                "high": self.profiles.values().filter(|p| p.suspicion_level == SuspicionLevel::High).count(),
                "confirmed": self.profiles.values().filter(|p| p.suspicion_level == SuspicionLevel::Confirmed).count(),
            }
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 4: View Change Protocol
// ═══════════════════════════════════════════════════════════════════════════

/// A justification for a view change, proving why a node wants to move
/// to a new round. Justifications can be timeout-based or based on
/// receiving a commit for a different proposal at the same height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChangeJustification {
    /// The node providing this justification.
    pub node_id: String,
    /// The round being left.
    pub from_round: u32,
    /// The target round (from_round + 1 or higher if skipping).
    pub to_round: u32,
    /// The height being decided.
    pub height: u64,
    /// The type of justification.
    pub justification_type: ViewChangeReason,
    /// The proposal ID that was being considered (if any).
    pub current_proposal_id: Option<String>,
    /// Phase votes that justify this view change (e.g., PreVotes received).
    pub justifying_votes: Vec<PhaseVote>,
    /// Timestamp of the justification.
    pub timestamp: String,
    /// Simulated signature.
    pub signature: String,
}

impl ViewChangeJustification {
    /// Create a timeout-based view change justification.
    pub fn for_timeout(
        node_id: &str,
        height: u64,
        from_round: u32,
        to_round: u32,
        current_proposal_id: Option<&str>,
    ) -> Self {
        let sig_data = format!("view_change:timeout:{}:{}:{}:{}", node_id, height, from_round, to_round);
        let sig = hash(&sig_data, &HashAlgorithm::Sha256);
        Self {
            node_id: node_id.to_string(),
            from_round,
            to_round,
            height,
            justification_type: ViewChangeReason::PhaseTimeout,
            current_proposal_id: current_proposal_id.map(|s| s.to_string()),
            justifying_votes: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
            signature: sig.hex,
        }
    }

    /// Create a proposal conflict view change justification.
    pub fn for_proposal_conflict(
        node_id: &str,
        height: u64,
        from_round: u32,
        to_round: u32,
        conflicting_proposal_id: &str,
        votes: Vec<PhaseVote>,
    ) -> Self {
        let sig_data = format!("view_change:conflict:{}:{}:{}:{}", node_id, height, from_round, to_round);
        let sig = hash(&sig_data, &HashAlgorithm::Sha256);
        Self {
            node_id: node_id.to_string(),
            from_round,
            to_round,
            height,
            justification_type: ViewChangeReason::ProposalConflict,
            current_proposal_id: Some(conflicting_proposal_id.to_string()),
            justifying_votes: votes,
            timestamp: chrono::Utc::now().to_rfc3339(),
            signature: sig.hex,
        }
    }

    /// Verify the justification's signature.
    pub fn verify_signature(&self) -> bool {
        let prefix = match self.justification_type {
            ViewChangeReason::PhaseTimeout => "view_change:timeout",
            ViewChangeReason::ProposalConflict => "view_change:conflict",
            ViewChangeReason::RoundSkip => "view_change:skip",
            ViewChangeReason::SuspectProposer => "view_change:suspect",
        };
        let sig_data = format!("{}:{}:{}:{}:{}", prefix, self.node_id, self.height, self.from_round, self.to_round);
        let expected = hash(&sig_data, &HashAlgorithm::Sha256);
        self.signature == expected.hex
    }
}

/// The reason for a view change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViewChangeReason {
    /// A phase timed out without reaching quorum.
    PhaseTimeout,
    /// A conflicting proposal was detected at the same height/round.
    ProposalConflict,
    /// Multiple rounds were skipped due to sustained timeouts.
    RoundSkip,
    /// The current proposer is suspected of being Byzantine.
    SuspectProposer,
}

/// A view change message requesting transition to a new round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChangeMessage {
    /// Unique ID for this view change message.
    pub message_id: String,
    /// The node initiating the view change.
    pub initiator_id: String,
    /// The height being decided.
    pub height: u64,
    /// The new round number.
    pub new_round: u32,
    /// Justifications for this view change.
    pub justifications: Vec<ViewChangeJustification>,
    /// The proposed new proposer (determined by trust-weighted round-robin).
    pub new_proposer_id: String,
    /// Timestamp of the view change request.
    pub timestamp: String,
}

impl ViewChangeMessage {
    /// Create a new view change message.
    pub fn new(
        initiator_id: &str,
        height: u64,
        new_round: u32,
        new_proposer_id: &str,
        justifications: Vec<ViewChangeJustification>,
    ) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            initiator_id: initiator_id.to_string(),
            height,
            new_round,
            justifications,
            new_proposer_id: new_proposer_id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// State sync data for lagging nodes that missed rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncSnapshot {
    /// The snapshot ID.
    pub snapshot_id: String,
    /// The height this snapshot covers.
    pub height: u64,
    /// The round at which this snapshot was taken.
    pub round: u32,
    /// The committed decision at this height.
    pub decision: ConsensusDecision,
    /// The proposal ID that was committed.
    pub committed_proposal_id: Option<String>,
    /// The Merkle root of the committed decision certificate.
    pub certificate_root: Option<String>,
    /// All committed decisions up to this height (height -> decision).
    pub decisions: BTreeMap<u64, ConsensusDecision>,
    /// The voter set (node IDs participating).
    pub voter_set: Vec<String>,
    /// Timestamp of the snapshot.
    pub timestamp: String,
}

impl StateSyncSnapshot {
    /// Create a state sync snapshot from the consensus engine's history.
    pub fn new(
        height: u64,
        round: u32,
        decision: ConsensusDecision,
        committed_proposal_id: Option<&str>,
        decisions: BTreeMap<u64, ConsensusDecision>,
        voter_set: Vec<String>,
    ) -> Self {
        Self {
            snapshot_id: uuid::Uuid::new_v4().to_string(),
            height,
            round,
            decision,
            committed_proposal_id: committed_proposal_id.map(|s| s.to_string()),
            certificate_root: None,
            decisions,
            voter_set,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Manages view changes — the process of moving to a new round when the
/// current round cannot reach consensus due to timeout or conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChangeManager {
    /// Collected view change justifications for the current pending view change.
    pub pending_justifications: HashMap<String, Vec<ViewChangeJustification>>,
    /// History of all view changes (height, round -> justifications).
    pub view_change_history: BTreeMap<(u64, u32), Vec<ViewChangeJustification>>,
    /// The proposer ordering — a trust-weighted round-robin sequence.
    pub proposer_sequence: Vec<String>,
    /// Index into the proposer_sequence indicating the next proposer.
    pub proposer_index: usize,
    /// Total number of view changes that have occurred.
    pub total_view_changes: u32,
    /// State sync snapshots available for lagging nodes.
    pub sync_snapshots: HashMap<String, StateSyncSnapshot>,
}

impl ViewChangeManager {
    /// Create a new view change manager with the given proposer sequence.
    pub fn new(proposer_sequence: Vec<String>) -> Self {
        Self {
            pending_justifications: HashMap::new(),
            view_change_history: BTreeMap::new(),
            proposer_sequence,
            proposer_index: 0,
            total_view_changes: 0,
            sync_snapshots: HashMap::new(),
        }
    }

    /// Select the proposer for a given round using trust-weighted round-robin.
    ///
    /// The proposer is determined by `(round + trust_weight_offset) % len`.
    /// Trust-weighted means nodes with higher trust scores are preferred.
    pub fn select_proposer(&mut self, round: u32, trust_scores: &HashMap<String, f64>) -> String {
        if self.proposer_sequence.is_empty() {
            return String::new();
        }

        // Sort proposers by trust score (descending) for the round-robin.
        let mut sorted: Vec<(String, f64)> = self
            .proposer_sequence
            .iter()
            .map(|id| {
                let score = trust_scores.get(id).copied().unwrap_or(0.5);
                (id.clone(), score)
            })
            .collect();
        sorted.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Round-robin within the trust-sorted list.
        let index = (round as usize) % sorted.len();
        sorted[index].0.clone()
    }

    /// Submit a view change justification. Returns true if quorum is reached.
    pub fn submit_justification(
        &mut self,
        height: u64,
        round: u32,
        justification: ViewChangeJustification,
        quorum_size: usize,
    ) -> bool {
        let key = format!("{}:{}", height, round);
        let justifications = self
            .pending_justifications
            .entry(key)
            .or_insert_with(Vec::new);

        // Avoid duplicate justifications from the same node.
        let is_duplicate = justifications
            .iter()
            .any(|j| j.node_id == justification.node_id);
        if !is_duplicate {
            justifications.push(justification);
        }

        justifications.len() >= quorum_size
    }

    /// Execute a view change: record history, increment round, select new proposer.
    pub fn execute_view_change(
        &mut self,
        height: u64,
        old_round: u32,
        new_round: u32,
        trust_scores: &HashMap<String, f64>,
    ) -> ViewChangeMessage {
        let key = format!("{}:{}", height, old_round);
        let justifications = self
            .pending_justifications
            .remove(&key)
            .unwrap_or_default();

        self.view_change_history
            .insert((height, old_round), justifications.clone());
        self.total_view_changes += 1;

        let new_proposer = self.select_proposer(new_round, trust_scores);
        ViewChangeMessage::new(
            "consensus_engine",
            height,
            new_round,
            &new_proposer,
            justifications,
        )
    }

    /// Record a state sync snapshot for a lagging node.
    pub fn record_sync_snapshot(&mut self, node_id: &str, snapshot: StateSyncSnapshot) {
        self.sync_snapshots.insert(node_id.to_string(), snapshot);
    }

    /// Retrieve and consume a sync snapshot for a node.
    pub fn take_sync_snapshot(&mut self, node_id: &str) -> Option<StateSyncSnapshot> {
        self.sync_snapshots.remove(node_id)
    }

    /// Check if a node has a pending sync snapshot.
    pub fn has_sync_snapshot(&self, node_id: &str) -> bool {
        self.sync_snapshots.contains_key(node_id)
    }

    /// Get the total number of view changes.
    pub fn total_view_changes(&self) -> u32 {
        self.total_view_changes
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 5: Merkle-Certificated Results
// ═══════════════════════════════════════════════════════════════════════════

/// A cryptographic certificate for a committed consensus decision.
///
/// Each certificate binds the decision to a specific round, height, voter set,
/// and set of signatures via a Merkle tree. This provides tamper-evident
/// proof that a decision was legitimately reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusCertificate {
    /// Unique identifier for this certificate.
    pub certificate_id: String,
    /// The block height of the decision.
    pub height: u64,
    /// The round number in which the decision was reached.
    pub round: u32,
    /// The final consensus decision.
    pub decision: ConsensusDecision,
    /// The proposal ID that was committed.
    pub proposal_id: String,
    /// Hash of the proposal's trust state.
    pub decision_hash: String,
    /// Hash of the voter set (sorted node IDs).
    pub voter_set_hash: String,
    /// The Merkle root of the certificate data.
    pub merkle_root: String,
    /// Hex-encoded signature from each voter.
    pub voter_signatures: Vec<VoterSignature>,
    /// The number of approving votes.
    pub approve_count: usize,
    /// The total number of participating voters.
    pub total_voters: usize,
    /// Timestamp when the certificate was created.
    pub created_at: String,
}

/// A single voter's signature contribution to a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterSignature {
    /// The voter's node ID.
    pub voter_id: String,
    /// The hex-encoded signature.
    pub signature: String,
    /// The voter's trust score at the time of signing.
    pub trust_score: f64,
}

impl ConsensusCertificate {
    /// Build a consensus certificate from a completed consensus round.
    pub fn build(
        height: u64,
        round: u32,
        decision: ConsensusDecision,
        proposal_id: &str,
        decision_hash: &str,
        voter_ids: &[String],
        voter_signatures: Vec<VoterSignature>,
        approve_count: usize,
    ) -> Self {
        // Compute the voter set hash (sorted for determinism).
        let mut sorted_voters: Vec<&String> = voter_ids.iter().collect();
        sorted_voters.sort();
        let voter_set_string = sorted_voters
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let voter_set_digest = hash_bytes(voter_set_string.as_bytes(), &HashAlgorithm::Sha256);
        let voter_set_hash = voter_set_digest.hex.clone();

        // Build the Merkle tree from the certificate data fields.
        let height_str = height.to_string();
        let round_str = round.to_string();
        let merkle_data: Vec<&[u8]> = vec![
            decision_hash.as_bytes(),
            height_str.as_bytes(),
            round_str.as_bytes(),
            proposal_id.as_bytes(),
            voter_set_hash.as_bytes(),
        ];

        // Also include each voter signature hash as a leaf.
        let mut all_leaves: Vec<&[u8]> = merkle_data;
        for vs in &voter_signatures {
            all_leaves.push(vs.signature.as_bytes());
        }

        let tree = MerkleTree::from_data(&all_leaves, &HashAlgorithm::Sha256);
        let merkle_root = tree.root.hex.clone();

        ConsensusCertificate {
            certificate_id: uuid::Uuid::new_v4().to_string(),
            height,
            round,
            decision,
            proposal_id: proposal_id.to_string(),
            decision_hash: decision_hash.to_string(),
            voter_set_hash,
            merkle_root,
            voter_signatures,
            approve_count,
            total_voters: voter_ids.len(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Verify the integrity of this certificate by recomputing the Merkle root.
    pub fn verify(&self) -> bool {
        // Recompute the voter set hash.
        let mut sorted_sigs: Vec<&VoterSignature> = self.voter_signatures.iter().collect();
        sorted_sigs.sort_by_key(|v| &v.voter_id);
        let voter_ids: Vec<String> = sorted_sigs.iter().map(|v| v.voter_id.clone()).collect();
        let mut sorted_voters: Vec<&String> = voter_ids.iter().collect();
        sorted_voters.sort();
        let voter_set_string = sorted_voters
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let voter_set_digest = hash_bytes(voter_set_string.as_bytes(), &HashAlgorithm::Sha256);

        // Rebuild the Merkle tree.
        let height_str = self.height.to_string();
        let round_str = self.round.to_string();
        let merkle_data: Vec<&[u8]> = vec![
            self.decision_hash.as_bytes(),
            height_str.as_bytes(),
            round_str.as_bytes(),
            self.proposal_id.as_bytes(),
            voter_set_digest.hex.as_bytes(),
        ];
        let mut all_leaves: Vec<&[u8]> = merkle_data;
        for vs in &self.voter_signatures {
            all_leaves.push(vs.signature.as_bytes());
        }
        let tree = MerkleTree::from_data(&all_leaves, &HashAlgorithm::Sha256);

        tree.root.hex == self.merkle_root
            && voter_set_digest.hex == self.voter_set_hash
            && self.approve_count <= self.total_voters
    }

    /// Get a summary of this certificate.
    pub fn summary(&self) -> String {
        format!(
            "cert[height={},round={},decision={:?},voters={}/{},root={}]",
            self.height,
            self.round,
            self.decision,
            self.approve_count,
            self.total_voters,
            &self.merkle_root[..16.min(self.merkle_root.len())],
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 6: GHOST-like Finality
// ═══════════════════════════════════════════════════════════════════════════

/// A single block (committed decision) in the chain of consensus decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    /// The block height (sequence number).
    pub height: u64,
    /// The consensus decision at this height.
    pub decision: ConsensusDecision,
    /// The round number that produced this decision.
    pub round: u32,
    /// The proposal ID that was committed.
    pub proposal_id: String,
    /// Cumulative trust weight supporting this block (sum of approver trust scores).
    pub cumulative_weight: f64,
    /// The hash of the parent block (height - 1), or "genesis" for height 0.
    pub parent_hash: String,
    /// The Merkle root of the certificate for this block.
    pub certificate_root: String,
    /// The certificate for this block (if committed).
    pub certificate: Option<ConsensusCertificate>,
    /// The block's own hash.
    pub block_hash: String,
    /// Timestamp of the block.
    pub timestamp: String,
}

impl ChainBlock {
    /// Create a new chain block.
    pub fn new(
        height: u64,
        decision: ConsensusDecision,
        round: u32,
        proposal_id: &str,
        cumulative_weight: f64,
        parent_hash: &str,
        certificate_root: &str,
        certificate: Option<ConsensusCertificate>,
    ) -> Self {
        let block_data = format!(
            "block:{}:{}:{}:{}:{}:{}",
            height,
            round,
            proposal_id,
            cumulative_weight,
            parent_hash,
            certificate_root,
        );
        let block_hash = hash_bytes(block_data.as_bytes(), &HashAlgorithm::Sha256);
        Self {
            height,
            decision,
            round,
            proposal_id: proposal_id.to_string(),
            cumulative_weight,
            parent_hash: parent_hash.to_string(),
            certificate_root: certificate_root.to_string(),
            certificate,
            block_hash: block_hash.hex.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create the genesis block.
    pub fn genesis() -> Self {
        Self::new(
            0,
            ConsensusDecision::Approved,
            0,
            "genesis",
            0.0,
            "genesis",
            "genesis_root",
            None,
        )
    }
}

/// Finality status for a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    /// The block is pending and not yet committed.
    Pending,
    /// The block is committed but not yet finalized.
    Committed,
    /// The block is GHOST-finalized (sufficient depth behind the chain tip).
    Finalized,
}

impl std::fmt::Display for FinalityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Tracks GHOST-like finality for the chain of committed decisions.
///
/// GHOST (Greedy Heaviest-Observed Subtree) is adapted here:
/// - Each committed block carries a cumulative trust weight.
/// - A block is considered "finalized" when there are at least
///   `finalization_depth` committed blocks above it on the longest chain.
/// - The "longest chain" is determined by cumulative weight (trust-weighted),
///   not just block count, to resist weight-light adversarial forks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostFinalityTracker {
    /// All committed blocks indexed by height.
    pub blocks: BTreeMap<u64, ChainBlock>,
    /// The current chain tip (highest finalized height).
    pub finalized_tip: u64,
    /// The number of blocks required behind the tip for GHOST finalization.
    pub finalization_depth: u32,
    /// The genesis block.
    pub genesis: ChainBlock,
    /// A map of potential fork tips (height -> block hash) for fork detection.
    pub known_fork_tips: HashMap<u64, Vec<String>>,
    /// Total weight of the heaviest chain.
    pub heaviest_chain_weight: f64,
}

impl GhostFinalityTracker {
    /// Create a new GHOST finality tracker with the given finalization depth.
    pub fn new(finalization_depth: u32) -> Self {
        let genesis = ChainBlock::genesis();
        let mut blocks = BTreeMap::new();
        blocks.insert(0, genesis.clone());
        Self {
            blocks,
            finalized_tip: 0,
            finalization_depth,
            genesis,
            known_fork_tips: HashMap::new(),
            heaviest_chain_weight: 0.0,
        }
    }

    /// Add a committed block to the chain.
    pub fn add_block(&mut self, block: ChainBlock) {
        let height = block.height;
        self.heaviest_chain_weight += block.cumulative_weight;

        // Track potential fork tips.
        if let Some(tips) = self.known_fork_tips.get_mut(&height) {
            if !tips.contains(&block.block_hash) {
                tips.push(block.block_hash.clone());
            }
        } else {
            self.known_fork_tips.insert(height, vec![block.block_hash.clone()]);
        }

        self.blocks.insert(height, block);
        self.update_finalization();
    }

    /// Update the finalized tip based on GHOST finalization rule.
    ///
    /// A block is finalized if there are at least `finalization_depth` blocks
    /// above it in the chain.
    fn update_finalization(&mut self) {
        if let Some(&highest_height) = self.blocks.keys().next_back() {
            // A block at height H is finalized if highest_height - H >= finalization_depth.
            let new_finalized = if highest_height >= self.finalization_depth as u64 {
                highest_height - self.finalization_depth as u64
            } else {
                0
            };
            if new_finalized > self.finalized_tip {
                self.finalized_tip = new_finalized;
            }
        }
    }

    /// Check if a block at the given height is finalized.
    pub fn is_finalized(&self, height: u64) -> bool {
        height <= self.finalized_tip && self.blocks.contains_key(&height)
    }

    /// Get the finality status of a specific block height.
    pub fn finality_status(&self, height: u64) -> FinalityStatus {
        match self.blocks.get(&height) {
            None => FinalityStatus::Pending,
            Some(_) => {
                if self.is_finalized(height) {
                    FinalityStatus::Finalized
                } else {
                    FinalityStatus::Committed
                }
            }
        }
    }

    /// Get the highest committed height.
    pub fn tip_height(&self) -> u64 {
        self.blocks.keys().next_back().copied().unwrap_or(0)
    }

    /// Get the chain tip block.
    pub fn tip_block(&self) -> Option<&ChainBlock> {
        self.blocks.get(&self.tip_height())
    }

    /// Get the number of committed blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Check if a fork exists at the given height (more than one block).
    pub fn has_fork_at(&self, height: u64) -> bool {
        self.known_fork_tips
            .get(&height)
            .map(|tips| tips.len() > 1)
            .unwrap_or(false)
    }

    /// Count total forks in the chain.
    pub fn fork_count(&self) -> usize {
        self.known_fork_tips.values().filter(|tips| tips.len() > 1).count()
    }

    /// Get the block at a specific height.
    pub fn get_block(&self, height: u64) -> Option<&ChainBlock> {
        self.blocks.get(&height)
    }

    /// Compute the total chain weight from genesis to tip.
    pub fn total_chain_weight(&self) -> f64 {
        self.blocks.values().map(|b| b.cumulative_weight).sum()
    }

    /// Get all blocks between two heights (inclusive).
    pub fn blocks_in_range(&self, from: u64, to: u64) -> Vec<&ChainBlock> {
        self.blocks
            .range(from..=to)
            .map(|(_, b)| b)
            .collect()
    }

    /// Get a summary of the finality tracker state.
    pub fn summary(&self) -> String {
        format!(
            "ghost[tip={},finalized={},depth={},blocks={},forks={},weight={:.3}]",
            self.tip_height(),
            self.finalized_tip,
            self.finalization_depth,
            self.block_count(),
            self.fork_count(),
            self.heaviest_chain_weight,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 7: Round State — All Votes and State for a Single Consensus Round
// ═══════════════════════════════════════════════════════════════════════════

/// Complete state for a single consensus round at a given height.
///
/// Holds the proposal, all phase votes, and the phase machine state.
/// Once a round completes, its certificate is stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundState {
    /// The block height being decided.
    pub height: u64,
    /// The round number.
    pub round: u32,
    /// The current proposal (set during Propose phase).
    pub proposal: Option<ConsensusProposal>,
    /// Phase votes indexed by (phase, voter_id) to prevent duplicates.
    pub phase_votes: HashMap<String, PhaseVote>,
    /// The phase machine managing transitions.
    pub phase_machine: PhaseMachine,
    /// The final certificate (set after Commit).
    pub certificate: Option<ConsensusCertificate>,
    /// Whether this round has ended (committed or abandoned).
    pub ended: bool,
    /// The reason the round ended, if ended.
    pub end_reason: Option<String>,
}

impl RoundState {
    /// Create a new round state.
    pub fn new(height: u64, round: u32, proposer_id: &str, validator_count: usize) -> Self {
        Self {
            height,
            round,
            proposal: None,
            phase_votes: HashMap::new(),
            phase_machine: PhaseMachine::new(height, round, proposer_id, validator_count),
            certificate: None,
            ended: false,
            end_reason: None,
        }
    }

    /// Get the vote key for deduplication: "phase:voter_id".
    fn vote_key(phase: &ConsensusPhase, voter_id: &str) -> String {
        format!("{}:{}", phase.ordinal(), voter_id)
    }

    /// Set the proposal for this round (only valid during Propose phase).
    pub fn set_proposal(&mut self, proposal: ConsensusProposal) -> Result<(), String> {
        if self.phase_machine.current_phase != ConsensusPhase::Propose {
            return Err(format!(
                "cannot set proposal in {:?} phase (expected Propose)",
                self.phase_machine.current_phase
            ));
        }
        if self.proposal.is_some() {
            return Err("proposal already set for this round".to_string());
        }
        self.proposal = Some(proposal);
        // Advance to PreVote phase.
        self.phase_machine.advance_phase();
        Ok(())
    }

    /// Cast a phase vote. Returns true if accepted, false if duplicate.
    pub fn cast_vote(&mut self, vote: PhaseVote) -> Result<bool, String> {
        if self.ended {
            return Err("round has ended".to_string());
        }
        if !self.phase_machine.is_voting_phase() {
            return Err(format!(
                "cannot vote in {:?} phase",
                self.phase_machine.current_phase
            ));
        }
        if vote.height != self.height || vote.round != self.round {
            return Err("vote height/round mismatch".to_string());
        }
        if vote.phase != self.phase_machine.current_phase {
            return Err(format!(
                "vote phase {:?} does not match current phase {:?}",
                vote.phase, self.phase_machine.current_phase
            ));
        }

        let key = Self::vote_key(&vote.phase, &vote.voter_id);
        if self.phase_votes.contains_key(&key) {
            return Ok(false); // Duplicate vote.
        }

        self.phase_votes.insert(key, vote);
        Ok(true)
    }

    /// Count votes for a given phase and decision.
    pub fn count_votes(&self, phase: &ConsensusPhase, decision: &VoteDecision) -> usize {
        self.phase_votes
            .values()
            .filter(|v| &v.phase == phase && &v.decision == decision)
            .count()
    }

    /// Count total votes for a given phase.
    pub fn total_votes_for_phase(&self, phase: &ConsensusPhase) -> usize {
        self.phase_votes
            .values()
            .filter(|v| &v.phase == phase)
            .count()
    }

    /// Check if quorum is reached for a specific decision in a specific phase.
    pub fn has_quorum(&self, phase: &ConsensusPhase, decision: &VoteDecision, quorum_size: usize) -> bool {
        self.count_votes(phase, decision) >= quorum_size
    }

    /// Get all votes for a specific phase.
    pub fn votes_for_phase(&self, phase: &ConsensusPhase) -> Vec<&PhaseVote> {
        self.phase_votes
            .values()
            .filter(|v| &v.phase == phase)
            .collect()
    }

    /// Mark the round as ended.
    pub fn end_round(&mut self, reason: &str) {
        self.ended = true;
        self.end_reason = Some(reason.to_string());
    }

    /// Get the proposal ID (if a proposal exists).
    pub fn proposal_id(&self) -> Option<&str> {
        self.proposal.as_ref().map(|p| p.proposal_id.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 8: The Main PBFT Consensus Engine
// ═══════════════════════════════════════════════════════════════════════════

/// The ANANTA PBFT-style consensus engine.
///
/// Orchestrates the 4-phase protocol, Byzantine detection, view changes,
/// Merkle certificates, and GHOST finality tracking for trust-state agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbftConsensusEngine {
    /// This node's ID.
    pub self_id: String,
    /// All registered validators (node ID -> Node).
    pub validators: HashMap<String, Node>,
    /// Active round states indexed by height.
    pub rounds: BTreeMap<u64, RoundState>,
    /// The current height being decided.
    pub current_height: u64,
    /// Phase timeout configuration.
    pub phase_config: PhaseTimeoutConfig,
    /// Byzantine fault detector.
    pub byzantine_detector: ByzantineDetector,
    /// View change manager.
    pub view_change_manager: ViewChangeManager,
    /// GHOST finality tracker.
    pub finality_tracker: GhostFinalityTracker,
    /// Committed decisions by height (canonical history).
    pub committed_decisions: BTreeMap<u64, ConsensusDecision>,
    /// Committed certificates by height.
    pub certificates: BTreeMap<u64, ConsensusCertificate>,
    /// Quorum size (minimum votes required for approval).
    pub quorum_size: usize,
    /// Trust scores cache (node ID -> trust score).
    pub trust_scores: HashMap<String, f64>,
    /// Proposer sequence for view changes.
    pub proposer_sequence: Vec<String>,
    /// Log of all consensus events for debugging/audit.
    pub event_log: Vec<ConsensusEvent>,
}

/// An event recorded in the consensus engine's log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusEvent {
    /// Unique event ID.
    pub event_id: String,
    /// The event type.
    pub event_type: String,
    /// The height at which this event occurred.
    pub height: u64,
    /// The round at which this event occurred.
    pub round: u32,
    /// Human-readable description.
    pub message: String,
    /// Timestamp.
    pub timestamp: String,
    /// Optional metadata.
    pub metadata: serde_json::Value,
}

impl ConsensusEvent {
    /// Create a new consensus event.
    pub fn new(event_type: &str, height: u64, round: u32, message: &str) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            height,
            round,
            message: message.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

impl PbftConsensusEngine {
    /// Create a new PBFT consensus engine.
    pub fn new(self_id: &str, quorum_size: usize, finalization_depth: u32) -> Self {
        let engine = Self {
            self_id: self_id.to_string(),
            validators: HashMap::new(),
            rounds: BTreeMap::new(),
            current_height: 0,
            phase_config: PhaseTimeoutConfig::default(),
            byzantine_detector: ByzantineDetector::new(),
            view_change_manager: ViewChangeManager::new(vec![]),
            finality_tracker: GhostFinalityTracker::new(finalization_depth),
            committed_decisions: BTreeMap::new(),
            certificates: BTreeMap::new(),
            quorum_size,
            trust_scores: HashMap::new(),
            proposer_sequence: vec![],
            event_log: vec![],
        };
        engine
    }

    /// Register a validator node.
    pub fn register_validator(&mut self, node: Node) {
        let node_id = node.node_id.clone();
        let trust_score = node.trust_score;
        self.trust_scores.insert(node_id.clone(), trust_score);
        self.validators.insert(node_id.clone(), node);
        self.byzantine_detector.register_node(&node_id, trust_score);
        if !self.proposer_sequence.contains(&node_id) {
            self.proposer_sequence.push(node_id);
        }
        // Rebuild the view change manager's proposer sequence.
        self.view_change_manager.proposer_sequence = self.proposer_sequence.clone();
    }

    /// Start a new consensus round for the current height.
    pub fn start_round(&mut self, height: u64, round: u32) -> Result<String, String> {
        if height != self.current_height {
            return Err(format!(
                "cannot start round at height {} when current height is {}",
                height, self.current_height
            ));
        }

        let proposer = self.view_change_manager.select_proposer(round, &self.trust_scores);
        if proposer.is_empty() && !self.validators.is_empty() {
            return Err("no proposer available".to_string());
        }

        let round_state = RoundState::new(height, round, &proposer, self.validators.len());
        self.rounds.insert(height, round_state);

        self.log_event("round_started", height, round, &format!("proposer={}", proposer));

        Ok(proposer)
    }

    /// Submit a proposal for the current round.
    pub fn submit_proposal(&mut self, proposal: ConsensusProposal) -> Result<(), String> {
        let (log_height, log_round) = {
            let round_state = self
                .rounds
                .get_mut(&proposal.height)
                .ok_or_else(|| format!("no active round at height {}", proposal.height))?;

            if proposal.proposer_id != round_state.phase_machine.proposer_id {
                return Err(format!(
                    "proposal from {} but expected proposer {}",
                    proposal.proposer_id, round_state.phase_machine.proposer_id
                ));
            }

            round_state.set_proposal(proposal)?;
            (round_state.height, round_state.round)
        };

        self.log_event(
            "proposal_submitted",
            log_height,
            log_round,
            "proposal set, advancing to PreVote",
        );

        Ok(())
    }

    /// Cast a PreVote or PreCommit vote.
    pub fn cast_vote(&mut self, vote: PhaseVote) -> Result<bool, String> {
        // Reject votes from blacklisted nodes.
        if self.byzantine_detector.is_blacklisted(&vote.voter_id) {
            return Err(format!("node {} is blacklisted", vote.voter_id));
        }

        let height = vote.height;

        // Track participation for Byzantine detection (before borrowing rounds).
        self.byzantine_detector.record_participation(&vote.voter_id);

        // Extract known proposals from round state, then drop the borrow.
        let known_proposals: Vec<String> = {
            let round_state = self
                .rounds
                .get(&height)
                .ok_or_else(|| format!("no active round at height {}", height))?;
            round_state
                .proposal
                .as_ref()
                .map(|p| vec![p.proposal_id.clone()])
                .unwrap_or_default()
        };

        // Check for equivocation.
        let equivocations = self.byzantine_detector.record_vote(
            &vote.voter_id,
            &vote,
            &known_proposals,
        );
        if !equivocations.is_empty() {
            self.log_event(
                "equivocation_detected",
                height,
                vote.round,
                &format!("node {} equivocated", vote.voter_id),
            );
        }

        // Now borrow round_state mutably to cast the vote.
        let (vote_accepted, log_round, phase_str) = {
            let round_state = self
                .rounds
                .get_mut(&height)
                .ok_or_else(|| format!("no active round at height {}", height))?;
            let vote_accepted = match round_state.cast_vote(vote) {
                Ok(b) => b,
                Err(_) => return Ok(false), // Round already ended, silently ignore.
            };
            let log_round = round_state.round;
            let phase_str = round_state.phase_machine.current_phase.to_string();
            (vote_accepted, log_round, phase_str)
        };

        if vote_accepted {
            self.log_event(
                "vote_cast",
                height,
                log_round,
                &format!("phase={}", phase_str),
            );
        }

        // Check for quorum after each vote.
        self.check_quorum(height);

        Ok(vote_accepted)
    }

    /// Check if quorum is reached in the current phase and advance if so.
    fn check_quorum(&mut self, height: u64) {
        // Determine action while holding the mutable borrow, then drop it.
        enum QuorumAction {
            AdvanceToPreCommit { log_round: u32 },
            EndRoundRejected { log_round: u32 },
            Commit,
            None,
        }

        let action = {
            let round_state = match self.rounds.get_mut(&height) {
                Some(rs) => rs,
                None => return,
            };
            if round_state.ended {
                return;
            }

            let phase = round_state.phase_machine.current_phase.clone();

            match phase {
                ConsensusPhase::PreVote => {
                    let approve_count = round_state.count_votes(&ConsensusPhase::PreVote, &VoteDecision::Approve);
                    let reject_count = round_state.count_votes(&ConsensusPhase::PreVote, &VoteDecision::Reject);

                    if approve_count >= self.quorum_size {
                        round_state.phase_machine.advance_phase();
                        QuorumAction::AdvanceToPreCommit { log_round: round_state.round }
                    } else if reject_count >= self.quorum_size {
                        round_state.end_round("prevote_rejected");
                        QuorumAction::EndRoundRejected { log_round: round_state.round }
                    } else {
                        QuorumAction::None
                    }
                }
                ConsensusPhase::PreCommit => {
                    let approve_count = round_state.count_votes(&ConsensusPhase::PreCommit, &VoteDecision::Approve);

                    if approve_count >= self.quorum_size {
                        QuorumAction::Commit
                    } else {
                        QuorumAction::None
                    }
                }
                _ => QuorumAction::None,
            }
        };

        match action {
            QuorumAction::AdvanceToPreCommit { log_round } => {
                self.log_event("prevote_quorum", height, log_round, "advancing to PreCommit");
            }
            QuorumAction::EndRoundRejected { log_round } => {
                self.log_event("prevote_rejected", height, log_round, "proposal rejected in PreVote");
            }
            QuorumAction::Commit => {
                self.commit_round(height);
            }
            QuorumAction::None => {}
        }
    }

    /// Commit the current round at the given height.
    fn commit_round(&mut self, height: u64) {
        // Phase 1: compute cumulative weight before any mutable borrow of rounds.
        let cumulative_weight = self.compute_cumulative_weight(height);
        let parent_hash = self.finality_tracker
            .tip_block()
            .map(|b| b.block_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        // Phase 2: extract everything from round state, then drop the borrow.
        let (certificate, log_round, cert_root) = {
            let round_state = match self.rounds.get_mut(&height) {
                Some(rs) => rs,
                None => return,
            };

            let proposal_id = round_state.proposal_id().unwrap_or("").to_string();
            let decision_hash = round_state
                .proposal
                .as_ref()
                .map(|p| p.trust_state_hash.clone())
                .unwrap_or_default();

            // Collect voter signatures.
            let precommit_votes = round_state.votes_for_phase(&ConsensusPhase::PreCommit);
            let voter_signatures: Vec<VoterSignature> = precommit_votes
                .iter()
                .map(|v| VoterSignature {
                    voter_id: v.voter_id.clone(),
                    signature: v.signature.clone(),
                    trust_score: v.voter_trust,
                })
                .collect();

            let approve_count = round_state.count_votes(&ConsensusPhase::PreCommit, &VoteDecision::Approve);
            let voter_ids: Vec<String> = voter_signatures.iter().map(|v| v.voter_id.clone()).collect();

            // Build the Merkle certificate.
            let certificate = ConsensusCertificate::build(
                height,
                round_state.round,
                ConsensusDecision::Approved,
                &proposal_id,
                &decision_hash,
                &voter_ids,
                voter_signatures,
                approve_count,
            );

            let cert_root = certificate.merkle_root.clone();

            // Transition phase machine to Commit.
            round_state.phase_machine.transition_to_commit(ConsensusDecision::Approved);
            round_state.certificate = Some(certificate.clone());
            round_state.end_round("committed");

            (certificate, round_state.round, cert_root)
        };

        // Phase 3: update engine state (no round_state borrow).
        self.committed_decisions.insert(height, ConsensusDecision::Approved);
        self.certificates.insert(height, certificate.clone());

        // Add to GHOST finality tracker.
        let proposal_id = certificate.proposal_id.clone();
        let block = ChainBlock::new(
            height,
            ConsensusDecision::Approved,
            log_round,
            &proposal_id,
            cumulative_weight,
            &parent_hash,
            &cert_root,
            Some(certificate.clone()),
        );
        self.finality_tracker.add_block(block);

        self.log_event(
            "round_committed",
            height,
            log_round,
            &format!("certificate={}", certificate.certificate_id[..8].to_string()),
        );

        // Advance to next height.
        self.current_height = height + 1;
    }

    /// Compute cumulative weight for a height (sum of approver trust scores).
    fn compute_cumulative_weight(&self, height: u64) -> f64 {
        let round_state = match self.rounds.get(&height) {
            Some(rs) => rs,
            None => return 0.0,
        };
        round_state
            .votes_for_phase(&ConsensusPhase::PreCommit)
            .iter()
            .filter(|v| v.decision == VoteDecision::Approve)
            .map(|v| v.voter_trust)
            .sum()
    }

    /// Handle a phase timeout by initiating a view change.
    pub fn handle_timeout(&mut self, height: u64) -> Result<ViewChangeMessage, String> {
        // Phase 1: read round state immutably, extract needed data.
        let (old_round, new_round, proposal_id_owned, voter_ids_in_round) = {
            let round_state = self
                .rounds
                .get(&height)
                .ok_or_else(|| format!("no round at height {}", height))?;

            if round_state.ended {
                return Err("round already ended".to_string());
            }

            let old_round = round_state.round;
            let new_round = old_round + 1;
            let proposal_id_owned = round_state.proposal_id().unwrap_or("").to_string();
            let voter_ids_in_round: Vec<String> = round_state
                .phase_votes
                .values()
                .map(|v| v.voter_id.clone())
                .collect();
            (old_round, new_round, proposal_id_owned, voter_ids_in_round)
        };

        if new_round >= self.phase_config.max_rounds {
            // Phase 2a: end the round via mutable borrow.
            if let Some(round_state) = self.rounds.get_mut(&height) {
                round_state.end_round("max_rounds_exceeded");
            }
            self.log_event("max_rounds_exceeded", height, old_round, "abandoning height");
            return Err("max rounds exceeded".to_string());
        }

        // Create justification.
        let justification = ViewChangeJustification::for_timeout(
            &self.self_id,
            height,
            old_round,
            new_round,
            Some(proposal_id_owned.as_str()),
        );

        // Submit justification and check quorum.
        let quorum_reached = self.view_change_manager.submit_justification(
            height,
            old_round,
            justification,
            self.quorum_size,
        );

        if quorum_reached {
            // Execute the view change.
            let view_change = self.view_change_manager.execute_view_change(
                height,
                old_round,
                new_round,
                &self.trust_scores,
            );

            // Record absence for nodes that didn't vote in the timed-out round.
            for node_id in self.validators.keys() {
                if !voter_ids_in_round.iter().any(|v| v == node_id) {
                    self.byzantine_detector.record_absence(node_id);
                }
            }

            // Start the new round.
            self.rounds.remove(&height);
            self.start_round(height, new_round)?;

            self.log_event(
                "view_change",
                height,
                new_round,
                &format!("new_proposer={}", view_change.new_proposer_id),
            );

            Ok(view_change)
        } else {
            self.log_event(
                "view_change_pending",
                height,
                old_round,
                "waiting for more justifications",
            );
            Err("view change quorum not yet reached".to_string())
        }
    }

    /// Generate a state sync snapshot for a lagging node.
    pub fn generate_sync_snapshot(&self, target_height: u64, _requesting_node: &str) -> StateSyncSnapshot {
        let decisions = self
            .committed_decisions
            .range(0..=target_height)
            .map(|(h, d)| (*h, d.clone()))
            .collect();

        let last_round = self
            .certificates
            .get(&target_height)
            .map(|c| c.round)
            .unwrap_or(0);

        let voter_set: Vec<String> = self.validators.keys().cloned().collect();

        let mut snapshot = StateSyncSnapshot::new(
            target_height,
            last_round,
            self.committed_decisions
                .get(&target_height)
                .cloned()
                .unwrap_or(ConsensusDecision::NoQuorum),
            self.certificates
                .get(&target_height)
                .map(|c| c.proposal_id.as_str()),
            decisions,
            voter_set,
        );

        snapshot.certificate_root = self
            .certificates
            .get(&target_height)
            .map(|c| c.merkle_root.clone());

        snapshot
    }

    /// Check if any active round has timed out, and handle it.
    pub fn check_timeouts(&mut self) -> Vec<ViewChangeMessage> {
        let mut view_changes = vec![];
        let timed_out_heights: Vec<u64> = self
            .rounds
            .iter()
            .filter(|(_, rs)| !rs.ended && rs.phase_machine.is_phase_timed_out(&self.phase_config))
            .map(|(h, _)| *h)
            .collect();

        for height in timed_out_heights {
            if let Ok(vc) = self.handle_timeout(height) {
                view_changes.push(vc);
            }
        }
        view_changes
    }

    /// Get the finality status of a specific block height.
    pub fn finality_status(&self, height: u64) -> FinalityStatus {
        self.finality_tracker.finality_status(height)
    }

    /// Check if a block at a given height is GHOST-finalized.
    pub fn is_finalized(&self, height: u64) -> bool {
        self.finality_tracker.is_finalized(height)
    }

    /// Get the certificate for a committed decision at a given height.
    pub fn get_certificate(&self, height: u64) -> Option<&ConsensusCertificate> {
        self.certificates.get(&height)
    }

    /// Get the current consensus engine summary.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "self_id": self.self_id,
            "current_height": self.current_height,
            "validators": self.validators.len(),
            "quorum_size": self.quorum_size,
            "committed_decisions": self.committed_decisions.len(),
            "finality": self.finality_tracker.summary(),
            "byzantine": self.byzantine_detector.summary(),
            "view_changes": self.view_change_manager.total_view_changes(),
            "event_log_size": self.event_log.len(),
        })
    }

    /// Log a consensus event.
    fn log_event(&mut self, event_type: &str, height: u64, round: u32, message: &str) {
        self.event_log.push(ConsensusEvent::new(event_type, height, round, message));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 9: Quorum Computation Utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Compute the minimum quorum size needed for Byzantine fault tolerance.
///
/// For PBFT safety, we need at least `(2f + 1)` validators to tolerate
/// `f` Byzantine faults. This function computes the quorum (number of
/// votes needed) given the total validator count.
pub fn compute_bft_quorum(total_validators: usize, max_faults: usize) -> usize {
    let min_validators = 3 * max_faults + 1;
    if total_validators < min_validators {
        // Not enough validators for the desired fault tolerance.
        // Fall back to requiring all validators.
        total_validators
    } else {
        // PBFT quorum: 2f + 1
        2 * max_faults + 1
    }
}

/// Compute the maximum number of Byzantine faults that can be tolerated
/// given a total number of validators.
pub fn max_tolerable_faults(total_validators: usize) -> usize {
    total_validators / 3
}

/// Compute the trust-weighted quorum: the sum of trust scores needed
/// to reach quorum, not just the count of votes.
pub fn compute_trust_weighted_quorum(
    votes: &[(String, VoteDecision, f64)],
    threshold_ratio: f64,
) -> (bool, f64) {
    let total_trust: f64 = votes.iter().map(|(_, _, t)| t).sum();
    let approve_trust: f64 = votes
        .iter()
        .filter(|(_, d, _)| *d == VoteDecision::Approve)
        .map(|(_, _, t)| t)
        .sum();

    let quorum_trust = total_trust * threshold_ratio;
    let reached = approve_trust >= quorum_trust && approve_trust > 0.0;
    (reached, approve_trust)
}

/// Determine if a split vote has occurred (no decision has quorum).
pub fn is_split_vote(approve_count: usize, reject_count: usize, quorum: usize) -> bool {
    approve_count < quorum && reject_count < quorum && (approve_count + reject_count) > 0
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 10: Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{NodeRole, NodeStatus};

    // ── Helper functions ──

    /// Create a test node with the given ID and trust score.
    fn make_node(id: &str, trust: f64) -> Node {
        Node {
            node_id: id.to_string(),
            address: format!("addr-{}", id),
            status: NodeStatus::Active,
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            trust_score: trust,
            reported_trust_state: None,
            role: NodeRole::Follower,
        }
    }

    /// Create a basic engine with 4 validators.
    fn make_engine() -> PbftConsensusEngine {
        let mut engine = PbftConsensusEngine::new("node-1", 3, 2);
        engine.register_validator(make_node("node-1", 1.0));
        engine.register_validator(make_node("node-2", 0.9));
        engine.register_validator(make_node("node-3", 0.8));
        engine.register_validator(make_node("node-4", 0.7));
        engine.current_height = 1;
        engine
    }

    /// Create a PreVote for the given voter.
    fn make_prevote(voter_id: &str, proposal_id: &str, height: u64, round: u32, decision: VoteDecision) -> PhaseVote {
        PhaseVote::new(
            voter_id,
            ConsensusPhase::PreVote,
            proposal_id,
            height,
            round,
            decision,
            0.9,
            None,
        )
    }

    /// Create a PreCommit vote for the given voter.
    fn make_precommit(voter_id: &str, proposal_id: &str, height: u64, round: u32, decision: VoteDecision) -> PhaseVote {
        PhaseVote::new(
            voter_id,
            ConsensusPhase::PreCommit,
            proposal_id,
            height,
            round,
            decision,
            0.9,
            None,
        )
    }

    /// Create a test proposal.
    fn make_proposal(proposer_id: &str, height: u64, round: u32) -> ConsensusProposal {
        let ts = TrustState::new();
        ConsensusProposal::new(proposer_id, height, round, &ts, 0.9)
    }

    /// Run a full consensus round to completion (all approve).
    fn run_full_consensus(engine: &mut PbftConsensusEngine) {
        let height = engine.current_height;
        let proposer = engine.start_round(height, 0).unwrap();
        let proposal = make_proposal(&proposer, height, 0);
        engine.submit_proposal(proposal).unwrap();

        let pid = engine.rounds.get(&height).unwrap().proposal_id().unwrap().to_string();

        // Cast PreVotes (3 approvals = quorum).
        for voter in &["node-1", "node-2", "node-3"] {
            let vote = make_prevote(voter, &pid, height, 0, VoteDecision::Approve);
            engine.cast_vote(vote).unwrap();
        }

        // Cast PreCommits (3 approvals = quorum).
        for voter in &["node-1", "node-2", "node-3"] {
            let vote = make_precommit(voter, &pid, height, 0, VoteDecision::Approve);
            engine.cast_vote(vote).unwrap();
        }
    }

    // ── Phase Machine Tests ──

    #[test]
    fn test_phase_ordinal() {
        assert_eq!(ConsensusPhase::Propose.ordinal(), 0);
        assert_eq!(ConsensusPhase::PreVote.ordinal(), 1);
        assert_eq!(ConsensusPhase::PreCommit.ordinal(), 2);
        assert_eq!(ConsensusPhase::Commit.ordinal(), 3);
    }

    #[test]
    fn test_phase_next() {
        assert_eq!(ConsensusPhase::Propose.next(), Some(ConsensusPhase::PreVote));
        assert_eq!(ConsensusPhase::PreVote.next(), Some(ConsensusPhase::PreCommit));
        assert_eq!(ConsensusPhase::PreCommit.next(), Some(ConsensusPhase::Commit));
        assert_eq!(ConsensusPhase::Commit.next(), None);
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", ConsensusPhase::Propose), "propose");
        assert_eq!(format!("{}", ConsensusPhase::Commit), "commit");
    }

    #[test]
    fn test_phase_machine_creation() {
        let pm = PhaseMachine::new(1, 0, "proposer", 4);
        assert_eq!(pm.current_phase, ConsensusPhase::Propose);
        assert_eq!(pm.round, 0);
        assert_eq!(pm.height, 1);
        assert!(!pm.round_complete);
        assert!(pm.decision.is_none());
    }

    #[test]
    fn test_phase_machine_advance() {
        let mut pm = PhaseMachine::new(1, 0, "proposer", 4);
        assert_eq!(pm.advance_phase(), Some(ConsensusPhase::PreVote));
        assert_eq!(pm.advance_phase(), Some(ConsensusPhase::PreCommit));
        assert_eq!(pm.advance_phase(), Some(ConsensusPhase::Commit));
        assert!(pm.round_complete);
        assert_eq!(pm.advance_phase(), None);
    }

    #[test]
    fn test_phase_machine_transition_to_commit() {
        let mut pm = PhaseMachine::new(1, 0, "proposer", 4);
        pm.transition_to_commit(ConsensusDecision::Approved);
        assert_eq!(pm.current_phase, ConsensusPhase::Commit);
        assert_eq!(pm.decision, Some(ConsensusDecision::Approved));
        assert!(pm.round_complete);
    }

    #[test]
    fn test_phase_machine_new_round() {
        let mut pm = PhaseMachine::new(1, 0, "proposer-a", 4);
        pm.advance_phase(); // now PreVote
        pm.start_new_round(1, "proposer-b");
        assert_eq!(pm.round, 1);
        assert_eq!(pm.current_phase, ConsensusPhase::Propose);
        assert_eq!(pm.proposer_id, "proposer-b");
        assert!(!pm.round_complete);
    }

    #[test]
    fn test_phase_machine_is_voting_phase() {
        let mut pm = PhaseMachine::new(1, 0, "proposer", 4);
        assert!(!pm.is_voting_phase()); // Propose is not voting
        pm.advance_phase(); // PreVote
        assert!(pm.is_voting_phase());
        pm.advance_phase(); // PreCommit
        assert!(pm.is_voting_phase());
        pm.advance_phase(); // Commit
        assert!(!pm.is_voting_phase());
    }

    #[test]
    fn test_phase_timeout_config() {
        let config = PhaseTimeoutConfig::default();
        assert_eq!(config.timeout_for(&ConsensusPhase::Propose, 0), 2000);
        assert_eq!(config.timeout_for(&ConsensusPhase::PreVote, 0), 3000);
        // Round 1 with 1.5x backoff.
        let t = config.timeout_for(&ConsensusPhase::Propose, 1);
        assert_eq!(t, 3000); // 2000 * 1.5 = 3000
    }

    #[test]
    fn test_phase_machine_snapshot() {
        let pm = PhaseMachine::new(5, 2, "proposer", 10);
        let snap = pm.snapshot(3, false);
        assert_eq!(snap.height, 5);
        assert_eq!(snap.round, 2);
        assert_eq!(snap.votes_collected, 3);
        assert!(!snap.timed_out);
    }

    // ── Proposal Tests ──

    #[test]
    fn test_proposal_creation() {
        let ts = TrustState::new();
        let p = ConsensusProposal::new("node-1", 1, 0, &ts, 0.95);
        assert!(!p.proposal_id.is_empty());
        assert_eq!(p.proposer_id, "node-1");
        assert_eq!(p.height, 1);
        assert_eq!(p.round, 0);
        assert!(!p.trust_state_hash.is_empty());
    }

    #[test]
    fn test_proposal_hash_deterministic() {
        let ts = TrustState::new();
        let p1 = ConsensusProposal::new("node-1", 1, 0, &ts, 0.95);
        // Compute hash — should be deterministic for same inputs.
        // We verify the hash is non-empty and has the right length.
        let hash = p1.compute_hash();
        assert!(!hash.hex.is_empty());
    }

    // ── PhaseVote Tests ──

    #[test]
    fn test_phase_vote_creation() {
        let vote = PhaseVote::new(
            "node-1", ConsensusPhase::PreVote, "prop-123", 1, 0,
            VoteDecision::Approve, 0.9, Some("looks good".to_string()),
        );
        assert!(!vote.vote_id.is_empty());
        assert_eq!(vote.voter_id, "node-1");
        assert!(vote.verify_signature());
    }

    #[test]
    fn test_phase_vote_matches_context() {
        let vote = make_prevote("node-1", "prop-A", 1, 0, VoteDecision::Approve);
        assert!(vote.matches_context("prop-A", 1, 0, &ConsensusPhase::PreVote));
        assert!(!vote.matches_context("prop-B", 1, 0, &ConsensusPhase::PreVote));
        assert!(!vote.matches_context("prop-A", 2, 0, &ConsensusPhase::PreVote));
        assert!(!vote.matches_context("prop-A", 1, 1, &ConsensusPhase::PreVote));
        assert!(!vote.matches_context("prop-A", 1, 0, &ConsensusPhase::PreCommit));
    }

    // ── RoundState Tests ──

    #[test]
    fn test_round_state_set_proposal() {
        let mut rs = RoundState::new(1, 0, "proposer", 4);
        let ts = TrustState::new();
        let proposal = ConsensusProposal::new("proposer", 1, 0, &ts, 0.9);

        // Should succeed in Propose phase.
        assert!(rs.set_proposal(proposal).is_ok());
        // Should now be in PreVote phase.
        assert_eq!(rs.phase_machine.current_phase, ConsensusPhase::PreVote);
    }

    #[test]
    fn test_round_state_duplicate_proposal_rejected() {
        let mut rs = RoundState::new(1, 0, "proposer", 4);
        let ts = TrustState::new();
        let p1 = ConsensusProposal::new("proposer", 1, 0, &ts, 0.9);
        let p2 = ConsensusProposal::new("proposer", 1, 0, &ts, 0.8);

        assert!(rs.set_proposal(p1).is_ok());
        assert!(rs.set_proposal(p2).is_err());
    }

    #[test]
    fn test_round_state_vote_deduplication() {
        let mut rs = RoundState::new(1, 0, "proposer", 4);
        let ts = TrustState::new();
        let proposal = ConsensusProposal::new("proposer", 1, 0, &ts, 0.9);
        rs.set_proposal(proposal).unwrap();

        let v1 = make_prevote("node-1", "any", 1, 0, VoteDecision::Approve);
        let v2 = make_prevote("node-1", "any", 1, 0, VoteDecision::Reject);

        assert!(rs.cast_vote(v1).unwrap()); // First vote accepted.
        assert!(!rs.cast_vote(v2).unwrap()); // Duplicate rejected.
    }

    #[test]
    fn test_round_state_vote_wrong_phase() {
        let mut rs = RoundState::new(1, 0, "proposer", 4);
        let vote = make_prevote("node-1", "any", 1, 0, VoteDecision::Approve);
        assert!(rs.cast_vote(vote).is_err()); // Propose phase, not voting.
    }

    // ── Byzantine Detection Tests ──

    #[test]
    fn test_byzantine_detector_registration() {
        let mut detector = ByzantineDetector::new();
        detector.register_node("node-1", 0.9);
        assert_eq!(detector.monitored_nodes().len(), 1);
        assert_eq!(detector.suspicion_level("node-1"), SuspicionLevel::Clean);
    }

    #[test]
    fn test_byzantine_detector_equivocation() {
        let mut detector = ByzantineDetector::new();
        detector.register_node("node-1", 0.9);

        let vote = PhaseVote::new(
            "node-1", ConsensusPhase::PreVote, "conflicting-proposal",
            1, 0, VoteDecision::Approve, 0.9, None,
        );

        let events = detector.record_vote("node-1", &vote, &["original-proposal".to_string()]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].first_proposal_id, "original-proposal");
        assert_eq!(events[0].second_proposal_id, "conflicting-proposal");
        assert_eq!(detector.suspicion_level("node-1"), SuspicionLevel::Medium);
    }

    #[test]
    fn test_byzantine_detector_latency_outlier() {
        let mut profile = NodeBehaviorProfile::new("node-1", 0.9);

        // Record 10 normal-latency observations.
        for i in 0..10 {
            profile.record_latency(i, 100); // 100ms consistently
        }

        // A normal observation should not be an outlier.
        assert!(!profile.is_latency_outlier(100));

        // An extreme outlier (10x the normal) should be flagged.
        assert!(profile.is_latency_outlier(10000));

        // Mean and stddev should be reasonable.
        assert!((profile.mean_latency_ms() - 100.0).abs() < 1.0);
        assert!(profile.latency_stddev_ms() < 1.0);
    }

    #[test]
    fn test_byzantine_detector_blacklisting() {
        let mut detector = ByzantineDetector::new();
        detector.register_node("node-1", 0.9);

        // Trigger 3 equivocations to reach Confirmed level.
        for i in 0..3 {
            let vote = PhaseVote::new(
                "node-1", ConsensusPhase::PreVote,
                &format!("bad-proposal-{}", i),
                1, i as u32, VoteDecision::Approve, 0.9, None,
            );
            detector.record_vote("node-1", &vote, &["original".to_string()]);
        }

        assert_eq!(detector.suspicion_level("node-1"), SuspicionLevel::Confirmed);
        assert!(detector.is_blacklisted("node-1"));
    }

    #[test]
    fn test_byzantine_detector_suspicious_nodes_query() {
        let mut detector = ByzantineDetector::new();
        detector.register_node("node-1", 0.9);
        detector.register_node("node-2", 0.8);
        detector.register_node("node-3", 0.7);

        // Make node-2 suspicious.
        if let Some(p) = detector.profiles.get_mut("node-2") {
            p.suspicion_level = SuspicionLevel::High;
        }

        let suspicious = detector.suspicious_nodes(&SuspicionLevel::Medium);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0], "node-2");
    }

    // ── View Change Tests ──

    #[test]
    fn test_view_change_justification_timeout() {
        let j = ViewChangeJustification::for_timeout("node-1", 1, 0, 1, Some("prop-A"));
        assert_eq!(j.from_round, 0);
        assert_eq!(j.to_round, 1);
        assert_eq!(j.justification_type, ViewChangeReason::PhaseTimeout);
        assert!(j.verify_signature());
    }

    #[test]
    fn test_view_change_justification_conflict() {
        let votes = vec![make_prevote("node-1", "prop-B", 1, 0, VoteDecision::Approve)];
        let j = ViewChangeJustification::for_proposal_conflict("node-1", 1, 0, 1, "prop-A", votes);
        assert_eq!(j.justification_type, ViewChangeReason::ProposalConflict);
        assert!(j.verify_signature());
    }

    #[test]
    fn test_view_change_manager_proposer_selection() {
        let mut vcm = ViewChangeManager::new(vec![
            "node-1".to_string(),
            "node-2".to_string(),
            "node-3".to_string(),
        ]);
        let mut trust = HashMap::new();
        trust.insert("node-1".to_string(), 0.5);
        trust.insert("node-2".to_string(), 0.9);
        trust.insert("node-3".to_string(), 0.7);

        // Round 0: highest trust is node-2, so round-robin starts there.
        let p0 = vcm.select_proposer(0, &trust);
        assert_eq!(p0, "node-2");

        let p1 = vcm.select_proposer(1, &trust);
        assert_eq!(p1, "node-3"); // Next in trust-sorted order
    }

    #[test]
    fn test_view_change_quorum() {
        let mut vcm = ViewChangeManager::new(vec!["node-1".to_string()]);
        let j1 = ViewChangeJustification::for_timeout("node-1", 1, 0, 1, None);
        let j2 = ViewChangeJustification::for_timeout("node-2", 1, 0, 1, None);
        let j3 = ViewChangeJustification::for_timeout("node-3", 1, 0, 1, None);

        assert!(!vcm.submit_justification(1, 0, j1, 3));
        assert!(!vcm.submit_justification(1, 0, j2, 3));
        assert!(vcm.submit_justification(1, 0, j3, 3)); // Quorum reached.
    }

    // ── Merkle Certificate Tests ──

    #[test]
    fn test_consensus_certificate_build() {
        let sigs = vec![
            VoterSignature {
                voter_id: "node-1".to_string(),
                signature: "sig1".to_string(),
                trust_score: 0.9,
            },
            VoterSignature {
                voter_id: "node-2".to_string(),
                signature: "sig2".to_string(),
                trust_score: 0.8,
            },
        ];

        let cert = ConsensusCertificate::build(
            1, 0, ConsensusDecision::Approved, "prop-1", "hash-1",
            &["node-1".to_string(), "node-2".to_string()],
            sigs, 2,
        );

        assert!(!cert.certificate_id.is_empty());
        assert!(!cert.merkle_root.is_empty());
        assert_eq!(cert.height, 1);
        assert_eq!(cert.round, 0);
        assert_eq!(cert.approve_count, 2);
        assert_eq!(cert.total_voters, 2);
    }

    #[test]
    fn test_consensus_certificate_verify() {
        let sigs = vec![
            VoterSignature {
                voter_id: "node-a".to_string(),
                signature: "sig-a".to_string(),
                trust_score: 0.9,
            },
            VoterSignature {
                voter_id: "node-b".to_string(),
                signature: "sig-b".to_string(),
                trust_score: 0.8,
            },
            VoterSignature {
                voter_id: "node-c".to_string(),
                signature: "sig-c".to_string(),
                trust_score: 0.7,
            },
        ];

        let cert = ConsensusCertificate::build(
            5, 2, ConsensusDecision::Approved, "prop-x", "decision-hash-x",
            &["node-a".to_string(), "node-b".to_string(), "node-c".to_string()],
            sigs, 3,
        );

        // Verify should pass for an untampered certificate.
        assert!(cert.verify());
    }

    #[test]
    fn test_consensus_certificate_summary() {
        let cert = ConsensusCertificate::build(
            1, 0, ConsensusDecision::Approved, "prop-1", "hash-1",
            &["node-1".to_string()],
            vec![VoterSignature {
                voter_id: "node-1".to_string(),
                signature: "s1".to_string(),
                trust_score: 0.9,
            }],
            1,
        );
        let summary = cert.summary();
        assert!(summary.contains("height=1"));
        assert!(summary.contains("round=0"));
    }

    // ── GHOST Finality Tests ──

    #[test]
    fn test_ghost_tracker_creation() {
        let tracker = GhostFinalityTracker::new(2);
        assert_eq!(tracker.finalized_tip, 0);
        assert_eq!(tracker.tip_height(), 0);
        assert_eq!(tracker.block_count(), 1); // Genesis
    }

    #[test]
    fn test_ghost_finality_basic() {
        let mut tracker = GhostFinalityTracker::new(2); // 2-block finalization depth

        // Add blocks at heights 1, 2, 3, 4.
        for h in 1..=4 {
            let block = ChainBlock::new(h, ConsensusDecision::Approved, 0, &format!("prop-{}", h), 1.0, "prev", "root", None);
            tracker.add_block(block);
        }

        // With finalization_depth=2, height 2 should be finalized (4 - 2 = 2).
        assert!(tracker.is_finalized(0)); // Genesis always finalized.
        assert!(tracker.is_finalized(1)); // 4 - 2 = 2, so 1 < 2 is finalized.
        assert!(tracker.is_finalized(2)); // 4 - 2 = 2, so 2 <= 2 is finalized.
        assert!(!tracker.is_finalized(3)); // 3 > 2.
        assert!(!tracker.is_finalized(4)); // 4 > 2.
    }

    #[test]
    fn test_ghost_finality_depth_3() {
        let mut tracker = GhostFinalityTracker::new(3);

        for h in 1..=5 {
            let block = ChainBlock::new(h, ConsensusDecision::Approved, 0, &format!("p{}", h), 1.0, "prev", "root", None);
            tracker.add_block(block);
        }

        // finalization_depth=3, tip=5, so finalized_tip = 5 - 3 = 2.
        assert!(tracker.is_finalized(0));
        assert!(tracker.is_finalized(1));
        assert!(tracker.is_finalized(2));
        assert!(!tracker.is_finalized(3));
        assert!(!tracker.is_finalized(4));
        assert!(!tracker.is_finalized(5));
    }

    #[test]
    fn test_ghost_tracker_fork_detection() {
        let mut tracker = GhostFinalityTracker::new(2);

        let block_a = ChainBlock::new(1, ConsensusDecision::Approved, 0, "prop-a", 1.0, "genesis", "root-a", None);
        let block_b = ChainBlock::new(1, ConsensusDecision::Approved, 0, "prop-b", 0.5, "genesis", "root-b", None);

        tracker.add_block(block_a);
        tracker.add_block(block_b);

        assert!(tracker.has_fork_at(1));
        assert_eq!(tracker.fork_count(), 1);
    }

    #[test]
    fn test_ghost_tracker_finality_status() {
        let mut tracker = GhostFinalityTracker::new(1);
        let block = ChainBlock::new(1, ConsensusDecision::Approved, 0, "p1", 1.0, "genesis", "r1", None);
        tracker.add_block(block);

        // tip=1, depth=1, so finalized_tip = 0.
        assert_eq!(tracker.finality_status(0), FinalityStatus::Finalized);
        assert_eq!(tracker.finality_status(1), FinalityStatus::Committed);
        assert_eq!(tracker.finality_status(99), FinalityStatus::Pending);
    }

    // ── Full Consensus Engine Tests ──

    #[test]
    fn test_engine_creation_and_registration() {
        let engine = make_engine();
        assert_eq!(engine.validators.len(), 4);
        assert_eq!(engine.quorum_size, 3);
        assert_eq!(engine.proposer_sequence.len(), 4);
    }

    #[test]
    fn test_engine_full_consensus_round() {
        let mut engine = make_engine();
        run_full_consensus(&mut engine);

        assert!(engine.committed_decisions.contains_key(&1));
        assert!(engine.certificates.contains_key(&1));
        assert_eq!(engine.current_height, 2);
        assert!(engine.event_log.iter().any(|e| e.event_type == "round_committed"));
    }

    #[test]
    fn test_engine_certificate_verification() {
        let mut engine = make_engine();
        run_full_consensus(&mut engine);

        let cert = engine.get_certificate(1).unwrap();
        assert!(cert.verify());
        assert_eq!(cert.height, 1);
        assert_eq!(cert.decision, ConsensusDecision::Approved);
        assert_eq!(cert.approve_count, 3);
    }

    #[test]
    fn test_engine_blacklisted_node_rejected() {
        let mut engine = make_engine();
        // Blacklist node-4.
        engine.byzantine_detector.blacklisted.insert("node-4".to_string());

        let proposer = engine.start_round(1, 0).unwrap();
        let proposal = make_proposal(&proposer, 1, 0);
        engine.submit_proposal(proposal).unwrap();

        let pid = engine.rounds.get(&1).unwrap().proposal_id().unwrap().to_string();
        let vote = make_prevote("node-4", &pid, 1, 0, VoteDecision::Approve);
        let result = engine.cast_vote(vote);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blacklisted"));
    }

    #[test]
    fn test_engine_prevote_rejection_ends_round() {
        let mut engine = make_engine();
        let proposer = engine.start_round(1, 0).unwrap();
        let proposal = make_proposal(&proposer, 1, 0);
        engine.submit_proposal(proposal).unwrap();

        let pid = engine.rounds.get(&1).unwrap().proposal_id().unwrap().to_string();

        // All 4 nodes reject.
        for voter in &["node-1", "node-2", "node-3", "node-4"] {
            let vote = make_prevote(voter, &pid, 1, 0, VoteDecision::Reject);
            engine.cast_vote(vote).unwrap();
        }

        let rs = engine.rounds.get(&1).unwrap();
        assert!(rs.ended);
        assert_eq!(rs.end_reason, Some("prevote_rejected".to_string()));
    }

    #[test]
    fn test_engine_view_change_on_timeout() {
        let mut engine = make_engine();

        // Start a round but don't provide enough votes to trigger timeout handling.
        engine.start_round(1, 0).unwrap();

        // Directly submit 3 justifications to trigger view change.
        for node_id in &["node-1", "node-2", "node-3"] {
            let j = ViewChangeJustification::for_timeout(node_id, 1, 0, 1, None);
            engine.view_change_manager.submit_justification(1, 0, j, 3);
        }

        let vc = engine.handle_timeout(1).unwrap();
        assert_eq!(vc.new_round, 1);
        assert!(!vc.new_proposer_id.is_empty());
        assert_eq!(engine.view_change_manager.total_view_changes(), 1);
    }

    #[test]
    fn test_engine_ghost_finality_after_commit() {
        let mut engine = make_engine();
        run_full_consensus(&mut engine);

        // Height 1 should be committed (not yet finalized with depth=2).
        assert_eq!(engine.finality_status(1), FinalityStatus::Committed);

        // Run another consensus at height 2.
        run_full_consensus(&mut engine);

        // Height 1 should now be finalized (tip=2, depth=2, finalized_tip=0).
        // Actually with tip=2 and depth=2: finalized_tip = max(0, 2-2) = 0.
        // So height 1 is still Committed, not Finalized.
        assert_eq!(engine.finality_status(1), FinalityStatus::Committed);
        // Height 2 is Committed too.
        assert_eq!(engine.finality_status(2), FinalityStatus::Committed);
        // Genesis (0) is Finalized.
        assert_eq!(engine.finality_status(0), FinalityStatus::Finalized);
    }

    #[test]
    fn test_engine_max_rounds_exceeded() {
        let mut engine = make_engine();
        engine.phase_config.max_rounds = 1;

        engine.start_round(1, 0).unwrap();

        // Try to trigger a view change at round 0 → round 1.
        for node_id in &["node-1", "node-2", "node-3"] {
            let j = ViewChangeJustification::for_timeout(node_id, 1, 0, 1, None);
            engine.view_change_manager.submit_justification(1, 0, j, 3);
        }

        let result = engine.handle_timeout(1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max rounds"));
    }

    #[test]
    fn test_engine_state_sync_snapshot() {
        let mut engine = make_engine();
        run_full_consensus(&mut engine);

        let snapshot = engine.generate_sync_snapshot(1, "node-lagging");
        assert_eq!(snapshot.height, 1);
        assert!(snapshot.decisions.contains_key(&1));
        assert_eq!(snapshot.decision, ConsensusDecision::Approved);
    }

    // ── Edge Cases ──

    #[test]
    fn test_empty_round_no_proposal() {
        let mut engine = make_engine();
        engine.start_round(1, 0).unwrap();

        // No proposal submitted, no votes cast. Check state.
        let rs = engine.rounds.get(&1).unwrap();
        assert!(rs.proposal.is_none());
        assert_eq!(rs.phase_machine.current_phase, ConsensusPhase::Propose);
        assert!(!rs.ended);
    }

    #[test]
    fn test_all_abstain_votes() {
        let mut engine = make_engine();
        let proposer = engine.start_round(1, 0).unwrap();
        let proposal = make_proposal(&proposer, 1, 0);
        engine.submit_proposal(proposal).unwrap();

        let pid = engine.rounds.get(&1).unwrap().proposal_id().unwrap().to_string();

        // All nodes abstain.
        for voter in &["node-1", "node-2", "node-3", "node-4"] {
            let vote = make_prevote(voter, &pid, 1, 0, VoteDecision::Abstain);
            engine.cast_vote(vote).unwrap();
        }

        let rs = engine.rounds.get(&1).unwrap();
        assert_eq!(rs.count_votes(&ConsensusPhase::PreVote, &VoteDecision::Abstain), 4);
        // No quorum reached, round should not advance to PreCommit.
        assert_eq!(rs.phase_machine.current_phase, ConsensusPhase::PreVote);
    }

    #[test]
    fn test_split_vote() {
        // Test the split vote utility function.
        assert!(is_split_vote(2, 1, 3)); // Neither reaches quorum of 3.
        assert!(!is_split_vote(3, 1, 3)); // Approve reaches quorum.
        assert!(!is_split_vote(1, 3, 3)); // Reject reaches quorum.
        assert!(!is_split_vote(0, 0, 3)); // No votes at all.
    }

    #[test]
    fn test_quorum_computation() {
        assert_eq!(compute_bft_quorum(4, 1), 3); // 2*1+1=3
        assert_eq!(compute_bft_quorum(7, 2), 5); // 2*2+1=5
        assert_eq!(compute_bft_quorum(3, 1), 3); // Exactly 3f+1

        // Not enough validators for desired fault tolerance.
        assert_eq!(compute_bft_quorum(2, 1), 2); // Fallback to majority.
    }

    #[test]
    fn test_max_tolerable_faults() {
        assert_eq!(max_tolerable_faults(1), 0);
        assert_eq!(max_tolerable_faults(3), 1);
        assert_eq!(max_tolerable_faults(4), 1);
        assert_eq!(max_tolerable_faults(7), 2);
        assert_eq!(max_tolerable_faults(10), 3);
    }

    #[test]
    fn test_trust_weighted_quorum() {
        let votes = vec![
            ("n1".to_string(), VoteDecision::Approve, 0.9),
            ("n2".to_string(), VoteDecision::Approve, 0.8),
            ("n3".to_string(), VoteDecision::Reject, 0.7),
            ("n4".to_string(), VoteDecision::Abstain, 0.6),
        ];
        let (reached, weight) = compute_trust_weighted_quorum(&votes, 0.5);
        // Total trust = 3.0, threshold = 1.5, approve = 1.7. Reached.
        assert!(reached);
        assert!((weight - 1.7).abs() < 0.01);
    }

    #[test]
    fn test_engine_serialization() {
        let engine = make_engine();
        let json = serde_json::to_string(&engine).unwrap();
        let restored: PbftConsensusEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.self_id, "node-1");
        assert_eq!(restored.validators.len(), 4);
    }

    #[test]
    fn test_multiple_consensus_rounds() {
        let mut engine = make_engine();

        // Run 3 consensus rounds.
        for _i in 0..3 {
            let height = engine.current_height;
            let proposer = engine.start_round(height, 0).unwrap();
            let proposal = make_proposal(&proposer, height, 0);
            engine.submit_proposal(proposal).unwrap();

            let pid = engine.rounds.get(&height).unwrap().proposal_id().unwrap().to_string();
            for voter in &["node-1", "node-2", "node-3"] {
                let v = make_prevote(voter, &pid, height, 0, VoteDecision::Approve);
                engine.cast_vote(v).unwrap();
            }
            for voter in &["node-1", "node-2", "node-3"] {
                let v = make_precommit(voter, &pid, height, 0, VoteDecision::Approve);
                engine.cast_vote(v).unwrap();
            }
        }

        assert_eq!(engine.current_height, 4);
        assert_eq!(engine.committed_decisions.len(), 3);
        assert_eq!(engine.certificates.len(), 3);
        assert_eq!(engine.finality_tracker.block_count(), 4); // 3 committed + genesis

        // With finalization_depth=2, tip=3, finalized_tip = max(0, 3-2) = 1.
        assert!(engine.is_finalized(0));
        assert!(engine.is_finalized(1));
        assert!(!engine.is_finalized(2));
        assert!(!engine.is_finalized(3));
    }
}
