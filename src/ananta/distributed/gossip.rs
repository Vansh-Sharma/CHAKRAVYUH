// ANANTA Distributed Gossip Protocol — Plumtree + SWIM-inspired failure detection
//
// This module implements a production-grade gossip protocol for the ANANTA
// distributed trust plane, built on two proven algorithms:
//
//   1. **Plumtree** (J. Leitão et al., 2007) — an epidemic broadcast tree that
//      combines eager push along an optimized spanning tree with lazy gossip
//      recovery for reliability. Guarantees O(log N) message overhead per
//      broadcast under stable conditions.
//
//   2. **SWIM** (G. Chandra et al., 2002) — a scalable, weakly-consistent
//      failure detector using periodic ping/ack with indirect probing via
//      ping-req. Suspicion-based confirmation reduces false positives.
//
// The overlay is a structured gossip network with configurable parameters:
//   - `gossip_interval`: time between gossip rounds
//   - `fanout`: number of peers selected per round
//   - `retransmit_limit`: maximum retransmissions for a single message
//   - `suspicion_timeout`: duration before a suspected node is declared dead
//   - `indirect_probe_count`: number of ping-req relays for indirect probing

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rand::seq::{IteratorRandom, SliceRandom};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configurable parameters for the gossip protocol engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Interval between gossip rounds (milliseconds).
    pub gossip_interval_ms: u64,
    /// Number of peers selected per gossip round.
    pub fanout: usize,
    /// Maximum retransmissions for a single broadcast message.
    pub retransmit_limit: u32,
    /// Duration in milliseconds before a suspected node is declared dead.
    pub suspicion_timeout_ms: u64,
    /// Number of peers to relay ping-req through (indirect probing).
    pub indirect_probe_count: usize,
    /// Protocol period for SWIM ping/ack cycles (milliseconds).
    pub protocol_period_ms: u64,
    /// Maximum number of entries in the message deduplication bloom filter.
    pub dedup_capacity: usize,
    /// Number of bits per entry in the bloom filter.
    pub dedup_bits_per_entry: usize,
    /// Interval between anti-entropy full-state syncs (milliseconds).
    pub anti_entropy_interval_ms: u64,
    /// Number of key ranges for Merkle-based anti-entropy diff.
    pub merkle_key_ranges: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            gossip_interval_ms: 1000,
            fanout: 3,
            retransmit_limit: 10,
            suspicion_timeout_ms: 5000,
            indirect_probe_count: 3,
            protocol_period_ms: 1000,
            dedup_capacity: 100_000,
            dedup_bits_per_entry: 10,
            anti_entropy_interval_ms: 30_000,
            merkle_key_ranges: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Vector Clock
// ---------------------------------------------------------------------------

/// A lightweight vector clock for causal ordering and conflict resolution.
/// Uses a map of node_id -> logical timestamp. Conflict resolution is
/// last-writer-wins (LWW) when a single node dominates, otherwise the
/// message with the higher node_id (lexicographic tie-break) wins.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VectorClock {
    entries: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create an empty vector clock.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Increment the counter for a given node.
    pub fn increment(&mut self, node_id: &str) {
        let entry = self.entries.entry(node_id.to_string()).or_insert(0);
        *entry += 1;
    }

    /// Get the counter value for a node.
    pub fn get(&self, node_id: &str) -> u64 {
        *self.entries.get(node_id).unwrap_or(&0)
    }

    /// Merge another vector clock into this one (component-wise max).
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, ts) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(*ts);
        }
    }

    /// Check if this clock dominates another (happened-after relation).
    /// Returns true if for all entries in `other`, `self` has >= value
    /// AND at least one entry is strictly greater.
    pub fn dominates(&self, other: &VectorClock) -> bool {
        let mut at_least_one_greater = false;
        for (node, ts) in &other.entries {
            let my_ts = self.entries.get(node).unwrap_or(&0);
            if my_ts < ts {
                return false;
            }
            if my_ts > ts {
                at_least_one_greater = true;
            }
        }
        at_least_one_greater
    }

    /// Check if two vector clocks are concurrent (neither dominates the other).
    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        !self.dominates(other) && !other.dominates(self)
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute a deterministic summary hash for the vector clock.
    pub fn hash_summary(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        for (node, ts) in &self.entries {
            node.hash(&mut hasher);
            ts.hash(&mut hasher);
        }
        hasher.finish()
    }
}

// ---------------------------------------------------------------------------
// Bloom Filter for Message Deduplication
// ---------------------------------------------------------------------------

/// A simple bloom filter for probabilistic message deduplication.
/// Provides a space-efficient way to check if a message ID has been seen.
/// False positives are possible but false negatives are not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipBloomFilter {
    /// Bit array stored as a vector of u64 words.
    bits: Vec<u64>,
    /// Number of hash functions (derived from bits_per_entry).
    num_hashes: usize,
    /// Number of bits in the filter.
    num_bits: usize,
    /// Count of items inserted (for capacity tracking).
    count: usize,
}

impl GossipBloomFilter {
    /// Create a new bloom filter with the given capacity and bits per entry.
    pub fn new(capacity: usize, bits_per_entry: usize) -> Self {
        let num_bits = capacity * bits_per_entry;
        let num_words = (num_bits + 63) / 64;
        let num_hashes = (bits_per_entry as f64 * 2.0_f64.ln()).round() as usize;
        Self {
            bits: vec![0u64; num_words],
            num_hashes: num_hashes.max(1),
            num_bits,
            count: 0,
        }
    }

    /// Insert a message ID into the filter.
    pub fn insert(&mut self, item: &str) {
        for hash_val in self.hashes(item) {
            let word_idx = hash_val / 64;
            let bit_idx = hash_val % 64;
            if word_idx < self.bits.len() {
                self.bits[word_idx] |= 1u64 << bit_idx;
            }
        }
        self.count += 1;
    }

    /// Check if a message ID might be in the filter.
    /// Returns false if definitely not seen, true if probably seen.
    pub fn might_contain(&self, item: &str) -> bool {
        for hash_val in self.hashes(item) {
            let word_idx = hash_val / 64;
            let bit_idx = hash_val % 64;
            if word_idx < self.bits.len() {
                if self.bits[word_idx] & (1u64 << bit_idx) == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Number of items inserted.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if the filter is over capacity (should be reset).
    pub fn is_over_capacity(&self, capacity: usize) -> bool {
        self.count > capacity * 2
    }

    /// Reset the filter.
    pub fn reset(&mut self) {
        for word in &mut self.bits {
            *word = 0;
        }
        self.count = 0;
    }

    /// Compute k hash values for an item using double hashing.
    fn hashes(&self, item: &str) -> Vec<usize> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        let h1_val = h1.finish() as usize;

        let mut h2 = DefaultHasher::new();
        item.hash(&mut h2);
        h2.write_u8(0xFF);
        let h2_val = (h2.finish() as usize).wrapping_add(1);

        (0..self.num_hashes)
            .map(|i| (h1_val.wrapping_add(i.wrapping_mul(h2_val))) % self.num_bits)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Gossip Message Types
// ---------------------------------------------------------------------------

/// Unique identifier for a gossip broadcast.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GossipMessageId {
    /// Originating node ID.
    pub origin: String,
    /// Monotonically increasing sequence number from the origin.
    pub sequence: u64,
}

impl std::fmt::Display for GossipMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.origin, self.sequence)
    }
}

/// Topic/channel for scoped broadcasts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Topic(String);

impl Topic {
    pub fn new(name: &str) -> Self {
        Topic(name.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The global system topic for membership events.
    pub fn membership() -> Self {
        Topic("__membership__".to_string())
    }

    /// The anti-entropy sync topic.
    pub fn anti_entropy() -> Self {
        Topic("__anti_entropy__".to_string())
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The payload carried by gossip messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BroadcastPayload {
    /// Key for the state entry being gossiped.
    pub key: String,
    /// Serialized value.
    pub value: Vec<u8>,
    /// Vector clock for conflict resolution.
    pub vclock: VectorClock,
    /// Logical timestamp (wall-clock fallback for LWW).
    pub timestamp: i64,
}

/// Complete set of gossip message types exchanged between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Broadcast a payload to the cluster (Plumtree eager push).
    Broadcast {
        id: GossipMessageId,
        topic: Topic,
        payload: BroadcastPayload,
        retransmit_count: u32,
    },
    /// Direct (unicast) message to a specific peer.
    Direct {
        id: GossipMessageId,
        target: String,
        payload: BroadcastPayload,
    },
    /// SWIM ping: probe a node's liveness.
    Ping {
        from: String,
        incarnation: u64,
        seq: u64,
    },
    /// SWIM ping-req: request another node to probe on our behalf.
    PingReq {
        from: String,
        target: String,
        incarnation: u64,
        seq: u64,
    },
    /// SWIM ack: response to ping or ping-req.
    Ack {
        from: String,
        incarnation: u64,
        seq: u64,
    },
    /// Suspect: announce that a node is suspected of being down.
    Suspect {
        suspect_node: String,
        incarnation: u64,
        suspector: String,
    },
    /// Alive: refute a suspicion (node is still alive with higher incarnation).
    Alive {
        node_id: String,
        incarnation: u64,
        address: String,
    },
    /// Sync: anti-entropy full-state reconciliation.
    Sync {
        from: String,
        /// Merkle root hashes per key range.
        merkle_roots: Vec<MerkleRangeHash>,
        /// The sending node's memberlist incarnation map.
        member_vclock: VectorClock,
    },
    /// SyncDiff: response to Sync containing only the differing key ranges.
    SyncDiff {
        from: String,
        /// Key-value pairs for the requested ranges.
        entries: Vec<BroadcastPayload>,
        /// Merkle roots that matched (no diff needed).
        matched_ranges: Vec<usize>,
    },
    /// Graft: Plumtree message — request to be added as a tree child.
    Graft {
        from: String,
        topic: Topic,
        message_id: GossipMessageId,
    },
    /// Prune: Plumtree message — remove a peer from the tree.
    Prune { from: String, topic: Topic },
    /// IHave: Plumtree lazy push — announce a message without sending the full payload.
    IHave {
        from: String,
        topic: Topic,
        message_ids: Vec<GossipMessageId>,
    },
    /// Join: a new node requests to join the cluster.
    Join {
        node_id: String,
        address: String,
        incarnation: u64,
    },
    /// Leave: graceful node departure.
    Leave { node_id: String, incarnation: u64 },
    /// StateTransfer: full state snapshot sent to a new node.
    StateTransfer {
        from: String,
        entries: Vec<BroadcastPayload>,
        member_vclock: VectorClock,
    },
}

impl GossipMessage {
    /// Return a string key suitable for deduplication.
    pub fn dedup_key(&self) -> String {
        match self {
            GossipMessage::Broadcast { id, .. } => format!("bcast:{}", id),
            GossipMessage::Direct { id, target, .. } => format!("direct:{}:{}", target, id),
            GossipMessage::Suspect {
                suspect_node,
                incarnation,
                ..
            } => {
                format!("suspect:{}:{}", suspect_node, incarnation)
            }
            GossipMessage::Alive {
                node_id,
                incarnation,
                ..
            } => {
                format!("alive:{}:{}", node_id, incarnation)
            }
            _ => String::new(), // Non-deduplicated messages.
        }
    }

    /// Return the originating node ID for routing.
    pub fn sender(&self) -> &str {
        match self {
            GossipMessage::Broadcast { .. } | GossipMessage::Direct { .. } => "broadcast",
            GossipMessage::Ping { from, .. } => from,
            GossipMessage::PingReq { from, .. } => from,
            GossipMessage::Ack { from, .. } => from,
            GossipMessage::Suspect { suspector, .. } => suspector,
            GossipMessage::Alive { node_id, .. } => node_id,
            GossipMessage::Sync { from, .. } => from,
            GossipMessage::SyncDiff { from, .. } => from,
            GossipMessage::Graft { from, .. } => from,
            GossipMessage::Prune { from, .. } => from,
            GossipMessage::IHave { from, .. } => from,
            GossipMessage::Join { node_id, .. } => node_id,
            GossipMessage::Leave { node_id, .. } => node_id,
            GossipMessage::StateTransfer { from, .. } => from,
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle Range Hash for Anti-Entropy
// ---------------------------------------------------------------------------

/// A hash for a contiguous range of keys, used in Merkle-based anti-entropy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleRangeHash {
    /// Index of this key range.
    pub range_index: usize,
    /// Number of keys in this range.
    pub key_count: usize,
    /// Root hash of the Merkle tree for this range.
    pub root_hash: u64,
}

impl MerkleRangeHash {
    /// Compute the Merkle range hash from a sorted list of (key, value_hash) pairs.
    pub fn from_entries(range_index: usize, entries: &[(String, u64)]) -> Self {
        let key_count = entries.len();
        let root_hash = if entries.is_empty() {
            // Deterministic hash for an empty range.
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            range_index.hash(&mut h);
            h.finish()
        } else if entries.len() == 1 {
            entries[0].1
        } else {
            // Build a simple binary Merkle tree.
            let mut hashes: Vec<u64> = entries.iter().map(|(_, h)| *h).collect();
            while hashes.len() > 1 {
                let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
                let mut i = 0;
                while i < hashes.len() {
                    if i + 1 < hashes.len() {
                        next.push(combine_hashes(hashes[i], hashes[i + 1]));
                        i += 2;
                    } else {
                        next.push(combine_hashes(hashes[i], hashes[i]));
                        i += 1;
                    }
                }
                hashes = next;
            }
            hashes[0]
        };
        Self {
            range_index,
            key_count,
            root_hash,
        }
    }
}

/// Combine two hashes into a parent hash.
fn combine_hashes(a: u64, b: u64) -> u64 {
    // Simple but deterministic hash combination.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    a.hash(&mut h);
    b.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// Member State
// ---------------------------------------------------------------------------

/// The state of a node in the memberlist.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemberState {
    /// Node is alive and participating.
    Alive,
    /// Node is suspected of being down (awaiting confirmation).
    Suspect,
    /// Node has been confirmed dead.
    Dead,
    /// Node is in the process of joining.
    Joining,
    /// Node is leaving gracefully.
    Leaving,
}

/// A member in the cluster memberlist with incarnation-based liveness tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Unique node identifier.
    pub node_id: String,
    /// Network address (host:port).
    pub address: String,
    /// Current state in the memberlist.
    pub state: MemberState,
    /// Incarnation number — incremented to refute suspicions.
    pub incarnation: u64,
    /// Timestamp of the last ack received from this node.
    pub last_ack: DateTime<Utc>,
    /// Timestamp when this node was first suspected.
    pub suspected_at: Option<DateTime<Utc>>,
    /// Number of nodes that have confirmed the suspicion.
    pub suspicion_confirmations: u32,
    /// Measured round-trip time in microseconds (for Plumtree optimization).
    pub rtt_us: u64,
}

impl Member {
    /// Create a new alive member.
    pub fn new(node_id: &str, address: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            address: address.to_string(),
            state: MemberState::Alive,
            incarnation: 0,
            last_ack: Utc::now(),
            suspected_at: None,
            suspicion_confirmations: 0,
            rtt_us: 0,
        }
    }

    /// Refute a suspicion by incrementing the incarnation.
    pub fn refute(&mut self, new_address: Option<&str>) {
        self.incarnation += 1;
        self.state = MemberState::Alive;
        self.suspected_at = None;
        self.suspicion_confirmations = 0;
        self.last_ack = Utc::now();
        if let Some(addr) = new_address {
            self.address = addr.to_string();
        }
    }

    /// Mark this member as suspected.
    pub fn suspect(&mut self) {
        if self.state == MemberState::Alive {
            self.state = MemberState::Suspect;
            self.suspected_at = Some(Utc::now());
            self.suspicion_confirmations = 0;
        } else if self.state == MemberState::Suspect {
            self.suspicion_confirmations += 1;
        }
    }

    /// Declare this member dead.
    pub fn declare_dead(&mut self) {
        self.state = MemberState::Dead;
    }
}

// ---------------------------------------------------------------------------
// Plumtree Broadcast Tree
// ---------------------------------------------------------------------------

/// Per-topic Plumtree broadcast tree state.
/// Maintains the eager push tree and lazy peer set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlumtreeState {
    /// The topic this tree is for.
    pub topic: Topic,
    /// Tree parent — the node that eagerly pushes to us.
    pub parent: Option<String>,
    /// Tree children — nodes we eagerly push to.
    pub children: HashSet<String>,
    /// Lazy peers — nodes we exchange IHave messages with.
    pub lazy_peers: HashSet<String>,
    /// Set of message IDs we have seen on this topic (bounded).
    pub seen_messages: VecDeque<GossipMessageId>,
    /// Maximum number of seen messages to track before eviction.
    pub seen_capacity: usize,
    /// Round-trip time measurements for tree optimization.
    pub rtt_measurements: HashMap<String, Vec<u64>>,
}

impl PlumtreeState {
    /// Create a new Plumtree state for a topic.
    pub fn new(topic: Topic) -> Self {
        Self {
            topic,
            parent: None,
            children: HashSet::new(),
            lazy_peers: HashSet::new(),
            seen_messages: VecDeque::new(),
            seen_capacity: 10_000,
            rtt_measurements: HashMap::new(),
        }
    }

    /// Record that a message has been seen on this topic.
    pub fn mark_seen(&mut self, msg_id: GossipMessageId) {
        if self.seen_messages.contains(&msg_id) {
            return;
        }
        self.seen_messages.push_back(msg_id);
        while self.seen_messages.len() > self.seen_capacity {
            self.seen_messages.pop_front();
        }
    }

    /// Check if a message has been seen on this topic.
    pub fn has_seen(&self, msg_id: &GossipMessageId) -> bool {
        self.seen_messages.contains(msg_id)
    }

    /// Add a node as a tree child (eager push target).
    pub fn add_child(&mut self, node_id: &str) {
        self.children.insert(node_id.to_string());
        self.lazy_peers.remove(node_id);
    }

    /// Remove a node as a tree child, moving it to lazy peers.
    pub fn remove_child_to_lazy(&mut self, node_id: &str) {
        if self.children.remove(node_id) {
            self.lazy_peers.insert(node_id.to_string());
        }
    }

    /// Record an RTT measurement for a peer.
    pub fn record_rtt(&mut self, node_id: &str, rtt_us: u64) {
        let measurements = self
            .rtt_measurements
            .entry(node_id.to_string())
            .or_default();
        measurements.push(rtt_us);
        // Keep only the last 10 measurements for a rolling average.
        if measurements.len() > 10 {
            measurements.remove(0);
        }
    }

    /// Get the average RTT for a peer in microseconds.
    pub fn avg_rtt(&self, node_id: &str) -> Option<u64> {
        self.rtt_measurements.get(node_id).map(|m| {
            if m.is_empty() {
                return 0;
            }
            m.iter().sum::<u64>() / m.len() as u64
        })
    }

    /// Compute the current tree depth (longest path from root through children).
    pub fn tree_depth(&self, members: &HashMap<String, Member>) -> usize {
        self._depth_helper(&self.topic, members, 0)
    }

    fn _depth_helper(
        &self,
        _topic: &Topic,
        _members: &HashMap<String, Member>,
        depth: usize,
    ) -> usize {
        // In a real distributed system, tree depth requires knowledge of the
        // full tree topology. Here we approximate by counting children.
        if self.children.is_empty() {
            depth
        } else {
            depth + 1
        }
    }

    /// Get the list of nodes this node should eagerly push to.
    pub fn eager_push_targets(&self) -> Vec<&str> {
        self.children.iter().map(|s| s.as_str()).collect()
    }

    /// Get the list of lazy peers for IHave exchange.
    pub fn lazy_peer_list(&self) -> Vec<&str> {
        self.lazy_peers.iter().map(|s| s.as_str()).collect()
    }

    /// Optimize the tree by pruning slow children and grafting faster lazy peers.
    /// Returns a list of (action, peer, topic) tuples to execute.
    pub fn optimize(&mut self) -> Vec<TreeOp> {
        let mut ops = Vec::new();

        // Compute average RTT across all children.
        let child_rtts: Vec<(String, u64)> = self
            .children
            .iter()
            .filter_map(|c| self.avg_rtt(c).map(|rtt| (c.to_string(), rtt)))
            .collect();

        if child_rtts.is_empty() {
            return ops;
        }

        let _avg_child_rtt: u64 =
            child_rtts.iter().map(|(_, rtt)| *rtt).sum::<u64>() / child_rtts.len() as u64;

        // Find lazy peers with better RTT than the worst child.
        let mut worst_child: Option<(usize, u64)> = None;
        for (i, (_, rtt)) in child_rtts.iter().enumerate() {
            if worst_child.map_or(true, |(_, worst_rtt)| *rtt > worst_rtt) {
                worst_child = Some((i, *rtt));
            }
        }

        let lazy_peers_clone: Vec<String> = self.lazy_peers.iter().cloned().collect();
        if let Some((worst_idx, worst_rtt)) = worst_child {
            for lazy in &lazy_peers_clone {
                if let Some(lazy_rtt) = self.avg_rtt(lazy) {
                    // Graft if the lazy peer is significantly faster (2x threshold).
                    if lazy_rtt < worst_rtt / 2 {
                        ops.push(TreeOp::Graft {
                            peer: lazy.clone(),
                            topic: self.topic.clone(),
                        });
                        ops.push(TreeOp::Prune {
                            peer: child_rtts[worst_idx].0.clone(),
                            topic: self.topic.clone(),
                        });
                        // Apply locally.
                        self.lazy_peers.remove(lazy);
                        self.children.insert(lazy.clone());
                        self.children.remove(&child_rtts[worst_idx].0);
                        self.lazy_peers.insert(child_rtts[worst_idx].0.clone());
                        break; // One swap per round.
                    }
                }
            }
        }

        ops
    }
}

/// Tree optimization operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TreeOp {
    /// Request to be added as a tree child.
    Graft { peer: String, topic: Topic },
    /// Remove a peer from the tree.
    Prune { peer: String, topic: Topic },
}

// ---------------------------------------------------------------------------
// Gossip Metrics
// ---------------------------------------------------------------------------

/// Comprehensive metrics for the gossip protocol.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GossipMetrics {
    /// Total number of messages sent.
    pub messages_sent: u64,
    /// Total number of messages received.
    pub messages_received: u64,
    /// Number of messages deduplicated (already seen).
    pub messages_deduplicated: u64,
    /// Number of broadcast messages initiated locally.
    pub broadcasts_initiated: u64,
    /// Number of broadcast messages delivered.
    pub broadcasts_delivered: u64,
    /// Broadcast latency samples in microseconds (last 1000).
    pub broadcast_latencies_us: VecDeque<u64>,
    /// Total membership change events.
    pub membership_changes: u64,
    /// Number of nodes currently alive.
    pub alive_members: usize,
    /// Number of nodes currently suspected.
    pub suspected_members: usize,
    /// Number of nodes currently dead.
    pub dead_members: usize,
    /// Number of anti-entropy syncs performed.
    pub anti_entropy_syncs: u64,
    /// Number of key entries transferred during anti-entropy.
    pub anti_entropy_entries_transferred: u64,
    /// Number of graft operations.
    pub graft_count: u64,
    /// Number of prune operations.
    pub prune_count: u64,
    /// Current tree depth across all topics.
    pub tree_depth: usize,
    /// Number of pings sent.
    pub pings_sent: u64,
    /// Number of pings received.
    pub pings_received: u64,
    /// Number of acks received.
    pub acks_received: u64,
    /// Number of indirect probes (ping-req) sent.
    pub indirect_probes_sent: u64,
}

impl GossipMetrics {
    /// Create a new zero-initialized metrics struct.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a message sent.
    pub fn record_sent(&mut self) {
        self.messages_sent += 1;
    }

    /// Record a message received.
    pub fn record_received(&mut self) {
        self.messages_received += 1;
    }

    /// Record a deduplicated message.
    pub fn record_dedup(&mut self) {
        self.messages_deduplicated += 1;
    }

    /// Record a broadcast latency sample.
    pub fn record_broadcast_latency(&mut self, latency_us: u64) {
        self.broadcast_latencies_us.push_back(latency_us);
        if self.broadcast_latencies_us.len() > 1000 {
            self.broadcast_latencies_us.pop_front();
        }
    }

    /// Compute the p50 (median) broadcast latency in microseconds.
    pub fn latency_p50(&self) -> Option<u64> {
        self.percentile(50.0)
    }

    /// Compute the p95 broadcast latency in microseconds.
    pub fn latency_p95(&self) -> Option<u64> {
        self.percentile(95.0)
    }

    /// Compute the p99 broadcast latency in microseconds.
    pub fn latency_p99(&self) -> Option<u64> {
        self.percentile(99.0)
    }

    /// Compute an arbitrary percentile of broadcast latencies.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        if self.broadcast_latencies_us.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = self.broadcast_latencies_us.iter().copied().collect();
        sorted.sort();
        let idx = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        let idx = if idx > 0 { idx - 1 } else { 0 };
        Some(sorted[idx.min(sorted.len() - 1)])
    }
}

// ---------------------------------------------------------------------------
// Gossip Protocol Engine
// ---------------------------------------------------------------------------

/// The central gossip protocol engine combining Plumtree broadcast with
/// SWIM-inspired membership and failure detection.
///
/// This engine manages:
///   - A memberlist with incarnation-based liveness
///   - Plumtree broadcast trees per topic
///   - Message deduplication via bloom filter
///   - Anti-entropy sync via Merkle range hashes
///   - Comprehensive metrics collection
pub struct GossipEngine {
    /// Protocol configuration.
    pub config: GossipConfig,
    /// This node's unique identifier.
    pub self_id: String,
    /// This node's network address.
    pub self_address: String,
    /// This node's current incarnation number.
    pub self_incarnation: u64,
    /// Cluster memberlist.
    pub members: HashMap<String, Member>,
    /// Per-topic Plumtree broadcast tree state.
    pub plumtree: HashMap<String, PlumtreeState>,
    /// Message deduplication bloom filter.
    pub dedup: GossipBloomFilter,
    /// Local state store (key -> payload with versioning).
    pub state: BTreeMap<String, BroadcastPayload>,
    /// Pending outgoing messages to be sent on the next gossip round.
    pub pending_outbound: VecDeque<GossipMessage>,
    /// Vector clock for the local node's state changes.
    pub local_vclock: VectorClock,
    /// Next sequence number for locally-originated broadcasts.
    pub next_sequence: u64,
    /// Monotonically increasing sequence for SWIM pings.
    pub ping_seq: u64,
    /// Metrics.
    pub metrics: GossipMetrics,
    /// Pending ping-req tracking (seq -> target, deadline).
    pub pending_pings: HashMap<u64, (String, Instant)>,
    /// Timestamp of the last gossip round.
    pub last_gossip_round: Instant,
    /// Timestamp of the last anti-entropy sync.
    pub last_anti_entropy: Instant,
}

impl GossipEngine {
    /// Create a new gossip engine for this node.
    pub fn new(self_id: &str, self_address: &str, config: GossipConfig) -> Self {
        let dedup = GossipBloomFilter::new(config.dedup_capacity, config.dedup_bits_per_entry);
        let mut engine = Self {
            config,
            self_id: self_id.to_string(),
            self_address: self_address.to_string(),
            self_incarnation: 0,
            members: HashMap::new(),
            plumtree: HashMap::new(),
            dedup,
            state: BTreeMap::new(),
            pending_outbound: VecDeque::new(),
            local_vclock: VectorClock::new(),
            next_sequence: 0,
            ping_seq: 0,
            metrics: GossipMetrics::new(),
            pending_pings: HashMap::new(),
            last_gossip_round: Instant::now(),
            last_anti_entropy: Instant::now(),
        };

        // Initialize the default membership topic.
        engine.ensure_plumtree(Topic::membership());
        engine
    }

    /// Ensure a Plumtree state exists for a topic.
    fn ensure_plumtree(&mut self, topic: Topic) {
        self.plumtree
            .entry(topic.as_str().to_string())
            .or_insert_with(|| PlumtreeState::new(topic));
    }

    // ------------------------------------------------------------------
    // Broadcast API
    // ------------------------------------------------------------------

    /// Initiate a broadcast of a key-value pair on a topic.
    /// Returns the message ID assigned to this broadcast.
    pub fn broadcast(&mut self, topic: &Topic, key: &str, value: Vec<u8>) -> GossipMessageId {
        self.local_vclock.increment(&self.self_id);
        let payload = BroadcastPayload {
            key: key.to_string(),
            value,
            vclock: self.local_vclock.clone(),
            timestamp: Utc::now().timestamp_millis(),
        };

        // Store locally (LWW merge).
        self.merge_state(&payload);

        let msg_id = GossipMessageId {
            origin: self.self_id.clone(),
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        // Mark as seen in the Plumtree state.
        self.ensure_plumtree(topic.clone());
        if let Some(pt) = self.plumtree.get_mut(topic.as_str()) {
            pt.mark_seen(msg_id.clone());
        }

        // Eager push to tree children.
        if let Some(pt) = self.plumtree.get(topic.as_str()) {
            for _child in pt.eager_push_targets() {
                let msg = GossipMessage::Broadcast {
                    id: msg_id.clone(),
                    topic: topic.clone(),
                    payload: payload.clone(),
                    retransmit_count: 0,
                };
                self.pending_outbound.push_back(msg);
                self.metrics.record_sent();
            }

            // Lazy IHave to lazy peers.
            let ihave_ids = vec![msg_id.clone()];
            for _peer in pt.lazy_peer_list() {
                let msg = GossipMessage::IHave {
                    from: self.self_id.clone(),
                    topic: topic.clone(),
                    message_ids: ihave_ids.clone(),
                };
                self.pending_outbound.push_back(msg);
                self.metrics.record_sent();
            }
        }

        self.metrics.broadcasts_initiated += 1;
        msg_id
    }

    /// Merge a payload into local state using last-writer-wins with vector clocks.
    /// If the incoming payload's vclock dominates or is concurrent with higher
    /// timestamp, it replaces the existing value.
    pub fn merge_state(&mut self, payload: &BroadcastPayload) {
        let existing = self.state.get(&payload.key);
        let should_replace = match existing {
            None => true,
            Some(existing_payload) => {
                if payload.vclock.dominates(&existing_payload.vclock) {
                    true
                } else if existing_payload.vclock.dominates(&payload.vclock) {
                    false
                } else if payload.vclock.is_concurrent_with(&existing_payload.vclock) {
                    // Concurrent: use LWW on timestamp, then key tie-break.
                    payload.timestamp > existing_payload.timestamp
                        || (payload.timestamp == existing_payload.timestamp
                            && payload.key > existing_payload.key)
                } else {
                    // Identical clocks — keep existing.
                    false
                }
            }
        };
        if should_replace {
            self.state.insert(payload.key.clone(), payload.clone());
        }
    }

    // ------------------------------------------------------------------
    // Message Handling
    // ------------------------------------------------------------------

    /// Process an incoming gossip message. Returns a list of response messages
    /// that should be sent back.
    pub fn handle_message(&mut self, msg: GossipMessage) -> Vec<GossipMessage> {
        self.metrics.record_received();
        let mut responses = Vec::new();

        // Deduplication for idempotent messages.
        let dedup_key = msg.dedup_key();
        if !dedup_key.is_empty() {
            if self.dedup.might_contain(&dedup_key) {
                self.metrics.record_dedup();
                return responses;
            }
            self.dedup.insert(&dedup_key);
        }

        match msg {
            GossipMessage::Broadcast {
                id,
                topic,
                payload,
                retransmit_count,
            } => {
                responses = self.handle_broadcast(id, topic, payload, retransmit_count);
            }
            GossipMessage::Direct {
                id,
                target,
                payload,
            } => {
                if target == self.self_id {
                    self.merge_state(&payload);
                    self.metrics.broadcasts_delivered += 1;
                }
                let _ = id;
            }
            GossipMessage::Ping {
                from,
                incarnation,
                seq,
            } => {
                self.metrics.pings_received += 1;
                // Update member state if we know this node.
                if let Some(member) = self.members.get_mut(&from) {
                    if incarnation >= member.incarnation {
                        member.last_ack = Utc::now();
                        if member.state == MemberState::Suspect {
                            member.refute(None);
                        }
                    }
                }
                responses.push(GossipMessage::Ack {
                    from: self.self_id.clone(),
                    incarnation: self.self_incarnation,
                    seq,
                });
            }
            GossipMessage::PingReq {
                from,
                target,
                incarnation,
                seq,
            } => {
                // Forward ping to target, will ack back through the requester.
                if target != self.self_id {
                    let ping = GossipMessage::Ping {
                        from: self.self_id.clone(),
                        incarnation: self.self_incarnation,
                        seq: self.ping_seq,
                    };
                    self.ping_seq += 1;
                    self.pending_outbound.push_back(ping);
                    self.metrics.indirect_probes_sent += 1;
                }
                let _ = (from, incarnation, seq);
            }
            GossipMessage::Ack {
                from,
                incarnation,
                seq,
            } => {
                self.metrics.acks_received += 1;
                if let Some((target, sent_at)) = self.pending_pings.remove(&seq) {
                    if from == target {
                        let rtt = sent_at.elapsed().as_micros() as u64;
                        if let Some(member) = self.members.get_mut(&from) {
                            member.last_ack = Utc::now();
                            member.rtt_us = rtt;
                            if member.state == MemberState::Suspect {
                                // Ack received — refute the suspicion.
                                member.refute(None);
                            }
                        }
                        // Record RTT in all Plumtree states.
                        for pt in self.plumtree.values_mut() {
                            pt.record_rtt(&from, rtt);
                        }
                    }
                }
                let _ = incarnation;
            }
            GossipMessage::Suspect {
                suspect_node,
                incarnation,
                suspector,
            } => {
                if suspect_node == self.self_id {
                    // We are being suspected — refute with higher incarnation.
                    self.self_incarnation += 1;
                    responses.push(GossipMessage::Alive {
                        node_id: self.self_id.clone(),
                        incarnation: self.self_incarnation,
                        address: self.self_address.clone(),
                    });
                } else if let Some(member) = self.members.get_mut(&suspect_node) {
                    if incarnation >= member.incarnation && member.state != MemberState::Dead {
                        member.suspect();
                        self.metrics.membership_changes += 1;
                    }
                }
                let _ = suspector;
            }
            GossipMessage::Alive {
                node_id,
                incarnation,
                address,
            } => {
                if let Some(member) = self.members.get_mut(&node_id) {
                    if incarnation > member.incarnation {
                        member.refute(Some(&address));
                        self.metrics.membership_changes += 1;
                    }
                } else {
                    // Unknown node declaring itself alive — add it.
                    let mut member = Member::new(&node_id, &address);
                    member.incarnation = incarnation;
                    self.members.insert(node_id.clone(), member);
                    self.metrics.membership_changes += 1;
                }
            }
            GossipMessage::IHave {
                from,
                topic,
                message_ids,
            } => {
                self.ensure_plumtree(topic.clone());
                let mut missing = Vec::new();
                if let Some(pt) = self.plumtree.get(topic.as_str()) {
                    for msg_id in &message_ids {
                        if !pt.has_seen(msg_id) {
                            missing.push(msg_id.clone());
                        }
                    }
                }
                if !missing.is_empty() {
                    // Send Graft to request the missing messages.
                    for msg_id in missing {
                        responses.push(GossipMessage::Graft {
                            from: self.self_id.clone(),
                            topic: topic.clone(),
                            message_id: msg_id,
                        });
                    }
                    // The IHave sender becomes a candidate tree parent.
                    if let Some(pt) = self.plumtree.get_mut(topic.as_str()) {
                        pt.parent = Some(from.clone());
                        pt.children.remove(&from);
                        pt.lazy_peers.remove(&from);
                    }
                }
            }
            GossipMessage::Graft {
                from,
                topic,
                message_id,
            } => {
                self.ensure_plumtree(topic.clone());
                // Add the requester as a tree child.
                if let Some(pt) = self.plumtree.get_mut(topic.as_str()) {
                    pt.add_child(&from);
                }
                self.metrics.graft_count += 1;
                // If we have the message in our seen set, we already forwarded
                // it. The graft is just for future messages. The sender will
                // get missing messages via the anti-entropy path.
                let _ = message_id;
            }
            GossipMessage::Prune { from, topic } => {
                if let Some(pt) = self.plumtree.get_mut(topic.as_str()) {
                    pt.children.remove(&from);
                    pt.lazy_peers.insert(from);
                }
                self.metrics.prune_count += 1;
            }
            GossipMessage::Sync {
                from,
                merkle_roots,
                member_vclock,
            } => {
                responses = self.handle_sync(from, merkle_roots, member_vclock);
            }
            GossipMessage::SyncDiff {
                from,
                entries,
                matched_ranges: _,
            } => {
                let entry_count = entries.len() as u64;
                for entry in entries {
                    self.merge_state(&entry);
                }
                self.metrics.anti_entropy_entries_transferred += entry_count;
                // Also update our member vclock.
                self.local_vclock.merge(&self.compute_member_vclock());
                let _ = from;
            }
            GossipMessage::Join {
                node_id,
                address,
                incarnation,
            } => {
                self.handle_join(node_id, address, incarnation, &mut responses);
            }
            GossipMessage::Leave {
                node_id,
                incarnation,
            } => {
                if let Some(member) = self.members.get_mut(&node_id) {
                    if incarnation >= member.incarnation {
                        member.state = MemberState::Leaving;
                        self.metrics.membership_changes += 1;
                    }
                }
            }
            GossipMessage::StateTransfer {
                from,
                entries,
                member_vclock,
            } => {
                for entry in entries {
                    self.merge_state(&entry);
                }
                self.local_vclock.merge(&member_vclock);
                let _ = from;
            }
        }

        responses
    }

    /// Handle an incoming broadcast message (Plumtree eager push).
    fn handle_broadcast(
        &mut self,
        id: GossipMessageId,
        topic: Topic,
        payload: BroadcastPayload,
        retransmit_count: u32,
    ) -> Vec<GossipMessage> {
        let mut responses = Vec::new();

        self.ensure_plumtree(topic.clone());
        let already_seen = self
            .plumtree
            .get(topic.as_str())
            .map_or(false, |pt| pt.has_seen(&id));

        if already_seen {
            // Already seen — send Prune to the sender to optimize the tree.
            // Only if the sender is our parent or a child.
            if let Some(pt) = self.plumtree.get(topic.as_str()) {
                if pt.parent.as_deref() == Some(id.origin.as_str())
                    || pt.children.contains(&id.origin)
                {
                    responses.push(GossipMessage::Prune {
                        from: self.self_id.clone(),
                        topic: topic.clone(),
                    });
                }
            }
            return responses;
        }

        // New message — deliver locally and forward.
        self.merge_state(&payload);
        self.metrics.broadcasts_delivered += 1;

        if let Some(pt) = self.plumtree.get_mut(topic.as_str()) {
            pt.mark_seen(id.clone());
        }

        // Eager push to tree children (skip the sender).
        if let Some(pt) = self.plumtree.get(topic.as_str()) {
            if retransmit_count < self.config.retransmit_limit {
                for child in pt.eager_push_targets() {
                    if child == id.origin {
                        continue;
                    }
                    let msg = GossipMessage::Broadcast {
                        id: id.clone(),
                        topic: topic.clone(),
                        payload: payload.clone(),
                        retransmit_count: retransmit_count + 1,
                    };
                    self.pending_outbound.push_back(msg);
                    self.metrics.record_sent();
                }
            }

            // Lazy IHave to lazy peers.
            let ihave_ids = vec![id.clone()];
            for peer in pt.lazy_peer_list() {
                if peer == id.origin {
                    continue;
                }
                let msg = GossipMessage::IHave {
                    from: self.self_id.clone(),
                    topic: topic.clone(),
                    message_ids: ihave_ids.clone(),
                };
                self.pending_outbound.push_back(msg);
                self.metrics.record_sent();
            }
        }

        responses
    }

    /// Handle a node join request.
    fn handle_join(
        &mut self,
        node_id: String,
        address: String,
        incarnation: u64,
        responses: &mut Vec<GossipMessage>,
    ) {
        let is_new = !self.members.contains_key(&node_id);
        let should_accept = match self.members.get(&node_id) {
            None => true,
            Some(existing) => {
                incarnation > existing.incarnation
                    || (incarnation == existing.incarnation && existing.state == MemberState::Dead)
            }
        };

        if should_accept {
            let mut member = Member::new(&node_id, &address);
            member.incarnation = incarnation;
            self.members.insert(node_id.clone(), member);
            self.metrics.membership_changes += 1;

            // Add the new node as a lazy peer in all Plumtree trees.
            for pt in self.plumtree.values_mut() {
                pt.lazy_peers.insert(node_id.clone());
            }

            // Send full state transfer to the new node.
            let entries: Vec<BroadcastPayload> = self.state.values().cloned().collect();
            responses.push(GossipMessage::StateTransfer {
                from: self.self_id.clone(),
                entries,
                member_vclock: self.compute_member_vclock(),
            });

            // Broadcast the join to the membership topic.
            if is_new {
                self.local_vclock.increment(&self.self_id);
                let join_payload = BroadcastPayload {
                    key: format!("member:{}", node_id),
                    value: format!(
                        "{{\"address\":\"{}\",\"incarnation\":{}}}",
                        address, incarnation
                    )
                    .into_bytes(),
                    vclock: self.local_vclock.clone(),
                    timestamp: Utc::now().timestamp_millis(),
                };
                let msg_id = GossipMessageId {
                    origin: self.self_id.clone(),
                    sequence: self.next_sequence,
                };
                self.next_sequence += 1;
                self.pending_outbound.push_back(GossipMessage::Broadcast {
                    id: msg_id,
                    topic: Topic::membership(),
                    payload: join_payload,
                    retransmit_count: 0,
                });
                self.metrics.record_sent();
            }
        }
    }

    // ------------------------------------------------------------------
    // SWIM Failure Detection
    // ------------------------------------------------------------------

    /// Initiate a gossip round: ping a random subset of members and process
    /// any pending suspicion timeouts.
    pub fn gossip_round(&mut self) -> Vec<GossipMessage> {
        let mut outbound = Vec::new();
        self.last_gossip_round = Instant::now();

        // Collect alive and suspect members for probing.
        let probe_targets: Vec<String> = self
            .members
            .values()
            .filter(|m| m.state == MemberState::Alive || m.state == MemberState::Suspect)
            .map(|m| m.node_id.clone())
            .collect();

        let fanout = self.config.fanout.min(probe_targets.len());
        if fanout == 0 {
            return outbound;
        }

        let mut rng = rand::rng();
        let mut selected = probe_targets.clone();
        selected.shuffle(&mut rng);
        let selected: Vec<String> = selected.into_iter().take(fanout).collect();

        for target in &selected {
            let seq = self.ping_seq;
            self.ping_seq += 1;

            self.pending_pings
                .insert(seq, (target.clone(), Instant::now()));

            outbound.push(GossipMessage::Ping {
                from: self.self_id.clone(),
                incarnation: self.self_incarnation,
                seq,
            });
            self.metrics.pings_sent += 1;
        }

        // Process suspicion timeouts.
        let _suspicion_timeout = Duration::from_millis(self.config.suspicion_timeout_ms);
        let mut dead_nodes = Vec::new();
        for (node_id, member) in &mut self.members {
            if member.state == MemberState::Suspect {
                if let Some(suspected_at) = member.suspected_at {
                    let elapsed = Utc::now() - suspected_at;
                    if elapsed.num_milliseconds() as u64 > self.config.suspicion_timeout_ms {
                        dead_nodes.push(node_id.clone());
                    }
                }
            }
        }
        for node_id in dead_nodes {
            if let Some(member) = self.members.get_mut(&node_id) {
                member.declare_dead();
                self.metrics.membership_changes += 1;
                // Remove from all Plumtree states.
                for pt in self.plumtree.values_mut() {
                    pt.parent = pt.parent.take().filter(|p| p != &node_id);
                    pt.children.remove(&node_id);
                    pt.lazy_peers.remove(&node_id);
                    pt.rtt_measurements.remove(&node_id);
                }
            }
        }

        // Clean up expired pending pings.
        let protocol_period = Duration::from_millis(self.config.protocol_period_ms);
        let expired: Vec<u64> = self
            .pending_pings
            .iter()
            .filter(|(_, (_, sent_at))| sent_at.elapsed() > protocol_period * 3)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            if let Some((target, _)) = self.pending_pings.remove(&seq) {
                // Ping timed out — send indirect probes.
                let other_members: Vec<String> = self
                    .members
                    .keys()
                    .filter(|n| *n != &target && *n != &self.self_id)
                    .take(self.config.indirect_probe_count)
                    .cloned()
                    .collect();
                for _relay in other_members {
                    let seq = self.ping_seq;
                    self.ping_seq += 1;
                    self.pending_pings
                        .insert(seq, (target.clone(), Instant::now()));
                    outbound.push(GossipMessage::PingReq {
                        from: self.self_id.clone(),
                        target: target.clone(),
                        incarnation: self.self_incarnation,
                        seq,
                    });
                    self.metrics.indirect_probes_sent += 1;
                }
                // Mark as suspect if not already.
                if let Some(member) = self.members.get_mut(&target) {
                    if member.state == MemberState::Alive {
                        member.suspect();
                        outbound.push(GossipMessage::Suspect {
                            suspect_node: target.clone(),
                            incarnation: member.incarnation,
                            suspector: self.self_id.clone(),
                        });
                    }
                }
            }
        }

        outbound
    }

    /// Initiate a graceful leave from the cluster.
    pub fn leave(&mut self) -> GossipMessage {
        self.self_incarnation += 1;
        GossipMessage::Leave {
            node_id: self.self_id.clone(),
            incarnation: self.self_incarnation,
        }
    }

    // ------------------------------------------------------------------
    // Anti-Entropy Sync
    // ------------------------------------------------------------------

    /// Initiate an anti-entropy sync round. Returns a Sync message to send
    /// to a randomly chosen peer.
    pub fn anti_entropy_round(&mut self) -> Option<GossipMessage> {
        self.last_anti_entropy = Instant::now();

        let peers: Vec<String> = self
            .members
            .keys()
            .filter(|n| *n != &self.self_id)
            .cloned()
            .collect();

        if peers.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let _target = peers.iter().choose(&mut rng)?;

        let merkle_roots = self.compute_merkle_ranges();
        let member_vclock = self.compute_member_vclock();

        self.metrics.anti_entropy_syncs += 1;

        Some(GossipMessage::Sync {
            from: self.self_id.clone(),
            merkle_roots,
            member_vclock,
        })
    }

    /// Compute Merkle range hashes for the local state.
    pub fn compute_merkle_ranges(&self) -> Vec<MerkleRangeHash> {
        let num_ranges = self.config.merkle_key_ranges.max(1);
        let keys: Vec<&String> = self.state.keys().collect();
        let total_keys = keys.len();

        if total_keys == 0 {
            return (0..num_ranges)
                .map(|i| MerkleRangeHash {
                    range_index: i,
                    key_count: 0,
                    root_hash: 0,
                })
                .collect();
        }

        // Distribute keys into ranges by hash-based partitioning.
        let mut ranges: Vec<Vec<(String, u64)>> = vec![Vec::new(); num_ranges];
        for (key, payload) in &self.state {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            key.hash(&mut h);
            let hash_val = h.finish();
            let range_idx = (hash_val as usize) % num_ranges;
            let payload_hash = payload.vclock.hash_summary();
            ranges[range_idx].push((key.clone(), payload_hash));
        }

        ranges
            .into_iter()
            .enumerate()
            .map(|(i, entries)| MerkleRangeHash::from_entries(i, &entries))
            .collect()
    }

    /// Handle an incoming Sync message by comparing Merkle roots and
    /// returning differing entries in a SyncDiff response.
    fn handle_sync(
        &mut self,
        _from: String,
        their_roots: Vec<MerkleRangeHash>,
        their_member_vclock: VectorClock,
    ) -> Vec<GossipMessage> {
        let my_roots = self.compute_merkle_ranges();
        let mut differing_ranges = Vec::new();
        let mut matched_ranges = Vec::new();

        for their_root in &their_roots {
            let my_root = my_roots
                .iter()
                .find(|r| r.range_index == their_root.range_index);

            match my_root {
                Some(mine) if mine.root_hash == their_root.root_hash => {
                    matched_ranges.push(their_root.range_index);
                }
                _ => {
                    differing_ranges.push(their_root.range_index);
                }
            }
        }

        // Also include local ranges that the peer didn't send (peer may not know about them).
        for (i, my_root) in my_roots.iter().enumerate() {
            if my_root.key_count > 0
                && !matched_ranges.contains(&i)
                && !differing_ranges.contains(&i)
            {
                differing_ranges.push(i);
            }
        }

        // Collect entries from differing ranges.
        let mut entries = Vec::new();
        for (key, payload) in &self.state {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            key.hash(&mut h);
            let hash_val = h.finish();
            let range_idx = (hash_val as usize) % self.config.merkle_key_ranges;
            if differing_ranges.contains(&range_idx) {
                entries.push(payload.clone());
            }
        }

        // Merge their member vclock.
        self.local_vclock.merge(&their_member_vclock);

        vec![GossipMessage::SyncDiff {
            from: self.self_id.clone(),
            entries,
            matched_ranges,
        }]
    }

    /// Compute a vector clock summarizing the memberlist state.
    fn compute_member_vclock(&self) -> VectorClock {
        let mut vc = VectorClock::new();
        for (node_id, member) in &self.members {
            let entry = vc.entries.entry(node_id.clone()).or_insert(0);
            *entry = (*entry).max(member.incarnation);
        }
        vc
    }

    // ------------------------------------------------------------------
    // Pending Messages & Tree Optimization
    // ------------------------------------------------------------------

    /// Drain pending outbound messages.
    pub fn drain_outbound(&mut self) -> Vec<GossipMessage> {
        self.pending_outbound.drain(..).collect()
    }

    /// Run tree optimization across all topics. Returns operations to execute.
    pub fn optimize_trees(&mut self) -> Vec<TreeOp> {
        let mut all_ops = Vec::new();
        for pt in self.plumtree.values_mut() {
            all_ops.extend(pt.optimize());
        }
        all_ops
    }

    /// Update the aggregate metrics from current memberlist state.
    pub fn update_metrics(&mut self) {
        let mut alive = 0usize;
        let mut suspected = 0usize;
        let mut dead = 0usize;
        for member in self.members.values() {
            match member.state {
                MemberState::Alive | MemberState::Joining => alive += 1,
                MemberState::Suspect | MemberState::Leaving => suspected += 1,
                MemberState::Dead => dead += 1,
            }
        }
        self.metrics.alive_members = alive;
        self.metrics.suspected_members = suspected;
        self.metrics.dead_members = dead;

        // Max tree depth across topics.
        self.metrics.tree_depth = self
            .plumtree
            .values()
            .map(|pt| pt.tree_depth(&self.members))
            .max()
            .unwrap_or(0);

        // Reset bloom filter if over capacity.
        if self.dedup.is_over_capacity(self.config.dedup_capacity) {
            self.dedup.reset();
        }
    }

    /// Get the current metrics snapshot.
    pub fn metrics(&self) -> &GossipMetrics {
        &self.metrics
    }

    /// Get the number of alive members.
    pub fn alive_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.state == MemberState::Alive)
            .count()
    }

    /// Get the total number of members (all states).
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get the number of topics with active Plumtree trees.
    pub fn topic_count(&self) -> usize {
        self.plumtree.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GossipConfig {
        GossipConfig {
            gossip_interval_ms: 100,
            fanout: 3,
            retransmit_limit: 5,
            suspicion_timeout_ms: 500,
            indirect_probe_count: 2,
            protocol_period_ms: 100,
            dedup_capacity: 10_000,
            dedup_bits_per_entry: 10,
            anti_entropy_interval_ms: 1000,
            merkle_key_ranges: 4,
        }
    }

    fn make_engine(id: &str) -> GossipEngine {
        let addr = format!("{}:8080", id);
        GossipEngine::new(id, &addr, test_config())
    }

    fn make_member(id: &str) -> Member {
        let addr = format!("{}:8080", id);
        Member::new(id, addr.as_str())
    }

    // -- Vector Clock Tests --

    #[test]
    fn vector_clock_increment_and_get() {
        let mut vc = VectorClock::new();
        assert_eq!(vc.get("node-a"), 0);
        vc.increment("node-a");
        assert_eq!(vc.get("node-a"), 1);
        vc.increment("node-a");
        assert_eq!(vc.get("node-a"), 2);
    }

    #[test]
    fn vector_clock_merge() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("a");
        vc1.increment("a");
        vc2.increment("b");
        vc1.merge(&vc2);
        assert_eq!(vc1.get("a"), 2);
        assert_eq!(vc1.get("b"), 1);
    }

    #[test]
    fn vector_clock_dominates() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("a");
        vc1.increment("a");
        vc2.increment("a");
        assert!(vc1.dominates(&vc2));
        assert!(!vc2.dominates(&vc1));
    }

    #[test]
    fn vector_clock_concurrent() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("a");
        vc2.increment("b");
        assert!(vc1.is_concurrent_with(&vc2));
        assert!(!vc1.dominates(&vc2));
    }

    #[test]
    fn vector_clock_serialization() {
        let mut vc = VectorClock::new();
        vc.increment("node-1");
        vc.increment("node-2");
        let json = serde_json::to_string(&vc).unwrap();
        let restored: VectorClock = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.get("node-1"), 1);
        assert_eq!(restored.get("node-2"), 1);
    }

    // -- Bloom Filter Tests --

    #[test]
    fn bloom_filter_basic() {
        let mut bf = GossipBloomFilter::new(1000, 10);
        assert!(!bf.might_contain("msg-1"));
        bf.insert("msg-1");
        assert!(bf.might_contain("msg-1"));
        assert_eq!(bf.count(), 1);
    }

    #[test]
    fn bloom_filter_no_false_negatives() {
        let mut bf = GossipBloomFilter::new(1000, 10);
        for i in 0..100 {
            bf.insert(&format!("msg-{}", i));
        }
        for i in 0..100 {
            assert!(bf.might_contain(&format!("msg-{}", i)));
        }
    }

    #[test]
    fn bloom_filter_reset() {
        let mut bf = GossipBloomFilter::new(100, 10);
        bf.insert("test");
        assert!(bf.might_contain("test"));
        bf.reset();
        assert_eq!(bf.count(), 0);
    }

    #[test]
    fn bloom_filter_capacity_tracking() {
        let mut bf = GossipBloomFilter::new(10, 10);
        for i in 0..25 {
            bf.insert(&format!("item-{}", i));
        }
        assert!(bf.is_over_capacity(10));
        assert!(!bf.is_over_capacity(100));
    }

    // -- Member Tests --

    #[test]
    fn member_new_is_alive() {
        let m = make_member("node-1");
        assert_eq!(m.state, MemberState::Alive);
        assert_eq!(m.incarnation, 0);
    }

    #[test]
    fn member_refute_increments_incarnation() {
        let mut m = make_member("node-1");
        m.suspect();
        assert_eq!(m.state, MemberState::Suspect);
        m.refute(None);
        assert_eq!(m.state, MemberState::Alive);
        assert_eq!(m.incarnation, 1);
        assert!(m.suspected_at.is_none());
    }

    #[test]
    fn member_suspect_accumulates_confirmations() {
        let mut m = make_member("node-1");
        m.suspect();
        assert_eq!(m.suspicion_confirmations, 0);
        m.suspect();
        assert_eq!(m.suspicion_confirmations, 1);
        m.suspect();
        assert_eq!(m.suspicion_confirmations, 2);
    }

    #[test]
    fn member_serialization() {
        let m = make_member("node-1");
        let json = serde_json::to_string(&m).unwrap();
        let restored: Member = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.node_id, "node-1");
        assert_eq!(restored.state, MemberState::Alive);
    }

    // -- Plumtree Tests --

    #[test]
    fn plumtree_mark_and_check_seen() {
        let mut pt = PlumtreeState::new(Topic::new("test-topic"));
        let msg_id = GossipMessageId {
            origin: "node-1".to_string(),
            sequence: 1,
        };
        assert!(!pt.has_seen(&msg_id));
        pt.mark_seen(msg_id.clone());
        assert!(pt.has_seen(&msg_id));
    }

    #[test]
    fn plumtree_seen_eviction() {
        let mut pt = PlumtreeState::new(Topic::new("test-topic"));
        pt.seen_capacity = 3;
        for i in 0..5 {
            pt.mark_seen(GossipMessageId {
                origin: "node-1".to_string(),
                sequence: i,
            });
        }
        assert_eq!(pt.seen_messages.len(), 3);
        // Oldest entries should be evicted.
        assert!(!pt.has_seen(&GossipMessageId {
            origin: "node-1".to_string(),
            sequence: 0,
        }));
        assert!(pt.has_seen(&GossipMessageId {
            origin: "node-1".to_string(),
            sequence: 4,
        }));
    }

    #[test]
    fn plumtree_add_remove_child() {
        let mut pt = PlumtreeState::new(Topic::new("test"));
        pt.add_child("node-2");
        assert!(pt.children.contains("node-2"));
        assert!(!pt.lazy_peers.contains("node-2"));
        pt.remove_child_to_lazy("node-2");
        assert!(!pt.children.contains("node-2"));
        assert!(pt.lazy_peers.contains("node-2"));
    }

    #[test]
    fn plumtree_rtt_tracking() {
        let mut pt = PlumtreeState::new(Topic::new("test"));
        pt.record_rtt("node-2", 100);
        pt.record_rtt("node-2", 200);
        pt.record_rtt("node-2", 300);
        assert_eq!(pt.avg_rtt("node-2"), Some(200));
        assert_eq!(pt.avg_rtt("unknown"), None);
    }

    #[test]
    fn plumtree_optimize_swaps_slow_child() {
        let mut pt = PlumtreeState::new(Topic::new("test"));
        // Add a slow child and a fast lazy peer.
        pt.add_child("slow-node");
        pt.lazy_peers.insert("fast-node".to_string());
        pt.record_rtt("slow-node", 1000);
        pt.record_rtt("slow-node", 1000);
        pt.record_rtt("fast-node", 100);
        pt.record_rtt("fast-node", 100);

        let ops = pt.optimize();
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], TreeOp::Graft { peer, .. } if peer == "fast-node"));
        assert!(matches!(&ops[1], TreeOp::Prune { peer, .. } if peer == "slow-node"));
        // Verify the state was actually updated.
        assert!(pt.children.contains("fast-node"));
        assert!(pt.lazy_peers.contains("slow-node"));
    }

    // -- Message Tests --

    #[test]
    fn message_dedup_key_broadcast() {
        let msg = GossipMessage::Broadcast {
            id: GossipMessageId {
                origin: "node-1".to_string(),
                sequence: 1,
            },
            topic: Topic::new("t"),
            payload: BroadcastPayload {
                key: "k".to_string(),
                value: vec![1, 2, 3],
                vclock: VectorClock::new(),
                timestamp: 0,
            },
            retransmit_count: 0,
        };
        assert_eq!(msg.dedup_key(), "bcast:node-1:1");
    }

    #[test]
    fn message_serialization_roundtrip() {
        let msg = GossipMessage::Ping {
            from: "node-1".to_string(),
            incarnation: 5,
            seq: 42,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let restored: GossipMessage = serde_json::from_str(&json).unwrap();
        match restored {
            GossipMessage::Ping {
                from,
                incarnation,
                seq,
            } => {
                assert_eq!(from, "node-1");
                assert_eq!(incarnation, 5);
                assert_eq!(seq, 42);
            }
            _ => panic!("wrong message type after deserialization"),
        }
    }

    #[test]
    fn topic_membership_is_deterministic() {
        let t1 = Topic::membership();
        let t2 = Topic::membership();
        assert_eq!(t1, t2);
        assert_eq!(t1.as_str(), "__membership__");
    }

    // -- Engine Tests --

    #[test]
    fn engine_creation() {
        let engine = make_engine("node-1");
        assert_eq!(engine.self_id, "node-1");
        assert_eq!(engine.alive_count(), 0);
        assert!(engine.plumtree.contains_key("__membership__"));
    }

    #[test]
    fn engine_broadcast_stores_locally() {
        let mut engine = make_engine("node-1");
        let msg_id = engine.broadcast(&Topic::new("test"), "key-1", vec![1, 2, 3]);
        assert_eq!(msg_id.origin, "node-1");
        assert_eq!(msg_id.sequence, 0);
        assert!(engine.state.contains_key("key-1"));
        assert_eq!(engine.state["key-1"].value, vec![1, 2, 3]);
    }

    #[test]
    fn engine_broadcast_increments_sequence() {
        let mut engine = make_engine("node-1");
        let id1 = engine.broadcast(&Topic::new("t"), "k1", vec![]);
        let id2 = engine.broadcast(&Topic::new("t"), "k2", vec![]);
        assert_eq!(id1.sequence, 0);
        assert_eq!(id2.sequence, 1);
    }

    #[test]
    fn engine_handle_ping_responds_ack() {
        let mut engine = make_engine("node-1");
        let ping = GossipMessage::Ping {
            from: "node-2".to_string(),
            incarnation: 0,
            seq: 10,
        };
        let responses = engine.handle_message(ping);
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            GossipMessage::Ack { from, seq, .. } => {
                assert_eq!(from, "node-1");
                assert_eq!(*seq, 10);
            }
            _ => panic!("expected Ack"),
        }
    }

    #[test]
    fn engine_handle_join_accepts_new_member() {
        let mut engine = make_engine("node-1");
        let join = GossipMessage::Join {
            node_id: "node-2".to_string(),
            address: "node-2:8080".to_string(),
            incarnation: 0,
        };
        let responses = engine.handle_message(join);
        assert!(engine.members.contains_key("node-2"));
        assert_eq!(engine.members["node-2"].state, MemberState::Alive);
        // Should receive a StateTransfer response.
        assert!(responses
            .iter()
            .any(|r| matches!(r, GossipMessage::StateTransfer { .. })));
    }

    #[test]
    fn engine_handle_join_rejects_lower_incarnation() {
        let mut engine = make_engine("node-1");
        // First join with incarnation 5.
        let join1 = GossipMessage::Join {
            node_id: "node-2".to_string(),
            address: "node-2:8080".to_string(),
            incarnation: 5,
        };
        engine.handle_message(join1);
        assert_eq!(engine.members["node-2"].incarnation, 5);

        // Second join with lower incarnation should be rejected.
        let join2 = GossipMessage::Join {
            node_id: "node-2".to_string(),
            address: "node-2:8081".to_string(),
            incarnation: 3,
        };
        engine.handle_message(join2);
        assert_eq!(engine.members["node-2"].incarnation, 5);
        assert_eq!(engine.members["node-2"].address, "node-2:8080");
    }

    #[test]
    fn engine_handle_suspect_self_refutes() {
        let mut engine = make_engine("node-1");
        let suspect = GossipMessage::Suspect {
            suspect_node: "node-1".to_string(),
            incarnation: 0,
            suspector: "node-2".to_string(),
        };
        let responses = engine.handle_message(suspect);
        assert_eq!(engine.self_incarnation, 1);
        assert!(responses
            .iter()
            .any(|r| matches!(r, GossipMessage::Alive { .. })));
    }

    #[test]
    fn engine_dedup_filters_duplicate_broadcast() {
        let mut engine = make_engine("node-1");
        let msg_id = GossipMessageId {
            origin: "node-2".to_string(),
            sequence: 0,
        };
        let bcast = GossipMessage::Broadcast {
            id: msg_id.clone(),
            topic: Topic::new("test"),
            payload: BroadcastPayload {
                key: "k".to_string(),
                value: vec![1],
                vclock: VectorClock::new(),
                timestamp: 0,
            },
            retransmit_count: 0,
        };
        let r1 = engine.handle_message(bcast.clone());
        assert_eq!(r1.len(), 0); // No children, no responses.
        assert_eq!(engine.metrics.broadcasts_delivered, 1);

        let r2 = engine.handle_message(bcast);
        assert_eq!(r2.len(), 0);
        assert_eq!(engine.metrics.messages_deduplicated, 1);
        assert_eq!(engine.metrics.broadcasts_delivered, 1); // Not incremented.
    }

    #[test]
    fn engine_lww_merge_higher_timestamp_wins() {
        let mut engine = make_engine("node-1");

        // Insert first version.
        let p1 = BroadcastPayload {
            key: "key-1".to_string(),
            value: b"v1".to_vec(),
            vclock: {
                let mut vc = VectorClock::new();
                vc.increment("node-a");
                vc
            },
            timestamp: 100,
        };
        engine.merge_state(&p1);
        assert_eq!(engine.state["key-1"].value, b"v1");

        // Insert concurrent version with higher timestamp.
        let p2 = BroadcastPayload {
            key: "key-1".to_string(),
            value: b"v2".to_vec(),
            vclock: {
                let mut vc = VectorClock::new();
                vc.increment("node-b");
                vc
            },
            timestamp: 200,
        };
        engine.merge_state(&p2);
        assert_eq!(engine.state["key-1"].value, b"v2");
    }

    #[test]
    fn engine_lww_dominating_vclock_wins() {
        let mut engine = make_engine("node-1");

        let p1 = BroadcastPayload {
            key: "key-1".to_string(),
            value: b"v1".to_vec(),
            vclock: {
                let mut vc = VectorClock::new();
                vc.increment("node-a");
                vc
            },
            timestamp: 200,
        };
        engine.merge_state(&p1);

        let p2 = BroadcastPayload {
            key: "key-1".to_string(),
            value: b"v2".to_vec(),
            vclock: {
                let mut vc = VectorClock::new();
                vc.increment("node-a");
                vc.increment("node-a");
                vc
            },
            timestamp: 100, // Lower timestamp but dominating vclock.
        };
        engine.merge_state(&p2);
        assert_eq!(engine.state["key-1"].value, b"v2");
    }

    #[test]
    fn engine_anti_entropy_computes_merkle_ranges() {
        let mut engine = make_engine("node-1");
        engine.config.merkle_key_ranges = 4;
        engine.broadcast(&Topic::new("t"), "key-a", vec![1]);
        engine.broadcast(&Topic::new("t"), "key-b", vec![2]);
        engine.broadcast(&Topic::new("t"), "key-c", vec![3]);

        let ranges = engine.compute_merkle_ranges();
        assert_eq!(ranges.len(), 4);
        let total_keys: usize = ranges.iter().map(|r| r.key_count).sum();
        assert_eq!(total_keys, 3);
    }

    #[test]
    fn engine_anti_entropy_sync_returns_diffs() {
        let mut engine = make_engine("node-1");
        engine.config.merkle_key_ranges = 4;
        engine.broadcast(&Topic::new("t"), "key-a", vec![1]);

        // Create a sync message from a peer with empty state.
        let sync = GossipMessage::Sync {
            from: "node-2".to_string(),
            merkle_roots: vec![MerkleRangeHash {
                range_index: 0,
                key_count: 0,
                root_hash: 0,
            }],
            member_vclock: VectorClock::new(),
        };
        let responses = engine.handle_message(sync);
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            GossipMessage::SyncDiff { entries, .. } => {
                assert!(!entries.is_empty());
            }
            _ => panic!("expected SyncDiff"),
        }
    }

    #[test]
    fn engine_leave_message() {
        let mut engine = make_engine("node-1");
        let leave = engine.leave();
        match leave {
            GossipMessage::Leave {
                node_id,
                incarnation,
            } => {
                assert_eq!(node_id, "node-1");
                assert_eq!(incarnation, 1);
            }
            _ => panic!("expected Leave"),
        }
    }

    #[test]
    fn engine_gossip_round_pings_fanout_peers() {
        let mut engine = make_engine("node-1");
        engine
            .members
            .insert("node-2".to_string(), make_member("node-2"));
        engine
            .members
            .insert("node-3".to_string(), make_member("node-3"));
        engine
            .members
            .insert("node-4".to_string(), make_member("node-4"));
        engine
            .members
            .insert("node-5".to_string(), make_member("node-5"));

        let messages = engine.gossip_round();
        assert_eq!(messages.len(), 3); // fanout = 3
        for msg in &messages {
            assert!(matches!(msg, GossipMessage::Ping { .. }));
        }
        assert_eq!(engine.metrics.pings_sent, 3);
    }

    #[test]
    fn engine_metrics_latency_percentiles() {
        let mut metrics = GossipMetrics::new();
        for i in 1..=100u64 {
            metrics.record_broadcast_latency(i);
        }
        assert_eq!(metrics.latency_p50(), Some(50));
        assert_eq!(metrics.latency_p95(), Some(95));
        assert_eq!(metrics.latency_p99(), Some(99));
    }

    #[test]
    fn engine_metrics_empty_percentiles() {
        let metrics = GossipMetrics::new();
        assert!(metrics.latency_p50().is_none());
        assert!(metrics.latency_p95().is_none());
        assert!(metrics.latency_p99().is_none());
    }

    #[test]
    fn merkle_range_hash_empty_and_single() {
        let empty = MerkleRangeHash::from_entries(0, &[]);
        assert_eq!(empty.key_count, 0);

        let single = MerkleRangeHash::from_entries(0, &[("k1".to_string(), 42)]);
        assert_eq!(single.key_count, 1);
        assert_eq!(single.root_hash, 42);
    }

    #[test]
    fn merkle_range_hash_deterministic() {
        let entries = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ];
        let h1 = MerkleRangeHash::from_entries(0, &entries);
        let h2 = MerkleRangeHash::from_entries(0, &entries);
        assert_eq!(h1.root_hash, h2.root_hash);
    }

    #[test]
    fn gossip_message_id_display() {
        let id = GossipMessageId {
            origin: "node-1".to_string(),
            sequence: 42,
        };
        assert_eq!(format!("{}", id), "node-1:42");
    }

    #[test]
    fn engine_state_transfer_merges_entries() {
        let mut engine = make_engine("node-1");
        let payload = BroadcastPayload {
            key: "remote-key".to_string(),
            value: b"remote-value".to_vec(),
            vclock: {
                let mut vc = VectorClock::new();
                vc.increment("node-2");
                vc
            },
            timestamp: 100,
        };
        let xfer = GossipMessage::StateTransfer {
            from: "node-2".to_string(),
            entries: vec![payload],
            member_vclock: VectorClock::new(),
        };
        engine.handle_message(xfer);
        assert!(engine.state.contains_key("remote-key"));
        assert_eq!(engine.state["remote-key"].value, b"remote-value");
    }

    #[test]
    fn engine_update_metrics_counts_members() {
        let mut engine = make_engine("node-1");
        engine
            .members
            .insert("node-2".to_string(), make_member("node-2"));
        let mut dead = make_member("node-3");
        dead.declare_dead();
        engine.members.insert("node-3".to_string(), dead);
        let mut suspect = make_member("node-4");
        suspect.suspect();
        engine.members.insert("node-4".to_string(), suspect);

        engine.update_metrics();
        assert_eq!(engine.metrics.alive_members, 1);
        assert_eq!(engine.metrics.suspected_members, 1);
        assert_eq!(engine.metrics.dead_members, 1);
    }
}
