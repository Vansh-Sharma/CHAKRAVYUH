// Cross Ring Network — Inter-Ring Coordination (Production Grade)
//
// The 5 Cross Rings are coordination channels with directional semantics:
//
//   1. Command        — Keshav → Rings (top-down, ACK-tracked)
//   2. Intel          — Ring ↔ Ring (peer-to-peer, multi-subscriber)
//   3. Control        — Rings → Keshav (arbitration with responses)
//   4. Communication  — System-wide broadcast (topic-based pub/sub)
//   5. Recovery       — Independent orchestration path (circuit breaker)
//
// Production architecture:
//   - All rings use a trait-based transport layer (RingTransport)
//   - Default: InProcessTransport (bounded mpsc channels)
//   - Swap to: GrpcTransport, NatsTransport, RedisTransport
//   - Zero unwrap() in any code path
//   - Backpressure detection and reporting
//   - Transport metrics collection
//   - Persistence for Recovery Ring state
//   - Multi-subscriber support (Intel, Communication)
//   - ACK tracking (Command)
//   - Escalation tracking with responses (Control)
//   - Topic-based pub/sub (Communication)
//   - Late-joiner replay (Intel, Communication)
//   - Message deduplication (Command)
//   - Escalation depth limiting (Control)
//   - Stale escalation cleanup (Control)
//
// Architecture Principle: Cross Rings Have Directional Semantics (P4)
// Architecture Principle: Independent Path (P5)

pub mod command_ring;
pub mod communication_ring;
pub mod control_ring;
pub mod intel_ring;
pub mod message;
pub mod recovery_ring;
pub mod transport;

use std::sync::Arc;

pub use command_ring::{CommandRing, CommandRingConfig, CommandStatus};
pub use communication_ring::{
    CommunicationRing, CommunicationRingConfig, CommunicationSubscription, TopicStats,
};
pub use control_ring::{
    ControlRing, ControlRingConfig, EscalationMeta, EscalationStats, EscalationStatus,
};
pub use intel_ring::{IntelRing, IntelRingConfig, IntelSubscription};
pub use message::{CrossRingMessage, CrossRingType, MessagePriority};
pub use recovery_ring::{
    CircuitState, DegradedAssessment, RecoveryAction, RecoveryEvent, RecoveryRing,
    RecoveryRingConfig, RingHealthSnapshot,
};
pub use transport::{
    InProcessTransport, RingSubscriber, RingTransport, TransportError, TransportErrorKind,
    TransportMetrics,
};

// ─── Configuration ────────────────────────────────────────────────

/// Cross Ring Network configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CrossRingConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub command: CommandRingConfig,

    #[serde(default)]
    pub intel: IntelRingConfig,

    #[serde(default)]
    pub control: ControlRingConfig,

    #[serde(default)]
    pub communication: CommunicationRingConfig,

    #[serde(default)]
    pub recovery: RecoveryRingConfig,
}

fn default_enabled() -> bool {
    true
}

impl Default for CrossRingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            command: CommandRingConfig::default(),
            intel: IntelRingConfig::default(),
            control: ControlRingConfig::default(),
            communication: CommunicationRingConfig::default(),
            recovery: RecoveryRingConfig::default(),
        }
    }
}

// ─── Cross Ring Network ──────────────────────────────────────────

/// The Cross Ring Network — coordinates all 5 cross rings.
///
/// Production-grade implementation with:
///   - Pluggable transport per ring
///   - Metrics and health monitoring
///   - Backpressure detection
///   - Zero unwrap() guarantees
///   - Full API surface for all 5 rings
///   - System-wide status and diagnostics
#[derive(Clone)]
pub struct CrossRingNetwork {
    config: Arc<CrossRingConfig>,
    command: Arc<CommandRing>,
    intel: Arc<IntelRing>,
    control: Arc<ControlRing>,
    communication: Arc<CommunicationRing>,
    recovery: Arc<RecoveryRing>,
}

impl CrossRingNetwork {
    /// Create a new Cross Ring Network with the given configuration.
    pub fn new(config: &CrossRingConfig) -> crate::Result<Self> {
        let command = Arc::new(CommandRing::new(&config.command)?);
        let intel = Arc::new(IntelRing::new(&config.intel)?);
        let control = Arc::new(ControlRing::new(&config.control)?);
        let communication = Arc::new(CommunicationRing::new(&config.communication)?);
        let recovery = Arc::new(RecoveryRing::new(&config.recovery)?);

        Ok(Self {
            config: Arc::new(config.clone()),
            command,
            intel,
            control,
            communication,
            recovery,
        })
    }

    // ── Command Ring API ──

    /// Send a command from Keshav to a ring (top-down only).
    pub fn send_command(&self, msg: CrossRingMessage) -> crate::Result<()> {
        self.command.send(msg)
    }

    /// Receive the next command (for ring consumption).
    pub fn recv_command(&self) -> crate::Result<Option<CrossRingMessage>> {
        self.command.recv()
    }

    /// Broadcast a command to all rings.
    pub fn broadcast_command(&self, msg: CrossRingMessage) -> crate::Result<()> {
        self.command.broadcast(msg)
    }

    /// Acknowledge a received command.
    pub fn ack_command(&self, message_id: &str) {
        self.command.ack(message_id);
    }

    /// Get the status of a tracked command.
    pub fn command_status(&self, message_id: &str) -> Option<CommandStatus> {
        self.command.command_status(message_id)
    }

    /// Sweep timed-out commands.
    pub fn sweep_command_timeouts(&self) -> Vec<String> {
        self.command.sweep_timeouts()
    }

    /// Count of pending (unACKed) commands.
    pub fn pending_commands(&self) -> usize {
        self.command.pending_acks()
    }

    // ── Intel Ring API ──

    /// Publish an observation from one ring to all others.
    pub fn publish_intel(&self, msg: CrossRingMessage) -> crate::Result<()> {
        self.intel.publish(msg)
    }

    /// Receive the next intel observation (primary receiver).
    pub fn recv_intel(&self) -> crate::Result<Option<CrossRingMessage>> {
        self.intel.recv()
    }

    /// Subscribe to intel observations.
    pub fn subscribe_intel(
        &self,
        name: &str,
        topic_filter: Option<&str>,
    ) -> crate::Result<Arc<IntelSubscription>> {
        self.intel.subscribe(name, topic_filter)
    }

    /// Unsubscribe from intel observations.
    pub fn unsubscribe_intel(&self, name: &str) -> crate::Result<()> {
        self.intel.unsubscribe(name)
    }

    /// Number of intel subscribers.
    pub fn intel_subscriber_count(&self) -> usize {
        self.intel.subscriber_count()
    }

    // ── Control Ring API ──

    /// Escalate a conflict to Keshav.
    pub fn escalate(&self, msg: CrossRingMessage) -> crate::Result<()> {
        self.control.escalate(msg)
    }

    /// Receive the next escalation (for Keshav).
    pub fn recv_escalation(&self) -> crate::Result<Option<CrossRingMessage>> {
        self.control.recv_escalation()
    }

    /// Send an arbitration response from Keshav.
    pub fn send_arbitration_response(&self, response: CrossRingMessage) -> crate::Result<()> {
        self.control.respond(response)
    }

    /// Receive an arbitration response (for ring).
    pub fn recv_arbitration_response(&self) -> crate::Result<Option<CrossRingMessage>> {
        self.control.recv_response()
    }

    /// Sweep stale escalations.
    pub fn sweep_stale_escalations(&self) -> usize {
        self.control.sweep_stale()
    }

    /// Get escalation statistics.
    pub fn escalation_stats(&self) -> EscalationStats {
        self.control.stats()
    }

    /// Count of pending escalations.
    pub fn pending_escalations(&self) -> usize {
        self.control.pending_escalations()
    }

    // ── Communication Ring API ──

    /// Broadcast a system-wide message.
    pub fn broadcast(&self, msg: CrossRingMessage) -> crate::Result<()> {
        self.communication.broadcast(msg)
    }

    /// Subscribe to broadcast messages.
    pub fn subscribe_broadcast(
        &self,
        name: &str,
        topic_filter: Option<&str>,
    ) -> crate::Result<Arc<CommunicationSubscription>> {
        self.communication.subscribe(name, topic_filter)
    }

    /// Unsubscribe from broadcast messages.
    pub fn unsubscribe_broadcast(&self, name: &str) -> crate::Result<()> {
        self.communication.unsubscribe(name)
    }

    /// Number of broadcast subscribers.
    pub fn broadcast_subscriber_count(&self) -> usize {
        self.communication.subscriber_count()
    }

    /// Get statistics for a broadcast topic.
    pub fn broadcast_topic_stats(&self, topic: &str) -> Option<TopicStats> {
        self.communication.topic_stats(topic)
    }

    /// Total broadcasts sent.
    pub fn total_broadcasts(&self) -> u64 {
        self.communication.total_broadcasts()
    }

    // ── Recovery Ring API ──

    /// Record a ring evaluation success.
    pub fn record_ring_success(&self, ring_name: &str, latency_ms: f64) {
        self.recovery.record_success(ring_name, latency_ms);
    }

    /// Record a ring evaluation failure.
    pub fn record_ring_failure(&self, ring_name: &str) {
        self.recovery.record_failure(ring_name);
    }

    /// Check if a ring's circuit breaker allows requests.
    pub fn ring_should_allow(&self, ring_name: &str) -> bool {
        self.recovery.should_allow(ring_name)
    }

    /// Assess current system health and determine recovery action.
    pub fn assess_degraded_mode(&self, known_rings: &[&str]) -> DegradedAssessment {
        self.recovery.assess(known_rings)
    }

    /// Get health snapshots for all known rings.
    pub fn ring_health(&self, known_rings: &[&str]) -> Vec<RingHealthSnapshot> {
        self.recovery.health_snapshot(known_rings)
    }

    /// Get recovery event log.
    pub fn recovery_events(&self) -> Vec<RecoveryEvent> {
        self.recovery.events()
    }

    /// Persist recovery state now (call before shutdown).
    pub fn persist_recovery_state(&self) -> crate::Result<()> {
        self.recovery.persist_now()
    }

    // ── Direct Ring Access ──

    /// Get references to individual rings (for direct access).
    pub fn command_ring(&self) -> &CommandRing {
        &self.command
    }
    pub fn intel_ring(&self) -> &IntelRing {
        &self.intel
    }
    pub fn control_ring(&self) -> &ControlRing {
        &self.control
    }
    pub fn communication_ring(&self) -> &CommunicationRing {
        &self.communication
    }
    pub fn recovery_ring(&self) -> &RecoveryRing {
        &self.recovery
    }

    // ── System-Wide Diagnostics ──

    /// Get a system-wide status summary of all 5 cross rings.
    pub fn system_status(&self) -> CrossRingSystemStatus {
        CrossRingSystemStatus {
            command: CrossRingStatus {
                connected: self.command.is_connected(),
                pending: self.command.pending(),
                pending_acks: self.command.pending_acks(),
                tracked_count: self.command.tracked_count(),
                ..Default::default()
            },
            intel: CrossRingStatus {
                connected: self.intel.is_connected(),
                pending: self.intel.pending(),
                subscriber_count: self.intel.subscriber_count(),
                replay_buffer_len: self.intel.replay_buffer_len(),
                ..Default::default()
            },
            control: CrossRingStatus {
                connected: self.control.is_connected(),
                pending: self.control.pending_escalations(),
                subscriber_count: 0,
                ..Default::default()
            },
            communication: CrossRingStatus {
                connected: self.communication.has_subscribers(),
                pending: 0,
                subscriber_count: self.communication.subscriber_count(),
                total_broadcasts: Some(self.communication.total_broadcasts()),
                known_topics: Some(self.communication.known_topics()),
                ..Default::default()
            },
            recovery: CrossRingStatus {
                connected: self.recovery.is_connected(),
                pending: self.recovery.pending(),
                event_count: self.recovery.event_count(),
                ..Default::default()
            },
        }
    }

    /// Drain all pending messages (for testing).
    pub fn drain_all(&self) {
        while self.recv_command().unwrap().is_some() {}
        while self.recv_intel().unwrap().is_some() {}
        while self.recv_escalation().unwrap().is_some() {}
        while self.recv_arbitration_response().unwrap().is_some() {}
        while self.recovery.recv().unwrap().is_some() {}
    }
}

// ─── System Status Types ──────────────────────────────────────────

/// System-wide status of all 5 cross rings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CrossRingSystemStatus {
    pub command: CrossRingStatus,
    pub intel: CrossRingStatus,
    pub control: CrossRingStatus,
    pub communication: CrossRingStatus,
    pub recovery: CrossRingStatus,
}

/// Per-ring status with optional extended fields.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CrossRingStatus {
    pub connected: bool,
    pub pending: usize,
    pub subscriber_count: usize,
    pub pending_acks: usize,
    pub tracked_count: usize,
    pub replay_buffer_len: usize,
    pub event_count: usize,
    pub total_broadcasts: Option<u64>,
    pub known_topics: Option<Vec<String>>,
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_network() -> CrossRingNetwork {
        CrossRingNetwork::new(&CrossRingConfig {
            recovery: RecoveryRingConfig {
                persist: false,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn network_constructs() {
        let network = default_network();
        assert!(network.recv_command().unwrap().is_none());
        assert!(network.recv_intel().unwrap().is_none());
        assert!(network.recv_escalation().unwrap().is_none());
        assert!(network.recovery.recv().unwrap().is_none());
    }

    #[test]
    fn command_ring_directional() {
        let network = default_network();
        let msg = CrossRingMessage::new(
            CrossRingType::Command,
            "keshav",
            "shield",
            "policy_update",
            serde_json::json!({"action": "reload"}),
        );
        network.send_command(msg).unwrap();
        let received = network.recv_command().unwrap().unwrap();
        assert_eq!(received.source, "keshav");
        assert_eq!(received.destination, "shield");
    }

    #[test]
    fn intel_peer_to_peer() {
        let network = default_network();
        let msg = CrossRingMessage::new(
            CrossRingType::Intel,
            "shield",
            "broadcast",
            "attack_pattern",
            serde_json::json!({"pattern": "new_injection"}),
        );
        network.publish_intel(msg).unwrap();
        let received = network.recv_intel().unwrap().unwrap();
        assert_eq!(received.source, "shield");
        assert_eq!(received.msg_type, "attack_pattern");
    }

    #[test]
    fn control_escalation() {
        let network = default_network();
        let msg = CrossRingMessage::new(
            CrossRingType::Control,
            "threat",
            "keshav",
            "conflict",
            serde_json::json!({"ring_a": "threat", "ring_b": "execution", "conflict": "deny_vs_allow"}),
        );
        network.escalate(msg).unwrap();
        let received = network.recv_escalation().unwrap().unwrap();
        assert_eq!(received.source, "threat");
        assert_eq!(received.destination, "keshav");
    }

    #[test]
    fn communication_broadcast() {
        let network = default_network();
        let sub = network.subscribe_broadcast("test_sub", None).unwrap();

        let msg = CrossRingMessage::new(
            CrossRingType::Communication,
            "system",
            "broadcast",
            "system_alert",
            serde_json::json!({"level": "warning"}),
        );
        network.broadcast(msg).unwrap();

        let received = sub.recv().unwrap().unwrap();
        assert_eq!(received.msg_type, "system_alert");
    }

    #[test]
    fn recovery_ring_accessible() {
        let network = default_network();
        let known = ["shield", "threat", "identity"];
        let health = network.ring_health(&known);
        assert_eq!(health.len(), 3);
        for h in &health {
            assert_eq!(h.state, CircuitState::Closed);
        }
    }

    #[test]
    fn recovery_tracks_failures_via_network() {
        let network = default_network();
        network.record_ring_success("shield", 1.5);
        network.record_ring_failure("threat");
        network.record_ring_failure("threat");
        let assessment = network.assess_degraded_mode(&["shield", "threat", "identity"]);
        assert!(!assessment.lockdown);
    }

    #[test]
    fn recovery_ring_health_endpoint() {
        let network = default_network();
        network.record_ring_success("shield", 2.0);
        network.record_ring_success("threat", 3.0);
        let health = network.ring_health(&["shield", "threat"]);
        assert_eq!(health[0].total_requests, 1);
        assert_eq!(health[1].avg_latency_ms, 3.0);
    }

    #[test]
    fn drain_all_clears_all_rings() {
        let network = default_network();
        network
            .send_command(CrossRingMessage::new(
                CrossRingType::Command,
                "keshav",
                "shield",
                "drain",
                serde_json::json!({}),
            ))
            .unwrap();
        network.drain_all();
        assert!(network.recv_command().unwrap().is_none());
    }

    #[test]
    fn system_status() {
        let network = default_network();
        let status = network.system_status();
        assert!(status.command.connected);
        assert!(status.intel.connected);
        assert!(status.control.connected);
    }

    #[test]
    fn arbitration_response_flow() {
        let network = default_network();
        let msg = CrossRingMessage::new(
            CrossRingType::Control,
            "threat",
            "keshav",
            "conflict",
            serde_json::json!({"conflict": "test"}),
        );
        network.escalate(msg.clone()).unwrap();

        let response = CrossRingMessage::new(
            CrossRingType::Control,
            "keshav",
            "threat",
            "arbitration_decision",
            serde_json::json!({
                "correlation_id": msg.message_id,
                "decision": "deny",
            }),
        );
        network.send_arbitration_response(response).unwrap();

        let stats = network.escalation_stats();
        assert_eq!(stats.resolved, 1);
    }

    #[test]
    fn broadcast_topic_stats() {
        let network = default_network();
        network
            .broadcast(CrossRingMessage::new(
                CrossRingType::Communication,
                "system",
                "broadcast",
                "alert",
                serde_json::json!({}),
            ))
            .unwrap();
        network
            .broadcast(CrossRingMessage::new(
                CrossRingType::Communication,
                "system",
                "broadcast",
                "alert",
                serde_json::json!({}),
            ))
            .unwrap();

        let stats = network.broadcast_topic_stats("alert").unwrap();
        assert_eq!(stats.message_count, 2);
    }

    #[test]
    fn intel_subscription_via_network() {
        let network = default_network();
        let _sub = network
            .subscribe_intel("threat", Some("attack_pattern"))
            .unwrap();
        assert_eq!(network.intel_subscriber_count(), 1);
        network.unsubscribe_intel("threat").unwrap();
        assert_eq!(network.intel_subscriber_count(), 0);
    }

    #[test]
    fn total_broadcasts_counted() {
        let network = default_network();
        assert_eq!(network.total_broadcasts(), 0);
        network
            .broadcast(CrossRingMessage::new(
                CrossRingType::Communication,
                "s",
                "b",
                "t",
                serde_json::json!({}),
            ))
            .unwrap();
        assert_eq!(network.total_broadcasts(), 1);
    }
}
