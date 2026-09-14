// Control Ring — Bidirectional Arbitration: Rings → Keshav (Production Grade)
//
// Directional: Rings escalate conflicts to Keshav.
// Keshav returns arbitration decisions.
//
// Production features:
//   - Trait-based transport (swap mpsc → gRPC request/response)
//   - Escalation tracking with response correlation
//   - Priority-based processing (critical escalations first)
//   - Backpressure detection
//   - Zero unwrap() in any code path
//   - Escalation metrics (by type, by ring)
//   - Configurable timeout for arbitration responses

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::message::{CrossRingMessage, MessagePriority};
use super::transport::{
    InProcessTransport, RingTransport, TransportErrorKind, TransportMetrics,
    TransportMetricsCollector,
};

// ─── Configuration ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ControlRingConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Buffer size for escalations (default: 500).
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Number of seconds before an escalation is considered stale (default: 60).
    #[serde(default = "default_stale_timeout_secs")]
    pub stale_timeout_secs: u64,

    /// Maximum escalation depth to prevent escalation loops (default: 3).
    #[serde(default = "default_max_depth")]
    pub max_escalation_depth: u32,

    /// Track escalation metadata for metrics (default: true).
    #[serde(default = "default_true")]
    pub track_metadata: bool,

    /// Transport type: "in_process" (default), "grpc".
    #[serde(default = "default_transport")]
    pub transport: String,
}

fn default_enabled() -> bool {
    true
}
fn default_buffer_size() -> usize {
    500
}
fn default_stale_timeout_secs() -> u64 {
    60
}
fn default_max_depth() -> u32 {
    3
}
fn default_true() -> bool {
    true
}
fn default_transport() -> String {
    "in_process".into()
}

impl Default for ControlRingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            buffer_size: default_buffer_size(),
            stale_timeout_secs: default_stale_timeout_secs(),
            max_escalation_depth: default_max_depth(),
            track_metadata: default_true(),
            transport: default_transport(),
        }
    }
}

// ─── Escalation Metadata ──────────────────────────────────────────

/// Status of an escalation.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    /// Escalation received, awaiting arbitration.
    Pending,
    /// Keshav has issued an arbitration decision.
    Resolved,
    /// Escalation timed out without resolution.
    Stale,
}

/// Metadata tracked for each escalation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationMeta {
    pub message_id: String,
    pub source_ring: String,
    pub escalation_type: String,
    pub priority: MessagePriority,
    pub status: EscalationStatus,
    pub received_at: String,
    pub resolved_at: Option<String>,
    pub escalation_depth: u32,
}

/// Aggregated escalation statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EscalationStats {
    pub total_escalations: u64,
    pub pending: u64,
    pub resolved: u64,
    pub stale: u64,
    pub by_source: HashMap<String, u64>,
    pub by_type: HashMap<String, u64>,
}

// ─── Control Ring ─────────────────────────────────────────────────

/// The Control Ring — Rings escalate conflicts to Keshav for arbitration.
///
/// Production features:
///   - Per-escalation tracking with status
///   - Stale escalation detection and cleanup
///   - Escalation depth tracking (prevent loops)
///   - Aggregated statistics
///   - Backpressure detection
///   - Zero unwrap()
pub struct ControlRing {
    config: ControlRingConfig,
    escalation_transport: Arc<dyn RingTransport>,
    response_transport: Arc<dyn RingTransport>,
    metrics: TransportMetricsCollector,
    /// Active escalations (message_id → metadata).
    escalations: Mutex<HashMap<String, EscalationMeta>>,
}

impl ControlRing {
    /// Create a new Control Ring with the given configuration.
    pub fn new(config: &ControlRingConfig) -> crate::Result<Self> {
        let make_transport = || -> crate::Result<Arc<dyn RingTransport>> {
            match config.transport.as_str() {
                "in_process" | "" => Ok(Arc::new(InProcessTransport::new(config.buffer_size))),
                other => Err(crate::error::Error::EngineInit(format!(
                    "control ring transport '{}' not yet implemented; use 'in_process'",
                    other
                ))),
            }
        };

        let escalation_transport = make_transport()?;
        let response_transport = make_transport()?;

        Ok(Self {
            config: config.clone(),
            escalation_transport,
            response_transport,
            metrics: TransportMetricsCollector::new("control_ring", config.buffer_size),
            escalations: Mutex::new(HashMap::new()),
        })
    }

    /// Create with custom transports (for testing).
    #[cfg(test)]
    pub fn with_transports(
        config: &ControlRingConfig,
        escalation_transport: Arc<dyn RingTransport>,
        response_transport: Arc<dyn RingTransport>,
    ) -> Self {
        let capacity = escalation_transport.capacity();
        Self {
            config: config.clone(),
            escalation_transport,
            response_transport,
            metrics: TransportMetricsCollector::new("control_ring", capacity),
            escalations: Mutex::new(HashMap::new()),
        }
    }

    /// Escalate a conflict from a ring to Keshav.
    ///
    /// Validates: destination must be "keshav".
    /// Tracks escalation metadata if configured.
    pub fn escalate(&self, msg: CrossRingMessage) -> crate::Result<()> {
        // 1. Validate direction.
        msg.validate_direction()
            .map_err(|e| crate::error::Error::Evaluation(e))?;

        // 2. Check escalation depth.
        let depth: u32 = msg
            .payload
            .get("escalation_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        if depth >= self.config.max_escalation_depth {
            return Err(crate::error::Error::Other(format!(
                "escalation depth {} exceeds max {} — possible escalation loop from '{}'",
                depth, self.config.max_escalation_depth, msg.source
            )));
        }

        // 3. Track metadata.
        if self.config.track_metadata {
            let meta = EscalationMeta {
                message_id: msg.message_id.clone(),
                source_ring: msg.source.clone(),
                escalation_type: msg.msg_type.clone(),
                priority: msg.priority.clone(),
                status: EscalationStatus::Pending,
                received_at: chrono::Utc::now().to_rfc3339(),
                resolved_at: None,
                escalation_depth: depth,
            };
            if let Ok(mut esc) = self.escalations.lock() {
                esc.insert(msg.message_id.clone(), meta);
            }
        }

        // 4. Send via escalation transport.
        match self.escalation_transport.send(msg) {
            Ok(()) => {
                self.metrics.record_send();
                Ok(())
            }
            Err(e) => {
                self.metrics.record_send_error();
                if e.kind == TransportErrorKind::Full {
                    self.metrics.record_backpressure();
                    Err(crate::error::Error::Other(format!(
                        "control ring backpressure: {}",
                        e
                    )))
                } else {
                    Err(crate::error::Error::Other(format!(
                        "control ring escalation failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Receive the next escalation (for Keshav consumption).
    pub fn recv_escalation(&self) -> crate::Result<Option<CrossRingMessage>> {
        match self.escalation_transport.recv() {
            Ok(msg) => {
                if msg.is_some() {
                    self.metrics.record_recv();
                }
                Ok(msg)
            }
            Err(e) => {
                self.metrics.record_recv_error();
                Err(crate::error::Error::Other(format!(
                    "control ring recv failed: {}",
                    e
                )))
            }
        }
    }

    /// Send an arbitration response from Keshav back to the escalating ring.
    ///
    /// The response correlates with the original escalation via `correlation_id`
    /// in the payload.
    pub fn respond(&self, response: CrossRingMessage) -> crate::Result<()> {
        // Mark escalation as resolved.
        if self.config.track_metadata {
            let correlation_id = response
                .payload
                .get("correlation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if !correlation_id.is_empty() {
                if let Ok(mut esc) = self.escalations.lock() {
                    if let Some(meta) = esc.get_mut(correlation_id) {
                        meta.status = EscalationStatus::Resolved;
                        meta.resolved_at = Some(chrono::Utc::now().to_rfc3339());
                    }
                }
            }
        }

        // Send via response transport.
        match self.response_transport.send(response) {
            Ok(()) => {
                self.metrics.record_send();
                Ok(())
            }
            Err(e) => {
                self.metrics.record_send_error();
                Err(crate::error::Error::Other(format!(
                    "control ring respond failed: {}",
                    e
                )))
            }
        }
    }

    /// Receive an arbitration response (for ring consumption).
    pub fn recv_response(&self) -> crate::Result<Option<CrossRingMessage>> {
        match self.response_transport.recv() {
            Ok(msg) => {
                if msg.is_some() {
                    self.metrics.record_recv();
                }
                Ok(msg)
            }
            Err(e) => {
                self.metrics.record_recv_error();
                Err(crate::error::Error::Other(format!(
                    "control ring recv_response failed: {}",
                    e
                )))
            }
        }
    }

    /// Sweep stale escalations (timed out without resolution).
    /// Returns the number of escalations marked as stale.
    pub fn sweep_stale(&self) -> usize {
        let mut count = 0usize;
        if let Ok(mut esc) = self.escalations.lock() {
            for meta in esc.values_mut() {
                if meta.status != EscalationStatus::Pending {
                    continue;
                }
                // Parse the received_at timestamp.
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&meta.received_at) {
                    let elapsed = chrono::Utc::now() - dt.with_timezone(&chrono::Utc);
                    if elapsed.num_seconds() >= self.config.stale_timeout_secs as i64 {
                        meta.status = EscalationStatus::Stale;
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Get aggregated escalation statistics.
    pub fn stats(&self) -> EscalationStats {
        let mut stats = EscalationStats::default();
        if let Ok(esc) = self.escalations.lock() {
            stats.total_escalations = esc.len() as u64;
            for meta in esc.values() {
                match meta.status {
                    EscalationStatus::Pending => stats.pending += 1,
                    EscalationStatus::Resolved => stats.resolved += 1,
                    EscalationStatus::Stale => stats.stale += 1,
                }
                *stats.by_source.entry(meta.source_ring.clone()).or_insert(0) += 1;
                *stats
                    .by_type
                    .entry(meta.escalation_type.clone())
                    .or_insert(0) += 1;
            }
        }
        stats
    }

    /// Count of pending escalations in the transport buffer.
    pub fn pending_escalations(&self) -> usize {
        self.escalation_transport.pending_count()
    }

    /// Count of pending responses in the response transport buffer.
    pub fn pending_responses(&self) -> usize {
        self.response_transport.pending_count()
    }

    /// Whether the escalation transport is connected.
    pub fn is_connected(&self) -> bool {
        self.escalation_transport.is_connected()
    }

    /// Get transport metrics snapshot.
    pub fn metrics(&self) -> TransportMetrics {
        self.metrics
            .snapshot(self.escalation_transport.pending_count())
    }

    /// Clear all escalation tracking (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut e) = self.escalations.lock() {
            e.clear();
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_ring::message::CrossRingType;

    fn default_ring() -> ControlRing {
        ControlRing::new(&ControlRingConfig::default()).unwrap()
    }

    fn escalation_msg(src: &str, esc_type: &str) -> CrossRingMessage {
        CrossRingMessage::new(
            CrossRingType::Control,
            src,
            "keshav",
            esc_type,
            serde_json::json!({
                "conflict": format!("{}_vs_{}", src, "other"),
            }),
        )
    }

    #[test]
    fn escalate_and_recv() {
        let ring = default_ring();
        let msg = escalation_msg("threat", "conflict");
        ring.escalate(msg.clone()).unwrap();

        let received = ring.recv_escalation().unwrap().unwrap();
        assert_eq!(received.message_id, msg.message_id);
        assert_eq!(received.source, "threat");
        assert_eq!(received.destination, "keshav");
    }

    #[test]
    fn directional_validation() {
        let ring = default_ring();
        // Destination must be "keshav".
        let bad_msg = CrossRingMessage::new(
            CrossRingType::Control,
            "threat",
            "shield",
            "bad",
            serde_json::json!({}),
        );
        assert!(ring.escalate(bad_msg).is_err());
    }

    #[test]
    fn escalation_tracking() {
        let ring = default_ring();
        let msg = escalation_msg("threat", "deny_vs_allow");
        ring.escalate(msg.clone()).unwrap();

        let stats = ring.stats();
        assert_eq!(stats.total_escalations, 1);
        assert_eq!(stats.pending, 1);
        assert_eq!(*stats.by_source.get("threat").unwrap(), 1);
    }

    #[test]
    fn escalation_depth_limit() {
        let ring = ControlRing::new(&ControlRingConfig {
            max_escalation_depth: 2,
            ..Default::default()
        })
        .unwrap();

        let mut msg = escalation_msg("threat", "loop");
        msg.payload["escalation_depth"] = serde_json::json!(3); // Exceeds max.

        let result = ring.escalate(msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("escalation depth"));
    }

    #[test]
    fn arbitration_response() {
        let ring = default_ring();
        let msg = escalation_msg("threat", "conflict");
        ring.escalate(msg.clone()).unwrap();

        // Keshav sends response correlated to the escalation.
        let response = CrossRingMessage::new(
            CrossRingType::Control,
            "keshav",
            "threat",
            "arbitration_decision",
            serde_json::json!({
                "correlation_id": msg.message_id,
                "decision": "deny",
                "reason": "threat ring takes precedence",
            }),
        );
        ring.respond(response).unwrap();

        // Verify escalation is now resolved.
        let stats = ring.stats();
        assert_eq!(stats.resolved, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn stale_sweep() {
        let ring = ControlRing::new(&ControlRingConfig {
            stale_timeout_secs: 0, // Instant stale
            ..Default::default()
        })
        .unwrap();

        ring.escalate(escalation_msg("threat", "old")).unwrap();
        let stale_count = ring.sweep_stale();
        assert_eq!(stale_count, 1);

        let stats = ring.stats();
        assert_eq!(stats.stale, 1);
    }

    #[test]
    fn stats_by_type() {
        let ring = default_ring();
        ring.escalate(escalation_msg("threat", "conflict")).unwrap();
        ring.escalate(escalation_msg("execution", "timeout"))
            .unwrap();
        ring.escalate(escalation_msg("threat", "conflict")).unwrap();

        let stats = ring.stats();
        assert_eq!(stats.total_escalations, 3);
        assert_eq!(*stats.by_type.get("conflict").unwrap(), 2);
        assert_eq!(*stats.by_type.get("timeout").unwrap(), 1);
    }

    #[test]
    fn backpressure_reported() {
        let ring = ControlRing::new(&ControlRingConfig {
            buffer_size: 1,
            ..Default::default()
        })
        .unwrap();

        ring.escalate(escalation_msg("threat", "a")).unwrap();
        let result = ring.escalate(escalation_msg("threat", "b"));
        assert!(result.is_err());
    }

    #[test]
    fn metrics_tracking() {
        let ring = default_ring();
        ring.escalate(escalation_msg("threat", "test")).unwrap();
        let _ = ring.recv_escalation().unwrap();
        let m = ring.metrics();
        assert_eq!(m.messages_sent, 1);
        assert_eq!(m.messages_received, 1);
    }

    #[test]
    fn is_connected() {
        let ring = default_ring();
        assert!(ring.is_connected());
    }

    #[test]
    fn clear_resets_state() {
        let ring = default_ring();
        ring.escalate(escalation_msg("threat", "test")).unwrap();
        ring.clear();
        assert_eq!(ring.stats().total_escalations, 0);
    }

    #[test]
    fn recv_response_works() {
        let ring = default_ring();

        let response = CrossRingMessage::new(
            CrossRingType::Control,
            "keshav",
            "threat",
            "arbitration_decision",
            serde_json::json!({"decision": "allow"}),
        );
        ring.respond(response.clone()).unwrap();

        let received = ring.recv_response().unwrap().unwrap();
        assert_eq!(received.message_id, response.message_id);
    }
}
