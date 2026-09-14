// Command Ring — Top-down: Keshav → Rings (Production Grade)
//
// Directional: Keshav sends commands; rings receive and ACK.
// Rings NEVER send commands to Keshav or other rings via this channel.
//
// Production features:
//   - Trait-based transport (swap mpsc → gRPC/NATS/Redis)
//   - ACK tracking with configurable timeout
//   - Backpressure reporting (no silent drops)
//   - Zero unwrap() in hot path
//   - Transport metrics collection
//   - Ordered delivery guarantee (FIFO per sender)
//   - Message deduplication (idempotency key = message_id)

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::message::{CrossRingMessage, MessagePriority};
use super::transport::{
    InProcessTransport, RingTransport, TransportErrorKind, TransportMetricsCollector,
};

// ─── Configuration ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CommandRingConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Buffer size for the command channel (default: 1000).
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Whether to track ACKs for sent commands (default: true).
    #[serde(default = "default_true")]
    pub track_acks: bool,

    /// Number of seconds before an unACKed command is considered lost (default: 30).
    #[serde(default = "default_ack_timeout_secs")]
    pub ack_timeout_secs: u64,

    /// Enable message deduplication (default: true).
    #[serde(default = "default_true")]
    pub deduplicate: bool,

    /// Maximum number of dedup history entries (default: 10_000).
    #[serde(default = "default_dedup_window")]
    pub dedup_window: usize,

    /// Transport type: "in_process" (default), "grpc", "nats", "redis".
    #[serde(default = "default_transport")]
    pub transport: String,
}

fn default_enabled() -> bool {
    true
}
fn default_buffer_size() -> usize {
    1000
}
fn default_true() -> bool {
    true
}
fn default_ack_timeout_secs() -> u64 {
    30
}
fn default_dedup_window() -> usize {
    10_000
}
fn default_transport() -> String {
    "in_process".into()
}

impl Default for CommandRingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            buffer_size: default_buffer_size(),
            track_acks: default_true(),
            ack_timeout_secs: default_ack_timeout_secs(),
            deduplicate: default_true(),
            dedup_window: default_dedup_window(),
            transport: default_transport(),
        }
    }
}

// ─── ACK Tracking ─────────────────────────────────────────────────

/// Status of a sent command.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    /// Sent, waiting for ACK.
    Pending,
    /// ACK received from the destination ring.
    Acknowledged,
    /// Timed out waiting for ACK.
    TimedOut,
}

/// Tracked command with metadata.
struct TrackedCommand {
    message_id: String,
    destination: String,
    sent_at: Instant,
    status: Mutex<CommandStatus>,
}

// ─── Command Ring ─────────────────────────────────────────────────

/// The Command Ring — Keshav → Rings (top-down, ordered, ACK-tracked).
///
/// Production-grade implementation with:
///   - Pluggable transport (InProcess by default)
///   - Per-message ACK tracking
///   - Backpressure detection and reporting
///   - Message deduplication
///   - Zero unwrap() in any code path
///   - Transport metrics
pub struct CommandRing {
    config: CommandRingConfig,
    transport: Arc<dyn RingTransport>,
    metrics: TransportMetricsCollector,
    /// Tracked commands (message_id → TrackedCommand).
    ack_tracker: Mutex<std::collections::HashMap<String, Arc<TrackedCommand>>>,
    /// Deduplication set (message_id ring buffer).
    seen_ids: Mutex<HashSet<String>>,
    /// Dedup FIFO for eviction.
    dedup_fifo: Mutex<Vec<String>>,
}

impl CommandRing {
    /// Create a new Command Ring with the given configuration.
    pub fn new(config: &CommandRingConfig) -> crate::Result<Self> {
        let transport: Arc<dyn RingTransport> = match config.transport.as_str() {
            "in_process" | "" => Arc::new(InProcessTransport::new(config.buffer_size)),
            other => {
                return Err(crate::error::Error::EngineInit(format!(
                    "command ring transport '{}' not yet implemented; use 'in_process'",
                    other
                )));
            }
        };

        Ok(Self {
            config: config.clone(),
            metrics: TransportMetricsCollector::new("command_ring", config.buffer_size),
            transport,
            ack_tracker: Mutex::new(std::collections::HashMap::new()),
            seen_ids: Mutex::new(HashSet::with_capacity(config.dedup_window)),
            dedup_fifo: Mutex::new(Vec::with_capacity(config.dedup_window)),
        })
    }

    /// Create with a custom transport (for testing or custom deployments).
    pub fn with_transport(config: &CommandRingConfig, transport: Arc<dyn RingTransport>) -> Self {
        let capacity = transport.capacity();
        Self {
            config: config.clone(),
            metrics: TransportMetricsCollector::new("command_ring", capacity),
            transport,
            ack_tracker: Mutex::new(std::collections::HashMap::new()),
            seen_ids: Mutex::new(HashSet::with_capacity(config.dedup_window)),
            dedup_fifo: Mutex::new(Vec::with_capacity(config.dedup_window)),
        }
    }

    /// Send a command from Keshav to a ring.
    ///
    /// Validates directional semantics (source must be "keshav"),
    /// applies deduplication, tracks ACK if enabled, and reports
    /// backpressure via the Result.
    pub fn send(&self, msg: CrossRingMessage) -> crate::Result<()> {
        // 1. Validate direction.
        msg.validate_direction()
            .map_err(|e| crate::error::Error::Evaluation(e))?;

        // 2. Deduplication.
        if self.config.deduplicate {
            if let Ok(mut seen) = self.seen_ids.lock() {
                if seen.contains(&msg.message_id) {
                    return Ok(()); // Idempotent — silently skip duplicate.
                }
                seen.insert(msg.message_id.clone());
            }
            if let Ok(mut fifo) = self.dedup_fifo.lock() {
                fifo.push(msg.message_id.clone());
                while fifo.len() > self.config.dedup_window {
                    if let Some(evicted) = fifo.first() {
                        if let Ok(mut seen) = self.seen_ids.lock() {
                            seen.remove(evicted);
                        }
                    }
                    fifo.remove(0);
                }
            }
        }

        // 3. Track ACK before sending.
        if self.config.track_acks {
            let tracked = Arc::new(TrackedCommand {
                message_id: msg.message_id.clone(),
                destination: msg.destination.clone(),
                sent_at: Instant::now(),
                status: Mutex::new(CommandStatus::Pending),
            });
            if let Ok(mut tracker) = self.ack_tracker.lock() {
                tracker.insert(msg.message_id.clone(), tracked);
            }
        }

        // 4. Send via transport.
        match self.transport.send(msg) {
            Ok(()) => {
                self.metrics.record_send();
                Ok(())
            }
            Err(e) => {
                self.metrics.record_send_error();
                if e.kind == TransportErrorKind::Full {
                    self.metrics.record_backpressure();
                    Err(crate::error::Error::Other(format!(
                        "command ring backpressure: {}",
                        e
                    )))
                } else {
                    Err(crate::error::Error::Other(format!(
                        "command ring send failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Broadcast a command from Keshav to ALL rings.
    pub fn broadcast(&self, msg: CrossRingMessage) -> crate::Result<()> {
        let mut broadcast_msg = msg.clone();
        broadcast_msg.destination = "broadcast".into();
        broadcast_msg.priority = MessagePriority::High;
        self.send(broadcast_msg)
    }

    /// Receive the next command (for ring consumption).
    /// Returns None if no message is available (non-blocking).
    pub fn recv(&self) -> crate::Result<Option<CrossRingMessage>> {
        match self.transport.recv() {
            Ok(msg) => {
                if let Some(ref _m) = msg {
                    self.metrics.record_recv();
                }
                Ok(msg)
            }
            Err(e) => {
                self.metrics.record_recv_error();
                Err(crate::error::Error::Other(format!(
                    "command ring recv failed: {}",
                    e
                )))
            }
        }
    }

    /// Acknowledge a received command (by message_id).
    /// Rings call this after processing a command.
    pub fn ack(&self, message_id: &str) {
        if !self.config.track_acks {
            return;
        }
        if let Ok(mut tracker) = self.ack_tracker.lock() {
            if let Some(tracked) = tracker.get_mut(message_id) {
                if let Ok(mut status) = tracked.status.lock() {
                    *status = CommandStatus::Acknowledged;
                }
            }
        }
    }

    /// Get the status of a tracked command.
    pub fn command_status(&self, message_id: &str) -> Option<CommandStatus> {
        let tracker = self.ack_tracker.lock().ok()?;
        let tracked = tracker.get(message_id)?;
        let status = tracked.status.lock().ok()?.clone();
        Some(status)
    }

    /// Sweep timed-out commands and mark them as TimedOut.
    /// Call periodically from a background task.
    pub fn sweep_timeouts(&self) -> Vec<String> {
        let mut timed_out = Vec::new();
        if let Ok(mut tracker) = self.ack_tracker.lock() {
            for (id, tracked) in tracker.iter_mut() {
                let should_timeout = {
                    let status = tracked.status.lock().ok();
                    match status {
                        Some(s) if *s == CommandStatus::Pending => {
                            tracked.sent_at.elapsed().as_secs() >= self.config.ack_timeout_secs
                        }
                        _ => false,
                    }
                };
                if should_timeout {
                    if let Ok(mut status) = tracked.status.lock() {
                        *status = CommandStatus::TimedOut;
                    }
                    timed_out.push(id.clone());
                }
            }
        }
        timed_out
    }

    /// Number of pending (unACKed) commands.
    pub fn pending_acks(&self) -> usize {
        self.ack_tracker
            .lock()
            .map(|t| {
                t.values()
                    .filter(|tc| {
                        tc.status
                            .lock()
                            .map(|s| *s == CommandStatus::Pending)
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Count of messages in the transport buffer.
    pub fn pending(&self) -> usize {
        self.transport.pending_count()
    }

    /// Whether the transport is connected.
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Get transport metrics snapshot.
    pub fn metrics(&self) -> super::transport::TransportMetrics {
        self.metrics.snapshot(self.transport.pending_count())
    }

    /// Total commands tracked (pending + acked + timed out).
    pub fn tracked_count(&self) -> usize {
        self.ack_tracker.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// Clear all tracked commands and dedup state (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut t) = self.ack_tracker.lock() {
            t.clear();
        }
        if let Ok(mut s) = self.seen_ids.lock() {
            s.clear();
        }
        if let Ok(mut f) = self.dedup_fifo.lock() {
            f.clear();
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_ring::message::CrossRingMessage;
    use crate::cross_ring::message::CrossRingType;

    fn default_ring() -> CommandRing {
        CommandRing::new(&CommandRingConfig::default()).unwrap()
    }

    fn cmd_msg(dst: &str) -> CrossRingMessage {
        CrossRingMessage::new(
            CrossRingType::Command,
            "keshav",
            dst,
            "test_cmd",
            serde_json::json!({"action": "test"}),
        )
    }

    #[test]
    fn send_and_recv() {
        let ring = default_ring();
        let msg = cmd_msg("shield");
        ring.send(msg.clone()).unwrap();
        let received = ring.recv().unwrap().unwrap();
        assert_eq!(received.message_id, msg.message_id);
        assert_eq!(received.source, "keshav");
        assert_eq!(received.destination, "shield");
    }

    #[test]
    fn directional_validation_enforced() {
        let ring = default_ring();
        // Ring → Ring via Command Ring should fail.
        let bad_msg = CrossRingMessage::new(
            CrossRingType::Command,
            "shield",
            "threat",
            "bad",
            serde_json::json!({}),
        );
        assert!(ring.send(bad_msg).is_err());
    }

    #[test]
    fn ack_tracking() {
        let ring = default_ring();
        let msg = cmd_msg("threat");
        ring.send(msg.clone()).unwrap();

        // Before ACK, status is Pending.
        assert_eq!(
            ring.command_status(&msg.message_id),
            Some(CommandStatus::Pending)
        );
        assert_eq!(ring.pending_acks(), 1);

        // ACK the command.
        ring.ack(&msg.message_id);
        assert_eq!(
            ring.command_status(&msg.message_id),
            Some(CommandStatus::Acknowledged)
        );
        assert_eq!(ring.pending_acks(), 0);
    }

    #[test]
    fn timeout_sweep() {
        let ring = CommandRing::new(&CommandRingConfig {
            ack_timeout_secs: 0, // Instant timeout
            ..Default::default()
        })
        .unwrap();

        let msg = cmd_msg("memory");
        ring.send(msg).unwrap();

        let timed_out = ring.sweep_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(ring.pending_acks(), 0);
    }

    #[test]
    fn deduplication() {
        let ring = default_ring();
        let msg = cmd_msg("agent");

        // Send twice with same message_id.
        ring.send(msg.clone()).unwrap();
        ring.send(msg.clone()).unwrap(); // Should be silently dropped.

        // Only one message in buffer.
        let count = ring.recv().unwrap().and_then(|_| ring.recv().unwrap());
        assert!(count.is_none());
    }

    #[test]
    fn broadcast_to_all() {
        let ring = default_ring();
        let msg = cmd_msg("shield");
        ring.broadcast(msg.clone()).unwrap();

        let received = ring.recv().unwrap().unwrap();
        assert_eq!(received.destination, "broadcast");
        assert_eq!(received.priority, MessagePriority::High);
    }

    #[test]
    fn backpressure_reported() {
        let ring = CommandRing::new(&CommandRingConfig {
            buffer_size: 2,
            ..Default::default()
        })
        .unwrap();

        ring.send(cmd_msg("shield")).unwrap();
        ring.send(cmd_msg("threat")).unwrap();
        // Third send should fail with backpressure.
        let result = ring.send(cmd_msg("identity"));
        assert!(result.is_err());
    }

    #[test]
    fn metrics_tracking() {
        let ring = default_ring();
        ring.send(cmd_msg("shield")).unwrap();
        let _ = ring.recv().unwrap();

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
        ring.send(cmd_msg("shield")).unwrap();
        ring.clear();
        assert_eq!(ring.tracked_count(), 0);
        assert_eq!(ring.pending_acks(), 0);
    }

    #[test]
    fn custom_transport() {
        let transport = Arc::new(InProcessTransport::new(50));
        let ring = CommandRing::with_transport(&CommandRingConfig::default(), transport);
        ring.send(cmd_msg("shield")).unwrap();
        assert_eq!(ring.metrics().messages_sent, 1);
    }
}
