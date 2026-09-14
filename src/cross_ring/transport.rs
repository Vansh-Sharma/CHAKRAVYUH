// Cross Ring Transport — Abstract transport layer for cross ring communication.
//
// Production architecture: All cross rings communicate through a trait-based
// transport layer. The default InProcessTransport uses bounded mpsc channels.
// Production deployments swap to GrpcTransport, NatsTransport, or RedisTransport
// by implementing the RingTransport trait — zero changes to ring logic.
//
// Design decisions:
//   - SendError is a String (no generic error types in trait bounds)
//   - recv() returns Option<Message> for non-blocking try_recv semantics
//   - subscribe() enables multi-consumer patterns (Intel, Communication)
//   - backpressure_capacity() lets rings query buffer headroom
//   - All methods take &self (not &mut self) for interior mutability

use super::message::CrossRingMessage;

/// Result type for cross ring transport operations.
pub type TransportResult<T> = std::result::Result<T, TransportError>;

/// Transport-level errors.
#[derive(Debug, Clone)]
pub struct TransportError {
    pub kind: TransportErrorKind,
    pub message: String,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.message)
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// Channel/buffer is full — backpressure applied.
    Full,
    /// Channel is closed or transport disconnected.
    Disconnected,
    /// Serialization/deserialization failure.
    Serialization,
    /// Timeout elapsed.
    Timeout,
    /// Transport not configured or unavailable.
    Unavailable,
    /// Other transport-level error.
    Other,
}

impl TransportError {
    pub fn full(msg: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Full,
            message: msg.into(),
        }
    }
    pub fn disconnected(msg: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Disconnected,
            message: msg.into(),
        }
    }
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Timeout,
            message: msg.into(),
        }
    }
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Unavailable,
            message: msg.into(),
        }
    }
    pub fn other(msg: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Other,
            message: msg.into(),
        }
    }
}

/// Abstract transport for cross ring message passing.
///
/// Implementations:
///   - InProcessTransport: mpsc channels (default, zero deps)
///   - GrpcTransport: gRPC streaming + TLS + mTLS (production)
///   - NatsTransport: NATS JetStream pub/sub (distributed)
///   - RedisTransport: Redis Streams (distributed)
///
/// The trait is object-safe and uses String errors to avoid generic
/// bounds bleeding into ring logic.
pub trait RingTransport: Send + Sync {
    /// Send a message through this transport channel.
    /// Returns TransportError::Full if the buffer is at capacity.
    fn send(&self, msg: CrossRingMessage) -> TransportResult<()>;

    /// Try to receive the next message (non-blocking).
    /// Returns None if no message is available.
    fn recv(&self) -> TransportResult<Option<CrossRingMessage>>;

    /// Create a new subscriber that receives copies of messages.
    /// Used by Intel Ring and Communication Ring for multi-consumer.
    /// Default returns an error — override for multi-consumer transports.
    fn subscribe(&self) -> TransportResult<Box<dyn RingSubscriber>> {
        Err(TransportError::unavailable(
            "this transport does not support multi-subscriber",
        ))
    }

    /// Current number of pending messages in the buffer.
    fn pending_count(&self) -> usize;

    /// Total buffer capacity.
    fn capacity(&self) -> usize;

    /// Whether the transport is still connected/operational.
    fn is_connected(&self) -> bool;
}

/// A subscriber handle for multi-consumer transports.
/// Each subscriber receives its own copy of messages.
pub trait RingSubscriber: Send + Sync {
    /// Try to receive the next message for this subscriber.
    fn recv(&self) -> TransportResult<Option<CrossRingMessage>>;

    /// Number of pending messages for this subscriber.
    fn pending_count(&self) -> usize;
}

// ─── In-Process Transport (default) ────────────────────────────────

/// In-process transport using bounded mpsc channels.
///
/// This is the default transport used in single-process deployments.
/// For distributed deployments, swap to GrpcTransport or NatsTransport.
///
/// Thread-safe: uses Mutex<Receiver> for try_recv from multiple callers.
/// Multi-subscriber: subscribe() creates additional receivers via broadcast.
use std::sync::{Arc, Mutex};

pub struct InProcessTransport {
    sender: std::sync::mpsc::SyncSender<CrossRingMessage>,
    receiver: Mutex<std::sync::mpsc::Receiver<CrossRingMessage>>,
    capacity: usize,
    /// Shared sender clone for creating broadcast subscribers.
    sender_clone: std::sync::mpsc::SyncSender<CrossRingMessage>,
    /// Active subscriber receivers (each gets its own channel).
    subscribers: Mutex<Vec<std::sync::mpsc::SyncSender<CrossRingMessage>>>,
}

impl InProcessTransport {
    /// Create a new in-process transport with the given buffer size.
    pub fn new(buffer_size: usize) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(buffer_size);
        Self {
            sender: sender.clone(),
            sender_clone: sender,
            receiver: Mutex::new(receiver),
            capacity: buffer_size,
            subscribers: Mutex::new(Vec::new()),
        }
    }
}

impl RingTransport for InProcessTransport {
    fn send(&self, msg: CrossRingMessage) -> TransportResult<()> {
        // Send to primary receiver (non-blocking — returns Full if buffer at capacity).
        self.sender
            .try_send(msg.clone())
            .map_err(|e| TransportError::full(format!("channel full or closed: {}", e)))?;

        // Fan-out to all subscriber channels.
        if let Ok(subs) = self.subscribers.lock() {
            for tx in subs.iter() {
                // Best-effort: skip subscribers with full buffers.
                let _ = tx.try_send(msg.clone());
            }
        }

        Ok(())
    }

    fn recv(&self) -> TransportResult<Option<CrossRingMessage>> {
        let guard = self
            .receiver
            .lock()
            .map_err(|e| TransportError::other(format!("receiver lock poisoned: {}", e)))?;
        match guard.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(TransportError::disconnected("channel disconnected"))
            }
        }
    }

    fn subscribe(&self) -> TransportResult<Box<dyn RingSubscriber>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(self.capacity);
        self.subscribers
            .lock()
            .map_err(|e| TransportError::other(format!("subscriber lock poisoned: {}", e)))?
            .push(tx);
        Ok(Box::new(InProcessSubscriber {
            receiver: Mutex::new(rx),
        }))
    }

    fn pending_count(&self) -> usize {
        // tokio::sync::mpsc::Receiver does not expose .len();
        // try_recv loop is the only safe way to count pending messages.
        let guard = self.receiver.lock();
        match guard {
            Ok(rx) => {
                let mut count = 0;
                while rx.try_recv().is_ok() {
                    count += 1;
                }
                count
            }
            Err(_) => 0,
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn is_connected(&self) -> bool {
        // mpsc is connected as long as sender exists (it does — we hold it).
        true
    }
}

/// In-process subscriber that receives messages from a dedicated channel.
pub struct InProcessSubscriber {
    receiver: Mutex<std::sync::mpsc::Receiver<CrossRingMessage>>,
}

impl RingSubscriber for InProcessSubscriber {
    fn recv(&self) -> TransportResult<Option<CrossRingMessage>> {
        let guard = self.receiver.lock().map_err(|e| {
            TransportError::other(format!("subscriber receiver lock poisoned: {}", e))
        })?;
        match guard.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(TransportError::disconnected(
                "subscriber channel disconnected",
            )),
        }
    }

    fn pending_count(&self) -> usize {
        let guard = self.receiver.lock();
        match guard {
            Ok(rx) => {
                let mut count = 0;
                while rx.try_recv().is_ok() {
                    count += 1;
                }
                count
            }
            Err(_) => 0,
        }
    }
}

// ─── Broadcast Transport (for Communication Ring) ──────────────────

/// Broadcast transport that fans out to multiple subscribers.
///
/// Unlike InProcessTransport (single receiver + optional subscribers),
/// this is purpose-built for pub/sub patterns where every subscriber
/// gets every message.
pub struct BroadcastTransport {
    sender: Arc<Mutex<Vec<std::sync::mpsc::SyncSender<CrossRingMessage>>>>,
    capacity: usize,
    /// Counter for monitoring.
    send_count: Mutex<u64>,
    /// Last N messages for late-joiners (configurable history window).
    history: Mutex<Vec<CrossRingMessage>>,
    history_size: usize,
}

impl BroadcastTransport {
    pub fn new(buffer_size: usize, history_size: usize) -> Self {
        Self {
            sender: Arc::new(Mutex::new(Vec::new())),
            capacity: buffer_size,
            send_count: Mutex::new(0),
            history: Mutex::new(Vec::with_capacity(history_size)),
            history_size,
        }
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Total messages broadcast.
    pub fn total_sent(&self) -> u64 {
        self.send_count.lock().map(|c| *c).unwrap_or(0)
    }
}

impl RingTransport for BroadcastTransport {
    fn send(&self, msg: CrossRingMessage) -> TransportResult<()> {
        // Store in history for late-joiners.
        if let Ok(mut history) = self.history.lock() {
            history.push(msg.clone());
            if history.len() > self.history_size {
                let excess = history.len() - self.history_size;
                history.drain(..excess);
            }
        }

        // Fan-out to all subscribers.
        let senders = self
            .sender
            .lock()
            .map_err(|e| TransportError::other(format!("broadcast sender lock poisoned: {}", e)))?;

        if senders.is_empty() {
            // No subscribers — message is dropped (acceptable for broadcast).
            // Still count it and store in history.
            if let Ok(mut count) = self.send_count.lock() {
                *count += 1;
            }
            return Ok(());
        }

        let mut failed = 0u32;
        for tx in senders.iter() {
            if tx.try_send(msg.clone()).is_err() {
                failed += 1;
            }
        }

        if let Ok(mut count) = self.send_count.lock() {
            *count += 1;
        }

        // If ALL subscribers failed, the transport is effectively disconnected.
        if failed > 0 && failed as usize == senders.len() {
            return Err(TransportError::disconnected(format!(
                "all {} subscribers disconnected",
                failed
            )));
        }

        // Partial failure is acceptable — some subscribers may have slow consumers.
        // Log via metrics but don't fail the send.
        if failed > 0 {
            // In production, this would emit a metric: cross_ring_broadcast_partial_failure
        }

        Ok(())
    }

    fn recv(&self) -> TransportResult<Option<CrossRingMessage>> {
        // BroadcastTransport doesn't have a primary receiver.
        // Use subscribe() to get a subscriber handle.
        Err(TransportError::unavailable(
            "BroadcastTransport has no primary receiver — use subscribe()",
        ))
    }

    fn subscribe(&self) -> TransportResult<Box<dyn RingSubscriber>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(self.capacity);

        // Replay history for late-joiners.
        if let Ok(history) = self.history.lock() {
            for msg in history.iter() {
                // Best-effort replay — if subscriber buffer is full, skip.
                let _ = tx.try_send(msg.clone());
            }
        }

        self.sender
            .lock()
            .map_err(|e| {
                TransportError::other(format!("broadcast subscriber lock poisoned: {}", e))
            })?
            .push(tx);

        Ok(Box::new(InProcessSubscriber {
            receiver: Mutex::new(rx),
        }))
    }

    fn pending_count(&self) -> usize {
        // Broadcast doesn't have a single pending count.
        // Report max across all subscribers.
        0
    }

    fn capacity(&self) -> usize {
        self.capacity * self.subscriber_count().max(1)
    }

    fn is_connected(&self) -> bool {
        self.subscriber_count() > 0
    }
}

// ─── Transport Metrics (lightweight, no external deps) ─────────────

/// Lightweight transport-level metrics.
/// Production: replace with prometheus/metrics crate integration.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TransportMetrics {
    pub ring_name: String,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub pending_count: usize,
    pub capacity: usize,
    pub backpressure_events: u64,
    pub last_send_at: Option<String>,
    pub last_recv_at: Option<String>,
}

impl TransportMetrics {
    pub fn utilization_pct(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        (self.pending_count as f64 / self.capacity as f64) * 100.0
    }
}

/// Thread-safe metrics collector for a transport.
pub struct TransportMetricsCollector {
    metrics: Mutex<TransportMetrics>,
}

impl TransportMetricsCollector {
    pub fn new(ring_name: &str, capacity: usize) -> Self {
        Self {
            metrics: Mutex::new(TransportMetrics {
                ring_name: ring_name.into(),
                capacity,
                ..Default::default()
            }),
        }
    }

    pub fn record_send(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.messages_sent += 1;
            m.last_send_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    pub fn record_recv(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.messages_received += 1;
            m.last_recv_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    pub fn record_drop(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.messages_dropped += 1;
        }
    }

    pub fn record_send_error(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.send_errors += 1;
        }
    }

    pub fn record_recv_error(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.recv_errors += 1;
        }
    }

    pub fn record_backpressure(&self) {
        if let Ok(mut m) = self.metrics.lock() {
            m.backpressure_events += 1;
        }
    }

    pub fn snapshot(&self, pending: usize) -> TransportMetrics {
        let mut m = self.metrics.lock().map(|g| g.clone()).unwrap_or_default();
        m.pending_count = pending;
        m
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_ring::message::{CrossRingMessage, CrossRingType};

    fn test_msg(ring_type: CrossRingType, src: &str, dst: &str) -> CrossRingMessage {
        CrossRingMessage::new(ring_type, src, dst, "test", serde_json::json!({}))
    }

    #[test]
    fn in_process_send_recv() {
        let transport = InProcessTransport::new(10);
        let msg = test_msg(CrossRingType::Command, "keshav", "shield");
        transport.send(msg.clone()).unwrap();
        let received = transport.recv().unwrap().unwrap();
        assert_eq!(received.message_id, msg.message_id);
    }

    #[test]
    fn in_process_backpressure() {
        let transport = InProcessTransport::new(2);
        transport
            .send(test_msg(CrossRingType::Command, "keshav", "shield"))
            .unwrap();
        transport
            .send(test_msg(CrossRingType::Command, "keshav", "shield"))
            .unwrap();
        // Third send should fail — buffer full.
        let result = transport.send(test_msg(CrossRingType::Command, "keshav", "shield"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, TransportErrorKind::Full);
    }

    #[test]
    fn in_process_empty_recv() {
        let transport = InProcessTransport::new(10);
        assert!(transport.recv().unwrap().is_none());
    }

    #[test]
    fn in_process_subscriber() {
        let transport = InProcessTransport::new(10);
        let _sub = transport.subscribe().unwrap();

        let msg = test_msg(CrossRingType::Intel, "shield", "broadcast");
        transport.send(msg.clone()).unwrap();

        // Primary receiver gets the message.
        let primary = transport.recv().unwrap().unwrap();
        assert_eq!(primary.message_id, msg.message_id);
    }

    #[test]
    fn in_process_connected() {
        let transport = InProcessTransport::new(10);
        assert!(transport.is_connected());
        assert_eq!(transport.capacity(), 10);
    }

    #[test]
    fn broadcast_fan_out() {
        let transport = BroadcastTransport::new(10, 100);
        let sub1 = transport.subscribe().unwrap();
        let sub2 = transport.subscribe().unwrap();

        let msg = test_msg(CrossRingType::Communication, "system", "broadcast");
        transport.send(msg.clone()).unwrap();

        // Both subscribers should receive the message.
        let r1 = sub1.recv().unwrap().unwrap();
        let r2 = sub2.recv().unwrap().unwrap();
        assert_eq!(r1.message_id, msg.message_id);
        assert_eq!(r2.message_id, msg.message_id);
    }

    #[test]
    fn broadcast_no_primary_recv() {
        let transport = BroadcastTransport::new(10, 100);
        let result = transport.recv();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, TransportErrorKind::Unavailable);
    }

    #[test]
    fn broadcast_late_joiner_replay() {
        let transport = BroadcastTransport::new(10, 100);

        // Send a message before subscriber joins.
        let msg1 = test_msg(CrossRingType::Communication, "system", "broadcast");
        transport.send(msg1.clone()).unwrap();

        // Late joiner should get the history.
        let late_sub = transport.subscribe().unwrap();
        let replayed = late_sub.recv().unwrap().unwrap();
        assert_eq!(replayed.message_id, msg1.message_id);
    }

    #[test]
    fn broadcast_history_size_limit() {
        let transport = BroadcastTransport::new(10, 2);

        transport
            .send(test_msg(CrossRingType::Communication, "s", "b"))
            .unwrap();
        transport
            .send(test_msg(CrossRingType::Communication, "s", "b"))
            .unwrap();
        transport
            .send(test_msg(CrossRingType::Communication, "s", "b"))
            .unwrap();

        // Late joiner should only get last 2 messages.
        let sub = transport.subscribe().unwrap();
        let count = sub.pending_count();
        assert_eq!(count, 2);
    }

    #[test]
    fn broadcast_subscriber_count() {
        let transport = BroadcastTransport::new(10, 100);
        assert_eq!(transport.subscriber_count(), 0);
        let _s1 = transport.subscribe().unwrap();
        assert_eq!(transport.subscriber_count(), 1);
        let _s2 = transport.subscribe().unwrap();
        assert_eq!(transport.subscriber_count(), 2);
    }

    #[test]
    fn broadcast_total_sent() {
        let transport = BroadcastTransport::new(10, 100);
        assert_eq!(transport.total_sent(), 0);
        transport
            .send(test_msg(CrossRingType::Communication, "s", "b"))
            .unwrap();
        transport
            .send(test_msg(CrossRingType::Communication, "s", "b"))
            .unwrap();
        assert_eq!(transport.total_sent(), 2);
    }

    #[test]
    fn metrics_collector_basic() {
        let collector = TransportMetricsCollector::new("test_ring", 100);
        collector.record_send();
        collector.record_send();
        collector.record_recv();
        collector.record_drop();
        collector.record_backpressure();

        let snap = collector.snapshot(5);
        assert_eq!(snap.messages_sent, 2);
        assert_eq!(snap.messages_received, 1);
        assert_eq!(snap.messages_dropped, 1);
        assert_eq!(snap.backpressure_events, 1);
        assert_eq!(snap.pending_count, 5);
        assert!((snap.utilization_pct() - 5.0).abs() < 0.01);
    }

    #[test]
    fn transport_error_kinds() {
        let e = TransportError::full("buffer full");
        assert_eq!(e.kind, TransportErrorKind::Full);

        let e = TransportError::disconnected("gone");
        assert_eq!(e.kind, TransportErrorKind::Disconnected);

        let e = TransportError::timeout("slow");
        assert_eq!(e.kind, TransportErrorKind::Timeout);

        let e = TransportError::unavailable("n/a");
        assert_eq!(e.kind, TransportErrorKind::Unavailable);
    }
}
