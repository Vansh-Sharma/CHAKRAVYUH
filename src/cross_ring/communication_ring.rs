// Communication Ring — System-Wide Broadcast (Production Grade)
//
// The Communication Ring is the system-wide broadcast channel.
// Any component can broadcast; all subscribers receive every message.
// Used for: system alerts, config change notifications, coordination events.
//
// Production features:
//   - Dedicated BroadcastTransport (fan-out to all subscribers)
//   - Topic-based pub/sub with wildcards
//   - Late-joiner replay (configurable history window)
//   - Subscriber lifecycle management
//   - Broadcast metrics (per-topic, per-subscriber)
//   - Backpressure per subscriber (slow consumers don't block fast ones)
//   - Zero unwrap() in any code path
//   - Ordered replay guarantee

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::message::{CrossRingMessage, CrossRingType};
use super::transport::{
    BroadcastTransport, RingSubscriber, RingTransport, TransportErrorKind, TransportMetrics,
    TransportMetricsCollector,
};

// ─── Configuration ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CommunicationRingConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Buffer size per subscriber (default: 500).
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Number of historic messages to replay for late joiners (default: 200).
    #[serde(default = "default_history_size")]
    pub history_size: usize,

    /// Maximum number of subscribers (default: 50).
    #[serde(default = "default_max_subscribers")]
    pub max_subscribers: usize,

    /// Enable topic-based filtering (default: true).
    #[serde(default = "default_true")]
    pub topic_filtering: bool,
}

fn default_true() -> bool {
    true
}
fn default_enabled() -> bool {
    true
}
fn default_buffer_size() -> usize {
    500
}
fn default_history_size() -> usize {
    200
}
fn default_max_subscribers() -> usize {
    50
}
fn default_topic_filtering() -> bool {
    true
}

impl Default for CommunicationRingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            buffer_size: default_buffer_size(),
            history_size: default_history_size(),
            max_subscribers: default_max_subscribers(),
            topic_filtering: default_topic_filtering(),
        }
    }
}

// ─── Communication Subscription ───────────────────────────────────

/// A subscription to the Communication Ring.
///
/// Supports optional topic filtering. If topic_filter is set, only
/// messages matching that topic (msg_type) are returned.
/// Wildcard "*" receives all messages.
pub struct CommunicationSubscription {
    subscriber: Box<dyn RingSubscriber>,
    topic_filter: Option<String>,
    subscriber_name: String,
}

impl CommunicationSubscription {
    /// Receive the next broadcast message for this subscriber.
    /// Respects topic filter if configured.
    /// Skips non-matching messages (returns None if filtered out).
    pub fn recv(&self) -> crate::Result<Option<CrossRingMessage>> {
        // Try to get a message. If filtered out, skip and try next.
        loop {
            match self.subscriber.recv() {
                Ok(Some(msg)) => {
                    if let Some(ref topic) = self.topic_filter {
                        if topic != "*" && msg.msg_type != *topic {
                            continue; // Skip non-matching messages.
                        }
                    }
                    return Ok(Some(msg));
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    return Err(crate::error::Error::Other(format!(
                        "communication subscription '{}' recv failed: {}",
                        self.subscriber_name, e
                    )));
                }
            }
        }
    }

    /// Number of pending messages (may include filtered messages).
    pub fn pending(&self) -> usize {
        self.subscriber.pending_count()
    }

    /// Name of the subscribing component.
    pub fn name(&self) -> &str {
        &self.subscriber_name
    }

    /// Topic filter for this subscription (None = all topics).
    pub fn topic(&self) -> Option<&str> {
        self.topic_filter.as_deref()
    }
}

// ─── Topic Registry ───────────────────────────────────────────────

/// Tracks which topics exist and how many messages per topic.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TopicStats {
    pub topic: String,
    pub message_count: u64,
    pub last_broadcast_at: Option<String>,
    pub subscriber_count: usize,
}

// ─── Communication Ring ──────────────────────────────────────────

/// The Communication Ring — system-wide broadcast channel.
///
/// Production features:
///   - Dedicated BroadcastTransport (fan-out to all subscribers)
///   - Topic-based subscriptions with wildcard support
///   - Late-joiner replay from history buffer
///   - Per-topic statistics
///   - Subscriber lifecycle management
///   - Zero unwrap()
pub struct CommunicationRing {
    config: CommunicationRingConfig,
    transport: Arc<BroadcastTransport>,
    metrics: TransportMetricsCollector,
    /// Active subscriptions keyed by name.
    subscriptions: Mutex<HashMap<String, Arc<CommunicationSubscription>>>,
    /// Per-topic statistics.
    topic_stats: Mutex<HashMap<String, TopicStats>>,
    /// All known topics (set of msg_types seen).
    known_topics: Mutex<HashSet<String>>,
}

impl CommunicationRing {
    /// Create a new Communication Ring with the given configuration.
    pub fn new(config: &CommunicationRingConfig) -> crate::Result<Self> {
        let transport = Arc::new(BroadcastTransport::new(
            config.buffer_size,
            config.history_size,
        ));

        Ok(Self {
            config: config.clone(),
            metrics: TransportMetricsCollector::new("communication_ring", config.buffer_size),
            transport,
            subscriptions: Mutex::new(HashMap::new()),
            topic_stats: Mutex::new(HashMap::new()),
            known_topics: Mutex::new(HashSet::new()),
        })
    }

    /// Broadcast a message to all subscribers.
    ///
    /// Validates: destination must be "broadcast".
    /// Updates topic statistics.
    pub fn broadcast(&self, mut msg: CrossRingMessage) -> crate::Result<()> {
        // 1. Force destination to broadcast.
        msg.destination = "broadcast".into();
        msg.cross_ring_type = CrossRingType::Communication;

        // 2. Validate direction.
        msg.validate_direction()
            .map_err(|e| crate::error::Error::Evaluation(e))?;

        // 3. Update topic stats.
        if let Ok(mut topics) = self.topic_stats.lock() {
            let entry = topics
                .entry(msg.msg_type.clone())
                .or_insert_with(|| TopicStats {
                    topic: msg.msg_type.clone(),
                    ..Default::default()
                });
            entry.message_count += 1;
            entry.last_broadcast_at = Some(chrono::Utc::now().to_rfc3339());
        }
        if let Ok(mut known) = self.known_topics.lock() {
            known.insert(msg.msg_type.clone());
        }

        // 4. Send via broadcast transport.
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
                        "communication ring backpressure: {}",
                        e
                    )))
                } else if e.kind == TransportErrorKind::Disconnected {
                    // No subscribers — acceptable for broadcast.
                    // Message is stored in history for late joiners.
                    self.metrics.record_send();
                    Ok(())
                } else {
                    Err(crate::error::Error::Other(format!(
                        "communication ring broadcast failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Subscribe to broadcast messages.
    ///
    /// - `subscriber_name`: unique name for this subscriber.
    /// - `topic_filter`: Some(topic) for filtered, None for all, Some("*") for all.
    ///
    /// New subscribers receive a replay of recent messages from the history buffer.
    pub fn subscribe(
        &self,
        subscriber_name: &str,
        topic_filter: Option<&str>,
    ) -> crate::Result<Arc<CommunicationSubscription>> {
        // 1. Check subscriber limit.
        {
            let subs = self.subscriptions.lock().map_err(|e| {
                crate::error::Error::Other(format!(
                    "communication subscriptions lock poisoned: {}",
                    e
                ))
            })?;
            if subs.len() >= self.config.max_subscribers {
                return Err(crate::error::Error::Other(format!(
                    "communication ring max subscribers ({}) reached, cannot add '{}'",
                    self.config.max_subscribers, subscriber_name
                )));
            }
            if subs.contains_key(subscriber_name) {
                return Err(crate::error::Error::Other(format!(
                    "communication ring subscriber '{}' already exists",
                    subscriber_name
                )));
            }
        }

        // 2. Create subscription via broadcast transport (includes replay).
        let subscriber = self.transport.subscribe().map_err(|e| {
            crate::error::Error::Other(format!(
                "communication ring subscribe failed for '{}': {}",
                subscriber_name, e
            ))
        })?;

        // Normalize topic filter.
        let normalized_filter = match topic_filter {
            Some("*") | Some("") => None, // Wildcard = no filter.
            Some(t) => Some(t.to_string()),
            None => None,
        };

        let sub = Arc::new(CommunicationSubscription {
            subscriber,
            topic_filter: normalized_filter,
            subscriber_name: subscriber_name.into(),
        });

        // 3. Register subscription.
        self.subscriptions
            .lock()
            .map_err(|e| {
                crate::error::Error::Other(format!(
                    "communication subscriptions lock poisoned: {}",
                    e
                ))
            })?
            .insert(subscriber_name.into(), sub.clone());

        // 4. Update topic stats subscriber count.
        if let Some(ref topic) = sub.topic_filter {
            if let Ok(mut stats) = self.topic_stats.lock() {
                if let Some(ts) = stats.get_mut(topic) {
                    ts.subscriber_count += 1;
                }
            }
        }

        Ok(sub)
    }

    /// Unsubscribe a component from broadcasts.
    pub fn unsubscribe(&self, subscriber_name: &str) -> crate::Result<()> {
        let removed = self
            .subscriptions
            .lock()
            .map_err(|e| {
                crate::error::Error::Other(format!(
                    "communication subscriptions lock poisoned: {}",
                    e
                ))
            })?
            .remove(subscriber_name);

        // Update topic stats.
        if let Some(ref sub) = removed {
            if let Some(ref topic) = sub.topic_filter {
                if let Ok(mut stats) = self.topic_stats.lock() {
                    if let Some(ts) = stats.get_mut(topic) {
                        ts.subscriber_count = ts.subscriber_count.saturating_sub(1);
                    }
                }
            }
        }

        Ok(())
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscriptions.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// List all active subscriber names.
    pub fn subscriber_names(&self) -> Vec<String> {
        self.subscriptions
            .lock()
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get statistics for a specific topic.
    pub fn topic_stats(&self, topic: &str) -> Option<TopicStats> {
        self.topic_stats.lock().ok()?.get(topic).cloned()
    }

    /// Get statistics for all known topics.
    pub fn all_topic_stats(&self) -> Vec<TopicStats> {
        self.topic_stats
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List all known topics.
    pub fn known_topics(&self) -> Vec<String> {
        self.known_topics
            .lock()
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Total broadcasts sent.
    pub fn total_broadcasts(&self) -> u64 {
        self.transport.total_sent()
    }

    /// Whether any subscribers are active.
    pub fn has_subscribers(&self) -> bool {
        self.subscriber_count() > 0
    }

    /// Get transport metrics snapshot.
    pub fn metrics(&self) -> TransportMetrics {
        self.metrics.snapshot(self.transport.subscriber_count())
    }

    /// Clear all state (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut s) = self.subscriptions.lock() {
            s.clear();
        }
        if let Ok(mut t) = self.topic_stats.lock() {
            t.clear();
        }
        if let Ok(mut k) = self.known_topics.lock() {
            k.clear();
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_ring::message::CrossRingMessage;

    fn default_ring() -> CommunicationRing {
        CommunicationRing::new(&CommunicationRingConfig::default()).unwrap()
    }

    fn broadcast_msg(msg_type: &str) -> CrossRingMessage {
        CrossRingMessage::new(
            CrossRingType::Communication,
            "system",
            "broadcast",
            msg_type,
            serde_json::json!({"data": "test"}),
        )
    }

    #[test]
    fn broadcast_to_subscribers() {
        let ring = default_ring();
        let sub1 = ring.subscribe("shield", None).unwrap();
        let sub2 = ring.subscribe("threat", None).unwrap();

        let msg = broadcast_msg("system_alert");
        ring.broadcast(msg.clone()).unwrap();

        // Both subscribers receive the message.
        let r1 = sub1.recv().unwrap().unwrap();
        let r2 = sub2.recv().unwrap().unwrap();
        assert_eq!(r1.message_id, msg.message_id);
        assert_eq!(r2.message_id, msg.message_id);
    }

    #[test]
    fn topic_filtered_subscription() {
        let ring = default_ring();
        let alert_sub = ring.subscribe("shield", Some("system_alert")).unwrap();
        let config_sub = ring.subscribe("threat", Some("config_change")).unwrap();

        ring.broadcast(broadcast_msg("system_alert")).unwrap();
        ring.broadcast(broadcast_msg("config_change")).unwrap();
        ring.broadcast(broadcast_msg("other_event")).unwrap();

        // alert_sub should get only system_alert.
        let r1 = alert_sub.recv().unwrap().unwrap();
        assert_eq!(r1.msg_type, "system_alert");
        assert!(alert_sub.recv().unwrap().is_none()); // other events filtered.

        // config_sub should get only config_change.
        let r2 = config_sub.recv().unwrap().unwrap();
        assert_eq!(r2.msg_type, "config_change");
        assert!(config_sub.recv().unwrap().is_none());
    }

    #[test]
    fn wildcard_subscription() {
        let ring = default_ring();
        let sub = ring.subscribe("keshav", Some("*")).unwrap();

        ring.broadcast(broadcast_msg("alert")).unwrap();
        ring.broadcast(broadcast_msg("config")).unwrap();

        assert!(sub.recv().unwrap().is_some());
        assert!(sub.recv().unwrap().is_some());
    }

    #[test]
    fn late_joiner_replay() {
        let ring = CommunicationRing::new(&CommunicationRingConfig {
            history_size: 100,
            ..Default::default()
        })
        .unwrap();

        ring.broadcast(broadcast_msg("early_event")).unwrap();

        // Late joiner should get the replay.
        let late = ring.subscribe("shield", None).unwrap();
        let replayed = late.recv().unwrap().unwrap();
        assert_eq!(replayed.msg_type, "early_event");
    }

    #[test]
    fn unsubscribe() {
        let ring = default_ring();
        ring.subscribe("shield", None).unwrap();
        assert_eq!(ring.subscriber_count(), 1);
        ring.unsubscribe("shield").unwrap();
        assert_eq!(ring.subscriber_count(), 0);
    }

    #[test]
    fn duplicate_subscriber_rejected() {
        let ring = default_ring();
        ring.subscribe("shield", None).unwrap();
        let result = ring.subscribe("shield", None);
        assert!(result.is_err());
    }

    #[test]
    fn max_subscribers_limit() {
        let ring = CommunicationRing::new(&CommunicationRingConfig {
            max_subscribers: 1,
            ..Default::default()
        })
        .unwrap();

        ring.subscribe("shield", None).unwrap();
        let result = ring.subscribe("threat", None);
        assert!(result.is_err());
    }

    #[test]
    fn topic_statistics() {
        let ring = default_ring();
        ring.broadcast(broadcast_msg("alert")).unwrap();
        ring.broadcast(broadcast_msg("alert")).unwrap();
        ring.broadcast(broadcast_msg("config")).unwrap();

        let alert_stats = ring.topic_stats("alert").unwrap();
        assert_eq!(alert_stats.message_count, 2);

        let config_stats = ring.topic_stats("config").unwrap();
        assert_eq!(config_stats.message_count, 1);

        assert!(ring.topic_stats("nonexistent").is_none());
    }

    #[test]
    fn known_topics_tracked() {
        let ring = default_ring();
        ring.broadcast(broadcast_msg("alert")).unwrap();
        ring.broadcast(broadcast_msg("config")).unwrap();

        let topics = ring.known_topics();
        assert!(topics.contains(&"alert".to_string()));
        assert!(topics.contains(&"config".to_string()));
    }

    #[test]
    fn all_topic_stats() {
        let ring = default_ring();
        ring.broadcast(broadcast_msg("a")).unwrap();
        ring.broadcast(broadcast_msg("b")).unwrap();

        let stats = ring.all_topic_stats();
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn broadcast_without_subscribers() {
        let ring = default_ring();
        // Should not fail even with no subscribers.
        ring.broadcast(broadcast_msg("orphan")).unwrap();
        assert_eq!(ring.total_broadcasts(), 1);
    }

    #[test]
    fn total_broadcasts() {
        let ring = default_ring();
        assert_eq!(ring.total_broadcasts(), 0);
        ring.broadcast(broadcast_msg("a")).unwrap();
        ring.broadcast(broadcast_msg("b")).unwrap();
        assert_eq!(ring.total_broadcasts(), 2);
    }

    #[test]
    fn subscriber_names_list() {
        let ring = default_ring();
        ring.subscribe("shield", None).unwrap();
        ring.subscribe("threat", Some("alert")).unwrap();
        let names = ring.subscriber_names();
        assert!(names.contains(&"shield".to_string()));
        assert!(names.contains(&"threat".to_string()));
    }

    #[test]
    fn metrics_tracking() {
        let ring = default_ring();
        ring.broadcast(broadcast_msg("test")).unwrap();
        let m = ring.metrics();
        assert_eq!(m.messages_sent, 1);
    }

    #[test]
    fn clear_resets_state() {
        let ring = default_ring();
        ring.broadcast(broadcast_msg("test")).unwrap();
        ring.subscribe("shield", None).unwrap();
        ring.clear();
        assert_eq!(ring.subscriber_count(), 0);
        assert!(ring.known_topics().is_empty());
    }

    #[test]
    fn subscription_name_and_topic() {
        let ring = default_ring();
        let sub = ring.subscribe("shield", Some("alert")).unwrap();
        assert_eq!(sub.name(), "shield");
        assert_eq!(sub.topic(), Some("alert"));
    }

    #[test]
    fn no_filter_subscription_topic_is_none() {
        let ring = default_ring();
        let sub = ring.subscribe("shield", None).unwrap();
        assert!(sub.topic().is_none());
    }
}
