// Webhook Integration — External notification delivery.
//
// Sends incident notifications to external systems (Slack, PagerDuty,
// Jira, or generic webhooks) with HMAC-SHA256 payload signing
// and rate limiting per endpoint.

use std::collections::HashMap;
use std::time::Instant;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::IncidentSeverity;
use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

// ── Webhook Event Types ──

/// Type of webhook event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    IncidentDetected,
    IncidentUpdated,
    IncidentResolved,
    PlaybookStarted,
    PlaybookCompleted,
    EvidenceCollected,
}

// ── Webhook Endpoint ──

/// Configuration for a webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Human-readable name for this endpoint.
    pub name: String,
    /// The URL to send requests to.
    pub url: String,
    /// Custom headers to include.
    pub headers: HashMap<String, String>,
    /// Which event types this endpoint subscribes to.
    pub event_types: Vec<WebhookEventType>,
    /// Whether this endpoint is enabled.
    pub enabled: bool,
    /// Rate limit: maximum requests per minute.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_min: u32,
    /// HMAC signing secret.
    pub signing_secret: Option<String>,
}

fn default_rate_limit() -> u32 {
    60
}

impl WebhookEndpoint {
    /// Create a new webhook endpoint.
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            headers: HashMap::new(),
            event_types: Vec::new(),
            enabled: true,
            rate_limit_per_min: default_rate_limit(),
            signing_secret: None,
        }
    }

    /// Builder: set event types.
    pub fn with_events(mut self, events: Vec<WebhookEventType>) -> Self {
        self.event_types = events;
        self
    }

    /// Builder: set headers.
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Builder: set signing secret.
    pub fn with_signing_secret(mut self, secret: &str) -> Self {
        self.signing_secret = Some(secret.to_string());
        self
    }

    /// Check if this endpoint handles a given event type.
    pub fn handles_event(&self, event_type: &WebhookEventType) -> bool {
        self.enabled && (self.event_types.is_empty() || self.event_types.contains(event_type))
    }
}

// ── Webhook Event ──

/// A webhook event to be sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Type of the event.
    pub event_type: WebhookEventType,
    /// The incident this event relates to.
    pub incident_id: String,
    /// Severity of the incident.
    pub severity: IncidentSeverity,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Additional payload data.
    pub payload: serde_json::Value,
}

// ── Payload Builders ──

/// Trait for building platform-specific webhook payloads.
pub trait WebhookPayload {
    /// Build the JSON payload for this platform.
    fn build(&self, event: &WebhookEvent) -> serde_json::Value;
}

/// Slack block-kit payload builder.
#[derive(Debug, Default)]
pub struct SlackPayload {
    pub channel: Option<String>,
}

impl SlackPayload {
    pub fn new(channel: Option<&str>) -> Self {
        Self {
            channel: channel.map(|s| s.to_string()),
        }
    }
}

impl WebhookPayload for SlackPayload {
    fn build(&self, event: &WebhookEvent) -> serde_json::Value {
        let color = match event.severity {
            IncidentSeverity::Critical => "#c62828",
            IncidentSeverity::High => "#e65100",
            IncidentSeverity::Medium => "#f9a825",
            IncidentSeverity::Low => "#2e7d32",
        };

        let mut blocks = vec![
            serde_json::json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!(":rotating_light: Security Incident: {}", 
                        format!("{:?}", event.event_type).replace("_", " "))
                }
            }),
            serde_json::json!({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": format!("*Severity:* {}", event.severity)},
                    {"type": "mrkdwn", "text": format!("*Incident ID:* {}", event.incident_id)},
                    {"type": "mrkdwn", "text": format!("*Time:* {}", event.timestamp.format("%H:%M:%S UTC"))},
                ]
            }),
            serde_json::json!({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": format!("{}✨ Powered by CHAKRAVYUH", color)}]
            }),
        ];

        // Add payload detail if present
        if !event.payload.is_null() {
            blocks.push(serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("```{}```", serde_json::to_string(&event.payload).unwrap_or_default())
                }
            }));
        }

        let mut payload = serde_json::json!({"blocks": blocks});
        if let Some(ref ch) = self.channel {
            payload["channel"] = serde_json::json!(ch);
        }
        payload
    }
}

/// PagerDuty payload builder.
#[derive(Debug, Default)]
pub struct PagerDutyPayload {
    pub routing_key: Option<String>,
    pub dedup_key: Option<String>,
}

impl PagerDutyPayload {
    pub fn new(routing_key: Option<&str>, dedup_key: Option<&str>) -> Self {
        Self {
            routing_key: routing_key.map(|s| s.to_string()),
            dedup_key: dedup_key.map(|s| s.to_string()),
        }
    }
}

impl WebhookPayload for PagerDutyPayload {
    fn build(&self, event: &WebhookEvent) -> serde_json::Value {
        let severity = match event.severity {
            IncidentSeverity::Critical | IncidentSeverity::High => "critical",
            IncidentSeverity::Medium => "warning",
            IncidentSeverity::Low => "info",
        };

        let mut payload = serde_json::json!({
            "event_action": "trigger",
            "payload": {
                "summary": format!("Incident {}: {}", event.incident_id, format!("{:?}", event.event_type)),
                "severity": severity,
                "source": "chakravyuh",
                "timestamp": event.timestamp.to_rfc3339(),
                "custom_details": event.payload,
            }
        });

        if let Some(ref key) = self.routing_key {
            payload["routing_key"] = serde_json::json!(key);
        }
        if let Some(ref key) = self.dedup_key {
            payload["dedup_key"] = serde_json::json!(key);
        }

        payload
    }
}

/// Jira issue payload builder.
#[derive(Debug, Default)]
pub struct JiraPayload {
    pub project_key: Option<String>,
    pub issue_type: Option<String>,
}

impl JiraPayload {
    pub fn new(project_key: Option<&str>, issue_type: Option<&str>) -> Self {
        Self {
            project_key: project_key.map(|s| s.to_string()),
            issue_type: issue_type.map(|s| s.to_string()),
        }
    }
}

impl WebhookPayload for JiraPayload {
    fn build(&self, event: &WebhookEvent) -> serde_json::Value {
        let labels: Vec<String> = vec![
            format!("severity:{}", event.severity),
            format!("chakravyuh"),
        ];

        let priority = match event.severity {
            IncidentSeverity::Critical => "Highest",
            IncidentSeverity::High => "High",
            IncidentSeverity::Medium => "Medium",
            IncidentSeverity::Low => "Low",
        };

        let mut fields = serde_json::json!({
            "summary": format!("[Security] Incident {} - {}", 
                event.incident_id,
                format!("{:?}", event.event_type).replace("_", " ")
            ),
            "description": format!(
                "h2. Incident Details\\n\\n* Severity: {}\\n* Event: {:?}\\n* Time: {}\\n\\nh2. Payload\\n\\n{{code:json}}{}{{code}}",
                event.severity, event.event_type, event.timestamp,
                serde_json::to_string(&event.payload).unwrap_or_default()
            ),
            "labels": labels,
            "priority": {"name": priority},
        });

        if let Some(ref key) = self.project_key {
            fields["project"] = serde_json::json!({"key": key});
        }
        if let Some(ref itype) = self.issue_type {
            fields["issuetype"] = serde_json::json!({"name": itype});
        }

        serde_json::json!({"fields": fields})
    }
}

/// Generic webhook payload builder.
#[derive(Debug, Default)]
pub struct GenericPayload;

impl WebhookPayload for GenericPayload {
    fn build(&self, event: &WebhookEvent) -> serde_json::Value {
        serde_json::json!({
            "event_type": format!("{:?}", event.event_type),
            "incident_id": event.incident_id,
            "severity": format!("{}", event.severity),
            "timestamp": event.timestamp.to_rfc3339(),
            "payload": event.payload,
        })
    }
}

// ── Webhook Sender ──

/// Sends webhook notifications with rate limiting and signing.
pub struct WebhookSender {
    /// Per-endpoint rate limit tracking: (count, window_start).
    rate_limits: HashMap<String, (u32, Instant)>,
}

impl WebhookSender {
    /// Create a new webhook sender.
    pub fn new() -> Self {
        Self {
            rate_limits: HashMap::new(),
        }
    }

    /// Build a payload for a specific endpoint.
    pub fn build_payload(
        &self,
        endpoint: &WebhookEndpoint,
        event: &WebhookEvent,
    ) -> serde_json::Value {
        // Determine payload format from endpoint name/URL
        let url_lower = endpoint.url.to_lowercase();
        if url_lower.contains("slack") || url_lower.contains("hooks.slack") {
            SlackPayload::default().build(event)
        } else if url_lower.contains("pagerduty") || url_lower.contains("events.pagerduty") {
            PagerDutyPayload::default().build(event)
        } else if url_lower.contains("jira") || url_lower.contains("atlassian") {
            JiraPayload::default().build(event)
        } else {
            GenericPayload.build(event)
        }
    }

    /// Sign a payload using HMAC-SHA256.
    ///
    /// Returns the hex-encoded signature.
    pub fn sign_payload(&self, payload: &str, secret: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key length is valid");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Check whether a request to an endpoint is allowed under its rate limit.
    pub fn rate_limit_check(&mut self, endpoint: &WebhookEndpoint) -> bool {
        let now = Instant::now();
        let limit = endpoint.rate_limit_per_min;
        let entry = self.rate_limits.entry(endpoint.name.clone()).or_insert((0, now));

        // Reset window if more than 60 seconds have passed
        if now.duration_since(entry.1).as_secs() >= 60 {
            entry.0 = 0;
            entry.1 = now;
        }

        if entry.0 < limit {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    /// Send a webhook event to an endpoint.
    ///
    /// In production this would perform an HTTP POST. Here we
    /// simulate the send and return the payload that would be sent.
    pub fn send(
        &mut self,
        endpoint: &WebhookEndpoint,
        event: &WebhookEvent,
    ) -> Result<WebhookSendResult> {
        if !endpoint.handles_event(&event.event_type) {
            return Err(Error::Evaluation(format!(
                "Endpoint {} does not handle event type {:?}",
                endpoint.name, event.event_type
            )));
        }

        if !self.rate_limit_check(endpoint) {
            return Err(Error::Evaluation(format!(
                "Rate limit exceeded for endpoint {} ({} per min)",
                endpoint.name, endpoint.rate_limit_per_min
            )));
        }

        let payload = self.build_payload(endpoint, event);
        let payload_str = serde_json::to_string(&payload)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        let mut headers = endpoint.headers.clone();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        // Add HMAC signature if secret is configured
        if let Some(ref secret) = endpoint.signing_secret {
            let signature = self.sign_payload(&payload_str, secret);
            headers.insert("X-CHAKRAVYUH-Signature".to_string(), signature.clone());
            headers.insert(
                "X-CHAKRAVYUH-Signature-256".to_string(),
                format!("sha256={signature}"),
            );
        }

        Ok(WebhookSendResult {
            endpoint_name: endpoint.name.clone(),
            payload: payload_str,
            headers,
            simulated: true,
        })
    }
}

impl Default for WebhookSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a webhook send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSendResult {
    pub endpoint_name: String,
    pub payload: String,
    pub headers: HashMap<String, String>,
    pub simulated: bool,
}

// ── Webhook Registry ──

/// Registry for managing webhook endpoints.
#[derive(Debug, Default)]
pub struct WebhookRegistry {
    endpoints: HashMap<String, WebhookEndpoint>,
}

impl WebhookRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a webhook endpoint.
    pub fn register(&mut self, endpoint: WebhookEndpoint) {
        self.endpoints.insert(endpoint.name.clone(), endpoint);
    }

    /// Remove a webhook endpoint by name.
    pub fn remove(&mut self, name: &str) -> Option<WebhookEndpoint> {
        self.endpoints.remove(name)
    }

    /// Get a webhook endpoint by name.
    pub fn get(&self, name: &str) -> Option<&WebhookEndpoint> {
        self.endpoints.get(name)
    }

    /// List all registered endpoint names.
    pub fn list(&self) -> Vec<&str> {
        self.endpoints.keys().map(|s| s.as_str()).collect()
    }

    /// Get all endpoints that handle a given event type.
    pub fn get_for_event(&self, event_type: &WebhookEventType) -> Vec<&WebhookEndpoint> {
        self.endpoints
            .values()
            .filter(|ep| ep.handles_event(event_type))
            .collect()
    }

    /// Return the number of registered endpoints.
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: WebhookEventType) -> WebhookEvent {
        WebhookEvent {
            event_type,
            incident_id: "inc-test-123".to_string(),
            severity: IncidentSeverity::High,
            timestamp: Utc::now(),
            payload: serde_json::json!({"description": "Test incident"}),
        }
    }

    #[test]
    fn test_webhook_event_type_serialization() {
        let et = WebhookEventType::IncidentDetected;
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"incident_detected\"");
        let back: WebhookEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }

    #[test]
    fn test_endpoint_builder() {
        let ep = WebhookEndpoint::new("slack-sec", "https://hooks.slack.com/services/xxx")
            .with_events(vec![WebhookEventType::IncidentDetected])
            .with_header("Authorization", "Bearer token123");

        assert_eq!(ep.name, "slack-sec");
        assert!(ep.enabled);
        assert_eq!(ep.event_types.len(), 1);
        assert_eq!(ep.headers["Authorization"], "Bearer token123");
    }

    #[test]
    fn test_endpoint_handles_event() {
        let ep = WebhookEndpoint::new("test", "https://example.com")
            .with_events(vec![WebhookEventType::IncidentDetected, WebhookEventType::IncidentResolved]);

        assert!(ep.handles_event(&WebhookEventType::IncidentDetected));
        assert!(ep.handles_event(&WebhookEventType::IncidentResolved));
        assert!(!ep.handles_event(&WebhookEventType::PlaybookStarted));
    }

    #[test]
    fn test_endpoint_handles_all_when_empty() {
        let ep = WebhookEndpoint::new("catchall", "https://example.com");
        assert!(ep.handles_event(&WebhookEventType::IncidentDetected));
        assert!(ep.handles_event(&WebhookEventType::EvidenceCollected));
    }

    #[test]
    fn test_endpoint_disabled_rejects() {
        let mut ep = WebhookEndpoint::new("off", "https://example.com");
        ep.enabled = false;
        assert!(!ep.handles_event(&WebhookEventType::IncidentDetected));
    }

    // ── Payload building tests ──

    #[test]
    fn test_slack_payload() {
        let builder = SlackPayload::new(Some("#security"));
        let event = make_event(WebhookEventType::IncidentDetected);
        let payload = builder.build(&event);

        assert!(payload["blocks"].is_array());
        assert_eq!(payload["channel"], "#security");
    }

    #[test]
    fn test_pagerduty_payload() {
        let builder = PagerDutyPayload::new(Some("routing-key-123"), Some("dedup-key"));
        let event = make_event(WebhookEventType::IncidentDetected);
        let payload = builder.build(&event);

        assert_eq!(payload["routing_key"], "routing-key-123");
        assert_eq!(payload["dedup_key"], "dedup-key");
        assert_eq!(payload["payload"]["severity"], "critical"); // High severity -> critical
    }

    #[test]
    fn test_pagerduty_severity_mapping() {
        let builder = PagerDutyPayload::default();

        let mut event = make_event(WebhookEventType::IncidentDetected);
        event.severity = IncidentSeverity::Low;
        let payload = builder.build(&event);
        assert_eq!(payload["payload"]["severity"], "info");

        event.severity = IncidentSeverity::Medium;
        let payload = builder.build(&event);
        assert_eq!(payload["payload"]["severity"], "warning");
    }

    #[test]
    fn test_jira_payload() {
        let builder = JiraPayload::new(Some("SEC"), Some("Bug"));
        let event = make_event(WebhookEventType::IncidentDetected);
        let payload = builder.build(&event);

        assert!(payload["fields"]["summary"].as_str().unwrap().contains("Security"));
        assert_eq!(payload["fields"]["project"]["key"], "SEC");
        assert_eq!(payload["fields"]["issuetype"]["name"], "Bug");
    }

    #[test]
    fn test_generic_payload() {
        let builder = GenericPayload;
        let event = make_event(WebhookEventType::IncidentResolved);
        let payload = builder.build(&event);

        assert_eq!(payload["incident_id"], "inc-test-123");
        assert_eq!(payload["severity"], "high");
    }

    // ── HMAC signing tests ──

    #[test]
    fn test_sign_payload_deterministic() {
        let sender = WebhookSender::new();
        let sig1 = sender.sign_payload("hello world", "secret-key");
        let sig2 = sender.sign_payload("hello world", "secret-key");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_sign_payload_different_inputs() {
        let sender = WebhookSender::new();
        let sig1 = sender.sign_payload("data1", "secret");
        let sig2 = sender.sign_payload("data2", "secret");
        let sig3 = sender.sign_payload("data1", "other");
        assert_ne!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    // ── Rate limiting tests ──

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let mut sender = WebhookSender::new();
        let mut ep = WebhookEndpoint::new("test", "https://example.com");
        ep.rate_limit_per_min = 3;

        assert!(sender.rate_limit_check(&ep));
        assert!(sender.rate_limit_check(&ep));
        assert!(sender.rate_limit_check(&ep));
        assert!(!sender.rate_limit_check(&ep)); // 4th should be rejected
    }

    #[test]
    fn test_send_webhook_success() {
        let mut sender = WebhookSender::new();
        let ep = {
            let mut e = WebhookEndpoint::new("slack", "https://hooks.slack.com/services/xxx")
                .with_signing_secret("my-secret");
            e.event_types = vec![WebhookEventType::IncidentDetected];
            e
        };

        let event = make_event(WebhookEventType::IncidentDetected);
        let result = sender.send(&ep, &event).unwrap();

        assert_eq!(result.endpoint_name, "slack");
        assert!(result.simulated);
        assert!(result.headers.contains_key("X-CHAKRAVYUH-Signature"));
        assert!(result.headers["X-CHAKRAVYUH-Signature-256"].starts_with("sha256="));
    }

    #[test]
    fn test_send_rejects_wrong_event() {
        let mut sender = WebhookSender::new();
        let mut ep = WebhookEndpoint::new("test", "https://example.com");
        ep.event_types = vec![WebhookEventType::IncidentDetected];

        let event = make_event(WebhookEventType::PlaybookCompleted);
        let result = sender.send(&ep, &event);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_rejects_rate_limited() {
        let mut sender = WebhookSender::new();
        let mut ep = WebhookEndpoint::new("limited", "https://example.com");
        ep.rate_limit_per_min = 1;
        ep.event_types = vec![WebhookEventType::IncidentDetected];

        let event = make_event(WebhookEventType::IncidentDetected);
        assert!(sender.send(&ep, &event).is_ok());
        assert!(sender.send(&ep, &event).is_err()); // Rate limited
    }

    // ── WebhookRegistry tests ──

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = WebhookRegistry::new();
        let ep = WebhookEndpoint::new("slack", "https://hooks.slack.com/xxx");
        reg.register(ep);

        assert!(reg.get("slack").is_some());
        assert!(reg.get("nonexistent").is_none());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = WebhookRegistry::new();
        reg.register(WebhookEndpoint::new("a", "https://a.com"));
        reg.register(WebhookEndpoint::new("b", "https://b.com"));

        let removed = reg.remove("a");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "a");
        assert_eq!(reg.len(), 1);
        assert!(reg.remove("nonexistent").is_none());
    }

    #[test]
    fn test_registry_list() {
        let mut reg = WebhookRegistry::new();
        reg.register(WebhookEndpoint::new("a", "https://a.com"));
        reg.register(WebhookEndpoint::new("b", "https://b.com"));

        let names = reg.list();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_registry_get_for_event() {
        let mut reg = WebhookRegistry::new();
        let mut ep1 = WebhookEndpoint::new("ep1", "https://example.com");
        ep1.event_types = vec![WebhookEventType::IncidentDetected];
        reg.register(ep1);

        let mut ep2 = WebhookEndpoint::new("ep2", "https://example.com");
        ep2.event_types = vec![WebhookEventType::IncidentResolved];
        reg.register(ep2);

        let catchall = WebhookEndpoint::new("catchall", "https://example.com");
        reg.register(catchall);

        let for_detected = reg.get_for_event(&WebhookEventType::IncidentDetected);
        assert_eq!(for_detected.len(), 2); // ep1 + catchall
    }

    #[test]
    fn test_auto_detect_slack_payload() {
        let sender = WebhookSender::new();
        let ep = WebhookEndpoint::new("slack", "https://hooks.slack.com/services/abc/def");
        let event = make_event(WebhookEventType::IncidentDetected);
        let payload = sender.build_payload(&ep, &event);

        // Should be a Slack block-kit payload
        assert!(payload["blocks"].is_array());
    }
}
