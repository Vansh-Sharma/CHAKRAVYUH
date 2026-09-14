// Phase 14.0 — Webhook Events
//
// Implements webhook delivery for security events:
//   - security.denied          (request was blocked)
//   - security.high_risk       (risk_score > 0.7)
//   - apikey.created            (API key was generated)
//   - organization.created     (org was created)
//
// Each delivery is signed with HMAC-SHA256 using the org's webhook secret.
// Delivery is best-effort (fire-and-forget) — failures are logged but
// don't block the caller.
//
// Endpoints:
//   POST   /v1/orgs/{org_id}/webhooks           # Register a webhook URL
//   GET    /v1/orgs/{org_id}/webhooks           # List registered webhooks
//   DELETE /v1/orgs/{org_id}/webhooks/{wh_id}    # Remove a webhook

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

use crate::identity::{hash_api_key, PlatformStore};

use super::auth_handlers::require_user_id;
use super::dto::ErrorBody;
use super::PlatformState;

// ── Webhook types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub url: String,
    pub events: Vec<String>, // e.g. ["security.denied", "security.high_risk"]
    pub secret: String,      // HMAC signing key
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event_type: String,
    pub organization_id: Uuid,
    pub timestamp: String,
    pub data: Value,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

impl CreateWebhookRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.url.trim().is_empty() || !self.url.starts_with("http") {
            return Err("url must be a valid HTTP(S) URL".into());
        }
        // Default to all events if not specified.
        Ok(())
    }

    /// Returns the events this webhook should fire on. Defaults to all 4 if empty.
    pub fn events_or_default(&self) -> Vec<String> {
        if self.events.is_empty() {
            ALL_EVENTS.iter().map(|s| s.to_string()).collect()
        } else {
            self.events.clone()
        }
    }
}

pub const ALL_EVENTS: &[&str] = &[
    "security.denied",
    "security.high_risk",
    "apikey.created",
    "organization.created",
];

// ── Webhook registry (in-memory, scoped to PlatformStore) ────────────────

use std::collections::HashMap;
use std::sync::RwLock;

/// Webhook registry — stored separately from PlatformStore to keep
/// PlatformStore focused on identity data. Each org has its own set
/// of webhook endpoints.
#[derive(Clone)]
pub struct WebhookRegistry {
    endpoints: Arc<RwLock<HashMap<Uuid, WebhookEndpoint>>>, // wh_id → endpoint
    by_org: Arc<RwLock<HashMap<Uuid, Vec<Uuid>>>>, // org_id → [wh_id]
}

impl WebhookRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            by_org: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add(&self, endpoint: WebhookEndpoint) {
        let org_id = endpoint.organization_id;
        let id = endpoint.id;
        self.endpoints.write().unwrap().insert(id, endpoint);
        self.by_org
            .write()
            .unwrap()
            .entry(org_id)
            .or_default()
            .push(id);
    }

    pub fn list_for_org(&self, org_id: Uuid) -> Vec<WebhookEndpoint> {
        let endpoints = self.endpoints.read().unwrap();
        let by_org = self.by_org.read().unwrap();
        let ids = by_org.get(&org_id).cloned().unwrap_or_default();
        ids.iter()
            .filter_map(|id| endpoints.get(id).cloned())
            .collect()
    }

    pub fn remove(&self, wh_id: Uuid, org_id: Uuid) -> bool {
        let mut endpoints = self.endpoints.write().unwrap();
        if let Some(ep) = endpoints.get(&wh_id) {
            if ep.organization_id != org_id {
                return false; // tenant isolation
            }
        } else {
            return false;
        }
        endpoints.remove(&wh_id);
        let mut by_org = self.by_org.write().unwrap();
        if let Some(ids) = by_org.get_mut(&org_id) {
            ids.retain(|id| *id != wh_id);
        }
        true
    }

    pub fn matching(&self, org_id: Uuid, event_type: &str) -> Vec<WebhookEndpoint> {
        let endpoints = self.endpoints.read().unwrap();
        let by_org = self.by_org.read().unwrap();
        let ids = by_org.get(&org_id).cloned().unwrap_or_default();
        ids.iter()
            .filter_map(|id| endpoints.get(id).cloned())
            .filter(|ep| ep.enabled && (ep.events.is_empty() || ep.events.iter().any(|e| e == event_type)))
            .collect()
    }
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Webhook delivery ────────────────────────────────────────────────────

/// Compute HMAC-SHA256 signature for a webhook payload.
pub fn sign_payload(payload: &str, secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let bytes = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(bytes))
}

/// Verify a webhook signature (used by the receiver).
pub fn verify_signature(payload: &str, signature: &str, secret: &str) -> bool {
    let expected = sign_payload(payload, secret);
    // Constant-time comparison via subtle.
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

/// Dispatch a webhook event. Best-effort — failures are logged but
/// don't propagate to the caller.
pub async fn dispatch_event(
    registry: &WebhookRegistry,
    org_id: Uuid,
    event_type: &str,
    data: Value,
) {
    let endpoints = registry.matching(org_id, event_type);
    if endpoints.is_empty() {
        return;
    }

    let timestamp = Utc::now().to_rfc3339();
    let event = json!({
        "event_type": event_type,
        "organization_id": org_id,
        "timestamp": timestamp,
        "data": data,
    });
    let payload = event.to_string();

    for ep in endpoints {
        let signature = sign_payload(&payload, &ep.secret);
        // Fire-and-forget. In production, this would go through a retry queue.
        let _ = deliver_to_endpoint(&ep.url, &payload, &signature).await;
    }
}

async fn deliver_to_endpoint(url: &str, payload: &str, signature: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-CHAKRAVYUH-Signature", signature)
        .header("X-CHAKRAVYUH-Event", "security.denied")
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        tracing::warn!(
            url = url,
            status = res.status().as_u16(),
            "webhook delivery failed"
        );
    }
    Ok(())
}

// ── HTTP handlers ────────────────────────────────────────────────────────

/// POST /v1/orgs/{org_id}/webhooks — register a webhook
pub async fn create_webhook(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateWebhookRequest>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }
    if let Err(msg) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_request", &msg, "n/a")),
        )
            .into_response();
    }

    let secret = format!("whsec_{}", &Uuid::new_v4().to_string()[..24]);
    let endpoint = WebhookEndpoint {
        id: Uuid::new_v4(),
        organization_id: org_id,
        url: req.url.clone(),
        events: req.events_or_default(),
        secret: secret.clone(),
        created_at: Utc::now(),
        enabled: true,
    };
    state.webhooks.add(endpoint.clone());

    let resp = json!({
        "id": endpoint.id,
        "url": endpoint.url,
        "events": endpoint.events,
        "secret": endpoint.secret, // shown ONCE
        "created_at": endpoint.created_at.to_rfc3339()
    });
    (StatusCode::CREATED, Json(resp)).into_response()
}

/// GET /v1/orgs/{org_id}/webhooks — list registered webhooks (no secrets)
pub async fn list_webhooks(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }
    let endpoints = state.webhooks.list_for_org(org_id);
    let resp: Vec<Value> = endpoints
        .iter()
        .map(|ep| {
            json!({
                "id": ep.id,
                "url": ep.url,
                "events": ep.events,
                "enabled": ep.enabled,
                "created_at": ep.created_at.to_rfc3339()
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "webhooks": resp }))).into_response()
}

/// DELETE /v1/orgs/{org_id}/webhooks/{wh_id}
pub async fn revoke_webhook(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path((org_id, wh_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }
    if state.webhooks.remove(wh_id, org_id) {
        (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new("webhook_not_found", "Webhook not found", "n/a")),
        )
            .into_response()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_payload() {
        let payload = r#"{"event":"security.denied"}"#;
        let secret = "whsec_test123";
        let sig = sign_payload(payload, secret);
        assert!(sig.starts_with("sha256="));
        assert!(verify_signature(payload, &sig, secret));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let payload = r#"{"event":"test"}"#;
        let sig = sign_payload(payload, "correct_secret");
        assert!(!verify_signature(payload, &sig, "wrong_secret"));
    }

    #[test]
    fn registry_adds_and_lists_endpoints() {
        let reg = WebhookRegistry::new();
        let org_id = Uuid::new_v4();
        let ep = WebhookEndpoint {
            id: Uuid::new_v4(),
            organization_id: org_id,
            url: "https://example.com/hook".to_string(),
            events: vec!["security.denied".to_string()],
            secret: "whsec_abc".to_string(),
            created_at: Utc::now(),
            enabled: true,
        };
        reg.add(ep);
        let list = reg.list_for_org(org_id);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn registry_filters_by_event_type() {
        let reg = WebhookRegistry::new();
        let org_id = Uuid::new_v4();
        let ep1 = WebhookEndpoint {
            id: Uuid::new_v4(),
            organization_id: org_id,
            url: "https://a.com/h".to_string(),
            events: vec!["security.denied".to_string()],
            secret: "s1".to_string(),
            created_at: Utc::now(),
            enabled: true,
        };
        let ep2 = WebhookEndpoint {
            id: Uuid::new_v4(),
            organization_id: org_id,
            url: "https://b.com/h".to_string(),
            events: vec!["apikey.created".to_string()],
            secret: "s2".to_string(),
            created_at: Utc::now(),
            enabled: true,
        };
        reg.add(ep1);
        reg.add(ep2);

        let denied = reg.matching(org_id, "security.denied");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].url, "https://a.com/h");
    }

    #[test]
    fn registry_remove_respects_tenant_isolation() {
        let reg = WebhookRegistry::new();
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let ep = WebhookEndpoint {
            id: Uuid::new_v4(),
            organization_id: org_a,
            url: "https://a.com/h".to_string(),
            events: vec![],
            secret: "s".to_string(),
            created_at: Utc::now(),
            enabled: true,
        };
        let ep_id = ep.id;
        reg.add(ep);

        // Org B cannot remove org A's webhook.
        assert!(!reg.remove(ep_id, org_b));
        // Org A can.
        assert!(reg.remove(ep_id, org_a));
    }

    #[test]
    fn create_webhook_request_defaults_to_all_events() {
        let req = CreateWebhookRequest {
            url: "https://example.com/h".to_string(),
            events: vec![],
        };
        let events = req.events_or_default();
        assert!(events.contains(&"security.denied".to_string()));
        assert!(events.contains(&"apikey.created".to_string()));
        assert!(events.contains(&"organization.created".to_string()));
        assert!(events.contains(&"security.high_risk".to_string()));
    }

    #[test]
    fn create_webhook_request_validates_url() {
        let req = CreateWebhookRequest {
            url: "not-a-url".to_string(),
            events: vec![],
        };
        assert!(req.validate().is_err());

        let req2 = CreateWebhookRequest {
            url: "https://valid.url/h".to_string(),
            events: vec![],
        };
        assert!(req2.validate().is_ok());
    }
}
