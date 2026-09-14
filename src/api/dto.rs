// Phase 12.0 — Public API Data Transfer Objects (DTOs)
//
// Wire-format types for the public REST surface. These are intentionally
// decoupled from the internal engine types (Decision, RiskScore,
// DecisionRecord) so the engine can evolve without breaking the API
// contract documented in specs/openapi.yaml.
//
// Mapping rules:
//   - Incoming ProtectRequest → internal ShieldRequest + PipelineContext
//   - Internal PipelineResult → outgoing ProtectResponse
//   - No engine types leak into the DTO layer.

use serde::{Deserialize, Serialize};

// ── POST /v1/protect ────────────────────────────────────────────────────

/// The `input` field of a ProtectRequest.
///
/// Accepts two wire forms for backward compatibility:
///   - **Simple string** (Phase 12.0 form): `"input": "What is 2+2?"`
///   - **Structured object** (SDK form): `"input": {"type":"prompt","content":"..."}`
///
/// Both forms extract to the same content string for the engine.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProtectInput {
    /// Flat string form — used by curl, Phase 12 integration tests, and
    /// the OpenAPI quickstart.
    Simple(String),
    /// Structured object form — used by the Python, TypeScript, and Rust
    /// SDKs (matches the `ProtectInput` schema in the OpenAPI spec).
    Structured {
        #[serde(default = "default_input_type")]
        r#type: String,
        content: String,
        #[serde(default)]
        content_type: Option<String>,
        #[serde(default)]
        tools: Vec<serde_json::Value>,
    },
}

fn default_input_type() -> String {
    "prompt".to_string()
}

impl ProtectInput {
    /// Extract the prompt text regardless of which form was sent.
    pub fn content(&self) -> &str {
        match self {
            ProtectInput::Simple(s) => s,
            ProtectInput::Structured { content, .. } => content,
        }
    }
}

/// Request body for `POST /v1/protect`.
///
/// The `input` field accepts either a flat string or a structured
/// `{type, content}` object — see [`ProtectInput`].
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectRequest {
    /// The prompt or content to evaluate. May be a string or a
    /// structured object.
    pub input: ProtectInput,
    /// Tenant identifier for multi-tenant isolation and rate limiting.
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
    /// Optional client-supplied request ID. If absent, the server
    /// generates a UUID v4.
    pub request_id: Option<String>,
    /// Optional request context (source IP, session ID, etc.).
    /// Accepted but currently unused by the engine — preserved for
    /// forward compatibility with the SDK contract.
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    /// Optional metadata for policy evaluation.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

fn default_tenant() -> String {
    "default".to_string()
}

impl ProtectRequest {
    /// Validate the request after deserialization. Returns an error
    /// message suitable for a 400 response, or Ok(()) if valid.
    pub fn validate(&self) -> Result<(), String> {
        let content = self.input.content();
        if content.trim().is_empty() {
            return Err("input must not be empty".into());
        }
        if content.len() > 1_000_000 {
            return Err("input exceeds maximum length of 1,000,000 characters".into());
        }
        if self.tenant_id.trim().is_empty() {
            return Err("tenant_id must not be empty".into());
        }
        Ok(())
    }
}

/// Response body for `POST /v1/protect`.
///
/// **Field names match the SDK contract** (TypeScript / Python / Rust).
/// The SDKs use snake_case + lowercase enum values, so this DTO uses
/// the same convention rather than Rust's typical PascalCase + uppercase.
///
/// Serialized as JSON. The HTTP status code is 200 for ALLOW, 403 for
/// DENY, 401 for CHALLENGE, 202 for ESCALATE.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectResponse {
    /// Whether the request is allowed to proceed to the LLM.
    pub allowed: bool,
    /// Machine-readable action: "allow", "block", "challenge", "escalate".
    /// Lowercase to match SDK `Action` enum.
    pub action: String,
    /// Composite risk score in [0.0, 1.0]. Higher = more risky.
    pub risk_score: f64,
    /// Confidence in the decision in [0.0, 1.0].
    pub confidence: f64,
    /// The ring that made the final decision: "shield", "threat",
    /// "identity", "memory", "agent", "execution", "reasoning",
    /// "governance", or "keshav" (composite).
    /// Lowercase to match SDK `Ring` enum. Null when allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_ring: Option<String>,
    /// Policy ID that was applied. SDKs require this field.
    pub policy_id: String,
    /// Cryptographic evidence ID for audit trail lookup.
    pub evidence_id: String,
    /// End-to-end latency in milliseconds.
    pub latency_ms: f64,
    /// Per-ring risk scores. SDKs expect a dict keyed by ring name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_scores: Option<serde_json::Value>,
    /// Deny details (reason, patterns, recommendation).
    /// Present only when action is "block".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ProtectDetails>,
    /// The request ID (client-supplied or server-generated).
    /// Extra field not in SDK — SDKs ignore unknown fields by default.
    pub request_id: String,
}

/// Deny details — reason, matched patterns, recommendation.
/// Matches the SDK `ProtectDetails` struct.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectDetails {
    /// Machine-readable deny reason (e.g., "WAF_PROMPT_INJECTION_IGNORE").
    pub reason: String,
    /// Matched signature/pattern IDs (if any).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// Human-readable recommendation for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

impl ProtectResponse {
    /// Build a response from the pipeline result + request metadata.
    pub fn from_pipeline(
        decision: &crate::decision::Decision,
        risk_score: &crate::decision::RiskScore,
        latency_ms: f64,
        request_id: String,
        evidence_id: String,
        triggered_ring: Option<String>,
    ) -> Self {
        use crate::decision::Decision::*;

        let (allowed, action, details) = match decision {
            Allow => (true, "allow".to_string(), None),
            Deny { code, .. } => (
                false,
                "block".to_string(),
                Some(ProtectDetails {
                    reason: code.clone(),
                    patterns: Vec::new(),
                    recommendation: Some("Review and sanitize input before processing".to_string()),
                }),
            ),
            Challenge { .. } => (false, "challenge".to_string(), None),
            Escalate { .. } => (false, "escalate".to_string(), None),
        };

        // Build ring_scores dict from the per-dimension scores.
        // SDK expects keys: "prompt", "input", "identity", "behavior",
        // "memory", "execution", "context".
        let ring_scores = serde_json::json!({
            "prompt": risk_score.threat,
            "input": risk_score.identity,
            "identity": risk_score.identity,
            "behavior": risk_score.behavior,
            "memory": risk_score.memory,
            "execution": risk_score.execution,
            "context": risk_score.context,
        });

        Self {
            allowed,
            action,
            // Engine risk_score.overall is on a 0.0–10.0 scale (see keshav/risk.rs).
            // The public API contract uses a 0.0–1.0 scale, so we normalize.
            // Clamp guards against any future engine change that exceeds 10.0.
            risk_score: (risk_score.overall / 10.0).clamp(0.0, 1.0),
            confidence: risk_score.confidence.clamp(0.0, 1.0),
            triggered_ring: triggered_ring.map(|r| r.to_lowercase()),
            policy_id: "pol_default_v1".to_string(),
            evidence_id,
            latency_ms,
            ring_scores: Some(ring_scores),
            details,
            request_id,
        }
    }
}

// ── GET /v1/health ──────────────────────────────────────────────────────

/// Response body for `GET /v1/health`.
///
/// Matches the SDK `HealthResponse` pydantic model (Python) and the
/// TypeScript `HealthResponse` interface. The server returns:
///   - `status`: "operational" / "degraded" / "unavailable"
///   - `uptime_seconds`: seconds since server start (note: seconds, not secs)
///   - `active_rings`: count of active security rings (9)
///   - `build`: build metadata
///   - `components`: per-component health
///   - `latency`: optional latency percentiles
///   - `degraded_reasons`: empty list when healthy
///
/// Plus the CHAKRAVYUH-specific extensions:
///   - `ananta_active`: whether the trust plane is running
///   - `trust_score`: ANANTA trust score in [0.0, 1.0]
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_rings: u32,
    pub build: BuildInfo,
    pub components: ComponentsHealth,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyStats>,
    pub degraded_reasons: Vec<serde_json::Value>,
    // CHAKRAVYUH extensions (SDK ignores unknown fields by default)
    pub ananta_active: bool,
    pub trust_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub version: String,
    pub commit: String,
    pub target: String,
    pub profile: String,
    pub rustc: String,
    pub built_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentsHealth {
    pub keshav_orchestrator: String,
    pub ananta_engine: String,
    pub sentinel: String,
    pub phoenix: String,
    pub trust_engine: String,
    pub identity: String,
    pub policy_compiler: String,
    pub audit_engine: String,
    pub ovaph: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

// ── GET /v1/version ─────────────────────────────────────────────────────

/// Response body for `GET /v1/version`.
#[derive(Debug, Clone, Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub engine_version: String,
    pub api_version: String,
    pub rustc_version: String,
    pub build_target: String,
    pub build_profile: String,
}

// ── Error response ──────────────────────────────────────────────────────

/// Standard error envelope returned for 4xx / 5xx responses.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

impl ErrorBody {
    pub fn new(code: &str, message: &str, request_id: &str) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
                request_id: request_id.to_string(),
            },
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Decision, RiskScore};

    #[test]
    fn protect_request_validates_empty_input() {
        let req = ProtectRequest {
            input: ProtectInput::Simple("   ".to_string()),
            tenant_id: "demo".to_string(),
            request_id: None,
            context: None,
            metadata: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn protect_request_validates_empty_tenant() {
        let req = ProtectRequest {
            input: ProtectInput::Simple("hello".to_string()),
            tenant_id: "".to_string(),
            request_id: None,
            context: None,
            metadata: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn protect_request_accepts_valid_input() {
        let req = ProtectRequest {
            input: ProtectInput::Simple("What is 2+2?".to_string()),
            tenant_id: "demo".to_string(),
            request_id: None,
            context: None,
            metadata: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn protect_response_from_allow_decision() {
        let decision = Decision::Allow;
        let risk = RiskScore::default();
        let resp = ProtectResponse::from_pipeline(
            &decision,
            &risk,
            4.2,
            "req_123".to_string(),
            "ev_abc".to_string(),
            None,
        );
        assert!(resp.allowed);
        assert_eq!(resp.action, "allow");
        assert!(resp.details.is_none());
        assert_eq!(resp.request_id, "req_123");
        assert_eq!(resp.policy_id, "pol_default_v1");
    }

    #[test]
    fn protect_response_from_deny_decision() {
        let decision = Decision::Deny {
            code: "WAF_PROMPT_INJECTION_IGNORE".to_string(),
            retry_after: None,
        };
        // Engine risk_score.overall is on a 0–10 scale. A threat score of
        // 9.5 (high confidence attack) normalizes to 0.95 in the public API.
        let risk = RiskScore {
            overall: 9.5,
            confidence: 0.98,
            ..Default::default()
        };
        let resp = ProtectResponse::from_pipeline(
            &decision,
            &risk,
            6.5,
            "req_456".to_string(),
            "ev_def".to_string(),
            Some("Threat".to_string()),
        );
        assert!(!resp.allowed);
        assert_eq!(resp.action, "block");
        assert!(resp.details.is_some());
        let details = resp.details.as_ref().unwrap();
        assert_eq!(details.reason, "WAF_PROMPT_INJECTION_IGNORE");
        assert_eq!(resp.triggered_ring.as_deref(), Some("threat"));
        assert!((resp.risk_score - 0.95).abs() < 1e-9);
    }

    #[test]
    fn protect_request_default_tenant() {
        let json = r#"{"input":"hello"}"#;
        let req: ProtectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tenant_id, "default");
        assert!(req.request_id.is_none());
    }

    #[test]
    fn protect_request_with_request_id() {
        let json = r#"{"input":"hello","tenant_id":"acme","request_id":"req_xyz"}"#;
        let req: ProtectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tenant_id, "acme");
        assert_eq!(req.request_id.as_deref(), Some("req_xyz"));
    }

    #[test]
    fn error_body_serializes_correctly() {
        let body = ErrorBody::new("invalid_request", "input is required", "req_123");
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"code\":\"invalid_request\""));
        assert!(json.contains("\"request_id\":\"req_123\""));
    }
}
