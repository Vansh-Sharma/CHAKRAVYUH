// Gateway Models — request/response types matching the OpenAPI 3.1 contract.
//
// Every type here maps 1:1 to a schema in specs/openapi.yaml.
// snake_case JSON fields throughout, matching the API contract.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ═══════════════════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════════════════

/// Risk severity classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.10 => RiskLevel::None,
            s if s < 0.40 => RiskLevel::Low,
            s if s < 0.70 => RiskLevel::Medium,
            s if s < 0.90 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

/// Action taken by the orchestrator.
///
/// Serializes to UPPER_SNAKE_CASE for the public API (ALLOW, DENY, CONDITIONAL, WARN).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPER_SNAKE_CASE")]
pub enum Action {
    Allow,
    Deny,
    Conditional,
    Warn,
}

// Keep Block as an alias for backward compat (internal use only).
impl Action {
    /// Map from an internal engine decision to the public Action.
    pub fn from_decision(d: &chakravyuh::Decision) -> (Self, bool) {
        match d {
            chakravyuh::Decision::Allow => (Action::Allow, true),
            chakravyuh::Decision::Deny { .. } => (Action::Deny, false),
            chakravyuh::Decision::Challenge { .. } => (Action::Conditional, false),
            chakravyuh::Decision::Escalate { .. } => (Action::Warn, false),
        }
    }
}

/// Defense ring identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Ring {
    Prompt,
    Input,
    Output,
    Context,
    Agent,
    Identity,
    Trust,
    Compliance,
    Rate,
    Geo,
    Anomaly,
    Behavioral,
    Session,
    Semantic,
    Ovaph,
}

impl Ring {
    /// Map from the OpenAPI input type to the primary evaluation ring.
    pub fn from_input_type(input_type: &str) -> Option<Self> {
        match input_type {
            "prompt" => Some(Ring::Prompt),
            "api_request" => Some(Ring::Input),
            "agent_instruction" => Some(Ring::Agent),
            "output" => Some(Ring::Output),
            "conversation" => Some(Ring::Session),
            _ => None,
        }
    }
}

/// Severity classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_risk_level(level: &RiskLevel) -> Self {
        match level {
            RiskLevel::None => Severity::None,
            RiskLevel::Low => Severity::Low,
            RiskLevel::Medium => Severity::Medium,
            RiskLevel::High => Severity::High,
            RiskLevel::Critical => Severity::Critical,
        }
    }
}

/// Integrity verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Intact,
    Corrupted,
    Unknown,
}

/// System health status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemStatus {
    Operational,
    Degraded,
    Unavailable,
}

/// Component health status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComponentHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

// ═══════════════════════════════════════════════════════════════════════════
// Protect Input
// ═══════════════════════════════════════════════════════════════════════════

/// Tool definition for agent instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// The input payload to protect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectInput {
    pub r#type: String,
    pub content: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDef>>,
}

fn default_content_type() -> String {
    "text/plain".to_string()
}

/// Geolocation information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vpn: Option<bool>,
}

/// Request context metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
}

/// POST /v1/protect request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectRequest {
    pub input: ProtectInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ProtectContext>,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Simplified protect request — flat input string for quick evaluations.
///
/// Accepts `"input"` as a plain string (auto-wrapped as a prompt)
/// and optionally `"tenant_id"`. This is the user-friendly API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectRequestSimple {
    /// The prompt text to evaluate.
    pub input: String,
    /// Optional tenant identifier (defaults to "default").
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
}

fn default_tenant() -> String {
    "default".to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Protect Response
// ═══════════════════════════════════════════════════════════════════════════

/// Step-up requirement for conditional decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpRequired {
    pub r#type: String,
    pub challenge: String,
}

/// Additional decision details (present when action is not `allow`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionDetails {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_required: Option<StepUpRequired>,
}

/// POST /v1/protect response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectResponse {
    pub allowed: bool,
    pub action: Action,
    pub risk_score: f64,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_ring: Option<Ring>,
    pub policy_id: String,
    pub evidence_id: String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_scores: Option<std::collections::HashMap<String, f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<DecisionDetails>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Verify
// ═══════════════════════════════════════════════════════════════════════════

/// Hash specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSpec {
    pub algorithm: String,
    pub value: String,
}

/// Signature specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSpec {
    pub algorithm: String,
    pub value: String,
}

/// POST /v1/verify request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub evidence_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureSpec>,
}

/// Verification failure details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFailureDetails {
    pub expected_hash: String,
    pub actual_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergence_at: Option<String>,
}

/// POST /v1/verify response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub integrity: IntegrityStatus,
    pub timestamp: DateTime<Utc>,
    pub chain_position: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<VerifyFailureDetails>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy
// ═══════════════════════════════════════════════════════════════════════════

/// POST /v1/policy/evaluate request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub policy_id: String,
    pub request_payload: ProtectInput,
    #[serde(default)]
    pub dry_run: bool,
}

/// A matched rule from policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub ring: Ring,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    pub confidence: f64,
}

/// POST /v1/policy/evaluate response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub decision: String,
    pub matched_rules: Vec<MatchedRule>,
    pub severity: Severity,
    pub explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit
// ═══════════════════════════════════════════════════════════════════════════

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub evidence_id: String,
    pub timestamp: String,
    pub tenant_id: String,
    pub action: Action,
    pub severity: Severity,
    pub risk_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_ring: Option<Ring>,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub chain_position: u64,
    pub chain_hash: String,
}

/// Pagination metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub total_records: u64,
    pub limit: u32,
    pub offset: u32,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u32>,
}

/// GET /v1/audit response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListResponse {
    pub records: Vec<AuditRecord>,
    pub pagination: Pagination,
}

// ═══════════════════════════════════════════════════════════════════════════
// Health
// ═══════════════════════════════════════════════════════════════════════════

/// Build metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub commit: String,
    pub target: String,
    pub profile: String,
    pub rustc: String,
    pub built_at: DateTime<Utc>,
}

/// Latency percentiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Degraded reason entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedReason {
    pub component: String,
    pub issue: String,
}

/// Ring name for DENY responses ("Threat" for threat-detected content).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPER_SNAKE_CASE")]
pub enum RingSimple {
    Threat,
    Shield,
    Identity,
    Memory,
    Agent,
    Execution,
    Reasoning,
    Governance,
}

/// Simplified protect response — the clean public API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectResponseSimple {
    pub allowed: bool,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring: Option<RingSimple>,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
}

/// GET /v1/version response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub engine_version: String,
    pub api_version: String,
    pub rustc_version: String,
    pub build_target: String,
    pub build_profile: String,
}

/// GET /v1/health response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: SystemStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_rings: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyStats>,
    pub build: BuildInfo,
    pub components: std::collections::HashMap<String, ComponentHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reasons: Option<Vec<DegradedReason>>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error
// ═══════════════════════════════════════════════════════════════════════════

/// Unified error response body matching the OpenAPI contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal: Request Extensions
// ═══════════════════════════════════════════════════════════════════════════

use axum::extract::Request;
use axum::http::HeaderMap;
use std::time::Instant;

/// Typed wrapper for the request-scoped start time.
#[derive(Clone)]
pub struct RequestStartTime(pub Instant);

/// Extract the source IP from headers, falling back to the connecting address.
pub fn extract_source_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_from_score_boundary_checks() {
        assert_eq!(RiskLevel::from_score(0.0), RiskLevel::None);
        assert_eq!(RiskLevel::from_score(0.09), RiskLevel::None);
        assert_eq!(RiskLevel::from_score(0.10), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.39), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.40), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.69), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.70), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(0.89), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(0.90), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(1.0), RiskLevel::Critical);
    }

    #[test]
    fn severity_from_risk_level_roundtrip() {
        for level in &[RiskLevel::None, RiskLevel::Low, RiskLevel::Medium, RiskLevel::High, RiskLevel::Critical] {
            let sev = Severity::from_risk_level(level);
            assert_eq!(format!("{:?}", sev).to_lowercase(), format!("{:?}", level).to_lowercase());
        }
    }

    #[test]
    fn ring_from_input_type() {
        assert_eq!(Ring::from_input_type("prompt"), Some(Ring::Prompt));
        assert_eq!(Ring::from_input_type("api_request"), Some(Ring::Input));
        assert_eq!(Ring::from_input_type("agent_instruction"), Some(Ring::Agent));
        assert_eq!(Ring::from_input_type("output"), Some(Ring::Output));
        assert_eq!(Ring::from_input_type("conversation"), Some(Ring::Session));
        assert_eq!(Ring::from_input_type("unknown_type"), None);
    }

    #[test]
    fn protect_request_deserialization() {
        let json = r#"{
            "input": {
                "type": "prompt",
                "content": "hello world",
                "content_type": "text/plain"
            },
            "tenant_id": "tenant_001",
            "context": {
                "source_ip": "10.0.0.1",
                "session_id": "sess_abc"
            }
        }"#;
        let req: ProtectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.input.content, "hello world");
        assert_eq!(req.tenant_id, "tenant_001");
        assert_eq!(req.context.as_ref().unwrap().source_ip.as_ref().unwrap(), "10.0.0.1");
    }

    #[test]
    fn protect_response_serialization() {
        let resp = ProtectResponse {
            allowed: true,
            action: Action::Allow,
            risk_score: 0.12,
            confidence: 0.97,
            triggered_ring: None,
            policy_id: "pol_default_v1".to_string(),
            evidence_id: "ev_8f14e45f".to_string(),
            latency_ms: 3.42,
            ring_scores: None,
            details: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(json.contains("\"action\":\"ALLOW\""));
        assert!(json.contains("\"risk_score\":0.12"));
    }

    #[test]
    fn action_serializes_upper_snake() {
        assert_eq!(serde_json::to_string(&Action::Allow).unwrap(), "\"ALLOW\"");
        assert_eq!(serde_json::to_string(&Action::Deny).unwrap(), "\"DENY\"");
        assert_eq!(serde_json::to_string(&Action::Conditional).unwrap(), "\"CONDITIONAL\"");
        assert_eq!(serde_json::to_string(&Action::Warn).unwrap(), "\"WARN\"");
    }

    #[test]
    fn protect_request_simple_deserialization() {
        let json = r#"{ "input": "Explain Rust ownership", "tenant_id": "demo" }"#;
        let req: ProtectRequestSimple = serde_json::from_str(json).unwrap();
        assert_eq!(req.input, "Explain Rust ownership");
        assert_eq!(req.tenant_id, "demo");
    }

    #[test]
    fn protect_request_simple_defaults_tenant() {
        let json = r#"{ "input": "hello" }"#;
        let req: ProtectRequestSimple = serde_json::from_str(json).unwrap();
        assert_eq!(req.tenant_id, "default");
    }

    #[test]
    fn protect_response_simple_serialization() {
        let resp = ProtectResponseSimple {
            allowed: true,
            action: Action::Allow,
            risk_score: Some(0.05),
            confidence: Some(0.99),
            ring: None,
            request_id: "req_abc123".to_string(),
            latency_ms: Some(4.2),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(json.contains("\"action\":\"ALLOW\""));
        assert!(json.contains("\"request_id\":\"req_abc123\""));
    }

    #[test]
    fn action_from_decision() {
        let (a, allowed) = Action::from_decision(&chakravyuh::Decision::Allow);
        assert_eq!(a, Action::Allow);
        assert!(allowed);

        let (a, allowed) = Action::from_decision(&chakravyuh::Decision::Deny {
            code: "TEST".into(),
            retry_after: None,
        });
        assert_eq!(a, Action::Deny);
        assert!(!allowed);
    }

    #[test]
    fn error_body_serialization() {
        let err = ErrorBody {
            error: ErrorDetail {
                code: "authentication_required".to_string(),
                message: "A valid Bearer token is required.".to_string(),
                request_id: "req_abc123".to_string(),
                details: None,
            },
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("authentication_required"));
    }
}
