/// Data models matching the CHAKRAVYUH OS OpenAPI 3.1.0 contract.
///
/// Every struct mirrors a schema defined in the official API specification.
/// All models use Serde for JSON serialization with `snake_case` field names.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════════

/// The type of input being protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// User prompt or question to an LLM.
    Prompt,
    /// Structured API request body.
    ApiRequest,
    /// System instruction for an AI agent.
    AgentInstruction,
    /// LLM-generated output for post-analysis.
    Output,
    /// Multi-turn conversation transcript.
    Conversation,
}

impl std::fmt::Display for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prompt => write!(f, "prompt"),
            Self::ApiRequest => write!(f, "api_request"),
            Self::AgentInstruction => write!(f, "agent_instruction"),
            Self::Output => write!(f, "output"),
            Self::Conversation => write!(f, "conversation"),
        }
    }
}

/// Action taken by the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Request passes through.
    Allow,
    /// Request is rejected.
    Block,
    /// Request requires step-up verification.
    Conditional,
    /// Request passes but is flagged for review.
    Warn,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Block => write!(f, "block"),
            Self::Conditional => write!(f, "conditional"),
            Self::Warn => write!(f, "warn"),
        }
    }
}

/// Defense ring that produced a trigger.
///
/// Each ring corresponds to a subsystem in the Ananta Security Engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Display for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prompt => write!(f, "prompt"),
            Self::Input => write!(f, "input"),
            Self::Output => write!(f, "output"),
            Self::Context => write!(f, "context"),
            Self::Agent => write!(f, "agent"),
            Self::Identity => write!(f, "identity"),
            Self::Trust => write!(f, "trust"),
            Self::Compliance => write!(f, "compliance"),
            Self::Rate => write!(f, "rate"),
            Self::Geo => write!(f, "geo"),
            Self::Anomaly => write!(f, "anomaly"),
            Self::Behavioral => write!(f, "behavioral"),
            Self::Session => write!(f, "session"),
            Self::Semantic => write!(f, "semantic"),
            Self::Ovaph => write!(f, "ovaph"),
        }
    }
}

/// Risk severity classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Integrity verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Record matches its cryptographic hash.
    Intact,
    /// Record has been modified since creation.
    Corrupted,
    /// Verification could not be completed.
    Unknown,
}

impl std::fmt::Display for IntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Intact => write!(f, "intact"),
            Self::Corrupted => write!(f, "corrupted"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Policy evaluation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Input complies with the policy.
    Allow,
    /// Input violates the policy.
    Deny,
    /// Input is suspicious but not definitively malicious.
    Warn,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Warn => write!(f, "warn"),
        }
    }
}

/// Hash algorithm used for evidence verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Signature algorithm used for evidence verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    RsaPss,
}

/// Component health status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Overall system health status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemStatus {
    Operational,
    Degraded,
    Unavailable,
}

/// Build profile used for the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    Debug,
    Release,
}

// ═══════════════════════════════════════════════════════════════════
// Shared Types
// ═══════════════════════════════════════════════════════════════════

/// A tool definition available to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    /// Tool name.
    pub name: String,
    /// Tool description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema describing tool parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// Geolocation data for geo-ring evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// State, province, or region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// City name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Latitude coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    /// Longitude coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// Autonomous system number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Whether the IP is associated with a known VPN/proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vpn: Option<bool>,
}

/// Hash specification for evidence verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSpec {
    /// Hash algorithm used.
    pub algorithm: HashAlgorithm,
    /// Hex-encoded hash value.
    pub value: String,
}

/// Signature specification for evidence verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSpec {
    /// Signature algorithm used.
    pub algorithm: SignatureAlgorithm,
    /// Base64-encoded signature value.
    pub value: String,
}

/// Step-up authentication requirement (conditional action).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpRequired {
    /// Type of step-up verification.
    #[serde(rename = "type")]
    pub step_type: String,
    /// Challenge description.
    pub challenge: String,
}

/// Additional decision details (present when action is not `allow`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectDetails {
    /// Human-readable explanation of the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Matched pattern identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// Suggested remediation action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    /// Step-up authentication requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_required: Option<StepUpRequired>,
}

// ═══════════════════════════════════════════════════════════════════
// Protect Types
// ═══════════════════════════════════════════════════════════════════

/// The input to be analyzed by the protect endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectInput {
    /// The type of input being protected.
    #[serde(rename = "type")]
    pub input_type: InputType,
    /// The raw content to analyze.
    pub content: String,
    /// MIME type of the content. Defaults to `text/plain`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Tools available to the agent (only for `agent_instruction`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDef>,
}

/// Contextual metadata about the request environment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectContext {
    /// Client IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Client user agent string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Authenticated user identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// API endpoint being accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// HTTP method of the original request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Agent identifier in multi-agent systems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Depth in an agent chain (0 = direct user request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_depth: Option<u32>,
    /// Geolocation data for geo-ring evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
}

/// Request body for [`POST /v1/protect`](crate::Chakravyuh::protect).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectRequest {
    /// The input to analyze.
    pub input: ProtectInput,
    /// Contextual metadata about the request environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ProtectContext>,
    /// Tenant identifier for multi-tenant isolation.
    pub tenant_id: String,
    /// Additional key-value metadata for custom policy evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl ProtectRequest {
    /// Convenience constructor for a simple prompt protection request.
    ///
    /// # Examples
    ///
    /// ```
    /// use chakravyuh::models::{ProtectRequest, ProtectInput, InputType};
    ///
    /// let req = ProtectRequest::prompt("tenant_001", "Hello, world!");
    /// assert_eq!(req.input.content, "Hello, world!");
    /// ```
    pub fn prompt(tenant_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            input: ProtectInput {
                input_type: InputType::Prompt,
                content: content.into(),
                content_type: None,
                tools: Vec::new(),
            },
            context: None,
            tenant_id: tenant_id.into(),
            metadata: None,
        }
    }

    /// Add context metadata to the request.
    pub fn with_context(mut self, ctx: ProtectContext) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Add arbitrary metadata to the request.
    pub fn with_metadata(mut self, meta: serde_json::Value) -> Self {
        self.metadata = Some(meta);
        self
    }
}

/// Response from [`POST /v1/protect`](crate::Chakravyuh::protect).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectResponse {
    /// Whether the input is allowed to proceed.
    pub allowed: bool,
    /// Action taken by the orchestrator.
    pub action: Action,
    /// Aggregated risk score (0.0 = no risk, 1.0 = maximum risk).
    pub risk_score: f64,
    /// Confidence of the risk assessment.
    pub confidence: f64,
    /// The defense ring that triggered the decision. `None` when allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_ring: Option<Ring>,
    /// ID of the policy that was evaluated.
    pub policy_id: String,
    /// Unique ID of the audit evidence record created for this evaluation.
    pub evidence_id: String,
    /// Total processing time in milliseconds.
    pub latency_ms: f64,
    /// Per-ring risk sub-scores.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ring_scores: HashMap<String, f64>,
    /// Additional decision context (present when action is not `allow`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ProtectDetails>,
}

// ═══════════════════════════════════════════════════════════════════
// Verify Types
// ═══════════════════════════════════════════════════════════════════

/// Verification failure details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyDetails {
    /// The hash value stored when the record was created.
    pub expected_hash: String,
    /// The hash value computed during verification.
    pub actual_hash: String,
    /// Location where the record diverges from expected.
    pub divergence_at: String,
}

/// Request body for [`POST /v1/verify`](crate::Chakravyuh::verify).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// ID of the audit evidence record to verify.
    pub evidence_id: String,
    /// Optional hash to verify against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashSpec>,
    /// Optional signature to verify against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureSpec>,
}

impl VerifyRequest {
    /// Create a minimal verify request by evidence ID.
    pub fn new(evidence_id: impl Into<String>) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            hash: None,
            signature: None,
        }
    }

    /// Add a hash specification to the request.
    pub fn with_hash(mut self, hash: HashSpec) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Add a signature specification to the request.
    pub fn with_signature(mut self, sig: SignatureSpec) -> Self {
        self.signature = Some(sig);
        self
    }
}

/// Response from [`POST /v1/verify`](crate::Chakravyuh::verify).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Whether the evidence passed integrity verification.
    pub verified: bool,
    /// Integrity verification result.
    pub integrity: IntegrityStatus,
    /// ISO 8601 timestamp of when verification was performed.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Position of this record in the immutable audit chain.
    pub chain_position: u64,
    /// Hash specification used for verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashSpec>,
    /// Additional details when verification fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<VerifyDetails>,
}

// ═══════════════════════════════════════════════════════════════════
// Policy Types
// ═══════════════════════════════════════════════════════════════════

/// A rule that matched during policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    /// Unique identifier of the matched rule.
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Defense ring that matched.
    pub ring: Ring,
    /// Severity of the match.
    pub severity: Severity,
    /// The specific pattern or condition that matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Additional context about the match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Confidence score of the rule match (0.0 – 1.0).
    pub confidence: f64,
}

/// Request body for [`POST /v1/policy/evaluate`](crate::Chakravyuh::evaluate_policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// ID of the security policy to evaluate.
    pub policy_id: String,
    /// The request payload to evaluate against the policy.
    pub request_payload: ProtectInput,
    /// When `true`, evaluates without creating audit records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

impl PolicyRequest {
    /// Create a policy evaluation request.
    pub fn new(policy_id: impl Into<String>, payload: ProtectInput) -> Self {
        Self {
            policy_id: policy_id.into(),
            request_payload: payload,
            dry_run: None,
        }
    }

    /// Enable dry-run mode (no audit records created).
    pub fn dry_run(mut self) -> Self {
        self.dry_run = Some(true);
        self
    }
}

/// Response from [`POST /v1/policy/evaluate`](crate::Chakravyuh::evaluate_policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Policy evaluation decision.
    pub decision: PolicyDecision,
    /// List of rules that matched the input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<MatchedRule>,
    /// Overall severity of the evaluation.
    pub severity: Severity,
    /// Human-readable explanation of the decision.
    pub explanation: String,
    /// Suggested action based on the evaluation result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Audit Types
// ═══════════════════════════════════════════════════════════════════

/// Query parameters for listing audit records.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by tenant ID.
    pub tenant: Option<String>,
    /// Number of records to return (1–100, default 20).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
    /// Filter by severity level.
    pub severity: Option<Severity>,
    /// Filter by action taken.
    pub action: Option<Action>,
    /// Start of time range (inclusive, ISO 8601).
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// End of time range (exclusive, ISO 8601).
    pub to: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuditQuery {
    /// Create a new empty audit query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by tenant ID.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Set the page size (1–100).
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit.min(100));
        self
    }

    /// Set the pagination offset.
    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Filter by severity level.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Filter by action type.
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the start of the time range (inclusive).
    pub fn from(mut self, from: chrono::DateTime<chrono::Utc>) -> Self {
        self.from = Some(from);
        self
    }

    /// Set the end of the time range (exclusive).
    pub fn to(mut self, to: chrono::DateTime<chrono::Utc>) -> Self {
        self.to = Some(to);
        self
    }

    /// Build the query string for the URL.
    pub(crate) fn to_query(&self) -> String {
        let mut params = vec![];
        if let Some(ref t) = self.tenant {
            params.push(format!("tenant={t}"));
        }
        if let Some(l) = self.limit {
            params.push(format!("limit={l}"));
        }
        if let Some(o) = self.offset {
            params.push(format!("offset={o}"));
        }
        if let Some(ref s) = self.severity {
            params.push(format!("severity={s}"));
        }
        if let Some(ref a) = self.action {
            params.push(format!("action={a}"));
        }
        if let Some(f) = self.from {
            params.push(format!("from={}", f.to_rfc3339()));
        }
        if let Some(t) = self.to {
            params.push(format!("to={}", t.to_rfc3339()));
        }
        if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        }
    }
}

/// A single immutable audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique evidence identifier.
    pub evidence_id: String,
    /// When the security event occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Tenant that owns this record.
    pub tenant_id: String,
    /// Action that was taken.
    pub action: Action,
    /// Severity of the event.
    pub severity: Severity,
    /// Risk score at the time of the event.
    pub risk_score: f64,
    /// Defense ring that triggered the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_ring: Option<Ring>,
    /// Policy that was active during evaluation.
    pub policy_id: String,
    /// Type of the input that triggered this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    /// Hash of the input content (PII-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    /// Human-readable event summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Additional structured event details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Position in the immutable audit chain.
    pub chain_position: u64,
    /// Cryptographic hash linking this record to the chain.
    pub chain_hash: String,
}

/// Pagination metadata for audit listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    /// Total number of matching records.
    pub total_records: u64,
    /// Page size used for this request.
    pub limit: u32,
    /// Current pagination offset.
    pub offset: u32,
    /// Whether more records exist beyond this page.
    pub has_more: bool,
    /// Offset to use for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u32>,
}

/// Response from [`GET /v1/audit`](crate::Chakravyuh::audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListResponse {
    /// The list of audit records for this page.
    pub records: Vec<AuditRecord>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

// ═══════════════════════════════════════════════════════════════════
// Health Types
// ═══════════════════════════════════════════════════════════════════

/// Request latency percentiles (rolling 5-minute window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    /// 50th percentile latency in milliseconds.
    #[serde(rename = "p50_ms")]
    pub p50_ms: f64,
    /// 95th percentile latency in milliseconds.
    #[serde(rename = "p95_ms")]
    pub p95_ms: f64,
    /// 99th percentile latency in milliseconds.
    #[serde(rename = "p99_ms")]
    pub p99_ms: f64,
}

/// Build metadata compiled into the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Semantic version of the build.
    pub version: String,
    /// Git commit hash (short).
    pub commit: String,
    /// Rust target triple.
    pub target: String,
    /// Build profile.
    pub profile: BuildProfile,
    /// Rust compiler version used.
    pub rustc: String,
    /// Build timestamp.
    pub built_at: chrono::DateTime<chrono::Utc>,
}

/// Reason for degraded system status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedReason {
    /// The component that is degraded.
    pub component: String,
    /// Description of the issue.
    pub issue: String,
}

/// Component health status map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentsHealth {
    #[serde(rename = "keshav_orchestrator")]
    pub keshav_orchestrator: ComponentHealth,
    #[serde(rename = "ananta_engine")]
    pub ananta_engine: ComponentHealth,
    pub sentinel: ComponentHealth,
    pub phoenix: ComponentHealth,
    #[serde(rename = "trust_engine")]
    pub trust_engine: ComponentHealth,
    pub identity: ComponentHealth,
    #[serde(rename = "policy_compiler")]
    pub policy_compiler: ComponentHealth,
    #[serde(rename = "audit_engine")]
    pub audit_engine: ComponentHealth,
    pub ovaph: ComponentHealth,
}

/// Response from [`GET /v1/health`](crate::Chakravyuh::health).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall system health status.
    pub status: SystemStatus,
    /// Semantic version of the running instance.
    pub version: String,
    /// Seconds since the instance started.
    pub uptime_seconds: u64,
    /// Number of defense rings currently active.
    pub active_rings: u32,
    /// Request latency percentiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyStats>,
    /// Build metadata.
    pub build: BuildInfo,
    /// Health status of each subsystem.
    pub components: ComponentsHealth,
    /// Reasons for degraded status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<DegradedReason>,
}

// ═══════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════

/// Structured error body returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable error description.
    pub message: String,
    /// Request identifier for support correlation.
    pub request_id: String,
    /// Additional error context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Top-level error response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error payload.
    pub error: ApiError,
}

// ═══════════════════════════════════════════════════════════════════
// Internal: Response Envelope with Headers
// ═══════════════════════════════════════════════════════════════════

/// Internal wrapper that pairs a deserialized response with extracted headers.
#[derive(Debug)]
pub(crate) struct WithHeaders<T> {
    /// The deserialized response body.
    pub data: T,
    /// The `X-Request-Id` from the response.
    pub request_id: Option<String>,
    /// The `X-Audit-Trace-Id` from the response.
    pub audit_trace_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protect_request_prompt() {
        let req = ProtectRequest::prompt("tenant_001", "Hello world");
        assert_eq!(req.input.input_type, InputType::Prompt);
        assert_eq!(req.input.content, "Hello world");
        assert_eq!(req.tenant_id, "tenant_001");
        assert!(req.context.is_none());
    }

    #[test]
    fn test_protect_request_with_context() {
        let ctx = ProtectContext {
            source_ip: Some("10.0.0.1".into()),
            session_id: Some("sess_abc".into()),
            ..Default::default()
        };
        let req = ProtectRequest::prompt("t1", "test").with_context(ctx);
        assert!(req.context.is_some());
        assert_eq!(req.context.as_ref().unwrap().source_ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_action_display() {
        assert_eq!(Action::Allow.to_string(), "allow");
        assert_eq!(Action::Block.to_string(), "block");
    }

    #[test]
    fn test_ring_all_variants() {
        let rings = [
            Ring::Prompt, Ring::Input, Ring::Output, Ring::Context, Ring::Agent,
            Ring::Identity, Ring::Trust, Ring::Compliance, Ring::Rate, Ring::Geo,
            Ring::Anomaly, Ring::Behavioral, Ring::Session, Ring::Semantic, Ring::Ovaph,
        ];
        assert_eq!(rings.len(), 15);
        for r in &rings {
            let s = r.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_audit_query_builder() {
        let q = AuditQuery::new()
            .tenant("t1")
            .limit(50)
            .offset(100)
            .severity(Severity::High);
        let qs = q.to_query();
        assert!(qs.contains("tenant=t1"));
        assert!(qs.contains("limit=50"));
        assert!(qs.contains("offset=100"));
        assert!(qs.contains("severity=high"));
        assert!(!qs.contains("action="));
    }

    #[test]
    fn test_audit_query_empty() {
        let q = AuditQuery::new();
        assert!(q.to_query().is_empty());
    }

    #[test]
    fn test_verify_request_builder() {
        let req = VerifyRequest::new("ev_abc")
            .with_hash(HashSpec {
                algorithm: HashAlgorithm::Sha256,
                value: "abc123".into(),
            });
        assert!(req.hash.is_some());
    }

    #[test]
    fn test_policy_request_dry_run() {
        let req = PolicyRequest::new(
            "pol_001",
            ProtectInput {
                input_type: InputType::Prompt,
                content: "test".into(),
                content_type: None,
                tools: vec![],
            },
        )
        .dry_run();
        assert_eq!(req.dry_run, Some(true));
    }

    #[test]
    fn test_serialize_deserialize_protect_response() {
        let json = r#{
            "allowed": true,
            "action": "allow",
            "risk_score": 0.12,
            "confidence": 0.97,
            "triggered_ring": null,
            "policy_id": "pol_v1",
            "evidence_id": "ev_123",
            "latency_ms": 3.42,
            "ring_scores": {"prompt": 0.05, "input": 0.08}
        }#;
        let resp: ProtectResponse = serde_json::from_str(json).unwrap();
        assert!(resp.allowed);
        assert_eq!(resp.action, Action::Allow);
        assert!((resp.risk_score - 0.12).abs() < f64::EPSILON);
        assert_eq!(resp.ring_scores.len(), 2);
    }

    #[test]
    fn test_serialize_deserialize_health_response() {
        let json = r#{
            "status": "operational",
            "version": "1.0.0",
            "uptime_seconds": 86400,
            "active_rings": 15,
            "latency": {"p50_ms": 2.1, "p95_ms": 5.3, "p99_ms": 12.7},
            "build": {
                "version": "1.0.0",
                "commit": "a3f2b91c",
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "rustc": "1.82.0",
                "built_at": "2026-08-21T18:00:00Z"
            },
            "components": {
                "keshav_orchestrator": "healthy",
                "ananta_engine": "healthy",
                "sentinel": "healthy",
                "phoenix": "healthy",
                "trust_engine": "healthy",
                "identity": "healthy",
                "policy_compiler": "healthy",
                "audit_engine": "healthy",
                "ovaph": "healthy"
            }
        }#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, SystemStatus::Operational);
        assert_eq!(resp.active_rings, 15);
        assert_eq!(resp.components.keshav_orchestrator, ComponentHealth::Healthy);
    }

    #[test]
    fn test_serialize_deserialize_error_response() {
        let json = r#{
            "error": {
                "code": "invalid_request",
                "message": "missing field",
                "request_id": "req_abc"
            }
        }#;
        let resp: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error.code, "invalid_request");
        assert_eq!(resp.error.request_id, "req_abc");
    }

    #[test]
    fn test_limit_capped_at_100() {
        let q = AuditQuery::new().limit(500);
        assert_eq!(q.limit, Some(100));
    }
}