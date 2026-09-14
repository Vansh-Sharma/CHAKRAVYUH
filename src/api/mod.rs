// HTTP API router for CHAKRAVYUH.
//
// Endpoints:
//   GET  /health              — basic health check (uptime + version)
//   GET  /health/ready        — K8s readiness probe (ring health + error rates)
//   GET  /health/live         — K8s liveness probe (process alive check)
//   GET  /version             — version info
//   POST /v1/evaluate         — evaluate a request (Shield → Threat → Identity → Memory → Keshav)
//   POST /v1/proxy            — evaluate + forward to upstream LLM API
//   POST /v1/execute          — evaluate a tool call (Shield → Threat → Identity → Memory → Agent → Execution → Keshav)
//   GET  /v1/recovery         — ring health, circuit breaker state, recovery status
//   GET  /v1/decisions        — list recent decision records
//   GET  /v1/decisions/export — export decisions as JSON/CSV
//   GET  /v1/learn/status      — learning system status
//   POST /v1/learn/optimize    — trigger threshold optimization
//   POST /v1/learn/feedback   — submit decision feedback (FP/FN/approve/reject)
//   GET  /v1/learn/thresholds  — view learned thresholds
//   POST /v1/learn/thresholds/reset — reset thresholds to defaults
//   GET  /v1/learn/patterns    — pattern store statistics
//   GET  /v1/learn/patterns/export — JSON export
//   POST /v1/learn/patterns/import — JSON import
//   GET  /v1/policy/info       — current policy version, rules (Phase 7)
//   GET  /v1/policy/export    — export policy as YAML (Phase 7)
//   POST /v1/policy/reload    — hot-reload policy from file (Phase 7)
//   GET  /v1/storage/health    — storage backend health (Phase 7)
//   GET  /metrics              — Prometheus metrics (Phase 8)
//
// Pipeline (v0.9.0):
//   1. Shield Ring    — perimeter defense (input, rate, WAF, DoS, geo, bot)
//   2. Threat Ring    — cognitive threat detection (pattern, semantic, jailbreak)
//   3. Identity Ring  — auth, authz, trust scoring, anomaly detection
//   4. Memory Ring    — context integrity, PII, RAG poison, conversation hijacking
//   5. Agent Ring     — agent policy, behavior, scope, capability (tool calls only)
//   6. Execution Ring — tool call firewall (allowlist, params, sandbox, approval, SSRF)
//      (only for /v1/execute tool call requests)
//   7. Keshav-Decide  — policy engine combines ring verdicts → final Decision
//   8. Keshav-Risk    — composite risk scoring (threat + identity + agent + memory + execution + context)
//   9. Recovery Ring  — circuit breaker + degraded mode (cross-ring health monitoring)
//
// All handlers extract source IP and User-Agent from request headers
// so engines can rate-limit / detect on real client identity.

// HTTP API router for CHAKRAVYUH.
//
// Phase 13.0: Identity & Multi-Tenant Platform.
// Adds /v1/auth/* (signup/login/refresh/logout/me), /v1/orgs/* (CRUD),
// /v1/orgs/{id}/workspaces, /v1/orgs/{id}/keys, /v1/orgs/{id}/audit.
// The /v1/protect endpoint now accepts API keys (ck_live_*/ck_test_*)
// and resolves them to organizations for tenant isolation.
//
// Phase 12.0: Public API surface includes /v1/protect — the primary
// customer endpoint. It reuses the existing Keshav PipelineExecutor
// without any new security logic.
//
// Module layout:
//   mod.rs               — existing routes (evaluate, proxy, learn, recovery, etc.)
//   dto.rs               — Phase 12.0 public DTOs (ProtectRequest, ProtectResponse, etc.)
//   handlers.rs          — Phase 12.0 public handlers (protect, health, version)
//   auth_dto.rs          — Phase 13.0 auth DTOs (signup, login, refresh, etc.)
//   auth_handlers.rs     — Phase 13.0 auth handlers
//   org_dto.rs           — Phase 13.0 org/workspace/api-key DTOs
//   org_handlers.rs      — Phase 13.0 org/workspace/api-key/audit handlers
//   tenant_middleware.rs — Phase 13.0 API key → org resolution
//
// Endpoints (Phase 13.0 surface in addition to Phase 12.0):
//   POST /v1/auth/signup   POST /v1/orgs
//   POST /v1/auth/login    GET  /v1/orgs
//   POST /v1/auth/refresh  GET  /v1/orgs/{id}
//   POST /v1/auth/logout  PATCH /v1/orgs/{id}
//   GET  /v1/auth/me       POST /v1/orgs/{id}/workspaces
//                          GET  /v1/orgs/{id}/workspaces
//                          POST /v1/orgs/{id}/keys
//                          GET  /v1/orgs/{id}/keys
//                          DELETE /v1/orgs/{id}/keys/{key_id}
//                          GET  /v1/orgs/{id}/audit
//
// Phase 12.0 public surface:
//   POST /v1/protect   — flat-input protect (now with API key auth)
//   GET  /v1/health    — versioned health with ANANTA trust score
//   GET  /v1/version   — build metadata

pub mod auth_dto;
pub mod auth_handlers;
pub mod dto;
pub mod handlers;
pub mod openapi;
pub mod org_dto;
pub mod org_handlers;
pub mod postman;
pub mod snippets;
pub mod tenant_middleware;
pub mod webhooks;

// Re-export the Phase 12.0 public handlers so callers can use them directly.
pub use dto::{
    ErrorBody, ErrorDetail, HealthResponse as PublicHealthResponse,
    ProtectRequest, ProtectResponse, VersionResponse as PublicVersionResponse,
};
pub use handlers::{health as public_health, protect, version as public_version};

// Re-export Phase 13.0 types.
pub use tenant_middleware::{MaybeTenant, TenantContext};

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{from_fn_with_state},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::agent::AgentRing;
use crate::config::UpstreamConfig;
use crate::cross_ring::CrossRingNetwork;
use crate::execution::ExecutionRing;
use crate::governance::GovernanceRing;
use crate::identity::{AuthService, IdentityRequest, IdentityRing, JwtConfig, PlatformStore};
use crate::infra::{is_alive, is_ready, metrics_text, ShutdownState};
use crate::keshav::{KeshavDecide, KeshavLearn, KeshavOrchestrate, KeshavRisk, PipelineExecutor, PipelineContext, PolicyManager};
use crate::keshav::orchestrate::RequestType;
use crate::memory::MemoryRing;
use crate::reasoning::ReasoningRing;
use crate::recovery_sec::RecoveryRing;
use crate::shield::{ShieldRequest, ShieldRing};
use crate::storage::Store;
use crate::threat::ThreatRing;

/// Phase 13.0 platform state — auth + multi-tenant store.
/// This is separate from ApiState so it can be used by the auth handlers
/// without needing all the ring state.
#[derive(Clone)]
pub struct PlatformState {
    pub auth: Arc<AuthService>,
    pub store: Arc<PlatformStore>,
    /// Phase 14.0 — webhook registry (HMAC-signed event delivery)
    pub webhooks: Arc<webhooks::WebhookRegistry>,
}

impl PlatformState {
    /// Create a new PlatformState with default JwtConfig + fresh in-memory store.
    pub fn new() -> Self {
        let store = Arc::new(PlatformStore::new());
        let auth = Arc::new(AuthService::new(JwtConfig::default(), store.as_ref().clone()));
        let webhooks = Arc::new(webhooks::WebhookRegistry::new());
        Self { auth, store, webhooks }
    }

    /// Create with a custom JWT config (e.g. for production secret).
    pub fn with_jwt_config(config: JwtConfig) -> Self {
        let store = Arc::new(PlatformStore::new());
        let auth = Arc::new(AuthService::new(config, store.as_ref().clone()));
        let webhooks = Arc::new(webhooks::WebhookRegistry::new());
        Self { auth, store, webhooks }
    }
}

impl Default for PlatformState {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state threaded through the router.
#[derive(Clone)]
pub struct ApiState {
    pub shield: ShieldRing,
    pub threat: ThreatRing,
    pub identity: IdentityRing,
    pub memory: MemoryRing,
    pub agent: AgentRing,
    pub execution: ExecutionRing,
    pub reasoning: ReasoningRing,
    pub governance: GovernanceRing,
    pub recovery_sec: RecoveryRing,
    pub decide: KeshavDecide,
    pub risk: KeshavRisk,
    pub learn: KeshavLearn,
    pub orchestrate: KeshavOrchestrate,
    pub cross_ring: CrossRingNetwork,
    pub pipeline: PipelineExecutor,
    pub started_at: Arc<Instant>,
    pub upstream_client: Option<Arc<UpstreamClient>>,
    /// Policy manager with hot-reload support (Phase 7).
    pub policy_manager: Arc<PolicyManager>,
    /// Persistent storage backend (Phase 7).
    pub storage: Arc<Box<dyn Store>>,
    /// Graceful shutdown state (Phase 7).
    pub shutdown: Arc<ShutdownState>,
    /// ANANTA — Autonomous Trust Plane (optional).
    /// When present, trust state and attestation queries are available.
    pub ananta: Option<Arc<crate::AnantaPlane>>,
    /// Phase 13.0 — Platform store for tenant-isolated audit logs.
    /// When present, /v1/protect writes audit logs scoped to the API key's org.
    pub platform_store: Option<Arc<PlatformStore>>,
    /// Phase 14.0 — Webhook registry for security event delivery.
    pub webhooks: Option<Arc<webhooks::WebhookRegistry>>,
}

/// Wraps a configured reqwest client + upstream URL.
/// Cloning is cheap (Arc + reqwest::Client is internally Arc'd).
#[derive(Clone)]
pub struct UpstreamClient {
    client: reqwest::Client,
    config: UpstreamConfig,
}

impl UpstreamClient {
    pub fn new(config: UpstreamConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(concat!("chakravyuh/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client, config }
    }

    /// Resolve the API key to send to the upstream.
    /// Priority: env var > config field.
    fn api_key(&self) -> String {
        std::env::var("CHAKRAVYUH_UPSTREAM_API_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.config.api_key.clone())
    }

    /// Forward a request body to the upstream and return the response.
    pub async fn forward(
        &self,
        body: serde_json::Value,
        client_auth_header: Option<String>,
    ) -> Result<reqwest::Response, String> {
        let url = &self.config.url;
        let mut req = self.client.post(url).json(&body);

        // Set Authorization header.
        if self.config.forward_client_auth {
            if let Some(auth) = client_auth_header {
                req = req.header("authorization", auth);
            } else {
                tracing::warn!(
                    "forward_client_auth is true but client sent no Authorization header"
                );
            }
        } else {
            let key = self.api_key();
            if !key.is_empty() {
                req = req.header("authorization", format!("Bearer {}", key));
            }
        }

        req.send()
            .await
            .map_err(|e| format!("upstream request failed: {}", e))
    }
}

/// Build the axum router with all endpoints.
///
/// `platform_state` is the Phase 13.0 identity/multi-tenant layer.
/// If None, all /v1/auth/* and /v1/orgs/* routes return 503 Service Unavailable.
/// Pass `Some(PlatformState::new())` to enable the full SaaS platform.
pub fn build_router(
    shield: ShieldRing,
    threat: ThreatRing,
    identity: IdentityRing,
    memory: MemoryRing,
    agent: AgentRing,
    execution: ExecutionRing,
    reasoning: ReasoningRing,
    governance: GovernanceRing,
    recovery_sec: RecoveryRing,
    decide: KeshavDecide,
    risk: KeshavRisk,
    learn: KeshavLearn,
    orchestrate: KeshavOrchestrate,
    cross_ring: CrossRingNetwork,
    upstream: Option<UpstreamConfig>,
    policy_manager: Option<Arc<PolicyManager>>,
    storage: Option<Arc<Box<dyn Store>>>,
    shutdown: Option<Arc<ShutdownState>>,
    ananta: Option<Arc<crate::AnantaPlane>>,
    platform_state: Option<PlatformState>,
) -> Router {
    let upstream_client = upstream.map(|c| Arc::new(UpstreamClient::new(c)));
    let pipeline = PipelineExecutor {
        shield: shield.clone(),
        threat: threat.clone(),
        identity: identity.clone(),
        memory: memory.clone(),
        agent: agent.clone(),
        execution: execution.clone(),
        reasoning: reasoning.clone(),
        governance: governance.clone(),
        decide: decide.clone(),
        risk: risk.clone(),
    };
    let state = ApiState {
        shield,
        threat,
        identity,
        memory,
        agent,
        execution,
        reasoning,
        governance,
        recovery_sec,
        decide,
        risk,
        learn,
        orchestrate,
        cross_ring,
        pipeline,
        started_at: Arc::new(Instant::now()),
        upstream_client,
        policy_manager: policy_manager.unwrap_or_else(|| Arc::new(PolicyManager::with_defaults())),
        storage: storage.unwrap_or_else(|| Arc::new(Box::new(crate::storage::MemoryStore::new()))),
        shutdown: shutdown.unwrap_or_else(|| Arc::new(ShutdownState::new(30))),
        ananta,
        platform_store: platform_state.as_ref().map(|p| p.store.clone()),
        webhooks: platform_state.as_ref().map(|p| p.webhooks.clone()),
    };

    // Phase 13.0: Build the auth/org routes. If platform_state is None,
    // we still register the routes but they will return 503 because
    // PlatformState is required by the handlers.
    let platform = platform_state.clone().unwrap_or_else(PlatformState::new);

    // The /v1/protect route needs the tenant middleware applied so it can
    // resolve API keys to organizations. We apply it as a layer on top of
    // the protect route.
    let protect_router = Router::new()
        .route("/v1/protect", post(handlers::protect))
        .with_state(state.clone())
        .layer(from_fn_with_state(
            platform.store.clone(),
            tenant_middleware::tenant_middleware,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        // Phase 12.0: Public API surface — primary customer endpoints.
        .route("/v1/health", get(handlers::health))
        .route("/v1/version", get(handlers::version))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/proxy", post(proxy))
        .route("/v1/execute", post(execute))
        .route("/v1/decisions", get(list_decisions))
        .route("/v1/decisions/export", get(export_decisions))
        .route("/v1/recovery", get(recovery_status))
        .route("/v1/learn/status", get(learn_status))
        .route("/v1/learn/optimize", post(learn_optimize))
        .route("/v1/learn/feedback", post(learn_feedback))
        .route("/v1/learn/thresholds", get(learn_thresholds))
        .route("/v1/learn/thresholds/reset", post(learn_thresholds_reset))
        .route("/v1/learn/patterns", get(learn_patterns))
        .route("/v1/learn/patterns/export", get(learn_patterns_export))
        .route("/v1/learn/patterns/import", post(learn_patterns_import))
        // Phase 7: Health probes (Kubernetes-style)
        .route("/health/ready", get(health_ready))
        .route("/health/live", get(health_live))
        // Phase 7: Policy management
        .route("/v1/policy/info", get(policy_info))
        .route("/v1/policy/export", get(policy_export))
        .route("/v1/policy/reload", post(policy_reload))
        // Phase 7: Storage health
        .route("/v1/storage/health", get(storage_health))
        // Phase 8: Prometheus metrics
        .route("/metrics", get(metrics_endpoint))
        // ANANTA: Trust Plane endpoints (optional)
        .route("/v1/ananta/trust", get(ananta_trust_state))
        .route("/v1/ananta/attestation", get(ananta_attestation))
        .route("/v1/ananta/proof", get(ananta_trust_proof))
        .route("/v1/ananta/health", get(ananta_health))
        .with_state(state.clone())
        // Phase 13.0: Identity & Multi-Tenant Platform
        .nest("/v1/auth", Router::new()
            .route("/signup", post(auth_handlers::signup))
            .route("/login", post(auth_handlers::login))
            .route("/refresh", post(auth_handlers::refresh))
            .route("/logout", post(auth_handlers::logout))
            .route("/me", get(auth_handlers::me))
            .with_state(platform.clone())
        )
        // Phase 13.0: Organizations, Workspaces, API Keys, Audit
        .nest("/v1/orgs", Router::new()
            .route("/", post(org_handlers::create_org))
            .route("/", get(org_handlers::list_orgs))
            .route("/:org_id", get(org_handlers::get_org))
            .route("/:org_id", axum::routing::patch(org_handlers::update_org))
            .route("/:org_id/workspaces", post(org_handlers::create_workspace))
            .route("/:org_id/workspaces", get(org_handlers::list_workspaces))
            .route("/:org_id/keys", post(org_handlers::create_api_key))
            .route("/:org_id/keys", get(org_handlers::list_api_keys))
            .route("/:org_id/keys/:key_id", axum::routing::delete(org_handlers::revoke_api_key))
            .route("/:org_id/audit", get(org_handlers::list_audit_logs))
            // Phase 14.0: Webhooks
            .route("/:org_id/webhooks", post(webhooks::create_webhook))
            .route("/:org_id/webhooks", get(webhooks::list_webhooks))
            .route("/:org_id/webhooks/:wh_id", axum::routing::delete(webhooks::revoke_webhook))
            .with_state(platform.clone())
        )
        // Phase 14.0: Developer platform — OpenAPI, Swagger UI, Postman, Snippets
        .route("/openapi.json", get(openapi::openapi_spec))
        .route("/docs", get(openapi::swagger_ui))
        .route("/docs/oauth2-redirect.html", get(openapi::oauth2_redirect))
        .route("/postman.json", get(postman::postman_collection))
        .route("/snippets", get(snippets::snippets))
        // Phase 13.0: /v1/protect with tenant middleware (resolves API keys)
        .merge(protect_router)
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_secs: u64,
}

async fn health(State(state): State<ApiState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: state.started_at.elapsed().as_secs(),
    })
}

#[derive(Serialize)]
struct VersionResponse {
    version: String,
    build: String,
    license: String,
    repo: String,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        build: std::env::var("BUILD_PROFILE").unwrap_or_else(|_| "debug".into()),
        license: "Apache-2.0".into(),
        repo: "https://github.com/vinomoid/chakravyuh".into(),
    })
}

/// Known ring names for health monitoring.
const KNOWN_RINGS: &[&str] = &["shield", "threat", "identity", "memory", "agent", "execution"];

/// GET /v1/recovery — ring health, circuit breaker state, and recovery status.
async fn recovery_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let ring_health = state.cross_ring.ring_health(KNOWN_RINGS);
    let assessment = state.cross_ring.assess_degraded_mode(KNOWN_RINGS);
    let recovery_events = state.cross_ring.recovery_events();

    Json(serde_json::json!({
        "degraded": assessment.degraded,
        "lockdown": assessment.lockdown,
        "action": format!("{:?}", assessment.action),
        "rings_down": assessment.rings_down,
        "open_rings": assessment.open_rings,
        "slow_rings": assessment.slow_rings,
        "summary": assessment.summary,
        "rings": ring_health.iter().map(|h| serde_json::json!({
            "name": h.ring_name,
            "state": format!("{:?}", h.state),
            "healthy": h.is_healthy,
            "slow": h.is_slow,
            "total_requests": h.total_requests,
            "total_failures": h.total_failures,
            "error_rate": format!("{:.3}", h.error_rate),
            "avg_latency_ms": format!("{:.2}", h.avg_latency_ms),
        })).collect::<Vec<_>>(),
        "recent_recovery_events": recovery_events.iter().rev().take(10).map(|e| serde_json::json!({
            "event_type": e.event_type,
            "ring": e.ring_name,
            "from": format!("{:?}", e.previous_state),
            "to": format!("{:?}", e.new_state),
            "reason": e.reason,
            "action": e.action_taken,
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct EvaluateRequest {
    #[serde(default)]
    model: Option<String>,
    /// Optional so that requests missing this required field still
    /// reach the Shield Ring — the input_validator engine will deny
    /// them with a structured `MISSING_REQUIRED_FIELD` verdict rather
    /// than a generic axum 400. We preserve absence via `Option` so
    /// the shield body also has no `messages` key.
    #[serde(default)]
    messages: Option<Vec<serde_json::Value>>,
    /// Extra fields (temperature, max_tokens, etc.) passed through unchanged.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}



async fn evaluate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<EvaluateRequest>,
) -> impl IntoResponse {
    let mut body = serde_json::Map::new();
    if let Some(model) = req.model {
        body.insert("model".into(), model.into());
    }
    if let Some(messages) = req.messages {
        body.insert("messages".into(), messages.into());
    }
    let shield_request =
        build_shield_request("/v1/evaluate", &headers, serde_json::Value::Object(body));

    let request_id = uuid::Uuid::new_v4().to_string();
    let prompt_text = extract_prompt_text(&shield_request.body);

    // Build orchestration plan and execute via PipelineExecutor.
    let plan = state.orchestrate.plan(RequestType::SimplePrompt, false);
    let ctx = PipelineContext {
        shield_request,
        request_id,
        prompt_text,
        tool_call: None,
    };

    let result = state.pipeline.execute(&plan, &ctx).await;
    let response = result.shape_full_response();

    let status = if result.decision_record.final_decision.is_allow() {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    (status, Json(response))
}

/// POST /v1/execute — evaluate a tool call through the full pipeline.
///
/// Pipeline: Shield → [Threat+Identity+Memory in parallel] → Agent → Execution → Keshav-Decide/Risk
/// Returns the verdict with per-ring details.
#[derive(Deserialize)]
struct ExecuteRequest {
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
}

async fn execute(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    let request_id = req.request_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Build a shield request for the tool call.
    let body = serde_json::json!({
        "tool_name": req.tool_name,
        "parameters": req.parameters,
    });
    let shield_request = build_shield_request("/v1/execute", &headers, body);
    let prompt_text = extract_prompt_text(&shield_request.body);

    // Build orchestration plan and execute via PipelineExecutor.
    let plan = state.orchestrate.plan(RequestType::ToolCall, true);
    let ctx = PipelineContext {
        shield_request,
        request_id,
        prompt_text,
        tool_call: Some(crate::keshav::ToolCallContext {
            tool_name: req.tool_name,
            parameters: req.parameters,
            agent_id: req.agent_id,
        }),
    };

    let result = state.pipeline.execute(&plan, &ctx).await;
    let response = result.shape_full_response();

    let status = if result.decision_record.final_decision.is_allow()
        && result.execution_verdict.as_ref().map_or(true, |v| v.decision.is_allow())
        && result.agent_verdict.as_ref().map_or(true, |v| v.decision.is_allow())
    {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    (status, Json(response))
}

/// Proxy endpoint — evaluate and forward to upstream.
///
/// Full pipeline: Shield → [Threat+Identity+Memory+Reasoning+Governance in parallel] → Keshav-Decide → Keshav-Risk.
/// If any ring denies, returns the verdict (403). If allowed, forwards to
/// the configured upstream and returns the upstream's response.
async fn proxy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let client_auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let shield_request = build_shield_request("/v1/proxy", &headers, req.clone());

    let request_id = uuid::Uuid::new_v4().to_string();
    let prompt_text = extract_prompt_text(&shield_request.body);

    // Build orchestration plan and execute via PipelineExecutor.
    let plan = state.orchestrate.plan(RequestType::SimplePrompt, false);
    let ctx = PipelineContext {
        shield_request,
        request_id: request_id.clone(),
        prompt_text,
        tool_call: None,
    };

    let result = state.pipeline.execute(&plan, &ctx).await;

    // If Keshav denies, return verdict without forwarding.
    if !result.decision_record.final_decision.is_allow() {
        let response = result.shape_full_response();
        let status = StatusCode::from_u16(result.decision_record.final_decision.http_status())
            .unwrap_or(StatusCode::FORBIDDEN);
        return (status, Json(response)).into_response();
    }

    tracing::info!(
        request_id = %request_id,
        shield_decision = ?result.shield_verdict.decision,
        threat_score = result.threat_verdict.as_ref().map(|v| v.composite_score),
        identity_risk = result.identity_verdict.as_ref().map(|v| v.identity_risk_score),
        memory_risk = result.memory_verdict.as_ref().map(|v| v.memory_risk_score),
        final_decision = ?result.decision_record.final_decision,
        risk_score = result.risk_score.overall,
        "proxy: full pipeline passed, forwarding to upstream"
    );

    // Allow — forward to upstream if configured.
    let Some(upstream) = &state.upstream_client else {
        // No upstream configured — return the verdict.
        return Json(serde_json::json!({
            "decision": "allow",
            "message": "no upstream configured — verdict only",
            "latency_ms": result.shield_verdict.latency_ms,
        }))
        .into_response();
    };

    let upstream_start = Instant::now();
    match upstream.forward(req, client_auth).await {
        Ok(resp) => {
            let status = resp.status();
            // Extract headers we want to forward BEFORE consuming the body.
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            // Stream the upstream's response body back to the client.
            // We convert reqwest::StatusCode → axum::http::StatusCode.
            let axum_status =
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let upstream_latency_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
            let total_latency_ms = result.shield_verdict.latency_ms + upstream_latency_ms;

            tracing::info!(
                request_id = %request_id,
                upstream_status = status.as_u16(),
                shield_latency_ms = result.shield_verdict.latency_ms,
                upstream_latency_ms,
                total_latency_ms,
                "proxy request completed"
            );

            // Read the body and re-wrap it as an axum body.
            let body_bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({
                            "error": "upstream response read failed",
                            "detail": e.to_string(),
                        })),
                    )
                        .into_response();
                }
            };

            // Forward the upstream's content-type header if present.
            let mut response = Response::new(Body::from(body_bytes));
            *response.status_mut() = axum_status;
            if let Some(ct) = content_type {
                response.headers_mut().insert(
                    "content-type",
                    ct.parse()
                        .unwrap_or_else(|_| "application/json".parse().unwrap()),
                );
            }
            // Add a custom header so clients can see the Shield verdict + latencies.
            response
                .headers_mut()
                .insert("x-chakravyuh-decision", "allow".parse().unwrap());
            response.headers_mut().insert(
                "x-chakravyuh-shield-latency-ms",
                format!("{:.3}", result.shield_verdict.latency_ms).parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-chakravyuh-risk-score",
                format!("{:.3}", result.risk_score.overall).parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-chakravyuh-request-id",
                request_id.parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-chakravyuh-upstream-latency-ms",
                format!("{:.3}", upstream_latency_ms).parse().unwrap(),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "upstream forwarding failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "upstream forwarding failed",
                    "detail": e,
                    "shield_decision": "allow",
                    "shield_latency_ms": result.shield_verdict.latency_ms,
                })),
            )
                .into_response()
        }
    }
}

/// Build a [`ShieldRequest`] from the incoming HTTP headers and body.
///
/// Source IP resolution order:
///   1. `X-Real-IP` (set by trusted reverse proxy)
///   2. First entry of `X-Forwarded-For` (left-most = original client)
///   3. `0.0.0.0` fallback (no proxy header present — caller is the proxy)
///
/// We deliberately do NOT trust the socket address because in dev/test
/// we are typically called via `oneshot` or from `127.0.0.1`, and that
/// would mask any IP-based rules.
pub(crate) fn build_shield_request(path: &str, headers: &HeaderMap, body: serde_json::Value) -> ShieldRequest {
    let source_ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "0.0.0.0".into());

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let header_map = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.as_str().to_string();
            let val = v.to_str().ok()?.to_string();
            Some((key, val))
        })
        .collect();

    ShieldRequest {
        source_ip,
        user_agent,
        api_key,
        user_id: None,
        method: "POST".into(),
        path: path.into(),
        headers: header_map,
        body,
    }
}

/// Build an [`IdentityRequest`] from the shield request data.
pub(crate) fn build_identity_request(shield_req: &ShieldRequest, request_id: &str) -> IdentityRequest {
    IdentityRequest {
        source_ip: shield_req.source_ip.clone(),
        user_agent: shield_req.user_agent.clone(),
        api_key: shield_req.api_key.clone(),
        was_denied: false, // Set by caller based on actual shield verdict
        request_id: request_id.to_string(),
        headers: shield_req.headers.clone(),
    }
}

/// Extract prompt text from the request body for Memory Ring evaluation.
pub(crate) fn extract_prompt_text(body: &serde_json::Value) -> String {
    // Try to extract from OpenAI-compatible messages array.
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        let mut parts = Vec::new();
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                parts.push(content.to_string());
            }
        }
        if !parts.is_empty() {
            return parts.join("\n");
        }
    }
    // Fallback: serialize the whole body.
    body.to_string()
}

/// Build a [`MemoryRequest`] from shield request + prompt text.
pub(crate) fn build_memory_request(
    shield_req: &ShieldRequest,
    request_id: &str,
    prompt_text: &str,
) -> crate::memory::MemoryRequest {
    crate::memory::MemoryRequest {
        source_ip: shield_req.source_ip.clone(),
        user_id: shield_req.user_id.clone(),
        role: None,
        prompt: prompt_text.to_string(),
        conversation_id: shield_req.headers.get("x-conversation-id").cloned(),
        turn_count: shield_req.headers.get("x-turn-count").and_then(|v| v.parse().ok()).unwrap_or(1),
        context_length: prompt_text.len(),
        memory_entries: None,
        headers: shield_req.headers.clone(),
        request_id: request_id.to_string(),
    }
}

/// Internal execute request for gRPC bridge.
pub(crate) struct ExecuteRequestInternal {
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub agent_id: Option<String>,
    pub request_id: Option<String>,
}

/// Build an [`AgentRequest`] from internal execute request data (used by gRPC).
pub(crate) fn build_agent_request_from_parts(
    shield_req: &ShieldRequest,
    request_id: &str,
    exec_req: &ExecuteRequestInternal,
) -> crate::agent::AgentRequest {
    crate::agent::AgentRequest {
        agent_id: exec_req.agent_id.clone().unwrap_or_else(|| "unknown".into()),
        agent_type: None,
        action: format!("tool_call:{}", exec_req.tool_name),
        target: None,
        tools_requested: vec![exec_req.tool_name.clone()],
        source_ip: shield_req.source_ip.clone(),
        user_id: shield_req.user_id.clone(),
        role: None,
        scope: None,
        request_id: request_id.to_string(),
        headers: shield_req.headers.clone(),
    }
}

/// GET /v1/decisions — list recent decision records (newest first).
async fn list_decisions(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let entries = state.decide.logger().entries();
    let count = entries.len();
    Json(serde_json::json!({
        "count": count,
        "decisions": entries,
    }))
}

/// GET /v1/decisions/export?format=json|csv — export all decision records.
async fn export_decisions(
    State(state): State<ApiState>,
    axum::extract::Query(params): axum::extract::Query<ExportParams>,
) -> Response {
    let format = params.format.as_deref().unwrap_or("json");
    match format {
        "csv" => match state.decide.logger().export_csv() {
            Ok(csv) => {
                let mut resp = Response::new(Body::from(csv));
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut()
                    .insert("content-type", "text/csv".parse().unwrap());
                resp.headers_mut().insert(
                    "content-disposition",
                    "attachment; filename=\"chakravyuh_decisions.csv\""
                        .parse()
                        .unwrap(),
                );
                resp
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "csv export failed", "detail": e})),
            )
                .into_response(),
        },
        _ => match state.decide.logger().export_json() {
            Ok(json) => {
                let mut resp = Response::new(Body::from(json));
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut()
                    .insert("content-type", "application/json".parse().unwrap());
                resp.headers_mut().insert(
                    "content-disposition",
                    "attachment; filename=\"chakravyuh_decisions.json\""
                        .parse()
                        .unwrap(),
                );
                resp
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "json export failed", "detail": e})),
            )
                .into_response(),
        },
    }
}

#[derive(Deserialize)]
struct ExportParams {
    format: Option<String>,
}

// ── Keshav-Learn API Endpoints ──

/// GET /v1/learn/status — learning system status.
async fn learn_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let status = state.learn.status();
    let anomaly_example = state.learn.assess_anomaly("sample");
    Json(serde_json::json!({
        "enabled": status.enabled,
        "feedback": status.feedback_stats,
        "unprocessed_feedback": status.unprocessed_feedback,
        "auto_optimize_pending": status.auto_optimize_pending,
        "profiles_count": status.profiles_count,
        "patterns_count": status.patterns_count,
        "thresholds_count": status.threshold_count,
        "last_optimization": status.last_optimization,
        "anomaly_assessment_example": anomaly_example,
    }))
}

/// POST /v1/learn/optimize — trigger a threshold optimization pass.
async fn learn_optimize(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let results = state.learn.optimize_thresholds();
    Json(serde_json::json!({
        "optimizations_applied": results.len(),
        "adjustments": results.iter().map(|r| serde_json::json!({
            "ring": r.ring_name,
            "old_deny": r.old_deny,
            "new_deny": r.new_deny,
            "old_challenge": r.old_challenge,
            "new_challenge": r.new_challenge,
            "direction": format!("{:?}", r.direction),
            "reason": r.reason,
            "confidence": r.confidence,
        })).collect::<Vec<_>>(),
    }))
}

/// POST /v1/learn/feedback — submit decision feedback.
#[derive(Deserialize)]
struct FeedbackRequest {
    request_id: String,
    #[serde(rename = "type")]
    feedback_type: String,
    ring: Option<String>,
    original_decision: String,
    explanation: String,
    submitted_by: String,
    severity: Option<String>,
}

async fn learn_feedback(State(state): State<ApiState>, Json(req): Json<FeedbackRequest>) -> impl IntoResponse {
    use crate::keshav::feedback_collector::{FeedbackEntry, FeedbackType, FeedbackSeverity};

    let feedback_type = match req.feedback_type.to_lowercase().as_str() {
        "false_positive" | "fp" => FeedbackType::FalsePositive,
        "false_negative" | "fn" => FeedbackType::FalseNegative,
        "approve" => FeedbackType::Approve,
        "reject" => FeedbackType::Reject,
        "escalation_approved" => FeedbackType::EscalationApproved,
        "escalation_denied" => FeedbackType::EscalationDenied,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid feedback_type",
                "valid_types": ["false_positive", "false_negative", "approve", "reject", "escalation_approved", "escalation_denied"],
            }))).into_response();
        }
    };

    let severity = match req.severity.as_deref() {
        Some("low") => FeedbackSeverity::Low,
        Some("medium") => FeedbackSeverity::Medium,
        Some("high") => FeedbackSeverity::High,
        Some("critical") => FeedbackSeverity::Critical,
        _ => FeedbackSeverity::Medium,
    };

    let target_rings = req.ring.map(|r| vec![r]).unwrap_or_default();

    state.learn.submit_feedback(FeedbackEntry {
        feedback_id: uuid::Uuid::new_v4().to_string(),
        request_id: req.request_id,
        feedback_type,
        severity,
        target_rings,
        original_decision: req.original_decision,
        explanation: req.explanation,
        submitted_by: req.submitted_by,
        timestamp: chrono::Utc::now().to_rfc3339(),
        processed: false,
    });

    (StatusCode::OK, Json(serde_json::json!({
        "status": "accepted",
        "message": "feedback recorded for learning"
    }))).into_response()
}

/// GET /v1/learn/thresholds — get all learned thresholds.
async fn learn_thresholds(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let thresholds = state.learn.threshold_optimizer().all_thresholds();
    Json(serde_json::json!({
        "thresholds": thresholds.iter().map(|(name, state)| serde_json::json!({
            "ring": name,
            "deny_threshold": state.deny_threshold,
            "challenge_threshold": state.challenge_threshold,
            "default_deny": state.default_deny_threshold,
            "default_challenge": state.default_challenge_threshold,
            "adjustment_count": state.adjustment_count,
            "total_adjustment": state.total_adjustment,
            "feedback_count": state.feedback_count,
        })).collect::<Vec<_>>(),
    }))
}

/// POST /v1/learn/thresholds/reset — reset all thresholds to defaults.
async fn learn_thresholds_reset(State(state): State<ApiState>) -> Json<serde_json::Value> {
    state.learn.reset_thresholds();
    Json(serde_json::json!({
        "status": "reset",
        "message": "all thresholds reset to defaults"
    }))
}

/// GET /v1/learn/patterns — list all stored patterns.
async fn learn_patterns(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let stats = state.learn.pattern_store().stats();
    Json(serde_json::json!({
        "stats": stats,
    }))
}

/// GET /v1/learn/patterns/export — export patterns as JSON.
async fn learn_patterns_export(State(state): State<ApiState>) -> Response {
    match state.learn.export_patterns() {
        Ok(json) => {
            let mut resp = Response::new(Body::from(json));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert("content-type", "application/json".parse().unwrap());
            resp.headers_mut().insert(
                "content-disposition",
                "attachment; filename=\"chakravyuh_patterns.json\"".parse().unwrap(),
            );
            resp
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "pattern export failed", "detail": format!("{}", e)})),
        ).into_response(),
    }
}

/// POST /v1/learn/patterns/import — import patterns from JSON.
async fn learn_patterns_import(State(state): State<ApiState>, Json(body): Json<serde_json::Value>) -> Response {
    let json_str = serde_json::to_string(&body).unwrap_or_default();
    match state.learn.import_patterns(&json_str) {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({
            "status": "imported",
            "count": count,
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "pattern import failed", "detail": format!("{}", e)}))).into_response(),
    }
}

// ── Phase 8: Prometheus Metrics ──

/// GET /metrics — Prometheus-style metrics in text format.
async fn metrics_endpoint() -> Response {
    let body = metrics_text();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("content-type", "text/plain; version=0.0.4; charset=utf-8".parse().unwrap());
    resp
}

// ── Phase 7: Health Probes (Kubernetes-style) ──

/// GET /health/ready — readiness probe. Returns 200 if all enabled rings are healthy.
async fn health_ready(State(state): State<ApiState>) -> (StatusCode, Json<serde_json::Value>) {
    if state.shutdown.is_shutting_down() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "status": "shutting_down",
            "ready": false,
        })));
    }

    let ring_health = state.cross_ring.ring_health(KNOWN_RINGS);
    let ready = is_ready(&ring_health.iter().map(|h| crate::infra::RingHealth {
        name: h.ring_name.clone(),
        enabled: true,
        healthy: h.is_healthy,
        last_check_ms: 0.0,
        total_evaluations: h.total_requests,
        total_errors: h.total_failures,
        error_rate: h.error_rate,
    }).collect::<Vec<_>>());

    let (total_reqs, total_errs) = crate::infra::request_counts();
    let status = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(serde_json::json!({
        "status": if ready { "ready" } else { "not_ready" },
        "ready": ready,
        "total_requests": total_reqs,
        "total_errors": total_errs,
        "rings": ring_health.iter().map(|h| serde_json::json!({
            "name": h.ring_name,
            "healthy": h.is_healthy,
        })).collect::<Vec<_>>(),
    })))
}

/// GET /health/live — liveness probe. Always returns 200 if the process is alive.
async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "alive",
        "alive": is_alive(),
    }))
}

// ── Phase 7: Policy Management Endpoints ──

/// GET /v1/policy/info — current policy version, rule count, and rules.
async fn policy_info(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let info = state.policy_manager.policy_info();
    Json(serde_json::json!({
        "version": info.version,
        "rule_count": info.rule_count,
        "rules": info.rules,
        "policy_path": info.policy_path,
    }))
}

/// GET /v1/policy/export — export current policy as YAML.
async fn policy_export(State(state): State<ApiState>) -> Response {
    let yaml = state.policy_manager.export_policy_yaml();
    let mut resp = Response::new(Body::from(yaml));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("content-type", "application/x-yaml".parse().unwrap());
    resp.headers_mut().insert(
        "content-disposition",
        "attachment; filename=\"chakravyuh_policy.yaml\"".parse().unwrap(),
    );
    resp
}

/// POST /v1/policy/reload — trigger hot-reload from the configured policy file.
async fn policy_reload(State(state): State<ApiState>) -> impl IntoResponse {
    match state.policy_manager.reload_from_file() {
        Ok(version) => (StatusCode::OK, Json(serde_json::json!({
            "status": "reloaded",
            "version": version,
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "reload_failed",
            "error": e,
            "note": "existing policy continues to serve requests",
        }))).into_response(),
    }
}

// ── Phase 7: Storage Health ──

/// GET /v1/storage/health — storage backend health check.
async fn storage_health(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let health = state.storage.health_check();
    Json(serde_json::json!({
        "backend": health.backend,
        "reachable": health.reachable,
        "latency_ms": health.latency_ms,
        "detail": health.detail,
    }))
}

// ═══════════════════════════════════════════════════════════════
// ANANTA — Trust Plane API Endpoints
//
// These endpoints expose ANANTA's trust state, attestation,
// trust proofs, and platform health. They return 503 with
// a descriptive message when ANANTA is not active.
// ═══════════════════════════════════════════════════════════════

/// GET /v1/ananta/trust — current trust state across all domains.
async fn ananta_trust_state(State(state): State<ApiState>) -> Response {
    let ananta = match &state.ananta {
        Some(a) => a,
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "active": false,
                "message": "ANANTA trust plane is not enabled. Set ananta_config_path in config.yaml.",
            }))
        ).into_response(),
    };

    let trust_state = ananta.trust_state().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active": true,
            "started": ananta.is_started(),
            "overall_score": trust_state.overall_score(),
            "consecutive_passes": ananta.consecutive_passes(),
            "consecutive_failures": ananta.consecutive_failures(),
            "domains": trust_state.domains,
            "alerts": trust_state.alerts,
            "cycles_completed": trust_state.cycle_count,
            "summary": ananta.trust_summary().await,
        }))
    ).into_response()
}

/// GET /v1/ananta/attestation — latest attestation report.
async fn ananta_attestation(State(state): State<ApiState>) -> Response {
    let ananta = match &state.ananta {
        Some(a) => a,
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "active": false,
                "message": "ANANTA trust plane is not enabled.",
            }))
        ).into_response(),
    };

    let report = ananta.latest_attestation().await;
    match report {
        Some(r) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "active": true,
                "trust_level": r.trust_level,
                "passed": r.integrity.passed,
                "failed_count": r.integrity.failed_count,
                "total_components": r.integrity.results.len(),
                "merkle_root": r.integrity.merkle_root.hex,
                "signature": r.signature.as_ref().map(|s| hex::encode(&s.bytes)),
                "timestamp": r.timestamp,
                "summary": r.summary(),
            }))
        ).into_response(),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "active": true,
                "message": "no attestation cycle completed yet",
            }))
        ).into_response(),
    }
}

/// GET /v1/ananta/proof — latest cryptographic trust proof.
async fn ananta_trust_proof(State(state): State<ApiState>) -> Response {
    let ananta = match &state.ananta {
        Some(a) => a,
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "active": false,
                "message": "ANANTA trust plane is not enabled.",
            }))
        ).into_response(),
    };

    let proof = ananta.latest_trust_proof().await;
    match proof {
        Some(p) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "active": true,
                "proof_id": p.proof_id,
                "trust_score": p.trust_score,
                "all_passed": p.all_passed,
                "attestation_id": p.proof_id,
                "chain_head": p.trust_chain_head,
                "signature": p.signature.as_ref().map(|s| hex::encode(&s.bytes)),
                "timestamp": p.timestamp,
            }))
        ).into_response(),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "active": true,
                "message": "no trust proof generated yet (attestation must complete first)",
            }))
        ).into_response(),
    }
}

/// GET /v1/ananta/health — platform-wide health graph score.
async fn ananta_health(State(state): State<ApiState>) -> Response {
    let ananta = match &state.ananta {
        Some(a) => a,
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "active": false,
                "message": "ANANTA trust plane is not enabled.",
            }))
        ).into_response(),
    };

    let overall = ananta.overall_health().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active": true,
            "overall_health": overall,
            "status": if overall >= 0.8 { "healthy" }
                       else if overall >= 0.5 { "degraded" }
                       else { "critical" },
        }))
    ).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn make_state() -> ApiState {
        let config: Config = Config::default_yaml().parse().expect("config parses");
        let config = Arc::new(config);
        let shield = ShieldRing::new(config.clone()).expect("shield builds");
        let threat_config = Arc::new(config.threat.clone());
        let threat = crate::threat::ThreatRing::new(threat_config).expect("threat builds");
        let identity = crate::identity::IdentityRing::new(&config.identity).expect("identity builds");
        let memory = crate::memory::MemoryRing::new(&config.memory).expect("memory builds");
        let agent = crate::agent::AgentRing::new(&config.agent).expect("agent builds");
        let execution = crate::execution::ExecutionRing::new(&config.execution).expect("execution builds");
        let reasoning = crate::reasoning::ReasoningRing::new(&config.reasoning).expect("reasoning builds");
        let governance = crate::governance::GovernanceRing::new(&config.governance).expect("governance builds");
        let recovery_sec = crate::recovery_sec::RecoveryRing::new(&config.recovery_sec).expect("recovery_sec builds");
        let decide = crate::keshav::KeshavDecide::with_defaults().expect("decide builds");
        let risk = crate::keshav::KeshavRisk::new(config.keshav.risk.clone());
        let learn = crate::keshav::KeshavLearn::new(config.keshav.learn.clone()).expect("learn builds");
        let orchestrate = crate::keshav::KeshavOrchestrate::new(config.keshav.orchestrate.clone());
        let cross_ring = crate::cross_ring::CrossRingNetwork::new(&config.cross_ring).expect("cross_ring builds");
        let pipeline = PipelineExecutor {
            shield: shield.clone(),
            threat: threat.clone(),
            identity: identity.clone(),
            memory: memory.clone(),
            agent: agent.clone(),
            execution: execution.clone(),
            reasoning: reasoning.clone(),
            governance: governance.clone(),
            decide: decide.clone(),
            risk: risk.clone(),
        };
        ApiState {
            shield,
            threat,
            identity,
            memory,
            agent,
            execution,
            reasoning,
            governance,
            recovery_sec,
            decide,
            risk,
            learn,
            orchestrate,
            cross_ring,
            pipeline,
            started_at: Arc::new(Instant::now()),
            upstream_client: None,
            policy_manager: Arc::new(PolicyManager::with_defaults()),
            storage: Arc::new(Box::new(crate::storage::MemoryStore::new())),
            shutdown: Arc::new(ShutdownState::new(30)),
            ananta: None,
            platform_store: Some(Arc::new(PlatformStore::new())),
            webhooks: Some(Arc::new(webhooks::WebhookRegistry::new())),
        }
    }

    #[test]
    fn test_source_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.42".parse().unwrap());
        let req = build_shield_request("/v1/evaluate", &headers, serde_json::json!({}));
        assert_eq!(req.source_ip, "203.0.113.42");
    }

    #[test]
    fn test_source_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7, 10.0.0.1".parse().unwrap());
        let req = build_shield_request("/v1/evaluate", &headers, serde_json::json!({}));
        assert_eq!(req.source_ip, "198.51.100.7");
    }

    #[test]
    fn test_source_ip_fallback_when_no_header() {
        let headers = HeaderMap::new();
        let req = build_shield_request("/v1/evaluate", &headers, serde_json::json!({}));
        assert_eq!(req.source_ip, "0.0.0.0");
    }

    #[test]
    fn test_api_key_extracted_from_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-test-123".parse().unwrap());
        let req = build_shield_request("/v1/evaluate", &headers, serde_json::json!({}));
        assert_eq!(req.api_key.as_deref(), Some("sk-test-123"));
    }

    #[test]
    fn test_user_agent_extracted() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/8.4.0".parse().unwrap());
        let req = build_shield_request("/v1/evaluate", &headers, serde_json::json!({}));
        assert_eq!(req.user_agent.as_deref(), Some("curl/8.4.0"));
    }

    #[test]
    fn test_state_constructs() {
        let _state = make_state();
    }
}
