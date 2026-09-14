// Route definitions — all v1 endpoints.

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::handlers::{
    audit_list_handler, health_handler, policy_evaluate_handler,
    protect_handler, protect_simple_handler, verify_handler,
    version_handler,
};
use crate::handlers::protect::AppState;

/// Build the complete v1 router.
///
/// Public routes (no auth required):
///   GET  /v1/health   — System health
///   GET  /v1/version  — Version metadata
///
/// Protected routes (auth required):
///   POST /v1/protect            — Full protect (OpenAPI contract)
///   POST /v1/verify             — Evidence verification
///   POST /v1/policy/evaluate    — Policy dry-run
///   GET  /v1/audit              — Audit log
///
/// Simplified public routes (no auth required, Phase 12.0):
///   POST /v1/protect (simple)   — Flat input string protect
pub fn build_router(state: AppState, api_key_manager: Arc<chakravyuh::infra::ApiKeyManager>) -> Router {
    // Authenticated routes — require Bearer API key
    let protected_routes = Router::new()
        .route("/v1/protect/full", post(protect_handler))
        .route("/v1/verify", post(verify_handler))
        .route("/v1/policy/evaluate", post(policy_evaluate_handler))
        .route("/v1/audit", get(audit_list_handler))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            api_key_manager,
            crate::auth::auth_middleware,
        ));

    // Public routes — no authentication required
    let public_routes = Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/version", get(version_handler))
        .route("/v1/protect", post(protect_simple_handler))
        .with_state(state);

    Router::new()
        .merge(protected_routes)
        .merge(public_routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_builds_without_panic() {
        let config = Arc::new(chakravyuh::Config::default());
        let audit_trail = Arc::new(chakravyuh::infra::AuditTrail::new(
            chakravyuh::infra::AuditConfig::default(),
        ));
        let api_key_mgr = Arc::new(chakravyuh::infra::ApiKeyManager::new(
            chakravyuh::infra::ApiKeyConfig::default(),
            None,
        ));
        let rate_limiter = Arc::new(crate::middleware::InMemoryRateLimiter::new(1000, 60));

        let shield = chakravyuh::shield::ShieldRing::new(Arc::clone(&config)).unwrap();
        let threat = chakravyuh::threat::ThreatRing::new(Arc::new(config.threat.clone())).unwrap();
        let identity = chakravyuh::identity::IdentityRing::new(&config.identity).unwrap();
        let memory = chakravyuh::memory::MemoryRing::new(&config.memory).unwrap();
        let agent = chakravyuh::agent::AgentRing::new(&config.agent).unwrap();
        let execution = chakravyuh::execution::ExecutionRing::new(&config.execution).unwrap();
        let reasoning = chakravyuh::reasoning::ReasoningRing::new(&config.reasoning).unwrap();
        let governance = chakravyuh::governance::GovernanceRing::new(&config.governance).unwrap();
        let decide = chakravyuh::keshav::KeshavDecide::with_defaults().unwrap();
        let risk = chakravyuh::keshav::KeshavRisk::with_defaults();
        let executor = Arc::new(chakravyuh::keshav::PipelineExecutor {
            shield, threat, identity, memory, agent, execution,
            reasoning, governance, decide, risk,
        });
        let orchestrator = Arc::new(chakravyuh::keshav::KeshavOrchestrate::with_defaults());

        let state = AppState {
            audit_trail,
            api_key_manager: Arc::clone(&api_key_mgr),
            rate_limiter,
            start_time: std::time::Instant::now(),
            executor,
            orchestrator,
        };
        let _router = build_router(state, api_key_mgr);
    }
}
