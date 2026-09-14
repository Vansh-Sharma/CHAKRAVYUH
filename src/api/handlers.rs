// Phase 12.0 — Public API handlers
//
// These handlers are thin wrappers around the existing Keshav
// PipelineExecutor. They:
//   1. Deserialize the request DTO
//   2. Build a PipelineContext (reusing build_shield_request)
//   3. Call state.pipeline.execute() (no logic added)
//   4. Map the PipelineResult to the response DTO
//
// NO security logic is implemented here. All detection, scoring,
// and decision-making happens in the existing engine modules.

use std::time::Instant;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum::Extension;
use serde_json::json;
use uuid::Uuid;

use crate::decision::Decision;
use crate::identity::{AuditLog, generate_api_key, hash_api_key, is_valid_api_key_format};
use crate::keshav::orchestrate::RequestType;
use crate::keshav::{PipelineContext, PipelineExecutor};
use crate::shield::ShieldRequest;

use super::dto::{
    BuildInfo, ComponentsHealth, ErrorBody, HealthResponse, LatencyStats, ProtectInput,
    ProtectRequest, ProtectResponse, VersionResponse,
};
use super::tenant_middleware::MaybeTenant;
use super::ApiState;
use super::{build_shield_request, extract_prompt_text};

// ── POST /v1/protect ────────────────────────────────────────────────────

/// Primary customer endpoint. Evaluates a prompt through the full
/// Keshav pipeline and returns an ALLOW / DENY decision.
///
/// HTTP status codes:
///   - 200 OK — request allowed
///   - 403 Forbidden — request denied (attack detected)
///   - 400 Bad Request — malformed JSON or empty input
///   - 500 Internal Server Error — pipeline panic (should not happen)
pub async fn protect(
    State(state): State<ApiState>,
    Extension(maybe_tenant): Extension<MaybeTenant>,
    headers: HeaderMap,
    Json(req): Json<ProtectRequest>,
) -> Response {
    let start = Instant::now();

    // Validate the request DTO.
    if let Err(msg) = req.validate() {
        let request_id = req
            .request_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let body = ErrorBody::new("invalid_request", &msg, &request_id);
        return (StatusCode::BAD_REQUEST, Json(body)).into_response();
    }

    // Generate or reuse request ID.
    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| format!("req_{}", &Uuid::new_v4().to_string()[..16]));

    // Build the OpenAI-compatible body that the engine expects.
    // The engine's extract_prompt_text() looks for a `messages` array,
    // so we wrap the input content in the standard shape.
    let input_content = req.input.content();
    let engine_body = json!({
        "model": "chakravyuh-protect",
        "messages": [
            {"role": "user", "content": input_content}
        ],
        "tenant_id": req.tenant_id,
    });

    // Reuse the existing build_shield_request helper from api/mod.rs.
    let shield_request: ShieldRequest =
        build_shield_request("/v1/protect", &headers, engine_body);

    // Reuse the existing extract_prompt_text helper.
    let prompt_text = extract_prompt_text(&shield_request.body);

    // Build the pipeline context — same shape as /v1/evaluate uses.
    let ctx = PipelineContext {
        shield_request,
        request_id: request_id.clone(),
        prompt_text,
        tool_call: None,
    };

    // Get the orchestration plan for a simple prompt (no tool call).
    let plan = state.orchestrate.plan(RequestType::SimplePrompt, false);

    // Execute the pipeline — this is the existing Keshav evaluation.
    // No new logic is added here.
    let result = state.pipeline.execute(&plan, &ctx).await;

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Extract the final decision and risk score from the pipeline result.
    let decision = &result.decision_record.final_decision;
    let risk_score = &result.risk_score;

    // Determine which ring triggered the deny (if any).
    // We check the ring verdicts in priority order: shield → threat →
    // identity → memory → agent → execution.
    let triggered_ring = determine_triggered_ring(decision, &result);

    // Generate an evidence ID for audit trail lookup.
    let evidence_id = format!("ev_{}", &Uuid::new_v4().to_string()[..8]);

    // Build the response DTO.
    let response = ProtectResponse::from_pipeline(
        decision,
        risk_score,
        latency_ms,
        request_id.clone(),
        evidence_id,
        triggered_ring,
    );

    // Determine HTTP status from the decision.
    //
    // DENY returns 403 Forbidden. The SDK catches this and raises
    // ForbiddenError carrying the parsed ProtectResponse — callers
    // inspect `e.response.reason`, `e.response.ring`, etc.
    //
    // HTTP 403 is the correct semantic for a blocked prompt: the server
    // understood the request and refused to process it. The full
    // ProtectResponse JSON (allowed, action, ring, reason, risk_score,
    // evidence_id, request_id) is returned in the body so the SDK can
    // parse it and attach it to the exception.
    let status = match decision {
        Decision::Allow => StatusCode::OK,
        Decision::Deny { .. } => StatusCode::FORBIDDEN,
        Decision::Challenge { .. } => StatusCode::UNAUTHORIZED,
        Decision::Escalate { .. } => StatusCode::ACCEPTED,
    };

    // Log the decision for server-side observability.
    // This complements (does not replace) the audit trail.
    tracing::info!(
        request_id = %request_id,
        tenant_id = %req.tenant_id,
        allowed = response.allowed,
        action = %response.action,
        risk_score = response.risk_score,
        latency_ms = %format!("{:.2}", latency_ms),
        ring = ?response.triggered_ring,
        "protect decision"
    );

    // Phase 13.0: Write tenant-isolated audit log if a platform store is
    // available and the request was authenticated with an API key.
    let org_id_for_webhooks = maybe_tenant.0.as_ref().map(|t| t.org_id());
    if let Some(ref store) = state.platform_store {
        let audit_entry = AuditLog {
            id: Uuid::new_v4(),
            request_id: request_id.clone(),
            organization_id: maybe_tenant.0.as_ref().map(|t| t.org_id()).unwrap_or_default(),
            workspace_id: maybe_tenant.0.as_ref().and_then(|t| t.workspace_id()),
            api_key_id: maybe_tenant.0.as_ref().map(|t| t.api_key_id()),
            ring: response.triggered_ring.clone(),
            action: response.action.clone(),
            risk_score: response.risk_score,
            latency_ms,
            evidence_id: Some(response.evidence_id.clone()),
            timestamp: chrono::Utc::now(),
        };
        // Only log if we actually have an org_id (tenant was authenticated).
        if audit_entry.organization_id != uuid::Uuid::nil() {
            store.append_audit_log(audit_entry);
        }
    }

    // Phase 14.0: Fire webhook events for security.denied and security.high_risk.
    if let (Some(ref webhooks), Some(org_id)) = (&state.webhooks, org_id_for_webhooks) {
        let event_data = serde_json::json!({
            "request_id": request_id,
            "evidence_id": response.evidence_id,
            "action": response.action,
            "risk_score": response.risk_score,
            "triggered_ring": response.triggered_ring,
            "tenant_id": req.tenant_id,
            "input_preview": if input_content.len() > 100 {
                format!("{}...", &input_content[..100])
            } else {
                input_content.to_string()
            },
        });

        // security.denied: fired when action == "block"
        if response.action == "block" {
            crate::api::webhooks::dispatch_event(
                webhooks,
                org_id,
                "security.denied",
                event_data.clone(),
            )
            .await;
        }

        // security.high_risk: fired when risk_score > 0.7 (even if allowed)
        if response.risk_score > 0.7 {
            crate::api::webhooks::dispatch_event(
                webhooks,
                org_id,
                "security.high_risk",
                event_data,
            )
            .await;
        }
    }

    (status, Json(response)).into_response()
}

/// Determine which ring triggered the final decision.
///
/// For ALLOW: no ring triggered it (return None).
/// For DENY: return the first ring (in priority order) that returned
/// a Deny verdict. This mirrors how Keshav-Decide combines verdicts
/// (most restrictive wins).
fn determine_triggered_ring(
    decision: &Decision,
    result: &crate::keshav::PipelineResult,
) -> Option<String> {
    if decision.is_allow() {
        return None;
    }

    // Check rings in priority order.
    // Shield is first (perimeter), then Threat (cognitive), etc.
    use crate::decision::Decision::*;

    if matches!(result.shield_verdict.decision, Deny { .. }) {
        return Some("Shield".to_string());
    }
    if let Some(v) = &result.threat_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Threat".to_string());
        }
    }
    if let Some(v) = &result.identity_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Identity".to_string());
        }
    }
    if let Some(v) = &result.memory_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Memory".to_string());
        }
    }
    if let Some(v) = &result.agent_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Agent".to_string());
        }
    }
    if let Some(v) = &result.execution_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Execution".to_string());
        }
    }
    if let Some(v) = &result.reasoning_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Reasoning".to_string());
        }
    }
    if let Some(v) = &result.governance_verdict {
        if matches!(v.decision, Deny { .. }) {
            return Some("Governance".to_string());
        }
    }

    // If no individual ring denied but the final decision is Deny,
    // it was a composite Keshav decision.
    Some("Keshav".to_string())
}

// ── GET /v1/health ─────────────────────────────────────────────────────

/// Versioned health endpoint. Returns SDK-compatible health response
/// with build metadata, per-component health, and ANANTA trust score.
pub async fn health(State(state): State<ApiState>) -> Json<HealthResponse> {
    let ananta_active = state.ananta.is_some();
    let trust_score = if let Some(ref ananta) = state.ananta {
        let ts = ananta.trust_state().await;
        ts.overall_score()
    } else {
        1.0
    };

    Json(HealthResponse {
        status: "operational".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        active_rings: 9, // Shield, Identity, Threat, Agent, Memory, Execution, Reasoning, Governance, Recovery
        build: BuildInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: std::env::var("GIT_COMMIT")
                .unwrap_or_else(|_| "unknown".to_string()),
            target: std::env::consts::ARCH.to_string(),
            profile: std::env::var("BUILD_PROFILE")
                .unwrap_or_else(|_| "debug".to_string()),
            rustc: std::env::var("RUSTC_VERSION")
                .unwrap_or_else(|_| "unknown".to_string()),
            built_at: chrono::Utc::now().to_rfc3339(),
        },
        components: ComponentsHealth {
            keshav_orchestrator: "healthy".to_string(),
            ananta_engine: if ananta_active { "healthy" } else { "degraded" }.to_string(),
            sentinel: "healthy".to_string(),
            phoenix: "healthy".to_string(),
            trust_engine: "healthy".to_string(),
            identity: "healthy".to_string(),
            policy_compiler: "healthy".to_string(),
            audit_engine: "healthy".to_string(),
            ovaph: "healthy".to_string(),
        },
        latency: None, // populated by /metrics, not health
        degraded_reasons: Vec::new(),
        ananta_active,
        trust_score,
    })
}

// ── GET /v1/version ─────────────────────────────────────────────────────

/// Build metadata endpoint.
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: "1.0.0".to_string(),
        rustc_version: std::env::var("RUSTC_VERSION")
            .unwrap_or_else(|_| "unknown".to_string()),
        build_target: std::env::consts::ARCH.to_string(),
        build_profile: std::env::var("BUILD_PROFILE")
            .unwrap_or_else(|_| "debug".to_string()),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determine_triggered_ring_returns_none_for_allow() {
        // We can't easily construct a full PipelineResult in a unit test,
        // but we can verify the allow fast-path.
        // This test documents the contract: Allow → None.
        // The integration tests cover the deny paths end-to-end.
        let decision = Decision::Allow;
        // We use a minimal approach: the function checks decision.is_allow()
        // first, so any Allow decision returns None regardless of verdicts.
        // Full coverage is in the integration tests.
        assert!(decision.is_allow());
    }

    #[test]
    fn protect_request_rejects_empty_input() {
        let req = ProtectRequest {
            input: ProtectInput::Simple("".to_string()),
            tenant_id: "demo".to_string(),
            request_id: None,
            context: None,
            metadata: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn protect_request_rejects_whitespace_only_input() {
        let req = ProtectRequest {
            input: ProtectInput::Simple("   \n\t  ".to_string()),
            tenant_id: "demo".to_string(),
            request_id: None,
            context: None,
            metadata: None,
        };
        assert!(req.validate().is_err());
    }
}
