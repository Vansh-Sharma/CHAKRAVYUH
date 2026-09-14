// POST /v1/protect — Analyze and protect an LLM interaction.
//
// Calls the Keshav PipelineExecutor to evaluate the input through
// the defense rings. The executor runs the orchestration plan:
//   1. Shield (gate ring, always first)
//   2. Parallel batch: Threat, Identity, Memory, Reasoning, Governance
//   3. Sequential batch: Agent, Execution (if dependencies met)
//   4. Keshav-Decide + Keshav-Risk for final decision

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use uuid::Uuid;

use crate::errors::GatewayError;
use crate::models::*;
use crate::middleware::*;

/// Shared application state accessible by all handlers.
#[derive(Clone)]
pub struct AppState {
    pub audit_trail: Arc<chakravyuh::infra::AuditTrail>,
    pub api_key_manager: Arc<chakravyuh::infra::ApiKeyManager>,
    pub rate_limiter: Arc<InMemoryRateLimiter>,
    pub start_time: std::time::Instant,
    /// Pre-built pipeline executor with all rings initialized.
    pub executor: Arc<chakravyuh::keshav::PipelineExecutor>,
    pub orchestrator: Arc<chakravyuh::keshav::KeshavOrchestrate>,
}

/// POST /v1/protect
pub async fn protect_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProtectRequest>,
) -> Result<(HeaderMap, Json<ProtectResponse>), GatewayError> {
    let start = Instant::now();
    let request_id = extract_request_id(&headers);
    let source_ip = extract_source_ip(&headers);

    // ── Rate limiting ────────────────────────────────────────────────
    let (rl_allowed, remaining, reset_at) = state.rate_limiter.check(&req.tenant_id).await;
    if !rl_allowed {
        let mut resp_headers = build_rate_limit_headers(0, 0, reset_at);
        resp_headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_str("60").unwrap_or_default(),
        );
        return Err(GatewayError::RateLimited(
            "Rate limit exceeded. Retry after 60 seconds.".to_string(),
        ));
    }

    // ── Map input type to Keshav RequestType ─────────────────────────
    let request_type = match req.input.r#type.as_str() {
        "prompt" => chakravyuh::keshav::RequestType::SimplePrompt,
        "agent_instruction" | "tool_call" => chakravyuh::keshav::RequestType::ToolCall,
        _ => chakravyuh::keshav::RequestType::Unknown,
    };
    let has_tool_call = req.input.tools.as_ref().map_or(false, |t| !t.is_empty());

    // ── Build ShieldRequest from the incoming protect request ───────
    let shield_request = chakravyuh::shield::ShieldRequest {
        source_ip: source_ip.clone(),
        user_agent: req.context.as_ref().and_then(|c| c.user_agent.clone()),
        api_key: headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        user_id: req.context.as_ref().and_then(|c| c.user_id.clone()),
        method: "POST".to_string(),
        path: "/v1/protect".to_string(),
        headers: req
            .context
            .as_ref()
            .map(|c| {
                let mut h = HashMap::new();
                if let Some(ref sid) = c.session_id { h.insert("x-session-id".into(), sid.clone()); }
                if let Some(ref aid) = c.agent_id { h.insert("x-agent-id".into(), aid.clone()); }
                h
            })
            .unwrap_or_default(),
        body: serde_json::json!({
            "content": req.input.content,
            "type": req.input.r#type,
            "content_type": req.input.content_type,
        }),
    };

    // ── Get orchestration plan ───────────────────────────────────────
    let plan = state.orchestrator.plan(request_type, has_tool_call);

    // ── Build PipelineContext and execute ───────────────────────────
    let pipeline_ctx = chakravyuh::keshav::PipelineContext {
        shield_request,
        request_id: request_id.clone(),
        prompt_text: req.input.content.clone(),
        tool_call: None,
    };

    let pipeline_result = state.executor.execute(&plan, &pipeline_ctx).await;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── Determine action from pipeline decision ──────────────────────
    let decision = &pipeline_result.decision_record.final_decision;
    let (action, allowed) = Action::from_decision(decision);
    let triggered_ring = if allowed { None } else { Ring::from_input_type(&req.input.r#type) };

    // ── Risk scoring ─────────────────────────────────────────────────
    let overall_risk = pipeline_result.risk_score.overall.clamp(0.0, 1.0);
    let confidence = pipeline_result.risk_score.confidence;

    // ── Generate evidence ID ─────────────────────────────────────────
    let evidence_id = format!("ev_{}", &Uuid::new_v4().to_string()[..8]);

    // ── Compute ring scores map ──────────────────────────────────────
    let rs = &pipeline_result.risk_score;
    let mut ring_scores = HashMap::new();
    ring_scores.insert("prompt".to_string(), rs.threat);
    ring_scores.insert("input".to_string(), rs.identity);
    ring_scores.insert("identity".to_string(), rs.identity);
    ring_scores.insert("behavior".to_string(), rs.behavior);
    ring_scores.insert("memory".to_string(), rs.memory);
    ring_scores.insert("execution".to_string(), rs.execution);
    ring_scores.insert("context".to_string(), rs.context);

    // ── Build response details for non-allow decisions ────────────────
    let details = if !allowed {
        Some(DecisionDetails {
            reason: match decision {
                chakravyuh::Decision::Deny { code, .. } => {
                    format!("Security policy violation: {}", code)
                }
                chakravyuh::Decision::Challenge { .. } => {
                    "Step-up verification required".to_string()
                }
                chakravyuh::Decision::Escalate { .. } => {
                    "Request escalated for review".to_string()
                }
                _ => "Unknown decision".to_string(),
            },
            patterns: None,
            recommendation: if matches!(action, Action::Deny) {
                Some("Review and sanitize input before processing".to_string())
            } else {
                None
            },
            step_up_required: None,
        })
    } else {
        None
    };

    // ── Record to audit trail ─────────────────────────────────────────
    let decision_json = serde_json::to_string(decision)
        .unwrap_or_else(|_| "{}".to_string());
    let _ = state.audit_trail.append(
        &request_id,
        &decision_json,
        &source_ip,
        "/v1/protect",
    );

    // ── Build response headers ───────────────────────────────────────
    let mut resp_headers = build_rate_limit_headers(RATE_LIMIT_MAX, remaining, reset_at);
    resp_headers.insert(
        X_AUDIT_TRACE_ID.clone(),
        HeaderValue::from_str(&format!("trace_ev_{}", &evidence_id[3..]))
            .unwrap_or_default(),
    );

    let response = ProtectResponse {
        allowed,
        action,
        risk_score: overall_risk,
        confidence,
        triggered_ring,
        policy_id: "pol_default_v1".to_string(),
        evidence_id: evidence_id.clone(),
        latency_ms,
        ring_scores: Some(ring_scores),
        details,
    };

    tracing::info!(
        request_id = %request_id,
        tenant_id = %req.tenant_id,
        allowed,
        action = ?action,
        risk_score = overall_risk,
        latency_ms = %format!("{:.2}", latency_ms),
        evidence_id = %evidence_id,
        "protect decision"
    );

    Ok((resp_headers, Json(response)))
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string()
}

pub fn build_rate_limit_headers(limit: u32, remaining: u32, reset_at: i64) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        X_RATELIMIT_LIMIT.clone(),
        HeaderValue::from_str(&limit.to_string()).unwrap_or_default(),
    );
    h.insert(
        X_RATELIMIT_REMAINING.clone(),
        HeaderValue::from_str(&remaining.to_string()).unwrap_or_default(),
    );
    h.insert(
        X_RATELIMIT_RESET.clone(),
        HeaderValue::from_str(&reset_at.to_string()).unwrap_or_default(),
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_request_id_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-request-id"),
            header::HeaderValue::from_static("req_abc123"),
        );
        assert_eq!(extract_request_id(&headers), "req_abc123");
    }

    #[test]
    fn extract_request_id_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_request_id(&headers), "req_unknown");
    }

    #[test]
    fn build_rate_limit_headers_valid() {
        let h = build_rate_limit_headers(1000, 997, 1724320800);
        assert_eq!(h.get("x-ratelimit-limit").unwrap(), "1000");
        assert_eq!(h.get("x-ratelimit-remaining").unwrap(), "997");
        assert_eq!(h.get("x-ratelimit-reset").unwrap(), "1724320800");
    }

    #[test]
    fn protect_response_model_construction() {
        let response = ProtectResponse {
            allowed: true,
            action: Action::Allow,
            risk_score: 0.12,
            confidence: 0.97,
            triggered_ring: None,
            policy_id: "pol_default_v1".to_string(),
            evidence_id: "ev_test1234".to_string(),
            latency_ms: 3.42,
            ring_scores: Some(HashMap::new()),
            details: None,
        };
        assert!(response.allowed);
        assert_eq!(response.action, Action::Allow);
        assert!(response.risk_score < 0.5);
        assert!(response.confidence > 0.9);
    }
}