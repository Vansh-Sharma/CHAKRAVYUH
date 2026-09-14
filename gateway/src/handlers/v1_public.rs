// Phase 12.0 — Public API handlers.
//
// These handlers expose the CHAKRAVYUH engine through a clean, simple
// REST interface. No authentication required (Phase 12.1 adds that).
//
// Endpoints:
//   POST /v1/protect     — Simplified protect (flat input string)
//   GET  /v1/health      — System health (re-export from existing)
//   GET  /v1/version     — Version metadata

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use uuid::Uuid;

use crate::errors::GatewayError;
use crate::models::*;
use crate::handlers::protect::{AppState, extract_request_id, build_rate_limit_headers};

/// POST /v1/protect — Simplified public API.
///
/// Accepts a flat JSON body:
///   { "input": "<prompt text>", "tenant_id": "<optional>" }
///
/// Returns:
///   200 + { "allowed": true,  "action": "ALLOW",  ... } for safe input
///   403 + { "allowed": false, "action": "DENY",   ... } for threats
///   400 + { "error": { ... } }                     for invalid requests
pub async fn protect_simple_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<ProtectRequestSimple>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // ── Parse request body with validation ──────────────────────────────
    let Json(simple_req) = match req {
        Ok(r) => r,
        Err(e) => {
            let status = match e.status() {
                StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
                s => s,
            };
            let body = ErrorBody {
                error: ErrorDetail {
                    code: "invalid_request".to_string(),
                    message: format!("Invalid JSON body: {}", e),
                    request_id: extract_request_id(&headers),
                    details: None,
                },
            };
            return (status, Json(body)).into_response();
        }
    };

    // ── Validate input is not empty ─────────────────────────────────────
    let input_text = simple_req.input.trim().to_string();
    if input_text.is_empty() {
        let body = ErrorBody {
            error: ErrorDetail {
                code: "invalid_request".to_string(),
                message: "Field 'input' must be a non-empty string.".to_string(),
                request_id: extract_request_id(&headers),
                details: None,
            },
        };
        return (StatusCode::BAD_REQUEST, Json(body)).into_response();
    }

    let start = Instant::now();
    let request_id = extract_request_id(&headers);
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // ── Rate limiting ────────────────────────────────────────────────────
    let (rl_allowed, remaining, reset_at) = state.rate_limiter.check(&simple_req.tenant_id).await;
    if !rl_allowed {
        let mut resp_headers = build_rate_limit_headers(0, 0, reset_at);
        resp_headers.insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_str("60").unwrap_or_default(),
        );
        let body = ErrorBody {
            error: ErrorDetail {
                code: "rate_limited".to_string(),
                message: "Rate limit exceeded. Retry after 60 seconds.".to_string(),
                request_id: request_id.clone(),
                details: None,
            },
        };
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
        resp.headers_mut().extend(resp_headers);
        return resp;
    }

    // ── Build ShieldRequest from the simple input ───────────────────────
    let shield_request = chakravyuh::shield::ShieldRequest {
        source_ip: source_ip.clone(),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        api_key: headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        user_id: None,
        method: "POST".to_string(),
        path: "/v1/protect".to_string(),
        headers: HashMap::new(),
        body: serde_json::json!({
            "content": input_text,
            "type": "prompt",
            "content_type": "text/plain",
        }),
    };

    // ── Execute through the Keshav pipeline ─────────────────────────────
    let plan = state
        .orchestrator
        .plan(chakravyuh::keshav::RequestType::SimplePrompt, false);

    let pipeline_ctx = chakravyuh::keshav::PipelineContext {
        shield_request,
        request_id: request_id.clone(),
        prompt_text: input_text.clone(),
        tool_call: None,
    };

    let pipeline_result = state.executor.execute(&plan, &pipeline_ctx).await;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── Map engine decision to public response ───────────────────────────
    let decision = &pipeline_result.decision_record.final_decision;
    let (action, allowed) = Action::from_decision(decision);
    let overall_risk = pipeline_result.risk_score.overall.clamp(0.0, 1.0);
    let confidence = pipeline_result.risk_score.confidence;

    let ring = if allowed {
        None
    } else {
        Some(RingSimple::Threat)
    };

    // ── Record to audit trail ─────────────────────────────────────────────
    let decision_json =
        serde_json::to_string(decision).unwrap_or_else(|_| "{}".to_string());
    let _ = state
        .audit_trail
        .append(&request_id, &decision_json, &source_ip, "/v1/protect");

    // ── Build response ───────────────────────────────────────────────────
    let response = ProtectResponseSimple {
        allowed,
        action,
        risk_score: Some(overall_risk),
        confidence: Some(confidence),
        ring,
        request_id: request_id.clone(),
        latency_ms: Some(latency_ms),
    };

    // ── HTTP status: 200 for ALLOW, 403 for DENY ────────────────────────
    let status = if allowed {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    // ── Response headers (rate limit info) ────────────────────────────────
    let resp_headers = build_rate_limit_headers(
        crate::middleware::RATE_LIMIT_MAX,
        remaining,
        reset_at,
    );

    tracing::info!(
        request_id = %request_id,
        tenant_id = %simple_req.tenant_id,
        allowed,
        action = ?action,
        risk_score = overall_risk,
        latency_ms = %format!("{:.2}", latency_ms),
        status = status.as_u16(),
        "protect decision (public API)"
    );

    let mut resp = (status, Json(response)).into_response();
    resp.headers_mut().extend(resp_headers);
    resp
}

/// GET /v1/version — Return version metadata.
pub async fn version_handler() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        engine_version: "1.0.0".to_string(),
        api_version: "2024-08-01".to_string(),
        rustc_version: "1.82.0".to_string(),
        build_target: std::env::consts::ARCH.to_string(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_response_serialization() {
        let resp = VersionResponse {
            version: "1.0.0".to_string(),
            engine_version: "1.0.0".to_string(),
            api_version: "2024-08-01".to_string(),
            rustc_version: "1.82.0".to_string(),
            build_target: "x86_64".to_string(),
            build_profile: "release".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"api_version\":\"2024-08-01\""));
    }

    #[test]
    fn protect_response_simple_deny_serialization() {
        let resp = ProtectResponseSimple {
            allowed: false,
            action: Action::Deny,
            risk_score: Some(0.95),
            confidence: Some(0.98),
            ring: Some(RingSimple::Threat),
            request_id: "req_test".to_string(),
            latency_ms: Some(61.0),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"allowed\":false"));
        assert!(json.contains("\"action\":\"DENY\""));
        assert!(json.contains("\"ring\":\"THREAT\""));
    }
}
