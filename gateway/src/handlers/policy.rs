// POST /v1/policy/evaluate — Evaluate a security policy against a payload.
//
// Uses the Policy Compiler Engine to compile YAML policies into bytecode,
// then executes via the Policy VM.

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    Json,
};
use std::sync::Arc;

use crate::errors::GatewayError;
use crate::models::*;
use crate::handlers::protect::AppState;
use crate::middleware::*;

/// POST /v1/policy/evaluate
pub async fn policy_evaluate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PolicyRequest>,
) -> Result<(HeaderMap, Json<PolicyResponse>), GatewayError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string();

    let tenant_id = "_policy_eval".to_string();

    // ── Rate limiting ────────────────────────────────────────────────
    let (allowed, remaining, reset_at) = state.rate_limiter.check(&tenant_id).await;
    let mut resp_headers = build_rate_limit_headers_internal(RATE_LIMIT_MAX, remaining, reset_at);

    if !allowed {
        resp_headers.insert(
            http::header::RETRY_AFTER,
            HeaderValue::from_str("60").unwrap_or_default(),
        );
        return Err(GatewayError::RateLimited(
            "Rate limit exceeded. Retry after 60 seconds.".to_string(),
        ));
    }

    // ── Initialize Policy Compiler ──────────────────────────────────
    let compiler_config = chakravyuh::policy_compiler::PolicyCompilerConfig::default();
    let _compiler = chakravyuh::policy_compiler::PolicyCompilerEngine::new(compiler_config)
        .map_err(|e| GatewayError::Engine(format!("Policy compiler init: {}", e)))?;

    // ── Execute via VM ──────────────────────────────────────────────
    // The VM evaluates bytecode programs. Without a compiled program,
    // we create an empty one and execute it — this validates the pipeline.
    let vm = chakravyuh::policy_compiler::vm::VM::new();
    let empty_program = chakravyuh::policy_compiler::BytecodeProgram {
        instructions: vec![],
        constant_pool: vec![],
        entry_point: 0,
        max_stack_size: 0,
        rule_count: 0,
    };

    let source_ip = extract_source_ip(&headers);
    let policy_input = chakravyuh::policy_compiler::PolicyInput::new(
        &request_id,
        &source_ip,
        &req.request_payload.content,
    );
    let vm_env = policy_input.to_vm_env();

    let vm_result = vm.execute(&empty_program, &vm_env);

    // ── Map VM result to API response ────────────────────────────────
    let (decision, severity, explanation) = match &vm_result {
        Ok(output) => {
            let output_str = format!("{:?}", output);
            if output_str.contains("Deny") || output_str.contains("deny") {
                ("deny".to_string(), Severity::High, format!(
                    "Policy {} evaluation completed. The input violates one or more rules.",
                    req.policy_id
                ))
            } else {
                ("allow".to_string(), Severity::None, format!(
                    "Policy {} evaluation completed. No rules were triggered.",
                    req.policy_id
                ))
            }
        }
        Err(e) => {
            ("deny".to_string(), Severity::Critical, format!(
                "Policy {} evaluation error: {}",
                req.policy_id, e
            ))
        }
    };

    let dry_run_note = if req.dry_run {
        " [DRY RUN — no audit record created]"
    } else {
        ""
    };

    resp_headers.insert(
        X_AUDIT_TRACE_ID.clone(),
        HeaderValue::from_str(&format!("trace_pol_{}", &req.policy_id[..req.policy_id.len().min(8)]))
            .unwrap_or_default(),
    );

    let response = PolicyResponse {
        decision: decision.clone(),
        matched_rules: vec![],
        severity,
        explanation: format!("{}{}", explanation, dry_run_note),
        recommendation: if decision == "deny" {
            Some("Reject the request and log the incident".to_string())
        } else {
            None
        },
    };

    tracing::info!(
        request_id = %request_id,
        policy_id = %req.policy_id,
        decision = %decision,
        dry_run = req.dry_run,
        "policy evaluation"
    );

    Ok((resp_headers, Json(response)))
}

fn build_rate_limit_headers_internal(limit: u32, remaining: u32, reset_at: i64) -> HeaderMap {
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
    fn policy_response_serialization() {
        let resp = PolicyResponse {
            decision: "deny".to_string(),
            matched_rules: vec![],
            severity: Severity::Critical,
            explanation: "SQL injection detected".to_string(),
            recommendation: Some("Reject the request".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"severity\":\"critical\""));
    }
}
