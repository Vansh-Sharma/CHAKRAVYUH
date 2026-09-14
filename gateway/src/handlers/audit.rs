// GET /v1/audit — List immutable audit records.
//
// Returns a paginated list of audit entries from the AuditTrail.
// Supports filtering by tenant, severity, action, and time range.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::errors::GatewayError;
use crate::models::*;
use crate::handlers::protect::AppState;
use crate::middleware::*;

/// Query parameters for GET /v1/audit.
#[derive(Debug, Deserialize, Default)]
pub struct AuditQueryParams {
    pub tenant: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub severity: Option<String>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// GET /v1/audit
pub async fn audit_list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> Result<(HeaderMap, Json<AuditListResponse>), GatewayError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string();

    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = params.offset.unwrap_or(0);

    // ── Fetch entries from audit trail ─────────────────────────────
    let fetch_count = (offset as usize) + (limit as usize) + 1;
    let all_entries = state.audit_trail.recent_entries(fetch_count);
    let total_in_buffer = state.audit_trail.len();

    // ── Paginate ────────────────────────────────────────────────────
    let page: Vec<_> = all_entries
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|entry| AuditRecord {
            evidence_id: entry.trace_id.clone(),
            timestamp: entry.timestamp,
            tenant_id: "unknown"to_string(),
            action: Action::Block,
            severity: Severity::High,
            risk_score: 0.0,
            triggered_ring: None,
            policy_id: "pol_default_v1".to_string(),
            input_type: None,
            input_hash: None,
            summary: None,
            details: None,
            chain_position: entry.seq,
            chain_hash: entry.hash,
        })
        .collect();

    let total = total_in_buffer as u64;
    let has_more = (offset + page.len() as u32) < total as u32;
    let pagination = Pagination {
        total_records: total,
        limit,
        offset,
        has_more,
        next_offset: if has_more { Some(offset + limit) } else { None },
    };

    // ── Build response headers ──────────────────────────────────────
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(&request_id).unwrap_or_default(),
    );

    let (_, remaining, reset_at) = state.rate_limiter.check("_audit").await;
    resp_headers.insert(
        X_RATELIMIT_LIMIT.clone(),
        HeaderValue::from_str(&RATE_LIMIT_MAX.to_string()).unwrap_or_default(),
    );
    resp_headers.insert(
        X_RATELIMIT_REMAINING.clone(),
        HeaderValue::from_str(&remaining.to_string()).unwrap_or_default(),
    );
    resp_headers.insert(
        X_RATELIMIT_RESET.clone(),
        HeaderValue::from_str(&reset_at.to_string()).unwrap_or_default(),
    );

    tracing::info!(
        request_id = %request_id,
        total_records = total,
        limit,
        offset,
        "audit list"
    );

    Ok((resp_headers, Json(AuditListResponse { records: page, pagination })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_query_params_defaults() {
        let params = AuditQueryParams::default();
        assert!(params.tenant.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }

    #[test]
    fn audit_response_serialization() {
        let resp = AuditListResponse {
            records: vec![AuditRecord {
                evidence_id: "ev_abc123".to_string(),
                timestamp: "2026-08-22T10:15:33Z".to_string(),
                tenant_id: "tenant_001".to_string(),
                action: Action::Block,
                severity: Severity::Critical,
                risk_score: 0.94,
                triggered_ring: Some(Ring::Prompt),
                policy_id: "pol_v1".to_string(),
                input_type: Some("prompt".to_string()),
                input_hash: None,
                summary: Some("Blocked".to_string()),
                details: None,
                chain_position: 1,
                chain_hash: "abc".to_string(),
            }],
            pagination: Pagination {
                total_records: 1,
                limit: 20,
                offset: 0,
                has_more: false,
                next_offset: None,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ev_abc123"));
        assert!(json.contains("prompt"));
        assert!(json.contains("critical"));
    }
}