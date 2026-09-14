// POST /v1/verify — Verify audit evidence integrity.
//
// Looks up the audit evidence by trace ID and verifies its
// cryptographic hash chain integrity.

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

/// POST /v1/verify
pub async fn verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<(HeaderMap, Json<VerifyResponse>), GatewayError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string();

    // ── Fetch entries and find the one matching the evidence_id ───
    // The audit trail stores entries with a trace_id field.
    // We search recent entries for a match.
    let entries = state.audit_trail.recent_entries(10_000);
    let entry = entries
        .iter()
        .find(|e| e.trace_id == req.evidence_id)
        .ok_or_else(|| {
            GatewayError::NotFound(format!(
                "No audit evidence found for the given evidence_id: {}",
                req.evidence_id
            ))
        })?;

    // ── Verify hash chain integrity ──────────────────────────────────
    let chain_position = entry.seq;
    let stored_hash = entry.hash.clone();
    let hash_valid = entry.verify_hash();

    // If caller provided an explicit hash, compare against stored
    let integrity = if !hash_valid {
        IntegrityStatus::Corrupted
    } else if let Some(ref provided_hash) = req.hash {
        if provided_hash.value == stored_hash {
            IntegrityStatus::Intact
        } else {
            IntegrityStatus::Corrupted
        }
    } else {
        IntegrityStatus::Intact
    };

    let verified = integrity == IntegrityStatus::Intact;

    // ── Build response headers ──────────────────────────────────────
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        X_AUDIT_TRACE_ID.clone(),
        HeaderValue::from_str(&format!("trace_ev_{}", &req.evidence_id[3..]))
            .unwrap_or_default(),
    );

    let mut response = VerifyResponse {
        verified,
        integrity,
        timestamp: chrono::Utc::now(),
        chain_position,
        hash: Some(HashSpec {
            algorithm: "sha256".to_string(),
            value: stored_hash,
        }),
        details: None,
    };

    // Add failure details if hash mismatch
    if let Some(ref provided_hash) = req.hash {
        if provided_hash.value != stored_hash {
            response.details = Some(VerifyFailureDetails {
                expected_hash: stored_hash,
                actual_hash: provided_hash.value.clone(),
                divergence_at: None,
            });
        }
    }

    tracing::info!(
        request_id = %request_id,
        evidence_id = %req.evidence_id,
        verified,
        integrity = ?integrity,
        chain_position,
        "evidence verification"
    );

    Ok((resp_headers, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_response_serialization() {
        let resp = VerifyResponse {
            verified: true,
            integrity: IntegrityStatus::Intact,
            timestamp: chrono::Utc::now(),
            chain_position: 47821,
            hash: Some(HashSpec {
                algorithm: "sha256".to_string(),
                value: "a3f2b91c".to_string(),
            }),
            details: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"verified\":true"));
        assert!(json.contains("\"intact\""));
        assert!(json.contains("47821"));
    }

    #[test]
    fn verify_corrupted_response() {
        let resp = VerifyResponse {
            verified: false,
            integrity: IntegrityStatus::Corrupted,
            timestamp: chrono::Utc::now(),
            chain_position: 1,
            hash: Some(HashSpec {
                algorithm: "sha256".to_string(),
                value: "aaaa".to_string(),
            }),
            details: Some(VerifyFailureDetails {
                expected_hash: "aaaa".to_string(),
                actual_hash: "bbbb".to_string(),
                divergence_at: Some("byte 2".to_string()),
            }),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"corrupted\""));
    }
}
