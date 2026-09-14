// Authentication middleware — Bearer API Key validation.
//
// Validates `Authorization: Bearer ck_live_xxx` or `ck_test_xxx` tokens
// against the configured master secret. Token format:
//   - Live keys:  ck_live_<hmac_hex>
//   - Test keys:  ck_test_<hmac_hex>
//
// When api_keys is disabled or require_for_v1 is false, auth is skipped.

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chakravyuh::infra::ApiKeyManager;
use tower::ServiceExt;

use crate::errors::{self, GatewayError};
use crate::models::ErrorBody;

/// Authentication extractor — runs as axum middleware.
///
/// If the ApiKeyManager is configured and require_for_v1 is true,
/// validates the Bearer token. Otherwise passes through.
pub async fn auth_middleware(
    api_key_manager: std::sync::Arc<ApiKeyManager>,
    request: Request,
    next: Next,
) -> Response {
    // Skip auth for /v1/health (no auth required per OpenAPI spec)
    if request.uri().path() == "/v1/health" {
        return next.run(request).await;
    }

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h.strip_prefix("Bearer ").unwrap(),
        Some(h) if h.is_empty() => {
            return unauthorized_response("Missing Bearer token");
        }
        Some(_) => {
            return unauthorized_response("Invalid authorization scheme. Use 'Bearer <token>'.");
        }
        None => {
            return unauthorized_response("Authorization header is required.");
        }
    };

    let result = api_key_manager.authenticate(token);
    match result {
        chakravyuh::infra::AuthResult::Ok { .. } => next.run(request).await,
        chakravyuh::infra::AuthResult::Err(msg) => {
            tracing::warn!(token_prefix = &token[..token.len().min(12)], reason = %msg, "Auth failed");
            unauthorized_response(&msg)
        }
    }
}

/// Build a 401 JSON response.
fn unauthorized_response(message: &str) -> Response {
    let body = ErrorBody {
        error: crate::models::ErrorDetail {
            code: "authentication_required".to_string(),
            message: message.to_string(),
            request_id: String::new(),
            details: None,
        },
    };
    (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use chakravyuh::infra::{ApiKeyConfig, ApiKeyManager};

    fn make_manager(secret: &str) -> ApiKeyManager {
        let config = ApiKeyConfig {
            enabled: true,
            master_secret: secret.to_string(),
            timestamp_tolerance_secs: 300,
            require_for_v1: true,
        };
        ApiKeyManager::new(config, None)
    }

    #[test]
    fn auth_manager_rejects_empty_token() {
        let mgr = make_manager("test_secret");
        let result = mgr.authenticate("");
        match result {
            chakravyuh::infra::AuthResult::Err(msg) => {
                assert!(!msg.is_empty());
            }
            chakravyuh::infra::AuthResult::Ok { .. } => panic!("empty token should fail"),
        }
    }

    #[test]
    fn auth_manager_rejects_wrong_prefix() {
        let mgr = make_manager("test_secret");
        let result = mgr.authenticate("invalid_token");
        match result {
            chakravyuh::infra::AuthResult::Err(msg) => {
                assert!(msg.contains("prefix") || msg.contains("format"));
            }
            chakravyuh::infra::AuthResult::Ok { .. } => panic!("wrong prefix should fail"),
        }
    }
}
