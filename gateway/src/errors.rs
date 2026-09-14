// Unified error types for the CHAKRAVYUH Gateway.
//
// Every error is converted to a JSON response matching the OpenAPI contract:
//   { "error": { "code": "...", "message": "...", "request_id": "..." } }

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::models::ErrorBody;

/// Gateway-specific error type.
///
/// Carries both the HTTP status code and the machine-readable error code.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Authentication required: {0}")]
    Unauthorized(String),

    #[error("Access denied: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Service unavailable: {0}")]
    Unavailable(String),

    #[error("Engine error: {0}")]
    Engine(String),
}

impl GatewayError {
    /// Machine-readable error code for the API response.
    pub fn code(&self) -> &str {
        match self {
            Self::Unauthorized(_) => "authentication_required",
            Self::Forbidden(_) => "access_denied",
            Self::NotFound(_) => "not_found",
            Self::BadRequest(_) => "invalid_request",
            Self::RateLimited(_) => "rate_limited",
            Self::Internal(_) => "internal_error",
            Self::Unavailable(_) => "service_unavailable",
            Self::Engine(_) => "engine_error",
        }
    }

    /// The request_id will be injected by middleware before serialization.
    /// This method creates the error body with a placeholder.
    fn to_error_body(&self, request_id: &str) -> ErrorBody {
        ErrorBody {
            error: crate::models::ErrorDetail {
                code: self.code().to_string(),
                message: self.to_string(),
                request_id: request_id.to_string(),
                details: None,
            },
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let request_id = "req_unknown".to_string();
        let body = self.to_error_body(&request_id);
        let status = match &self {
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(body)).into_response()
    }
}

/// Extension trait to convert chakravyuh engine errors into gateway errors.
impl From<chakravyuh::Error> for GatewayError {
    fn from(e: chakravyuh::Error) -> Self {
        tracing::warn!(error = %e, "Engine error converted to gateway error");
        match e {
            chakravyuh::Error::ConfigLoad(msg)
            | chakravyuh::Error::ConfigParse(msg) => GatewayError::BadRequest(msg),
            chakravyuh::Error::EngineInit(msg) => GatewayError::Unavailable(msg),
            chakravyuh::Error::Evaluation(msg) => GatewayError::Engine(msg),
            chakravyuh::Error::Serialization(msg) => GatewayError::Internal(msg),
            chakravyuh::Error::Io(msg) => GatewayError::Internal(msg.to_string()),
            chakravyuh::Error::Other(msg) => GatewayError::Internal(msg),
            chakravyuh::Error::RateLimiterStorage(msg) => GatewayError::Internal(msg),
        }
    }
}

/// Helper: create a 400 BadRequest error.
pub fn bad_request(msg: impl Into<String>) -> GatewayError {
    GatewayError::BadRequest(msg.into())
}

/// Helper: create a 401 Unauthorized error.
pub fn unauthorized(msg: impl Into<String>) -> GatewayError {
    GatewayError::Unauthorized(msg.into())
}

/// Helper: create a 403 Forbidden error.
pub fn forbidden(msg: impl Into<String>) -> GatewayError {
    GatewayError::Forbidden(msg.into())
}

/// Helper: create a 404 Not Found error.
pub fn not_found(msg: impl Into<String>) -> GatewayError {
    GatewayError::NotFound(msg.into())
}

/// Helper: create a 429 Rate Limited error.
pub fn rate_limited(msg: impl Into<String>) -> GatewayError {
    GatewayError::RateLimited(msg.into())
}

/// Helper: create a 500 Internal error.
pub fn internal(msg: impl Into<String>) -> GatewayError {
    GatewayError::Internal(msg.into())
}

/// Helper: create a 503 Unavailable error.
pub fn unavailable(msg: impl Into<String>) -> GatewayError {
    GatewayError::Unavailable(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_openapi() {
        assert_eq!(GatewayError::Unauthorized("".into()).code(), "authentication_required");
        assert_eq!(GatewayError::Forbidden("".into()).code(), "access_denied");
        assert_eq!(GatewayError::NotFound("".into()).code(), "not_found");
        assert_eq!(GatewayError::BadRequest("".into()).code(), "invalid_request");
        assert_eq!(GatewayError::RateLimited("".into()).code(), "rate_limited");
        assert_eq!(GatewayError::Internal("".into()).code(), "internal_error");
        assert_eq!(GatewayError::Unavailable("".into()).code(), "service_unavailable");
    }

    #[test]
    fn into_response_status_codes() {
        assert_eq!(GatewayError::Unauthorized("".into()).into_response().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(GatewayError::Forbidden("".into()).into_response().status(), StatusCode::FORBIDDEN);
        assert_eq!(GatewayError::NotFound("".into()).into_response().status(), StatusCode::NOT_FOUND);
        assert_eq!(GatewayError::BadRequest("".into()).into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(GatewayError::RateLimited("".into()).into_response().status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(GatewayError::Internal("".into()).into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(GatewayError::Unavailable("".into()).into_response().status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn helper_functions() {
        let e = bad_request("missing field");
        assert!(matches!(e, GatewayError::BadRequest(_)));
        let e = unauthorized("no token");
        assert!(matches!(e, GatewayError::Unauthorized(_)));
        let e = not_found("policy xyz");
        assert!(matches!(e, GatewayError::NotFound(_)));
    }
}
