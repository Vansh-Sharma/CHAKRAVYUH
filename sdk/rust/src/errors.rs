/// Unified error type for the CHAKRAVYUH SDK.
///
/// All SDK operations return `Result<T, ChakravyuhError>`. The error type covers
/// authentication failures, rate limiting, network issues, serialization problems,
/// and structured API errors returned by the gateway.

use crate::models::ApiError;

/// Errors that can occur when interacting with the CHAKRAVYUH OS API.
#[derive(Debug, thiserror::Error)]
pub enum ChakravyuhError {
    /// Authentication failed — the API key is missing, invalid, or expired.
    ///
    /// Ensure your API key follows the format `ck_live_*` or `ck_test_*`
    /// and has not been revoked.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Rate limit exceeded. The response includes a `Retry-After` header
    /// indicating when to retry.
    #[error("rate limited: retry after {retry_after_secs} seconds (request_id: {request_id})")]
    RateLimited {
        /// Seconds until the rate limit window resets.
        retry_after_secs: u64,
        /// The request ID for support correlation.
        request_id: String,
    },

    /// A network error occurred — the client could not reach the API.
    ///
    /// This covers connection timeouts, DNS failures, and transport errors.
    #[error("network error: {0}")]
    Network(String),

    /// Request or response serialization/deserialization failed.
    ///
    /// This typically indicates a bug in the SDK or a malformed response.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The API returned a structured error response.
    #[error("api error [{code}]: {message} (request_id: {request_id})")]
    Api {
        /// Machine-readable error code from the API.
        code: String,
        /// Human-readable error description.
        message: String,
        /// The request ID for support correlation.
        request_id: String,
    },

    /// The service is temporarily unavailable (HTTP 503).
    #[error("service unavailable: {0}")]
    Unavailable(String),

    /// The request timed out.
    #[error("request timed out after {0} seconds")]
    Timeout(u64),

    /// The requested resource was not found (HTTP 404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Access denied — the authenticated tenant lacks permission.
    #[error("forbidden: {0}")]
    Forbidden(String),
}

impl ChakravyuhError {
    /// Returns the machine-readable error code, if available.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Unauthorized(_) => Some("authentication_required"),
            Self::RateLimited { .. } => Some("rate_limited"),
            Self::Api { code, .. } => Some(code),
            Self::NotFound(_) => Some("not_found"),
            Self::Forbidden(_) => Some("access_denied"),
            Self::Unavailable(_) => Some("service_unavailable"),
            Self::Network(_) | Self::Serialization(_) | Self::Timeout(_) => None,
        }
    }

    /// Returns the request ID for support correlation, if available.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::RateLimited { request_id, .. } => Some(request_id),
            Self::Api { request_id, .. } => Some(request_id),
            _ => None,
        }
    }

    /// Whether this error is retryable with backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Timeout(_) | Self::Unavailable(_) | Self::Network(_)
        )
    }
}

impl From<reqwest::Error> for ChakravyuhError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            return Self::Timeout(0);
        }
        if err.is_connect() {
            return Self::Network(format!("connection error: {err}"));
        }
        if err.is_request() {
            return Self::Network(format!("request error: {err}"));
        }
        Self::Network(format!("{err}"))
    }
}

impl From<serde_json::Error> for ChakravyuhError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

/// Convert a raw API error body into a [`ChakravyuhError`].
pub fn api_error_from_status(status: u16, body: &ApiError) -> ChakravyuhError {
    let code = body.code.clone();
    let message = body.message.clone();
    let request_id = body.request_id.clone();

    match status {
        401 => ChakravyuhError::Unauthorized(message),
        403 => ChakravyuhError::Forbidden(message),
        404 => ChakravyuhError::NotFound(message),
        429 => ChakravyuhError::RateLimited {
            retry_after_secs: 0,
            request_id,
        },
        503 => ChakravyuhError::Unavailable(message),
        _ => ChakravyuhError::Api {
            code,
            message,
            request_id,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_mapping() {
        let err = ChakravyuhError::Unauthorized("bad key".into());
        assert_eq!(err.code(), Some("authentication_required"));
        assert!(!err.is_retryable());

        let err = ChakravyuhError::RateLimited {
            retry_after_secs: 30,
            request_id: "req_123".into(),
        };
        assert_eq!(err.code(), Some("rate_limited"));
        assert!(err.is_retryable());
        assert_eq!(err.request_id(), Some("req_123"));

        let err = ChakravyuhError::Timeout(10);
        assert_eq!(err.code(), None);
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let err = ChakravyuhError::Api {
            code: "invalid_request".into(),
            message: "missing field".into(),
            request_id: "req_abc".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("invalid_request"));
        assert!(msg.contains("missing field"));
        assert!(msg.contains("req_abc"));
    }

    #[test]
    fn test_api_error_from_status() {
        let body = ApiError {
            code: "auth_failed".into(),
            message: "bad token".into(),
            request_id: "req_x".into(),
            details: None,
        };
        let err = api_error_from_status(401, &body);
        assert!(matches!(err, ChakravyuhError::Unauthorized(_)));

        let err = api_error_from_status(429, &body);
        assert!(matches!(err, ChakravyuhError::RateLimited { .. }));
    }
}
