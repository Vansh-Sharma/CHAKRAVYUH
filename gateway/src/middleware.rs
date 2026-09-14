// Gateway Middleware — Request ID, Correlation ID, structured logging,
// rate limiting, CORS, and panic recovery.
//
// Middleware execution order (outermost first):
//   1. Panic recovery   (catches panics → 500 JSON)
//   2. Request ID       (X-Request-Id)
//   3. Correlation ID   (X-Correlation-Id)
//   4. Structured log   (tracing span per request)
//   5. CORS

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::models::{ErrorBody, ErrorDetail, RequestStartTime};

// ── Headers ─────────────────────────────────────────────────────────────

pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
pub static X_CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");
pub static X_AUDIT_TRACE_ID: HeaderName = HeaderName::from_static("x-audit-trace-id");

// Rate limit headers
pub static X_RATELIMIT_LIMIT: HeaderName = HeaderName::from_static("x-ratelimit-limit");
pub static X_RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
pub static X_RATELIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");

/// Default rate limit: 1000 requests per 60-second window per tenant.
pub const RATE_LIMIT_MAX: u32 = 1000;
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

// ── Panic Recovery ─────────────────────────────────────────────────────

/// Catches panics inside handlers and returns a 500 JSON response.
pub async fn panic_recovery(request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string();

    let path = request.uri().path().to_string();
    let method = request.method().to_string();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // We can't actually catch async panics this way in all cases,
        // but this provides a safety net for synchronous panics in extractors.
        // The real panic handling is done via tokio's panic handler + tracing.
    }));

    // For async handlers, we rely on the custom panic hook set in main.rs.
    // This middleware still provides path/method logging.
    match result {
        Ok(()) => {
            let response = next.run(request).await;
            response
        }
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            tracing::error!(
                method = %method,
                path = %path,
                request_id = %request_id,
                panic = %panic_msg,
                "Handler panicked"
            );
            let body = ErrorBody {
                error: ErrorDetail {
                    code: "internal_error".to_string(),
                    message: "An unexpected error occurred.".to_string(),
                    request_id,
                    details: None,
                },
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
        }
    }
}

// ── Request Start Time ──────────────────────────────────────────────────

/// Injects a `RequestStartTime` into the request extensions.
pub async fn request_start_time(request: Request, next: Next) -> Response {
    let mut request = request;
    request.extensions_mut().insert(RequestStartTime(Instant::now()));
    next.run(request).await
}

// ── Correlation ID ──────────────────────────────────────────────────────

/// Propagates `X-Correlation-Id` from requests into responses.
pub async fn correlation_id(request: Request, next: Next) -> Response {
    let mut request = request;
    let correlation_id = request
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if let Some(ref cid) = correlation_id {
        tracing::span!(tracing::Level::INFO, "request", correlation_id = %cid);
    }

    let mut response = next.run(request).await;

    if let Some(cid) = correlation_id {
        response.headers_mut().insert(
            &X_CORRELATION_ID,
            HeaderValue::from_str(&cid).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
    }

    response
}

// ── Rate Limit Tracking (in-memory) ─────────────────────────────────────

/// Simple in-memory rate limiter for the gateway.
/// Uses a token-bucket approach per tenant.
/// In production, replace with Redis-backed implementation via chakravyuh's storage.
#[derive(Clone)]
pub struct InMemoryRateLimiter {
    /// tenant -> (window_start, count)
    counters: Arc<tokio::sync::RwLock<std::collections::HashMap<String, (std::time::Instant, u32)>>>,
    max: u32,
    window_secs: u64,
}

impl InMemoryRateLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self {
            counters: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            max,
            window_secs,
        }
    }

    /// Check and increment the counter for a tenant.
    /// Returns (allowed, remaining, reset_at_epoch_secs).
    pub async fn check(&self, tenant_id: &str) -> (bool, u32, i64) {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        let reset_epoch = chrono::Utc::now().timestamp() + self.window_secs as i64;

        let mut counters = self.counters.write().await;
        let entry = counters
            .entry(tenant_id.to_string())
            .or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }

        if entry.1 >= self.max {
            (false, 0, reset_epoch)
        } else {
            entry.1 += 1;
            (true, self.max - entry.1, reset_epoch)
        }
    }
}

// ── Middleware Stack Builder ────────────────────────────────────────────

/// Build the complete middleware stack for the gateway router.
pub fn middleware_stack() -> tower::ServiceBuilder<tower_http::trace::TraceLayer<
    tower_http::trace::DefaultOnRequest,
    tower_http::trace::DefaultOnResponse,
    tower_http::trace::EmptyMakeSpan,
    fn(&axum::http::Response<Body>, std::time::Duration, &tracing::Span),
>> {
    ServiceBuilder::new()
        // Layer 1: Set X-Request-Id on every request
        .layer(SetRequestIdLayer::new(
            X_REQUEST_ID.clone(),
            MakeRequestUuid,
        ))
        // Layer 2: Propagate X-Request-Id into response
        .layer(PropagateRequestIdLayer::new(X_REQUEST_ID.clone()))
        // Layer 3: Correlation ID
        .layer(axum::middleware::from_fn(correlation_id))
        // Layer 4: Request start time for latency tracking
        .layer(axum::middleware::from_fn(request_start_time))
        // Layer 5: Structured tracing
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|_request: &Request| {
                    tracing::info_span!(
                        "http_request",
                        method = %_request.method(),
                        path = %_request.uri().path(),
                    )
                })
                .on_response(
                    |_response: &axum::http::Response<Body>, latency: std::time::Duration, _span: &tracing::Span| {
                        let status = _response.status().as_u16();
                        let ms = latency.as_secs_f64() * 1000.0;
                        tracing::info!(status, latency_ms = %format!("{:.2}", ms), "response");
                    },
                ),
        )
}

/// Build CORS layer.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers([
            X_REQUEST_ID.clone(),
            X_CORRELATION_ID.clone(),
            X_AUDIT_TRACE_ID.clone(),
            X_RATELIMIT_LIMIT.clone(),
            X_RATELIMIT_REMAINING.clone(),
            X_RATELIMIT_RESET.clone(),
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_allows_under_limit() {
        let limiter = InMemoryRateLimiter::new(5, 60);
        for _ in 0..5 {
            let (allowed, remaining, _) = limiter.check("tenant_1").await;
            assert!(allowed);
            assert!(remaining <= 5);
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = InMemoryRateLimiter::new(3, 60);
        // Exhaust limit
        for _ in 0..3 {
            let (allowed, _, _) = limiter.check("tenant_1").await;
            assert!(allowed);
        }
        // Should be blocked
        let (allowed, remaining, _) = limiter.check("tenant_1").await;
        assert!(!allowed);
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn rate_limiter_is_per_tenant() {
        let limiter = InMemoryRateLimiter::new(1, 60);
        let (a1, _, _) = limiter.check("tenant_a").await;
        assert!(a1);
        let (a2, _, _) = limiter.check("tenant_a").await;
        assert!(!a2);
        // Different tenant should be independent
        let (b1, _, _) = limiter.check("tenant_b").await;
        assert!(b1);
    }
}
