// Phase 13.0 — Tenant Isolation Middleware
//
// For requests to /v1/protect (and other protected endpoints), this
// middleware:
//   1. Extracts the Bearer token from the Authorization header.
//   2. If the token is a ck_live_*/ck_test_* API key:
//        - Hashes it with SHA-256
//        - Looks up the API key record in PlatformStore
//        - Resolves the organization + workspace
//        - Attaches the TenantContext to the request
//   3. If the token is a JWT (user auth), passes through without
//        tenant context (the user-scoped handlers handle auth themselves).
//   4. If no token or invalid format, passes through with no tenant
//        context. The protect handler will allow anonymous access for
//        backwards compatibility (Phase 12.0 behavior).
//
// Tenant isolation guarantee: no handler can access another org's data
// because the TenantContext is derived from the API key, not from any
// user-controlled query parameter.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::identity::{hash_api_key, is_valid_api_key_format, ApiKey, Organization, PlatformStore};

/// Tenant context attached to protected requests.
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub api_key: ApiKey,
    pub organization: Organization,
}

impl TenantContext {
    pub fn org_id(&self) -> uuid::Uuid {
        self.organization.id
    }

    pub fn api_key_id(&self) -> uuid::Uuid {
        self.api_key.id
    }

    pub fn workspace_id(&self) -> Option<uuid::Uuid> {
        self.api_key.workspace_id
    }
}

/// Axum extractor for the TenantContext.
#[derive(Debug, Clone)]
pub struct MaybeTenant(pub Option<TenantContext>);

/// Resolve the API key from the Authorization header and build a TenantContext.
///
/// In axum 0.7, `from_fn_with_state(state, fn)` passes the state via the
/// `State<S>` extractor — not as a raw argument.
pub async fn tenant_middleware(
    State(store): State<Arc<PlatformStore>>,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let tenant = if let Some(auth) = auth_header {
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth);

        if is_valid_api_key_format(token) {
            let hash = hash_api_key(token);
            match store.resolve_api_key(&hash) {
                Some((key, org)) => Some(TenantContext {
                    api_key: key,
                    organization: org,
                }),
                None => {
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"error":{"code":"invalid_api_key","message":"API key not found or revoked"}}"#,
                        ))
                        .unwrap();
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut request = request;
    request.extensions_mut().insert(MaybeTenant(tenant));

    next.run(request).await
}
