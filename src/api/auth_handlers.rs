// Phase 13.0 — Authentication handlers
//
//   POST /v1/auth/signup
//   POST /v1/auth/login
//   POST /v1/auth/refresh
//   POST /v1/auth/logout
//   GET  /v1/auth/me

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::identity::{AuthError, AuthService};

use super::auth_dto::{
    LoginRequest, LogoutRequest, LogoutResponse, MeResponse, OrgSummary, RefreshRequest,
    SignupRequest, TokenResponse, UserPublic,
};
use super::dto::ErrorBody;
use super::PlatformState;

// ── POST /v1/auth/signup ────────────────────────────────────────────────

pub async fn signup(
    State(state): State<PlatformState>,
    Json(req): Json<SignupRequest>,
) -> Response {
    if let Err(msg) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_request", &msg, "n/a")),
        )
            .into_response();
    }

    match state
        .auth
        .signup(&req.email, &req.password, req.name.as_deref())
    {
        Ok((tokens, user)) => {
            let resp = TokenResponse {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                user: user.into(),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(AuthError::UserExists) => (
            StatusCode::CONFLICT,
            Json(ErrorBody::new(
                "user_exists",
                "A user with this email already exists",
                "n/a",
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("signup_failed", &e.to_string(), "n/a")),
        )
            .into_response(),
    }
}

// ── POST /v1/auth/login ──────────────────────────────────────────────────

pub async fn login(State(state): State<PlatformState>, Json(req): Json<LoginRequest>) -> Response {
    match state.auth.login(&req.email, &req.password) {
        Ok(tokens) => {
            // Fetch the user to populate the response.
            let user = match state.auth.get_user_from_token(&tokens.access_token) {
                Ok(u) => u,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorBody::new(
                            "internal_error",
                            "Failed to fetch user after login",
                            "n/a",
                        )),
                    )
                        .into_response();
                }
            };
            let resp = TokenResponse {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                user: user.into(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(AuthError::InvalidCredentials) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody::new(
                "invalid_credentials",
                "Invalid email or password",
                "n/a",
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody::new("login_failed", &e.to_string(), "n/a")),
        )
            .into_response(),
    }
}

// ── POST /v1/auth/refresh ────────────────────────────────────────────────

pub async fn refresh(
    State(state): State<PlatformState>,
    Json(req): Json<RefreshRequest>,
) -> Response {
    match state.auth.refresh(&req.refresh_token) {
        Ok(tokens) => {
            let user = match state.auth.get_user_from_token(&tokens.access_token) {
                Ok(u) => u,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorBody::new(
                            "internal_error",
                            "Failed to fetch user after refresh",
                            "n/a",
                        )),
                    )
                        .into_response();
                }
            };
            let resp = TokenResponse {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_in: tokens.expires_in,
                user: user.into(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody::new(
                "invalid_refresh_token",
                "Refresh token is invalid, expired, or revoked",
                "n/a",
            )),
        )
            .into_response(),
    }
}

// ── POST /v1/auth/logout ────────────────────────────────────────────────

pub async fn logout(
    State(state): State<PlatformState>,
    Json(req): Json<LogoutRequest>,
) -> Response {
    let logged_out = state.auth.logout(req.refresh_token.as_deref());
    (StatusCode::OK, Json(LogoutResponse { logged_out })).into_response()
}

// ── GET /v1/auth/me ─────────────────────────────────────────────────────

pub async fn me(State(state): State<PlatformState>, headers: HeaderMap) -> Response {
    // Extract the Bearer token.
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody::new(
                    "authentication_required",
                    "Missing Bearer token",
                    "n/a",
                )),
            )
                .into_response();
        }
    };

    // Verify and get the user.
    let user = match state.auth.get_user_from_token(&token) {
        Ok(u) => u,
        Err(AuthError::TokenExpired) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody::new(
                    "token_expired",
                    "Access token has expired",
                    "n/a",
                )),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody::new(
                    "invalid_token",
                    "Invalid access token",
                    "n/a",
                )),
            )
                .into_response();
        }
    };

    // Get the user's organizations.
    let orgs = state.store.list_orgs_for_user(user.id);
    let org_summaries: Vec<OrgSummary> = orgs
        .into_iter()
        .map(|o| OrgSummary {
            id: o.id,
            name: o.name,
            slug: o.slug,
            plan: format!("{:?}", o.plan).to_lowercase(),
            role: "owner".to_string(), // simplified
        })
        .collect();

    let resp = MeResponse {
        user: user.into(),
        organizations: org_summaries,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Extract the Bearer token from the Authorization header.
pub fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?;
    let s = auth.to_str().ok()?;
    if let Some(token) = s.strip_prefix("Bearer ") {
        return Some(token.to_string());
    }
    if s.starts_with("ck_live_") || s.starts_with("ck_test_") {
        return Some(s.to_string());
    }
    None
}

/// Extract user_id from a valid JWT in the Authorization header.
/// Returns None if no token or token is invalid.
pub fn require_user_id(state: &PlatformState, headers: &HeaderMap) -> Result<uuid::Uuid, Response> {
    let token = extract_bearer(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody::new(
                "authentication_required",
                "Missing Bearer token",
                "n/a",
            )),
        )
            .into_response()
    })?;

    let claims = state.auth.verify_access_token(&token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody::new(
                "invalid_token",
                "Invalid or expired access token",
                "n/a",
            )),
        )
            .into_response()
    })?;

    let user_id: uuid::Uuid = claims.sub.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody::new(
                "invalid_token",
                "Invalid user ID in token",
                "n/a",
            )),
        )
            .into_response()
    })?;

    Ok(user_id)
}
