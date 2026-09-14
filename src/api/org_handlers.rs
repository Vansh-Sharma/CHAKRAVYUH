// Phase 13.0 — Organization, Workspace, API Key, and Audit handlers
//
//   POST   /v1/orgs
//   GET    /v1/orgs
//   GET    /v1/orgs/{id}
//   PATCH  /v1/orgs/{id}
//   POST   /v1/orgs/{id}/workspaces
//   GET    /v1/orgs/{id}/workspaces
//   POST   /v1/orgs/{id}/keys
//   GET    /v1/orgs/{id}/keys
//   DELETE /v1/orgs/{id}/keys/{key_id}
//   GET    /v1/orgs/{id}/audit

use std::str::FromStr;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::identity::{api_key_prefix, generate_api_key, hash_api_key, is_live_key};

use super::auth_handlers::require_user_id;
use super::dto::ErrorBody;
use super::org_dto::{
    ApiKeyResponse, AuditRecord, AuditResponse, CreateApiKeyRequest, CreateApiKeyResponse,
    CreateOrgRequest, CreateWorkspaceRequest, OrgResponse, Pagination, WorkspaceResponse,
};
use super::PlatformState;

// ── POST /v1/orgs ────────────────────────────────────────────────────────

pub async fn create_org(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Json(req): Json<CreateOrgRequest>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(msg) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_request", &msg, "n/a")),
        )
            .into_response();
    }

    match state
        .store
        .create_org(&req.name, &req.slug, req.plan_enum(), user_id)
    {
        Ok(org) => {
            // Phase 14.0: Fire organization.created webhook event.
            let org_id = org.id;
            let org_data = serde_json::json!({
                "organization_id": org.id,
                "name": org.name,
                "slug": org.slug,
                "plan": format!("{:?}", org.plan).to_lowercase(),
            });
            crate::api::webhooks::dispatch_event(
                &state.webhooks,
                org_id,
                "organization.created",
                org_data,
            )
            .await;

            let resp: OrgResponse = org.into();
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            Json(ErrorBody::new("org_slug_taken", &e, "n/a")),
        )
            .into_response(),
    }
}

// ── GET /v1/orgs ──────────────────────────────────────────────────────────

pub async fn list_orgs(State(state): State<PlatformState>, headers: HeaderMap) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let orgs = state.store.list_orgs_for_user(user_id);
    let resp: Vec<OrgResponse> = orgs.into_iter().map(Into::into).collect();
    (StatusCode::OK, Json(json!({ "organizations": resp }))).into_response()
}

// ── GET /v1/orgs/{id} ───────────────────────────────────────────────────

pub async fn get_org(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    match state.store.get_org(org_id) {
        Some(org) => {
            let resp: OrgResponse = org.into();
            (StatusCode::OK, Json(resp)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(
                "org_not_found",
                "Organization not found",
                "n/a",
            )),
        )
            .into_response(),
    }
}

// ── PATCH /v1/orgs/{id} ────────────────────────────────────────────────

pub async fn update_org(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<crate::api::org_dto::UpdateOrgRequest>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    match state
        .store
        .update_org(org_id, req.name.as_deref(), req.plan_enum())
    {
        Some(org) => {
            let resp: OrgResponse = org.into();
            (StatusCode::OK, Json(resp)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(
                "org_not_found",
                "Organization not found",
                "n/a",
            )),
        )
            .into_response(),
    }
}

// ── POST /v1/orgs/{id}/workspaces ─────────────────────────────────────

pub async fn create_workspace(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    if let Err(msg) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_request", &msg, "n/a")),
        )
            .into_response();
    }

    match state
        .store
        .create_workspace(org_id, &req.name, &req.environment)
    {
        Ok(ws) => {
            let resp: WorkspaceResponse = ws.into();
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("workspace_creation_failed", &e, "n/a")),
        )
            .into_response(),
    }
}

// ── GET /v1/orgs/{id}/workspaces ────────────────────────────────────────

pub async fn list_workspaces(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    let workspaces = state.store.list_workspaces(org_id);
    let resp: Vec<WorkspaceResponse> = workspaces.into_iter().map(Into::into).collect();
    (StatusCode::OK, Json(json!({ "workspaces": resp }))).into_response()
}

// ── POST /v1/orgs/{id}/keys ────────────────────────────────────────────

pub async fn create_api_key(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    if let Err(msg) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_request", &msg, "n/a")),
        )
            .into_response();
    }

    // Generate a new plaintext API key.
    let plaintext = generate_api_key(req.is_live);
    let hash = hash_api_key(&plaintext);
    let prefix = api_key_prefix(&plaintext);

    let key = state.store.create_api_key(
        org_id,
        req.workspace_id,
        &req.name,
        &hash,
        &prefix,
        req.is_live,
    );

    // Phase 14.0: Fire apikey.created webhook event.
    let key_id = key.id;
    let key_data = serde_json::json!({
        "api_key_id": key.id,
        "organization_id": org_id,
        "name": key.name,
        "is_live": key.is_live,
    });
    crate::api::webhooks::dispatch_event(&state.webhooks, org_id, "apikey.created", key_data).await;
    let _ = key_id; // silence unused warning

    // The plaintext key is returned ONCE — never retrievable again.
    let resp = CreateApiKeyResponse {
        api_key: plaintext,
        id: key.id,
        name: key.name,
        is_live: key.is_live,
        key_prefix: key.key_prefix,
        created_at: key.created_at.to_rfc3339(),
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ── GET /v1/orgs/{id}/keys ─────────────────────────────────────────────

pub async fn list_api_keys(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    let keys = state.store.list_api_keys(org_id);
    let resp: Vec<ApiKeyResponse> = keys.into_iter().map(Into::into).collect();
    (StatusCode::OK, Json(json!({ "api_keys": resp }))).into_response()
}

// ── DELETE /v1/orgs/{id}/keys/{key_id} ──────────────────────────────────

pub async fn revoke_api_key(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path((org_id, key_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    match state.store.revoke_api_key(key_id, org_id) {
        Some(key) => {
            let resp: ApiKeyResponse = key.into();
            (StatusCode::OK, Json(resp)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(
                "api_key_not_found",
                "API key not found or does not belong to this organization",
                "n/a",
            )),
        )
            .into_response(),
    }
}

// ── GET /v1/orgs/{id}/audit ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

pub async fn list_audit_logs(
    State(state): State<PlatformState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let user_id = match require_user_id(&state, &headers) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if !state.store.user_belongs_to_org(user_id, org_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "access_denied",
                "You do not have access to this organization",
                "n/a",
            )),
        )
            .into_response();
    }

    let limit = query.limit.min(500); // cap at 500
    let logs = state.store.list_audit_logs(org_id, limit);
    let returned = logs.len();
    let records: Vec<AuditRecord> = logs.into_iter().map(Into::into).collect();

    let resp = AuditResponse {
        records,
        pagination: Pagination {
            total_records: returned, // in-memory store: total == returned
            limit,
            returned,
        },
    };

    (StatusCode::OK, Json(resp)).into_response()
}
