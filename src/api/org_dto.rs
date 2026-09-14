// Phase 13.0 — Organization / Workspace / API Key DTOs

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Organizations ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
    #[serde(default = "default_plan")]
    pub plan: String,
}

fn default_plan() -> String {
    "free".to_string()
}

impl CreateOrgRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name must not be empty".into());
        }
        if self.slug.trim().is_empty() {
            return Err("slug must not be empty".into());
        }
        if !self
            .slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err("slug must contain only alphanumeric characters and hyphens".into());
        }
        Ok(())
    }

    pub fn plan_enum(&self) -> crate::identity::platform::Plan {
        match self.plan.to_lowercase().as_str() {
            "pro" => crate::identity::platform::Plan::Pro,
            "enterprise" => crate::identity::platform::Plan::Enterprise,
            _ => crate::identity::platform::Plan::Free,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateOrgRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
}

impl UpdateOrgRequest {
    pub fn plan_enum(&self) -> Option<crate::identity::platform::Plan> {
        self.plan.as_ref().map(|p| match p.to_lowercase().as_str() {
            "pro" => crate::identity::platform::Plan::Pro,
            "enterprise" => crate::identity::platform::Plan::Enterprise,
            _ => crate::identity::platform::Plan::Free,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub owner_user_id: Uuid,
    pub created_at: String,
}

impl From<crate::identity::platform::Organization> for OrgResponse {
    fn from(o: crate::identity::platform::Organization) -> Self {
        let plan_str = match o.plan {
            crate::identity::platform::Plan::Free => "free",
            crate::identity::platform::Plan::Pro => "pro",
            crate::identity::platform::Plan::Enterprise => "enterprise",
        };
        Self {
            id: o.id,
            name: o.name,
            slug: o.slug,
            plan: plan_str.to_string(),
            owner_user_id: o.owner_user_id,
            created_at: o.created_at.to_rfc3339(),
        }
    }
}

// ── Workspaces ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    #[serde(default = "default_environment")]
    pub environment: String,
}

fn default_environment() -> String {
    "production".to_string()
}

impl CreateWorkspaceRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name must not be empty".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub environment: String,
    pub created_at: String,
}

impl From<crate::identity::platform::Workspace> for WorkspaceResponse {
    fn from(w: crate::identity::platform::Workspace) -> Self {
        Self {
            id: w.id,
            organization_id: w.organization_id,
            name: w.name,
            environment: w.environment,
            created_at: w.created_at.to_rfc3339(),
        }
    }
}

// ── API Keys ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub workspace_id: Option<Uuid>,
    #[serde(default = "default_live")]
    pub is_live: bool,
}

fn default_live() -> bool {
    true
}

impl CreateApiKeyRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name must not be empty".into());
        }
        Ok(())
    }
}

/// Returned ONCE at creation time — the plaintext key is never retrievable again.
#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,         // the plaintext ck_live_xxx (shown once)
    pub id: Uuid,
    pub name: String,
    pub is_live: bool,
    pub key_prefix: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub is_live: bool,
    pub key_prefix: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl From<crate::identity::platform::ApiKey> for ApiKeyResponse {
    fn from(k: crate::identity::platform::ApiKey) -> Self {
        Self {
            id: k.id,
            name: k.name,
            is_live: k.is_live,
            key_prefix: k.key_prefix,
            created_at: k.created_at.to_rfc3339(),
            revoked_at: k.revoked_at.map(|t| t.to_rfc3339()),
        }
    }
}

// ── Audit ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditResponse {
    pub records: Vec<AuditRecord>,
    pub pagination: Pagination,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub id: Uuid,
    pub request_id: String,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub ring: Option<String>,
    pub action: String,
    pub risk_score: f64,
    pub latency_ms: f64,
    pub evidence_id: Option<String>,
    pub timestamp: String,
}

impl From<crate::identity::platform::AuditLog> for AuditRecord {
    fn from(l: crate::identity::platform::AuditLog) -> Self {
        Self {
            id: l.id,
            request_id: l.request_id,
            organization_id: l.organization_id,
            workspace_id: l.workspace_id,
            api_key_id: l.api_key_id,
            ring: l.ring,
            action: l.action,
            risk_score: l.risk_score,
            latency_ms: l.latency_ms,
            evidence_id: l.evidence_id,
            timestamp: l.timestamp.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Pagination {
    pub total_records: usize,
    pub limit: usize,
    pub returned: usize,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_org_validates_slug() {
        let req = CreateOrgRequest {
            name: "Acme".to_string(),
            slug: "acme with spaces".to_string(),
            plan: "free".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn create_org_accepts_valid_slug() {
        let req = CreateOrgRequest {
            name: "Acme".to_string(),
            slug: "acme-inc".to_string(),
            plan: "pro".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_api_key_defaults_to_live() {
        let json = r#"{"name":"prod-key"}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert!(req.is_live);
    }

    #[test]
    fn create_workspace_defaults_to_production() {
        let json = r#"{"name":"Prod"}"#;
        let req: CreateWorkspaceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.environment, "production");
    }
}
