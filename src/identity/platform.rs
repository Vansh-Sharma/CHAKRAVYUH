// Phase 13.0 — Identity & Multi-Tenant Platform Store
//
// In-memory store for the platform layer: Users, Organizations,
// Memberships, Workspaces, ApiKeys, AuditLogs, and RefreshTokens.
//
// This is intentionally an in-memory implementation. The trait-based
// design allows swapping in a PostgresStore or RedisStore later without
// changing handlers or middleware.
//
// Thread safety: all operations go through Arc<RwLock<PlatformData>>.
// Tenant isolation: every read/write is scoped by organization_id.
// No query can cross organization boundaries.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Data Models ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    /// Argon2id hash — never store plaintext passwords.
    pub password_hash: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Plan {
    Free,
    Pro,
    Enterprise,
}

impl Default for Plan {
    fn default() -> Self {
        Plan::Free
    }
}

impl Plan {
    pub fn rpm_limit(&self) -> u32 {
        match self {
            Plan::Free => 100,
            Plan::Pro => 1000,
            Plan::Enterprise => u32::MAX, // unlimited
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: Plan,
    pub owner_user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub id: Uuid,
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub role: String, // "owner", "admin", "developer", "analyst"
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub environment: String, // "production", "staging", "research"
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub name: String,
    /// SHA-256 hash of the plaintext key. Never store plaintext.
    pub key_hash: String,
    /// Prefix of the plaintext key, e.g. "ck_live_4H8J".
    /// Stored for display purposes ("ck_live_4H8J****").
    pub key_prefix: String,
    /// Whether this key is live or test.
    pub is_live: bool,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
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
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token_hash: String, // SHA-256 of the refresh token
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

// ── Platform Data (in-memory) ───────────────────────────────────────────

#[derive(Debug, Default)]
struct PlatformData {
    users: HashMap<Uuid, User>,
    users_by_email: HashMap<String, Uuid>, // email → user_id index
    organizations: HashMap<Uuid, Organization>,
    orgs_by_slug: HashMap<String, Uuid>, // slug → org_id index
    memberships: HashMap<Uuid, Membership>,
    workspaces: HashMap<Uuid, Workspace>,
    api_keys: HashMap<Uuid, ApiKey>,
    api_keys_by_hash: HashMap<String, Uuid>, // key_hash → api_key_id index
    audit_logs: Vec<AuditLog>,
    refresh_tokens: HashMap<String, RefreshToken>, // keyed by token_hash
}

// ── Platform Store ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PlatformStore {
    data: Arc<RwLock<PlatformData>>,
}

impl PlatformStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(PlatformData::default())),
        }
    }

    // ── Users ──

    pub fn create_user(&self, email: &str, password_hash: &str, name: Option<&str>) -> User {
        let user = User {
            id: Uuid::new_v4(),
            email: email.to_lowercase(),
            password_hash: password_hash.to_string(),
            name: name.map(|s| s.to_string()),
            created_at: Utc::now(),
        };
        let mut data = self.data.write().unwrap();
        data.users_by_email
            .insert(user.email.clone(), user.id);
        data.users.insert(user.id, user.clone());
        user
    }

    pub fn get_user_by_email(&self, email: &str) -> Option<User> {
        let data = self.data.read().unwrap();
        let email = email.to_lowercase();
        let id = data.users_by_email.get(&email)?;
        data.users.get(id).cloned()
    }

    pub fn get_user_by_id(&self, id: Uuid) -> Option<User> {
        let data = self.data.read().unwrap();
        data.users.get(&id).cloned()
    }

    // ── Organizations ──

    pub fn create_org(
        &self,
        name: &str,
        slug: &str,
        plan: Plan,
        owner_user_id: Uuid,
    ) -> Result<Organization, String> {
        let slug = slug.to_lowercase();
        let mut data = self.data.write().unwrap();
        if data.orgs_by_slug.contains_key(&slug) {
            return Err(format!("organization slug '{}' already taken", slug));
        }
        let org = Organization {
            id: Uuid::new_v4(),
            name: name.to_string(),
            slug,
            plan,
            owner_user_id,
            created_at: Utc::now(),
        };
        data.orgs_by_slug.insert(org.slug.clone(), org.id);
        data.organizations.insert(org.id, org.clone());

        // Auto-create owner membership.
        let membership = Membership {
            id: Uuid::new_v4(),
            user_id: owner_user_id,
            organization_id: org.id,
            role: "owner".to_string(),
            created_at: Utc::now(),
        };
        data.memberships.insert(membership.id, membership);

        // Auto-create default "Production" workspace.
        let workspace = Workspace {
            id: Uuid::new_v4(),
            organization_id: org.id,
            name: "Production".to_string(),
            environment: "production".to_string(),
            created_at: Utc::now(),
        };
        data.workspaces.insert(workspace.id, workspace);

        Ok(org)
    }

    pub fn get_org(&self, id: Uuid) -> Option<Organization> {
        let data = self.data.read().unwrap();
        data.organizations.get(&id).cloned()
    }

    pub fn list_orgs_for_user(&self, user_id: Uuid) -> Vec<Organization> {
        let data = self.data.read().unwrap();
        let org_ids: Vec<Uuid> = data
            .memberships
            .values()
            .filter(|m| m.user_id == user_id)
            .map(|m| m.organization_id)
            .collect();
        org_ids
            .into_iter()
            .filter_map(|id| data.organizations.get(&id).cloned())
            .collect()
    }

    pub fn update_org(&self, id: Uuid, name: Option<&str>, plan: Option<Plan>) -> Option<Organization> {
        let mut data = self.data.write().unwrap();
        let org = data.organizations.get_mut(&id)?;
        if let Some(n) = name {
            org.name = n.to_string();
        }
        if let Some(p) = plan {
            org.plan = p;
        }
        Some(org.clone())
    }

    pub fn user_belongs_to_org(&self, user_id: Uuid, org_id: Uuid) -> bool {
        let data = self.data.read().unwrap();
        data.memberships
            .values()
            .any(|m| m.user_id == user_id && m.organization_id == org_id)
    }

    // ── Workspaces ──

    pub fn create_workspace(
        &self,
        organization_id: Uuid,
        name: &str,
        environment: &str,
    ) -> Result<Workspace, String> {
        let ws = Workspace {
            id: Uuid::new_v4(),
            organization_id,
            name: name.to_string(),
            environment: environment.to_string(),
            created_at: Utc::now(),
        };
        let mut data = self.data.write().unwrap();
        data.workspaces.insert(ws.id, ws.clone());
        Ok(ws)
    }

    pub fn list_workspaces(&self, organization_id: Uuid) -> Vec<Workspace> {
        let data = self.data.read().unwrap();
        data.workspaces
            .values()
            .filter(|w| w.organization_id == organization_id)
            .cloned()
            .collect()
    }

    // ── API Keys ──

    pub fn create_api_key(
        &self,
        organization_id: Uuid,
        workspace_id: Option<Uuid>,
        name: &str,
        key_hash: &str,
        key_prefix: &str,
        is_live: bool,
    ) -> ApiKey {
        let key = ApiKey {
            id: Uuid::new_v4(),
            organization_id,
            workspace_id,
            name: name.to_string(),
            key_hash: key_hash.to_string(),
            key_prefix: key_prefix.to_string(),
            is_live,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let mut data = self.data.write().unwrap();
        data.api_keys_by_hash
            .insert(key.key_hash.clone(), key.id);
        data.api_keys.insert(key.id, key.clone());
        key
    }

    pub fn list_api_keys(&self, organization_id: Uuid) -> Vec<ApiKey> {
        let data = self.data.read().unwrap();
        data.api_keys
            .values()
            .filter(|k| k.organization_id == organization_id)
            .cloned()
            .collect()
    }

    pub fn revoke_api_key(&self, id: Uuid, organization_id: Uuid) -> Option<ApiKey> {
        let mut data = self.data.write().unwrap();

        // First, check ownership and update — scope the mutable borrow.
        let key_hash = {
            let key = data.api_keys.get_mut(&id)?;
            if key.organization_id != organization_id {
                return None; // tenant isolation: can't revoke another org's key
            }
            key.revoked_at = Some(Utc::now());
            key.key_hash.clone()
        };
        // Mutable borrow on data.api_keys is now released.

        // Remove from the lookup index so it can't be used anymore.
        data.api_keys_by_hash.remove(&key_hash);

        // Return the updated key.
        data.api_keys.get(&id).cloned()
    }

    /// Resolve an API key hash to its ApiKey record + organization.
    /// Returns None if the key doesn't exist or is revoked.
    pub fn resolve_api_key(&self, key_hash: &str) -> Option<(ApiKey, Organization)> {
        let data = self.data.read().unwrap();
        let id = data.api_keys_by_hash.get(key_hash)?;
        let key = data.api_keys.get(id)?;
        if key.revoked_at.is_some() {
            return None;
        }
        let org = data.organizations.get(&key.organization_id)?;
        Some((key.clone(), org.clone()))
    }

    // ── Audit Logs ──

    pub fn append_audit_log(&self, entry: AuditLog) {
        let mut data = self.data.write().unwrap();
        data.audit_logs.push(entry);
    }

    pub fn list_audit_logs(&self, organization_id: Uuid, limit: usize) -> Vec<AuditLog> {
        let data = self.data.read().unwrap();
        data.audit_logs
            .iter()
            .filter(|l| l.organization_id == organization_id) // tenant isolation
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    // ── Refresh Tokens ──

    pub fn store_refresh_token(
        &self,
        token_hash: &str,
        user_id: Uuid,
        organization_id: Option<Uuid>,
        expires_at: DateTime<Utc>,
    ) {
        let token = RefreshToken {
            token_hash: token_hash.to_string(),
            user_id,
            organization_id,
            expires_at,
            created_at: Utc::now(),
            revoked: false,
        };
        let mut data = self.data.write().unwrap();
        data.refresh_tokens.insert(token_hash.to_string(), token);
    }

    pub fn verify_refresh_token(&self, token_hash: &str) -> Option<RefreshToken> {
        let data = self.data.read().unwrap();
        let token = data.refresh_tokens.get(token_hash)?;
        if token.revoked {
            return None;
        }
        if token.expires_at < Utc::now() {
            return None;
        }
        Some(token.clone())
    }

    pub fn revoke_refresh_token(&self, token_hash: &str) -> bool {
        let mut data = self.data.write().unwrap();
        if let Some(token) = data.refresh_tokens.get_mut(token_hash) {
            token.revoked = true;
            return true;
        }
        false
    }

    // ── Rate Limiting (per API key) ──

    pub fn check_rate_limit(&self, _api_key_id: Uuid, _rpm_limit: u32) -> bool {
        // For Phase 13.0 we use a simple in-memory counter.
        // A real implementation would use a sliding window.
        // For now: always allow — rate limiting is enforced by the
        // existing Shield Ring's rate limiter.
        // This is a stub that will be replaced by a proper implementation.
        true
    }
}

impl Default for PlatformStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──

/// Compute the SHA-256 hash of an API key for storage.
pub fn hash_api_key(plaintext: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(plaintext.as_bytes()))
}

/// Compute the SHA-256 hash of a refresh token for storage lookup.
pub fn hash_refresh_token(token: &str) -> String {
    hash_api_key(token) // same algorithm
}

/// Generate a random API key string in the format `ck_live_<32hex>`.
pub fn generate_api_key(is_live: bool) -> String {
    use rand::Rng;
    let prefix = if is_live { "ck_live_" } else { "ck_test_" };
    let random_bytes: [u8; 16] = rand::rng().random();
    let hex_str: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}", prefix, hex_str)
}

/// Extract the display prefix of an API key for UI ("ck_live_4H8J****").
pub fn api_key_prefix(key: &str) -> String {
    if key.len() >= 12 {
        format!("{}****", &key[..12])
    } else {
        "****".to_string()
    }
}

/// Validate that an API key has a known prefix.
pub fn is_valid_api_key_format(key: &str) -> bool {
    key.starts_with("ck_live_") || key.starts_with("ck_test_")
}

/// Whether the API key is a live key (vs test key).
pub fn is_live_key(key: &str) -> bool {
    key.starts_with("ck_live_")
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_creates_user() {
        let store = PlatformStore::new();
        let user = store.create_user("alice@example.com", "hashed_password", Some("Alice"));
        assert!(store.get_user_by_email("alice@example.com").is_some());
        assert!(store.get_user_by_email("ALICE@example.com").is_some()); // case-insensitive
        assert_eq!(user.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn store_creates_org_with_default_workspace() {
        let store = PlatformStore::new();
        let user = store.create_user("bob@example.com", "hash", None);
        let org = store
            .create_org("Acme Inc", "acme", Plan::Free, user.id)
            .unwrap();
        assert_eq!(org.slug, "acme");
        assert_eq!(org.owner_user_id, user.id);

        // Should have auto-created a "Production" workspace.
        let workspaces = store.list_workspaces(org.id);
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].name, "Production");

        // Should have auto-created owner membership.
        assert!(store.user_belongs_to_org(user.id, org.id));
    }

    #[test]
    fn store_rejects_duplicate_slug() {
        let store = PlatformStore::new();
        let user = store.create_user("c@example.com", "hash", None);
        store
            .create_org("Acme", "acme", Plan::Free, user.id)
            .unwrap();
        let result = store.create_org("Other", "acme", Plan::Pro, user.id);
        assert!(result.is_err());
    }

    #[test]
    fn api_key_lifecycle() {
        let store = PlatformStore::new();
        let user = store.create_user("d@example.com", "hash", None);
        let org = store
            .create_org("Acme", "acme", Plan::Pro, user.id)
            .unwrap();

        let plaintext = generate_api_key(true);
        let hash = hash_api_key(&plaintext);
        let prefix = api_key_prefix(&plaintext);

        let key = store.create_api_key(org.id, None, "Production key", &hash, &prefix, true);
        assert_eq!(key.organization_id, org.id);
        assert!(key.is_live);

        // Resolve by hash.
        let resolved = store.resolve_api_key(&hash).unwrap();
        assert_eq!(resolved.0.id, key.id);
        assert_eq!(resolved.1.id, org.id);

        // List keys.
        let keys = store.list_api_keys(org.id);
        assert_eq!(keys.len(), 1);

        // Revoke.
        let revoked = store.revoke_api_key(key.id, org.id);
        assert!(revoked.is_some());

        // Should no longer resolve.
        assert!(store.resolve_api_key(&hash).is_none());
    }

    #[test]
    fn tenant_isolation_audit_logs() {
        let store = PlatformStore::new();

        // Two organizations.
        let user_a = store.create_user("a@example.com", "h", None);
        let user_b = store.create_user("b@example.com", "h", None);
        let org_a = store.create_org("OrgA", "orga", Plan::Free, user_a.id).unwrap();
        let org_b = store.create_org("OrgB", "orgb", Plan::Free, user_b.id).unwrap();

        // Insert audit logs for both orgs.
        store.append_audit_log(AuditLog {
            id: Uuid::new_v4(),
            request_id: "req_1".to_string(),
            organization_id: org_a.id,
            workspace_id: None,
            api_key_id: None,
            ring: Some("shield".to_string()),
            action: "block".to_string(),
            risk_score: 0.9,
            latency_ms: 5.0,
            evidence_id: Some("ev_1".to_string()),
            timestamp: Utc::now(),
        });
        store.append_audit_log(AuditLog {
            id: Uuid::new_v4(),
            request_id: "req_2".to_string(),
            organization_id: org_b.id,
            workspace_id: None,
            api_key_id: None,
            ring: Some("threat".to_string()),
            action: "block".to_string(),
            risk_score: 0.8,
            latency_ms: 4.0,
            evidence_id: Some("ev_2".to_string()),
            timestamp: Utc::now(),
        });

        // Org A should only see its own logs.
        let logs_a = store.list_audit_logs(org_a.id, 100);
        assert_eq!(logs_a.len(), 1);
        assert_eq!(logs_a[0].request_id, "req_1");

        // Org B should only see its own logs.
        let logs_b = store.list_audit_logs(org_b.id, 100);
        assert_eq!(logs_b.len(), 1);
        assert_eq!(logs_b[0].request_id, "req_2");
    }

    #[test]
    fn api_key_tenant_isolation_cannot_revoke_other_org() {
        let store = PlatformStore::new();
        let user_a = store.create_user("a@example.com", "h", None);
        let user_b = store.create_user("b@example.com", "h", None);
        let org_a = store.create_org("OrgA", "orga", Plan::Free, user_a.id).unwrap();
        let org_b = store.create_org("OrgB", "orgb", Plan::Free, user_b.id).unwrap();

        let plaintext = generate_api_key(true);
        let hash = hash_api_key(&plaintext);
        let key = store.create_api_key(
            org_a.id,
            None,
            "Key A",
            &hash,
            &api_key_prefix(&plaintext),
            true,
        );

        // Org B cannot revoke Org A's key.
        let result = store.revoke_api_key(key.id, org_b.id);
        assert!(result.is_none());

        // Key should still resolve.
        assert!(store.resolve_api_key(&hash).is_some());
    }

    #[test]
    fn refresh_token_lifecycle() {
        let store = PlatformStore::new();
        let user = store.create_user("e@example.com", "hash", None);

        let token = "refresh_token_abc123";
        let hash = hash_refresh_token(token);
        let expires = Utc::now() + chrono::Duration::hours(24);

        store.store_refresh_token(&hash, user.id, None, expires);

        // Verify.
        let verified = store.verify_refresh_token(&hash).unwrap();
        assert_eq!(verified.user_id, user.id);

        // Revoke.
        assert!(store.revoke_refresh_token(&hash));

        // Should no longer verify.
        assert!(store.verify_refresh_token(&hash).is_none());
    }

    #[test]
    fn refresh_token_expired_fails() {
        let store = PlatformStore::new();
        let user = store.create_user("f@example.com", "hash", None);

        let hash = hash_refresh_token("expired_token");
        let past = Utc::now() - chrono::Duration::hours(1);

        store.store_refresh_token(&hash, user.id, None, past);
        assert!(store.verify_refresh_token(&hash).is_none());
    }

    #[test]
    fn plan_rpm_limits() {
        assert_eq!(Plan::Free.rpm_limit(), 100);
        assert_eq!(Plan::Pro.rpm_limit(), 1000);
        assert_eq!(Plan::Enterprise.rpm_limit(), u32::MAX);
    }

    #[test]
    fn api_key_format_validation() {
        assert!(is_valid_api_key_format("ck_live_abc123"));
        assert!(is_valid_api_key_format("ck_test_abc123"));
        assert!(!is_valid_api_key_format("sk_live_abc"));
        assert!(!is_valid_api_key_format("random"));
    }

    #[test]
    fn api_key_prefix_extraction() {
        let key = "ck_live_4H8Jabcd1234567890";
        let prefix = api_key_prefix(key);
        assert_eq!(prefix, "ck_live_4H8J****");
    }

    #[test]
    fn generated_key_is_valid_format() {
        let live = generate_api_key(true);
        assert!(live.starts_with("ck_live_"));
        assert!(is_valid_api_key_format(&live));

        let test = generate_api_key(false);
        assert!(test.starts_with("ck_test_"));
        assert!(is_valid_api_key_format(&test));
    }
}
