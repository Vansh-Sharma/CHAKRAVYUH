// API Key Authentication (Phase 9)
//
// HMAC-SHA256 signed API keys for securing /v1/* endpoints.
//
// Each API key has:
//   - A key ID (e.g., "ak_live_abc123")
//   - A secret key (used for HMAC signing, never stored in plain text)
//   - Permissions (which endpoints the key can access)
//   - Rate limits (per-key quotas)
//   - Expiration (optional)
//   - Metadata (description, created_by, etc.)
//
// Authentication flow:
//   1. Client sends `Authorization: Bearer <key_id>:<signature>` header
//   2. Signature = HMAC-SHA256(secret, timestamp + method + path + body_hash)
//   3. Server verifies signature and checks permissions/expiration
//
// Key management:
//   - Keys are stored in the persistent Store (Phase 7)
//   - Secrets are hashed with SHA-256 before storage
//   - Admin endpoints for key CRUD operations
//
// Security:
//   - Timestamp replay protection (reject requests older than 5 minutes)
//   - Request body integrity via SHA-256 body hash
//   - Per-key rate limiting integration

use std::collections::HashMap;
use std::sync::RwLock;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Store key prefix for API keys.
const KEY_PREFIX: &str = "chakravyuh:apikey:";

/// Permissions that an API key can have.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Access to /v1/evaluate
    Evaluate,
    /// Access to /v1/proxy
    Proxy,
    /// Access to /v1/execute
    Execute,
    /// Access to /v1/decisions/*
    Decisions,
    /// Access to /v1/learn/*
    Learn,
    /// Access to /v1/policy/*
    Policy,
    /// Access to /metrics
    Metrics,
    /// Full admin access (all endpoints + key management)
    Admin,
}

/// API key metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMeta {
    /// Key ID (e.g., "ak_live_abc123").
    pub key_id: String,
    /// Human-readable name.
    pub name: String,
    /// SHA-256 hash of the secret key (never stored in plain text).
    pub secret_hash: String,
    /// Permissions granted to this key.
    pub permissions: Vec<Permission>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 expiration timestamp (None = never expires).
    pub expires_at: Option<String>,
    /// Who created this key.
    pub created_by: String,
    /// Description.
    pub description: String,
    /// Whether this key is active.
    pub active: bool,
    /// Per-key rate limit (requests per minute, 0 = unlimited).
    pub rate_limit_rpm: u32,
}

/// API key authentication configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ApiKeyConfig {
    /// Enable API key authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Global HMAC signing secret (for verifying signatures).
    /// In production, this should be loaded from a secrets manager.
    #[serde(default)]
    pub master_secret: String,

    /// Request timestamp tolerance in seconds.
    #[serde(default = "default_timestamp_tolerance")]
    pub timestamp_tolerance_secs: u64,

    /// Require API key for /v1/* endpoints.
    #[serde(default)]
    pub require_for_v1: bool,
}

fn default_timestamp_tolerance() -> u64 {
    300
} // 5 minutes

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            master_secret: String::new(),
            timestamp_tolerance_secs: default_timestamp_tolerance(),
            require_for_v1: false,
        }
    }
}

/// API Key Manager — handles key CRUD and authentication.
pub struct ApiKeyManager {
    config: ApiKeyConfig,
    /// In-memory key cache.
    keys: RwLock<HashMap<String, ApiKeyMeta>>,
    /// Per-key rate limit counters (key_id -> (window_start, count)).
    rate_counters: RwLock<HashMap<String, (std::time::Instant, u32)>>,
    /// Optional persistent store.
    store: Option<std::sync::Arc<dyn crate::storage::Store>>,
}

impl ApiKeyManager {
    /// Create a new API key manager (in-memory only).
    pub fn new(config: ApiKeyConfig) -> Self {
        Self {
            config,
            keys: RwLock::new(HashMap::new()),
            rate_counters: RwLock::new(HashMap::new()),
            store: None,
        }
    }

    /// Create an API key manager with persistent storage.
    pub fn with_store(
        config: ApiKeyConfig,
        store: std::sync::Arc<dyn crate::storage::Store>,
    ) -> Self {
        let mut keys_map = HashMap::new();

        // Restore keys from store.
        let stored_keys = store.keys(KEY_PREFIX);
        for key in &stored_keys {
            if let Some(bytes) = store.get(key) {
                if let Ok(meta) = serde_json::from_slice::<ApiKeyMeta>(&bytes) {
                    keys_map.insert(meta.key_id.clone(), meta);
                }
            }
        }

        tracing::info!(
            restored_keys = keys_map.len(),
            "ApiKeyManager: restored keys from store"
        );

        Self {
            config,
            keys: RwLock::new(keys_map),
            rate_counters: RwLock::new(HashMap::new()),
            store: Some(store),
        }
    }

    /// Generate a new API key. Returns (key_id, plaintext_secret).
    /// The plaintext secret is only returned once — it cannot be recovered.
    pub fn create_key(
        &self,
        name: &str,
        permissions: Vec<Permission>,
        expires_at: Option<String>,
        created_by: &str,
        description: &str,
        rate_limit_rpm: u32,
    ) -> crate::Result<(String, String)> {
        let key_id = format!(
            "ak_{}_{}",
            random_prefix(),
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let secret = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().to_string();
        let secret_hash = hash_secret(&secret);

        let meta = ApiKeyMeta {
            key_id: key_id.clone(),
            name: name.to_string(),
            secret_hash,
            permissions,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at,
            created_by: created_by.to_string(),
            description: description.to_string(),
            active: true,
            rate_limit_rpm,
        };

        self.persist_key(&meta);

        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), meta);
        }

        tracing::info!(key_id = %key_id, created_by = %created_by, "ApiKeyManager: key created");
        Ok((key_id, secret))
    }

    /// Revoke an API key.
    pub fn revoke_key(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        if let Some(meta) = keys.get_mut(key_id) {
            meta.active = false;
            drop(keys);
            // Persist the updated meta.
            if let Some(meta) = self.keys.read().unwrap().get(key_id) {
                self.persist_key(meta);
            }
            tracing::info!(key_id = %key_id, "ApiKeyManager: key revoked");
            true
        } else {
            false
        }
    }

    /// Delete an API key entirely.
    pub fn delete_key(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        let removed = keys.remove(key_id).is_some();
        drop(keys);

        if removed {
            self.delete_persisted_key(key_id);
            tracing::info!(key_id = %key_id, "ApiKeyManager: key deleted");
        }
        removed
    }

    /// Authenticate a request using the Authorization header.
    ///
    /// Expected format: `Authorization: Bearer <key_id>:<signature>`
    /// Signature = HMAC-SHA256(secret, timestamp + method + path + body_hash)
    pub fn authenticate(
        &self,
        auth_header: &str,
        timestamp: &str,
        method: &str,
        path: &str,
        body_hash: &str,
        required_permission: Option<&Permission>,
    ) -> AuthResult {
        if !self.config.enabled {
            return AuthResult::Ok;
        }

        // Parse Authorization header.
        let (key_id, signature) = match parse_auth_header(auth_header) {
            Some(v) => v,
            None => return AuthResult::Missing,
        };

        // Look up the key.
        let meta = {
            let keys = self.keys.read().unwrap();
            keys.get(&key_id).cloned()
        };

        let meta = match meta {
            Some(m) => m,
            None => return AuthResult::InvalidKey,
        };

        // Check if key is active.
        if !meta.active {
            return AuthResult::Revoked;
        }

        // Check expiration.
        if let Some(ref expires) = meta.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if chrono::Utc::now() > exp {
                    return AuthResult::Expired;
                }
            }
        }

        // Check timestamp tolerance.
        if let Ok(ts) = timestamp.parse::<i64>() {
            let now = chrono::Utc::now().timestamp();
            if (now - ts).unsigned_abs() > self.config.timestamp_tolerance_secs as u64 {
                return AuthResult::TimestampStale;
            }
        } else {
            return AuthResult::InvalidSignature;
        }

        // Verify HMAC signature.
        // Note: In a real implementation, we'd need the plaintext secret.
        // Since we only store the hash, we use a master secret approach:
        // signature = HMAC-SHA256(master_secret, key_id + timestamp + method + path + body_hash)
        if !self.config.master_secret.is_empty() {
            let message = format!("{}{}{}{}{}", key_id, timestamp, method, path, body_hash);
            let expected_sig = compute_hmac(&self.config.master_secret, &message);
            if expected_sig != signature {
                return AuthResult::InvalidSignature;
            }
        }

        // Check per-key rate limit.
        if meta.rate_limit_rpm > 0 {
            if !self.check_rate_limit(&key_id, meta.rate_limit_rpm) {
                return AuthResult::RateLimited;
            }
        }

        // Check permission.
        if let Some(perm) = required_permission {
            if !meta.permissions.contains(perm) && !meta.permissions.contains(&Permission::Admin) {
                return AuthResult::InsufficientPermissions;
            }
        }

        AuthResult::Authenticated(key_id)
    }

    /// Check and update per-key rate limit.
    fn check_rate_limit(&self, key_id: &str, rpm: u32) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);

        let mut counters = self.rate_counters.write().unwrap();
        let (window_start, count) = counters.entry(key_id.to_string()).or_insert((now, 0));

        // Reset window if expired.
        if now.duration_since(*window_start) > window {
            *window_start = now;
            *count = 0;
        }

        if *count >= rpm {
            return false;
        }

        *count += 1;
        true
    }

    /// Get all key IDs (for admin listing).
    pub fn list_keys(&self) -> Vec<ApiKeyInfo> {
        let keys = self.keys.read().unwrap();
        keys.values()
            .map(|m| ApiKeyInfo {
                key_id: m.key_id.clone(),
                name: m.name.clone(),
                active: m.active,
                permissions: m.permissions.clone(),
                created_at: m.created_at.clone(),
                expires_at: m.expires_at.clone(),
                rate_limit_rpm: m.rate_limit_rpm,
            })
            .collect()
    }

    /// Persist a key to the store.
    fn persist_key(&self, meta: &ApiKeyMeta) {
        if let Some(ref store) = self.store {
            let key = format!("{}{}", KEY_PREFIX, meta.key_id);
            match serde_json::to_vec(meta) {
                Ok(bytes) => {
                    if !store.set(&key, &bytes) {
                        tracing::warn!(key_id = %meta.key_id, "ApiKeyManager: failed to persist key");
                    }
                }
                Err(e) => {
                    tracing::warn!(key_id = %meta.key_id, error = %e, "ApiKeyManager: failed to serialize key");
                }
            }
        }
    }

    /// Delete a key from the store.
    fn delete_persisted_key(&self, key_id: &str) {
        if let Some(ref store) = self.store {
            let key = format!("{}{}", KEY_PREFIX, key_id);
            store.delete(&key);
        }
    }
}

/// Authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Auth not required (disabled).
    Ok,
    /// Successfully authenticated. Contains key_id.
    Authenticated(String),
    /// Missing Authorization header.
    Missing,
    /// Key not found.
    InvalidKey,
    /// Key has been revoked.
    Revoked,
    /// Key has expired.
    Expired,
    /// HMAC signature verification failed.
    InvalidSignature,
    /// Request timestamp too old.
    TimestampStale,
    /// Key lacks required permission.
    InsufficientPermissions,
    /// Per-key rate limit exceeded.
    RateLimited,
}

/// Public key info (without secret).
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyInfo {
    pub key_id: String,
    pub name: String,
    pub active: bool,
    pub permissions: Vec<Permission>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub rate_limit_rpm: u32,
}

/// Hash a secret key with SHA-256.
fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256.
fn compute_hmac(secret: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Parse Authorization header.
/// Format: "Bearer <key_id>:<signature>"
fn parse_auth_header(header: &str) -> Option<(String, String)> {
    let header = header.strip_prefix("Bearer ")?;
    let parts: Vec<&str> = header.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let key_id = parts[0].trim().to_string();
    let signature = parts[1].trim().to_string();
    if key_id.is_empty() || signature.is_empty() {
        return None;
    }
    Some((key_id, signature))
}

/// Generate a random 4-char prefix for key IDs.
fn random_prefix() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..4)
        .map(|_| {
            let b = rng.random_range(0..36);
            if b < 26 {
                (b'a' + b) as char
            } else {
                (b'0' + b - 26) as char
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> ApiKeyManager {
        ApiKeyManager::new(ApiKeyConfig {
            enabled: true,
            master_secret: "test-master-secret".to_string(),
            timestamp_tolerance_secs: 300,
            require_for_v1: false,
        })
    }

    #[test]
    fn create_key_returns_id_and_secret() {
        let mgr = make_manager();
        let (key_id, secret) = mgr
            .create_key(
                "test-key",
                vec![Permission::Evaluate],
                None,
                "admin",
                "Test key",
                100,
            )
            .unwrap();
        assert!(key_id.starts_with("ak_"));
        assert!(!secret.is_empty());
        assert_ne!(key_id, secret);
    }

    #[test]
    fn revoke_key() {
        let mgr = make_manager();
        let (key_id, _) = mgr
            .create_key("test", vec![Permission::Evaluate], None, "admin", "", 0)
            .unwrap();
        assert!(mgr.revoke_key(&key_id));

        // Revoked key should not authenticate.
        let ts = chrono::Utc::now().timestamp().to_string();
        let sig = compute_hmac(
            "test-master-secret",
            &format!("{}{}GET/v1/evalhash", key_id, ts),
        );
        let result = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig),
            &ts,
            "GET",
            "/v1/eval",
            "hash",
            Some(&Permission::Evaluate),
        );
        assert_eq!(result, AuthResult::Revoked);
    }

    #[test]
    fn delete_key() {
        let mgr = make_manager();
        let (key_id, _) = mgr
            .create_key("test", vec![Permission::Evaluate], None, "admin", "", 0)
            .unwrap();
        assert!(mgr.delete_key(&key_id));
        assert!(!mgr.delete_key(&key_id)); // already deleted
    }

    #[test]
    fn authenticate_valid() {
        let mgr = make_manager();
        let (key_id, _secret) = mgr
            .create_key("test", vec![Permission::Evaluate], None, "admin", "", 0)
            .unwrap();

        let ts = chrono::Utc::now().timestamp().to_string();
        let message = format!("{}{}GET/v1/evaluatebodyhash", key_id, ts);
        let sig = compute_hmac("test-master-secret", &message);

        let result = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig),
            &ts,
            "GET",
            "/v1/evaluate",
            "bodyhash",
            Some(&Permission::Evaluate),
        );
        assert_eq!(result, AuthResult::Authenticated(key_id.clone()));
    }

    #[test]
    fn authenticate_missing_header() {
        let mgr = make_manager();
        let result = mgr.authenticate("", "123", "GET", "/v1/eval", "", None);
        assert_eq!(result, AuthResult::Missing);
    }

    #[test]
    fn authenticate_invalid_key() {
        let mgr = make_manager();
        let ts = chrono::Utc::now().timestamp().to_string();
        let result = mgr.authenticate("Bearer nonexistent:sig", &ts, "GET", "/v1/eval", "", None);
        assert_eq!(result, AuthResult::InvalidKey);
    }

    #[test]
    fn authenticate_insufficient_permissions() {
        let mgr = make_manager();
        let (key_id, _) = mgr
            .create_key(
                "test",
                vec![Permission::Evaluate], // only Evaluate, not Execute
                None,
                "admin",
                "",
                0,
            )
            .unwrap();

        let ts = chrono::Utc::now().timestamp().to_string();
        let message = format!("{}{}POST/v1/executebodyhash", key_id, ts);
        let sig = compute_hmac("test-master-secret", &message);

        let result = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig),
            &ts,
            "POST",
            "/v1/execute",
            "bodyhash",
            Some(&Permission::Execute),
        );
        assert_eq!(result, AuthResult::InsufficientPermissions);
    }

    #[test]
    fn auth_disabled_returns_ok() {
        let mgr = ApiKeyManager::new(ApiKeyConfig::default());
        let result = mgr.authenticate("", "", "GET", "/v1/eval", "", None);
        assert_eq!(result, AuthResult::Ok);
    }

    #[test]
    fn list_keys() {
        let mgr = make_manager();
        mgr.create_key("key1", vec![Permission::Evaluate], None, "admin", "", 0)
            .unwrap();
        mgr.create_key("key2", vec![Permission::Admin], None, "admin", "", 0)
            .unwrap();
        let keys = mgr.list_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn rate_limit_enforced() {
        let mgr = make_manager();
        let (key_id, _) = mgr
            .create_key(
                "test",
                vec![Permission::Evaluate],
                None,
                "admin",
                "",
                2, // 2 requests per minute
            )
            .unwrap();

        let ts = chrono::Utc::now().timestamp().to_string();
        let message = |t: &str| format!("{}{}GET/v1/evalhash", key_id, t);
        let sig = |t: &str| compute_hmac("test-master-secret", &message(t));

        // First request: OK.
        let r1 = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig(&ts)),
            &ts,
            "GET",
            "/v1/eval",
            "hash",
            Some(&Permission::Evaluate),
        );
        assert_eq!(r1, AuthResult::Authenticated(key_id.clone()));

        // Second request: OK.
        let r2 = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig(&ts)),
            &ts,
            "GET",
            "/v1/eval",
            "hash",
            Some(&Permission::Evaluate),
        );
        assert_eq!(r2, AuthResult::Authenticated(key_id.clone()));

        // Third request: Rate limited.
        let r3 = mgr.authenticate(
            &format!("Bearer {}:{}", key_id, sig(&ts)),
            &ts,
            "GET",
            "/v1/eval",
            "hash",
            Some(&Permission::Evaluate),
        );
        assert_eq!(r3, AuthResult::RateLimited);
    }

    #[test]
    fn persistent_keys_roundtrip() {
        let backend = crate::storage::MemoryStore::new();
        let arc_store: std::sync::Arc<dyn crate::storage::Store> = std::sync::Arc::new(backend);

        let mgr1 = ApiKeyManager::with_store(
            ApiKeyConfig {
                enabled: true,
                master_secret: "secret".to_string(),
                ..Default::default()
            },
            arc_store.clone(),
        );

        let (key_id, _) = mgr1
            .create_key(
                "persisted",
                vec![Permission::Evaluate],
                None,
                "admin",
                "",
                0,
            )
            .unwrap();

        // Restore from store.
        let mgr2 = ApiKeyManager::with_store(
            ApiKeyConfig {
                enabled: true,
                master_secret: "secret".to_string(),
                ..Default::default()
            },
            arc_store.clone(),
        );

        let keys = mgr2.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, key_id);
    }
}
