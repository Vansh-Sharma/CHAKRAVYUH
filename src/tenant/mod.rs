// Multi-Tenancy System — Tenant isolation, per-tenant policies, quotas
//
// Provides tenant context propagation through all 9 rings of the CHAKRAVYUH
// security gateway. Each tenant is isolated with its own policy overrides,
// resource quotas, and risk tolerance settings.
//
// Architecture:
//   - `TenantManager` is the top-level registry for all tenants
//   - `TenantContext` carries identity through ring evaluation
//   - `TenantPolicyEngine` evaluates per-tenant policy overrides
//   - `QuotaEnforcer` tracks and enforces resource usage quotas
//
// Thread Safety: All shared state is protected by `RwLock`.
// Performance: Tenant lookup is O(1) via HashMap; no hot-path allocations.

pub mod tenant_context;
pub mod tenant_policy;
pub mod tenant_quota;

pub use tenant_context::*;
pub use tenant_policy::*;
pub use tenant_quota::*;

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TenantConfig — full configuration for a registered tenant
// ---------------------------------------------------------------------------

/// Complete configuration for a registered tenant, including context,
/// policy overrides, and resource quotas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Tenant identity context.
    pub context: TenantContext,
    /// Per-tenant policy overrides.
    pub policy_config: TenantPolicyConfig,
    /// Per-tenant resource quota limits.
    pub quota: ResourceQuota,
}

impl TenantConfig {
    /// Create a new TenantConfig from components.
    pub fn new(
        context: TenantContext,
        policy_config: TenantPolicyConfig,
        quota: ResourceQuota,
    ) -> Self {
        TenantConfig {
            context,
            policy_config,
            quota,
        }
    }

    /// Create a TenantConfig with tier-appropriate defaults.
    pub fn for_tier(tenant_id: TenantId, tenant_name: impl Into<String>, tier: TenantTier) -> Self {
        let context = TenantContext::new(tenant_id.clone(), tenant_name, tier);
        let policy_config = TenantPolicyStore::default_for_tier(tier);
        let quota = TierQuotaDefaults::for_tier(tier);
        TenantConfig {
            context,
            policy_config,
            quota,
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant — a registered tenant with its active engines
// ---------------------------------------------------------------------------

/// A registered tenant with its active policy engine and quota enforcer.
pub struct Tenant {
    /// Tenant configuration (immutable identity).
    config: TenantConfig,
    /// Active policy engine for this tenant.
    policy_engine: TenantPolicyEngine,
    /// Active quota enforcer for this tenant.
    quota_enforcer: QuotaEnforcer,
}

impl Tenant {
    /// Create a new Tenant from a TenantConfig.
    pub fn new(config: TenantConfig) -> Self {
        let policy_engine = TenantPolicyEngine::new(config.policy_config.clone());
        let quota_enforcer = QuotaEnforcer::new(config.quota.clone());
        Tenant {
            config,
            policy_engine,
            quota_enforcer,
        }
    }

    /// Get a reference to the tenant's context.
    pub fn context(&self) -> &TenantContext {
        &self.config.context
    }

    /// Get a mutable reference to the tenant's context.
    pub fn context_mut(&mut self) -> &mut TenantContext {
        &mut self.config.context
    }

    /// Get a reference to the tenant's policy engine.
    pub fn policy_engine(&self) -> &TenantPolicyEngine {
        &self.policy_engine
    }

    /// Get a reference to the tenant's quota enforcer.
    pub fn quota_enforcer(&self) -> &QuotaEnforcer {
        &self.quota_enforcer
    }

    /// Get a reference to the tenant's configuration.
    pub fn config(&self) -> &TenantConfig {
        &self.config
    }

    /// Get the tenant's tier.
    pub fn tier(&self) -> TenantTier {
        self.config.context.tier
    }

    /// Get the tenant's ID.
    pub fn id(&self) -> &TenantId {
        &self.config.context.tenant_id
    }
}

// ---------------------------------------------------------------------------
// TenantManager — top-level tenant registry
// ---------------------------------------------------------------------------

/// Central registry for all tenants in the CHAKRAVYUH system.
///
/// Provides O(1) lookup by tenant ID, registration, removal, and listing.
/// All access is thread-safe via `RwLock`.
pub struct TenantManager {
    tenants: RwLock<HashMap<String, Tenant>>,
}

impl TenantManager {
    /// Create a new empty tenant manager.
    pub fn new() -> Self {
        TenantManager {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new tenant. Returns an error string if a tenant with
    /// the same ID already exists.
    pub fn register_tenant(&self, config: TenantConfig) -> Result<(), String> {
        let id = config.context.tenant_id.0.clone();
        let mut tenants = self.tenants.write().unwrap();
        if tenants.contains_key(&id) {
            return Err(format!("tenant '{}' already registered", id));
        }
        tenants.insert(id.clone(), Tenant::new(config));
        Ok(())
    }

    /// Register a tenant with tier-appropriate defaults.
    pub fn register_tenant_with_tier(
        &self,
        tenant_id: TenantId,
        tenant_name: impl Into<String>,
        tier: TenantTier,
    ) -> Result<(), String> {
        let config = TenantConfig::for_tier(tenant_id, tenant_name, tier);
        self.register_tenant(config)
    }

    /// Get a tenant by ID. Returns a clone of the tenant's context.
    pub fn get_tenant(&self, tenant_id: &str) -> Option<TenantContext> {
        let tenants = self.tenants.read().unwrap();
        tenants.get(tenant_id).map(|t| t.config.context.clone())
    }

    /// Get a tenant's policy engine reference (via closure to avoid lock issues).
    /// The closure receives a reference to the `TenantPolicyEngine`.
    pub fn with_policy_engine<F, R>(&self, tenant_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TenantPolicyEngine) -> R,
    {
        let tenants = self.tenants.read().unwrap();
        tenants.get(tenant_id).map(|t| f(&t.policy_engine))
    }

    /// Get a tenant's quota enforcer reference (via closure).
    pub fn with_quota_enforcer<F, R>(&self, tenant_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&QuotaEnforcer) -> R,
    {
        let tenants = self.tenants.read().unwrap();
        tenants.get(tenant_id).map(|t| f(&t.quota_enforcer))
    }

    /// Remove a tenant by ID. Returns true if it existed.
    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        let mut tenants = self.tenants.write().unwrap();
        tenants.remove(tenant_id).is_some()
    }

    /// List all registered tenant IDs.
    pub fn list_tenant_ids(&self) -> Vec<String> {
        let tenants = self.tenants.read().unwrap();
        tenants.keys().cloned().collect()
    }

    /// List all registered tenant contexts.
    pub fn list_tenants(&self) -> Vec<TenantContext> {
        let tenants = self.tenants.read().unwrap();
        tenants.values().map(|t| t.config.context.clone()).collect()
    }

    /// Check if a tenant is registered.
    pub fn is_registered(&self, tenant_id: &str) -> bool {
        let tenants = self.tenants.read().unwrap();
        tenants.contains_key(tenant_id)
    }

    /// Get the number of registered tenants.
    pub fn count(&self) -> usize {
        let tenants = self.tenants.read().unwrap();
        tenants.len()
    }

    /// Check if a tenant is registered, returning the system default if not.
    pub fn get_tenant_or_default(&self, tenant_id: &str) -> TenantContext {
        self.get_tenant(tenant_id)
            .unwrap_or_else(TenantContext::system_default)
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── TenantConfig tests ──

    #[test]
    fn tenant_config_new() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        let policy = TenantPolicyConfig::default();
        let quota = ResourceQuota::default();
        let config = TenantConfig::new(ctx, policy, quota);
        assert_eq!(config.context.tenant_id.0, "acme");
    }

    #[test]
    fn tenant_config_for_tier() {
        let config = TenantConfig::for_tier(
            TenantId("acme".to_string()),
            "ACME Corp",
            TenantTier::Premium,
        );
        assert_eq!(config.context.tier, TenantTier::Premium);
        assert_eq!(config.policy_config.override_deny_threshold, Some(8.5));
        assert_eq!(config.quota.max_requests_per_day, 100_000);
    }

    #[test]
    fn tenant_config_serialization() {
        let config = TenantConfig::for_tier(TenantId("acme".to_string()), "ACME", TenantTier::Free);
        let json = serde_json::to_string(&config).unwrap();
        let decoded: TenantConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.context.tenant_id.0, "acme");
    }

    // ── Tenant tests ──

    #[test]
    fn tenant_new() {
        let config =
            TenantConfig::for_tier(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        let tenant = Tenant::new(config);
        assert_eq!(tenant.id().0, "acme");
        assert_eq!(tenant.tier(), TenantTier::Standard);
    }

    #[test]
    fn tenant_context_access() {
        let mut config =
            TenantConfig::for_tier(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        config.context.set_metadata("env", "production");
        let tenant = Tenant::new(config);
        assert_eq!(tenant.context().metadata.get("env").unwrap(), "production");
    }

    // ── TenantManager tests ──

    #[test]
    fn manager_new_empty() {
        let mgr = TenantManager::new();
        assert_eq!(mgr.count(), 0);
        assert!(mgr.list_tenant_ids().is_empty());
    }

    #[test]
    fn manager_register_and_get() {
        let mgr = TenantManager::new();
        let config =
            TenantConfig::for_tier(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        mgr.register_tenant(config).unwrap();
        assert!(mgr.is_registered("acme"));
        assert!(!mgr.is_registered("other"));

        let ctx = mgr.get_tenant("acme").unwrap();
        assert_eq!(ctx.tenant_id.0, "acme");
    }

    #[test]
    fn manager_register_duplicate_fails() {
        let mgr = TenantManager::new();
        let config =
            TenantConfig::for_tier(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        assert!(mgr.register_tenant(config).is_ok());
        let config2 =
            TenantConfig::for_tier(TenantId("acme".to_string()), "ACME Dup", TenantTier::Free);
        assert!(mgr.register_tenant(config2).is_err());
    }

    #[test]
    fn manager_register_with_tier() {
        let mgr = TenantManager::new();
        mgr.register_tenant_with_tier(
            TenantId("globex".to_string()),
            "Globex",
            TenantTier::Enterprise,
        )
        .unwrap();
        let ctx = mgr.get_tenant("globex").unwrap();
        assert_eq!(ctx.tier, TenantTier::Enterprise);
    }

    #[test]
    fn manager_remove() {
        let mgr = TenantManager::new();
        mgr.register_tenant_with_tier(TenantId("acme".to_string()), "ACME", TenantTier::Free)
            .unwrap();
        assert!(mgr.remove_tenant("acme"));
        assert!(!mgr.remove_tenant("acme"));
        assert!(!mgr.is_registered("acme"));
    }

    #[test]
    fn manager_list_tenants() {
        let mgr = TenantManager::new();
        mgr.register_tenant_with_tier(TenantId("a".to_string()), "A", TenantTier::Free)
            .unwrap();
        mgr.register_tenant_with_tier(TenantId("b".to_string()), "B", TenantTier::Standard)
            .unwrap();
        assert_eq!(mgr.count(), 2);
        let ids = mgr.list_tenant_ids();
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
    }

    #[test]
    fn manager_get_tenant_or_default() {
        let mgr = TenantManager::new();
        let ctx = mgr.get_tenant_or_default("nonexistent");
        assert_eq!(ctx.tenant_id.0, "system-default");
    }

    #[test]
    fn manager_with_policy_engine() {
        let mgr = TenantManager::new();
        mgr.register_tenant_with_tier(TenantId("acme".to_string()), "ACME", TenantTier::Premium)
            .unwrap();

        let result = mgr.with_policy_engine("acme", |engine| {
            engine.effective_deny_threshold(&TenantContext::system_default())
        });
        assert_eq!(result, Some(8.5));
    }

    #[test]
    fn manager_with_quota_enforcer() {
        let mgr = TenantManager::new();
        mgr.register_tenant_with_tier(TenantId("acme".to_string()), "ACME", TenantTier::Free)
            .unwrap();

        let result =
            mgr.with_quota_enforcer("acme", |enforcer| enforcer.quota().max_requests_per_day);
        assert_eq!(result, Some(1_000));
    }
}
