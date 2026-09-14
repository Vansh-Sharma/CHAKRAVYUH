// Tenant Context Propagation
//
// Tenant context propagation through all 9 rings of the CHAKRAVYUH gateway.
// Each ring evaluation receives a TenantContext that carries tenant identity,
// tier, risk tolerance, and metadata. Context is extracted from incoming
// request headers and injected into downstream ring calls.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TenantId — newtype wrapper for tenant identifiers
// ---------------------------------------------------------------------------

/// Unique tenant identifier. Must be alphanumeric + hyphens, 3-64 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    /// Validate that the inner string is a legal tenant ID.
    ///
    /// Rules:
    /// - length 3..=64
    /// - only ASCII alphanumeric characters and hyphens
    /// - must not start or end with a hyphen
    /// - must not contain two consecutive hyphens
    pub fn is_valid(&self) -> bool {
        let s = &self.0;
        if s.len() < 3 || s.len() > 64 {
            return false;
        }
        if s.starts_with('-') || s.ends_with('-') {
            return false;
        }
        if s.contains("--") {
            return false;
        }
        s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        TenantId(s.to_string())
    }
}

impl From<String> for TenantId {
    fn from(s: String) -> Self {
        TenantId(s)
    }
}

impl From<TenantId> for String {
    fn from(id: TenantId) -> Self {
        id.0
    }
}

impl FromStr for TenantId {
    type Err = TenantIdParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let id = TenantId(s.to_string());
        if id.is_valid() {
            Ok(id)
        } else {
            Err(TenantIdParseError {
                input: s.to_string(),
            })
        }
    }
}

/// Error returned when a tenant ID fails validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantIdParseError {
    pub input: String,
}

impl fmt::Display for TenantIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid tenant ID {:?}: must be 3-64 alphanumeric/hyphen characters",
            self.input
        )
    }
}

impl std::error::Error for TenantIdParseError {}

// ---------------------------------------------------------------------------
// TenantTier — service tier for a tenant
// ---------------------------------------------------------------------------

/// Service tier determines default risk tolerance, quotas, and feature access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TenantTier {
    Free,
    Standard,
    Premium,
    Enterprise,
}

impl TenantTier {
    /// Default risk tolerance for this tier (0.0-10.0 scale).
    pub fn default_risk_tolerance(&self) -> f64 {
        match self {
            TenantTier::Free => 5.0,
            TenantTier::Standard => 7.0,
            TenantTier::Premium => 8.0,
            TenantTier::Enterprise => 10.0,
        }
    }

    /// Parse a tier from a case-insensitive string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "free" => Some(TenantTier::Free),
            "standard" => Some(TenantTier::Standard),
            "premium" => Some(TenantTier::Premium),
            "enterprise" => Some(TenantTier::Enterprise),
            _ => None,
        }
    }
}

impl fmt::Display for TenantTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenantTier::Free => write!(f, "free"),
            TenantTier::Standard => write!(f, "standard"),
            TenantTier::Premium => write!(f, "premium"),
            TenantTier::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl Default for TenantTier {
    fn default() -> Self {
        TenantTier::Free
    }
}

// ---------------------------------------------------------------------------
// TenantScope — capability scopes for tenants (bitflag-style via u32)
// ---------------------------------------------------------------------------

/// Tenant scopes control what actions a tenant can perform.
/// Uses a u32 bitflag representation so scopes can be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantScope {
    bits: u32,
}

impl TenantScope {
    /// No permissions.
    pub const NONE: u32 = 0;
    /// Read access to resources.
    pub const READ: u32 = 1 << 0;
    /// Write access to resources.
    pub const WRITE: u32 = 1 << 1;
    /// Full administrative access.
    pub const ADMIN: u32 = 1 << 2;
    /// Execute tool calls / code execution.
    pub const EXECUTE: u32 = 1 << 3;
    /// Manage users within tenant.
    pub const MANAGE_USERS: u32 = 1 << 4;
    /// View audit logs and trails.
    pub const VIEW_AUDIT: u32 = 1 << 5;

    /// Create an empty scope set.
    pub const fn empty() -> Self {
        TenantScope { bits: 0 }
    }

    /// Create a scope set from a raw bitmask.
    pub const fn from_bits(bits: u32) -> Self {
        TenantScope { bits }
    }

    /// Get the raw bitmask.
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Add a scope.
    pub fn add(&mut self, scope: u32) {
        self.bits |= scope;
    }

    /// Remove a scope.
    pub fn remove(&mut self, scope: u32) {
        self.bits &= !scope;
    }

    /// Check if a scope is present.
    pub fn has(&self, scope: u32) -> bool {
        (self.bits & scope) != 0
    }

    /// Check if any of the given scopes are present.
    pub fn has_any(&self, scopes: u32) -> bool {
        (self.bits & scopes) != 0
    }

    /// Merge two scope sets.
    pub fn union(&self, other: &TenantScope) -> TenantScope {
        TenantScope {
            bits: self.bits | other.bits,
        }
    }

    /// Default scopes for each tier.
    pub fn default_for_tier(tier: TenantTier) -> TenantScope {
        match tier {
            TenantTier::Free => TenantScope::from_bits(Self::READ),
            TenantTier::Standard => {
                TenantScope::from_bits(Self::READ | Self::WRITE | Self::EXECUTE | Self::VIEW_AUDIT)
            }
            TenantTier::Premium => TenantScope::from_bits(
                Self::READ | Self::WRITE | Self::EXECUTE | Self::VIEW_AUDIT | Self::MANAGE_USERS,
            ),
            TenantTier::Enterprise => TenantScope::from_bits(
                Self::READ
                    | Self::WRITE
                    | Self::ADMIN
                    | Self::EXECUTE
                    | Self::VIEW_AUDIT
                    | Self::MANAGE_USERS,
            ),
        }
    }

    /// Scope name constants as a mapping for validation.
    pub fn scope_name_to_bit(name: &str) -> Option<u32> {
        match name.to_ascii_lowercase().as_str() {
            "read" => Some(Self::READ),
            "write" => Some(Self::WRITE),
            "admin" => Some(Self::ADMIN),
            "execute" => Some(Self::EXECUTE),
            "manage_users" | "manageusers" => Some(Self::MANAGE_USERS),
            "view_audit" | "viewaudit" => Some(Self::VIEW_AUDIT),
            _ => None,
        }
    }
}

impl Default for TenantScope {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for TenantScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.has(Self::READ) {
            parts.push("READ");
        }
        if self.has(Self::WRITE) {
            parts.push("WRITE");
        }
        if self.has(Self::ADMIN) {
            parts.push("ADMIN");
        }
        if self.has(Self::EXECUTE) {
            parts.push("EXECUTE");
        }
        if self.has(Self::MANAGE_USERS) {
            parts.push("MANAGE_USERS");
        }
        if self.has(Self::VIEW_AUDIT) {
            parts.push("VIEW_AUDIT");
        }
        if parts.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

// ---------------------------------------------------------------------------
// TenantAuditEntry — audit record for tenant-scoped actions
// ---------------------------------------------------------------------------

/// A single audit trail entry scoped to a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantAuditEntry {
    /// Tenant that performed the action.
    pub tenant_id: TenantId,
    /// Action name (e.g., "tool_call", "policy_eval", "ring_pass").
    pub action: String,
    /// Outcome (e.g., "allowed", "denied", "challenged").
    pub outcome: String,
    /// RFC3339 timestamp.
    pub timestamp: String,
    /// Correlation ID for the request.
    pub request_id: String,
    /// Ring name where this audit entry was generated.
    pub ring_name: String,
}

impl TenantAuditEntry {
    /// Create a new audit entry.
    pub fn new(
        tenant_id: TenantId,
        action: impl Into<String>,
        outcome: impl Into<String>,
        request_id: impl Into<String>,
        ring_name: impl Into<String>,
    ) -> Self {
        TenantAuditEntry {
            tenant_id,
            action: action.into(),
            outcome: outcome.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.into(),
            ring_name: ring_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TenantContext — full tenant identity for ring evaluation
// ---------------------------------------------------------------------------

/// Full tenant context propagated through all 9 rings of CHAKRAVYUH.
///
/// Carries tenant identity, tier, risk tolerance, metadata, labels, and
/// internal status. Extracted from incoming request headers by
/// [`TenantContextExtractor`] and injected into downstream ring calls by
/// [`TenantPropagation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    /// Unique tenant identifier.
    pub tenant_id: TenantId,
    /// Human-readable tenant name.
    pub tenant_name: String,
    /// Service tier (determines defaults).
    pub tier: TenantTier,
    /// RFC3339 creation timestamp.
    pub created_at: String,
    /// Freeform metadata key-value pairs.
    pub metadata: HashMap<String, String>,
    /// Labels used for policy matching.
    pub labels: HashMap<String, String>,
    /// Geographic region (e.g., "us-east-1").
    pub region: Option<String>,
    /// Maximum risk tolerance (0.0-10.0). Higher = more permissive.
    pub max_risk_tolerance: f64,
    /// Internal tenants bypass certain security checks.
    pub is_internal: bool,
    /// Granted scopes for this tenant.
    pub scopes: TenantScope,
}

impl TenantContext {
    /// Create a new TenantContext with the given ID and name.
    pub fn new(id: TenantId, name: impl Into<String>, tier: TenantTier) -> Self {
        let tolerance = tier.default_risk_tolerance();
        TenantContext {
            tenant_id: id,
            tenant_name: name.into(),
            tier,
            created_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::new(),
            labels: HashMap::new(),
            region: None,
            max_risk_tolerance: tolerance,
            is_internal: false,
            scopes: TenantScope::default_for_tier(tier),
        }
    }

    /// Create the system default tenant context (anonymous / unauthenticated).
    pub fn system_default() -> Self {
        TenantContext {
            tenant_id: TenantId("system-default".to_string()),
            tenant_name: "System Default".to_string(),
            tier: TenantTier::Free,
            created_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::new(),
            labels: HashMap::new(),
            region: None,
            max_risk_tolerance: TenantTier::Free.default_risk_tolerance(),
            is_internal: false,
            scopes: TenantScope::default_for_tier(TenantTier::Free),
        }
    }

    /// Check whether the tenant's risk tolerance can accommodate the given risk.
    pub fn can_accept_risk(&self, risk_score: f64) -> bool {
        risk_score <= self.max_risk_tolerance
    }

    /// Set a metadata key-value pair.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Set a label key-value pair (for policy matching).
    pub fn set_label(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.labels.insert(key.into(), value.into());
    }

    /// Check if the tenant has a specific label.
    pub fn has_label(&self, key: &str) -> bool {
        self.labels.contains_key(key)
    }

    /// Get a label value.
    pub fn get_label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(|s| s.as_str())
    }

    /// Check if the tenant has a specific scope.
    pub fn has_scope(&self, scope: u32) -> bool {
        self.scopes.has(scope)
    }

    /// Clamp risk tolerance to the 0.0-10.0 range.
    pub fn clamp_risk_tolerance(&mut self) {
        self.max_risk_tolerance = self.max_risk_tolerance.clamp(0.0, 10.0);
    }
}

impl Default for TenantContext {
    fn default() -> Self {
        Self::system_default()
    }
}

// ---------------------------------------------------------------------------
// TenantContextExtractor — extract context from HTTP headers
// ---------------------------------------------------------------------------

/// Extracts tenant context from incoming HTTP request headers.
///
/// Looks for standard CHAKRAVYUH tenant headers:
/// - `X-Tenant-Id` — required for authenticated tenants
/// - `X-Tenant-Tier` — optional, defaults to Free if absent
/// - `X-Tenant-Region` — optional
/// - `X-Tenant-Internal` — optional, "true" marks tenant as internal
///
/// Returns `None` when no tenant headers are present, indicating
/// an anonymous request that should use the system default context.
pub struct TenantContextExtractor;

impl TenantContextExtractor {
    /// Tenant ID header name.
    pub const HEADER_TENANT_ID: &str = "x-tenant-id";
    /// Tenant tier header name.
    pub const HEADER_TENANT_TIER: &str = "x-tenant-tier";
    /// Tenant region header name.
    pub const HEADER_TENANT_REGION: &str = "x-tenant-region";
    /// Tenant internal flag header name.
    pub const HEADER_TENANT_INTERNAL: &str = "x-tenant-internal";

    /// Extract tenant context from request headers.
    ///
    /// Returns `None` if no tenant headers are present (anonymous request).
    /// Returns `Some(context)` if at least `X-Tenant-Id` is present and valid.
    /// If the tenant ID is invalid (bad format), returns `None`.
    pub fn extract(headers: &axum::http::HeaderMap) -> Option<TenantContext> {
        let tenant_id_header = headers.get(Self::HEADER_TENANT_ID)?;
        let tenant_id_str = tenant_id_header.to_str().ok()?;

        // Validate format
        let parsed_id = TenantId::from_str(tenant_id_str).ok()?;

        // Parse tier (default to Free)
        let tier = headers
            .get(Self::HEADER_TENANT_TIER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| TenantTier::from_str_loose(s))
            .unwrap_or(TenantTier::Free);

        // Parse region
        let region = headers
            .get(Self::HEADER_TENANT_REGION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Parse internal flag
        let is_internal = headers
            .get(Self::HEADER_TENANT_INTERNAL)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut ctx = TenantContext::new(parsed_id.clone(), parsed_id.0.clone(), tier);
        ctx.region = region;
        ctx.is_internal = is_internal;

        Some(ctx)
    }

    /// Check whether the given headers contain any tenant-specific headers.
    pub fn has_tenant_headers(headers: &axum::http::HeaderMap) -> bool {
        headers.get(Self::HEADER_TENANT_ID).is_some()
    }
}

// ---------------------------------------------------------------------------
// TenantPropagation — inject context into downstream ring calls
// ---------------------------------------------------------------------------

/// Propagates tenant context through ring evaluation chains.
///
/// Generates downstream HTTP headers from a TenantContext and provides
/// scope validation and audit trail generation utilities.
pub struct TenantPropagation;

impl TenantPropagation {
    /// Inject tenant context into a set of HTTP headers for downstream calls.
    ///
    /// This creates a new `HeaderMap` with all tenant headers populated
    /// so downstream rings can extract the same tenant context.
    pub fn inject_headers(ctx: &TenantContext) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            TenantContextExtractor::HEADER_TENANT_ID,
            axum::http::HeaderValue::from_str(&ctx.tenant_id.0)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("unknown")),
        );
        headers.insert(
            TenantContextExtractor::HEADER_TENANT_TIER,
            axum::http::HeaderValue::from_static(ctx.tier.display_name()),
        );
        if let Some(ref region) = ctx.region {
            if let Ok(val) = axum::http::HeaderValue::from_str(region) {
                headers.insert(TenantContextExtractor::HEADER_TENANT_REGION, val);
            }
        }
        if ctx.is_internal {
            headers.insert(
                TenantContextExtractor::HEADER_TENANT_INTERNAL,
                axum::http::HeaderValue::from_static("true"),
            );
        }
        headers
    }

    /// Validate that a tenant has the required scope.
    ///
    /// The `required_scope` parameter accepts scope names like
    /// "read", "write", "admin", "execute", "manage_users", "view_audit".
    pub fn validate_scope(ctx: &TenantContext, required_scope: &str) -> bool {
        match TenantScope::scope_name_to_bit(required_scope) {
            Some(bit) => ctx.scopes.has(bit),
            None => false,
        }
    }

    /// Create an audit trail entry for a tenant action within a ring.
    pub fn audit_trail_entry(ctx: &TenantContext, action: &str, outcome: &str) -> TenantAuditEntry {
        TenantAuditEntry::new(
            ctx.tenant_id.clone(),
            action,
            outcome,
            uuid::Uuid::new_v4().to_string(),
            "propagation",
        )
    }

    /// Create an audit trail entry with an explicit ring name.
    pub fn audit_trail_entry_for_ring(
        ctx: &TenantContext,
        action: &str,
        outcome: &str,
        ring_name: &str,
    ) -> TenantAuditEntry {
        TenantAuditEntry::new(
            ctx.tenant_id.clone(),
            action,
            outcome,
            uuid::Uuid::new_v4().to_string(),
            ring_name,
        )
    }
}

// ---------------------------------------------------------------------------
// TenantTier helper: display name for header injection
// ---------------------------------------------------------------------------

impl TenantTier {
    /// Return the display name suitable for HTTP headers.
    fn display_name(&self) -> &'static str {
        match self {
            TenantTier::Free => "free",
            TenantTier::Standard => "standard",
            TenantTier::Premium => "premium",
            TenantTier::Enterprise => "enterprise",
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    // ── TenantId tests ──

    #[test]
    fn tenant_id_valid_basic() {
        let id = TenantId("acme-corp".to_string());
        assert!(id.is_valid());
    }

    #[test]
    fn tenant_id_valid_numeric() {
        let id = TenantId("tenant-12345".to_string());
        assert!(id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_too_short() {
        let id = TenantId("ab".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_too_long() {
        let id = TenantId("a".repeat(65));
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_start_with_hyphen() {
        let id = TenantId("-tenant".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_end_with_hyphen() {
        let id = TenantId("tenant-".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_double_hyphen() {
        let id = TenantId("tenant--corp".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_special_chars() {
        let id = TenantId("tenant_corp".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_invalid_spaces() {
        let id = TenantId("tenant corp".to_string());
        assert!(!id.is_valid());
    }

    #[test]
    fn tenant_id_from_str_valid() {
        let id: TenantId = "acme-corp".parse().unwrap();
        assert_eq!(id.0, "acme-corp");
    }

    #[test]
    fn tenant_id_from_str_invalid() {
        let result: std::result::Result<TenantId, TenantIdParseError> = "ab".parse();
        assert!(result.is_err());
    }

    #[test]
    fn tenant_id_from_string() {
        let id = TenantId::from("hello-world".to_string());
        assert_eq!(id.0, "hello-world");
    }

    #[test]
    fn tenant_id_display() {
        let id = TenantId("acme".to_string());
        assert_eq!(format!("{id}"), "acme");
    }

    #[test]
    fn tenant_id_into_string() {
        let id = TenantId("acme".to_string());
        let s: String = id.into();
        assert_eq!(s, "acme");
    }

    // ── TenantTier tests ──

    #[test]
    fn tier_default_risk_tolerance() {
        assert_eq!(TenantTier::Free.default_risk_tolerance(), 5.0);
        assert_eq!(TenantTier::Standard.default_risk_tolerance(), 7.0);
        assert_eq!(TenantTier::Premium.default_risk_tolerance(), 8.0);
        assert_eq!(TenantTier::Enterprise.default_risk_tolerance(), 10.0);
    }

    #[test]
    fn tier_from_str_loose() {
        assert_eq!(TenantTier::from_str_loose("Free"), Some(TenantTier::Free));
        assert_eq!(
            TenantTier::from_str_loose("STANDARD"),
            Some(TenantTier::Standard)
        );
        assert_eq!(
            TenantTier::from_str_loose("Premium"),
            Some(TenantTier::Premium)
        );
        assert_eq!(
            TenantTier::from_str_loose("ENTERPRISE"),
            Some(TenantTier::Enterprise)
        );
        assert_eq!(TenantTier::from_str_loose("unknown"), None);
    }

    #[test]
    fn tier_display() {
        assert_eq!(format!("{}", TenantTier::Free), "free");
        assert_eq!(format!("{}", TenantTier::Enterprise), "enterprise");
    }

    #[test]
    fn tier_default_is_free() {
        assert_eq!(TenantTier::default(), TenantTier::Free);
    }

    // ── TenantScope tests ──

    #[test]
    fn scope_empty() {
        let scope = TenantScope::empty();
        assert!(!scope.has(TenantScope::READ));
        assert!(!scope.has(TenantScope::WRITE));
        assert!(!scope.has(TenantScope::ADMIN));
    }

    #[test]
    fn scope_add_and_check() {
        let mut scope = TenantScope::empty();
        scope.add(TenantScope::READ);
        assert!(scope.has(TenantScope::READ));
        assert!(!scope.has(TenantScope::WRITE));
    }

    #[test]
    fn scope_remove() {
        let mut scope = TenantScope::from_bits(TenantScope::READ | TenantScope::WRITE);
        scope.remove(TenantScope::READ);
        assert!(!scope.has(TenantScope::READ));
        assert!(scope.has(TenantScope::WRITE));
    }

    #[test]
    fn scope_union() {
        let a = TenantScope::from_bits(TenantScope::READ);
        let b = TenantScope::from_bits(TenantScope::WRITE);
        let merged = a.union(&b);
        assert!(merged.has(TenantScope::READ));
        assert!(merged.has(TenantScope::WRITE));
    }

    #[test]
    fn scope_default_for_tier() {
        let free = TenantScope::default_for_tier(TenantTier::Free);
        assert!(free.has(TenantScope::READ));
        assert!(!free.has(TenantScope::WRITE));

        let enterprise = TenantScope::default_for_tier(TenantTier::Enterprise);
        assert!(enterprise.has(TenantScope::READ));
        assert!(enterprise.has(TenantScope::WRITE));
        assert!(enterprise.has(TenantScope::ADMIN));
        assert!(enterprise.has(TenantScope::EXECUTE));
        assert!(enterprise.has(TenantScope::MANAGE_USERS));
        assert!(enterprise.has(TenantScope::VIEW_AUDIT));
    }

    #[test]
    fn scope_name_to_bit() {
        assert_eq!(
            TenantScope::scope_name_to_bit("read"),
            Some(TenantScope::READ)
        );
        assert_eq!(
            TenantScope::scope_name_to_bit("WRITE"),
            Some(TenantScope::WRITE)
        );
        assert_eq!(
            TenantScope::scope_name_to_bit("admin"),
            Some(TenantScope::ADMIN)
        );
        assert_eq!(
            TenantScope::scope_name_to_bit("execute"),
            Some(TenantScope::EXECUTE)
        );
        assert_eq!(
            TenantScope::scope_name_to_bit("manage_users"),
            Some(TenantScope::MANAGE_USERS)
        );
        assert_eq!(
            TenantScope::scope_name_to_bit("view_audit"),
            Some(TenantScope::VIEW_AUDIT)
        );
        assert_eq!(TenantScope::scope_name_to_bit("unknown"), None);
    }

    #[test]
    fn scope_has_any() {
        let scope = TenantScope::from_bits(TenantScope::READ);
        assert!(scope.has_any(TenantScope::READ | TenantScope::WRITE));
        assert!(!scope.has_any(TenantScope::WRITE | TenantScope::ADMIN));
    }

    #[test]
    fn scope_display_none() {
        let scope = TenantScope::empty();
        assert_eq!(format!("{scope}"), "NONE");
    }

    #[test]
    fn scope_display_combined() {
        let scope = TenantScope::from_bits(TenantScope::READ | TenantScope::WRITE);
        let display = format!("{scope}");
        assert!(display.contains("READ"));
        assert!(display.contains("WRITE"));
    }

    // ── TenantContext tests ──

    #[test]
    fn tenant_context_new() {
        let ctx = TenantContext::new(
            TenantId("acme".to_string()),
            "ACME Corp",
            TenantTier::Standard,
        );
        assert_eq!(ctx.tenant_id.0, "acme");
        assert_eq!(ctx.tenant_name, "ACME Corp");
        assert_eq!(ctx.tier, TenantTier::Standard);
        assert_eq!(ctx.max_risk_tolerance, 7.0);
        assert!(!ctx.is_internal);
        assert!(ctx.region.is_none());
        assert!(ctx.metadata.is_empty());
        assert!(ctx.labels.is_empty());
    }

    #[test]
    fn tenant_context_system_default() {
        let ctx = TenantContext::system_default();
        assert_eq!(ctx.tenant_id.0, "system-default");
        assert_eq!(ctx.tier, TenantTier::Free);
        assert_eq!(ctx.max_risk_tolerance, 5.0);
    }

    #[test]
    fn tenant_context_default_trait() {
        let ctx = TenantContext::default();
        assert_eq!(ctx.tenant_id.0, "system-default");
    }

    #[test]
    fn tenant_context_can_accept_risk() {
        let ctx = TenantContext::system_default();
        assert!(ctx.can_accept_risk(3.0));
        assert!(ctx.can_accept_risk(5.0));
        assert!(!ctx.can_accept_risk(6.0));
    }

    #[test]
    fn tenant_context_metadata() {
        let mut ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Free);
        ctx.set_metadata("team", "engineering");
        assert_eq!(ctx.metadata.get("team").unwrap(), "engineering");
    }

    #[test]
    fn tenant_context_labels() {
        let mut ctx = TenantContext::system_default();
        ctx.set_label("env", "production");
        assert!(ctx.has_label("env"));
        assert_eq!(ctx.get_label("env"), Some("production"));
        assert!(!ctx.has_label("region"));
        assert_eq!(ctx.get_label("region"), None);
    }

    #[test]
    fn tenant_context_has_scope() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Enterprise);
        assert!(ctx.has_scope(TenantScope::ADMIN));
        assert!(ctx.has_scope(TenantScope::READ));
    }

    #[test]
    fn tenant_context_clamp_risk_tolerance() {
        let mut ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Free);
        ctx.max_risk_tolerance = 15.0;
        ctx.clamp_risk_tolerance();
        assert_eq!(ctx.max_risk_tolerance, 10.0);

        ctx.max_risk_tolerance = -3.0;
        ctx.clamp_risk_tolerance();
        assert_eq!(ctx.max_risk_tolerance, 0.0);
    }

    // ── TenantContextExtractor tests ──

    #[test]
    fn extract_no_headers_returns_none() {
        let headers = HeaderMap::new();
        assert!(TenantContextExtractor::extract(&headers).is_none());
    }

    #[test]
    fn extract_valid_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "acme-corp".parse().unwrap());
        headers.insert("x-tenant-tier", "premium".parse().unwrap());
        headers.insert("x-tenant-region", "us-east-1".parse().unwrap());
        headers.insert("x-tenant-internal", "true".parse().unwrap());

        let ctx = TenantContextExtractor::extract(&headers).unwrap();
        assert_eq!(ctx.tenant_id.0, "acme-corp");
        assert_eq!(ctx.tier, TenantTier::Premium);
        assert_eq!(ctx.region.as_deref(), Some("us-east-1"));
        assert!(ctx.is_internal);
    }

    #[test]
    fn extract_id_only_defaults_tier_to_free() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "acme".parse().unwrap());

        let ctx = TenantContextExtractor::extract(&headers).unwrap();
        assert_eq!(ctx.tier, TenantTier::Free);
        assert!(ctx.region.is_none());
        assert!(!ctx.is_internal);
    }

    #[test]
    fn extract_invalid_id_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "ab".parse().unwrap());

        assert!(TenantContextExtractor::extract(&headers).is_none());
    }

    #[test]
    fn extract_invalid_tier_defaults_to_free() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "valid-tenant".parse().unwrap());
        headers.insert("x-tenant-tier", "platinum".parse().unwrap());

        let ctx = TenantContextExtractor::extract(&headers).unwrap();
        assert_eq!(ctx.tier, TenantTier::Free);
    }

    #[test]
    fn has_tenant_headers_true() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "acme".parse().unwrap());
        assert!(TenantContextExtractor::has_tenant_headers(&headers));
    }

    #[test]
    fn has_tenant_headers_false() {
        let headers = HeaderMap::new();
        assert!(!TenantContextExtractor::has_tenant_headers(&headers));
    }

    // ── TenantPropagation tests ──

    #[test]
    fn propagation_inject_headers() {
        let mut ctx =
            TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        ctx.region = Some("eu-west-1".to_string());
        ctx.is_internal = true;

        let headers = TenantPropagation::inject_headers(&ctx);
        assert_eq!(headers.get("x-tenant-id").unwrap(), "acme");
        assert_eq!(headers.get("x-tenant-tier").unwrap(), "standard");
        assert_eq!(headers.get("x-tenant-region").unwrap(), "eu-west-1");
        assert_eq!(headers.get("x-tenant-internal").unwrap(), "true");
    }

    #[test]
    fn propagation_inject_headers_no_region() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Free);
        let headers = TenantPropagation::inject_headers(&ctx);
        assert!(headers.get("x-tenant-region").is_none());
        assert!(headers.get("x-tenant-internal").is_none());
    }

    #[test]
    fn propagation_validate_scope() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Enterprise);
        assert!(TenantPropagation::validate_scope(&ctx, "admin"));
        assert!(TenantPropagation::validate_scope(&ctx, "read"));
        assert!(TenantPropagation::validate_scope(&ctx, "execute"));
    }

    #[test]
    fn propagation_validate_scope_denied() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Free);
        assert!(!TenantPropagation::validate_scope(&ctx, "admin"));
        assert!(TenantPropagation::validate_scope(&ctx, "read"));
    }

    #[test]
    fn propagation_validate_unknown_scope() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Enterprise);
        assert!(!TenantPropagation::validate_scope(&ctx, "nonexistent"));
    }

    #[test]
    fn propagation_audit_trail_entry() {
        let ctx = TenantContext::new(TenantId("acme".to_string()), "ACME", TenantTier::Standard);
        let entry = TenantPropagation::audit_trail_entry(&ctx, "tool_call", "allowed");
        assert_eq!(entry.tenant_id.0, "acme");
        assert_eq!(entry.action, "tool_call");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.ring_name, "propagation");
        assert!(!entry.timestamp.is_empty());
        assert!(!entry.request_id.is_empty());
    }

    #[test]
    fn propagation_audit_trail_entry_for_ring() {
        let ctx = TenantContext::system_default();
        let entry = TenantPropagation::audit_trail_entry_for_ring(&ctx, "eval", "denied", "shield");
        assert_eq!(entry.ring_name, "shield");
        assert_eq!(entry.tenant_id.0, "system-default");
    }

    // ── TenantAuditEntry tests ──

    #[test]
    fn audit_entry_new() {
        let entry = TenantAuditEntry::new(
            TenantId("acme".to_string()),
            "action-test",
            "outcome-test",
            "req-123",
            "shield-ring",
        );
        assert_eq!(entry.tenant_id.0, "acme");
        assert_eq!(entry.action, "action-test");
        assert_eq!(entry.outcome, "outcome-test");
        assert_eq!(entry.request_id, "req-123");
        assert_eq!(entry.ring_name, "shield-ring");
        assert!(!entry.timestamp.is_empty());
    }

    #[test]
    fn audit_entry_serialization_roundtrip() {
        let entry =
            TenantAuditEntry::new(TenantId("acme".to_string()), "test", "ok", "req-1", "ring");
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: TenantAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tenant_id.0, "acme");
        assert_eq!(decoded.action, "test");
    }

    // ── Roundtrip: extract → inject ──

    #[test]
    fn roundtrip_extract_then_inject() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "roundtrip-tenant".parse().unwrap());
        headers.insert("x-tenant-tier", "enterprise".parse().unwrap());
        headers.insert("x-tenant-region", "ap-south-1".parse().unwrap());

        let ctx = TenantContextExtractor::extract(&headers).unwrap();
        let reinjected = TenantPropagation::inject_headers(&ctx);

        assert_eq!(reinjected.get("x-tenant-id").unwrap(), "roundtrip-tenant");
        assert_eq!(reinjected.get("x-tenant-tier").unwrap(), "enterprise");
        assert_eq!(reinjected.get("x-tenant-region").unwrap(), "ap-south-1");
    }
}
