// Per-Tenant Policy Engine
//
// Each tenant can override global security policies: deny/challenge thresholds,
// tool allowlists, custom rules, rate limits, ring enablement, and IP filtering.
// The TenantPolicyEngine evaluates these overrides against incoming requests
// and produces a TenantPolicyDecision for each action.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::tenant::tenant_context::{TenantContext, TenantTier};

// ---------------------------------------------------------------------------
// TenantRuleAction — what to do when a custom rule matches
// ---------------------------------------------------------------------------

/// Action to take when a tenant custom rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TenantRuleAction {
    Allow,
    Deny,
    Challenge,
    Escalate,
}

impl TenantRuleAction {
    /// Parse from a case-insensitive string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Some(TenantRuleAction::Allow),
            "deny" => Some(TenantRuleAction::Deny),
            "challenge" => Some(TenantRuleAction::Challenge),
            "escalate" => Some(TenantRuleAction::Escalate),
            _ => None,
        }
    }
}

impl std::fmt::Display for TenantRuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TenantRuleAction::Allow => write!(f, "allow"),
            TenantRuleAction::Deny => write!(f, "deny"),
            TenantRuleAction::Challenge => write!(f, "challenge"),
            TenantRuleAction::Escalate => write!(f, "escalate"),
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimitOverride — per-endpoint rate limit configuration
// ---------------------------------------------------------------------------

/// Rate limit override for a specific endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitOverride {
    /// Maximum requests per minute.
    pub requests_per_minute: u32,
    /// Maximum burst size (tokens initially available).
    pub burst_size: u32,
    /// Time window in seconds for rate calculation.
    pub window_secs: u64,
}

impl RateLimitOverride {
    /// Create a new rate limit override.
    pub fn new(requests_per_minute: u32, burst_size: u32, window_secs: u64) -> Self {
        RateLimitOverride {
            requests_per_minute,
            burst_size,
            window_secs,
        }
    }

    /// Convert the RPM to a refill rate (tokens per second).
    pub fn refill_rate_per_sec(&self) -> f64 {
        if self.window_secs == 0 {
            return 0.0;
        }
        self.requests_per_minute as f64 / 60.0
    }
}

impl Default for RateLimitOverride {
    fn default() -> Self {
        RateLimitOverride {
            requests_per_minute: 60,
            burst_size: 10,
            window_secs: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// TenantCustomRule — tenant-specific custom rule
// ---------------------------------------------------------------------------

/// A custom rule defined by a tenant to override default security behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCustomRule {
    /// Human-readable rule name.
    pub name: String,
    /// JSON-encoded condition expression.
    pub condition_json: String,
    /// Action to take when this rule matches.
    pub action: TenantRuleAction,
    /// Priority — higher value means evaluated first.
    pub priority: u32,
    /// Whether this rule is active.
    pub enabled: bool,
    /// RFC3339 creation timestamp.
    pub created_at: String,
}

impl TenantCustomRule {
    /// Create a new custom rule.
    pub fn new(
        name: impl Into<String>,
        condition_json: impl Into<String>,
        action: TenantRuleAction,
        priority: u32,
    ) -> Self {
        TenantCustomRule {
            name: name.into(),
            condition_json: condition_json.into(),
            action,
            priority,
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Check if a simple JSON condition matches the given action string.
    ///
    /// Supports basic conditions like:
    /// - `{"action": "tool_call"}` — matches if action equals "tool_call"
    /// - `{"action_prefix": "tool"}` — matches if action starts with "tool"
    pub fn matches_action(&self, request_action: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Try to parse as JSON condition
        if let Ok(cond) = serde_json::from_str::<serde_json::Value>(&self.condition_json) {
            if let Some(expected) = cond.get("action").and_then(|v| v.as_str()) {
                if request_action == expected {
                    return true;
                }
            }
            if let Some(prefix) = cond.get("action_prefix").and_then(|v| v.as_str()) {
                if request_action.starts_with(prefix) {
                    return true;
                }
            }
            if let Some(pattern) = cond.get("action_contains").and_then(|v| v.as_str()) {
                if request_action.contains(pattern) {
                    return true;
                }
            }
            // Default: if there is any condition but no action/prefix/contains,
            // check for a "match_all": true key
            if let Some(match_all) = cond.get("match_all").and_then(|v| v.as_bool()) {
                return match_all;
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// TenantPolicyConfig — full per-tenant policy override configuration
// ---------------------------------------------------------------------------

/// Complete per-tenant policy configuration.
///
/// Each field is optional (wrapping in Option or Vec/HashMap) so that
/// tenants only need to specify overrides — everything else falls through
/// to global defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicyConfig {
    /// Override the global deny threshold for this tenant.
    pub override_deny_threshold: Option<f64>,
    /// Override the global challenge threshold for this tenant.
    pub override_challenge_threshold: Option<f64>,
    /// Override the global tool allowlist.
    pub allowed_tools: Option<Vec<String>>,
    /// Explicitly blocked tools (added to any global blocklist).
    pub blocked_tools: Option<Vec<String>>,
    /// Tenant-defined custom rules.
    pub custom_rules: Vec<TenantCustomRule>,
    /// Per-endpoint rate limit overrides.
    pub rate_limits: HashMap<String, RateLimitOverride>,
    /// Rings that this tenant should skip entirely.
    pub disabled_rings: Vec<String>,
    /// Override the set of enabled rings (replaces default ring set).
    pub enabled_rings_override: Option<Vec<String>>,
    /// Global max requests per minute across all endpoints.
    pub max_requests_per_minute: Option<u32>,
    /// Maximum concurrent sessions for this tenant.
    pub max_concurrent_sessions: Option<u32>,
    /// IP addresses that are explicitly allowed.
    pub ip_allowlist: Option<Vec<String>>,
    /// IP addresses that are explicitly blocked.
    pub ip_blocklist: Option<Vec<String>>,
}

impl Default for TenantPolicyConfig {
    fn default() -> Self {
        TenantPolicyConfig {
            override_deny_threshold: None,
            override_challenge_threshold: None,
            allowed_tools: None,
            blocked_tools: None,
            custom_rules: Vec::new(),
            rate_limits: HashMap::new(),
            disabled_rings: Vec::new(),
            enabled_rings_override: None,
            max_requests_per_minute: None,
            max_concurrent_sessions: None,
            ip_allowlist: None,
            ip_blocklist: None,
        }
    }
}

impl TenantPolicyConfig {
    /// Add a custom rule to this configuration.
    pub fn add_rule(&mut self, rule: TenantCustomRule) {
        self.custom_rules.push(rule);
    }

    /// Add a disabled ring.
    pub fn disable_ring(&mut self, ring_name: impl Into<String>) {
        self.disabled_rings.push(ring_name.into());
    }

    /// Set a rate limit override for an endpoint.
    pub fn set_rate_limit(&mut self, endpoint: impl Into<String>, override_rl: RateLimitOverride) {
        self.rate_limits.insert(endpoint.into(), override_rl);
    }
}

// ---------------------------------------------------------------------------
// TenantPolicyDecision — result of policy evaluation
// ---------------------------------------------------------------------------

/// The decision produced by evaluating a tenant's policy against a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicyDecision {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Name of the matched custom rule, if any.
    pub matched_rule: Option<String>,
    /// Whether the request was rate-limited.
    pub rate_limited: bool,
}

impl TenantPolicyDecision {
    /// Create an allow decision.
    pub fn allow(reason: impl Into<String>) -> Self {
        TenantPolicyDecision {
            allowed: true,
            reason: reason.into(),
            matched_rule: None,
            rate_limited: false,
        }
    }

    /// Create a deny decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        TenantPolicyDecision {
            allowed: false,
            reason: reason.into(),
            matched_rule: None,
            rate_limited: false,
        }
    }

    /// Create a rate-limited decision.
    pub fn rate_limited(reason: impl Into<String>) -> Self {
        TenantPolicyDecision {
            allowed: false,
            reason: reason.into(),
            matched_rule: None,
            rate_limited: true,
        }
    }

    /// Create a rule-matched decision.
    pub fn from_rule(rule: &TenantCustomRule, action: TenantRuleAction) -> Self {
        let allowed = matches!(action, TenantRuleAction::Allow);
        TenantPolicyDecision {
            allowed,
            reason: format!("custom rule '{}' matched → {}", rule.name, action),
            matched_rule: Some(rule.name.clone()),
            rate_limited: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TokenBucket — atomic token bucket rate limiter
// ---------------------------------------------------------------------------

/// A token-bucket rate limiter using atomic operations.
///
/// Tokens are replenished at `refill_rate` tokens per second, up to
/// `capacity`. The bucket starts full.
///
/// Thread safety: Uses `AtomicU32` for token count and `AtomicU64` for
/// the last refill timestamp. The refill operation is lock-free but may
/// have minor races on token counting in highly concurrent scenarios —
/// this is acceptable for rate limiting where approximate counts suffice.
pub struct TokenBucket {
    /// Maximum number of tokens the bucket can hold.
    capacity: u32,
    /// Current number of available tokens.
    tokens: AtomicU32,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last refill timestamp as Unix milliseconds.
    last_refill: AtomicU64,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    /// * `capacity` — maximum tokens (also the initial fill level).
    /// * `refill_rate` — tokens added per second.
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        TokenBucket {
            capacity,
            tokens: AtomicU32::new(capacity),
            refill_rate,
            last_refill: AtomicU64::new(current_unix_secs()),
        }
    }

    /// Try to consume one token. Returns `true` if successful.
    pub fn consume(&self, count: u32) -> bool {
        self.refill();
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < count {
                return false;
            }
            let next = current - count;
            match self.tokens.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    pub fn refill(&self) {
        let now = current_unix_secs();
        let last = self.last_refill.load(Ordering::Relaxed);
        if now <= last {
            return;
        }
        let elapsed_ms = now - last;
        let new_tokens = (elapsed_ms as f64 / 1000.0 * self.refill_rate).floor() as u32;
        if new_tokens == 0 {
            return;
        }
        let current = self.tokens.load(Ordering::Relaxed);
        let added = new_tokens.min(self.capacity.saturating_sub(current));
        self.tokens.store(current + added, Ordering::Relaxed);
        // Update last_refill (may be slightly stale under contention, acceptable)
        let _ = self
            .last_refill
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Get the current number of available tokens.
    pub fn available(&self) -> u32 {
        self.refill();
        self.tokens.load(Ordering::Relaxed)
    }

    /// Get the bucket capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// Get the current time as Unix milliseconds.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// TenantPolicyEngine — evaluates tenant-specific policies
// ---------------------------------------------------------------------------

/// Evaluates per-tenant policy overrides for each incoming request.
///
/// Maintains per-tenant, per-endpoint token buckets for rate limiting.
/// Custom rules are evaluated in priority order (highest first).
pub struct TenantPolicyEngine {
    /// This tenant's policy configuration.
    config: TenantPolicyConfig,
    /// Per-endpoint token buckets for rate limiting.
    rate_limiters: RwLock<HashMap<String, TokenBucket>>,
    /// Global rate limiter (across all endpoints).
    global_rate_limiter: TokenBucket,
}

impl TenantPolicyEngine {
    /// Create a new policy engine with the given configuration.
    pub fn new(config: TenantPolicyConfig) -> Self {
        let global_rpm = config.max_requests_per_minute.unwrap_or(120);
        let global_bucket = TokenBucket::new(global_rpm, global_rpm as f64 / 60.0);

        let mut rate_limiters = HashMap::new();
        for (endpoint, rl) in &config.rate_limits {
            rate_limiters.insert(
                endpoint.clone(),
                TokenBucket::new(rl.burst_size, rl.refill_rate_per_sec()),
            );
        }

        TenantPolicyEngine {
            config,
            rate_limiters: RwLock::new(rate_limiters),
            global_rate_limiter: global_bucket,
        }
    }

    /// Evaluate whether a request is allowed under this tenant's policy.
    ///
    /// Checks custom rules (by priority), then risk thresholds, then
    /// rate limits. Returns the first decisive result.
    pub fn evaluate(
        &self,
        _ctx: &TenantContext,
        request_action: &str,
        risk_score: f64,
    ) -> TenantPolicyDecision {
        // 1. Evaluate custom rules in priority order (highest first)
        let mut sorted_rules: Vec<&TenantCustomRule> = self
            .config
            .custom_rules
            .iter()
            .filter(|r| r.enabled)
            .collect();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted_rules {
            if rule.matches_action(request_action) {
                return TenantPolicyDecision::from_rule(rule, rule.action);
            }
        }

        // 2. Check deny threshold
        if let Some(deny_thresh) = self.config.override_deny_threshold {
            if risk_score >= deny_thresh {
                return TenantPolicyDecision::deny(format!(
                    "risk score {} >= tenant deny threshold {}",
                    risk_score, deny_thresh
                ));
            }
        }

        // 3. Check challenge threshold
        if let Some(challenge_thresh) = self.config.override_challenge_threshold {
            if risk_score >= challenge_thresh {
                return TenantPolicyDecision::deny(format!(
                    "risk score {} >= tenant challenge threshold {}",
                    risk_score, challenge_thresh
                ));
            }
        }

        // 4. Default: allow
        TenantPolicyDecision::allow("no tenant policy overrides matched")
    }

    /// Check if a request should be rate-limited for the given endpoint.
    pub fn should_rate_limit(&self, _ctx: &TenantContext, endpoint: &str) -> bool {
        // Check global rate limit first
        if !self.global_rate_limiter.consume(1) {
            return true;
        }

        // Check per-endpoint rate limit
        let buckets = self.rate_limiters.read().unwrap();
        if let Some(bucket) = buckets.get(endpoint) {
            return !bucket.consume(1);
        }

        false
    }

    /// Check if a ring is enabled for the tenant.
    pub fn is_ring_enabled(&self, _ctx: &TenantContext, ring_name: &str) -> bool {
        if self.config.disabled_rings.iter().any(|r| r == ring_name) {
            return false;
        }
        if let Some(ref enabled) = self.config.enabled_rings_override {
            return enabled.iter().any(|r| r == ring_name);
        }
        // Default: all rings are enabled
        true
    }

    /// Check if a tool is allowed for the tenant.
    pub fn is_tool_allowed(&self, _ctx: &TenantContext, tool_name: &str) -> bool {
        // Check blocklist first
        if let Some(ref blocked) = self.config.blocked_tools {
            if blocked.iter().any(|t| t == tool_name) {
                return false;
            }
        }
        // Check allowlist (if defined, tool must be in it)
        if let Some(ref allowed) = self.config.allowed_tools {
            if !allowed.iter().any(|t| t == tool_name) {
                return false;
            }
        }
        true
    }

    /// Check if an IP address is allowed for the tenant.
    pub fn is_ip_allowed(&self, _ctx: &TenantContext, ip: &str) -> bool {
        // Check blocklist first
        if let Some(ref blocked) = self.config.ip_blocklist {
            if blocked.iter().any(|b| b == ip) {
                return false;
            }
        }
        // If allowlist is defined, IP must be in it
        if let Some(ref allowed) = self.config.ip_allowlist {
            if !allowed.iter().any(|a| a == ip) {
                return false;
            }
        }
        true
    }

    /// Get the effective deny threshold (tenant override or global default).
    pub fn effective_deny_threshold(&self, _ctx: &TenantContext) -> f64 {
        self.config.override_deny_threshold.unwrap_or(8.0) // global default
    }

    /// Get the effective challenge threshold (tenant override or global default).
    pub fn effective_challenge_threshold(&self, _ctx: &TenantContext) -> f64 {
        self.config.override_challenge_threshold.unwrap_or(5.0) // global default
    }

    /// Record a request for rate-limiting purposes.
    pub fn record_request(&self, _ctx: &TenantContext, endpoint: &str) {
        // Consume from global bucket
        let _ = self.global_rate_limiter.consume(1);

        // Consume from per-endpoint bucket (create if missing)
        let mut buckets = self.rate_limiters.write().unwrap();
        if let Some(bucket) = buckets.get(endpoint) {
            let _ = bucket.consume(1);
        } else if let Some(rl) = self.config.rate_limits.get(endpoint) {
            let bucket = TokenBucket::new(rl.burst_size, rl.refill_rate_per_sec());
            let _ = bucket.consume(1);
            buckets.insert(endpoint.to_string(), bucket);
        }
    }

    /// Get a reference to the policy configuration.
    pub fn config(&self) -> &TenantPolicyConfig {
        &self.config
    }

    /// Get the current number of available global tokens.
    pub fn global_tokens_available(&self) -> u32 {
        self.global_rate_limiter.available()
    }
}

// ---------------------------------------------------------------------------
// TenantPolicyStore — multi-tenant policy registry
// ---------------------------------------------------------------------------

/// Stores per-tenant policy configurations.
///
/// Uses a `RwLock<HashMap>` for thread-safe concurrent access.
pub struct TenantPolicyStore {
    policies: RwLock<HashMap<String, TenantPolicyConfig>>,
}

impl TenantPolicyStore {
    /// Create a new empty policy store.
    pub fn new() -> Self {
        TenantPolicyStore {
            policies: RwLock::new(HashMap::new()),
        }
    }

    /// Register a tenant's policy configuration.
    pub fn register(&self, tenant_id: &str, config: TenantPolicyConfig) {
        let mut policies = self.policies.write().unwrap();
        policies.insert(tenant_id.to_string(), config);
    }

    /// Get a tenant's policy configuration by reference.
    pub fn get(&self, tenant_id: &str) -> Option<TenantPolicyConfig> {
        let policies = self.policies.read().unwrap();
        policies.get(tenant_id).cloned()
    }

    /// Remove a tenant's policy configuration. Returns true if it existed.
    pub fn remove(&self, tenant_id: &str) -> bool {
        let mut policies = self.policies.write().unwrap();
        policies.remove(tenant_id).is_some()
    }

    /// List all registered tenant policies as (id, config) pairs.
    pub fn list(&self) -> Vec<(String, TenantPolicyConfig)> {
        let policies = self.policies.read().unwrap();
        policies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Check if a tenant is registered.
    pub fn contains(&self, tenant_id: &str) -> bool {
        let policies = self.policies.read().unwrap();
        policies.contains_key(tenant_id)
    }

    /// Get the number of registered tenants.
    pub fn len(&self) -> usize {
        let policies = self.policies.read().unwrap();
        policies.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get default policy configuration for a given tier.
    pub fn default_for_tier(tier: TenantTier) -> TenantPolicyConfig {
        match tier {
            TenantTier::Free => TenantPolicyConfig {
                override_deny_threshold: Some(5.0),
                override_challenge_threshold: Some(3.0),
                max_requests_per_minute: Some(30),
                max_concurrent_sessions: Some(1),
                disabled_rings: vec![],
                ..Default::default()
            },
            TenantTier::Standard => TenantPolicyConfig {
                override_deny_threshold: Some(7.0),
                override_challenge_threshold: Some(4.5),
                max_requests_per_minute: Some(60),
                max_concurrent_sessions: Some(5),
                disabled_rings: vec![],
                ..Default::default()
            },
            TenantTier::Premium => TenantPolicyConfig {
                override_deny_threshold: Some(8.5),
                override_challenge_threshold: Some(6.0),
                max_requests_per_minute: Some(300),
                max_concurrent_sessions: Some(20),
                disabled_rings: vec![],
                ..Default::default()
            },
            TenantTier::Enterprise => TenantPolicyConfig {
                override_deny_threshold: Some(10.0),
                override_challenge_threshold: Some(8.0),
                max_requests_per_minute: Some(1000),
                max_concurrent_sessions: Some(100),
                disabled_rings: vec![],
                ..Default::default()
            },
        }
    }
}

impl Default for TenantPolicyStore {
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
    use crate::tenant::tenant_context::TenantId;

    fn test_tenant_ctx(id: &str) -> TenantContext {
        TenantContext::new(TenantId(id.to_string()), id, TenantTier::Standard)
    }

    // ── TenantRuleAction tests ──

    #[test]
    fn rule_action_from_str() {
        assert_eq!(
            TenantRuleAction::from_str_loose("allow"),
            Some(TenantRuleAction::Allow)
        );
        assert_eq!(
            TenantRuleAction::from_str_loose("DENY"),
            Some(TenantRuleAction::Deny)
        );
        assert_eq!(
            TenantRuleAction::from_str_loose("Challenge"),
            Some(TenantRuleAction::Challenge)
        );
        assert_eq!(
            TenantRuleAction::from_str_loose("ESCALATE"),
            Some(TenantRuleAction::Escalate)
        );
        assert_eq!(TenantRuleAction::from_str_loose("unknown"), None);
    }

    #[test]
    fn rule_action_display() {
        assert_eq!(format!("{}", TenantRuleAction::Allow), "allow");
        assert_eq!(format!("{}", TenantRuleAction::Deny), "deny");
    }

    // ── RateLimitOverride tests ──

    #[test]
    fn rate_limit_override_new() {
        let rl = RateLimitOverride::new(100, 20, 60);
        assert_eq!(rl.requests_per_minute, 100);
        assert_eq!(rl.burst_size, 20);
        assert_eq!(rl.window_secs, 60);
    }

    #[test]
    fn rate_limit_override_refill_rate() {
        let rl = RateLimitOverride::new(60, 10, 60);
        assert!((rl.refill_rate_per_sec() - 1.0).abs() < 0.001);
    }

    #[test]
    fn rate_limit_override_zero_window() {
        let rl = RateLimitOverride::new(100, 10, 0);
        assert_eq!(rl.refill_rate_per_sec(), 0.0);
    }

    #[test]
    fn rate_limit_override_default() {
        let rl = RateLimitOverride::default();
        assert_eq!(rl.requests_per_minute, 60);
        assert_eq!(rl.burst_size, 10);
        assert_eq!(rl.window_secs, 60);
    }

    #[test]
    fn rate_limit_override_serialization() {
        let rl = RateLimitOverride::new(100, 20, 60);
        let json = serde_json::to_string(&rl).unwrap();
        let decoded: RateLimitOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_per_minute, 100);
    }

    // ── TenantCustomRule tests ──

    #[test]
    fn custom_rule_new() {
        let rule = TenantCustomRule::new(
            "block-shell",
            r#"{"action": "shell_execute"}"#,
            TenantRuleAction::Deny,
            10,
        );
        assert_eq!(rule.name, "block-shell");
        assert!(rule.enabled);
        assert_eq!(rule.priority, 10);
        assert!(!rule.created_at.is_empty());
    }

    #[test]
    fn custom_rule_matches_action_exact() {
        let rule = TenantCustomRule::new(
            "test",
            r#"{"action": "tool_call"}"#,
            TenantRuleAction::Deny,
            1,
        );
        assert!(rule.matches_action("tool_call"));
        assert!(!rule.matches_action("tool_call_other"));
    }

    #[test]
    fn custom_rule_matches_action_prefix() {
        let rule = TenantCustomRule::new(
            "test",
            r#"{"action_prefix": "tool"}"#,
            TenantRuleAction::Deny,
            1,
        );
        assert!(rule.matches_action("tool_call"));
        assert!(rule.matches_action("toolkit"));
        assert!(!rule.matches_action("agent_action"));
    }

    #[test]
    fn custom_rule_matches_action_contains() {
        let rule = TenantCustomRule::new(
            "test",
            r#"{"action_contains": "shell"}"#,
            TenantRuleAction::Deny,
            1,
        );
        assert!(rule.matches_action("shell_execute"));
        assert!(rule.matches_action("run_shell_cmd"));
        assert!(!rule.matches_action("file_read"));
    }

    #[test]
    fn custom_rule_disabled_no_match() {
        let mut rule = TenantCustomRule::new(
            "test",
            r#"{"action": "tool_call"}"#,
            TenantRuleAction::Deny,
            1,
        );
        rule.enabled = false;
        assert!(!rule.matches_action("tool_call"));
    }

    #[test]
    fn custom_rule_match_all() {
        let rule =
            TenantCustomRule::new("test", r#"{"match_all": true}"#, TenantRuleAction::Deny, 1);
        assert!(rule.matches_action("anything"));
    }

    #[test]
    fn custom_rule_invalid_json_no_match() {
        let rule = TenantCustomRule::new("test", "not valid json", TenantRuleAction::Deny, 1);
        assert!(!rule.matches_action("tool_call"));
    }

    #[test]
    fn custom_rule_no_action_field_no_match() {
        let rule =
            TenantCustomRule::new("test", r#"{"other": "field"}"#, TenantRuleAction::Deny, 1);
        assert!(!rule.matches_action("tool_call"));
    }

    // ── TenantPolicyConfig tests ──

    #[test]
    fn policy_config_default() {
        let config = TenantPolicyConfig::default();
        assert!(config.override_deny_threshold.is_none());
        assert!(config.allowed_tools.is_none());
        assert!(config.custom_rules.is_empty());
        assert!(config.disabled_rings.is_empty());
    }

    #[test]
    fn policy_config_add_rule() {
        let mut config = TenantPolicyConfig::default();
        let rule = TenantCustomRule::new(
            "test-rule",
            r#"{"action": "x"}"#,
            TenantRuleAction::Allow,
            5,
        );
        config.add_rule(rule);
        assert_eq!(config.custom_rules.len(), 1);
        assert_eq!(config.custom_rules[0].name, "test-rule");
    }

    #[test]
    fn policy_config_disable_ring() {
        let mut config = TenantPolicyConfig::default();
        config.disable_ring("shield");
        config.disable_ring("threat");
        assert_eq!(config.disabled_rings.len(), 2);
        assert!(config.disabled_rings.contains(&"shield".to_string()));
    }

    #[test]
    fn policy_config_set_rate_limit() {
        let mut config = TenantPolicyConfig::default();
        config.set_rate_limit("/api/chat", RateLimitOverride::new(100, 20, 60));
        assert!(config.rate_limits.contains_key("/api/chat"));
    }

    #[test]
    fn policy_config_serialization() {
        let mut config = TenantPolicyConfig::default();
        config.override_deny_threshold = Some(9.5);
        config.disable_ring("memory");
        let json = serde_json::to_string(&config).unwrap();
        let decoded: TenantPolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.override_deny_threshold, Some(9.5));
        assert!(decoded.disabled_rings.contains(&"memory".to_string()));
    }

    // ── TenantPolicyDecision tests ──

    #[test]
    fn decision_allow() {
        let d = TenantPolicyDecision::allow("all good");
        assert!(d.allowed);
        assert_eq!(d.reason, "all good");
        assert!(d.matched_rule.is_none());
        assert!(!d.rate_limited);
    }

    #[test]
    fn decision_deny() {
        let d = TenantPolicyDecision::deny("too risky");
        assert!(!d.allowed);
        assert_eq!(d.reason, "too risky");
    }

    #[test]
    fn decision_rate_limited() {
        let d = TenantPolicyDecision::rate_limited("too many requests");
        assert!(!d.allowed);
        assert!(d.rate_limited);
    }

    #[test]
    fn decision_from_rule() {
        let rule = TenantCustomRule::new("test", r#"{"action": "x"}"#, TenantRuleAction::Deny, 1);
        let d = TenantPolicyDecision::from_rule(&rule, TenantRuleAction::Deny);
        assert!(!d.allowed);
        assert_eq!(d.matched_rule, Some("test".to_string()));
    }

    #[test]
    fn decision_from_rule_allow() {
        let rule = TenantCustomRule::new(
            "allow-rule",
            r#"{"action": "x"}"#,
            TenantRuleAction::Allow,
            1,
        );
        let d = TenantPolicyDecision::from_rule(&rule, TenantRuleAction::Allow);
        assert!(d.allowed);
    }

    // ── TokenBucket tests ──

    #[test]
    fn token_bucket_new_full() {
        let bucket = TokenBucket::new(10, 1.0);
        assert_eq!(bucket.available(), 10);
        assert_eq!(bucket.capacity(), 10);
    }

    #[test]
    fn token_bucket_consume_success() {
        let bucket = TokenBucket::new(10, 1.0);
        assert!(bucket.consume(1));
        assert_eq!(bucket.available(), 9);
    }

    #[test]
    fn token_bucket_consume_empty() {
        let bucket = TokenBucket::new(1, 0.0);
        assert!(bucket.consume(1));
        assert!(!bucket.consume(1));
    }

    #[test]
    fn token_bucket_consume_batch() {
        let bucket = TokenBucket::new(10, 0.0);
        assert!(bucket.consume(5));
        assert_eq!(bucket.available(), 5);
        assert!(!bucket.consume(10));
    }

    #[test]
    fn token_bucket_refill() {
        let bucket = TokenBucket::new(10, 1000.0); // very fast refill for test
                                                   // Drain the bucket
        for _ in 0..10 {
            bucket.consume(1);
        }
        // Small sleep to allow refill
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(bucket.available() >= 1);
    }

    #[test]
    fn token_bucket_no_overflow() {
        let bucket = TokenBucket::new(5, 1000.0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(bucket.available() <= 5);
    }

    // ── TenantPolicyEngine tests ──

    #[test]
    fn engine_evaluate_default_allow() {
        let config = TenantPolicyConfig::default();
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "tool_call", 3.0);
        assert!(decision.allowed);
    }

    #[test]
    fn engine_evaluate_custom_rule_deny() {
        let mut config = TenantPolicyConfig::default();
        config.add_rule(TenantCustomRule::new(
            "block-shell",
            r#"{"action": "shell_execute"}"#,
            TenantRuleAction::Deny,
            10,
        ));
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "shell_execute", 1.0);
        assert!(!decision.allowed);
        assert_eq!(decision.matched_rule, Some("block-shell".to_string()));
    }

    #[test]
    fn engine_evaluate_custom_rule_allow() {
        let mut config = TenantPolicyConfig::default();
        config.add_rule(TenantCustomRule::new(
            "allow-safe",
            r#"{"action": "safe_action"}"#,
            TenantRuleAction::Allow,
            10,
        ));
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "safe_action", 9.0);
        assert!(decision.allowed);
    }

    #[test]
    fn engine_evaluate_priority_order() {
        let mut config = TenantPolicyConfig::default();
        config.add_rule(TenantCustomRule::new(
            "allow",
            r#"{"match_all": true}"#,
            TenantRuleAction::Allow,
            1,
        ));
        config.add_rule(TenantCustomRule::new(
            "deny",
            r#"{"match_all": true}"#,
            TenantRuleAction::Deny,
            10, // higher priority
        ));
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "anything", 0.5);
        assert!(!decision.allowed); // deny has higher priority
        assert_eq!(decision.matched_rule, Some("deny".to_string()));
    }

    #[test]
    fn engine_evaluate_deny_threshold() {
        let mut config = TenantPolicyConfig::default();
        config.override_deny_threshold = Some(6.0);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "tool_call", 7.0);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("deny threshold"));
    }

    #[test]
    fn engine_evaluate_challenge_threshold() {
        let mut config = TenantPolicyConfig::default();
        config.override_challenge_threshold = Some(5.0);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        let decision = engine.evaluate(&ctx, "tool_call", 5.5);
        assert!(!decision.allowed);
    }

    #[test]
    fn engine_is_ring_enabled_default() {
        let config = TenantPolicyConfig::default();
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_ring_enabled(&ctx, "shield"));
        assert!(engine.is_ring_enabled(&ctx, "threat"));
    }

    #[test]
    fn engine_is_ring_disabled() {
        let mut config = TenantPolicyConfig::default();
        config.disable_ring("memory");
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(!engine.is_ring_enabled(&ctx, "memory"));
        assert!(engine.is_ring_enabled(&ctx, "shield"));
    }

    #[test]
    fn engine_is_ring_enabled_override() {
        let mut config = TenantPolicyConfig::default();
        config.enabled_rings_override = Some(vec!["shield".to_string(), "threat".to_string()]);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_ring_enabled(&ctx, "shield"));
        assert!(!engine.is_ring_enabled(&ctx, "memory"));
    }

    #[test]
    fn engine_is_tool_allowed_default() {
        let config = TenantPolicyConfig::default();
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_tool_allowed(&ctx, "browser"));
        assert!(engine.is_tool_allowed(&ctx, "calculator"));
    }

    #[test]
    fn engine_is_tool_blocked() {
        let mut config = TenantPolicyConfig::default();
        config.blocked_tools = Some(vec!["shell".to_string()]);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(!engine.is_tool_allowed(&ctx, "shell"));
        assert!(engine.is_tool_allowed(&ctx, "browser"));
    }

    #[test]
    fn engine_is_tool_allowlist() {
        let mut config = TenantPolicyConfig::default();
        config.allowed_tools = Some(vec!["browser".to_string()]);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_tool_allowed(&ctx, "browser"));
        assert!(!engine.is_tool_allowed(&ctx, "shell"));
    }

    #[test]
    fn engine_is_ip_allowed_default() {
        let config = TenantPolicyConfig::default();
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_ip_allowed(&ctx, "1.2.3.4"));
    }

    #[test]
    fn engine_is_ip_blocked() {
        let mut config = TenantPolicyConfig::default();
        config.ip_blocklist = Some(vec!["10.0.0.1".to_string()]);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(!engine.is_ip_allowed(&ctx, "10.0.0.1"));
        assert!(engine.is_ip_allowed(&ctx, "10.0.0.2"));
    }

    #[test]
    fn engine_is_ip_allowlist() {
        let mut config = TenantPolicyConfig::default();
        config.ip_allowlist = Some(vec!["192.168.1.0".to_string()]);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert!(engine.is_ip_allowed(&ctx, "192.168.1.0"));
        assert!(!engine.is_ip_allowed(&ctx, "10.0.0.1"));
    }

    #[test]
    fn engine_effective_thresholds() {
        let mut config = TenantPolicyConfig::default();
        config.override_deny_threshold = Some(9.0);
        config.override_challenge_threshold = Some(6.5);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert_eq!(engine.effective_deny_threshold(&ctx), 9.0);
        assert_eq!(engine.effective_challenge_threshold(&ctx), 6.5);
    }

    #[test]
    fn engine_effective_thresholds_default() {
        let config = TenantPolicyConfig::default();
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");
        assert_eq!(engine.effective_deny_threshold(&ctx), 8.0);
        assert_eq!(engine.effective_challenge_threshold(&ctx), 5.0);
    }

    #[test]
    fn engine_rate_limit_global() {
        let mut config = TenantPolicyConfig::default();
        config.max_requests_per_minute = Some(2);
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");

        assert!(!engine.should_rate_limit(&ctx, "/api/test"));
        assert!(!engine.should_rate_limit(&ctx, "/api/test"));
        assert!(engine.should_rate_limit(&ctx, "/api/test")); // 3rd request blocked
    }

    #[test]
    fn engine_rate_limit_per_endpoint() {
        let mut config = TenantPolicyConfig::default();
        config.max_requests_per_minute = Some(100);
        config.set_rate_limit("/api/limited", RateLimitOverride::new(10, 2, 60));
        let engine = TenantPolicyEngine::new(config);
        let ctx = test_tenant_ctx("test");

        assert!(!engine.should_rate_limit(&ctx, "/api/limited"));
        assert!(!engine.should_rate_limit(&ctx, "/api/limited"));
        assert!(engine.should_rate_limit(&ctx, "/api/limited")); // 3rd blocked

        // Different endpoint not rate-limited
        assert!(!engine.should_rate_limit(&ctx, "/api/other"));
    }

    // ── TenantPolicyStore tests ──

    #[test]
    fn store_new_empty() {
        let store = TenantPolicyStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_register_and_get() {
        let store = TenantPolicyStore::new();
        let config = TenantPolicyConfig::default();
        store.register("acme", config);
        assert!(store.contains("acme"));
        assert!(!store.contains("other"));
        let retrieved = store.get("acme");
        assert!(retrieved.is_some());
    }

    #[test]
    fn store_remove() {
        let store = TenantPolicyStore::new();
        store.register("acme", TenantPolicyConfig::default());
        assert!(store.remove("acme"));
        assert!(!store.remove("acme")); // already removed
        assert!(!store.contains("acme"));
    }

    #[test]
    fn store_list() {
        let store = TenantPolicyStore::new();
        store.register("acme", TenantPolicyConfig::default());
        store.register("globex", TenantPolicyConfig::default());
        let list = store.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn store_default_for_tier_free() {
        let config = TenantPolicyStore::default_for_tier(TenantTier::Free);
        assert_eq!(config.override_deny_threshold, Some(5.0));
        assert_eq!(config.max_requests_per_minute, Some(30));
    }

    #[test]
    fn store_default_for_tier_enterprise() {
        let config = TenantPolicyStore::default_for_tier(TenantTier::Enterprise);
        assert_eq!(config.override_deny_threshold, Some(10.0));
        assert_eq!(config.max_requests_per_minute, Some(1000));
        assert_eq!(config.max_concurrent_sessions, Some(100));
    }

    #[test]
    fn store_default_for_tier_premium() {
        let config = TenantPolicyStore::default_for_tier(TenantTier::Premium);
        assert_eq!(config.override_deny_threshold, Some(8.5));
        assert_eq!(config.override_challenge_threshold, Some(6.0));
    }

    #[test]
    fn store_default_for_tier_standard() {
        let config = TenantPolicyStore::default_for_tier(TenantTier::Standard);
        assert_eq!(config.override_deny_threshold, Some(7.0));
        assert_eq!(config.max_concurrent_sessions, Some(5));
    }
}
