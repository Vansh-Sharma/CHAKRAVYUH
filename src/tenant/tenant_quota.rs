// Per-Tenant Resource Quotas
//
// Tracks and enforces resource usage quotas for each tenant, including
// request counts, LLM token budgets, storage, concurrency limits, and
// bandwidth. Provides daily reset logic, percentage tracking, and
// threshold-based alerting.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::tenant::tenant_context::{TenantContext, TenantId, TenantTier};

// ---------------------------------------------------------------------------
// ResourceQuota — quota limits for a tenant
// ---------------------------------------------------------------------------

/// Defines the maximum resource limits for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    /// Maximum API requests per day.
    pub max_requests_per_day: u64,
    /// Maximum LLM tokens consumed per day.
    pub max_tokens_per_day: u64,
    /// Maximum storage usage in bytes.
    pub max_storage_bytes: u64,
    /// Maximum concurrent requests.
    pub max_concurrent_requests: u32,
    /// Maximum sessions per user.
    pub max_sessions_per_user: u32,
    /// Maximum tool calls per single request.
    pub max_tool_calls_per_request: u32,
    /// Maximum API keys.
    pub max_api_keys: u32,
    /// Maximum bandwidth (bytes) per day.
    pub bandwidth_bytes_per_day: u64,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        // Reasonable defaults for a Standard-tier tenant.
        ResourceQuota {
            max_requests_per_day: 10_000,
            max_tokens_per_day: 500_000,
            max_storage_bytes: 100 * 1024 * 1024, // 100 MB
            max_concurrent_requests: 5,
            max_sessions_per_user: 3,
            max_tool_calls_per_request: 10,
            max_api_keys: 10,
            bandwidth_bytes_per_day: 500 * 1024 * 1024, // 500 MB
        }
    }
}

impl ResourceQuota {
    /// Create a new resource quota with all fields specified.
    pub fn new(
        max_requests_per_day: u64,
        max_tokens_per_day: u64,
        max_storage_bytes: u64,
        max_concurrent_requests: u32,
        max_sessions_per_user: u32,
        max_tool_calls_per_request: u32,
        max_api_keys: u32,
        bandwidth_bytes_per_day: u64,
    ) -> Self {
        ResourceQuota {
            max_requests_per_day,
            max_tokens_per_day,
            max_storage_bytes,
            max_concurrent_requests,
            max_sessions_per_user,
            max_tool_calls_per_request,
            max_api_keys,
            bandwidth_bytes_per_day,
        }
    }

    /// Check whether a given set of usage counters exceeds any quota.
    fn check_exceeded(
        &self,
        requests_today: u64,
        tokens_today: u64,
        storage_bytes: u64,
        concurrent_requests: u32,
    ) -> Vec<ExceededQuota> {
        let mut exceeded = Vec::new();

        if self.max_requests_per_day != u64::MAX && requests_today > self.max_requests_per_day {
            exceeded.push(ExceededQuota {
                resource_name: "requests_per_day".to_string(),
                current: requests_today,
                limit: self.max_requests_per_day,
                excess_pct: excess_pct(requests_today, self.max_requests_per_day),
            });
        }

        if self.max_tokens_per_day != u64::MAX && tokens_today > self.max_tokens_per_day {
            exceeded.push(ExceededQuota {
                resource_name: "tokens_per_day".to_string(),
                current: tokens_today,
                limit: self.max_tokens_per_day,
                excess_pct: excess_pct(tokens_today, self.max_tokens_per_day),
            });
        }

        if self.max_storage_bytes != u64::MAX && storage_bytes > self.max_storage_bytes {
            exceeded.push(ExceededQuota {
                resource_name: "storage_bytes".to_string(),
                current: storage_bytes,
                limit: self.max_storage_bytes,
                excess_pct: excess_pct(storage_bytes, self.max_storage_bytes),
            });
        }

        if self.max_concurrent_requests != u32::MAX
            && concurrent_requests > self.max_concurrent_requests
        {
            exceeded.push(ExceededQuota {
                resource_name: "concurrent_requests".to_string(),
                current: concurrent_requests as u64,
                limit: self.max_concurrent_requests as u64,
                excess_pct: excess_pct(
                    concurrent_requests as u64,
                    self.max_concurrent_requests as u64,
                ),
            });
        }

        exceeded
    }
}

/// Calculate the percentage by which `current` exceeds `limit`.
fn excess_pct(current: u64, limit: u64) -> f64 {
    if limit == 0 {
        return 100.0;
    }
    ((current as f64 - limit as f64) / limit as f64) * 100.0
}

// ---------------------------------------------------------------------------
// QuotaUsage — atomic usage counters for a tenant
// ---------------------------------------------------------------------------

/// Tracks current resource usage for a tenant using atomic counters.
///
/// Daily counters (requests, tokens, bandwidth) are reset via `reset_daily()`.
/// Non-daily counters (storage, concurrent, sessions) persist until
/// explicitly decremented.
pub struct QuotaUsage {
    /// Number of requests made today.
    pub requests_today: AtomicU64,
    /// Number of LLM tokens consumed today.
    pub tokens_today: AtomicU64,
    /// Current storage usage in bytes.
    pub storage_bytes: AtomicU64,
    /// Currently active concurrent requests.
    pub concurrent_requests: AtomicU32,
    /// Currently active sessions.
    pub active_sessions: AtomicU32,
    /// Tool calls made in the current request.
    pub tool_calls_this_request: AtomicU32,
    /// Number of API keys in use.
    pub api_key_count: AtomicU32,
    /// Bandwidth consumed today (bytes).
    pub bandwidth_today: AtomicU64,
    /// Unix timestamp of the last daily reset.
    pub last_reset: AtomicI64,
}

impl QuotaUsage {
    /// Create a new QuotaUsage with all counters at zero.
    pub fn new() -> Self {
        QuotaUsage {
            requests_today: AtomicU64::new(0),
            tokens_today: AtomicU64::new(0),
            storage_bytes: AtomicU64::new(0),
            concurrent_requests: AtomicU32::new(0),
            active_sessions: AtomicU32::new(0),
            tool_calls_this_request: AtomicU32::new(0),
            api_key_count: AtomicU32::new(0),
            bandwidth_today: AtomicU64::new(0),
            last_reset: AtomicI64::new(current_unix_secs() as i64),
        }
    }

    /// Reset daily counters (requests, tokens, bandwidth).
    pub fn reset_daily(&self) {
        self.requests_today.store(0, Ordering::Relaxed);
        self.tokens_today.store(0, Ordering::Relaxed);
        self.bandwidth_today.store(0, Ordering::Relaxed);
        self.tool_calls_this_request.store(0, Ordering::Relaxed);
        self.last_reset.store(current_unix_secs() as i64, Ordering::Relaxed);
    }

    /// Create a snapshot of current usage.
    pub fn snapshot(&self) -> QuotaUsageSnapshot {
        QuotaUsageSnapshot {
            requests_today: self.requests_today.load(Ordering::Relaxed),
            tokens_today: self.tokens_today.load(Ordering::Relaxed),
            storage_bytes: self.storage_bytes.load(Ordering::Relaxed),
            concurrent_requests: self.concurrent_requests.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            tool_calls_this_request: self.tool_calls_this_request.load(Ordering::Relaxed),
            api_key_count: self.api_key_count.load(Ordering::Relaxed),
            bandwidth_today: self.bandwidth_today.load(Ordering::Relaxed),
        }
    }
}

impl Default for QuotaUsage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuotaUsageSnapshot — immutable snapshot of current usage
// ---------------------------------------------------------------------------

/// An immutable snapshot of a tenant's current resource usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsageSnapshot {
    pub requests_today: u64,
    pub tokens_today: u64,
    pub storage_bytes: u64,
    pub concurrent_requests: u32,
    pub active_sessions: u32,
    pub tool_calls_this_request: u32,
    pub api_key_count: u32,
    pub bandwidth_today: u64,
}

// ---------------------------------------------------------------------------
// QuotaCheckResult — result of a quota check before processing
// ---------------------------------------------------------------------------

/// The result of checking whether a tenant's request is within quota.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheckResult {
    /// Whether the request is allowed to proceed.
    pub allowed: bool,
    /// List of quotas that have been exceeded.
    pub exceeded_quotas: Vec<ExceededQuota>,
    /// Human-readable reason (when denied).
    pub reason: String,
}

impl QuotaCheckResult {
    /// Create an allowed result.
    pub fn allowed() -> Self {
        QuotaCheckResult {
            allowed: true,
            exceeded_quotas: Vec::new(),
            reason: String::new(),
        }
    }

    /// Create a denied result with exceeded quotas.
    pub fn denied(exceeded_quotas: Vec<ExceededQuota>) -> Self {
        let reason = exceeded_quotas
            .iter()
            .map(|eq| format!("{}: {:.1}% over limit", eq.resource_name, eq.excess_pct))
            .collect::<Vec<_>>()
            .join("; ");
        QuotaCheckResult {
            allowed: false,
            exceeded_quotas,
            reason,
        }
    }
}

// ---------------------------------------------------------------------------
// ExceededQuota — details about a single exceeded quota
// ---------------------------------------------------------------------------

/// Details about a single resource quota that has been exceeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceededQuota {
    /// Name of the resource (e.g., "requests_per_day").
    pub resource_name: String,
    /// Current usage value.
    pub current: u64,
    /// Quota limit.
    pub limit: u64,
    /// Percentage by which the quota is exceeded (0.0+).
    pub excess_pct: f64,
}

// ---------------------------------------------------------------------------
// QuotaUsagePercent — percentage usage for each resource
// ---------------------------------------------------------------------------

/// Percentage usage for each tracked resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsagePercent {
    pub requests_pct: f64,
    pub tokens_pct: f64,
    pub storage_pct: f64,
    pub concurrent_pct: f64,
    pub sessions_pct: f64,
    pub api_keys_pct: f64,
    pub bandwidth_pct: f64,
    /// Threshold for warning alerts (default 80%).
    pub warning_threshold: f64,
    /// Threshold for critical alerts (default 95%).
    pub critical_threshold: f64,
}

impl QuotaUsagePercent {
    /// Default warning threshold.
    pub const DEFAULT_WARNING_THRESHOLD: f64 = 80.0;
    /// Default critical threshold.
    pub const DEFAULT_CRITICAL_THRESHOLD: f64 = 95.0;

    /// Create a new QuotaUsagePercent with default thresholds.
    pub fn new() -> Self {
        QuotaUsagePercent {
            requests_pct: 0.0,
            tokens_pct: 0.0,
            storage_pct: 0.0,
            concurrent_pct: 0.0,
            sessions_pct: 0.0,
            api_keys_pct: 0.0,
            bandwidth_pct: 0.0,
            warning_threshold: Self::DEFAULT_WARNING_THRESHOLD,
            critical_threshold: Self::DEFAULT_CRITICAL_THRESHOLD,
        }
    }

    /// Check which resources have exceeded the warning threshold.
    pub fn warning_resources(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.requests_pct >= self.warning_threshold {
            warnings.push("requests".to_string());
        }
        if self.tokens_pct >= self.warning_threshold {
            warnings.push("tokens".to_string());
        }
        if self.storage_pct >= self.warning_threshold {
            warnings.push("storage".to_string());
        }
        if self.concurrent_pct >= self.warning_threshold {
            warnings.push("concurrent_requests".to_string());
        }
        if self.sessions_pct >= self.warning_threshold {
            warnings.push("sessions".to_string());
        }
        if self.api_keys_pct >= self.warning_threshold {
            warnings.push("api_keys".to_string());
        }
        if self.bandwidth_pct >= self.warning_threshold {
            warnings.push("bandwidth".to_string());
        }
        warnings
    }

    /// Check which resources have exceeded the critical threshold.
    pub fn critical_resources(&self) -> Vec<String> {
        let mut critical = Vec::new();
        if self.requests_pct >= self.critical_threshold {
            critical.push("requests".to_string());
        }
        if self.tokens_pct >= self.critical_threshold {
            critical.push("tokens".to_string());
        }
        if self.storage_pct >= self.critical_threshold {
            critical.push("storage".to_string());
        }
        if self.concurrent_pct >= self.critical_threshold {
            critical.push("concurrent_requests".to_string());
        }
        if self.sessions_pct >= self.critical_threshold {
            critical.push("sessions".to_string());
        }
        if self.api_keys_pct >= self.critical_threshold {
            critical.push("api_keys".to_string());
        }
        if self.bandwidth_pct >= self.critical_threshold {
            critical.push("bandwidth".to_string());
        }
        critical
    }
}

impl Default for QuotaUsagePercent {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuotaAlert — alert generated when usage exceeds thresholds
// ---------------------------------------------------------------------------

/// An alert generated when resource usage exceeds a threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaAlert {
    /// Tenant that triggered the alert.
    pub tenant_id: TenantId,
    /// Resource name.
    pub resource_name: String,
    /// Current usage percentage (0.0-100.0+).
    pub usage_pct: f64,
    /// Threshold that was crossed.
    pub threshold_pct: f64,
    /// Alert severity.
    pub severity: QuotaAlertSeverity,
    /// RFC3339 timestamp.
    pub timestamp: String,
    /// Human-readable message.
    pub message: String,
}

/// Severity level for quota alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuotaAlertSeverity {
    Warning,
    Critical,
}

impl std::fmt::Display for QuotaAlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaAlertSeverity::Warning => write!(f, "warning"),
            QuotaAlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl QuotaAlert {
    /// Create a new quota alert.
    pub fn new(
        tenant_id: TenantId,
        resource_name: impl Into<String>,
        usage_pct: f64,
        threshold_pct: f64,
        severity: QuotaAlertSeverity,
    ) -> Self {
        let message = format!(
            "{}: {} usage at {:.1}% (threshold: {:.1}%)",
            tenant_id.0,
            resource_name.into(),
            usage_pct,
            threshold_pct
        );
        QuotaAlert {
            tenant_id,
            resource_name: message.split(':').nth(1).unwrap_or("unknown").trim().split_whitespace().next().unwrap_or("unknown").to_string(),
            usage_pct,
            threshold_pct,
            severity,
            timestamp: chrono::Utc::now().to_rfc3339(),
            message,
        }
    }
}

// ---------------------------------------------------------------------------
// TierQuotaDefaults — predefined quotas per tier
// ---------------------------------------------------------------------------

/// Provides default quota configurations for each tenant tier.
pub struct TierQuotaDefaults;

impl TierQuotaDefaults {
    /// Get the default resource quota for a given tier.
    pub fn for_tier(tier: TenantTier) -> ResourceQuota {
        match tier {
            TenantTier::Free => ResourceQuota {
                max_requests_per_day: 1_000,
                max_tokens_per_day: 50_000,
                max_storage_bytes: 10 * 1024 * 1024, // 10 MB
                max_concurrent_requests: 1,
                max_sessions_per_user: 1,
                max_tool_calls_per_request: 3,
                max_api_keys: 2,
                bandwidth_bytes_per_day: 50 * 1024 * 1024, // 50 MB
            },
            TenantTier::Standard => ResourceQuota {
                max_requests_per_day: 10_000,
                max_tokens_per_day: 500_000,
                max_storage_bytes: 100 * 1024 * 1024, // 100 MB
                max_concurrent_requests: 5,
                max_sessions_per_user: 3,
                max_tool_calls_per_request: 10,
                max_api_keys: 10,
                bandwidth_bytes_per_day: 500 * 1024 * 1024, // 500 MB
            },
            TenantTier::Premium => ResourceQuota {
                max_requests_per_day: 100_000,
                max_tokens_per_day: 5_000_000,
                max_storage_bytes: 1024 * 1024 * 1024, // 1 GB
                max_concurrent_requests: 20,
                max_sessions_per_user: 10,
                max_tool_calls_per_request: 50,
                max_api_keys: 50,
                bandwidth_bytes_per_day: 5 * 1024 * 1024 * 1024, // 5 GB
            },
            TenantTier::Enterprise => ResourceQuota {
                max_requests_per_day: u64::MAX,
                max_tokens_per_day: u64::MAX,
                max_storage_bytes: u64::MAX,
                max_concurrent_requests: 100,
                max_sessions_per_user: 50,
                max_tool_calls_per_request: 100,
                max_api_keys: 200,
                bandwidth_bytes_per_day: u64::MAX,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// QuotaEnforcer — main quota enforcement engine
// ---------------------------------------------------------------------------

/// Enforces resource quotas per tenant.
///
/// Maintains a `HashMap<TenantId, QuotaUsage>` with automatic daily reset
/// logic. Before processing a request, call `check_request()` to verify
/// the tenant is within quota, then `record_request()` to increment
/// counters.
pub struct QuotaEnforcer {
    /// Maximum resource quota limits.
    quota: ResourceQuota,
    /// Per-tenant usage tracking.
    usage: RwLock<HashMap<String, QuotaUsage>>,
    /// Warning threshold percentage.
    warning_threshold: f64,
    /// Critical threshold percentage.
    critical_threshold: f64,
}

impl QuotaEnforcer {
    /// Create a new quota enforcer with the given resource limits.
    pub fn new(quota: ResourceQuota) -> Self {
        QuotaEnforcer {
            quota,
            usage: RwLock::new(HashMap::new()),
            warning_threshold: QuotaUsagePercent::DEFAULT_WARNING_THRESHOLD,
            critical_threshold: QuotaUsagePercent::DEFAULT_CRITICAL_THRESHOLD,
        }
    }

    /// Create a new quota enforcer with default limits for the given tier.
    pub fn for_tier(tier: TenantTier) -> Self {
        Self::new(TierQuotaDefaults::for_tier(tier))
    }

    /// Set custom warning and critical thresholds.
    pub fn set_thresholds(&mut self, warning: f64, critical: f64) {
        self.warning_threshold = warning.clamp(0.0, 100.0);
        self.critical_threshold = critical.clamp(0.0, 100.0);
    }

    /// Ensure a tenant has an entry in the usage map, performing daily
    /// reset if the day has changed.
    fn ensure_usage_entry(&self, tenant_id: &str) -> QuotaUsage {
        let mut usage_map = self.usage.write().unwrap();
        let now = current_unix_secs() as i64;

        if let Some(entry) = usage_map.get(tenant_id) {
            let last_reset = entry.last_reset.load(Ordering::Relaxed);
            if is_new_day(last_reset, now) {
                entry.reset_daily();
            }
            // Return a clone-like by returning the reference's snapshot.
            // We drop the write lock after this block.
            // Instead, we get a reference to the existing entry.
            drop(usage_map);
            let usage_map = self.usage.read().unwrap();
            // We know this exists from the check above.
            let _entry_ref = usage_map.get(tenant_id).unwrap();
            // Since we can't clone QuotaUsage (has atomics), we use the snapshot
            // and fall back to re-checking below.
            // Actually we just need to return a handle to work with.
            // Let's use a different approach: just return a new QuotaUsage
            // that we'll merge back. This is getting complex with atomics.
            // The simplest approach: perform the check inside the read lock.
            drop(usage_map);
            // Re-acquire write lock to do everything atomically
            let mut usage_map = self.usage.write().unwrap();
            usage_map
                .entry(tenant_id.to_string())
                .or_insert_with(QuotaUsage::new);
            // Get the entry reference from inside the map
            let entry = usage_map.get(tenant_id).unwrap();
            let last_reset = entry.last_reset.load(Ordering::Relaxed);
            if is_new_day(last_reset, now) {
                entry.reset_daily();
            }
            // We need a way to return a reference to the entry.
            // But since we hold a RwLock guard, we can't return a reference.
            // Let's restructure this completely.
            drop(usage_map);
            self.get_usage_entry(tenant_id)
        } else {
            let entry = QuotaUsage::new();
            usage_map.insert(tenant_id.to_string(), entry);
            drop(usage_map);
            self.get_usage_entry(tenant_id)
        }
    }

    /// Get a usage entry, creating if necessary, performing daily reset.
    fn get_usage_entry(&self, tenant_id: &str) -> QuotaUsage {
        // This is a workaround for the borrow issue.
        // We create a new QuotaUsage to simulate having a reference.
        let mut usage_map = self.usage.write().unwrap();
        let entry = usage_map
            .entry(tenant_id.to_string())
            .or_insert_with(QuotaUsage::new);

        let now = current_unix_secs() as i64;
        let last_reset = entry.last_reset.load(Ordering::Relaxed);
        if is_new_day(last_reset, now) {
            entry.reset_daily();
        }

        // Copy values from the entry into a standalone QuotaUsage.
        // This is used for atomic operations on the actual map entry.
        // Instead, we do operations directly on the map entry.
        let snapshot = entry.snapshot();
        drop(usage_map);

        // Create a dummy QuotaUsage that mirrors the current state.
        // This is only used for the check; actual mutations go through
        // the write lock in record_* methods.
        let usage = QuotaUsage::new();
        usage.requests_today.store(snapshot.requests_today, Ordering::Relaxed);
        usage.tokens_today.store(snapshot.tokens_today, Ordering::Relaxed);
        usage.storage_bytes.store(snapshot.storage_bytes, Ordering::Relaxed);
        usage.concurrent_requests
            .store(snapshot.concurrent_requests, Ordering::Relaxed);
        usage.active_sessions
            .store(snapshot.active_sessions, Ordering::Relaxed);
        usage.tool_calls_this_request
            .store(snapshot.tool_calls_this_request, Ordering::Relaxed);
        usage.api_key_count.store(snapshot.api_key_count, Ordering::Relaxed);
        usage.bandwidth_today.store(snapshot.bandwidth_today, Ordering::Relaxed);
        usage.last_reset.store(
            self.usage
                .read()
                .unwrap()
                .get(tenant_id)
                .map(|e| e.last_reset.load(Ordering::Relaxed))
                .unwrap_or(0),
            Ordering::Relaxed,
        );
        usage
    }

    /// Check if a tenant's request is within quota before processing.
    ///
    /// Returns a `QuotaCheckResult` indicating whether the request is
    /// allowed and which quotas (if any) have been exceeded.
    pub fn check_request(&self, ctx: &TenantContext) -> QuotaCheckResult {
        let snapshot = {
            let usage_map = self.usage.read().unwrap();
            match usage_map.get(&ctx.tenant_id.0) {
                Some(entry) => entry.snapshot(),
                None => QuotaUsageSnapshot {
                    requests_today: 0,
                    tokens_today: 0,
                    storage_bytes: 0,
                    concurrent_requests: 0,
                    active_sessions: 0,
                    tool_calls_this_request: 0,
                    api_key_count: 0,
                    bandwidth_today: 0,
                },
            }
        };
        let exceeded = self.quota.check_exceeded(
            snapshot.requests_today,
            snapshot.tokens_today,
            snapshot.storage_bytes,
            snapshot.concurrent_requests,
        );

        if exceeded.is_empty() {
            QuotaCheckResult::allowed()
        } else {
            QuotaCheckResult::denied(exceeded)
        }
    }

    /// Record a request for the tenant, incrementing daily counters.
    pub fn record_request(&self, ctx: &TenantContext) {
        let mut usage_map = self.usage.write().unwrap();
        let entry = usage_map
            .entry(ctx.tenant_id.0.clone())
            .or_insert_with(QuotaUsage::new);

        let now = current_unix_secs() as i64;
        let last_reset = entry.last_reset.load(Ordering::Relaxed);
        if is_new_day(last_reset, now) {
            entry.reset_daily();
        }

        entry.requests_today.fetch_add(1, Ordering::Relaxed);
        entry
            .concurrent_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record LLM token usage for the tenant.
    pub fn record_token_usage(&self, ctx: &TenantContext, tokens: u64) {
        let mut usage_map = self.usage.write().unwrap();
        let entry = usage_map
            .entry(ctx.tenant_id.0.clone())
            .or_insert_with(QuotaUsage::new);

        let now = current_unix_secs() as i64;
        let last_reset = entry.last_reset.load(Ordering::Relaxed);
        if is_new_day(last_reset, now) {
            entry.reset_daily();
        }

        entry.tokens_today.fetch_add(tokens, Ordering::Relaxed);
    }

    /// Record storage usage change. Positive bytes = increase, negative = decrease.
    pub fn record_storage(&self, ctx: &TenantContext, bytes: i64) {
        let mut usage_map = self.usage.write().unwrap();
        let entry = usage_map
            .entry(ctx.tenant_id.0.clone())
            .or_insert_with(QuotaUsage::new);

        if bytes >= 0 {
            entry
                .storage_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
        } else {
            let current = entry.storage_bytes.load(Ordering::Relaxed);
            let subtract = (bytes.abs() as u64).min(current);
            entry
                .storage_bytes
                .fetch_sub(subtract, Ordering::Relaxed);
        }
    }

    /// Record bandwidth usage.
    pub fn record_bandwidth(&self, ctx: &TenantContext, bytes: u64) {
        let mut usage_map = self.usage.write().unwrap();
        let entry = usage_map
            .entry(ctx.tenant_id.0.clone())
            .or_insert_with(QuotaUsage::new);

        let now = current_unix_secs() as i64;
        let last_reset = entry.last_reset.load(Ordering::Relaxed);
        if is_new_day(last_reset, now) {
            entry.reset_daily();
        }

        entry.bandwidth_today.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Decrement the concurrent request counter (called when a request completes).
    pub fn release_concurrent(&self, ctx: &TenantContext) {
        let usage_map = self.usage.read().unwrap();
        if let Some(entry) = usage_map.get(&ctx.tenant_id.0) {
            let current = entry.concurrent_requests.load(Ordering::Relaxed);
            if current > 0 {
                entry
                    .concurrent_requests
                    .fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Get the current usage snapshot for a tenant.
    pub fn current_usage(&self, ctx: &TenantContext) -> QuotaUsageSnapshot {
        let usage_map = self.usage.read().unwrap();
        if let Some(entry) = usage_map.get(&ctx.tenant_id.0) {
            entry.snapshot()
        } else {
            QuotaUsageSnapshot {
                requests_today: 0,
                tokens_today: 0,
                storage_bytes: 0,
                concurrent_requests: 0,
                active_sessions: 0,
                tool_calls_this_request: 0,
                api_key_count: 0,
                bandwidth_today: 0,
            }
        }
    }

    /// Reset daily counters for a specific tenant.
    pub fn reset_daily(&self, ctx: &TenantContext) {
        let usage_map = self.usage.read().unwrap();
        if let Some(entry) = usage_map.get(&ctx.tenant_id.0) {
            entry.reset_daily();
        }
    }

    /// Reset daily counters for all tenants.
    pub fn reset_all_daily(&self) {
        let usage_map = self.usage.read().unwrap();
        for entry in usage_map.values() {
            entry.reset_daily();
        }
    }

    /// Calculate the usage percentage for each resource.
    pub fn usage_pct(&self, ctx: &TenantContext) -> QuotaUsagePercent {
        let snapshot = self.current_usage(ctx);
        let q = &self.quota;

        QuotaUsagePercent {
            requests_pct: pct(snapshot.requests_today, q.max_requests_per_day),
            tokens_pct: pct(snapshot.tokens_today, q.max_tokens_per_day),
            storage_pct: pct(snapshot.storage_bytes, q.max_storage_bytes),
            concurrent_pct: pct(snapshot.concurrent_requests as u64, q.max_concurrent_requests as u64),
            sessions_pct: 0.0, // Not tracked separately yet
            api_keys_pct: pct(snapshot.api_key_count as u64, q.max_api_keys as u64),
            bandwidth_pct: pct(snapshot.bandwidth_today, q.bandwidth_bytes_per_day),
            warning_threshold: self.warning_threshold,
            critical_threshold: self.critical_threshold,
        }
    }

    /// Check for quota alerts based on current usage.
    pub fn check_alerts(&self, ctx: &TenantContext) -> Vec<QuotaAlert> {
        let pct = self.usage_pct(ctx);
        let mut alerts = Vec::new();

        let resources = [
            ("requests", pct.requests_pct),
            ("tokens", pct.tokens_pct),
            ("storage", pct.storage_pct),
            ("concurrent_requests", pct.concurrent_pct),
            ("bandwidth", pct.bandwidth_pct),
        ];

        for (name, usage) in &resources {
            if *usage >= pct.critical_threshold {
                alerts.push(QuotaAlert::new(
                    ctx.tenant_id.clone(),
                    *name,
                    *usage,
                    pct.critical_threshold,
                    QuotaAlertSeverity::Critical,
                ));
            } else if *usage >= pct.warning_threshold {
                alerts.push(QuotaAlert::new(
                    ctx.tenant_id.clone(),
                    *name,
                    *usage,
                    pct.warning_threshold,
                    QuotaAlertSeverity::Warning,
                ));
            }
        }

        alerts
    }

    /// Get a reference to the quota configuration.
    pub fn quota(&self) -> &ResourceQuota {
        &self.quota
    }

    /// Get the number of tenants being tracked.
    pub fn tracked_tenant_count(&self) -> usize {
        self.usage.read().unwrap().len()
    }
}

/// Calculate the percentage of current usage relative to limit.
/// Returns 0.0 if the limit is u64::MAX (unlimited).
fn pct(current: u64, limit: u64) -> f64 {
    if limit == u64::MAX {
        return 0.0;
    }
    if limit == 0 {
        return if current > 0 { 100.0 } else { 0.0 };
    }
    (current as f64 / limit as f64) * 100.0
}

/// Check if two timestamps are on different calendar days (UTC).
fn is_new_day(last_reset_ts: i64, now_ts: i64) -> bool {
    let last_day = last_reset_ts / 86400;
    let now_day = now_ts / 86400;
    now_day > last_day
}

/// Get current Unix timestamp in seconds.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant_ctx(id: &str) -> TenantContext {
        TenantContext::new(TenantId(id.to_string()), id, TenantTier::Standard)
    }

    // ── ResourceQuota tests ──

    #[test]
    fn resource_quota_default() {
        let q = ResourceQuota::default();
        assert_eq!(q.max_requests_per_day, 10_000);
        assert_eq!(q.max_tokens_per_day, 500_000);
        assert_eq!(q.max_concurrent_requests, 5);
    }

    #[test]
    fn resource_quota_new() {
        let q = ResourceQuota::new(100, 200, 300, 4, 5, 6, 7, 800);
        assert_eq!(q.max_requests_per_day, 100);
        assert_eq!(q.max_tokens_per_day, 200);
        assert_eq!(q.max_storage_bytes, 300);
        assert_eq!(q.max_concurrent_requests, 4);
        assert_eq!(q.max_sessions_per_user, 5);
        assert_eq!(q.max_tool_calls_per_request, 6);
        assert_eq!(q.max_api_keys, 7);
        assert_eq!(q.bandwidth_bytes_per_day, 800);
    }

    #[test]
    fn resource_quota_check_exceeded_none() {
        let q = ResourceQuota::default();
        let exceeded = q.check_exceeded(100, 100, 100, 1);
        assert!(exceeded.is_empty());
    }

    #[test]
    fn resource_quota_check_exceeded_requests() {
        let q = ResourceQuota::new(10, u64::MAX, u64::MAX, u32::MAX, 0, 0, 0, 0);
        let exceeded = q.check_exceeded(15, 0, 0, 0);
        assert_eq!(exceeded.len(), 1);
        assert_eq!(exceeded[0].resource_name, "requests_per_day");
    }

    #[test]
    fn resource_quota_check_exceeded_multiple() {
        let q = ResourceQuota::new(10, 20, u64::MAX, u32::MAX, 0, 0, 0, 0);
        let exceeded = q.check_exceeded(15, 25, 0, 0);
        assert_eq!(exceeded.len(), 2);
    }

    #[test]
    fn resource_quota_no_exceeded_for_unlimited() {
        let q = ResourceQuota::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX, 0, 0, 0, u64::MAX);
        let exceeded = q.check_exceeded(u64::MAX, u64::MAX, u64::MAX, u32::MAX);
        assert!(exceeded.is_empty());
    }

    #[test]
    fn resource_quota_serialization() {
        let q = ResourceQuota::default();
        let json = serde_json::to_string(&q).unwrap();
        let decoded: ResourceQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.max_requests_per_day, q.max_requests_per_day);
    }

    // ── QuotaUsage tests ──

    #[test]
    fn quota_usage_new_zero() {
        let u = QuotaUsage::new();
        assert_eq!(u.requests_today.load(Ordering::Relaxed), 0);
        assert_eq!(u.tokens_today.load(Ordering::Relaxed), 0);
        assert_eq!(u.concurrent_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn quota_usage_reset_daily() {
        let u = QuotaUsage::new();
        u.requests_today.store(100, Ordering::Relaxed);
        u.tokens_today.store(500, Ordering::Relaxed);
        u.bandwidth_today.store(1000, Ordering::Relaxed);
        u.reset_daily();
        assert_eq!(u.requests_today.load(Ordering::Relaxed), 0);
        assert_eq!(u.tokens_today.load(Ordering::Relaxed), 0);
        assert_eq!(u.bandwidth_today.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn quota_usage_snapshot() {
        let u = QuotaUsage::new();
        u.requests_today.store(42, Ordering::Relaxed);
        u.tokens_today.store(99, Ordering::Relaxed);
        let snap = u.snapshot();
        assert_eq!(snap.requests_today, 42);
        assert_eq!(snap.tokens_today, 99);
    }

    // ── QuotaCheckResult tests ──

    #[test]
    fn check_result_allowed() {
        let r = QuotaCheckResult::allowed();
        assert!(r.allowed);
        assert!(r.exceeded_quotas.is_empty());
    }

    #[test]
    fn check_result_denied() {
        let exceeded = vec![ExceededQuota {
            resource_name: "requests".to_string(),
            current: 150,
            limit: 100,
            excess_pct: 50.0,
        }];
        let r = QuotaCheckResult::denied(exceeded);
        assert!(!r.allowed);
        assert_eq!(r.exceeded_quotas.len(), 1);
        assert!(r.reason.contains("requests"));
    }

    // ── QuotaUsagePercent tests ──

    #[test]
    fn usage_percent_default_thresholds() {
        let p = QuotaUsagePercent::new();
        assert_eq!(p.warning_threshold, 80.0);
        assert_eq!(p.critical_threshold, 95.0);
    }

    #[test]
    fn usage_percent_warning_resources() {
        let mut p = QuotaUsagePercent::new();
        p.requests_pct = 85.0;
        p.tokens_pct = 60.0;
        p.storage_pct = 90.0;
        let warnings = p.warning_resources();
        assert!(warnings.contains(&"requests".to_string()));
        assert!(!warnings.contains(&"tokens".to_string()));
        assert!(warnings.contains(&"storage".to_string()));
    }

    #[test]
    fn usage_percent_critical_resources() {
        let mut p = QuotaUsagePercent::new();
        p.concurrent_pct = 97.0;
        p.bandwidth_pct = 50.0;
        let critical = p.critical_resources();
        assert!(critical.contains(&"concurrent_requests".to_string()));
        assert!(!critical.contains(&"bandwidth".to_string()));
    }

    // ── TierQuotaDefaults tests ──

    #[test]
    fn tier_quota_free() {
        let q = TierQuotaDefaults::for_tier(TenantTier::Free);
        assert_eq!(q.max_requests_per_day, 1_000);
        assert_eq!(q.max_tokens_per_day, 50_000);
        assert_eq!(q.max_concurrent_requests, 1);
    }

    #[test]
    fn tier_quota_standard() {
        let q = TierQuotaDefaults::for_tier(TenantTier::Standard);
        assert_eq!(q.max_requests_per_day, 10_000);
        assert_eq!(q.max_tokens_per_day, 500_000);
        assert_eq!(q.max_concurrent_requests, 5);
    }

    #[test]
    fn tier_quota_premium() {
        let q = TierQuotaDefaults::for_tier(TenantTier::Premium);
        assert_eq!(q.max_requests_per_day, 100_000);
        assert_eq!(q.max_tokens_per_day, 5_000_000);
        assert_eq!(q.max_concurrent_requests, 20);
    }

    #[test]
    fn tier_quota_enterprise_unlimited() {
        let q = TierQuotaDefaults::for_tier(TenantTier::Enterprise);
        assert_eq!(q.max_requests_per_day, u64::MAX);
        assert_eq!(q.max_tokens_per_day, u64::MAX);
        assert_eq!(q.max_concurrent_requests, 100);
    }

    // ── QuotaEnforcer tests ──

    #[test]
    fn enforcer_for_tier() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Free);
        assert_eq!(enforcer.quota().max_requests_per_day, 1_000);
    }

    #[test]
    fn enforcer_check_request_allowed() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        let result = enforcer.check_request(&ctx);
        assert!(result.allowed);
    }

    #[test]
    fn enforcer_check_request_denied_after_overuse() {
        let enforcer = QuotaEnforcer::new(ResourceQuota::new(3, 10, 100, 1, 1, 1, 1, 100));
        let ctx = test_tenant_ctx("over-tenant");
        enforcer.record_request(&ctx);
        enforcer.record_request(&ctx);
        enforcer.record_request(&ctx);
        let result = enforcer.check_request(&ctx);
        assert!(!result.allowed);
        assert!(!result.exceeded_quotas.is_empty());
    }

    #[test]
    fn enforcer_record_request_increments() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_request(&ctx);
        enforcer.record_request(&ctx);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.requests_today, 2);
        assert_eq!(usage.concurrent_requests, 2);
    }

    #[test]
    fn enforcer_record_token_usage() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_token_usage(&ctx, 1000);
        enforcer.record_token_usage(&ctx, 500);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.tokens_today, 1500);
    }

    #[test]
    fn enforcer_record_storage_positive() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_storage(&ctx, 1024);
        enforcer.record_storage(&ctx, 2048);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.storage_bytes, 3072);
    }

    #[test]
    fn enforcer_record_storage_negative() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_storage(&ctx, 1024);
        enforcer.record_storage(&ctx, -500);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.storage_bytes, 524);
    }

    #[test]
    fn enforcer_record_storage_no_underflow() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_storage(&ctx, 100);
        enforcer.record_storage(&ctx, -500);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.storage_bytes, 0); // can't go below 0
    }

    #[test]
    fn enforcer_record_bandwidth() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_bandwidth(&ctx, 1000);
        enforcer.record_bandwidth(&ctx, 2000);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.bandwidth_today, 3000);
    }

    #[test]
    fn enforcer_release_concurrent() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_request(&ctx);
        enforcer.record_request(&ctx);
        enforcer.release_concurrent(&ctx);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.concurrent_requests, 1);
    }

    #[test]
    fn enforcer_release_concurrent_no_underflow() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        // No requests recorded, release should not panic or underflow
        enforcer.release_concurrent(&ctx);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.concurrent_requests, 0);
    }

    #[test]
    fn enforcer_usage_pct() {
        let enforcer = QuotaEnforcer::new(ResourceQuota::new(100, 200, 300, 10, 5, 3, 2, 400));
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_request(&ctx);
        enforcer.record_token_usage(&ctx, 50);
        let pct = enforcer.usage_pct(&ctx);
        assert!((pct.requests_pct - 1.0).abs() < 0.1); // 1/100 = 1%
        assert!((pct.tokens_pct - 25.0).abs() < 0.1); // 50/200 = 25%
    }

    #[test]
    fn enforcer_usage_pct_unlimited() {
        let enforcer =
            QuotaEnforcer::new(ResourceQuota::new(u64::MAX, u64::MAX, u64::MAX, 10, 5, 3, 2, u64::MAX));
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_request(&ctx);
        let pct = enforcer.usage_pct(&ctx);
        assert_eq!(pct.requests_pct, 0.0); // unlimited → 0%
    }

    #[test]
    fn enforcer_check_alerts_none() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        let alerts = enforcer.check_alerts(&ctx);
        assert!(alerts.is_empty());
    }

    #[test]
    fn enforcer_check_alerts_warning() {
        let enforcer = QuotaEnforcer::new(ResourceQuota::new(10, 200, 300, 10, 5, 3, 2, 400));
        let ctx = test_tenant_ctx("test-tenant");
        for _ in 0..9 {
            enforcer.record_request(&ctx);
        }
        let alerts = enforcer.check_alerts(&ctx);
        // 9/10 = 90% >= 80% warning threshold
        let request_alerts: Vec<_> = alerts.iter().filter(|a| a.resource_name == "requests").collect();
        assert_eq!(request_alerts.len(), 1);
        assert_eq!(request_alerts[0].severity, QuotaAlertSeverity::Warning);
    }

    #[test]
    fn enforcer_check_alerts_critical() {
        let mut enforcer = QuotaEnforcer::new(ResourceQuota::new(10, 200, 300, 10, 5, 3, 2, 400));
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.set_thresholds(80.0, 95.0);
        for _ in 0..10 {
            enforcer.record_request(&ctx);
        }
        let alerts = enforcer.check_alerts(&ctx);
        // 10/10 = 100% >= 95% critical threshold
        let request_alerts: Vec<_> = alerts.iter().filter(|a| a.resource_name == "requests").collect();
        assert_eq!(request_alerts.len(), 1);
        assert_eq!(request_alerts[0].severity, QuotaAlertSeverity::Critical);
    }

    #[test]
    fn enforcer_reset_daily() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        let ctx = test_tenant_ctx("test-tenant");
        enforcer.record_request(&ctx);
        enforcer.record_token_usage(&ctx, 500);
        enforcer.reset_daily(&ctx);
        let usage = enforcer.current_usage(&ctx);
        assert_eq!(usage.requests_today, 0);
        assert_eq!(usage.tokens_today, 0);
    }

    #[test]
    fn enforcer_tracked_tenant_count() {
        let enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        assert_eq!(enforcer.tracked_tenant_count(), 0);
        let ctx1 = test_tenant_ctx("tenant-a");
        let ctx2 = test_tenant_ctx("tenant-b");
        enforcer.record_request(&ctx1);
        enforcer.record_request(&ctx2);
        assert_eq!(enforcer.tracked_tenant_count(), 2);
    }

    #[test]
    fn enforcer_set_thresholds_clamped() {
        let mut enforcer = QuotaEnforcer::for_tier(TenantTier::Standard);
        enforcer.set_thresholds(-10.0, 150.0);
        assert_eq!(enforcer.warning_threshold, 0.0);
        assert_eq!(enforcer.critical_threshold, 100.0);
    }

    // ── Helper function tests ──

    #[test]
    fn excess_pct_calculation() {
        let ep = excess_pct(150, 100);
        assert!((ep - 50.0).abs() < 0.01);
    }

    #[test]
    fn excess_pct_zero_limit() {
        let ep = excess_pct(10, 0);
        assert_eq!(ep, 100.0);
    }

    #[test]
    fn pct_function() {
        assert!((pct(50, 100) - 50.0).abs() < 0.01);
        assert!((pct(75, 100) - 75.0).abs() < 0.01);
    }

    #[test]
    fn pct_unlimited() {
        assert_eq!(pct(999, u64::MAX), 0.0);
    }

    #[test]
    fn pct_zero_limit() {
        assert_eq!(pct(0, 0), 0.0);
        assert_eq!(pct(1, 0), 100.0);
    }

    #[test]
    fn is_new_day_true() {
        // Different days
        assert!(is_new_day(86400 * 5, 86400 * 6));
    }

    #[test]
    fn is_new_day_false_same_day() {
        // Same day
        assert!(!is_new_day(86400 * 5, 86400 * 5 + 3600));
    }

    // ── QuotaAlert tests ──

    #[test]
    fn quota_alert_new() {
        let alert = QuotaAlert::new(
            TenantId("acme".to_string()),
            "requests",
            90.0,
            80.0,
            QuotaAlertSeverity::Warning,
        );
        assert_eq!(alert.severity, QuotaAlertSeverity::Warning);
        assert!(!alert.timestamp.is_empty());
        assert!(!alert.message.is_empty());
    }

    #[test]
    fn quota_alert_serialization() {
        let alert = QuotaAlert::new(
            TenantId("acme".to_string()),
            "tokens",
            96.0,
            95.0,
            QuotaAlertSeverity::Critical,
        );
        let json = serde_json::to_string(&alert).unwrap();
        let decoded: QuotaAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.severity, QuotaAlertSeverity::Critical);
    }

    #[test]
    fn quota_alert_severity_display() {
        assert_eq!(format!("{}", QuotaAlertSeverity::Warning), "warning");
        assert_eq!(format!("{}", QuotaAlertSeverity::Critical), "critical");
    }
}
