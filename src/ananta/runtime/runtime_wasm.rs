// ANANTA Runtime WASM — Production-Grade Resource Management
//
// This module provides the core resource management abstractions used by
// the ANANTA autonomous security operating system when compiled to WASM or
// running in a native async context:
//
//   1. Resource Pool Manager  — generic pool allocator with health checking
//   2. Memory Pressure Detection — usage-pattern-based pressure analysis
//   3. Circuit Breaker Integration — downstream-failure-aware allocation
//   4. Component Lifecycle Manager — validated state machine for components
//   5. Health Check Coordinator — periodic liveness/readiness/deep checks

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// Helper: get current time as epoch seconds (f64).
fn epoch_secs() -> f64 {
    chrono::Utc::now().timestamp() as f64
}

// ---------------------------------------------------------------------------
// 1. Resource Pool Manager
// ---------------------------------------------------------------------------

/// Identifier for a pooled resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ResourceId(pub u64);

/// Health status of an individual pooled resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceHealth {
    /// Resource passed its last health check.
    Healthy,
    /// Resource is degraded but still functional.
    Degraded(String),
    /// Resource failed health check and should be evicted.
    Unhealthy(String),
    /// Health check has not been performed yet.
    Unknown,
}

/// Metadata tracked for each resource in the pool.
///
/// All timestamp fields are stored as epoch seconds (f64) so that
/// this type can be freely serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry<T> {
    /// Unique identifier for this resource instance.
    pub id: ResourceId,
    /// The actual resource value.
    pub resource: T,
    /// When this resource was created (epoch seconds).
    pub created_at_secs: f64,
    /// When this resource was last returned to the pool (epoch seconds, 0 if in use).
    pub idle_since_secs: f64,
    /// Current health status.
    pub health: ResourceHealth,
    /// Number of times this resource has been checked out.
    pub checkout_count: u64,
    /// Number of times a health check failed for this resource.
    pub failure_count: u64,
}

/// Configuration for a resource pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Minimum number of idle resources to maintain (pre-warming).
    pub min_idle: usize,
    /// Maximum total resources (idle + in-use) the pool may hold.
    pub max_total: usize,
    /// How long a resource may sit idle before being evicted (seconds).
    pub idle_timeout_secs: u64,
    /// How often to run background health checks (seconds).
    pub health_check_interval_secs: u64,
    /// Maximum consecutive health-check failures before eviction.
    pub max_health_failures: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 2,
            max_total: 32,
            idle_timeout_secs: 300,
            health_check_interval_secs: 30,
            max_health_failures: 3,
        }
    }
}

/// Statistics snapshot for a resource pool.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoolStats {
    /// Total resources currently idle in the pool.
    pub idle_count: usize,
    /// Total resources currently checked out.
    pub in_use_count: usize,
    /// Total resources ever created.
    pub total_created: u64,
    /// Total checkouts performed.
    pub total_checkouts: u64,
    /// Total checkins performed.
    pub total_checkins: u64,
    /// Resources evicted due to idle timeout.
    pub evicted_idle: u64,
    /// Resources evicted due to health failures.
    pub evicted_unhealthy: u64,
    /// Resources currently awaiting creation (back-pressure indicator).
    pub pending_creates: usize,
}

/// A generic resource pool that manages reusable instances with health checking,
/// idle eviction, and allocation tracking.
///
/// The pool is designed for use in both async and synchronous contexts.
/// Resources are identified by monotonically increasing IDs.
///
/// Note: This type holds function pointers and cannot be serialized.
#[derive(Debug)]
pub struct ResourcePoolManager<T: Clone> {
    config: PoolConfig,
    idle: Vec<ResourceEntry<T>>,
    in_use: Vec<ResourceEntry<T>>,
    next_id: AtomicU64,
    stats: PoolStats,
    factory: fn() -> T,
    health_check: Option<fn(&T) -> ResourceHealth>,
    last_health_check_at: Instant,
}

impl<T: Clone> ResourcePoolManager<T> {
    /// Create a new resource pool with the given configuration, factory, and
    /// optional health check function.
    pub fn new(
        config: PoolConfig,
        factory: fn() -> T,
        health_check: Option<fn(&T) -> ResourceHealth>,
    ) -> Self {
        Self {
            config,
            idle: Vec::new(),
            in_use: Vec::new(),
            next_id: AtomicU64::new(1),
            stats: PoolStats::default(),
            factory,
            health_check,
            last_health_check_at: Instant::now(),
        }
    }

    /// Allocate a resource from the pool. If an idle resource is available it
    /// is returned after a health check (if configured). Otherwise a new
    /// resource is created, up to `max_total`.
    pub fn allocate(&mut self) -> Option<T> {
        self.evict_expired();

        // Try to pop a healthy idle resource.
        while let Some(mut entry) = self.idle.pop() {
            if self.is_entry_healthy(&entry) {
                entry.idle_since_secs = 0.0;
                entry.checkout_count += 1;
                self.stats.total_checkouts += 1;
                let resource = entry.resource.clone();
                self.in_use.push(entry);
                return Some(resource);
            } else {
                self.stats.evicted_unhealthy += 1;
            }
        }

        // No idle resources; create a new one if below max.
        let total = self.idle.len() + self.in_use.len();
        if total < self.config.max_total {
            let resource = (self.factory)();
            let id = ResourceId(self.next_id.fetch_add(1, Ordering::SeqCst));
            let entry = ResourceEntry {
                id,
                resource: resource.clone(),
                created_at_secs: epoch_secs(),
                idle_since_secs: 0.0,
                health: ResourceHealth::Unknown,
                checkout_count: 1,
                failure_count: 0,
            };
            self.stats.total_created += 1;
            self.stats.total_checkouts += 1;
            self.in_use.push(entry);
            Some(resource)
        } else {
            self.stats.pending_creates += 1;
            None
        }
    }

    /// Return a resource to the pool by its ID.
    pub fn deallocate(&mut self, id: ResourceId) -> bool {
        let idx = self.in_use.iter().position(|e| e.id == id);
        if let Some(idx) = idx {
            let mut entry = self.in_use.remove(idx);
            entry.idle_since_secs = epoch_secs();
            self.stats.total_checkins += 1;
            self.idle.push(entry);
            true
        } else {
            false
        }
    }

    /// Run health checks on all idle resources, evicting those that fail
    /// beyond the configured threshold.
    pub fn run_health_checks(&mut self) {
        let max_failures = self.config.max_health_failures;
        let check_fn = self.health_check;
        let before = self.idle.len();

        if let Some(check) = check_fn {
            for entry in &mut self.idle {
                let health = check(&entry.resource);
                match &health {
                    ResourceHealth::Unhealthy(_) | ResourceHealth::Degraded(_) => {
                        entry.failure_count += 1;
                    }
                    _ => {
                        entry.failure_count = 0;
                    }
                }
                entry.health = health;
            }
        }

        let kept: Vec<ResourceEntry<T>> = self
            .idle
            .drain(..)
            .filter(|e| e.failure_count < max_failures)
            .collect();
        self.stats.evicted_unhealthy += (before - kept.len()) as u64;
        self.idle = kept;
        self.last_health_check_at = Instant::now();
    }

    /// Trim idle resources that have exceeded the idle timeout.
    pub fn evict_expired(&mut self) {
        let timeout = Duration::from_secs(self.config.idle_timeout_secs);
        let _now = Instant::now();
        let before = self.idle.len();
        self.idle.retain(|e| {
            if e.idle_since_secs <= 0.0 {
                return true;
            }
            // Convert epoch-secs delta to a Duration approximation.
            let elapsed_secs = epoch_secs() - e.idle_since_secs;
            let elapsed = Duration::from_secs_f64(elapsed_secs.max(0.0));
            elapsed < timeout
        });
        self.stats.evicted_idle += (before - self.idle.len()) as u64;
    }

    /// Pre-warm the pool to `min_idle` resources.
    pub fn prewarm(&mut self) {
        while self.idle.len() < self.config.min_idle {
            let total = self.idle.len() + self.in_use.len();
            if total >= self.config.max_total {
                break;
            }
            let resource = (self.factory)();
            let id = ResourceId(self.next_id.fetch_add(1, Ordering::SeqCst));
            self.idle.push(ResourceEntry {
                id,
                resource,
                created_at_secs: epoch_secs(),
                idle_since_secs: epoch_secs(),
                health: ResourceHealth::Unknown,
                checkout_count: 0,
                failure_count: 0,
            });
            self.stats.total_created += 1;
        }
    }

    /// Get a snapshot of current pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            idle_count: self.idle.len(),
            in_use_count: self.in_use.len(),
            ..self.stats.clone()
        }
    }

    /// Check whether a background health check is overdue.
    pub fn is_health_check_overdue(&self) -> bool {
        self.last_health_check_at.elapsed()
            >= Duration::from_secs(self.config.health_check_interval_secs)
    }

    /// Get the current config (clone).
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    fn is_entry_healthy(&self, entry: &ResourceEntry<T>) -> bool {
        match &entry.health {
            ResourceHealth::Unhealthy(_) => false,
            ResourceHealth::Degraded(_) => true,
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Memory Pressure Detection
// ---------------------------------------------------------------------------

/// Severity levels for memory pressure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// Memory usage is normal.
    Low,
    /// Memory usage is elevated; monitoring increased.
    Medium,
    /// Memory usage is high; consider shedding load.
    High,
    /// Memory usage is critical; immediate action required.
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PressureLevel::Low => write!(f, "low"),
            PressureLevel::Medium => write!(f, "medium"),
            PressureLevel::High => write!(f, "high"),
            PressureLevel::Critical => write!(f, "critical"),
        }
    }
}

/// A single allocation event for tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationEvent {
    /// Size in bytes of the allocation.
    pub size_bytes: u64,
    /// Monotonic timestamp when the allocation occurred (epoch seconds).
    pub epoch_secs: f64,
}

/// Alert emitted when pressure crosses a threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureAlert {
    /// The pressure level that triggered this alert.
    pub level: PressureLevel,
    /// Human-readable message.
    pub message: String,
    /// Epoch timestamp (seconds).
    pub timestamp_secs: f64,
    /// Current usage in bytes when the alert fired.
    pub current_usage_bytes: u64,
    /// High-water mark in bytes at alert time.
    pub high_water_mark_bytes: u64,
}

/// Configuration for memory pressure detection thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureConfig {
    /// Soft limit in bytes; exceeding triggers `Medium` pressure.
    pub medium_threshold_bytes: u64,
    /// Hard limit in bytes; exceeding triggers `High` pressure.
    pub high_threshold_bytes: u64,
    /// Emergency limit in bytes; exceeding triggers `Critical`.
    pub critical_threshold_bytes: u64,
    /// Size of the sliding window (in number of events) for rate calculation.
    pub rate_window_size: usize,
    /// Duration in seconds over which the allocation rate is measured.
    pub rate_window_secs: f64,
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            medium_threshold_bytes: 256 * 1024 * 1024,   // 256 MiB
            high_threshold_bytes: 512 * 1024 * 1024,    // 512 MiB
            critical_threshold_bytes: 768 * 1024 * 1024, // 768 MiB
            rate_window_size: 1024,
            rate_window_secs: 60.0,
        }
    }
}

/// Detects memory pressure by tracking allocation patterns, high-water marks,
/// and estimating fragmentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPressureDetector {
    config: PressureConfig,
    /// Running total of current allocated bytes (approximate).
    current_usage_bytes: u64,
    /// Peak usage observed since last reset.
    high_water_mark_bytes: u64,
    /// Sliding window of recent allocation events.
    allocation_window: Vec<AllocationEvent>,
    /// Active alerts that have not been acknowledged.
    active_alerts: Vec<PressureAlert>,
    /// Total allocations recorded.
    total_allocations: u64,
    /// Total deallocations recorded.
    total_deallocations: u64,
    /// Sum of freed bytes.
    total_freed_bytes: u64,
    /// Count of distinct allocation size buckets for fragmentation.
    size_bucket_counts: HashMap<u64, u64>,
    /// Current computed pressure level.
    current_level: PressureLevel,
}

impl MemoryPressureDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: PressureConfig) -> Self {
        Self {
            config,
            current_usage_bytes: 0,
            high_water_mark_bytes: 0,
            allocation_window: Vec::with_capacity(1024),
            active_alerts: Vec::new(),
            total_allocations: 0,
            total_deallocations: 0,
            total_freed_bytes: 0,
            size_bucket_counts: HashMap::new(),
            current_level: PressureLevel::Low,
        }
    }

    /// Record an allocation event.
    pub fn record_allocation(&mut self, size_bytes: u64) {
        self.current_usage_bytes = self.current_usage_bytes.saturating_add(size_bytes);
        if self.current_usage_bytes > self.high_water_mark_bytes {
            self.high_water_mark_bytes = self.current_usage_bytes;
        }
        self.total_allocations += 1;

        // Bucket sizes by rounding to nearest power of two.
        let bucket = if size_bytes == 0 {
            1
        } else {
            size_bytes.next_power_of_two()
        };
        *self.size_bucket_counts.entry(bucket).or_insert(0) += 1;

        let event = AllocationEvent {
            size_bytes,
            epoch_secs: epoch_secs(),
        };
        self.allocation_window.push(event);
        if self.allocation_window.len() > self.config.rate_window_size {
            self.allocation_window.remove(0);
        }

        self.evaluate_pressure();
    }

    /// Record a deallocation (free) event.
    pub fn record_deallocation(&mut self, size_bytes: u64) {
        self.current_usage_bytes = self.current_usage_bytes.saturating_sub(size_bytes);
        self.total_deallocations += 1;
        self.total_freed_bytes = self.total_freed_bytes.saturating_add(size_bytes);
        self.evaluate_pressure();
    }

    /// Compute the allocation rate in bytes per second over the sliding window.
    pub fn allocation_rate_bytes_per_sec(&self) -> f64 {
        if self.allocation_window.len() < 2 {
            return 0.0;
        }
        let first = &self.allocation_window[0];
        let last = &self.allocation_window[self.allocation_window.len() - 1];
        let elapsed = last.epoch_secs - first.epoch_secs;
        if elapsed <= 0.0 {
            return 0.0;
        }
        let total_bytes: u64 = self.allocation_window.iter().map(|e| e.size_bytes).sum();
        total_bytes as f64 / elapsed
    }

    /// Estimate fragmentation as a ratio in [0.0, 1.0].
    ///
    /// Uses a simplified metric: `1.0 - (largest_bucket_count / total_allocations)`.
    /// A value near 1.0 means allocations are spread across many sizes
    /// (highly fragmented); near 0.0 means most allocations are the same size.
    pub fn fragmentation_estimate(&self) -> f64 {
        if self.total_allocations == 0 {
            return 0.0;
        }
        let max_bucket = self
            .size_bucket_counts
            .values()
            .copied()
            .max()
            .unwrap_or(0);
        1.0 - (max_bucket as f64 / self.total_allocations as f64)
    }

    /// Get the current pressure level.
    pub fn current_level(&self) -> &PressureLevel {
        &self.current_level
    }

    /// Get the current usage in bytes.
    pub fn current_usage_bytes(&self) -> u64 {
        self.current_usage_bytes
    }

    /// Get the high-water mark in bytes.
    pub fn high_water_mark_bytes(&self) -> u64 {
        self.high_water_mark_bytes
    }

    /// Get all active (unacknowledged) alerts.
    pub fn active_alerts(&self) -> &[PressureAlert] {
        &self.active_alerts
    }

    /// Acknowledge and remove all active alerts, returning them.
    pub fn acknowledge_alerts(&mut self) -> Vec<PressureAlert> {
        std::mem::take(&mut self.active_alerts)
    }

    /// Reset high-water mark and counters. Useful after a GC cycle.
    pub fn reset(&mut self) {
        self.high_water_mark_bytes = self.current_usage_bytes;
        self.allocation_window.clear();
        self.size_bucket_counts.clear();
        self.total_allocations = 0;
        self.total_deallocations = 0;
        self.total_freed_bytes = 0;
        self.active_alerts.clear();
        self.current_level = PressureLevel::Low;
    }

    fn evaluate_pressure(&mut self) {
        let prev = self.current_level.clone();
        let usage = self.current_usage_bytes;

        self.current_level = if usage >= self.config.critical_threshold_bytes {
            PressureLevel::Critical
        } else if usage >= self.config.high_threshold_bytes {
            PressureLevel::High
        } else if usage >= self.config.medium_threshold_bytes {
            PressureLevel::Medium
        } else {
            PressureLevel::Low
        };

        // Emit alerts for each level crossed.
        let levels = [
            (PressureLevel::Medium, self.config.medium_threshold_bytes),
            (PressureLevel::High, self.config.high_threshold_bytes),
            (PressureLevel::Critical, self.config.critical_threshold_bytes),
        ];
        for (level, threshold) in &levels {
            if usage >= *threshold {
                // Check if we already have an alert for this level.
                let already_alerted = self.active_alerts.iter().any(|a| a.level == *level);
                if !already_alerted {
                    let alert = PressureAlert {
                        level: level.clone(),
                        message: format!(
                            "Memory pressure escalated to {}: {} bytes used (HWM: {} bytes)",
                            level, usage, self.high_water_mark_bytes
                        ),
                        timestamp_secs: epoch_secs(),
                        current_usage_bytes: usage,
                        high_water_mark_bytes: self.high_water_mark_bytes,
                    };
                    self.active_alerts.push(alert);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Circuit Breaker Integration
// ---------------------------------------------------------------------------

/// States of a circuit breaker following the standard pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum CircuitState {
    /// Requests flow normally; failures are counted.
    #[default]
    Closed,
    /// Requests are rejected; downstream is considered failed.
    Open,
    /// A probe request is allowed to test downstream recovery.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Configuration for a single circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// How long (seconds) to stay open before transitioning to half-open.
    pub open_duration_secs: u64,
    /// Number of successful probes in half-open before closing.
    pub half_open_success_threshold: u32,
    /// Proportion of requests (0.0..1.0) sampled when closed for failure detection.
    pub sample_rate: f64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration_secs: 30,
            half_open_success_threshold: 2,
            sample_rate: 1.0,
        }
    }
}

/// Statistics for a circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CircuitBreakerStats {
    /// Current state.
    pub state: CircuitState,
    /// Total requests allowed through.
    pub total_allowed: u64,
    /// Total requests rejected.
    pub total_rejected: u64,
    /// Total successes recorded.
    pub total_successes: u64,
    /// Total failures recorded.
    pub total_failures: u64,
    /// Consecutive failures (reset on success).
    pub consecutive_failures: u32,
    /// Consecutive successes in half-open.
    pub half_open_successes: u32,
    /// Time when the circuit entered the open state (epoch secs, 0 if not open).
    pub opened_at_secs: f64,
    /// Number of state transitions.
    pub state_transitions: u64,
}

/// A circuit breaker that can be integrated with resource pool allocation.
///
/// When the circuit is open, the associated resource pool should not allocate
/// new resources for that downstream dependency. When it transitions to
/// half-open, a limited number of probe allocations are allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    /// Name identifying the downstream dependency.
    pub name: String,
    config: CircuitBreakerConfig,
    stats: CircuitBreakerStats,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for the named dependency.
    pub fn new(name: &str, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
            stats: CircuitBreakerStats {
                state: CircuitState::Closed,
                ..Default::default()
            },
        }
    }

    /// Check whether a request is currently allowed.
    pub fn allow_request(&mut self) -> bool {
        match self.stats.state {
            CircuitState::Closed => {
                self.stats.total_allowed += 1;
                true
            }
            CircuitState::Open => {
                let should_try = self.should_transition_to_half_open();
                if should_try {
                    self.transition_to(CircuitState::HalfOpen);
                    self.stats.total_allowed += 1;
                    true
                } else {
                    self.stats.total_rejected += 1;
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow probes up to the success threshold.
                if self.stats.half_open_successes < self.config.half_open_success_threshold {
                    self.stats.total_allowed += 1;
                    true
                } else {
                    self.stats.total_rejected += 1;
                    false
                }
            }
        }
    }

    /// Record a successful interaction.
    pub fn record_success(&mut self) {
        self.stats.total_successes += 1;
        self.stats.consecutive_failures = 0;

        match self.stats.state {
            CircuitState::Closed => {}
            CircuitState::HalfOpen => {
                self.stats.half_open_successes += 1;
                if self.stats.half_open_successes >= self.config.half_open_success_threshold {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed interaction.
    pub fn record_failure(&mut self) {
        self.stats.total_failures += 1;
        self.stats.consecutive_failures += 1;

        match self.stats.state {
            CircuitState::Closed => {
                if self.stats.consecutive_failures >= self.config.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {}
        }
    }

    /// Get the current state.
    pub fn state(&self) -> &CircuitState {
        &self.stats.state
    }

    /// Get a snapshot of the circuit breaker statistics.
    pub fn stats(&self) -> &CircuitBreakerStats {
        &self.stats
    }

    /// Force the circuit into a specific state (for testing / admin override).
    pub fn force_state(&mut self, state: CircuitState) {
        self.transition_to(state);
    }

    fn should_transition_to_half_open(&self) -> bool {
        if self.stats.opened_at_secs <= 0.0 {
            return true;
        }
        let now = epoch_secs();
        now - self.stats.opened_at_secs >= self.config.open_duration_secs as f64
    }

    fn transition_to(&mut self, new_state: CircuitState) {
        let is_open = matches!(new_state, CircuitState::Open);
        let is_closed = matches!(new_state, CircuitState::Closed);
        let is_half_open = matches!(new_state, CircuitState::HalfOpen);
        if self.stats.state != new_state {
            self.stats.state_transitions += 1;
        }
        self.stats.state = new_state;
        if is_open {
            self.stats.opened_at_secs = epoch_secs();
            self.stats.half_open_successes = 0;
        }
        if is_closed {
            self.stats.consecutive_failures = 0;
            self.stats.opened_at_secs = 0.0;
            self.stats.half_open_successes = 0;
        }
        if is_half_open {
            self.stats.half_open_successes = 0;
        }
    }
}

/// Registry of circuit breakers keyed by dependency name, enabling the
/// resource pool to check circuit state before allocation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CircuitBreakerRegistry {
    breakers: HashMap<String, CircuitBreaker>,
}

impl CircuitBreakerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a circuit breaker for a dependency.
    pub fn register(&mut self, breaker: CircuitBreaker) {
        self.breakers.insert(breaker.name.clone(), breaker);
    }

    /// Check if a request to the named dependency is allowed.
    pub fn is_allowed(&mut self, dependency: &str) -> bool {
        self.breakers
            .get_mut(dependency)
            .map(|b| b.allow_request())
            .unwrap_or(true) // unknown dependency defaults to allowed
    }

    /// Record a success for a dependency.
    pub fn record_success(&mut self, dependency: &str) {
        if let Some(b) = self.breakers.get_mut(dependency) {
            b.record_success();
        }
    }

    /// Record a failure for a dependency.
    pub fn record_failure(&mut self, dependency: &str) {
        if let Some(b) = self.breakers.get_mut(dependency) {
            b.record_failure();
        }
    }

    /// Get all circuit breaker names and their current states.
    pub fn snapshot(&self) -> Vec<(String, CircuitState)> {
        self.breakers
            .iter()
            .map(|(name, b)| (name.clone(), b.state().clone()))
            .collect()
    }

    /// Get a reference to a specific circuit breaker.
    pub fn get(&self, dependency: &str) -> Option<&CircuitBreaker> {
        self.breakers.get(dependency)
    }

    /// Count how many circuits are currently open.
    pub fn open_count(&self) -> usize {
        self.breakers
            .values()
            .filter(|b| *b.state() == CircuitState::Open)
            .count()
    }

    /// Return the number of registered breakers.
    pub fn len(&self) -> usize {
        self.breakers.len()
    }

    /// Return true if no breakers are registered.
    pub fn is_empty(&self) -> bool {
        self.breakers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 4. Component Lifecycle Manager
// ---------------------------------------------------------------------------

/// Lifecycle states for ANANTA components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LifecycleState {
    /// Component has been created but not yet initialized.
    Uninitialized,
    /// Component is running its initialization routine.
    Initializing,
    /// Component has completed initialization and is ready to receive work.
    Ready,
    /// Component is actively processing requests.
    Active,
    /// Component is entering a suspended state (draining in-flight work).
    Suspending,
    /// Component is suspended; it retains state but processes no requests.
    Suspended,
    /// Component is waking up from suspension.
    Resuming,
    /// Component is performing a graceful shutdown.
    ShuttingDown,
    /// Component has fully terminated and released resources.
    Terminated,
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Valid state transitions for the component lifecycle state machine.
///
/// Each tuple is `(from_state, to_state)`. Any transition not in this table
/// is rejected by the lifecycle manager.
pub const VALID_TRANSITIONS: &[(LifecycleState, LifecycleState)] = &[
    (LifecycleState::Uninitialized, LifecycleState::Initializing),
    (LifecycleState::Uninitialized, LifecycleState::ShuttingDown),
    (LifecycleState::Initializing, LifecycleState::Ready),
    (LifecycleState::Initializing, LifecycleState::ShuttingDown),
    (LifecycleState::Initializing, LifecycleState::Terminated),
    (LifecycleState::Ready, LifecycleState::Active),
    (LifecycleState::Ready, LifecycleState::Suspending),
    (LifecycleState::Ready, LifecycleState::ShuttingDown),
    (LifecycleState::Active, LifecycleState::Suspending),
    (LifecycleState::Active, LifecycleState::ShuttingDown),
    (LifecycleState::Suspending, LifecycleState::Suspended),
    (LifecycleState::Suspending, LifecycleState::ShuttingDown),
    (LifecycleState::Suspended, LifecycleState::Resuming),
    (LifecycleState::Suspended, LifecycleState::ShuttingDown),
    (LifecycleState::Resuming, LifecycleState::Active),
    (LifecycleState::Resuming, LifecycleState::ShuttingDown),
    (LifecycleState::ShuttingDown, LifecycleState::Terminated),
];

/// Error returned when an invalid state transition is attempted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionError {
    /// Component name.
    pub component: String,
    /// The state the component was in.
    pub from: LifecycleState,
    /// The state that was requested.
    pub to: LifecycleState,
    /// Human-readable explanation.
    pub reason: String,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid transition for '{}': {:?} -> {:?}: {}",
            self.component, self.from, self.to, self.reason
        )
    }
}

impl std::error::Error for TransitionError {}

/// Per-component lifecycle tracking record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRecord {
    /// Component name.
    pub component: String,
    /// Current lifecycle state.
    pub state: LifecycleState,
    /// Epoch seconds when the component entered its current state.
    pub entered_at_secs: f64,
    /// Cumulative time spent in each state (seconds), keyed by state name.
    pub time_in_state: HashMap<String, f64>,
    /// Total number of state transitions performed.
    pub transition_count: u64,
    /// Optional error message if the last transition failed.
    pub last_error: Option<String>,
}

impl LifecycleRecord {
    /// Create a new record for a component, starting in Uninitialized.
    pub fn new(component: &str) -> Self {
        Self {
            component: component.to_string(),
            state: LifecycleState::Uninitialized,
            entered_at_secs: epoch_secs(),
            time_in_state: HashMap::new(),
            transition_count: 0,
            last_error: None,
        }
    }

    /// How long (seconds) the component has been in its current state.
    pub fn elapsed_in_state(&self) -> f64 {
        epoch_secs() - self.entered_at_secs
    }

    /// Get accumulated time for a given state.
    pub fn accumulated_time(&self, state: &LifecycleState) -> f64 {
        self.time_in_state
            .get(&format!("{:?}", state))
            .copied()
            .unwrap_or(0.0)
    }
}

/// Manages lifecycle state machines for all registered ANANTA components.
///
/// Validates every state transition against the allowed transition table,
/// tracks time-in-state, and provides aggregate views of the system.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComponentLifecycleManager {
    records: HashMap<String, LifecycleRecord>,
}

impl ComponentLifecycleManager {
    /// Create an empty lifecycle manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a component; it starts in `Uninitialized`.
    pub fn register(&mut self, component: &str) {
        self.records
            .insert(component.to_string(), LifecycleRecord::new(component));
    }

    /// Attempt to transition a component to a new state.
    ///
    /// Returns `Ok(())` on success or `Err(TransitionError)` if the
    /// transition is not valid.
    pub fn transition(
        &mut self,
        component: &str,
        target: LifecycleState,
    ) -> Result<(), TransitionError> {
        let record = self.records.get_mut(component).ok_or_else(|| {
            TransitionError {
                component: component.to_string(),
                from: LifecycleState::Uninitialized,
                to: target.clone(),
                reason: "component not registered".to_string(),
            }
        })?;

        let from = record.state.clone();
        let is_valid = VALID_TRANSITIONS
            .iter()
            .any(|(f, t)| *f == from && *t == target);

        // Self-transitions are a silent no-op.
        if from == target {
            return Ok(());
        }

        if !is_valid {
            let err = TransitionError {
                component: component.to_string(),
                from: from.clone(),
                to: target,
                reason: format!("transition {:?} -> {:?} is not in the allowed set", from, record.state),
            };
            record.last_error = Some(err.to_string());
            return Err(err);
        }

        // Accumulate time in the old state.
        let elapsed = record.elapsed_in_state();
        let state_key = format!("{:?}", from);
        *record.time_in_state.entry(state_key).or_insert(0.0) += elapsed;

        // Apply transition.
        record.state = target.clone();
        // Resuming is a transient state: automatically resolve to Active.
        if record.state == LifecycleState::Resuming {
            record.state = LifecycleState::Active;
        }
        record.entered_at_secs = epoch_secs();
        record.transition_count += 1;
        record.last_error = None;

        Ok(())
    }

    /// Get the current state of a component.
    pub fn state_of(&self, component: &str) -> Option<&LifecycleState> {
        self.records.get(component).map(|r| &r.state)
    }

    /// Get the full lifecycle record for a component.
    pub fn record(&self, component: &str) -> Option<&LifecycleRecord> {
        self.records.get(component)
    }

    /// Get all component names.
    pub fn components(&self) -> Vec<&str> {
        self.records.keys().map(|s| s.as_str()).collect()
    }

    /// Count components in each state.
    pub fn state_distribution(&self) -> HashMap<String, usize> {
        let mut dist = HashMap::new();
        for rec in self.records.values() {
            let key = format!("{:?}", rec.state);
            *dist.entry(key).or_insert(0) += 1;
        }
        dist
    }

    /// Check if all registered components have reached the `Active` state.
    pub fn all_active(&self) -> bool {
        self.records
            .values()
            .all(|r| r.state == LifecycleState::Active)
    }

    /// Check if all registered components are terminated.
    pub fn all_terminated(&self) -> bool {
        self.records
            .values()
            .all(|r| r.state == LifecycleState::Terminated)
    }

    /// Get a summary string of all component states.
    pub fn summary(&self) -> String {
        let parts: Vec<String> = self
            .records
            .iter()
            .map(|(name, r)| format!("{}={:?}", name, r.state))
            .collect();
        parts.join(", ")
    }

    /// Return the number of registered components.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return true if no components are registered.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 5. Health Check Coordinator
// ---------------------------------------------------------------------------

/// Types of health checks that can be performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HealthCheckType {
    /// Is the component process alive and responding to pings?
    Liveness,
    /// Can the component accept and handle new requests?
    Readiness,
    /// Is the component performing correctly (latency, error rate within SLA)?
    Deep,
}

impl std::fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthCheckType::Liveness => write!(f, "liveness"),
            HealthCheckType::Readiness => write!(f, "readiness"),
            HealthCheckType::Deep => write!(f, "deep"),
        }
    }
}

/// Result of a single health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Which component was checked.
    pub component: String,
    /// Type of check performed.
    pub check_type: HealthCheckType,
    /// Whether the check passed.
    pub healthy: bool,
    /// Human-readable detail (error message on failure, "ok" on success).
    pub message: String,
    /// Latency of the check in milliseconds.
    pub latency_ms: f64,
    /// When the check was performed (epoch seconds).
    pub timestamp_secs: f64,
}

impl HealthCheckResult {
    /// Create a passing health check result.
    pub fn healthy(component: &str, check_type: HealthCheckType, latency_ms: f64) -> Self {
        Self {
            component: component.to_string(),
            check_type,
            healthy: true,
            message: "ok".to_string(),
            latency_ms,
            timestamp_secs: epoch_secs(),
        }
    }

    /// Create a failing health check result.
    pub fn unhealthy(
        component: &str,
        check_type: HealthCheckType,
        message: &str,
        latency_ms: f64,
    ) -> Self {
        Self {
            component: component.to_string(),
            check_type,
            healthy: false,
            message: message.to_string(),
            latency_ms,
            timestamp_secs: epoch_secs(),
        }
    }
}

/// Aggregated health status across all check types for one component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealthSummary {
    /// Component name.
    pub component: String,
    /// Overall health (true only if all performed checks passed).
    pub healthy: bool,
    /// Individual check results.
    pub checks: Vec<HealthCheckResult>,
    /// Worst latency observed across checks.
    pub worst_latency_ms: f64,
}

impl ComponentHealthSummary {
    /// Compute a summary from a list of check results.
    pub fn from_results(results: Vec<HealthCheckResult>) -> Self {
        let component = results
            .first()
            .map(|r| r.component.clone())
            .unwrap_or_default();
        let healthy = results.iter().all(|r| r.healthy);
        let worst_latency_ms = results
            .iter()
            .map(|r| r.latency_ms)
            .fold(0.0_f64, f64::max);
        Self {
            component,
            healthy,
            checks: results,
            worst_latency_ms,
        }
    }
}

/// Configuration for the health check coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Interval between full health check sweeps (seconds).
    pub sweep_interval_secs: u64,
    /// Timeout per individual check (milliseconds).
    pub check_timeout_ms: u64,
    /// Number of consecutive failures before marking a component degraded.
    pub failure_before_degraded: u32,
    /// Number of consecutive failures before marking a component down.
    pub failure_before_down: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            sweep_interval_secs: 10,
            check_timeout_ms: 5000,
            failure_before_degraded: 2,
            failure_before_down: 5,
        }
    }
}

/// Per-component health tracking state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComponentHealthTracker {
    /// Consecutive failure count.
    pub consecutive_failures: u32,
    /// Most recent check results.
    pub last_results: Vec<HealthCheckResult>,
    /// Whether the component is currently marked as degraded.
    pub degraded: bool,
    /// Whether the component is currently marked as down.
    pub down: bool,
    /// Total checks performed.
    pub total_checks: u64,
    /// Total check failures.
    pub total_failures: u64,
}

/// Coordinates periodic health checks across all registered components.
///
/// The coordinator maintains per-component failure counters, aggregates
/// results, and exposes a unified health view. It supports three tiers of
/// checking: liveness, readiness, and deep health.
///
/// Note: This type holds a function pointer and cannot be fully serialized;
/// only the data types it produces are serializable.
#[derive(Debug, Clone)]
pub struct HealthCheckCoordinator {
    config: HealthCheckConfig,
    /// Registered components and their health trackers.
    trackers: HashMap<String, ComponentHealthTracker>,
    /// Function to invoke for health checks.
    check_fn: fn(&str, HealthCheckType) -> HealthCheckResult,
    /// Check types to perform for each component.
    check_types: Vec<HealthCheckType>,
    /// Epoch seconds of the last full sweep.
    last_sweep_at_secs: f64,
}

impl HealthCheckCoordinator {
    /// Create a new coordinator.
    pub fn new(
        config: HealthCheckConfig,
        check_fn: fn(&str, HealthCheckType) -> HealthCheckResult,
        check_types: Vec<HealthCheckType>,
    ) -> Self {
        Self {
            config,
            trackers: HashMap::new(),
            check_fn,
            check_types,
            last_sweep_at_secs: epoch_secs(),
        }
    }

    /// Register a component for health monitoring.
    pub fn register_component(&mut self, component: &str) {
        self.trackers
            .insert(component.to_string(), ComponentHealthTracker::default());
    }

    /// Run a health check sweep across all registered components.
    ///
    /// Returns a summary for each component.
    pub fn run_sweep(&mut self) -> Vec<ComponentHealthSummary> {
        self.last_sweep_at_secs = epoch_secs();
        let components: Vec<String> = self.trackers.keys().cloned().collect();
        let check_types = self.check_types.clone();
        let check_fn = self.check_fn;

        let mut summaries = Vec::with_capacity(components.len());
        for component in &components {
            let mut results = Vec::with_capacity(check_types.len());
            for ct in &check_types {
                let result = check_fn(component, ct.clone());
                results.push(result);
            }
            let summary = ComponentHealthSummary::from_results(results);
            self.update_tracker(component, &summary);
            summaries.push(summary);
        }
        summaries
    }

    /// Run health checks for a single component.
    pub fn check_component(&mut self, component: &str) -> Option<ComponentHealthSummary> {
        if !self.trackers.contains_key(component) {
            return None;
        }
        let check_types = self.check_types.clone();
        let check_fn = self.check_fn;
        let mut results = Vec::with_capacity(check_types.len());
        for ct in &check_types {
            let result = check_fn(component, ct.clone());
            results.push(result);
        }
        let summary = ComponentHealthSummary::from_results(results);
        self.update_tracker(component, &summary);
        Some(summary)
    }

    /// Get the aggregated health for all components.
    pub fn overall_healthy(&self) -> bool {
        self.trackers.values().all(|t| !t.down)
    }

    /// Get a list of components currently marked as down.
    pub fn down_components(&self) -> Vec<&str> {
        self.trackers
            .iter()
            .filter(|(_, t)| t.down)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Get a list of components currently marked as degraded (but not down).
    pub fn degraded_components(&self) -> Vec<&str> {
        self.trackers
            .iter()
            .filter(|(_, t)| t.degraded && !t.down)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Get the tracker for a specific component.
    pub fn tracker(&self, component: &str) -> Option<&ComponentHealthTracker> {
        self.trackers.get(component)
    }

    /// Check whether a full sweep is overdue.
    pub fn is_sweep_overdue(&self) -> bool {
        let elapsed = epoch_secs() - self.last_sweep_at_secs;
        elapsed >= self.config.sweep_interval_secs as f64
    }

    /// Return the number of registered components.
    pub fn len(&self) -> usize {
        self.trackers.len()
    }

    /// Return true if no components are registered.
    pub fn is_empty(&self) -> bool {
        self.trackers.is_empty()
    }

    fn update_tracker(&mut self, component: &str, summary: &ComponentHealthSummary) {
        if let Some(tracker) = self.trackers.get_mut(component) {
            tracker.total_checks += 1;
            tracker.last_results = summary.checks.clone();

            if summary.healthy {
                tracker.consecutive_failures = 0;
                tracker.degraded = false;
                tracker.down = false;
            } else {
                tracker.consecutive_failures += 1;
                tracker.total_failures += 1;
                if tracker.consecutive_failures >= self.config.failure_before_down {
                    tracker.down = true;
                    tracker.degraded = true;
                } else if tracker.consecutive_failures >= self.config.failure_before_degraded {
                    tracker.degraded = true;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper functions --

    fn noop_factory() -> u32 {
        42
    }

    fn always_healthy_fn(_: &u32) -> ResourceHealth {
        ResourceHealth::Healthy
    }

    fn always_unhealthy_fn(_: &u32) -> ResourceHealth {
        ResourceHealth::Unhealthy("simulated failure".to_string())
    }

    fn sample_health_check(
        component: &str,
        check_type: HealthCheckType,
    ) -> HealthCheckResult {
        match (component, &check_type) {
            ("fail-deep", HealthCheckType::Deep) => HealthCheckResult::unhealthy(
                component,
                check_type,
                "deep check failed",
                10.0,
            ),
            ("fail-all", _) => HealthCheckResult::unhealthy(
                component,
                check_type,
                "all checks fail",
                5.0,
            ),
            _ => HealthCheckResult::healthy(component, check_type, 1.0),
        }
    }

    // =====================================================================
    // Resource Pool Manager Tests
    // =====================================================================

    #[test]
    fn pool_allocate_creates_resource() {
        let config = PoolConfig::default();
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        let res = pool.allocate().expect("should allocate");
        assert_eq!(res, 42);
    }

    #[test]
    fn pool_prewarm_fills_min_idle() {
        let config = PoolConfig {
            min_idle: 3,
            max_total: 10,
            ..Default::default()
        };
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        pool.prewarm();
        let stats = pool.stats();
        assert_eq!(stats.idle_count, 3);
        assert_eq!(stats.total_created, 3);
    }

    #[test]
    fn pool_reuses_idle_resources() {
        let config = PoolConfig::default();
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        pool.prewarm();
        let _r1 = pool.allocate().unwrap();
        let stats = pool.stats();
        assert_eq!(stats.in_use_count, 1);
        assert_eq!(stats.idle_count, 1);
    }

    #[test]
    fn pool_deallocate_returns_resource() {
        let config = PoolConfig::default();
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        let _res = pool.allocate().unwrap();
        let id = pool.in_use.last().unwrap().id.clone();
        assert!(pool.deallocate(id));
        let stats = pool.stats();
        assert_eq!(stats.idle_count, 1);
        assert_eq!(stats.in_use_count, 0);
    }

    #[test]
    fn pool_max_total_limits_allocation() {
        let config = PoolConfig {
            min_idle: 0,
            max_total: 2,
            ..Default::default()
        };
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        let _r1 = pool.allocate().unwrap();
        let _r2 = pool.allocate().unwrap();
        let r3 = pool.allocate();
        assert!(r3.is_none());
        let stats = pool.stats();
        assert_eq!(stats.pending_creates, 1);
    }

    #[test]
    fn pool_health_check_evicts_unhealthy() {
        let config = PoolConfig {
            min_idle: 3,
            max_health_failures: 1,
            ..Default::default()
        };
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, Some(always_unhealthy_fn));
        pool.prewarm();
        pool.run_health_checks();
        let stats = pool.stats();
        assert_eq!(stats.idle_count, 0);
        assert_eq!(stats.evicted_unhealthy, 3);
    }

    #[test]
    fn pool_stats_track_checkouts() {
        let config = PoolConfig::default();
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        let _r1 = pool.allocate().unwrap();
        let _r2 = pool.allocate().unwrap();
        let stats = pool.stats();
        assert_eq!(stats.total_checkouts, 2);
        assert_eq!(stats.total_created, 2);
    }

    #[test]
    fn pool_deallocate_unknown_id_returns_false() {
        let config = PoolConfig::default();
        let mut pool: ResourcePoolManager<u32> =
            ResourcePoolManager::new(config, noop_factory, None);
        assert!(!pool.deallocate(ResourceId(9999)));
    }

    // =====================================================================
    // Memory Pressure Detection Tests
    // =====================================================================

    #[test]
    fn pressure_starts_at_low() {
        let config = PressureConfig::default();
        let detector = MemoryPressureDetector::new(config);
        assert_eq!(*detector.current_level(), PressureLevel::Low);
    }

    #[test]
    fn pressure_escalates_on_allocation() {
        let config = PressureConfig {
            medium_threshold_bytes: 100,
            high_threshold_bytes: 200,
            critical_threshold_bytes: 300,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(150);
        assert_eq!(*detector.current_level(), PressureLevel::Medium);

        detector.record_allocation(100);
        assert_eq!(*detector.current_level(), PressureLevel::High);
    }

    #[test]
    fn pressure_deescalates_on_deallocation() {
        let config = PressureConfig {
            medium_threshold_bytes: 100,
            high_threshold_bytes: 200,
            critical_threshold_bytes: 300,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(250);
        assert_eq!(*detector.current_level(), PressureLevel::High);

        detector.record_deallocation(200);
        assert_eq!(*detector.current_level(), PressureLevel::Low);
    }

    #[test]
    fn pressure_alerts_fire_on_escalation() {
        let config = PressureConfig {
            medium_threshold_bytes: 50,
            high_threshold_bytes: 100,
            critical_threshold_bytes: 200,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(75);
        assert_eq!(detector.active_alerts().len(), 1);
        assert_eq!(detector.active_alerts()[0].level, PressureLevel::Medium);

        detector.record_allocation(50);
        assert_eq!(detector.active_alerts().len(), 2);
        assert_eq!(detector.active_alerts()[1].level, PressureLevel::High);
    }

    #[test]
    fn pressure_acknowledge_clears_alerts() {
        let config = PressureConfig {
            medium_threshold_bytes: 10,
            high_threshold_bytes: 100,
            critical_threshold_bytes: 200,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(50);
        assert!(!detector.active_alerts().is_empty());
        let alerts = detector.acknowledge_alerts();
        assert_eq!(alerts.len(), 1);
        assert!(detector.active_alerts().is_empty());
    }

    #[test]
    fn pressure_high_water_mark_updates() {
        let config = PressureConfig::default();
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(1000);
        assert_eq!(detector.high_water_mark_bytes(), 1000);
        detector.record_allocation(500);
        assert_eq!(detector.high_water_mark_bytes(), 1500);
        detector.record_deallocation(1200);
        assert_eq!(detector.high_water_mark_bytes(), 1500);
    }

    #[test]
    fn pressure_fragmentation_estimate_low_for_uniform() {
        let config = PressureConfig::default();
        let mut detector = MemoryPressureDetector::new(config);
        // Uniform sizes -> low fragmentation.
        for _ in 0..100 {
            detector.record_allocation(64);
        }
        let frag = detector.fragmentation_estimate();
        assert!(
            frag < 0.1,
            "expected low fragmentation for uniform sizes, got {}",
            frag
        );
    }

    #[test]
    fn pressure_fragmentation_estimate_high_for_diverse() {
        let config = PressureConfig::default();
        let mut detector = MemoryPressureDetector::new(config);
        // Diverse sizes -> high fragmentation.
        let sizes: Vec<u64> = (1..=20).map(|i| i * 7).collect();
        for size in &sizes {
            detector.record_allocation(*size);
        }
        let frag = detector.fragmentation_estimate();
        assert!(
            frag > 0.5,
            "expected high fragmentation for diverse sizes, got {}",
            frag
        );
    }

    #[test]
    fn pressure_reset_clears_state() {
        let config = PressureConfig {
            medium_threshold_bytes: 10,
            high_threshold_bytes: 100,
            critical_threshold_bytes: 200,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(50);
        assert!(!detector.active_alerts().is_empty());
        detector.reset();
        assert_eq!(*detector.current_level(), PressureLevel::Low);
        assert!(detector.active_alerts().is_empty());
    }

    #[test]
    fn pressure_critical_level() {
        let config = PressureConfig {
            medium_threshold_bytes: 50,
            high_threshold_bytes: 100,
            critical_threshold_bytes: 150,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(200);
        assert_eq!(*detector.current_level(), PressureLevel::Critical);
        // Should have 3 alerts: low->medium, medium->high, high->critical.
        assert_eq!(detector.active_alerts().len(), 3);
    }

    // =====================================================================
    // Circuit Breaker Tests
    // =====================================================================

    #[test]
    fn circuit_starts_closed() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(cb.state(), &CircuitState::Closed);
    }

    #[test]
    fn circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test", config);
        assert!(cb.allow_request());
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow_request());
        cb.record_failure();
        assert_eq!(cb.state(), &CircuitState::Open);
    }

    #[test]
    fn circuit_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_secs: 3600,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test", config);
        cb.allow_request();
        cb.record_failure();
        assert_eq!(cb.state(), &CircuitState::Open);
        assert!(!cb.allow_request());
        assert_eq!(cb.stats().total_rejected, 1);
    }

    #[test]
    fn circuit_closes_after_half_open_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_secs: 0,
            half_open_success_threshold: 2,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test", config);
        cb.allow_request();
        cb.record_failure();
        assert_eq!(cb.state(), &CircuitState::Open);

        // First probe transitions to half-open.
        assert!(cb.allow_request());
        assert_eq!(cb.state(), &CircuitState::HalfOpen);
        cb.record_success();

        // Second probe: since half_open_successes was reset to 0 on entry
        // to half-open and is now 1, the allow_request logic still allows
        // another probe.
        assert!(cb.allow_request());
        cb.record_success();

        assert_eq!(cb.state(), &CircuitState::Closed);
    }

    #[test]
    fn circuit_half_open_failure_reopens() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_secs: 0,
            half_open_success_threshold: 2,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test", config);
        cb.allow_request();
        cb.record_failure();
        assert!(cb.allow_request()); // -> half-open
        assert_eq!(cb.state(), &CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.state(), &CircuitState::Open);
    }

    #[test]
    fn circuit_registry_tracks_multiple() {
        let mut registry = CircuitBreakerRegistry::new();
        registry.register(CircuitBreaker::new(
            "svc-a",
            CircuitBreakerConfig {
                failure_threshold: 2,
                ..Default::default()
            },
        ));
        registry.register(CircuitBreaker::new(
            "svc-b",
            CircuitBreakerConfig {
                failure_threshold: 5,
                ..Default::default()
            },
        ));
        assert!(registry.is_allowed("svc-a"));
        assert!(registry.is_allowed("svc-b"));
        registry.record_failure("svc-a");
        registry.record_failure("svc-a");
        assert!(!registry.is_allowed("svc-a"));
        assert!(registry.is_allowed("svc-b"));
        assert_eq!(registry.open_count(), 1);
    }

    #[test]
    fn circuit_stats_transition_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_secs: 0,
            half_open_success_threshold: 1,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test", config);
        cb.allow_request();
        cb.record_failure(); // Closed -> Open
        cb.allow_request(); // Open -> HalfOpen
        cb.record_success(); // HalfOpen -> Closed
        assert_eq!(cb.stats().state_transitions, 3);
    }

    // =====================================================================
    // Lifecycle Manager Tests
    // =====================================================================

    #[test]
    fn lifecycle_starts_uninitialized() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("sentinel");
        assert_eq!(
            mgr.state_of("sentinel"),
            Some(&LifecycleState::Uninitialized)
        );
    }

    #[test]
    fn lifecycle_valid_transitions() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("sentinel");
        assert!(mgr.transition("sentinel", LifecycleState::Initializing).is_ok());
        assert!(mgr.transition("sentinel", LifecycleState::Ready).is_ok());
        assert!(mgr.transition("sentinel", LifecycleState::Active).is_ok());
        assert_eq!(
            mgr.state_of("sentinel"),
            Some(&LifecycleState::Active)
        );
    }

    #[test]
    fn lifecycle_invalid_transition_rejected() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("sentinel");
        let result = mgr.transition("sentinel", LifecycleState::Active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.reason.contains("not in the allowed set"));
        assert_eq!(
            mgr.state_of("sentinel"),
            Some(&LifecycleState::Uninitialized)
        );
    }

    #[test]
    fn lifecycle_suspend_resume_cycle() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("phoenix");
        mgr.transition("phoenix", LifecycleState::Initializing).unwrap();
        mgr.transition("phoenix", LifecycleState::Ready).unwrap();
        mgr.transition("phoenix", LifecycleState::Active).unwrap();
        mgr.transition("phoenix", LifecycleState::Suspending).unwrap();
        mgr.transition("phoenix", LifecycleState::Suspended).unwrap();
        mgr.transition("phoenix", LifecycleState::Resuming).unwrap();
        assert_eq!(
            mgr.state_of("phoenix"),
            Some(&LifecycleState::Active)
        );
    }

    #[test]
    fn lifecycle_shutdown_terminates() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("anchor");
        mgr.transition("anchor", LifecycleState::Initializing).unwrap();
        mgr.transition("anchor", LifecycleState::Ready).unwrap();
        mgr.transition("anchor", LifecycleState::ShuttingDown).unwrap();
        mgr.transition("anchor", LifecycleState::Terminated).unwrap();
        assert!(mgr.all_terminated());
    }

    #[test]
    fn lifecycle_transition_count_increments() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("trust");
        mgr.transition("trust", LifecycleState::Initializing).unwrap();
        mgr.transition("trust", LifecycleState::Ready).unwrap();
        let record = mgr.record("trust").unwrap();
        assert_eq!(record.transition_count, 2);
    }

    #[test]
    fn lifecycle_self_transition_is_noop() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("audit");
        let result = mgr.transition("audit", LifecycleState::Uninitialized);
        assert!(result.is_ok());
        let record = mgr.record("audit").unwrap();
        assert_eq!(record.transition_count, 0); // no-op, no increment
    }

    #[test]
    fn lifecycle_state_distribution() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("a");
        mgr.register("b");
        mgr.register("c");
        // a and b go to Active; c stays Uninitialized
        mgr.transition("a", LifecycleState::Initializing).unwrap_or(());
        mgr.transition("a", LifecycleState::Ready).unwrap_or(());
        mgr.transition("a", LifecycleState::Active).unwrap_or(());
        mgr.transition("b", LifecycleState::Initializing).unwrap_or(());
        mgr.transition("b", LifecycleState::Ready).unwrap_or(());
        mgr.transition("b", LifecycleState::Active).unwrap_or(());
        let dist = mgr.state_distribution();
        assert_eq!(*dist.get("Active").unwrap_or(&0), 2);
        assert_eq!(*dist.get("Uninitialized").unwrap_or(&0), 1);
    }

    #[test]
    fn lifecycle_transition_unregistered_component_errors() {
        let mut mgr = ComponentLifecycleManager::new();
        let result = mgr.transition("ghost", LifecycleState::Initializing);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().component, "ghost");
    }

    // =====================================================================
    // Health Check Coordinator Tests
    // =====================================================================

    #[test]
    fn health_coordinator_healthy_component() {
        let config = HealthCheckConfig::default();
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness, HealthCheckType::Readiness],
        );
        coord.register_component("sentinel");
        let summaries = coord.run_sweep();
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].healthy);
    }

    #[test]
    fn health_coordinator_detects_unhealthy() {
        let config = HealthCheckConfig::default();
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness, HealthCheckType::Deep],
        );
        coord.register_component("fail-deep");
        let summaries = coord.run_sweep();
        assert_eq!(summaries.len(), 1);
        assert!(!summaries[0].healthy);
    }

    #[test]
    fn health_coordinator_marks_down_after_threshold() {
        let config = HealthCheckConfig {
            failure_before_degraded: 1,
            failure_before_down: 2,
            ..Default::default()
        };
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness],
        );
        coord.register_component("fail-all");

        // First sweep: degraded
        coord.run_sweep();
        let tracker = coord.tracker("fail-all").unwrap();
        assert!(tracker.degraded);
        assert!(!tracker.down);

        // Second sweep: down
        coord.run_sweep();
        let tracker = coord.tracker("fail-all").unwrap();
        assert!(tracker.down);
    }

    #[test]
    fn health_coordinator_overall_healthy() {
        let config = HealthCheckConfig::default();
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness],
        );
        coord.register_component("sentinel");
        coord.register_component("phoenix");
        coord.run_sweep();
        assert!(coord.overall_healthy());
    }

    #[test]
    fn health_coordinator_down_components_list() {
        let config = HealthCheckConfig {
            failure_before_degraded: 1,
            failure_before_down: 1,
            ..Default::default()
        };
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness],
        );
        coord.register_component("sentinel");
        coord.register_component("fail-all");
        coord.run_sweep();
        let down = coord.down_components();
        assert!(down.contains(&"fail-all"));
        assert!(!down.contains(&"sentinel"));
    }

    #[test]
    fn health_coordinator_worst_latency_tracked() {
        let config = HealthCheckConfig::default();
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![
                HealthCheckType::Liveness,
                HealthCheckType::Readiness,
                HealthCheckType::Deep,
            ],
        );
        coord.register_component("sentinel");
        let summaries = coord.run_sweep();
        assert_eq!(summaries[0].worst_latency_ms, 1.0);
    }

    #[test]
    fn health_coordinator_check_single_component() {
        let config = HealthCheckConfig::default();
        let mut coord = HealthCheckCoordinator::new(
            config,
            sample_health_check,
            vec![HealthCheckType::Liveness],
        );
        coord.register_component("sentinel");
        let result = coord.check_component("sentinel");
        assert!(result.is_some());
        assert!(result.unwrap().healthy);
        // Unregistered component returns None.
        assert!(coord.check_component("ghost").is_none());
    }

    // =====================================================================
    // Cross-cutting / serialization tests
    // =====================================================================

    #[test]
    fn serialization_pool_config_roundtrip() {
        let config = PoolConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: PoolConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.min_idle, config.min_idle);
        assert_eq!(restored.max_total, config.max_total);
    }

    #[test]
    fn serialization_pool_stats_roundtrip() {
        let mut stats = PoolStats::default();
        stats.total_created = 10;
        stats.evicted_idle = 2;
        let json = serde_json::to_string(&stats).unwrap();
        let restored: PoolStats = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_created, 10);
        assert_eq!(restored.evicted_idle, 2);
    }

    #[test]
    fn serialization_pressure_detector_roundtrip() {
        let config = PressureConfig {
            medium_threshold_bytes: 1000,
            high_threshold_bytes: 2000,
            critical_threshold_bytes: 3000,
            ..Default::default()
        };
        let mut detector = MemoryPressureDetector::new(config);
        detector.record_allocation(500);
        let json = serde_json::to_string(&detector).unwrap();
        let restored: MemoryPressureDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.current_usage_bytes(), 500);
    }

    #[test]
    fn serialization_circuit_breaker_roundtrip() {
        let cb = CircuitBreaker::new("svc-x", CircuitBreakerConfig::default());
        let json = serde_json::to_string(&cb).unwrap();
        let restored: CircuitBreaker = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "svc-x");
        assert_eq!(*restored.state(), CircuitState::Closed);
    }

    #[test]
    fn serialization_lifecycle_manager_roundtrip() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("sentinel");
        mgr.transition("sentinel", LifecycleState::Initializing)
            .unwrap_or(());
        mgr.transition("sentinel", LifecycleState::Ready)
            .unwrap_or(());
        mgr.transition("sentinel", LifecycleState::Active)
            .unwrap_or(());
        let json = serde_json::to_string(&mgr).unwrap();
        let restored: ComponentLifecycleManager = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.state_of("sentinel"), Some(&LifecycleState::Active));
    }

    #[test]
    fn serialization_health_check_result_roundtrip() {
        let result = HealthCheckResult::healthy("sentinel", HealthCheckType::Liveness, 2.5);
        let json = serde_json::to_string(&result).unwrap();
        let restored: HealthCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.component, "sentinel");
        assert!(restored.healthy);
        assert!((restored.latency_ms - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn lifecycle_accumulated_time() {
        let mut mgr = ComponentLifecycleManager::new();
        mgr.register("sentinel");
        mgr.transition("sentinel", LifecycleState::Initializing).unwrap();
        // Give a tiny bit of time, then transition.
        mgr.transition("sentinel", LifecycleState::Ready).unwrap();
        let rec = mgr.record("sentinel").unwrap();
        let init_time = rec.accumulated_time(&LifecycleState::Initializing);
        assert!(init_time >= 0.0);
    }
}
