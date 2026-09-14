// Health Monitoring (Phase 7)
//
// Per-ring health tracking and system-level health checks for
// Kubernetes-style readiness/liveness probes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

/// Global request counter.
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Get the global start time.
pub fn start_time() -> Instant {
    START_TIME.get_or_init(Instant::now).clone()
}

/// Increment request counters.
pub fn record_request(success: bool) {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if !success {
        TOTAL_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read request counters.
pub fn request_counts() -> (u64, u64) {
    (
        TOTAL_REQUESTS.load(Ordering::Relaxed),
        TOTAL_ERRORS.load(Ordering::Relaxed),
    )
}

/// Per-ring health tracking.
#[derive(Debug, Clone, Serialize)]
pub struct RingHealth {
    pub name: String,
    pub enabled: bool,
    pub healthy: bool,
    pub last_check_ms: f64,
    pub total_evaluations: u64,
    pub total_errors: u64,
    pub error_rate: f64,
}

/// Ring health tracker — monitors a single ring.
pub struct RingHealthTracker {
    name: String,
    enabled: AtomicBool,
    evaluations: AtomicU64,
    errors: AtomicU64,
    last_latency: std::sync::RwLock<f64>,
    last_check: std::sync::RwLock<Instant>,
    consecutive_errors: AtomicU64,
    /// Consecutive errors before marking unhealthy.
    unhealthy_threshold: u64,
}

impl RingHealthTracker {
    pub fn new(name: &str, enabled: bool, unhealthy_threshold: u64) -> Self {
        Self {
            name: name.to_string(),
            enabled: AtomicBool::new(enabled),
            evaluations: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_latency: std::sync::RwLock::new(0.0),
            last_check: std::sync::RwLock::new(Instant::now()),
            consecutive_errors: AtomicU64::new(0),
            unhealthy_threshold,
        }
    }

    /// Record a successful evaluation.
    pub fn record_success(&self, latency_ms: f64) {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        self.consecutive_errors.store(0, Ordering::Relaxed);
        if let Ok(mut last) = self.last_latency.write() {
            *last = latency_ms;
        }
        if let Ok(mut check) = self.last_check.write() {
            *check = Instant::now();
        }
    }

    /// Record a failed evaluation.
    pub fn record_error(&self, latency_ms: f64) {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last_latency.write() {
            *last = latency_ms;
        }
        if let Ok(mut check) = self.last_check.write() {
            *check = Instant::now();
        }
    }

    /// Check if the ring is healthy.
    pub fn is_healthy(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }
        self.consecutive_errors.load(Ordering::Relaxed) < self.unhealthy_threshold
    }

    /// Get the health snapshot.
    pub fn health(&self) -> RingHealth {
        let evals = self.evaluations.load(Ordering::Relaxed);
        let errs = self.errors.load(Ordering::Relaxed);
        let error_rate = if evals > 0 {
            errs as f64 / evals as f64
        } else {
            0.0
        };
        let last_check_ago = if let Ok(check) = self.last_check.read() {
            check.elapsed().as_secs_f64() * 1000.0
        } else {
            0.0
        };
        RingHealth {
            name: self.name.clone(),
            enabled: self.enabled.load(Ordering::Relaxed),
            healthy: self.is_healthy(),
            last_check_ms: last_check_ago,
            total_evaluations: evals,
            total_errors: errs,
            error_rate,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

/// System-wide health status.
#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub status: String,
    pub uptime_secs: u64,
    pub version: String,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub storage: Option<StoreHealthReport>,
    pub rings: Vec<RingHealth>,
}

/// Storage health for system health response.
#[derive(Debug, Clone, Serialize)]
pub struct StoreHealthReport {
    pub backend: String,
    pub reachable: bool,
}

/// Check if the system is ready to serve requests.
pub fn is_ready(ring_health: &[RingHealth]) -> bool {
    ring_health.iter().all(|r| r.healthy || !r.enabled)
}

/// Check if the system is alive (basic liveness probe).
pub fn is_alive() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_health_tracker_success() {
        let t = RingHealthTracker::new("test", true, 3);
        t.record_success(1.0);
        assert!(t.is_healthy());
        let h = t.health();
        assert_eq!(h.total_evaluations, 1);
        assert_eq!(h.total_errors, 0);
        assert!(h.healthy);
    }

    #[test]
    fn ring_health_tracker_errors() {
        let t = RingHealthTracker::new("test", true, 3);
        t.record_error(1.0);
        t.record_error(1.0);
        assert!(t.is_healthy());
        t.record_error(1.0);
        assert!(!t.is_healthy());
        let h = t.health();
        assert!(!h.healthy);
        assert_eq!(h.total_errors, 3);
    }

    #[test]
    fn disabled_ring_always_healthy() {
        let t = RingHealthTracker::new("test", false, 1);
        t.record_error(1.0);
        t.record_error(1.0);
        assert!(t.is_healthy());
    }

    #[test]
    fn request_counters() {
        record_request(true);
        record_request(true);
        record_request(false);
        let (total, errors) = request_counts();
        assert_eq!(total, 3);
        assert_eq!(errors, 1);
    }

    #[test]
    fn readiness_check() {
        let rings = vec![
            RingHealth {
                name: "shield".into(),
                enabled: true,
                healthy: true,
                last_check_ms: 0.0,
                total_evaluations: 10,
                total_errors: 0,
                error_rate: 0.0,
            },
            RingHealth {
                name: "threat".into(),
                enabled: true,
                healthy: true,
                last_check_ms: 0.0,
                total_evaluations: 5,
                total_errors: 1,
                error_rate: 0.2,
            },
            RingHealth {
                name: "agent".into(),
                enabled: false,
                healthy: false,
                last_check_ms: 0.0,
                total_evaluations: 0,
                total_errors: 0,
                error_rate: 0.0,
            },
        ];
        assert!(is_ready(&rings));
    }

    #[test]
    fn readiness_unhealthy_ring() {
        let rings = vec![RingHealth {
            name: "shield".into(),
            enabled: true,
            healthy: false,
            last_check_ms: 0.0,
            total_evaluations: 10,
            total_errors: 10,
            error_rate: 1.0,
        }];
        assert!(!is_ready(&rings));
    }

    #[test]
    fn liveness_always_true() {
        assert!(is_alive());
    }
}
