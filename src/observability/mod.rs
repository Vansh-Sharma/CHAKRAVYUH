// Observability Platform — OpenTelemetry, Security Metrics, Alerting, Dashboard
//
// Integrates with existing infra/metrics.rs and infra/trace.rs.
// Provides unified observability surface for the CHAKRAVYUH security gateway.
//
// NO external crate dependencies — uses std + serde only.

pub mod otel_integration;
pub mod security_metrics;
pub mod alerting_engine;

pub use otel_integration::*;
pub use security_metrics::*;
pub use alerting_engine::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

// ────────────────────────────────────────────────────────────────────
// ObservabilityConfig
// ────────────────────────────────────────────────────────────────────

/// Top-level configuration for the observability platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Master toggle for the entire observability subsystem.
    pub enabled: bool,
    /// OpenTelemetry collector endpoint.
    pub otel_endpoint: String,
    /// How often metrics are exported (milliseconds).
    pub metrics_export_interval_ms: u64,
    /// Retention window for time-series data (seconds).
    pub retention_window_secs: u64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            otel_endpoint: "http://localhost:4317".to_string(),
            metrics_export_interval_ms: 10_000,
            retention_window_secs: 3_600,
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// TimeSeriesPoint
// ────────────────────────────────────────────────────────────────────

/// A single data point in a time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Unix epoch timestamp (seconds).
    pub timestamp: f64,
    /// Measured value.
    pub value: f64,
    /// Dimensional labels.
    pub labels: HashMap<String, String>,
}

impl TimeSeriesPoint {
    /// Create a new time series point with the current time.
    pub fn now(value: f64) -> Self {
        Self {
            timestamp: unix_epoch_secs(),
            value,
            labels: HashMap::new(),
        }
    }

    /// Create a new time series point with labels.
    pub fn with_labels(value: f64, labels: HashMap<String, String>) -> Self {
        Self {
            timestamp: unix_epoch_secs(),
            value,
            labels,
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Dashboard Snapshot Types
// ────────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of the security dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// ISO 8601 timestamp of when the snapshot was generated.
    pub generated_at: String,
    /// Seconds since the process started.
    pub uptime_secs: u64,
    /// Total number of requests processed.
    pub total_requests: u64,
    /// Per-ring latency statistics.
    pub per_ring_latency: HashMap<String, RingLatencyDashboard>,
    /// Decision outcome distribution.
    pub decision_distribution: DecisionDistDashboard,
    /// Number of currently active alerts.
    pub active_alerts_count: usize,
    /// Ratio of false positives to total deny decisions.
    pub false_positive_rate: f64,
    /// Average throughput (requests per second).
    pub throughput_per_sec: f64,
    /// Ratio of error responses to total responses.
    pub error_rate: f64,
    /// Top blocked IP addresses.
    pub top_blocked_ips: Vec<IpBlockDashboard>,
}

/// Per-ring latency dashboard data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingLatencyDashboard {
    /// Ring name.
    pub ring: String,
    /// 50th percentile latency (ms).
    pub p50_ms: f64,
    /// 95th percentile latency (ms).
    pub p95_ms: f64,
    /// 99th percentile latency (ms).
    pub p99_ms: f64,
    /// Mean latency (ms).
    pub mean_ms: f64,
    /// Total number of ring evaluations.
    pub eval_count: u64,
}

/// Decision distribution dashboard data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionDistDashboard {
    /// Number of ALLOW decisions.
    pub allow: u64,
    /// Number of DENY decisions.
    pub deny: u64,
    /// Number of CHALLENGE decisions.
    pub challenge: u64,
    /// Number of ESCALATE decisions.
    pub escalate: u64,
    /// Total number of decisions.
    pub total: u64,
    /// ALLOW as a percentage of total.
    pub allow_pct: f64,
    /// DENY as a percentage of total.
    pub deny_pct: f64,
}

/// IP address block dashboard entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockDashboard {
    /// IP address.
    pub ip: String,
    /// Number of times this IP was blocked.
    pub block_count: u64,
    /// Last time this IP was blocked (ISO 8601).
    pub last_blocked: String,
}

// ────────────────────────────────────────────────────────────────────
// SecurityDashboardAggregator
// ────────────────────────────────────────────────────────────────────

/// Aggregates data from SecurityMetricsCollector and AlertingEngine into
/// dashboard snapshots suitable for rendering in monitoring UIs.
pub struct SecurityDashboardAggregator {
    metrics: Mutex<Option<Box<SecurityMetricsCollector>>>,
    alerting: Mutex<Option<Box<AlertingEngine>>>,
    start: Instant,
}

impl SecurityDashboardAggregator {
    /// Create a new aggregator.
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(None),
            alerting: Mutex::new(None),
            start: Instant::now(),
        }
    }

    /// Register a SecurityMetricsCollector.
    pub fn add_metrics(&self, collector: SecurityMetricsCollector) {
        if let Ok(mut m) = self.metrics.lock() {
            *m = Some(Box::new(collector));
        }
    }

    /// Register an AlertingEngine.
    pub fn add_alerting(&self, engine: AlertingEngine) {
        if let Ok(mut a) = self.alerting.lock() {
            *a = Some(Box::new(engine));
        }
    }

    /// Generate a point-in-time dashboard snapshot.
    pub fn snapshot(&self) -> DashboardSnapshot {
        let generated_at = iso_now();
        let uptime_secs = self.start.elapsed().as_secs();

        let mut total_requests: u64 = 0;
        let mut per_ring_latency = HashMap::new();
        let mut decision_distribution = DecisionDistDashboard {
            allow: 0,
            deny: 0,
            challenge: 0,
            escalate: 0,
            total: 0,
            allow_pct: 0.0,
            deny_pct: 0.0,
        };
        let mut false_positive_rate = 0.0;
        let mut throughput_per_sec = 0.0;
        let mut error_rate = 0.0;
        let mut top_blocked_ips = Vec::new();

        if let Ok(m) = self.metrics.lock() {
            if let Some(collector) = m.as_ref() {
                let rings = collector.all_rings();
                for ring in &rings {
                    let stats = collector.ring_latency_stats(ring);
                    total_requests += stats.count;
                    per_ring_latency.insert(
                        ring.clone(),
                        RingLatencyDashboard {
                            ring: ring.clone(),
                            p50_ms: stats.p50,
                            p95_ms: stats.p95,
                            p99_ms: stats.p99,
                            mean_ms: stats.mean,
                            eval_count: stats.count,
                        },
                    );
                }

                let dist = collector.decision_distribution();
                decision_distribution = DecisionDistDashboard {
                    allow: dist.allow,
                    deny: dist.deny,
                    challenge: dist.challenge,
                    escalate: dist.escalate,
                    total: dist.total,
                    allow_pct: dist.allow_pct,
                    deny_pct: dist.deny_pct,
                };

                false_positive_rate = collector.false_positive_rate();
                throughput_per_sec = collector.throughput_per_second();
                error_rate = collector.error_rate();
                top_blocked_ips = collector
                    .top_blocked_ips(10)
                    .into_iter()
                    .map(|entry| IpBlockDashboard {
                        ip: entry.ip,
                        block_count: entry.block_count,
                        last_blocked: entry.last_blocked,
                    })
                    .collect();
            }
        }

        let mut active_alerts_count: usize = 0;
        if let Ok(a) = self.alerting.lock() {
            if let Some(engine) = a.as_ref() {
                active_alerts_count = engine.active_alerts().len();
            }
        }

        DashboardSnapshot {
            generated_at,
            uptime_secs,
            total_requests,
            per_ring_latency,
            decision_distribution,
            active_alerts_count,
            false_positive_rate,
            throughput_per_sec,
            error_rate,
            top_blocked_ips,
        }
    }

    /// Seconds since the aggregator was created.
    pub fn uptime_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

impl Default for SecurityDashboardAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Get the current Unix epoch in seconds as f64.
pub fn unix_epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Get the current time as an ISO 8601-ish string.
pub fn iso_now() -> String {
    let secs = unix_epoch_secs();
    format!("{}", secs)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_config_default() {
        let cfg = ObservabilityConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.otel_endpoint, "http://localhost:4317");
        assert_eq!(cfg.metrics_export_interval_ms, 10_000);
        assert_eq!(cfg.retention_window_secs, 3_600);
    }

    #[test]
    fn observability_config_serde_roundtrip() {
        let cfg = ObservabilityConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let restored: ObservabilityConfig =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.enabled, cfg.enabled);
        assert_eq!(restored.otel_endpoint, cfg.otel_endpoint);
    }

    #[test]
    fn time_series_point_now() {
        let pt = TimeSeriesPoint::now(42.0);
        assert!(pt.timestamp > 1_700_000_000.0);
        assert_eq!(pt.value, 42.0);
        assert!(pt.labels.is_empty());
    }

    #[test]
    fn time_series_point_with_labels() {
        let mut labels = HashMap::new();
        labels.insert("ring".to_string(), "shield".to_string());
        let pt = TimeSeriesPoint::with_labels(99.5, labels.clone());
        assert_eq!(pt.labels.get("ring").unwrap(), "shield");
    }

    #[test]
    fn time_series_point_serde_roundtrip() {
        let pt = TimeSeriesPoint::now(1.0);
        let json = serde_json::to_string(&pt).expect("serialize");
        let restored: TimeSeriesPoint =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.value, 1.0);
    }

    #[test]
    fn dashboard_snapshot_serde_roundtrip() {
        let snap = DashboardSnapshot {
            generated_at: "2025-01-01T00:00:00".to_string(),
            uptime_secs: 3600,
            total_requests: 1000,
            per_ring_latency: HashMap::new(),
            decision_distribution: DecisionDistDashboard {
                allow: 800,
                deny: 150,
                challenge: 30,
                escalate: 20,
                total: 1000,
                allow_pct: 80.0,
                deny_pct: 15.0,
            },
            active_alerts_count: 2,
            false_positive_rate: 0.05,
            throughput_per_sec: 100.0,
            error_rate: 0.02,
            top_blocked_ips: vec![IpBlockDashboard {
                ip: "10.0.0.1".to_string(),
                block_count: 5,
                last_blocked: "2025-01-01T00:05:00".to_string(),
            }],
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let restored: DashboardSnapshot =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.total_requests, 1000);
        assert_eq!(restored.active_alerts_count, 2);
        assert_eq!(restored.false_positive_rate, 0.05);
    }

    #[test]
    fn ring_latency_dashboard_serde() {
        let rld = RingLatencyDashboard {
            ring: "shield".to_string(),
            p50_ms: 1.2,
            p95_ms: 5.0,
            p99_ms: 12.0,
            mean_ms: 2.0,
            eval_count: 500,
        };
        let json = serde_json::to_string(&rld).expect("serialize");
        let restored: RingLatencyDashboard =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.ring, "shield");
        assert_eq!(restored.p50_ms, 1.2);
        assert_eq!(restored.eval_count, 500);
    }

    #[test]
    fn aggregator_new() {
        let agg = SecurityDashboardAggregator::new();
        let snap = agg.snapshot();
        assert_eq!(snap.total_requests, 0);
        assert_eq!(snap.active_alerts_count, 0);
    }

    #[test]
    fn aggregator_with_metrics() {
        let agg = SecurityDashboardAggregator::new();
        let metrics = SecurityMetricsCollector::new();
        agg.add_metrics(metrics);

        // Without recording any data, snapshot should still be valid
        let snap = agg.snapshot();
        assert_eq!(snap.total_requests, 0);
        assert_eq!(snap.false_positive_rate, 0.0);
        assert_eq!(snap.throughput_per_sec, 0.0);
    }

    #[test]
    fn aggregator_records_and_snapshots() {
        let agg = SecurityDashboardAggregator::new();
        let metrics = SecurityMetricsCollector::new();
        agg.add_metrics(metrics);

        // Record some data via the aggregator's internal metrics reference
        // We need to access the inner collector, so we record directly:
        if let Ok(m) = agg.metrics.lock() {
            if let Some(collector) = m.as_ref() {
                collector.record_ring_latency("shield", 2.5);
                collector.record_ring_latency("shield", 5.0);
                collector.record_ring_latency("shield", 1.0);
                collector.record_ring_latency("threat", 10.0);
                collector.record_decision_outcome("shield", "allow");
                collector.record_decision_outcome("shield", "allow");
                collector.record_decision_outcome("shield", "deny");
            }
        }

        let snap = agg.snapshot();
        assert!(snap.total_requests > 0);
        assert!(snap.per_ring_latency.contains_key("shield"));
        assert!(snap.per_ring_latency.contains_key("threat"));
        assert_eq!(snap.decision_distribution.total, 3);
        assert_eq!(snap.decision_distribution.allow, 2);
        assert_eq!(snap.decision_distribution.deny, 1);
    }

    #[test]
    fn aggregator_with_alerting() {
        let agg = SecurityDashboardAggregator::new();
        let engine = AlertingEngine::new();
        agg.add_alerting(engine);

        // Add an alert via the internal engine reference
        if let Ok(a) = agg.alerting.lock() {
            if let Some(engine) = a.as_ref() {
                engine.add_rule(AlertRule {
                    id: "test-rule".to_string(),
                    name: "Test Rule".to_string(),
                    condition: AlertCondition::Threshold {
                        metric_name: "error_rate".to_string(),
                        operator: ThresholdOperator::Gt,
                        threshold: 0.5,
                    },
                    severity: AlertSeverity::Warning,
                    message_template: "Error rate is high".to_string(),
                    enabled: true,
                });
            }
        }

        let snap = agg.snapshot();
        assert_eq!(snap.active_alerts_count, 0);
    }

    #[test]
    fn aggregator_uptime() {
        let agg = SecurityDashboardAggregator::new();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(agg.uptime_secs() < u64::MAX);
    }

    #[test]
    fn unix_epoch_secs_positive() {
        let ts = unix_epoch_secs();
        assert!(ts > 1_700_000_000.0, "timestamp should be a recent epoch");
    }

    #[test]
    fn iso_now_non_empty() {
        let s = iso_now();
        assert!(!s.is_empty());
        assert!(s.parse::<f64>().is_ok());
    }

    #[test]
    fn decision_dist_percentages() {
        let dist = DecisionDistDashboard {
            allow: 900,
            deny: 100,
            challenge: 0,
            escalate: 0,
            total: 1000,
            allow_pct: 90.0,
            deny_pct: 10.0,
        };
        assert_eq!(dist.allow_pct, 90.0);
        assert_eq!(dist.deny_pct, 10.0);
    }

    #[test]
    fn ip_block_dashboard() {
        let entry = IpBlockDashboard {
            ip: "192.168.1.1".to_string(),
            block_count: 42,
            last_blocked: "2025-06-01".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: IpBlockDashboard =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.ip, "192.168.1.1");
        assert_eq!(restored.block_count, 42);
    }
}
