// Performance Framework — Report Generator (D5)
//
// Assembles a PerformanceReport from collected metrics and profiling data,
// checks against configurable targets, and produces text/JSON output.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::load_generator::LoadConfig;
use super::metrics_collector::{LatencySummary, MetricsCollector, ThroughputPoint};
use super::profiler::{Profiler, RegionSummary};

/// Performance targets to evaluate against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTargets {
    /// Maximum acceptable p99 latency (us).
    pub p99_latency_us: u64,
    /// Maximum acceptable p95 latency (us).
    pub p95_latency_us: u64,
    /// Minimum required RPS.
    pub target_rps: u64,
    /// Maximum acceptable error rate (0.0–1.0).
    pub max_error_rate: f64,
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            p99_latency_us: 50_000,   // 50ms
            p95_latency_us: 10_000,   // 10ms
            target_rps: 1000,
            max_error_rate: 0.01,      // 1%
        }
    }
}

/// Result of checking performance targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetsMet {
    /// p99 latency target met.
    pub p99_met: bool,
    /// p95 latency target met.
    pub p95_met: bool,
    /// RPS target met.
    pub rps_met: bool,
    /// Error rate target met.
    pub error_rate_met: bool,
    /// All targets met.
    pub all_met: bool,
}

/// The complete performance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    /// Unique run identifier.
    pub run_id: String,
    /// Load configuration used.
    pub load_config: LoadConfig,
    /// Total test duration in microseconds.
    pub duration_us: u64,
    /// Total number of requests processed.
    pub total_requests: u64,
    /// Overall latency summary.
    pub latency: LatencySummary,
    /// Time-bucketed throughput.
    pub throughput: Vec<ThroughputPoint>,
    /// Overall error rate.
    pub error_rate: f64,
    /// Per-ring latency breakdown.
    pub per_ring: HashMap<String, LatencySummary>,
    /// Per-request-type latency breakdown.
    pub per_type: HashMap<String, LatencySummary>,
    /// Profiling region summaries.
    pub profiling: Vec<RegionSummary>,
    /// Targets that were checked.
    pub targets_met: TargetsMet,
}

/// Generate a performance report from collected data.
pub fn generate_report(
    metrics: &MetricsCollector,
    profiler: &Profiler,
    config: &LoadConfig,
    targets: &PerformanceTargets,
) -> PerformanceReport {
    let run_id = uuid::Uuid::new_v4().to_string();

    let latency = metrics.latency_summary();
    let window_ms = metrics.config().aggregation_window_ms;
    let throughput = metrics.throughput_rps(window_ms);
    let error_rate = metrics.error_rate();
    let per_ring = metrics.per_ring_latency();
    let per_type = metrics.per_type_latency();
    let profiling = profiler.hottest_regions(20);

    // Compute duration from samples if available.
    let duration_us = if metrics.sample_count() >= 2 {
        // Use a const for safety: sample_count() returns usize, so max(2) is fine.
        let min_ts = match metrics.samples().iter().map(|s| s.timestamp_us).min() {
            Some(v) => v,
            None => config.duration_secs * 1_000_000,
        };
        let max_ts = match metrics.samples().iter().map(|s| s.timestamp_us).max() {
            Some(v) => v,
            None => config.duration_secs * 1_000_000,
        };
        max_ts.saturating_sub(min_ts)
    } else {
        config.duration_secs * 1_000_000
    };

    let total_requests = latency.count;

    // Build a preliminary report for target checking.
    let report = PerformanceReport {
        run_id,
        load_config: config.clone(),
        duration_us,
        total_requests,
        latency: latency.clone(),
        throughput,
        error_rate,
        per_ring,
        per_type,
        profiling,
        targets_met: TargetsMet {
            p99_met: false,
            p95_met: false,
            rps_met: false,
            error_rate_met: false,
            all_met: false,
        },
    };

    let targets_met = check_targets(&report, targets);

    PerformanceReport { targets_met, ..report }
}

/// Check whether the report meets all performance targets.
pub fn check_targets(report: &PerformanceReport, targets: &PerformanceTargets) -> TargetsMet {
    // Compute median RPS from throughput points.
    let median_rps = if !report.throughput.is_empty() {
        let mut rps_values: Vec<f64> = report.throughput.iter().map(|p| p.rps).collect();
        rps_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = rps_values.len() / 2;
        if rps_values.len() % 2 == 0 && rps_values.len() >= 2 {
            (rps_values[mid - 1] + rps_values[mid]) / 2.0
        } else {
            rps_values[mid]
        }
    } else {
        0.0
    };

    let p99_met = report.latency.p99_us <= targets.p99_latency_us;
    let p95_met = report.latency.p95_us <= targets.p95_latency_us;
    let rps_met = (median_rps as u64) >= targets.target_rps;
    let error_rate_met = report.error_rate <= targets.max_error_rate;
    let all_met = p99_met && p95_met && rps_met && error_rate_met;

    TargetsMet {
        p99_met,
        p95_met,
        rps_met,
        error_rate_met,
        all_met,
    }
}

impl PerformanceReport {
    /// Produce a human-readable text report.
    pub fn to_text(&self) -> String {
        let mut lines = Vec::new();

        lines.push("=".repeat(72).to_string());
        lines.push(format!("  CHAKRAVYUH Performance Report — {}", self.run_id));
        lines.push("=".repeat(72).to_string());
        lines.push(String::new());

        // Load configuration.
        lines.push("── Load Configuration ──────────────────────────────────────".to_string());
        lines.push(format!("  Target RPS:      {}", self.load_config.target_rps));
        lines.push(format!("  Duration:         {}s", self.load_config.duration_secs));
        lines.push(format!("  Ramp-up:          {}s", self.load_config.ramp_up_secs));
        lines.push(format!("  Request types:    {}", self.load_config.request_mix.len()));
        lines.push(format!("  Payload range:    {}–{} bytes", self.load_config.payload_size_range.0, self.load_config.payload_size_range.1));
        lines.push(String::new());

        // Overall results.
        lines.push("── Overall Results ──────────────────────────────────────────".to_string());
        lines.push(format!("  Total requests:   {}", self.total_requests));
        lines.push(format!("  Duration:         {:.2}s", self.duration_us as f64 / 1_000_000.0));
        lines.push(format!("  Error rate:       {:.2}%", self.error_rate * 100.0));
        lines.push(String::new());

        // Latency.
        lines.push("── Latency (μs) ─────────────────────────────────────────────".to_string());
        lines.push(format!("  Count:            {}", self.latency.count));
        lines.push(format!("  Min:              {}", self.latency.min_us));
        lines.push(format!("  Max:              {}", self.latency.max_us));
        lines.push(format!("  Mean:             {:.1}", self.latency.mean_us));
        lines.push(format!("  P50:              {}", self.latency.p50_us));
        lines.push(format!("  P90:              {}", self.latency.p90_us));
        lines.push(format!("  P95:              {}", self.latency.p95_us));
        lines.push(format!("  P99:              {}", self.latency.p99_us));
        lines.push(String::new());

        // Target results.
        lines.push("── Target Results ───────────────────────────────────────────".to_string());
        let status = |met: bool| -> &str {
            if met { "PASS" } else { "FAIL" }
        };
        lines.push(format!("  P99 latency:      {}", status(self.targets_met.p99_met)));
        lines.push(format!("  P95 latency:      {}", status(self.targets_met.p95_met)));
        lines.push(format!("  RPS target:       {}", status(self.targets_met.rps_met)));
        lines.push(format!("  Error rate:       {}", status(self.targets_met.error_rate_met)));
        lines.push(format!("  ALL TARGETS:      {}", status(self.targets_met.all_met)));
        lines.push(String::new());

        // Per-ring breakdown.
        if !self.per_ring.is_empty() {
            lines.push("── Per-Ring Latency ──────────────────────────────────────".to_string());
            let mut rings: Vec<_> = self.per_ring.iter().collect();
            rings.sort_by_key(|(name, _)| name.to_string());
            for (name, summary) in rings {
                lines.push(format!(
                    "  {:12}  n={:6}  p50={:8}  p99={:8}",
                    name, summary.count, summary.p50_us, summary.p99_us
                ));
            }
            lines.push(String::new());
        }

        // Per-type breakdown.
        if !self.per_type.is_empty() {
            lines.push("── Per-Type Latency ──────────────────────────────────────".to_string());
            let mut types: Vec<_> = self.per_type.iter().collect();
            types.sort_by_key(|(name, _)| name.to_string());
            for (name, summary) in types {
                lines.push(format!(
                    "  {:16}  n={:6}  p50={:8}  p99={:8}",
                    name, summary.count, summary.p50_us, summary.p99_us
                ));
            }
            lines.push(String::new());
        }

        // Profiling hot paths.
        if !self.profiling.is_empty() {
            lines.push("── Profiling (Hottest Regions) ───────────────────────────".to_string());
            for region in &self.profiling {
                lines.push(format!(
                    "  {:24}  calls={:6}  total={:10}μs  avg={:8.1}μs  ({:.1}%)",
                    region.name,
                    region.call_count,
                    region.total_us,
                    region.avg_us,
                    region.pct_of_total
                ));
            }
            lines.push(String::new());
        }

        lines.push("=".repeat(72).to_string());
        lines.join("\n")
    }

    /// Serialize the report as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize performance report: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::metrics_collector::{MetricsConfig, PerformanceSample};

    fn make_collector_with_samples() -> MetricsCollector {
        let mut collector = MetricsCollector::new(MetricsConfig {
            aggregation_window_ms: 1000,
            percentile_buckets: vec![0.50, 0.90, 0.95, 0.99],
        });
        for i in 0..100u64 {
 let mut sample = PerformanceSample {
                request_id: format!("r{}", i),
                timestamp_us: i * 10_000, // 10ms apart
                latency_us: 100 + i,
                ring: ["shield", "threat", "identity"][i as usize % 3].to_string(),
                request_type: ["Benign", "Attack(sqli)", "Mixed"][i as usize % 3].to_string(),
                verdict: "PASS".to_string(),
                error: None,
            };
            // Make a few error samples.
            if i % 20 == 0 {
                sample.error = Some("timeout".to_string());
                sample.verdict = "ERR".to_string();
            }
            collector.record(sample);
        }
        collector
    }

    fn default_load_config() -> LoadConfig {
        LoadConfig {
            target_rps: 500,
            duration_secs: 1,
            ramp_up_secs: 0,
            request_mix: vec![],
            payload_size_range: (64, 1024),
        }
    }

    #[test]
    fn generate_report_populates_fields() {
        let collector = make_collector_with_samples();
        let profiler = Profiler::new();
        let config = default_load_config();
        let targets = PerformanceTargets::default();

        let report = generate_report(&collector, &profiler, &config, &targets);
        assert!(!report.run_id.is_empty());
        assert_eq!(report.total_requests, 100);
        assert_eq!(report.latency.count, 100);
        assert_eq!(report.latency.min_us, 100);
        assert_eq!(report.latency.max_us, 199);
        assert!(report.error_rate > 0.0);
        assert!(!report.per_ring.is_empty());
        assert!(!report.per_type.is_empty());
    }

    #[test]
    fn check_targets_all_pass() {
        let report = PerformanceReport {
            run_id: "test".to_string(),
            load_config: default_load_config(),
            duration_us: 1_000_000,
            total_requests: 1000,
            latency: LatencySummary {
                count: 1000,
                min_us: 10,
                max_us: 100,
                mean_us: 50.0,
                p50_us: 45,
                p90_us: 70,
                p95_us: 80,
                p99_us: 90,
            },
            throughput: vec![ThroughputPoint {
                window_start_us: 0,
                requests_in_window: 1000,
                rps: 1000.0,
            }],
            error_rate: 0.001,
            per_ring: HashMap::new(),
            per_type: HashMap::new(),
            profiling: vec![],
            targets_met: TargetsMet {
                p99_met: false,
                p95_met: false,
                rps_met: false,
                error_rate_met: false,
                all_met: false,
            },
        };
        let targets = PerformanceTargets {
            p99_latency_us: 100,
            p95_latency_us: 100,
            target_rps: 500,
            max_error_rate: 0.01,
        };
        let met = check_targets(&report, &targets);
        assert!(met.p99_met);
        assert!(met.p95_met);
        assert!(met.rps_met);
        assert!(met.error_rate_met);
        assert!(met.all_met);
    }

    #[test]
    fn check_targets_all_fail() {
        let report = PerformanceReport {
            run_id: "test".to_string(),
            load_config: default_load_config(),
            duration_us: 1_000_000,
            total_requests: 10,
            latency: LatencySummary {
                count: 10,
                min_us: 10,
                max_us: 100_000,
                mean_us: 50_000.0,
                p50_us: 40_000,
                p90_us: 80_000,
                p95_us: 90_000,
                p99_us: 99_000,
            },
            throughput: vec![ThroughputPoint {
                window_start_us: 0,
                requests_in_window: 10,
                rps: 10.0,
            }],
            error_rate: 0.5,
            per_ring: HashMap::new(),
            per_type: HashMap::new(),
            profiling: vec![],
            targets_met: TargetsMet {
                p99_met: false,
                p95_met: false,
                rps_met: false,
                error_rate_met: false,
                all_met: false,
            },
        };
        let targets = PerformanceTargets {
            p99_latency_us: 50_000,
            p95_latency_us: 10_000,
            target_rps: 1000,
            max_error_rate: 0.01,
        };
        let met = check_targets(&report, &targets);
        assert!(!met.p99_met);
        assert!(!met.p95_met);
        assert!(!met.rps_met);
        assert!(!met.error_rate_met);
        assert!(!met.all_met);
    }

    #[test]
    fn to_text_contains_key_sections() {
        let collector = make_collector_with_samples();
        let profiler = Profiler::new();
        let config = default_load_config();
        let targets = PerformanceTargets::default();

        let report = generate_report(&collector, &profiler, &config, &targets);
        let text = report.to_text();

        assert!(text.contains("CHAKRAVYUH Performance Report"));
        assert!(text.contains("Load Configuration"));
        assert!(text.contains("Latency"));
        assert!(text.contains("Target Results"));
        assert!(text.contains("P99:"));
        assert!(text.contains("P95:"));
    }

    #[test]
    fn to_json_roundtrip() {
        let collector = make_collector_with_samples();
        let profiler = Profiler::new();
        let config = default_load_config();
        let targets = PerformanceTargets::default();

        let report = generate_report(&collector, &profiler, &config, &targets);
        let json = report.to_json().unwrap();

        // Verify JSON is valid and contains expected fields.
        assert!(json.contains("run_id"));
        assert!(json.contains("latency"));
        assert!(json.contains("targets_met"));

        // Verify round-trip.
        let restored: PerformanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.run_id, report.run_id);
        assert_eq!(restored.total_requests, report.total_requests);
        assert_eq!(restored.latency.count, report.latency.count);
    }
}
