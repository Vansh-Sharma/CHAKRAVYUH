// Performance Framework — Metrics Collector (D5)
//
// Records and analyzes performance samples: latency percentiles,
// time-bucketed throughput, error rates, and per-dimension breakdowns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single performance sample recorded during a load test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSample {
    /// Unique request identifier.
    pub request_id: String,
    /// Arrival timestamp in microseconds.
    pub timestamp_us: u64,
    /// Observed latency in microseconds.
    pub latency_us: u64,
    /// Ring that processed this request.
    pub ring: String,
    /// Type of request (Benign, Attack, etc.).
    pub request_type: String,
    /// Verdict string (e.g. "PASS", "FAIL").
    pub verdict: String,
    /// Error message if the request failed.
    pub error: Option<String>,
}

/// Configuration for the metrics collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Aggregation window in milliseconds.
    pub aggregation_window_ms: u64,
    /// Percentile buckets to compute (e.g. [0.50, 0.90, 0.95, 0.99]).
    pub percentile_buckets: Vec<f64>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            aggregation_window_ms: 1000,
            percentile_buckets: vec![0.50, 0.90, 0.95, 0.99],
        }
    }
}

/// Summary statistics for a latency distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySummary {
    /// Number of samples.
    pub count: u64,
    /// Minimum latency in microseconds.
    pub min_us: u64,
    /// Maximum latency in microseconds.
    pub max_us: u64,
    /// Mean latency in microseconds.
    pub mean_us: f64,
    /// 50th percentile latency.
    pub p50_us: u64,
    /// 90th percentile latency.
    pub p90_us: u64,
    /// 95th percentile latency.
    pub p95_us: u64,
    /// 99th percentile latency.
    pub p99_us: u64,
}

/// A single throughput data point (time-bucketed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputPoint {
    /// Start of the window in microseconds.
    pub window_start_us: u64,
    /// Number of requests in this window.
    pub requests_in_window: u64,
    /// Requests per second for this window.
    pub rps: f64,
}

/// Collects and analyzes performance samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollector {
    samples: Vec<PerformanceSample>,
    config: MetricsConfig,
}

impl MetricsCollector {
    /// Create a new metrics collector with the given configuration.
    pub fn new(config: MetricsConfig) -> Self {
        tracing::info!(
            window_ms = config.aggregation_window_ms,
            buckets = ?config.percentile_buckets,
            "MetricsCollector initialized"
        );
        Self {
            samples: Vec::new(),
            config,
        }
    }

    /// Record a single performance sample.
    pub fn record(&mut self, sample: PerformanceSample) {
        self.samples.push(sample);
    }

    /// Record multiple samples at once.
    pub fn record_batch(&mut self, samples: Vec<PerformanceSample>) {
        self.samples.extend(samples);
    }

    /// Return the number of recorded samples.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Return a reference to the raw samples slice.
    pub fn samples(&self) -> &[PerformanceSample] {
        &self.samples
    }

    /// Return the configuration.
    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// Compute overall latency summary across all samples.
    pub fn latency_summary(&self) -> LatencySummary {
        Self::compute_latency(&self.samples, &self.config.percentile_buckets)
    }

    /// Compute time-bucketed throughput (RPS).
    /// `window_ms` is the bucket width in milliseconds.
    pub fn throughput_rps(&self, window_ms: u64) -> Vec<ThroughputPoint> {
        if self.samples.is_empty() {
            return Vec::new();
        }

        let window_us = window_ms as u64 * 1_000;

        // Find the time range.
        let min_ts = self
            .samples
            .iter()
            .map(|s| s.timestamp_us)
            .min()
            .unwrap_or(0);
        let max_ts = self
            .samples
            .iter()
            .map(|s| s.timestamp_us)
            .max()
            .unwrap_or(0);

        if window_us == 0 || max_ts <= min_ts {
            return Vec::new();
        }

        let mut buckets: HashMap<u64, u64> = HashMap::new();
        for sample in &self.samples {
            let bucket_start = ((sample.timestamp_us - min_ts) / window_us) * window_us + min_ts;
            *buckets.entry(bucket_start).or_insert(0) += 1;
        }

        let mut points: Vec<ThroughputPoint> = buckets
            .into_iter()
            .map(|(window_start, count)| {
                let window_secs = window_ms as f64 / 1000.0;
                ThroughputPoint {
                    window_start_us: window_start,
                    requests_in_window: count,
                    rps: count as f64 / window_secs,
                }
            })
            .collect();

        points.sort_by_key(|p| p.window_start_us);
        points
    }

    /// Compute the overall error rate (fraction of samples with errors).
    pub fn error_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let errors = self
            .samples
            .iter()
            .filter(|s| s.error.is_some())
            .count();
        errors as f64 / self.samples.len() as f64
    }

    /// Compute latency summary per ring.
    pub fn per_ring_latency(&self) -> HashMap<String, LatencySummary> {
        Self::grouped_latency(&self.samples, &self.config.percentile_buckets, |s| {
            s.ring.clone()
        })
    }

    /// Compute latency summary per request type.
    pub fn per_type_latency(&self) -> HashMap<String, LatencySummary> {
        Self::grouped_latency(&self.samples, &self.config.percentile_buckets, |s| {
            s.request_type.clone()
        })
    }

    /// Clear all recorded samples.
    pub fn clear(&mut self) {
        self.samples.clear();
        tracing::debug!("MetricsCollector cleared");
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Compute latency summary from a slice of samples.
    fn compute_latency(
        samples: &[PerformanceSample],
        _percentiles: &[f64],
    ) -> LatencySummary {
        if samples.is_empty() {
            return LatencySummary {
                count: 0,
                min_us: 0,
                max_us: 0,
                mean_us: 0.0,
                p50_us: 0,
                p90_us: 0,
                p95_us: 0,
                p99_us: 0,
            };
        }

        let count = samples.len() as u64;
        let mut latencies: Vec<u64> = samples.iter().map(|s| s.latency_us).collect();
        latencies.sort();

        let min_us = latencies[0];
        let max_us = latencies[latencies.len() - 1];
        let sum: u64 = latencies.iter().sum();
        let mean_us = sum as f64 / count as f64;

        let p50_us = percentile(&latencies, 0.50);
        let p90_us = percentile(&latencies, 0.90);
        let p95_us = percentile(&latencies, 0.95);
        let p99_us = percentile(&latencies, 0.99);

        LatencySummary {
            count,
            min_us,
            max_us,
            mean_us,
            p50_us,
            p90_us,
            p95_us,
            p99_us,
        }
    }

    /// Compute latency summaries grouped by a key function.
    fn grouped_latency<F>(
        samples: &[PerformanceSample],
        percentiles: &[f64],
        key_fn: F,
    ) -> HashMap<String, LatencySummary>
    where
        F: Fn(&PerformanceSample) -> String,
    {
        let mut groups: HashMap<String, Vec<PerformanceSample>> = HashMap::new();
        for sample in samples {
            let key = key_fn(sample);
            groups.entry(key).or_default().push(sample.clone());
        }

        groups
            .into_iter()
            .map(|(key, group_samples)| {
                let summary = Self::compute_latency(&group_samples, percentiles);
                (key, summary)
            })
            .collect()
    }
}

/// Compute a percentile from a sorted slice.
/// Uses linear interpolation (nearest-rank method).
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = (p * (sorted.len() - 1) as f64).round() as usize;
    let idx = idx.min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(id: &str, latency_us: u64, ring: &str, req_type: &str) -> PerformanceSample {
        PerformanceSample {
            request_id: id.to_string(),
            timestamp_us: 1_000_000,
            latency_us,
            ring: ring.to_string(),
            request_type: req_type.to_string(),
            verdict: "PASS".to_string(),
            error: None,
        }
    }

    fn make_error_sample(id: &str, latency_us: u64) -> PerformanceSample {
        PerformanceSample {
            request_id: id.to_string(),
            timestamp_us: 1_000_000,
            latency_us,
            ring: "shield".to_string(),
            request_type: "Benign".to_string(),
            verdict: "ERR".to_string(),
            error: Some("timeout".to_string()),
        }
    }

    #[test]
    fn latency_summary_basic() {
        let mut collector = MetricsCollector::new(MetricsConfig::default());
        for i in 0..100u64 {
            collector.record(make_sample(&format!("r{}", i), 100 + i, "shield", "Benign"));
        }
        let summary = collector.latency_summary();
        assert_eq!(summary.count, 100);
        assert_eq!(summary.min_us, 100);
        assert_eq!(summary.max_us, 199);
        assert!((summary.mean_us - 149.5).abs() < 0.1);
    }

    #[test]
    fn empty_collector_returns_zero_summary() {
        let collector = MetricsCollector::new(MetricsConfig::default());
        let summary = collector.latency_summary();
        assert_eq!(summary.count, 0);
        assert_eq!(summary.p50_us, 0);
    }

    #[test]
    fn error_rate_calculation() {
        let mut collector = MetricsCollector::new(MetricsConfig::default());
        for i in 0..80u64 {
            collector.record(make_sample(&format!("ok-{}", i), 100, "shield", "Benign"));
        }
        for i in 0..20u64 {
            collector.record(make_error_sample(&format!("err-{}", i), 200));
        }
        let rate = collector.error_rate();
        assert!((rate - 0.2).abs() < 1e-9);
    }

    #[test]
    fn per_ring_latency_breakdown() {
        let mut collector = MetricsCollector::new(MetricsConfig::default());
        for i in 0..50u64 {
            collector.record(make_sample(&format!("a{}", i), 50 + i, "shield", "Benign"));
        }
        for i in 0..50u64 {
            collector.record(make_sample(
                &format!("b{}", i),
                200 + i,
                "threat",
                "Attack",
            ));
        }
        let per_ring = collector.per_ring_latency();
        assert_eq!(per_ring.len(), 2);
        let shield = &per_ring["shield"];
        assert_eq!(shield.count, 50);
        assert_eq!(shield.min_us, 50);
        let threat = &per_ring["threat"];
        assert_eq!(threat.count, 50);
        assert_eq!(threat.min_us, 200);
    }

    #[test]
    fn throughput_rps_buckets() {
        let mut collector = MetricsCollector::new(MetricsConfig::default());
        // 10 requests in first second, 5 in second second.
        for i in 0..10u64 {
            let mut s = make_sample(&format!("r{}", i), 100, "shield", "Benign");
            s.timestamp_us = i * 100_000; // 0..1s
            collector.record(s);
        }
        for i in 0..5u64 {
            let mut s = make_sample(&format!("r2-{}", i), 100, "shield", "Benign");
            s.timestamp_us = 1_500_000 + i * 100_000; // 1.5..2s
            collector.record(s);
        }
        let points = collector.throughput_rps(1000);
        assert!(!points.is_empty());
        // The total requests should be 15.
        let total: u64 = points.iter().map(|p| p.requests_in_window).sum();
        assert_eq!(total, 15);
    }

    #[test]
    fn record_batch_and_clear() {
        let mut collector = MetricsCollector::new(MetricsConfig::default());
        let batch: Vec<PerformanceSample> = (0..30)
            .map(|i| make_sample(&format!("b{}", i), 100, "shield", "Benign"))
            .collect();
        collector.record_batch(batch);
        assert_eq!(collector.sample_count(), 30);
        collector.clear();
        assert_eq!(collector.sample_count(), 0);
    }

    #[test]
    fn percentile_single_value() {
        assert_eq!(percentile(&[42], 0.99), 42);
        assert_eq!(percentile(&[42], 0.50), 42);
    }
}
