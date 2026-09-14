// Verification Engine — Metrics Collection (D0)
//
// Captures quantitative metrics for every validation run.
// Metrics are aggregated into summaries and feed into reports.

use serde::{Deserialize, Serialize};

use super::evidence::{Severity, Verdict};

/// A single metric measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// The metric name (e.g., "latency_p99_us", "detection_rate").
    pub name: String,
    /// The numeric value.
    pub value: f64,
    /// Unit (e.g., "us", "ms", "count", "ratio", "bytes").
    pub unit: String,
    /// Optional: the ring or subsystem this metric belongs to.
    pub subsystem: String,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

impl Metric {
    pub fn new(name: &str, value: f64, unit: &str) -> Self {
        Self {
            name: name.to_string(),
            value,
            unit: unit.to_string(),
            subsystem: String::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_subsystem(mut self, sub: &str) -> Self {
        self.subsystem = sub.to_string();
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Aggregated summary for a set of metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricSummary {
    /// Number of data points.
    pub count: u64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
    /// Mean value.
    pub mean: f64,
    /// Median value.
    pub median: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// 50th percentile (same as median).
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
}

impl MetricSummary {
    /// Compute summary statistics from a slice of values.
    pub fn from_values(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self::default();
        }

        let count = values.len() as u64;
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean = values.iter().sum::<f64>() / values.len() as f64;

        let variance = if values.len() > 1 {
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64
        } else {
            0.0
        };
        let stddev = variance.sqrt();

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let percentile = |p: f64| -> f64 {
            if sorted.is_empty() {
                return 0.0;
            }
            if sorted.len() == 1 {
                return sorted[0];
            }
            let rank = (p / 100.0) * (sorted.len() - 1) as f64;
            let lower = rank.floor() as usize;
            let upper = (lower + 1).min(sorted.len() - 1);
            let frac = rank - lower as f64;
            sorted[lower] + frac * (sorted[upper] - sorted[lower])
        };

        let median = percentile(50.0);

        Self {
            count,
            min,
            max,
            mean,
            median,
            stddev,
            p50: percentile(50.0),
            p90: percentile(90.0),
            p95: percentile(95.0),
            p99: percentile(99.0),
        }
    }
}

/// Verdict distribution — how many pass/fail/skip/error.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerdictDistribution {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub error: u64,
    pub total: u64,
}

impl VerdictDistribution {
    /// Create from a slice of verdicts.
    pub fn from_verdicts(verdicts: &[Verdict]) -> Self {
        let mut dist = Self::default();
        for v in verdicts {
            match v {
                Verdict::Pass => dist.pass += 1,
                Verdict::Fail => dist.fail += 1,
                Verdict::Skip => dist.skip += 1,
                Verdict::Error => dist.error += 1,
            }
        }
        dist.total = dist.pass + dist.fail + dist.skip + dist.error;
        dist
    }

    /// Pass rate (0.0 to 1.0), excluding skips and errors.
    pub fn pass_rate(&self) -> f64 {
        let relevant = self.pass + self.fail;
        if relevant == 0 {
            return 1.0;
        }
        self.pass as f64 / relevant as f64
    }

    /// Returns true if any blocking severity failures exist.
    pub fn has_blocking_failures(&self) -> bool {
        self.fail > 0
    }
}

/// Severity distribution for failed checks.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeverityDistribution {
    pub info: u64,
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

impl SeverityDistribution {
    /// Create from a slice of severities.
    pub fn from_severities(severities: &[Severity]) -> Self {
        let mut dist = Self::default();
        for s in severities {
            match s {
                Severity::Info => dist.info += 1,
                Severity::Low => dist.low += 1,
                Severity::Medium => dist.medium += 1,
                Severity::High => dist.high += 1,
                Severity::Critical => dist.critical += 1,
            }
        }
        dist
    }

    /// Count of blocking failures (High + Critical).
    pub fn blocking_count(&self) -> u64 {
        self.high + self.critical
    }
}

/// Timing information for a validation run or sub-phase.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingMetrics {
    /// Total wall-clock time in microseconds.
    pub total_us: u64,
    /// Time spent in the system under test (excluding framework overhead).
    pub system_us: u64,
    /// Time spent in framework overhead (setup, teardown, etc.).
    pub framework_us: u64,
    /// Peak memory usage in bytes (if available).
    pub peak_memory_bytes: Option<u64>,
    /// Number of allocations (if available).
    pub allocations: Option<u64>,
}

impl TimingMetrics {
    pub fn new(total_us: u64, system_us: u64, framework_us: u64) -> Self {
        Self {
            total_us,
            system_us,
            framework_us,
            peak_memory_bytes: None,
            allocations: None,
        }
    }
}

/// Per-subsystem breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemMetrics {
    pub subsystem: String,
    pub verdicts: VerdictDistribution,
    pub severities: SeverityDistribution,
    pub timing: TimingMetrics,
    pub custom: Vec<Metric>,
}

/// A collection of metrics for an entire validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetrics {
    /// The run ID.
    pub run_id: String,
    /// Overall verdict distribution.
    pub verdicts: VerdictDistribution,
    /// Overall severity distribution (fail-only).
    pub severities: SeverityDistribution,
    /// Overall timing.
    pub timing: TimingMetrics,
    /// Per-subsystem breakdown.
    pub subsystems: Vec<SubsystemMetrics>,
    /// Custom metrics.
    pub custom: Vec<Metric>,
}

impl RunMetrics {
    pub fn new(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_string(),
            verdicts: VerdictDistribution::default(),
            severities: SeverityDistribution::default(),
            timing: TimingMetrics::default(),
            subsystems: Vec::new(),
            custom: Vec::new(),
        }
    }

    /// Add a custom metric.
    pub fn add_metric(&mut self, metric: Metric) {
        self.custom.push(metric);
    }

    /// Get all custom metric values for a named metric.
    pub fn metric_values(&self, name: &str) -> Vec<f64> {
        self.custom
            .iter()
            .filter(|m| m.name == name)
            .map(|m| m.value)
            .collect()
    }

    /// Compute summary for a named metric.
    pub fn metric_summary(&self, name: &str) -> MetricSummary {
        let values = self.metric_values(name);
        MetricSummary::from_values(&values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_creation() {
        let m = Metric::new("latency_p99", 1234.0, "us").with_subsystem("shield");
        assert_eq!(m.name, "latency_p99");
        assert_eq!(m.subsystem, "shield");
    }

    #[test]
    fn metric_summary_basic() {
        let values: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let s = MetricSummary::from_values(&values);
        assert_eq!(s.count, 100);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 100.0);
        assert!((s.mean - 50.5).abs() < 0.01);
        assert!((s.p50 - 50.5).abs() < 0.01);
        assert!((s.p99 - 99.0).abs() < 1.0);
    }

    #[test]
    fn metric_summary_empty() {
        let s = MetricSummary::from_values(&[]);
        assert_eq!(s.count, 0);
        assert_eq!(s.mean, 0.0);
    }

    #[test]
    fn verdict_distribution() {
        let v = VerdictDistribution::from_verdicts(&[
            Verdict::Pass, Verdict::Pass, Verdict::Fail,
            Verdict::Skip, Verdict::Error, Verdict::Pass,
        ]);
        assert_eq!(v.pass, 3);
        assert_eq!(v.fail, 1);
        assert_eq!(v.skip, 1);
        assert_eq!(v.error, 1);
        assert_eq!(v.total, 6);
        assert!((v.pass_rate() - 0.75).abs() < 0.01);
    }

    #[test]
    fn severity_distribution() {
        let s = SeverityDistribution::from_severities(&[
            Severity::Low, Severity::Medium, Severity::High,
            Severity::Critical, Severity::Medium, Severity::High,
        ]);
        assert_eq!(s.low, 1);
        assert_eq!(s.medium, 2);
        assert_eq!(s.high, 2);
        assert_eq!(s.critical, 1);
        assert_eq!(s.blocking_count(), 3);
    }

    #[test]
    fn run_metrics_metric_values() {
        let mut rm = RunMetrics::new("run-1");
        rm.add_metric(Metric::new("detection_rate", 0.95, "ratio"));
        rm.add_metric(Metric::new("detection_rate", 0.90, "ratio"));
        rm.add_metric(Metric::new("latency", 100.0, "us"));
        assert_eq!(rm.metric_values("detection_rate").len(), 2);
        assert_eq!(rm.metric_values("latency").len(), 1);
        assert_eq!(rm.metric_values("nonexistent").len(), 0);
    }

    #[test]
    fn timing_metrics() {
        let t = TimingMetrics::new(1000, 800, 200);
        assert_eq!(t.total_us, 1000);
        assert_eq!(t.system_us, 800);
        assert_eq!(t.framework_us, 200);
    }
}
