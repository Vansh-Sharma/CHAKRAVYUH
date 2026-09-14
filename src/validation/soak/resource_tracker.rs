// Soak Framework — Resource Tracker (D6)
//
// Tracks system resource usage over time: memory, CPU, file descriptors,
// threads, and tokio tasks. Provides trend detection and exhaustion alerts.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::ananta::TrendDirection;
use crate::validation::verification::Severity;

/// A single resource usage sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSample {
    /// RFC 3339 timestamp of the sample.
    pub timestamp: String,
    /// Memory usage in bytes.
    pub memory_bytes: u64,
    /// CPU usage as a percentage (0.0–100.0).
    pub cpu_percent: f64,
    /// Number of open file descriptors.
    pub open_fds: u64,
    /// Thread count.
    pub thread_count: u64,
    /// Tokio task count (goroutine equivalent).
    pub goroutine_equivalent: u64,
    /// Custom metrics (e.g., connection pool size, buffer usage).
    pub custom: HashMap<String, f64>,
}

impl ResourceSample {
    /// Create a new resource sample with the current timestamp.
    pub fn new(memory_bytes: u64, cpu_percent: f64, open_fds: u64, thread_count: u64) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            memory_bytes,
            cpu_percent,
            open_fds,
            thread_count,
            goroutine_equivalent: 0,
            custom: HashMap::new(),
        }
    }

    /// Builder: set the timestamp.
    pub fn with_timestamp(mut self, ts: &str) -> Self {
        self.timestamp = ts.to_string();
        self
    }

    /// Builder: set goroutine equivalent (tokio tasks).
    pub fn with_goroutines(mut self, count: u64) -> Self {
        self.goroutine_equivalent = count;
        self
    }

    /// Builder: add a custom metric.
    pub fn with_custom(mut self, key: &str, value: f64) -> Self {
        self.custom.insert(key.to_string(), value);
        self
    }
}

/// Summary of resource usage over all collected samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    /// Peak memory usage in bytes.
    pub memory_peak_bytes: u64,
    /// Net memory growth (last - first) in bytes. Can be negative.
    pub memory_growth: i64,
    /// Average CPU usage percentage.
    pub cpu_avg: f64,
    /// Peak CPU usage percentage.
    pub cpu_peak: f64,
    /// Peak open file descriptor count.
    pub fd_peak: u64,
    /// Peak thread count.
    pub thread_peak: u64,
    /// Total number of samples collected.
    pub samples: u64,
}

/// Configurable resource limits for exhaustion checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum allowed memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum allowed CPU percentage (0.0–100.0).
    pub max_cpu_percent: f64,
    /// Maximum allowed open file descriptors.
    pub max_fds: u64,
    /// Maximum allowed threads.
    pub max_threads: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
            max_cpu_percent: 90.0,
            max_fds: 10_000,
            max_threads: 1000,
        }
    }
}

/// An alert for a resource that is approaching or exceeding its limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAlert {
    /// The resource name (e.g., "memory", "cpu", "fds", "threads").
    pub resource: String,
    /// Current observed value.
    pub current: f64,
    /// Configured limit.
    pub limit: f64,
    /// Severity of the alert.
    pub severity: Severity,
}

/// Tracks system resource usage over time.
///
/// Records periodic resource samples and provides:
/// - Aggregate summaries (peak, avg, growth)
/// - Trend detection (growing/stable/declining)
/// - Exhaustion alerts against configurable limits
pub struct ResourceTracker {
    samples: Vec<ResourceSample>,
}

impl ResourceTracker {
    /// Create a new resource tracker.
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    /// Record a resource sample.
    pub fn sample(&mut self, sample: ResourceSample) {
        info!(
            memory = sample.memory_bytes,
            cpu = sample.cpu_percent,
            fds = sample.open_fds,
            threads = sample.thread_count,
            "Resource sample recorded"
        );
        self.samples.push(sample);
    }

    /// Generate a summary of all collected resource samples.
    pub fn summary(&self) -> ResourceSummary {
        if self.samples.is_empty() {
            return ResourceSummary {
                memory_peak_bytes: 0,
                memory_growth: 0,
                cpu_avg: 0.0,
                cpu_peak: 0.0,
                fd_peak: 0,
                thread_peak: 0,
                samples: 0,
            };
        }

        let memory_peak = self
            .samples
            .iter()
            .map(|s| s.memory_bytes)
            .max()
            .unwrap_or(0);
        let memory_first = self.samples.first().map(|s| s.memory_bytes).unwrap_or(0);
        let memory_last = self.samples.last().map(|s| s.memory_bytes).unwrap_or(0);
        let memory_growth = memory_last as i64 - memory_first as i64;

        let cpu_sum: f64 = self.samples.iter().map(|s| s.cpu_percent).sum();
        let cpu_avg = cpu_sum / self.samples.len() as f64;
        let cpu_peak = self
            .samples
            .iter()
            .map(|s| s.cpu_percent)
            .fold(0.0, f64::max);

        let fd_peak = self.samples.iter().map(|s| s.open_fds).max().unwrap_or(0);
        let thread_peak = self
            .samples
            .iter()
            .map(|s| s.thread_count)
            .max()
            .unwrap_or(0);

        ResourceSummary {
            memory_peak_bytes: memory_peak,
            memory_growth,
            cpu_avg,
            cpu_peak,
            fd_peak,
            thread_peak,
            samples: self.samples.len() as u64,
        }
    }

    /// Determine the trend direction of memory usage.
    ///
    /// Uses simple linear regression on the last 10 samples to classify
    /// the trend as growing, stable, or declining.
    pub fn memory_trend(&self) -> TrendDirection {
        if self.samples.len() < 3 {
            return TrendDirection::Stable;
        }

        let window_size = 10usize.min(self.samples.len());
        let start = self.samples.len() - window_size;
        let window = &self.samples[start..];
        let n = window.len();

        let sum_x: f64 = (0..n).map(|i| i as f64).sum();
        let sum_y: f64 = window.iter().map(|s| s.memory_bytes as f64).sum();
        let sum_xy: f64 = (0..n)
            .map(|i| i as f64 * window[i].memory_bytes as f64)
            .sum();
        let sum_x2: f64 = (0..n).map(|i| (i as f64).powi(2)).sum();

        let denom = (n as f64) * sum_x2 - sum_x * sum_x;
        if denom.abs() < 1e-10 {
            return TrendDirection::Stable;
        }

        let slope = ((n as f64) * sum_xy - sum_x * sum_y) / denom;

        // Classify based on slope relative to the first sample's magnitude.
        let baseline = window.first().map(|s| s.memory_bytes as f64).unwrap_or(1.0);
        let relative_slope = slope / baseline.max(1.0);

        if relative_slope > 0.001 {
            TrendDirection::Improving
        } else if relative_slope < -0.001 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        }
    }

    /// Check all resources against the given limits and return alerts.
    ///
    /// Produces alerts for resources that exceed 80% of their limit (Medium)
    /// or 95% of their limit (High/Critical depending on severity).
    pub fn resource_exhaustion_check(&self, limits: &ResourceLimits) -> Vec<ResourceAlert> {
        let mut alerts = Vec::new();

        let last = match self.samples.last() {
            Some(s) => s,
            None => return alerts,
        };

        // Memory check.
        let mem_usage = last.memory_bytes as f64 / limits.max_memory_bytes as f64;
        if mem_usage > 0.95 {
            alerts.push(ResourceAlert {
                resource: "memory".to_string(),
                current: last.memory_bytes as f64,
                limit: limits.max_memory_bytes as f64,
                severity: Severity::Critical,
            });
        } else if mem_usage > 0.80 {
            alerts.push(ResourceAlert {
                resource: "memory".to_string(),
                current: last.memory_bytes as f64,
                limit: limits.max_memory_bytes as f64,
                severity: Severity::Medium,
            });
        }

        // CPU check.
        let cpu_ratio = last.cpu_percent / limits.max_cpu_percent;
        if cpu_ratio > 0.95 {
            alerts.push(ResourceAlert {
                resource: "cpu".to_string(),
                current: last.cpu_percent,
                limit: limits.max_cpu_percent,
                severity: Severity::High,
            });
        } else if cpu_ratio > 0.80 {
            alerts.push(ResourceAlert {
                resource: "cpu".to_string(),
                current: last.cpu_percent,
                limit: limits.max_cpu_percent,
                severity: Severity::Medium,
            });
        }

        // FD check.
        let fd_ratio = last.open_fds as f64 / limits.max_fds as f64;
        if fd_ratio > 0.95 {
            alerts.push(ResourceAlert {
                resource: "fds".to_string(),
                current: last.open_fds as f64,
                limit: limits.max_fds as f64,
                severity: Severity::High,
            });
        } else if fd_ratio > 0.80 {
            alerts.push(ResourceAlert {
                resource: "fds".to_string(),
                current: last.open_fds as f64,
                limit: limits.max_fds as f64,
                severity: Severity::Low,
            });
        }

        // Thread check.
        let thread_ratio = last.thread_count as f64 / limits.max_threads as f64;
        if thread_ratio > 0.95 {
            alerts.push(ResourceAlert {
                resource: "threads".to_string(),
                current: last.thread_count as f64,
                limit: limits.max_threads as f64,
                severity: Severity::High,
            });
        } else if thread_ratio > 0.80 {
            alerts.push(ResourceAlert {
                resource: "threads".to_string(),
                current: last.thread_count as f64,
                limit: limits.max_threads as f64,
                severity: Severity::Low,
            });
        }

        if !alerts.is_empty() {
            warn!(
                alert_count = alerts.len(),
                "Resource exhaustion alerts generated"
            );
        }

        alerts
    }

    /// Get the number of samples collected.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get all collected samples (read-only).
    pub fn samples(&self) -> &[ResourceSample] {
        &self.samples
    }
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_with_no_samples() {
        let tracker = ResourceTracker::new();
        let summary = tracker.summary();
        assert_eq!(summary.samples, 0);
        assert_eq!(summary.memory_peak_bytes, 0);
    }

    #[test]
    fn summary_with_samples() {
        let mut tracker = ResourceTracker::new();
        tracker.sample(ResourceSample::new(1000, 25.0, 50, 10));
        tracker.sample(ResourceSample::new(2000, 50.0, 100, 20));
        tracker.sample(ResourceSample::new(3000, 75.0, 150, 30));

        let summary = tracker.summary();
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.memory_peak_bytes, 3000);
        assert_eq!(summary.memory_growth, 2000);
        assert!((summary.cpu_avg - 50.0).abs() < 0.01);
        assert!((summary.cpu_peak - 75.0).abs() < 0.01);
        assert_eq!(summary.fd_peak, 150);
        assert_eq!(summary.thread_peak, 30);
    }

    #[test]
    fn memory_trend_growing() {
        let mut tracker = ResourceTracker::new();
        for i in 0..10 {
            tracker.sample(ResourceSample::new(1000 + i * 500, 10.0, 50, 10));
        }
        assert_eq!(tracker.memory_trend(), TrendDirection::Improving);
    }

    #[test]
    fn memory_trend_declining() {
        let mut tracker = ResourceTracker::new();
        for i in 0..10 {
            tracker.sample(ResourceSample::new(10000 - i * 500, 10.0, 50, 10));
        }
        assert_eq!(tracker.memory_trend(), TrendDirection::Degrading);
    }

    #[test]
    fn resource_exhaustion_no_alerts() {
        let mut tracker = ResourceTracker::new();
        tracker.sample(ResourceSample::new(100, 10.0, 10, 5));
        let limits = ResourceLimits::default();
        let alerts = tracker.resource_exhaustion_check(&limits);
        assert!(alerts.is_empty());
    }

    #[test]
    fn resource_exhaustion_critical_memory() {
        let mut tracker = ResourceTracker::new();
        let limit_bytes = 1000u64;
        tracker.sample(ResourceSample::new(990, 10.0, 10, 5)); // 99% of limit
        let limits = ResourceLimits {
            max_memory_bytes: limit_bytes,
            max_cpu_percent: 100.0,
            max_fds: 100,
            max_threads: 100,
        };
        let alerts = tracker.resource_exhaustion_check(&limits);
        assert!(!alerts.is_empty());
        let mem_alert = alerts.iter().find(|a| a.resource == "memory").unwrap();
        assert_eq!(mem_alert.severity, Severity::Critical);
    }
}
