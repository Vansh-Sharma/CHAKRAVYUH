// Soak Framework — Memory Leak Detector (D6)
//
// Detects memory leaks by tracking allocation/deallocation samples over time
// and performing linear regression analysis on net byte growth.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::validation::verification::Severity;

/// Configuration for the memory leak detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetectorConfig {
    /// Sampling interval in milliseconds.
    pub sample_interval_ms: u64,
    /// Minimum number of samples required before analysis.
    pub min_samples_for_analysis: usize,
    /// Growth rate threshold in bytes/sec to flag a leak.
    pub growth_rate_threshold: f64,
    /// Number of trailing samples for trend window.
    pub trend_window_samples: usize,
}

impl Default for LeakDetectorConfig {
    fn default() -> Self {
        Self {
            sample_interval_ms: 5000,
            min_samples_for_analysis: 10,
            growth_rate_threshold: 1024.0, // 1 KB/s
            trend_window_samples: 20,
        }
    }
}

/// A single memory sample captured at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySample {
    /// RFC 3339 timestamp of the sample.
    pub timestamp: String,
    /// Total allocated bytes at this point.
    pub allocated_bytes: u64,
    /// Cumulative allocation count.
    pub allocation_count: u64,
    /// Cumulative deallocation count.
    pub deallocation_count: u64,
    /// Net bytes (allocations - deallocations).
    pub net_bytes: i64,
}

/// Analysis result from leak detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakAnalysis {
    /// Whether a leak was detected.
    pub has_leak: bool,
    /// Growth rate in bytes per second (from linear regression).
    pub growth_rate_bytes_per_sec: f64,
    /// Total net growth over the observation window.
    pub total_growth_bytes: i64,
    /// Individual leak reports for detected growth regions.
    pub leaks: Vec<LeakReport>,
}

/// A single leak report describing a growth region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakReport {
    /// Index of the first sample in the growth region.
    pub start_sample: usize,
    /// Index of the last sample in the growth region.
    pub end_sample: usize,
    /// Net byte growth in this region.
    pub growth_bytes: i64,
    /// Growth rate in bytes/sec for this region.
    pub growth_rate: f64,
    /// Severity of the detected leak.
    pub severity: Severity,
    /// Human-readable description.
    pub description: String,
}

/// Detects memory leaks by tracking allocation samples over time.
///
/// Uses linear regression on net_bytes to compute growth rate (bytes/sec).
/// When the growth rate exceeds the configured threshold, a leak is flagged.
pub struct MemoryLeakDetector {
    samples: Vec<MemorySample>,
    config: LeakDetectorConfig,
}

impl MemoryLeakDetector {
    /// Create a new memory leak detector with the given configuration.
    pub fn new(config: LeakDetectorConfig) -> Self {
        info!(
            sample_interval_ms = config.sample_interval_ms,
            min_samples = config.min_samples_for_analysis,
            threshold = config.growth_rate_threshold,
            "MemoryLeakDetector initialized"
        );
        Self {
            samples: Vec::new(),
            config,
        }
    }

    /// Record a memory sample.
    ///
    /// Takes the current allocated bytes, cumulative allocation count,
    /// and cumulative deallocation count. Computes net_bytes internally.
    pub fn sample(&mut self, allocated_bytes: u64, alloc_count: u64, dealloc_count: u64) {
        let net_bytes = allocated_bytes as i64 - dealloc_count as i64;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let sample = MemorySample {
            timestamp,
            allocated_bytes,
            allocation_count: alloc_count,
            deallocation_count: dealloc_count,
            net_bytes,
        };
        info!(
            allocated = allocated_bytes,
            net = net_bytes,
            samples_total = self.samples.len() + 1,
            "Memory sample recorded"
        );
        self.samples.push(sample);
    }

    /// Analyze collected samples for memory leaks.
    ///
    /// Returns an error if there are insufficient samples.
    pub fn analyze(&self) -> Result<LeakAnalysis, String> {
        if self.samples.len() < self.config.min_samples_for_analysis {
            return Err(format!(
                "Insufficient samples for analysis: {} (need {})",
                self.samples.len(),
                self.config.min_samples_for_analysis
            ));
        }

        let growth_rate = self.compute_growth_rate();
        let leaks = self.detect_leaks();
        let total_growth = if self.samples.len() >= 2 {
            self.samples.last().map(|s| s.net_bytes).unwrap_or(0)
                - self.samples.first().map(|s| s.net_bytes).unwrap_or(0)
        } else {
            0
        };

        let has_leak = growth_rate > self.config.growth_rate_threshold;

        Ok(LeakAnalysis {
            has_leak,
            growth_rate_bytes_per_sec: growth_rate,
            total_growth_bytes: total_growth,
            leaks,
        })
    }

    /// Compute the growth rate (bytes/sec) using linear regression on net_bytes.
    ///
    /// The x-axis is the sample index, and the y-axis is net_bytes.
    /// The slope of the regression line gives bytes/sample; we convert to bytes/sec
    /// using the configured sample interval.
    fn compute_growth_rate(&self) -> f64 {
        let n = self.samples.len();
        if n < 2 {
            return 0.0;
        }

        // Use the trend window (last N samples) if available.
        let window_start = if n > self.config.trend_window_samples {
            n - self.config.trend_window_samples
        } else {
            0
        };

        let window = &self.samples[window_start..];
        let wn = window.len();

        // Linear regression: y = mx + b
        // m = (n * Σxy - Σx * Σy) / (n * Σx² - (Σx)²)
        let sum_x: f64 = (0..wn).map(|i| i as f64).sum();
        let sum_y: f64 = window.iter().map(|s| s.net_bytes as f64).sum();
        let sum_xy: f64 = (0..wn).map(|i| i as f64 * window[i].net_bytes as f64).sum();
        let sum_x2: f64 = (0..wn).map(|i| (i as f64) * (i as f64)).sum();

        let denominator = (wn as f64) * sum_x2 - sum_x * sum_x;
        if denominator.abs() < 1e-10 {
            return 0.0;
        }

        let slope = ((wn as f64) * sum_xy - sum_x * sum_y) / denominator;

        // slope is bytes per sample. Convert to bytes/sec.
        let interval_secs = self.config.sample_interval_ms as f64 / 1000.0;
        if interval_secs < 1e-10 {
            return 0.0;
        }

        slope / interval_secs
    }

    /// Detect leaks by scanning for statistically significant growth regions.
    ///
    /// Scans the samples in windows. If a window shows net positive growth
    /// that exceeds the threshold, a leak is reported.
    fn detect_leaks(&self) -> Vec<LeakReport> {
        let mut leaks = Vec::new();
        let n = self.samples.len();
        if n < self.config.trend_window_samples {
            return leaks;
        }

        let window_size = self.config.trend_window_samples;
        let num_windows = n.saturating_sub(window_size) + 1;

        for i in 0..num_windows {
            let start = i;
            let end = i + window_size;
            let window = &self.samples[start..end];

            let first_net = window.first().map(|s| s.net_bytes).unwrap_or(0);
            let last_net = window.last().map(|s| s.net_bytes).unwrap_or(0);
            let growth = last_net - first_net;

            if growth <= 0 {
                continue;
            }

            // Calculate growth rate for this window.
            let interval_secs = self.config.sample_interval_ms as f64 / 1000.0;
            let window_duration_secs = (window_size as f64) * interval_secs;
            let rate = if window_duration_secs > 0.0 {
                growth as f64 / window_duration_secs
            } else {
                0.0
            };

            if rate > self.config.growth_rate_threshold {
                let severity = if rate > self.config.growth_rate_threshold * 10.0 {
                    Severity::Critical
                } else if rate > self.config.growth_rate_threshold * 5.0 {
                    Severity::High
                } else if rate > self.config.growth_rate_threshold * 2.0 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let description = format!(
                    "Memory growth of {} bytes in window [{}..{}] = {:.2} bytes/sec",
                    growth, start, end, rate
                );

                warn!(
                    start = start,
                    end = end,
                    growth_bytes = growth,
                    rate = rate,
                    severity = %severity,
                    "Memory leak detected"
                );

                leaks.push(LeakReport {
                    start_sample: start,
                    end_sample: end,
                    growth_bytes: growth,
                    growth_rate: rate,
                    severity,
                    description,
                });
            }
        }

        leaks
    }

    /// Get the number of samples collected.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get all collected samples (read-only).
    pub fn samples(&self) -> &[MemorySample] {
        &self.samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LeakDetectorConfig {
        LeakDetectorConfig {
            sample_interval_ms: 1000,
            min_samples_for_analysis: 5,
            growth_rate_threshold: 100.0,
            trend_window_samples: 5,
        }
    }

    #[test]
    fn no_leak_with_flat_memory() {
        let config = default_config();
        let mut detector = MemoryLeakDetector::new(config);

        // Stable memory — no growth.
        for i in 0..10 {
            detector.sample(10_000 + i as u64, 500 + i as u64, 500 + i as u64);
        }

        let analysis = detector.analyze().unwrap();
        assert!(!analysis.has_leak);
        assert!(analysis.growth_rate_bytes_per_sec.abs() < 10.0);
    }

    #[test]
    fn leak_detected_with_steady_growth() {
        let config = LeakDetectorConfig {
            sample_interval_ms: 1000,
            min_samples_for_analysis: 5,
            growth_rate_threshold: 50.0,
            trend_window_samples: 5,
        };
        let mut detector = MemoryLeakDetector::new(config);

        // Growing memory — 200 bytes per sample.
        for i in 0..15 {
            let alloc = 10_000u64 + (i * 200) as u64;
            detector.sample(alloc, (i * 200) as u64, 0);
        }

        let analysis = detector.analyze().unwrap();
        assert!(analysis.has_leak);
        assert!(analysis.growth_rate_bytes_per_sec > 50.0);
        assert!(!analysis.leaks.is_empty());
    }

    #[test]
    fn insufficient_samples_returns_error() {
        let config = LeakDetectorConfig {
            sample_interval_ms: 1000,
            min_samples_for_analysis: 10,
            growth_rate_threshold: 100.0,
            trend_window_samples: 5,
        };
        let mut detector = MemoryLeakDetector::new(config);

        for i in 0..5 {
            detector.sample(1000 + i as u64, 100 + i as u64, 100 + i as u64);
        }

        let result = detector.analyze();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient samples"));
    }

    #[test]
    fn leak_severity_scaling() {
        let config = LeakDetectorConfig {
            sample_interval_ms: 1000,
            min_samples_for_analysis: 5,
            growth_rate_threshold: 10.0,
            trend_window_samples: 5,
        };
        let mut detector = MemoryLeakDetector::new(config);

        // Rapid growth — 500 bytes per sample → high severity.
        for i in 0..10 {
            let alloc = 10_000u64 + (i * 500) as u64;
            detector.sample(alloc, (i * 500) as u64, 0);
        }

        let analysis = detector.analyze().unwrap();
        assert!(analysis.has_leak);
        // Growth rate is 500 bytes/sec, threshold is 10 → 50x threshold → Critical.
        let has_critical = analysis
            .leaks
            .iter()
            .any(|l| l.severity == Severity::Critical);
        assert!(has_critical);
    }

    #[test]
    fn net_bytes_computation() {
        let config = default_config();
        let mut detector = MemoryLeakDetector::new(config);

        // Allocation count grows, deallocation stays same → net growth.
        detector.sample(5000, 100, 50);
        assert_eq!(detector.samples().last().map(|s| s.net_bytes), Some(4950));

        detector.sample(6000, 200, 100);
        assert_eq!(detector.samples().last().map(|s| s.net_bytes), Some(5900));
    }
}
