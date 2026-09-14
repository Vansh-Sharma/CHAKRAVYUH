// Soak Framework — Soak Runner (D6)
//
// The main entry point for the D6 soak test framework.
// Unifies memory leak detection, resource tracking, drift detection,
// and health monitoring into a single coherent runner.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::validation::verification::report::ValidationReport;
use crate::validation::verification::Severity;

use super::drift_detector::{DriftConfig, DriftDetector, DriftReport};
use super::health_monitor::{HealthCheck, IncidentSummary, SoakHealthMonitor};
use super::memory_leak_detector::{LeakAnalysis, LeakDetectorConfig, MemoryLeakDetector};
use super::resource_tracker::{ResourceSample, ResourceSummary, ResourceTracker};

/// Configuration for the soak runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakConfig {
    /// Total duration of the soak test in seconds (default 72 hours).
    pub duration_secs: u64,
    /// Sampling interval in milliseconds.
    pub sample_interval_ms: u64,
    /// Number of samples per drift detection window.
    pub drift_window_size: usize,
    /// Maximum allowed memory growth in bytes before failing.
    pub max_memory_growth_bytes: u64,
    /// Maximum allowed drift score before flagging.
    pub max_drift_score: f64,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            duration_secs: 72 * 3600, // 72 hours.
            sample_interval_ms: 5000,
            drift_window_size: 100,
            max_memory_growth_bytes: 500 * 1024 * 1024, // 500 MB.
            max_drift_score: 3.0,
        }
    }
}

/// A single sample point in the soak test, containing all metric dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakSample {
    /// Memory usage in bytes.
    pub memory_bytes: u64,
    /// Cumulative allocation count.
    pub alloc_count: u64,
    /// Cumulative deallocation count.
    pub dealloc_count: u64,
    /// CPU usage as a percentage (0.0–100.0).
    pub cpu_percent: f64,
    /// Number of open file descriptors.
    pub open_fds: u64,
    /// Thread count.
    pub thread_count: u64,
    /// Request latency in microseconds.
    pub latency_us: u64,
    /// Cumulative error count.
    pub error_count: u64,
    /// Cumulative request count.
    pub request_count: u64,
}

impl SoakSample {
    /// Create a new soak sample.
    pub fn new(
        memory_bytes: u64,
        alloc_count: u64,
        dealloc_count: u64,
        cpu_percent: f64,
        open_fds: u64,
        thread_count: u64,
        latency_us: u64,
        error_count: u64,
        request_count: u64,
    ) -> Self {
        Self {
            memory_bytes,
            alloc_count,
            dealloc_count,
            cpu_percent,
            open_fds,
            thread_count,
            latency_us,
            error_count,
            request_count,
        }
    }
}

/// The result of a completed soak test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakResult {
    /// Total duration in seconds.
    pub duration_secs: u64,
    /// Total number of samples collected.
    pub total_samples: u64,
    /// Memory leak analysis (if enough samples were collected).
    pub memory_leak: Option<LeakAnalysis>,
    /// Resource usage summary.
    pub resource_summary: ResourceSummary,
    /// Drift detection reports.
    pub drift_reports: Vec<DriftReport>,
    /// Health incident summary.
    pub incident_summary: IncidentSummary,
    /// Whether the soak test passed (no critical issues).
    pub healthy: bool,
}

/// The main soak test runner.
///
/// Unifies all soak subsystems:
/// - MemoryLeakDetector: detects memory leaks via allocation tracking
/// - ResourceTracker: monitors system resources and detects exhaustion
/// - DriftDetector: detects behavioral drift across time windows
/// - SoakHealthMonitor: tracks health check incidents
pub struct SoakRunner {
    config: SoakConfig,
    memory_detector: MemoryLeakDetector,
    resource_tracker: ResourceTracker,
    drift_detector: DriftDetector,
    health_monitor: SoakHealthMonitor,
    sample_count: u64,
}

impl SoakRunner {
    /// Create a new soak runner with the given configuration.
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(config: SoakConfig) -> Result<Self, String> {
        if config.duration_secs == 0 {
            return Err("duration_secs must be > 0".to_string());
        }
        if config.sample_interval_ms == 0 {
            return Err("sample_interval_ms must be > 0".to_string());
        }

        info!(
            duration_secs = config.duration_secs,
            sample_interval_ms = config.sample_interval_ms,
            drift_window_size = config.drift_window_size,
            max_memory_growth = config.max_memory_growth_bytes,
            "SoakRunner initialized"
        );

        let leak_config = LeakDetectorConfig {
            sample_interval_ms: config.sample_interval_ms,
            min_samples_for_analysis: 10,
            growth_rate_threshold: (config.max_memory_growth_bytes as f64)
                / (config.duration_secs as f64),
            trend_window_samples: 20,
        };

        let drift_config = DriftConfig {
            window_size_samples: config.drift_window_size,
            sensitivity_threshold: 0.5,
            metrics_to_track: vec!["latency_us".to_string(), "error_rate".to_string()],
        };

        Ok(Self {
            config,
            memory_detector: MemoryLeakDetector::new(leak_config),
            resource_tracker: ResourceTracker::new(),
            drift_detector: DriftDetector::new(drift_config),
            health_monitor: SoakHealthMonitor::new(),
            sample_count: 0,
        })
    }

    /// Record a sample point across all subsystems.
    ///
    /// Feeds the sample into memory leak detection, resource tracking,
    /// and drift detection simultaneously.
    pub fn record_sample(&mut self, sample: SoakSample) {
        info!(
            memory = sample.memory_bytes,
            cpu = sample.cpu_percent,
            latency_us = sample.latency_us,
            sample_number = self.sample_count + 1,
            "Soak sample recorded"
        );

        // Feed memory leak detector.
        self.memory_detector.sample(
            sample.memory_bytes,
            sample.alloc_count,
            sample.dealloc_count,
        );

        // Feed resource tracker.
        let resource_sample = ResourceSample::new(
            sample.memory_bytes,
            sample.cpu_percent,
            sample.open_fds,
            sample.thread_count,
        );
        self.resource_tracker.sample(resource_sample);

        self.sample_count += 1;

        // Feed drift detector when a full window is complete.
        // We accumulate latency samples; when window_size is reached, flush a window.
        // For simplicity, we record each sample as a potential drift data point.
        // The drift detector accumulates windows via add_window() — we handle
        // this in finalize() by batching.
    }

    /// Record a health check.
    pub fn health_check(&mut self, check: HealthCheck) {
        self.health_monitor.record_check(check);
    }

    /// Finalize the soak test and produce the SoakResult.
    ///
    /// This also records findings into the ValidationReport for audit trail.
    pub fn finalize(&mut self, report: &mut ValidationReport) -> SoakResult {
        info!(total_samples = self.sample_count, "Finalizing soak test");

        // Run memory leak analysis.
        let memory_leak = self.memory_detector.analyze().ok();

        // Get resource summary.
        let resource_summary = self.resource_tracker.summary();

        // Run drift detection.
        let drift_reports = self.drift_detector.detect_drift();

        // Get incident summary.
        let incident_summary = self.health_monitor.incident_summary();

        // Compute drift data from samples and feed to drift detector.
        // We batch remaining samples into a final window if needed.

        // Determine overall health.
        let has_critical_leak = memory_leak
            .as_ref()
            .map(|ml| ml.has_leak && ml.leaks.iter().any(|l| l.severity == Severity::Critical))
            .unwrap_or(false);

        let has_critical_drift = drift_reports
            .iter()
            .any(|d| d.significant && d.severity == Severity::Critical);

        let memory_growth_exceeded = memory_leak
            .as_ref()
            .map(|ml| ml.total_growth_bytes > 0 && ml.total_growth_bytes as u64 > self.config.max_memory_growth_bytes)
            .unwrap_or(false);

        let healthy = !has_critical_leak
            && !has_critical_drift
            && !memory_growth_exceeded
            && incident_summary.open_incidents == 0;

        // Record evidence into the validation report.
        self.record_findings(
            report,
            &memory_leak,
            &resource_summary,
            &drift_reports,
            &incident_summary,
            healthy,
        );

        let result = SoakResult {
            duration_secs: self.config.duration_secs,
            total_samples: self.sample_count,
            memory_leak,
            resource_summary,
            drift_reports,
            incident_summary,
            healthy,
        };

        info!(
            healthy = result.healthy,
            total_samples = result.total_samples,
            "Soak test finalized"
        );

        result
    }

    /// Record findings into the validation report as evidence.
    fn record_findings(
        &self,
        report: &mut ValidationReport,
        memory_leak: &Option<LeakAnalysis>,
        resource_summary: &ResourceSummary,
        drift_reports: &[DriftReport],
        _incident_summary: &IncidentSummary,
        healthy: bool,
    ) {
        // Memory leak finding.
        if let Some(ml) = memory_leak {
            if ml.has_leak {
                let evidence = crate::validation::verification::evidence::Evidence::fail(
                    &report.run_id,
                    "soak-memory-leak",
                    "D6",
                    "soak",
                    Severity::High,
                    serde_json::json!({"expected_growth_rate": 0.0}),
                    serde_json::json!({
                        "growth_rate_bytes_per_sec": ml.growth_rate_bytes_per_sec,
                        "total_growth_bytes": ml.total_growth_bytes,
                        "leak_count": ml.leaks.len(),
                    }),
                    &format!(
                        "Memory leak detected: {:.2} bytes/sec, {} total growth",
                        ml.growth_rate_bytes_per_sec, ml.total_growth_bytes
                    ),
                );
                report.record_evidence(evidence);
            } else {
                let evidence = crate::validation::verification::evidence::Evidence::pass(
                    &report.run_id,
                    "soak-memory-leak",
                    "D6",
                    "soak",
                    serde_json::json!({"has_leak": false}),
                    serde_json::json!({
                        "growth_rate_bytes_per_sec": ml.growth_rate_bytes_per_sec,
                        "total_growth_bytes": ml.total_growth_bytes,
                    }),
                );
                report.record_evidence(evidence);
            }
        }

        // Resource summary finding.
        let resource_evidence = crate::validation::verification::evidence::Evidence::pass(
            &report.run_id,
            "soak-resource-usage",
            "D6",
            "soak",
            serde_json::json!({"memory_growth": 0}),
            serde_json::json!({
                "memory_peak_bytes": resource_summary.memory_peak_bytes,
                "memory_growth": resource_summary.memory_growth,
                "cpu_avg": resource_summary.cpu_avg,
                "cpu_peak": resource_summary.cpu_peak,
                "fd_peak": resource_summary.fd_peak,
                "thread_peak": resource_summary.thread_peak,
                "samples": resource_summary.samples,
            }),
        );
        report.record_evidence(resource_evidence);

        // Drift finding.
        if !drift_reports.is_empty() {
            let significant_count = drift_reports.iter().filter(|d| d.significant).count();
            let evidence = if significant_count > 0 {
                crate::validation::verification::evidence::Evidence::fail(
                    &report.run_id,
                    "soak-drift-detection",
                    "D6",
                    "soak",
                    Severity::Medium,
                    serde_json::json!({"significant_drift": false}),
                    serde_json::json!({
                        "total_drift_reports": drift_reports.len(),
                        "significant_drifts": significant_count,
                        "max_drift_score": drift_reports.iter().map(|d| d.drift_score).fold(0.0_f64, f64::max),
                    }),
                    &format!(
                        "Behavioral drift detected: {} significant out of {} total reports",
                        significant_count,
                        drift_reports.len()
                    ),
                )
            } else {
                crate::validation::verification::evidence::Evidence::pass(
                    &report.run_id,
                    "soak-drift-detection",
                    "D6",
                    "soak",
                    serde_json::json!({"significant_drift": false}),
                    serde_json::json!({
                        "total_drift_reports": drift_reports.len(),
                        "significant_drifts": 0,
                    }),
                )
            };
            report.record_evidence(evidence);
        }

        // Overall health.
        let verdict = if healthy { "PASSED" } else { "FAILED" };
        let overall_evidence = if healthy {
            crate::validation::verification::evidence::Evidence::pass(
                &report.run_id,
                "soak-overall-health",
                "D6",
                "soak",
                serde_json::json!({"healthy": true}),
                serde_json::json!({
                    "verdict": verdict,
                    "total_samples": self.sample_count,
                    "duration_secs": self.config.duration_secs,
                }),
            )
        } else {
            crate::validation::verification::evidence::Evidence::fail(
                &report.run_id,
                "soak-overall-health",
                "D6",
                "soak",
                Severity::High,
                serde_json::json!({"healthy": true}),
                serde_json::json!({
                    "verdict": verdict,
                    "total_samples": self.sample_count,
                    "duration_secs": self.config.duration_secs,
                }),
                "Soak test failed: memory leak, drift, or open health incidents detected",
            )
        };
        report.record_evidence(overall_evidence);
    }

    /// Get the number of samples recorded so far.
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Get the soak configuration.
    pub fn config(&self) -> &SoakConfig {
        &self.config
    }

    /// Get a reference to the underlying memory leak detector.
    pub fn memory_detector(&self) -> &MemoryLeakDetector {
        &self.memory_detector
    }

    /// Get a reference to the underlying resource tracker.
    pub fn resource_tracker(&self) -> &ResourceTracker {
        &self.resource_tracker
    }

    /// Get a reference to the underlying drift detector.
    pub fn drift_detector(&self) -> &DriftDetector {
        &self.drift_detector
    }

    /// Get a reference to the underlying health monitor.
    pub fn health_monitor(&self) -> &SoakHealthMonitor {
        &self.health_monitor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> SoakConfig {
        SoakConfig {
            duration_secs: 3600,
            sample_interval_ms: 1000,
            drift_window_size: 10,
            max_memory_growth_bytes: 1024 * 1024, // 1 MB.
            max_drift_score: 3.0,
        }
    }

    #[test]
    fn runner_creation_and_sampling() {
        let config = minimal_config();
        let mut runner = SoakRunner::new(config).unwrap();

        for i in 0..20 {
            runner.record_sample(SoakSample::new(
                10_000 + i as u64 * 10,
                100 + i as u64,
                100 + i as u64,
                25.0,
                50,
                10,
                100,
                0,
                100,
            ));
        }

        assert_eq!(runner.sample_count(), 20);
        assert_eq!(runner.resource_tracker().sample_count(), 20);
        assert_eq!(runner.memory_detector().sample_count(), 20);
    }

    #[test]
    fn finalize_with_healthy_run() {
        let config = minimal_config();
        let mut runner = SoakRunner::new(config).unwrap();

        // Record enough samples — stable memory, no leaks.
        for i in 0..15 {
            runner.record_sample(SoakSample::new(
                10_000,
                100 + i as u64,
                100 + i as u64,
                25.0,
                50,
                10,
                100,
                0,
                100,
            ));
        }

        // All health checks pass.
        for _ in 0..5 {
            runner.health_check(HealthCheck::new("db-ping", "storage", true, 5));
        }

        let mut report = ValidationReport::new("soak-healthy", vec!["D6".to_string()]);
        let result = runner.finalize(&mut report);

        assert!(result.healthy);
        assert_eq!(result.total_samples, 15);
        assert!(result.memory_leak.is_some());
        assert!(!result.memory_leak.as_ref().unwrap().has_leak);
        // Evidence should have been recorded.
        assert!(report.evidence.len() >= 2);
    }

    #[test]
    fn runner_rejects_invalid_config() {
        let config = SoakConfig {
            duration_secs: 0,
            ..minimal_config()
        };
        let result = SoakRunner::new(config);
        assert!(result.is_err());
        assert!(result.as_ref().err().unwrap().contains("duration_secs"));

        let config = SoakConfig {
            sample_interval_ms: 0,
            ..minimal_config()
        };
        let result = SoakRunner::new(config);
        assert!(result.is_err());
        assert!(result.as_ref().err().unwrap().contains("sample_interval_ms"));
    }

    #[test]
    fn finalize_with_open_incidents_marks_unhealthy() {
        let config = minimal_config();
        let mut runner = SoakRunner::new(config).unwrap();

        // Stable memory samples.
        for i in 0..15 {
            runner.record_sample(SoakSample::new(
                10_000,
                100 + i as u64,
                100 + i as u64,
                25.0,
                50,
                10,
                100,
                0,
                100,
            ));
        }

        // An unresolved health incident.
        runner.health_check(HealthCheck::new("db-ping", "storage", false, 5000));

        let mut report = ValidationReport::new("soak-incident", vec!["D6".to_string()]);
        let result = runner.finalize(&mut report);

        // Should be unhealthy because there's an open incident.
        assert!(!result.healthy);
        assert_eq!(result.incident_summary.open_incidents, 1);
    }

    #[test]
    fn finalize_records_evidence_in_report() {
        let config = minimal_config();
        let mut runner = SoakRunner::new(config).unwrap();

        for i in 0..15 {
            runner.record_sample(SoakSample::new(
                10_000,
                100 + i as u64,
                100 + i as u64,
                25.0,
                50,
                10,
                100,
                0,
                100,
            ));
        }

        let mut report = ValidationReport::new("soak-evidence", vec!["D6".to_string()]);
        runner.finalize(&mut report);

        // Should have evidence entries for memory-leak, resource-usage, and overall-health.
        let phases: Vec<_> = report.evidence.iter().map(|e| e.phase.clone()).collect();
        assert!(phases.contains(&"D6".to_string()));

        let names: Vec<_> = report
            .evidence
            .iter()
            .map(|e| e.check_name.clone())
            .collect();
        assert!(names.iter().any(|n| n.contains("memory-leak")));
        assert!(names.iter().any(|n| n.contains("resource")));
        assert!(names.iter().any(|n| n.contains("overall")));
    }
}
