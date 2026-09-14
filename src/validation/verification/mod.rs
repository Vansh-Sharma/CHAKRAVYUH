// Verification Engine — D0 Core Module
//
// The Verification Engine is the foundation of the Security Validation Platform.
// Every D-phase (D1-D7) uses this engine to produce:
//   Evidence → Metrics → Audit Trail → Replay → Report
//
// Architecture:
//   evidence.rs   — Evidence, ReplayData, Verdict, Severity (immutable, tamper-proof)
//   metrics.rs    — Metric, MetricSummary, VerdictDistribution, SeverityDistribution, RunMetrics
//   report.rs     — ValidationReport, RunStatus, ChainStatus (top-level report output)
//   verifier.rs   — MatchStrategy, VerificationSpec, verify_match(), verify_and_record()

pub mod evidence;
pub mod metrics;
pub mod report;
pub mod verifier;

// Re-export the core types that every D-phase uses.
pub use evidence::{Evidence, EvidenceId, ReplayData, RunId, Severity, Verdict};
pub use metrics::{
    Metric, MetricSummary, RunMetrics, SeverityDistribution, SubsystemMetrics,
    TimingMetrics, VerdictDistribution,
};
pub use report::{ChainStatus, RunStatus, ValidationReport};
pub use verifier::{verify_and_record, verify_match, MatchStrategy, VerificationSpec};

/// Global configuration for the verification engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationConfig {
    /// Maximum number of evidence items per report (0 = unlimited).
    pub max_evidence_per_report: usize,
    /// Whether to compute integrity hashes on evidence (adds overhead).
    pub enable_integrity_hashes: bool,
    /// Whether to record replay data for every check.
    pub enable_replay: bool,
    /// Tags to apply to all evidence in this session.
    pub global_tags: Vec<String>,
    /// Output directory for report exports.
    pub output_dir: String,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            max_evidence_per_report: 1_000_000,
            enable_integrity_hashes: true,
            enable_replay: true,
            global_tags: Vec::new(),
            output_dir: ".".to_string(),
        }
    }
}

impl VerificationConfig {
    /// Create a config optimized for fast iteration (fewer checks, no replay).
    pub fn fast_iter() -> Self {
        Self {
            max_evidence_per_report: 10_000,
            enable_integrity_hashes: false,
            enable_replay: false,
            global_tags: vec!["fast-iter".to_string()],
            output_dir: ".".to_string(),
        }
    }

    /// Create a config optimized for full release validation.
    pub fn release() -> Self {
        Self {
            max_evidence_per_report: 0,
            enable_integrity_hashes: true,
            enable_replay: true,
            global_tags: vec!["release".to_string()],
            output_dir: "./validation_reports".to_string(),
        }
    }
}

/// The top-level Verification Engine.
///
/// Manages the lifecycle of validation runs: create reports,
/// run verification specs, and produce final reports.
#[derive(Debug)]
pub struct VerificationEngine {
    config: VerificationConfig,
    /// Active reports (keyed by run_id).
    active_reports: std::collections::HashMap<String, ValidationReport>,
}

impl VerificationEngine {
    /// Create a new engine with the given config.
    pub fn new(config: VerificationConfig) -> Self {
        Self {
            config,
            active_reports: std::collections::HashMap::new(),
        }
    }

    /// Create with default config.
    pub fn default() -> Self {
        Self::new(VerificationConfig::default())
    }

    /// Start a new validation run and return its mutable report.
    pub fn start_run(&mut self, name: &str, phases: Vec<String>) -> &mut ValidationReport {
        let report = ValidationReport::new(name, phases);
        let run_id = report.run_id.clone();
        self.active_reports.insert(run_id.clone(), report);
        self.active_reports.get_mut(&run_id).expect("just inserted")
    }

    /// Get a mutable reference to an active report.
    pub fn report_mut(&mut self, run_id: &str) -> Option<&mut ValidationReport> {
        self.active_reports.get_mut(run_id)
    }

    /// Finalize a run, compute aggregates, and return the report.
    pub fn finalize_run(&mut self, run_id: &str) -> Option<ValidationReport> {
        if let Some(report) = self.active_reports.get_mut(run_id) {
            report.finalize();
            Some(report.clone())
        } else {
            None
        }
    }

    /// Finalize and export a run as JSON.
    pub fn export_run_json(&mut self, run_id: &str) -> Result<String, String> {
        let report = self.finalize_run(run_id)
            .ok_or_else(|| format!("Run {} not found", run_id))?;
        report.to_json()
    }

    /// Finalize and export a run as text summary.
    pub fn export_run_text(&mut self, run_id: &str) -> Result<String, String> {
        let report = self.finalize_run(run_id)
            .ok_or_else(|| format!("Run {} not found", run_id))?;
        Ok(report.to_text_summary())
    }

    /// List all active (not yet finalized) run IDs.
    pub fn active_run_ids(&self) -> Vec<String> {
        self.active_reports.keys().cloned().collect()
    }

    /// Get the engine configuration.
    pub fn config(&self) -> &VerificationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::verification::evidence::Evidence;

    #[test]
    fn engine_lifecycle() {
        let mut engine = VerificationEngine::new(VerificationConfig::default());
        let report = engine.start_run("lifecycle-test", vec!["D0".to_string()]);
        let run_id = report.run_id.clone();

        report.record_evidence(Evidence::pass(
            &run_id, "check", "D0", "v",
            serde_json::json!(true), serde_json::json!(true),
        ));

        let json = engine.export_run_json(&run_id).unwrap();
        assert!(json.contains("lifecycle-test"));
        assert!(json.contains("passed"));
    }

    #[test]
    fn engine_text_export() {
        let mut engine = VerificationEngine::new(VerificationConfig::default());
        let report = engine.start_run("text-test", vec!["D0".to_string()]);
        let run_id = report.run_id.clone();

        report.record_evidence(Evidence::pass(
            &run_id, "c", "D0", "v",
            serde_json::json!(1), serde_json::json!(1),
        ));

        let text = engine.export_run_text(&run_id).unwrap();
        assert!(text.contains("text-test"));
    }

    #[test]
    fn engine_missing_run() {
        let mut engine = VerificationEngine::new(VerificationConfig::default());
        assert!(engine.finalize_run("nonexistent").is_none());
    }

    #[test]
    fn config_presets() {
        let fast = VerificationConfig::fast_iter();
        assert!(!fast.enable_integrity_hashes);
        assert!(!fast.enable_replay);

        let release = VerificationConfig::release();
        assert!(release.enable_integrity_hashes);
        assert!(release.enable_replay);
    }
}
