// Verification Engine — Report Generation (D0)
//
// Produces structured, machine-readable and human-auditable reports.
// Every report contains: evidence summary, metrics, audit trail, and replay index.
//
// Output formats: JSON (structured), Text (terminal), and a summary struct
// that higher-level tools can consume.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::evidence::{Evidence, EvidenceId, ReplayData, RunId, Severity, Verdict};
use super::metrics::{RunMetrics, SeverityDistribution, VerdictDistribution};

/// The status of an entire validation run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// The run is still in progress.
    Running,
    /// All checks passed (or only non-blocking failures).
    Passed,
    /// One or more blocking failures found.
    Failed,
    /// The run encountered an infrastructure error.
    Error,
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunStatus::Running => write!(f, "RUNNING"),
            RunStatus::Passed => write!(f, "PASSED"),
            RunStatus::Failed => write!(f, "FAILED"),
            RunStatus::Error => write!(f, "ERROR"),
        }
    }
}

/// A complete validation report.
///
/// This is the top-level output of the verification engine.
/// It bundles together: evidence, metrics, replay data, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Unique run ID.
    pub run_id: RunId,
    /// Human-readable run name.
    pub run_name: String,
    /// Which phase(s) were executed.
    pub phases: Vec<String>,
    /// Overall run status.
    pub status: RunStatus,
    /// RFC 3339 start timestamp.
    pub started_at: String,
    /// RFC 3339 end timestamp.
    pub finished_at: Option<String>,
    /// Total duration in microseconds.
    pub duration_us: u64,
    /// Verdict distribution.
    pub verdicts: VerdictDistribution,
    /// Severity distribution (fail-only).
    pub severities: SeverityDistribution,
    /// All evidence collected.
    pub evidence: Vec<Evidence>,
    /// All replay data collected.
    pub replays: Vec<ReplayData>,
    /// Metrics for this run.
    pub metrics: RunMetrics,
    /// Environment metadata.
    pub environment: HashMap<String, String>,
    /// Tags for filtering.
    pub tags: Vec<String>,
    /// Custom report metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ValidationReport {
    /// Start a new validation run.
    pub fn new(run_name: &str, phases: Vec<String>) -> Self {
        let run_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now().to_rfc3339();
        Self {
            run_id: run_id.clone(),
            run_name: run_name.to_string(),
            phases,
            status: RunStatus::Running,
            started_at,
            finished_at: None,
            duration_us: 0,
            verdicts: VerdictDistribution::default(),
            severities: SeverityDistribution::default(),
            evidence: Vec::new(),
            replays: Vec::new(),
            metrics: RunMetrics::new(&run_id),
            environment: collect_report_env(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Record a piece of evidence. Chains it to the previous evidence for audit trail.
    pub fn record_evidence(&mut self, mut evidence: Evidence) {
        // Link to previous evidence for chain of custody.
        let prev_id = self.evidence.last().map(|e| e.id.clone());
        evidence.prev_evidence_id = prev_id;
        evidence.run_id = self.run_id.clone();
        self.evidence.push(evidence);
    }

    /// Record replay data.
    pub fn record_replay(&mut self, replay: ReplayData) {
        self.replays.push(replay);
    }

    /// Finalize the report — compute aggregates and set status.
    pub fn finalize(&mut self) {
        let verdicts: Vec<Verdict> = self.evidence.iter().map(|e| e.verdict).collect();
        self.verdicts = VerdictDistribution::from_verdicts(&verdicts);

        let severities: Vec<Severity> = self
            .evidence
            .iter()
            .filter(|e| e.verdict == Verdict::Fail)
            .map(|e| e.severity)
            .collect();
        self.severities = SeverityDistribution::from_severities(&severities);

        self.finished_at = Some(chrono::Utc::now().to_rfc3339());
        self.status = if self.verdicts.error > 0 {
            RunStatus::Error
        } else if self.severities.blocking_count() > 0 {
            RunStatus::Failed
        } else {
            RunStatus::Passed
        };
    }

    /// Get evidence for a specific phase.
    pub fn evidence_for_phase(&self, phase: &str) -> Vec<&Evidence> {
        self.evidence.iter().filter(|e| e.phase == phase).collect()
    }

    /// Get evidence for a specific subsystem.
    pub fn evidence_for_subsystem(&self, subsystem: &str) -> Vec<&Evidence> {
        self.evidence.iter().filter(|e| e.subsystem == subsystem).collect()
    }

    /// Get only failed evidence, sorted by severity (highest first).
    pub fn failures(&self) -> Vec<&Evidence> {
        let mut fails: Vec<&Evidence> = self.evidence.iter().filter(|e| e.verdict == Verdict::Fail).collect();
        fails.sort_by(|a, b| b.severity.cmp(&a.severity));
        fails
    }

    /// Check if the evidence chain is intact (no broken links).
    pub fn verify_evidence_chain(&self) -> bool {
        for window in self.evidence.windows(2) {
            if window[1].prev_evidence_id.as_deref() != Some(&window[0].id) {
                return false;
            }
        }
        // Also verify each evidence item's integrity hash.
        self.evidence.iter().all(|e| e.verify_integrity())
    }

    /// Export the full report as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Export a compact text summary for terminal output.
    pub fn to_text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("=== {} ===\n", self.run_name));
        out.push_str(&format!("Run ID: {}\n", self.run_id));
        out.push_str(&format!("Status: {}\n", self.status));
        out.push_str(&format!("Phases: {}\n", self.phases.join(", ")));
        out.push_str(&format!(
            "Verdicts: {} pass, {} fail, {} skip, {} error (total: {})\n",
            self.verdicts.pass, self.verdicts.fail,
            self.verdicts.skip, self.verdicts.error, self.verdicts.total
        ));
        if self.severities.critical > 0 {
            out.push_str(&format!("CRITICAL: {}  HIGH: {}  MEDIUM: {}  LOW: {}\n",
                self.severities.critical, self.severities.high,
                self.severities.medium, self.severities.low
            ));
        }
        out.push_str(&format!("Duration: {} us\n", self.duration_us));
        out.push_str(&format!("Evidence items: {}\n", self.evidence.len()));
        out.push_str(&format!("Replay entries: {}\n", self.replays.len()));

        // List failures.
        let fails = self.failures();
        if !fails.is_empty() {
            out.push_str(&format!("\n--- Failures ({} total) ---\n", fails.len()));
            for f in fails.iter().take(20) {
                out.push_str(&format!(
                    "  [{}] {} :: {} :: {}\n",
                    f.severity, f.phase, f.subsystem, f.check_name
                ));
                out.push_str(&format!("    Expected: {}\n", f.expected));
                out.push_str(&format!("    Observed: {}\n", f.observed));
            }
            if fails.len() > 20 {
                out.push_str(&format!("  ... and {} more\n", fails.len() - 20));
            }
        }

        out
    }

    /// Export evidence chain verification status.
    pub fn chain_status(&self) -> ChainStatus {
        let intact = self.verify_evidence_chain();
        let tampered: Vec<&EvidenceId> = self
            .evidence
            .iter()
            .filter(|e| !e.verify_integrity())
            .map(|e| &e.id)
            .collect();
        let broken_links: Vec<(usize, &Evidence)> = self
            .evidence
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[1].prev_evidence_id.as_deref() != Some(&w[0].id))
            .map(|(i, w)| (i, &w[1]))
            .collect();
        ChainStatus {
            intact,
            total_items: self.evidence.len(),
            tampered_count: tampered.len(),
            broken_link_count: broken_links.len(),
        }
    }
}

/// Status of the evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    /// Is the entire chain intact and all hashes valid?
    pub intact: bool,
    /// Total number of evidence items.
    pub total_items: usize,
    /// Number of tampered items.
    pub tampered_count: usize,
    /// Number of broken chain links.
    pub broken_link_count: usize,
}

fn collect_report_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("crate_version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    env.insert("rust_version".to_string(), env!("CARGO_PKG_RUST_VERSION").to_string());
    env.insert("target_arch".to_string(), std::env::consts::ARCH.to_string());
    env.insert("target_os".to_string(), std::env::consts::OS.to_string());
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::verification::evidence::Evidence;

    #[test]
    fn report_creation_and_finalization() {
        let mut report = ValidationReport::new("test-run", vec!["D0".to_string()]);
        assert_eq!(report.status, RunStatus::Running);

        report.record_evidence(Evidence::pass(
            "ignored", "check-1", "D0", "verification",
            serde_json::json!(true), serde_json::json!(true),
        ));
        report.record_evidence(Evidence::pass(
            "ignored", "check-2", "D0", "verification",
            serde_json::json!(true), serde_json::json!(true),
        ));

        report.finalize();
        assert_eq!(report.status, RunStatus::Passed);
        assert_eq!(report.verdicts.pass, 2);
        assert_eq!(report.verdicts.total, 2);
        assert!(report.finished_at.is_some());
    }

    #[test]
    fn report_with_failure() {
        let mut report = ValidationReport::new("fail-run", vec!["D1".to_string()]);

        report.record_evidence(Evidence::fail(
            "ignored", "sqli-check", "D1", "shield",
            Severity::Critical,
            serde_json::json!({"blocked": true}),
            serde_json::json!({"blocked": false}),
            "SQLi was not blocked",
        ));

        report.finalize();
        assert_eq!(report.status, RunStatus::Failed);
        assert_eq!(report.severities.critical, 1);
        assert_eq!(report.failures().len(), 1);
    }

    #[test]
    fn evidence_chain_integrity() {
        let mut report = ValidationReport::new("chain-test", vec!["D0".to_string()]);
        report.record_evidence(Evidence::pass(
            "ignored", "a", "D0", "x",
            serde_json::json!(1), serde_json::json!(1),
        ));
        report.record_evidence(Evidence::pass(
            "ignored", "b", "D0", "x",
            serde_json::json!(2), serde_json::json!(2),
        ));
        report.record_evidence(Evidence::pass(
            "ignored", "c", "D0", "x",
            serde_json::json!(3), serde_json::json!(3),
        ));

        let chain = report.chain_status();
        assert!(chain.intact);
        assert_eq!(chain.total_items, 3);
        assert_eq!(chain.tampered_count, 0);
        assert_eq!(chain.broken_link_count, 0);
    }

    #[test]
    fn text_summary_non_empty() {
        let mut report = ValidationReport::new("summary-test", vec!["D0".to_string()]);
        report.record_evidence(Evidence::pass(
            "ignored", "test", "D0", "v",
            serde_json::json!(true), serde_json::json!(true),
        ));
        report.finalize();
        let text = report.to_text_summary();
        assert!(text.contains("summary-test"));
        assert!(text.contains("PASSED"));
    }

    #[test]
    fn json_roundtrip() {
        let mut report = ValidationReport::new("json-test", vec!["D0".to_string()]);
        report.record_evidence(Evidence::pass(
            "ignored", "j", "D0", "k",
            serde_json::json!(true), serde_json::json!(true),
        ));
        report.finalize();

        let json = report.to_json().unwrap();
        let restored: ValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.run_id, report.run_id);
        assert_eq!(restored.evidence.len(), 1);
    }

    #[test]
    fn filter_evidence() {
        let mut report = ValidationReport::new("filter-test", vec!["D0".to_string(), "D1".to_string()]);
        report.record_evidence(Evidence::pass(
            "ignored", "a", "D0", "sub-x",
            serde_json::json!(true), serde_json::json!(true),
        ));
        report.record_evidence(Evidence::pass(
            "ignored", "b", "D1", "sub-y",
            serde_json::json!(true), serde_json::json!(true),
        ));
        report.record_evidence(Evidence::pass(
            "ignored", "c", "D1", "sub-x",
            serde_json::json!(true), serde_json::json!(true),
        ));

        assert_eq!(report.evidence_for_phase("D0").len(), 1);
        assert_eq!(report.evidence_for_phase("D1").len(), 2);
        assert_eq!(report.evidence_for_subsystem("sub-x").len(), 2);
        assert_eq!(report.evidence_for_subsystem("sub-y").len(), 1);
    }
}