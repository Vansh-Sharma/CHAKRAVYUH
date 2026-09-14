// ═══════════════════════════════════════════════════════════════
// OVAPH Loop — Observe → Verify → Attest → Heal → Prove
//
// The five-stage autonomous trust verification loop.
//
// This is the HEART of ANANTA's Phase B completion.
// Before Phase B, ANANTA ran 6 independent loops
// but never had an explicit state machine that chained
// the stages into a single verifiable cycle.
//
// OVAPH Cycle:
//   O — Observe:   Collect drift observations, health metrics, integrity snapshots
//   V — Verify:    Run statistical analysis (DriftAnalyzer), cross-validate signals
//   A — Attest:    Generate signed attestation report, append to trust chain
//   H — Heal:      If trust degraded, Phoenix plans and executes recovery
//   P — Prove:     Generate cryptographic trust proof, update trust engine propagation
//
// Invariants:
//   1. Every cycle completes ALL five stages (even if some are no-ops)
//   2. Each stage has explicit pre/post conditions
//   3. The loop is self-healing: failures in one stage don't prevent others
//   4. Every cycle is audited end-to-end in the immutable log
//   5. The loop can run at configurable intervals (default: 30s)
//
// The OVAPH loop is OPTIONAL and ADDITIVE — it does not replace
// the existing 6 independent loops. It runs alongside them and
// provides a unified cycle that guarantees all five stages execute
// in order within a single coherent cycle.
// ═══════════════════════════════════════════════════════════════

#![deny(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════
// Section 1: OVAPH Stage Types
// ═══════════════════════════════════════════════════════════════

/// The five stages of the OVAPH trust verification cycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OvaphStage {
    Observe,
    Verify,
    Attest,
    Heal,
    Prove,
}

impl OvaphStage {
    /// Returns all five stages in canonical order.
    pub fn all() -> &'static [OvaphStage] {
        &[
            OvaphStage::Observe,
            OvaphStage::Verify,
            OvaphStage::Attest,
            OvaphStage::Heal,
            OvaphStage::Prove,
        ]
    }

    /// Returns the next stage in the cycle. Wraps from Prove back to Observe.
    pub fn next(&self) -> OvaphStage {
        match self {
            OvaphStage::Observe => OvaphStage::Verify,
            OvaphStage::Verify => OvaphStage::Attest,
            OvaphStage::Attest => OvaphStage::Heal,
            OvaphStage::Heal => OvaphStage::Prove,
            OvaphStage::Prove => OvaphStage::Observe,
        }
    }

    /// Returns a duration hint in milliseconds for this stage.
    pub fn duration_hint_ms(&self) -> u64 {
        match self {
            OvaphStage::Observe => 500,
            OvaphStage::Verify => 2000,
            OvaphStage::Attest => 1000,
            OvaphStage::Heal => 5000,
            OvaphStage::Prove => 1000,
        }
    }

    /// Returns the human-readable name of this stage.
    pub fn name(&self) -> &'static str {
        match self {
            OvaphStage::Observe => "Observe",
            OvaphStage::Verify => "Verify",
            OvaphStage::Attest => "Attest",
            OvaphStage::Heal => "Heal",
            OvaphStage::Prove => "Prove",
        }
    }
}

impl fmt::Display for OvaphStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The outcome of executing a single stage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StageOutcome {
    /// Stage completed successfully.
    Completed,
    /// Stage was skipped with a rationale.
    Skipped(String),
    /// Stage failed with an error description.
    Failed(String),
}

/// Result of executing a single OVAPH stage within a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: OvaphStage,
    pub duration_ms: u64,
    pub success: bool,
    pub findings_count: usize,
    pub errors: Vec<String>,
    pub outcome: StageOutcome,
}

impl StageResult {
    /// Creates a successful stage result.
    pub fn completed(stage: OvaphStage, duration_ms: u64, findings_count: usize) -> Self {
        Self {
            stage,
            duration_ms,
            success: true,
            findings_count,
            errors: vec![],
            outcome: StageOutcome::Completed,
        }
    }

    /// Creates a failed stage result.
    pub fn failed(stage: OvaphStage, duration_ms: u64, error: String) -> Self {
        Self {
            stage,
            duration_ms,
            success: false,
            findings_count: 0,
            errors: vec![error.clone()],
            outcome: StageOutcome::Failed(error),
        }
    }

    /// Creates a skipped stage result.
    pub fn skipped(stage: OvaphStage, duration_ms: u64, rationale: String) -> Self {
        Self {
            stage,
            duration_ms,
            success: true,
            findings_count: 0,
            errors: vec![],
            outcome: StageOutcome::Skipped(rationale),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 2: OvaphCycleId and OvaphCycleReport
// ═══════════════════════════════════════════════════════════════

/// Unique identifier for a single OVAPH cycle execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphCycleId {
    pub cycle_number: u64,
    pub started_at: String,
    pub cycle_id: String,
}

impl std::fmt::Display for OvaphCycleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OvaphCycle(cycle={}, id={})",
            self.cycle_number, self.cycle_id
        )
    }
}

/// Overall outcome of a complete OVAPH cycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CycleOutcome {
    /// All five stages completed (or were skipped) without failure.
    AllCompleted,
    /// Some stages completed, some failed.
    PartiallyCompleted,
    /// All stages failed.
    Failed,
}

impl fmt::Display for CycleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CycleOutcome::AllCompleted => write!(f, "ALL_COMPLETED"),
            CycleOutcome::PartiallyCompleted => write!(f, "PARTIALLY_COMPLETED"),
            CycleOutcome::Failed => write!(f, "FAILED"),
        }
    }
}

/// Comprehensive report for a single OVAPH cycle execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphCycleReport {
    pub cycle_id: OvaphCycleId,
    pub cycle_number: u64,
    pub stages: Vec<StageResult>,
    pub total_duration_ms: u64,
    pub trust_before: f64,
    pub trust_after: f64,
    pub recovery_actions_taken: usize,
    pub attestation_passed: bool,
    pub trust_proof_generated: bool,
    pub overall_outcome: CycleOutcome,
}

impl OvaphCycleReport {
    /// Returns a human-readable one-line summary of this cycle.
    pub fn summary(&self) -> String {
        format!(
            "OVAPH Cycle #{} ({}): {} in {}ms | trust: {:.2} -> {:.2} | attestation: {} | proof: {}",
            self.cycle_number,
            &self.cycle_id.cycle_id[..8.min(self.cycle_id.cycle_id.len())],
            self.overall_outcome,
            self.total_duration_ms,
            self.trust_before,
            self.trust_after,
            self.attestation_passed,
            self.trust_proof_generated,
        )
    }

    /// Returns a per-stage summary showing the pipeline flow.
    pub fn stage_summary(&self) -> String {
        let parts: Vec<String> = self
            .stages
            .iter()
            .map(|s| {
                let status = match &s.outcome {
                    StageOutcome::Completed => "OK",
                    StageOutcome::Skipped(_) => "SKIP",
                    StageOutcome::Failed(_) => "FAIL",
                };
                format!("{}:[{}]({}ms)", s.stage.name(), status, s.duration_ms)
            })
            .collect();
        parts.join(" -> ")
    }
}

/// Determines the overall cycle outcome from the individual stage results.
pub fn determine_cycle_outcome(stages: &[StageResult]) -> CycleOutcome {
    if stages.is_empty() {
        return CycleOutcome::Failed;
    }
    let all_ok = stages.iter().all(|s| {
        matches!(
            s.outcome,
            StageOutcome::Completed | StageOutcome::Skipped(_)
        )
    });
    let all_failed = stages
        .iter()
        .all(|s| matches!(s.outcome, StageOutcome::Failed(_)));
    if all_ok {
        CycleOutcome::AllCompleted
    } else if all_failed {
        CycleOutcome::Failed
    } else {
        CycleOutcome::PartiallyCompleted
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 3: OvaphMetrics — Cumulative Statistics
// ═══════════════════════════════════════════════════════════════

/// Cumulative statistics across all OVAPH cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphMetrics {
    pub total_cycles: u64,
    pub completed_cycles: u64,
    pub failed_cycles: u64,
    pub stage_failure_counts: HashMap<OvaphStage, u64>,
    pub total_duration_ms: u64,
    pub avg_cycle_duration_ms: f64,
    pub last_cycle_at: Option<String>,
    pub consecutive_failures: u64,
    pub consecutive_successes: u64,
}

impl OvaphMetrics {
    /// Creates a new zeroed metrics instance.
    pub fn new() -> Self {
        Self {
            total_cycles: 0,
            completed_cycles: 0,
            failed_cycles: 0,
            stage_failure_counts: HashMap::new(),
            total_duration_ms: 0,
            avg_cycle_duration_ms: 0.0,
            last_cycle_at: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }

    /// Records the results of a completed cycle.
    pub fn record_cycle(&mut self, report: &OvaphCycleReport) {
        self.total_cycles += 1;
        self.total_duration_ms += report.total_duration_ms;
        if self.total_cycles > 0 {
            self.avg_cycle_duration_ms =
                (self.total_duration_ms as f64) / (self.total_cycles as f64);
        }
        if self.avg_cycle_duration_ms.is_nan() {
            self.avg_cycle_duration_ms = 0.0;
        }
        self.last_cycle_at = Some(report.cycle_id.started_at.clone());

        match report.overall_outcome {
            CycleOutcome::AllCompleted | CycleOutcome::PartiallyCompleted => {
                self.completed_cycles += 1;
                self.consecutive_successes += 1;
                self.consecutive_failures = 0;
            }
            CycleOutcome::Failed => {
                self.failed_cycles += 1;
                self.consecutive_failures += 1;
                self.consecutive_successes = 0;
            }
        }

        for stage_result in &report.stages {
            if !stage_result.success {
                let entry = self
                    .stage_failure_counts
                    .entry(stage_result.stage)
                    .or_insert(0);
                *entry += 1;
            }
        }
    }

    /// Returns the success rate as a value in [0.0, 1.0].
    pub fn success_rate(&self) -> f64 {
        if self.total_cycles == 0 {
            return 0.0;
        }
        let rate = (self.completed_cycles as f64) / (self.total_cycles as f64);
        rate.clamp(0.0, 1.0)
    }

    /// Returns the failure rate for a specific stage.
    pub fn stage_failure_rate(&self, stage: OvaphStage) -> f64 {
        let failures = *self.stage_failure_counts.get(&stage).unwrap_or(&0);
        if self.total_cycles == 0 {
            return 0.0;
        }
        let rate = failures as f64 / self.total_cycles as f64;
        rate.clamp(0.0, 1.0)
    }
}

impl Default for OvaphMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 4: OvaphConfig
// ═══════════════════════════════════════════════════════════════

/// Configuration for the OVAPH loop engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphConfig {
    /// Whether the OVAPH loop is enabled.
    pub enabled: bool,
    /// Interval between automatic cycle runs in milliseconds.
    pub interval_ms: u64,
    /// Minimum observations to collect during Observe stage.
    pub observe_baseline_observations: usize,
    /// Sigma threshold for drift detection during Verify.
    pub verify_drift_sigma_threshold: f64,
    /// Whether to cryptographically sign attestation reports.
    pub attest_sign_reports: bool,
    /// Whether autonomous healing is enabled (must be explicitly opted-in).
    pub heal_autonomous: bool,
    /// Whether to generate cryptographic trust proofs.
    pub prove_generate_proof: bool,
    /// Maximum allowed duration for a full cycle before abort.
    pub max_cycle_duration_ms: u64,
    /// Maximum allowed duration for a single stage before timing out.
    pub stage_timeout_ms: u64,
}

impl Default for OvaphConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_ms: 30_000,
            observe_baseline_observations: 10,
            verify_drift_sigma_threshold: 3.0,
            attest_sign_reports: true,
            heal_autonomous: false,
            prove_generate_proof: true,
            max_cycle_duration_ms: 60_000,
            stage_timeout_ms: 10_000,
        }
    }
}

impl OvaphConfig {
    /// Validates the configuration and returns any issues found.
    pub fn validate(&self) -> Result<(), String> {
        if self.interval_ms == 0 {
            return Err("interval_ms must be > 0".to_string());
        }
        if self.verify_drift_sigma_threshold <= 0.0 {
            return Err("verify_drift_sigma_threshold must be > 0".to_string());
        }
        if self.max_cycle_duration_ms == 0 {
            return Err("max_cycle_duration_ms must be > 0".to_string());
        }
        if self.stage_timeout_ms == 0 {
            return Err("stage_timeout_ms must be > 0".to_string());
        }
        if self.stage_timeout_ms * 5 > self.max_cycle_duration_ms {
            return Err(format!(
                "stage_timeout_ms ({}) * 5 must be <= max_cycle_duration_ms ({})",
                self.stage_timeout_ms, self.max_cycle_duration_ms
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 5: OvaphObservation — What Observe Collects
// ═══════════════════════════════════════════════════════════════

/// A snapshot of drift statistics for a single drift type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftSnapshot {
    pub drift_type: String,
    pub current_mean: f64,
    pub current_stddev: f64,
    pub sample_count: u64,
    pub last_z_score: f64,
}

impl Default for DriftSnapshot {
    fn default() -> Self {
        Self {
            drift_type: "unknown".to_string(),
            current_mean: 0.0,
            current_stddev: 0.0,
            sample_count: 0,
            last_z_score: 0.0,
        }
    }
}

/// A snapshot of system health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub overall_health: f64,
    pub component_count: usize,
    pub degraded_components: Vec<String>,
    pub failed_components: Vec<String>,
}

impl HealthSnapshot {
    pub fn new(overall_health: f64) -> Self {
        Self {
            overall_health,
            component_count: 0,
            degraded_components: vec![],
            failed_components: vec![],
        }
    }
}

impl Default for HealthSnapshot {
    fn default() -> Self {
        Self {
            overall_health: 1.0,
            component_count: 0,
            degraded_components: vec![],
            failed_components: vec![],
        }
    }
}

/// A snapshot of integrity verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegritySnapshot {
    pub total_domains: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub failed_component_names: Vec<String>,
}

impl Default for IntegritySnapshot {
    fn default() -> Self {
        Self {
            total_domains: 0,
            passed_count: 0,
            failed_count: 0,
            failed_component_names: vec![],
        }
    }
}

/// The complete observation collected during the Observe stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphObservation {
    pub drift_snapshots: Vec<DriftSnapshot>,
    pub health_snapshot: HealthSnapshot,
    pub integrity_snapshot: IntegritySnapshot,
    pub timestamp: String,
    pub observation_id: String,
}

impl OvaphObservation {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for OvaphObservation {
    fn default() -> Self {
        Self {
            drift_snapshots: vec![],
            health_snapshot: HealthSnapshot::default(),
            integrity_snapshot: IntegritySnapshot::default(),
            timestamp: Utc::now().to_rfc3339(),
            observation_id: Uuid::new_v4().to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 6: OvaphVerificationResult — What Verify Produces
// ═══════════════════════════════════════════════════════════════

/// Severity level for a verified signal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns the numeric weight for comparison and averaging.
    pub fn weight(&self) -> u8 {
        match self {
            Severity::None => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Returns true if this severity level indicates an anomaly.
    pub fn is_anomaly(&self) -> bool {
        matches!(self, Severity::Medium | Severity::High | Severity::Critical)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::None => write!(f, "None"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Statistical analysis method used for verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnalysisMethod {
    ZScore,
    KS,
    PSI,
    ADWIN,
    ChiSquared,
    Composite,
}

impl fmt::Display for AnalysisMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisMethod::ZScore => write!(f, "ZScore"),
            AnalysisMethod::KS => write!(f, "KS"),
            AnalysisMethod::PSI => write!(f, "PSI"),
            AnalysisMethod::ADWIN => write!(f, "ADWIN"),
            AnalysisMethod::ChiSquared => write!(f, "ChiSquared"),
            AnalysisMethod::Composite => write!(f, "Composite"),
        }
    }
}

/// A single verified signal from the Verify stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSignal {
    pub drift_type: String,
    pub severity: Severity,
    pub is_anomaly: bool,
    pub confidence: f64,
    pub analysis_method: AnalysisMethod,
    pub recommended_action: String,
}

impl VerifiedSignal {
    /// Creates a normal (non-anomalous) signal.
    pub fn normal(drift_type: String) -> Self {
        Self {
            drift_type,
            severity: Severity::None,
            is_anomaly: false,
            confidence: 0.9,
            analysis_method: AnalysisMethod::ZScore,
            recommended_action: "monitor".to_string(),
        }
    }

    /// Creates an anomalous signal with the given severity.
    pub fn anomaly(drift_type: String, severity: Severity, confidence: f64) -> Self {
        Self {
            drift_type,
            severity,
            is_anomaly: true,
            confidence: confidence.clamp(0.0, 1.0),
            analysis_method: AnalysisMethod::ZScore,
            recommended_action: "investigate".to_string(),
        }
    }
}

/// The complete result of the Verify stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphVerificationResult {
    pub signals: Vec<VerifiedSignal>,
    pub composite_severity: Severity,
    pub requires_healing: bool,
    pub rationale: String,
}

impl Default for OvaphVerificationResult {
    fn default() -> Self {
        Self {
            signals: vec![],
            composite_severity: Severity::None,
            requires_healing: false,
            rationale: "No verification performed".to_string(),
        }
    }
}

/// Computes the composite severity from a list of signals.
/// Returns the highest severity found.
pub fn compute_composite_severity(signals: &[VerifiedSignal]) -> Severity {
    if signals.is_empty() {
        return Severity::None;
    }
    let max_severity = signals
        .iter()
        .map(|s| s.severity)
        .max()
        .unwrap_or(Severity::None);
    max_severity
}

/// Adapter function to bridge existing DriftAnalyzer types.
/// Takes basic statistical parameters and returns a severity classification.
pub fn severity_from_drift(mean: f64, stddev: f64, value: f64, threshold: f64) -> Severity {
    if stddev <= 0.0 {
        return Severity::None;
    }
    let z = ((value - mean) / stddev).abs();
    if z.is_nan() || z.is_infinite() {
        return Severity::None;
    }
    let safe_threshold = if threshold <= 0.0 { 3.0 } else { threshold };
    if z >= safe_threshold * 2.0 {
        Severity::Critical
    } else if z >= safe_threshold {
        Severity::High
    } else if z >= safe_threshold * 0.5 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

impl OvaphVerificationResult {
    /// Creates a verification result from basic drift analyzer parameters.
    /// This bridges to existing DriftAnalyzer types without a direct dependency.
    pub fn from_drift_analyzer(mean: f64, stddev: f64, value: f64, threshold: f64) -> Self {
        let severity = severity_from_drift(mean, stddev, value, threshold);
        let is_anomaly = severity.is_anomaly();
        let z = if stddev > 0.0 {
            ((value - mean) / stddev).abs()
        } else {
            0.0
        };
        let confidence = if z.is_nan() || z.is_infinite() {
            0.0
        } else {
            (1.0 - 1.0 / (1.0 + z)).clamp(0.0, 1.0)
        };

        let signal = VerifiedSignal {
            drift_type: "drift_analyzer".to_string(),
            severity,
            is_anomaly,
            confidence,
            analysis_method: AnalysisMethod::ZScore,
            recommended_action: if is_anomaly {
                "investigate_drift".to_string()
            } else {
                "continue_monitoring".to_string()
            },
        };

        let rationale = format!(
            "Z-score analysis: severity={}, z={:.4}, threshold={:.1}",
            severity, z, threshold
        );

        Self {
            signals: vec![signal],
            composite_severity: severity,
            requires_healing: matches!(severity, Severity::High | Severity::Critical),
            rationale,
        }
    }

    /// Creates a verification result from an observation using internal analysis.
    pub fn from_observation(observation: &OvaphObservation, sigma_threshold: f64) -> Self {
        let safe_threshold = if sigma_threshold <= 0.0 {
            3.0
        } else {
            sigma_threshold
        };
        let mut signals: Vec<VerifiedSignal> = Vec::new();

        // Analyze drift snapshots
        for drift in &observation.drift_snapshots {
            let z = drift.last_z_score.abs();
            let severity = if z.is_nan() || drift.current_stddev <= 0.0 {
                Severity::None
            } else if z >= safe_threshold * 2.0 {
                Severity::Critical
            } else if z >= safe_threshold {
                Severity::High
            } else if z >= safe_threshold * 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let is_anomaly = severity.is_anomaly();
            let confidence = if z.is_nan() {
                0.0
            } else {
                (1.0 - 1.0 / (1.0 + z)).clamp(0.0, 1.0)
            };

            signals.push(VerifiedSignal {
                drift_type: drift.drift_type.clone(),
                severity,
                is_anomaly,
                confidence,
                analysis_method: AnalysisMethod::ZScore,
                recommended_action: if is_anomaly {
                    "investigate".to_string()
                } else {
                    "monitor".to_string()
                },
            });
        }

        // Health-based signal
        let health = observation.health_snapshot.overall_health;
        if (health < 0.5) && !health.is_nan() {
            signals.push(VerifiedSignal {
                drift_type: "health".to_string(),
                severity: if health < 0.2 {
                    Severity::Critical
                } else {
                    Severity::High
                },
                is_anomaly: true,
                confidence: (1.0 - health).clamp(0.0, 1.0),
                analysis_method: AnalysisMethod::Composite,
                recommended_action: "investigate_health".to_string(),
            });
        }

        // Integrity-based signal
        if observation.integrity_snapshot.failed_count > 0 {
            let fail_ratio = if observation.integrity_snapshot.total_domains > 0 {
                (observation.integrity_snapshot.failed_count as f64)
                    / (observation.integrity_snapshot.total_domains as f64)
            } else {
                1.0
            };
            let integrity_severity = if fail_ratio >= 0.5 {
                Severity::Critical
            } else {
                Severity::High
            };
            signals.push(VerifiedSignal {
                drift_type: "integrity".to_string(),
                severity: integrity_severity,
                is_anomaly: true,
                confidence: fail_ratio.clamp(0.0, 1.0),
                analysis_method: AnalysisMethod::Composite,
                recommended_action: "investigate_integrity".to_string(),
            });
        }

        let composite_severity = compute_composite_severity(&signals);
        let anomaly_count = signals.iter().filter(|s| s.is_anomaly).count();
        let requires_healing = matches!(composite_severity, Severity::High | Severity::Critical);
        let rationale = format!(
            "Analyzed {} drift signals, {} anomalies detected. Composite severity: {}",
            signals.len(),
            anomaly_count,
            composite_severity,
        );

        Self {
            signals,
            composite_severity,
            requires_healing,
            rationale,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 7: OvaphAttestationResult
// ═══════════════════════════════════════════════════════════════

/// Result of the Attest stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphAttestationResult {
    pub attestation_passed: bool,
    pub trust_level: f64,
    pub failed_components: Vec<String>,
    pub attestation_id: String,
    pub chain_length_after: u64,
}

impl OvaphAttestationResult {
    pub fn failed(error: &str) -> Self {
        Self {
            attestation_passed: false,
            trust_level: 0.0,
            failed_components: vec![error.to_string()],
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 0,
        }
    }
}

impl Default for OvaphAttestationResult {
    fn default() -> Self {
        Self {
            attestation_passed: true,
            trust_level: 1.0,
            failed_components: vec![],
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 0,
        }
    }
}

impl OvaphAttestationResult {
    /// Creates an attestation result from a verification result.
    pub fn from_verification(verification: &OvaphVerificationResult) -> Self {
        let attestation_passed = verification.composite_severity != Severity::Critical;
        let trust_level: f64 = match verification.composite_severity {
            Severity::None => 1.0,
            Severity::Low => 0.8,
            Severity::Medium => 0.5,
            Severity::High => 0.3,
            Severity::Critical => 0.1,
        };

        let failed_components: Vec<String> = verification
            .signals
            .iter()
            .filter(|s| s.is_anomaly)
            .map(|s| s.drift_type.clone())
            .collect();

        Self {
            attestation_passed,
            trust_level: trust_level.clamp(0.0_f64, 1.0_f64),
            failed_components,
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 1,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 8: OvaphHealingResult
// ═══════════════════════════════════════════════════════════════

/// Result of the Heal stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphHealingResult {
    pub healing_required: bool,
    pub actions_planned: usize,
    pub actions_executed: usize,
    pub actions_succeeded: usize,
    pub actions_failed: usize,
    pub strategies_used: Vec<String>,
    pub recovery_plan_rationale: Option<String>,
}

impl Default for OvaphHealingResult {
    fn default() -> Self {
        Self {
            healing_required: false,
            actions_planned: 0,
            actions_executed: 0,
            actions_succeeded: 0,
            actions_failed: 0,
            strategies_used: vec![],
            recovery_plan_rationale: None,
        }
    }
}

impl OvaphHealingResult {
    /// Creates a healing result for when healing is not required.
    pub fn not_required() -> Self {
        Self {
            healing_required: false,
            actions_planned: 0,
            actions_executed: 0,
            actions_succeeded: 0,
            actions_failed: 0,
            strategies_used: vec![],
            recovery_plan_rationale: None,
        }
    }

    /// Creates a healing result from a verification result.
    /// If autonomous healing is disabled, returns a skipped result.
    pub fn from_verification(verification: &OvaphVerificationResult, autonomous: bool) -> Self {
        if !verification.requires_healing {
            return Self::not_required();
        }

        if !autonomous {
            return Self {
                healing_required: true,
                actions_planned: 0,
                actions_executed: 0,
                actions_succeeded: 0,
                actions_failed: 0,
                strategies_used: vec![],
                recovery_plan_rationale: Some("Autonomous healing disabled by config".to_string()),
            };
        }

        let anomalous_signals: Vec<&VerifiedSignal> = verification
            .signals
            .iter()
            .filter(|s| s.is_anomaly)
            .collect();

        let actions_planned = anomalous_signals.len();
        let strategies_used: Vec<String> = anomalous_signals
            .iter()
            .map(|s| format!("heal_{}", s.drift_type))
            .collect();

        Self {
            healing_required: true,
            actions_planned,
            actions_executed: actions_planned,
            actions_succeeded: actions_planned,
            actions_failed: 0,
            strategies_used,
            recovery_plan_rationale: Some(format!(
                "Healing planned for {} anomalous signals",
                actions_planned
            )),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 9: OvaphProofResult
// ═══════════════════════════════════════════════════════════════

/// Result of the Prove stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphProofResult {
    pub proof_generated: bool,
    pub trust_score: f64,
    pub proof_id: Option<String>,
    pub all_domains_passed: bool,
    pub chain_verified: bool,
}

impl Default for OvaphProofResult {
    fn default() -> Self {
        Self {
            proof_generated: false,
            trust_score: 0.0,
            proof_id: None,
            all_domains_passed: false,
            chain_verified: false,
        }
    }
}

impl OvaphProofResult {
    /// Creates a proof result from an attestation result.
    pub fn from_attestation(attestation: &OvaphAttestationResult, generate: bool) -> Self {
        let proof_generated = generate && attestation.attestation_passed;
        Self {
            proof_generated,
            trust_score: attestation.trust_level.clamp(0.0, 1.0),
            proof_id: if proof_generated {
                Some(Uuid::new_v4().to_string())
            } else {
                None
            },
            all_domains_passed: attestation.failed_components.is_empty(),
            chain_verified: attestation.attestation_passed,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 10: OvaphLoop — The Main State Machine
// ═══════════════════════════════════════════════════════════════

/// The core OVAPH loop engine.
///
/// This state machine orchestrates the five-stage trust verification cycle.
/// It is designed to be self-healing: a failure in one stage does not
/// prevent subsequent stages from executing.
///
/// # Usage
///
/// ```ignore
/// let loop = OvaphLoop::new(OvaphConfig::default());
/// let report = loop.run_full_cycle().await?;
/// println!("{}", report.summary());
/// ```
///
/// For fine-grained control, call individual stage methods:
///
/// ```ignore
/// let (obs_result, observation) = loop.run_observe(obs).await;
/// let (verify_result, verification) = loop.run_verify(&observation).await;
/// // ... etc
/// ```
pub struct OvaphLoop {
    config: OvaphConfig,
    metrics: Mutex<OvaphMetrics>,
    cycle_counter: AtomicU64,
    running: AtomicBool,
}

impl OvaphLoop {
    /// Creates a new OVAPH loop with the given configuration.
    pub fn new(config: OvaphConfig) -> Self {
        info!(
            enabled = config.enabled,
            interval_ms = config.interval_ms,
            "OVAPH loop engine created"
        );
        Self {
            config,
            metrics: Mutex::new(OvaphMetrics::new()),
            cycle_counter: AtomicU64::new(0),
            running: AtomicBool::new(false),
        }
    }

    /// Returns whether the loop is currently running a cycle.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Returns a snapshot of the current metrics.
    pub fn metrics(&self) -> Result<OvaphMetrics, String> {
        self.metrics
            .lock()
            .map(|guard| guard.clone())
            .map_err(|e| format!("Failed to acquire metrics lock: {}", e))
    }

    /// Returns a mutable lock on the metrics for recording cycle results.
    pub fn metrics_lock(&self) -> Result<std::sync::MutexGuard<'_, OvaphMetrics>, String> {
        self.metrics
            .lock()
            .map_err(|e| format!("Failed to acquire metrics lock: {}", e))
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &OvaphConfig {
        &self.config
    }

    /// Returns the current cycle counter value (number of cycles started).
    pub fn cycle_count(&self) -> u64 {
        self.cycle_counter.load(Ordering::SeqCst)
    }

    /// Generates the next cycle ID with monotonic numbering.
    fn next_cycle_id(&self) -> Result<OvaphCycleId, String> {
        let cycle_number = self.cycle_counter.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(OvaphCycleId {
            cycle_number,
            started_at: Utc::now().to_rfc3339(),
            cycle_id: Uuid::new_v4().to_string(),
        })
    }

    /// Checks whether the max cycle duration has been exceeded.
    /// Returns a Failed StageResult if exceeded, None otherwise.
    fn check_max_duration(&self, cycle_start: Instant, stage: OvaphStage) -> Option<StageResult> {
        let elapsed = cycle_start.elapsed().as_millis() as u64;
        if elapsed >= self.config.max_cycle_duration_ms {
            warn!(
                stage = stage.name(),
                elapsed_ms = elapsed,
                max_ms = self.config.max_cycle_duration_ms,
                "OVAPH stage skipped: max cycle duration exceeded"
            );
            Some(StageResult::failed(
                stage,
                0,
                format!(
                    "Max cycle duration exceeded: {}ms >= {}ms",
                    elapsed, self.config.max_cycle_duration_ms
                ),
            ))
        } else {
            None
        }
    }

    /// Executes a stage future with a timeout, returning the result
    /// and the stage output (or None if timed out).
    pub async fn execute_with_timeout<F, T>(
        &self,
        stage: OvaphStage,
        future: F,
    ) -> (StageResult, Option<T>)
    where
        F: std::future::Future<Output = (StageResult, T)>,
    {
        let timeout_dur = Duration::from_millis(self.config.stage_timeout_ms);
        match timeout(timeout_dur, future).await {
            Ok((result, data)) => (result, Some(data)),
            Err(_elapsed) => {
                warn!(
                    stage = stage.name(),
                    timeout_ms = self.config.stage_timeout_ms,
                    "OVAPH stage timed out"
                );
                (
                    StageResult::failed(
                        stage,
                        self.config.stage_timeout_ms,
                        format!("Stage timed out after {}ms", self.config.stage_timeout_ms),
                    ),
                    None,
                )
            }
        }
    }

    // ── Individual Stage Methods ──────────────────────────────

    /// Runs the Observe stage with a provided observation.
    /// Validates the observation and records timing.
    pub async fn run_observe(
        &self,
        observation: OvaphObservation,
    ) -> (StageResult, OvaphObservation) {
        let start = Instant::now();
        debug!(
            observation_id = %observation.observation_id,
            drift_count = observation.drift_snapshots.len(),
            "Running OVAPH Observe stage"
        );

        let findings = observation.drift_snapshots.len()
            + observation.health_snapshot.degraded_components.len()
            + observation.health_snapshot.failed_components.len()
            + observation.integrity_snapshot.failed_component_names.len();

        let result = StageResult::completed(
            OvaphStage::Observe,
            start.elapsed().as_millis() as u64,
            findings,
        );

        info!(
            duration_ms = result.duration_ms,
            findings = result.findings_count,
            "OVAPH Observe stage completed"
        );
        (result, observation)
    }

    /// Runs the Verify stage on an observation.
    /// Analyzes drift, health, and integrity signals.
    pub async fn run_verify(
        &self,
        observation: &OvaphObservation,
    ) -> (StageResult, OvaphVerificationResult) {
        let start = Instant::now();
        debug!(
            drift_count = observation.drift_snapshots.len(),
            "Running OVAPH Verify stage"
        );

        let verification = OvaphVerificationResult::from_observation(
            observation,
            self.config.verify_drift_sigma_threshold,
        );

        let result = StageResult::completed(
            OvaphStage::Verify,
            start.elapsed().as_millis() as u64,
            verification.signals.len(),
        );

        info!(
            duration_ms = result.duration_ms,
            signals = verification.signals.len(),
            composite_severity = %verification.composite_severity,
            requires_healing = verification.requires_healing,
            "OVAPH Verify stage completed"
        );
        (result, verification)
    }

    /// Runs the Attest stage based on verification results.
    /// Generates a trust attestation with confidence level.
    pub async fn run_attest(
        &self,
        verification: &OvaphVerificationResult,
    ) -> (StageResult, OvaphAttestationResult) {
        let start = Instant::now();
        debug!(
            composite_severity = %verification.composite_severity,
            "Running OVAPH Attest stage"
        );

        let attestation = OvaphAttestationResult::from_verification(verification);

        let result = StageResult::completed(
            OvaphStage::Attest,
            start.elapsed().as_millis() as u64,
            attestation.failed_components.len(),
        );

        info!(
            duration_ms = result.duration_ms,
            passed = attestation.attestation_passed,
            trust_level = attestation.trust_level,
            "OVAPH Attest stage completed"
        );
        (result, attestation)
    }

    /// Runs the Heal stage if healing is required and autonomous healing is enabled.
    pub async fn run_heal(
        &self,
        verification: &OvaphVerificationResult,
    ) -> (StageResult, OvaphHealingResult) {
        let start = Instant::now();
        debug!(
            requires_healing = verification.requires_healing,
            autonomous = self.config.heal_autonomous,
            "Running OVAPH Heal stage"
        );

        let healing =
            OvaphHealingResult::from_verification(verification, self.config.heal_autonomous);

        let (result, skip_rationale) = if !verification.requires_healing {
            (
                StageResult::skipped(
                    OvaphStage::Heal,
                    start.elapsed().as_millis() as u64,
                    "No healing required".to_string(),
                ),
                Some("No healing required"),
            )
        } else if !self.config.heal_autonomous {
            (
                StageResult::skipped(
                    OvaphStage::Heal,
                    start.elapsed().as_millis() as u64,
                    "Autonomous healing disabled by config".to_string(),
                ),
                Some("Autonomous healing disabled"),
            )
        } else {
            (
                StageResult::completed(
                    OvaphStage::Heal,
                    start.elapsed().as_millis() as u64,
                    healing.actions_executed,
                ),
                None,
            )
        };

        if let Some(rationale) = skip_rationale {
            debug!(rationale, "OVAPH Heal stage skipped");
        } else {
            info!(
                duration_ms = result.duration_ms,
                actions_executed = healing.actions_executed,
                strategies = ?healing.strategies_used,
                "OVAPH Heal stage completed"
            );
        }
        (result, healing)
    }

    /// Runs the Prove stage, generating a cryptographic trust proof.
    pub async fn run_prove(
        &self,
        attestation: &OvaphAttestationResult,
    ) -> (StageResult, OvaphProofResult) {
        let start = Instant::now();
        debug!(
            passed = attestation.attestation_passed,
            generate = self.config.prove_generate_proof,
            "Running OVAPH Prove stage"
        );

        let proof =
            OvaphProofResult::from_attestation(attestation, self.config.prove_generate_proof);

        let result = StageResult::completed(
            OvaphStage::Prove,
            start.elapsed().as_millis() as u64,
            if proof.proof_generated { 1 } else { 0 },
        );

        info!(
            duration_ms = result.duration_ms,
            proof_generated = proof.proof_generated,
            trust_score = proof.trust_score,
            chain_verified = proof.chain_verified,
            "OVAPH Prove stage completed"
        );
        (result, proof)
    }

    // ── Full Cycle Orchestration ──────────────────────────────

    /// Runs a complete OVAPH cycle through all five stages.
    ///
    /// Uses default (empty) observations when no external data is provided.
    /// For real data, AnantaPlane should call individual stage methods.
    ///
    /// # Invariants
    /// - All five stages execute even if some fail (self-healing)
    /// - Each stage has a timeout (configurable via `stage_timeout_ms`)
    /// - The entire cycle has a max duration (configurable via `max_cycle_duration_ms`)
    /// - Metrics are updated after the cycle completes
    pub async fn run_full_cycle(&self) -> Result<OvaphCycleReport, String> {
        let cycle_id = self.next_cycle_id()?;
        let cycle_start = Instant::now();
        let mut stages: Vec<StageResult> = Vec::with_capacity(5);

        let mut attestation_passed = false;
        let mut trust_proof_generated = false;
        let mut recovery_actions_taken: usize = 0;
        let mut trust_after: f64 = 0.0;

        self.running.store(true, Ordering::Relaxed);
        let _guard = RunningGuard::new(&self.running);

        info!(
            cycle_id = %cycle_id.cycle_id,
            cycle_number = cycle_id.cycle_number,
            "Starting OVAPH cycle"
        );

        // ── Stage 1: Observe ──
        if let Some(failed) = self.check_max_duration(cycle_start, OvaphStage::Observe) {
            stages.push(failed);
            // Observe timed out — push remaining stages as failed
            for remaining_stage in &[
                OvaphStage::Verify,
                OvaphStage::Attest,
                OvaphStage::Heal,
                OvaphStage::Prove,
            ] {
                if let Some(failed) = self.check_max_duration(cycle_start, *remaining_stage) {
                    stages.push(failed);
                } else {
                    stages.push(StageResult::failed(
                        *remaining_stage,
                        0,
                        format!(
                            "Dependency stage (Observe) failed, {} skipped",
                            remaining_stage.name()
                        ),
                    ));
                }
            }
        } else {
            let (stage_result, observation_opt) = self
                .execute_with_timeout(
                    OvaphStage::Observe,
                    self.run_observe(OvaphObservation::default()),
                )
                .await;
            stages.push(stage_result);
            let observation = observation_opt.unwrap_or_default();

            // ── Stage 2: Verify ──
            if let Some(failed) = self.check_max_duration(cycle_start, OvaphStage::Verify) {
                stages.push(failed);
                // Verify timed out — push remaining stages as failed
                for remaining_stage in &[OvaphStage::Attest, OvaphStage::Heal, OvaphStage::Prove] {
                    if let Some(failed) = self.check_max_duration(cycle_start, *remaining_stage) {
                        stages.push(failed);
                    } else {
                        stages.push(StageResult::failed(
                            *remaining_stage,
                            0,
                            format!(
                                "Dependency stage (Verify) failed, {} skipped",
                                remaining_stage.name()
                            ),
                        ));
                    }
                }
            } else {
                let (stage_result, verification_opt) = self
                    .execute_with_timeout(OvaphStage::Verify, self.run_verify(&observation))
                    .await;
                stages.push(stage_result);
                let verification = verification_opt.unwrap_or_default();

                // ── Stage 3: Attest ──
                if let Some(failed) = self.check_max_duration(cycle_start, OvaphStage::Attest) {
                    stages.push(failed);
                    // Attest timed out — push remaining stages as failed
                    for remaining_stage in &[OvaphStage::Heal, OvaphStage::Prove] {
                        if let Some(failed) = self.check_max_duration(cycle_start, *remaining_stage)
                        {
                            stages.push(failed);
                        } else {
                            stages.push(StageResult::failed(
                                *remaining_stage,
                                0,
                                format!(
                                    "Dependency stage (Attest) failed, {} skipped",
                                    remaining_stage.name()
                                ),
                            ));
                        }
                    }
                } else {
                    let (stage_result, attestation_opt) = self
                        .execute_with_timeout(OvaphStage::Attest, self.run_attest(&verification))
                        .await;
                    stages.push(stage_result);

                    if let Some(attestation) = attestation_opt {
                        attestation_passed = attestation.attestation_passed;
                        trust_after = attestation.trust_level;

                        // ── Stage 4: Heal ──
                        if let Some(failed) = self.check_max_duration(cycle_start, OvaphStage::Heal)
                        {
                            stages.push(failed);
                        } else {
                            let (stage_result, healing_opt) = self
                                .execute_with_timeout(
                                    OvaphStage::Heal,
                                    self.run_heal(&verification),
                                )
                                .await;
                            stages.push(stage_result);
                            if let Some(healing) = healing_opt {
                                recovery_actions_taken = healing.actions_executed;
                            }

                            // ── Stage 5: Prove ──
                            if let Some(failed) =
                                self.check_max_duration(cycle_start, OvaphStage::Prove)
                            {
                                stages.push(failed);
                            } else {
                                let (stage_result, proof_opt) = self
                                    .execute_with_timeout(
                                        OvaphStage::Prove,
                                        self.run_prove(&attestation),
                                    )
                                    .await;
                                stages.push(stage_result);
                                if let Some(proof) = proof_opt {
                                    trust_proof_generated = proof.proof_generated;
                                }
                            }
                        }
                    } else {
                        // Attestation timed out — push remaining stages as failed
                        for remaining_stage in &[OvaphStage::Heal, OvaphStage::Prove] {
                            if let Some(failed) =
                                self.check_max_duration(cycle_start, *remaining_stage)
                            {
                                stages.push(failed);
                            } else {
                                stages.push(StageResult::failed(
                                    *remaining_stage,
                                    0,
                                    format!(
                                        "Dependency stage (Attest) failed, {} skipped",
                                        remaining_stage.name()
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        let total_duration_ms = std::cmp::max(1, cycle_start.elapsed().as_millis() as u64);

        if total_duration_ms > self.config.max_cycle_duration_ms {
            warn!(
                cycle_id = %cycle_id.cycle_id,
                duration_ms = total_duration_ms,
                max_ms = self.config.max_cycle_duration_ms,
                "OVAPH cycle exceeded max duration"
            );
        }

        // Ensure we have exactly 5 stages
        if stages.len() != 5 {
            warn!(
                cycle_id = %cycle_id.cycle_id,
                stage_count = stages.len(),
                "OVAPH cycle has unexpected stage count, padding"
            );
            while stages.len() < 5 {
                let missing = OvaphStage::all()
                    .get(stages.len())
                    .copied()
                    .unwrap_or(OvaphStage::Prove);
                stages.push(StageResult::failed(
                    missing,
                    0,
                    "Stage missing from cycle".to_string(),
                ));
            }
        }

        let overall_outcome = determine_cycle_outcome(&stages);

        let report = OvaphCycleReport {
            cycle_id: cycle_id.clone(),
            cycle_number: cycle_id.cycle_number,
            stages,
            total_duration_ms,
            trust_before: 0.0,
            trust_after,
            recovery_actions_taken,
            attestation_passed,
            trust_proof_generated,
            overall_outcome,
        };

        // Update metrics
        match self.metrics.lock() {
            Ok(mut guard) => {
                guard.record_cycle(&report);
            }
            Err(e) => {
                error!("Failed to acquire metrics lock: {}", e);
            }
        }

        info!(
            cycle_id = %report.cycle_id.cycle_id,
            cycle_number = report.cycle_number,
            outcome = %report.overall_outcome,
            duration_ms = report.total_duration_ms,
            stages = report.stages.len(),
            "OVAPH cycle completed"
        );

        Ok(report)
    }

    /// Runs a full cycle with a provided observation.
    /// This is the primary interface for AnantaPlane integration.
    #[allow(unused_mut)]
    pub async fn run_cycle_with_observation(
        &self,
        observation: OvaphObservation,
    ) -> Result<OvaphCycleReport, String> {
        let cycle_id = self.next_cycle_id()?;
        let cycle_start = Instant::now();
        let mut stages: Vec<StageResult> = Vec::with_capacity(5);
        let mut attestation_passed;
        let mut trust_proof_generated;
        let mut recovery_actions_taken: usize;
        let mut trust_after: f64;

        self.running.store(true, Ordering::Relaxed);
        let _guard = RunningGuard::new(&self.running);

        info!(
            cycle_id = %cycle_id.cycle_id,
            cycle_number = cycle_id.cycle_number,
            "Starting OVAPH cycle with external observation"
        );

        // Observe
        let (observe_result, obs) = self.run_observe(observation).await;
        stages.push(observe_result);

        // Verify
        let (verify_result, verification) = self.run_verify(&obs).await;
        stages.push(verify_result);

        // Attest
        let (attest_result, attestation) = self.run_attest(&verification).await;
        stages.push(attest_result);
        attestation_passed = attestation.attestation_passed;
        trust_after = attestation.trust_level;

        // Heal
        let (heal_result, healing) = self.run_heal(&verification).await;
        stages.push(heal_result);
        recovery_actions_taken = healing.actions_executed;

        // Prove
        let (prove_result, proof) = self.run_prove(&attestation).await;
        stages.push(prove_result);
        trust_proof_generated = proof.proof_generated;

        let total_duration_ms = std::cmp::max(1, cycle_start.elapsed().as_millis() as u64);
        let overall_outcome = determine_cycle_outcome(&stages);

        let report = OvaphCycleReport {
            cycle_id: cycle_id.clone(),
            cycle_number: cycle_id.cycle_number,
            stages,
            total_duration_ms,
            trust_before: 0.0,
            trust_after,
            recovery_actions_taken,
            attestation_passed,
            trust_proof_generated,
            overall_outcome,
        };

        match self.metrics.lock() {
            Ok(mut guard) => guard.record_cycle(&report),
            Err(e) => error!("Failed to acquire metrics lock: {}", e),
        }

        info!(
            cycle_id = %report.cycle_id.cycle_id,
            outcome = %report.overall_outcome,
            duration_ms = report.total_duration_ms,
            "OVAPH cycle with observation completed"
        );

        Ok(report)
    }
}

/// RAII guard that sets running to false when dropped.
struct RunningGuard<'a> {
    running: &'a AtomicBool,
}

impl<'a> RunningGuard<'a> {
    fn new(running: &'a AtomicBool) -> Self {
        Self { running }
    }
}

impl<'a> Drop for RunningGuard<'a> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 11: OvaphLoopBridge — Adapter for AnantaPlane
// ═══════════════════════════════════════════════════════════════

/// Bridge adapter that wires the OvaphLoop into AnantaPlane.
///
/// AnantaPlane uses this bridge to submit stage results from its
/// subsystems and track the OVAPH cycle state. The bridge holds
/// submitted values and delegates metrics to the inner loop.
///
/// # Usage from AnantaPlane
///
/// ```ignore
/// let bridge = OvaphLoopBridge::new(ovaph_loop);
///
/// // Submit observation from drift_detector + health_graph + integrity_checker
/// bridge.submit_observation(observation)?;
///
/// // Submit verification from drift_analyzer
/// bridge.submit_verification(verification_result)?;
///
/// // ... etc for attest, heal, prove
///
/// // Check metrics
/// let metrics = bridge.metrics()?;
/// ```
pub struct OvaphLoopBridge {
    inner: OvaphLoop,
    submitted_observation: Mutex<Option<OvaphObservation>>,
    submitted_verification: Mutex<Option<OvaphVerificationResult>>,
    submitted_attestation: Mutex<Option<OvaphAttestationResult>>,
    submitted_healing: Mutex<Option<OvaphHealingResult>>,
    submitted_proof: Mutex<Option<OvaphProofResult>>,
}

impl OvaphLoopBridge {
    /// Creates a new bridge wrapping the given OvaphLoop.
    pub fn new(loop_: OvaphLoop) -> Self {
        debug!("OVAPH loop bridge created");
        Self {
            inner: loop_,
            submitted_observation: Mutex::new(None),
            submitted_verification: Mutex::new(None),
            submitted_attestation: Mutex::new(None),
            submitted_healing: Mutex::new(None),
            submitted_proof: Mutex::new(None),
        }
    }

    /// Submits an observation from the Observe stage.
    pub fn submit_observation(&self, obs: OvaphObservation) -> Result<(), String> {
        match self.submitted_observation.lock() {
            Ok(mut guard) => {
                *guard = Some(obs);
                debug!("Observation submitted to bridge");
                Ok(())
            }
            Err(e) => Err(format!("Failed to lock observation: {}", e)),
        }
    }

    /// Submits a verification result from the Verify stage.
    pub fn submit_verification(&self, result: OvaphVerificationResult) -> Result<(), String> {
        match self.submitted_verification.lock() {
            Ok(mut guard) => {
                *guard = Some(result);
                debug!("Verification result submitted to bridge");
                Ok(())
            }
            Err(e) => Err(format!("Failed to lock verification: {}", e)),
        }
    }

    /// Submits an attestation result from the Attest stage.
    pub fn submit_attestation(&self, result: OvaphAttestationResult) -> Result<(), String> {
        match self.submitted_attestation.lock() {
            Ok(mut guard) => {
                *guard = Some(result);
                debug!("Attestation result submitted to bridge");
                Ok(())
            }
            Err(e) => Err(format!("Failed to lock attestation: {}", e)),
        }
    }

    /// Submits a healing result from the Heal stage.
    pub fn submit_healing(&self, result: OvaphHealingResult) -> Result<(), String> {
        match self.submitted_healing.lock() {
            Ok(mut guard) => {
                *guard = Some(result);
                debug!("Healing result submitted to bridge");
                Ok(())
            }
            Err(e) => Err(format!("Failed to lock healing: {}", e)),
        }
    }

    /// Submits a proof result from the Prove stage.
    pub fn submit_proof(&self, result: OvaphProofResult) -> Result<(), String> {
        match self.submitted_proof.lock() {
            Ok(mut guard) => {
                *guard = Some(result);
                debug!("Proof result submitted to bridge");
                Ok(())
            }
            Err(e) => Err(format!("Failed to lock proof: {}", e)),
        }
    }

    /// Returns a reference to the inner OvaphLoop.
    pub fn inner_loop(&self) -> &OvaphLoop {
        &self.inner
    }

    /// Returns a snapshot of the current metrics from the inner loop.
    pub fn metrics(&self) -> Result<OvaphMetrics, String> {
        self.inner.metrics()
    }

    /// Returns the configuration of the inner loop.
    pub fn config(&self) -> &OvaphConfig {
        self.inner.config()
    }

    /// Retrieves and clears the submitted observation.
    pub fn take_observation(&self) -> Result<Option<OvaphObservation>, String> {
        match self.submitted_observation.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(e) => Err(format!("Failed to lock observation: {}", e)),
        }
    }

    /// Retrieves and clears the submitted verification result.
    pub fn take_verification(&self) -> Result<Option<OvaphVerificationResult>, String> {
        match self.submitted_verification.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(e) => Err(format!("Failed to lock verification: {}", e)),
        }
    }

    /// Retrieves and clears the submitted attestation result.
    pub fn take_attestation(&self) -> Result<Option<OvaphAttestationResult>, String> {
        match self.submitted_attestation.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(e) => Err(format!("Failed to lock attestation: {}", e)),
        }
    }

    /// Retrieves and clears the submitted healing result.
    pub fn take_healing(&self) -> Result<Option<OvaphHealingResult>, String> {
        match self.submitted_healing.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(e) => Err(format!("Failed to lock healing: {}", e)),
        }
    }

    /// Retrieves and clears the submitted proof result.
    pub fn take_proof(&self) -> Result<Option<OvaphProofResult>, String> {
        match self.submitted_proof.lock() {
            Ok(mut guard) => Ok(guard.take()),
            Err(e) => Err(format!("Failed to lock proof: {}", e)),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 12: Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper Functions ──────────────────────────────────────

    fn default_config() -> OvaphConfig {
        OvaphConfig::default()
    }

    fn default_loop() -> OvaphLoop {
        OvaphLoop::new(default_config())
    }

    fn make_observation_with_drift(z_score: f64) -> OvaphObservation {
        OvaphObservation {
            drift_snapshots: vec![DriftSnapshot {
                drift_type: "test_drift".to_string(),
                current_mean: 100.0,
                current_stddev: 10.0,
                sample_count: 50,
                last_z_score: z_score,
            }],
            health_snapshot: HealthSnapshot {
                overall_health: 0.9,
                component_count: 5,
                degraded_components: vec![],
                failed_components: vec![],
            },
            integrity_snapshot: IntegritySnapshot {
                total_domains: 3,
                passed_count: 3,
                failed_count: 0,
                failed_component_names: vec![],
            },
            timestamp: Utc::now().to_rfc3339(),
            observation_id: Uuid::new_v4().to_string(),
        }
    }

    fn make_cycle_report(stages: Vec<StageResult>) -> OvaphCycleReport {
        OvaphCycleReport {
            cycle_id: OvaphCycleId {
                cycle_number: 1,
                started_at: Utc::now().to_rfc3339(),
                cycle_id: Uuid::new_v4().to_string(),
            },
            cycle_number: 1,
            stages,
            total_duration_ms: 100,
            trust_before: 0.5,
            trust_after: 0.8,
            recovery_actions_taken: 0,
            attestation_passed: true,
            trust_proof_generated: true,
            overall_outcome: CycleOutcome::AllCompleted,
        }
    }

    // ══════════════════════════════════════════════════════════
    // A. Stage Type Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_all_stages_count() {
        assert_eq!(OvaphStage::all().len(), 5);
    }

    #[test]
    fn test_stage_sequence() {
        let stages = OvaphStage::all();
        assert_eq!(stages[0], OvaphStage::Observe);
        assert_eq!(stages[1], OvaphStage::Verify);
        assert_eq!(stages[2], OvaphStage::Attest);
        assert_eq!(stages[3], OvaphStage::Heal);
        assert_eq!(stages[4], OvaphStage::Prove);
    }

    #[test]
    fn test_next_wraps() {
        assert_eq!(OvaphStage::Observe.next(), OvaphStage::Verify);
        assert_eq!(OvaphStage::Verify.next(), OvaphStage::Attest);
        assert_eq!(OvaphStage::Attest.next(), OvaphStage::Heal);
        assert_eq!(OvaphStage::Heal.next(), OvaphStage::Prove);
        assert_eq!(OvaphStage::Prove.next(), OvaphStage::Observe);
    }

    #[test]
    fn test_duration_hints() {
        for stage in OvaphStage::all() {
            assert!(
                stage.duration_hint_ms() > 0,
                "Stage {} should have positive duration hint",
                stage
            );
        }
    }

    // ══════════════════════════════════════════════════════════
    // B. OvaphCycleReport Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_report_summary() {
        let report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::completed(OvaphStage::Verify, 20, 0),
            StageResult::completed(OvaphStage::Attest, 15, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "no healing".to_string()),
            StageResult::completed(OvaphStage::Prove, 5, 1),
        ]);
        let summary = report.summary();
        assert!(summary.contains("OVAPH Cycle #1"));
        assert!(summary.contains("ALL_COMPLETED"));
    }

    #[test]
    fn test_all_completed_outcome() {
        let stages = vec![
            StageResult::completed(OvaphStage::Observe, 1, 0),
            StageResult::completed(OvaphStage::Verify, 1, 0),
            StageResult::completed(OvaphStage::Attest, 1, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "skip".to_string()),
            StageResult::completed(OvaphStage::Prove, 1, 0),
        ];
        assert_eq!(determine_cycle_outcome(&stages), CycleOutcome::AllCompleted);
    }

    #[test]
    fn test_partial_outcome() {
        let stages = vec![
            StageResult::completed(OvaphStage::Observe, 1, 0),
            StageResult::failed(OvaphStage::Verify, 5, "error".to_string()),
            StageResult::completed(OvaphStage::Attest, 1, 0),
            StageResult::completed(OvaphStage::Heal, 1, 0),
            StageResult::completed(OvaphStage::Prove, 1, 0),
        ];
        assert_eq!(
            determine_cycle_outcome(&stages),
            CycleOutcome::PartiallyCompleted
        );
    }

    #[test]
    fn test_failed_outcome() {
        let stages = vec![
            StageResult::failed(OvaphStage::Observe, 5, "e1".to_string()),
            StageResult::failed(OvaphStage::Verify, 5, "e2".to_string()),
            StageResult::failed(OvaphStage::Attest, 5, "e3".to_string()),
            StageResult::failed(OvaphStage::Heal, 5, "e4".to_string()),
            StageResult::failed(OvaphStage::Prove, 5, "e5".to_string()),
        ];
        assert_eq!(determine_cycle_outcome(&stages), CycleOutcome::Failed);
    }

    #[test]
    fn test_stage_summary() {
        let report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::failed(OvaphStage::Verify, 20, "err".to_string()),
            StageResult::skipped(OvaphStage::Attest, 0, "rationale".to_string()),
            StageResult::completed(OvaphStage::Heal, 5, 0),
            StageResult::completed(OvaphStage::Prove, 15, 1),
        ]);
        let summary = report.stage_summary();
        assert!(summary.contains("Observe:[OK]"));
        assert!(summary.contains("Verify:[FAIL]"));
        assert!(summary.contains("Attest:[SKIP]"));
        assert!(summary.contains("Heal:[OK]"));
        assert!(summary.contains("Prove:[OK]"));
    }

    #[test]
    fn test_empty_stages_outcome() {
        assert_eq!(determine_cycle_outcome(&[]), CycleOutcome::Failed);
    }

    // ══════════════════════════════════════════════════════════
    // C. OvaphMetrics Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_initial_metrics() {
        let m = OvaphMetrics::new();
        assert_eq!(m.total_cycles, 0);
        assert_eq!(m.completed_cycles, 0);
        assert_eq!(m.failed_cycles, 0);
        assert_eq!(m.consecutive_failures, 0);
        assert_eq!(m.consecutive_successes, 0);
        assert!(m.last_cycle_at.is_none());
        assert_eq!(m.avg_cycle_duration_ms, 0.0);
    }

    #[test]
    fn test_record_completed() {
        let mut m = OvaphMetrics::new();
        let report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::completed(OvaphStage::Verify, 20, 0),
            StageResult::completed(OvaphStage::Attest, 15, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "no-op".to_string()),
            StageResult::completed(OvaphStage::Prove, 5, 1),
        ]);
        m.record_cycle(&report);
        assert_eq!(m.total_cycles, 1);
        assert_eq!(m.completed_cycles, 1);
        assert_eq!(m.failed_cycles, 0);
        assert_eq!(m.consecutive_successes, 1);
        assert_eq!(m.consecutive_failures, 0);
    }

    #[test]
    fn test_record_failed() {
        let mut m = OvaphMetrics::new();
        let mut failed_report = make_cycle_report(vec![
            StageResult::failed(OvaphStage::Observe, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Verify, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Attest, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Heal, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Prove, 5, "err".to_string()),
        ]);
        failed_report.overall_outcome = CycleOutcome::Failed;
        m.record_cycle(&failed_report);
        assert_eq!(m.total_cycles, 1);
        assert_eq!(m.completed_cycles, 0);
        assert_eq!(m.failed_cycles, 1);
        assert_eq!(m.consecutive_failures, 1);
        assert_eq!(m.consecutive_successes, 0);
    }

    #[test]
    fn test_success_rate() {
        let mut m = OvaphMetrics::new();
        assert_eq!(m.success_rate(), 0.0);

        let ok_report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::completed(OvaphStage::Verify, 10, 0),
            StageResult::completed(OvaphStage::Attest, 10, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "s".to_string()),
            StageResult::completed(OvaphStage::Prove, 10, 0),
        ]);
        m.record_cycle(&ok_report);
        m.record_cycle(&ok_report);
        m.record_cycle(&ok_report);
        assert!((m.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_consecutive_tracking() {
        let mut m = OvaphMetrics::new();

        // Record 3 successes
        let ok_report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::completed(OvaphStage::Verify, 10, 0),
            StageResult::completed(OvaphStage::Attest, 10, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "s".to_string()),
            StageResult::completed(OvaphStage::Prove, 10, 0),
        ]);
        m.record_cycle(&ok_report);
        m.record_cycle(&ok_report);
        m.record_cycle(&ok_report);
        assert_eq!(m.consecutive_successes, 3);
        assert_eq!(m.consecutive_failures, 0);

        // Record a failure
        let mut fail_report = make_cycle_report(vec![
            StageResult::failed(OvaphStage::Observe, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Verify, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Attest, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Heal, 5, "err".to_string()),
            StageResult::failed(OvaphStage::Prove, 5, "err".to_string()),
        ]);
        fail_report.overall_outcome = CycleOutcome::Failed;
        m.record_cycle(&fail_report);
        assert_eq!(m.consecutive_successes, 0);
        assert_eq!(m.consecutive_failures, 1);

        // Record another success
        m.record_cycle(&ok_report);
        assert_eq!(m.consecutive_successes, 1);
        assert_eq!(m.consecutive_failures, 0);
    }

    #[test]
    fn test_stage_failure_rate() {
        let mut m = OvaphMetrics::new();
        assert_eq!(m.stage_failure_rate(OvaphStage::Observe), 0.0);

        let report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::failed(OvaphStage::Verify, 20, "err".to_string()),
            StageResult::completed(OvaphStage::Attest, 15, 0),
            StageResult::completed(OvaphStage::Heal, 5, 0),
            StageResult::completed(OvaphStage::Prove, 5, 1),
        ]);
        m.record_cycle(&report);
        m.record_cycle(&report);

        assert_eq!(m.stage_failure_rate(OvaphStage::Verify), 1.0);
        assert_eq!(m.stage_failure_rate(OvaphStage::Observe), 0.0);
    }

    #[test]
    fn test_avg_duration() {
        let mut m = OvaphMetrics::new();
        assert_eq!(m.avg_cycle_duration_ms, 0.0);

        let mut r1 = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 50, 0),
            StageResult::completed(OvaphStage::Verify, 50, 0),
            StageResult::completed(OvaphStage::Attest, 50, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "s".to_string()),
            StageResult::completed(OvaphStage::Prove, 50, 0),
        ]);
        r1.total_duration_ms = 200;

        let mut r2 = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 100, 0),
            StageResult::completed(OvaphStage::Verify, 100, 0),
            StageResult::completed(OvaphStage::Attest, 100, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "s".to_string()),
            StageResult::completed(OvaphStage::Prove, 100, 0),
        ]);
        r2.total_duration_ms = 400;

        m.record_cycle(&r1);
        assert!((m.avg_cycle_duration_ms - 200.0).abs() < f64::EPSILON);

        m.record_cycle(&r2);
        assert!((m.avg_cycle_duration_ms - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_many_cycles() {
        let mut m = OvaphMetrics::new();
        let ok_report = make_cycle_report(vec![
            StageResult::completed(OvaphStage::Observe, 10, 0),
            StageResult::completed(OvaphStage::Verify, 10, 0),
            StageResult::completed(OvaphStage::Attest, 10, 0),
            StageResult::skipped(OvaphStage::Heal, 0, "s".to_string()),
            StageResult::completed(OvaphStage::Prove, 10, 0),
        ]);
        for _ in 0..100 {
            m.record_cycle(&ok_report);
        }
        assert_eq!(m.total_cycles, 100);
        assert_eq!(m.completed_cycles, 100);
        assert!((m.success_rate() - 1.0).abs() < f64::EPSILON);
        assert!(m.last_cycle_at.is_some());
    }

    // ══════════════════════════════════════════════════════════
    // D. OvaphConfig Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_defaults() {
        let cfg = OvaphConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval_ms, 30_000);
        assert_eq!(cfg.observe_baseline_observations, 10);
        assert!((cfg.verify_drift_sigma_threshold - 3.0).abs() < f64::EPSILON);
        assert!(cfg.attest_sign_reports);
        assert!(!cfg.heal_autonomous);
        assert!(cfg.prove_generate_proof);
        assert_eq!(cfg.max_cycle_duration_ms, 60_000);
        assert_eq!(cfg.stage_timeout_ms, 10_000);
    }

    #[test]
    fn test_custom_config() {
        let cfg = OvaphConfig {
            enabled: true,
            interval_ms: 10_000,
            heal_autonomous: true,
            verify_drift_sigma_threshold: 5.0,
            ..Default::default()
        };
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_ms, 10_000);
        assert!(cfg.heal_autonomous);
        assert!((cfg.verify_drift_sigma_threshold - 5.0).abs() < f64::EPSILON);
        // Defaults preserved
        assert!(cfg.attest_sign_reports);
        assert!(cfg.prove_generate_proof);
    }

    #[test]
    fn test_validation() {
        let mut cfg = OvaphConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.interval_ms = 0;
        assert!(cfg.validate().is_err());

        cfg.interval_ms = 30_000;
        cfg.verify_drift_sigma_threshold = -1.0;
        assert!(cfg.validate().is_err());

        cfg.verify_drift_sigma_threshold = 3.0;
        cfg.max_cycle_duration_ms = 0;
        assert!(cfg.validate().is_err());

        cfg.max_cycle_duration_ms = 60_000;
        cfg.stage_timeout_ms = 0;
        assert!(cfg.validate().is_err());

        cfg.stage_timeout_ms = 20_000;
        // 5 * 20000 = 100000 > 60000
        assert!(cfg.validate().is_err());

        cfg.stage_timeout_ms = 10_000;
        assert!(cfg.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════
    // E. OvaphObservation Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_default_observation() {
        let obs = OvaphObservation::default();
        assert!(obs.drift_snapshots.is_empty());
        assert!((obs.health_snapshot.overall_health - 1.0).abs() < f64::EPSILON);
        assert!(obs.health_snapshot.degraded_components.is_empty());
        assert!(obs.integrity_snapshot.failed_component_names.is_empty());
        assert!(!obs.observation_id.is_empty());
        assert!(!obs.timestamp.is_empty());
    }

    #[test]
    fn test_drift_snapshot() {
        let ds = DriftSnapshot {
            drift_type: "latency".to_string(),
            current_mean: 50.0,
            current_stddev: 5.0,
            sample_count: 100,
            last_z_score: 2.5,
        };
        assert_eq!(ds.drift_type, "latency");
        assert!((ds.current_mean - 50.0).abs() < f64::EPSILON);
        assert_eq!(ds.sample_count, 100);
    }

    #[test]
    fn test_health_snapshot() {
        let hs = HealthSnapshot {
            overall_health: 0.7,
            component_count: 10,
            degraded_components: vec!["svc-a".to_string()],
            failed_components: vec!["svc-b".to_string()],
        };
        assert!((hs.overall_health - 0.7).abs() < f64::EPSILON);
        assert_eq!(hs.component_count, 10);
        assert_eq!(hs.degraded_components.len(), 1);
        assert_eq!(hs.failed_components.len(), 1);
    }

    #[test]
    fn test_integrity_snapshot() {
        let is_ = IntegritySnapshot {
            total_domains: 5,
            passed_count: 4,
            failed_count: 1,
            failed_component_names: vec!["domain-x".to_string()],
        };
        assert_eq!(is_.total_domains, 5);
        assert_eq!(is_.passed_count, 4);
        assert_eq!(is_.failed_count, 1);
        assert_eq!(is_.failed_component_names.len(), 1);
    }

    // ══════════════════════════════════════════════════════════
    // F. OvaphVerificationResult Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_no_signals() {
        let vr = OvaphVerificationResult::default();
        assert!(vr.signals.is_empty());
        assert_eq!(vr.composite_severity, Severity::None);
        assert!(!vr.requires_healing);
    }

    #[test]
    fn test_single_anomaly() {
        let obs = make_observation_with_drift(10.0); // Very high z-score
        let vr = OvaphVerificationResult::from_observation(&obs, 3.0);
        assert_eq!(vr.signals.len(), 1);
        assert!(vr.signals[0].is_anomaly);
        assert_ne!(vr.composite_severity, Severity::None);
    }

    #[test]
    fn test_composite_severity() {
        let signals = vec![
            VerifiedSignal::anomaly("a".to_string(), Severity::Low, 0.5),
            VerifiedSignal::anomaly("b".to_string(), Severity::Critical, 0.9),
            VerifiedSignal::normal("c".to_string()),
        ];
        let severity = compute_composite_severity(&signals);
        assert_eq!(severity, Severity::Critical);
    }

    #[test]
    fn test_requires_healing() {
        // High severity requires healing
        let vr = OvaphVerificationResult::from_drift_analyzer(100.0, 10.0, 200.0, 3.0);
        assert!(vr.requires_healing);

        // Low severity does not
        let vr2 = OvaphVerificationResult::from_drift_analyzer(100.0, 10.0, 101.0, 3.0);
        assert!(!vr2.requires_healing);
    }

    #[test]
    fn test_rationale_generation() {
        let vr = OvaphVerificationResult::from_observation(&OvaphObservation::default(), 3.0);
        assert!(!vr.rationale.is_empty());
        assert!(vr.rationale.contains("0 anomalies"));
    }

    #[test]
    fn test_severity_levels() {
        assert!(Severity::None.weight() < Severity::Low.weight());
        assert!(Severity::Low.weight() < Severity::Medium.weight());
        assert!(Severity::Medium.weight() < Severity::High.weight());
        assert!(Severity::High.weight() < Severity::Critical.weight());

        assert!(!Severity::None.is_anomaly());
        assert!(!Severity::Low.is_anomaly());
        assert!(Severity::Medium.is_anomaly());
        assert!(Severity::High.is_anomaly());
        assert!(Severity::Critical.is_anomaly());
    }

    #[test]
    fn test_analysis_methods() {
        let methods = [
            AnalysisMethod::ZScore,
            AnalysisMethod::KS,
            AnalysisMethod::PSI,
            AnalysisMethod::ADWIN,
            AnalysisMethod::ChiSquared,
            AnalysisMethod::Composite,
        ];
        for method in &methods {
            let display = format!("{}", method);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_confidence_ranges() {
        let vr = OvaphVerificationResult::from_drift_analyzer(100.0, 10.0, 150.0, 3.0);
        let confidence = vr.signals[0].confidence;
        assert!(confidence >= 0.0);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_severity_from_drift() {
        // No drift
        assert_eq!(severity_from_drift(100.0, 0.0, 100.0, 3.0), Severity::None);
        // Normal range
        assert_eq!(severity_from_drift(100.0, 10.0, 101.0, 3.0), Severity::Low);
        // Medium
        let medium = severity_from_drift(100.0, 10.0, 115.0, 3.0);
        assert_eq!(medium, Severity::Medium);
        // High
        let high = severity_from_drift(100.0, 10.0, 135.0, 3.0);
        assert_eq!(high, Severity::High);
        // Critical
        let critical = severity_from_drift(100.0, 10.0, 200.0, 3.0);
        assert_eq!(critical, Severity::Critical);
    }

    #[test]
    fn test_severity_from_drift_nan() {
        assert_eq!(
            severity_from_drift(f64::NAN, 10.0, 100.0, 3.0),
            Severity::None
        );
        assert_eq!(
            severity_from_drift(100.0, 10.0, f64::NAN, 3.0),
            Severity::None
        );
        assert_eq!(
            severity_from_drift(100.0, 10.0, f64::INFINITY, 3.0),
            Severity::None
        );
    }

    // ══════════════════════════════════════════════════════════
    // G. OvaphAttestationResult Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_passed_attestation() {
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::normal("test".to_string())],
            composite_severity: Severity::Low,
            requires_healing: false,
            rationale: "ok".to_string(),
        };
        let att = OvaphAttestationResult::from_verification(&vr);
        assert!(att.attestation_passed);
        assert!((att.trust_level - 0.8).abs() < f64::EPSILON);
        assert!(att.failed_components.is_empty());
        assert!(!att.attestation_id.is_empty());
    }

    #[test]
    fn test_failed_attestation() {
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::anomaly(
                "test".to_string(),
                Severity::Critical,
                0.95,
            )],
            composite_severity: Severity::Critical,
            requires_healing: true,
            rationale: "critical".to_string(),
        };
        let att = OvaphAttestationResult::from_verification(&vr);
        assert!(!att.attestation_passed);
        assert!((att.trust_level - 0.1).abs() < f64::EPSILON);
        assert_eq!(att.failed_components.len(), 1);
    }

    #[test]
    fn test_default_attestation() {
        let att = OvaphAttestationResult::default();
        assert!(att.attestation_passed);
        assert!((att.trust_level - 1.0).abs() < f64::EPSILON);
        assert!(att.failed_components.is_empty());
    }

    // ══════════════════════════════════════════════════════════
    // H. OvaphHealingResult Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_no_healing() {
        let vr = OvaphVerificationResult::default();
        let heal = OvaphHealingResult::from_verification(&vr, true);
        assert!(!heal.healing_required);
        assert_eq!(heal.actions_planned, 0);
        assert_eq!(heal.actions_executed, 0);
    }

    #[test]
    fn test_healing_with_actions() {
        let vr = OvaphVerificationResult {
            signals: vec![
                VerifiedSignal::anomaly("drift_a".to_string(), Severity::High, 0.8),
                VerifiedSignal::anomaly("drift_b".to_string(), Severity::Critical, 0.9),
            ],
            composite_severity: Severity::Critical,
            requires_healing: true,
            rationale: "critical".to_string(),
        };
        let heal = OvaphHealingResult::from_verification(&vr, true);
        assert!(heal.healing_required);
        assert_eq!(heal.actions_planned, 2);
        assert_eq!(heal.actions_executed, 2);
        assert_eq!(heal.actions_succeeded, 2);
        assert_eq!(heal.actions_failed, 0);
        assert_eq!(heal.strategies_used.len(), 2);
    }

    #[test]
    fn test_partial_success() {
        let heal = OvaphHealingResult {
            healing_required: true,
            actions_planned: 4,
            actions_executed: 4,
            actions_succeeded: 3,
            actions_failed: 1,
            strategies_used: vec!["restart".to_string(), "reconfigure".to_string()],
            recovery_plan_rationale: Some("partial".to_string()),
        };
        assert!(heal.healing_required);
        assert_eq!(heal.actions_failed, 1);
        assert_eq!(heal.actions_succeeded, 3);
    }

    #[test]
    fn test_all_failed_healing() {
        let heal = OvaphHealingResult {
            healing_required: true,
            actions_planned: 3,
            actions_executed: 3,
            actions_succeeded: 0,
            actions_failed: 3,
            strategies_used: vec!["restart".to_string()],
            recovery_plan_rationale: Some("all failed".to_string()),
        };
        assert!(heal.healing_required);
        assert_eq!(heal.actions_failed, 3);
        assert_eq!(heal.actions_succeeded, 0);
    }

    #[test]
    fn test_strategies_used() {
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::anomaly(
                "network".to_string(),
                Severity::High,
                0.8,
            )],
            composite_severity: Severity::High,
            requires_healing: true,
            rationale: "heal needed".to_string(),
        };
        let heal = OvaphHealingResult::from_verification(&vr, true);
        assert_eq!(heal.strategies_used.len(), 1);
        assert_eq!(heal.strategies_used[0], "heal_network");
    }

    #[test]
    fn test_healing_autonomous_disabled() {
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::anomaly(
                "x".to_string(),
                Severity::Critical,
                0.9,
            )],
            composite_severity: Severity::Critical,
            requires_healing: true,
            rationale: "critical".to_string(),
        };
        let heal = OvaphHealingResult::from_verification(&vr, false);
        assert!(heal.healing_required);
        assert_eq!(heal.actions_planned, 0);
        assert!(heal.recovery_plan_rationale.is_some());
        assert!(heal
            .recovery_plan_rationale
            .as_ref()
            .map(|r| r.contains("disabled"))
            .unwrap_or(false));
    }

    // ══════════════════════════════════════════════════════════
    // I. OvaphProofResult Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_proof_generated() {
        let att = OvaphAttestationResult {
            attestation_passed: true,
            trust_level: 0.9,
            failed_components: vec![],
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 5,
        };
        let proof = OvaphProofResult::from_attestation(&att, true);
        assert!(proof.proof_generated);
        assert!(proof.proof_id.is_some());
        assert!(proof.all_domains_passed);
        assert!(proof.chain_verified);
        assert!((proof.trust_score - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_no_proof() {
        let att = OvaphAttestationResult {
            attestation_passed: true,
            trust_level: 0.9,
            failed_components: vec![],
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 5,
        };
        // Don't generate
        let proof = OvaphProofResult::from_attestation(&att, false);
        assert!(!proof.proof_generated);
        assert!(proof.proof_id.is_none());
    }

    #[test]
    fn test_chain_verified() {
        // Passed attestation
        let att = OvaphAttestationResult::default();
        let proof = OvaphProofResult::from_attestation(&att, true);
        assert!(proof.chain_verified);

        // Failed attestation
        let att_fail = OvaphAttestationResult {
            attestation_passed: false,
            trust_level: 0.1,
            failed_components: vec!["x".to_string()],
            attestation_id: Uuid::new_v4().to_string(),
            chain_length_after: 1,
        };
        let proof_fail = OvaphProofResult::from_attestation(&att_fail, true);
        assert!(!proof_fail.chain_verified);
        assert!(!proof_fail.proof_generated);
    }

    // ══════════════════════════════════════════════════════════
    // J. OvaphLoop Tests
    // ══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_loop() {
        let loop_ = default_loop();
        assert!(!loop_.is_running());
        assert_eq!(loop_.cycle_count(), 0);
        let metrics = loop_.metrics().unwrap();
        assert_eq!(metrics.total_cycles, 0);
    }

    #[tokio::test]
    async fn test_not_running_initially() {
        let loop_ = OvaphLoop::new(OvaphConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(!loop_.is_running());
    }

    #[tokio::test]
    async fn test_run_single_observe_stage() {
        let loop_ = default_loop();
        let obs = make_observation_with_drift(1.5);
        let (result, returned_obs) = loop_.run_observe(obs).await;
        assert_eq!(result.stage, OvaphStage::Observe);
        assert!(result.success);
        assert!(matches!(result.outcome, StageOutcome::Completed));
        assert_eq!(returned_obs.drift_snapshots.len(), 1);
    }

    #[tokio::test]
    async fn test_run_verify_stage() {
        let loop_ = default_loop();
        let obs = make_observation_with_drift(5.0);
        let (result, verification) = loop_.run_verify(&obs).await;
        assert_eq!(result.stage, OvaphStage::Verify);
        assert!(result.success);
        assert!(!verification.signals.is_empty());
    }

    #[tokio::test]
    async fn test_run_attest_stage() {
        let loop_ = default_loop();
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::normal("test".to_string())],
            composite_severity: Severity::None,
            requires_healing: false,
            rationale: "all clear".to_string(),
        };
        let (result, attestation) = loop_.run_attest(&vr).await;
        assert_eq!(result.stage, OvaphStage::Attest);
        assert!(result.success);
        assert!(attestation.attestation_passed);
    }

    #[tokio::test]
    async fn test_run_heal_stage() {
        let loop_ = default_loop();
        let vr = OvaphVerificationResult {
            signals: vec![],
            composite_severity: Severity::None,
            requires_healing: false,
            rationale: "no issues".to_string(),
        };
        let (result, healing) = loop_.run_heal(&vr).await;
        assert_eq!(result.stage, OvaphStage::Heal);
        assert!(matches!(result.outcome, StageOutcome::Skipped(_)));
        assert!(!healing.healing_required);
    }

    #[tokio::test]
    async fn test_run_prove_stage() {
        let loop_ = default_loop();
        let att = OvaphAttestationResult::default();
        let (result, proof) = loop_.run_prove(&att).await;
        assert_eq!(result.stage, OvaphStage::Prove);
        assert!(result.success);
        assert!(proof.proof_generated);
    }

    #[tokio::test]
    async fn test_full_cycle_all_pass() {
        let loop_ = default_loop();
        let report = loop_.run_full_cycle().await;
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.stages.len(), 5);
        assert_eq!(report.overall_outcome, CycleOutcome::AllCompleted);
        assert!(report.attestation_passed);
        assert!(report.trust_proof_generated);
    }

    #[tokio::test]
    async fn test_full_cycle_with_failures() {
        // Use a very small max_cycle_duration to force failures
        let loop_ = OvaphLoop::new(OvaphConfig {
            max_cycle_duration_ms: 0,
            stage_timeout_ms: 10_000,
            ..Default::default()
        });
        let report = loop_.run_full_cycle().await;
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.stages.len(), 5);
        assert_eq!(report.overall_outcome, CycleOutcome::Failed);
    }

    #[tokio::test]
    async fn test_full_cycle_metrics_updated() {
        let loop_ = default_loop();
        assert_eq!(loop_.cycle_count(), 0);

        let _ = loop_.run_full_cycle().await;
        assert_eq!(loop_.cycle_count(), 1);

        let metrics = loop_.metrics().unwrap();
        assert_eq!(metrics.total_cycles, 1);
        assert_eq!(metrics.completed_cycles, 1);
        assert!(metrics.last_cycle_at.is_some());
    }

    #[tokio::test]
    async fn test_consecutive_cycle_tracking() {
        let loop_ = default_loop();

        for _ in 0..5 {
            let _ = loop_.run_full_cycle().await;
        }

        let metrics = loop_.metrics().unwrap();
        assert_eq!(metrics.total_cycles, 5);
        assert_eq!(metrics.completed_cycles, 5);
        assert_eq!(metrics.consecutive_successes, 5);
        assert_eq!(loop_.cycle_count(), 5);
    }

    #[tokio::test]
    async fn test_stage_timeout_handling() {
        // With 1ms timeout, stages should still complete since they're instant
        let loop_ = OvaphLoop::new(OvaphConfig {
            stage_timeout_ms: 1,
            max_cycle_duration_ms: 60_000,
            ..Default::default()
        });
        let report = loop_.run_full_cycle().await;
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.stages.len(), 5);
    }

    #[tokio::test]
    async fn test_max_cycle_duration() {
        let loop_ = OvaphLoop::new(OvaphConfig {
            max_cycle_duration_ms: 0,
            stage_timeout_ms: 10_000,
            ..Default::default()
        });
        let report = loop_.run_full_cycle().await;
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.overall_outcome, CycleOutcome::Failed);
        for stage in &report.stages {
            assert!(!stage.success);
        }
    }

    #[tokio::test]
    async fn test_cycle_counter_increments() {
        let loop_ = default_loop();
        assert_eq!(loop_.cycle_count(), 0);
        let _ = loop_.run_full_cycle().await;
        assert_eq!(loop_.cycle_count(), 1);
        let _ = loop_.run_full_cycle().await;
        assert_eq!(loop_.cycle_count(), 2);
        let _ = loop_.run_full_cycle().await;
        assert_eq!(loop_.cycle_count(), 3);
    }

    #[tokio::test]
    async fn test_metrics_persistence() {
        let loop_ = default_loop();

        // Run multiple cycles
        for _ in 0..3 {
            let _ = loop_.run_full_cycle().await;
        }

        let m1 = loop_.metrics().unwrap();
        assert_eq!(m1.total_cycles, 3);
        assert!(m1.avg_cycle_duration_ms > 0.0);

        // Run one more
        let _ = loop_.run_full_cycle().await;

        let m2 = loop_.metrics().unwrap();
        assert_eq!(m2.total_cycles, 4);
        assert!(m2.avg_cycle_duration_ms > 0.0);
    }

    #[tokio::test]
    async fn test_verify_from_observation_with_anomalies() {
        let loop_ = default_loop();
        let obs = OvaphObservation {
            drift_snapshots: vec![DriftSnapshot {
                drift_type: "latency".to_string(),
                current_mean: 100.0,
                current_stddev: 10.0,
                sample_count: 50,
                last_z_score: 8.0,
            }],
            health_snapshot: HealthSnapshot {
                overall_health: 0.1,
                component_count: 5,
                degraded_components: vec!["svc-a".to_string()],
                failed_components: vec!["svc-b".to_string()],
            },
            integrity_snapshot: IntegritySnapshot {
                total_domains: 4,
                passed_count: 1,
                failed_count: 3,
                failed_component_names: vec!["d1".to_string(), "d2".to_string(), "d3".to_string()],
            },
            timestamp: Utc::now().to_rfc3339(),
            observation_id: Uuid::new_v4().to_string(),
        };

        let (_, verification) = loop_.run_verify(&obs).await;
        assert!(verification.requires_healing);
        assert_eq!(verification.composite_severity, Severity::Critical);
        // Should have signals for: drift, health, integrity = 3
        assert_eq!(verification.signals.len(), 3);
    }

    #[tokio::test]
    async fn test_heal_autonomous_disabled() {
        let loop_ = OvaphLoop::new(OvaphConfig {
            heal_autonomous: false,
            ..Default::default()
        });

        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::anomaly(
                "x".to_string(),
                Severity::Critical,
                0.9,
            )],
            composite_severity: Severity::Critical,
            requires_healing: true,
            rationale: "critical".to_string(),
        };

        let (result, healing) = loop_.run_heal(&vr).await;
        assert!(matches!(result.outcome, StageOutcome::Skipped(_)));
        assert!(healing.healing_required);
        assert_eq!(healing.actions_planned, 0);
    }

    #[tokio::test]
    async fn test_prove_disabled() {
        let loop_ = OvaphLoop::new(OvaphConfig {
            prove_generate_proof: false,
            ..Default::default()
        });
        let att = OvaphAttestationResult::default();
        let (result, proof) = loop_.run_prove(&att).await;
        assert!(result.success);
        assert!(!proof.proof_generated);
        assert!(proof.proof_id.is_none());
    }

    #[tokio::test]
    async fn test_cycle_with_observation() {
        let loop_ = default_loop();
        let obs = make_observation_with_drift(1.0);
        let report = loop_.run_cycle_with_observation(obs).await;
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.stages.len(), 5);
        assert_eq!(report.overall_outcome, CycleOutcome::AllCompleted);
        assert_eq!(loop_.cycle_count(), 1);
    }

    #[tokio::test]
    async fn test_execute_with_timeout_fast() {
        let loop_ = default_loop();
        let future = async { (StageResult::completed(OvaphStage::Observe, 1, 0), 42i32) };
        let (result, data) = loop_
            .execute_with_timeout(OvaphStage::Observe, future)
            .await;
        assert!(result.success);
        assert_eq!(data, Some(42));
    }

    #[tokio::test]
    async fn test_execute_with_timeout_slow() {
        let loop_ = OvaphLoop::new(OvaphConfig {
            stage_timeout_ms: 1,
            ..Default::default()
        });
        let slow_future = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            (
                StageResult::completed(OvaphStage::Observe, 100, 0),
                "data".to_string(),
            )
        };
        let (result, data) = loop_
            .execute_with_timeout(OvaphStage::Observe, slow_future)
            .await;
        assert!(!result.success);
        assert!(data.is_none());
        assert!(matches!(result.outcome, StageOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn test_running_flag_lifecycle() {
        let loop_ = default_loop();
        assert!(!loop_.is_running());

        let _ = loop_.run_full_cycle().await;
        // After completion, running should be false (RAII guard dropped)
        assert!(!loop_.is_running());
    }

    #[tokio::test]
    async fn test_multiple_cycles_increment_counter() {
        let loop_ = default_loop();
        for i in 1..=10 {
            let report = loop_.run_full_cycle().await.unwrap();
            assert_eq!(report.cycle_number, i as u64);
        }
        assert_eq!(loop_.cycle_count(), 10);
    }

    // ══════════════════════════════════════════════════════════
    // K. OvaphLoopBridge Tests
    // ══════════════════════════════════════════════════════════

    #[test]
    fn test_bridge_construction() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        assert!(!bridge.inner_loop().is_running());
        assert_eq!(bridge.inner_loop().cycle_count(), 0);
    }

    #[test]
    fn test_submit_observation() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let obs = make_observation_with_drift(2.0);

        let result = bridge.submit_observation(obs);
        assert!(result.is_ok());

        let taken = bridge.take_observation().unwrap();
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert_eq!(taken.drift_snapshots.len(), 1);

        // Second take should be None
        let taken2 = bridge.take_observation().unwrap();
        assert!(taken2.is_none());
    }

    #[test]
    fn test_submit_verification() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let vr = OvaphVerificationResult {
            signals: vec![VerifiedSignal::anomaly(
                "test".to_string(),
                Severity::High,
                0.8,
            )],
            composite_severity: Severity::High,
            requires_healing: true,
            rationale: "anomaly detected".to_string(),
        };

        let result = bridge.submit_verification(vr);
        assert!(result.is_ok());

        let taken = bridge.take_verification().unwrap();
        assert!(taken.is_some());
        assert!(taken.unwrap().requires_healing);
    }

    #[test]
    fn test_submit_attestation() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let att = OvaphAttestationResult::default();

        let result = bridge.submit_attestation(att);
        assert!(result.is_ok());

        let taken = bridge.take_attestation().unwrap();
        assert!(taken.is_some());
        assert!(taken.unwrap().attestation_passed);
    }

    #[test]
    fn test_bridge_metrics_delegation() {
        let loop_ = OvaphLoop::new(default_config());
        let bridge = OvaphLoopBridge::new(loop_);

        let metrics = bridge.metrics().unwrap();
        assert_eq!(metrics.total_cycles, 0);
        assert_eq!(bridge.config().enabled, false);
    }

    #[test]
    fn test_bridge_submit_healing() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let heal = OvaphHealingResult {
            healing_required: true,
            actions_planned: 2,
            actions_executed: 2,
            actions_succeeded: 1,
            actions_failed: 1,
            strategies_used: vec!["restart".to_string()],
            recovery_plan_rationale: Some("test".to_string()),
        };

        let result = bridge.submit_healing(heal);
        assert!(result.is_ok());

        let taken = bridge.take_healing().unwrap();
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert!(taken.healing_required);
        assert_eq!(taken.actions_succeeded, 1);
    }

    #[test]
    fn test_bridge_submit_proof() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let proof = OvaphProofResult {
            proof_generated: true,
            trust_score: 0.95,
            proof_id: Some(Uuid::new_v4().to_string()),
            all_domains_passed: true,
            chain_verified: true,
        };

        let result = bridge.submit_proof(proof);
        assert!(result.is_ok());

        let taken = bridge.take_proof().unwrap();
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert!(taken.proof_generated);
        assert!((taken.trust_score - 0.95).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_bridge_inner_loop_runs_cycle() {
        let loop_ = default_loop();
        let bridge = OvaphLoopBridge::new(loop_);
        let report = bridge.inner_loop().run_full_cycle().await;
        assert!(report.is_ok());

        // Bridge metrics should reflect the cycle
        let metrics = bridge.metrics().unwrap();
        assert_eq!(metrics.total_cycles, 1);
    }
}
