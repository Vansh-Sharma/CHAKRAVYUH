// D2 ANANTA Verification — Runner
//
// The AnantaVerifyRunner orchestrates verification across all ANANTA subsystems.
// It runs specs from each subsystem, records evidence, and produces per-subsystem
// pass/fail counts.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing;

use crate::validation::verification::{
    verify_and_record, ValidationReport, VerificationEngine, VerificationSpec,
};

use super::corruption_detector::CorruptionDetector;
use super::ovaph_verify::{OvaphCycleData, OvaphVerifier};
use super::specs::{AdapterSpecs, PhoenixSpecs, SentinelSpecs, VaultSpecs};

/// Configuration for the ANANTA verification runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnantaVerifyConfig {
    /// Subsystems to skip during verification.
    pub skip_subsystems: Vec<String>,
    /// Maximum drift tolerance for WithinTolerance checks.
    pub max_drift_tolerance: f64,
    /// Whether to run integrity/tamper detection checks.
    pub integrity_check_enabled: bool,
    /// Trust chain depth to verify.
    pub trust_chain_depth: u32,
}

impl Default for AnantaVerifyConfig {
    fn default() -> Self {
        Self {
            skip_subsystems: Vec::new(),
            max_drift_tolerance: 0.05,
            integrity_check_enabled: true,
            trust_chain_depth: 10,
        }
    }
}

/// Per-subsystem verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemResult {
    /// Subsystem name (e.g. "ananta.sentinel").
    pub subsystem: String,
    /// Total checks run.
    pub total: u64,
    /// Checks that passed.
    pub passed: u64,
    /// Checks that failed.
    pub failed: u64,
    /// Names of failed checks.
    pub failed_checks: Vec<String>,
}

impl SubsystemResult {
    pub fn new(subsystem: &str) -> Self {
        Self {
            subsystem: subsystem.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            failed_checks: Vec::new(),
        }
    }

    pub fn record_pass(&mut self, check_name: &str) {
        self.total += 1;
        self.passed += 1;
        tracing::debug!(subsystem = %self.subsystem, check = %check_name, "PASS");
    }

    pub fn record_fail(&mut self, check_name: &str) {
        self.total += 1;
        self.failed += 1;
        self.failed_checks.push(check_name.to_string());
        tracing::warn!(subsystem = %self.subsystem, check = %check_name, "FAIL");
    }

    /// Whether all checks passed.
    pub fn is_clean(&self) -> bool {
        self.failed == 0
    }
}

/// Aggregate result of the full ANANTA verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnantaVerifyResult {
    pub sentinel_results: SubsystemResult,
    pub phoenix_results: SubsystemResult,
    pub vault_results: SubsystemResult,
    pub adapter_results: SubsystemResult,
    pub ovaph_results: SubsystemResult,
    /// Total across all subsystems.
    pub total_checks: u64,
    pub total_passed: u64,
    pub total_failed: u64,
}

impl AnantaVerifyResult {
    /// Whether all checks across all subsystems passed.
    pub fn is_clean(&self) -> bool {
        self.total_failed == 0
    }

    /// Collect all failed check names across subsystems.
    pub fn all_failed_checks(&self) -> Vec<String> {
        let mut checks = Vec::new();
        checks.extend(self.sentinel_results.failed_checks.iter().cloned());
        checks.extend(self.phoenix_results.failed_checks.iter().cloned());
        checks.extend(self.vault_results.failed_checks.iter().cloned());
        checks.extend(self.adapter_results.failed_checks.iter().cloned());
        checks.extend(self.ovaph_results.failed_checks.iter().cloned());
        checks
    }
}

/// The ANANTA Verification Runner.
///
/// Orchestrates verification across all ANANTA subsystems using
/// the D0 Verification Engine.
pub struct AnantaVerifyRunner {
    config: AnantaVerifyConfig,
}

impl AnantaVerifyRunner {
    pub fn new(config: AnantaVerifyConfig) -> Self {
        Self { config }
    }

    /// Run the full ANANTA verification suite.
    pub fn run(
        &self,
        report: &mut ValidationReport,
        _engine: &mut VerificationEngine,
        subsystem_state: &AnantaSubsystemState,
    ) -> AnantaVerifyResult {
        let mut sentinel = SubsystemResult::new("ananta.sentinel");
        let mut phoenix = SubsystemResult::new("ananta.phoenix");
        let mut vault = SubsystemResult::new("ananta.vault");
        let mut adapter = SubsystemResult::new("ananta.adapter");
        let mut ovaph = SubsystemResult::new("ananta.ovaph");

        // ── Sentinel ──
        if !self
            .config
            .skip_subsystems
            .contains(&"sentinel".to_string())
        {
            self.run_sentinel_specs(report, &subsystem_state.sentinel, &mut sentinel);
        }

        // ── Phoenix ──
        if !self.config.skip_subsystems.contains(&"phoenix".to_string()) {
            self.run_phoenix_specs(report, &subsystem_state.phoenix, &mut phoenix);
        }

        // ── Vault ──
        if !self.config.skip_subsystems.contains(&"vault".to_string()) {
            self.run_vault_specs(report, &subsystem_state.vault, &mut vault);
        }

        // ── Adapter ──
        if !self.config.skip_subsystems.contains(&"adapter".to_string()) {
            self.run_adapter_specs(report, &subsystem_state.adapter, &mut adapter);
        }

        // ── OVAPH ──
        if !self.config.skip_subsystems.contains(&"ovaph".to_string()) {
            self.run_ovaph_verification(report, &subsystem_state.ovaph_cycle, &mut ovaph);
        }

        let total_checks =
            sentinel.total + phoenix.total + vault.total + adapter.total + ovaph.total;
        let total_passed =
            sentinel.passed + phoenix.passed + vault.passed + adapter.passed + ovaph.passed;
        let total_failed =
            sentinel.failed + phoenix.failed + vault.failed + adapter.failed + ovaph.failed;

        AnantaVerifyResult {
            sentinel_results: sentinel,
            phoenix_results: phoenix,
            vault_results: vault,
            adapter_results: adapter,
            ovaph_results: ovaph,
            total_checks,
            total_passed,
            total_failed,
        }
    }

    // ── Sentinel subsystem runner ──
    fn run_sentinel_specs(
        &self,
        report: &mut ValidationReport,
        state: &SentinelState,
        result: &mut SubsystemResult,
    ) {
        let specs = SentinelSpecs::all();
        for spec in &specs {
            let observed = match spec.check_name.as_str() {
                "sentinel-decision-drift" => serde_json::json!(state.decision_drift),
                "sentinel-policy-drift" => serde_json::json!(state.policy_drift),
                "sentinel-learning-drift" => serde_json::json!(state.learning_drift),
                "sentinel-runtime-drift" => serde_json::json!(state.runtime_drift),
                "sentinel-integrity-drift" => serde_json::json!(state.integrity_drift),
                "sentinel-configuration-drift" => serde_json::json!(state.configuration_drift),
                _ => serde_json::json!(null),
            };

            let input = serde_json::json!({"subsystem": "sentinel"});
            let system_state = serde_json::json!({"tolerance": self.config.max_drift_tolerance});
            self.run_single_spec(report, spec, observed, input, system_state, result);
        }
    }

    // ── Phoenix subsystem runner ──
    fn run_phoenix_specs(
        &self,
        report: &mut ValidationReport,
        state: &PhoenixState,
        result: &mut SubsystemResult,
    ) {
        let specs = PhoenixSpecs::all();
        for spec in &specs {
            let observed = match spec.check_name.as_str() {
                "phoenix-recovery-rate" => serde_json::json!(state.recovery_rate),
                "phoenix-rollback-integrity" => serde_json::json!(state.rollback_intact),
                "phoenix-quarantine-active" => serde_json::json!(state.quarantine_active),
                "phoenix-safe-mode-entry" => serde_json::json!(state.safe_mode_entered),
                "phoenix-healing-trust-restore" => serde_json::json!(state.healing_trust_restored),
                "phoenix-recovery-validation" => serde_json::json!(state.recovery_validated),
                _ => serde_json::json!(null),
            };

            let input = serde_json::json!({"subsystem": "phoenix"});
            let system_state =
                serde_json::json!({"integrity_check": self.config.integrity_check_enabled});
            self.run_single_spec(report, spec, observed, input, system_state, result);
        }
    }

    // ── Vault subsystem runner ──
    fn run_vault_specs(
        &self,
        report: &mut ValidationReport,
        state: &VaultState,
        result: &mut SubsystemResult,
    ) {
        let specs = VaultSpecs::all();
        for spec in &specs {
            let observed = match spec.check_name.as_str() {
                "vault-signature-valid" => serde_json::json!(state.signatures_valid),
                "vault-hash-match" => serde_json::json!(state.hashes_match),
                "vault-secret-integrity" => serde_json::json!(state.secrets_intact),
                "vault-attestation-valid" => serde_json::json!(state.attestations_valid),
                "vault-trust-chain-intact" => serde_json::json!(state.trust_chain_intact),
                _ => serde_json::json!(null),
            };

            let input = serde_json::json!({"subsystem": "vault"});
            let system_state =
                serde_json::json!({"trust_chain_depth": self.config.trust_chain_depth});
            self.run_single_spec(report, spec, observed, input, system_state, result);

            // Additional integrity check: run tamper detection on vault items.
            if self.config.integrity_check_enabled && spec.check_name == "vault-trust-chain-intact"
            {
                let corruption_report =
                    CorruptionDetector::detect_trust_chain_corruption(&state.trust_chain_links);
                if corruption_report.corrupt {
                    result.record_fail("vault-trust-chain-corruption-detection");
                } else {
                    result.record_pass("vault-trust-chain-corruption-detection");
                }
            }
        }
    }

    // ── Adapter subsystem runner ──
    fn run_adapter_specs(
        &self,
        report: &mut ValidationReport,
        state: &AdapterState,
        result: &mut SubsystemResult,
    ) {
        let specs = AdapterSpecs::all();
        for spec in &specs {
            let observed = match spec.check_name.as_str() {
                "adapter-dynamic-routing-correct" => serde_json::json!(state.routing_correct),
                "adapter-pipeline-override-active" => serde_json::json!(state.override_active),
                "adapter-emergency-mode-entered" => serde_json::json!(state.emergency_mode_entered),
                "adapter-adaptive-rings-bounded" => serde_json::json!(state.ring_adjustment_drift),
                _ => serde_json::json!(null),
            };

            let input = serde_json::json!({"subsystem": "adapter"});
            let system_state = serde_json::json!({"tolerance": 0.1});
            self.run_single_spec(report, spec, observed, input, system_state, result);
        }
    }

    // ── OVAPH verification ──
    fn run_ovaph_verification(
        &self,
        report: &mut ValidationReport,
        cycle_data: &OvaphCycleData,
        result: &mut SubsystemResult,
    ) {
        let mut ovaph_fails = 0u64;

        OvaphVerifier::verify_observe(report, &cycle_data.observed_state);
        let observe_pass = report
            .evidence
            .iter()
            .rev()
            .find(|e| e.check_name == "ovaph-observe-state-complete")
            .map_or(false, |e| e.verdict.is_pass());
        if observe_pass {
            result.record_pass("ovaph-observe");
        } else {
            result.record_fail("ovaph-observe");
            ovaph_fails += 1;
        }

        OvaphVerifier::verify_verify(
            report,
            &cycle_data.anomalies_detected,
            &cycle_data.expected_anomalies,
        );
        let verify_pass = report
            .evidence
            .iter()
            .rev()
            .find(|e| e.check_name == "ovaph-verify-anomalies-detected")
            .map_or(false, |e| e.verdict.is_pass());
        if verify_pass {
            result.record_pass("ovaph-verify");
        } else {
            result.record_fail("ovaph-verify");
            ovaph_fails += 1;
        }

        OvaphVerifier::verify_attest(report, &cycle_data.attestation);
        let attest_pass = report
            .evidence
            .iter()
            .rev()
            .find(|e| e.check_name == "ovaph-attestation-valid")
            .map_or(false, |e| e.verdict.is_pass());
        if attest_pass {
            result.record_pass("ovaph-attest");
        } else {
            result.record_fail("ovaph-attest");
            ovaph_fails += 1;
        }

        OvaphVerifier::verify_heal(
            report,
            &cycle_data.initial_state,
            &cycle_data.post_heal_state,
        );
        let heal_pass = report
            .evidence
            .iter()
            .rev()
            .find(|e| e.check_name == "ovaph-heal-state-restored")
            .map_or(false, |e| e.verdict.is_pass());
        if heal_pass {
            result.record_pass("ovaph-heal");
        } else {
            result.record_fail("ovaph-heal");
            ovaph_fails += 1;
        }

        OvaphVerifier::verify_prove(report, &cycle_data.proof);
        let prove_pass = report
            .evidence
            .iter()
            .rev()
            .find(|e| e.check_name == "ovaph-proof-generated")
            .map_or(false, |e| e.verdict.is_pass());
        if prove_pass {
            result.record_pass("ovaph-prove");
        } else {
            result.record_fail("ovaph-prove");
            ovaph_fails += 1;
        }

        let _ = ovaph_fails; // used above for branch logic
    }

    // ── Helper: run a single spec and record in the subsystem result ──
    fn run_single_spec(
        &self,
        report: &mut ValidationReport,
        spec: &VerificationSpec,
        observed: Value,
        input: Value,
        system_state: Value,
        result: &mut SubsystemResult,
    ) {
        let pre_count = report.evidence.len();
        verify_and_record(report, spec, observed, input, system_state);
        let post_count = report.evidence.len();

        if post_count > pre_count {
            let last = &report.evidence[post_count - 1];
            if last.verdict.is_pass() {
                result.record_pass(&spec.check_name);
            } else {
                result.record_fail(&spec.check_name);
            }
        } else {
            // If no evidence was recorded (shouldn't happen), count as fail.
            result.record_fail(&spec.check_name);
        }
    }
}

// ────────────────────────────────────────────────────────────────
// Subsystem state inputs — what the runner needs to verify against
// ────────────────────────────────────────────────────────────────

/// Aggregated state of all ANANTA subsystems for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnantaSubsystemState {
    pub sentinel: SentinelState,
    pub phoenix: PhoenixState,
    pub vault: VaultState,
    pub adapter: AdapterState,
    pub ovaph_cycle: OvaphCycleData,
}

/// Sentinel subsystem state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelState {
    pub decision_drift: f64,
    pub policy_drift: f64,
    pub learning_drift: f64,
    pub runtime_drift: f64,
    pub integrity_drift: i64,
    pub configuration_drift: f64,
}

impl Default for SentinelState {
    fn default() -> Self {
        Self {
            decision_drift: 0.0,
            policy_drift: 0.0,
            learning_drift: 0.0,
            runtime_drift: 0.0,
            integrity_drift: 0,
            configuration_drift: 0.0,
        }
    }
}

/// Phoenix subsystem state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoenixState {
    pub recovery_rate: u64,
    pub rollback_intact: bool,
    pub quarantine_active: bool,
    pub safe_mode_entered: bool,
    pub healing_trust_restored: f64,
    pub recovery_validated: bool,
}

impl Default for PhoenixState {
    fn default() -> Self {
        Self {
            recovery_rate: 100,
            rollback_intact: true,
            quarantine_active: true,
            safe_mode_entered: true,
            healing_trust_restored: 0.95,
            recovery_validated: true,
        }
    }
}

/// Vault subsystem state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultState {
    pub signatures_valid: bool,
    pub hashes_match: bool,
    pub secrets_intact: bool,
    pub attestations_valid: bool,
    pub trust_chain_intact: bool,
    pub trust_chain_links: Vec<Value>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            signatures_valid: true,
            hashes_match: true,
            secrets_intact: true,
            attestations_valid: true,
            trust_chain_intact: true,
            trust_chain_links: Vec::new(),
        }
    }
}

/// Adapter subsystem state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterState {
    pub routing_correct: bool,
    pub override_active: bool,
    pub emergency_mode_entered: bool,
    pub ring_adjustment_drift: f64,
}

impl Default for AdapterState {
    fn default() -> Self {
        Self {
            routing_correct: true,
            override_active: true,
            emergency_mode_entered: true,
            ring_adjustment_drift: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::verification::{VerificationConfig, VerificationEngine};

    fn make_report() -> ValidationReport {
        ValidationReport::new("d2-ananta-test", vec!["D2".to_string()])
    }

    fn make_engine() -> VerificationEngine {
        VerificationEngine::new(VerificationConfig::fast_iter())
    }

    fn clean_state() -> AnantaSubsystemState {
        AnantaSubsystemState {
            sentinel: SentinelState::default(),
            phoenix: PhoenixState::default(),
            vault: VaultState::default(),
            adapter: AdapterState::default(),
            ovaph_cycle: OvaphCycleData::clean(),
        }
    }

    #[test]
    fn runner_clean_state_all_pass() {
        let config = AnantaVerifyConfig::default();
        let runner = AnantaVerifyRunner::new(config);
        let mut report = make_report();
        let mut engine = make_engine();
        let state = clean_state();

        let result = runner.run(&mut report, &mut engine, &state);
        assert!(result.is_clean());
        assert!(result.total_checks > 0);
        assert_eq!(result.total_passed, result.total_checks);
        assert_eq!(result.total_failed, 0);
    }

    #[test]
    fn runner_skip_subsystems() {
        let config = AnantaVerifyConfig {
            skip_subsystems: vec!["sentinel".to_string(), "vault".to_string()],
            ..Default::default()
        };
        let runner = AnantaVerifyRunner::new(config);
        let mut report = make_report();
        let mut engine = make_engine();
        let state = clean_state();

        let result = runner.run(&mut report, &mut engine, &state);
        // Sentinel and vault should have zero checks.
        assert_eq!(result.sentinel_results.total, 0);
        assert_eq!(result.vault_results.total, 0);
        // Phoenix, adapter, ovaph should still run.
        assert!(result.phoenix_results.total > 0);
        assert!(result.adapter_results.total > 0);
    }

    #[test]
    fn subsystem_result_tracking() {
        let mut result = SubsystemResult::new("test");
        result.record_pass("check-1");
        result.record_pass("check-2");
        result.record_fail("check-3");
        assert_eq!(result.total, 3);
        assert_eq!(result.passed, 2);
        assert_eq!(result.failed, 1);
        assert!(!result.is_clean());
        assert_eq!(result.failed_checks, vec!["check-3"]);
    }

    #[test]
    fn sentinel_drift_failure_detected() {
        let state = AnantaSubsystemState {
            sentinel: SentinelState {
                integrity_drift: 1, // Non-zero = tampered
                ..Default::default()
            },
            ..clean_state()
        };
        let runner = AnantaVerifyRunner::new(AnantaVerifyConfig::default());
        let mut report = make_report();
        let mut engine = make_engine();

        let result = runner.run(&mut report, &mut engine, &state);
        assert!(!result.sentinel_results.is_clean());
        assert!(result
            .sentinel_results
            .failed_checks
            .contains(&"sentinel-integrity-drift".to_string()));
    }

    #[test]
    fn all_failed_checks_aggregation() {
        let state = AnantaSubsystemState {
            sentinel: SentinelState {
                decision_drift: 0.5, // Way beyond tolerance
                ..Default::default()
            },
            phoenix: PhoenixState {
                recovery_rate: 50, // Below 100
                ..Default::default()
            },
            ..clean_state()
        };
        let runner = AnantaVerifyRunner::new(AnantaVerifyConfig::default());
        let mut report = make_report();
        let mut engine = make_engine();

        let result = runner.run(&mut report, &mut engine, &state);
        let fails = result.all_failed_checks();
        assert!(fails.len() >= 2);
    }
}
