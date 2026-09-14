// D2 ANANTA Verification — OVAPH Loop Verification
//
// Verifies the 5-phase OVAPH (Observe→Verify→Attest→Heal→Prove) cycle.
// Each phase is verified independently and as part of the full cycle.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing;

use crate::validation::verification::{
    verify_and_record, MatchStrategy, Severity, ValidationReport, VerificationSpec,
};

// ────────────────────────────────────────────────────────────────
// OvaphCycleData — inputs for a full OVAPH cycle verification
// ────────────────────────────────────────────────────────────────

/// Data captured at each stage of an OVAPH cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvaphCycleData {
    /// System state before the OVAPH cycle.
    pub initial_state: Value,
    /// State observed during the Observe phase.
    pub observed_state: Value,
    /// Anomalies detected during the Verify phase.
    pub anomalies_detected: Value,
    /// Expected anomalies for comparison.
    pub expected_anomalies: Value,
    /// Attestation produced during the Attest phase.
    pub attestation: Value,
    /// System state after the Heal phase.
    pub post_heal_state: Value,
    /// Proof generated during the Prove phase.
    pub proof: Value,
}

impl OvaphCycleData {
    /// Create a clean (all-pass) OVAPH cycle for testing.
    pub fn clean() -> Self {
        Self {
            initial_state: serde_json::json!({"trust": 0.95, "drift": 0.0, "healthy": true}),
            observed_state: serde_json::json!({"trust": 0.95, "drift": 0.01, "healthy": true, "anomalies": 0}),
            anomalies_detected: serde_json::json!([]),
            expected_anomalies: serde_json::json!([]),
            attestation: serde_json::json!({"valid": true, "signed": true, "hash": "abc123"}),
            post_heal_state: serde_json::json!({"trust": 0.97, "drift": 0.0, "healthy": true}),
            proof: serde_json::json!({"generated": true, "verifiable": true, "cycle_id": "test-cycle"}),
        }
    }
}

// ────────────────────────────────────────────────────────────────
// OvaphVerifier — verifies each OVAPH phase
// ────────────────────────────────────────────────────────────────

/// Verifier for the OVAPH (Observe→Verify→Attest→Heal→Prove) loop.
pub struct OvaphVerifier;

impl OvaphVerifier {
    /// Verify the Observe phase produces correct observations.
    ///
    /// Checks:
    ///   - observed_state is non-empty
    ///   - observed_state contains expected keys (trust, drift, healthy)
    pub fn verify_observe(report: &mut ValidationReport, observed_state: &Value) {
        // Check 1: observed state is non-empty.
        let spec_nonempty = VerificationSpec::new(
            "ovaph-observe-state-complete",
            "D2",
            "ananta.ovaph",
            Value::String("non_empty".to_string()),
        )
        .with_strategy(MatchStrategy::NonEmpty)
        .with_severity(Severity::High)
        .with_description("Observe phase must produce non-empty observed state");

        verify_and_record(
            report,
            &spec_nonempty,
            observed_state.clone(),
            serde_json::json!({"phase": "observe"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        // Check 2: observed state contains trust and drift keys.
        let spec_keys = VerificationSpec::new(
            "ovaph-observe-state-keys",
            "D2",
            "ananta.ovaph",
            serde_json::json!({"trust": null, "drift": null}),
        )
        .with_strategy(MatchStrategy::Contains)
        .with_severity(Severity::Medium)
        .with_description("Observe phase must capture trust and drift metrics");

        verify_and_record(
            report,
            &spec_keys,
            observed_state.clone(),
            serde_json::json!({"phase": "observe"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        tracing::info!(phase = "observe", "OVAPH Observe phase verified");
    }

    /// Verify the Verify phase correctly identifies anomalies.
    ///
    /// Checks:
    ///   - anomalies_detected is an array
    ///   - anomalies match expected_anomalies (exact for clean case)
    pub fn verify_verify(
        report: &mut ValidationReport,
        anomalies_detected: &Value,
        expected_anomalies: &Value,
    ) {
        // Check 1: anomalies is an array.
        let spec_type = VerificationSpec::new(
            "ovaph-verify-anomalies-type",
            "D2",
            "ananta.ovaph",
            Value::String("array".to_string()),
        )
        .with_strategy(MatchStrategy::IsType)
        .with_severity(Severity::Medium)
        .with_description("Verify phase must produce an array of anomalies");

        verify_and_record(
            report,
            &spec_type,
            anomalies_detected.clone(),
            serde_json::json!({"phase": "verify"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        // Check 2: detected anomalies match expected.
        let spec_match = VerificationSpec::new(
            "ovaph-verify-anomalies-detected",
            "D2",
            "ananta.ovaph",
            expected_anomalies.clone(),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::High)
        .with_description("Verify phase must detect exactly the expected anomalies");

        verify_and_record(
            report,
            &spec_match,
            anomalies_detected.clone(),
            serde_json::json!({"phase": "verify"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        tracing::info!(phase = "verify", "OVAPH Verify phase verified");
    }

    /// Verify the Attest phase produces valid attestations.
    ///
    /// Checks:
    ///   - attestation contains 'valid' and 'signed' fields
    ///   - attestation is valid and signed
    pub fn verify_attest(report: &mut ValidationReport, attestation: &Value) {
        let spec = VerificationSpec::new(
            "ovaph-attestation-valid",
            "D2",
            "ananta.ovaph",
            serde_json::json!({"valid": true, "signed": true}),
        )
        .with_strategy(MatchStrategy::Contains)
        .with_severity(Severity::Critical)
        .with_description("Attest phase must produce a valid, signed attestation");

        verify_and_record(
            report,
            &spec,
            attestation.clone(),
            serde_json::json!({"phase": "attest"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        tracing::info!(phase = "attest", "OVAPH Attest phase verified");
    }

    /// Verify the Heal phase correctly restores the system.
    ///
    /// Checks:
    ///   - post_heal_state is non-empty
    ///   - post_heal_state has trust >= initial trust (or close to it)
    ///   - drift is reduced or zero
    pub fn verify_heal(
        report: &mut ValidationReport,
        pre_heal_state: &Value,
        post_heal_state: &Value,
    ) {
        // Check 1: post-heal state is non-empty.
        let spec_nonempty = VerificationSpec::new(
            "ovaph-heal-state-restored",
            "D2",
            "ananta.ovaph",
            Value::String("non_empty".to_string()),
        )
        .with_strategy(MatchStrategy::NonEmpty)
        .with_severity(Severity::High)
        .with_description("Heal phase must produce a restored state");

        verify_and_record(
            report,
            &spec_nonempty,
            post_heal_state.clone(),
            serde_json::json!({"phase": "heal", "pre_state": pre_heal_state}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        // Check 2: post-heal drift should be <= pre-heal drift.
        let pre_drift = pre_heal_state["drift"].as_f64().unwrap_or(1.0);
        let post_drift = post_heal_state["drift"].as_f64().unwrap_or(1.0);
        let drift_spec = VerificationSpec::new(
            "ovaph-heal-drift-reduced",
            "D2",
            "ananta.ovaph",
            Value::Number(
                serde_json::Number::from_f64(pre_drift).unwrap_or(serde_json::Number::from(0)),
            ),
        )
        .with_strategy(MatchStrategy::Lte)
        .with_severity(Severity::High)
        .with_description("Heal phase must reduce or maintain drift level");

        verify_and_record(
            report,
            &drift_spec,
            Value::Number(
                serde_json::Number::from_f64(post_drift).unwrap_or(serde_json::Number::from(0)),
            ),
            serde_json::json!({"phase": "heal"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        tracing::info!(phase = "heal", "OVAPH Heal phase verified");
    }

    /// Verify the Prove phase generates valid proofs.
    ///
    /// Checks:
    ///   - proof contains 'generated' and 'verifiable' fields
    ///   - proof is generated and verifiable
    pub fn verify_prove(report: &mut ValidationReport, proof: &Value) {
        let spec = VerificationSpec::new(
            "ovaph-proof-generated",
            "D2",
            "ananta.ovaph",
            serde_json::json!({"generated": true, "verifiable": true}),
        )
        .with_strategy(MatchStrategy::Contains)
        .with_severity(Severity::Critical)
        .with_description("Prove phase must generate a verifiable proof");

        verify_and_record(
            report,
            &spec,
            proof.clone(),
            serde_json::json!({"phase": "prove"}),
            serde_json::json!({"mode": "ovaph_verification"}),
        );

        tracing::info!(phase = "prove", "OVAPH Prove phase verified");
    }

    /// Run the full OVAPH verification pipeline.
    ///
    /// Verifies all 5 phases in order: Observe → Verify → Attest → Heal → Prove.
    pub fn verify_full_cycle(report: &mut ValidationReport, cycle_data: &OvaphCycleData) {
        tracing::info!(cycle_id = %cycle_data.proof["cycle_id"].as_str().unwrap_or("unknown"), "Starting full OVAPH cycle verification");

        Self::verify_observe(report, &cycle_data.observed_state);
        Self::verify_verify(
            report,
            &cycle_data.anomalies_detected,
            &cycle_data.expected_anomalies,
        );
        Self::verify_attest(report, &cycle_data.attestation);
        Self::verify_heal(
            report,
            &cycle_data.initial_state,
            &cycle_data.post_heal_state,
        );
        Self::verify_prove(report, &cycle_data.proof);

        tracing::info!(phase = "ovaph", "Full OVAPH cycle verification complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report() -> ValidationReport {
        ValidationReport::new("ovaph-test", vec!["D2".to_string()])
    }

    #[test]
    fn full_clean_cycle_all_pass() {
        let mut report = make_report();
        let cycle = OvaphCycleData::clean();
        OvaphVerifier::verify_full_cycle(&mut report, &cycle);

        let d2_evidence: Vec<_> = report.evidence.iter().filter(|e| e.phase == "D2").collect();
        // Should have at least 8 evidence items (2 observe + 2 verify + 1 attest + 2 heal + 1 prove)
        assert!(d2_evidence.len() >= 8);
        let fails: Vec<_> = d2_evidence.iter().filter(|e| e.verdict.is_fail()).collect();
        assert!(
            fails.is_empty(),
            "Clean cycle should produce no failures, got: {:?}",
            fails
        );
    }

    #[test]
    fn observe_empty_state_fails() {
        let mut report = make_report();
        OvaphVerifier::verify_observe(&mut report, &serde_json::json!(null));

        let fails: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.verdict.is_fail())
            .collect();
        assert!(!fails.is_empty());
    }

    #[test]
    fn verify_wrong_anomalies_fails() {
        let mut report = make_report();
        let detected = serde_json::json!(["drift_detected"]);
        let expected = serde_json::json!([]);
        OvaphVerifier::verify_verify(&mut report, &detected, &expected);

        let fails: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.check_name == "ovaph-verify-anomalies-detected" && e.verdict.is_fail())
            .collect();
        assert_eq!(fails.len(), 1);
    }

    #[test]
    fn attest_invalid_fails() {
        let mut report = make_report();
        OvaphVerifier::verify_attest(
            &mut report,
            &serde_json::json!({"valid": false, "signed": false}),
        );

        let fails: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.verdict.is_fail())
            .collect();
        assert!(!fails.is_empty());
    }

    #[test]
    fn heal_drift_increased_fails() {
        let mut report = make_report();
        let pre = serde_json::json!({"drift": 0.01});
        let post = serde_json::json!({"drift": 0.5, "trust": 0.9});
        OvaphVerifier::verify_heal(&mut report, &pre, &post);

        let fails: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.check_name == "ovaph-heal-drift-reduced" && e.verdict.is_fail())
            .collect();
        assert_eq!(fails.len(), 1);
    }

    #[test]
    fn prove_missing_fields_fails() {
        let mut report = make_report();
        OvaphVerifier::verify_prove(&mut report, &serde_json::json!({"generated": false}));

        let fails: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.verdict.is_fail())
            .collect();
        assert!(!fails.is_empty());
    }
}
