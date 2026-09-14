// D2 ANANTA Verification — Subsystem Verification Specs
//
// Defines VerificationSpec for every ANANTA subsystem:
//   - SentinelSpecs  (6 specs: decision, policy, learning, runtime, integrity, configuration drift)
//   - PhoenixSpecs   (6 specs: recovery, rollback, quarantine, safe_mode, healing, validation)
//   - VaultSpecs     (5 specs: signature, hash, secret, attestation, trust_chain)
//   - AdapterSpecs   (4 specs: dynamic_routing, pipeline_override, emergency_mode, adaptive_rings)

use serde_json::Value;

use crate::validation::verification::{MatchStrategy, Severity, VerificationSpec};

// ────────────────────────────────────────────────────────────────
// Sentinel Specs — Drift Detection
// ────────────────────────────────────────────────────────────────

/// Verification specs for the Sentinel subsystem (drift detection).
pub struct SentinelSpecs;

impl SentinelSpecs {
    /// Decision drift: risk score drift must be within tolerance.
    pub fn decision_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-decision-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.05 })
        .with_severity(Severity::High)
        .with_description("Decision drift (risk score shift) must be < 0.05")
        .with_tags(vec!["drift".to_string(), "sentinel".to_string()])
    }

    /// Policy drift: policy threshold changes must be within tolerance.
    pub fn policy_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-policy-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.03 })
        .with_severity(Severity::High)
        .with_description("Policy threshold drift must be < 0.03")
        .with_tags(vec!["drift".to_string(), "sentinel".to_string()])
    }

    /// Learning drift: model weight changes must be bounded.
    pub fn learning_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-learning-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.1 })
        .with_severity(Severity::Medium)
        .with_description("Learning weight drift must be < 0.1")
        .with_tags(vec![
            "drift".to_string(),
            "sentinel".to_string(),
            "learning".to_string(),
        ])
    }

    /// Runtime drift: latency/throughput deviation must be bounded.
    pub fn runtime_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-runtime-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.15 })
        .with_severity(Severity::Medium)
        .with_description("Runtime performance drift must be < 0.15")
        .with_tags(vec![
            "drift".to_string(),
            "sentinel".to_string(),
            "runtime".to_string(),
        ])
    }

    /// Integrity drift: binary/config hash changes must be zero.
    pub fn integrity_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-integrity-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from(0)),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("Integrity hash drift must be exactly zero (no tampering)")
        .with_tags(vec![
            "drift".to_string(),
            "sentinel".to_string(),
            "integrity".to_string(),
        ])
    }

    /// Configuration drift: config field changes must be within tolerance.
    pub fn configuration_drift() -> VerificationSpec {
        VerificationSpec::new(
            "sentinel-configuration-drift",
            "D2",
            "ananta.sentinel",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.02 })
        .with_severity(Severity::High)
        .with_description("Configuration drift must be < 0.02")
        .with_tags(vec![
            "drift".to_string(),
            "sentinel".to_string(),
            "config".to_string(),
        ])
    }

    /// All sentinel specs.
    pub fn all() -> Vec<VerificationSpec> {
        vec![
            Self::decision_drift(),
            Self::policy_drift(),
            Self::learning_drift(),
            Self::runtime_drift(),
            Self::integrity_drift(),
            Self::configuration_drift(),
        ]
    }
}

// ────────────────────────────────────────────────────────────────
// Phoenix Specs — Recovery & Rollback
// ────────────────────────────────────────────────────────────────

/// Verification specs for the Phoenix subsystem (recovery & rollback).
pub struct PhoenixSpecs;

impl PhoenixSpecs {
    /// Recovery: recovery success rate must be 100%.
    pub fn recovery() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-recovery-rate",
            "D2",
            "ananta.phoenix",
            Value::Number(serde_json::Number::from(100)),
        )
        .with_strategy(MatchStrategy::Gte)
        .with_severity(Severity::Critical)
        .with_description("Recovery success rate must be >= 100% (all recoveries succeed)")
        .with_tags(vec!["recovery".to_string(), "phoenix".to_string()])
    }

    /// Rollback: rollback must restore to the exact previous state.
    pub fn rollback() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-rollback-integrity",
            "D2",
            "ananta.phoenix",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("Rollback must restore to the exact previous state hash")
        .with_tags(vec!["rollback".to_string(), "phoenix".to_string()])
    }

    /// Quarantine: quarantine must isolate the corrupted component.
    pub fn quarantine() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-quarantine-active",
            "D2",
            "ananta.phoenix",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::High)
        .with_description("Quarantine must be active for all corrupted components")
        .with_tags(vec!["quarantine".to_string(), "phoenix".to_string()])
    }

    /// Safe mode: system must enter safe mode when critical failure is detected.
    pub fn safe_mode() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-safe-mode-entry",
            "D2",
            "ananta.phoenix",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("System must enter safe mode on critical failure")
        .with_tags(vec!["safe-mode".to_string(), "phoenix".to_string()])
    }

    /// Healing: healing action must restore trust score above minimum.
    pub fn healing() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-healing-trust-restore",
            "D2",
            "ananta.phoenix",
            Value::Number(
                serde_json::Number::from_f64(0.75).unwrap_or(serde_json::Number::from(1)),
            ),
        )
        .with_strategy(MatchStrategy::Gte)
        .with_severity(Severity::High)
        .with_description("Healing must restore trust score >= 0.75")
        .with_tags(vec!["healing".to_string(), "phoenix".to_string()])
    }

    /// Validation: recovery validation must confirm system consistency.
    pub fn validation() -> VerificationSpec {
        VerificationSpec::new(
            "phoenix-recovery-validation",
            "D2",
            "ananta.phoenix",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::High)
        .with_description("Recovery validation must confirm post-recovery consistency")
        .with_tags(vec!["validation".to_string(), "phoenix".to_string()])
    }

    /// All phoenix specs.
    pub fn all() -> Vec<VerificationSpec> {
        vec![
            Self::recovery(),
            Self::rollback(),
            Self::quarantine(),
            Self::safe_mode(),
            Self::healing(),
            Self::validation(),
        ]
    }
}

// ────────────────────────────────────────────────────────────────
// Vault Specs — Anchor / Trust / Crypto
// ────────────────────────────────────────────────────────────────

/// Verification specs for the Vault/Anchor subsystem (trust chain, crypto).
pub struct VaultSpecs;

impl VaultSpecs {
    /// Signature validation: all signatures must verify correctly.
    pub fn signature_validation() -> VerificationSpec {
        VerificationSpec::new(
            "vault-signature-valid",
            "D2",
            "ananta.vault",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("All cryptographic signatures must verify correctly")
        .with_tags(vec![
            "crypto".to_string(),
            "vault".to_string(),
            "signature".to_string(),
        ])
    }

    /// Hash verification: computed hashes must match expected hashes.
    pub fn hash_verification() -> VerificationSpec {
        VerificationSpec::new("vault-hash-match", "D2", "ananta.vault", Value::Bool(true))
            .with_strategy(MatchStrategy::Exact)
            .with_severity(Severity::Critical)
            .with_description("All integrity hashes must match expected values")
            .with_tags(vec![
                "crypto".to_string(),
                "vault".to_string(),
                "hash".to_string(),
            ])
    }

    /// Secret integrity: encrypted secrets must decrypt correctly.
    pub fn secret_integrity() -> VerificationSpec {
        VerificationSpec::new(
            "vault-secret-integrity",
            "D2",
            "ananta.vault",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("All encrypted secrets must decrypt and roundtrip correctly")
        .with_tags(vec![
            "crypto".to_string(),
            "vault".to_string(),
            "secrets".to_string(),
        ])
    }

    /// Attestation: attestation reports must be valid and unexpired.
    pub fn attestation() -> VerificationSpec {
        VerificationSpec::new(
            "vault-attestation-valid",
            "D2",
            "ananta.vault",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("All attestation reports must be valid and unexpired")
        .with_tags(vec!["attestation".to_string(), "vault".to_string()])
    }

    /// Trust chain: trust chain links must be unbroken.
    pub fn trust_chain() -> VerificationSpec {
        VerificationSpec::new(
            "vault-trust-chain-intact",
            "D2",
            "ananta.vault",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("Trust chain must have no broken links")
        .with_tags(vec!["trust-chain".to_string(), "vault".to_string()])
    }

    /// All vault specs.
    pub fn all() -> Vec<VerificationSpec> {
        vec![
            Self::signature_validation(),
            Self::hash_verification(),
            Self::secret_integrity(),
            Self::attestation(),
            Self::trust_chain(),
        ]
    }
}

// ────────────────────────────────────────────────────────────────
// Adapter Specs — Orchestration & Dynamic Pipeline
// ────────────────────────────────────────────────────────────────

/// Verification specs for the Adapter subsystem (orchestration, pipeline).
pub struct AdapterSpecs;

impl AdapterSpecs {
    /// Dynamic routing: routing decisions must match expected targets.
    pub fn dynamic_routing() -> VerificationSpec {
        VerificationSpec::new(
            "adapter-dynamic-routing-correct",
            "D2",
            "ananta.adapter",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::High)
        .with_description("Dynamic routing must route to the expected ring/target")
        .with_tags(vec!["routing".to_string(), "adapter".to_string()])
    }

    /// Pipeline override: emergency overrides must take effect.
    pub fn pipeline_override() -> VerificationSpec {
        VerificationSpec::new(
            "adapter-pipeline-override-active",
            "D2",
            "ananta.adapter",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::High)
        .with_description("Emergency pipeline override must be active when triggered")
        .with_tags(vec!["override".to_string(), "adapter".to_string()])
    }

    /// Emergency mode: system must correctly enter emergency mode.
    pub fn emergency_mode() -> VerificationSpec {
        VerificationSpec::new(
            "adapter-emergency-mode-entered",
            "D2",
            "ananta.adapter",
            Value::Bool(true),
        )
        .with_strategy(MatchStrategy::Exact)
        .with_severity(Severity::Critical)
        .with_description("Emergency mode must be entered when triggered")
        .with_tags(vec!["emergency".to_string(), "adapter".to_string()])
    }

    /// Adaptive rings: ring priority adjustments must be within expected bounds.
    pub fn adaptive_rings() -> VerificationSpec {
        VerificationSpec::new(
            "adapter-adaptive-rings-bounded",
            "D2",
            "ananta.adapter",
            Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(serde_json::Number::from(0))),
        )
        .with_strategy(MatchStrategy::WithinTolerance { tolerance: 0.1 })
        .with_severity(Severity::Medium)
        .with_description("Adaptive ring priority adjustments must be within 0.1 tolerance")
        .with_tags(vec!["rings".to_string(), "adapter".to_string()])
    }

    /// All adapter specs.
    pub fn all() -> Vec<VerificationSpec> {
        vec![
            Self::dynamic_routing(),
            Self::pipeline_override(),
            Self::emergency_mode(),
            Self::adaptive_rings(),
        ]
    }
}

// ────────────────────────────────────────────────────────────────
// Summary: total spec count
// ────────────────────────────────────────────────────────────────

/// Returns the total number of ANANTA verification specs.
pub fn total_spec_count() -> usize {
    SentinelSpecs::all().len()
        + PhoenixSpecs::all().len()
        + VaultSpecs::all().len()
        + AdapterSpecs::all().len()
}

/// Returns all ANANTA verification specs across all subsystems.
pub fn all_specs() -> Vec<VerificationSpec> {
    let mut specs = Vec::new();
    specs.extend(SentinelSpecs::all());
    specs.extend(PhoenixSpecs::all());
    specs.extend(VaultSpecs::all());
    specs.extend(AdapterSpecs::all());
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_spec_count() {
        let specs = SentinelSpecs::all();
        assert_eq!(specs.len(), 6);
        for spec in &specs {
            assert_eq!(spec.phase, "D2");
            assert_eq!(spec.subsystem, "ananta.sentinel");
        }
    }

    #[test]
    fn phoenix_spec_count() {
        let specs = PhoenixSpecs::all();
        assert_eq!(specs.len(), 6);
        for spec in &specs {
            assert_eq!(spec.phase, "D2");
            assert_eq!(spec.subsystem, "ananta.phoenix");
        }
    }

    #[test]
    fn vault_spec_count() {
        let specs = VaultSpecs::all();
        assert_eq!(specs.len(), 5);
        for spec in &specs {
            assert_eq!(spec.phase, "D2");
            assert_eq!(spec.subsystem, "ananta.vault");
        }
    }

    #[test]
    fn adapter_spec_count() {
        let specs = AdapterSpecs::all();
        assert_eq!(specs.len(), 4);
        for spec in &specs {
            assert_eq!(spec.phase, "D2");
            assert_eq!(spec.subsystem, "ananta.adapter");
        }
    }

    #[test]
    fn total_specs_correct() {
        assert_eq!(total_spec_count(), 21);
        let all = all_specs();
        assert_eq!(all.len(), 21);
    }

    #[test]
    fn integrity_drift_uses_exact_strategy() {
        let spec = SentinelSpecs::integrity_drift();
        assert!(matches!(spec.strategy, MatchStrategy::Exact));
        assert_eq!(spec.severity, Severity::Critical);
    }

    #[test]
    fn decision_drift_uses_tolerance() {
        let spec = SentinelSpecs::decision_drift();
        match spec.strategy {
            MatchStrategy::WithinTolerance { tolerance } => {
                assert!((tolerance - 0.05).abs() < f64::EPSILON);
            }
            _ => panic!("Expected WithinTolerance strategy"),
        }
    }

    #[test]
    fn vault_specs_are_critical() {
        for spec in VaultSpecs::all() {
            assert_eq!(spec.severity, Severity::Critical);
        }
    }
}
