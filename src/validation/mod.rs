// Security Validation Platform — Module Root
//
// The Security Validation Platform is CHAKRAVYUH's permanent security laboratory.
// Every future release, new ring, ANANTA change, and policy update must pass
// through this platform before it can ship.
//
// Architecture:
//   D0: Verification Engine — Evidence, Metrics, Audit Trail, Replay, Report
//   D1: Red Team OS — 10 attack generators, mutations, encoders, combinator, runner, regression
//   D2: ANANTA Verification — Sentinel/Phoenix/Vault/Adapter specs, drift injection, corruption detection
//   D3: Security Twin — Predict → Run → Compare → Learn loop
//   D4: Chaos Framework — Fault injection, health monitoring, recovery metrics
//   D5: Performance Framework — Load generation, metrics collection, profiling, report generation
//   D6: Soak Framework — Memory leak detection, resource tracking, drift detection, health monitoring
//   D7: Comparative Research Lab — Benchmark definitions, version comparison, persistent store
//
// Flow:
//   Every phase produces Evidence via the D0 Verification Engine.
//   Evidence chains are tamper-proof (blake3 integrity hashes).
//   Every test produces: Evidence → Metrics → Audit Trail → Replay → Report.

pub mod verification;
pub mod redteam;
pub mod ananta_verify;
pub mod security_twin;
pub mod chaos;
pub mod performance;
pub mod soak;
pub mod comparative;

// Re-export the D0 Verification Engine types — these are the most commonly used.
pub use verification::{
    ChainStatus, Evidence, EvidenceId, MatchStrategy, Metric, MetricSummary,
    ReplayData, RunId, RunMetrics, RunStatus, Severity, ValidationReport,
    VerificationConfig, VerificationEngine, VerificationSpec, Verdict,
    VerdictDistribution, verify_and_record, verify_match,
};
// Backward-compatible aliases
pub use verification::{VerificationConfig as ValidationConfig, VerificationEngine as ValidationEngine};

/// Convenience: start a new validation run with all phases.
pub fn start_full_validation(name: &str) -> ValidationReport {
    ValidationReport::new(
        name,
        vec![
            "D0".to_string(), "D1".to_string(), "D2".to_string(),
            "D3".to_string(), "D4".to_string(), "D5".to_string(),
            "D6".to_string(), "D7".to_string(),
        ],
    )
}

/// Convenience: start a targeted validation run for specific phases.
pub fn start_phase_validation(name: &str, phases: &[&str]) -> ValidationReport {
    ValidationReport::new(
        name,
        phases.iter().map(|s| s.to_string()).collect(),
    )
}