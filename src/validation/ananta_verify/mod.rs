// D2 ANANTA Verification — Module Root
//
// Provides verification for the ANANTA Autonomous Trust Plane.
// Covers all subsystems: Sentinel, Phoenix, Vault, Adapter, and the OVAPH loop.
//
// Architecture:
//   specs.rs             — VerificationSpec definitions for all subsystems (21 specs)
//   runner.rs            — AnantaVerifyRunner orchestrates full verification
//   drift_injector.rs    — Controlled drift injection for testing
//   ovaph_verify.rs      — OVAPH (Observe→Verify→Attest→Heal→Prove) cycle verification
//   corruption_detector.rs — Corruption detection and classification

pub mod corruption_detector;
pub mod drift_injector;
pub mod ovaph_verify;
pub mod runner;
pub mod specs;

// Re-export primary types for external consumers.
pub use corruption_detector::{CorruptionDetector, CorruptionReport};
pub use drift_injector::DriftInjector;
pub use ovaph_verify::{OvaphCycleData, OvaphVerifier};
pub use runner::{
    AdapterState, AnantaSubsystemState, AnantaVerifyConfig, AnantaVerifyResult, AnantaVerifyRunner,
    PhoenixState, SentinelState, SubsystemResult, VaultState,
};
pub use specs::{total_spec_count, AdapterSpecs, PhoenixSpecs, SentinelSpecs, VaultSpecs};
