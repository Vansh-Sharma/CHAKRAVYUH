// ANANTA Sentinel — Continuous Integrity Verification
//
// Sentinel monitors 10 types of drift:
//   1. Decision drift     — allow/deny ratio shifting
//   2. Policy drift       — policy rules changing unexpectedly
//   3. Model drift        — ring behavior patterns changing
//   4. Orchestration drift — pipeline configuration changing
//   5. Learning drift     — threshold/model adaptation going wrong
//   6. Memory drift       — memory access patterns anomalous
//   7. Configuration drift — config changes outside policy
//   8. Plugin drift       — loaded modules changed
//   9. Runtime drift      — performance characteristics changing
//  10. Trust drift       — trust levels degrading
//
// Each drift type uses the same statistical engine:
//   sliding window → Welford's online variance → z-score → alert

pub mod drift;
pub mod drift_analyzer;
pub mod sentinel_wiring;
pub mod trust_state_updater;

pub use drift::{DriftDetector, DriftType, DriftObservation, DriftAlert};
pub use drift_analyzer::*;
pub use trust_state_updater::TrustStateUpdater;