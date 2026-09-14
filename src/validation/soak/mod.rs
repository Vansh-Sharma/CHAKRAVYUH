// Soak Framework — D6 Module Root
//
// Long-duration soak testing framework for detecting memory leaks,
// resource exhaustion, behavioral drift, and health degradation.
//
// Architecture:
//   memory_leak_detector.rs — MemoryLeakDetector, LeakAnalysis (linear regression growth analysis)
//   resource_tracker.rs     — ResourceTracker, ResourceSummary (trend detection, exhaustion alerts)
//   drift_detector.rs       — DriftDetector, DriftReport (z-score window comparison)
//   health_monitor.rs        — SoakHealthMonitor, IncidentSummary (incident tracking, uptime)
//   soak_runner.rs          — SoakRunner, SoakResult, SoakSample (unified entry point)

pub mod drift_detector;
pub mod health_monitor;
pub mod memory_leak_detector;
pub mod resource_tracker;
pub mod soak_runner;

pub use drift_detector::{DriftConfig, DriftDetector, DriftReport, DriftWindow, WindowMetric};
pub use health_monitor::{HealthCheck, HealthIncident, IncidentSummary, SoakHealthMonitor};
pub use memory_leak_detector::{
    LeakAnalysis, LeakDetectorConfig, LeakReport, MemoryLeakDetector, MemorySample,
};
pub use resource_tracker::{
    ResourceAlert, ResourceLimits, ResourceSample, ResourceSummary, ResourceTracker,
};
pub use soak_runner::{SoakConfig, SoakResult, SoakRunner, SoakSample};
