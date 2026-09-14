// Chaos Framework — D4 Module Root
//
// Provides fault injection, health monitoring, cascade detection,
// and recovery metrics for validating system resilience.
//
// Architecture:
//   fault_types.rs    — FaultTarget, FaultType, FaultInjection (all fault definitions)
//   fault_injector.rs — FaultInjector, ActiveFault, FaultSnapshot (inject/release/rollback)
//   health_monitor.rs — HealthMonitor, HealthSample (health tracking, cascade detection)
//   recovery_metrics.rs — RecoveryMetrics, RecoverySummary (per-fault & aggregate summaries)
//   chaos_engine.rs  — ChaosEngine, ChaosScenario, ChaosResult (orchestration)

pub mod chaos_engine;
pub mod fault_injector;
pub mod fault_types;
pub mod health_monitor;
pub mod recovery_metrics;

pub use chaos_engine::{ChaosConfig, ChaosEngine, ChaosResult, ChaosScenario, FaultResult};
pub use fault_injector::{ActiveFault, FaultInjector, FaultSnapshot};
pub use fault_types::{FaultInjection, FaultTarget, FaultType};
pub use health_monitor::{HealthMonitor, HealthSample};
pub use recovery_metrics::{RecoveryMetrics, RecoverySummary};
