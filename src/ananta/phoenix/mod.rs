// ANANTA Phoenix — Autonomous Recovery Intelligence
//
// Phoenix doesn't just heal. It PLANS recovery.
//
// Recovery pipeline:
//   Threat detected → Impact Analysis → Choose Strategy →
//   Execute → Verify → Validate → Audit
//
// Strategies:
//   - Restart: restart a ring/subsystem
//   - Rollback: revert config/policy to last-known-good
//   - Quarantine: isolate a degraded component
//   - Observe: do nothing but monitor more closely
//   - Escalate: alert human operator

pub mod strategies;
pub mod recovery_history;
pub mod planner;
pub mod recovery_simulator;
pub mod rollback_engine;

pub use strategies::{RecoveryOutcome, RecoveryStrategy, RecoveryAction, RecoveryResult};
pub use recovery_history::RecoveryHistory;
pub use planner::RecoveryPlanner;
pub use recovery_simulator::*;