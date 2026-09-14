// Security Twin™ — External-facing operator interface for simulation.
//
// This module is the operator-facing API for the Security Twin™ technology.
// It provides:
//   1. TwinState       — snapshot/restore of the security system state
//   2. Scenario        — attack, recovery, what-if, and replay definitions
//   3. TwinEngine      — runs scenarios against cloned state
//   4. SecurityTwinService — the top-level service that composes all three
//
// IMPORTANT: This module is independent of `crate::ananta`. ANANTA has
// its own internal SecurityTwin (in ananta/simulation/mod.rs). This is
// the external-facing operator interface — a separate module per design.

pub mod engine;
pub mod scenario;
pub mod state;

pub use engine::TwinEngine;
pub use scenario::{
    Scenario, ScenarioMetrics, ScenarioOutcome, ScenarioResult, ScenarioType,
};
pub use state::{StateSnapshot, TwinState};

use std::collections::HashMap;

/// The top-level Security Twin™ service.
///
/// This is the entry point for operators who want to:
/// - Snapshot the current security state
/// - Run what-if / attack / recovery / replay simulations
/// - Compare policies across snapshots
///
/// Composes TwinState (snapshot management) with TwinEngine (scenario execution).
#[derive(Debug, Clone)]
pub struct SecurityTwinService {
    /// Manages ring configuration snapshots.
    state: TwinState,
    /// Executes scenarios against cloned snapshots.
    engine: TwinEngine,
    /// Cached list of available scenario templates.
    scenario_templates: Vec<scenario::Scenario>,
}

impl SecurityTwinService {
    /// Create a new SecurityTwinService.
    pub fn new() -> Self {
        let scenario_templates = vec![
            scenario::jailbreak_bypass_shield(),
            scenario::policy_threshold_change("shield", "threshold", 0.5, 100),
            scenario::ring_restart_recovery("threat"),
            scenario::ring_restart_recovery("identity"),
            scenario::ring_restart_recovery("shield"),
        ];

        tracing::info!(
            templates = scenario_templates.len(),
            "Security Twin™ service initialized"
        );

        Self {
            state: TwinState::new(),
            engine: TwinEngine::new(),
            scenario_templates,
        }
    }

    /// Capture a snapshot of the current ring configurations.
    ///
    /// Operators call this to create a point-in-time digital replica
    /// of the security system state.
    pub fn snapshot(
        &mut self,
        name: &str,
        description: &str,
        ring_configs: HashMap<String, serde_json::Value>,
    ) -> Result<String, String> {
        self.state.capture(name, description, ring_configs)
    }

    /// Run a scenario against the twin state.
    ///
    /// The scenario is executed against a cloned copy of the latest
    /// snapshot so the original state is never modified.
    pub fn run_scenario(
        &self,
        scenario: &scenario::Scenario,
    ) -> Result<scenario::ScenarioResult, String> {
        // Clone the state so the engine can mutate freely.
        let mut state_clone = self.state.clone();
        self.engine.run(scenario, &mut state_clone)
    }

    /// List all available scenario templates.
    pub fn list_scenarios(&self) -> &[scenario::Scenario] {
        &self.scenario_templates
    }

    /// Replay the last N decisions against a modified policy.
    ///
    /// This is a convenience method that creates a StateReplay scenario
    /// and runs it. The `policy_overrides` parameter allows operators
    /// to specify which ring parameters to change before replaying.
    pub fn replay_decisions(
        &self,
        replay_count: u64,
        policy_overrides: serde_json::Value,
        max_outcome_change_rate: f64,
    ) -> Result<scenario::ScenarioResult, String> {
        let scenario = scenario::Scenario::new(
            scenario::ScenarioType::StateReplay,
            "custom_replay",
            "Operator-initiated decision replay with policy modifications",
            serde_json::json!({
                "replay_count": replay_count,
                "policy_overrides": policy_overrides,
                "max_outcome_change_rate": max_outcome_change_rate,
            }),
        );

        let mut state_clone = self.state.clone();
        self.engine.run(&scenario, &mut state_clone)
    }

    /// Compare two policy snapshots and return the diff.
    ///
    /// Both snapshot IDs must exist in the twin state.
    pub fn compare_policies(
        &self,
        before_id: &str,
        after_id: &str,
    ) -> Result<HashMap<String, serde_json::Value>, String> {
        self.state.diff(before_id, after_id)
    }

    /// Get a reference to the underlying TwinState.
    pub fn state(&self) -> &TwinState {
        &self.state
    }

    /// Get a reference to the underlying TwinEngine.
    pub fn engine(&self) -> &TwinEngine {
        &self.engine
    }

    /// Get the number of stored snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.state.len()
    }

    /// Export a snapshot as JSON.
    pub fn export_snapshot(&self, snapshot_id: Option<&str>) -> Result<String, String> {
        self.state.export_json(snapshot_id)
    }

    /// Import a snapshot from JSON.
    pub fn import_snapshot(&mut self, json: &str) -> Result<String, String> {
        self.state.import_json(json)
    }
}

impl Default for SecurityTwinService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_configs() -> HashMap<String, serde_json::Value> {
        let mut configs = HashMap::new();
        configs.insert(
            "shield".to_string(),
            serde_json::json!({"threshold": 0.8, "mode": "strict"}),
        );
        configs.insert(
            "threat".to_string(),
            serde_json::json!({"sensitivity": 0.7, "patterns_enabled": true}),
        );
        configs
    }

    #[test]
    fn service_new_and_defaults() {
        let svc = SecurityTwinService::new();
        assert_eq!(svc.snapshot_count(), 0);
        assert!(svc.list_scenarios().len() >= 5);
    }

    #[test]
    fn snapshot_and_run() {
        let mut svc = SecurityTwinService::new();
        let _id = svc
            .snapshot("baseline", "initial state", sample_configs())
            .unwrap();
        assert_eq!(svc.snapshot_count(), 1);

        // Run the jailbreak bypass scenario.
        let scenario = scenario::jailbreak_bypass_shield();
        let result = svc.run_scenario(&scenario).unwrap();
        assert!(result.duration_ms < u64::MAX);
        assert!(!result.details.is_empty());
    }

    #[test]
    fn compare_policies() {
        let mut svc = SecurityTwinService::new();
        let id1 = svc
            .snapshot("before", "before change", sample_configs())
            .unwrap();

        let mut modified = sample_configs();
        modified.insert(
            "shield".to_string(),
            serde_json::json!({"threshold": 0.5, "mode": "permissive"}),
        );
        let id2 = svc.snapshot("after", "after change", modified).unwrap();

        let diffs = svc.compare_policies(&id1, &id2).unwrap();
        assert!(diffs.contains_key("shield"));
    }

    #[test]
    fn replay_decisions() {
        let mut svc = SecurityTwinService::new();
        svc.snapshot("baseline", "test", sample_configs())
            .unwrap();

        let overrides = serde_json::json!({
            "shield": {"threshold": 0.9}
        });
        let result = svc.replay_decisions(50, overrides, 0.2).unwrap();
        assert!(result.metrics.decisions_evaluated > 0);
    }
}
