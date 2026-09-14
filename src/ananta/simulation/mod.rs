// ANANTA Simulation — Security Twin & Attack/Recovery Simulators
//
// Simulation lets ANANTA test recovery strategies in a safe
// sandbox before applying them to the live system.
//
// Components:
//   1. SecurityTwin  — lightweight mirror of the platform's trust state
//   2. AttackSimulator — injects synthetic threats into the twin
//   3. RecoverySimulator — tests recovery strategies against the twin
//   4. ChaosEngine      — production-grade chaos engineering framework
//   5. SimulationResult  — outcome of a simulation run

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod chaos_engine;
pub use chaos_engine::*;

pub mod scenario_runner;
pub use scenario_runner::*;

use crate::ananta::config::HashAlgorithm;
use crate::ananta::phoenix::recovery_history::RecoveryHistory;
use crate::ananta::phoenix::strategies::{
    RecoveryAction, RecoveryOutcome, RecoveryResult, RecoveryStrategy,
};
use crate::ananta::sentinel::drift::{
    AlertSeverity as DriftAlertSeverity, DriftAlert, DriftObservation, DriftType,
};
use crate::ananta::trust::trust_state::{AlertSeverity, AlertType, TrustAlert, TrustState};

/// A simulated threat to inject into the security twin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScenario {
    /// Scenario name.
    pub name: String,
    /// Description.
    pub description: String,
    /// The sequence of threat events to inject.
    pub events: Vec<ThreatEvent>,
    /// Expected outcome (for validation).
    pub expected_final_trust: Option<f64>,
}

/// A single threat event within a scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Type of threat event.
    pub event_type: ThreatEventType,
    /// Target domain/component.
    pub target: String,
    /// Severity (0.0-1.0).
    pub severity: f64,
    /// Simulated z-score for drift events.
    pub z_score: Option<f64>,
    /// Delay before this event fires (ms in simulation time).
    pub delay_ms: u64,
}

/// Types of threat events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatEventType {
    /// Inject a drift observation.
    DriftInjection,
    /// Set trust level directly.
    TrustDegradation,
    /// Simulate an integrity failure.
    IntegrityFailure,
    /// Simulate a configuration change.
    ConfigChange,
}

/// Result of running a simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// The scenario that was run.
    pub scenario_name: String,
    /// Whether the simulation completed successfully.
    pub completed: bool,
    /// Final trust state score.
    pub final_trust_score: f64,
    /// Initial trust state score.
    pub initial_trust_score: f64,
    /// Recovery actions that were triggered.
    pub recovery_actions: Vec<RecoveryAction>,
    /// Recovery results.
    pub recovery_results: Vec<RecoveryResult>,
    /// Total drift alerts generated.
    pub drift_alerts: Vec<DriftAlert>,
    /// Trust alerts generated.
    pub trust_alerts: Vec<TrustAlert>,
    /// Duration of the simulation (ms).
    pub duration_ms: u64,
    /// Whether the expected outcome was achieved.
    pub expected_outcome_achieved: Option<bool>,
    /// Summary.
    pub summary: String,
}

/// The security twin — a lightweight clone of the platform's trust state.
///
/// This is where simulations run without affecting the live system.
pub struct SecurityTwin {
    /// The twin's trust state.
    trust_state: TrustState,
    /// Recovery history within the twin.
    recovery_history: RecoveryHistory,
    /// Drift observations accumulated during simulation.
    drift_observations: Vec<DriftObservation>,
    /// Drift alerts generated.
    drift_alerts: Vec<DriftAlert>,
    /// Trust alerts generated.
    trust_alerts: Vec<TrustAlert>,
    /// Recovery actions taken.
    recovery_actions: Vec<RecoveryAction>,
    /// Recovery results.
    recovery_results: Vec<RecoveryResult>,
}

impl SecurityTwin {
    /// Create a new security twin from a live trust state snapshot.
    pub fn new(live_state: &TrustState) -> Self {
        Self {
            trust_state: live_state.clone(),
            recovery_history: RecoveryHistory::new(HashAlgorithm::Sha256),
            drift_observations: vec![],
            drift_alerts: vec![],
            trust_alerts: vec![],
            recovery_actions: vec![],
            recovery_results: vec![],
        }
    }

    /// Create a twin with default (healthy) trust state.
    pub fn new_healthy() -> Self {
        Self::new(&TrustState::new())
    }

    /// Inject a drift observation into the twin.
    pub fn inject_drift(&mut self, obs: DriftObservation) -> Option<DriftAlert> {
        self.drift_observations.push(obs.clone());

        // Simple drift detection: if value is far from 0.5 (normal), alert.
        let deviation = (obs.value - 0.5).abs();
        if deviation > 0.3 {
            let z_score = deviation / 0.1; // Simplified.
            let severity = if z_score > 5.0 {
                DriftAlertSeverity::Critical
            } else if z_score > 3.0 {
                DriftAlertSeverity::Warning
            } else {
                DriftAlertSeverity::Info
            };

            let alert = DriftAlert {
                drift_type: obs.drift_type.clone(),
                z_score,
                current_mean: 0.5,
                current_stddev: 0.1,
                observed_value: obs.value,
                context: obs.context.clone(),
                timestamp: obs.timestamp.clone(),
                severity,
            };

            self.drift_alerts.push(alert.clone());

            // Update trust state based on the alert.
            let domain = format!("{:?}", obs.drift_type).to_lowercase();
            let current_trust = self.trust_state.domain_level(&domain);
            let reduction = (z_score / 10.0).min(0.3);
            self.trust_state
                .set_domain_level(&domain, (current_trust - reduction).max(0.0));

            self.trust_state.add_alert(TrustAlert {
                alert_type: AlertType::DecisionDrift,
                domain,
                message: format!("simulated drift: z={:.2}", z_score),
                severity: match severity {
                    DriftAlertSeverity::Critical => AlertSeverity::Critical,
                    DriftAlertSeverity::Warning => AlertSeverity::Warning,
                    DriftAlertSeverity::Info => AlertSeverity::Info,
                },
                timestamp: obs.timestamp,
                data: None,
            });

            Some(alert)
        } else {
            None
        }
    }

    /// Directly degrade a domain's trust level.
    pub fn degrade_trust(&mut self, domain: &str, new_level: f64) {
        let old = self.trust_state.domain_level(domain);
        let new_level = new_level.clamp(0.0, 1.0);
        self.trust_state.set_domain_level(domain, new_level);
        if new_level < old {
            self.trust_alerts.push(TrustAlert {
                alert_type: AlertType::TrustDegradation,
                domain: domain.to_string(),
                message: format!("trust degraded from {:.3} to {:.3}", old, new_level),
                severity: AlertSeverity::Warning,
                timestamp: chrono::Utc::now().to_rfc3339(),
                data: None,
            });
        }
    }

    /// Simulate a recovery action and return the result.
    pub fn simulate_recovery(&mut self, action: RecoveryAction) -> RecoveryResult {
        self.recovery_actions.push(action.clone());

        // Simulate the outcome based on strategy and target.
        let (outcome, message) = match action.strategy {
            RecoveryStrategy::Restart => {
                // Restart has 70% chance of success.
                if action.confidence > 0.5 {
                    // Apply recovery to the target domain.
                    let current = self.trust_state.domain_level(&action.target);
                    let recovered = (current + 0.3).min(1.0);
                    self.trust_state.set_domain_level(&action.target, recovered);
                    (
                        RecoveryOutcome::Success,
                        format!(
                            "{} restarted, trust recovered to {:.2}",
                            action.target, recovered
                        ),
                    )
                } else {
                    (
                        RecoveryOutcome::Failed,
                        format!("{} restart failed", action.target),
                    )
                }
            }
            RecoveryStrategy::Rollback => {
                let current = self.trust_state.domain_level(&action.target);
                let recovered = (current + 0.5).min(1.0);
                self.trust_state.set_domain_level(&action.target, recovered);
                (
                    RecoveryOutcome::Success,
                    format!("{} rolled back, trust={:.2}", action.target, recovered),
                )
            }
            RecoveryStrategy::Quarantine => {
                // Quarantine doesn't improve trust but prevents further damage.
                (
                    RecoveryOutcome::Success,
                    format!("{} quarantined", action.target),
                )
            }
            RecoveryStrategy::Observe => (
                RecoveryOutcome::Skipped,
                "observing — no action taken".into(),
            ),
            RecoveryStrategy::Escalate => (
                RecoveryOutcome::Escalated,
                format!("{} escalated to human", action.target),
            ),
            RecoveryStrategy::ResetThresholds => {
                let recovered = 0.8;
                self.trust_state.set_domain_level(&action.target, recovered);
                (
                    RecoveryOutcome::Success,
                    format!("{} thresholds reset, trust={:.2}", action.target, recovered),
                )
            }
            RecoveryStrategy::ReloadPolicy => {
                let current = self.trust_state.domain_level(&action.target);
                let recovered = (current + 0.4).min(1.0);
                self.trust_state.set_domain_level(&action.target, recovered);
                (
                    RecoveryOutcome::Success,
                    format!("{} policy reloaded, trust={:.2}", action.target, recovered),
                )
            }
            RecoveryStrategy::ReconfigurePipeline => {
                (RecoveryOutcome::Success, "pipeline reconfigured".into())
            }
        };

        let result = match outcome {
            RecoveryOutcome::Success => RecoveryResult::success(action.clone(), &message, 1.0),
            _ => RecoveryResult::failed(action.clone(), &message, 1.0),
        };

        self.recovery_results.push(result.clone());
        self.recovery_history.record(&action, &result);

        result
    }

    /// Get the current trust state of the twin.
    pub fn trust_state(&self) -> &TrustState {
        &self.trust_state
    }

    /// Get the recovery history.
    pub fn recovery_history(&self) -> &RecoveryHistory {
        &self.recovery_history
    }

    /// Get the drift alerts generated.
    pub fn drift_alerts(&self) -> &[DriftAlert] {
        &self.drift_alerts
    }

    /// Get the trust alerts generated.
    pub fn trust_alerts(&self) -> &[TrustAlert] {
        &self.trust_alerts
    }

    /// Get recovery actions taken.
    pub fn recovery_actions(&self) -> &[RecoveryAction] {
        &self.recovery_actions
    }
}

/// The simulation engine.
pub struct SimulationEngine {
    /// Predefined threat scenarios.
    scenarios: HashMap<String, ThreatScenario>,
}

impl SimulationEngine {
    pub fn new() -> Self {
        Self {
            scenarios: HashMap::new(),
        }
    }

    /// Register a threat scenario.
    pub fn register_scenario(&mut self, scenario: ThreatScenario) {
        self.scenarios.insert(scenario.name.clone(), scenario);
    }

    /// Run a named scenario against a security twin.
    pub fn run_scenario(
        &self,
        name: &str,
        twin: &mut SecurityTwin,
    ) -> Result<SimulationResult, String> {
        let scenario = self
            .scenarios
            .get(name)
            .ok_or_else(|| format!("scenario '{}' not found", name))?
            .clone();

        self.run_scenario_direct(&scenario, twin)
    }

    /// Run a scenario directly.
    pub fn run_scenario_direct(
        &self,
        scenario: &ThreatScenario,
        twin: &mut SecurityTwin,
    ) -> Result<SimulationResult, String> {
        let start = std::time::Instant::now();
        let initial_score = twin.trust_state().overall_score();

        // Process events in sequence.
        for event in &scenario.events {
            match event.event_type {
                ThreatEventType::DriftInjection => {
                    if let Some(drift_type) = self.target_to_drift_type(&event.target) {
                        let obs = DriftObservation {
                            drift_type,
                            value: if event.severity > 0.5 { 0.1 } else { 0.3 },
                            context: format!("sim: {}", scenario.name),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        };
                        twin.inject_drift(obs);
                    }
                }
                ThreatEventType::TrustDegradation => {
                    twin.degrade_trust(&event.target, 1.0 - event.severity);
                }
                ThreatEventType::IntegrityFailure => {
                    twin.degrade_trust(&event.target, 0.1);
                }
                ThreatEventType::ConfigChange => {
                    // Config change causes minor trust impact.
                    let current = twin.trust_state().domain_level(&event.target);
                    twin.degrade_trust(&event.target, current - 0.1);
                }
            }
        }

        let final_score = twin.trust_state().overall_score();
        let duration_ms = start.elapsed().as_millis() as u64;

        let expected_achieved = scenario
            .expected_final_trust
            .map(|expected| (final_score - expected).abs() < 0.2);

        Ok(SimulationResult {
            scenario_name: scenario.name.clone(),
            completed: true,
            final_trust_score: final_score,
            initial_trust_score: initial_score,
            recovery_actions: twin.recovery_actions.clone(),
            recovery_results: twin.recovery_results.clone(),
            drift_alerts: twin.drift_alerts().to_vec(),
            trust_alerts: twin.trust_alerts().to_vec(),
            duration_ms,
            expected_outcome_achieved: expected_achieved,
            summary: format!(
                "scenario='{}' trust: {:.3} -> {:.3} alerts={} duration={}ms",
                scenario.name,
                initial_score,
                final_score,
                twin.drift_alerts().len(),
                duration_ms,
            ),
        })
    }

    /// Create a built-in scenario: gradual trust decay.
    pub fn gradual_decay_scenario() -> ThreatScenario {
        let mut events = vec![];
        for i in 0..20 {
            events.push(ThreatEvent {
                event_type: ThreatEventType::TrustDegradation,
                target: "decision".into(),
                severity: 0.03 * (i as f64 + 1.0),
                z_score: None,
                delay_ms: i * 100,
            });
        }
        ThreatScenario {
            name: "gradual_trust_decay".into(),
            description: "Simulates gradual trust decay in the decision domain".into(),
            events,
            expected_final_trust: Some(0.6),
        }
    }

    /// Create a built-in scenario: sudden integrity failure.
    pub fn sudden_integrity_failure_scenario() -> ThreatScenario {
        ThreatScenario {
            name: "sudden_integrity_failure".into(),
            description: "Simulates a sudden integrity check failure".into(),
            events: vec![ThreatEvent {
                event_type: ThreatEventType::IntegrityFailure,
                target: "configuration".into(),
                severity: 0.9,
                z_score: Some(8.0),
                delay_ms: 0,
            }],
            expected_final_trust: Some(0.5),
        }
    }

    /// Map a target name to a drift type.
    fn target_to_drift_type(&self, target: &str) -> Option<DriftType> {
        match target {
            "decision" => Some(DriftType::Decision),
            "policy" => Some(DriftType::Policy),
            "model" => Some(DriftType::Model),
            "orchestration" => Some(DriftType::Orchestration),
            "learning" => Some(DriftType::Learning),
            "memory" => Some(DriftType::Memory),
            "configuration" => Some(DriftType::Configuration),
            "plugin" => Some(DriftType::Plugin),
            "runtime" => Some(DriftType::Runtime),
            "trust" => Some(DriftType::Trust),
            _ => None,
        }
    }
}

impl Default for SimulationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twin_starts_healthy() {
        let twin = SecurityTwin::new_healthy();
        assert_eq!(twin.trust_state().overall_score(), 1.0);
    }

    #[test]
    fn twin_clones_live_state() {
        let mut live = TrustState::new();
        live.set_domain_level("decision", 0.5);
        let twin = SecurityTwin::new(&live);
        assert_eq!(twin.trust_state().domain_level("decision"), 0.5);
    }

    #[test]
    fn drift_injection_degrades_trust() {
        let mut twin = SecurityTwin::new_healthy();
        let obs = DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.0, // Very far from normal.
            context: "test".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let alert = twin.inject_drift(obs);
        assert!(alert.is_some());
        assert!(twin.trust_state().overall_score() < 1.0);
    }

    #[test]
    fn normal_drift_no_alert() {
        let mut twin = SecurityTwin::new_healthy();
        let obs = DriftObservation {
            drift_type: DriftType::Decision,
            value: 0.52, // Close to normal.
            context: "test".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let alert = twin.inject_drift(obs);
        assert!(alert.is_none());
    }

    #[test]
    fn simulate_restart_recovery() {
        let mut twin = SecurityTwin::new_healthy();
        twin.degrade_trust("decision", 0.3);

        let action =
            RecoveryAction::new(RecoveryStrategy::Restart, "decision", "simulated restart")
                .with_confidence(0.8);
        let result = twin.simulate_recovery(action);
        assert_eq!(result.outcome, RecoveryOutcome::Success);
        assert!(twin.trust_state().domain_level("decision") > 0.3);
    }

    #[test]
    fn simulate_quarantine() {
        let mut twin = SecurityTwin::new_healthy();
        let action = RecoveryAction::new(RecoveryStrategy::Quarantine, "plugin", "test")
            .with_confidence(0.9);
        let result = twin.simulate_recovery(action);
        assert_eq!(result.outcome, RecoveryOutcome::Success);
    }

    #[test]
    fn run_gradual_decay_scenario() {
        let engine = SimulationEngine::new();
        let scenario = SimulationEngine::gradual_decay_scenario();
        let mut twin = SecurityTwin::new_healthy();

        let result = engine.run_scenario_direct(&scenario, &mut twin).unwrap();
        assert!(result.completed);
        assert!(result.final_trust_score < result.initial_trust_score);
        assert!(result.initial_trust_score > result.final_trust_score);
    }

    #[test]
    fn run_sudden_failure_scenario() {
        let engine = SimulationEngine::new();
        let scenario = SimulationEngine::sudden_integrity_failure_scenario();
        let mut twin = SecurityTwin::new_healthy();

        let result = engine.run_scenario_direct(&scenario, &mut twin).unwrap();
        assert!(result.completed);
        assert!(result.trust_alerts.len() > 0);
    }

    #[test]
    fn registered_scenario_run() {
        let mut engine = SimulationEngine::new();
        engine.register_scenario(SimulationEngine::gradual_decay_scenario());
        let mut twin = SecurityTwin::new_healthy();

        let result = engine.run_scenario("gradual_trust_decay", &mut twin);
        assert!(result.is_ok());
    }

    #[test]
    fn missing_scenario_errors() {
        let engine = SimulationEngine::new();
        let mut twin = SecurityTwin::new_healthy();
        let result = engine.run_scenario("nonexistent", &mut twin);
        assert!(result.is_err());
    }

    #[test]
    fn scenario_serialization() {
        let scenario = SimulationEngine::gradual_decay_scenario();
        let json = serde_json::to_string(&scenario).unwrap();
        let restored: ThreatScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, scenario.name);
        assert_eq!(restored.events.len(), scenario.events.len());
    }

    #[test]
    fn result_serialization() {
        let result = SimulationResult {
            scenario_name: "test".into(),
            completed: true,
            final_trust_score: 0.7,
            initial_trust_score: 1.0,
            recovery_actions: vec![],
            recovery_results: vec![],
            drift_alerts: vec![],
            trust_alerts: vec![],
            duration_ms: 10,
            expected_outcome_achieved: None,
            summary: "test run".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: SimulationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.scenario_name, "test");
    }
}
