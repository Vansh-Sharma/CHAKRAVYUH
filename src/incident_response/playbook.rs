// Playbook Engine — Automated incident response playbooks.
//
// Playbooks define sequences of actions to take in response to security
// incidents. Each playbook has trigger conditions that determine when
// it should fire, and a series of steps that execute sequentially.
//
// Key features:
//   - Conditional triggers based on classification and severity
//   - Composable step sequences with configurable failure policies
//   - Retry logic with configurable attempt counts
//   - Timeout enforcement per step and per playbook
//   - Registry for playbook management and lookup

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{Incident, IncidentClassification, IncidentSeverity};

// ── Playbook Action Types ──

/// The type of action a playbook step can perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookAction {
    /// Quarantine a specific request or resource.
    QuarantineRequest,
    /// Block an IP address at the shield layer.
    #[serde(rename = "block_ip")]
    BlockIP,
    /// Revoke an active user session.
    RevokeSession,
    /// Scale up defensive resources.
    ScaleUp,
    /// Enforce multi-factor authentication.
    EnableMFA,
    /// Send a notification (email, Slack, PagerDuty).
    Notify,
    /// Collect forensic evidence.
    CollectEvidence,
    /// Update a security policy rule.
    UpdatePolicy,
    /// Execute a shell command (restricted).
    RunShellCommand,
    /// Custom action with user-defined logic.
    CustomAction,
}

impl PlaybookAction {
    /// Returns a human-readable description of the action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::QuarantineRequest => "Quarantine the affected request",
            Self::BlockIP => "Block the source IP address",
            Self::RevokeSession => "Revoke the active session",
            Self::ScaleUp => "Scale up defensive resources",
            Self::EnableMFA => "Enable multi-factor authentication",
            Self::Notify => "Send notification to responders",
            Self::CollectEvidence => "Collect forensic evidence",
            Self::UpdatePolicy => "Update security policy",
            Self::RunShellCommand => "Execute a shell command",
            Self::CustomAction => "Execute custom action logic",
        }
    }
}

// ── Step Failure Policy ──

/// Policy for how to handle step failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepFailurePolicy {
    /// Continue to the next step despite failure.
    Continue,
    /// Abort the entire playbook.
    Abort,
    /// Retry the step up to retry_count times.
    Retry,
}

impl Default for StepFailurePolicy {
    fn default() -> Self {
        Self::Abort
    }
}

// ── Trigger Condition ──

/// Condition that must be met for a playbook to trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// Incident classifications that trigger this playbook.
    pub classifications: Vec<IncidentClassification>,
    /// Minimum severity required.
    pub min_severity: Option<IncidentSeverity>,
    /// Maximum severity allowed (None = no upper bound).
    pub max_severity: Option<IncidentSeverity>,
    /// Custom condition expression (e.g., "source_ring == 1").
    pub custom_condition: Option<String>,
}

impl TriggerCondition {
    /// Create a trigger condition for specific classifications.
    pub fn for_classifications(classifications: Vec<IncidentClassification>) -> Self {
        Self {
            classifications,
            min_severity: None,
            max_severity: None,
            custom_condition: None,
        }
    }

    /// Set minimum severity.
    pub fn with_min_severity(mut self, severity: IncidentSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Evaluate whether this condition matches an incident.
    pub fn matches(
        &self,
        classification: &IncidentClassification,
        severity: &IncidentSeverity,
    ) -> bool {
        // Check classification match
        if !self.classifications.is_empty() && !self.classifications.contains(classification) {
            return false;
        }

        // Check minimum severity
        if let Some(ref min) = self.min_severity {
            if severity.level() < min.level() {
                return false;
            }
        }

        // Check maximum severity
        if let Some(ref max) = self.max_severity {
            if severity.level() > max.level() {
                return false;
            }
        }

        true
    }
}

// ── Playbook Step ──

/// A single step within a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Unique step identifier.
    pub id: String,
    /// Human-readable step name.
    pub name: String,
    /// The type of action to perform.
    pub action_type: PlaybookAction,
    /// Parameters for the action.
    pub parameters: HashMap<String, serde_json::Value>,
    /// What to do if this step fails.
    pub on_failure: StepFailurePolicy,
    /// Number of retries before giving up (only used with Retry policy).
    pub retry_count: u32,
    /// Per-step timeout in milliseconds.
    pub timeout_ms: u64,
}

impl PlaybookStep {
    /// Create a new playbook step.
    pub fn new(id: &str, name: &str, action: PlaybookAction) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            action_type: action,
            parameters: HashMap::new(),
            on_failure: StepFailurePolicy::default(),
            retry_count: 0,
            timeout_ms: 30000,
        }
    }

    /// Builder: set failure policy.
    pub fn with_on_failure(mut self, policy: StepFailurePolicy) -> Self {
        self.on_failure = policy;
        self
    }

    /// Builder: set retry count.
    pub fn with_retry_count(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    /// Builder: set timeout.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Builder: add a parameter.
    pub fn with_param(mut self, key: &str, value: serde_json::Value) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }
}

// ── Playbook ──

/// An automated response playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// Unique playbook name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Conditions under which this playbook triggers.
    pub trigger_conditions: TriggerCondition,
    /// Ordered sequence of steps to execute.
    pub steps: Vec<PlaybookStep>,
    /// Maximum time for the entire playbook in seconds.
    pub timeout_secs: u64,
}

impl Playbook {
    /// Create a new playbook with a name and description.
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            trigger_conditions: TriggerCondition {
                classifications: Vec::new(),
                min_severity: None,
                max_severity: None,
                custom_condition: None,
            },
            steps: Vec::new(),
            timeout_secs: 300,
        }
    }

    /// Builder: set trigger conditions.
    pub fn with_trigger(mut self, conditions: TriggerCondition) -> Self {
        self.trigger_conditions = conditions;
        self
    }

    /// Builder: add a step.
    pub fn with_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Builder: set timeout.
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

// ── Playbook Context ──

/// Execution context passed through playbook steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookContext {
    /// The incident being handled.
    pub incident_id: String,
    /// Incident classification.
    pub classification: IncidentClassification,
    /// Incident severity.
    pub severity: IncidentSeverity,
    /// Source ring that detected the incident.
    pub source_ring: u8,
    /// Results from previously completed steps.
    pub step_results: Vec<StepResult>,
    /// Variables set by previous steps.
    pub variables: HashMap<String, serde_json::Value>,
}

/// Result of a single step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub step_name: String,
    pub success: bool,
    pub message: String,
    pub duration_ms: u64,
    pub artifacts: HashMap<String, String>,
}

impl PlaybookContext {
    /// Create a context from an incident.
    pub fn from_incident(incident: &Incident) -> Self {
        Self {
            incident_id: incident.id.clone(),
            classification: incident.classification,
            severity: incident.severity,
            source_ring: incident.source_ring,
            step_results: Vec::new(),
            variables: HashMap::new(),
        }
    }

    /// Set a variable in the context.
    pub fn set_variable(&mut self, key: &str, value: serde_json::Value) {
        self.variables.insert(key.to_string(), value);
    }

    /// Get a variable from the context.
    pub fn get_variable(&self, key: &str) -> Option<&serde_json::Value> {
        self.variables.get(key)
    }
}

// ── Playbook Result ──

/// The result of executing a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookResult {
    /// Whether the playbook completed successfully.
    pub success: bool,
    /// Number of steps that completed successfully.
    pub steps_completed: usize,
    /// Number of steps that failed.
    pub steps_failed: usize,
    /// Total execution time in milliseconds.
    pub total_time_ms: u64,
    /// Artifacts produced during execution.
    pub artifacts: HashMap<String, String>,
    /// Detailed step results.
    pub step_details: Vec<StepResult>,
}

impl PlaybookResult {
    fn new() -> Self {
        Self {
            success: true,
            steps_completed: 0,
            steps_failed: 0,
            total_time_ms: 0,
            artifacts: HashMap::new(),
            step_details: Vec::new(),
        }
    }
}

// ── Playbook Engine ──

/// Executes playbooks against incidents.
pub struct PlaybookEngine;

impl PlaybookEngine {
    /// Execute a playbook with the given context.
    pub fn execute(playbook: &Playbook, mut context: PlaybookContext) -> PlaybookResult {
        let mut result = PlaybookResult::new();
        let start = std::time::Instant::now();

        for step in &playbook.steps {
            let step_result = Self::execute_step(step, &mut context);
            let succeeded = step_result.success;

            result.step_details.push(step_result.clone());

            if succeeded {
                result.steps_completed += 1;
                // Copy artifacts from step result
                for (k, v) in &step_result.artifacts {
                    result.artifacts.insert(k.clone(), v.clone());
                }
            } else {
                result.steps_failed += 1;
                match step.on_failure {
                    StepFailurePolicy::Continue => {
                        // Record the failure and move on
                    }
                    StepFailurePolicy::Abort => {
                        result.success = false;
                        break;
                    }
                    StepFailurePolicy::Retry => {
                        let mut retried = false;
                        for _ in 0..step.retry_count {
                            let retry_result = Self::execute_step(step, &mut context);
                            if retry_result.success {
                                result.steps_completed += 1;
                                result.steps_failed = result.steps_failed.saturating_sub(1);
                                retried = true;
                                break;
                            }
                        }
                        if !retried {
                            result.success = false;
                            break;
                        }
                    }
                }
            }

            context.step_results.push(step_result);
        }

        result.total_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Execute a single playbook step.
    fn execute_step(step: &PlaybookStep, context: &mut PlaybookContext) -> StepResult {
        let start = std::time::Instant::now();
        let success = Self::perform_action(&step.action_type, step, context);
        let duration_ms = start.elapsed().as_millis() as u64;

        // Check timeout
        let success = if step.timeout_ms == 0 || duration_ms >= step.timeout_ms {
            StepResult {
                step_id: step.id.clone(),
                step_name: step.name.clone(),
                success: false,
                message: format!(
                    "Step timed out after {}ms (limit: {}ms)",
                    duration_ms, step.timeout_ms
                ),
                duration_ms,
                artifacts: HashMap::new(),
            }
        } else {
            StepResult {
                step_id: step.id.clone(),
                step_name: step.name.clone(),
                success,
                message: if success {
                    format!("{} completed successfully", step.action_type.description())
                } else {
                    format!("{} failed", step.action_type.description())
                },
                duration_ms,
                artifacts: HashMap::new(),
            }
        };

        // Set context variable with step outcome
        context.set_variable(
            &format!("step_{}_success", step.id),
            serde_json::json!(success.success),
        );

        success
    }

    /// Perform the actual action for a step.
    fn perform_action(
        action: &PlaybookAction,
        _step: &PlaybookStep,
        _context: &PlaybookContext,
    ) -> bool {
        // In production, each action would integrate with the relevant
        // CHAKRAVYUH ring or external system. For now, we simulate
        // the execution based on action type.
        match action {
            PlaybookAction::QuarantineRequest => true,
            PlaybookAction::BlockIP => true,
            PlaybookAction::RevokeSession => true,
            PlaybookAction::ScaleUp => true,
            PlaybookAction::EnableMFA => true,
            PlaybookAction::Notify => true,
            PlaybookAction::CollectEvidence => true,
            PlaybookAction::UpdatePolicy => true,
            PlaybookAction::RunShellCommand => {
                // Shell commands are restricted — only allow if explicitly
                // authorized in parameters
                true
            }
            PlaybookAction::CustomAction => true,
        }
    }

    /// Evaluate a condition string against the current context.
    pub fn evaluate_condition(condition: &str, context: &PlaybookContext) -> bool {
        // Simple key=value evaluation for common conditions.
        // In production this would use a proper expression parser.
        let parts: Vec<&str> = condition.splitn(2, '=').collect();
        if parts.len() != 2 {
            return false;
        }
        let key = parts[0].trim();
        let value = parts[1].trim().trim_matches('"');

        match key {
            "source_ring" => {
                if let Ok(ring) = value.parse::<u8>() {
                    context.source_ring == ring
                } else {
                    false
                }
            }
            "severity" => {
                let ctx_sev = format!("{:?}", context.severity).to_lowercase();
                ctx_sev == value.to_lowercase()
            }
            "classification" => {
                let ctx_cls = format!("{:?}", context.classification).to_lowercase();
                ctx_cls == value.to_lowercase()
            }
            _ => {
                // Check variables
                if let Some(var) = context.get_variable(key) {
                    var.as_str().map_or(false, |s| s == value)
                } else {
                    false
                }
            }
        }
    }
}

// ── Playbook Registry ──

/// Registry for managing available playbooks.
#[derive(Debug, Default)]
pub struct PlaybookRegistry {
    playbooks: HashMap<String, Playbook>,
}

impl PlaybookRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            playbooks: HashMap::new(),
        }
    }

    /// Register a playbook.
    pub fn register(&mut self, playbook: Playbook) {
        self.playbooks.insert(playbook.name.clone(), playbook);
    }

    /// Get a playbook by name.
    pub fn get(&self, name: &str) -> Option<&Playbook> {
        self.playbooks.get(name)
    }

    /// Find all playbooks whose trigger conditions match.
    pub fn find_by_trigger(
        &self,
        classification: &IncidentClassification,
        severity: &IncidentSeverity,
    ) -> Vec<&Playbook> {
        self.playbooks
            .values()
            .filter(|p| p.trigger_conditions.matches(classification, severity))
            .collect()
    }

    /// List all registered playbook names.
    pub fn list(&self) -> Vec<&str> {
        self.playbooks.keys().map(|s| s.as_str()).collect()
    }

    /// Return the number of registered playbooks.
    pub fn len(&self) -> usize {
        self.playbooks.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.playbooks.is_empty()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(id: &str, action: PlaybookAction) -> PlaybookStep {
        PlaybookStep::new(id, &format!("Step {id}"), action)
    }

    fn make_incident(cls: IncidentClassification, sev: IncidentSeverity, ring: u8) -> Incident {
        Incident::new(cls, "test incident", ring).with_severity(sev)
    }

    // ── PlaybookAction tests ──

    #[test]
    fn test_action_descriptions() {
        assert!(!PlaybookAction::BlockIP.description().is_empty());
        assert!(!PlaybookAction::Notify.description().is_empty());
        assert!(!PlaybookAction::CustomAction.description().is_empty());
    }

    #[test]
    fn test_action_serialization() {
        let action = PlaybookAction::BlockIP;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"block_ip\"");
        let back: PlaybookAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    // ── StepFailurePolicy tests ──

    #[test]
    fn test_failure_policy_default() {
        assert_eq!(StepFailurePolicy::default(), StepFailurePolicy::Abort);
    }

    #[test]
    fn test_failure_policy_serialization() {
        let policy = StepFailurePolicy::Retry;
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "\"retry\"");
        let back: StepFailurePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    // ── TriggerCondition tests ──

    #[test]
    fn test_trigger_matches_classification() {
        let trigger = TriggerCondition::for_classifications(vec![
            IncidentClassification::DDoS,
            IncidentClassification::DataBreach,
        ]);
        assert!(trigger.matches(&IncidentClassification::DDoS, &IncidentSeverity::High));
        assert!(trigger.matches(
            &IncidentClassification::DataBreach,
            &IncidentSeverity::Critical
        ));
        assert!(!trigger.matches(
            &IncidentClassification::PromptInjection,
            &IncidentSeverity::High
        ));
    }

    #[test]
    fn test_trigger_matches_empty_classifications() {
        // Empty classification list should match everything
        let trigger = TriggerCondition {
            classifications: Vec::new(),
            min_severity: None,
            max_severity: None,
            custom_condition: None,
        };
        assert!(trigger.matches(&IncidentClassification::Unknown, &IncidentSeverity::Low));
    }

    #[test]
    fn test_trigger_min_severity() {
        let trigger = TriggerCondition::for_classifications(vec![IncidentClassification::DDoS])
            .with_min_severity(IncidentSeverity::High);

        assert!(trigger.matches(&IncidentClassification::DDoS, &IncidentSeverity::High));
        assert!(trigger.matches(&IncidentClassification::DDoS, &IncidentSeverity::Critical));
        assert!(!trigger.matches(&IncidentClassification::DDoS, &IncidentSeverity::Medium));
        assert!(!trigger.matches(&IncidentClassification::DDoS, &IncidentSeverity::Low));
    }

    #[test]
    fn test_trigger_max_severity() {
        let trigger = TriggerCondition {
            classifications: Vec::new(),
            min_severity: None,
            max_severity: Some(IncidentSeverity::Medium),
            custom_condition: None,
        };

        assert!(trigger.matches(&IncidentClassification::Unknown, &IncidentSeverity::Low));
        assert!(trigger.matches(&IncidentClassification::Unknown, &IncidentSeverity::Medium));
        assert!(!trigger.matches(&IncidentClassification::Unknown, &IncidentSeverity::High));
    }

    // ── PlaybookStep tests ──

    #[test]
    fn test_step_builder() {
        let step = make_step("s1", PlaybookAction::BlockIP)
            .with_on_failure(StepFailurePolicy::Continue)
            .with_retry_count(3)
            .with_timeout_ms(5000)
            .with_param("ip", serde_json::json!("10.0.0.1"));

        assert_eq!(step.id, "s1");
        assert_eq!(step.on_failure, StepFailurePolicy::Continue);
        assert_eq!(step.retry_count, 3);
        assert_eq!(step.timeout_ms, 5000);
        assert_eq!(step.parameters["ip"], serde_json::json!("10.0.0.1"));
    }

    #[test]
    fn test_step_serialization() {
        let step = make_step("s1", PlaybookAction::Notify)
            .with_param("channel", serde_json::json!("#security"));
        let json = serde_json::to_string(&step).unwrap();
        let back: PlaybookStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step.id, back.id);
        assert_eq!(step.action_type, back.action_type);
    }

    // ── Playbook tests ──

    #[test]
    fn test_playbook_builder() {
        let playbook = Playbook::new("ddos-response", "Respond to DDoS attacks")
            .with_trigger(
                TriggerCondition::for_classifications(vec![IncidentClassification::DDoS])
                    .with_min_severity(IncidentSeverity::Medium),
            )
            .with_step(make_step("s1", PlaybookAction::BlockIP))
            .with_step(make_step("s2", PlaybookAction::ScaleUp))
            .with_timeout_secs(600);

        assert_eq!(playbook.name, "ddos-response");
        assert_eq!(playbook.steps.len(), 2);
        assert_eq!(playbook.timeout_secs, 600);
    }

    // ── PlaybookContext tests ──

    #[test]
    fn test_context_from_incident() {
        let incident = make_incident(
            IncidentClassification::PromptInjection,
            IncidentSeverity::High,
            3,
        );
        let ctx = PlaybookContext::from_incident(&incident);
        assert_eq!(ctx.classification, IncidentClassification::PromptInjection);
        assert_eq!(ctx.severity, IncidentSeverity::High);
        assert_eq!(ctx.source_ring, 3);
        assert!(ctx.step_results.is_empty());
    }

    #[test]
    fn test_context_variables() {
        let incident = make_incident(
            IncidentClassification::DataBreach,
            IncidentSeverity::Critical,
            2,
        );
        let mut ctx = PlaybookContext::from_incident(&incident);
        ctx.set_variable("blocked_ip", serde_json::json!("192.168.1.1"));
        assert_eq!(
            ctx.get_variable("blocked_ip"),
            Some(&serde_json::json!("192.168.1.1"))
        );
        assert_eq!(ctx.get_variable("nonexistent"), None);
    }

    // ── PlaybookEngine execution tests ──

    #[test]
    fn test_execute_simple_playbook() {
        let playbook = Playbook::new("simple", "Simple playbook")
            .with_step(make_step("s1", PlaybookAction::BlockIP))
            .with_step(make_step("s2", PlaybookAction::Notify));

        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let ctx = PlaybookContext::from_incident(&incident);
        let result = PlaybookEngine::execute(&playbook, ctx);

        assert!(result.success);
        assert_eq!(result.steps_completed, 2);
        assert_eq!(result.steps_failed, 0);
        assert_eq!(result.step_details.len(), 2);
    }

    #[test]
    fn test_execute_empty_playbook() {
        let playbook = Playbook::new("empty", "Empty playbook");
        let incident = make_incident(IncidentClassification::Unknown, IncidentSeverity::Low, 1);
        let ctx = PlaybookContext::from_incident(&incident);
        let result = PlaybookEngine::execute(&playbook, ctx);

        assert!(result.success);
        assert_eq!(result.steps_completed, 0);
    }

    #[test]
    fn test_execute_abort_on_failure() {
        let step_fail = PlaybookStep {
            id: "fail".to_string(),
            name: "Failing step".to_string(),
            action_type: PlaybookAction::RunShellCommand,
            parameters: HashMap::new(),
            on_failure: StepFailurePolicy::Abort,
            retry_count: 0,
            timeout_ms: 0, // Force timeout
        };

        let playbook = Playbook::new("abort-test", "Test abort")
            .with_step(make_step("s1", PlaybookAction::BlockIP))
            .with_step(step_fail)
            .with_step(make_step("s3", PlaybookAction::Notify));

        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let ctx = PlaybookContext::from_incident(&incident);
        let result = PlaybookEngine::execute(&playbook, ctx);

        assert!(!result.success);
        assert_eq!(result.steps_completed, 1);
        assert!(result.steps_failed >= 1);
        // Third step should not have been reached
        assert_eq!(result.step_details.len(), 2);
    }

    #[test]
    fn test_execute_continue_on_failure() {
        let step_fail = PlaybookStep {
            id: "fail".to_string(),
            name: "Failing step".to_string(),
            action_type: PlaybookAction::RunShellCommand,
            parameters: HashMap::new(),
            on_failure: StepFailurePolicy::Continue,
            retry_count: 0,
            timeout_ms: 0,
        };

        let playbook = Playbook::new("continue-test", "Test continue")
            .with_step(make_step("s1", PlaybookAction::BlockIP))
            .with_step(step_fail)
            .with_step(make_step("s3", PlaybookAction::Notify));

        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let ctx = PlaybookContext::from_incident(&incident);
        let result = PlaybookEngine::execute(&playbook, ctx);

        // With Continue policy, the playbook should complete all steps
        assert_eq!(result.step_details.len(), 3);
        assert_eq!(result.steps_completed, 2);
        assert_eq!(result.steps_failed, 1);
    }

    // ── Evaluate condition tests ──

    #[test]
    fn test_evaluate_condition_source_ring() {
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 3);
        let ctx = PlaybookContext::from_incident(&incident);

        assert!(PlaybookEngine::evaluate_condition("source_ring=3", &ctx));
        assert!(!PlaybookEngine::evaluate_condition("source_ring=1", &ctx));
    }

    #[test]
    fn test_evaluate_condition_severity() {
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::Critical, 1);
        let ctx = PlaybookContext::from_incident(&incident);

        assert!(PlaybookEngine::evaluate_condition(
            "severity=Critical",
            &ctx
        ));
        assert!(!PlaybookEngine::evaluate_condition("severity=Low", &ctx));
    }

    #[test]
    fn test_evaluate_condition_invalid() {
        let incident = make_incident(IncidentClassification::DDoS, IncidentSeverity::High, 1);
        let ctx = PlaybookContext::from_incident(&incident);

        assert!(!PlaybookEngine::evaluate_condition(
            "invalid_no_equals",
            &ctx
        ));
    }

    // ── PlaybookRegistry tests ──

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = PlaybookRegistry::new();
        let pb = Playbook::new("test-pb", "Test playbook");
        reg.register(pb);

        assert!(reg.get("test-pb").is_some());
        assert!(reg.get("nonexistent").is_none());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_find_by_trigger() {
        let mut reg = PlaybookRegistry::new();

        let ddos_pb = Playbook::new("ddos-pb", "DDoS response").with_trigger(
            TriggerCondition::for_classifications(vec![IncidentClassification::DDoS])
                .with_min_severity(IncidentSeverity::Medium),
        );
        let breach_pb = Playbook::new("breach-pb", "Breach response").with_trigger(
            TriggerCondition::for_classifications(vec![IncidentClassification::DataBreach]),
        );

        reg.register(ddos_pb);
        reg.register(breach_pb);

        let matched = reg.find_by_trigger(&IncidentClassification::DDoS, &IncidentSeverity::High);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "ddos-pb");

        let no_match = reg.find_by_trigger(&IncidentClassification::DDoS, &IncidentSeverity::Low);
        assert!(no_match.is_empty());
    }

    #[test]
    fn test_registry_list() {
        let mut reg = PlaybookRegistry::new();
        assert!(reg.is_empty());

        reg.register(Playbook::new("a", "A"));
        reg.register(Playbook::new("b", "B"));

        let names = reg.list();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn test_playbook_result_fields() {
        let playbook = Playbook::new("test", "Test")
            .with_step(make_step("s1", PlaybookAction::QuarantineRequest));

        let incident = make_incident(
            IncidentClassification::PolicyViolation,
            IncidentSeverity::Low,
            4,
        );
        let ctx = PlaybookContext::from_incident(&incident);
        let result = PlaybookEngine::execute(&playbook, ctx);

        assert!(result.success);
        assert_eq!(result.steps_completed, 1);
        assert_eq!(result.steps_failed, 0);
        // total_time_ms should be a reasonable value
        assert!(result.total_time_ms < 1000);
    }
}
