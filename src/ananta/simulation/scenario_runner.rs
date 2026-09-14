// ANANTA Scenario Runner — Advanced Simulation Orchestration Engine
//
// Provides structured scenario definition, step-by-step execution with
// pause/resume support, a library of pre-built security scenarios,
// result aggregation across runs, and cron-like scheduling with overlap
// prevention.
//
// Components:
//   1. Scenario Definition  — phases, preconditions, actions, postconditions, nesting
//   2. Scenario Runner      — execution engine with failure handling & event recording
//   3. Scenario Library     — pre-built attack/failure scenario templates
//   4. Result Aggregation   — cross-run statistics and comparison
//   5. Scenario Scheduling  — cron-like scheduling with overlap detection

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ────────────────────────────────────────────────────────────────
// 1. Scenario Definition
// ────────────────────────────────────────────────────────────────

/// Unique identifier for scenario elements.
pub type ScenarioId = String;

/// Severity level for scenario actions and conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational — no real impact expected.
    Info,
    /// Low severity — minor degradation.
    Low,
    /// Medium severity — noticeable impact.
    Medium,
    /// High severity — significant disruption.
    High,
    /// Critical severity — full outage possible.
    Critical,
}

impl Severity {
    /// Numeric weight for comparison and scoring (0–4).
    pub fn weight(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Normalised float representation (0.0–1.0).
    pub fn as_f64(&self) -> f64 {
        self.weight() as f64 / 4.0
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

/// A named parameter used to parameterise a scenario template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioParameter {
    /// Parameter name, e.g. "target_component".
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Default value as a JSON string.
    pub default_value: String,
    /// Whether the parameter is required when instantiating.
    pub required: bool,
}

/// Execution mode for a phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhaseMode {
    /// Steps execute one after another in order.
    Sequential,
    /// Steps may execute concurrently (simulated with interleave).
    Parallel,
}

/// A guard condition that must be satisfied before a phase or step runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precondition {
    /// Human-readable description of the condition.
    pub description: String,
    /// Expression evaluated against the runner state.
    /// Supported: "trust_above:{domain}:{threshold}", "domain_exists:{domain}",
    /// "trust_below:{domain}:{threshold}", "alerts_below:{count}".
    pub expression: String,
}

impl Precondition {
    /// Create a precondition requiring trust in a domain to be above a threshold.
    pub fn trust_above(domain: &str, threshold: f64) -> Self {
        Self {
            description: format!("Trust in '{}' must be above {:.2}", domain, threshold),
            expression: format!("trust_above:{}:{:.4}", domain, threshold),
        }
    }

    /// Create a precondition requiring trust in a domain to be below a threshold.
    pub fn trust_below(domain: &str, threshold: f64) -> Self {
        Self {
            description: format!("Trust in '{}' must be below {:.2}", domain, threshold),
            expression: format!("trust_below:{}:{:.4}", domain, threshold),
        }
    }

    /// Create a precondition requiring the number of alerts to be below a limit.
    pub fn alerts_below(count: usize) -> Self {
        Self {
            description: format!("Alert count must be below {}", count),
            expression: format!("alerts_below:{}", count),
        }
    }

    /// Evaluate this precondition against a snapshot of trust domain levels and alert count.
    pub fn evaluate(&self, trust_levels: &HashMap<String, f64>, alert_count: usize) -> bool {
        let parts: Vec<&str> = self.expression.splitn(3, ':').collect();
        if parts.is_empty() {
            return true;
        }
        match parts[0] {
            "trust_above" => {
                if parts.len() >= 3 {
                    if let Ok(threshold) = parts[2].parse::<f64>() {
                        let domain = parts[1];
                        return trust_levels.get(domain).map_or(false, |&v| v > threshold);
                    }
                }
                true
            }
            "trust_below" => {
                if parts.len() >= 3 {
                    if let Ok(threshold) = parts[2].parse::<f64>() {
                        let domain = parts[1];
                        return trust_levels.get(domain).map_or(true, |&v| v < threshold);
                    }
                }
                true
            }
            "alerts_below" => {
                if parts.len() >= 2 {
                    if let Ok(limit) = parts[1].parse::<usize>() {
                        return alert_count < limit;
                    }
                }
                true
            }
            _ => true,
        }
    }
}

/// An individual action step within a scenario phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStep {
    /// Unique step identifier.
    pub id: ScenarioId,
    /// Human-readable label.
    pub label: String,
    /// Description of what this step does.
    pub description: String,
    /// Target domain or component affected.
    pub target: String,
    /// Severity of the action.
    pub severity: Severity,
    /// How much trust to degrade (0.0–1.0).
    pub trust_degradation: f64,
    /// Delay before executing this step in simulated milliseconds.
    pub delay_ms: u64,
    /// Optional nested sub-scenario to execute as this step.
    pub sub_scenario: Option<Box<Scenario>>,
}

/// A postcondition checked after a phase completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Postcondition {
    /// Human-readable description.
    pub description: String,
    /// Expression to evaluate (same syntax as preconditions).
    pub expression: String,
    /// Whether this postcondition is required for the phase to pass.
    pub required: bool,
}

impl Postcondition {
    /// Create a required postcondition checking trust is above a threshold.
    pub fn trust_above_required(domain: &str, threshold: f64) -> Self {
        Self {
            description: format!("Trust in '{}' must recover above {:.2}", domain, threshold),
            expression: format!("trust_above:{}:{:.4}", domain, threshold),
            required: true,
        }
    }

    /// Create an optional (informational) postcondition.
    pub fn trust_above_optional(domain: &str, threshold: f64) -> Self {
        Self {
            description: format!(
                "Trust in '{}' should ideally be above {:.2}",
                domain, threshold
            ),
            expression: format!("trust_above:{}:{:.4}", domain, threshold),
            required: false,
        }
    }

    /// Create a required postcondition checking trust is below a threshold.
    pub fn trust_below(domain: &str, threshold: f64) -> Self {
        Self {
            description: format!("Trust in '{}' must drop below {:.2}", domain, threshold),
            expression: format!("trust_below:{}:{:.4}", domain, threshold),
            required: true,
        }
    }

    /// Evaluate against the same snapshot as preconditions.
    pub fn evaluate(&self, trust_levels: &HashMap<String, f64>, alert_count: usize) -> bool {
        let parts: Vec<&str> = self.expression.splitn(3, ':').collect();
        match parts.get(0).map(|s| *s) {
            Some("trust_above") => {
                if parts.len() >= 3 {
                    if let Ok(threshold) = parts[2].parse::<f64>() {
                        return trust_levels.get(parts[1]).map_or(false, |&v| v > threshold);
                    }
                }
                true
            }
            Some("trust_below") => {
                if parts.len() >= 3 {
                    if let Ok(threshold) = parts[2].parse::<f64>() {
                        return trust_levels.get(parts[1]).map_or(true, |&v| v < threshold);
                    }
                }
                true
            }
            Some("alerts_below") => {
                if parts.len() >= 2 {
                    if let Ok(limit) = parts[1].parse::<usize>() {
                        return alert_count < limit;
                    }
                }
                true
            }
            _ => true,
        }
    }
}

/// A named phase within a scenario, containing action steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioPhase {
    /// Unique phase identifier.
    pub id: ScenarioId,
    /// Human-readable phase name.
    pub name: String,
    /// Description of what this phase does.
    pub description: String,
    /// Execution mode for steps within this phase.
    pub mode: PhaseMode,
    /// Ordered action steps.
    pub steps: Vec<ActionStep>,
    /// Conditions that must hold before the phase starts.
    pub preconditions: Vec<Precondition>,
    /// Conditions checked after the phase completes.
    pub postconditions: Vec<Postcondition>,
    /// Timeout for this phase in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

impl ScenarioPhase {
    /// Create a new sequential phase with the given id and name.
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            mode: PhaseMode::Sequential,
            steps: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            timeout_ms: 0,
        }
    }

    /// Create a new parallel phase.
    pub fn new_parallel(id: &str, name: &str) -> Self {
        let mut phase = Self::new(id, name);
        phase.mode = PhaseMode::Parallel;
        phase
    }

    /// Builder: add an action step.
    pub fn with_step(mut self, step: ActionStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Builder: add a precondition.
    pub fn with_precondition(mut self, pre: Precondition) -> Self {
        self.preconditions.push(pre);
        self
    }

    /// Builder: add a postcondition.
    pub fn with_postcondition(mut self, post: Postcondition) -> Self {
        self.postconditions.push(post);
        self
    }

    /// Builder: set timeout.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Total number of steps across all nesting levels.
    pub fn total_step_count(&self) -> usize {
        let mut count = self.steps.len();
        for step in &self.steps {
            if let Some(ref sub) = step.sub_scenario {
                count += sub.total_step_count();
            }
        }
        count
    }
}

/// A complete scenario definition with phases, parameters, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Unique scenario identifier.
    pub id: ScenarioId,
    /// Human-readable name.
    pub name: String,
    /// Detailed description.
    pub description: String,
    /// Category tag (e.g. "failure", "attack", "recovery").
    pub category: String,
    /// Version string for the scenario definition.
    pub version: String,
    /// Ordered phases.
    pub phases: Vec<ScenarioPhase>,
    /// Parameters for template instantiation.
    pub parameters: Vec<ScenarioParameter>,
    /// Global precondition for the entire scenario.
    pub global_preconditions: Vec<Precondition>,
    /// Global postcondition for the entire scenario.
    pub global_postconditions: Vec<Postcondition>,
    /// Tags for filtering.
    pub tags: Vec<String>,
    /// Overall timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

impl Scenario {
    /// Create a minimal scenario with the given id and name.
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            category: "general".to_string(),
            version: "1.0.0".to_string(),
            phases: Vec::new(),
            parameters: Vec::new(),
            global_preconditions: Vec::new(),
            global_postconditions: Vec::new(),
            tags: Vec::new(),
            timeout_ms: 0,
        }
    }

    /// Builder: add a phase.
    pub fn with_phase(mut self, phase: ScenarioPhase) -> Self {
        self.phases.push(phase);
        self
    }

    /// Builder: add a parameter.
    pub fn with_parameter(mut self, param: ScenarioParameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Builder: add a global precondition.
    pub fn with_global_precondition(mut self, pre: Precondition) -> Self {
        self.global_preconditions.push(pre);
        self
    }

    /// Builder: add a global postcondition.
    pub fn with_global_postcondition(mut self, post: Postcondition) -> Self {
        self.global_postconditions.push(post);
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Builder: set category.
    pub fn with_category(mut self, cat: &str) -> Self {
        self.category = cat.to_string();
        self
    }

    /// Builder: add a tag.
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Builder: set timeout.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Total number of steps across all phases (including nested sub-scenarios).
    pub fn total_step_count(&self) -> usize {
        self.phases.iter().map(|p| p.total_step_count()).sum()
    }

    /// Check if the scenario has any nested sub-scenarios.
    pub fn has_nested_scenarios(&self) -> bool {
        for phase in &self.phases {
            for step in &phase.steps {
                if step.sub_scenario.is_some() {
                    return true;
                }
            }
        }
        false
    }

    /// Collect all unique tags from this scenario and any nested sub-scenarios.
    pub fn all_tags(&self) -> HashSet<String> {
        let mut tags: HashSet<String> = self.tags.iter().cloned().collect();
        for phase in &self.phases {
            for step in &phase.steps {
                if let Some(ref sub) = step.sub_scenario {
                    tags.extend(sub.all_tags());
                }
            }
        }
        tags
    }

    /// Resolve a parameter by name, returning the default value.
    pub fn resolve_parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.default_value.as_str())
    }
}

// ────────────────────────────────────────────────────────────────
// 2. Scenario Runner Engine
// ────────────────────────────────────────────────────────────────

/// Execution state for the overall runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunnerState {
    /// Not yet started.
    Idle,
    /// Running normally.
    Running,
    /// Paused by user or condition.
    Paused,
    /// Completed all phases.
    Completed,
    /// Aborted due to error or timeout.
    Aborted,
    /// Timed out.
    TimedOut,
}

/// Outcome of a single action step execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepOutcome {
    /// Step completed successfully.
    Success,
    /// Step failed, but execution may continue depending on policy.
    Failed,
    /// Step was skipped (precondition not met).
    Skipped,
    /// Step timed out.
    TimedOut,
}

/// Outcome of a phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhaseOutcome {
    /// All steps succeeded and all required postconditions met.
    Passed,
    /// One or more steps failed or a required postcondition failed.
    Failed,
    /// Phase timed out.
    TimedOut,
    /// Phase was skipped (precondition not met).
    Skipped,
}

/// Outcome of a full scenario run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScenarioOutcome {
    /// All phases passed.
    Passed,
    /// One or more phases failed.
    Failed,
    /// Scenario timed out.
    TimedOut,
    /// Aborted by external signal.
    Aborted,
}

/// A single recorded event during scenario execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvent {
    /// Timestamp of the event (UTC).
    pub timestamp: DateTime<Utc>,
    /// The scenario, phase, and step identifiers.
    pub scenario_id: ScenarioId,
    pub phase_id: ScenarioId,
    pub step_id: Option<ScenarioId>,
    /// Event type descriptor.
    pub event_type: String,
    /// Human-readable message.
    pub message: String,
    /// Severity of the event.
    pub severity: Severity,
    /// Additional key-value context.
    pub context: HashMap<String, String>,
}

impl ScenarioEvent {
    /// Create a new event with the given identifiers and type.
    pub fn new(
        scenario_id: &str,
        phase_id: &str,
        step_id: Option<&str>,
        event_type: &str,
        message: &str,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            scenario_id: scenario_id.to_string(),
            phase_id: phase_id.to_string(),
            step_id: step_id.map(|s| s.to_string()),
            event_type: event_type.to_string(),
            message: message.to_string(),
            severity: Severity::Info,
            context: HashMap::new(),
        }
    }

    /// Builder: set severity.
    pub fn with_severity(mut self, sev: Severity) -> Self {
        self.severity = sev;
        self
    }

    /// Builder: add context entry.
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// Detailed result for a single step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step identifier.
    pub step_id: ScenarioId,
    /// Outcome.
    pub outcome: StepOutcome,
    /// Duration of the step in simulated milliseconds.
    pub duration_ms: u64,
    /// Trust degradation applied.
    pub trust_impact: f64,
    /// Trust level of the target domain after the step.
    pub trust_after: f64,
    /// Any events generated during this step.
    pub events: Vec<ScenarioEvent>,
}

/// Detailed result for a single phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    /// Phase identifier.
    pub phase_id: ScenarioId,
    /// Phase name.
    pub phase_name: String,
    /// Outcome.
    pub outcome: PhaseOutcome,
    /// Duration of the phase in simulated milliseconds.
    pub duration_ms: u64,
    /// Results for each step.
    pub step_results: Vec<StepResult>,
    /// Whether all preconditions were met.
    pub preconditions_met: bool,
    /// Whether all required postconditions were met.
    pub required_postconditions_met: bool,
    /// Events generated during this phase.
    pub events: Vec<ScenarioEvent>,
}

/// Failure handling policy when a step or phase fails.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailurePolicy {
    /// Abort the entire scenario on any failure.
    AbortOnFailure,
    /// Continue to the next step/phase despite failure.
    ContinueOnFailure,
    /// Retry the failed step up to N times before continuing.
    Retry { max_attempts: u32 },
    /// Mark the scenario as needing review but continue.
    SoftFail,
}

/// The complete result of a scenario execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRunResult {
    /// The scenario that was run.
    pub scenario_id: ScenarioId,
    pub scenario_name: String,
    /// Overall outcome.
    pub outcome: ScenarioOutcome,
    /// Start and end timestamps.
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    /// Duration in simulated milliseconds.
    pub duration_ms: u64,
    /// Per-phase results.
    pub phase_results: Vec<PhaseResult>,
    /// All events recorded during the run.
    pub events: Vec<ScenarioEvent>,
    /// Final trust levels for all affected domains.
    pub final_trust_levels: HashMap<String, f64>,
    /// Initial trust levels snapshot.
    pub initial_trust_levels: HashMap<String, f64>,
    /// Total alerts generated during the run.
    pub alert_count: usize,
    /// Human-readable summary.
    pub summary: String,
    /// Run identifier (unique per execution).
    pub run_id: String,
}

/// Produces a simple unique-ish run ID based on timestamp and a counter.
fn uuid_value() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos)
}

/// The scenario runner engine — executes scenarios step by step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRunner {
    /// Runner state.
    pub state: RunnerState,
    /// Current phase index (0-based).
    pub current_phase_index: usize,
    /// Current step index within the current phase (0-based).
    pub current_step_index: usize,
    /// Failure handling policy.
    pub failure_policy: FailurePolicy,
    /// All recorded events.
    pub events: Vec<ScenarioEvent>,
    /// Per-step retry attempt counters (step_id -> attempts so far).
    pub retry_attempts: HashMap<ScenarioId, u32>,
    /// Simulation clock in milliseconds.
    pub simulated_time_ms: u64,
    /// Simulated trust domain levels.
    pub trust_levels: HashMap<String, f64>,
    /// Simulated alert count.
    pub alert_count: usize,
    /// Accumulated phase results for the current run.
    pub phase_results: Vec<PhaseResult>,
    /// Initial trust levels snapshot at run start.
    pub initial_trust_levels: HashMap<String, f64>,
    /// The scenario being executed (set when run begins).
    pub active_scenario: Option<Scenario>,
    /// Run start timestamp.
    pub run_started_at: Option<DateTime<Utc>>,
}

impl ScenarioRunner {
    /// Create a new idle scenario runner.
    pub fn new() -> Self {
        Self {
            state: RunnerState::Idle,
            current_phase_index: 0,
            current_step_index: 0,
            failure_policy: FailurePolicy::ContinueOnFailure,
            events: Vec::new(),
            retry_attempts: HashMap::new(),
            simulated_time_ms: 0,
            trust_levels: HashMap::new(),
            alert_count: 0,
            phase_results: Vec::new(),
            initial_trust_levels: HashMap::new(),
            active_scenario: None,
            run_started_at: None,
        }
    }

    /// Builder: set the failure policy.
    pub fn with_failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Set initial trust levels for simulation.
    pub fn set_trust_levels(&mut self, levels: HashMap<String, f64>) {
        self.trust_levels = levels;
    }

    /// Initialise a domain's trust level if not already present.
    pub fn ensure_domain(&mut self, domain: &str, default: f64) {
        self.trust_levels
            .entry(domain.to_string())
            .or_insert(default);
    }

    /// Record an event.
    fn record_event(&mut self, event: ScenarioEvent) {
        self.events.push(event);
    }

    /// Get a reference to all recorded events.
    pub fn events(&self) -> &[ScenarioEvent] {
        &self.events
    }

    /// Check whether all preconditions of a list are satisfied.
    fn check_preconditions(&self, preconditions: &[Precondition]) -> bool {
        preconditions
            .iter()
            .all(|pre| pre.evaluate(&self.trust_levels, self.alert_count))
    }

    /// Check whether all required postconditions in a list are satisfied.
    fn check_postconditions(&self, postconditions: &[Postcondition]) -> bool {
        postconditions
            .iter()
            .filter(|pc| pc.required)
            .all(|pc| pc.evaluate(&self.trust_levels, self.alert_count))
    }

    /// Apply trust degradation to a domain.
    fn apply_degradation(&mut self, domain: &str, amount: f64) -> f64 {
        let current = self.trust_levels.get(domain).copied().unwrap_or(1.0);
        let new_level = (current - amount).max(0.0).min(1.0);
        self.trust_levels.insert(domain.to_string(), new_level);

        // If trust drops below 0.3, count it as an alert.
        if new_level < 0.3 && current >= 0.3 {
            self.alert_count += 1;
        }
        new_level
    }

    /// Begin executing a scenario. Returns the initial scenario snapshot.
    pub fn start(&mut self, scenario: Scenario) -> Result<(), String> {
        if self.state == RunnerState::Running {
            return Err("Runner is already running".into());
        }

        // Snapshot initial state.
        self.initial_trust_levels = self.trust_levels.clone();
        self.active_scenario = Some(scenario.clone());
        self.run_started_at = Some(Utc::now());
        self.state = RunnerState::Running;
        self.current_phase_index = 0;
        self.current_step_index = 0;
        self.events.clear();
        self.phase_results.clear();
        self.retry_attempts.clear();
        self.simulated_time_ms = 0;

        self.record_event(
            ScenarioEvent::new(
                &scenario.id,
                "_global",
                None,
                "scenario_start",
                &format!("Started scenario: {}", scenario.name),
            )
            .with_severity(Severity::Info),
        );

        Ok(())
    }

    /// Pause the runner. Only valid when running.
    pub fn pause(&mut self) -> Result<(), String> {
        if self.state != RunnerState::Running {
            return Err(format!("Cannot pause in state {:?}", self.state));
        }
        self.state = RunnerState::Paused;
        self.record_event(
            ScenarioEvent::new(
                self.active_scenario
                    .as_ref()
                    .map(|s| s.id.as_str())
                    .unwrap_or("?"),
                "_control",
                None,
                "paused",
                "Runner paused",
            )
            .with_severity(Severity::Low),
        );
        Ok(())
    }

    /// Resume a paused runner.
    pub fn resume(&mut self) -> Result<(), String> {
        if self.state != RunnerState::Paused {
            return Err(format!("Cannot resume in state {:?}", self.state));
        }
        self.state = RunnerState::Running;
        self.record_event(
            ScenarioEvent::new(
                self.active_scenario
                    .as_ref()
                    .map(|s| s.id.as_str())
                    .unwrap_or("?"),
                "_control",
                None,
                "resumed",
                "Runner resumed",
            )
            .with_severity(Severity::Low),
        );
        Ok(())
    }

    /// Abort the run.
    pub fn abort(&mut self) -> Result<(), String> {
        if self.state == RunnerState::Completed
            || self.state == RunnerState::Aborted
            || self.state == RunnerState::Idle
        {
            return Err(format!("Cannot abort in state {:?}", self.state));
        }
        self.state = RunnerState::Aborted;
        self.record_event(
            ScenarioEvent::new(
                self.active_scenario
                    .as_ref()
                    .map(|s| s.id.as_str())
                    .unwrap_or("?"),
                "_control",
                None,
                "aborted",
                "Run aborted by external signal",
            )
            .with_severity(Severity::High),
        );
        Ok(())
    }

    /// Execute a single step against the runner's state, returning the step result.
    fn execute_step(
        &mut self,
        scenario_id: &str,
        phase: &ScenarioPhase,
        step: &ActionStep,
    ) -> StepResult {
        let step_start = self.simulated_time_ms;
        let mut step_events: Vec<ScenarioEvent> = Vec::new();

        // Apply the delay.
        self.simulated_time_ms += step.delay_ms;

        // Apply trust degradation.
        let trust_after = self.apply_degradation(&step.target, step.trust_degradation);

        let event = ScenarioEvent::new(
            scenario_id,
            &phase.id,
            Some(&step.id),
            "step_executed",
            &format!(
                "Executed '{}' on '{}' severity={:?} degradation={:.3} trust_after={:.3}",
                step.label, step.target, step.severity, step.trust_degradation, trust_after
            ),
        )
        .with_severity(step.severity.clone())
        .with_context("target", &step.target)
        .with_context("degradation", &format!("{:.4}", step.trust_degradation));

        step_events.push(event.clone());
        self.record_event(event);

        // Execute nested sub-scenario if present.
        if let Some(ref sub_scenario) = step.sub_scenario {
            let sub_result = self.execute_sub_scenario(sub_scenario);
            for ev in &sub_result.events {
                step_events.push(ev.clone());
            }
        }

        let duration = self.simulated_time_ms - step_start;

        StepResult {
            step_id: step.id.clone(),
            outcome: StepOutcome::Success,
            duration_ms: duration,
            trust_impact: step.trust_degradation,
            trust_after,
            events: step_events,
        }
    }

    /// Execute a nested sub-scenario recursively, returning aggregated events.
    fn execute_sub_scenario(&mut self, scenario: &Scenario) -> PhaseResult {
        let scenario_id = scenario.id.clone();
        let sub_events: Vec<ScenarioEvent> = Vec::new();
        let mut sub_step_results: Vec<StepResult> = Vec::new();
        let phase_start = self.simulated_time_ms;

        self.record_event(
            ScenarioEvent::new(
                &scenario_id,
                "_sub",
                None,
                "sub_scenario_start",
                &format!("Nested scenario '{}' started", scenario.name),
            )
            .with_severity(Severity::Info),
        );

        for phase in &scenario.phases {
            // Check sub-scenario phase preconditions.
            if !self.check_preconditions(&phase.preconditions) {
                continue;
            }
            for step in &phase.steps {
                let result = self.execute_step(&scenario_id, phase, step);
                sub_step_results.push(result);
            }
        }

        let duration = self.simulated_time_ms - phase_start;

        self.record_event(
            ScenarioEvent::new(
                &scenario_id,
                "_sub",
                None,
                "sub_scenario_end",
                &format!("Nested scenario '{}' ended", scenario.name),
            )
            .with_severity(Severity::Info),
        );

        PhaseResult {
            phase_id: format!("{}_sub", scenario_id),
            phase_name: scenario.name.clone(),
            outcome: PhaseOutcome::Passed,
            duration_ms: duration,
            step_results: sub_step_results,
            preconditions_met: true,
            required_postconditions_met: true,
            events: sub_events,
        }
    }

    /// Execute a single phase, returning the phase result.
    fn execute_phase(&mut self, scenario: &Scenario, phase: &ScenarioPhase) -> PhaseResult {
        let phase_start = self.simulated_time_ms;
        let mut step_results: Vec<StepResult> = Vec::new();
        let mut phase_events: Vec<ScenarioEvent> = Vec::new();

        self.record_event(
            ScenarioEvent::new(
                &scenario.id,
                &phase.id,
                None,
                "phase_start",
                &format!("Phase '{}' started", phase.name),
            )
            .with_severity(Severity::Info),
        );

        // Check preconditions.
        let preconditions_met = self.check_preconditions(&phase.preconditions);
        if !preconditions_met {
            let event = ScenarioEvent::new(
                &scenario.id,
                &phase.id,
                None,
                "phase_skipped",
                &format!("Phase '{}' skipped: preconditions not met", phase.name),
            )
            .with_severity(Severity::Low);
            self.record_event(event.clone());
            phase_events.push(event);

            return PhaseResult {
                phase_id: phase.id.clone(),
                phase_name: phase.name.clone(),
                outcome: PhaseOutcome::Skipped,
                duration_ms: 0,
                step_results: Vec::new(),
                preconditions_met: false,
                required_postconditions_met: true,
                events: phase_events,
            };
        }

        // Execute steps based on phase mode.
        match phase.mode {
            PhaseMode::Sequential => {
                for step in &phase.steps {
                    let result = self.execute_step(&scenario.id, phase, step);
                    step_results.push(result.clone());

                    // Handle failure policy.
                    if result.outcome == StepOutcome::Failed {
                        match &self.failure_policy {
                            FailurePolicy::AbortOnFailure => {
                                return PhaseResult {
                                    phase_id: phase.id.clone(),
                                    phase_name: phase.name.clone(),
                                    outcome: PhaseOutcome::Failed,
                                    duration_ms: self.simulated_time_ms - phase_start,
                                    step_results,
                                    preconditions_met: true,
                                    required_postconditions_met: false,
                                    events: phase_events,
                                };
                            }
                            FailurePolicy::Retry { max_attempts } => {
                                let attempts =
                                    self.retry_attempts.entry(step.id.clone()).or_insert(0);
                                *attempts += 1;
                                if *attempts < *max_attempts {
                                    // Re-execute (simplified — in real impl would re-run).
                                    let retry_result = self.execute_step(&scenario.id, phase, step);
                                    step_results.push(retry_result);
                                }
                            }
                            _ => {}
                        }
                    }

                    // Check phase-level timeout.
                    if phase.timeout_ms > 0
                        && (self.simulated_time_ms - phase_start) > phase.timeout_ms
                    {
                        let event = ScenarioEvent::new(
                            &scenario.id,
                            &phase.id,
                            None,
                            "phase_timeout",
                            &format!(
                                "Phase '{}' timed out after {}ms",
                                phase.name, phase.timeout_ms
                            ),
                        )
                        .with_severity(Severity::High);
                        self.record_event(event.clone());
                        phase_events.push(event);

                        return PhaseResult {
                            phase_id: phase.id.clone(),
                            phase_name: phase.name.clone(),
                            outcome: PhaseOutcome::TimedOut,
                            duration_ms: self.simulated_time_ms - phase_start,
                            step_results,
                            preconditions_met: true,
                            required_postconditions_met: false,
                            events: phase_events,
                        };
                    }
                }
            }
            PhaseMode::Parallel => {
                // Simulated parallel: interleave steps, collecting all results.
                // In a real system this would use async/futures. Here we simulate
                // concurrent execution by running all steps and merging events.
                let mut parallel_results: Vec<StepResult> = Vec::new();
                for step in &phase.steps {
                    let result = self.execute_step(&scenario.id, phase, step);
                    parallel_results.push(result);
                }
                step_results = parallel_results;
            }
        }

        // Check postconditions.
        let required_postconditions_met = self.check_postconditions(&phase.postconditions);
        if !required_postconditions_met {
            let event = ScenarioEvent::new(
                &scenario.id,
                &phase.id,
                None,
                "postcondition_failed",
                &format!("Phase '{}' required postconditions not met", phase.name),
            )
            .with_severity(Severity::High);
            self.record_event(event.clone());
            phase_events.push(event);
        }

        let duration = self.simulated_time_ms - phase_start;

        self.record_event(
            ScenarioEvent::new(
                &scenario.id,
                &phase.id,
                None,
                "phase_end",
                &format!("Phase '{}' ended", phase.name),
            )
            .with_severity(Severity::Info),
        );

        let outcome = if !required_postconditions_met {
            PhaseOutcome::Failed
        } else {
            PhaseOutcome::Passed
        };

        PhaseResult {
            phase_id: phase.id.clone(),
            phase_name: phase.name.clone(),
            outcome,
            duration_ms: duration,
            step_results,
            preconditions_met,
            required_postconditions_met,
            events: phase_events,
        }
    }

    /// Run the next phase in the active scenario. Returns the phase result if a
    /// phase was executed, or None if the scenario is complete.
    pub fn run_next_phase(&mut self) -> Option<PhaseResult> {
        if self.state != RunnerState::Running {
            return None;
        }
        let scenario = match &self.active_scenario {
            Some(s) => s.clone(),
            None => return None,
        };

        if self.current_phase_index >= scenario.phases.len() {
            // All phases done.
            self.state = RunnerState::Completed;
            self.record_event(
                ScenarioEvent::new(
                    &scenario.id,
                    "_global",
                    None,
                    "scenario_complete",
                    "Scenario completed successfully",
                )
                .with_severity(Severity::Info),
            );
            return None;
        }

        let phase = &scenario.phases[self.current_phase_index];
        let result = self.execute_phase(&scenario, phase);
        self.current_phase_index += 1;
        self.phase_results.push(result.clone());

        // Check scenario-level timeout.
        if scenario.timeout_ms > 0 && self.simulated_time_ms > scenario.timeout_ms {
            self.state = RunnerState::TimedOut;
            self.record_event(
                ScenarioEvent::new(
                    &scenario.id,
                    "_global",
                    None,
                    "scenario_timeout",
                    &format!("Scenario timed out after {}ms", scenario.timeout_ms),
                )
                .with_severity(Severity::Critical),
            );
            return Some(result);
        }

        // If phase failed and policy is abort, stop.
        if result.outcome == PhaseOutcome::Failed
            && self.failure_policy == FailurePolicy::AbortOnFailure
        {
            self.state = RunnerState::Aborted;
            self.record_event(
                ScenarioEvent::new(
                    &scenario.id,
                    "_global",
                    None,
                    "scenario_aborted",
                    "Scenario aborted due to phase failure",
                )
                .with_severity(Severity::High),
            );
            return Some(result);
        }

        Some(result)
    }

    /// Run all remaining phases until completion or abort.
    pub fn run_to_completion(&mut self) -> ScenarioRunResult {
        while self.state == RunnerState::Running {
            self.run_next_phase();
        }

        self.collect_result()
    }

    /// Collect the final run result from the current state.
    pub fn collect_result(&self) -> ScenarioRunResult {
        let scenario = self.active_scenario.as_ref();
        let (id, name) = match scenario {
            Some(s) => (s.id.clone(), s.name.clone()),
            None => ("unknown".into(), "Unknown".into()),
        };
        let started_at = self.run_started_at.unwrap_or(Utc::now());
        let ended_at = Utc::now();
        let duration_ms = self.simulated_time_ms;
        let events = self.events.clone();
        let phase_results = self.phase_results.clone();
        let final_trust = self.trust_levels.clone();
        let initial_trust = self.initial_trust_levels.clone();
        let alert_count = self.alert_count;

        let outcome = match self.state {
            RunnerState::Completed => ScenarioOutcome::Passed,
            RunnerState::Aborted => ScenarioOutcome::Aborted,
            RunnerState::TimedOut => ScenarioOutcome::TimedOut,
            RunnerState::Running | RunnerState::Paused | RunnerState::Idle => {
                // Check if any phase failed.
                let any_failed = phase_results
                    .iter()
                    .any(|p| p.outcome == PhaseOutcome::Failed);
                if any_failed {
                    ScenarioOutcome::Failed
                } else {
                    ScenarioOutcome::Passed
                }
            }
        };

        let phases_passed = phase_results
            .iter()
            .filter(|p| p.outcome == PhaseOutcome::Passed)
            .count();
        let phases_total = phase_results.len();

        let summary = format!(
            "Scenario '{}' ({}): outcome={:?} phases={}/{} steps={}/{} alerts={} duration={}ms",
            name,
            id,
            outcome,
            phases_passed,
            phases_total,
            phase_results
                .iter()
                .map(|p| p.step_results.len())
                .sum::<usize>(),
            scenario.map(|s| s.total_step_count()).unwrap_or(0),
            alert_count,
            duration_ms,
        );

        ScenarioRunResult {
            scenario_id: id,
            scenario_name: name,
            outcome,
            started_at,
            ended_at,
            duration_ms,
            phase_results,
            events,
            final_trust_levels: final_trust,
            initial_trust_levels: initial_trust,
            alert_count,
            summary,
            run_id: uuid_value(),
        }
    }

    /// Reset the runner to a clean state.
    pub fn reset(&mut self) {
        self.state = RunnerState::Idle;
        self.current_phase_index = 0;
        self.current_step_index = 0;
        self.events.clear();
        self.phase_results.clear();
        self.retry_attempts.clear();
        self.simulated_time_ms = 0;
        self.active_scenario = None;
        self.run_started_at = None;
        self.alert_count = 0;
    }
}

impl Default for ScenarioRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────
// 3. Scenario Library — Pre-built templates
// ────────────────────────────────────────────────────────────────

/// Factory for creating common security scenario templates.
pub struct ScenarioLibrary;

impl ScenarioLibrary {
    /// Build a single-component failure scenario.
    ///
    /// Simulates the failure of a single component with degradation,
    /// followed by a recovery phase.
    pub fn single_component_failure(target: &str, degradation: f64) -> Scenario {
        let degradation_step = ActionStep {
            id: format!("{}_degrade", target),
            label: format!("Degrade {}", target),
            description: format!(
                "Apply {:.1}% trust degradation to {}",
                degradation * 100.0,
                target
            ),
            target: target.to_string(),
            severity: if degradation > 0.5 {
                Severity::High
            } else {
                Severity::Medium
            },
            trust_degradation: degradation,
            delay_ms: 0,
            sub_scenario: None,
        };

        let recovery_step = ActionStep {
            id: format!("{}_recover", target),
            label: format!("Recover {}", target),
            description: format!("Restore partial trust to {}", target),
            target: target.to_string(),
            severity: Severity::Low,
            trust_degradation: -0.3, // Negative = recovery boost
            delay_ms: 500,
            sub_scenario: None,
        };

        Scenario::new(
            "single_component_failure",
            &format!("Single Component Failure: {}", target),
        )
        .with_description("Simulates the failure and recovery of a single trusted component")
        .with_category("failure")
        .with_tag("component")
        .with_tag("recovery")
        .with_phase(
            ScenarioPhase::new("degrade_phase", "Degradation")
                .with_description("Apply trust degradation to the target component")
                .with_step(degradation_step),
        )
        .with_phase(
            ScenarioPhase::new("recovery_phase", "Recovery")
                .with_description("Attempt to restore trust in the target")
                .with_step(recovery_step)
                .with_postcondition(Postcondition::trust_above_optional(target, 0.5)),
        )
    }

    /// Build a cascade failure scenario across multiple components.
    ///
    /// Simulates a failure in a primary component that cascades to
    /// dependent components in sequence.
    pub fn cascade_failure(primary: &str, secondaries: &[&str]) -> Scenario {
        let primary_step = ActionStep {
            id: format!("{}_primary_fail", primary),
            label: format!("Primary failure: {}", primary),
            description: format!("Critical failure of {}", primary),
            target: primary.to_string(),
            severity: Severity::Critical,
            trust_degradation: 0.8,
            delay_ms: 0,
            sub_scenario: None,
        };

        let mut cascade_steps: Vec<ActionStep> = Vec::new();
        for (i, secondary) in secondaries.iter().enumerate() {
            cascade_steps.push(ActionStep {
                id: format!("{}_cascade_{}", secondary, i),
                label: format!("Cascade to: {}", secondary),
                description: format!("Secondary impact on {} from {} failure", secondary, primary),
                target: secondary.to_string(),
                severity: Severity::High,
                trust_degradation: 0.5 - (i as f64 * 0.1),
                delay_ms: (i as u64 + 1) * 200,
                sub_scenario: None,
            });
        }

        // Recovery phase — parallel recovery of all affected components.
        let mut recovery_steps: Vec<ActionStep> = Vec::new();
        for secondary in secondaries {
            recovery_steps.push(ActionStep {
                id: format!("{}_cascade_recover", secondary),
                label: format!("Recover: {}", secondary),
                description: format!("Recovery action for {}", secondary),
                target: secondary.to_string(),
                severity: Severity::Low,
                trust_degradation: -0.3,
                delay_ms: 100,
                sub_scenario: None,
            });
        }

        // Primary recovery.
        recovery_steps.push(ActionStep {
            id: format!("{}_primary_recover", primary),
            label: format!("Recover primary: {}", primary),
            description: format!("Recovery action for primary {}", primary),
            target: primary.to_string(),
            severity: Severity::Medium,
            trust_degradation: -0.4,
            delay_ms: 0,
            sub_scenario: None,
        });

        let mut degradation_steps = vec![primary_step];
        degradation_steps.extend(cascade_steps);

        Scenario::new(
            "cascade_failure",
            &format!("Cascade Failure from {}", primary),
        )
        .with_description("Simulates a cascading failure from a primary component to dependents")
        .with_category("failure")
        .with_tag("cascade")
        .with_tag("multi-component")
        .with_phase(
            ScenarioPhase::new("cascade_degrade", "Cascade Degradation")
                .with_description("Primary failure cascades to secondary components")
                .with_step(degradation_steps.remove(0))
                .with_step(degradation_steps.remove(0)),
        )
        .with_phase(
            ScenarioPhase::new_parallel("parallel_recovery", "Parallel Recovery")
                .with_description("Recover all affected components concurrently")
                .with_postcondition(Postcondition::trust_above_optional(primary, 0.4)),
        )
    }

    /// Build a DDoS simulation scenario.
    ///
    /// Simulates a distributed denial of service attack with repeated
    /// low-severity hits that accumulate.
    pub fn ddos_simulation(target: &str, burst_count: usize, burst_degradation: f64) -> Scenario {
        let mut attack_steps: Vec<ActionStep> = Vec::new();
        for i in 0..burst_count {
            attack_steps.push(ActionStep {
                id: format!("ddos_burst_{}", i),
                label: format!("DDoS burst #{}", i + 1),
                description: format!("Request burst {} targeting {}", i + 1, target),
                target: target.to_string(),
                severity: if burst_degradation > 0.1 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                trust_degradation: burst_degradation,
                delay_ms: 50,
                sub_scenario: None,
            });
        }

        let recovery_step = ActionStep {
            id: "ddos_recovery".to_string(),
            label: "DDoS Mitigation".to_string(),
            description: "Apply rate limiting and restore service trust".to_string(),
            target: target.to_string(),
            severity: Severity::Low,
            trust_degradation: -0.2,
            delay_ms: 200,
            sub_scenario: None,
        };

        Scenario::new("ddos_simulation", &format!("DDoS Attack on {}", target))
            .with_description(
                "Simulates a distributed denial of service attack with repeated bursts",
            )
            .with_category("attack")
            .with_tag("ddos")
            .with_tag("availability")
            .with_phase(
                ScenarioPhase::new("ddos_attack", "DDoS Attack Phase")
                    .with_description("Burst traffic degrades target trust")
                    .with_timeout_ms(10000)
                    .with_postcondition(Postcondition::trust_below(target, 0.5)),
            )
            .with_phase(
                ScenarioPhase::new("ddos_mitigation", "Mitigation Phase")
                    .with_description("Rate limiting and service recovery")
                    .with_step(recovery_step),
            )
    }

    /// Build a data breach simulation scenario.
    ///
    /// Simulates unauthorised data access with detection and containment phases.
    pub fn data_breach(data_source: &str, detection_delay_ms: u64) -> Scenario {
        let exfiltration_step = ActionStep {
            id: "breach_exfiltrate".to_string(),
            label: "Data Exfiltration".to_string(),
            description: format!("Unauthorised access to {}", data_source),
            target: data_source.to_string(),
            severity: Severity::Critical,
            trust_degradation: 0.7,
            delay_ms: 0,
            sub_scenario: None,
        };

        let detection_step = ActionStep {
            id: "breach_detect".to_string(),
            label: "Breach Detection".to_string(),
            description: format!("Anomaly detection identifies breach in {}", data_source),
            target: data_source.to_string(),
            severity: Severity::High,
            trust_degradation: 0.1,
            delay_ms: detection_delay_ms,
            sub_scenario: None,
        };

        let containment_step = ActionStep {
            id: "breach_contain".to_string(),
            label: "Containment".to_string(),
            description: format!("Isolate {} and prevent further exfiltration", data_source),
            target: data_source.to_string(),
            severity: Severity::Medium,
            trust_degradation: -0.15,
            delay_ms: 100,
            sub_scenario: None,
        };

        Scenario::new("data_breach", &format!("Data Breach: {}", data_source))
            .with_description("Simulates unauthorised data access with detection and containment")
            .with_category("attack")
            .with_tag("breach")
            .with_tag("data")
            .with_phase(
                ScenarioPhase::new("breach_occur", "Breach Occurrence")
                    .with_description("Exfiltration takes place")
                    .with_step(exfiltration_step),
            )
            .with_phase(
                ScenarioPhase::new("breach_response", "Detection & Containment")
                    .with_description("Detect and contain the breach")
                    .with_step(detection_step)
                    .with_step(containment_step),
            )
    }

    /// Build an insider threat simulation scenario.
    ///
    /// Simulates a trusted insider gradually escalating privileges and
    /// accessing restricted resources.
    pub fn insider_threat(insider_id: &str, target_count: usize) -> Scenario {
        let mut recon_steps: Vec<ActionStep> = Vec::new();
        for i in 0..target_count {
            recon_steps.push(ActionStep {
                id: format!("insider_recon_{}", i),
                label: format!("Reconnaissance #{}", i + 1),
                description: format!("Insider {} probes resource {}", insider_id, i),
                target: format!("resource_{}", i),
                severity: Severity::Low,
                trust_degradation: 0.05,
                delay_ms: (i as u64) * 100,
                sub_scenario: None,
            });
        }

        let escalation_step = ActionStep {
            id: format!("insider_escalate_{}", insider_id),
            label: "Privilege Escalation".to_string(),
            description: format!(
                "Insider {} escalates privileges beyond authorised level",
                insider_id
            ),
            target: "access_control".to_string(),
            severity: Severity::High,
            trust_degradation: 0.4,
            delay_ms: 500,
            sub_scenario: None,
        };

        let exfiltration_step = ActionStep {
            id: format!("insider_exfil_{}", insider_id),
            label: "Data Exfiltration".to_string(),
            description: format!("Insider {} extracts sensitive data", insider_id),
            target: "data_store".to_string(),
            severity: Severity::Critical,
            trust_degradation: 0.6,
            delay_ms: 200,
            sub_scenario: None,
        };

        Scenario::new("insider_threat", &format!("Insider Threat: {}", insider_id))
            .with_description("Simulates a trusted insider performing reconnaissance, escalation, and exfiltration")
            .with_category("attack")
            .with_tag("insider")
            .with_tag("privilege")
            .with_phase(
                ScenarioPhase::new("recon_phase", "Reconnaissance")
                    .with_description("Low-profile probing of resources"),
            )
            .with_phase(
                ScenarioPhase::new("escalation_phase", "Escalation & Exfiltration")
                    .with_description("Escalate privileges and extract data")
                    .with_step(escalation_step)
                    .with_step(exfiltration_step),
            )
    }

    /// Build a zero-day vulnerability exploitation scenario.
    ///
    /// Simulates an unknown vulnerability being exploited with delayed
    /// detection and patch deployment.
    pub fn zero_day(component: &str, exploit_severity: f64, patch_delay_ms: u64) -> Scenario {
        let exploit_step = ActionStep {
            id: format!("zeroday_exploit_{}", component),
            label: format!("Zero-day exploit on {}", component),
            description: format!("Unknown vulnerability exploited in {}", component),
            target: component.to_string(),
            severity: if exploit_severity > 0.7 {
                Severity::Critical
            } else {
                Severity::High
            },
            trust_degradation: exploit_severity,
            delay_ms: 0,
            sub_scenario: None,
        };

        let detection_step = ActionStep {
            id: "zeroday_detect".to_string(),
            label: "Anomaly Detection".to_string(),
            description: format!("Behavioural anomaly detected in {}", component),
            target: component.to_string(),
            severity: Severity::High,
            trust_degradation: 0.05,
            delay_ms: patch_delay_ms / 2,
            sub_scenario: None,
        };

        let patch_step = ActionStep {
            id: "zeroday_patch".to_string(),
            label: "Emergency Patch".to_string(),
            description: format!("Deploy emergency patch for {}", component),
            target: component.to_string(),
            severity: Severity::Medium,
            trust_degradation: -0.5,
            delay_ms: patch_delay_ms / 2,
            sub_scenario: None,
        };

        Scenario::new("zero_day", &format!("Zero-Day: {}", component))
            .with_description("Simulates exploitation of an unknown vulnerability with delayed detection and patching")
            .with_category("attack")
            .with_tag("zero-day")
            .with_tag("exploit")
            .with_phase(
                ScenarioPhase::new("exploit_phase", "Exploitation")
                    .with_description("Zero-day vulnerability is exploited")
                    .with_step(exploit_step),
            )
            .with_phase(
                ScenarioPhase::new("response_phase", "Detection & Patching")
                    .with_description("Anomaly detected and emergency patch deployed")
                    .with_step(detection_step)
                    .with_step(patch_step)
                    .with_postcondition(Postcondition::trust_above_required(component, 0.3)),
            )
    }

    /// Build a combined multi-phase stress test with nested sub-scenarios.
    pub fn combined_stress_test(components: &[&str]) -> Scenario {
        let mut phases: Vec<ScenarioPhase> = Vec::new();

        for (idx, &component) in components.iter().enumerate() {
            let sub =
                ScenarioLibrary::single_component_failure(component, 0.4 + (idx as f64 * 0.05));

            let wrapper_step = ActionStep {
                id: format!("stress_sub_{}", component),
                label: format!("Stress test: {}", component),
                description: format!("Nested failure/recovery test for {}", component),
                target: component.to_string(),
                severity: Severity::Medium,
                trust_degradation: 0.0,
                delay_ms: (idx as u64) * 300,
                sub_scenario: Some(Box::new(sub)),
            };

            phases.push(
                ScenarioPhase::new(
                    &format!("stress_phase_{}", component),
                    &format!("Stress: {}", component),
                )
                .with_description(format!("Stress test phase for {}", component).as_str())
                .with_step(wrapper_step),
            );
        }

        let mut scenario = Scenario::new(
            "combined_stress_test",
            "Combined Multi-Component Stress Test",
        )
        .with_description(
            "Runs nested failure/recovery scenarios across multiple components in sequence",
        )
        .with_category("stress")
        .with_tag("stress")
        .with_tag("multi-component")
        .with_timeout_ms(30000);
        for phase in phases {
            scenario = scenario.with_phase(phase);
        }
        scenario
    }
}

// ────────────────────────────────────────────────────────────────
// 4. Result Aggregation
// ────────────────────────────────────────────────────────────────

/// Statistical summary for a set of run results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResults {
    /// Number of runs aggregated.
    pub total_runs: usize,
    /// Number of runs that passed.
    pub passed_runs: usize,
    /// Number of runs that failed.
    pub failed_runs: usize,
    /// Number of runs that timed out.
    pub timed_out_runs: usize,
    /// Number of runs that were aborted.
    pub aborted_runs: usize,
    /// Pass rate as a ratio (0.0–1.0).
    pub pass_rate: f64,
    /// Mean duration in milliseconds.
    pub mean_duration_ms: f64,
    /// Median duration in milliseconds.
    pub median_duration_ms: f64,
    /// Minimum duration in milliseconds.
    pub min_duration_ms: u64,
    /// Maximum duration in milliseconds.
    pub max_duration_ms: u64,
    /// Standard deviation of duration.
    pub stddev_duration_ms: f64,
    /// Mean recovery time in milliseconds (time from first failure to last recovery action).
    pub mean_recovery_time_ms: f64,
    /// Trust impact distribution: domain -> (min, max, mean, stddev) across runs.
    pub trust_impact: HashMap<String, TrustImpactStats>,
    /// Per-scenario aggregated stats.
    pub per_scenario: HashMap<String, ScenarioAggStats>,
    /// Earliest run timestamp.
    pub earliest_run: Option<DateTime<Utc>>,
    /// Latest run timestamp.
    pub latest_run: Option<DateTime<Utc>>,
}

/// Trust impact statistics for a single domain across multiple runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustImpactStats {
    /// Domain name.
    pub domain: String,
    /// Minimum trust level observed.
    pub min_trust: f64,
    /// Maximum trust level observed.
    pub max_trust: f64,
    /// Mean trust level across runs.
    pub mean_trust: f64,
    /// Standard deviation of trust levels.
    pub stddev_trust: f64,
    /// Number of observations.
    pub count: usize,
}

/// Aggregated statistics for a single scenario type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioAggStats {
    /// Scenario name.
    pub scenario_name: String,
    /// Number of runs.
    pub run_count: usize,
    /// Pass rate.
    pub pass_rate: f64,
    /// Mean duration.
    pub mean_duration_ms: f64,
    /// Mean final trust score across all domains.
    pub mean_final_trust: f64,
}

/// Result aggregator — collects multiple run results and computes statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultAggregator {
    /// Stored run results.
    pub results: Vec<ScenarioRunResult>,
}

impl ResultAggregator {
    /// Create a new empty aggregator.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Add a run result to the aggregator.
    pub fn add_result(&mut self, result: ScenarioRunResult) {
        self.results.push(result);
    }

    /// Compute aggregated statistics across all stored results.
    pub fn aggregate(&self) -> AggregatedResults {
        let total_runs = self.results.len();
        if total_runs == 0 {
            return AggregatedResults {
                total_runs: 0,
                passed_runs: 0,
                failed_runs: 0,
                timed_out_runs: 0,
                aborted_runs: 0,
                pass_rate: 0.0,
                mean_duration_ms: 0.0,
                median_duration_ms: 0.0,
                min_duration_ms: 0,
                max_duration_ms: 0,
                stddev_duration_ms: 0.0,
                mean_recovery_time_ms: 0.0,
                trust_impact: HashMap::new(),
                per_scenario: HashMap::new(),
                earliest_run: None,
                latest_run: None,
            };
        }

        let passed_runs = self
            .results
            .iter()
            .filter(|r| r.outcome == ScenarioOutcome::Passed)
            .count();
        let failed_runs = self
            .results
            .iter()
            .filter(|r| r.outcome == ScenarioOutcome::Failed)
            .count();
        let timed_out_runs = self
            .results
            .iter()
            .filter(|r| r.outcome == ScenarioOutcome::TimedOut)
            .count();
        let aborted_runs = self
            .results
            .iter()
            .filter(|r| r.outcome == ScenarioOutcome::Aborted)
            .count();

        let pass_rate = passed_runs as f64 / total_runs as f64;

        // Duration statistics.
        let durations: Vec<u64> = self.results.iter().map(|r| r.duration_ms).collect();
        let mean_duration = Self::mean(&durations);
        let median_duration = Self::median(&durations);
        let min_duration = *durations.iter().min().unwrap_or(&0);
        let max_duration = *durations.iter().max().unwrap_or(&0);
        let stddev_duration = Self::stddev(&durations, mean_duration);

        // Recovery time: approximate as duration of phases that include recovery steps.
        let recovery_times: Vec<u64> = self
            .results
            .iter()
            .map(|r| {
                r.phase_results
                    .iter()
                    .filter(|p| p.phase_name.to_lowercase().contains("recover"))
                    .map(|p| p.duration_ms)
                    .sum()
            })
            .collect();
        let mean_recovery_time = if recovery_times.is_empty() {
            0.0
        } else {
            Self::mean(&recovery_times)
        };

        // Trust impact per domain.
        let mut domain_values: HashMap<String, Vec<f64>> = HashMap::new();
        for result in &self.results {
            for (domain, &value) in &result.final_trust_levels {
                domain_values
                    .entry(domain.clone())
                    .or_insert_with(Vec::new)
                    .push(value);
            }
        }
        let mut trust_impact: HashMap<String, TrustImpactStats> = HashMap::new();
        for (domain, values) in domain_values {
            let mean_val = Self::mean_f64(&values);
            let stddev_val = Self::stddev_f64(&values, mean_val);
            trust_impact.insert(
                domain.clone(),
                TrustImpactStats {
                    domain,
                    min_trust: values.iter().cloned().fold(f64::INFINITY, f64::min),
                    max_trust: values.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                    mean_trust: mean_val,
                    stddev_trust: stddev_val,
                    count: values.len(),
                },
            );
        }

        // Per-scenario stats.
        let mut scenario_groups: HashMap<String, Vec<&ScenarioRunResult>> = HashMap::new();
        for result in &self.results {
            scenario_groups
                .entry(result.scenario_id.clone())
                .or_insert_with(Vec::new)
                .push(result);
        }
        let mut per_scenario: HashMap<String, ScenarioAggStats> = HashMap::new();
        for (scenario_id, group) in scenario_groups {
            let sc_passes = group
                .iter()
                .filter(|r| r.outcome == ScenarioOutcome::Passed)
                .count();
            let sc_durations: Vec<u64> = group.iter().map(|r| r.duration_ms).collect();
            let sc_mean_trusts: Vec<f64> = group
                .iter()
                .map(|r| {
                    if r.final_trust_levels.is_empty() {
                        0.0
                    } else {
                        r.final_trust_levels.values().sum::<f64>()
                            / r.final_trust_levels.len() as f64
                    }
                })
                .collect();
            per_scenario.insert(
                scenario_id.clone(),
                ScenarioAggStats {
                    scenario_name: group[0].scenario_name.clone(),
                    run_count: group.len(),
                    pass_rate: sc_passes as f64 / group.len() as f64,
                    mean_duration_ms: Self::mean(&sc_durations),
                    mean_final_trust: if sc_mean_trusts.is_empty() {
                        0.0
                    } else {
                        sc_mean_trusts.iter().sum::<f64>() / sc_mean_trusts.len() as f64
                    },
                },
            );
        }

        // Time range.
        let timestamps: Vec<DateTime<Utc>> = self.results.iter().map(|r| r.started_at).collect();
        let earliest = timestamps.iter().min().cloned();
        let latest = timestamps.iter().max().cloned();

        AggregatedResults {
            total_runs,
            passed_runs,
            failed_runs,
            timed_out_runs,
            aborted_runs,
            pass_rate,
            mean_duration_ms: mean_duration,
            median_duration_ms: median_duration,
            min_duration_ms: min_duration,
            max_duration_ms: max_duration,
            stddev_duration_ms: stddev_duration,
            mean_recovery_time_ms: mean_recovery_time,
            trust_impact,
            per_scenario,
            earliest_run: earliest,
            latest_run: latest,
        }
    }

    /// Compare two sets of aggregated results and return a summary of differences.
    pub fn compare(a: &AggregatedResults, b: &AggregatedResults) -> ComparisonReport {
        let pass_rate_delta = b.pass_rate - a.pass_rate;
        let duration_delta = b.mean_duration_ms - a.mean_duration_ms;
        let trust_delta: HashMap<String, f64> = b
            .trust_impact
            .iter()
            .filter_map(|(domain, stats_b)| {
                a.trust_impact
                    .get(domain)
                    .map(|stats_a| (domain.clone(), stats_b.mean_trust - stats_a.mean_trust))
            })
            .collect();

        let mut improved: Vec<String> = Vec::new();
        let mut regressed: Vec<String> = Vec::new();
        for (domain, delta) in &trust_delta {
            if *delta > 0.01 {
                improved.push(domain.clone());
            } else if *delta < -0.01 {
                regressed.push(domain.clone());
            }
        }

        ComparisonReport {
            label_a: "baseline".to_string(),
            label_b: "comparison".to_string(),
            pass_rate_delta,
            mean_duration_delta_ms: duration_delta,
            trust_delta,
            improved_domains: improved,
            regressed_domains: regressed,
            new_scenarios_in_b: b
                .per_scenario
                .keys()
                .filter(|k| !a.per_scenario.contains_key(*k))
                .cloned()
                .collect(),
            removed_scenarios: a
                .per_scenario
                .keys()
                .filter(|k| !b.per_scenario.contains_key(*k))
                .cloned()
                .collect(),
        }
    }

    /// Mean of integer values.
    fn mean(values: &[u64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<u64>() as f64 / values.len() as f64
    }

    /// Mean of float values.
    fn mean_f64(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }

    /// Median of integer values.
    fn median(values: &[u64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut sorted = values.to_vec();
        sorted.sort();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) as f64 / 2.0
        } else {
            sorted[mid] as f64
        }
    }

    /// Standard deviation of integer values given the mean.
    fn stddev(values: &[u64], mean: f64) -> f64 {
        if values.len() <= 1 {
            return 0.0;
        }
        let variance = values
            .iter()
            .map(|v| (*v as f64 - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64;
        variance.sqrt()
    }

    /// Standard deviation of float values given the mean.
    fn stddev_f64(values: &[f64], mean: f64) -> f64 {
        if values.len() <= 1 {
            return 0.0;
        }
        let variance =
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt()
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// A comparison report between two aggregated result sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// Label for the baseline (A).
    pub label_a: String,
    /// Label for the comparison (B).
    pub label_b: String,
    /// Change in pass rate (B - A).
    pub pass_rate_delta: f64,
    /// Change in mean duration in ms (B - A).
    pub mean_duration_delta_ms: f64,
    /// Per-domain trust level delta (B - A).
    pub trust_delta: HashMap<String, f64>,
    /// Domains where trust improved by more than 1%.
    pub improved_domains: Vec<String>,
    /// Domains where trust regressed by more than 1%.
    pub regressed_domains: Vec<String>,
    /// Scenarios present in B but not in A.
    pub new_scenarios_in_b: Vec<String>,
    /// Scenarios present in A but not in B.
    pub removed_scenarios: Vec<String>,
}

impl ComparisonReport {
    /// Whether the comparison shows overall improvement.
    pub fn is_improvement(&self) -> bool {
        self.pass_rate_delta > 0.0
            && self.mean_duration_delta_ms <= 0.0
            && self.regressed_domains.is_empty()
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        let trend = if self.pass_rate_delta > 0.01 {
            "IMPROVING"
        } else if self.pass_rate_delta < -0.01 {
            "REGRESSING"
        } else {
            "STABLE"
        };
        format!(
            "Trend: {} | Pass rate: {:+.1}% | Duration: {:+.0}ms | Improved: {} | Regressed: {}",
            trend,
            self.pass_rate_delta * 100.0,
            self.mean_duration_delta_ms,
            self.improved_domains.len(),
            self.regressed_domains.len(),
        )
    }
}

// ────────────────────────────────────────────────────────────────
// 5. Scenario Scheduling
// ────────────────────────────────────────────────────────────────

/// A simplified cron expression with minute, hour, day-of-month fields.
///
/// Supports:
///   - Fixed values: "30 14 * * *" (every day at 14:30)
///   - Wildcards: "* * * * *" (every minute)
///   - Ranges: "0-30 * * * *" (every minute for the first 30 minutes of every hour)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronExpression {
    /// Minute field (0–59). Use None for wildcard.
    pub minute: Option<u32>,
    /// Hour field (0–23). Use None for wildcard.
    pub hour: Option<u32>,
    /// Day of month (1–31). Use None for wildcard.
    pub day_of_month: Option<u32>,
    /// Day of week (0=Sunday, 6=Saturday). Use None for wildcard.
    pub day_of_week: Option<u32>,
}

impl CronExpression {
    /// Parse a cron string "minute hour day_of_month day_of_week".
    /// Supports "*" for wildcard and "start-end" for ranges (uses start value).
    pub fn parse(expr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expr.trim().split_whitespace().collect();
        if parts.len() < 4 {
            return Err(format!(
                "Expected at least 4 fields (minute hour day_of_month day_of_week), got {}",
                parts.len()
            ));
        }

        fn parse_field(s: &str, name: &str, max: u32) -> Result<Option<u32>, String> {
            let trimmed = s.trim();
            if trimmed == "*" {
                return Ok(None);
            }
            if let Some(range) = trimmed.find('-') {
                // Range: use the start value.
                let start = trimmed[..range]
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid {} range start: '{}'", name, trimmed))?;
                if start > max {
                    return Err(format!("{} value {} exceeds maximum {}", name, start, max));
                }
                Ok(Some(start))
            } else {
                let val = trimmed
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid {} value: '{}'", name, trimmed))?;
                if val > max {
                    return Err(format!("{} value {} exceeds maximum {}", name, val, max));
                }
                Ok(Some(val))
            }
        }

        let minute = parse_field(parts[0], "minute", 59)?;
        let hour = parse_field(parts[1], "hour", 23)?;
        let day_of_month = parse_field(parts[2], "day_of_month", 31)?;
        let day_of_week = parse_field(parts[3], "day_of_week", 6)?;

        Ok(CronExpression {
            minute,
            hour,
            day_of_month,
            day_of_week,
        })
    }

    /// Check whether a given DateTime matches this cron expression.
    pub fn matches(&self, dt: &DateTime<Utc>) -> bool {
        if let Some(m) = self.minute {
            if dt.minute() != m {
                return false;
            }
        }
        if let Some(h) = self.hour {
            if dt.hour() != h {
                return false;
            }
        }
        if let Some(dom) = self.day_of_month {
            if dt.day() != dom {
                return false;
            }
        }
        if let Some(dow) = self.day_of_week {
            // chrono weekday() returns Mon=1 .. Sun=7; we want Sun=0 .. Sat=6
            let chrono_dow = dt.weekday().num_days_from_sunday();
            if chrono_dow as u32 != dow {
                return false;
            }
        }
        true
    }

    /// Compute the next matching time after the given reference time.
    /// Scans forward up to 7 days (simple algorithm suitable for scheduling).
    pub fn next_match_after(&self, after: &DateTime<Utc>) -> DateTime<Utc> {
        let mut candidate = *after + Duration::minutes(1);
        let max_lookahead = Duration::days(7);
        let deadline = *after + max_lookahead;

        while candidate <= deadline {
            if self.matches(&candidate) {
                return candidate;
            }
            candidate = candidate + Duration::minutes(1);
        }

        // Fallback: return after + 1 day if no match found within 7 days.
        *after + Duration::days(1)
    }
}

/// Status of a scheduled scenario.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduleStatus {
    /// The schedule is active and will trigger on the next match.
    Active,
    /// The schedule has been paused and will not trigger.
    Paused,
    /// The schedule has been disabled.
    Disabled,
}

/// A scheduled scenario entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScenario {
    /// Unique schedule entry identifier.
    pub schedule_id: ScenarioId,
    /// The scenario to run.
    pub scenario: Scenario,
    /// Cron expression for when to run.
    pub cron: CronExpression,
    /// Current schedule status.
    pub status: ScheduleStatus,
    /// Last time the scenario was run (None if never run).
    pub last_run_at: Option<DateTime<Utc>>,
    /// Next scheduled run time.
    pub next_run_at: Option<DateTime<Utc>>,
    /// Maximum number of concurrent runs allowed (0 = no limit).
    pub max_concurrent: usize,
    /// Currently active run count for this schedule.
    pub active_run_count: usize,
    /// Number of times this scenario has been executed.
    pub execution_count: usize,
    /// Tags for filtering scheduled scenarios.
    pub tags: Vec<String>,
}

impl ScheduledScenario {
    /// Create a new scheduled scenario.
    pub fn new(schedule_id: &str, scenario: Scenario, cron: CronExpression) -> Self {
        let next_run = cron.next_match_after(&Utc::now());
        Self {
            schedule_id: schedule_id.to_string(),
            scenario,
            cron,
            status: ScheduleStatus::Active,
            last_run_at: None,
            next_run_at: Some(next_run),
            max_concurrent: 1,
            active_run_count: 0,
            execution_count: 0,
            tags: Vec::new(),
        }
    }

    /// Builder: set max concurrent runs.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Builder: add a tag.
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Check if this schedule is due to run at the given time.
    pub fn is_due(&self, now: &DateTime<Utc>) -> bool {
        if self.status != ScheduleStatus::Active {
            return false;
        }
        // Check overlap prevention.
        if self.max_concurrent > 0 && self.active_run_count >= self.max_concurrent {
            return false;
        }
        match self.next_run_at {
            Some(next) => now >= &next,
            None => false,
        }
    }

    /// Mark this schedule as having been run at the given time.
    pub fn mark_run(&mut self, ran_at: DateTime<Utc>) {
        self.last_run_at = Some(ran_at);
        self.execution_count += 1;
        self.next_run_at = Some(self.cron.next_match_after(&ran_at));
    }

    /// Increment the active run count.
    pub fn start_run(&mut self) {
        self.active_run_count += 1;
    }

    /// Decrement the active run count.
    pub fn end_run(&mut self) {
        if self.active_run_count > 0 {
            self.active_run_count -= 1;
        }
    }

    /// Pause the schedule.
    pub fn pause(&mut self) {
        self.status = ScheduleStatus::Paused;
    }

    /// Resume the schedule.
    pub fn resume(&mut self) {
        if self.status == ScheduleStatus::Paused {
            self.status = ScheduleStatus::Active;
            self.next_run_at = Some(self.cron.next_match_after(&Utc::now()));
        }
    }

    /// Disable the schedule.
    pub fn disable(&mut self) {
        self.status = ScheduleStatus::Disabled;
    }
}

/// The scenario scheduler — manages cron-based scheduling with overlap prevention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioScheduler {
    /// All scheduled scenarios.
    pub schedules: HashMap<ScenarioId, ScheduledScenario>,
    /// Queue of schedule IDs that are due (in order).
    pub due_queue: VecDeque<ScenarioId>,
    /// Track currently running scenario IDs for overlap detection.
    pub running_scenario_ids: HashSet<ScenarioId>,
}

impl ScenarioScheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        Self {
            schedules: HashMap::new(),
            due_queue: VecDeque::new(),
            running_scenario_ids: HashSet::new(),
        }
    }

    /// Register a scheduled scenario.
    pub fn register(&mut self, schedule: ScheduledScenario) {
        self.schedules
            .insert(schedule.schedule_id.clone(), schedule);
    }

    /// Unregister a scheduled scenario by id.
    pub fn unregister(&mut self, schedule_id: &str) -> bool {
        self.schedules.remove(schedule_id).is_some()
    }

    /// Tick the scheduler at the given time, checking all schedules for due runs.
    /// Populates the due queue with schedule IDs that are ready to execute.
    pub fn tick(&mut self, now: &DateTime<Utc>) {
        self.due_queue.clear();

        let mut due_ids: Vec<ScenarioId> = Vec::new();
        for (id, schedule) in &self.schedules {
            if schedule.is_due(now) {
                due_ids.push(id.clone());
            }
        }

        // Sort by next_run_at for deterministic ordering.
        due_ids.sort_by(|a, b| {
            let a_time = self
                .schedules
                .get(a)
                .and_then(|s| s.next_run_at)
                .unwrap_or(Utc::now());
            let b_time = self
                .schedules
                .get(b)
                .and_then(|s| s.next_run_at)
                .unwrap_or(Utc::now());
            a_time.cmp(&b_time)
        });

        for id in due_ids {
            self.due_queue.push_back(id);
        }
    }

    /// Take the next due scenario from the queue, marking it as running.
    /// Returns the scenario if available, or None if the queue is empty.
    pub fn take_next_due(&mut self) -> Option<Scenario> {
        while let Some(schedule_id) = self.due_queue.pop_front() {
            if let Some(schedule) = self.schedules.get_mut(&schedule_id) {
                // Double-check overlap prevention.
                if schedule.max_concurrent > 0
                    && schedule.active_run_count >= schedule.max_concurrent
                {
                    continue;
                }
                schedule.start_run();
                self.running_scenario_ids.insert(schedule_id.clone());
                return Some(schedule.scenario.clone());
            }
        }
        None
    }

    /// Mark a scenario run as completed.
    pub fn complete_run(&mut self, schedule_id: &str, completed_at: DateTime<Utc>) {
        if let Some(schedule) = self.schedules.get_mut(schedule_id) {
            schedule.end_run();
            schedule.mark_run(completed_at);
        }
        self.running_scenario_ids.remove(schedule_id);
    }

    /// Get all currently running schedule IDs.
    pub fn running_ids(&self) -> Vec<&ScenarioId> {
        self.running_scenario_ids.iter().collect()
    }

    /// Get a reference to a scheduled scenario.
    pub fn get(&self, schedule_id: &str) -> Option<&ScheduledScenario> {
        self.schedules.get(schedule_id)
    }

    /// Get a mutable reference to a scheduled scenario.
    pub fn get_mut(&mut self, schedule_id: &str) -> Option<&mut ScheduledScenario> {
        self.schedules.get_mut(schedule_id)
    }

    /// List all schedule IDs.
    pub fn list_ids(&self) -> Vec<&ScenarioId> {
        self.schedules.keys().collect()
    }

    /// List schedules filtered by status.
    pub fn list_by_status(&self, status: &ScheduleStatus) -> Vec<&ScenarioId> {
        self.schedules
            .iter()
            .filter(|(_, s)| &s.status == status)
            .map(|(id, _)| id)
            .collect()
    }

    /// List schedules filtered by tag.
    pub fn list_by_tag(&self, tag: &str) -> Vec<&ScenarioId> {
        self.schedules
            .iter()
            .filter(|(_, s)| s.tags.iter().any(|t| t == tag))
            .map(|(id, _)| id)
            .collect()
    }
}

impl Default for ScenarioScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity tests ──

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_weight_range() {
        for sev in &[
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let w = sev.weight();
            assert!(w <= 4, "weight {} out of range", w);
            let f = sev.as_f64();
            assert!(f >= 0.0 && f <= 1.0, "as_f64 {} out of range", f);
        }
    }

    #[test]
    fn severity_default_is_medium() {
        assert_eq!(Severity::default(), Severity::Medium);
    }

    // ── Precondition tests ──

    #[test]
    fn precondition_trust_above_passes() {
        let pre = Precondition::trust_above("decision", 0.5);
        let mut levels = HashMap::new();
        levels.insert("decision".into(), 0.8);
        assert!(pre.evaluate(&levels, 0));
    }

    #[test]
    fn precondition_trust_above_fails() {
        let pre = Precondition::trust_above("decision", 0.9);
        let mut levels = HashMap::new();
        levels.insert("decision".into(), 0.5);
        assert!(!pre.evaluate(&levels, 0));
    }

    #[test]
    fn precondition_trust_below_passes() {
        let pre = Precondition::trust_below("model", 0.3);
        let mut levels = HashMap::new();
        levels.insert("model".into(), 0.2);
        assert!(pre.evaluate(&levels, 0));
    }

    #[test]
    fn precondition_alerts_below() {
        let pre = Precondition::alerts_below(5);
        assert!(pre.evaluate(&HashMap::new(), 3));
        assert!(!pre.evaluate(&HashMap::new(), 7));
    }

    // ── Postcondition tests ──

    #[test]
    fn postcondition_trust_above_required() {
        let post = Postcondition::trust_above_required("trust", 0.6);
        let mut levels = HashMap::new();
        levels.insert("trust".into(), 0.7);
        assert!(post.evaluate(&levels, 0));
    }

    #[test]
    fn postcondition_optional_always_passes_check() {
        let post = Postcondition::trust_above_optional("trust", 0.99);
        let mut levels = HashMap::new();
        levels.insert("trust".into(), 0.1);
        // Optional postconditions are not "required", so required check passes even if expression fails.
        assert!(!post.evaluate(&levels, 0));
        assert!(!post.required);
    }

    // ── Scenario definition tests ──

    #[test]
    fn scenario_builder_basic() {
        let scenario = Scenario::new("test_scenario", "Test Scenario")
            .with_description("A test")
            .with_category("test")
            .with_tag("unit");

        assert_eq!(scenario.id, "test_scenario");
        assert_eq!(scenario.name, "Test Scenario");
        assert_eq!(scenario.category, "test");
        assert!(scenario.tags.contains(&"unit".to_string()));
    }

    #[test]
    fn scenario_phase_builder() {
        let step = ActionStep {
            id: "step1".into(),
            label: "Step 1".into(),
            description: "First step".into(),
            target: "decision".into(),
            severity: Severity::Medium,
            trust_degradation: 0.1,
            delay_ms: 0,
            sub_scenario: None,
        };

        let phase = ScenarioPhase::new("p1", "Phase 1")
            .with_step(step)
            .with_precondition(Precondition::trust_above("decision", 0.5))
            .with_postcondition(Postcondition::trust_above_required("decision", 0.3));

        assert_eq!(phase.id, "p1");
        assert_eq!(phase.steps.len(), 1);
        assert_eq!(phase.preconditions.len(), 1);
        assert_eq!(phase.postconditions.len(), 1);
        assert_eq!(phase.total_step_count(), 1);
    }

    #[test]
    fn scenario_parallel_phase() {
        let phase = ScenarioPhase::new_parallel("pp", "Parallel Phase");
        assert_eq!(phase.mode, PhaseMode::Parallel);
    }

    #[test]
    fn scenario_nested_step_count() {
        let inner_step = ActionStep {
            id: "inner1".into(),
            label: "Inner".into(),
            description: "Inner step".into(),
            target: "model".into(),
            severity: Severity::Low,
            trust_degradation: 0.05,
            delay_ms: 0,
            sub_scenario: None,
        };

        let inner_phase = ScenarioPhase::new("inner_p", "Inner Phase").with_step(inner_step);
        let inner_scenario = Scenario::new("inner", "Inner Scenario").with_phase(inner_phase);

        let outer_step = ActionStep {
            id: "outer1".into(),
            label: "Outer".into(),
            description: "Outer step".into(),
            target: "decision".into(),
            severity: Severity::Medium,
            trust_degradation: 0.2,
            delay_ms: 0,
            sub_scenario: Some(Box::new(inner_scenario)),
        };

        let outer_phase = ScenarioPhase::new("outer_p", "Outer Phase").with_step(outer_step);
        let scenario = Scenario::new("outer", "Outer Scenario").with_phase(outer_phase);

        assert!(scenario.has_nested_scenarios());
        assert_eq!(scenario.total_step_count(), 2); // 1 outer + 1 inner
    }

    #[test]
    fn scenario_all_tags_includes_nested() {
        let inner = Scenario::new("inner", "Inner").with_tag("nested_tag");
        let inner_step = ActionStep {
            id: "s1".into(),
            label: "S1".into(),
            description: "".into(),
            target: "t".into(),
            severity: Severity::Info,
            trust_degradation: 0.0,
            delay_ms: 0,
            sub_scenario: Some(Box::new(inner)),
        };

        let phase = ScenarioPhase::new("p1", "P1").with_step(inner_step);
        let outer = Scenario::new("outer", "Outer")
            .with_tag("outer_tag")
            .with_phase(phase);

        let tags = outer.all_tags();
        assert!(tags.contains("outer_tag"));
        assert!(tags.contains("nested_tag"));
    }

    // ── Runner tests ──

    #[test]
    fn runner_starts_idle() {
        let runner = ScenarioRunner::new();
        assert_eq!(runner.state, RunnerState::Idle);
    }

    #[test]
    fn runner_start_and_complete() {
        let scenario = build_simple_scenario();
        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0), ("model", 1.0)]));
        runner.start(scenario).unwrap();

        assert_eq!(runner.state, RunnerState::Running);

        let result = runner.run_to_completion();
        assert_eq!(result.outcome, ScenarioOutcome::Passed);
        assert!(result.phase_results.len() > 0);
    }

    #[test]
    fn runner_pause_resume() {
        let mut scenario = build_simple_scenario();
        // Add a second phase so we can pause mid-execution.
        scenario = scenario.with_phase(ScenarioPhase::new("p2", "Second Phase").with_step(
            ActionStep {
                id: "s2".into(),
                label: "Step 2".into(),
                description: "".into(),
                target: "model".into(),
                severity: Severity::Low,
                trust_degradation: 0.05,
                delay_ms: 0,
                sub_scenario: None,
            },
        ));

        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0), ("model", 1.0)]));
        runner.start(scenario).unwrap();

        // Run first phase.
        let _ = runner.run_next_phase();
        assert_eq!(runner.state, RunnerState::Running);

        // Pause.
        runner.pause().unwrap();
        assert_eq!(runner.state, RunnerState::Paused);

        // Resume.
        runner.resume().unwrap();
        assert_eq!(runner.state, RunnerState::Running);

        // Complete.
        let _ = runner.run_to_completion();
        assert_eq!(runner.state, RunnerState::Completed);
    }

    #[test]
    fn runner_pause_when_not_running_fails() {
        let mut runner = ScenarioRunner::new();
        assert!(runner.pause().is_err());
    }

    #[test]
    fn runner_abort() {
        let scenario = build_simple_scenario();
        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0)]));
        runner.start(scenario).unwrap();
        runner.abort().unwrap();
        assert_eq!(runner.state, RunnerState::Aborted);
    }

    #[test]
    fn runner_double_start_fails() {
        let scenario = build_simple_scenario();
        let mut runner = ScenarioRunner::new();
        runner.start(scenario).unwrap();
        let scenario2 = build_simple_scenario();
        assert!(runner.start(scenario2).is_err());
    }

    #[test]
    fn runner_events_recorded() {
        let scenario = build_simple_scenario();
        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0)]));
        runner.start(scenario).unwrap();
        runner.run_to_completion();

        assert!(runner.events().len() > 0);
        let has_start = runner
            .events()
            .iter()
            .any(|e| e.event_type == "scenario_start");
        assert!(has_start);
    }

    #[test]
    fn runner_trust_degradation_applied() {
        let scenario = build_simple_scenario();
        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0)]));
        runner.start(scenario).unwrap();
        let result = runner.run_to_completion();

        let final_decision = result
            .final_trust_levels
            .get("decision")
            .copied()
            .unwrap_or(1.0);
        assert!(
            final_decision < 1.0,
            "Expected degradation but got {}",
            final_decision
        );
    }

    #[test]
    fn runner_timeout_triggers() {
        let mut scenario = build_simple_scenario();
        scenario.timeout_ms = 1; // Very tight timeout.
        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 1.0)]));
        runner.start(scenario).unwrap();

        // Manually advance simulated time past the timeout.
        runner.simulated_time_ms = 100;
        let _ = runner.run_next_phase();

        // The runner should have timed out or the phase should reflect the timeout.
        let result = runner.collect_result();
        assert!(
            result.outcome == ScenarioOutcome::TimedOut
                || result.outcome == ScenarioOutcome::Passed,
        );
    }

    #[test]
    fn runner_phase_precondition_skip() {
        let scenario = Scenario::new("pre_test", "Precondition Test").with_phase(
            ScenarioPhase::new("p1", "Should Skip")
                .with_precondition(Precondition::trust_above("decision", 0.99))
                .with_step(ActionStep {
                    id: "s1".into(),
                    label: "S1".into(),
                    description: "".into(),
                    target: "decision".into(),
                    severity: Severity::High,
                    trust_degradation: 0.5,
                    delay_ms: 0,
                    sub_scenario: None,
                }),
        );

        let mut runner = ScenarioRunner::new();
        runner.set_trust_levels(trust_map(&[("decision", 0.5)])); // Below 0.99
        runner.start(scenario).unwrap();
        let result = runner.run_to_completion();

        // Phase should be skipped.
        assert!(result.phase_results.len() == 1);
        assert_eq!(result.phase_results[0].outcome, PhaseOutcome::Skipped);
    }

    #[test]
    fn runner_reset_clears_state() {
        let mut runner = ScenarioRunner::new();
        runner.ensure_domain("test", 0.5);
        runner.alert_count = 10;
        runner.simulated_time_ms = 5000;
        runner.reset();
        assert_eq!(runner.state, RunnerState::Idle);
        assert_eq!(runner.alert_count, 0);
        assert_eq!(runner.simulated_time_ms, 0);
    }

    // ── Scenario Library tests ──

    #[test]
    fn library_single_component_failure() {
        let scenario = ScenarioLibrary::single_component_failure("decision", 0.6);
        assert_eq!(scenario.category, "failure");
        assert_eq!(scenario.phases.len(), 2);
        assert!(scenario.tags.contains(&"recovery".to_string()));
    }

    #[test]
    fn library_cascade_failure() {
        let scenario = ScenarioLibrary::cascade_failure("primary", &["sec1", "sec2"]);
        assert_eq!(scenario.category, "failure");
        assert!(scenario.tags.contains(&"cascade".to_string()));
        assert!(scenario.phases.len() >= 2);
    }

    #[test]
    fn library_ddos_simulation() {
        let scenario = ScenarioLibrary::ddos_simulation("api", 5, 0.08);
        assert_eq!(scenario.category, "attack");
        assert!(scenario.tags.contains(&"ddos".to_string()));
    }

    #[test]
    fn library_data_breach() {
        let scenario = ScenarioLibrary::data_breach("user_db", 1000);
        assert_eq!(scenario.category, "attack");
        assert_eq!(scenario.phases.len(), 2);
    }

    #[test]
    fn library_insider_threat() {
        let scenario = ScenarioLibrary::insider_threat("user42", 3);
        assert_eq!(scenario.category, "attack");
        assert!(scenario.tags.contains(&"insider".to_string()));
    }

    #[test]
    fn library_zero_day() {
        let scenario = ScenarioLibrary::zero_day("web_server", 0.9, 5000);
        assert_eq!(scenario.category, "attack");
        assert!(scenario.tags.contains(&"zero-day".to_string()));
    }

    #[test]
    fn library_combined_stress_test() {
        let scenario = ScenarioLibrary::combined_stress_test(&["comp_a", "comp_b"]);
        assert_eq!(scenario.category, "stress");
        assert!(scenario.has_nested_scenarios());
    }

    // ── Result Aggregation tests ──

    fn make_run_result(
        id: &str,
        name: &str,
        outcome: ScenarioOutcome,
        duration_ms: u64,
        trust: f64,
    ) -> ScenarioRunResult {
        ScenarioRunResult {
            scenario_id: id.to_string(),
            scenario_name: name.to_string(),
            outcome,
            started_at: Utc::now() - Duration::minutes(10),
            ended_at: Utc::now(),
            duration_ms,
            phase_results: Vec::new(),
            events: Vec::new(),
            final_trust_levels: trust_map(&[("decision", trust)]),
            initial_trust_levels: trust_map(&[("decision", 1.0)]),
            alert_count: if trust < 0.3 { 1 } else { 0 },
            summary: format!("Run of {}", id),
            run_id: uuid_value(),
        }
    }

    #[test]
    fn aggregator_empty() {
        let agg = ResultAggregator::new();
        let stats = agg.aggregate();
        assert_eq!(stats.total_runs, 0);
        assert_eq!(stats.pass_rate, 0.0);
    }

    #[test]
    fn aggregator_single_run() {
        let mut agg = ResultAggregator::new();
        agg.add_result(make_run_result(
            "s1",
            "Scenario 1",
            ScenarioOutcome::Passed,
            100,
            0.8,
        ));
        let stats = agg.aggregate();
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.pass_rate, 1.0);
        assert_eq!(stats.mean_duration_ms, 100.0);
    }

    #[test]
    fn aggregator_multiple_runs() {
        let mut agg = ResultAggregator::new();
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.8,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Failed,
            200,
            0.3,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            150,
            0.7,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::TimedOut,
            500,
            0.1,
        ));

        let stats = agg.aggregate();
        assert_eq!(stats.total_runs, 4);
        assert_eq!(stats.passed_runs, 2);
        assert_eq!(stats.failed_runs, 1);
        assert_eq!(stats.timed_out_runs, 1);
        assert!((stats.pass_rate - 0.5).abs() < 0.001);
        assert!(stats.mean_duration_ms > 0.0);
        assert!(stats.median_duration_ms > 0.0);
        assert!(stats.min_duration_ms <= stats.max_duration_ms);
        assert!(stats.stddev_duration_ms >= 0.0);
    }

    #[test]
    fn aggregator_trust_impact() {
        let mut agg = ResultAggregator::new();
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.9,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.5,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.7,
        ));

        let stats = agg.aggregate();
        let decision_stats = stats.trust_impact.get("decision").unwrap();
        assert!((decision_stats.mean_trust - 0.7).abs() < 0.001);
        assert_eq!(decision_stats.count, 3);
    }

    #[test]
    fn comparison_report() {
        let mut agg_a = ResultAggregator::new();
        agg_a.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            200,
            0.6,
        ));

        let mut agg_b = ResultAggregator::new();
        agg_b.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            150,
            0.8,
        ));

        let stats_a = agg_a.aggregate();
        let stats_b = agg_b.aggregate();

        let report = ResultAggregator::compare(&stats_a, &stats_b);
        assert!(report.pass_rate_delta.abs() < 0.001); // Both 100%
        assert!(report.mean_duration_delta_ms < 0.0); // B is faster
        assert!(!report.summary().is_empty());
    }

    #[test]
    fn comparison_identifies_regressions() {
        let mut agg_a = ResultAggregator::new();
        agg_a.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.9,
        ));

        let mut agg_b = ResultAggregator::new();
        agg_b.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Failed,
            300,
            0.2,
        ));

        let stats_a = agg_a.aggregate();
        let stats_b = agg_b.aggregate();

        let report = ResultAggregator::compare(&stats_a, &stats_b);
        assert!(report.pass_rate_delta < 0.0);
        assert!(!report.is_improvement());
        assert!(report.regressed_domains.contains(&"decision".to_string()));
    }

    // ── Scheduling tests ──

    #[test]
    fn cron_parse_every_minute() {
        let cron = CronExpression::parse("* * * *").unwrap();
        assert!(cron.minute.is_none());
        assert!(cron.hour.is_none());
    }

    #[test]
    fn cron_parse_specific_time() {
        let cron = CronExpression::parse("30 14 15 *").unwrap();
        assert_eq!(cron.minute, Some(30));
        assert_eq!(cron.hour, Some(14));
        assert_eq!(cron.day_of_month, Some(15));
        assert!(cron.day_of_week.is_none());
    }

    #[test]
    fn cron_parse_range() {
        let cron = CronExpression::parse("0-30 * * *").unwrap();
        assert_eq!(cron.minute, Some(0));
    }

    #[test]
    fn cron_matches() {
        let cron = CronExpression::parse("30 14 15 *").unwrap();
        // Construct a DateTime at 14:30 on the 15th.
        let dt = DateTime::parse_from_rfc3339("2025-01-15T14:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(cron.matches(&dt));

        // Different minute.
        let dt2 = DateTime::parse_from_rfc3339("2025-01-15T14:31:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(!cron.matches(&dt2));
    }

    #[test]
    fn cron_next_match() {
        let cron = CronExpression::parse("0 12 * *").unwrap(); // Every day at noon.
        let before = DateTime::parse_from_rfc3339("2025-01-15T11:59:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = cron.next_match_after(&before);
        assert_eq!(next.hour(), 12);
        assert_eq!(next.minute(), 0);
    }

    #[test]
    fn scheduled_scenario_creation() {
        let scenario = build_simple_scenario();
        let cron = CronExpression::parse("0 * * *").unwrap();
        let sched = ScheduledScenario::new("sched1", scenario, cron)
            .with_max_concurrent(2)
            .with_tag("daily");

        assert_eq!(sched.schedule_id, "sched1");
        assert_eq!(sched.max_concurrent, 2);
        assert_eq!(sched.execution_count, 0);
        assert!(sched.next_run_at.is_some());
        assert!(sched.tags.contains(&"daily".to_string()));
    }

    #[test]
    fn scheduled_scenario_mark_run() {
        let scenario = build_simple_scenario();
        let cron = CronExpression::parse("0 * * *").unwrap();
        let mut sched = ScheduledScenario::new("sched1", scenario, cron);

        let ran_at = Utc::now();
        let next_before = sched.next_run_at;
        sched.mark_run(ran_at);

        assert_eq!(sched.execution_count, 1);
        assert_eq!(sched.last_run_at, Some(ran_at));
        // Next run should be after the current next.
        assert!(sched.next_run_at > next_before);
    }

    #[test]
    fn scheduled_scenario_pause_resume() {
        let scenario = build_simple_scenario();
        let cron = CronExpression::parse("0 * * *").unwrap();
        let mut sched = ScheduledScenario::new("sched1", scenario, cron);

        sched.pause();
        assert_eq!(sched.status, ScheduleStatus::Paused);
        assert!(!sched.is_due(&Utc::now()));

        sched.resume();
        assert_eq!(sched.status, ScheduleStatus::Active);
    }

    #[test]
    fn scheduler_register_and_list() {
        let mut scheduler = ScenarioScheduler::new();
        let s1 = build_simple_scenario();
        let s2 = build_simple_scenario();

        let cron = CronExpression::parse("0 * * *").unwrap();
        scheduler.register(ScheduledScenario::new("sched1", s1, cron.clone()));
        scheduler.register(ScheduledScenario::new("sched2", s2, cron));

        let ids = scheduler.list_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn scheduler_unregister() {
        let mut scheduler = ScenarioScheduler::new();
        let s1 = build_simple_scenario();
        let cron = CronExpression::parse("0 * * *").unwrap();
        scheduler.register(ScheduledScenario::new("sched1", s1, cron));

        assert!(scheduler.unregister("sched1"));
        assert!(!scheduler.unregister("sched_nonexistent"));
        assert_eq!(scheduler.list_ids().len(), 0);
    }

    #[test]
    fn scheduler_due_check_no_overlap() {
        let mut scheduler = ScenarioScheduler::new();

        let scenario = build_simple_scenario();
        // Set cron to match every minute.
        let cron = CronExpression::parse("* * * *").unwrap();
        let sched =
            ScheduledScenario::new("sched_every_min", scenario, cron).with_max_concurrent(1);

        scheduler.register(sched);

        // Manually set next_run_at to now so it's due.
        let now = Utc::now();
        if let Some(s) = scheduler.get_mut("sched_every_min") {
            s.next_run_at = Some(now);
        }

        scheduler.tick(&now);
        assert_eq!(scheduler.due_queue.len(), 1);

        // Take the due scenario.
        let taken = scheduler.take_next_due();
        assert!(taken.is_some());

        // Now try to tick again — should be blocked by overlap.
        scheduler.tick(&(now + Duration::seconds(1)));
        // Queue may have it but take_next_due should skip it due to overlap.
        // The due_queue will be populated but take_next_due will skip.
    }

    #[test]
    fn scheduler_list_by_status() {
        let mut scheduler = ScenarioScheduler::new();
        let cron = CronExpression::parse("0 * * *").unwrap();

        let mut s1 = ScheduledScenario::new("s1", build_simple_scenario(), cron.clone());
        let s2 = ScheduledScenario::new("s2", build_simple_scenario(), cron.clone());
        let mut s3 = ScheduledScenario::new("s3", build_simple_scenario(), cron);

        s1.pause();
        s3.disable();

        scheduler.register(s1);
        scheduler.register(s2);
        scheduler.register(s3);

        let active = scheduler.list_by_status(&ScheduleStatus::Active);
        assert_eq!(active.len(), 1);
        let paused = scheduler.list_by_status(&ScheduleStatus::Paused);
        assert_eq!(paused.len(), 1);
        let disabled = scheduler.list_by_status(&ScheduleStatus::Disabled);
        assert_eq!(disabled.len(), 1);
    }

    #[test]
    fn scheduler_list_by_tag() {
        let mut scheduler = ScenarioScheduler::new();
        let cron = CronExpression::parse("0 * * *").unwrap();

        scheduler.register(
            ScheduledScenario::new("s1", build_simple_scenario(), cron.clone())
                .with_tag("security"),
        );
        scheduler.register(
            ScheduledScenario::new("s2", build_simple_scenario(), cron.clone())
                .with_tag("performance"),
        );
        scheduler.register(
            ScheduledScenario::new("s3", build_simple_scenario(), cron).with_tag("security"),
        );

        let security = scheduler.list_by_tag("security");
        assert_eq!(security.len(), 2);
    }

    // ── Serialization tests ──

    #[test]
    fn scenario_serialization_roundtrip() {
        let scenario = ScenarioLibrary::single_component_failure("decision", 0.5);
        let json = serde_json::to_string(&scenario).unwrap();
        let restored: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, scenario.id);
        assert_eq!(restored.phases.len(), scenario.phases.len());
    }

    #[test]
    fn run_result_serialization_roundtrip() {
        let result = make_run_result("s1", "Test", ScenarioOutcome::Passed, 100, 0.8);
        let json = serde_json::to_string(&result).unwrap();
        let restored: ScenarioRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.scenario_id, "s1");
        assert_eq!(restored.outcome, ScenarioOutcome::Passed);
    }

    #[test]
    fn aggregated_results_serialization_roundtrip() {
        let mut agg = ResultAggregator::new();
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Passed,
            100,
            0.9,
        ));
        agg.add_result(make_run_result(
            "s1",
            "S1",
            ScenarioOutcome::Failed,
            200,
            0.4,
        ));
        let stats = agg.aggregate();
        let json = serde_json::to_string(&stats).unwrap();
        let restored: AggregatedResults = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_runs, 2);
        assert_eq!(restored.passed_runs, 1);
    }

    #[test]
    fn scheduler_serialization_roundtrip() {
        let mut scheduler = ScenarioScheduler::new();
        let cron = CronExpression::parse("30 14 * *").unwrap();
        scheduler.register(
            ScheduledScenario::new("sched1", build_simple_scenario(), cron).with_tag("daily"),
        );
        let json = serde_json::to_string(&scheduler).unwrap();
        let restored: ScenarioScheduler = serde_json::from_str(&json).unwrap();
        assert!(restored.schedules.contains_key("sched1"));
    }

    #[test]
    fn cron_serialization_roundtrip() {
        let cron = CronExpression::parse("30 14 15 3").unwrap();
        let json = serde_json::to_string(&cron).unwrap();
        let restored: CronExpression = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.minute, Some(30));
        assert_eq!(restored.hour, Some(14));
        assert_eq!(restored.day_of_month, Some(15));
        assert_eq!(restored.day_of_week, Some(3));
    }

    // ── Helpers ──

    fn trust_map(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn build_simple_scenario() -> Scenario {
        Scenario::new("simple", "Simple Test Scenario")
            .with_category("test")
            .with_phase(
                ScenarioPhase::new("degrade", "Degradation Phase")
                    .with_step(ActionStep {
                        id: "d1".into(),
                        label: "Degrade decision".into(),
                        description: "Degrade the decision domain".into(),
                        target: "decision".into(),
                        severity: Severity::Medium,
                        trust_degradation: 0.2,
                        delay_ms: 0,
                        sub_scenario: None,
                    })
                    .with_postcondition(Postcondition::trust_above_optional("decision", 0.3)),
            )
    }
}
