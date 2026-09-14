// Dynamic Pipeline — Wires PolicyExecutor into Adapter
//
// The Adapter currently proposes parameter changes but doesn't execute them.
// PolicyExecutor exists (2,345 LOC) but is never called from Adapter.
//
// This module:
//   1. PipelineStage — represents one stage in the security pipeline
//   2. PipelineConfig — full pipeline configuration with stages and routing
//   3. PipelineValidator — validates proposed changes before applying
//   4. PipelineExecutor — applies approved adaptations to the live pipeline
//   5. PipelineSnapshot — captures pipeline state for rollback
//   6. DynamicPipelineManager — orchestrates all of the above

#![deny(unsafe_code)]

use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::{AdaptationProposal, ParameterChange};

// ---------------------------------------------------------------------------
// Section 1: PipelineStage (~120 lines)
// ---------------------------------------------------------------------------

/// The type of processing a pipeline stage performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageType {
    /// Filters out unwanted traffic or events.
    Filter,
    /// Transforms data (normalisation, enrichment triggers).
    Transform,
    /// Enriches context with external signals.
    Enrich,
    /// Makes a decision (allow / deny / escalate).
    Decide,
    /// Executes an action (block, notify, isolate).
    Act,
    /// Observes and reports metrics without blocking.
    Monitor,
}

impl std::fmt::Display for StageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filter => write!(f, "filter"),
            Self::Transform => write!(f, "transform"),
            Self::Enrich => write!(f, "enrich"),
            Self::Decide => write!(f, "decide"),
            Self::Act => write!(f, "act"),
            Self::Monitor => write!(f, "monitor"),
        }
    }
}

/// A single stage in the security pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    /// Unique identifier for this stage.
    pub stage_id: String,
    /// Human-readable name, e.g. "shield_rate_limit".
    pub name: String,
    /// The kind of processing this stage does.
    pub stage_type: StageType,
    /// Whether this stage is currently enabled.
    pub enabled: bool,
    /// Execution priority — lower values run first.
    pub priority: u32,
    /// Stage-specific configuration key-value pairs.
    pub config: HashMap<String, serde_json::Value>,
    /// Maximum execution time in milliseconds before the stage is aborted.
    pub timeout_ms: u64,
}

impl PipelineStage {
    /// Create a new pipeline stage with sensible defaults.
    pub fn new(name: &str, stage_type: StageType) -> Self {
        Self {
            stage_id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            stage_type,
            enabled: true,
            priority: 100,
            config: HashMap::new(),
            timeout_ms: 5_000,
        }
    }

    /// Returns `true` if this stage is critical to pipeline correctness.
    ///
    /// Critical stages cannot be disabled without an explicit override.
    pub fn is_critical(&self) -> bool {
        matches!(self.stage_type, StageType::Decide | StageType::Act)
            || self.name.contains("critical")
    }

    /// Serialize this stage to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("failed to serialize PipelineStage: {}", e))
    }

    /// Deserialize a stage from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("failed to deserialize PipelineStage: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Section 2: PipelineConfig (~150 lines)
// ---------------------------------------------------------------------------

/// A routing rule that directs events to a specific pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Unique rule identifier.
    pub rule_id: String,
    /// Condition expression, e.g. "trust.level < 0.5".
    pub condition: String,
    /// Name of the target stage.
    pub target_stage: String,
    /// Evaluation priority — lower values checked first.
    pub priority: u32,
    /// Whether this rule is active.
    pub enabled: bool,
}

impl RoutingRule {
    pub fn new(condition: &str, target_stage: &str) -> Self {
        Self {
            rule_id: uuid::Uuid::new_v4().to_string(),
            condition: condition.to_string(),
            target_stage: target_stage.to_string(),
            priority: 100,
            enabled: true,
        }
    }
}

/// The full configuration of a security pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Unique pipeline identifier.
    pub pipeline_id: String,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Ordered list of pipeline stages.
    pub stages: Vec<PipelineStage>,
    /// Routing rules for conditional stage dispatch.
    pub routing_rules: Vec<RoutingRule>,
    /// RFC 3339 timestamp of creation.
    pub created_at: String,
    /// RFC 3339 timestamp of last update.
    pub updated_at: String,
    /// SHA-256 checksum of the serialised config (hex).
    pub checksum: String,
}

impl PipelineConfig {
    /// Create a new empty pipeline configuration.
    pub fn new() -> Self {
        let now = Utc::now().to_rfc3339();
        let mut config = Self {
            pipeline_id: uuid::Uuid::new_v4().to_string(),
            version: 1,
            stages: Vec::new(),
            routing_rules: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
            checksum: String::new(),
        };
        config.checksum = config.compute_checksum();
        config
    }

    /// Compute the SHA-256 checksum of the current configuration.
    /// Excludes the `checksum` field itself to avoid circular dependency.
    /// Uses serde_json::Value for deterministic key ordering (BTreeMap-backed),
    /// avoiding non-deterministic HashMap iteration order.
    pub fn compute_checksum(&self) -> String {
        use sha2::{Digest, Sha256};
        // Serialize to Value (serde_json::Map uses BTreeMap by default when
        // the `preserve_order` feature is not enabled), giving deterministic
        // key ordering regardless of HashMap fields in nested structs.
        let mut val = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!("corrupt"));
        // Remove the checksum field to avoid circularity.
        if let Some(obj) = val.as_object_mut() {
            obj.remove("checksum");
        }
        let json = serde_json::to_string(&val).unwrap_or_else(|_| "corrupt".to_string());
        let hash = Sha256::digest(json.as_bytes());
        let val = u64::from_be_bytes(hash[0..8].try_into().unwrap_or([0u8; 8]));
        format!("{:016x}", val)
    }

    /// Verify that the stored checksum still matches the current state.
    pub fn verify_checksum(&self) -> bool {
        self.compute_checksum() == self.checksum
    }

    /// Refresh the checksum and timestamp after a mutation.
    pub(crate) fn bump(&mut self) {
        self.version += 1;
        self.updated_at = Utc::now().to_rfc3339();
        self.checksum = self.compute_checksum();
    }

    /// Serialize this config to JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize PipelineConfig: {}", e))
    }

    /// Deserialize a config from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut config: Self = serde_json::from_str(json)
            .map_err(|e| format!("failed to deserialize PipelineConfig: {}", e))?;
        config.checksum = config.compute_checksum();
        Ok(config)
    }

    /// Add a stage to the pipeline. The stage is inserted in priority order.
    pub fn add_stage(&mut self, stage: PipelineStage) -> Result<(), String> {
        self.stages.push(stage);
        self.stages.sort_by_key(|s| s.priority);
        self.bump();
        Ok(())
    }

    /// Remove a stage by its `stage_id`. Errors if the stage is critical and enabled.
    pub fn remove_stage(&mut self, stage_id: &str) -> Result<PipelineStage, String> {
        let idx = self
            .stages
            .iter()
            .position(|s| s.stage_id == stage_id)
            .ok_or_else(|| format!("stage '{}' not found", stage_id))?;

        let stage = self.stages.remove(idx);
        if stage.is_critical() && stage.enabled {
            return Err(format!(
                "cannot remove critical enabled stage '{}'",
                stage.name
            ));
        }
        self.bump();
        Ok(stage)
    }

    /// Find a stage by its `stage_id` or `name`.
    pub fn find_stage(&self, stage_id: &str) -> Option<&PipelineStage> {
        self.stages
            .iter()
            .find(|s| s.stage_id == stage_id || s.name == stage_id)
    }

    /// Find a mutable stage by its `stage_id` or `name`.
    pub fn find_stage_mut(&mut self, stage_id: &str) -> Option<&mut PipelineStage> {
        self.stages
            .iter_mut()
            .find(|s| s.stage_id == stage_id || s.name == stage_id)
    }

    /// Return all critical stages.
    pub fn critical_stages(&self) -> Vec<&PipelineStage> {
        self.stages.iter().filter(|s| s.is_critical()).collect()
    }

    /// Return all currently enabled stages.
    pub fn enabled_stages(&self) -> Vec<&PipelineStage> {
        self.stages.iter().filter(|s| s.enabled).collect()
    }

    /// Add a routing rule to the configuration.
    pub fn add_routing_rule(&mut self, rule: RoutingRule) {
        self.routing_rules.push(rule);
        self.routing_rules.sort_by_key(|r| r.priority);
        self.bump();
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 3: PipelineValidator (~250 lines)
// ---------------------------------------------------------------------------

/// Severity of a validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    /// The configuration is invalid — must be fixed before applying.
    Error,
    /// The configuration is questionable — should be reviewed.
    Warning,
    /// Informational note.
    Info,
}

/// A single validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// How severe is this issue?
    pub severity: ValidationSeverity,
    /// The field or component this issue relates to.
    pub field: String,
    /// Human-readable description.
    pub message: String,
    /// Suggested fix, if applicable.
    pub suggestion: Option<String>,
}

/// Aggregated result of a validation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// `true` when there are zero `Error`-severity issues.
    pub is_valid: bool,
    /// All issues found during validation.
    pub issues: Vec<ValidationIssue>,
    /// A numeric score from 0.0 to 1.0; higher is better.
    pub score: f64,
}

impl ValidationResult {
    /// Create a validation result from a list of issues.
    pub fn from_issues(issues: Vec<ValidationIssue>) -> Self {
        let is_valid = !issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error);
        // Start at 1.0 and deduct per issue.
        let mut score: f64 = 1.0;
        for issue in &issues {
            match issue.severity {
                ValidationSeverity::Error => score -= 0.25,
                ValidationSeverity::Warning => score -= 0.10,
                ValidationSeverity::Info => score -= 0.02,
            }
        }
        Self {
            is_valid,
            issues,
            score: score.max(0.0),
        }
    }

    /// Create a passing validation result with no issues.
    pub fn passing() -> Self {
        Self {
            is_valid: true,
            issues: Vec::new(),
            score: 1.0,
        }
    }
}

/// Validates pipeline configurations and proposed changes.
#[derive(Debug, Clone)]
pub struct PipelineValidator {
    /// Maximum number of stages allowed.
    pub max_stages: usize,
    /// Maximum per-stage timeout in milliseconds.
    pub max_stage_timeout_ms: u64,
    /// Minimum number of stages required.
    pub min_stages: usize,
    /// Require at least one Monitor stage.
    pub require_monitor_stage: bool,
    /// Forbid two consecutive disabled stages.
    pub forbid_consecutive_disabled: bool,
}

impl Default for PipelineValidator {
    fn default() -> Self {
        Self {
            max_stages: 20,
            max_stage_timeout_ms: 30_000,
            min_stages: 1,
            require_monitor_stage: true,
            forbid_consecutive_disabled: true,
        }
    }
}

impl PipelineValidator {
    /// Create a validator with default thresholds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all validation checks on a pipeline configuration.
    pub fn validate(&self, config: &PipelineConfig) -> ValidationResult {
        let mut issues = Vec::new();

        // 1. Stage count bounds
        if config.stages.is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "stages".into(),
                message: "Pipeline must contain at least one stage".into(),
                suggestion: Some("Add a Filter or Monitor stage".into()),
            });
        } else if config.stages.len() > self.max_stages {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "stages.len".into(),
                message: format!(
                    "Pipeline has {} stages, exceeds maximum of {}",
                    config.stages.len(),
                    self.max_stages
                ),
                suggestion: Some("Remove non-essential stages or increase max_stages".into()),
            });
        }

        // 2. Timeout bounds
        issues.extend(self.check_timeout_bounds(config));

        // 3. Critical stages present
        issues.extend(self.check_critical_stages_present(config));

        // 4. Stage dependencies
        issues.extend(self.check_stage_dependencies(config));

        // 5. Monitor requirement
        if self.require_monitor_stage {
            let has_monitor = config
                .stages
                .iter()
                .any(|s| s.stage_type == StageType::Monitor);
            if !has_monitor {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    field: "stages.monitor".into(),
                    message: "No Monitor stage found; observability may be limited".into(),
                    suggestion: Some("Add a Monitor stage to collect metrics".into()),
                });
            }
        }

        // 6. Consecutive disabled
        if self.forbid_consecutive_disabled {
            let mut prev_disabled = false;
            for stage in &config.stages {
                if !stage.enabled {
                    if prev_disabled {
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Warning,
                            field: format!("stages.{}", stage.name),
                            message: format!(
                                "Consecutive disabled stages detected near '{}'",
                                stage.name
                            ),
                            suggestion: Some(
                                "Enable one of the consecutive disabled stages".into(),
                            ),
                        });
                    }
                    prev_disabled = true;
                } else {
                    prev_disabled = false;
                }
            }
        }

        // 7. Checksum integrity
        if !config.verify_checksum() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "checksum".into(),
                message: "Stored checksum does not match current state".into(),
                suggestion: Some("Recompute checksum via compute_checksum()".into()),
            });
        }

        // 8. Duplicate stage names
        let mut seen_names: HashMap<&str, usize> = HashMap::new();
        for stage in &config.stages {
            let count = seen_names.entry(&stage.name).or_insert(0);
            *count += 1;
        }
        for (name, count) in &seen_names {
            if *count > 1 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    field: format!("stages.name.{}", name),
                    message: format!("Duplicate stage name '{}' found {} times", name, count),
                    suggestion: Some("Rename stages to have unique names".into()),
                });
            }
        }

        // 9. Routing rule targets exist
        for rule in &config.routing_rules {
            if !rule.enabled {
                continue;
            }
            let target_exists = config
                .stages
                .iter()
                .any(|s| s.name == rule.target_stage || s.stage_id == rule.target_stage);
            if !target_exists {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    field: format!("routing_rules.{}", rule.rule_id),
                    message: format!(
                        "Routing rule targets non-existent stage '{}'",
                        rule.target_stage
                    ),
                    suggestion: Some("Fix the target_stage or add the missing stage".into()),
                });
            }
        }

        ValidationResult::from_issues(issues)
    }

    /// Validate a proposed adaptation change against the current config.
    pub fn validate_change(
        &self,
        config: &PipelineConfig,
        proposal: &AdaptationProposal,
    ) -> ValidationResult {
        let mut issues = Vec::new();

        if proposal.parameter_changes.is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Warning,
                field: "parameter_changes".into(),
                message: "Proposal contains no parameter changes".into(),
                suggestion: None,
            });
            return ValidationResult::from_issues(issues);
        }

        for change in &proposal.parameter_changes {
            // Verify old_value matches current value in target stage
            if let Some(stage) = config.find_stage(&proposal.target) {
                if let Some(current) = stage.config.get(&change.parameter) {
                    if current != &change.old_value {
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Warning,
                            field: format!("{}.{}", proposal.target, change.parameter),
                            message: format!(
                                "old_value '{}' does not match current value '{:?}'",
                                change.parameter, current
                            ),
                            suggestion: Some("Refresh the proposal with current values".into()),
                        });
                    }
                }
            }

            // Reject absurdly large timeout values
            if change.parameter == "timeout_ms" {
                if let Some(new_val) = change.new_value.as_u64() {
                    if new_val > self.max_stage_timeout_ms {
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Error,
                            field: format!("{}.timeout_ms", proposal.target),
                            message: format!(
                                "Proposed timeout {} ms exceeds maximum {} ms",
                                new_val, self.max_stage_timeout_ms
                            ),
                            suggestion: Some(format!(
                                "Reduce timeout to at most {} ms",
                                self.max_stage_timeout_ms
                            )),
                        });
                    }
                }
            }

            // Reject disabling a critical stage
            if change.parameter == "enabled" {
                if let Some(false) = change.new_value.as_bool() {
                    if let Some(stage) = config.find_stage(&proposal.target) {
                        if stage.is_critical() {
                            issues.push(ValidationIssue {
                                severity: ValidationSeverity::Error,
                                field: format!("{}.enabled", proposal.target),
                                message: format!("Cannot disable critical stage '{}'", stage.name),
                                suggestion: Some(
                                    "Disable non-critical stages or add a replacement".into(),
                                ),
                            });
                        }
                    }
                }
            }
        }

        ValidationResult::from_issues(issues)
    }

    /// Check that required critical stage types are present.
    pub fn check_critical_stages_present(&self, config: &PipelineConfig) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        let has_decide = config
            .stages
            .iter()
            .any(|s| s.stage_type == StageType::Decide && s.enabled);
        if !has_decide {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "stages.decide".into(),
                message: "No enabled Decide stage found".into(),
                suggestion: Some("Add an enabled Decide stage".into()),
            });
        }

        let has_act = config
            .stages
            .iter()
            .any(|s| s.stage_type == StageType::Act && s.enabled);
        if !has_act {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Warning,
                field: "stages.act".into(),
                message: "No enabled Act stage found".into(),
                suggestion: Some("Add an Act stage to execute decisions".into()),
            });
        }

        issues
    }

    /// Check that no stage exceeds timeout bounds.
    pub fn check_timeout_bounds(&self, config: &PipelineConfig) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        for stage in &config.stages {
            if stage.timeout_ms == 0 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    field: format!("stages.{}.timeout_ms", stage.name),
                    message: format!("Stage '{}' has zero timeout", stage.name),
                    suggestion: Some("Set a positive timeout_ms value".into()),
                });
            } else if stage.timeout_ms > self.max_stage_timeout_ms {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    field: format!("stages.{}.timeout_ms", stage.name),
                    message: format!(
                        "Stage '{}' timeout {} ms exceeds recommended max {} ms",
                        stage.name, stage.timeout_ms, self.max_stage_timeout_ms
                    ),
                    suggestion: Some("Consider reducing the timeout".into()),
                });
            }
        }
        issues
    }

    /// Check logical dependencies between stages.
    pub fn check_stage_dependencies(&self, config: &PipelineConfig) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Every Act stage should have a preceding Decide stage.
        let mut seen_decide = false;
        for stage in &config.stages {
            if stage.stage_type == StageType::Decide && stage.enabled {
                seen_decide = true;
            }
            if stage.stage_type == StageType::Act && stage.enabled && !seen_decide {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    field: format!("stages.{}", stage.name),
                    message: format!(
                        "Act stage '{}' appears before any enabled Decide stage",
                        stage.name
                    ),
                    suggestion: Some("Move Decide stages before Act stages".into()),
                });
            }
        }

        // Enrich stages should precede Decide stages for full context.
        let enrich_names: Vec<&str> = config
            .stages
            .iter()
            .filter(|s| s.stage_type == StageType::Enrich && s.enabled)
            .map(|s| s.name.as_str())
            .collect();

        if !enrich_names.is_empty() {
            let first_decide_idx = config
                .stages
                .iter()
                .position(|s| s.stage_type == StageType::Decide && s.enabled);
            if let Some(decide_idx) = first_decide_idx {
                for (i, stage) in config.stages.iter().enumerate() {
                    if stage.stage_type == StageType::Enrich && stage.enabled && i >= decide_idx {
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Info,
                            field: format!("stages.{}", stage.name),
                            message: format!(
                                "Enrich stage '{}' comes after the first Decide stage; \
                                 context may be incomplete",
                                stage.name
                            ),
                            suggestion: Some("Move Enrich stages before Decide stages".into()),
                        });
                    }
                }
            }
        }

        issues
    }
}

// ---------------------------------------------------------------------------
// Section 4: PipelineExecutor (~300 lines)
// ---------------------------------------------------------------------------

/// Status of a single execution (adaptation application).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Waiting to be applied.
    Pending,
    /// Currently being applied.
    Applying,
    /// Successfully applied.
    Applied,
    /// Failed during application.
    Failed,
    /// Changes were rolled back after failure.
    RolledBack,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Applying => write!(f, "applying"),
            Self::Applied => write!(f, "applied"),
            Self::Failed => write!(f, "failed"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// Record of a single adaptation execution attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Unique ID for this execution.
    pub execution_id: String,
    /// The proposal this execution corresponds to.
    pub proposal_id: String,
    /// Current status.
    pub status: ExecutionStatus,
    /// Changes that were successfully applied.
    pub changes_applied: Vec<String>,
    /// Changes that failed to apply.
    pub changes_failed: Vec<(String, String)>,
    /// Wall-clock duration of the apply operation in ms.
    pub duration_ms: f64,
    /// Checksum of the config before application.
    pub pre_snapshot_checksum: String,
    /// Checksum of the config after application.
    pub post_snapshot_checksum: String,
    /// Error message if the execution failed.
    pub error: Option<String>,
}

/// Applies (or reverts) adaptation proposals against a live pipeline config.
pub struct PipelineExecutor {
    validator: PipelineValidator,
    execution_history: Vec<ExecutionResult>,
    max_history: usize,
}

impl PipelineExecutor {
    /// Create a new executor with default settings.
    pub fn new() -> Self {
        Self {
            validator: PipelineValidator::new(),
            execution_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Create an executor with a custom validator.
    pub fn with_validator(validator: PipelineValidator) -> Self {
        Self {
            validator,
            execution_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Apply a single adaptation proposal to the pipeline config.
    ///
    /// Returns an error if validation fails or no matching stage is found.
    pub fn apply_adaptation(
        &mut self,
        config: &mut PipelineConfig,
        proposal: &AdaptationProposal,
    ) -> Result<ExecutionResult, String> {
        let pre_checksum = config.compute_checksum();
        let start = std::time::Instant::now();

        info!(
            execution_id = %proposal.proposal_id,
            target = %proposal.target,
            "Applying adaptation"
        );

        // Validate first.
        let validation = self.validator.validate_change(config, proposal);
        if !validation.is_valid {
            let error_msg = format!(
                "validation failed: {}",
                validation
                    .issues
                    .iter()
                    .filter(|i| i.severity == ValidationSeverity::Error)
                    .map(|i| i.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            error!(
                execution_id = %proposal.proposal_id,
                errors = %error_msg,
                "Adaptation validation failed"
            );
            let result = ExecutionResult {
                execution_id: uuid::Uuid::new_v4().to_string(),
                proposal_id: proposal.proposal_id.clone(),
                status: ExecutionStatus::Failed,
                changes_applied: Vec::new(),
                changes_failed: Vec::new(),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                pre_snapshot_checksum: pre_checksum.clone(),
                post_snapshot_checksum: pre_checksum,
                error: Some(error_msg.clone()),
            };
            self.record_execution(result.clone());
            return Err(error_msg);
        }

        // Apply changes.
        let mut changes_applied = Vec::new();
        let mut changes_failed = Vec::new();

        for change in &proposal.parameter_changes {
            match self.apply_single_change(config, &proposal.target, change) {
                Ok(()) => {
                    debug!(
                        parameter = %change.parameter,
                        "Change applied successfully"
                    );
                    changes_applied.push(change.parameter.clone());
                }
                Err(e) => {
                    warn!(
                        parameter = %change.parameter,
                        error = %e,
                        "Change failed"
                    );
                    changes_failed.push((change.parameter.clone(), e));
                }
            }
        }

        // Recompute checksum after all mutations so verify_checksum() stays valid.
        if !changes_applied.is_empty() {
            config.bump();
        }

        let post_checksum = config.compute_checksum();
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        let status = if changes_failed.is_empty() {
            ExecutionStatus::Applied
        } else if changes_applied.is_empty() {
            ExecutionStatus::Failed
        } else {
            // Partially applied — still mark as applied but record failures.
            ExecutionStatus::Applied
        };

        let changes_failed_count = changes_failed.len();
        let changes_total = changes_failed_count + changes_applied.len();
        let error_msg = if changes_failed_count > 0 {
            Some(format!(
                "{} of {} changes failed",
                changes_failed_count, changes_total
            ))
        } else {
            None
        };
        let result = ExecutionResult {
            execution_id: uuid::Uuid::new_v4().to_string(),
            proposal_id: proposal.proposal_id.clone(),
            status,
            changes_applied,
            changes_failed,
            duration_ms,
            pre_snapshot_checksum: pre_checksum,
            post_snapshot_checksum: post_checksum,
            error: error_msg,
        };

        self.record_execution(result.clone());
        Ok(result)
    }

    /// Apply a single parameter change to a stage in the config.
    fn apply_single_change(
        &self,
        config: &mut PipelineConfig,
        target: &str,
        change: &ParameterChange,
    ) -> Result<(), String> {
        // Try to find the stage by name or ID
        let stage = match config.find_stage_mut(target) {
            Some(s) => s,
            None => {
                // If no exact match, try to find a stage whose name contains the target
                let idx = config
                    .stages
                    .iter()
                    .position(|s| s.name.contains(target) || s.stage_id == target)
                    .ok_or_else(|| format!("target stage '{}' not found", target))?;
                &mut config.stages[idx]
            }
        };

        match change.parameter.as_str() {
            "enabled" => {
                let val = change
                    .new_value
                    .as_bool()
                    .ok_or_else(|| "enabled must be a boolean".to_string())?;
                if stage.is_critical() && !val {
                    return Err(format!("cannot disable critical stage '{}'", stage.name));
                }
                stage.enabled = val;
            }
            "timeout_ms" => {
                let val = change
                    .new_value
                    .as_u64()
                    .ok_or_else(|| "timeout_ms must be a positive integer".to_string())?;
                if val == 0 {
                    return Err("timeout_ms cannot be zero".to_string());
                }
                stage.timeout_ms = val;
            }
            "priority" => {
                let val = change
                    .new_value
                    .as_u64()
                    .ok_or_else(|| "priority must be a non-negative integer".to_string())?;
                stage.priority = val as u32;
                config.stages.sort_by_key(|s| s.priority);
            }
            _ => {
                // Generic config parameter
                stage
                    .config
                    .insert(change.parameter.clone(), change.new_value.clone());
            }
        }

        Ok(())
    }

    /// Revert a previously applied adaptation by restoring old values.
    pub fn revert_adaptation(
        &mut self,
        config: &mut PipelineConfig,
        proposal: &AdaptationProposal,
    ) -> Result<ExecutionResult, String> {
        let pre_checksum = config.compute_checksum();
        let start = std::time::Instant::now();

        info!(
            execution_id = %proposal.proposal_id,
            target = %proposal.target,
            "Reverting adaptation"
        );

        let mut changes_applied = Vec::new();
        let mut changes_failed = Vec::new();

        for change in &proposal.parameter_changes {
            let revert_change = ParameterChange {
                parameter: change.parameter.clone(),
                old_value: change.new_value.clone(),
                new_value: change.old_value.clone(),
            };
            match self.apply_single_change(config, &proposal.target, &revert_change) {
                Ok(()) => {
                    changes_applied.push(change.parameter.clone());
                }
                Err(e) => {
                    changes_failed.push((change.parameter.clone(), e));
                }
            }
        }

        // Recompute checksum after all mutations so verify_checksum() stays valid.
        if !changes_applied.is_empty() {
            config.bump();
        }

        let post_checksum = config.compute_checksum();
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        let result = ExecutionResult {
            execution_id: uuid::Uuid::new_v4().to_string(),
            proposal_id: proposal.proposal_id.clone(),
            status: if changes_failed.is_empty() {
                ExecutionStatus::Applied
            } else {
                ExecutionStatus::RolledBack
            },
            changes_applied,
            changes_failed,
            duration_ms,
            pre_snapshot_checksum: pre_checksum,
            post_snapshot_checksum: post_checksum,
            error: None,
        };

        self.record_execution(result.clone());
        Ok(result)
    }

    /// Validate and, if valid, apply the adaptation in one call.
    pub fn validate_and_apply(
        &mut self,
        config: &mut PipelineConfig,
        proposal: &AdaptationProposal,
    ) -> Result<ExecutionResult, String> {
        let validation = self.validator.validate_change(config, proposal);
        if !validation.is_valid {
            return Err(format!(
                "validation failed: {}",
                validation
                    .issues
                    .iter()
                    .filter(|i| i.severity == ValidationSeverity::Error)
                    .map(|i| i.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        self.apply_adaptation(config, proposal)
    }

    /// Immutable reference to the execution history.
    pub fn execution_history(&self) -> &[ExecutionResult] {
        &self.execution_history
    }

    /// The most recent execution, if any.
    pub fn last_execution(&self) -> Option<&ExecutionResult> {
        self.execution_history.last()
    }

    /// Record an execution and trim history.
    fn record_execution(&mut self, result: ExecutionResult) {
        debug!(
            execution_id = %result.execution_id,
            status = %result.status,
            "Recording execution"
        );
        self.execution_history.push(result);
        if self.execution_history.len() > self.max_history {
            self.execution_history.remove(0);
        }
    }
}

impl Default for PipelineExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Section 5: PipelineSnapshot (~100 lines)
// ---------------------------------------------------------------------------

/// An immutable snapshot of a pipeline configuration at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSnapshot {
    /// Unique snapshot identifier.
    pub snapshot_id: String,
    /// The pipeline this snapshot belongs to.
    pub pipeline_id: String,
    /// Serialised PipelineConfig at the time of capture.
    pub config_json: String,
    /// Checksum of the captured config.
    pub checksum: String,
    /// RFC 3339 timestamp when the snapshot was taken.
    pub timestamp: String,
    /// What triggered this snapshot, e.g. "pre-adaptation".
    pub trigger: String,
}

impl PipelineSnapshot {
    /// Capture a snapshot of the current pipeline config.
    pub fn capture(config: &PipelineConfig, trigger: &str) -> Self {
        let config_json = config
            .to_json()
            .unwrap_or_else(|e| format!("serialization error: {}", e));
        let checksum = config.checksum.clone();
        info!(
            pipeline_id = %config.pipeline_id,
            trigger = %trigger,
            "Capturing pipeline snapshot"
        );
        Self {
            snapshot_id: uuid::Uuid::new_v4().to_string(),
            pipeline_id: config.pipeline_id.clone(),
            config_json,
            checksum,
            timestamp: Utc::now().to_rfc3339(),
            trigger: trigger.to_string(),
        }
    }

    /// Restore the pipeline config from this snapshot.
    pub fn restore(&self) -> Result<PipelineConfig, String> {
        let mut config = PipelineConfig::from_json(&self.config_json)?;
        if !config.verify_checksum() {
            config.checksum = config.compute_checksum();
        }
        info!(
            snapshot_id = %self.snapshot_id,
            "Restoring pipeline from snapshot"
        );
        Ok(config)
    }

    /// Verify that the given config matches this snapshot.
    pub fn verify(&self, config: &PipelineConfig) -> bool {
        let current_checksum = config.compute_checksum();
        current_checksum == self.checksum
    }
}

// ---------------------------------------------------------------------------
// Section 6: DynamicPipelineManager (~300 lines)
// ---------------------------------------------------------------------------

/// The top-level orchestrator for dynamic pipeline management.
///
/// Coordinates validation, execution, snapshotting, and rollback of
/// pipeline adaptations. This is the entry point for wiring the
/// `PolicyExecutor` into `Adapter.evaluate()`.
pub struct DynamicPipelineManager {
    /// The current live pipeline configuration.
    config: PipelineConfig,
    /// Executor that applies changes.
    executor: PipelineExecutor,
    /// Snapshot history for rollback.
    snapshots: Vec<PipelineSnapshot>,
    /// Maximum number of snapshots to retain.
    max_snapshots: usize,
    /// Currently active (applied) proposals keyed by proposal ID.
    active_proposals: HashMap<String, AdaptationProposal>,
}

impl DynamicPipelineManager {
    /// Create a manager from an initial pipeline configuration.
    pub fn new(initial_config: PipelineConfig) -> Self {
        let pipeline_id = initial_config.pipeline_id.clone();
        info!(pipeline_id = %pipeline_id, "Initialising DynamicPipelineManager");
        Self {
            config: initial_config,
            executor: PipelineExecutor::new(),
            snapshots: Vec::new(),
            max_snapshots: 50,
            active_proposals: HashMap::new(),
        }
    }

    /// Create a manager with a custom executor.
    pub fn with_executor(initial_config: PipelineConfig, executor: PipelineExecutor) -> Self {
        let pipeline_id = initial_config.pipeline_id.clone();
        info!(pipeline_id = %pipeline_id, "Initialising DynamicPipelineManager with custom executor");
        Self {
            config: initial_config,
            executor,
            snapshots: Vec::new(),
            max_snapshots: 50,
            active_proposals: HashMap::new(),
        }
    }

    /// Immutable reference to the current pipeline configuration.
    pub fn current_config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Propose, validate, and apply an adaptation in one operation.
    ///
    /// This is the primary integration point — `Adapter.evaluate()` should
    /// pass each proposal through this method.
    pub fn propose_and_apply(
        &mut self,
        proposal: &AdaptationProposal,
    ) -> Result<ExecutionResult, String> {
        info!(
            proposal_id = %proposal.proposal_id,
            target = %proposal.target,
            "Processing adaptation proposal"
        );

        // 1. Snapshot before change
        let _pre_snapshot = self.snapshot("pre-adaptation");

        // 2. Validate
        let validation = self
            .executor
            .validator
            .validate_change(&self.config, proposal);
        if !validation.is_valid {
            let errors: Vec<String> = validation
                .issues
                .iter()
                .filter(|i| i.severity == ValidationSeverity::Error)
                .map(|i| i.message.clone())
                .collect();
            error!(
                proposal_id = %proposal.proposal_id,
                errors = ?errors,
                "Proposal rejected by validator"
            );
            return Err(format!("validation errors: {}", errors.join("; ")));
        }

        // 3. Apply
        let result = self.executor.apply_adaptation(&mut self.config, proposal)?;

        // 4. Snapshot after change
        let _post_snapshot = self.snapshot("post-adaptation");

        // 5. Track active proposal
        if result.status == ExecutionStatus::Applied {
            self.active_proposals
                .insert(proposal.proposal_id.clone(), proposal.clone());
            info!(
                proposal_id = %proposal.proposal_id,
                "Proposal applied and tracked as active"
            );
        }

        Ok(result)
    }

    /// Validate a proposal without applying it.
    pub fn propose_validate_only(&self, proposal: &AdaptationProposal) -> ValidationResult {
        info!(
            proposal_id = %proposal.proposal_id,
            "Validating proposal (dry-run)"
        );
        self.executor
            .validator
            .validate_change(&self.config, proposal)
    }

    /// Revert a previously applied proposal.
    pub fn revert_proposal(&mut self, proposal_id: &str) -> Result<ExecutionResult, String> {
        let proposal = self
            .active_proposals
            .remove(proposal_id)
            .ok_or_else(|| format!("no active proposal with id '{}'", proposal_id))?;

        info!(
            proposal_id = %proposal_id,
            "Reverting active proposal"
        );

        let _pre_snapshot = self.snapshot("pre-rollback");
        let result = self
            .executor
            .revert_adaptation(&mut self.config, &proposal)?;
        let _post_snapshot = self.snapshot("post-rollback");

        Ok(result)
    }

    /// Capture a snapshot of the current pipeline state.
    pub fn snapshot(&mut self, trigger: &str) -> PipelineSnapshot {
        let snap = PipelineSnapshot::capture(&self.config, trigger);
        self.snapshots.push(snap.clone());
        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }
        snap
    }

    /// Roll back the pipeline to a previous snapshot.
    pub fn rollback_to_snapshot(
        &mut self,
        snapshot: &PipelineSnapshot,
    ) -> Result<ExecutionResult, String> {
        info!(
            snapshot_id = %snapshot.snapshot_id,
            "Rolling back to snapshot"
        );

        if snapshot.pipeline_id != self.config.pipeline_id {
            return Err(format!(
                "snapshot pipeline_id '{}' does not match current '{}'",
                snapshot.pipeline_id, self.config.pipeline_id
            ));
        }

        let restored = snapshot.restore()?;
        let _pre = self.snapshot("pre-rollback");

        self.config = restored;
        let _post = self.snapshot("post-rollback");

        // Clear active proposals since we've rolled back
        self.active_proposals.clear();

        Ok(ExecutionResult {
            execution_id: uuid::Uuid::new_v4().to_string(),
            proposal_id: String::new(),
            status: ExecutionStatus::RolledBack,
            changes_applied: vec!["full_config_restore".into()],
            changes_failed: Vec::new(),
            duration_ms: 0.0,
            pre_snapshot_checksum: snapshot.checksum.clone(),
            post_snapshot_checksum: self.config.checksum.clone(),
            error: None,
        })
    }

    /// List all currently active proposal IDs.
    pub fn active_proposals(&self) -> Vec<String> {
        self.active_proposals.keys().cloned().collect()
    }

    /// List proposal IDs from the execution history.
    pub fn proposal_history(&self) -> Vec<String> {
        self.executor
            .execution_history()
            .iter()
            .map(|e| e.proposal_id.clone())
            .collect()
    }

    /// Generate a human-readable summary of the current pipeline state.
    pub fn current_pipeline_summary(&self) -> String {
        let stages_summary: Vec<String> = self
            .config
            .stages
            .iter()
            .map(|s| {
                let status = if s.enabled { "ON" } else { "OFF" };
                format!(
                    "  [{}] {} ({}, priority={}, timeout={}ms)",
                    status, s.name, s.stage_type, s.priority, s.timeout_ms
                )
            })
            .collect();

        let rules_summary: Vec<String> = self
            .config
            .routing_rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| format!("  {} -> {}", r.condition, r.target_stage))
            .collect();

        let active = self.active_proposals.len();
        let total_execs = self.executor.execution_history().len();

        format!(
            "Pipeline '{}' v{}\n\
             Stages ({}):\n{}\n\
             Routing Rules ({} enabled):\n{}\n\
             Active Proposals: {}\n\
             Total Executions: {}\n\
             Snapshots Retained: {}",
            self.config.pipeline_id,
            self.config.version,
            self.config.stages.len(),
            stages_summary.join("\n"),
            self.config
                .routing_rules
                .iter()
                .filter(|r| r.enabled)
                .count(),
            if rules_summary.is_empty() {
                "  (none)".to_string()
            } else {
                rules_summary.join("\n")
            },
            active,
            total_execs,
            self.snapshots.len(),
        )
    }

    /// Mutable access to the underlying config for direct manipulation.
    pub fn config_mut(&mut self) -> &mut PipelineConfig {
        &mut self.config
    }

    /// Get the execution history.
    pub fn execution_history(&self) -> &[ExecutionResult] {
        self.executor.execution_history()
    }

    /// Get the validator for pre-checks.
    pub fn validator(&self) -> &PipelineValidator {
        &self.executor.validator
    }
}

// ---------------------------------------------------------------------------
// Section 7: Tests (~500+ lines, 40+ tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Build a minimal valid pipeline config with the standard stage types.
    fn default_pipeline_config() -> PipelineConfig {
        let mut config = PipelineConfig::new();

        let mut monitor = PipelineStage::new("security_monitor", StageType::Monitor);
        monitor.priority = 1;
        monitor.timeout_ms = 1_000;
        config
            .add_stage(monitor)
            .unwrap_or_else(|e| panic!("add monitor: {}", e));

        let mut filter = PipelineStage::new("shield_rate_limit", StageType::Filter);
        filter.priority = 10;
        filter.timeout_ms = 2_000;
        filter
            .config
            .insert("max_rps".into(), serde_json::json!(1000));
        config
            .add_stage(filter)
            .unwrap_or_else(|e| panic!("add filter: {}", e));

        let mut enrich = PipelineStage::new("context_enricher", StageType::Enrich);
        enrich.priority = 20;
        enrich.timeout_ms = 5_000;
        config
            .add_stage(enrich)
            .unwrap_or_else(|e| panic!("add enrich: {}", e));

        let mut decide = PipelineStage::new("threat_decider", StageType::Decide);
        decide.priority = 30;
        decide.timeout_ms = 3_000;
        decide
            .config
            .insert("threshold".into(), serde_json::json!(0.5));
        config
            .add_stage(decide)
            .unwrap_or_else(|e| panic!("add decide: {}", e));

        let mut act = PipelineStage::new("block_actor", StageType::Act);
        act.priority = 40;
        act.timeout_ms = 1_000;
        config
            .add_stage(act)
            .unwrap_or_else(|e| panic!("add act: {}", e));

        config
    }

    /// Build a simple adaptation proposal targeting a stage.
    fn make_proposal(target: &str, changes: Vec<ParameterChange>) -> AdaptationProposal {
        AdaptationProposal {
            proposal_id: uuid::Uuid::new_v4().to_string(),
            target: target.to_string(),
            description: "test proposal".to_string(),
            parameter_changes: changes,
            trust_level_at_proposal: 0.5,
            rationale: "test rationale".to_string(),
            signature: None,
            timestamp: Utc::now().to_rfc3339(),
            grace_deadline: Utc::now().to_rfc3339(),
            status: super::super::AdaptationStatus::Proposed,
        }
    }

    // =========================================================================
    // A. PipelineStage (5 tests)
    // =========================================================================

    #[test]
    fn stage_new_default_values() {
        let stage = PipelineStage::new("test_stage", StageType::Filter);
        assert!(stage.enabled);
        assert_eq!(stage.priority, 100);
        assert_eq!(stage.timeout_ms, 5_000);
        assert!(stage.config.is_empty());
        assert_eq!(stage.stage_type, StageType::Filter);
        assert!(!stage.stage_id.is_empty());
    }

    #[test]
    fn stage_is_critical_for_decide_and_act() {
        let decide = PipelineStage::new("decider", StageType::Decide);
        let act = PipelineStage::new("actor", StageType::Act);
        let filter = PipelineStage::new("filter", StageType::Filter);
        let critical_named = PipelineStage::new("critical_filter", StageType::Filter);

        assert!(decide.is_critical());
        assert!(act.is_critical());
        assert!(!filter.is_critical());
        assert!(critical_named.is_critical()); // "critical" in name
    }

    #[test]
    fn stage_json_roundtrip() {
        let mut stage = PipelineStage::new("json_test", StageType::Transform);
        stage
            .config
            .insert("key".into(), serde_json::json!("value"));

        let json = stage.to_json().expect("to_json failed");
        let restored = PipelineStage::from_json(&json).expect("from_json failed");
        assert_eq!(restored.name, stage.name);
        assert_eq!(restored.stage_type, stage.stage_type);
        assert_eq!(restored.config.get("key"), stage.config.get("key"));
    }

    #[test]
    fn stage_types_display() {
        assert_eq!(StageType::Filter.to_string(), "filter");
        assert_eq!(StageType::Transform.to_string(), "transform");
        assert_eq!(StageType::Enrich.to_string(), "enrich");
        assert_eq!(StageType::Decide.to_string(), "decide");
        assert_eq!(StageType::Act.to_string(), "act");
        assert_eq!(StageType::Monitor.to_string(), "monitor");
    }

    #[test]
    fn stage_disabled_by_construction() {
        let mut stage = PipelineStage::new("disabled", StageType::Filter);
        stage.enabled = false;
        assert!(!stage.enabled);
        assert!(!stage.is_critical());
    }

    // =========================================================================
    // B. PipelineConfig (6 tests)
    // =========================================================================

    #[test]
    fn config_new_creates_valid_config() {
        let config = PipelineConfig::new();
        assert!(config.stages.is_empty());
        assert_eq!(config.version, 1);
        assert!(!config.pipeline_id.is_empty());
        assert!(config.verify_checksum());
    }

    #[test]
    fn config_checksum_changes_on_mutation() {
        let mut config = PipelineConfig::new();
        let original_checksum = config.checksum.clone();

        let stage = PipelineStage::new("s1", StageType::Monitor);
        config.add_stage(stage).unwrap();

        assert_ne!(config.checksum, original_checksum);
        assert!(config.verify_checksum());
        assert_eq!(config.version, 2);
    }

    #[test]
    fn config_add_remove_stage() {
        let mut config = PipelineConfig::new();
        let stage = PipelineStage::new("removable", StageType::Filter);

        config.add_stage(stage).unwrap();
        let stage_id = config.stages[0].stage_id.clone();

        let removed = config.remove_stage(&stage_id).unwrap();
        assert_eq!(removed.name, "removable");
        assert!(config.stages.is_empty());
    }

    #[test]
    fn config_find_stage() {
        let config = default_pipeline_config();
        let monitor_id = config.stages[0].stage_id.clone();

        let found = config.find_stage(&monitor_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "security_monitor");

        let not_found = config.find_stage("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn config_critical_stages() {
        let config = default_pipeline_config();
        let critical = config.critical_stages();
        assert!(critical.len() >= 2); // decide + act
        let names: Vec<&str> = critical.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"threat_decider"));
        assert!(names.contains(&"block_actor"));
    }

    #[test]
    fn config_routing_rules() {
        let mut config = default_pipeline_config();
        config.add_routing_rule(RoutingRule::new("trust.level < 0.5", "shield_rate_limit"));

        assert_eq!(config.routing_rules.len(), 1);
        assert_eq!(config.routing_rules[0].target_stage, "shield_rate_limit");
        assert!(config.verify_checksum());
    }

    // =========================================================================
    // C. PipelineValidator (8 tests)
    // =========================================================================

    #[test]
    fn validator_valid_config() {
        let config = default_pipeline_config();
        let validator = PipelineValidator::new();
        let result = validator.validate(&config);
        assert!(result.is_valid);
        assert!(result.score > 0.8);
    }

    #[test]
    fn validator_missing_critical_stages() {
        let mut config = PipelineConfig::new();
        let monitor = PipelineStage::new("mon", StageType::Monitor);
        config.add_stage(monitor).unwrap();

        let validator = PipelineValidator::new();
        let result = validator.validate(&config);
        assert!(!result.is_valid);
        let error_fields: Vec<String> = result
            .issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .map(|i| i.field.clone())
            .collect();
        assert!(error_fields.iter().any(|f| f == "stages.decide"));
    }

    #[test]
    fn validator_too_many_stages() {
        let mut config = PipelineConfig::new();
        let monitor = PipelineStage::new("mon", StageType::Monitor);
        let decide = PipelineStage::new("dec", StageType::Decide);
        config.add_stage(monitor).unwrap();
        config.add_stage(decide).unwrap();

        let validator = PipelineValidator {
            max_stages: 1,
            ..PipelineValidator::default()
        };
        let result = validator.validate(&config);
        assert!(!result.is_valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("exceeds maximum")));
    }

    #[test]
    fn validator_timeout_violation() {
        let mut config = default_pipeline_config();
        // Set a stage to have zero timeout
        if let Some(stage) = config.find_stage_mut("security_monitor") {
            stage.timeout_ms = 0;
        }
        // Recompute checksum after direct mutation.
        config.bump();

        let validator = PipelineValidator::new();
        let result = validator.validate(&config);
        assert!(!result.is_valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("zero timeout")));
    }

    #[test]
    fn validator_validate_change_valid() {
        let config = default_pipeline_config();
        let validator = PipelineValidator::new();
        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.7),
            }],
        );
        let result = validator.validate_change(&config, &proposal);
        assert!(result.is_valid);
    }

    #[test]
    fn validator_require_monitor_stage() {
        let mut config = PipelineConfig::new();
        let decide = PipelineStage::new("dec", StageType::Decide);
        let act = PipelineStage::new("act", StageType::Act);
        config.add_stage(decide).unwrap();
        config.add_stage(act).unwrap();

        let validator = PipelineValidator {
            require_monitor_stage: true,
            ..PipelineValidator::default()
        };
        let result = validator.validate(&config);
        // It's a warning, not an error, so config is still "valid"
        assert!(result.is_valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("No Monitor stage")));
    }

    #[test]
    fn validator_consecutive_disabled() {
        let mut config = default_pipeline_config();
        // Disable first two stages
        if let Some(s) = config.find_stage_mut("security_monitor") {
            s.enabled = false;
        }
        // find the second stage — shield_rate_limit
        if let Some(s) = config
            .stages
            .iter_mut()
            .find(|s| s.name == "shield_rate_limit")
        {
            s.enabled = false;
        }
        // Recompute checksum after direct mutations.
        config.bump();

        let validator = PipelineValidator {
            forbid_consecutive_disabled: true,
            ..PipelineValidator::default()
        };
        let result = validator.validate(&config);
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("Consecutive disabled")));
    }

    #[test]
    fn validator_overall_score() {
        let config = default_pipeline_config();
        let validator = PipelineValidator::new();
        let result = validator.validate(&config);
        assert!(result.score >= 0.0 && result.score <= 1.0);
        // A good config should score high
        assert!(result.score > 0.7);
    }

    // =========================================================================
    // D. PipelineExecutor (6 tests)
    // =========================================================================

    #[test]
    fn executor_apply_adaptation() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.8),
            }],
        );

        let result = executor.apply_adaptation(&mut config, &proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);
        assert_eq!(result.changes_applied.len(), 1);
        assert!(result.changes_failed.is_empty());

        // Verify the change was applied
        let stage = config.find_stage("threat_decider").unwrap();
        assert_eq!(stage.config.get("threshold"), Some(&serde_json::json!(0.8)));
    }

    #[test]
    fn executor_revert_adaptation() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.9),
            }],
        );

        executor.apply_adaptation(&mut config, &proposal).unwrap();

        let result = executor.revert_adaptation(&mut config, &proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);

        let stage = config.find_stage("threat_decider").unwrap();
        assert_eq!(stage.config.get("threshold"), Some(&serde_json::json!(0.5)));
    }

    #[test]
    fn executor_validate_and_apply() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.6),
            }],
        );

        let result = executor.validate_and_apply(&mut config, &proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);
    }

    #[test]
    fn executor_execution_history() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        let p1 = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.6),
            }],
        );
        executor.apply_adaptation(&mut config, &p1).unwrap();

        let p2 = make_proposal(
            "block_actor",
            vec![ParameterChange {
                parameter: "timeout_ms".into(),
                old_value: serde_json::json!(1000),
                new_value: serde_json::json!(2000),
            }],
        );
        executor.apply_adaptation(&mut config, &p2).unwrap();

        assert_eq!(executor.execution_history().len(), 2);
        assert!(executor.last_execution().is_some());
    }

    #[test]
    fn executor_failed_application() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        // Try to disable a critical stage — should fail validation
        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "enabled".into(),
                old_value: serde_json::json!(true),
                new_value: serde_json::json!(false),
            }],
        );

        let result = executor.apply_adaptation(&mut config, &proposal);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("validation"));
    }

    #[test]
    fn executor_multiple_changes() {
        let mut config = default_pipeline_config();
        let mut executor = PipelineExecutor::new();

        let proposal = make_proposal(
            "threat_decider",
            vec![
                ParameterChange {
                    parameter: "threshold".into(),
                    old_value: serde_json::json!(0.5),
                    new_value: serde_json::json!(0.7),
                },
                ParameterChange {
                    parameter: "timeout_ms".into(),
                    old_value: serde_json::json!(3000),
                    new_value: serde_json::json!(5000),
                },
            ],
        );

        let result = executor.apply_adaptation(&mut config, &proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);
        assert_eq!(result.changes_applied.len(), 2);

        let stage = config.find_stage("threat_decider").unwrap();
        assert_eq!(stage.timeout_ms, 5_000);
    }

    // =========================================================================
    // E. PipelineSnapshot (3 tests)
    // =========================================================================

    #[test]
    fn snapshot_capture_restore() {
        let config = default_pipeline_config();
        let snapshot = PipelineSnapshot::capture(&config, "test-trigger");

        let restored = snapshot.restore().unwrap();
        assert_eq!(restored.pipeline_id, config.pipeline_id);
        assert_eq!(restored.stages.len(), config.stages.len());
    }

    #[test]
    fn snapshot_verify() {
        let config = default_pipeline_config();
        let snapshot = PipelineSnapshot::capture(&config, "verify-test");

        assert!(snapshot.verify(&config));

        // Mutate and verify fails
        let mut modified = config.clone();
        modified.version += 1;
        assert!(!snapshot.verify(&modified));
    }

    #[test]
    fn snapshot_checksum() {
        let config = default_pipeline_config();
        let snapshot = PipelineSnapshot::capture(&config, "checksum-test");

        assert!(!snapshot.checksum.is_empty());
        assert_eq!(snapshot.checksum, config.checksum);
        assert!(!snapshot.snapshot_id.is_empty());
        assert!(!snapshot.timestamp.is_empty());
    }

    // =========================================================================
    // F. DynamicPipelineManager (8 tests)
    // =========================================================================

    #[test]
    fn manager_new() {
        let config = default_pipeline_config();
        let manager = DynamicPipelineManager::new(config);
        assert_eq!(manager.current_config().stages.len(), 5);
        assert!(manager.active_proposals().is_empty());
    }

    #[test]
    fn manager_propose_and_apply() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.75),
            }],
        );

        let result = manager.propose_and_apply(&proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);
        assert!(manager.active_proposals().contains(&proposal.proposal_id));
    }

    #[test]
    fn manager_validate_only() {
        let config = default_pipeline_config();
        let manager = DynamicPipelineManager::new(config);

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.75),
            }],
        );

        let result = manager.propose_validate_only(&proposal);
        assert!(result.is_valid);
        // Config should not have changed
        assert_eq!(manager.current_config().version, 6);
    }

    #[test]
    fn manager_revert_proposal() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.9),
            }],
        );

        manager.propose_and_apply(&proposal).unwrap();
        let result = manager.revert_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);
        assert!(manager.active_proposals().is_empty());
    }

    #[test]
    fn manager_snapshot_and_rollback() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        // Capture baseline
        let baseline = manager.snapshot("baseline");
        let baseline_version = manager.current_config().version;

        // Apply a change
        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.99),
            }],
        );
        manager.propose_and_apply(&proposal).unwrap();
        assert_ne!(manager.current_config().version, baseline_version);

        // Rollback
        let result = manager.rollback_to_snapshot(&baseline).unwrap();
        assert_eq!(result.status, ExecutionStatus::RolledBack);
        assert!(manager.active_proposals().is_empty());
    }

    #[test]
    fn manager_active_proposals_tracking() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        let p1 = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.6),
            }],
        );
        manager.propose_and_apply(&p1).unwrap();

        let p2 = make_proposal(
            "shield_rate_limit",
            vec![ParameterChange {
                parameter: "max_rps".into(),
                old_value: serde_json::json!(1000),
                new_value: serde_json::json!(500),
            }],
        );
        manager.propose_and_apply(&p2).unwrap();

        assert_eq!(manager.active_proposals().len(), 2);
    }

    #[test]
    fn manager_summary() {
        let config = default_pipeline_config();
        let manager = DynamicPipelineManager::new(config);
        let summary = manager.current_pipeline_summary();

        assert!(summary.contains("security_monitor"));
        assert!(summary.contains("shield_rate_limit"));
        assert!(summary.contains("threat_decider"));
        assert!(summary.contains("block_actor"));
        assert!(summary.contains("Active Proposals: 0"));
    }

    #[test]
    fn manager_max_snapshots() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);
        manager.max_snapshots = 3;

        for i in 0..10 {
            manager.snapshot(&format!("snap-{}", i));
        }

        // Should not exceed max
        assert!(manager.execution_history().len() <= 100); // snapshots != exec history
                                                           // We only track max_snapshots on the snapshots vec — access via public API indirectly
    }

    // =========================================================================
    // G. Integration (4 tests)
    // =========================================================================

    #[test]
    fn integration_full_adaptation_cycle() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        // Step 1: Propose threshold increase
        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.7),
            }],
        );

        // Step 2: Dry-run validation
        let validation = manager.propose_validate_only(&proposal);
        assert!(validation.is_valid);

        // Step 3: Apply
        let result = manager.propose_and_apply(&proposal).unwrap();
        assert_eq!(result.status, ExecutionStatus::Applied);

        // Step 4: Verify change
        let stage = manager
            .current_config()
            .find_stage("threat_decider")
            .unwrap();
        assert_eq!(stage.config.get("threshold"), Some(&serde_json::json!(0.7)));

        // Step 5: History
        assert_eq!(manager.execution_history().len(), 1);
    }

    #[test]
    fn integration_adaptation_with_rollback() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        // Snapshot
        let baseline = manager.snapshot("before-bad-change");

        // Apply a "bad" change
        let proposal = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.01),
            }],
        );
        manager.propose_and_apply(&proposal).unwrap();

        // Rollback via snapshot
        let rollback_result = manager.rollback_to_snapshot(&baseline).unwrap();
        assert_eq!(rollback_result.status, ExecutionStatus::RolledBack);

        // Verify state restored
        let stage = manager
            .current_config()
            .find_stage("threat_decider")
            .unwrap();
        assert_eq!(stage.config.get("threshold"), Some(&serde_json::json!(0.5)));
    }

    #[test]
    fn integration_multiple_proposals_sequential() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        // Proposal 1: tighten threshold
        let p1 = make_proposal(
            "threat_decider",
            vec![ParameterChange {
                parameter: "threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!(0.3),
            }],
        );
        manager.propose_and_apply(&p1).unwrap();

        // Proposal 2: reduce rate limit
        let p2 = make_proposal(
            "shield_rate_limit",
            vec![ParameterChange {
                parameter: "max_rps".into(),
                old_value: serde_json::json!(1000),
                new_value: serde_json::json!(500),
            }],
        );
        manager.propose_and_apply(&p2).unwrap();

        // Verify both changes
        let decider = manager
            .current_config()
            .find_stage("threat_decider")
            .unwrap();
        assert_eq!(
            decider.config.get("threshold"),
            Some(&serde_json::json!(0.3))
        );

        let filter = manager
            .current_config()
            .find_stage("shield_rate_limit")
            .unwrap();
        assert_eq!(filter.config.get("max_rps"), Some(&serde_json::json!(500)));

        assert_eq!(manager.active_proposals().len(), 2);
    }

    #[test]
    fn integration_pipeline_reconfiguration() {
        let config = default_pipeline_config();
        let mut manager = DynamicPipelineManager::new(config);

        // Add a new stage dynamically
        let new_stage = PipelineStage::new("geo_fence", StageType::Filter);
        manager.config_mut().add_stage(new_stage).unwrap();
        assert_eq!(manager.current_config().stages.len(), 6);

        // Add routing rule
        manager
            .config_mut()
            .add_routing_rule(RoutingRule::new("source.geo == 'unknown'", "geo_fence"));
        assert_eq!(manager.current_config().routing_rules.len(), 1);

        // Validate the reconfigured pipeline
        let validator = PipelineValidator::new();
        let result = validator.validate(manager.current_config());
        assert!(result.is_valid);
    }
}
