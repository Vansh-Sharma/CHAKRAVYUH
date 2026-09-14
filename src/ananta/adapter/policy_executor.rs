// ANANTA Policy Execution Engine
//
// Production-grade policy evaluation, conflict resolution, versioning,
// condition matching, effect application, and full audit trail.
//
// Design goals:
//   - Deterministic: same input + same policy set → same decision
//   - Composable: multiple policies can layer effects on a single action
//   - Auditable: every evaluation is recorded for compliance review
//   - Performant: decision caching with TTL, short-circuit condition evaluation
//   - Safe: no panics in evaluation; errors degrade to deny-default

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Core enums
// ---------------------------------------------------------------------------

/// The decision a policy produces after evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Explicitly allow the action.
    Allow,
    /// Explicitly deny the action.
    Deny,
    /// Deny by default (no policy matched; conservative stance).
    DenyDefault,
    /// Allow by default (no policy matched; permissive stance).
    AllowDefault,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Allow => write!(f, "allow"),
            PolicyDecision::Deny => write!(f, "deny"),
            PolicyDecision::DenyDefault => write!(f, "deny_default"),
            PolicyDecision::AllowDefault => write!(f, "allow_default"),
        }
    }
}

impl PolicyDecision {
    /// Returns `true` if the decision is effectively an allow.
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow | PolicyDecision::AllowDefault)
    }

    /// Returns `true` if the decision is effectively a deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny | PolicyDecision::DenyDefault)
    }

    /// Numeric restriction score: higher means more restrictive.
    /// Used by most-restrictive-wins conflict resolution.
    pub fn restriction_score(&self) -> u8 {
        match self {
            PolicyDecision::Deny => 3,
            PolicyDecision::DenyDefault => 2,
            PolicyDecision::AllowDefault => 1,
            PolicyDecision::Allow => 0,
        }
    }
}

/// How a policy decision should be applied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    /// Actually block actions that violate the policy.
    Enforce,
    /// Log a warning but allow the action to proceed.
    Advisory,
    /// Record for later review without impacting the action.
    AuditOnly,
}

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyEffect::Enforce => write!(f, "enforce"),
            PolicyEffect::Advisory => write!(f, "advisory"),
            PolicyEffect::AuditOnly => write!(f, "audit_only"),
        }
    }
}

impl PolicyEffect {
    /// Whether this effect actually blocks the action.
    pub fn is_blocking(&self) -> bool {
        matches!(self, PolicyEffect::Enforce)
    }

    /// Restriction score for conflict resolution.
    pub fn restriction_score(&self) -> u8 {
        match self {
            PolicyEffect::Enforce => 3,
            PolicyEffect::Advisory => 2,
            PolicyEffect::AuditOnly => 1,
        }
    }
}

/// Strategy for resolving conflicts between multiple matching policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionStrategy {
    /// Higher-priority policy wins. Lower priority is ignored.
    Priority,
    /// The most restrictive (deny + enforce) wins.
    MostRestrictive,
    /// The first policy that matches (by insertion order) wins.
    FirstMatch,
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/// A pattern that can match a string value — either a literal, a wildcard
/// (using `*` and `?`), or a full regular expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    /// The raw pattern string as provided by the policy author.
    pub raw: String,
    /// Whether this pattern should be treated as a regex.
    #[serde(default)]
    pub is_regex: bool,
    /// Cached compiled regex (None for wildcard/literal patterns).
    #[serde(skip)]
    compiled: Option<Arc<Regex>>,
}

impl MatchPattern {
    /// Create a new match pattern from a raw string.
    /// If `is_regex` is false, `*` and `?` wildcards are supported.
    pub fn new(raw: &str, is_regex: bool) -> Result<Self, String> {
        let compiled = if is_regex {
            let re = Regex::new(raw).map_err(|e| format!("invalid regex '{}': {}", raw, e))?;
            Some(Arc::new(re))
        } else {
            None
        };
        Ok(Self {
            raw: raw.to_string(),
            is_regex,
            compiled,
        })
    }

    /// Test whether the given value matches this pattern.
    pub fn matches(&self, value: &str) -> bool {
        if let Some(ref re) = self.compiled {
            re.is_match(value)
        } else {
            wildcard_match(&self.raw, value)
        }
    }

    /// Returns a hashable representation of this pattern (the raw string + is_regex flag).
    pub fn key(&self) -> (&str, bool) {
        (&self.raw, self.is_regex)
    }
}

/// Simple wildcard matching: `*` matches any sequence, `?` matches any single char.
/// Uses a dynamic-programming approach for correctness.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let plen = p.len();
    let tlen = t.len();

    // dp[i][j] = pattern[0..i] matches text[0..j]
    let mut dp = vec![vec![false; tlen + 1]; plen + 1];
    dp[0][0] = true;

    // Handle leading '*' that can match empty.
    for i in 1..=plen {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        } else {
            break;
        }
    }

    // Fill the DP table.
    for i in 1..=plen {
        for j in 1..=tlen {
            if p[i - 1] == '*' {
                // '*' matches zero chars (dp[i-1][j]) or one+ chars (dp[i][j-1]).
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[plen][tlen]
}

// ---------------------------------------------------------------------------
// Condition language
// ---------------------------------------------------------------------------

/// Comparison operator for field conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    MatchesRegex,
    In,
    NotIn,
}

/// A single atomic condition that can be evaluated against a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCondition {
    /// The field path in the evaluation context (e.g. "trust.level", "source.ip").
    pub field: String,
    /// The comparison operator.
    pub op: ComparisonOp,
    /// The expected value (right-hand side). Stored as JSON for flexibility.
    pub value: serde_json::Value,
}

/// Logical combinator for compound conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOp {
    And,
    Or,
    Not,
}

/// A condition tree node — either a leaf (field condition) or a branch (logical combinator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionNode {
    /// A single field comparison.
    Leaf(FieldCondition),
    /// A logical combination of child conditions. `Not` should have exactly one child.
    Branch {
        op: LogicalOp,
        children: Vec<ConditionNode>,
    },
    /// Always true.
    AlwaysTrue,
    /// Always false.
    AlwaysFalse,
}

impl ConditionNode {
    /// Evaluate this condition against the given context map.
    /// Uses short-circuit evaluation: AND stops at first false, OR stops at first true.
    pub fn evaluate(&self, ctx: &EvaluationContext) -> bool {
        match self {
            ConditionNode::Leaf(fc) => evaluate_field_condition(fc, ctx),
            ConditionNode::Branch { op, children } => {
                match op {
                    LogicalOp::And => {
                        // Short-circuit: stop at first false.
                        for child in children {
                            if !child.evaluate(ctx) {
                                return false;
                            }
                        }
                        true
                    }
                    LogicalOp::Or => {
                        // Short-circuit: stop at first true.
                        for child in children {
                            if child.evaluate(ctx) {
                                return true;
                            }
                        }
                        false
                    }
                    LogicalOp::Not => {
                        // NOT expects exactly one child.
                        if let Some(child) = children.first() {
                            !child.evaluate(ctx)
                        } else {
                            true
                        }
                    }
                }
            }
            ConditionNode::AlwaysTrue => true,
            ConditionNode::AlwaysFalse => false,
        }
    }

    /// Convenience: create an AND branch from multiple nodes.
    pub fn and(children: Vec<ConditionNode>) -> Self {
        ConditionNode::Branch {
            op: LogicalOp::And,
            children,
        }
    }

    /// Convenience: create an OR branch from multiple nodes.
    pub fn or(children: Vec<ConditionNode>) -> Self {
        ConditionNode::Branch {
            op: LogicalOp::Or,
            children,
        }
    }

    /// Convenience: negate a node.
    pub fn not(child: ConditionNode) -> Self {
        ConditionNode::Branch {
            op: LogicalOp::Not,
            children: vec![child],
        }
    }
}

/// Evaluate a single field condition against the evaluation context.
fn evaluate_field_condition(fc: &FieldCondition, ctx: &EvaluationContext) -> bool {
    let field_val = ctx.get_field(&fc.field);
    match &fc.op {
        ComparisonOp::Eq => field_val == Some(&fc.value),
        ComparisonOp::Neq => field_val != Some(&fc.value),
        ComparisonOp::Gt => partial_ord_compare(field_val, &fc.value, |a, b| a > b),
        ComparisonOp::Gte => partial_ord_compare(field_val, &fc.value, |a, b| a >= b),
        ComparisonOp::Lt => partial_ord_compare(field_val, &fc.value, |a, b| a < b),
        ComparisonOp::Lte => partial_ord_compare(field_val, &fc.value, |a, b| a <= b),
        ComparisonOp::Contains => string_op(field_val, &fc.value, |h, n| h.contains(n)),
        ComparisonOp::StartsWith => string_op(field_val, &fc.value, |h, n| h.starts_with(n)),
        ComparisonOp::EndsWith => string_op(field_val, &fc.value, |h, n| h.ends_with(n)),
        ComparisonOp::MatchesRegex => {
            if let (Some(serde_json::Value::String(haystack)), serde_json::Value::String(needle)) =
                (field_val, &fc.value)
            {
                Regex::new(needle).map_or(false, |re| re.is_match(haystack))
            } else {
                false
            }
        }
        ComparisonOp::In => {
            if let serde_json::Value::Array(ref arr) = &fc.value {
                arr.iter().any(|item| field_val == Some(item))
            } else {
                false
            }
        }
        ComparisonOp::NotIn => {
            if let serde_json::Value::Array(ref arr) = &fc.value {
                !arr.iter().any(|item| field_val == Some(item))
            } else {
                false
            }
        }
    }
}

/// Helper: compare two JSON values as numbers using a comparator closure.
fn partial_ord_compare<F>(
    field_val: Option<&serde_json::Value>,
    target: &serde_json::Value,
    cmp: F,
) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let a = field_val.and_then(|v| v.as_f64());
    let b = target.as_f64();
    match (a, b) {
        (Some(av), Some(bv)) => cmp(av, bv),
        _ => false,
    }
}

/// Helper: apply a string operation between the field value and target.
fn string_op<F>(field_val: Option<&serde_json::Value>, target: &serde_json::Value, op: F) -> bool
where
    F: Fn(&str, &str) -> bool,
{
    if let (Some(serde_json::Value::String(h)), serde_json::Value::String(n)) = (field_val, target)
    {
        op(h, n)
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/// The input context for a single policy evaluation. Contains all the fields
/// that conditions can reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// Arbitrary key-value fields accessible to conditions.
    pub fields: HashMap<String, serde_json::Value>,
    /// The entity being evaluated (e.g. a user ID, service name, IP address).
    pub entity: String,
    /// The action being requested (e.g. "read", "write", "delete", "execute").
    pub action: String,
    /// The resource being accessed (e.g. "/api/admin/users", "database://prod").
    pub resource: String,
    /// Timestamp of the evaluation request.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub evaluated_at: DateTime<Utc>,
}

impl EvaluationContext {
    /// Create a new evaluation context.
    pub fn new(entity: &str, action: &str, resource: &str) -> Self {
        Self {
            fields: HashMap::new(),
            entity: entity.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            evaluated_at: Utc::now(),
        }
    }

    /// Set a field in the context.
    pub fn with_field(mut self, key: &str, value: serde_json::Value) -> Self {
        self.fields.insert(key.to_string(), value);
        self
    }

    /// Set a numeric field.
    pub fn with_f64(mut self, key: &str, value: f64) -> Self {
        let num =
            serde_json::Number::from_f64(value).unwrap_or_else(|| serde_json::Number::from(0));
        self.fields
            .insert(key.to_string(), serde_json::Value::Number(num));
        self
    }

    /// Set a string field.
    pub fn with_str(mut self, key: &str, value: &str) -> Self {
        self.fields
            .insert(key.to_string(), serde_json::json!(value));
        self
    }

    /// Get a field value by path (dot-separated for nested access).
    /// Tries exact key match first, then falls back to dot-path traversal.
    pub fn get_field(&self, path: &str) -> Option<&serde_json::Value> {
        // Try exact key match first (handles flat keys like "trust.level")
        if let Some(val) = self.fields.get(path) {
            return Some(val);
        }
        // Fall back to dot-separated nested path traversal
        let parts: Vec<&str> = path.split('.').collect();
        let mut current: &serde_json::Value = &serde_json::Value::Null;
        let mut found = false;

        for (i, part) in parts.iter().enumerate() {
            if i == 0 {
                if let Some(val) = self.fields.get(*part) {
                    current = val;
                    found = true;
                } else {
                    return None;
                }
            } else if let serde_json::Value::Object(map) = current {
                if let Some(val) = map.get(*part) {
                    current = val;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        if found {
            Some(current)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Policy definition
// ---------------------------------------------------------------------------

/// A single security policy with all its metadata and rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The version of this policy.
    pub version: PolicyVersion,
    /// Pattern for matching the entity (subject).
    pub entity_pattern: MatchPattern,
    /// Pattern for matching the action.
    pub action_pattern: MatchPattern,
    /// Pattern for matching the resource (object).
    pub resource_pattern: MatchPattern,
    /// The condition that must be satisfied for this policy to apply.
    pub condition: ConditionNode,
    /// The decision this policy produces when matched.
    pub decision: PolicyDecision,
    /// The effect to apply.
    pub effect: PolicyEffect,
    /// Priority for conflict resolution (higher = more important).
    pub priority: u32,
    /// Tags for categorization and querying.
    pub tags: HashSet<String>,
    /// Whether this policy is currently active.
    pub active: bool,
    /// When this policy was created.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    /// When this policy was last modified.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub updated_at: DateTime<Utc>,
}

impl Policy {
    /// Create a new policy with the given ID and name.
    pub fn new(id: &str, name: &str) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            version: PolicyVersion::new(1, 0, 0),
            entity_pattern: MatchPattern::new("*", false).unwrap(),
            action_pattern: MatchPattern::new("*", false).unwrap(),
            resource_pattern: MatchPattern::new("*", false).unwrap(),
            condition: ConditionNode::AlwaysTrue,
            decision: PolicyDecision::Allow,
            effect: PolicyEffect::Enforce,
            priority: 0,
            tags: HashSet::new(),
            active: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the decision of this policy.
    pub fn with_decision(mut self, decision: PolicyDecision) -> Self {
        self.decision = decision;
        self
    }

    /// Set the effect of this policy.
    pub fn with_effect(mut self, effect: PolicyEffect) -> Self {
        self.effect = effect;
        self
    }

    /// Set the priority of this policy.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set the entity pattern.
    pub fn with_entity_pattern(mut self, pattern: MatchPattern) -> Self {
        self.entity_pattern = pattern;
        self
    }

    /// Set the action pattern.
    pub fn with_action_pattern(mut self, pattern: MatchPattern) -> Self {
        self.action_pattern = pattern;
        self
    }

    /// Set the resource pattern.
    pub fn with_resource_pattern(mut self, pattern: MatchPattern) -> Self {
        self.resource_pattern = pattern;
        self
    }

    /// Set the condition.
    pub fn with_condition(mut self, condition: ConditionNode) -> Self {
        self.condition = condition;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set the version.
    pub fn with_version(mut self, version: PolicyVersion) -> Self {
        self.version = version;
        self
    }

    /// Set active flag.
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.insert(tag.to_string());
        self
    }

    /// Check whether this policy matches the given evaluation context.
    pub fn matches(&self, ctx: &EvaluationContext) -> bool {
        if !self.active {
            return false;
        }
        self.entity_pattern.matches(&ctx.entity)
            && self.action_pattern.matches(&ctx.action)
            && self.resource_pattern.matches(&ctx.resource)
            && self.condition.evaluate(ctx)
    }
}

// ---------------------------------------------------------------------------
// Policy versioning
// ---------------------------------------------------------------------------

/// Semantic version for policy tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PolicyVersion {
    /// Create a new semantic version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse from a string like "1.2.3".
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }

    /// Bump the major version.
    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    /// Bump the minor version.
    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    /// Bump the patch version.
    pub fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }
}

impl std::fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The rollout state of a policy version for canary deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RolloutState {
    /// Not yet deployed.
    Draft,
    /// Deployed to a small percentage of traffic for testing.
    Canary,
    /// Deployed to all traffic.
    Full,
    /// Previously deployed, now superseded.
    Superseded,
    /// Rolled back after a failed deployment.
    RolledBack,
}

impl std::fmt::Display for RolloutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RolloutState::Draft => write!(f, "draft"),
            RolloutState::Canary => write!(f, "canary"),
            RolloutState::Full => write!(f, "full"),
            RolloutState::Superseded => write!(f, "superseded"),
            RolloutState::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// Tracks a single version of a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersionRecord {
    /// The version number.
    pub version: PolicyVersion,
    /// The full policy at this version.
    pub policy: Policy,
    /// The rollout state of this version.
    pub state: RolloutState,
    /// For canary: the percentage of traffic (0.0 to 1.0).
    pub canary_percentage: f64,
    /// When this version was created.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    /// When this version's state was last changed.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub updated_at: DateTime<Utc>,
    /// Diff note describing what changed from the previous version.
    pub diff_note: String,
}

impl PolicyVersionRecord {
    /// Create a new version record for a policy.
    pub fn new(policy: Policy, diff_note: &str) -> Self {
        let now = Utc::now();
        Self {
            version: policy.version.clone(),
            policy,
            state: RolloutState::Draft,
            canary_percentage: 0.0,
            created_at: now,
            updated_at: now,
            diff_note: diff_note.to_string(),
        }
    }
}

/// Manages the version history of a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersionManager {
    /// The policy ID this manager tracks.
    pub policy_id: String,
    /// All known versions, ordered by version number (ascending).
    pub versions: Vec<PolicyVersionRecord>,
    /// The index of the currently active version in `versions`.
    pub active_version_index: Option<usize>,
}

impl PolicyVersionManager {
    /// Create a new version manager.
    pub fn new(policy_id: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            versions: Vec::new(),
            active_version_index: None,
        }
    }

    /// Register a new version of the policy.
    pub fn add_version(&mut self, mut record: PolicyVersionRecord) {
        record.policy.id = self.policy_id.clone();
        // Insert in sorted order by version.
        let pos = self
            .versions
            .iter()
            .position(|v| v.version >= record.version)
            .unwrap_or(self.versions.len());
        self.versions.insert(pos, record);
    }

    /// Get the currently active version's policy.
    pub fn active_policy(&self) -> Option<&Policy> {
        self.active_version_index
            .and_then(|idx| self.versions.get(idx))
            .map(|r| &r.policy)
    }

    /// Promote a version to canary with the given traffic percentage.
    pub fn promote_to_canary(&mut self, version: &PolicyVersion, percentage: f64) -> bool {
        let clamped_pct = percentage.clamp(0.0, 1.0);
        for record in &mut self.versions {
            if record.version == *version {
                record.state = RolloutState::Canary;
                record.canary_percentage = clamped_pct;
                record.updated_at = Utc::now();
                return true;
            }
        }
        false
    }

    /// Promote a version to full rollout.
    pub fn promote_to_full(&mut self, version: &PolicyVersion) -> bool {
        // First, mark the current active version as superseded.
        if let Some(idx) = self.active_version_index {
            if let Some(active) = self.versions.get_mut(idx) {
                active.state = RolloutState::Superseded;
                active.updated_at = Utc::now();
            }
        }

        // Find and promote the target version.
        for (i, record) in self.versions.iter_mut().enumerate() {
            if record.version == *version {
                record.state = RolloutState::Full;
                record.canary_percentage = 1.0;
                record.updated_at = Utc::now();
                self.active_version_index = Some(i);
                return true;
            }
        }
        false
    }

    /// Roll back to a previous version.
    pub fn rollback(&mut self, version: &PolicyVersion) -> bool {
        // Mark the current active version as rolled back.
        if let Some(idx) = self.active_version_index {
            if let Some(active) = self.versions.get_mut(idx) {
                active.state = RolloutState::RolledBack;
                active.updated_at = Utc::now();
            }
        }

        // Find and activate the target version.
        for (i, record) in self.versions.iter_mut().enumerate() {
            if record.version == *version {
                record.state = RolloutState::Full;
                record.canary_percentage = 1.0;
                record.updated_at = Utc::now();
                self.active_version_index = Some(i);
                return true;
            }
        }
        false
    }

    /// Generate a diff between two versions as a list of change descriptions.
    pub fn diff_versions(&self, v1: &PolicyVersion, v2: &PolicyVersion) -> Vec<String> {
        let p1 = self.versions.iter().find(|r| r.version == *v1);
        let p2 = self.versions.iter().find(|r| r.version == *v2);

        match (p1, p2) {
            (Some(r1), Some(r2)) => diff_policies(&r1.policy, &r2.policy),
            _ => vec!["One or both versions not found.".to_string()],
        }
    }

    /// Get all version records.
    pub fn all_versions(&self) -> &[PolicyVersionRecord] {
        &self.versions
    }

    /// Check if a given version is in canary state.
    pub fn is_canary(&self, version: &PolicyVersion) -> bool {
        self.versions
            .iter()
            .any(|r| r.version == *version && r.state == RolloutState::Canary)
    }

    /// Get the canary percentage for a version.
    pub fn canary_percentage(&self, version: &PolicyVersion) -> f64 {
        self.versions
            .iter()
            .find(|r| r.version == *version)
            .map(|r| r.canary_percentage)
            .unwrap_or(0.0)
    }
}

/// Generate a list of human-readable diffs between two policies.
pub fn diff_policies(p1: &Policy, p2: &Policy) -> Vec<String> {
    let mut diffs = Vec::new();

    if p1.name != p2.name {
        diffs.push(format!("name: '{}' -> '{}'", p1.name, p2.name));
    }
    if p1.description != p2.description {
        diffs.push(format!("description changed"));
    }
    if p1.decision != p2.decision {
        diffs.push(format!("decision: {} -> {}", p1.decision, p2.decision));
    }
    if p1.effect != p2.effect {
        diffs.push(format!("effect: {} -> {}", p1.effect, p2.effect));
    }
    if p1.priority != p2.priority {
        diffs.push(format!("priority: {} -> {}", p1.priority, p2.priority));
    }
    if p1.entity_pattern.raw != p2.entity_pattern.raw {
        diffs.push(format!(
            "entity_pattern: '{}' -> '{}'",
            p1.entity_pattern.raw, p2.entity_pattern.raw
        ));
    }
    if p1.action_pattern.raw != p2.action_pattern.raw {
        diffs.push(format!(
            "action_pattern: '{}' -> '{}'",
            p1.action_pattern.raw, p2.action_pattern.raw
        ));
    }
    if p1.resource_pattern.raw != p2.resource_pattern.raw {
        diffs.push(format!(
            "resource_pattern: '{}' -> '{}'",
            p1.resource_pattern.raw, p2.resource_pattern.raw
        ));
    }
    if p1.active != p2.active {
        diffs.push(format!("active: {} -> {}", p1.active, p2.active));
    }

    let t1 = &p1.tags;
    let t2 = &p2.tags;
    let added: Vec<_> = t2.difference(t1).collect();
    let removed: Vec<_> = t1.difference(t2).collect();
    if !added.is_empty() || !removed.is_empty() {
        diffs.push(format!("tags: +{:?} -{:?}", added, removed));
    }

    if diffs.is_empty() {
        diffs.push("no differences".to_string());
    }

    diffs
}

// ---------------------------------------------------------------------------
// Decision cache
// ---------------------------------------------------------------------------

/// A cached decision entry with a TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedDecision {
    decision: PolicyDecision,
    effects: Vec<(String, PolicyEffect)>,
    computed_at: DateTime<Utc>,
    ttl: Duration,
}

impl CachedDecision {
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.computed_at + self.ttl
    }
}

// ---------------------------------------------------------------------------
// Conflict audit record
// ---------------------------------------------------------------------------

/// A record of a conflict between multiple matching policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// Unique ID for this conflict event.
    pub conflict_id: String,
    /// The evaluation context that triggered the conflict.
    pub context_entity: String,
    pub context_action: String,
    pub context_resource: String,
    /// The conflicting policies and their decisions.
    pub conflicting: Vec<ConflictingPolicy>,
    /// Which resolution strategy was used.
    pub resolution_strategy: ConflictResolutionStrategy,
    /// The final decision after resolution.
    pub resolved_decision: PolicyDecision,
    /// Timestamp of the conflict.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

/// A single policy that participated in a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictingPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub decision: PolicyDecision,
    pub effect: PolicyEffect,
    pub priority: u32,
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

/// A single audit record for a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique ID for this audit event.
    pub audit_id: String,
    /// The evaluation context that was evaluated.
    pub entity: String,
    pub action: String,
    pub resource: String,
    /// All policies that matched the context.
    pub matching_policy_ids: Vec<String>,
    /// The final decision.
    pub decision: PolicyDecision,
    /// The stacked effects from all matching policies.
    pub effects: Vec<EffectRecord>,
    /// Evaluation latency in microseconds.
    pub latency_us: u64,
    /// Whether the decision was served from cache.
    pub cache_hit: bool,
    /// Timestamp of the evaluation.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Additional metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A record of a single effect applied during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectRecord {
    pub policy_id: String,
    pub effect: PolicyEffect,
    pub decision: PolicyDecision,
    pub policy_priority: u32,
}

// ---------------------------------------------------------------------------
// Audit trail storage & query
// ---------------------------------------------------------------------------

/// In-memory audit trail with configurable retention and querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    records: VecDeque<AuditRecord>,
    /// Maximum number of records to retain.
    max_records: usize,
    /// Maximum age of records to retain.
    max_age: Duration,
}

impl AuditTrail {
    /// Create a new audit trail with default retention (10,000 records, 24 hours).
    pub fn new() -> Self {
        Self {
            records: VecDeque::new(),
            max_records: 10_000,
            max_age: Duration::hours(24),
        }
    }

    /// Create with custom retention settings.
    pub fn with_retention(max_records: usize, max_age: Duration) -> Self {
        Self {
            records: VecDeque::new(),
            max_records,
            max_age,
        }
    }

    /// Record a policy evaluation.
    pub fn record(&mut self, record: AuditRecord) {
        self.records.push_back(record);
        self.evict();
    }

    /// Evict old and excess records.
    fn evict(&mut self) {
        let cutoff = Utc::now() - self.max_age;
        while let Some(front) = self.records.front() {
            if front.timestamp < cutoff || self.records.len() > self.max_records {
                self.records.pop_front();
            } else {
                break;
            }
        }
        // Also trim from front if we're still over limit.
        while self.records.len() > self.max_records {
            self.records.pop_front();
        }
    }

    /// Query audit records by time range.
    pub fn query_by_time(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp >= start && r.timestamp <= end)
            .collect()
    }

    /// Query audit records by entity.
    pub fn query_by_entity(&self, entity: &str) -> Vec<&AuditRecord> {
        self.records.iter().filter(|r| r.entity == entity).collect()
    }

    /// Query audit records by decision.
    pub fn query_by_decision(&self, decision: PolicyDecision) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.decision == decision)
            .collect()
    }

    /// Query audit records by action.
    pub fn query_by_action(&self, action: &str) -> Vec<&AuditRecord> {
        self.records.iter().filter(|r| r.action == action).collect()
    }

    /// Get all records.
    pub fn all_records(&self) -> Vec<&AuditRecord> {
        self.records.iter().collect()
    }

    /// Get the total number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the trail is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Evaluation result
// ---------------------------------------------------------------------------

/// The complete result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// The final policy decision.
    pub decision: PolicyDecision,
    /// All effects that should be applied (stacked from matching policies).
    pub effects: Vec<EffectRecord>,
    /// All matching policy IDs.
    pub matching_policy_ids: Vec<String>,
    /// Whether the action is ultimately blocked.
    pub blocked: bool,
    /// Any conflicts that were resolved.
    pub conflicts: Vec<ConflictRecord>,
    /// Latency of the evaluation in microseconds.
    pub latency_us: u64,
    /// Whether the result was served from cache.
    pub cache_hit: bool,
}

impl EvaluationResult {
    /// Check if the action is allowed (not blocked).
    pub fn is_allowed(&self) -> bool {
        !self.blocked
    }
}

// ---------------------------------------------------------------------------
// Policy executor — the main engine
// ---------------------------------------------------------------------------

/// Configuration for the policy executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// The default decision when no policies match.
    pub default_decision: PolicyDecision,
    /// The conflict resolution strategy.
    pub conflict_strategy: ConflictResolutionStrategy,
    /// Cache TTL for decisions.
    pub cache_ttl_ms: i64,
    /// Maximum number of cache entries.
    pub cache_max_entries: usize,
    /// Whether to enable the audit trail.
    pub audit_enabled: bool,
    /// Maximum audit trail size.
    pub audit_max_records: usize,
    /// Maximum audit record age in hours.
    pub audit_max_age_hours: i64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            default_decision: PolicyDecision::DenyDefault,
            conflict_strategy: ConflictResolutionStrategy::MostRestrictive,
            cache_ttl_ms: 5000,
            cache_max_entries: 10_000,
            audit_enabled: true,
            audit_max_records: 10_000,
            audit_max_age_hours: 24,
        }
    }
}

/// The core policy execution engine.
///
/// Evaluates security policies against evaluation contexts, resolves conflicts,
/// applies effects, manages versioning, and maintains an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExecutor {
    /// All registered policies.
    policies: HashMap<String, Policy>,
    /// Version managers keyed by policy ID.
    version_managers: HashMap<String, PolicyVersionManager>,
    /// Decision cache.
    cache: HashMap<String, CachedDecision>,
    /// Audit trail.
    audit_trail: AuditTrail,
    /// Conflict records.
    conflicts: Vec<ConflictRecord>,
    /// Configuration.
    config: ExecutorConfig,
}

impl PolicyExecutor {
    /// Create a new policy executor with default configuration.
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::default())
    }

    /// Create a new policy executor with custom configuration.
    pub fn with_config(config: ExecutorConfig) -> Self {
        let audit_trail = AuditTrail::with_retention(
            config.audit_max_records,
            Duration::hours(config.audit_max_age_hours),
        );
        Self {
            policies: HashMap::new(),
            version_managers: HashMap::new(),
            cache: HashMap::new(),
            audit_trail,
            conflicts: Vec::new(),
            config,
        }
    }

    /// Register a policy. If a policy with the same ID exists, it is replaced.
    pub fn add_policy(&mut self, policy: Policy) {
        let pid = policy.id.clone();
        // Initialize version manager if needed.
        if !self.version_managers.contains_key(&pid) {
            let mut vm = PolicyVersionManager::new(&pid);
            let record = PolicyVersionRecord::new(policy.clone(), "initial version");
            vm.add_version(record);
            vm.active_version_index = Some(0);
            self.version_managers.insert(pid.clone(), vm);
        }
        self.policies.insert(pid, policy);
    }

    /// Remove a policy by ID.
    pub fn remove_policy(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }

    /// Get a policy by ID.
    pub fn get_policy(&self, policy_id: &str) -> Option<&Policy> {
        self.policies.get(policy_id)
    }

    /// Get all registered policies.
    pub fn policies(&self) -> Vec<&Policy> {
        self.policies.values().collect()
    }

    /// Get the version manager for a policy.
    pub fn version_manager(&self, policy_id: &str) -> Option<&PolicyVersionManager> {
        self.version_managers.get(policy_id)
    }

    /// Get a mutable reference to the version manager for a policy.
    pub fn version_manager_mut(&mut self, policy_id: &str) -> Option<&mut PolicyVersionManager> {
        self.version_managers.get_mut(policy_id)
    }

    /// Evaluate a context against all registered policies.
    ///
    /// This is the main entry point. It:
    /// 1. Checks the cache for a cached decision.
    /// 2. Finds all matching policies.
    /// 3. Resolves any conflicts.
    /// 4. Stacks effects.
    /// 5. Records the audit trail.
    pub fn evaluate(&mut self, ctx: &EvaluationContext) -> EvaluationResult {
        let start = Utc::now();

        // Check cache.
        let cache_key = self.cache_key(ctx);
        if let Some(cached) = self.cache.get(&cache_key) {
            if !cached.is_expired(start) {
                let result = self.build_cached_result(ctx, cached, true);
                let latency_us = (Utc::now() - start).num_microseconds().unwrap_or(0) as u64;
                let mut result = result;
                result.latency_us = latency_us;
                self.record_audit(ctx, &result);
                return result;
            }
        }

        // Find matching policies.
        let matching: Vec<Policy> = self
            .policies
            .values()
            .filter(|p| p.matches(ctx))
            .cloned()
            .collect();

        let matching_ids: Vec<String> = matching.iter().map(|p| p.id.clone()).collect();

        let (decision, effects, conflicts) = if matching.is_empty() {
            (self.config.default_decision.clone(), vec![], vec![])
        } else {
            self.resolve_and_stack(&matching)
        };

        // Determine if blocked: an enforce-level deny blocks the action.
        let blocked = self.is_blocked(&decision, &effects);

        // Cache the result.
        let ttl = Duration::milliseconds(self.config.cache_ttl_ms);
        self.cache.insert(
            cache_key,
            CachedDecision {
                decision: decision.clone(),
                effects: effects
                    .iter()
                    .map(|e| (e.policy_id.clone(), e.effect.clone()))
                    .collect(),
                computed_at: start,
                ttl,
            },
        );

        // Evict excess cache entries.
        self.evict_cache();

        let latency_us = (Utc::now() - start).num_microseconds().unwrap_or(0) as u64;

        let result = EvaluationResult {
            decision,
            effects,
            matching_policy_ids: matching_ids,
            blocked,
            conflicts,
            latency_us,
            cache_hit: false,
        };

        self.record_audit(ctx, &result);

        result
    }

    /// Resolve conflicts and stack effects from matching policies.
    fn resolve_and_stack(
        &mut self,
        matching: &[Policy],
    ) -> (PolicyDecision, Vec<EffectRecord>, Vec<ConflictRecord>) {
        // Check if there are conflicting decisions.
        let has_allow = matching.iter().any(|p| p.decision.is_allow());
        let has_deny = matching.iter().any(|p| p.decision.is_deny());

        let mut conflicts = Vec::new();

        let decision = if has_allow && has_deny {
            // Record the conflict.
            let conflicting: Vec<ConflictingPolicy> = matching
                .iter()
                .map(|p| ConflictingPolicy {
                    policy_id: p.id.clone(),
                    policy_name: p.name.clone(),
                    decision: p.decision.clone(),
                    effect: p.effect.clone(),
                    priority: p.priority,
                })
                .collect();

            let resolved = self.resolve_conflict(matching);

            let conflict_record = ConflictRecord {
                conflict_id: uuid::Uuid::new_v4().to_string(),
                context_entity: matching
                    .first()
                    .map(|p| p.entity_pattern.raw.clone())
                    .unwrap_or_default(),
                context_action: matching
                    .first()
                    .map(|p| p.action_pattern.raw.clone())
                    .unwrap_or_default(),
                context_resource: matching
                    .first()
                    .map(|p| p.resource_pattern.raw.clone())
                    .unwrap_or_default(),
                conflicting,
                resolution_strategy: self.config.conflict_strategy.clone(),
                resolved_decision: resolved.clone(),
                timestamp: Utc::now(),
            };

            conflicts.push(conflict_record);
            resolved
        } else if has_deny {
            // All matching policies deny — pick the most restrictive.
            self.resolve_conflict(matching)
        } else {
            // All matching policies allow.
            self.resolve_conflict(matching)
        };

        // Stack effects from all matching policies.
        let effects: Vec<EffectRecord> = matching
            .iter()
            .map(|p| EffectRecord {
                policy_id: p.id.clone(),
                effect: p.effect.clone(),
                decision: p.decision.clone(),
                policy_priority: p.priority,
            })
            .collect();

        (decision, effects, conflicts)
    }

    /// Resolve a conflict using the configured strategy.
    fn resolve_conflict(&self, matching: &[Policy]) -> PolicyDecision {
        match self.config.conflict_strategy {
            ConflictResolutionStrategy::Priority => {
                // Highest priority wins.
                matching
                    .iter()
                    .max_by_key(|p| p.priority)
                    .map(|p| p.decision.clone())
                    .unwrap_or(self.config.default_decision.clone())
            }
            ConflictResolutionStrategy::MostRestrictive => {
                // The decision with the highest restriction score wins.
                matching
                    .iter()
                    .max_by_key(|p| p.decision.restriction_score())
                    .map(|p| p.decision.clone())
                    .unwrap_or(self.config.default_decision.clone())
            }
            ConflictResolutionStrategy::FirstMatch => {
                // First matching policy wins (by iteration order, which is
                // non-deterministic for HashMap, so we sort by insertion
                // order approximation using priority as tiebreaker).
                let mut sorted: Vec<&Policy> = matching.iter().collect();
                sorted.sort_by_key(|p| std::cmp::Reverse(p.priority));
                sorted
                    .first()
                    .map(|p| (*p).decision.clone())
                    .unwrap_or(self.config.default_decision.clone())
            }
        }
    }

    /// Determine whether the action is blocked based on the decision and effects.
    fn is_blocked(&self, decision: &PolicyDecision, effects: &[EffectRecord]) -> bool {
        match decision {
            PolicyDecision::Allow | PolicyDecision::AllowDefault => false,
            PolicyDecision::Deny => effects.iter().any(|e| e.effect.is_blocking()),
            PolicyDecision::DenyDefault => true,
        }
    }

    /// Build a result from a cached decision.
    fn build_cached_result(
        &self,
        _ctx: &EvaluationContext,
        cached: &CachedDecision,
        _cache_hit: bool,
    ) -> EvaluationResult {
        let effects: Vec<EffectRecord> = cached
            .effects
            .iter()
            .map(|(pid, effect)| EffectRecord {
                policy_id: pid.clone(),
                effect: effect.clone(),
                decision: cached.decision.clone(),
                policy_priority: 0,
            })
            .collect();

        let blocked = self.is_blocked(&cached.decision, &effects);

        EvaluationResult {
            decision: cached.decision.clone(),
            effects,
            matching_policy_ids: cached.effects.iter().map(|(pid, _)| pid.clone()).collect(),
            blocked,
            conflicts: vec![],
            latency_us: 0,
            cache_hit: true,
        }
    }

    /// Generate a cache key from the evaluation context.
    fn cache_key(&self, ctx: &EvaluationContext) -> String {
        // Include the key fields plus a hash of the context fields for uniqueness.
        let fields_json = serde_json::to_string(&ctx.fields).unwrap_or_default();
        format!(
            "{}:{}:{}:{}",
            ctx.entity, ctx.action, ctx.resource, fields_json
        )
    }

    /// Evict expired and excess cache entries.
    fn evict_cache(&mut self) {
        let now = Utc::now();
        // Remove expired entries.
        self.cache.retain(|_, v| !v.is_expired(now));

        // If still over limit, remove oldest entries.
        if self.cache.len() > self.config.cache_max_entries {
            let mut entries: Vec<_> = self
                .cache
                .iter()
                .map(|(k, v)| (k.clone(), v.computed_at))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let to_remove = self.cache.len() - self.config.cache_max_entries;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.cache.remove(&key);
            }
        }
    }

    /// Record an evaluation in the audit trail.
    fn record_audit(&mut self, ctx: &EvaluationContext, result: &EvaluationResult) {
        if !self.config.audit_enabled {
            return;
        }
        let record = AuditRecord {
            audit_id: uuid::Uuid::new_v4().to_string(),
            entity: ctx.entity.clone(),
            action: ctx.action.clone(),
            resource: ctx.resource.clone(),
            matching_policy_ids: result.matching_policy_ids.clone(),
            decision: result.decision.clone(),
            effects: result.effects.clone(),
            latency_us: result.latency_us,
            cache_hit: result.cache_hit,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };
        self.audit_trail.record(record);
    }

    /// Get a reference to the audit trail.
    pub fn audit_trail(&self) -> &AuditTrail {
        &self.audit_trail
    }

    /// Get all conflict records.
    pub fn conflicts(&self) -> &[ConflictRecord] {
        &self.conflicts
    }

    /// Clear the decision cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Clear the audit trail.
    pub fn clear_audit_trail(&mut self) {
        self.audit_trail.clear();
    }

    /// Get the number of policies currently registered.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Get the number of entries in the cache.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Get statistics about the executor.
    pub fn stats(&self) -> ExecutorStats {
        ExecutorStats {
            policy_count: self.policies.len(),
            cache_size: self.cache.len(),
            audit_record_count: self.audit_trail.len(),
            conflict_count: self.conflicts.len(),
            version_manager_count: self.version_managers.len(),
        }
    }
}

impl Default for PolicyExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime statistics for the policy executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorStats {
    pub policy_count: usize,
    pub cache_size: usize,
    pub audit_record_count: usize,
    pub conflict_count: usize,
    pub version_manager_count: usize,
}

// ---------------------------------------------------------------------------
// Effect applier — applies the stacked effects to produce an action outcome
// ---------------------------------------------------------------------------

/// The outcome of applying effects to an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// The primary decision.
    pub decision: PolicyDecision,
    /// All applied effects in order.
    pub applied_effects: Vec<AppliedEffect>,
    /// Advisory messages (from Advisory effects).
    pub advisory_messages: Vec<String>,
    /// Audit messages (from AuditOnly effects).
    pub audit_messages: Vec<String>,
}

/// A single applied effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedEffect {
    pub policy_id: String,
    pub effect: PolicyEffect,
    pub decision: PolicyDecision,
}

/// Applies the effects from an evaluation result to determine the final action outcome.
pub fn apply_effects(result: &EvaluationResult) -> ActionOutcome {
    let mut advisory_messages = Vec::new();
    let mut audit_messages = Vec::new();
    let mut applied_effects = Vec::new();

    for effect_record in &result.effects {
        applied_effects.push(AppliedEffect {
            policy_id: effect_record.policy_id.clone(),
            effect: effect_record.effect.clone(),
            decision: effect_record.decision.clone(),
        });

        match &effect_record.effect {
            PolicyEffect::Enforce => {
                // Enforce is already accounted for in `result.blocked`.
            }
            PolicyEffect::Advisory => {
                let msg = format!(
                    "[advisory] policy '{}' issued advisory for action",
                    effect_record.policy_id
                );
                advisory_messages.push(msg);
            }
            PolicyEffect::AuditOnly => {
                let msg = format!(
                    "[audit] policy '{}' recorded action for review",
                    effect_record.policy_id
                );
                audit_messages.push(msg);
            }
        }
    }

    ActionOutcome {
        allowed: !result.blocked,
        decision: result.decision.clone(),
        applied_effects,
        advisory_messages,
        audit_messages,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a simple policy with given parameters.
    fn make_policy(
        id: &str,
        entity_pat: &str,
        action_pat: &str,
        decision: PolicyDecision,
        effect: PolicyEffect,
        priority: u32,
    ) -> Policy {
        Policy::new(id, id)
            .with_entity_pattern(MatchPattern::new(entity_pat, false).unwrap())
            .with_action_pattern(MatchPattern::new(action_pat, false).unwrap())
            .with_decision(decision)
            .with_effect(effect)
            .with_priority(priority)
    }

    /// Helper: create a default evaluation context.
    fn make_ctx(entity: &str, action: &str, resource: &str) -> EvaluationContext {
        EvaluationContext::new(entity, action, resource)
    }

    #[test]
    fn test_wildcard_match_exact() {
        assert!(wildcard_match("hello", "hello"));
        assert!(!wildcard_match("hello", "world"));
    }

    #[test]
    fn test_wildcard_match_star() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("h*o", "hello"));
        assert!(wildcard_match("h*o", "ho"));
        assert!(!wildcard_match("h*o", "hellox"));
    }

    #[test]
    fn test_wildcard_match_question_mark() {
        assert!(wildcard_match("h?llo", "hello"));
        assert!(wildcard_match("h?llo", "hallo"));
        assert!(!wildcard_match("h?llo", "hllo"));
        assert!(!wildcard_match("h?llo", "heello"));
    }

    #[test]
    fn test_wildcard_match_combined() {
        assert!(wildcard_match("*.admin.*", "service.admin.users"));
        assert!(wildcard_match("*.admin.*", "admin.admin.admin"));
        assert!(!wildcard_match("*.admin.*", "admin.users"));
    }

    #[test]
    fn test_match_pattern_literal() {
        let p = MatchPattern::new("admin", false).unwrap();
        assert!(p.matches("admin"));
        assert!(!p.matches("administrator"));
    }

    #[test]
    fn test_match_pattern_regex() {
        let p = MatchPattern::new(r"^admin-\d+$", true).unwrap();
        assert!(p.matches("admin-42"));
        assert!(p.matches("admin-0"));
        assert!(!p.matches("admin-abc"));
        assert!(!p.matches("admin-"));
    }

    #[test]
    fn test_policy_decision_restrictions() {
        assert!(
            PolicyDecision::Deny.restriction_score()
                > PolicyDecision::DenyDefault.restriction_score()
        );
        assert!(
            PolicyDecision::DenyDefault.restriction_score()
                > PolicyDecision::AllowDefault.restriction_score()
        );
        assert!(
            PolicyDecision::AllowDefault.restriction_score()
                > PolicyDecision::Allow.restriction_score()
        );
        assert!(PolicyDecision::Allow.is_allow());
        assert!(!PolicyDecision::Allow.is_deny());
        assert!(PolicyDecision::Deny.is_deny());
        assert!(!PolicyDecision::Deny.is_allow());
    }

    #[test]
    fn test_policy_effect_is_blocking() {
        assert!(PolicyEffect::Enforce.is_blocking());
        assert!(!PolicyEffect::Advisory.is_blocking());
        assert!(!PolicyEffect::AuditOnly.is_blocking());
    }

    #[test]
    fn test_condition_leaf_evaluate_eq() {
        let ctx = EvaluationContext::new("user1", "read", "/data").with_str("role", "admin");
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "role".to_string(),
            op: ComparisonOp::Eq,
            value: serde_json::json!("admin"),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_leaf_evaluate_neq() {
        let ctx = EvaluationContext::new("user1", "read", "/data").with_str("role", "guest");
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "role".to_string(),
            op: ComparisonOp::Neq,
            value: serde_json::json!("admin"),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_leaf_evaluate_numeric_gt() {
        let ctx = EvaluationContext::new("svc", "call", "/api").with_f64("trust.level", 0.85);
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "trust.level".to_string(),
            op: ComparisonOp::Gt,
            value: serde_json::json!(0.7),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_and_short_circuit() {
        let ctx = EvaluationContext::new("u1", "read", "/r")
            .with_str("role", "admin")
            .with_f64("trust.level", 0.5);
        // AND with a false second condition — should short-circuit.
        let cond = ConditionNode::and(vec![
            ConditionNode::Leaf(FieldCondition {
                field: "role".to_string(),
                op: ComparisonOp::Eq,
                value: serde_json::json!("admin"),
            }),
            ConditionNode::Leaf(FieldCondition {
                field: "trust.level".to_string(),
                op: ComparisonOp::Gt,
                value: serde_json::json!(0.9),
            }),
        ]);
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_or_short_circuit() {
        let ctx = EvaluationContext::new("u1", "read", "/r").with_str("role", "guest");
        let cond = ConditionNode::or(vec![
            ConditionNode::Leaf(FieldCondition {
                field: "role".to_string(),
                op: ComparisonOp::Eq,
                value: serde_json::json!("admin"),
            }),
            ConditionNode::Leaf(FieldCondition {
                field: "role".to_string(),
                op: ComparisonOp::Eq,
                value: serde_json::json!("guest"),
            }),
        ]);
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_not() {
        let ctx = EvaluationContext::new("u1", "read", "/r").with_str("role", "admin");
        let cond = ConditionNode::not(ConditionNode::Leaf(FieldCondition {
            field: "role".to_string(),
            op: ComparisonOp::Eq,
            value: serde_json::json!("admin"),
        }));
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_contains() {
        let ctx = EvaluationContext::new("u1", "read", "/admin/users")
            .with_str("resource", "/admin/users");
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "resource".to_string(),
            op: ComparisonOp::Contains,
            value: serde_json::json!("admin"),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_in_operator() {
        let ctx = EvaluationContext::new("u1", "read", "/data").with_str("env", "staging");
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "env".to_string(),
            op: ComparisonOp::In,
            value: serde_json::json!(["dev", "staging", "qa"]),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_matches_regex() {
        let ctx =
            EvaluationContext::new("u1", "read", "/data").with_str("source_ip", "192.168.1.100");
        let cond = ConditionNode::Leaf(FieldCondition {
            field: "source_ip".to_string(),
            op: ComparisonOp::MatchesRegex,
            value: serde_json::json!(r"^192\.168\."),
        });
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_evaluation_context_nested_field() {
        let mut fields = HashMap::new();
        fields.insert(
            "trust".to_string(),
            serde_json::json!({"level": 0.95, "trend": "improving"}),
        );
        let ctx = EvaluationContext {
            fields,
            entity: "svc".to_string(),
            action: "call".to_string(),
            resource: "/api".to_string(),
            evaluated_at: Utc::now(),
        };
        assert_eq!(ctx.get_field("trust.level"), Some(&serde_json::json!(0.95)));
        assert_eq!(
            ctx.get_field("trust.trend"),
            Some(&serde_json::json!("improving"))
        );
        assert_eq!(ctx.get_field("trust.missing"), None);
    }

    #[test]
    fn test_single_policy_allow() {
        let mut executor = PolicyExecutor::new();
        let policy = make_policy(
            "p1",
            "user1",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            10,
        );
        executor.add_policy(policy);
        let ctx = make_ctx("user1", "read", "/data");
        let result = executor.evaluate(&ctx);
        assert!(result.is_allowed());
        assert!(!result.blocked);
        assert_eq!(result.decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_single_policy_deny_enforce() {
        let mut executor = PolicyExecutor::new();
        let policy = make_policy(
            "p1",
            "user1",
            "delete",
            PolicyDecision::Deny,
            PolicyEffect::Enforce,
            10,
        );
        executor.add_policy(policy);
        let ctx = make_ctx("user1", "delete", "/data");
        let result = executor.evaluate(&ctx);
        assert!(!result.is_allowed());
        assert!(result.blocked);
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_no_match_returns_default() {
        let mut executor = PolicyExecutor::with_config(ExecutorConfig {
            default_decision: PolicyDecision::DenyDefault,
            ..ExecutorConfig::default()
        });
        let policy = make_policy(
            "p1",
            "user1",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            10,
        );
        executor.add_policy(policy);
        let ctx = make_ctx("user2", "write", "/data");
        let result = executor.evaluate(&ctx);
        assert!(!result.is_allowed());
        assert_eq!(result.decision, PolicyDecision::DenyDefault);
    }

    #[test]
    fn test_conflict_most_restrictive_wins() {
        let mut executor = PolicyExecutor::with_config(ExecutorConfig {
            conflict_strategy: ConflictResolutionStrategy::MostRestrictive,
            ..ExecutorConfig::default()
        });
        executor.add_policy(make_policy(
            "allow-policy",
            "svc",
            "call",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            1,
        ));
        executor.add_policy(make_policy(
            "deny-policy",
            "svc",
            "call",
            PolicyDecision::Deny,
            PolicyEffect::Enforce,
            1,
        ));
        let ctx = make_ctx("svc", "call", "/api");
        let result = executor.evaluate(&ctx);
        assert_eq!(result.decision, PolicyDecision::Deny);
        assert!(result.blocked);
        assert!(!result.conflicts.is_empty());
    }

    #[test]
    fn test_conflict_priority_wins() {
        let mut executor = PolicyExecutor::with_config(ExecutorConfig {
            conflict_strategy: ConflictResolutionStrategy::Priority,
            ..ExecutorConfig::default()
        });
        executor.add_policy(make_policy(
            "low-priority-deny",
            "svc",
            "call",
            PolicyDecision::Deny,
            PolicyEffect::Enforce,
            1,
        ));
        executor.add_policy(make_policy(
            "high-priority-allow",
            "svc",
            "call",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            100,
        ));
        let ctx = make_ctx("svc", "call", "/api");
        let result = executor.evaluate(&ctx);
        assert_eq!(result.decision, PolicyDecision::Allow);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_deny_advisory_does_not_block() {
        let mut executor = PolicyExecutor::new();
        let policy = make_policy(
            "p1",
            "user1",
            "read",
            PolicyDecision::Deny,
            PolicyEffect::Advisory,
            10,
        );
        executor.add_policy(policy);
        let ctx = make_ctx("user1", "read", "/data");
        let result = executor.evaluate(&ctx);
        // Deny with Advisory effect should NOT block.
        assert!(!result.blocked);
    }

    #[test]
    fn test_deny_audit_only_does_not_block() {
        let mut executor = PolicyExecutor::new();
        let policy = make_policy(
            "p1",
            "user1",
            "read",
            PolicyDecision::Deny,
            PolicyEffect::AuditOnly,
            10,
        );
        executor.add_policy(policy);
        let ctx = make_ctx("user1", "read", "/data");
        let result = executor.evaluate(&ctx);
        assert!(!result.blocked);
    }

    #[test]
    fn test_inactive_policy_does_not_match() {
        let mut executor = PolicyExecutor::new();
        let policy = make_policy(
            "p1",
            "user1",
            "read",
            PolicyDecision::Deny,
            PolicyEffect::Enforce,
            10,
        )
        .with_active(false);
        executor.add_policy(policy);
        let ctx = make_ctx("user1", "read", "/data");
        let result = executor.evaluate(&ctx);
        assert_eq!(result.decision, PolicyDecision::DenyDefault);
    }

    #[test]
    fn test_condition_filtering() {
        let mut executor = PolicyExecutor::new();
        let policy = Policy::new("p1", "trust-policy")
            .with_entity_pattern(MatchPattern::new("*", false).unwrap())
            .with_action_pattern(MatchPattern::new("*", false).unwrap())
            .with_decision(PolicyDecision::Allow)
            .with_effect(PolicyEffect::Enforce)
            .with_priority(10)
            .with_condition(ConditionNode::Leaf(FieldCondition {
                field: "trust.level".to_string(),
                op: ComparisonOp::Gte,
                value: serde_json::json!(0.8),
            }));
        executor.add_policy(policy);

        // High trust — should match and allow.
        let ctx_high = EvaluationContext::new("svc", "call", "/api").with_f64("trust.level", 0.9);
        let result_high = executor.evaluate(&ctx_high);
        assert_eq!(result_high.decision, PolicyDecision::Allow);

        // Low trust — should not match, fall to default.
        let ctx_low = EvaluationContext::new("svc", "call", "/api").with_f64("trust.level", 0.3);
        let result_low = executor.evaluate(&ctx_low);
        assert_eq!(result_low.decision, PolicyDecision::DenyDefault);
    }

    #[test]
    fn test_apply_effects_enforce_deny() {
        let result = EvaluationResult {
            decision: PolicyDecision::Deny,
            effects: vec![EffectRecord {
                policy_id: "p1".to_string(),
                effect: PolicyEffect::Enforce,
                decision: PolicyDecision::Deny,
                policy_priority: 10,
            }],
            matching_policy_ids: vec!["p1".to_string()],
            blocked: true,
            conflicts: vec![],
            latency_us: 42,
            cache_hit: false,
        };
        let outcome = apply_effects(&result);
        assert!(!outcome.allowed);
        assert_eq!(outcome.applied_effects.len(), 1);
    }

    #[test]
    fn test_apply_effects_advisory_and_audit() {
        let result = EvaluationResult {
            decision: PolicyDecision::Allow,
            effects: vec![
                EffectRecord {
                    policy_id: "p1".to_string(),
                    effect: PolicyEffect::Advisory,
                    decision: PolicyDecision::Allow,
                    policy_priority: 10,
                },
                EffectRecord {
                    policy_id: "p2".to_string(),
                    effect: PolicyEffect::AuditOnly,
                    decision: PolicyDecision::Allow,
                    policy_priority: 5,
                },
            ],
            matching_policy_ids: vec!["p1".to_string(), "p2".to_string()],
            blocked: false,
            conflicts: vec![],
            latency_us: 10,
            cache_hit: false,
        };
        let outcome = apply_effects(&result);
        assert!(outcome.allowed);
        assert_eq!(outcome.advisory_messages.len(), 1);
        assert_eq!(outcome.audit_messages.len(), 1);
    }

    #[test]
    fn test_audit_trail_records_evaluations() {
        let mut executor = PolicyExecutor::new();
        executor.add_policy(make_policy(
            "p1",
            "u1",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            10,
        ));
        let ctx = make_ctx("u1", "read", "/data");
        executor.evaluate(&ctx);
        assert_eq!(executor.audit_trail().len(), 1);

        let records = executor.audit_trail().query_by_entity("u1");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_audit_trail_query_by_decision() {
        let mut executor = PolicyExecutor::new();
        executor.add_policy(make_policy(
            "p1",
            "u1",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            10,
        ));
        executor.add_policy(make_policy(
            "p2",
            "u1",
            "delete",
            PolicyDecision::Deny,
            PolicyEffect::Enforce,
            10,
        ));

        executor.evaluate(&make_ctx("u1", "read", "/data"));
        executor.evaluate(&make_ctx("u1", "delete", "/data"));

        let denies = executor
            .audit_trail()
            .query_by_decision(PolicyDecision::Deny);
        assert_eq!(denies.len(), 1);
    }

    #[test]
    fn test_audit_trail_retention() {
        let mut trail = AuditTrail::with_retention(3, Duration::hours(24));
        for i in 0..5 {
            trail.record(AuditRecord {
                audit_id: format!("audit-{}", i),
                entity: format!("u{}", i),
                action: "read".to_string(),
                resource: "/data".to_string(),
                matching_policy_ids: vec![],
                decision: PolicyDecision::Allow,
                effects: vec![],
                latency_us: 10,
                cache_hit: false,
                timestamp: Utc::now(),
                metadata: HashMap::new(),
            });
        }
        // Should have evicted down to 3.
        assert_eq!(trail.len(), 3);
    }

    #[test]
    fn test_policy_versioning_basics() {
        let mut vm = PolicyVersionManager::new("p1");
        let v1 = PolicyVersion::new(1, 0, 0);
        let p1 = Policy::new("p1", "policy-v1").with_version(v1.clone());
        vm.add_version(PolicyVersionRecord::new(p1, "initial"));

        let v2 = PolicyVersion::new(1, 1, 0);
        let p2 = Policy::new("p1", "policy-v2")
            .with_version(v2.clone())
            .with_description("updated policy");
        vm.add_version(PolicyVersionRecord::new(p2, "added description"));

        assert_eq!(vm.all_versions().len(), 2);
        assert!(vm.promote_to_full(&v1));
        assert!(vm.active_policy().is_some());
        assert_eq!(vm.active_policy().unwrap().version, v1);
    }

    #[test]
    fn test_policy_versioning_canary_rollout() {
        let mut vm = PolicyVersionManager::new("p1");
        let v1 = PolicyVersion::new(1, 0, 0);
        let p1 = Policy::new("p1", "v1").with_version(v1.clone());
        vm.add_version(PolicyVersionRecord::new(p1, "initial"));
        vm.promote_to_full(&v1);

        let v2 = PolicyVersion::new(2, 0, 0);
        let p2 = Policy::new("p1", "v2").with_version(v2.clone());
        vm.add_version(PolicyVersionRecord::new(p2, "major rewrite"));

        assert!(vm.promote_to_canary(&v2, 0.1));
        assert!(vm.is_canary(&v2));
        assert!((vm.canary_percentage(&v2) - 0.1).abs() < f64::EPSILON);

        // v1 should still be the active full version.
        assert_eq!(vm.active_policy().unwrap().version, v1);
    }

    #[test]
    fn test_policy_versioning_rollback() {
        let mut vm = PolicyVersionManager::new("p1");
        let v1 = PolicyVersion::new(1, 0, 0);
        let p1 = Policy::new("p1", "v1").with_version(v1.clone());
        vm.add_version(PolicyVersionRecord::new(p1, "initial"));
        vm.promote_to_full(&v1);

        let v2 = PolicyVersion::new(2, 0, 0);
        let p2 = Policy::new("p1", "v2").with_version(v2.clone());
        vm.add_version(PolicyVersionRecord::new(p2, "v2"));
        vm.promote_to_full(&v2);

        // Now v2 is active. Roll back to v1.
        assert!(vm.rollback(&v1));
        assert_eq!(vm.active_policy().unwrap().version, v1);
    }

    #[test]
    fn test_policy_diffing() {
        let p1 = Policy::new("p1", "old-policy")
            .with_decision(PolicyDecision::Allow)
            .with_effect(PolicyEffect::Enforce)
            .with_priority(5);
        let p2 = Policy::new("p1", "new-policy")
            .with_decision(PolicyDecision::Deny)
            .with_effect(PolicyEffect::Advisory)
            .with_priority(10);
        let diffs = diff_policies(&p1, &p2);
        assert!(diffs.iter().any(|d| d.contains("name:")));
        assert!(diffs.iter().any(|d| d.contains("decision:")));
        assert!(diffs.iter().any(|d| d.contains("effect:")));
        assert!(diffs.iter().any(|d| d.contains("priority:")));
    }

    #[test]
    fn test_policy_version_parse() {
        assert_eq!(
            PolicyVersion::parse("1.2.3"),
            Some(PolicyVersion::new(1, 2, 3))
        );
        assert_eq!(PolicyVersion::parse("1.2"), None);
        assert_eq!(PolicyVersion::parse("a.b.c"), None);
    }

    #[test]
    fn test_policy_version_bumps() {
        let v = PolicyVersion::new(1, 2, 3);
        assert_eq!(v.bump_major(), PolicyVersion::new(2, 0, 0));
        assert_eq!(v.bump_minor(), PolicyVersion::new(1, 3, 0));
        assert_eq!(v.bump_patch(), PolicyVersion::new(1, 2, 4));
    }

    #[test]
    fn test_policy_version_ordering() {
        let v1 = PolicyVersion::new(1, 0, 0);
        let v2 = PolicyVersion::new(1, 1, 0);
        let v3 = PolicyVersion::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_executor_stats() {
        let mut executor = PolicyExecutor::new();
        executor.add_policy(make_policy(
            "p1",
            "*",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            1,
        ));
        executor.evaluate(&make_ctx("u1", "read", "/data"));
        let stats = executor.stats();
        assert_eq!(stats.policy_count, 1);
        assert_eq!(stats.cache_size, 1);
        assert_eq!(stats.audit_record_count, 1);
    }

    #[test]
    fn test_executor_cache_hit() {
        let mut executor = PolicyExecutor::with_config(ExecutorConfig {
            cache_ttl_ms: 60_000, // long TTL for test
            ..ExecutorConfig::default()
        });
        executor.add_policy(make_policy(
            "p1",
            "u1",
            "read",
            PolicyDecision::Allow,
            PolicyEffect::Enforce,
            10,
        ));
        let ctx = make_ctx("u1", "read", "/data");

        let r1 = executor.evaluate(&ctx);
        assert!(!r1.cache_hit);

        let r2 = executor.evaluate(&ctx);
        assert!(r2.cache_hit);
    }

    #[test]
    fn test_policy_serialization_roundtrip() {
        let policy = Policy::new("p1", "test-policy")
            .with_decision(PolicyDecision::Deny)
            .with_effect(PolicyEffect::Enforce)
            .with_priority(42)
            .with_tag("security")
            .with_tag("critical");
        let json = serde_json::to_string(&policy).unwrap();
        let restored: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, policy.id);
        assert_eq!(restored.name, policy.name);
        assert_eq!(restored.decision, policy.decision);
        assert_eq!(restored.effect, policy.effect);
        assert_eq!(restored.priority, policy.priority);
        assert_eq!(restored.tags.len(), 2);
    }

    #[test]
    fn test_evaluation_result_serialization() {
        let result = EvaluationResult {
            decision: PolicyDecision::Allow,
            effects: vec![],
            matching_policy_ids: vec!["p1".to_string()],
            blocked: false,
            conflicts: vec![],
            latency_us: 123,
            cache_hit: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: EvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.decision, PolicyDecision::Allow);
        assert!(!restored.blocked);
    }
}
