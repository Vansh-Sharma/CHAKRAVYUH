// Policy validation module — dry-run validation of YAML policy files without loading them.
//
// Checks performed:
//   - Schema validity (version, name, rules fields present)
//   - Rule field completeness (id, name, condition, action, priority)
//   - Risk threshold bounds in [0.0, 10.0]
//   - Regex pattern compilation
//   - Duplicate rule ID detection
//   - Priority ordering consistency (numeric, non-decreasing is recommended)
//   - Action type validity (allow, deny, escalate, challenge, log)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── Validation issue ──────────────────────────────────────────────────────

/// Severity level of a validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    /// Critical error that prevents the policy from loading.
    Error,
    /// Warning that indicates a potential problem.
    Warning,
    /// Informational note.
    Info,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueSeverity::Error => write!(f, "ERROR"),
            IssueSeverity::Warning => write!(f, "WARNING"),
            IssueSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// A single validation issue found during policy validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Severity of this issue.
    pub severity: IssueSeverity,
    /// Human-readable description of the issue.
    pub message: String,
    /// Location in the policy file (e.g. "file:line" or "rule:rule_id").
    pub location: String,
    /// Optional suggestion for fixing the issue.
    pub suggestion: Option<String>,
}

impl ValidationIssue {
    /// Create a new validation issue.
    pub fn new(severity: IssueSeverity, message: &str, location: &str) -> Self {
        Self {
            severity,
            message: message.to_string(),
            location: location.to_string(),
            suggestion: None,
        }
    }

    /// Create a validation issue with a suggestion.
    pub fn with_suggestion(severity: IssueSeverity, message: &str, location: &str, suggestion: &str) -> Self {
        Self {
            severity,
            message: message.to_string(),
            location: location.to_string(),
            suggestion: Some(suggestion.to_string()),
        }
    }
}

// ── Validation stats ──────────────────────────────────────────────────────

/// Summary statistics from validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStats {
    /// Number of rules found in the policy.
    pub rule_count: usize,
    /// Version string from the policy (or "unknown").
    pub policy_version: String,
}

// ── Validation result ─────────────────────────────────────────────────────

/// Complete result of a policy validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the policy is valid (no errors).
    pub is_valid: bool,
    /// Error-level issues.
    pub errors: Vec<ValidationIssue>,
    /// Warning-level and info-level issues.
    pub warnings: Vec<ValidationIssue>,
    /// Summary statistics.
    pub stats: ValidationStats,
}

impl ValidationResult {
    /// Create an empty valid result.
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: ValidationStats {
                rule_count: 0,
                policy_version: "unknown".into(),
            },
        }
    }
}

// ── Policy validator ──────────────────────────────────────────────────────

/// Validates YAML policy documents.
///
/// Performs a comprehensive set of checks on the policy structure,
/// rules, and configuration without actually loading the policy
/// into the running system.
pub struct PolicyValidator;

// Valid action types in CHAKRAVYUH policies.
const VALID_ACTIONS: &[&str] = &[
    "allow",
    "deny",
    "escalate",
    "challenge",
    "log",
    "monitor",
    "quarantine",
];

// Required top-level fields in a policy document.
const REQUIRED_TOP_FIELDS: &[&str] = &["version", "name", "rules"];

// Required fields per rule.
const REQUIRED_RULE_FIELDS: &[&str] = &["id", "name", "action", "priority"];

impl PolicyValidator {
    /// Validate a YAML policy string.
    ///
    /// Parses the YAML, checks schema, rules, and constraints.
    pub fn validate_yaml(yaml_str: &str) -> ValidationResult {
        let mut issues: Vec<ValidationIssue> = Vec::new();

        // Parse the YAML document.
        let doc: serde_yaml::Value = match serde_yaml::from_str(yaml_str) {
            Ok(v) => v,
            Err(e) => {
                let mut result = ValidationResult::valid();
                result.errors.push(ValidationIssue::new(
                    IssueSeverity::Error,
                    &format!("YAML parse error: {}", e),
                    "document",
                ));
                result.is_valid = false;
                return result;
            }
        };

        // Must be a mapping.
        let mapping = match doc.as_mapping() {
            Some(m) => m,
            None => {
                let mut result = ValidationResult::valid();
                result.errors.push(ValidationIssue::new(
                    IssueSeverity::Error,
                    "policy document must be a YAML mapping",
                    "document",
                ));
                result.is_valid = false;
                return result;
            }
        };

        // Check required top-level fields.
        for &field in REQUIRED_TOP_FIELDS {
            if !mapping.contains_key(&serde_yaml::Value::String(field.to_string())) {
                issues.push(ValidationIssue::with_suggestion(
                    IssueSeverity::Error,
                    &format!("missing required top-level field: {}", field),
                    "document",
                    &format!("add '{}' to the policy document", field),
                ));
            }
        }

        // Extract policy version.
        let policy_version = mapping
            .get(&serde_yaml::Value::String("version".to_string()))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Extract and validate rules.
        let rules = mapping
            .get(&serde_yaml::Value::String("rules".to_string()))
            .and_then(|v| v.as_sequence())
            .cloned()
            .unwrap_or_default();

        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut last_priority: Option<i64> = None;

        for (idx, rule_val) in rules.iter().enumerate() {
            let rule_issues = Self::validate_rule(rule_val, idx);
            for issue in rule_issues {
                issues.push(issue);
            }

            // Check for duplicate rule IDs.
            let rule_id = rule_val
                .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<missing>")
                        .to_string();
            if !seen_ids.insert(rule_id.clone()) {
                issues.push(ValidationIssue::with_suggestion(
                    IssueSeverity::Error,
                    &format!("duplicate rule ID: {}", rule_id),
                    &format!("rules[{}]", idx),
                    "rename the duplicate rule to a unique ID",
                ));
            }

            // Check priority ordering consistency.
            let priority = rule_val
                .get("priority")
                        .and_then(|v| v.as_i64());
            if let Some(p) = priority {
                if let Some(prev) = last_priority {
                    if p < prev {
                        issues.push(ValidationIssue::new(
                            IssueSeverity::Warning,
                            &format!(
                                "priority ordering: rule '{}' has priority {} but previous rule had {}",
                                rule_id, p, prev
                            ),
                            &format!("rules[{}]", idx),
                        ));
                    }
                }
                last_priority = Some(p);
            }
        }

        // Separate errors from warnings.
        let mut errors: Vec<ValidationIssue> = Vec::new();
        let mut warnings: Vec<ValidationIssue> = Vec::new();
        for issue in issues {
            match issue.severity {
                IssueSeverity::Error => errors.push(issue),
                _ => warnings.push(issue),
            }
        }

        let is_valid = errors.is_empty();

        ValidationResult {
            is_valid,
            errors,
            warnings,
            stats: ValidationStats {
                rule_count: rules.len(),
                policy_version,
            },
        }
    }

    /// Validate a single rule within the policy.
    pub fn validate_rule(rule: &serde_yaml::Value, index: usize) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let location = format!("rules[{}]", index);

        let mapping = match rule.as_mapping() {
            Some(m) => m,
            None => {
                issues.push(ValidationIssue::new(
                    IssueSeverity::Error,
                    "rule must be a YAML mapping",
                    &location,
                ));
                return issues;
            }
        };

        // Check required fields.
        for &field in REQUIRED_RULE_FIELDS {
            if !mapping.contains_key(&serde_yaml::Value::String(field.to_string())) {
                issues.push(ValidationIssue::with_suggestion(
                    IssueSeverity::Error,
                    &format!("rule missing required field: {}", field),
                    &location,
                    &format!("add '{}' to this rule", field),
                ));
            }
        }

        // Validate action type.
        if let Some(action) = mapping
            .get(&serde_yaml::Value::String("action".to_string()))
            .and_then(|v| v.as_str())
        {
            if !VALID_ACTIONS.contains(&action) {
                issues.push(ValidationIssue::with_suggestion(
                    IssueSeverity::Error,
                    &format!("invalid action type: '{}' (expected one of: {})",
                        action, VALID_ACTIONS.join(", ")),
                    &location,
                    "use one of the valid action types",
                ));
            }
        }

        // Validate risk_threshold if present.
        if let Some(threshold) = mapping
            .get(&serde_yaml::Value::String("risk_threshold".to_string()))
            .and_then(|v| v.as_f64())
        {
            if threshold < 0.0 || threshold > 10.0 {
                issues.push(ValidationIssue::with_suggestion(
                    IssueSeverity::Error,
                    &format!(
                        "risk_threshold {} out of valid range [0.0, 10.0]",
                        threshold
                    ),
                    &location,
                    "set risk_threshold to a value between 0.0 and 10.0",
                ));
            }
        }

        // Validate regex pattern if present.
        if let Some(pattern) = mapping
            .get(&serde_yaml::Value::String("pattern".to_string()))
            .and_then(|v| v.as_str())
        {
            match regex::Regex::new(pattern) {
                Ok(_) => {}
                Err(e) => {
                    issues.push(ValidationIssue::with_suggestion(
                        IssueSeverity::Error,
                        &format!("invalid regex pattern: {}", e),
                        &location,
                        "fix the regex syntax",
                    ));
                }
            }
        }

        // Check for condition field (recommended but not required).
        if !mapping.contains_key(&serde_yaml::Value::String("condition".to_string())) {
            issues.push(ValidationIssue::new(
                IssueSeverity::Warning,
                "rule has no 'condition' field; it may match all requests",
                &location,
            ));
        }

        issues
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy_yaml() -> String {
        r#"
version: "1.0"
name: "test-policy"
rules:
  - id: "rule-001"
    name: "Block SQL injection"
    description: "Blocks requests containing SQL injection patterns"
    condition: "request.body contains 'SELECT'"
    action: deny
    priority: 100
    risk_threshold: 7.5
    pattern: "(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b"
  - id: "rule-002"
    name: "Allow health checks"
    description: "Always allow health check endpoints"
    condition: "request.path == '/health'"
    action: allow
    priority: 50
    risk_threshold: 0.0
"#.to_string()
    }

    #[test]
    fn test_valid_policy_passes() {
        let yaml = valid_policy_yaml();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.stats.rule_count, 2);
        assert_eq!(result.stats.policy_version, "1.0");
    }

    #[test]
    fn test_missing_top_level_fields() {
        let yaml = r#"
name: "incomplete"
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        // Should have errors for missing 'version' and 'rules'.
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn test_invalid_yaml_syntax() {
        let yaml = r#"
version: "1.0"
  bad indentation: [
    unclosed
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].message.contains("YAML parse error"));
    }

    #[test]
    fn test_document_not_mapping() {
        let yaml = r#"just a string, not a mapping"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("mapping")));
    }

    #[test]
    fn test_invalid_regex_pattern() {
        let yaml = r#"
version: "1.0"
name: "bad-regex"
rules:
  - id: "rule-bad-regex"
    name: "Bad regex rule"
    condition: "always"
    action: deny
    priority: 100
    pattern: "[invalid("
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("regex")));
    }

    #[test]
    fn test_duplicate_rule_ids() {
        let yaml = r#"
version: "1.0"
name: "dup-ids"
rules:
  - id: "rule-001"
    name: "First rule"
    condition: "always"
    action: allow
    priority: 10
  - id: "rule-001"
    name: "Second rule with same ID"
    condition: "always"
    action: deny
    priority: 20
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn test_out_of_range_risk_threshold() {
        let yaml = r#"
version: "1.0"
name: "bad-threshold"
rules:
  - id: "rule-high-threshold"
    name: "High threshold rule"
    condition: "always"
    action: deny
    priority: 100
    risk_threshold: 15.0
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("range")));
    }

    #[test]
    fn test_negative_risk_threshold() {
        let yaml = r#"
version: "1.0"
name: "negative-threshold"
rules:
  - id: "rule-neg"
    name: "Negative threshold"
    condition: "always"
    action: deny
    priority: 100
    risk_threshold: -1.0
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("range")));
    }

    #[test]
    fn test_invalid_action_type() {
        let yaml = r#"
version: "1.0"
name: "bad-action"
rules:
  - id: "rule-bad-action"
    name: "Bad action"
    condition: "always"
    action: explode
    priority: 100
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("invalid action")));
    }

    #[test]
    fn test_missing_rule_fields() {
        let yaml = r#"
version: "1.0"
name: "incomplete-rules"
rules:
  - id: "rule-incomplete"
    name: "Missing action and priority"
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.message.contains("action")));
        assert!(result.errors.iter().any(|e| e.message.contains("priority")));
    }

    #[test]
    fn test_empty_rules_list() {
        let yaml = r#"
version: "1.0"
name: "empty-rules"
rules: []
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(result.is_valid);
        assert_eq!(result.stats.rule_count, 0);
    }

    #[test]
    fn test_priority_ordering_warning() {
        let yaml = r#"
version: "1.0"
name: "unordered-priority"
rules:
  - id: "rule-high"
    name: "High priority"
    condition: "always"
    action: deny
    priority: 200
  - id: "rule-low"
    name: "Low priority"
    condition: "always"
    action: allow
    priority: 50
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        // Should be valid (just a warning).
        assert!(result.is_valid);
        assert!(result.warnings.iter().any(|w| w.message.contains("priority")));
    }

    #[test]
    fn test_multiple_issues_in_single_rule() {
        let yaml = r#"
version: "1.0"
name: "multi-issues"
rules:
  - id: "rule-multi"
    name: "Multiple issues"
    action: invalid_action
    priority: 100
    risk_threshold: 99.0
    pattern: "[broken(" 
"#.to_string();
        let result = PolicyValidator::validate_yaml(&yaml);
        assert!(!result.is_valid);
        // Invalid action, out-of-range threshold, bad regex = at least 3 errors.
        assert!(result.errors.len() >= 3);
    }

    #[test]
    fn test_validation_issue_with_suggestion() {
        let issue = ValidationIssue::with_suggestion(
            IssueSeverity::Error,
            "test message",
            "rules[0]",
            "fix it this way",
        );
        assert_eq!(issue.suggestion.as_deref(), Some("fix it this way"));
    }

    #[test]
    fn test_validation_result_serialization() {
        let yaml = valid_policy_yaml();
        let result = PolicyValidator::validate_yaml(&yaml);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"is_valid\":true"));
    }

    #[test]
    fn test_validate_single_rule() {
        let rule_yaml = serde_yaml::from_str(r#"
    id: "rule-100"
    name: "Test rule"
    condition: "request.path == '/test'"
    action: allow
    priority: 10
    "#).unwrap();
        let issues = PolicyValidator::validate_rule(&rule_yaml, 0);
        assert!(issues.is_empty());
    }
}
