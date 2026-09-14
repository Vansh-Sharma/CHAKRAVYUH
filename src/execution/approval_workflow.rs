// Approval Workflow — Engine 4 of the Execution Ring
//
// Requires human approval for high-impact tool calls.
// In the MVP, this engine produces an ApprovalRequest — it does NOT
// block the request. The host application handles the async workflow.
// The engine marks tools that require approval and provides the config.
//
// Latency Budget: N/A (config generation only, <0.1ms)

use serde::{Deserialize, Serialize};

/// A request that needs human approval before the tool call proceeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub tool_name: String,
    pub request_id: String,
    pub required_approver_role: String,
    pub timeout_secs: u64,
    pub fallback_action: ApprovalFallback,
    pub reason: String,
}

/// What happens when approval times out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalFallback {
    /// Block the tool call if no approval received.
    Deny,
    /// Allow the tool call if no approval received.
    Allow,
}

/// Configuration for the Approval Workflow engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWorkflowConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_timeout")]
    pub default_timeout_secs: u64,
    #[serde(default = "default_fallback")]
    pub default_fallback: ApprovalFallback,
    /// Tools that require approval with specific rules.
    #[serde(default)]
    pub rules: Vec<ApprovalRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub tool_name: String,
    #[serde(default = "default_approver_role")]
    pub required_approver_role: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Specific conditions that trigger approval (e.g., path patterns).
    #[serde(default)]
    pub conditions: ApprovalConditions,
    #[serde(default = "default_fallback")]
    pub fallback: ApprovalFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalConditions {
    /// If set, only triggers approval for these paths (glob patterns).
    #[serde(default)]
    pub paths: Vec<String>,
    /// If set, only triggers for these methods.
    #[serde(default)]
    pub methods: Vec<String>,
    /// If set, only triggers when impact is high.
    #[serde(default)]
    pub impact_levels: Vec<String>,
}

fn default_enabled() -> bool {
    true
}
fn default_timeout() -> u64 {
    300
}
fn default_fallback() -> ApprovalFallback {
    ApprovalFallback::Deny
}
fn default_approver_role() -> String {
    "admin".into()
}

impl Default for ApprovalWorkflowConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            default_timeout_secs: default_timeout(),
            default_fallback: default_fallback(),
            rules: vec![
                ApprovalRule {
                    tool_name: "file_write".into(),
                    required_approver_role: "admin".into(),
                    timeout_secs: Some(300),
                    fallback: ApprovalFallback::Deny,
                    conditions: ApprovalConditions {
                        paths: vec!["/production/**".into(), "/etc/**".into()],
                        methods: vec![],
                        impact_levels: vec!["high".into()],
                    },
                },
                ApprovalRule {
                    tool_name: "api_call".into(),
                    required_approver_role: "admin".into(),
                    timeout_secs: Some(120),
                    fallback: ApprovalFallback::Deny,
                    conditions: ApprovalConditions {
                        paths: vec![],
                        methods: vec!["DELETE".into(), "PUT".into()],
                        impact_levels: vec!["high".into()],
                    },
                },
                ApprovalRule {
                    tool_name: "email_send".into(),
                    required_approver_role: "admin".into(),
                    timeout_secs: Some(60),
                    fallback: ApprovalFallback::Deny,
                    conditions: ApprovalConditions {
                        paths: vec!["external".into()],
                        methods: vec![],
                        impact_levels: vec![],
                    },
                },
            ],
        }
    }
}

/// Result of an approval workflow check.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalWorkflowResult {
    /// None means no approval needed. Some means approval is required.
    pub approval_required: Option<ApprovalRequest>,
    pub reason: String,
    pub tool_name: String,
    pub latency_ms: f64,
}

/// The Approval Workflow engine.
///
/// Checks if a tool call requires human approval based on configured rules.
#[derive(Clone)]
pub struct ApprovalWorkflow {
    config: ApprovalWorkflowConfig,
}

impl ApprovalWorkflow {
    pub fn new(config: &ApprovalWorkflowConfig) -> crate::Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Check if a tool call requires approval.
    ///
    /// Returns Some(ApprovalRequest) if approval is needed, None otherwise.
    pub fn evaluate(
        &self,
        tool_name: &str,
        request_id: &str,
        params: &serde_json::Value,
    ) -> ApprovalWorkflowResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ApprovalWorkflowResult {
                approval_required: None,
                reason: "approval_workflow engine disabled".into(),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Find matching rules for this tool.
        let matching_rules: Vec<&ApprovalRule> = self
            .config
            .rules
            .iter()
            .filter(|r| r.tool_name == tool_name)
            .collect();

        for rule in matching_rules {
            // Check conditions.
            if let Some(path_val) = params.get("path").and_then(|v| v.as_str()) {
                if !rule.conditions.paths.is_empty() {
                    let matches = rule
                        .conditions
                        .paths
                        .iter()
                        .any(|pattern| glob_match(pattern, path_val));
                    if !matches {
                        continue;
                    }
                }
            }

            if let Some(method_val) = params.get("method").and_then(|v| v.as_str()) {
                if !rule.conditions.methods.is_empty() {
                    if !rule.conditions.methods.contains(&method_val.to_string()) {
                        continue;
                    }
                }
            }

            // Rule matches — approval required.
            let timeout = rule
                .timeout_secs
                .unwrap_or(self.config.default_timeout_secs);

            return ApprovalWorkflowResult {
                approval_required: Some(ApprovalRequest {
                    tool_name: tool_name.into(),
                    request_id: request_id.into(),
                    required_approver_role: rule.required_approver_role.clone(),
                    timeout_secs: timeout,
                    fallback_action: rule.fallback.clone(),
                    reason: format!(
                        "tool '{}' requires approval from '{}' (timeout: {}s)",
                        tool_name, rule.required_approver_role, timeout
                    ),
                }),
                reason: format!(
                    "tool '{}' matched approval rule requiring '{}' approval",
                    tool_name, rule.required_approver_role
                ),
                tool_name: tool_name.into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        ApprovalWorkflowResult {
            approval_required: None,
            reason: format!("no approval rules matched for tool '{}'", tool_name),
            tool_name: tool_name.into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

/// Simple glob matching (supports * and ** patterns).
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern.contains("**") {
        // "**" matches zero or more path segments.
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_matches('/');
            let suffix = parts[1].trim_matches('/');
            let val = value.trim_matches('/');
            if prefix.is_empty() && suffix.is_empty() {
                return true;
            }
            if !prefix.is_empty() && !val.starts_with(prefix) {
                return false;
            }
            if !suffix.is_empty() && !val.ends_with(suffix) {
                return false;
            }
            return true;
        }
        false
    } else if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            value.starts_with(parts[0]) && value.ends_with(parts[1])
        } else {
            false
        }
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_approval_for_unconfigured_tool() {
        let engine = ApprovalWorkflow::new(&ApprovalWorkflowConfig::default()).unwrap();
        let result = engine.evaluate("calculator", "req-1", &serde_json::json!({}));
        assert!(result.approval_required.is_none());
    }

    #[test]
    fn approval_for_production_file_write() {
        let engine = ApprovalWorkflow::new(&ApprovalWorkflowConfig::default()).unwrap();
        let params = serde_json::json!({"path": "/production/data/config.yaml"});
        let result = engine.evaluate("file_write", "req-2", &params);
        assert!(result.approval_required.is_some());
        let req = result.approval_required.unwrap();
        assert_eq!(req.required_approver_role, "admin");
    }

    #[test]
    fn no_approval_for_non_production_path() {
        let engine = ApprovalWorkflow::new(&ApprovalWorkflowConfig::default()).unwrap();
        let params = serde_json::json!({"path": "/tmp/test.txt"});
        let result = engine.evaluate("file_write", "req-3", &params);
        assert!(result.approval_required.is_none());
    }

    #[test]
    fn approval_for_delete_api_call() {
        let engine = ApprovalWorkflow::new(&ApprovalWorkflowConfig::default()).unwrap();
        let params = serde_json::json!({"method": "DELETE"});
        let result = engine.evaluate("api_call", "req-4", &params);
        assert!(result.approval_required.is_some());
    }

    #[test]
    fn glob_match_works() {
        assert!(glob_match("/production/**", "/production/data/config.yaml"));
        assert!(glob_match("/production/**", "/production/foo/bar/baz"));
        assert!(!glob_match("/production/**", "/staging/data/config.yaml"));
        assert!(glob_match("*.txt", "file.txt"));
    }
}
