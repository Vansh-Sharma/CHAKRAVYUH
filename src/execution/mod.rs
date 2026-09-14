// Execution Ring — Tool/API Call Firewall
//
// Ring 6 of the CHAKRAVYUH 9-ring architecture.
// Controls tool/API calls made by AI agents.
// Prevents misuse, injection, and excessive impact.
//
// Engines (Phase 3 scope):
//   1. Tool Allowlist        — only pre-approved tools callable
//   2. Parameter Validator   — JSON schema validation
//   3. Sandbox Executor      — sandbox configuration
//   4. Approval Workflow     — human-in-the-loop for high-impact
//   5. Action Logger         — full audit trail (hash-chained)
//   6. SSRF Protector        — block internal network access
//
// Latency Budget: <20ms p99 for full Execution Ring evaluation
// Architecture Principle: Fail Secure (default deny on error)

pub mod action_logger;
pub mod approval_workflow;
pub mod parameter_validator;
pub mod sandbox_executor;
pub mod ssrf_protector;
pub mod tool_allowlist;

use std::sync::Arc;

use crate::{
    decision::{Decision, Verdict},
    Result,
};

pub use action_logger::{ActionLogEntry, ActionLogger, ActionLoggerConfig};
pub use approval_workflow::{ApprovalFallback, ApprovalRequest, ApprovalWorkflow, ApprovalWorkflowConfig};
pub use parameter_validator::{ParameterValidator, ParameterValidatorConfig, ParameterValidatorResult};
pub use sandbox_executor::{SandboxConfig, SandboxExecutor, SandboxExecutorConfig, SandboxMode};
pub use ssrf_protector::{SsrfProtector, SsrfProtectorConfig, SsrfProtectorResult};
pub use tool_allowlist::{ToolAllowlist, ToolAllowlistConfig, ToolEntry};

/// Execution Ring configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub tool_allowlist: ToolAllowlistConfig,

    #[serde(default)]
    pub parameter_validator: ParameterValidatorConfig,

    #[serde(default)]
    pub sandbox_executor: SandboxExecutorConfig,

    #[serde(default)]
    pub approval_workflow: ApprovalWorkflowConfig,

    #[serde(default)]
    pub action_logger: ActionLoggerConfig,

    #[serde(default)]
    pub ssrf_protector: SsrfProtectorConfig,
}

fn default_enabled() -> bool {
    true
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            tool_allowlist: ToolAllowlistConfig::default(),
            parameter_validator: ParameterValidatorConfig::default(),
            sandbox_executor: SandboxExecutorConfig::default(),
            approval_workflow: ApprovalWorkflowConfig::default(),
            action_logger: ActionLoggerConfig::default(),
            ssrf_protector: SsrfProtectorConfig::default(),
        }
    }
}

/// A tool call request from an AI agent.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub request_id: String,
    pub source_ip: String,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
}

/// Result of a single engine evaluation within the Execution Ring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecutionEngineResult {
    pub engine_name: String,
    pub decision: Decision,
    pub reason: String,
    pub latency_ms: f64,
}

/// The overall Execution Ring verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecutionVerdict {
    pub decision: Decision,
    pub engine_results: Vec<ExecutionEngineResult>,
    pub sandbox_config: Option<sandbox_executor::SandboxConfig>,
    pub approval_request: Option<approval_workflow::ApprovalRequest>,
    pub latency_ms: f64,
}

impl Verdict for ExecutionVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }
    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

impl ExecutionVerdict {
    fn disabled(start: std::time::Instant) -> Self {
        Self {
            decision: Decision::Allow,
            engine_results: vec![],
            sandbox_config: None,
            approval_request: None,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

/// The Execution Ring — coordinates 6 engines for tool call security.
///
/// Engine evaluation order:
///   1. Tool Allowlist   — is the tool on the list?
///   2. Parameter Validator — are the parameters valid?
///   3. SSRF Protector  — does the target access internal networks?
///   4. Sandbox Executor — what sandbox is needed?
///   5. Approval Workflow — does it need human approval?
///   6. Action Logger    — record the call (always runs, never blocks)
///
/// Most restrictive decision wins (deny > approval_required > allow).
#[derive(Clone)]
pub struct ExecutionRing {
    config: Arc<ExecutionConfig>,
    tool_allowlist: Arc<ToolAllowlist>,
    parameter_validator: Arc<ParameterValidator>,
    sandbox_executor: Arc<SandboxExecutor>,
    approval_workflow: Arc<ApprovalWorkflow>,
    action_logger: Arc<ActionLogger>,
    ssrf_protector: Arc<SsrfProtector>,
}

impl ExecutionRing {
    /// Create a new Execution Ring with the given configuration.
    pub fn new(config: &ExecutionConfig) -> Result<Self> {
        Ok(Self {
            tool_allowlist: Arc::new(ToolAllowlist::new(&config.tool_allowlist)?),
            parameter_validator: Arc::new(ParameterValidator::new(&config.parameter_validator)?),
            sandbox_executor: Arc::new(SandboxExecutor::new(&config.sandbox_executor)?),
            approval_workflow: Arc::new(ApprovalWorkflow::new(&config.approval_workflow)?),
            action_logger: Arc::new(ActionLogger::new(&config.action_logger)?),
            ssrf_protector: Arc::new(SsrfProtector::new(&config.ssrf_protector)?),
            config: Arc::new(config.clone()),
        })
    }

    /// Evaluate a tool call through all Execution engines.
    ///
    /// Returns the most restrictive verdict. The Action Logger always runs
    /// (never blocks). If the tool needs approval, the decision is Escalate.
    pub fn evaluate(&self, call: &ToolCall) -> ExecutionVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ExecutionVerdict::disabled(start);
        }

        let mut engine_results: Vec<ExecutionEngineResult> = Vec::with_capacity(6);
        let mut final_decision = Decision::Allow;
        let sandbox_config: Option<sandbox_executor::SandboxConfig>;
        let mut approval_request = None;

        // Engine 1: Tool Allowlist
        let allow_result = self.tool_allowlist.evaluate(&call.tool_name, &call.request_id);
        engine_results.push(ExecutionEngineResult {
            engine_name: "tool_allowlist".into(),
            decision: allow_result.decision.clone(),
            reason: allow_result.reason.clone(),
            latency_ms: allow_result.latency_ms,
        });
        if allow_result.decision.is_deny() {
            final_decision = allow_result.decision;
            // Early exit — tool not allowed, no point checking further.
            let verdict = ExecutionVerdict {
                decision: final_decision,
                engine_results,
                sandbox_config: None,
                approval_request: None,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
            // Always log, even on deny.
            self.log_action(call, &verdict);
            return verdict;
        }

        // Engine 2: Parameter Validator
        let param_result = self.parameter_validator.evaluate(&call.tool_name, &call.parameters);
        engine_results.push(ExecutionEngineResult {
            engine_name: "parameter_validator".into(),
            decision: param_result.decision.clone(),
            reason: param_result.reason.clone(),
            latency_ms: param_result.latency_ms,
        });
        if param_result.decision.is_deny() {
            final_decision = param_result.decision;
            let verdict = ExecutionVerdict {
                decision: final_decision,
                engine_results,
                sandbox_config: None,
                approval_request: None,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
            self.log_action(call, &verdict);
            return verdict;
        }

        // Engine 3: SSRF Protector — check if parameters contain URLs/IPs
        let ssrf_targets = extract_targets_from_params(&call.parameters);
        for target in &ssrf_targets {
            let ssrf_result = self.ssrf_protector.evaluate(target);
            if ssrf_result.decision.is_deny() {
                engine_results.push(ExecutionEngineResult {
                    engine_name: "ssrf_protector".into(),
                    decision: ssrf_result.decision.clone(),
                    reason: ssrf_result.reason.clone(),
                    latency_ms: ssrf_result.latency_ms,
                });
                final_decision = ssrf_result.decision;
                let verdict = ExecutionVerdict {
                    decision: final_decision,
                    engine_results,
                    sandbox_config: None,
                    approval_request: None,
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
                self.log_action(call, &verdict);
                return verdict;
            }
        }
        // If no targets to check, record a pass.
        if ssrf_targets.is_empty() {
            engine_results.push(ExecutionEngineResult {
                engine_name: "ssrf_protector".into(),
                decision: Decision::Allow,
                reason: "no URL/IP targets found in parameters".into(),
                latency_ms: 0.0,
            });
        }

        // Engine 4: Sandbox Executor (config only, doesn't block)
        let sandbox_result = self.sandbox_executor.evaluate(&call.tool_name);
        sandbox_config = Some(sandbox_result.sandbox_config.clone());
        engine_results.push(ExecutionEngineResult {
            engine_name: "sandbox_executor".into(),
            decision: Decision::Allow, // Sandbox config doesn't block.
            reason: format!("sandbox mode: {:?}", sandbox_result.sandbox_config.mode),
            latency_ms: sandbox_result.latency_ms,
        });

        // Engine 5: Approval Workflow (config only, doesn't block — escalation)
        let approval_result = self.approval_workflow.evaluate(
            &call.tool_name,
            &call.request_id,
            &call.parameters,
        );
        if let Some(req) = &approval_result.approval_required {
            approval_request = Some(req.clone());
            final_decision = Decision::Escalate {
                approver_role: req.required_approver_role.clone(),
                timeout_secs: req.timeout_secs,
            };
        }
        engine_results.push(ExecutionEngineResult {
            engine_name: "approval_workflow".into(),
            decision: if approval_request.is_some() {
                Decision::Escalate {
                    approver_role: approval_request
                        .as_ref()
                        .map(|r| r.required_approver_role.clone())
                        .unwrap_or_else(|| "admin".into()),
                    timeout_secs: approval_request
                        .as_ref()
                        .map(|r| r.timeout_secs)
                        .unwrap_or(300),
                }
            } else {
                Decision::Allow
            },
            reason: approval_result.reason.clone(),
            latency_ms: approval_result.latency_ms,
        });

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let verdict = ExecutionVerdict {
            decision: final_decision,
            engine_results,
            sandbox_config,
            approval_request,
            latency_ms,
        };

        // Engine 6: Action Logger (always runs, never blocks)
        self.log_action(call, &verdict);

        verdict
    }

    fn log_action(&self, call: &ToolCall, verdict: &ExecutionVerdict) {
        let decision_str = match &verdict.decision {
            Decision::Allow => "allowed",
            Decision::Deny { .. } => "blocked",
            Decision::Challenge { .. } => "challenged",
            Decision::Escalate { .. } => "approval_required",
        };
        self.action_logger.log(
            &call.request_id,
            &call.tool_name,
            &call.parameters,
            decision_str,
            &call.source_ip,
            verdict.latency_ms,
        );
    }

    /// Get a reference to the action logger.
    pub fn action_logger(&self) -> &ActionLogger {
        &self.action_logger
    }
}

/// Extract potential URL/IP targets from tool call parameters.
fn extract_targets_from_params(params: &serde_json::Value) -> Vec<String> {
    let mut targets = vec![];

    // Recursively search for string values that look like URLs or IPs.
    fn search(value: &serde_json::Value, targets: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => {
                if s.starts_with("http://")
                    || s.starts_with("https://")
                    || s.starts_with("ftp://")
                    || s.contains("://")
                {
                    targets.push(s.clone());
                }
                // Check for bare IP addresses (simple heuristic).
                if s.parse::<std::net::IpAddr>().is_ok() {
                    targets.push(s.clone());
                }
            }
            serde_json::Value::Object(map) => {
                for (_, v) in map {
                    search(v, targets);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    search(v, targets);
                }
            }
            _ => {}
        }
    }

    search(params, &mut targets);
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ring() -> ExecutionRing {
        ExecutionRing::new(&ExecutionConfig::default()).unwrap()
    }

    fn make_call(tool: &str, params: serde_json::Value) -> ToolCall {
        ToolCall {
            tool_name: tool.into(),
            parameters: params,
            request_id: "test-req-1".into(),
            source_ip: "1.2.3.4".into(),
            agent_id: None,
            user_id: None,
        }
    }

    #[test]
    fn allow_known_tool_valid_params() {
        let ring = default_ring();
        let call = make_call("web_search", serde_json::json!({"query": "rust"}));
        let verdict = ring.evaluate(&call);
        assert!(verdict.decision.is_allow());
    }

    #[test]
    fn deny_unknown_tool() {
        let ring = default_ring();
        let call = make_call("rm_rf", serde_json::json!({}));
        let verdict = ring.evaluate(&call);
        assert!(verdict.decision.is_deny());
    }

    #[test]
    fn deny_invalid_params() {
        let ring = default_ring();
        // web_search requires "query" field.
        let call = make_call("web_search", serde_json::json!({"wrong_field": "test"}));
        let verdict = ring.evaluate(&call);
        assert!(verdict.decision.is_deny());
    }

    #[test]
    fn deny_ssrf_in_params() {
        let ring = default_ring();
        let call = make_call("web_search", serde_json::json!({
            "query": "test",
            "url": "http://169.254.169.254/latest/meta-data/"
        }));
        let verdict = ring.evaluate(&call);
        assert!(verdict.decision.is_deny());
        assert!(verdict.engine_results.iter().any(|r| r.engine_name == "ssrf_protector" && r.decision.is_deny()));
    }

    #[test]
    fn sandbox_config_produced() {
        let ring = default_ring();
        let call = make_call("calculator", serde_json::json!({"expression": "2+2"}));
        let verdict = ring.evaluate(&call);
        assert!(verdict.sandbox_config.is_some());
    }

    #[test]
    fn disabled_ring_allows_everything() {
        let config = ExecutionConfig {
            enabled: false,
            ..Default::default()
        };
        let ring = ExecutionRing::new(&config).unwrap();
        let call = make_call("anything", serde_json::json!({}));
        let verdict = ring.evaluate(&call);
        assert!(verdict.decision.is_allow());
    }

    #[test]
    fn action_logger_records() {
        let ring = default_ring();
        let call = make_call("web_search", serde_json::json!({"query": "test"}));
        ring.evaluate(&call);
        let entries = ring.action_logger().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool_name, "web_search");
    }

    #[test]
    fn enforce_tool_rate_limit() {
        let ring = default_ring();
        for _ in 0..5 {
            let call = make_call("web_search", serde_json::json!({"query": "test"}));
            let v = ring.evaluate(&call);
            assert!(v.decision.is_allow());
        }
        // 6th call should exceed max_calls_per_request (default 5).
        let call = make_call("web_search", serde_json::json!({"query": "test"}));
        let v = ring.evaluate(&call);
        assert!(v.decision.is_deny());
    }
}
