// Agent Ring — Agent Policy, Behavior & Scope (Ring 4)
//
// Ring 4 of the CHAKRAVYUH 9-ring architecture.
// Defends against excessive agency (OWASP LLM06), privilege escalation (AGT-02),
// agent drift (AGT-03), tool chaining exploits (EXE-05), and inter-agent manipulation (AGT-06).
//
// Engines (Phase 4 scope):
//   1. AgentPolicy          — defines per-agent-type policy
//   2. PermissionEnforcer   — checks action permissions
//   3. AgentScope           — enforces scope boundaries
//   4. CapabilityGuard      — gates capabilities
//   5. BehaviorMonitor       — tracks agent behavior over time
//   6. ToolChainingDetector — detects dangerous tool sequences
//
// Pipeline:
//   AgentPolicy → PermissionEnforcer → AgentScope → CapabilityGuard
//   → BehaviorMonitor → ToolChainingDetector
//
// The Agent Ring outputs a behavior_risk_score (0.0-10.0) for Keshav-Risk.
// Latency Budget: <5ms p99

pub mod agent_policy;
pub mod agent_scope;
pub mod behavior_monitor;
pub mod capability_guard;
pub mod permission_enforcer;
pub mod tool_chaining_detector;

use std::collections::HashMap;
use std::sync::Arc;

use crate::decision::{Decision, Verdict};
use crate::Result;

pub use agent_policy::{AgentPolicy, AgentPolicyConfig, AgentType};
pub use agent_scope::{AgentScope, AgentScopeConfig, AgentScopeType, ScopeVerdict};
pub use behavior_monitor::{BehaviorAnalysis, BehaviorMonitor, BehaviorMonitorConfig};
pub use capability_guard::{Capability, CapabilityGuard, CapabilityGuardConfig};
pub use permission_enforcer::{Permission, PermissionEnforcer, PermissionEnforcerConfig};
pub use tool_chaining_detector::{
    ChainPattern, ChainRisk, ToolChainingDetector, ToolChainingDetectorConfig,
};

/// Agent Ring configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AgentConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub agent_policy: AgentPolicyConfig,

    #[serde(default)]
    pub permission_enforcer: PermissionEnforcerConfig,

    #[serde(default)]
    pub agent_scope: AgentScopeConfig,

    #[serde(default)]
    pub capability_guard: CapabilityGuardConfig,

    #[serde(default)]
    pub behavior_monitor: BehaviorMonitorConfig,

    #[serde(default)]
    pub tool_chaining_detector: ToolChainingDetectorConfig,

    #[serde(default = "default_deny_threshold")]
    pub deny_threshold: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_deny_threshold() -> f64 {
    9.0
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            agent_policy: AgentPolicyConfig::default(),
            permission_enforcer: PermissionEnforcerConfig::default(),
            agent_scope: AgentScopeConfig::default(),
            capability_guard: CapabilityGuardConfig::default(),
            behavior_monitor: BehaviorMonitorConfig::default(),
            tool_chaining_detector: ToolChainingDetectorConfig::default(),
            deny_threshold: default_deny_threshold(),
        }
    }
}

/// A request as seen by the Agent Ring.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub agent_id: String,
    pub agent_type: Option<AgentType>,
    pub action: String,
    pub target: Option<String>,
    pub tools_requested: Vec<String>,
    pub source_ip: String,
    pub user_id: Option<String>,
    pub role: Option<String>,
    pub scope: Option<AgentScopeType>,
    pub request_id: String,
    pub headers: HashMap<String, String>,
}

/// Per-engine result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentEngineResult {
    pub engine_name: String,
    pub decision: String,
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

/// The verdict returned by the Agent Ring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentVerdict {
    pub decision: Decision,
    pub agent_type: Option<AgentType>,
    pub effective_permissions: Vec<Permission>,
    pub scope_verdict: Option<ScopeVerdict>,
    pub behavior_analysis: Option<BehaviorAnalysis>,
    pub chain_risk: Option<ChainRisk>,
    pub engine_results: Vec<AgentEngineResult>,
    pub latency_ms: f64,
    pub behavior_risk_score: f64,
}

impl Verdict for AgentVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }
    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

impl AgentVerdict {
    fn disabled(start: std::time::Instant) -> Self {
        Self {
            decision: Decision::Allow,
            agent_type: None,
            effective_permissions: vec![],
            scope_verdict: None,
            behavior_analysis: None,
            chain_risk: None,
            engine_results: vec![],
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            behavior_risk_score: 0.0,
        }
    }
}

/// The Agent Ring — coordinates 6 engines for agent security.
pub struct AgentRing {
    config: Arc<AgentConfig>,
    agent_policy: Arc<AgentPolicy>,
    permission_enforcer: Arc<PermissionEnforcer>,
    agent_scope: Arc<AgentScope>,
    capability_guard: Arc<CapabilityGuard>,
    behavior_monitor: Arc<BehaviorMonitor>,
    tool_chaining_detector: Arc<ToolChainingDetector>,
}

impl AgentRing {
    pub fn new(config: &AgentConfig) -> Result<Self> {
        Ok(Self {
            agent_policy: Arc::new(AgentPolicy::new(&config.agent_policy)),
            permission_enforcer: Arc::new(PermissionEnforcer::new(&config.permission_enforcer)),
            agent_scope: Arc::new(AgentScope::new(&config.agent_scope)),
            capability_guard: Arc::new(CapabilityGuard::new(&config.capability_guard)),
            behavior_monitor: Arc::new(BehaviorMonitor::new(&config.behavior_monitor)),
            tool_chaining_detector: Arc::new(ToolChainingDetector::new(
                &config.tool_chaining_detector,
            )),
            config: Arc::new(config.clone()),
        })
    }

    pub fn evaluate(&self, request: &AgentRequest) -> AgentVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return AgentVerdict::disabled(start);
        }

        let mut engine_results: Vec<AgentEngineResult> = Vec::with_capacity(6);
        let mut risk_accumulator = 0.0f64;

        // Engine 1: AgentPolicy
        let agent_type = request.agent_type.clone().unwrap_or(AgentType::Assistant);
        let policy_result = self.agent_policy.evaluate(&agent_type, &request.agent_id);
        risk_accumulator += policy_result.risk_score;
        engine_results.push(AgentEngineResult {
            engine_name: "agent_policy".into(), decision: if policy_result.allowed { "allowed" } else { "denied" }.into(),
            reason: policy_result.reason.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "agent_type": format!("{:?}", agent_type), "risk_score": policy_result.risk_score }),
        });
        if !policy_result.allowed {
            let verdict = AgentVerdict {
                decision: Decision::Deny {
                    code: "AGENT_POLICY_DENIED".into(),
                    retry_after: None,
                },
                agent_type: Some(agent_type),
                effective_permissions: vec![],
                scope_verdict: None,
                behavior_analysis: None,
                chain_risk: None,
                engine_results,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                behavior_risk_score: risk_accumulator.clamp(0.0, 10.0),
            };
            return verdict;
        }

        // Engine 2: PermissionEnforcer
        let perm_result = self.permission_enforcer.evaluate(
            &agent_type,
            &request.action,
            &request.tools_requested,
        );
        let effective_permissions = perm_result.effective_permissions.clone();
        if !perm_result.allowed {
            risk_accumulator += 6.0;
        }
        engine_results.push(AgentEngineResult {
            engine_name: "permission_enforcer".into(), decision: if perm_result.allowed { "allowed" } else { "denied" }.into(),
            reason: perm_result.reason.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "permissions": format!("{:?}", perm_result.effective_permissions), "denied_permissions": perm_result.denied_permissions }),
        });

        // Engine 3: AgentScope
        let scope = request.scope.clone().unwrap_or(AgentScopeType::Global);
        let scope_verdict = self
            .agent_scope
            .evaluate(&scope, &request.action, &request.target);
        if scope_verdict.violated {
            risk_accumulator += 5.0;
        }
        engine_results.push(AgentEngineResult {
            engine_name: "agent_scope".into(), decision: if scope_verdict.violated { "violated" } else { "within_scope" }.into(),
            reason: scope_verdict.reason.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "scope": format!("{:?}", scope), "violated": scope_verdict.violated }),
        });

        // Engine 4: CapabilityGuard
        let cap_result = self
            .capability_guard
            .evaluate(&agent_type, &request.tools_requested);
        if !cap_result.allowed {
            risk_accumulator += 4.0;
        }
        engine_results.push(AgentEngineResult {
            engine_name: "capability_guard".into(), decision: if cap_result.allowed { "allowed" } else { "denied" }.into(),
            reason: cap_result.reason.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "granted": format!("{:?}", cap_result.granted), "denied_caps": cap_result.denied_capabilities }),
        });

        // Engine 5: BehaviorMonitor
        let behavior_analysis = self.behavior_monitor.evaluate(
            &request.agent_id,
            &request.action,
            &request.tools_requested,
            &request.source_ip,
        );
        risk_accumulator += behavior_analysis.risk_score;
        engine_results.push(AgentEngineResult {
            engine_name: "behavior_monitor".into(),
            decision: if behavior_analysis.risk_score > 5.0 { "anomalous" } else if behavior_analysis.risk_score > 1.0 { "flagged" } else { "normal" }.into(),
            reason: behavior_analysis.summary.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "action_count": behavior_analysis.action_count, "risk_score": behavior_analysis.risk_score }),
        });

        // Engine 6: ToolChainingDetector
        let chain_risk = self
            .tool_chaining_detector
            .evaluate(&request.tools_requested);
        risk_accumulator += chain_risk.risk_score;
        engine_results.push(AgentEngineResult {
            engine_name: "tool_chaining_detector".into(),
            decision: if chain_risk.risk_score > 5.0 { "dangerous" } else if chain_risk.risk_score > 0.0 { "flagged" } else { "safe" }.into(),
            reason: chain_risk.summary.clone(), latency_ms: 0.0,
            metadata: serde_json::json!({ "chains_detected": chain_risk.chains_detected, "risk_score": chain_risk.risk_score }),
        });

        let behavior_risk_score = risk_accumulator.clamp(0.0, 10.0);

        let decision = if behavior_risk_score >= self.config.deny_threshold {
            Decision::Deny {
                code: "AGENT_BEHAVIOR_SEVERE".into(),
                retry_after: Some(300),
            }
        } else if !perm_result.allowed {
            Decision::Deny {
                code: "AGENT_PERMISSION_DENIED".into(),
                retry_after: None,
            }
        } else if scope_verdict.violated {
            Decision::Deny {
                code: "AGENT_SCOPE_VIOLATION".into(),
                retry_after: None,
            }
        } else if behavior_risk_score > 5.0 {
            Decision::Escalate {
                approver_role: "admin".into(),
                timeout_secs: 300,
            }
        } else {
            Decision::Allow
        };

        AgentVerdict {
            decision,
            agent_type: Some(agent_type),
            effective_permissions,
            scope_verdict: Some(scope_verdict),
            behavior_analysis: Some(behavior_analysis),
            chain_risk: Some(chain_risk),
            engine_results,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            behavior_risk_score,
        }
    }
}

impl Clone for AgentRing {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            agent_policy: Arc::clone(&self.agent_policy),
            permission_enforcer: Arc::clone(&self.permission_enforcer),
            agent_scope: Arc::clone(&self.agent_scope),
            capability_guard: Arc::clone(&self.capability_guard),
            behavior_monitor: Arc::clone(&self.behavior_monitor),
            tool_chaining_detector: Arc::clone(&self.tool_chaining_detector),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ring() -> AgentRing {
        AgentRing::new(&AgentConfig::default()).unwrap()
    }

    fn coder_request(tools: Vec<&str>) -> AgentRequest {
        AgentRequest {
            agent_id: "agent-1".into(),
            agent_type: Some(AgentType::Coder),
            action: "read_file".into(),
            target: Some("/project/src".into()),
            tools_requested: tools.iter().map(|s| s.to_string()).collect(),
            source_ip: "1.2.3.4".into(),
            user_id: Some("user-1".into()),
            role: Some("user".into()),
            scope: Some(AgentScopeType::Project("/project".into())),
            request_id: "test-1".into(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn coder_normal_action_allowed() {
        let ring = default_ring();
        let mut req = coder_request(vec!["file_read", "code_execution"]);
        req.agent_id = "test-coder-normal".into();
        let v = ring.evaluate(&req);
        assert!(
            v.decision.is_allow(),
            "decision={:?}, behavior_risk={:.1}, engine_results={:?}",
            v.decision,
            v.behavior_risk_score,
            v.engine_results
                .iter()
                .map(|e| (e.engine_name.as_str(), e.decision.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn dangerous_chain_detected() {
        let ring = default_ring();
        let req = coder_request(vec!["file_read", "email_send"]);
        let v = ring.evaluate(&req);
        assert!(v.chain_risk.unwrap().risk_score > 0.0);
    }

    #[test]
    fn assistant_restricted() {
        let ring = default_ring();
        let mut req = coder_request(vec!["shell_access"]);
        req.agent_type = Some(AgentType::Assistant);
        let v = ring.evaluate(&req);
        // Assistant can't use shell_access.
        assert!(v.behavior_risk_score > 0.0);
    }

    #[test]
    fn disabled_allows_all() {
        let ring = AgentRing::new(&AgentConfig {
            enabled: false,
            ..Default::default()
        })
        .unwrap();
        let req = coder_request(vec!["shell_access", "email_send"]);
        let v = ring.evaluate(&req);
        assert!(v.decision.is_allow());
    }

    #[test]
    fn six_engines_evaluated() {
        let ring = default_ring();
        let req = coder_request(vec!["file_read"]);
        let v = ring.evaluate(&req);
        assert_eq!(v.engine_results.len(), 6);
    }

    #[test]
    fn behavior_monitored() {
        let ring = default_ring();
        // First few actions are fine.
        for _i in 0..5 {
            let req = coder_request(vec!["file_read"]);
            ring.evaluate(&req);
        }
        // Many actions should start increasing risk.
        let req = coder_request(vec!["file_read"]);
        for _ in 0..50 {
            ring.evaluate(&req);
        }
        let v = ring.evaluate(&req);
        let analysis = v.behavior_analysis.as_ref().unwrap();
        assert!(analysis.action_count > 50);
    }
}
