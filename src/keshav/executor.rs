// PipelineExecutor — Executes OrchestrationPlan across rings.
//
// This module extracts the duplicated pipeline execution logic from api/mod.rs
// into a single, reusable executor. It consumes an OrchestrationPlan and:
//   1. Runs the parallel_batch rings concurrently via tokio::spawn_blocking
//   2. Runs the sequential_batch rings in order, respecting dependency conditions
//   3. Combines all verdicts into a PipelineResult
//
// This solves:
//   Risk 1 (God Module): Removes ~360 lines of duplicated orchestration from api/mod.rs
//   Risk 2 (Sequential Latency): Activates the parallel_batch that was dead code

use crate::agent::AgentRing;
use crate::decision::{Decision, DecisionRecord, RiskScore};
use crate::execution::ExecutionRing;
use crate::governance::GovernanceRing;
use crate::identity::IdentityRing;
use crate::memory::MemoryRing;
use crate::reasoning::ReasoningRing;
use crate::shield::{ShieldRequest, ShieldVerdict, ShieldRing};
use crate::threat::ThreatRing;

use super::orchestrate::{
    DepCondition, OrchestrationPlan, RingId,
};
use super::risk::{ContextSignals, KeshavRisk, RiskSignals};
use super::{KeshavDecide};

/// Context required to build per-ring requests.
/// This is populated from the incoming HTTP request before execution begins.
#[derive(Clone)]
pub struct PipelineContext {
    /// The canonical shield request built from HTTP headers + body.
    pub shield_request: ShieldRequest,
    /// Unique request ID (UUID).
    pub request_id: String,
    /// Prompt text extracted from the request body (for memory ring).
    pub prompt_text: String,
    /// Tool call details (only present for /v1/execute).
    pub tool_call: Option<ToolCallContext>,
}

/// Tool call context for execution ring evaluation.
#[derive(Clone)]
pub struct ToolCallContext {
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub agent_id: Option<String>,
}

/// Result of executing the pipeline — all ring verdicts + final decision.
pub struct PipelineResult {
    pub shield_verdict: ShieldVerdict,
    pub threat_verdict: Option<crate::threat::ThreatVerdict>,
    pub identity_verdict: Option<crate::identity::IdentityVerdict>,
    pub memory_verdict: Option<crate::memory::MemoryVerdict>,
    pub agent_verdict: Option<crate::agent::AgentVerdict>,
    pub execution_verdict: Option<crate::execution::ExecutionVerdict>,
    pub reasoning_verdict: Option<crate::reasoning::ReasoningVerdict>,
    pub governance_verdict: Option<crate::governance::GovernanceVerdict>,
    pub risk_score: RiskScore,
    pub decision_record: DecisionRecord,
}

impl PipelineResult {
    /// Shape the full JSON response including all ring verdicts + risk score.
    /// This was previously ~140 lines duplicated in api/mod.rs.
    pub fn shape_full_response(&self) -> serde_json::Value {
        use crate::decision::Decision::*;

        let decision_str = match &self.decision_record.final_decision {
            Allow => "allow".to_string(),
            Deny { code, .. } => format!("deny:{}", code),
            Challenge { .. } => "challenge".to_string(),
            Escalate { .. } => "escalate".to_string(),
        };

        let mut rings = serde_json::Map::new();

        // Shield Ring.
        rings.insert("shield".into(), serde_json::json!({
            "decision": format!("{:?}", self.shield_verdict.decision),
            "latency_ms": self.shield_verdict.latency_ms,
            "engine_results": self.shield_verdict.engine_results.iter().map(|r| {
                serde_json::json!({
                    "engine": r.engine_name,
                    "decision": format!("{:?}", r.decision),
                    "reason": r.reason,
                    "latency_ms": r.latency_ms,
                })
            }).collect::<Vec<_>>(),
        }));

        // Threat Ring.
        if let Some(threat_v) = &self.threat_verdict {
            rings.insert("threat".into(), serde_json::json!({
                "decision": format!("{:?}", threat_v.decision),
                "composite_score": threat_v.composite_score,
                "confidence": threat_v.confidence,
                "latency_ms": threat_v.latency_ms,
                "engine_results": threat_v.engine_results.iter().map(|r| {
                    serde_json::json!({
                        "engine": r.engine_name,
                        "score": r.score,
                        "confidence": r.confidence,
                        "signals": r.signals,
                        "reason": r.reason,
                        "latency_ms": r.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            }));
        }

        // Identity Ring.
        if let Some(id_v) = &self.identity_verdict {
            rings.insert("identity".into(), serde_json::json!({
                "decision": format!("{:?}", id_v.decision),
                "identity_risk_score": id_v.identity_risk_score,
                "latency_ms": id_v.latency_ms,
                "role": id_v.role.as_ref().map(|r| format!("{:?}", r)),
                "identity_type": id_v.identity_profile.as_ref().map(|p| format!("{:?}", p.identity_type)),
                "trust_score": id_v.trust_result.as_ref().map(|t| t.trust_score),
                "anomaly_score": id_v.anomaly_result.as_ref().map(|a| a.composite_score),
                "engine_results": id_v.engine_results.iter().map(|r| {
                    serde_json::json!({
                        "engine": r.engine_name,
                        "decision": r.decision,
                        "reason": r.reason,
                        "latency_ms": r.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            }));
        }

        // Memory Ring.
        if let Some(mem_v) = &self.memory_verdict {
            rings.insert("memory".into(), serde_json::json!({
                "decision": format!("{:?}", mem_v.decision),
                "memory_risk_score": mem_v.memory_risk_score,
                "latency_ms": mem_v.latency_ms,
                "pii_findings": mem_v.pii_findings.as_ref().map(|f| f.len()),
                "hijack_detected": mem_v.conversation_state.as_ref().map(|c| c.hijack_detected),
                "rag_verdict": mem_v.rag_verdict.as_ref().map(|r| r.risk_score),
                "access_denied": mem_v.access_verdict.as_ref().map(|a| a.denied),
                "engine_results": mem_v.engine_results.iter().map(|r| {
                    serde_json::json!({
                        "engine": r.engine_name,
                        "decision": r.decision,
                        "reason": r.reason,
                        "latency_ms": r.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            }));
        }

        // Agent Ring.
        if let Some(ag_v) = &self.agent_verdict {
            rings.insert("agent".into(), serde_json::json!({
                "decision": format!("{:?}", ag_v.decision),
                "behavior_risk_score": ag_v.behavior_risk_score,
                "latency_ms": ag_v.latency_ms,
                "agent_type": ag_v.agent_type.as_ref().map(|t| format!("{:?}", t)),
                "scope_violated": ag_v.scope_verdict.as_ref().map(|s| s.violated),
                "chain_risk": ag_v.chain_risk.as_ref().map(|c| c.risk_score),
                "engine_results": ag_v.engine_results.iter().map(|r| {
                    serde_json::json!({
                        "engine": r.engine_name,
                        "decision": r.decision,
                        "reason": r.reason,
                        "latency_ms": r.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            }));
        }

        // Execution Ring.
        if let Some(exec_v) = &self.execution_verdict {
            rings.insert("execution".into(), serde_json::json!({
                "decision": format!("{:?}", exec_v.decision),
                "latency_ms": exec_v.latency_ms,
                "sandbox_mode": exec_v.sandbox_config.as_ref().map(|s| format!("{:?}", s.mode)),
                "approval_required": exec_v.approval_request.is_some(),
                "engine_results": exec_v.engine_results.iter().map(|r| {
                    serde_json::json!({
                        "engine": r.engine_name,
                        "decision": format!("{:?}", r.decision),
                        "reason": r.reason,
                        "latency_ms": r.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            }));
        }

        serde_json::json!({
            "decision": decision_str,
            "reason": self.decision_record.reasoning,
            "request_id": self.decision_record.request_id,
            "policy_applied": self.decision_record.policy_applied,
            "latency_ms": self.decision_record.latency_ms,
            "rings": rings,
            "risk_score": self.risk_score,
            "decision_record": self.decision_record,
        })
    }
}

/// The pipeline executor — consumes an OrchestrationPlan and runs rings.
///
/// Hold references to all rings. The executor is cheap to clone (all rings
/// are internally Arc'd or Clone). It is constructed once at startup and
/// shared across all requests.
#[derive(Clone)]
pub struct PipelineExecutor {
    pub shield: ShieldRing,
    pub threat: ThreatRing,
    pub identity: IdentityRing,
    pub memory: MemoryRing,
    pub agent: AgentRing,
    pub execution: ExecutionRing,
    pub reasoning: ReasoningRing,
    pub governance: GovernanceRing,
    pub decide: KeshavDecide,
    pub risk: KeshavRisk,
}

impl PipelineExecutor {
    /// Execute the given orchestration plan with the provided context.
    ///
    /// 1. Shield is always evaluated first (gate ring).
    /// 2. If Shield denies, returns early with shield-only result.
    /// 3. Parallel batch rings are evaluated concurrently via tokio::spawn_blocking.
    /// 4. Sequential batch rings are evaluated in order, respecting conditions.
    /// 5. All verdicts are combined via Keshav-Decide and Keshav-Risk.
    pub async fn execute(
        &self,
        plan: &OrchestrationPlan,
        ctx: &PipelineContext,
    ) -> PipelineResult {
        // ── Phase 1: Shield Ring (always first, always sync) ──
        let shield_verdict = self.shield.evaluate(&ctx.shield_request);

        // If Shield denies, skip all other rings (Fail Secure).
        if !shield_verdict.decision.is_allow() {
            let source_ip = ctx.shield_request.source_ip.clone();
            let record = self.decide.evaluate(
                &shield_verdict,
                None,
                &ctx.request_id,
                &source_ip,
            );
            return PipelineResult {
                shield_verdict,
                threat_verdict: None,
                identity_verdict: None,
                memory_verdict: None,
                agent_verdict: None,
                execution_verdict: None,
                reasoning_verdict: None,
                governance_verdict: None,
                risk_score: RiskScore::default(),
                decision_record: record,
            };
        }

        // ── Phase 2: Parallel batch (concurrent via spawn_blocking) ──
        let shield_req = &ctx.shield_request;
        let request_id = &ctx.request_id;
        let prompt_text = &ctx.prompt_text;

        // Clone ring handles for async tasks.
        let threat = self.threat.clone();
        let identity = self.identity.clone();
        let memory = self.memory.clone();
        let reasoning = self.reasoning.clone();
        let governance = self.governance.clone();

        let shield_for_threat = shield_req.clone();
        let identity_req = crate::api::build_identity_request(shield_req, request_id);
        let memory_req = crate::api::build_memory_request(shield_req, request_id, prompt_text);

        // Build reasoning + governance requests (they need default context).
        let reasoning_req = crate::reasoning::ReasoningRequest {
            reasoning_text: prompt_text.clone(),
            output_text: None,
            task_description: None,
            reasoning_steps: vec![],
            source_ip: shield_req.source_ip.clone(),
            user_id: shield_req.user_id.clone(),
            request_id: request_id.clone(),
            headers: shield_req.headers.clone(),
        };
        let governance_req = crate::governance::GovernanceRequest {
            action: shield_req.method.clone(),
            resource: Some(shield_req.path.clone()),
            data_classification: None,
            consent_token: None,
            frameworks: vec![],
            entity_id: shield_req.user_id.clone(),
            region: None,
            source_ip: shield_req.source_ip.clone(),
            user_id: shield_req.user_id.clone(),
            role: None,
            request_id: request_id.clone(),
            headers: shield_req.headers.clone(),
        };

        // Collect which parallel rings to actually run.
        let run_threat = plan.parallel_batch.contains(&RingId::Threat);
        let run_identity = plan.parallel_batch.contains(&RingId::Identity);
        let run_memory = plan.parallel_batch.contains(&RingId::Memory);
        let run_reasoning = plan.parallel_batch.contains(&RingId::Reasoning);
        let run_governance = plan.parallel_batch.contains(&RingId::Governance);

        // Launch parallel tasks. Each ring's evaluate() is sync, so we
        // wrap in spawn_blocking for genuine concurrency.
        let threat_handle = if run_threat {
            Some(tokio::task::spawn_blocking(move || {
                threat.evaluate(&shield_for_threat)
            }))
        } else { None };

        let identity_handle = if run_identity {
            let req = identity_req;
            Some(tokio::task::spawn_blocking(move || {
                identity.evaluate(&req)
            }))
        } else { None };

        let memory_handle = if run_memory {
            let req = memory_req;
            Some(tokio::task::spawn_blocking(move || {
                memory.evaluate(&req)
            }))
        } else { None };

        let reasoning_handle = if run_reasoning {
            let req = reasoning_req;
            Some(tokio::task::spawn_blocking(move || {
                reasoning.evaluate(&req)
            }))
        } else { None };

        let governance_handle = if run_governance {
            let req = governance_req;
            Some(tokio::task::spawn_blocking(move || {
                governance.evaluate(&req)
            }))
        } else { None };

        // Await all parallel results.
        let threat_verdict = match threat_handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "threat ring task panicked");
                // Return a deny verdict on panic (Fail Secure).
                crate::threat::ThreatVerdict {
                    decision: Decision::Deny { code: "RING_PANIC".into(), retry_after: None },
                    engine_results: vec![],
                    composite_score: 10.0,
                    confidence: 1.0,
                    matched_signatures: vec![],
                    latency_ms: 0.0,
                }
            })),
            None => None,
        };

        let identity_verdict = match identity_handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "identity ring task panicked");
                crate::identity::IdentityVerdict {
                    decision: Decision::Deny { code: "RING_PANIC".into(), retry_after: None },
                    identity_profile: None,
                    role: None,
                    trust_result: None,
                    anomaly_result: None,
                    engine_results: vec![],
                    latency_ms: 0.0,
                    identity_risk_score: 10.0,
                }
            })),
            None => None,
        };

        let memory_verdict = match memory_handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "memory ring task panicked");
                crate::memory::MemoryVerdict {
                    decision: Decision::Deny { code: "RING_PANIC".into(), retry_after: None },
                    pii_findings: None,
                    conversation_state: None,
                    rag_verdict: None,
                    provenance_verdict: None,
                    access_verdict: None,
                    engine_results: vec![],
                    latency_ms: 0.0,
                    memory_risk_score: 10.0,
                }
            })),
            None => None,
        };

        let reasoning_verdict = match reasoning_handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "reasoning ring task panicked");
                crate::reasoning::ReasoningVerdict {
                    decision: Decision::Deny { code: "RING_PANIC".into(), retry_after: None },
                    coherence_result: None,
                    hallucination_result: None,
                    depth_result: None,
                    bias_result: None,
                    step_result: None,
                    consistency_result: None,
                    engine_results: vec![],
                    latency_ms: 0.0,
                    reasoning_risk_score: 10.0,
                }
            })),
            None => None,
        };

        let governance_verdict = match governance_handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| {
                tracing::error!(error = %e, "governance ring task panicked");
                crate::governance::GovernanceVerdict {
                    decision: Decision::Deny { code: "RING_PANIC".into(), retry_after: None },
                    policy_result: None,
                    audit_result: None,
                    retention_result: None,
                    consent_result: None,
                    compliance_report: None,
                    sanction_result: None,
                    engine_results: vec![],
                    latency_ms: 0.0,
                    governance_risk_score: 10.0,
                }
            })),
            None => None,
        };

        // ── Phase 3: Sequential batch (respecting dependency conditions) ──
        let mut agent_verdict: Option<crate::agent::AgentVerdict> = None;
        let mut execution_verdict: Option<crate::execution::ExecutionVerdict> = None;

        // Track dependency verdicts for conditional evaluation.
        let mut verdicts: std::collections::HashMap<RingId, bool> = std::collections::HashMap::new();
        verdicts.insert(RingId::Shield, shield_verdict.decision.is_allow());
        if let Some(ref v) = threat_verdict { verdicts.insert(RingId::Threat, v.decision.is_allow()); }
        if let Some(ref v) = identity_verdict { verdicts.insert(RingId::Identity, v.decision.is_allow()); }
        if let Some(ref v) = memory_verdict { verdicts.insert(RingId::Memory, v.decision.is_allow()); }
        if let Some(ref v) = reasoning_verdict { verdicts.insert(RingId::Reasoning, v.decision.is_allow()); }
        if let Some(ref v) = governance_verdict { verdicts.insert(RingId::Governance, v.decision.is_allow()); }

        for (ring, depends_on, condition) in &plan.sequential_batch {
            let should_run = match condition {
                DepCondition::AllowOnly => {
                    verdicts.get(depends_on).copied().unwrap_or(false)
                }
                DepCondition::DenyOnly => {
                    !verdicts.get(depends_on).copied().unwrap_or(true)
                }
                DepCondition::Always => true,
            };

            if !should_run {
                tracing::debug!(
                    ring = ?ring,
                    depends_on = ?depends_on,
                    condition = ?condition,
                    "skipping sequential ring (condition not met)"
                );
                continue;
            }

            match ring {
                RingId::Agent => {
                    if let Some(tool_ctx) = &ctx.tool_call {
                        let agent_request = crate::agent::AgentRequest {
                            agent_id: tool_ctx.agent_id.clone().unwrap_or_else(|| "unknown".into()),
                            agent_type: None,
                            action: format!("tool_call:{}", tool_ctx.tool_name),
                            target: None,
                            tools_requested: vec![tool_ctx.tool_name.clone()],
                            source_ip: ctx.shield_request.source_ip.clone(),
                            user_id: ctx.shield_request.user_id.clone(),
                            role: None,
                            scope: None,
                            request_id: ctx.request_id.clone(),
                            headers: ctx.shield_request.headers.clone(),
                        };
                        let verdict = self.agent.evaluate(&agent_request);
                        verdicts.insert(RingId::Agent, verdict.decision.is_allow());
                        agent_verdict = Some(verdict);
                    }
                }
                RingId::Execution => {
                    if let Some(tool_ctx) = &ctx.tool_call {
                        let tool_call = crate::execution::ToolCall {
                            tool_name: tool_ctx.tool_name.clone(),
                            parameters: tool_ctx.parameters.clone(),
                            request_id: ctx.request_id.clone(),
                            source_ip: ctx.shield_request.source_ip.clone(),
                            agent_id: tool_ctx.agent_id.clone(),
                            user_id: ctx.shield_request.user_id.clone(),
                        };
                        let verdict = self.execution.evaluate(&tool_call);
                        verdicts.insert(RingId::Execution, verdict.decision.is_allow());
                        execution_verdict = Some(verdict);
                    }
                }
                // Other rings in sequential batch are handled above.
                _ => {
                    tracing::warn!(ring = ?ring, "unexpected ring in sequential batch");
                }
            }
        }

        // ── Phase 4: Keshav-Decide + Keshav-Risk ──
        let source_ip = ctx.shield_request.source_ip.clone();
        let record = self.decide.evaluate_all(
            &shield_verdict,
            threat_verdict.as_ref(),
            identity_verdict.as_ref(),
            memory_verdict.as_ref(),
            agent_verdict.as_ref(),
            execution_verdict.as_ref(),
            &ctx.request_id,
            &source_ip,
        );

        let risk_score = self.risk.evaluate(&RiskSignals {
            threat_score: threat_verdict.as_ref().map(|v| v.composite_score),
            identity_score: identity_verdict.as_ref().map(|v| v.identity_risk_score),
            agent_score: agent_verdict.as_ref().map(|v| v.behavior_risk_score),
            memory_score: memory_verdict.as_ref().map(|v| v.memory_risk_score),
            execution_score: execution_verdict.as_ref()
                .map(|v| super::execution_to_risk_score(&v.decision)),
            reasoning_score: reasoning_verdict.as_ref().map(|v| v.reasoning_risk_score),
            governance_score: governance_verdict.as_ref().map(|v| v.governance_risk_score),
            context: ContextSignals::default(),
            recovery_score: None,
        });

        PipelineResult {
            shield_verdict,
            threat_verdict,
            identity_verdict,
            memory_verdict,
            agent_verdict,
            execution_verdict,
            reasoning_verdict,
            governance_verdict,
            risk_score,
            decision_record: record,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify PipelineContext can be constructed.
    #[test]
    fn pipeline_context_constructs() {
        let ctx = PipelineContext {
            shield_request: ShieldRequest {
                source_ip: "0.0.0.0".into(),
                user_agent: None,
                api_key: None,
                user_id: None,
                method: "POST".into(),
                path: "/v1/evaluate".into(),
                headers: std::collections::HashMap::new(),
                body: serde_json::json!({"messages": [{"role": "user", "content": "hello"}]}),
            },
            request_id: "test-123".into(),
            prompt_text: "hello".into(),
            tool_call: None,
        };
        assert_eq!(ctx.request_id, "test-123");
        assert!(ctx.tool_call.is_none());
    }

    /// Verify PipelineContext with tool call constructs.
    #[test]
    fn pipeline_context_with_tool_call() {
        let ctx = PipelineContext {
            shield_request: ShieldRequest {
                source_ip: "0.0.0.0".into(),
                user_agent: None,
                api_key: None,
                user_id: None,
                method: "POST".into(),
                path: "/v1/execute".into(),
                headers: std::collections::HashMap::new(),
                body: serde_json::json!({"tool_name": "read_file"}),
            },
            request_id: "test-456".into(),
            prompt_text: String::new(),
            tool_call: Some(ToolCallContext {
                tool_name: "read_file".into(),
                parameters: serde_json::json!({"path": "/tmp/test"}),
                agent_id: Some("agent-1".into()),
            }),
        };
        assert!(ctx.tool_call.is_some());
        assert_eq!(ctx.tool_call.as_ref().unwrap().tool_name, "read_file");
    }
}
