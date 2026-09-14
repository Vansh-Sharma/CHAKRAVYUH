// gRPC API Service (Phase 8)
//
// High-performance programmatic interface using tonic/gRPC.
// Mirrors the HTTP API endpoints for programmatic access by
// SDK clients, sidecars, and internal services.
//
// The gRPC server runs alongside the HTTP server on a configurable
// port (default: 50051). Both servers share the same ApiState.
//
// Pipeline execution is delegated to PipelineExecutor (same as HTTP),
// ensuring parallel ring evaluation and consistent behavior.

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/chakravyuh.v1.rs"));
}

pub use proto::chakravyuh_service_server::ChakravyuhService;

use proto::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::api::ApiState;
use crate::infra::{is_ready, RingHealth};
use crate::keshav::PipelineContext;
use crate::keshav::orchestrate::RequestType;

/// gRPC configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GrpcConfig {
    /// Enable the gRPC server.
    #[serde(default)]
    pub enabled: bool,

    /// Bind address for the gRPC server.
    #[serde(default = "default_grpc_addr")]
    pub addr: String,
}

fn default_grpc_addr() -> String {
    "0.0.0.0:50051".into()
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: default_grpc_addr(),
        }
    }
}

/// The gRPC service implementation.
/// Wraps the shared ApiState and delegates to PipelineExecutor
/// for ring evaluation (same path as the HTTP API).
pub struct ChakravyuhGrpcService {
    pub state: Arc<ApiState>,
}

impl ChakravyuhGrpcService {
    pub fn new(state: Arc<ApiState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl proto::chakravyuh_service_server::ChakravyuhService for ChakravyuhGrpcService {
    // ── Evaluate ──

    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<DecisionResponse>, Status> {
        let req = request.into_inner();

        // Build the request body from gRPC fields.
        let mut messages_json = Vec::new();
        for msg in &req.messages {
            messages_json.push(serde_json::json!({
                "role": msg.role,
                "content": msg.content,
            }));
        }
        let body = serde_json::json!({
            "model": req.model,
            "messages": messages_json,
        });

        let shield_request = crate::api::build_shield_request(
            "/grpc/evaluate", &axum::http::HeaderMap::new(), body,
        );

        let request_id = uuid::Uuid::new_v4().to_string();
        let prompt_text = crate::api::extract_prompt_text(&shield_request.body);

        // Build orchestration plan and execute via PipelineExecutor.
        let plan = self.state.orchestrate.plan(RequestType::SimplePrompt, false);
        let ctx = PipelineContext {
            shield_request,
            request_id,
            prompt_text,
            tool_call: None,
        };

        let result = self.state.pipeline.execute(&plan, &ctx).await;

        let resp = pipeline_result_to_decision_response(&result);
        Ok(Response::new(resp))
    }

    // ── Execute ──

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<DecisionResponse>, Status> {
        let req = request.into_inner();
        let request_id = if req.request_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            req.request_id.clone()
        };

        let parameters: serde_json::Value = serde_json::from_str(&req.parameters)
            .unwrap_or(serde_json::Value::Null);

        let body = serde_json::json!({
            "tool_name": req.tool_name,
            "parameters": parameters,
        });

        let shield_request = crate::api::build_shield_request(
            "/grpc/execute", &axum::http::HeaderMap::new(), body,
        );

        let prompt_text = crate::api::extract_prompt_text(&shield_request.body);

        // Build orchestration plan and execute via PipelineExecutor.
        let plan = self.state.orchestrate.plan(RequestType::ToolCall, true);
        let ctx = PipelineContext {
            shield_request,
            request_id,
            prompt_text,
            tool_call: Some(crate::keshav::ToolCallContext {
                tool_name: req.tool_name,
                parameters,
                agent_id: if req.agent_id.is_empty() { None } else { Some(req.agent_id) },
            }),
        };

        let result = self.state.pipeline.execute(&plan, &ctx).await;

        let resp = pipeline_result_to_decision_response(&result);
        Ok(Response::new(resp))
    }

    // ── Health ──

    async fn health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_secs: self.state.started_at.elapsed().as_secs(),
        }))
    }

    // ── Ready ──

    async fn ready(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ReadyResponse>, Status> {
        let known_rings = &["shield", "threat", "identity", "memory", "agent", "execution"];
        let ring_health = self.state.cross_ring.ring_health(known_rings);

        let infra_health: Vec<RingStatus> = ring_health.iter().map(|h| RingStatus {
            name: h.ring_name.clone(),
            healthy: h.is_healthy,
        }).collect();

        let ring_health_for_check: Vec<RingHealth> = infra_health.iter().map(|h| RingHealth {
            name: h.name.clone(),
            enabled: true,
            healthy: h.healthy,
            last_check_ms: 0.0,
            total_evaluations: 0,
            total_errors: 0,
            error_rate: 0.0,
        }).collect();

        let ready = is_ready(&ring_health_for_check);
        let (total_reqs, total_errs) = crate::infra::request_counts();

        Ok(Response::new(ReadyResponse {
            status: if ready { "ready".into() } else { "not_ready".into() },
            ready,
            total_requests: total_reqs,
            total_errors: total_errs,
            rings: infra_health,
        }))
    }

    // ── Policy ──

    async fn get_policy_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<PolicyInfo>, Status> {
        let info = self.state.policy_manager.policy_info();
        Ok(Response::new(PolicyInfo {
            version: info.version,
            rule_count: info.rule_count as u32,
            rules: info.rules,
            policy_path: info.policy_path.unwrap_or_default(),
        }))
    }

    async fn reload_policy(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ReloadResponse>, Status> {
        match self.state.policy_manager.reload_from_file() {
            Ok(version) => Ok(Response::new(ReloadResponse {
                status: "reloaded".into(),
                version,
            })),
            Err(e) => Err(Status::internal(format!("reload failed: {}", e))),
        }
    }

    // ── Learning ──

    async fn submit_feedback(
        &self,
        request: Request<FeedbackRequest>,
    ) -> Result<Response<AckResponse>, Status> {
        let req = request.into_inner();

        let feedback_type = match req.feedback_type.to_lowercase().as_str() {
            "false_positive" | "fp" => crate::keshav::feedback_collector::FeedbackType::FalsePositive,
            "false_negative" | "fn" => crate::keshav::feedback_collector::FeedbackType::FalseNegative,
            "approve" => crate::keshav::feedback_collector::FeedbackType::Approve,
            "reject" => crate::keshav::feedback_collector::FeedbackType::Reject,
            "escalation_approved" => crate::keshav::feedback_collector::FeedbackType::EscalationApproved,
            "escalation_denied" => crate::keshav::feedback_collector::FeedbackType::EscalationDenied,
            _ => return Err(Status::invalid_argument("invalid feedback_type")),
        };

        let severity = match req.severity.to_lowercase().as_str() {
            "low" => crate::keshav::feedback_collector::FeedbackSeverity::Low,
            "medium" => crate::keshav::feedback_collector::FeedbackSeverity::Medium,
            "high" => crate::keshav::feedback_collector::FeedbackSeverity::High,
            "critical" => crate::keshav::feedback_collector::FeedbackSeverity::Critical,
            _ => crate::keshav::feedback_collector::FeedbackSeverity::Medium,
        };

        let target_rings = if req.ring.is_empty() { vec![] } else { vec![req.ring.clone()] };

        self.state.learn.submit_feedback(crate::keshav::feedback_collector::FeedbackEntry {
            feedback_id: uuid::Uuid::new_v4().to_string(),
            request_id: req.request_id,
            feedback_type,
            severity,
            target_rings,
            original_decision: req.original_decision,
            explanation: req.explanation,
            submitted_by: req.submitted_by,
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        });

        Ok(Response::new(AckResponse {
            status: "accepted".into(),
            message: "feedback recorded".into(),
        }))
    }

    async fn get_learn_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<LearnStatusResponse>, Status> {
        let status = self.state.learn.status();
        Ok(Response::new(LearnStatusResponse {
            enabled: status.enabled,
            unprocessed_feedback: status.unprocessed_feedback as u64,
            auto_optimize_pending: status.auto_optimize_pending,
            profiles_count: status.profiles_count as u64,
            patterns_count: status.patterns_count as u64,
            thresholds_count: status.threshold_count as u64,
            last_optimization: status.last_optimization.map(|o| o.timestamp).unwrap_or_default(),
        }))
    }

    async fn optimize_thresholds(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OptimizeResponse>, Status> {
        let results = self.state.learn.optimize_thresholds();
        let adjustments: Vec<ThresholdAdjustment> = results.iter().map(|r| ThresholdAdjustment {
            ring: r.ring_name.clone(),
            old_deny: r.old_deny,
            new_deny: r.new_deny,
            old_challenge: r.old_challenge,
            new_challenge: r.new_challenge,
            direction: format!("{:?}", r.direction),
            reason: r.reason.clone(),
            confidence: r.confidence,
        }).collect();

        Ok(Response::new(OptimizeResponse {
            optimizations_applied: adjustments.len() as u32,
            adjustments,
        }))
    }

    // ── Decisions ──

    async fn list_decisions(
        &self,
        request: Request<ListDecisionsRequest>,
    ) -> Result<Response<DecisionLogResponse>, Status> {
        let _req = request.into_inner();
        let entries = self.state.decide.logger().entries();
        let records: Vec<DecisionRecord> = entries.iter().map(|e| DecisionRecord {
            request_id: e.record.request_id.clone(),
            decision: format!("{:?}", e.record.final_decision),
            reasoning: e.record.reasoning.clone(),
            policy_applied: e.record.policy_applied.clone().unwrap_or_default(),
            latency_ms: e.record.latency_ms,
            timestamp: 0,
        }).collect();

        Ok(Response::new(DecisionLogResponse {
            count: records.len() as u64,
            records,
        }))
    }

    // ── Storage ──

    async fn storage_health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<StorageHealthResponse>, Status> {
        let health = self.state.storage.health_check();
        Ok(Response::new(StorageHealthResponse {
            backend: health.backend,
            reachable: health.reachable,
            latency_ms: health.latency_ms,
            detail: health.detail,
        }))
    }
}

// ── Helper: Convert PipelineResult to protobuf DecisionResponse ──
//
// This is the single conversion point. Previously, gRPC built the
// protobuf response manually with per-ring logic duplicated from
// api/mod.rs. Now it reuses the PipelineResult from PipelineExecutor.

fn pipeline_result_to_decision_response(result: &crate::keshav::PipelineResult) -> DecisionResponse {
    use crate::decision::Decision;

    let decision_str = match &result.decision_record.final_decision {
        Decision::Allow => "allow".to_string(),
        Decision::Deny { code, .. } => format!("deny:{}", code),
        Decision::Challenge { .. } => "challenge".to_string(),
        Decision::Escalate { .. } => "escalate".to_string(),
    };

    let mut rings = std::collections::HashMap::new();

    // Shield Ring.
    rings.insert("shield".into(), RingDetail {
        decision: format!("{:?}", result.shield_verdict.decision),
        latency_ms: result.shield_verdict.latency_ms,
        engine_results: result.shield_verdict.engine_results.iter().map(|r| EngineResult {
            engine: r.engine_name.clone(),
            decision: format!("{:?}", r.decision),
            reason: r.reason.clone(),
            latency_ms: r.latency_ms,
        }).collect(),
    });

    // Threat Ring.
    if let Some(t) = &result.threat_verdict {
        rings.insert("threat".into(), RingDetail {
            decision: format!("{:?}", t.decision),
            latency_ms: t.latency_ms,
            engine_results: t.engine_results.iter().map(|r| EngineResult {
                engine: r.engine_name.clone(),
                decision: "score".into(),
                reason: r.reason.clone(),
                latency_ms: r.latency_ms,
            }).collect(),
        });
    }

    // Identity Ring.
    if let Some(i) = &result.identity_verdict {
        rings.insert("identity".into(), RingDetail {
            decision: format!("{:?}", i.decision),
            latency_ms: i.latency_ms,
            engine_results: i.engine_results.iter().map(|r| EngineResult {
                engine: r.engine_name.clone(),
                decision: r.decision.clone(),
                reason: r.reason.clone(),
                latency_ms: r.latency_ms,
            }).collect(),
        });
    }

    // Memory Ring.
    if let Some(m) = &result.memory_verdict {
        rings.insert("memory".into(), RingDetail {
            decision: format!("{:?}", m.decision),
            latency_ms: m.latency_ms,
            engine_results: m.engine_results.iter().map(|r| EngineResult {
                engine: r.engine_name.clone(),
                decision: r.decision.clone(),
                reason: r.reason.clone(),
                latency_ms: r.latency_ms,
            }).collect(),
        });
    }

    // Agent Ring.
    if let Some(a) = &result.agent_verdict {
        rings.insert("agent".into(), RingDetail {
            decision: format!("{:?}", a.decision),
            latency_ms: a.latency_ms,
            engine_results: a.engine_results.iter().map(|r| EngineResult {
                engine: r.engine_name.clone(),
                decision: r.decision.clone(),
                reason: r.reason.clone(),
                latency_ms: r.latency_ms,
            }).collect(),
        });
    }

    // Execution Ring.
    if let Some(e) = &result.execution_verdict {
        rings.insert("execution".into(), RingDetail {
            decision: format!("{:?}", e.decision),
            latency_ms: e.latency_ms,
            engine_results: e.engine_results.iter().map(|r| EngineResult {
                engine: r.engine_name.clone(),
                decision: format!("{:?}", r.decision),
                reason: r.reason.clone(),
                latency_ms: r.latency_ms,
            }).collect(),
        });
    }

    // Reasoning Ring.
    if let Some(r) = &result.reasoning_verdict {
        rings.insert("reasoning".into(), RingDetail {
            decision: format!("{:?}", r.decision),
            latency_ms: r.latency_ms,
            engine_results: r.engine_results.iter().map(|e| EngineResult {
                engine: e.engine_name.clone(),
                decision: format!("{:?}", e.decision),
                reason: e.reason.clone(),
                latency_ms: e.latency_ms,
            }).collect(),
        });
    }

    // Governance Ring.
    if let Some(g) = &result.governance_verdict {
        rings.insert("governance".into(), RingDetail {
            decision: format!("{:?}", g.decision),
            latency_ms: g.latency_ms,
            engine_results: g.engine_results.iter().map(|e| EngineResult {
                engine: e.engine_name.clone(),
                decision: format!("{:?}", e.decision),
                reason: e.reason.clone(),
                latency_ms: e.latency_ms,
            }).collect(),
        });
    }

    let risk_pb = RiskScore {
        overall: result.risk_score.overall,
        threat: result.risk_score.threat,
        identity: result.risk_score.identity,
        agent: result.risk_score.behavior,
        memory: result.risk_score.memory,
        execution: result.risk_score.execution,
        reasoning: 0.0,  // Not yet tracked in RiskScore
        governance: 0.0, // Not yet tracked in RiskScore
        recovery: 0.0,  // Not yet tracked in RiskScore
        context: result.risk_score.context,
    };

    DecisionResponse {
        decision: decision_str,
        reason: result.decision_record.reasoning.clone(),
        request_id: result.decision_record.request_id.clone(),
        policy_applied: result.decision_record.policy_applied.clone().unwrap_or_default(),
        latency_ms: result.decision_record.latency_ms,
        rings,
        risk_score: Some(risk_pb),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grpc_config() {
        let cfg = GrpcConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.addr, "0.0.0.0:50051");
    }

    #[test]
    fn grpc_config_parses() {
        let yaml = r#"enabled: true
addr: "0.0.0.0:50052"
"#;
        let cfg: GrpcConfig = serde_yaml::from_str(yaml).expect("parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.addr, "0.0.0.0:50052");
    }
}
