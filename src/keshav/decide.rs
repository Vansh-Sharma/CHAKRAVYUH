// Keshav-Decide — Rule-Based Policy Engine
//
// The first Keshav subsystem. Combines ring verdicts into a final
// Decision according to YAML policies. Logs every decision as a
// DecisionRecord (append-only audit log).
//
// CRITICAL (Principle 1): Decide MUST work without Learn, without
// Risk, and without any ring. If all rings are disabled or fail to
// initialize, Decide still returns a valid Decision using its
// Fallback Rules. This is the architectural guarantee that the system
// never fails open.
//
// Phase 2 scope:
//   - Policy Engine: evaluates ring verdicts against YAML policies
//   - Decision Logger: append-only audit log with full reasoning
//   - Fallback Rules: minimal rule set that runs if all else fails
//
// Phase 4 scope (v0.8.0):
//   - Extended to accept all 6 ring verdicts (Shield, Threat, Identity,
//     Memory, Agent, Execution) in both Policy Engine and Fallback Rules
//   - Policy Engine now has per-ring deny/challenge conditions for all rings
//   - Fallback Rules enforce deny-on-any-ring-deny across all rings
//
// Phase 6 (Keshav-Learn) will ADD a learning layer on top of Decide.
// Learn can adjust thresholds and weights, but it can NEVER override
// a Deny from Fallback Rules. This is the hard architectural boundary.

use std::sync::Arc;

#[cfg(test)]
use crate::decision::Decision;
use crate::agent::AgentVerdict;
use crate::decision::{DecisionRecord, RiskScore};
use crate::execution::ExecutionVerdict;
use crate::governance::GovernanceVerdict;
use crate::identity::IdentityVerdict;
use crate::keshav::{DecisionLogger, FallbackRules, Policy, PolicyEngine};
use crate::memory::MemoryVerdict;
use crate::reasoning::ReasoningVerdict;
use crate::recovery_sec::RecoveryVerdict;
use crate::shield::ShieldVerdict;
use crate::threat::ThreatVerdict;

/// All ring verdicts collected for a single request evaluation.
/// Used by Keshav-Decide, Policy Engine, and Fallback Rules
/// to run their logic against every ring that evaluated the request.
pub struct AllRingVerdicts<'a> {
    pub shield: &'a ShieldVerdict,
    pub threat: Option<&'a ThreatVerdict>,
    pub identity: Option<&'a IdentityVerdict>,
    pub memory: Option<&'a MemoryVerdict>,
    pub agent: Option<&'a AgentVerdict>,
    pub execution: Option<&'a ExecutionVerdict>,
    pub reasoning: Option<&'a ReasoningVerdict>,
    pub governance: Option<&'a GovernanceVerdict>,
    pub recovery: Option<&'a RecoveryVerdict>,
}

/// Keshav-Decide — the rule-based decision brain.
#[derive(Clone)]
pub struct KeshavDecide {
    policy_engine: Arc<PolicyEngine>,
    decision_logger: Arc<DecisionLogger>,
    fallback_rules: Arc<FallbackRules>,
    /// Static risk score used in Phase 2 (Keshav-Risk is Phase 3).
    /// All decisions get this same risk score — it's a placeholder.
    static_risk: RiskScore,
}

impl KeshavDecide {
    /// Create a new Keshav-Decide with the given policy and logger.
    pub fn new(policy: Policy, decision_logger: Arc<DecisionLogger>) -> crate::Result<Self> {
        Ok(Self {
            policy_engine: Arc::new(PolicyEngine::new(policy)),
            decision_logger,
            fallback_rules: Arc::new(FallbackRules::new()),
            static_risk: RiskScore::default(),
        })
    }

    /// Create with default policy (deny-on-any-ring-deny).
    pub fn with_defaults() -> crate::Result<Self> {
        Self::new(Policy::default(), Arc::new(DecisionLogger::in_memory()))
    }

    /// Evaluate ring verdicts and produce a final Decision.
    ///
    /// This is the primary entry point. It:
    ///   1. Runs the Policy Engine against all ring verdicts.
    ///   2. If the Policy Engine produces a decision, use it.
    ///   3. If the Policy Engine fails (shouldn't happen, but...),
    ///      run Fallback Rules.
    ///   4. Log the decision as a DecisionRecord.
    ///
    /// `shield_verdict` is required. All other verdicts are optional —
    /// if None, that ring was disabled or not applicable (Principle 1 test).
    pub fn evaluate(
        &self,
        shield_verdict: &ShieldVerdict,
        threat_verdict: Option<&ThreatVerdict>,
        request_id: &str,
        source_ip: &str,
    ) -> DecisionRecord {
        self.evaluate_all(
            shield_verdict,
            threat_verdict,
            None,
            None,
            None,
            None,
            request_id,
            source_ip,
        )
    }

    /// Extended evaluation accepting all 6 ring verdicts.
    ///
    /// This is the full-pipeline entry point used by the API handlers
    /// when all rings have been evaluated. Falls back to the legacy
    /// 2-argument `evaluate()` when only Shield + Threat are available.
    pub fn evaluate_all(
        &self,
        shield_verdict: &ShieldVerdict,
        threat_verdict: Option<&ThreatVerdict>,
        identity_verdict: Option<&IdentityVerdict>,
        memory_verdict: Option<&MemoryVerdict>,
        agent_verdict: Option<&AgentVerdict>,
        execution_verdict: Option<&ExecutionVerdict>,
        request_id: &str,
        source_ip: &str,
    ) -> DecisionRecord {
        let start = std::time::Instant::now();

        let all_verdicts = AllRingVerdicts {
            shield: shield_verdict,
            threat: threat_verdict,
            identity: identity_verdict,
            memory: memory_verdict,
            agent: agent_verdict,
            execution: execution_verdict,
            reasoning: None,
            governance: None,
            recovery: None,
        };

        // 1. Try the Policy Engine.
        let (decision, policy_name, reasoning) =
            match self
                .policy_engine
                .evaluate_all(&all_verdicts, &self.static_risk)
            {
                Some(result) => result,
                None => {
                    // 2. Policy Engine failed — fall back.
                    let (decision, reasoning) =
                        self.fallback_rules.evaluate_all(&all_verdicts);
                    (decision, Some("fallback".to_string()), reasoning)
                }
            };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let rings_evaluated: Vec<u8> = {
            let mut v = vec![1]; // Shield is always evaluated
            if threat_verdict.is_some() { v.push(3); }
            if identity_verdict.is_some() { v.push(2); }
            if memory_verdict.is_some() { v.push(5); }
            if agent_verdict.is_some() { v.push(4); }
            if execution_verdict.is_some() { v.push(6); }
            v
        };

        let ring_verdicts = serde_json::json!({
            "shield": {
                "decision": format!("{:?}", shield_verdict.decision),
                "latency_ms": shield_verdict.latency_ms,
            },
            "threat": threat_verdict.map(|tv| serde_json::json!({
                "decision": format!("{:?}", tv.decision),
                "composite_score": tv.composite_score,
                "confidence": tv.confidence,
                "latency_ms": tv.latency_ms,
            })),
            "identity": identity_verdict.map(|iv| serde_json::json!({
                "decision": format!("{:?}", iv.decision),
                "identity_risk_score": iv.identity_risk_score,
                "latency_ms": iv.latency_ms,
            })),
            "memory": memory_verdict.map(|mv| serde_json::json!({
                "decision": format!("{:?}", mv.decision),
                "memory_risk_score": mv.memory_risk_score,
                "latency_ms": mv.latency_ms,
            })),
            "agent": agent_verdict.map(|av| serde_json::json!({
                "decision": format!("{:?}", av.decision),
                "behavior_risk_score": av.behavior_risk_score,
                "latency_ms": av.latency_ms,
            })),
            "execution": execution_verdict.map(|ev| serde_json::json!({
                "decision": format!("{:?}", ev.decision),
                "latency_ms": ev.latency_ms,
            })),
        });

        let record = DecisionRecord {
            request_id: request_id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: crate::decision::DecisionSource {
                ip: source_ip.to_string(),
                user_id: identity_verdict.and_then(|iv| {
                    iv.identity_profile.as_ref().map(|p| p.principal_id.clone())
                }),
                agent_id: agent_verdict.map(|_| "agent".to_string()),
                api_key: None,
            },
            risk_score: self.static_risk.clone(),
            rings_evaluated,
            ring_verdicts,
            policy_applied: policy_name,
            final_decision: decision.clone(),
            reasoning,
            latency_ms,
            keshav_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_version: self.policy_engine.policy().version.clone(),
        };

        // Log the decision (append-only, never fails the request).
        if let Err(e) = self.decision_logger.log(&record) {
            tracing::warn!(error = %e, "decision logger failed (non-fatal)");
        }

        record
    }

    /// Get a reference to the decision logger (for introspection/export).
    pub fn logger(&self) -> &DecisionLogger {
        &self.decision_logger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shield::ShieldRequest;
    use crate::Config;

    fn make_shield_verdict(decision: Decision) -> ShieldVerdict {
        ShieldVerdict {
            decision,
            engine_results: vec![],
            latency_ms: 0.5,
        }
    }

    fn make_threat_verdict(score: f64, decision: Decision) -> ThreatVerdict {
        ThreatVerdict {
            decision,
            engine_results: vec![],
            composite_score: score,
            confidence: 0.9,
            matched_signatures: vec![],
            latency_ms: 1.0,
        }
    }

    #[test]
    fn decide_deny_when_shield_denies() {
        let decide = KeshavDecide::with_defaults().expect("builds");
        let shield = make_shield_verdict(Decision::Deny {
            code: "WAF_SQL_INJECTION".into(),
            retry_after: None,
        });
        let record = decide.evaluate(&shield, None, "req-1", "1.2.3.4");
        assert!(record.final_decision.is_deny());
        assert!(record.reasoning.to_lowercase().contains("shield"));
    }

    #[test]
    fn decide_deny_when_threat_denies() {
        let decide = KeshavDecide::with_defaults().expect("builds");
        let shield = make_shield_verdict(Decision::Allow);
        let threat = make_threat_verdict(
            0.9,
            Decision::Deny {
                code: "THREAT_DETECTED".into(),
                retry_after: None,
            },
        );
        let record = decide.evaluate(&shield, Some(&threat), "req-2", "1.2.3.4");
        assert!(record.final_decision.is_deny());
    }

    #[test]
    fn decide_allow_when_both_rings_allow() {
        let decide = KeshavDecide::with_defaults().expect("builds");
        let shield = make_shield_verdict(Decision::Allow);
        let threat = make_threat_verdict(0.1, Decision::Allow);
        let record = decide.evaluate(&shield, Some(&threat), "req-3", "1.2.3.4");
        assert!(record.final_decision.is_allow());
    }

    #[test]
    fn decide_works_without_threat_ring() {
        // Principle 1 test: Decide works when Threat Ring is absent.
        let decide = KeshavDecide::with_defaults().expect("builds");
        let shield = make_shield_verdict(Decision::Allow);
        let record = decide.evaluate(&shield, None, "req-4", "1.2.3.4");
        assert!(record.final_decision.is_allow());
        // Should still produce a valid record with reasoning.
        assert!(!record.reasoning.is_empty());
        assert_eq!(record.rings_evaluated, vec![1]); // only Shield
    }

    #[test]
    fn decide_logs_every_decision() {
        let decide = KeshavDecide::with_defaults().expect("builds");
        let shield = make_shield_verdict(Decision::Allow);

        decide.evaluate(&shield, None, "req-5", "1.2.3.4");
        decide.evaluate(&shield, None, "req-6", "1.2.3.4");

        let entries = decide.logger().entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn decide_end_to_end_with_real_shield() {
        // Build a real Shield Ring from default config.
        let config: Config = Config::default_yaml().parse().expect("config parses");
        let config = Arc::new(config);
        let shield_ring = crate::shield::ShieldRing::new(config.clone()).expect("shield builds");

        // Build a Threat Ring.
        let threat_config = Arc::new(crate::threat::ThreatConfig::default());
        let threat_ring = crate::threat::ThreatRing::new(threat_config).expect("threat builds");

        // Build Decide.
        let decide = KeshavDecide::with_defaults().expect("builds");

        // Evaluate a benign request.
        let req = ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: Some("test/1.0".into()),
            api_key: None,
            user_id: None,
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "What is the capital of France?"}]
            }),
        };

        let shield_v = shield_ring.evaluate(&req);
        let threat_v = threat_ring.evaluate(&req);
        let record = decide.evaluate(&shield_v, Some(&threat_v), "req-e2e", "1.2.3.4");

        assert!(record.final_decision.is_allow());
        assert!(record.latency_ms < 10.0);
    }
}
