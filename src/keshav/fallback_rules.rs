// Fallback Rules — the safety net when everything else fails.
//
// If the Policy Engine fails to produce a decision (no rule matched,
// or the policy itself is corrupted/unloadable), Fallback Rules take
// over. These rules are HARDCODED — they cannot be modified by
// configuration or by Keshav-Learn. This is the architectural guarantee
// that the system never fails open.
//
// Fallback Rules implement Principle 2 (Fail Secure):
//   - If ANY ring returned Deny → Deny (across all 6 rings)
//   - If any ring returned Challenge → Challenge
//   - Otherwise → Allow (but log that fallback was used)
//
// Fallback Rules also implement Principle 1 (Decide-without-Learn):
//   - They run without any ML, without Risk scoring, without Orchestrate.
//   - They are pure functions of ring verdicts.

use super::decide::AllRingVerdicts;
use crate::decision::Decision;
use crate::shield::ShieldVerdict;
use crate::threat::ThreatVerdict;

pub struct FallbackRules;

impl FallbackRules {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate ring verdicts using hardcoded fallback rules (legacy 2-ring).
    /// Returns `(decision, reasoning)`.
    pub fn evaluate(
        &self,
        shield: &ShieldVerdict,
        threat: Option<&ThreatVerdict>,
    ) -> (Decision, String) {
        // Build a minimal AllRingVerdicts for the full-path.
        let all = AllRingVerdicts {
            shield,
            threat,
            identity: None,
            memory: None,
            agent: None,
            execution: None,
            reasoning: None,
            governance: None,
            recovery: None,
        };
        self.evaluate_all(&all)
    }

    /// Evaluate all 6 ring verdicts using hardcoded fallback rules.
    /// Returns `(decision, reasoning)`.
    ///
    /// Order of evaluation:
    ///   1. Shield Deny/Challenge
    ///   2. Threat Deny/Challenge
    ///   3. Identity Deny/Challenge
    ///   4. Memory Deny/Challenge
    ///   5. Agent Deny
    ///   6. Execution Deny
    ///   7. Default: Allow
    pub fn evaluate_all(&self, all: &AllRingVerdicts<'_>) -> (Decision, String) {
        // 1. Shield
        if all.shield.decision.is_deny() {
            return (
                all.shield.decision.clone(),
                format!(
                    "fallback: shield ring denied ({})",
                    decision_code(&all.shield.decision)
                ),
            );
        }
        if matches!(all.shield.decision, Decision::Challenge { .. }) {
            return (
                all.shield.decision.clone(),
                "fallback: shield ring issued challenge".into(),
            );
        }

        // 2. Threat
        if let Some(t) = all.threat {
            if t.decision.is_deny() {
                return (
                    t.decision.clone(),
                    format!(
                        "fallback: threat ring denied (score={:.3}, sigs={})",
                        t.composite_score,
                        t.matched_signatures.len()
                    ),
                );
            }
            if matches!(t.decision, Decision::Challenge { .. }) {
                return (
                    t.decision.clone(),
                    "fallback: threat ring issued challenge".into(),
                );
            }
        }

        // 3. Identity
        if let Some(i) = all.identity {
            if i.decision.is_deny() {
                return (
                    i.decision.clone(),
                    format!(
                        "fallback: identity ring denied (risk={:.3})",
                        i.identity_risk_score
                    ),
                );
            }
            if matches!(i.decision, Decision::Challenge { .. }) {
                return (
                    i.decision.clone(),
                    format!(
                        "fallback: identity ring challenged (risk={:.3})",
                        i.identity_risk_score
                    ),
                );
            }
        }

        // 4. Memory
        if let Some(m) = all.memory {
            if m.decision.is_deny() {
                return (
                    m.decision.clone(),
                    format!(
                        "fallback: memory ring denied (risk={:.3})",
                        m.memory_risk_score
                    ),
                );
            }
            if matches!(m.decision, Decision::Challenge { .. }) {
                return (
                    m.decision.clone(),
                    format!(
                        "fallback: memory ring challenged (risk={:.3})",
                        m.memory_risk_score
                    ),
                );
            }
        }

        // 5. Agent
        if let Some(a) = all.agent {
            if a.decision.is_deny() {
                return (
                    a.decision.clone(),
                    format!(
                        "fallback: agent ring denied (risk={:.3})",
                        a.behavior_risk_score
                    ),
                );
            }
        }

        // 6. Execution
        if let Some(e) = all.execution {
            if e.decision.is_deny() {
                return (e.decision.clone(), "fallback: execution ring denied".into());
            }
        }

        // 7. Reasoning
        if let Some(r) = all.reasoning {
            if r.decision.is_deny() {
                return (
                    r.decision.clone(),
                    format!(
                        "fallback: reasoning ring denied (risk={:.3})",
                        r.reasoning_risk_score
                    ),
                );
            }
            if matches!(r.decision, Decision::Challenge { .. }) {
                return (
                    r.decision.clone(),
                    format!(
                        "fallback: reasoning ring challenged (risk={:.3})",
                        r.reasoning_risk_score
                    ),
                );
            }
        }

        // 8. Governance
        if let Some(g) = all.governance {
            if g.decision.is_deny() {
                return (
                    g.decision.clone(),
                    format!(
                        "fallback: governance ring denied (risk={:.3})",
                        g.governance_risk_score
                    ),
                );
            }
            if matches!(g.decision, Decision::Escalate { .. }) {
                return (
                    g.decision.clone(),
                    format!(
                        "fallback: governance ring escalated (risk={:.3})",
                        g.governance_risk_score
                    ),
                );
            }
        }

        // 9. Recovery
        if let Some(rc) = all.recovery {
            if rc.decision.is_deny() {
                return (
                    rc.decision.clone(),
                    format!(
                        "fallback: recovery ring denied (risk={:.3})",
                        rc.recovery_risk_score
                    ),
                );
            }
        }

        // 10. Default: allow.
        (
            Decision::Allow,
            "fallback: no ring denied or challenged".into(),
        )
    }
}

impl Default for FallbackRules {
    fn default() -> Self {
        Self::new()
    }
}

fn decision_code(d: &Decision) -> &str {
    match d {
        Decision::Deny { code, .. } => code,
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shield_allow() -> ShieldVerdict {
        ShieldVerdict {
            decision: Decision::Allow,
            engine_results: vec![],
            latency_ms: 0.5,
        }
    }

    fn shield_deny(code: &str) -> ShieldVerdict {
        ShieldVerdict {
            decision: Decision::Deny {
                code: code.into(),
                retry_after: None,
            },
            engine_results: vec![],
            latency_ms: 0.5,
        }
    }

    fn threat_allow() -> ThreatVerdict {
        ThreatVerdict {
            decision: Decision::Allow,
            engine_results: vec![],
            composite_score: 0.1,
            confidence: 0.9,
            matched_signatures: vec![],
            latency_ms: 1.0,
        }
    }

    fn threat_deny() -> ThreatVerdict {
        ThreatVerdict {
            decision: Decision::Deny {
                code: "THREAT".into(),
                retry_after: None,
            },
            engine_results: vec![],
            composite_score: 0.9,
            confidence: 0.95,
            matched_signatures: vec!["JB-DAN".into()],
            latency_ms: 1.0,
        }
    }

    #[test]
    fn fallback_denies_on_shield_deny() {
        let rules = FallbackRules::new();
        let (d, r) = rules.evaluate(&shield_deny("WAF"), None);
        assert!(d.is_deny());
        assert!(r.contains("fallback"));
    }

    #[test]
    fn fallback_denies_on_threat_deny() {
        let rules = FallbackRules::new();
        let (d, r) = rules.evaluate(&shield_allow(), Some(&threat_deny()));
        assert!(d.is_deny());
        assert!(r.contains("fallback"));
        assert!(r.contains("threat"));
    }

    #[test]
    fn fallback_allows_when_both_allow() {
        let rules = FallbackRules::new();
        let (d, r) = rules.evaluate(&shield_allow(), Some(&threat_allow()));
        assert!(d.is_allow());
        assert!(r.contains("fallback"));
    }

    #[test]
    fn fallback_works_without_threat() {
        // Principle 1: fallback works without Threat Ring.
        let rules = FallbackRules::new();
        let (d, _) = rules.evaluate(&shield_allow(), None);
        assert!(d.is_allow());
    }

    #[test]
    fn fallback_works_without_any_ring_verdicts() {
        // Extreme case: Shield has Allow (no engines), no Threat.
        let rules = FallbackRules::new();
        let (d, _) = rules.evaluate(&shield_allow(), None);
        assert!(d.is_allow());
    }
}
