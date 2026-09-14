// Policy Engine — evaluates ring verdicts against YAML policies.
//
// A Policy is a list of PolicyRules. Each rule has:
//   - name:        human-readable identifier
//   - condition:   when this rule applies (which rings, which decisions)
//   - action:      what to do (Allow, Deny, Challenge, Escalate)
//   - reason:      human-readable explanation
//
// The Policy Engine evaluates rules in order. The FIRST matching rule
// wins. If no rule matches, the engine returns None (and the caller
// falls back to Fallback Rules).
//
// Default policy (v2.0.0):
//   1. "deny_on_shield_deny"         — if Shield denies, deny
//   2. "deny_on_threat_deny"         — if Threat denies, deny
//   3. "deny_on_identity_deny"      — if Identity denies, deny
//   4. "deny_on_memory_deny"         — if Memory denies, deny
//   5. "deny_on_agent_deny"          — if Agent denies, deny
//   6. "deny_on_execution_deny"      — if Execution denies, deny
//   7. "deny_on_risk_above_8"        — if composite risk >= 8.0, deny
//   8. "challenge_on_threat_mid"    — if Threat challenges, challenge
//   9. "challenge_on_identity_mid"  — if Identity challenges, challenge
//  10. "challenge_on_memory_mid"    — if Memory challenges, challenge
//  11. "allow_default"               — if all rings allow, allow

use super::decide::AllRingVerdicts;
use crate::decision::{Decision, RiskScore};
use crate::shield::ShieldVerdict;
use crate::threat::ThreatVerdict;

/// A policy is a versioned list of rules.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub version: String,
    pub rules: Vec<PolicyRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: "2.0.0".into(),
            rules: vec![
                // Deny rules — most restrictive first (first-match-wins)
                PolicyRule {
                    name: "deny_on_shield_deny".into(),
                    condition: RuleCondition::ShieldDeny,
                    action: RuleAction::PassThrough,
                    reason: "Shield Ring denied the request".into(),
                },
                PolicyRule {
                    name: "deny_on_threat_deny".into(),
                    condition: RuleCondition::ThreatDeny,
                    action: RuleAction::PassThrough,
                    reason: "Threat Ring denied the request".into(),
                },
                PolicyRule {
                    name: "deny_on_identity_deny".into(),
                    condition: RuleCondition::IdentityDeny,
                    action: RuleAction::PassThrough,
                    reason: "Identity Ring denied the request".into(),
                },
                PolicyRule {
                    name: "deny_on_memory_deny".into(),
                    condition: RuleCondition::MemoryDeny,
                    action: RuleAction::PassThrough,
                    reason: "Memory Ring denied the request".into(),
                },
                PolicyRule {
                    name: "deny_on_agent_deny".into(),
                    condition: RuleCondition::AgentDeny,
                    action: RuleAction::PassThrough,
                    reason: "Agent Ring denied the request".into(),
                },
                PolicyRule {
                    name: "deny_on_execution_deny".into(),
                    condition: RuleCondition::ExecutionDeny,
                    action: RuleAction::PassThrough,
                    reason: "Execution Ring denied the request".into(),
                },
                // Risk threshold
                PolicyRule {
                    name: "deny_on_risk_above_8".into(),
                    condition: RuleCondition::RiskAbove(8.0),
                    action: RuleAction::Deny("COMPOSITE_RISK_HIGH".into()),
                    reason: "composite risk score exceeds threshold".into(),
                },
                // Challenge rules
                PolicyRule {
                    name: "challenge_on_threat_challenge".into(),
                    condition: RuleCondition::ThreatChallenge,
                    action: RuleAction::PassThrough,
                    reason: "Threat Ring issued a challenge".into(),
                },
                PolicyRule {
                    name: "challenge_on_identity_challenge".into(),
                    condition: RuleCondition::IdentityChallenge,
                    action: RuleAction::PassThrough,
                    reason: "Identity Ring issued a challenge".into(),
                },
                PolicyRule {
                    name: "challenge_on_memory_challenge".into(),
                    condition: RuleCondition::MemoryChallenge,
                    action: RuleAction::PassThrough,
                    reason: "Memory Ring issued a challenge".into(),
                },
                // Default allow
                PolicyRule {
                    name: "allow_default".into(),
                    condition: RuleCondition::AllRingsAllow,
                    action: RuleAction::Allow,
                    reason: "all evaluated rings allowed the request".into(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    /// Shield Ring returned a Deny.
    ShieldDeny,
    /// Threat Ring returned a Deny.
    ThreatDeny,
    /// Threat Ring returned a Challenge.
    ThreatChallenge,
    /// Identity Ring returned a Deny.
    IdentityDeny,
    /// Identity Ring returned a Challenge.
    IdentityChallenge,
    /// Memory Ring returned a Deny.
    MemoryDeny,
    /// Memory Ring returned a Challenge.
    MemoryChallenge,
    /// Agent Ring returned a Deny.
    AgentDeny,
    /// Execution Ring returned a Deny.
    ExecutionDeny,
    /// All evaluated rings returned Allow.
    AllRingsAllow,
    /// Risk score exceeds a threshold.
    RiskAbove(f64),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Use the ring's own decision (pass through).
    PassThrough,
    /// Force allow.
    Allow,
    /// Force deny with a specific code.
    Deny(String),
    /// Force challenge.
    Challenge,
    /// Escalate to human review.
    Escalate,
}

/// Internal struct for legacy 2-ring evaluation path.
struct PartialVerdicts<'a> {
    shield: &'a ShieldVerdict,
    threat: Option<&'a ThreatVerdict>,
    risk: &'a RiskScore,
}

pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate ring verdicts against the policy (legacy 2-ring interface).
    pub fn evaluate(
        &self,
        shield: &ShieldVerdict,
        threat: Option<&ThreatVerdict>,
        risk: &RiskScore,
    ) -> Option<(Decision, Option<String>, String)> {
        let all = PartialVerdicts {
            shield,
            threat,
            risk,
        };
        self.evaluate_partial(&all)
    }

    /// Evaluate all 6 ring verdicts against the policy.
    pub fn evaluate_all(
        &self,
        all: &AllRingVerdicts<'_>,
        risk: &RiskScore,
    ) -> Option<(Decision, Option<String>, String)> {
        for rule in &self.policy.rules {
            if self.condition_matches_all(rule, all, risk) {
                let decision = self.apply_action_all(rule, all);
                return Some((decision, Some(rule.name.clone()), rule.reason.clone()));
            }
        }
        None
    }

    /// Internal: evaluate with partial verdicts (legacy compat).
    fn evaluate_partial(
        &self,
        partial: &PartialVerdicts<'_>,
    ) -> Option<(Decision, Option<String>, String)> {
        for rule in &self.policy.rules {
            if self.condition_matches_partial(rule, partial) {
                let decision = self.apply_action_partial(rule, partial);
                return Some((decision, Some(rule.name.clone()), rule.reason.clone()));
            }
        }
        None
    }

    fn condition_matches_all(
        &self,
        rule: &PolicyRule,
        all: &AllRingVerdicts<'_>,
        risk: &RiskScore,
    ) -> bool {
        match &rule.condition {
            RuleCondition::ShieldDeny => all.shield.decision.is_deny(),
            RuleCondition::ThreatDeny => all.threat.map(|t| t.decision.is_deny()).unwrap_or(false),
            RuleCondition::ThreatChallenge => all
                .threat
                .map(|t| matches!(t.decision, Decision::Challenge { .. }))
                .unwrap_or(false),
            RuleCondition::IdentityDeny => {
                all.identity.map(|i| i.decision.is_deny()).unwrap_or(false)
            }
            RuleCondition::IdentityChallenge => all
                .identity
                .map(|i| matches!(i.decision, Decision::Challenge { .. }))
                .unwrap_or(false),
            RuleCondition::MemoryDeny => all.memory.map(|m| m.decision.is_deny()).unwrap_or(false),
            RuleCondition::MemoryChallenge => all
                .memory
                .map(|m| matches!(m.decision, Decision::Challenge { .. }))
                .unwrap_or(false),
            RuleCondition::AgentDeny => all.agent.map(|a| a.decision.is_deny()).unwrap_or(false),
            RuleCondition::ExecutionDeny => {
                all.execution.map(|e| e.decision.is_deny()).unwrap_or(false)
            }
            RuleCondition::AllRingsAllow => {
                all.shield.decision.is_allow()
                    && all.threat.map(|t| t.decision.is_allow()).unwrap_or(true)
                    && all.identity.map(|i| i.decision.is_allow()).unwrap_or(true)
                    && all.memory.map(|m| m.decision.is_allow()).unwrap_or(true)
                    && all.agent.map(|a| a.decision.is_allow()).unwrap_or(true)
                    && all.execution.map(|e| e.decision.is_allow()).unwrap_or(true)
            }
            RuleCondition::RiskAbove(threshold) => risk.overall >= *threshold,
        }
    }

    fn apply_action_all(&self, rule: &PolicyRule, all: &AllRingVerdicts<'_>) -> Decision {
        match rule.action {
            RuleAction::PassThrough => {
                // Return the most restrictive ring's decision.
                if all.shield.decision.is_deny() {
                    return all.shield.decision.clone();
                }
                if let Some(t) = all.threat {
                    if t.decision.is_deny() {
                        return t.decision.clone();
                    }
                    if matches!(t.decision, Decision::Challenge { .. }) {
                        return t.decision.clone();
                    }
                }
                if let Some(i) = all.identity {
                    if i.decision.is_deny() {
                        return i.decision.clone();
                    }
                    if matches!(i.decision, Decision::Challenge { .. }) {
                        return i.decision.clone();
                    }
                }
                if let Some(m) = all.memory {
                    if m.decision.is_deny() {
                        return m.decision.clone();
                    }
                    if matches!(m.decision, Decision::Challenge { .. }) {
                        return m.decision.clone();
                    }
                }
                if let Some(a) = all.agent {
                    if a.decision.is_deny() {
                        return a.decision.clone();
                    }
                }
                if let Some(e) = all.execution {
                    if e.decision.is_deny() {
                        return e.decision.clone();
                    }
                }
                Decision::Allow
            }
            RuleAction::Allow => Decision::Allow,
            RuleAction::Deny(ref code) => Decision::Deny {
                code: code.clone(),
                retry_after: None,
            },
            RuleAction::Challenge => Decision::Challenge {
                challenge_type: crate::decision::ChallengeType::Javascript,
            },
            RuleAction::Escalate => Decision::Escalate {
                approver_role: "security_admin".into(),
                timeout_secs: 3600,
            },
        }
    }

    fn condition_matches_partial(&self, rule: &PolicyRule, partial: &PartialVerdicts<'_>) -> bool {
        match &rule.condition {
            RuleCondition::ShieldDeny => partial.shield.decision.is_deny(),
            RuleCondition::ThreatDeny => partial
                .threat
                .map(|t| t.decision.is_deny())
                .unwrap_or(false),
            RuleCondition::ThreatChallenge => partial
                .threat
                .map(|t| matches!(t.decision, Decision::Challenge { .. }))
                .unwrap_or(false),
            RuleCondition::IdentityDeny | RuleCondition::IdentityChallenge => false,
            RuleCondition::MemoryDeny | RuleCondition::MemoryChallenge => false,
            RuleCondition::AgentDeny => false,
            RuleCondition::ExecutionDeny => false,
            RuleCondition::AllRingsAllow => {
                partial.shield.decision.is_allow()
                    && partial
                        .threat
                        .map(|t| t.decision.is_allow())
                        .unwrap_or(true)
            }
            RuleCondition::RiskAbove(threshold) => partial.risk.overall >= *threshold,
        }
    }

    fn apply_action_partial(&self, rule: &PolicyRule, partial: &PartialVerdicts<'_>) -> Decision {
        match rule.action {
            RuleAction::PassThrough => {
                if partial.shield.decision.is_deny() {
                    return partial.shield.decision.clone();
                }
                if let Some(t) = partial.threat {
                    if t.decision.is_deny() {
                        return t.decision.clone();
                    }
                    if matches!(t.decision, Decision::Challenge { .. }) {
                        return t.decision.clone();
                    }
                }
                Decision::Allow
            }
            RuleAction::Allow => Decision::Allow,
            RuleAction::Deny(ref code) => Decision::Deny {
                code: code.clone(),
                retry_after: None,
            },
            RuleAction::Challenge => Decision::Challenge {
                challenge_type: crate::decision::ChallengeType::Javascript,
            },
            RuleAction::Escalate => Decision::Escalate {
                approver_role: "security_admin".into(),
                timeout_secs: 3600,
            },
        }
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
                code: "THREAT_DETECTED".into(),
                retry_after: None,
            },
            engine_results: vec![],
            composite_score: 0.9,
            confidence: 0.95,
            matched_signatures: vec!["JB-DAN-001".into()],
            latency_ms: 1.0,
        }
    }

    #[test]
    fn default_policy_denies_on_shield_deny() {
        let engine = PolicyEngine::new(Policy::default());
        let result = engine.evaluate(&shield_deny("WAF_SQLI"), None, &RiskScore::default());
        let (decision, name, _) = result.expect("rule matched");
        assert!(decision.is_deny());
        assert_eq!(name.as_deref(), Some("deny_on_shield_deny"));
    }

    #[test]
    fn default_policy_denies_on_threat_deny() {
        let engine = PolicyEngine::new(Policy::default());
        let result = engine.evaluate(&shield_allow(), Some(&threat_deny()), &RiskScore::default());
        let (decision, name, _) = result.expect("rule matched");
        assert!(decision.is_deny());
        assert_eq!(name.as_deref(), Some("deny_on_threat_deny"));
    }

    #[test]
    fn default_policy_allows_when_both_allow() {
        let engine = PolicyEngine::new(Policy::default());
        let result = engine.evaluate(
            &shield_allow(),
            Some(&threat_allow()),
            &RiskScore::default(),
        );
        let (decision, name, _) = result.expect("rule matched");
        assert!(decision.is_allow());
        assert_eq!(name.as_deref(), Some("allow_default"));
    }

    #[test]
    fn default_policy_allows_when_threat_absent() {
        // Principle 1: Decide works without Threat Ring.
        let engine = PolicyEngine::new(Policy::default());
        let result = engine.evaluate(&shield_allow(), None, &RiskScore::default());
        let (decision, _, _) = result.expect("rule matched");
        assert!(decision.is_allow());
    }

    #[test]
    fn custom_policy_can_override() {
        let policy = Policy {
            version: "custom".into(),
            rules: vec![PolicyRule {
                name: "always_deny".into(),
                condition: RuleCondition::AllRingsAllow,
                action: RuleAction::Deny("CUSTOM_DENY".into()),
                reason: "test override".into(),
            }],
        };
        let engine = PolicyEngine::new(policy);
        let result = engine.evaluate(
            &shield_allow(),
            Some(&threat_allow()),
            &RiskScore::default(),
        );
        let (decision, _, _) = result.expect("rule matched");
        assert!(decision.is_deny());
        if let Decision::Deny { code, .. } = decision {
            assert_eq!(code, "CUSTOM_DENY");
        }
    }
}
