// Recovery Planner — analyzes threats and chooses recovery strategy.
//
// This is the BRAIN of Phoenix. It doesn't just react — it PLANS.
//
// Decision matrix:
//   - Trust level of affected domain
//   - Z-score of drift
//   - Number of consecutive failures
//   - Available recovery strategies
//   - Recovery history (what worked before)
//   - Rate limiting (max actions per hour)
//
// Output: ordered list of RecoveryActions, or "do nothing."

use crate::ananta::phoenix::strategies::{RecoveryAction, RecoveryStrategy};
use crate::ananta::phoenix::recovery_history::RecoveryHistory;
use crate::ananta::config::PhoenixConfig;
use serde::{Deserialize, Serialize};

/// A planned recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub actions: Vec<PlannedAction>,
    pub rationale: String,
    pub estimated_impact: String,
}

/// A single action in the plan with reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action: RecoveryAction,
    pub reasoning: String,
    pub expected_outcome: String,
}

/// The recovery planner.
pub struct RecoveryPlanner {
    config: PhoenixConfig,
    /// Rate limiting: actions in the current hour window.
    recent_actions: Vec<String>,
}

impl RecoveryPlanner {
    pub fn new(config: PhoenixConfig) -> Self {
        Self {
            config,
            recent_actions: vec![],
        }
    }

    /// Plan recovery for a threat.
    ///
    /// Returns a RecoveryPlan with 0 or more actions.
    /// Returns empty plan if:
    ///   - Rate limited
    ///   - Confidence too low
    ///   - Observe strategy is most appropriate
    pub fn plan(
        &mut self,
        domain: &str,
        trust_level: f64,
        z_score: f64,
        consecutive_failures: u64,
        history: &RecoveryHistory,
    ) -> RecoveryPlan {
        // Rate limit check.
        if self.recent_actions.len() >= self.config.max_recovery_actions_per_hour as usize {
            return RecoveryPlan {
                actions: vec![],
                rationale: "Rate limited: max recovery actions per hour reached".into(),
                estimated_impact: "none".into(),
            };
        }

        let mut plan = RecoveryPlan {
            actions: vec![],
            rationale: String::new(),
            estimated_impact: String::new(),
        };

        // Decision logic.
        let severity = self.assess_severity(trust_level, z_score, consecutive_failures);

        match severity {
            Severity::Low => {
                // Just observe.
                plan.rationale = "Low severity: increasing monitoring frequency".into();
                plan.estimated_impact = "Minimal — observation only".into();
                // Don't add an action — observation is the default.
            }
            Severity::Medium => {
                // Check if a recovery has worked before.
                let past = history.actions_for(domain);
                let (successes, _, _) = history.success_rate();

                if !past.is_empty() && successes > 0 {
                    // Repeat what worked.
                    let last_success = past.iter().rev().find(|r| r.outcome == super::RecoveryOutcome::Success);
                    if let Some(r) = last_success {
                        let action = RecoveryAction::new(
                            RecoveryStrategy::Restart,
                            domain,
                            &format!("repeating successful strategy: {:?}", r.action.strategy),
                        )
                        .with_confidence(0.8)
                        .with_priority(5);

                        plan.actions.push(PlannedAction {
                            action,
                            reasoning: format!(
                                "Previous {:?} succeeded for {}. Trust={:.2}, z={:.1}",
                                r.action.strategy, domain, trust_level, z_score,
                            ),
                            expected_outcome: "Component recovers to normal operation".into(),
                        });
                    }
                } else {
                    // No history — observe.
                    plan.rationale = "Medium severity but no recovery history. Observing.".into();
                }
            }
            Severity::High => {
                // Aggressive recovery.
                let action = if trust_level < 0.1 {
                    // Very low trust — quarantine.
                    RecoveryAction::new(
                        RecoveryStrategy::Quarantine,
                        domain,
                        &format!("trust critically low ({:.2}), quarantining", trust_level),
                    ).with_confidence(0.9).with_priority(9)
                } else {
                    // High z-score but some trust — try restart.
                    RecoveryAction::new(
                        RecoveryStrategy::Restart,
                        domain,
                        &format!("high drift z={:.1}, restarting", z_score),
                    ).with_confidence(0.9).with_priority(7)
                };

                plan.actions.push(PlannedAction {
                    action,
                    reasoning: format!(
                        "High severity: trust={:.2}, z={:.1}, failures={}. Taking aggressive action.",
                        trust_level, z_score, consecutive_failures,
                    ),
                    expected_outcome: "Component recovers or is isolated".into(),
                });
                plan.rationale = "High severity: aggressive recovery required".into();
                plan.estimated_impact = "Temporary disruption to affected domain".into();
            }
            Severity::Critical => {
                // Escalate to human + quarantine.
                plan.actions.push(PlannedAction {
                    action: RecoveryAction::new(
                        RecoveryStrategy::Quarantine,
                        domain,
                        &format!("CRITICAL: trust={:.2}, quarantining immediately", trust_level),
                    ).with_confidence(0.95).with_priority(10),
                    reasoning: "Critical trust failure. Isolating component.".into(),
                    expected_outcome: "Component isolated, human review required".into(),
                });
                plan.actions.push(PlannedAction {
                    action: RecoveryAction::new(
                        RecoveryStrategy::Escalate,
                        domain,
                        "Critical: requires human intervention",
                    ).with_confidence(1.0).with_priority(10),
                    reasoning: "Critical severity always escalates to human.".into(),
                    expected_outcome: "Human operator makes final decision".into(),
                });
                plan.rationale = "CRITICAL: quarantine + escalate to human".into();
                plan.estimated_impact = "Domain isolated pending human review".into();
            }
        }

        // Filter by confidence threshold.
        plan.actions.retain(|a| a.action.confidence >= self.config.action_confidence_threshold);

        // Record planned actions for rate limiting.
        for a in &plan.actions {
            self.recent_actions.push(a.action.action_id.clone());
        }

        plan
    }

    /// Assess severity from trust level, z-score, and consecutive failures.
    fn assess_severity(&self, trust_level: f64, z_score: f64, consecutive_failures: u64) -> Severity {
        // Critical: very low trust OR very high z-score OR many consecutive failures.
        if trust_level < 0.1 || z_score > 10.0 || consecutive_failures > 10 {
            return Severity::Critical;
        }
        // High: low trust OR high z-score OR moderate failures.
        if trust_level < 0.3 || z_score > 6.0 || consecutive_failures > 5 {
            return Severity::High;
        }
        // Medium: some trust degradation.
        if trust_level < 0.7 || z_score > 3.0 || consecutive_failures > 2 {
            return Severity::Medium;
        }
        // Low: minor anomaly.
        Severity::Low
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::config::HashAlgorithm;

    fn make_planner() -> RecoveryPlanner {
        RecoveryPlanner::new(PhoenixConfig::default())
    }

    fn empty_history() -> RecoveryHistory {
        RecoveryHistory::new(HashAlgorithm::Sha256)
    }

    #[test]
    fn low_severity_observes() {
        let mut planner = make_planner();
        let plan = planner.plan("policy", 0.9, 1.0, 0, &empty_history());
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn high_severity_plans_restart() {
        let mut planner = make_planner();
        let plan = planner.plan("shield", 0.2, 7.0, 6, &empty_history());
        assert!(!plan.actions.is_empty());
        assert_eq!(plan.actions[0].action.strategy, RecoveryStrategy::Restart);
    }

    #[test]
    fn critical_severity_quarantines_and_escalates() {
        let mut planner = make_planner();
        let plan = planner.plan("keshav", 0.05, 15.0, 20, &empty_history());
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(plan.actions[0].action.strategy, RecoveryStrategy::Quarantine);
        assert_eq!(plan.actions[1].action.strategy, RecoveryStrategy::Escalate);
    }

    #[test]
    fn rate_limiting_works() {
        let mut planner = RecoveryPlanner::new(PhoenixConfig {
            max_recovery_actions_per_hour: 2,
            ..Default::default()
        });
        // Use up the budget.
        planner.recent_actions.push("a".into());
        planner.recent_actions.push("b".into());
        let plan = planner.plan("test", 0.0, 20.0, 100, &empty_history());
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn confidence_filter() {
        let mut planner = RecoveryPlanner::new(PhoenixConfig {
            action_confidence_threshold: 0.9,
            ..Default::default()
        });
        // Medium severity actions have confidence 0.8 — should be filtered.
        let plan = planner.plan("test", 0.5, 4.0, 3, &empty_history());
        assert!(plan.actions.is_empty());
    }
}