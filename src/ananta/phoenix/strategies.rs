// Recovery Strategies — intentional, auditable recovery actions.
//
// Each strategy has:
//   1. Pre-condition check (should we act?)
//   2. Execute (the actual recovery)
//   3. Verify (did it work?)
//   4. Rollback (if it made things worse)

use serde::{Deserialize, Serialize};

/// The type of recovery action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    /// Restart a ring or subsystem.
    Restart,
    /// Revert configuration/policy to last-known-good state.
    Rollback,
    /// Isolate a degraded component (stop routing to it).
    Quarantine,
    /// Do nothing — increase monitoring frequency.
    Observe,
    /// Alert human operator.
    Escalate,
    /// Reset learning thresholds to defaults.
    ResetThresholds,
    /// Reload policy from file.
    ReloadPolicy,
    /// Reconfigure the pipeline (via Adapter).
    ReconfigurePipeline,
}

impl std::fmt::Display for RecoveryStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A recovery action to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAction {
    /// Unique action ID.
    pub action_id: String,
    /// The strategy to use.
    pub strategy: RecoveryStrategy,
    /// Target component (ring name, subsystem, etc.).
    pub target: String,
    /// The reason this recovery was triggered.
    pub reason: String,
    /// The drift alert or integrity failure that triggered this.
    pub trigger: Option<String>,
    /// Confidence that this recovery will succeed (0.0-1.0).
    pub confidence: f64,
    /// Priority (higher = more urgent).
    pub priority: u8,
}

impl RecoveryAction {
    pub fn new(strategy: RecoveryStrategy, target: &str, reason: &str) -> Self {
        Self {
            action_id: uuid::Uuid::new_v4().to_string(),
            strategy,
            target: target.into(),
            reason: reason.into(),
            trigger: None,
            confidence: 0.5,
            priority: 5,
        }
    }

    pub fn with_confidence(mut self, c: f64) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn with_priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    pub fn with_trigger(mut self, trigger: &str) -> Self {
        self.trigger = Some(trigger.into());
        self
    }
}

/// Result of executing a recovery action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub action: RecoveryAction,
    pub outcome: RecoveryOutcome,
    pub message: String,
    pub duration_ms: f64,
    pub timestamp: String,
    /// Post-recovery trust level (if measurable).
    pub post_trust_level: Option<f64>,
    /// Whether a human should be notified.
    pub requires_human_review: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    Success,
    Failed,
    Skipped,
    Escalated,
}

impl std::fmt::Display for RecoveryOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
            Self::Escalated => write!(f, "escalated"),
        }
    }
}

impl RecoveryResult {
    pub fn success(action: RecoveryAction, message: &str, duration_ms: f64) -> Self {
        Self {
            action,
            outcome: RecoveryOutcome::Success,
            message: message.into(),
            duration_ms,
            timestamp: chrono::Utc::now().to_rfc3339(),
            post_trust_level: None,
            requires_human_review: false,
        }
    }

    pub fn failed(action: RecoveryAction, message: &str, duration_ms: f64) -> Self {
        Self {
            action,
            outcome: RecoveryOutcome::Failed,
            message: message.into(),
            duration_ms,
            timestamp: chrono::Utc::now().to_rfc3339(),
            post_trust_level: None,
            requires_human_review: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_builder() {
        let action = RecoveryAction::new(
            RecoveryStrategy::Rollback,
            "policy",
            "policy integrity check failed",
        )
        .with_confidence(0.9)
        .with_priority(8)
        .with_trigger("drift:policy z=5.2");

        assert_eq!(action.strategy, RecoveryStrategy::Rollback);
        assert_eq!(action.confidence, 0.9);
        assert_eq!(action.priority, 8);
        assert!(action.trigger.is_some());
    }

    #[test]
    fn result_success() {
        let action = RecoveryAction::new(RecoveryStrategy::Restart, "shield", "ring degraded");
        let result = RecoveryResult::success(action, "shield restarted", 12.5);
        assert_eq!(result.outcome, RecoveryOutcome::Success);
        assert!(!result.requires_human_review);
    }

    #[test]
    fn result_failed() {
        let action = RecoveryAction::new(RecoveryStrategy::Rollback, "policy", "tampered");
        let result = RecoveryResult::failed(action, "rollback failed", 5.0);
        assert_eq!(result.outcome, RecoveryOutcome::Failed);
        assert!(result.requires_human_review);
    }
}
