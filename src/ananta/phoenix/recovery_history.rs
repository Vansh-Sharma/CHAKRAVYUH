// Recovery History — immutable, auditable log of all recovery actions.
//
// Uses the TrustChain for tamper-evidence.
// Every recovery action is chained, signed, and不可篡改.

use crate::ananta::anchor::TrustChain;
use crate::ananta::phoenix::strategies::{RecoveryAction, RecoveryResult};
use serde::{Deserialize, Serialize};

/// Immutable history of recovery actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryHistory {
    chain: TrustChain,
    /// All recovery results (indexed by action_id).
    results: Vec<RecoveryResult>,
}

impl RecoveryHistory {
    pub fn new(algorithm: crate::ananta::config::HashAlgorithm) -> Self {
        Self {
            chain: TrustChain::new(algorithm),
            results: vec![],
        }
    }

    /// Record a recovery action and result.
    pub fn record(&mut self, action: &RecoveryAction, result: &RecoveryResult) {
        // Append to trust chain.
        self.chain.append(
            "recovery",
            serde_json::json!({
                "action_id": action.action_id,
                "strategy": format!("{:?}", action.strategy),
                "target": action.target,
                "outcome": format!("{:?}", result.outcome),
                "confidence": action.confidence,
                "duration_ms": result.duration_ms,
                "message": result.message,
            }),
        );

        self.results.push(result.clone());
    }

    /// Get total recovery actions.
    pub fn total_actions(&self) -> usize {
        self.results.len()
    }

    /// Get success/failure counts.
    pub fn success_rate(&self) -> (usize, usize, f64) {
        let total = self.results.len();
        let successes = self.results.iter().filter(|r| r.outcome == super::RecoveryOutcome::Success).count();
        let rate = if total > 0 { successes as f64 / total as f64 } else { 1.0 };
        (successes, total - successes, rate)
    }

    /// Get actions for a specific target.
    pub fn actions_for(&self, target: &str) -> Vec<&RecoveryResult> {
        self.results.iter().filter(|r| r.action.target == target).collect()
    }

    /// Verify chain integrity.
    pub fn verify_chain(&self) -> bool {
        self.chain.verify().is_none()
    }

    /// Recent actions (last N).
    pub fn recent(&self, n: usize) -> &[RecoveryResult] {
        let start = self.results.len().saturating_sub(n);
        &self.results[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ananta::config::HashAlgorithm;
    use crate::ananta::RecoveryStrategy;

    #[test]
    fn record_and_retrieve() {
        let mut history = RecoveryHistory::new(HashAlgorithm::Sha256);
        let action = RecoveryAction::new(RecoveryStrategy::Restart, "shield", "degraded");
        let result = RecoveryResult::success(action.clone(), "restarted", 10.0);
        history.record(&action, &result);

        assert_eq!(history.total_actions(), 1);
        assert!(history.verify_chain());
    }

    #[test]
    fn success_rate() {
        let mut history = RecoveryHistory::new(HashAlgorithm::Sha256);

        for i in 0..7 {
            let action = RecoveryAction::new(RecoveryStrategy::Restart, "ring", "test");
            let outcome = if i < 5 {
                RecoveryResult::success(action.clone(), "ok", 1.0)
            } else {
                RecoveryResult::failed(action.clone(), "failed", 1.0)
            };
            history.record(&action, &outcome);
        }

        let (s, f, rate) = history.success_rate();
        assert_eq!(s, 5);
        assert_eq!(f, 2);
        assert!((rate - 0.714).abs() < 0.01);
    }

    #[test]
    fn recent_returns_last_n() {
        let mut history = RecoveryHistory::new(HashAlgorithm::Sha256);
        for i in 0..10 {
            let action = RecoveryAction::new(RecoveryStrategy::Observe, "test", &format!("{}", i));
            let result = RecoveryResult::success(action.clone(), "observed", 1.0);
            history.record(&action, &result);
        }

        assert_eq!(history.recent(3).len(), 3);
    }
}
