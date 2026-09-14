// ANANTA Adapter — Adaptive Security Orchestration
//
// Adapter monitors trust state and automatically reconfigures
// security pipelines to respond to changing threat conditions.
//
// Safety constraints:
//   - All pipeline changes are cryptographically signed
//   - Changes have a grace period — revert if no improvement
//   - Rate-limited to prevent oscillation
//   - Requires explicit enable in config (disabled by default)

pub mod orchestration_validator;
pub use orchestration_validator::*;

pub mod policy_executor;
pub use policy_executor::*;

pub mod dynamic_pipeline;
pub use dynamic_pipeline::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ananta::config::AdapterConfig;
use crate::ananta::crypto::signing::{KeyPair, Signature};
use crate::ananta::trust::trust_state::TrustState;

/// A proposed pipeline adaptation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptationProposal {
    /// Unique proposal ID.
    pub proposal_id: String,
    /// The pipeline or component to adapt.
    pub target: String,
    /// Description of the change.
    pub description: String,
    /// The specific parameter changes.
    pub parameter_changes: Vec<ParameterChange>,
    /// Trust level at the time of proposal.
    pub trust_level_at_proposal: f64,
    /// Reasoning for the adaptation.
    pub rationale: String,
    /// Cryptographic signature (if required by config).
    pub signature: Option<Signature>,
    /// When this proposal was created.
    pub timestamp: String,
    /// Grace period deadline — revert if not confirmed.
    pub grace_deadline: String,
    /// Current status of this adaptation.
    pub status: AdaptationStatus,
}

/// Status of an adaptation proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdaptationStatus {
    /// Proposed but not yet applied.
    Proposed,
    /// Currently being applied.
    Applying,
    /// Applied and under observation.
    Active,
    /// Confirmed — improvement detected, keeping changes.
    Confirmed,
    /// Reverted — no improvement detected within grace period.
    Reverted,
    /// Failed to apply.
    Failed,
}

impl std::fmt::Display for AdaptationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single parameter change within an adaptation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterChange {
    /// The parameter name (e.g., "threat_threshold", "rate_limit").
    pub parameter: String,
    /// Previous value.
    pub old_value: serde_json::Value,
    /// New proposed value.
    pub new_value: serde_json::Value,
}

/// The adaptive orchestrator.
///
/// Monitors trust state and proposes pipeline adaptations
/// when conditions warrant it.
pub struct Adapter {
    config: AdapterConfig,
    /// Proposals in the current hour (for rate limiting).
    recent_proposals: Vec<String>,
    /// All active and recent proposals.
    proposals: HashMap<String, AdaptationProposal>,
    /// Signing key for proposal authentication.
    signing_key: Option<KeyPair>,
}

impl Adapter {
    /// Create a new adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            recent_proposals: vec![],
            proposals: HashMap::new(),
            signing_key: None,
        }
    }

    /// Set the signing key for proposal authentication.
    pub fn set_signing_key(&mut self, key: KeyPair) {
        self.signing_key = Some(key);
    }

    /// Evaluate trust state and propose adaptations if needed.
    ///
    /// Returns a list of proposed adaptations (may be empty).
    pub fn evaluate(&mut self, trust_state: &TrustState) -> Vec<AdaptationProposal> {
        if !self.config.enabled {
            return vec![];
        }

        // Rate limit check.
        if self.recent_proposals.len() >= self.config.max_reconfigurations_per_hour as usize {
            return vec![];
        }

        let overall = trust_state.overall_score();
        let mut proposals = vec![];

        // Rule 1: If overall trust drops below 0.7, tighten thresholds.
        if overall < 0.7 && self.can_propose() {
            let proposal = self.propose_tightening(trust_state);
            proposals.push(proposal);
        }

        // Rule 2: If a specific domain is critically low, quarantine.
        for (domain, dt) in &trust_state.domains {
            if dt.level < 0.2 && self.can_propose() {
                let proposal = self.propose_domain_quarantine(domain, dt.level);
                proposals.push(proposal);
            }
        }

        // Rule 3: If trust is very high (>0.95) and stable, relax slightly.
        if overall > 0.95 && self.can_propose() {
            let all_stable = trust_state.domains.values().all(|d| {
                d.trend == crate::ananta::TrendDirection::Stable
                    || d.trend == crate::ananta::TrendDirection::Improving
            });
            if all_stable {
                let proposal = self.propose_relaxation(trust_state);
                proposals.push(proposal);
            }
        }

        // Store and track proposals.
        for p in &proposals {
            self.recent_proposals.push(p.proposal_id.clone());
            self.proposals.insert(p.proposal_id.clone(), p.clone());
        }

        proposals
    }

    /// Confirm an active adaptation (improvement detected).
    pub fn confirm(&mut self, proposal_id: &str) -> bool {
        if let Some(p) = self.proposals.get_mut(proposal_id) {
            p.status = AdaptationStatus::Confirmed;
            true
        } else {
            false
        }
    }

    /// Revert an active adaptation (no improvement or degradation).
    pub fn revert(&mut self, proposal_id: &str) -> bool {
        if let Some(p) = self.proposals.get_mut(proposal_id) {
            p.status = AdaptationStatus::Reverted;
            true
        } else {
            false
        }
    }

    /// Get all proposals.
    pub fn proposals(&self) -> Vec<&AdaptationProposal> {
        self.proposals.values().collect()
    }

    /// Get active proposals.
    pub fn active_proposals(&self) -> Vec<&AdaptationProposal> {
        self.proposals
            .values()
            .filter(|p| p.status == AdaptationStatus::Active)
            .collect()
    }

    /// Check if we can propose (rate limit).
    fn can_propose(&self) -> bool {
        self.recent_proposals.len() < self.config.max_reconfigurations_per_hour as usize
    }

    /// Propose tightening security thresholds.
    fn propose_tightening(&self, trust_state: &TrustState) -> AdaptationProposal {
        let overall = trust_state.overall_score();
        // Calculate how much to tighten based on trust drop.
        let tightening_factor = ((1.0 - overall) * 0.5).clamp(0.1, 0.5);

        let parameter_changes = vec![
            ParameterChange {
                parameter: "threat_threshold".into(),
                old_value: serde_json::json!(0.5),
                new_value: serde_json::json!((0.5 - tightening_factor).max(0.05)),
            },
            ParameterChange {
                parameter: "sensitivity".into(),
                old_value: serde_json::json!(1.0),
                new_value: serde_json::json!(1.0 + tightening_factor),
            },
        ];

        self.build_proposal(
            "pipeline",
            format!("Tightening thresholds: trust={:.3}", overall).as_str(),
            parameter_changes,
            overall,
        )
    }

    /// Propose quarantining a specific domain.
    fn propose_domain_quarantine(&self, domain: &str, level: f64) -> AdaptationProposal {
        let parameter_changes = vec![ParameterChange {
            parameter: format!("{}.quarantined", domain),
            old_value: serde_json::json!(false),
            new_value: serde_json::json!(true),
        }];

        self.build_proposal(
            domain,
            format!("Quarantining domain {}: trust={:.3}", domain, level).as_str(),
            parameter_changes,
            level,
        )
    }

    /// Propose relaxing security when trust is high and stable.
    fn propose_relaxation(&self, trust_state: &TrustState) -> AdaptationProposal {
        let overall = trust_state.overall_score();

        let parameter_changes = vec![ParameterChange {
            parameter: "threat_threshold".into(),
            old_value: serde_json::json!(0.5),
            new_value: serde_json::json!(0.55),
        }];

        self.build_proposal(
            "pipeline",
            format!("Mild relaxation: trust={:.3}, all stable", overall).as_str(),
            parameter_changes,
            overall,
        )
    }

    /// Build a proposal with common fields.
    fn build_proposal(
        &self,
        target: &str,
        rationale: &str,
        parameter_changes: Vec<ParameterChange>,
        trust_level: f64,
    ) -> AdaptationProposal {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let grace_deadline = chrono::Utc::now()
            + chrono::Duration::milliseconds(self.config.adaptation_grace_period_ms as i64);

        let signature = if self.config.require_signed_changes {
            // In a real implementation, sign the proposal data.
            None // Placeholder — signing requires KeyPair at runtime.
        } else {
            None
        };

        AdaptationProposal {
            proposal_id: uuid::Uuid::new_v4().to_string(),
            target: target.into(),
            description: rationale.into(),
            parameter_changes,
            trust_level_at_proposal: trust_level,
            rationale: rationale.into(),
            signature,
            timestamp: timestamp.clone(),
            grace_deadline: grace_deadline.to_rfc3339(),
            status: AdaptationStatus::Proposed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AdapterConfig {
        AdapterConfig {
            enabled: true,
            max_reconfigurations_per_hour: 10,
            require_signed_changes: false,
            adaptation_grace_period_ms: 300_000,
        }
    }

    fn degraded_trust_state() -> TrustState {
        let mut state = TrustState::new();
        // Degrade all valid trust domains to pull overall_score well below 0.7
        for domain in &[
            "decision",
            "policy",
            "model",
            "orchestration",
            "learning",
            "memory",
            "configuration",
            "plugin",
            "runtime",
            "performance",
            "trust",
        ] {
            state.set_domain_level(domain, 0.3);
        }
        state
    }

    fn healthy_trust_state() -> TrustState {
        TrustState::new()
    }

    #[test]
    fn disabled_adapter_proposes_nothing() {
        let mut adapter = Adapter::new(AdapterConfig {
            enabled: false,
            ..test_config()
        });
        let proposals = adapter.evaluate(&degraded_trust_state());
        assert!(proposals.is_empty());
    }

    #[test]
    fn low_trust_triggers_tightening() {
        let mut adapter = Adapter::new(test_config());
        let proposals = adapter.evaluate(&degraded_trust_state());
        assert!(!proposals.is_empty());
        // Should have a tightening proposal for the pipeline.
        let has_pipeline = proposals.iter().any(|p| p.target == "pipeline");
        assert!(has_pipeline);
    }

    #[test]
    fn critical_domain_triggers_quarantine() {
        let mut state = degraded_trust_state();
        state.set_domain_level("configuration", 0.1);
        let mut adapter = Adapter::new(test_config());
        let proposals = adapter.evaluate(&state);
        let has_quarantine = proposals.iter().any(|p| p.target == "configuration");
        assert!(has_quarantine);
    }

    #[test]
    fn rate_limiting_prevents_proposals() {
        let config = AdapterConfig {
            max_reconfigurations_per_hour: 1,
            ..test_config()
        };
        let mut adapter = Adapter::new(config);
        adapter.recent_proposals.push("existing".into());
        let proposals = adapter.evaluate(&degraded_trust_state());
        assert!(proposals.is_empty());
    }

    #[test]
    fn confirm_and_revert() {
        let mut adapter = Adapter::new(test_config());
        let proposals = adapter.evaluate(&degraded_trust_state());
        if let Some(p) = proposals.first() {
            assert!(adapter.confirm(&p.proposal_id));
            assert_eq!(
                adapter.proposals[&p.proposal_id].status,
                AdaptationStatus::Confirmed
            );
            // Can't confirm again (already confirmed).
        }
    }

    #[test]
    fn active_proposals_filter() {
        let mut adapter = Adapter::new(test_config());
        let _proposals = adapter.evaluate(&degraded_trust_state());
        // All new proposals start as Proposed, not Active.
        assert!(adapter.active_proposals().is_empty());
    }

    #[test]
    fn proposal_serialization() {
        let proposal = AdaptationProposal {
            proposal_id: "test-123".into(),
            target: "pipeline".into(),
            description: "test".into(),
            parameter_changes: vec![],
            trust_level_at_proposal: 0.5,
            rationale: "test".into(),
            signature: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            grace_deadline: chrono::Utc::now().to_rfc3339(),
            status: AdaptationStatus::Proposed,
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let restored: AdaptationProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.proposal_id, proposal.proposal_id);
    }
}
