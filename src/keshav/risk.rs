// Keshav-Risk — Composite Risk Scoring
//
// Phase 4 version: Weighted average of ring scores.
// Phase 6 (full version): ML-based dynamic weighting (future).
//
// Computes composite risk score from ring verdicts:
//   risk_overall = w_threat    * threat_score
//                + w_identity  * identity_score
//                + w_behavior  * agent_score      (from Agent Ring)
//                + w_memory    * memory_score     (from Memory Ring)
//                + w_execution * execution_score
//                + w_context   * context_score
//
// confidence = 1.0 - (variance(ring_scores) / max_possible_variance)
//
// Latency Budget: <0.5ms p99

use crate::decision::RiskScore;

/// Keshav-Risk configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RiskConfig {
    /// Weight for Threat Ring score (default: 0.30).
    #[serde(default = "default_w_threat")]
    pub w_threat: f64,
    /// Weight for Identity Ring score (default: 0.15).
    #[serde(default = "default_w_identity")]
    pub w_identity: f64,
    /// Weight for Agent Ring behavior score (default: 0.15).
    #[serde(default = "default_w_behavior")]
    pub w_behavior: f64,
    /// Weight for Memory Ring score (default: 0.10).
    #[serde(default = "default_w_memory")]
    pub w_memory: f64,
    /// Weight for Execution Ring score (default: 0.15).
    #[serde(default = "default_w_execution")]
    pub w_execution: f64,
    /// Weight for Reasoning Ring score (default: 0.05).
    #[serde(default = "default_w_reasoning")]
    pub w_reasoning: f64,
    /// Weight for Governance Ring score (default: 0.05).
    #[serde(default = "default_w_governance")]
    pub w_governance: f64,
    /// Weight for Recovery Ring score (default: 0.05).
    #[serde(default = "default_w_recovery")]
    pub w_recovery: f64,
    /// Weight for contextual signals (default: 0.10).
    #[serde(default = "default_w_context")]
    pub w_context: f64,
}

fn default_w_threat() -> f64 { 0.30 }
fn default_w_identity() -> f64 { 0.15 }
fn default_w_behavior() -> f64 { 0.15 }
fn default_w_memory() -> f64 { 0.10 }
fn default_w_execution() -> f64 { 0.15 }
fn default_w_reasoning() -> f64 { 0.05 }
fn default_w_governance() -> f64 { 0.05 }
fn default_w_recovery() -> f64 { 0.05 }
fn default_w_context() -> f64 { 0.10 }

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            w_threat: default_w_threat(),
            w_identity: default_w_identity(),
            w_behavior: default_w_behavior(),
            w_memory: default_w_memory(),
            w_execution: default_w_execution(),
            w_reasoning: default_w_reasoning(),
            w_governance: default_w_governance(),
            w_recovery: default_w_recovery(),
            w_context: default_w_context(),
        }
    }
}

/// Input signals for risk scoring.
#[derive(Debug, Clone)]
pub struct RiskSignals {
    /// Normalized threat score (0.0-10.0). None if Threat Ring is disabled.
    pub threat_score: Option<f64>,
    /// Normalized identity risk score (0.0-10.0). None if Identity Ring is disabled.
    pub identity_score: Option<f64>,
    /// Normalized agent behavior risk score (0.0-10.0). None if Agent Ring is disabled.
    pub agent_score: Option<f64>,
    /// Normalized memory risk score (0.0-10.0). None if Memory Ring is disabled.
    pub memory_score: Option<f64>,
    /// Normalized execution risk score (0.0-10.0). None if Execution Ring is not evaluated.
    pub execution_score: Option<f64>,
    /// Normalized reasoning risk score (0.0-10.0). None if Reasoning Ring is not evaluated.
    pub reasoning_score: Option<f64>,
    /// Normalized governance risk score (0.0-10.0). None if Governance Ring is not evaluated.
    pub governance_score: Option<f64>,
    /// Normalized recovery risk score (0.0-10.0). None if Recovery Ring is not evaluated.
    pub recovery_score: Option<f64>,
    /// Contextual signals.
    pub context: ContextSignals,
}

/// Contextual risk signals (computed from request metadata).
#[derive(Debug, Clone, Default)]
pub struct ContextSignals {
    /// Time-of-day risk (0.0-1.0). Higher during off-hours.
    pub time_of_day_risk: f64,
    /// Request rate anomaly (0.0-1.0). Higher for unusual burst patterns.
    pub rate_anomaly: f64,
    /// Source reputation (0.0-1.0). Higher = more trusted.
    pub source_reputation: f64,
}

impl ContextSignals {
    /// Compute basic contextual risk score (0.0-10.0).
    pub fn to_score(&self) -> f64 {
        // Context score is a blend of factors:
        // High off-hours + high anomaly + low reputation = high risk
        let risk = (self.time_of_day_risk * 0.4 + self.rate_anomaly * 0.3 + (1.0 - self.source_reputation) * 0.3) * 10.0;
        risk.clamp(0.0, 10.0)
    }
}

/// Keshav-Risk — composite risk scorer.
///
/// Phase 3 version uses simple weighted average.
/// Weights are configurable. Scores are normalized to 0-10 scale.
#[derive(Clone)]
pub struct KeshavRisk {
    config: RiskConfig,
}

impl KeshavRisk {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(RiskConfig::default())
    }

    /// Compute a composite risk score from ring signals.
    ///
    /// Returns a `RiskScore` with per-dimension decomposition.
    pub fn evaluate(&self, signals: &RiskSignals) -> RiskScore {
        let threat = signals.threat_score.unwrap_or(0.0);
        let identity = signals.identity_score.unwrap_or(0.0);
        let behavior = signals.agent_score.unwrap_or(0.0);
        let memory = signals.memory_score.unwrap_or(0.0);
        let execution = signals.execution_score.unwrap_or(0.0);
        let reasoning = signals.reasoning_score.unwrap_or(0.0);
        let governance = signals.governance_score.unwrap_or(0.0);
        let recovery = signals.recovery_score.unwrap_or(0.0);
        let context = signals.context.to_score();

        let overall = self.config.w_threat * threat
            + self.config.w_identity * identity
            + self.config.w_behavior * behavior
            + self.config.w_memory * memory
            + self.config.w_execution * execution
            + self.config.w_reasoning * reasoning
            + self.config.w_governance * governance
            + self.config.w_recovery * recovery
            + self.config.w_context * context;

        // Confidence based on how many signals contributed.
        let mut contributing = 0u32;
        if signals.threat_score.is_some() { contributing += 1; }
        if signals.identity_score.is_some() { contributing += 1; }
        if signals.agent_score.is_some() { contributing += 1; }
        if signals.memory_score.is_some() { contributing += 1; }
        if signals.execution_score.is_some() { contributing += 1; }
        if signals.reasoning_score.is_some() { contributing += 1; }
        if signals.governance_score.is_some() { contributing += 1; }
        if signals.recovery_score.is_some() { contributing += 1; }
        contributing += 1; // context always contributes

        // More signals -> higher confidence. 1 signal -> 0.11, 10 -> 1.0
        let confidence = (contributing as f64 / 10.0).clamp(0.11, 1.0);

        RiskScore {
            overall: overall.clamp(0.0, 10.0),
            threat,
            identity,
            behavior,
            memory,
            execution,
            context,
            confidence,
        }
    }

    /// Get the risk configuration (for introspection).
    pub fn config(&self) -> &RiskConfig {
        &self.config
    }
}

/// Convert a Threat Ring composite score to a normalized risk score (0-10).
/// The Threat Ring already outputs 0-10, so this is a passthrough.
pub fn threat_to_risk_score(composite_score: f64) -> f64 {
    composite_score.clamp(0.0, 10.0)
}

/// Convert an Execution Ring decision to a risk score.
/// Deny = 10.0, Escalate = 7.0, Challenge = 4.0, Allow = 0.0.
pub fn execution_to_risk_score(decision: &crate::decision::Decision) -> f64 {
    match decision {
        crate::decision::Decision::Deny { .. } => 10.0,
        crate::decision::Decision::Escalate { .. } => 7.0,
        crate::decision::Decision::Challenge { .. } => 4.0,
        crate::decision::Decision::Allow => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_signals_zero_risk() {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: None,
            identity_score: None,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let score = risk.evaluate(&signals);
        assert!(score.overall < 1.0, "expected low risk, got {}", score.overall);
    }

    #[test]
    fn high_threat_drives_risk() {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: Some(9.0),
            identity_score: None,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let score = risk.evaluate(&signals);
        assert!(score.overall > 2.0, "expected high risk, got {}", score.overall);
    }

    #[test]
    fn combined_signals() {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: Some(8.0),
            identity_score: Some(5.0),
            agent_score: Some(4.0),
            memory_score: Some(3.0),
            execution_score: Some(6.0),
            reasoning_score: Some(2.0),
            governance_score: Some(1.5),
            recovery_score: Some(1.0),
            context: ContextSignals {
                time_of_day_risk: 0.5,
                rate_anomaly: 0.3,
                source_reputation: 0.2,
            },
        };
        let score = risk.evaluate(&signals);
        assert!(score.overall > 4.0);
        assert!(score.threat == 8.0);
        assert!(score.identity == 5.0);
        assert!(score.execution == 6.0);
    }

    #[test]
    fn confidence_increases_with_more_signals() {
        let risk = KeshavRisk::with_defaults();

        let signals_minimal = RiskSignals {
            threat_score: None,
            identity_score: None,
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        let score_min = risk.evaluate(&signals_minimal);

        let signals_full = RiskSignals {
            threat_score: Some(5.0),
            identity_score: Some(3.0),
            agent_score: Some(2.0),
            memory_score: Some(1.5),
            execution_score: Some(5.0),
            reasoning_score: Some(1.0),
            governance_score: Some(1.0),
            recovery_score: Some(1.0),
            context: ContextSignals::default(),
        };
        let score_full = risk.evaluate(&signals_full);

        assert!(score_full.confidence > score_min.confidence);
    }

    #[test]
    fn execution_risk_conversion() {
        use crate::decision::Decision;
        assert_eq!(execution_to_risk_score(&Decision::Allow), 0.0);
        assert_eq!(execution_to_risk_score(&Decision::Deny { code: "X".into(), retry_after: None }), 10.0);
        assert_eq!(execution_to_risk_score(&Decision::Escalate { approver_role: "admin".into(), timeout_secs: 300 }), 7.0);
    }

    #[test]
    fn context_score_computation() {
        let ctx = ContextSignals {
            time_of_day_risk: 1.0,
            rate_anomaly: 1.0,
            source_reputation: 0.0, // untrusted
        };
        let score = ctx.to_score();
        assert!(score > 8.0, "expected high context risk, got {}", score);
    }

    #[test]
    fn risk_clamped_to_10() {
        let risk = KeshavRisk::with_defaults();
        let signals = RiskSignals {
            threat_score: Some(15.0), // way over 10
            identity_score: Some(20.0),
            agent_score: Some(15.0),
            memory_score: Some(15.0),
            execution_score: Some(20.0),
            reasoning_score: Some(15.0),
            governance_score: Some(15.0),
            recovery_score: Some(15.0),
            context: ContextSignals {
                time_of_day_risk: 2.0,
                rate_anomaly: 2.0,
                source_reputation: 0.0,
            },
        };
        let score = risk.evaluate(&signals);
        assert!(score.overall <= 10.0);
    }
}
