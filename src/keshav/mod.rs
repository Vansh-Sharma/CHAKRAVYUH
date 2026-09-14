#![allow(hidden_glob_reexports)]
// Keshav Core — Central Decision Brain
//
// Subsystems:
//   1. Decide       — rule-based policy engine (Phase 2) ✅
//   2. Risk         — composite risk scoring (Phase 3) ✅
//   3. Learn        — adaptive learning layer (Phase 6) ✅
//   4. Orchestrate  — ring coordination (Phase 3) ✅
//
// Critical Principle: Decide MUST work without Learn.

pub mod anomaly_profiler;
pub mod executor;
pub mod decide;
pub mod decision_logger;
pub mod feedback_collector;
pub mod fallback_rules;
pub mod learn;
pub mod orchestrate;
pub mod pattern_store;
pub mod policy_engine;
pub mod policy_manager;
pub mod risk;
pub mod threshold_optimizer;

pub use decision_logger::{DecisionLogEntry, DecisionLogger};
pub use decide::{KeshavDecide, AllRingVerdicts};
pub use fallback_rules::FallbackRules;
pub use learn::{KeshavLearn, LearnConfig, LearnStatus};
pub use executor::{PipelineContext, PipelineExecutor, PipelineResult, ToolCallContext};
pub use orchestrate::{KeshavOrchestrate, OrchestrateConfig, OrchestrationPlan, RequestType, RingId};
pub use policy_engine::{Policy, PolicyEngine, PolicyRule, RuleAction, RuleCondition};
pub use policy_manager::PolicyManager;
pub use risk::{ContextSignals, KeshavRisk, RiskConfig, RiskSignals, execution_to_risk_score, threat_to_risk_score};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct KeshavConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub policy_path: Option<String>,

    #[serde(default)]
    pub risk: RiskConfig,

    #[serde(default)]
    pub orchestrate: OrchestrateConfig,

    #[serde(default)]
    pub learn: LearnConfig,
}

pub struct KeshavCore;

impl KeshavCore {
    pub fn new(_config: &KeshavConfig) -> crate::Result<Self> {
        Ok(Self)
    }
}
