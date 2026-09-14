// Red Team OS — Module Root (D1)
//
// The D1 Red Team OS is a permanent security laboratory that:
//   1. Generates realistic attack payloads across 10 categories
//   2. Mutates and encodes payloads to test detection robustness
//   3. Combines them into a full attack matrix (payloads × mutations × encodings)
//   4. Runs them against the system and records per-ring/per-category detection rates
//   5. Produces regression baselines for continuous security monitoring

pub mod attack_types;
pub mod encoders;
pub mod generators;
pub mod mutations;
pub mod regression;
pub mod reports;
pub mod runners;
pub mod scenarios;

// Re-export all public types.
pub use attack_types::{AttackCategory, AttackPayload, AttackPayloadBuilder};
pub use encoders::encoding::Encoder;
pub use generators::Generator;
pub use mutations::strategies::MutationStrategy;
pub use regression::suite::{
    DiffEntry, DiffKind, RegressionBaseline, RegressionDiff, RegressionSuite,
};
pub use reports::redteam_report::{
    detection_rate_per_ring, generate_report, missed_attacks, RedTeamReportSummary, RingCell,
    RingDetectionMatrix,
};
pub use runners::{RedTeamRunner, RunResult, RunnerConfig, ScenarioOutcome};
pub use scenarios::{Combinator, CombinatorConfig, Scenario, ScenarioBundle};
