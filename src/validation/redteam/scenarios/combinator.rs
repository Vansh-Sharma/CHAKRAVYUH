// Red Team OS — Attack Combinator (D1)
//
// The combinator is the core of Red Team OS. It takes base payloads and
// generates the full attack matrix:
//   For each payload × each mutation (or identity) × each encoding (or identity)
//   = N_payloads × N_mutations × N_encodings scenarios.
//
// Each scenario is then assigned to target rings for execution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::validation::redteam::attack_types::AttackPayload;
use crate::validation::redteam::encoders::encoding::Encoder;
use crate::validation::redteam::mutations::strategies::MutationStrategy;

/// Configuration for the combinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinatorConfig {
    /// Target rings to test against.
    pub target_rings: Vec<String>,
    /// Whether to include the identity (no-op) mutation.
    pub include_identity_mutation: bool,
    /// Whether to include the identity (no-op) encoder.
    pub include_identity_encoder: bool,
    /// Maximum number of scenarios to generate (0 = unlimited).
    pub max_scenarios: usize,
}

impl Default for CombinatorConfig {
    fn default() -> Self {
        Self {
            target_rings: vec![
                "shield".to_string(),
                "threat".to_string(),
                "memory".to_string(),
                "agent".to_string(),
                "execution".to_string(),
                "identity".to_string(),
                "reasoning".to_string(),
                "governance".to_string(),
                "keshav".to_string(),
            ],
            include_identity_mutation: true,
            include_identity_encoder: true,
            max_scenarios: 0,
        }
    }
}

/// A single scenario: a specific payload, mutation, encoding, and target ring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Unique scenario ID.
    pub id: String,
    /// The original (pre-mutation) payload.
    pub original_payload: String,
    /// The mutated + encoded payload to actually send.
    pub final_payload: String,
    /// Name of the mutation applied.
    pub mutation_name: String,
    /// Name of the encoding applied.
    pub encoding_name: String,
    /// The attack category.
    pub attack_category: String,
    /// The attack name.
    pub attack_name: String,
    /// Which ring this scenario targets.
    pub target_ring: String,
    /// The severity of the base attack.
    pub severity: String,
    /// Tags from the original payload.
    pub tags: Vec<String>,
    /// Metadata from the original payload.
    pub metadata: HashMap<String, String>,
}

/// A bundle of all scenarios for a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioBundle {
    /// Unique bundle ID.
    pub id: String,
    /// RFC 3339 timestamp of bundle creation.
    pub created_at: String,
    /// The combinator config used.
    pub config: CombinatorConfig,
    /// All generated scenarios.
    pub scenarios: Vec<Scenario>,
    /// Summary statistics.
    pub stats: BundleStats,
}

/// Statistics about the scenario bundle.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundleStats {
    pub total_scenarios: usize,
    pub total_payloads: usize,
    pub total_mutations: usize,
    pub total_encodings: usize,
    pub scenarios_per_ring: HashMap<String, usize>,
    pub scenarios_per_category: HashMap<String, usize>,
}

/// The attack combinator.
pub struct Combinator {
    config: CombinatorConfig,
}

impl Combinator {
    pub fn new(config: CombinatorConfig) -> Self {
        Self { config }
    }

    /// Generate the full scenario bundle from the given payloads, mutations, and encoders.
    pub fn generate(
        &self,
        payloads: &[AttackPayload],
        mutations: &[Box<dyn MutationStrategy>],
        encoders: &[Box<dyn Encoder>],
    ) -> ScenarioBundle {
        let mut scenarios = Vec::new();
        let mut stats = BundleStats::default();
        stats.total_payloads = payloads.len();
        stats.total_mutations = mutations.len();
        stats.total_encodings = encoders.len();

        let effective_rings: Vec<String> = if self.config.target_rings.is_empty() {
            vec!["shield".to_string()]
        } else {
            self.config.target_rings.clone()
        };

        for payload in payloads {
            // Determine which rings this payload targets.
            let payload_rings: Vec<&str> = if payload.target_rings.is_empty() {
                effective_rings.iter().map(|s| s.as_str()).collect()
            } else {
                payload.target_rings.iter().map(|s| s.as_str()).collect()
            };

            for mutation in mutations {
                let mutated = mutation.apply(&payload.raw_payload);

                for encoder in encoders {
                    match encoder.encode(&mutated) {
                        Ok(encoded) => {
                            for ring in &payload_rings {
                                if self.config.max_scenarios > 0
                                    && scenarios.len() >= self.config.max_scenarios
                                {
                                    stats.total_scenarios = scenarios.len();
                                    return self.finalize_bundle(scenarios, stats);
                                }

                                let scenario = Scenario {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    original_payload: payload.raw_payload.clone(),
                                    final_payload: encoded.clone(),
                                    mutation_name: mutation.name().to_string(),
                                    encoding_name: encoder.name().to_string(),
                                    attack_category: format!("{:?}", payload.category),
                                    attack_name: payload.name.clone(),
                                    target_ring: (*ring).to_string(),
                                    severity: format!("{:?}", payload.severity),
                                    tags: payload.tags.clone(),
                                    metadata: payload.metadata.clone(),
                                };
                                scenarios.push(scenario);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                encoder = encoder.name(),
                                payload = %payload.name,
                                "Encoder failed, skipping scenario"
                            );
                        }
                    }
                }
            }
        }

        stats.total_scenarios = scenarios.len();

        // Compute per-ring and per-category counts.
        for s in &scenarios {
            *stats.scenarios_per_ring.entry(s.target_ring.clone()).or_insert(0) += 1;
            *stats.scenarios_per_category.entry(s.attack_category.clone()).or_insert(0) += 1;
        }

        self.finalize_bundle(scenarios, stats)
    }

    fn finalize_bundle(&self, scenarios: Vec<Scenario>, stats: BundleStats) -> ScenarioBundle {
        ScenarioBundle {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            config: self.config.clone(),
            scenarios,
            stats,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::redteam::attack_types::{AttackCategory, AttackPayloadBuilder};
    use crate::validation::redteam::encoders::encoding::IdentityEncoder;
    use crate::validation::redteam::mutations::strategies::IdentityMutation;
    use crate::validation::verification::Severity;

    fn make_payload(name: &str) -> AttackPayload {
        AttackPayloadBuilder::new(AttackCategory::PromptInjection, name, "test payload")
            .target_ring("shield")
            .severity(Severity::High)
            .build()
    }

    #[test]
    fn basic_combination() {
        let combinator = Combinator::new(CombinatorConfig::default());
        let payloads = vec![make_payload("p1")];
        let mutations: Vec<Box<dyn MutationStrategy>> = vec![Box::new(IdentityMutation)];
        let encoders: Vec<Box<dyn Encoder>> = vec![Box::new(IdentityEncoder)];

        let bundle = combinator.generate(&payloads, &mutations, &encoders);
        // 1 payload × 1 mutation × 1 encoding × 1 ring (payload targets shield only)
        assert_eq!(bundle.scenarios.len(), 1);
        assert_eq!(bundle.stats.total_scenarios, 1);
    }

    #[test]
    fn multi_ring_targets() {
        let combinator = Combinator::new(CombinatorConfig::default());
        let p = AttackPayloadBuilder::new(AttackCategory::Jailbreak, "j1", "jailbreak")
            .target_rings(vec!["shield", "threat"])
            .build();
        let mutations: Vec<Box<dyn MutationStrategy>> = vec![Box::new(IdentityMutation)];
        let encoders: Vec<Box<dyn Encoder>> = vec![Box::new(IdentityEncoder)];

        let bundle = combinator.generate(&[p], &mutations, &encoders);
        assert_eq!(bundle.scenarios.len(), 2);
    }

    #[test]
    fn max_scenarios_limit() {
        let mut config = CombinatorConfig::default();
        config.max_scenarios = 5;
        let combinator = Combinator::new(config);

        let payloads: Vec<AttackPayload> = (0..3).map(|i| make_payload(&format!("p{}", i))).collect();
        let mutations: Vec<Box<dyn MutationStrategy>> = vec![Box::new(IdentityMutation)];
        let encoders: Vec<Box<dyn Encoder>> = vec![Box::new(IdentityEncoder)];

        let bundle = combinator.generate(&payloads, &mutations, &encoders);
        assert!(bundle.scenarios.len() <= 5);
    }

    #[test]
    fn bundle_has_stats() {
        let combinator = Combinator::new(CombinatorConfig::default());
        let payloads = vec![make_payload("p1")];
        let mutations: Vec<Box<dyn MutationStrategy>> = vec![Box::new(IdentityMutation)];
        let encoders: Vec<Box<dyn Encoder>> = vec![Box::new(IdentityEncoder)];

        let bundle = combinator.generate(&payloads, &mutations, &encoders);
        assert!(bundle.stats.scenarios_per_ring.contains_key("shield"));
    }
}
