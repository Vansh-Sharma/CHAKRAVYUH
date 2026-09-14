// Red Team OS — Attack Generators Module Root (D1)

pub mod agent_attack;
pub mod ananta_attack;
pub mod identity_attack;
pub mod jailbreak;
pub mod memory_poisoning;
pub mod orchestration_attack;
pub mod policy_attack;
pub mod prompt_injection;
pub mod reasoning_attack;
pub mod tool_attack;

use crate::validation::redteam::attack_types::{AttackCategory, AttackPayload};

/// Trait that all attack generators must implement.
///
/// Each generator produces a vector of `AttackPayload` for its category.
/// Generators are the source of truth for attack payloads in the Red Team OS.
pub trait Generator {
    /// The attack category this generator produces payloads for.
    fn category(&self) -> AttackCategory;

    /// Generate `count` attack payloads. If the generator has fewer than
    /// `count` unique payloads, it returns all available payloads.
    fn generate(&self, count: usize) -> Vec<AttackPayload>;

    /// Human-readable name of this generator.
    fn name(&self) -> &str;
}

/// Convenience: collect payloads from all given generators.
pub fn generate_all(generators: &[&dyn Generator], count: usize) -> Vec<AttackPayload> {
    let mut all = Vec::new();
    for gen in generators {
        all.extend(gen.generate(count));
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::redteam::generators::prompt_injection::PromptInjectionGenerator;

    #[test]
    fn generator_trait_generate() {
        let gen = PromptInjectionGenerator::new();
        let payloads = gen.generate(5);
        assert_eq!(payloads.len(), 5);
        for p in &payloads {
            assert_eq!(p.category, AttackCategory::PromptInjection);
        }
    }

    #[test]
    fn generate_all_collects() {
        let gen = PromptInjectionGenerator::new();
        let all = generate_all(&[&gen as &dyn Generator], 3);
        assert_eq!(all.len(), 3);
    }
}
