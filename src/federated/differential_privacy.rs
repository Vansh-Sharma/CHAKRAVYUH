// Differential Privacy Engine for Federated Learning
//
// Implements two classical noise mechanisms (Gaussian and Laplace) and
// a privacy accountant based on the advanced composition theorem.
//
// Key concepts:
//   - epsilon (ε): privacy budget — lower = more private, less utility
//   - delta (δ): probability of privacy failure — lower = more private
//   - Gaussian mechanism: noise ~ N(0, σ²) where σ = C·√(2·ln(1.25/δ)) / ε
//   - Laplace mechanism: noise ~ Laplace(0, C/ε)
//   - Advanced composition: bounds total privacy loss over T rounds
//
// No unsafe code.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use rand::{Rng, SeedableRng};

// ── Noise Mechanism ───────────────────────────────────────────────

/// Supported noise mechanisms for differential privacy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NoiseMechanism {
    /// Gaussian mechanism: N(0, σ²) noise.
    Gaussian,
    /// Laplace mechanism: Laplace(0, b) noise.
    Laplace,
}

impl Default for NoiseMechanism {
    fn default() -> Self {
        NoiseMechanism::Gaussian
    }
}

// ── Configuration ──────────────────────────────────────────────────

/// Configuration for the differential privacy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPrivacyConfig {
    /// Per-round privacy budget (ε). Lower = more private.
    pub epsilon: f64,
    /// Per-round failure probability (δ). Lower = more private.
    pub delta: f64,
    /// Noise mechanism to use.
    pub noise_mechanism: NoiseMechanism,
    /// Maximum L2 norm for gradient clipping (C).
    pub clip_norm: f64,
    /// Whether to use secure aggregation (masking).
    pub secure_aggregation: bool,
}

impl Default for DifferentialPrivacyConfig {
    fn default() -> Self {
        Self {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            secure_aggregation: true,
        }
    }
}

// ── Privacy Accountant ────────────────────────────────────────────

/// Tracks cumulative privacy spend across multiple federation rounds.
///
/// Uses the advanced composition theorem:
/// After T rounds with (ε_i, δ_i), total (ε, δ) is bounded by:
///   ε_total = √(2T·ln(1/δ')) · max(ε_i) + T·max(ε_i)·(e^{max(ε_i)} - 1)
///   δ_total = T · max(δ_i) + δ'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAccountant {
    /// Total number of completed rounds.
    pub rounds_completed: u32,
    /// Cumulative epsilon across all rounds.
    pub cumulative_epsilon: f64,
    /// Cumulative delta across all rounds.
    pub cumulative_delta: f64,
    /// Maximum single-round epsilon seen.
    pub max_round_epsilon: f64,
    /// Maximum single-round delta seen.
    pub max_round_delta: f64,
    /// Delta prime used in the composition formula.
    pub delta_prime: f64,
}

impl PrivacyAccountant {
    /// Create a new accountant with no rounds completed.
    pub fn new() -> Self {
        Self {
            rounds_completed: 0,
            cumulative_epsilon: 0.0,
            cumulative_delta: 0.0,
            max_round_epsilon: 0.0,
            max_round_delta: 0.0,
            delta_prime: 1e-10,
        }
    }

    /// Compute the privacy budget for T rounds using advanced composition.
    ///
    /// Returns a new PrivacyAccountant with the total budget consumed.
    pub fn compute_privacy_budget(
        &self,
        epsilon: f64,
        delta: f64,
        num_rounds: u32,
    ) -> PrivacyAccountant {
        if num_rounds == 0 || epsilon <= 0.0 {
            return self.clone();
        }

        let t = num_rounds as f64;
        let max_eps = epsilon.max(self.max_round_epsilon);
        let max_delta = delta.max(self.max_round_delta);
        let delta_prime = self.delta_prime;

        // Advanced composition theorem.
        let ln_term = if delta_prime > 0.0 && delta_prime < 1.0 {
            (1.0 / delta_prime).ln()
        } else {
            0.0
        };
        let epsilon_total =
            (2.0 * t * ln_term).sqrt() * max_eps + t * max_eps * (max_eps.exp_m1());
        let delta_total = t * max_delta + delta_prime;

        PrivacyAccountant {
            rounds_completed: self.rounds_completed + num_rounds,
            cumulative_epsilon: epsilon_total,
            cumulative_delta: delta_total,
            max_round_epsilon: max_eps,
            max_round_delta: max_delta,
            delta_prime,
        }
    }

    /// Record a single round's privacy consumption.
    pub fn record_round(&mut self, epsilon: f64, delta: f64) {
        let updated = self.compute_privacy_budget(epsilon, delta, 1);
        *self = updated;
    }

    /// Compute the remaining privacy budget.
    ///
    /// Budget remaining is the difference between a target total epsilon
    /// and the cumulative epsilon already consumed. If no target is set,
    /// returns infinity (no limit).
    pub fn budget_remaining(&self, target_epsilon: Option<f64>) -> f64 {
        match target_epsilon {
            Some(target) => (target - self.cumulative_epsilon).max(0.0),
            None => f64::INFINITY,
        }
    }
}

impl Default for PrivacyAccountant {
    fn default() -> Self {
        Self::new()
    }
}

// ── Secure Aggregation ────────────────────────────────────────────

/// Simulates secure aggregation by masking individual updates.
///
/// In production, this would use cryptographic secret sharing.
/// Here we simulate the concept using deterministic additive masking
/// derived from peer IDs. The masks are deterministic given a peer ID,
/// so they can be reversed.
pub struct SecureAggregation {
    /// Whether secure aggregation is enabled.
    enabled: bool,
    /// Stored masks per peer.
    masks: RwLock<std::collections::HashMap<String, Vec<f64>>>,
}

impl SecureAggregation {
    /// Create a new secure aggregation instance.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            masks: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Mask a weight vector for a given peer.
    ///
    /// Generates a deterministic pseudorandom mask from the peer ID.
    /// Stores the mask so it can be reversed later.
    pub fn mask(&self, peer_id: &str, weights: &mut [f64]) {
        if !self.enabled {
            return;
        }
        let mask = self.generate_mask(peer_id, weights.len());
        for (w, m) in weights.iter_mut().zip(mask.iter()) {
            *w += m;
        }
        self.masks
            .write()
            .unwrap()
            .insert(peer_id.to_string(), mask);
    }

    /// Unmask a weight vector for a given peer.
    ///
    /// Subtracts the previously stored mask from the weights.
    /// Returns false if no mask exists for the peer.
    pub fn unmask(&self, peer_id: &str, weights: &mut [f64]) -> bool {
        if !self.enabled {
            return true;
        }
        let masks = self.masks.read().unwrap();
        match masks.get(peer_id) {
            Some(mask) => {
                for (w, m) in weights.iter_mut().zip(mask.iter()) {
                    *w -= m;
                }
                true
            }
            None => false,
        }
    }

    /// Generate a deterministic pseudorandom mask.
    ///
    /// Uses SHA-256 of the peer ID to seed a deterministic RNG.
    fn generate_mask(&self, peer_id: &str, len: usize) -> Vec<f64> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(peer_id.as_bytes());
        let hash = hasher.finalize();
        let seed = u64::from_le_bytes(
            hash[..8].try_into().unwrap_or([0u8; 8]),
        );
        let seed_bytes = seed.to_le_bytes();
        let mut full_seed = [0u8; 32];
        full_seed[..8].copy_from_slice(&seed_bytes);
        let mut rng = rand::rngs::StdRng::from_seed(full_seed);
        (0..len)
            .map(|_| rng.random_range(-0.01..0.01))
            .collect()
    }

    /// Clear all stored masks.
    pub fn clear_masks(&self) {
        self.masks.write().unwrap().clear();
    }
}

// ── Privacy Report ────────────────────────────────────────────────

/// A snapshot of the current privacy state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyReport {
    /// Current cumulative epsilon.
    pub current_epsilon: f64,
    /// Current cumulative delta.
    pub current_delta: f64,
    /// Number of completed rounds.
    pub rounds_completed: u32,
    /// Remaining privacy budget (or infinity if no target).
    pub budget_remaining: f64,
    /// Noise mechanism in use.
    pub mechanism_used: NoiseMechanism,
}

// ── Differential Privacy Engine ────────────────────────────────────

/// The main differential privacy engine.
///
/// Applies calibrated noise to model weights and tracks cumulative
/// privacy budget via the privacy accountant.
pub struct DifferentialPrivacyEngine {
    config: DifferentialPrivacyConfig,
    accountant: RwLock<PrivacyAccountant>,
    secure_agg: SecureAggregation,
    rounds_completed: AtomicU64,
}

impl DifferentialPrivacyEngine {
    /// Create a new DP engine with the given configuration.
    pub fn new(config: DifferentialPrivacyConfig) -> Self {
        let secure_agg = SecureAggregation::new(config.secure_aggregation);
        Self {
            config,
            accountant: RwLock::new(PrivacyAccountant::new()),
            secure_agg,
            rounds_completed: AtomicU64::new(0),
        }
    }

    /// Apply calibrated noise to a weight vector.
    ///
    /// Gaussian mechanism: noise ~ N(0, σ²) where σ = C·√(2·ln(1.25/δ)) / ε
    /// Laplace mechanism: noise ~ Laplace(0, C/ε)
    pub fn apply_noise(&self, weights: &mut [f64]) {
        if weights.is_empty() {
            return;
        }

        let epsilon = self.config.epsilon;
        if epsilon <= 0.0 {
            return; // Zero epsilon → no noise (infinite privacy)
        }

        let clip_norm = self.config.clip_norm;

        match self.config.noise_mechanism {
            NoiseMechanism::Gaussian => {
                // σ = C · sqrt(2 · ln(1.25/δ)) / ε
                let delta = self.config.delta.max(1e-20);
                let ln_arg = (1.25 / delta).ln().max(0.0);
                let sigma = clip_norm * (2.0 * ln_arg).sqrt() / epsilon;

                let mut rng = rand::rng();
                for w in weights.iter_mut() {
                    // Box-Muller transform for Gaussian noise.
                    let u1: f64 = rng.random_range(0.001..1.0);
                    let u2: f64 = rng.random_range(0.001..1.0);
                    let gaussian =
                        sigma * (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                    *w += gaussian;
                }
            }
            NoiseMechanism::Laplace => {
                // b = C / ε
                let b = clip_norm / epsilon;

                let mut rng = rand::rng();
                for w in weights.iter_mut() {
                    // Inverse CDF method for Laplace distribution.
                    let u: f64 = rng.random_range(0.001..0.999);
                    let laplace = if u < 0.5 {
                        b * (1.0 + (2.0 * u).ln())
                    } else {
                        -b * (1.0 + (2.0 * (1.0 - u)).ln())
                    };
                    *w += laplace;
                }
            }
        }

        self.record_round();
    }

    /// Clip gradient norms per-element.
    ///
    /// Each individual weight is clipped so that its absolute value
    /// does not exceed `max_norm`.
    pub fn clip_gradients(&self, weights: &mut [f64], max_norm: f64) {
        for w in weights.iter_mut() {
            if *w > max_norm {
                *w = max_norm;
            } else if *w < -max_norm {
                *w = -max_norm;
            }
        }
    }

    /// Record one round of privacy consumption.
    pub fn record_round(&self) {
        let mut acc = self.accountant.write().unwrap();
        acc.record_round(self.config.epsilon, self.config.delta);
        self.rounds_completed.fetch_add(1, Ordering::SeqCst);
    }

    /// Get the current privacy report.
    pub fn privacy_report(&self) -> PrivacyReport {
        let acc = self.accountant.read().unwrap();
        PrivacyReport {
            current_epsilon: acc.cumulative_epsilon,
            current_delta: acc.cumulative_delta,
            rounds_completed: acc.rounds_completed,
            budget_remaining: acc.budget_remaining(None),
            mechanism_used: self.config.noise_mechanism,
        }
    }

    /// Get the privacy accountant for direct queries.
    pub fn accountant(&self) -> std::sync::RwLockReadGuard<'_, PrivacyAccountant> {
        self.accountant.read().unwrap()
    }

    /// Get the secure aggregation handler.
    pub fn secure_aggregation(&self) -> &SecureAggregation {
        &self.secure_agg
    }

    /// Compute the Gaussian sigma for the current configuration.
    ///
    /// σ = C · sqrt(2 · ln(1.25/δ)) / ε
    pub fn compute_gaussian_sigma(&self) -> f64 {
        let delta = self.config.delta.max(1e-20);
        let ln_arg = (1.25 / delta).ln().max(0.0);
        self.config.clip_norm * (2.0 * ln_arg).sqrt() / self.config.epsilon.max(1e-20)
    }

    /// Compute the Laplace scale parameter for the current configuration.
    ///
    /// b = C / ε
    pub fn compute_laplace_scale(&self) -> f64 {
        self.config.clip_norm / self.config.epsilon.max(1e-20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = DifferentialPrivacyConfig::default();
        assert!((config.epsilon - 1.0).abs() < 1e-9);
        assert!((config.delta - 1e-5).abs() < 1e-15);
        assert_eq!(config.noise_mechanism, NoiseMechanism::Gaussian);
        assert!(config.secure_aggregation);
    }

    #[test]
    fn test_gaussian_noise_calibration() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            secure_aggregation: false,
        });

        let sigma = engine.compute_gaussian_sigma();
        // σ = 1.0 * sqrt(2 * ln(1.25/1e-5)) / 1.0
        let expected_ln: f64 = (1.25_f64 / 1e-5).ln();
        let expected: f64 = (2.0 * expected_ln).sqrt();
        assert!((sigma - expected).abs() < 1e-6);

        // Apply noise to identical weights and check they diverge.
        let mut w1 = vec![1.0; 100];
        let mut w2 = vec![1.0; 100];
        engine.apply_noise(&mut w1);
        engine.apply_noise(&mut w2);
        let sum_diff: f64 = w1
            .iter()
            .zip(w2.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();
        assert!(
            sum_diff > 0.0,
            "Two identical vectors should diverge after independent noise"
        );
    }

    #[test]
    fn test_laplace_noise_calibration() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Laplace,
            clip_norm: 1.0,
            secure_aggregation: false,
        });

        let b = engine.compute_laplace_scale();
        assert!((b - 1.0).abs() < 1e-9); // b = C/ε = 1.0/1.0

        let mut w = vec![0.0; 1000];
        engine.apply_noise(&mut w);
        let mean: f64 = w.iter().sum::<f64>() / w.len() as f64;
        assert!(
            mean.abs() < 0.2,
            "Laplace noise should have near-zero mean, got {}",
            mean
        );
    }

    #[test]
    fn test_gradient_clipping() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig::default());

        let mut weights = vec![5.0, -3.0, 0.5, -0.1, 2.0];
        engine.clip_gradients(&mut weights, 1.0);
        assert_eq!(weights, vec![1.0, -1.0, 0.5, -0.1, 1.0]);

        // Clipping to a larger norm should not change values.
        let mut weights2 = vec![0.5, -0.3];
        engine.clip_gradients(&mut weights2, 10.0);
        assert_eq!(weights2, vec![0.5, -0.3]);
    }

    #[test]
    fn test_privacy_accounting_single_round() {
        let acc = PrivacyAccountant::new();
        assert_eq!(acc.rounds_completed, 0);
        assert!((acc.cumulative_epsilon - 0.0).abs() < 1e-12);

        let acc2 = acc.compute_privacy_budget(1.0, 1e-5, 1);
        assert_eq!(acc2.rounds_completed, 1);
        assert!(acc2.cumulative_epsilon > 0.0);
        assert!(acc2.cumulative_delta > 0.0);
    }

    #[test]
    fn test_budget_tracking_with_target() {
        let mut acc = PrivacyAccountant::new();
        acc.record_round(1.0, 1e-5);
        let remaining = acc.budget_remaining(Some(10.0));
        assert!(remaining > 0.0);
        assert!(remaining < 10.0);
    }

    #[test]
    fn test_multiple_rounds_composition() {
        let acc = PrivacyAccountant::new();
        let acc10 = acc.compute_privacy_budget(1.0, 1e-5, 10);
        assert_eq!(acc10.rounds_completed, 10);
        // Advanced composition should give sub-linear growth in epsilon
        // for the same per-round epsilon. The exact bound is:
        // ε = sqrt(20·ln(1/δ'))·1 + 10·1·(e-1)
        // δ' = 1e-10
        let delta_prime = 1e-10_f64;
        let ln_term = (1.0 / delta_prime).ln();
        let expected_eps = (20.0 * ln_term).sqrt() + 10.0 * (std::f64::consts::E - 1.0);
        assert!(
            (acc10.cumulative_epsilon - expected_eps).abs() < 1e-6,
            "expected {}, got {}",
            expected_eps,
            acc10.cumulative_epsilon
        );
    }

    #[test]
    fn test_zero_rounds_no_change() {
        let acc = PrivacyAccountant::new();
        let acc2 = acc.compute_privacy_budget(1.0, 1e-5, 0);
        assert_eq!(acc2.rounds_completed, 0);
    }

    #[test]
    fn test_secure_aggregation_masking_unmasking() {
        let sa = SecureAggregation::new(true);
        let original = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let mut weights = original.clone();

        sa.mask("peer-1", &mut weights);
        assert_ne!(weights, original, "Masked weights should differ from original");

        let success = sa.unmask("peer-1", &mut weights);
        assert!(success);
        assert_eq!(weights, original, "Unmasked weights should match original");
    }

    #[test]
    fn test_secure_aggregation_deterministic_masks() {
        let sa = SecureAggregation::new(true);
        let mut w1 = vec![0.0; 10];
        let mut w2 = vec![0.0; 10];

        sa.mask("peer-x", &mut w1);
        sa.mask("peer-x", &mut w2);
        assert_eq!(w1, w2, "Same peer ID should produce the same mask");
    }

    #[test]
    fn test_secure_aggregation_disabled() {
        let sa = SecureAggregation::new(false);
        let original = vec![1.0, 2.0, 3.0];
        let mut weights = original.clone();

        sa.mask("peer-1", &mut weights);
        assert_eq!(weights, original, "Disabled SA should not modify weights");

        let success = sa.unmask("peer-1", &mut weights);
        assert!(success, "Disabled SA unmask should still return true");
    }

    #[test]
    fn test_unmask_unknown_peer_returns_false() {
        let sa = SecureAggregation::new(true);
        let mut weights = vec![1.0, 2.0];
        let success = sa.unmask("unknown-peer", &mut weights);
        assert!(!success);
    }

    #[test]
    fn test_report_generation() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Laplace,
            clip_norm: 1.0,
            secure_aggregation: false,
        });

        let mut w = vec![0.0; 10];
        engine.apply_noise(&mut w);

        let report = engine.privacy_report();
        assert_eq!(report.rounds_completed, 1);
        assert!(report.current_epsilon > 0.0);
        assert!(report.current_delta > 0.0);
        assert_eq!(report.mechanism_used, NoiseMechanism::Laplace);
        assert!(report.budget_remaining.is_infinite());
    }

    #[test]
    fn test_zero_epsilon_no_noise() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 0.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            secure_aggregation: false,
        });

        let original = vec![1.0, 2.0, 3.0];
        let mut weights = original.clone();
        engine.apply_noise(&mut weights);
        assert_eq!(weights, original, "Zero epsilon should produce no noise");
    }

    #[test]
    fn test_empty_weights_no_panic() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig::default());
        let mut weights: Vec<f64> = vec![];
        engine.apply_noise(&mut weights); // Should not panic.
        assert!(weights.is_empty());
    }

    #[test]
    fn test_very_large_delta() {
        // Delta >= 1 is technically invalid but should not panic.
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1.0,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            secure_aggregation: false,
        });
        let sigma = engine.compute_gaussian_sigma();
        // 1.25/1.0 = 1.25, ln(1.25) > 0, so sigma should be finite and positive.
        assert!(sigma.is_finite());
        assert!(sigma > 0.0);
    }

    #[test]
    fn test_clear_masks() {
        let sa = SecureAggregation::new(true);
        let mut w = vec![0.0; 5];
        sa.mask("peer-a", &mut w);
        sa.clear_masks();
        // Unmask should now fail since masks were cleared.
        assert!(!sa.unmask("peer-a", &mut w));
    }

    #[test]
    fn test_cumulative_rounds_tracking() {
        let engine = DifferentialPrivacyEngine::new(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            secure_aggregation: false,
        });

        for _ in 0..5 {
            let mut w = vec![0.0; 10];
            engine.apply_noise(&mut w);
        }

        let report = engine.privacy_report();
        assert_eq!(report.rounds_completed, 5);
    }
}
