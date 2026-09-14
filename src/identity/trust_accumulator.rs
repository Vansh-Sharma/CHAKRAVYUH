// TrustAccumulator Engine — Identity Trust Scoring
//
// Maintains per-identity trust scores based on observed behavior.
// Trust is a composite of:
//   - Base trust (from identity type)
//   - Age factor (older identities are more trusted)
//   - Consistency (same IP, same agent → higher trust)
//   - Request volume (too many → reduced trust; moderate → stable)
//   - History of denied requests (denials reduce trust)
//
// Trust range: 0.0 (no trust) to 1.0 (full trust).
// Trust decays over inactivity and recovers with consistent good behavior.
//
// This engine is stateful — it maintains in-memory state per identity.
// In production, this would use Redis or a persistent store.
//
// Latency Budget: <0.1ms per evaluation

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::identity::role_resolver::Role;
use crate::identity::session_identity::IdentityProfile;

/// Trust state for a single identity.
#[derive(Debug, Clone)]
struct TrustState {
    /// Number of requests seen from this identity.
    request_count: u64,
    /// Number of requests that were denied (by any ring).
    denial_count: u64,
    /// First seen timestamp (epoch seconds).
    first_seen: i64,
    /// Last seen timestamp (epoch seconds).
    last_seen: i64,
    /// Set of source IPs seen from this identity.
    seen_ips: Vec<String>,
    /// Set of user agents seen from this identity.
    seen_agents: Vec<String>,
    /// Current trust score (0.0-1.0).
    trust_score: f64,
    /// Smoothed request rate (requests per minute, exponentially weighted).
    rate_estimate: f64,
}

impl Default for TrustState {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            request_count: 0,
            denial_count: 0,
            first_seen: now,
            last_seen: now,
            seen_ips: vec![],
            seen_agents: vec![],
            trust_score: 0.0, // Will be set on first evaluation
            rate_estimate: 0.0,
        }
    }
}

/// TrustAccumulator engine configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TrustAccumulatorConfig {
    /// Whether this engine is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum number of identities to track (LRU eviction).
    /// Default: 10,000.
    #[serde(default = "default_max_identities")]
    pub max_identities: usize,

    /// Decay rate for trust over inactivity (per hour).
    /// Trust reduces by this fraction each hour of inactivity.
    /// Default: 0.02 (2% per hour → ~50% after 34 hours).
    #[serde(default = "default_decay_rate")]
    pub decay_rate: f64,

    /// Weight for request volume in trust calculation (0.0-1.0).
    /// Default: 0.2.
    #[serde(default = "default_w_volume")]
    pub w_volume: f64,

    /// Weight for IP consistency in trust calculation.
    /// Default: 0.15.
    #[serde(default = "default_w_consistency")]
    pub w_consistency: f64,

    /// Weight for denial ratio in trust calculation.
    /// Default: 0.3.
    #[serde(default = "default_w_denial")]
    pub w_denial: f64,

    /// Weight for base trust (from identity type).
    /// Default: 0.25.
    #[serde(default = "default_w_base")]
    pub w_base: f64,

    /// Weight for age (time since first seen).
    /// Default: 0.1.
    #[serde(default = "default_w_age")]
    pub w_age: f64,

    /// Request rate threshold for "excessive" (requests per minute).
    /// Above this, trust is reduced.
    /// Default: 60 (1 per second).
    #[serde(default = "default_excessive_rate")]
    pub excessive_rate: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_max_identities() -> usize {
    10_000
}
fn default_decay_rate() -> f64 {
    0.02
}
fn default_w_volume() -> f64 {
    0.2
}
fn default_w_consistency() -> f64 {
    0.15
}
fn default_w_denial() -> f64 {
    0.3
}
fn default_w_base() -> f64 {
    0.25
}
fn default_w_age() -> f64 {
    0.1
}
fn default_excessive_rate() -> f64 {
    60.0
}

impl Default for TrustAccumulatorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_identities: default_max_identities(),
            decay_rate: default_decay_rate(),
            w_volume: default_w_volume(),
            w_consistency: default_w_consistency(),
            w_denial: default_w_denial(),
            w_base: default_w_base(),
            w_age: default_w_age(),
            excessive_rate: default_excessive_rate(),
        }
    }
}

/// Result of trust evaluation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrustResult {
    /// The computed trust score (0.0-1.0).
    pub trust_score: f64,
    /// The base trust from identity type.
    pub base_trust: f64,
    /// The age component of trust (0.0-1.0).
    pub age_factor: f64,
    /// The consistency component (0.0-1.0).
    pub consistency_factor: f64,
    /// The volume/rate component (0.0-1.0).
    pub volume_factor: f64,
    /// The denial penalty component (0.0-1.0).
    pub denial_factor: f64,
    /// Total requests seen from this identity.
    pub request_count: u64,
    /// Total denials for this identity.
    pub denial_count: u64,
    /// Whether the identity is "new" (first request).
    pub is_new: bool,
    pub reason: String,
}

/// The TrustAccumulator engine.
///
/// Maintains per-identity trust state and computes composite trust scores.
/// Thread-safe via Arc<Mutex<>>.
pub struct TrustAccumulator {
    config: TrustAccumulatorConfig,
    state: Arc<Mutex<HashMap<String, TrustState>>>,
}

impl TrustAccumulator {
    pub fn new(config: &TrustAccumulatorConfig) -> Self {
        Self {
            config: config.clone(),
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Evaluate the trust score for an identity.
    ///
    /// Updates internal state and returns the composite trust score.
    pub fn evaluate(
        &self,
        profile: &IdentityProfile,
        _role: &Role,
        source_ip: &str,
        user_agent: Option<&str>,
        was_denied: bool,
    ) -> TrustResult {
        if !self.config.enabled {
            return TrustResult {
                trust_score: profile.trust_base,
                base_trust: profile.trust_base,
                age_factor: 0.0,
                consistency_factor: 1.0,
                volume_factor: 1.0,
                denial_factor: 1.0,
                request_count: 0,
                denial_count: 0,
                is_new: true,
                reason: "trust_accumulator disabled".into(),
            };
        }

        let principal = &profile.principal_id;
        let now = chrono::Utc::now().timestamp();

        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Evict if at capacity (LRU: remove oldest last_seen).
        if states.len() >= self.config.max_identities && !states.contains_key(principal) {
            if let Some(oldest_key) = states
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                states.remove(&oldest_key);
            }
        }

        let entry = states.entry(principal.clone()).or_default();
        let is_new = entry.request_count == 0;
        entry.request_count += 1;
        if was_denied {
            entry.denial_count += 1;
        }

        // Track IPs and agents.
        if !entry.seen_ips.contains(&source_ip.to_string()) {
            entry.seen_ips.push(source_ip.to_string());
            if entry.seen_ips.len() > 10 {
                entry.seen_ips.remove(0);
            }
        }
        if let Some(ua) = user_agent {
            if !entry.seen_agents.contains(&ua.to_string()) {
                entry.seen_agents.push(ua.to_string());
                if entry.seen_agents.len() > 5 {
                    entry.seen_agents.remove(0);
                }
            }
        }

        // Compute time delta.
        let hours_since_last = if entry.last_seen > 0 {
            ((now - entry.last_seen) as f64 / 3600.0).max(0.0)
        } else {
            0.0
        };
        let hours_since_first = if entry.first_seen > 0 {
            ((now - entry.first_seen) as f64 / 3600.0).max(0.0)
        } else {
            0.0
        };

        entry.last_seen = now;

        // Update rate estimate (exponential moving average).
        if hours_since_last > 0.0 && hours_since_last < 1.0 {
            let instant_rate = 1.0 / (hours_since_last * 60.0).max(0.001);
            entry.rate_estimate = entry.rate_estimate * 0.8 + instant_rate * 0.2;
        }

        // Compute trust components.

        // 1. Base trust (from identity type).
        let base_trust = profile.trust_base;

        // 2. Age factor — older identities get more trust (saturates at 24 hours).
        let age_factor = (1.0 - (-hours_since_first / 24.0).exp()).min(1.0);

        // 3. Consistency — same IP and same agent = high consistency.
        let ip_consistency = if entry.seen_ips.len() <= 1 {
            1.0
        } else {
            1.0 / (entry.seen_ips.len() as f64)
        };
        let agent_consistency = if entry.seen_agents.len() <= 1 {
            1.0
        } else {
            1.0 / (entry.seen_agents.len() as f64)
        };
        let consistency_factor = ip_consistency * 0.6 + agent_consistency * 0.4;

        // 4. Volume — moderate volume is good, excessive is bad.
        let volume_factor = if entry.rate_estimate > self.config.excessive_rate {
            let excess = entry.rate_estimate / self.config.excessive_rate;
            (1.0 / excess.sqrt()).max(0.1)
        } else if entry.request_count >= 10 {
            1.0 // Established user
        } else if entry.request_count >= 3 {
            0.8 // Getting established
        } else {
            0.5 // Too new to judge
        };

        // 5. Denial ratio — any denials reduce trust.
        let denial_ratio = if entry.request_count > 0 {
            entry.denial_count as f64 / entry.request_count as f64
        } else {
            0.0
        };
        let denial_factor = (1.0 - denial_ratio * 3.0).max(0.0);

        // Composite trust score.
        let trust = self.config.w_base * base_trust
            + self.config.w_age * age_factor
            + self.config.w_consistency * consistency_factor
            + self.config.w_volume * volume_factor
            + self.config.w_denial * denial_factor;

        // Apply decay from inactivity.
        let decay = (1.0 - self.config.decay_rate).powf(hours_since_last);
        let trust_score = (trust * decay).clamp(0.0, 1.0);

        entry.trust_score = trust_score;

        TrustResult {
            trust_score,
            base_trust,
            age_factor,
            consistency_factor,
            volume_factor,
            denial_factor,
            request_count: entry.request_count,
            denial_count: entry.denial_count,
            is_new,
            reason: format!(
                "trust={:.3} (base={:.2}, age={:.2}, consistency={:.2}, volume={:.2}, denial={:.2})",
                trust_score, base_trust, age_factor, consistency_factor, volume_factor, denial_factor
            ),
        }
    }

    /// Get the current trust score for a principal (without updating state).
    pub fn get_trust(&self, principal_id: &str) -> Option<f64> {
        let states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        states.get(principal_id).map(|s| s.trust_score)
    }

    /// Get the number of tracked identities.
    pub fn tracked_count(&self) -> usize {
        let states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        states.len()
    }

    /// Reset all trust state (for testing).
    pub fn reset(&self) {
        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        states.clear();
    }
}

// Implement Clone for TrustAccumulator (shares state via Arc).
impl Clone for TrustAccumulator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::session_identity::{IdentityProfile, IdentityType};

    fn default_engine() -> TrustAccumulator {
        TrustAccumulator::new(&TrustAccumulatorConfig::default())
    }

    fn test_profile(key: &str) -> IdentityProfile {
        IdentityProfile {
            identity_type: IdentityType::ApiKey,
            principal_id: format!("key:{}", key),
            credential_ref: key.to_string(),
            trust_base: 0.5,
            claims: vec![],
            format_valid: true,
        }
    }

    #[test]
    fn new_identity_low_trust() {
        let engine = default_engine();
        let profile = test_profile("sk-test-new-identity12345");
        let result = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            Some("test"),
            false,
        );
        // New identity should have moderate trust (base * w_base dominates).
        assert!(result.is_new);
        assert!(result.trust_score > 0.0 && result.trust_score < 1.0);
        assert_eq!(result.request_count, 1);
    }

    #[test]
    fn trust_increases_with_consistent_requests() {
        let engine = default_engine();
        let profile = test_profile("sk-trust-growth-key1234");

        // First request.
        let r1 = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            Some("agent"),
            false,
        );

        // Simulate 20 more consistent requests.
        for _ in 0..20 {
            engine.evaluate(
                &profile,
                &crate::identity::role_resolver::Role::User,
                "1.2.3.4",
                Some("agent"),
                false,
            );
        }

        let r_final = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            Some("agent"),
            false,
        );
        // Trust should grow with consistent requests.
        assert!(r_final.trust_score >= r1.trust_score);
        assert_eq!(r_final.request_count, 22);
    }

    #[test]
    fn denials_reduce_trust() {
        let engine = default_engine();
        let profile = test_profile("sk-deny-reduce-key12345");

        // 5 denied requests.
        for _ in 0..5 {
            engine.evaluate(
                &profile,
                &crate::identity::role_resolver::Role::User,
                "1.2.3.4",
                Some("test"),
                true,
            );
        }

        let result = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            Some("test"),
            false,
        );
        assert_eq!(result.denial_count, 5);
        assert!(result.denial_factor < 1.0);
    }

    #[test]
    fn ip_hopping_reduces_consistency() {
        let engine = default_engine();
        let profile = test_profile("sk-ip-hop-key123456789");

        engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.1.1.1",
            Some("agent"),
            false,
        );
        engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "2.2.2.2",
            Some("agent"),
            false,
        );
        engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "3.3.3.3",
            Some("agent"),
            false,
        );

        let result = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "4.4.4.4",
            Some("agent"),
            false,
        );
        // 4 different IPs → consistency factor should be lower.
        assert!(result.consistency_factor < 1.0);
    }

    #[test]
    fn disabled_engine_returns_base_trust() {
        let engine = TrustAccumulator::new(&TrustAccumulatorConfig {
            enabled: false,
            ..Default::default()
        });
        let profile = test_profile("sk-disabled-test-key12345");
        let result = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            None,
            false,
        );
        assert_eq!(result.trust_score, profile.trust_base);
    }

    #[test]
    fn eviction_at_capacity() {
        let engine = TrustAccumulator::new(&TrustAccumulatorConfig {
            max_identities: 3,
            ..Default::default()
        });

        // Create 4 identities.
        for i in 0..4 {
            let profile = IdentityProfile {
                principal_id: format!("user-{}", i),
                ..IdentityProfile::default()
            };
            engine.evaluate(
                &profile,
                &crate::identity::role_resolver::Role::User,
                "1.2.3.4",
                None,
                false,
            );
        }

        assert_eq!(engine.tracked_count(), 3);
    }

    #[test]
    fn reset_clears_state() {
        let engine = default_engine();
        let profile = test_profile("sk-reset-key12345678901");
        engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::User,
            "1.2.3.4",
            None,
            false,
        );
        assert!(engine.tracked_count() > 0);
        engine.reset();
        assert_eq!(engine.tracked_count(), 0);
    }

    #[test]
    fn trust_clamped_to_range() {
        let engine = default_engine();
        let profile = IdentityProfile {
            trust_base: 0.0,
            ..IdentityProfile::default()
        };
        let result = engine.evaluate(
            &profile,
            &crate::identity::role_resolver::Role::Anonymous,
            "1.2.3.4",
            None,
            false,
        );
        assert!(result.trust_score >= 0.0 && result.trust_score <= 1.0);
    }
}
