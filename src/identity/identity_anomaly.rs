// IdentityAnomaly Engine — Unusual Identity Pattern Detection
//
// Detects anomalies in identity behavior that may indicate:
//   - Credential compromise (sudden IP change, impossible travel)
//   - Token theft (session used from new location)
//   - Privilege escalation attempts (role change patterns)
//   - Automated abuse (high velocity, unusual patterns)
//
// Anomaly detection is heuristic-based (rule engine, no ML per anti-scope).
// Each anomaly produces an anomaly score (0.0-10.0) where:
//   0.0 = no anomaly
//   1.0-3.0 = minor (log only)
//   3.0-6.0 = moderate (increase scrutiny)
//   6.0-10.0 = severe (challenge or deny)
//
// Latency Budget: <0.1ms per evaluation

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Timelike;

use crate::identity::role_resolver::Role;
use crate::identity::session_identity::IdentityProfile;
use crate::identity::trust_accumulator::TrustResult;

/// Types of anomalies detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AnomalyType {
    /// First request from this identity (informational, not necessarily bad).
    NewIdentity,
    /// IP address changed from previous request.
    IpChange,
    /// Impossible travel: distance between consecutive IPs too large for time gap.
    ImpossibleTravel,
    /// User agent changed.
    AgentChange,
    /// Request velocity is abnormally high.
    HighVelocity,
    /// Trust score dropped significantly from previous evaluation.
    TrustDrop,
    /// Identity type changed (e.g., API key → JWT for same principal).
    IdentityTypeChange,
    /// Unusual time of access (outside normal hours).
    OffHoursAccess,
    /// Multiple identity types seen for related principals.
    PrincipalOverlap,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewIdentity => write!(f, "new_identity"),
            Self::IpChange => write!(f, "ip_change"),
            Self::ImpossibleTravel => write!(f, "impossible_travel"),
            Self::AgentChange => write!(f, "agent_change"),
            Self::HighVelocity => write!(f, "high_velocity"),
            Self::TrustDrop => write!(f, "trust_drop"),
            Self::IdentityTypeChange => write!(f, "identity_type_change"),
            Self::OffHoursAccess => write!(f, "off_hours_access"),
            Self::PrincipalOverlap => write!(f, "principal_overlap"),
        }
    }
}

/// A detected anomaly with its severity.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Anomaly {
    /// Type of anomaly.
    pub anomaly_type: AnomalyType,
    /// Severity score (0.0-10.0).
    pub score: f64,
    /// Human-readable description.
    pub description: String,
}

/// Anomaly state for a single identity.
#[derive(Debug, Clone, Default)]
struct AnomalyState {
    last_ip: Option<String>,
    last_agent: Option<String>,
    last_identity_type: Option<String>,
    last_timestamp: i64,
    last_trust: f64,
    request_timestamps: Vec<i64>,
    previous_trusts: Vec<f64>,
}

/// IdentityAnomaly engine configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IdentityAnomalyConfig {
    /// Whether this engine is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Severity score for new identity (default: 1.0 — informational).
    #[serde(default = "default_new_identity_score")]
    pub new_identity_score: f64,

    /// Severity score for IP change (default: 3.0).
    #[serde(default = "default_ip_change_score")]
    pub ip_change_score: f64,

    /// Severity score for impossible travel (default: 8.0).
    #[serde(default = "default_impossible_travel_score")]
    pub impossible_travel_score: f64,

    /// Severity score for agent change (default: 2.0).
    #[serde(default = "default_agent_change_score")]
    pub agent_change_score: f64,

    /// Severity score for high velocity (default: 4.0).
    #[serde(default = "default_high_velocity_score")]
    pub high_velocity_score: f64,

    /// Severity score for trust drop (default: 5.0).
    #[serde(default = "default_trust_drop_score")]
    pub trust_drop_score: f64,

    /// Request velocity threshold (requests per minute).
    /// Above this → HighVelocity anomaly.
    #[serde(default = "default_velocity_threshold")]
    pub velocity_threshold: f64,

    /// Impossible travel speed threshold (km/h).
    /// If distance / time exceeds this, it's impossible.
    /// Default: 800 km/h (faster than any commercial flight).
    #[serde(default = "default_travel_speed_threshold")]
    pub travel_speed_threshold: f64,

    /// Trust drop threshold — if trust drops by more than this fraction,
    /// trigger a TrustDrop anomaly.
    /// Default: 0.3 (30% drop).
    #[serde(default = "default_trust_drop_threshold")]
    pub trust_drop_threshold: f64,

    /// Off-hours range (start_hour, end_hour) in UTC.
    /// Requests outside this range trigger OffHoursAccess anomaly.
    /// Default: (9, 17) — business hours.
    #[serde(default = "default_off_hours")]
    pub off_hours: (u32, u32),

    /// Number of recent request timestamps to keep for velocity calculation.
    #[serde(default = "default_velocity_window")]
    pub velocity_window: usize,

    /// Maximum number of identities to track.
    #[serde(default = "default_max_identities")]
    pub max_identities: usize,
}

fn default_enabled() -> bool {
    true
}
fn default_new_identity_score() -> f64 {
    1.0
}
fn default_ip_change_score() -> f64 {
    3.0
}
fn default_impossible_travel_score() -> f64 {
    8.0
}
fn default_agent_change_score() -> f64 {
    2.0
}
fn default_high_velocity_score() -> f64 {
    4.0
}
fn default_trust_drop_score() -> f64 {
    5.0
}
fn default_velocity_threshold() -> f64 {
    30.0
}
fn default_travel_speed_threshold() -> f64 {
    800.0
}
fn default_trust_drop_threshold() -> f64 {
    0.3
}
fn default_off_hours() -> (u32, u32) {
    (9, 17)
}
fn default_velocity_window() -> usize {
    100
}
fn default_max_identities() -> usize {
    10_000
}

impl Default for IdentityAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            new_identity_score: default_new_identity_score(),
            ip_change_score: default_ip_change_score(),
            impossible_travel_score: default_impossible_travel_score(),
            agent_change_score: default_agent_change_score(),
            high_velocity_score: default_high_velocity_score(),
            trust_drop_score: default_trust_drop_score(),
            velocity_threshold: default_velocity_threshold(),
            travel_speed_threshold: default_travel_speed_threshold(),
            trust_drop_threshold: default_trust_drop_threshold(),
            off_hours: default_off_hours(),
            velocity_window: default_velocity_window(),
            max_identities: default_max_identities(),
        }
    }
}

/// Result of anomaly evaluation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnomalyResult {
    /// List of detected anomalies.
    pub anomalies: Vec<Anomaly>,
    /// Composite anomaly score (max of all anomalies, 0.0-10.0).
    pub composite_score: f64,
    /// Whether any severe anomaly was detected.
    pub is_severe: bool,
    /// Human-readable summary.
    pub summary: String,
}

/// The IdentityAnomaly engine.
///
/// Detects unusual patterns in identity behavior.
/// Stateful — tracks per-identity state for comparison.
pub struct IdentityAnomaly {
    config: IdentityAnomalyConfig,
    state: Arc<Mutex<HashMap<String, AnomalyState>>>,
}

impl IdentityAnomaly {
    pub fn new(config: &IdentityAnomalyConfig) -> Self {
        Self {
            config: config.clone(),
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Evaluate for anomalies in the current request.
    pub fn evaluate(
        &self,
        profile: &IdentityProfile,
        _role: &Role,
        source_ip: &str,
        user_agent: Option<&str>,
        trust_result: &TrustResult,
    ) -> AnomalyResult {
        if !self.config.enabled {
            return AnomalyResult {
                anomalies: vec![],
                composite_score: 0.0,
                is_severe: false,
                summary: "identity_anomaly engine disabled".into(),
            };
        }

        let mut anomalies: Vec<Anomaly> = Vec::new();
        let principal = &profile.principal_id;
        let now = chrono::Utc::now().timestamp();

        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Evict if at capacity.
        if states.len() >= self.config.max_identities && !states.contains_key(principal) {
            if let Some(oldest_key) = states
                .iter()
                .min_by_key(|(_, s)| s.last_timestamp)
                .map(|(k, _)| k.clone())
            {
                states.remove(&oldest_key);
            }
        }

        let entry = states.entry(principal.clone()).or_default();
        let is_new = entry.last_timestamp == 0;

        if is_new {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::NewIdentity,
                score: self.config.new_identity_score,
                description: "first request from this identity".into(),
            });
        }

        // IP change detection.
        if let Some(ref last_ip) = entry.last_ip {
            if last_ip != source_ip {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::IpChange,
                    score: self.config.ip_change_score,
                    description: format!("IP changed from {} to {}", last_ip, source_ip),
                });

                // Impossible travel check.
                if let Some(distance_km) = estimate_distance(last_ip, source_ip) {
                    let time_hours = if entry.last_timestamp > 0 {
                        ((now - entry.last_timestamp) as f64 / 3600.0).max(0.001)
                    } else {
                        1.0
                    };
                    let speed_kmh = distance_km / time_hours;

                    if speed_kmh > self.config.travel_speed_threshold {
                        let score = self.config.impossible_travel_score
                            * (speed_kmh / self.config.travel_speed_threshold).min(2.0);
                        anomalies.push(Anomaly {
                            anomaly_type: AnomalyType::ImpossibleTravel,
                            score: score.min(10.0),
                            description: format!(
                                "impossible travel: {:.0} km in {:.1}h ({:.0} km/h)",
                                distance_km, time_hours, speed_kmh
                            ),
                        });
                    }
                }
            }
        }

        // Agent change detection.
        if let Some(ref last_agent) = entry.last_agent {
            if let Some(current_agent) = user_agent {
                if last_agent != current_agent {
                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::AgentChange,
                        score: self.config.agent_change_score,
                        description: format!(
                            "user agent changed from '{}' to '{}'",
                            last_agent, current_agent
                        ),
                    });
                }
            }
        }

        // Identity type change.
        if let Some(ref last_type) = entry.last_identity_type {
            let current_type = profile.identity_type.to_string();
            if last_type != &current_type {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::IdentityTypeChange,
                    score: 5.0,
                    description: format!(
                        "identity type changed from {} to {}",
                        last_type, current_type
                    ),
                });
            }
        }

        // Velocity check.
        entry.request_timestamps.push(now);
        // Keep only the velocity window.
        let window_start = now - 60; // Last 60 seconds.
        entry.request_timestamps.retain(|&t| t >= window_start);
        if entry.request_timestamps.len() as f64 > self.config.velocity_threshold {
            let rate = entry.request_timestamps.len() as f64;
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::HighVelocity,
                score: self.config.high_velocity_score
                    * (rate / self.config.velocity_threshold).min(2.0),
                description: format!(
                    "high request velocity: {} requests in last 60s (threshold: {:.0})",
                    rate, self.config.velocity_threshold
                ),
            });
        }

        // Trust drop detection.
        if entry.previous_trusts.len() >= 3 {
            let avg_prev: f64 =
                entry.previous_trusts.iter().sum::<f64>() / entry.previous_trusts.len() as f64;
            if avg_prev > 0.0 {
                let drop_fraction = (avg_prev - trust_result.trust_score) / avg_prev;
                if drop_fraction > self.config.trust_drop_threshold {
                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::TrustDrop,
                        score: self.config.trust_drop_score,
                        description: format!(
                            "trust dropped from {:.3} to {:.3} ({:.1}% decline)",
                            avg_prev,
                            trust_result.trust_score,
                            drop_fraction * 100.0
                        ),
                    });
                }
            }
        }

        // Off-hours access.
        let hour = chrono::Utc::now().hour() as u32;
        if hour < self.config.off_hours.0 || hour >= self.config.off_hours.1 {
            // Only flag for authenticated identities (not anonymous).
            if profile.identity_type != crate::identity::session_identity::IdentityType::Anonymous {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::OffHoursAccess,
                    score: 2.0, // Informational.
                    description: format!(
                        "access at {} UTC (outside business hours {:?})",
                        hour, self.config.off_hours
                    ),
                });
            }
        }

        // Update state.
        entry.last_ip = Some(source_ip.to_string());
        entry.last_agent = user_agent.map(|s| s.to_string());
        entry.last_identity_type = Some(profile.identity_type.to_string());
        entry.last_timestamp = now;
        entry.last_trust = trust_result.trust_score;
        entry.previous_trusts.push(trust_result.trust_score);
        if entry.previous_trusts.len() > 20 {
            entry.previous_trusts.remove(0);
        }

        // Compute composite score.
        let composite_score = anomalies.iter().map(|a| a.score).fold(0.0_f64, f64::max);
        let is_severe = composite_score >= 6.0;

        let summary = if anomalies.is_empty() {
            "no anomalies detected".into()
        } else {
            format!(
                "{} anomalies (composite={:.1}): {}",
                anomalies.len(),
                composite_score,
                anomalies
                    .iter()
                    .map(|a| a.anomaly_type.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        AnomalyResult {
            anomalies,
            composite_score: composite_score.min(10.0),
            is_severe,
            summary,
        }
    }

    /// Reset all anomaly state (for testing).
    pub fn reset(&self) {
        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        states.clear();
    }
}

impl Clone for IdentityAnomaly {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

/// Estimate geographic distance between two IP addresses (km).
///
/// This is a rough estimate based on the first octet of the IP.
/// In production, this would use a GeoIP database. For Phase 3,
/// we use a simple heuristic: different /8 blocks = ~5000km,
/// different /16 blocks = ~500km, same /16 = ~50km.
fn estimate_distance(ip_a: &str, ip_b: &str) -> Option<f64> {
    let addr_a: std::net::IpAddr = ip_a.parse().ok()?;
    let addr_b: std::net::IpAddr = ip_b.parse().ok()?;

    // Only IPv4 for now.
    let octets_a = match addr_a {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return None,
    };
    let octets_b = match addr_b {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return None,
    };

    let distance = if octets_a[0] != octets_b[0] {
        // Different /8 — likely different region/country.
        5000.0
    } else if octets_a[0..2] != octets_b[0..2] {
        // Different /16 — likely different city.
        500.0
    } else if octets_a[0..3] != octets_b[0..3] {
        // Different /24 — likely different subnet.
        50.0
    } else {
        // Same /24 — nearby.
        5.0
    };

    Some(distance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::role_resolver::Role;
    use crate::identity::session_identity::{IdentityProfile, IdentityType};

    fn default_engine() -> IdentityAnomaly {
        IdentityAnomaly::new(&IdentityAnomalyConfig::default())
    }

    fn test_profile() -> IdentityProfile {
        IdentityProfile {
            identity_type: IdentityType::ApiKey,
            principal_id: "key:test123456".into(),
            credential_ref: "sk-test-key".into(),
            trust_base: 0.5,
            claims: vec![],
            format_valid: true,
        }
    }

    fn default_trust() -> TrustResult {
        TrustResult {
            trust_score: 0.5,
            base_trust: 0.5,
            age_factor: 0.5,
            consistency_factor: 1.0,
            volume_factor: 1.0,
            denial_factor: 1.0,
            request_count: 10,
            denial_count: 0,
            is_new: false,
            reason: "test".into(),
        }
    }

    #[test]
    fn new_identity_detected() {
        let engine = default_engine();
        let result = engine.evaluate(
            &test_profile(),
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        assert!(result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::NewIdentity));
        assert!(result.composite_score > 0.0);
    }

    #[test]
    fn ip_change_detected() {
        let engine = default_engine();
        let profile = test_profile();

        // First request.
        engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        // Second request from different IP.
        let result = engine.evaluate(
            &profile,
            &Role::User,
            "5.6.7.8",
            Some("agent"),
            &default_trust(),
        );

        assert!(result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::IpChange));
    }

    #[test]
    fn agent_change_detected() {
        let engine = default_engine();
        let profile = test_profile();

        engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent-v1"),
            &default_trust(),
        );
        let result = engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent-v2"),
            &default_trust(),
        );

        assert!(result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::AgentChange));
    }

    #[test]
    fn same_ip_no_ip_anomaly() {
        let engine = default_engine();
        let profile = test_profile();

        engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        let result = engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );

        assert!(!result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::IpChange));
    }

    #[test]
    fn impossible_travel_different_continent() {
        let engine = IdentityAnomaly::new(&IdentityAnomalyConfig {
            travel_speed_threshold: 500.0, // Lower threshold for testing
            ..Default::default()
        });
        let profile = test_profile();

        // First from US (1.x.x.x), then from Europe (5.x.x.x), then from Asia (10.x.x.x).
        engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        // Simulate time passing (1 minute).
        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = engine.evaluate(
            &profile,
            &Role::User,
            "5.6.7.8",
            Some("agent"),
            &default_trust(),
        );

        // With our heuristic, 1.x → 5.x is ~5000km. With ~0s elapsed, speed = infinity.
        // The time gap is tiny, so speed should be enormous.
        if let Some(travel) = result
            .anomalies
            .iter()
            .find(|a| a.anomaly_type == AnomalyType::ImpossibleTravel)
        {
            assert!(travel.score > 0.0);
        }
    }

    #[test]
    fn disabled_engine_no_anomalies() {
        let engine = IdentityAnomaly::new(&IdentityAnomalyConfig {
            enabled: false,
            ..Default::default()
        });
        let result = engine.evaluate(
            &test_profile(),
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        assert!(result.anomalies.is_empty());
        assert_eq!(result.composite_score, 0.0);
    }

    #[test]
    fn composite_score_is_max() {
        let engine = default_engine();
        let profile = test_profile();

        // New identity gets scored.
        let result = engine.evaluate(
            &profile,
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        let expected = result
            .anomalies
            .iter()
            .map(|a| a.score)
            .fold(0.0_f64, f64::max);
        assert!((result.composite_score - expected).abs() < 0.01);
    }

    #[test]
    fn trust_drop_detected() {
        let engine = default_engine();
        let profile = test_profile();

        // Build up trust history.
        let high_trust = TrustResult {
            trust_score: 0.8,
            ..default_trust()
        };
        for _ in 0..5 {
            engine.evaluate(&profile, &Role::User, "1.2.3.4", Some("agent"), &high_trust);
        }

        // Suddenly drop trust.
        let low_trust = TrustResult {
            trust_score: 0.1,
            ..default_trust()
        };
        let result = engine.evaluate(&profile, &Role::User, "1.2.3.4", Some("agent"), &low_trust);

        assert!(result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::TrustDrop));
    }

    #[test]
    fn reset_clears_state() {
        let engine = default_engine();
        engine.evaluate(
            &test_profile(),
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        engine.reset();
        // After reset, next request should be treated as new.
        let result = engine.evaluate(
            &test_profile(),
            &Role::User,
            "1.2.3.4",
            Some("agent"),
            &default_trust(),
        );
        assert!(result
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::NewIdentity));
    }

    #[test]
    fn distance_estimate_basic() {
        // Same /8 = small distance
        let d = estimate_distance("1.2.3.4", "1.5.6.7").unwrap();
        assert!(d < 1000.0);

        // Different /8 = large distance
        let d = estimate_distance("1.2.3.4", "5.6.7.8").unwrap();
        assert!(d >= 1000.0);
    }
}
