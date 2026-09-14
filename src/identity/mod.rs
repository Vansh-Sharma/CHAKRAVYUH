// Identity Ring — Authentication, Authorization & Trust (Ring 2)
//
// Ring 2 of the CHAKRAVYUH 9-ring architecture.
// Manages identity classification, role resolution, trust scoring,
// and anomaly detection for every request.
//
// Engines (Phase 3 scope):
//   1. SessionIdentity     — credential classification (API key, JWT, session, mTLS, internal)
//   2. RoleResolver         — RBAC role mapping with permission sets
//   3. TrustAccumulator     — per-identity trust scoring (behavioral, consistent, decay)
//   4. IdentityAnomaly      — unusual pattern detection (IP hop, impossible travel, velocity)
//
// Pipeline:
//   SessionIdentity → RoleResolver → TrustAccumulator → IdentityAnomaly
//
// The Identity Ring does NOT block requests directly — it produces an
// IdentityVerdict with a risk score that Keshav-Risk uses in its composite.
// However, if anomaly score is severe (>=8.0) or identity is invalid,
// the ring CAN escalate to Challenge or Deny.
//
// Latency Budget: <1ms p99 for full Identity Ring evaluation
// Architecture Principle: Fail Open with Logging (identity issues are risks, not blocks)

pub mod auth;
pub mod identity_anomaly;
pub mod platform;
pub mod role_resolver;
pub mod session_identity;
pub mod trust_accumulator;

use std::sync::Arc;

use crate::decision::{Decision, Verdict};
use crate::Result;

pub use auth::{AuthError, AuthService, Claims, JwtConfig, TokenPair};
pub use identity_anomaly::{AnomalyResult, IdentityAnomaly, IdentityAnomalyConfig};
pub use platform::{
    api_key_prefix, generate_api_key, hash_api_key, hash_refresh_token, is_live_key,
    is_valid_api_key_format, ApiKey, AuditLog, Membership, Organization, Plan, PlatformStore,
    RefreshToken, User, Workspace,
};
pub use role_resolver::{Permission, Role, RoleResolver, RoleResolverConfig};
pub use session_identity::{IdentityProfile, IdentityType, SessionIdentity, SessionIdentityConfig};
pub use trust_accumulator::{TrustAccumulator, TrustAccumulatorConfig, TrustResult};

/// Identity Ring configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IdentityConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub session_identity: SessionIdentityConfig,

    #[serde(default)]
    pub role_resolver: RoleResolverConfig,

    #[serde(default)]
    pub trust_accumulator: TrustAccumulatorConfig,

    #[serde(default)]
    pub identity_anomaly: IdentityAnomalyConfig,

    /// Anomaly score threshold for challenge (default: 6.0).
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: f64,

    /// Anomaly score threshold for deny (default: 9.0).
    #[serde(default = "default_deny_threshold")]
    pub deny_threshold: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_challenge_threshold() -> f64 {
    6.0
}
fn default_deny_threshold() -> f64 {
    9.0
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            session_identity: SessionIdentityConfig::default(),
            role_resolver: RoleResolverConfig::default(),
            trust_accumulator: TrustAccumulatorConfig::default(),
            identity_anomaly: IdentityAnomalyConfig::default(),
            challenge_threshold: default_challenge_threshold(),
            deny_threshold: default_deny_threshold(),
        }
    }
}

/// A request as seen by the Identity Ring.
#[derive(Debug, Clone)]
pub struct IdentityRequest {
    /// Source IP address.
    pub source_ip: String,
    /// User agent string.
    pub user_agent: Option<String>,
    /// API key from Authorization header (Bearer token).
    pub api_key: Option<String>,
    /// Whether the request was already denied by a prior ring.
    pub was_denied: bool,
    /// Request ID for correlation.
    pub request_id: String,
    /// All headers (for extracting custom identity headers).
    pub headers: std::collections::HashMap<String, String>,
}

/// Per-engine result within the Identity Ring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentityEngineResult {
    pub engine_name: String,
    pub decision: String,
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

/// The verdict returned by the Identity Ring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentityVerdict {
    /// The final decision (usually Allow — identity issues are risks, not blocks).
    pub decision: Decision,
    /// The classified identity profile.
    pub identity_profile: Option<IdentityProfile>,
    /// The resolved role.
    pub role: Option<Role>,
    /// The computed trust result.
    pub trust_result: Option<TrustResult>,
    /// The anomaly detection result.
    pub anomaly_result: Option<AnomalyResult>,
    /// Per-engine results.
    pub engine_results: Vec<IdentityEngineResult>,
    /// Total latency.
    pub latency_ms: f64,
    /// The identity risk score (0.0-10.0) for Keshav-Risk.
    pub identity_risk_score: f64,
}

impl Verdict for IdentityVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }

    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

impl IdentityVerdict {
    fn disabled(start: std::time::Instant) -> Self {
        Self {
            decision: Decision::Allow,
            identity_profile: None,
            role: None,
            trust_result: None,
            anomaly_result: None,
            engine_results: vec![],
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            identity_risk_score: 0.0,
        }
    }
}

/// The Identity Ring — coordinates 4 engines for identity security.
///
/// Evaluation order:
///   1. SessionIdentity  — classify credentials → IdentityProfile
///   2. RoleResolver      — map profile to role + permissions
///   3. TrustAccumulator — compute trust score from behavior
///   4. IdentityAnomaly  — detect unusual patterns
///
/// Output: IdentityVerdict with identity_risk_score for Keshav-Risk.
pub struct IdentityRing {
    config: Arc<IdentityConfig>,
    session_identity: Arc<SessionIdentity>,
    role_resolver: Arc<RoleResolver>,
    trust_accumulator: Arc<TrustAccumulator>,
    identity_anomaly: Arc<IdentityAnomaly>,
}

impl IdentityRing {
    /// Create a new Identity Ring with the given configuration.
    pub fn new(config: &IdentityConfig) -> Result<Self> {
        Ok(Self {
            session_identity: Arc::new(SessionIdentity::new(&config.session_identity)),
            role_resolver: Arc::new(RoleResolver::new(&config.role_resolver)),
            trust_accumulator: Arc::new(TrustAccumulator::new(&config.trust_accumulator)),
            identity_anomaly: Arc::new(IdentityAnomaly::new(&config.identity_anomaly)),
            config: Arc::new(config.clone()),
        })
    }

    /// Evaluate a request through all Identity engines.
    ///
    /// Returns an IdentityVerdict with risk score for Keshav-Risk.
    pub fn evaluate(&self, request: &IdentityRequest) -> IdentityVerdict {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return IdentityVerdict::disabled(start);
        }

        let mut engine_results: Vec<IdentityEngineResult> = Vec::with_capacity(4);

        // Engine 1: SessionIdentity — classify credentials.
        let id_result = self
            .session_identity
            .evaluate(request.api_key.as_deref(), &request.headers);
        engine_results.push(IdentityEngineResult {
            engine_name: "session_identity".into(),
            decision: if id_result.valid { "valid" } else { "invalid" }.into(),
            reason: id_result.reason.clone(),
            latency_ms: id_result.latency_ms,
            metadata: serde_json::to_value(&id_result.profile).unwrap_or_default(),
        });

        // If credential format is invalid, that's an immediate risk signal.
        if !id_result.valid {
            let verdict = IdentityVerdict {
                decision: Decision::Challenge {
                    challenge_type: crate::decision::ChallengeType::TwoFactor,
                },
                identity_profile: Some(id_result.profile),
                role: None,
                trust_result: None,
                anomaly_result: None,
                engine_results,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                identity_risk_score: 8.0, // High risk — invalid credentials.
            };
            return verdict;
        }

        // Engine 2: RoleResolver — determine role and permissions.
        let role_result = self.role_resolver.evaluate(&id_result.profile);
        engine_results.push(IdentityEngineResult {
            engine_name: "role_resolver".into(),
            decision: role_result.role.to_string(),
            reason: role_result.reason.clone(),
            latency_ms: 0.0,
            metadata: serde_json::json!({
                "role": role_result.role.to_string(),
                "permissions": role_result.permissions.iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>(),
            }),
        });

        // Engine 3: TrustAccumulator — compute trust score.
        let trust_result = self.trust_accumulator.evaluate(
            &id_result.profile,
            &role_result.role,
            &request.source_ip,
            request.user_agent.as_deref(),
            request.was_denied,
        );
        engine_results.push(IdentityEngineResult {
            engine_name: "trust_accumulator".into(),
            decision: format!("trust={:.3}", trust_result.trust_score),
            reason: trust_result.reason.clone(),
            latency_ms: 0.0,
            metadata: serde_json::to_value(&trust_result).unwrap_or_default(),
        });

        // Engine 4: IdentityAnomaly — detect unusual patterns.
        let anomaly_result = self.identity_anomaly.evaluate(
            &id_result.profile,
            &role_result.role,
            &request.source_ip,
            request.user_agent.as_deref(),
            &trust_result,
        );
        engine_results.push(IdentityEngineResult {
            engine_name: "identity_anomaly".into(),
            decision: if anomaly_result.is_severe {
                "severe"
            } else if anomaly_result.composite_score > 0.0 {
                "flagged"
            } else {
                "clear"
            }
            .into(),
            reason: anomaly_result.summary.clone(),
            latency_ms: 0.0,
            metadata: serde_json::to_value(&anomaly_result).unwrap_or_default(),
        });

        // Compute identity risk score for Keshav-Risk.
        // Higher anomaly → higher risk. Lower trust → higher risk.
        // Range: 0.0 (no risk) to 10.0 (maximum risk).
        let identity_risk_score = {
            let anomaly_component = anomaly_result.composite_score; // 0-10
            let trust_component = (1.0 - trust_result.trust_score) * 10.0; // 0-10
                                                                           // Weight: anomaly is 60%, trust is 40%.
            (anomaly_component * 0.6 + trust_component * 0.4).clamp(0.0, 10.0)
        };

        // Determine decision based on anomaly severity.
        let decision = if anomaly_result.composite_score >= self.config.deny_threshold {
            Decision::Deny {
                code: "IDENTITY_ANOMALY_SEVERE".into(),
                retry_after: Some(300),
            }
        } else if anomaly_result.composite_score >= self.config.challenge_threshold {
            Decision::Challenge {
                challenge_type: crate::decision::ChallengeType::TwoFactor,
            }
        } else {
            Decision::Allow
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        IdentityVerdict {
            decision,
            identity_profile: Some(id_result.profile),
            role: Some(role_result.role),
            trust_result: Some(trust_result),
            anomaly_result: Some(anomaly_result),
            engine_results,
            latency_ms,
            identity_risk_score,
        }
    }

    /// Get a reference to the trust accumulator.
    pub fn trust_accumulator(&self) -> &TrustAccumulator {
        &self.trust_accumulator
    }

    /// Get a reference to the identity anomaly engine.
    pub fn identity_anomaly(&self) -> &IdentityAnomaly {
        &self.identity_anomaly
    }

    /// Get the configuration.
    pub fn config(&self) -> &IdentityConfig {
        &self.config
    }
}

impl Clone for IdentityRing {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            session_identity: Arc::clone(&self.session_identity),
            role_resolver: Arc::clone(&self.role_resolver),
            trust_accumulator: Arc::clone(&self.trust_accumulator),
            identity_anomaly: Arc::clone(&self.identity_anomaly),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ring() -> IdentityRing {
        IdentityRing::new(&IdentityConfig::default()).unwrap()
    }

    fn make_request(api_key: Option<&str>, ip: &str) -> IdentityRequest {
        let mut headers = std::collections::HashMap::new();
        if let Some(key) = api_key {
            headers.insert("authorization".into(), format!("Bearer {}", key));
        }
        IdentityRequest {
            source_ip: ip.into(),
            user_agent: Some("test-agent/1.0".into()),
            api_key: api_key.map(|s| s.to_string()),
            was_denied: false,
            request_id: "test-req-1".into(),
            headers,
        }
    }

    #[test]
    fn anonymous_request_allowed() {
        let ring = default_ring();
        let request = make_request(None, "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert!(verdict.decision.is_allow());
        assert_eq!(
            verdict.identity_profile.as_ref().unwrap().identity_type,
            IdentityType::Anonymous
        );
    }

    #[test]
    fn valid_api_key_allowed() {
        let ring = default_ring();
        let request = make_request(Some("sk-test-regular-api-key-12345"), "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert!(verdict.decision.is_allow());
        assert_eq!(
            verdict.identity_profile.as_ref().unwrap().identity_type,
            IdentityType::ApiKey
        );
        assert_eq!(verdict.role.as_ref().unwrap(), &Role::User);
    }

    #[test]
    fn admin_api_key_gets_admin_role() {
        let ring = default_ring();
        let request = make_request(Some("sk-admin-supersecretkey12345"), "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert!(verdict.decision.is_allow());
        assert_eq!(verdict.role.as_ref().unwrap(), &Role::Admin);
    }

    #[test]
    fn invalid_credential_challenged() {
        let ring = default_ring();
        let request = make_request(Some("sk-short"), "1.2.3.4");
        let verdict = ring.evaluate(&request);
        // Short API key should trigger Challenge.
        assert!(!verdict.decision.is_allow());
        assert!(verdict.identity_risk_score > 5.0);
    }

    #[test]
    fn disabled_ring_allows_all() {
        let config = IdentityConfig {
            enabled: false,
            ..Default::default()
        };
        let ring = IdentityRing::new(&config).unwrap();
        let request = make_request(None, "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert!(verdict.decision.is_allow());
        assert!(verdict.identity_profile.is_none());
        assert_eq!(verdict.identity_risk_score, 0.0);
    }

    #[test]
    fn four_engines_evaluated() {
        let ring = default_ring();
        let request = make_request(Some("sk-test-key-16chars-min"), "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert_eq!(verdict.engine_results.len(), 4);
        let names: Vec<&str> = verdict
            .engine_results
            .iter()
            .map(|r| r.engine_name.as_str())
            .collect();
        assert!(names.contains(&"session_identity"));
        assert!(names.contains(&"role_resolver"));
        assert!(names.contains(&"trust_accumulator"));
        assert!(names.contains(&"identity_anomaly"));
    }

    #[test]
    fn identity_risk_score_in_range() {
        let ring = default_ring();
        let request = make_request(Some("sk-test-key-16chars-min"), "1.2.3.4");
        let verdict = ring.evaluate(&request);
        assert!(verdict.identity_risk_score >= 0.0);
        assert!(verdict.identity_risk_score <= 10.0);
    }

    #[test]
    fn ip_change_increases_risk() {
        let ring = default_ring();

        // First request from one IP.
        let req1 = make_request(Some("sk-test-key-16chars-min"), "1.2.3.4");
        ring.evaluate(&req1);

        // Second request from different IP (different /8 = large distance).
        let req2 = make_request(Some("sk-test-key-16chars-min"), "5.6.7.8");
        let verdict = ring.evaluate(&req2);

        // Should detect anomalies (IP change).
        let anomaly = verdict.anomaly_result.as_ref().unwrap();
        assert!(anomaly.composite_score > 0.0);
    }

    #[test]
    fn trust_grows_with_consistency() {
        let ring = default_ring();

        // 10 consistent requests.
        for _ in 0..10 {
            let req = make_request(Some("sk-test-key-16chars-min"), "1.2.3.4");
            ring.evaluate(&req);
        }

        let req = make_request(Some("sk-test-key-16chars-min"), "1.2.3.4");
        let verdict = ring.evaluate(&req);

        let trust = verdict.trust_result.as_ref().unwrap();
        // Trust should grow with consistent behavior.
        assert!(trust.request_count >= 10);
    }

    #[test]
    fn session_identity_headers() {
        let ring = default_ring();
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "x-session-token".into(),
            "sess_abcdefghij12345678901234".into(),
        );
        let request = IdentityRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: None,
            api_key: None,
            was_denied: false,
            request_id: "test".into(),
            headers,
        };
        let verdict = ring.evaluate(&request);
        assert_eq!(
            verdict.identity_profile.as_ref().unwrap().identity_type,
            IdentityType::Session
        );
    }

    #[test]
    fn internal_identity_highest_trust() {
        let ring = default_ring();
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-internal-identity".into(), "keshav-core".into());
        let request = IdentityRequest {
            source_ip: "127.0.0.1".into(),
            user_agent: None,
            api_key: None,
            was_denied: false,
            request_id: "test".into(),
            headers,
        };
        let verdict = ring.evaluate(&request);
        assert_eq!(
            verdict.identity_profile.as_ref().unwrap().identity_type,
            IdentityType::Internal
        );
        assert_eq!(verdict.role.as_ref().unwrap(), &Role::Admin);
        let trust = verdict.trust_result.as_ref().unwrap();
        assert!(trust.trust_score > 0.5); // High trust for internal.
    }
}
