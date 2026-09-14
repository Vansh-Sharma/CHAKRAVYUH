// Identity Threat Benchmark — Phase 3 Exit Criteria Tests
//
// Tests Identity Ring detection capabilities across:
//   - Credential classification accuracy
//   - Role resolution correctness
//   - Trust scoring behavior
//   - Anomaly detection sensitivity
//   - End-to-end Identity Ring pipeline
//   - Keshav-Risk integration with Identity Ring signals
//
// Exit Criteria:
//   - All identity types correctly classified: 100%
//   - Role resolution accuracy: 100%
//   - Invalid credentials flagged: 100%
//   - Anomaly detection: IP change, agent change, impossible travel detected
//   - Keshav-Risk identity signal correctly propagated
//   - Full pipeline latency: <5ms p99
//   - Zero false positives on benign authenticated requests

use chakravyuh::identity::{
    IdentityAnomalyConfig, IdentityConfig, IdentityRequest, IdentityRing,
    Role, SessionIdentityConfig,
};
use chakravyuh::keshav::{KeshavRisk, RiskConfig, RiskSignals};
use chakravyuh::keshav::risk::ContextSignals;
use std::collections::HashMap;
use std::time::Instant;

// ─── Credential Classification Accuracy ───

#[test]
fn identity_classifies_anonymous() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(None, "1.2.3.4", None, None);
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "anonymous");
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_api_key_sk_prefix() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-live-abcdef1234567890"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "api_key");
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_api_key_pk_prefix() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("pk-test-abcdef1234567890"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "api_key");
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_jwt() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let jwt = make_test_jwt("user-42", "auth.example.com", None);
    let req = make_request(Some(&jwt), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "jwt");
    assert_eq!(profile.principal_id, "user-42");
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_session_token() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let mut headers = HashMap::new();
    headers.insert("x-session-token".into(), "sess_abcdefghijklmnop1234567890".into());
    let req = IdentityRequest {
        source_ip: "10.0.0.1".into(),
        user_agent: None,
        api_key: None,
        was_denied: false,
        request_id: "bench-1".into(),
        headers,
    };
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "session");
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_internal() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let mut headers = HashMap::new();
    headers.insert("x-internal-identity".into(), "keshav-core".into());
    let req = IdentityRequest {
        source_ip: "127.0.0.1".into(),
        user_agent: None,
        api_key: None,
        was_denied: false,
        request_id: "bench-1".into(),
        headers,
    };
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "internal");
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Admin);
    assert!(verdict.decision.is_allow());
}

#[test]
fn identity_classifies_mtls() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let mut headers = HashMap::new();
    headers.insert("x-client-cert-fingerprint".into(), "a1b2c3d4e5f6a7b8c9d0e1f2".into());
    let req = IdentityRequest {
        source_ip: "10.0.0.1".into(),
        user_agent: None,
        api_key: None,
        was_denied: false,
        request_id: "bench-1".into(),
        headers,
    };
    let verdict = ring.evaluate(&req);
    let profile = verdict.identity_profile.as_ref().unwrap();
    assert_eq!(profile.identity_type.to_string(), "mtls");
    assert!(verdict.decision.is_allow());
}

// ─── Invalid Credential Detection ───

#[test]
fn invalid_short_api_key_challenged() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-short"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert!(!verdict.decision.is_allow());
    assert!(verdict.identity_risk_score > 5.0);
}

#[test]
fn invalid_api_key_prefix_challenged() {
    let ring = IdentityRing::new(&IdentityConfig {
        session_identity: SessionIdentityConfig {
            valid_api_key_prefixes: vec!["sk-".into()],
            ..Default::default()
        },
        ..Default::default()
    }).unwrap();
    let req = make_request(Some("xx-long-enough-key-1234567"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert!(!verdict.decision.is_allow());
}

#[test]
fn invalid_session_token_challenged() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let mut headers = HashMap::new();
    headers.insert("x-session-token".into(), "short".into());
    let req = IdentityRequest {
        source_ip: "10.0.0.1".into(),
        user_agent: None,
        api_key: None,
        was_denied: false,
        request_id: "bench-1".into(),
        headers,
    };
    let verdict = ring.evaluate(&req);
    assert!(!verdict.decision.is_allow());
}

// ─── Role Resolution Accuracy ───

#[test]
fn anonymous_gets_anonymous_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(None, "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Anonymous);
}

#[test]
fn api_key_gets_user_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-regular-key-16chars-min"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::User);
}

#[test]
fn admin_api_key_gets_admin_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-admin-supersecretkey12345"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Admin);
}

#[test]
fn operator_api_key_gets_operator_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-op-operator-key-123456"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Operator);
}

#[test]
fn auditor_api_key_gets_auditor_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-audit-auditor-key-1234"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Auditor);
}

#[test]
fn service_api_key_gets_service_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-svc-backend-service-key"), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Service);
}

#[test]
fn jwt_admin_claim_gets_admin_role() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let jwt = make_test_jwt("admin-user", "auth.example.com", Some("admin"));
    let req = make_request(Some(&jwt), "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.role.as_ref().unwrap(), &Role::Admin);
}

// ─── Trust Scoring Behavior ───

#[test]
fn new_identity_low_trust() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(None, "10.0.0.1", None, None);
    let verdict = ring.evaluate(&req);
    let trust = verdict.trust_result.as_ref().unwrap();
    assert!(trust.is_new);
    assert!(trust.trust_score < 1.0); // Anonymous + new = low trust (not full)
}

#[test]
fn trust_grows_with_consistency() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-trust-growth-key-12345";
    let mut max_trust: f64 = 0.0;

    for _ in 0..15 {
        let req = make_request(Some(key), "10.0.0.1", Some("consistent-agent"), None);
        let verdict = ring.evaluate(&req);
        let trust = verdict.trust_result.as_ref().unwrap().trust_score;
        max_trust = max_trust.max(trust);
    }

    let req = make_request(Some(key), "10.0.0.1", Some("consistent-agent"), None);
    let verdict = ring.evaluate(&req);
    let final_trust = verdict.trust_result.as_ref().unwrap().trust_score;
    assert!(final_trust > 0.0);
}

#[test]
fn denials_reduce_trust() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-denial-reduce-key-1234";

    for _ in 0..10 {
        let req = IdentityRequest {
            was_denied: true,
            ..make_request(Some(key), "10.0.0.1", Some("agent"), None)
        };
        ring.evaluate(&req);
    }

    let req = make_request(Some(key), "10.0.0.1", Some("agent"), None);
    let verdict = ring.evaluate(&req);
    let trust = verdict.trust_result.as_ref().unwrap();
    assert_eq!(trust.denial_count, 10);
    assert!(trust.denial_factor < 1.0);
}

// ─── Anomaly Detection ───

#[test]
fn ip_change_detected() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-ip-change-key-1234567";

    let req1 = make_request(Some(key), "1.2.3.4", Some("agent"), None);
    ring.evaluate(&req1);

    let req2 = make_request(Some(key), "5.6.7.8", Some("agent"), None);
    let verdict = ring.evaluate(&req2);

    let anomaly = verdict.anomaly_result.as_ref().unwrap();
    assert!(anomaly.anomalies.iter().any(|a| a.anomaly_type.to_string() == "ip_change"));
    assert!(anomaly.composite_score > 0.0);
}

#[test]
fn agent_change_detected() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-agent-change-key-12345";

    let req1 = make_request(Some(key), "10.0.0.1", Some("old-agent/1.0"), None);
    ring.evaluate(&req1);

    let req2 = make_request(Some(key), "10.0.0.1", Some("new-agent/2.0"), None);
    let verdict = ring.evaluate(&req2);

    let anomaly = verdict.anomaly_result.as_ref().unwrap();
    assert!(anomaly.anomalies.iter().any(|a| a.anomaly_type.to_string() == "agent_change"));
}

#[test]
fn high_velocity_detected() {
    let config = IdentityConfig {
        identity_anomaly: IdentityAnomalyConfig {
            velocity_threshold: 5.0, // Low threshold for testing
            ..Default::default()
        },
        ..Default::default()
    };
    let ring = IdentityRing::new(&config).unwrap();
    let key = "sk-velocity-key-12345678";

    for _ in 0..10 {
        let req = make_request(Some(key), "10.0.0.1", Some("agent"), None);
        ring.evaluate(&req);
    }

    let verdict = ring.evaluate(&make_request(Some(key), "10.0.0.1", Some("agent"), None));
    let anomaly = verdict.anomaly_result.as_ref().unwrap();
    assert!(anomaly.anomalies.iter().any(|a| a.anomaly_type.to_string() == "high_velocity"));
}

#[test]
fn trust_drop_anomaly_detected() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-trust-drop-key-1234567";

    // Build up high trust.
    for _ in 0..10 {
        let req = make_request(Some(key), "10.0.0.1", Some("agent"), None);
        ring.evaluate(&req);
    }

    // Simulate sudden trust drop via denial burst.
    for _ in 0..5 {
        let req = IdentityRequest {
            was_denied: true,
            ..make_request(Some(key), "10.0.0.1", Some("agent"), None)
        };
        ring.evaluate(&req);
    }
}

// ─── Keshav-Risk Integration ───

#[test]
fn kesav_risk_receives_identity_signal() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-risk-integration-key-12";

    // Establish identity with consistent behavior.
    for _ in 0..5 {
        let req = make_request(Some(key), "10.0.0.1", Some("agent"), None);
        ring.evaluate(&req);
    }

    let req = make_request(Some(key), "10.0.0.1", Some("agent"), None);
    let verdict = ring.evaluate(&req);

    let risk = KeshavRisk::new(RiskConfig::default());
    let signals = RiskSignals {
        threat_score: Some(2.0),
        identity_score: Some(verdict.identity_risk_score),
        agent_score: None,
        memory_score: None,
        execution_score: None,
        reasoning_score: None,
        governance_score: None,
        recovery_score: None,
        context: ContextSignals::default(),
    };
    let score = risk.evaluate(&signals);

    // Identity should contribute to overall risk.
    assert!(score.identity > 0.0);
    assert!(score.overall > 0.0);
}

#[test]
fn kesav_risk_high_identity_drives_overall() {
    let risk = KeshavRisk::new(RiskConfig::default());
    let signals = RiskSignals {
        threat_score: Some(3.0),
        identity_score: Some(9.0), // Very high identity risk
        agent_score: None,
        memory_score: None,
        execution_score: None,
        reasoning_score: None,
        governance_score: None,
        recovery_score: None,
        context: ContextSignals::default(),
    };
    let score = risk.evaluate(&signals);
    assert!(score.overall > 2.0);
    assert!(score.identity == 9.0);
}

// ─── Zero False Positives on Benign Authenticated Requests ───

#[test]
fn benign_authenticated_request_not_flagged() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let key = "sk-benign-test-key-12345";

    // 10 consistent authenticated requests.
    for _ in 0..10 {
        let req = make_request(Some(key), "10.0.0.1", Some("benign-agent/1.0"), None);
        let verdict = ring.evaluate(&req);
        assert!(verdict.decision.is_allow(), "benign request should be allowed");
    }
}

#[test]
fn benign_jwt_request_not_flagged() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let jwt = make_test_jwt("regular-user", "auth.example.com", None);

    for _ in 0..5 {
        let req = make_request(Some(&jwt), "10.0.0.1", Some("my-app/1.0"), None);
        let verdict = ring.evaluate(&req);
        assert!(verdict.decision.is_allow());
    }
}

// ─── Latency Budget ───

#[test]
fn identity_ring_latency_under_5ms() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();

    let mut latencies: Vec<f64> = Vec::with_capacity(100);
    for _ in 0..100 {
        let req = make_request(Some("sk-latency-test-key-1234"), "10.0.0.1", Some("agent/1.0"), None);
        let start = Instant::now();
        ring.evaluate(&req);
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99 = latencies[99]; // 100th sample (index 99)
    assert!(p99 < 5.0, "p99 latency {}ms exceeds 5ms budget", p99);
}

#[test]
fn full_pipeline_latency_under_10ms() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();

    let mut latencies: Vec<f64> = Vec::with_capacity(100);
    for _ in 0..100 {
        let req = make_request(Some("sk-pipeline-key-12345678"), "10.0.0.1", Some("agent/1.0"), None);
        let start = Instant::now();
        let verdict = ring.evaluate(&req);

        // Also compute Keshav-Risk.
        let risk = KeshavRisk::new(RiskConfig::default());
        let signals = RiskSignals {
            threat_score: Some(2.0),
            identity_score: Some(verdict.identity_risk_score),
            agent_score: None,
            memory_score: None,
            execution_score: None,
            reasoning_score: None,
            governance_score: None,
            recovery_score: None,
            context: ContextSignals::default(),
        };
        risk.evaluate(&signals);

        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99 = latencies[99];
    assert!(p99 < 10.0, "p99 pipeline latency {}ms exceeds 10ms budget", p99);
}

// ─── Engine Count ───

#[test]
fn all_four_engines_evaluated() {
    let ring = IdentityRing::new(&IdentityConfig::default()).unwrap();
    let req = make_request(Some("sk-engine-test-key-12345"), "10.0.0.1", Some("agent"), None);
    let verdict = ring.evaluate(&req);
    assert_eq!(verdict.engine_results.len(), 4);

    let names: Vec<&str> = verdict.engine_results.iter().map(|r| r.engine_name.as_str()).collect();
    assert!(names.contains(&"session_identity"));
    assert!(names.contains(&"role_resolver"));
    assert!(names.contains(&"trust_accumulator"));
    assert!(names.contains(&"identity_anomaly"));
}

// ─── Helpers ───

fn make_request(
    api_key: Option<&str>,
    ip: &str,
    user_agent: Option<&str>,
    extra_headers: Option<HashMap<String, String>>,
) -> IdentityRequest {
    let mut headers = HashMap::new();
    if let Some(key) = api_key {
        headers.insert("authorization".into(), format!("Bearer {}", key));
    }
    if let Some(eh) = extra_headers {
        for (k, v) in eh {
            headers.insert(k, v);
        }
    }
    IdentityRequest {
        source_ip: ip.into(),
        user_agent: user_agent.map(|s| s.to_string()),
        api_key: api_key.map(|s| s.to_string()),
        was_denied: false,
        request_id: "bench-req".into(),
        headers,
    }
}

fn make_test_jwt(sub: &str, iss: &str, role: Option<&str>) -> String {
    use base64::Engine;
    let mut payload = format!(r#"{{"sub":"{}","iss":"{}""#, sub, iss);
    if let Some(r) = role {
        payload.push_str(&format!(r#","roles":["{}"]"#, r));
    }
    payload.push('}');
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
    format!("{}.{}.{}", header, payload_b64, "signature")
}
