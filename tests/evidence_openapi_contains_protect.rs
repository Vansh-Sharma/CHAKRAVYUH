// Evidence Test 2 of 5: GET /openapi.json contains /v1/protect
//
// Verifies the OpenAPI 3.1 specification served at /openapi.json
// documents the primary customer endpoint /v1/protect.
//
// Run:
//   cargo test --test evidence_openapi_contains_protect -- --nocapture
//
// Acceptance: 200 OK, JSON content-type, "openapi":"3.1.0", and the
// "paths" object contains the key "/v1/protect".

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use chakravyuh::{
    api::build_router, AgentRing, Config, CrossRingNetwork, ExecutionRing, GovernanceRing,
    IdentityRing, KeshavDecide, KeshavLearn, KeshavOrchestrate, KeshavRisk, MemoryRing,
    ReasoningRing, RecoveryRing, ShieldRing, ThreatRing,
};

fn router() -> axum::Router {
    let config: Config = Config::default_yaml().parse().expect("config parses");
    let config = Arc::new(config);
    let shield = ShieldRing::new(config.clone()).expect("shield builds");
    let threat_config = Arc::new(config.threat.clone());
    let threat = ThreatRing::new(threat_config).expect("threat builds");
    let identity = IdentityRing::new(&config.identity).expect("identity builds");
    let memory = MemoryRing::new(&config.memory).expect("memory builds");
    let agent = AgentRing::new(&config.agent).expect("agent builds");
    let execution = ExecutionRing::new(&config.execution).expect("execution builds");
    let reasoning = ReasoningRing::new(&config.reasoning).expect("reasoning builds");
    let governance = GovernanceRing::new(&config.governance).expect("governance builds");
    let recovery_sec = RecoveryRing::new(&config.recovery_sec).expect("recovery_sec builds");
    let decide = KeshavDecide::with_defaults().expect("decide builds");
    let risk = KeshavRisk::new(config.keshav.risk.clone());
    let learn = KeshavLearn::new(config.keshav.learn.clone()).expect("learn builds");
    let orchestrate = KeshavOrchestrate::new(config.keshav.orchestrate.clone());
    let cross_ring = CrossRingNetwork::new(&config.cross_ring).expect("cross_ring builds");
    build_router(
        shield,
        threat,
        identity,
        memory,
        agent,
        execution,
        reasoning,
        governance,
        recovery_sec,
        decide,
        risk,
        learn,
        orchestrate,
        cross_ring,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

#[tokio::test]
async fn evidence_openapi_contains_protect() {
    let request = Request::builder()
        .method("GET")
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();

    let response = router().oneshot(request).await.expect("router responds");
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let spec: Value = serde_json::from_slice(&bytes).expect("body is valid JSON");

    let paths = spec["paths"].as_object().expect("paths is an object");
    let has_protect = paths.contains_key("/v1/protect");
    let protect_has_post = paths
        .get("/v1/protect")
        .and_then(|p| p.as_object())
        .map(|o| o.contains_key("post"))
        .unwrap_or(false);

    println!("=== EVIDENCE: GET /openapi.json ===");
    println!("status:                {}", status);
    println!("content-type:          {}", content_type);
    println!("openapi version:       {}", spec["openapi"]);
    println!("paths count:           {}", paths.len());
    println!("has /v1/protect:       {}", has_protect);
    println!("/v1/protect has POST:  {}", protect_has_post);
    println!("===================================");

    assert_eq!(status, StatusCode::OK, "GET /openapi.json must return 200");
    assert!(
        content_type.contains("json"),
        "Content-Type must be JSON, got: {}",
        content_type
    );
    assert_eq!(spec["openapi"], "3.1.0", "Must be OpenAPI 3.1");
    assert!(has_protect, "OpenAPI spec must document /v1/protect");
    assert!(
        protect_has_post,
        "/v1/protect must have a POST operation defined"
    );
}
