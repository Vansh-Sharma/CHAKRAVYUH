// Evidence Test 1 of 5: GET /docs returns 200
//
// This is a standalone, narrowly-scoped integration test that verifies
// the Swagger UI endpoint is reachable and returns HTML.
//
// Run:
//   cargo test --test evidence_docs_returns_200 -- --nocapture
//
// Acceptance: status code is 200 OK and body contains "swagger-ui".

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
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
        shield, threat, identity, memory, agent, execution, reasoning, governance, recovery_sec,
        decide, risk, learn, orchestrate, cross_ring, None, None, None, None, None, None,
    )
}

#[tokio::test]
async fn evidence_get_docs_returns_200() {
    let request = Request::builder()
        .method("GET")
        .uri("/docs")
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body);

    // Evidence assertions — print so CI logs show the proof
    println!("=== EVIDENCE: GET /docs ===");
    println!("status:       {}", status);
    println!("content-type: {}", content_type);
    println!("body length:  {} bytes", body_str.len());
    println!("contains 'swagger-ui': {}", body_str.contains("swagger-ui"));
    println!("contains '/openapi.json': {}", body_str.contains("/openapi.json"));
    println!("==========================");

    assert_eq!(status, StatusCode::OK, "GET /docs must return 200");
    assert!(
        content_type.contains("html"),
        "Content-Type must be HTML, got: {}",
        content_type
    );
    assert!(
        body_str.contains("swagger-ui"),
        "Body must contain swagger-ui"
    );
    assert!(
        body_str.contains("/openapi.json"),
        "Body must reference /openapi.json"
    );
}
