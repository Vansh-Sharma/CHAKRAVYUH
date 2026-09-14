//! Fuzz harness for the full Threat Ring evaluation pipeline.
//!
//! Exercises the complete threat detection chain:
//!   Obfuscation Decoder → Pattern Matcher → Semantic Classifier → Jailbreak Detector
//!   → Confidence Scorer
//!
//! Targets:
//!   - ReDoS in any of the detection engines
//!   - Panics on edge-case encoded payloads
//!   - Buffer overflows in obfuscation decoder
//!   - Score calculation edge cases (NaN, Inf)

#![no_main]

use chakravyuh::shield::ShieldRequest;
use chakravyuh::threat::{ThreatConfig, ThreatRing};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fn make_threat_ring() -> ThreatRing {
    let config = Arc::new(ThreatConfig::default());
    ThreatRing::new(config).expect("threat ring init")
}

fn make_request(prompt: &str) -> ShieldRequest {
    ShieldRequest {
        source_ip: "1.2.3.4".into(),
        user_agent: Some("fuzz/0.0".into()),
        api_key: None,
        user_id: None,
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        headers: std::collections::HashMap::new(),
        body: serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": prompt}]
        }),
    }
}

fuzz_target!(|data: &[u8]| {
    let prompt = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Cap at 64 KiB to prevent OOM from pathological cases.
    if prompt.len() > 64_000 {
        return;
    }

    let ring = make_threat_ring();
    let request = make_request(prompt);

    // Full pipeline — must not panic.
    let _verdict = ring.evaluate(&request);
});
