//! Fuzz harness for the Shield Ring WAF Engine.
//!
//! Feeds arbitrary byte sequences (interpreted as UTF-8 prompt text)
//! through the WAF engine to find:
//!   - Regex denial-of-service (ReDoS) via pathological inputs
//!   - Panics on unexpected character patterns
//!   - Logical errors in attack pattern matching

#![no_main]

use chakravyuh::shield::waf_engine::WafEngine;
use chakravyuh::shield::ShieldRequest;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fn make_waf_engine() -> WafEngine {
    // Construct a default Config from an empty YAML string to access
    // the ShieldConfig for WAF engine initialization.
    let config: chakravyuh::Config = serde_yaml::from_str("").expect("default config");
    WafEngine::new(&config.shield).expect("waf engine init")
}

fn make_shield_request(prompt: &str) -> ShieldRequest {
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
    // Attempt to interpret as UTF-8; skip non-UTF-8 inputs gracefully.
    let prompt = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Limit prompt length to avoid resource exhaustion.
    if prompt.len() > 64_000 {
        return;
    }

    let engine = make_waf_engine();
    let request = make_shield_request(prompt);

    // This must not panic.
    let _result = engine.evaluate(&request);
});
