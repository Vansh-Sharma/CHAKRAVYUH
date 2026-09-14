//! Fuzz harness for the Shield Ring Input Validator.
//!
//! Feeds arbitrary JSON bodies through the input validator to find:
//!   - Panics on malformed / deeply nested JSON
//!   - Integer overflow in message count / length checks
//!   - Edge cases in control character detection

#![no_main]

use chakravyuh::shield::input_validator::{InputValidator, InputValidatorConfig};
use chakravyuh::shield::ShieldRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON body; skip if invalid.
    let body: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    let config = InputValidatorConfig::default();
    let validator = InputValidator { config };

    let request = ShieldRequest {
        source_ip: "1.2.3.4".into(),
        user_agent: Some("fuzz/0.0".into()),
        api_key: None,
        user_id: None,
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        headers: std::collections::HashMap::new(),
        body,
    };

    // Must not panic.
    let _result = validator.evaluate(&request);
});
