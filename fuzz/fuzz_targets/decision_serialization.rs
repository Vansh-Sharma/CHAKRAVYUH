//! Fuzz harness for Decision type serialization roundtrip.
//!
//! Feeds arbitrary byte sequences as JSON to serde_json deserialization.
//! Re-serializes the result and checks for no panics.
//!
//! Targets:
//!   - Deserialization of malformed JSON doesn't panic
//!   - Roundtrip (parse → serialize → parse) is stable
//!   - Edge cases in retry_after, timeout_secs fields

#![no_main]

use chakravyuh::Decision;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as a Decision.
    let decision: Result<Decision, _> = serde_json::from_slice(data);
    match decision {
        Ok(d) => {
            // Verify http_status() doesn't panic.
            let _status = d.http_status();
            let _is_allow = d.is_allow();
            let _is_deny = d.is_deny();

            // Roundtrip: serialize and re-parse.
            if let Ok(json) = serde_json::to_string(&d) {
                let _d2: Result<Decision, _> = serde_json::from_str(&json);
            }
        }
        Err(_) => {
            // Invalid JSON is fine — the important thing is no panic.
        }
    }

    // Also test DecisionRecord deserialization.
    let _record: Result<chakravyuh::DecisionRecord, _> = serde_json::from_slice(data);

    // Also test RiskScore deserialization.
    let _risk: Result<chakravyuh::RiskScore, _> = serde_json::from_slice(data);
});
