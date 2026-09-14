//! Fuzz harness for the Execution Ring SSRF Protector.
//!
//! Feeds arbitrary strings as URL targets to the SSRF protector.
//! Targets:
//!   - Panics on malformed URLs / IPs
//!   - Correct handling of non-ASCII hostnames
//!   - Edge cases in CIDR matching
//!   - DNS rebinding patterns (URL with @, etc.)

#![no_main]

use chakravyuh::execution::ssrf_protector::{SsrfProtector, SsrfProtectorConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let target = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if target.len() > 4_000 {
        return;
    }

    let config = SsrfProtectorConfig::default();
    let protector = SsrfProtector::new(&config).expect("init");

    // Must not panic on any URL-like string.
    let _result = protector.evaluate(target);
});
