//! Fuzz harness for the Memory Ring PII Extractor.
//!
//! Exercises regex-based PII detection for:
//!   email, phone, SSN, credit card (Luhn), API keys, IP addresses
//!
//! Targets:
//!   - ReDoS in PII detection regex patterns
//!   - Panic on Luhn check with non-digit edge cases
//!   - Masking logic on very short/empty strings
//!   - min_severity filtering correctness

#![no_main]

use chakravyuh::memory::pii_extractor::{PIIExtractor, PIIExtractorConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if text.len() > 64_000 {
        return;
    }

    let extractor = PIIExtractor::new(&PIIExtractorConfig::default());

    // Must not panic.
    let _findings = extractor.extract(text);

    // Also test with a disabled extractor (should return empty).
    let disabled = PIIExtractor::new(&PIIExtractorConfig {
        enabled: false,
        ..Default::default()
    });
    let _empty = disabled.extract(text);

    // Test with high min_severity.
    let strict = PIIExtractor::new(&PIIExtractorConfig {
        min_severity: 10,
        ..Default::default()
    });
    let _filtered = strict.extract(text);
});