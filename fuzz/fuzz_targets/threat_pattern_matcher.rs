//! Fuzz harness for the Threat Ring Pattern Matcher.
//!
//! Matches arbitrary prompts against the full Attack Library signatures.
//! Targets:
//!   - ReDoS on attack signature regex patterns
//!   - Panic on regex match edge cases
//!   - Correct behavior on empty / extremely long inputs

#![no_main]

use chakravyuh::threat::{AttackLibrary, PatternMatcher, PatternMatcherConfig};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let prompt = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if prompt.len() > 64_000 {
        return;
    }

    let library = Arc::new(AttackLibrary::load_default());
    let matcher =
        PatternMatcher::new(&PatternMatcherConfig::default(), library).expect("init");

    let prompt_lower = prompt.to_lowercase();

    // Must not panic.
    let _result = matcher.evaluate(prompt, &prompt_lower);
});
