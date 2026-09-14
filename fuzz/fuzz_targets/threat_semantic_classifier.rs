//! Fuzz harness for the Threat Ring Semantic Classifier.
//!
//! Exercises the 6-axis heuristic classifier:
//!   instruction-override, persona-shift, authority-claim,
//!   output-manipulation, encoding-bypass, emotional-manipulation
//!
//! Targets:
//!   - ReDoS in the per-axis regex patterns
//!   - Score computation edge cases (NaN, Inf, negative)
//!   - Panic on boundary inputs

#![no_main]

use chakravyuh::threat::{SemanticClassifier, SemanticClassifierConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let prompt = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if prompt.len() > 64_000 {
        return;
    }

    let classifier =
        SemanticClassifier::new(&SemanticClassifierConfig::default()).expect("init");

    let prompt_lower = prompt.to_lowercase();

    // Must not panic.
    let _result = classifier.evaluate(prompt, &prompt_lower);
});
