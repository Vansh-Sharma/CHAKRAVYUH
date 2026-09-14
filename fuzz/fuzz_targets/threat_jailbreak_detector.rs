//! Fuzz harness for the Threat Ring Jailbreak Detector.
//!
//! Exercises all 9 jailbreak family detectors (DAN, STAN, AIM, UCAR,
//! EvilMode, Obligation, CharacterRP, Hypothetical, DeveloperMode).
//!
//! Targets:
//!   - ReDoS in the family-specific regex patterns
//!   - Panic on extremely long inputs to keyword matching
//!   - Score calculation edge cases

#![no_main]

use chakravyuh::threat::{AttackLibrary, JailbreakDetector, JailbreakDetectorConfig};
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
    let detector =
        JailbreakDetector::new(&JailbreakDetectorConfig::default(), library).expect("init");

    let prompt_lower = prompt.to_lowercase();

    // Must not panic.
    let _result = detector.evaluate(prompt, &prompt_lower);
});
