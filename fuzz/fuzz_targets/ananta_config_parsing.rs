//! Fuzz harness for ANANTA configuration YAML parsing.
//!
//! Feeds arbitrary byte sequences as YAML to AnantaConfig::from_yaml.
//! Targets:
//!   - YAML parser panics on malformed input
//!   - Config validation edge cases
//!   - Extreme numeric values in intervals/thresholds

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let yaml = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // This must not panic.
    match chakravyuh::AnantaConfig::from_yaml(yaml) {
        Ok(config) => {
            // Exercise validate() — must not panic.
            let _warnings = config.validate();

            // Exercise default_yaml() roundtrip.
            let default_yaml = config.default_yaml();
            if let Ok(config2) = chakravyuh::AnantaConfig::from_yaml(&default_yaml) {
                let _warnings2 = config2.validate();
            }
        }
        Err(_) => {
            // Invalid YAML is expected for most inputs.
        }
    }
});
