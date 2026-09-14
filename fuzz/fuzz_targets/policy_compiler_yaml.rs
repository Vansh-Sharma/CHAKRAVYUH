//! Fuzz harness for the Policy Compiler YAML frontend.
//!
//! Feeds arbitrary byte sequences as YAML policy source to the compiler.
//! Targets:
//!   - YAML parser panics on malformed input
//!   - Compiler crashes on unexpected rule structures
//!   - Code generator edge cases with empty/malicious conditions
//!   - Size limit enforcement

#![no_main]

use chakravyuh::policy_compiler::{PolicyCompiler, PolicyCompilerConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let yaml = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut compiler = PolicyCompiler::new(PolicyCompilerConfig {
        max_policy_size: 64_000,
        ..Default::default()
    })
    .expect("compiler init");

    // This must not panic — it should return Err on invalid YAML.
    let _result = compiler.compile_yaml(yaml);
});
