//! Fuzz harness for the Policy VM bytecode execution engine.
//!
//! Feeds arbitrary byte sequences as bytecode programs to the VM.
//! The VM has safety limits (max stack depth, max instructions) but
//! this harness tests whether those limits are correctly enforced
//! and whether no panics occur on malformed bytecode.
//!
//! Targets:
//!   - Stack overflow / underflow in VM execution
//!   - Division by zero
//!   - Regex compilation from arbitrary constant pool entries
//!   - Out-of-bounds jump targets
//!   - Infinite loop guard (max_instructions)
//!   - Type mismatch handling in arithmetic/comparisons

#![no_main]

use chakravyuh::policy_compiler::{BytecodeProgram, VMConfig};
use chakravyuh::policy_compiler::vm::PolicyVM;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as a bytecode program.
    let program = match BytecodeProgram::from_bytes(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // If deserialization succeeded, execute on the VM.
    // Use strict safety limits to prevent hangs.
    let vm = PolicyVM::with_config(VMConfig {
        max_stack_size: 64,
        max_instructions: 1_000,
        enable_profiling: false,
    });

    let env = std::collections::HashMap::new();

    // This must not panic — it should return Err on any execution fault.
    let _result = vm.execute(&program, &env);
});
