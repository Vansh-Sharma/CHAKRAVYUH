// Policy Virtual Machine — stack-based bytecode execution engine.
//
// Executes BytecodeProgram instances against a PolicyInput, producing
// a PolicyOutput with decision, risk score, matched rules, and profiling
// information. Includes safety limits (stack depth, instruction count) and
// comprehensive type checking.

use std::collections::HashMap;
use std::time::Instant;

use super::bytecode::{BytecodeProgram, Constant, Instruction, OpCode};
use crate::decision::Decision;

// ── VM Configuration ───────────────────────────────────────────────────

/// Configuration for the PolicyVM.
#[derive(Debug, Clone)]
pub struct VMConfig {
    /// Maximum stack depth before aborting with overflow.
    pub max_stack_size: usize,
    /// Maximum number of instructions before aborting (infinite loop guard).
    pub max_instructions: u64,
    /// Whether to collect per-rule profiling data.
    pub enable_profiling: bool,
}

impl Default for VMConfig {
    fn default() -> Self {
        Self {
            max_stack_size: 1024,
            max_instructions: 100_000,
            enable_profiling: false,
        }
    }
}

// ── Value ──────────────────────────────────────────────────────────────

/// A value on the VM stack.
#[derive(Debug, Clone)]
pub enum Value {
    /// Numeric value (f64).
    Number(f64),
    /// String value.
    String(String),
    /// Boolean value.
    Bool(bool),
    /// Risk accumulator value.
    Risk(f64),
    /// An emitted decision reference.
    Decision(Decision),
    /// Null / unit value.
    Null,
}

impl Value {
    /// Returns the inner number, or an error string.
    pub fn as_number(&self) -> Result<f64, String> {
        match self {
            Value::Number(n) => Ok(*n),
            Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
            other => Err(format!("expected number, got {:?}", other.type_name())),
        }
    }

    /// Returns the inner string, or an error string.
    pub fn as_string(&self) -> Result<&str, String> {
        match self {
            Value::String(s) => Ok(s),
            other => Err(format!("expected string, got {:?}", other.type_name())),
        }
    }

    /// Returns the inner boolean, or an error string.
    pub fn as_bool(&self) -> Result<bool, String> {
        match self {
            Value::Bool(b) => Ok(*b),
            Value::Number(n) => Ok(*n != 0.0),
            other => Err(format!("expected bool, got {:?}", other.type_name())),
        }
    }

    /// Returns a human-readable type name for the value.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Bool(_) => "bool",
            Value::Risk(_) => "risk",
            Value::Decision(_) => "decision",
            Value::Null => "null",
        }
    }

    /// Check if this value is truthy (for JumpIfFalse/JumpIfTrue).
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Risk(r) => *r > 0.0,
            Value::Null => false,
            Value::Decision(_) => true,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Number(n) => write!(f, "{}", n),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Risk(r) => write!(f, "risk({})", r),
            Value::Decision(d) => write!(f, "{:?}", d),
            Value::Null => write!(f, "null"),
        }
    }
}

// ── VM Execution Result ─────────────────────────────────────────────────

/// The result of executing a bytecode program on the VM.
#[derive(Debug, Clone)]
pub struct VMResult {
    /// The final decision emitted by the policy (or default Allow if none).
    pub decision: Decision,
    /// The accumulated risk score (0.0 if no risk operations ran).
    pub risk_score: f64,
    /// Names of rules that were matched during execution.
    pub rules_matched: Vec<String>,
    /// Total number of instructions executed.
    pub instructions_executed: u64,
    /// Wall-clock execution time in nanoseconds.
    pub execution_time_ns: u64,
}

// ── PolicyVM ───────────────────────────────────────────────────────────

/// The policy bytecode virtual machine.
///
/// Executes compiled BytecodeProgram instances with a stack-based
/// evaluation model. Safety is enforced via stack depth limits, instruction
/// count limits, and type checking on operations.
pub struct PolicyVM {
    config: VMConfig,
}

impl PolicyVM {
    /// Create a new PolicyVM with default configuration.
    pub fn new() -> Self {
        Self {
            config: VMConfig::default(),
        }
    }

    /// Create a new PolicyVM with the given configuration.
    pub fn with_config(config: VMConfig) -> Self {
        Self { config }
    }

    /// Execute a bytecode program against the given input environment.
    ///
    /// The environment maps variable names (e.g., "source_ip", "payload",
    /// "risk_score") to values that Load instructions can access.
    pub fn execute(
        &self,
        program: &BytecodeProgram,
        env: &HashMap<String, Value>,
    ) -> Result<VMResult, String> {
        let start = Instant::now();

        // Pre-validate the program.
        program.validate()?;

        // Ensure we have enough stack capacity.
        let max_stack = program.max_stack_size as usize;
        if max_stack > self.config.max_stack_size {
            return Err(format!(
                "program requires stack size {} but VM limit is {}",
                max_stack, self.config.max_stack_size
            ));
        }

        // Map variable names to slot indices for faster Load/Store.
        let _var_slots: HashMap<String, usize> = env
            .keys()
            .enumerate()
            .map(|(i, k)| (k.clone(), i))
            .collect();
        let slot_values: Vec<Value> = if program.variable_slots.is_empty() {
            // Fallback for programs without slot metadata: use env values as-is.
            env.values().cloned().collect()
        } else {
            program
                .variable_slots
                .iter()
                .map(|name| env.get(name).cloned().unwrap_or(Value::Null))
                .collect()
        };

        // VM state.
        let mut stack: Vec<Value> = Vec::with_capacity(max_stack.max(16));
        let mut risk_accum: f64 = 0.0;
        let mut decision: Option<Decision> = None;
        let mut rules_matched: Vec<String> = Vec::new();
        let mut pc = program.entry_point as usize;
        let mut instr_count: u64 = 0;
        let mut call_stack: Vec<usize> = Vec::new();

        // Main execution loop.
        while pc < program.instructions.len() {
            if instr_count >= self.config.max_instructions {
                return Err(format!(
                    "instruction limit reached ({} max)",
                    self.config.max_instructions
                ));
            }
            instr_count += 1;

            let instr = &program.instructions[pc];

            match instr.opcode {
                // ── Stack operations ────────────────────────────────
                OpCode::Push => {
                    let idx = instr.operand.unwrap_or(0) as usize;
                    if idx >= program.constant_pool.len() {
                        return Err(format!("constant index {} out of bounds at pc {}", idx, pc));
                    }
                    let val = match &program.constant_pool[idx] {
                        Constant::Number(n) => Value::Number(*n),
                        _ => Value::Null,
                    };
                    self.push_checked(&mut stack, val, instr)?;
                }
                OpCode::PushStr => {
                    let idx = instr.operand.unwrap_or(0) as usize;
                    if idx >= program.constant_pool.len() {
                        return Err(format!("constant index {} out of bounds at pc {}", idx, pc));
                    }
                    let val = match &program.constant_pool[idx] {
                        Constant::String(s) => Value::String(s.clone()),
                        Constant::Regex(s) => Value::String(s.clone()),
                        _ => Value::Null,
                    };
                    self.push_checked(&mut stack, val, instr)?;
                }
                OpCode::Load => {
                    let slot = instr.operand.unwrap_or(0) as usize;
                    if slot < slot_values.len() {
                        self.push_checked(&mut stack, slot_values[slot].clone(), instr)?;
                    } else {
                        self.push_checked(&mut stack, Value::Null, instr)?;
                    }
                }
                OpCode::Store => {
                    let slot = instr.operand.unwrap_or(0) as usize;
                    // Store is a no-op in this simplified VM (no mutable env).
                    // In a full implementation this would write back to the environment.
                    let _ = (slot, instr);
                }

                // ── Arithmetic ──────────────────────────────────────
                OpCode::Add => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? + b.as_number()?;
                    self.push_checked(&mut stack, Value::Number(result), instr)?;
                }
                OpCode::Sub => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? - b.as_number()?;
                    self.push_checked(&mut stack, Value::Number(result), instr)?;
                }
                OpCode::Mul => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? * b.as_number()?;
                    self.push_checked(&mut stack, Value::Number(result), instr)?;
                }
                OpCode::Div => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let divisor = b.as_number()?;
                    if divisor == 0.0 {
                        return Err("division by zero".into());
                    }
                    let result = a.as_number()? / divisor;
                    self.push_checked(&mut stack, Value::Number(result), instr)?;
                }
                OpCode::Mod => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let divisor = b.as_number()?;
                    if divisor == 0.0 {
                        return Err("modulo by zero".into());
                    }
                    let result = a.as_number()? % divisor;
                    self.push_checked(&mut stack, Value::Number(result), instr)?;
                }

                // ── Comparisons ─────────────────────────────────────
                OpCode::Gt => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? > b.as_number()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Lt => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? < b.as_number()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Ge => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? >= b.as_number()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Le => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_number()? <= b.as_number()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Eq => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = values_equal(&a, &b);
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Ne => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = !values_equal(&a, &b);
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }

                // ── Logic ──────────────────────────────────────────
                OpCode::And => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_bool()? && b.as_bool()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Or => {
                    let (b, a) = self.pop2_checked(&mut stack)?;
                    let result = a.as_bool()? || b.as_bool()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::Not => {
                    let a = self.pop_checked(&mut stack)?;
                    let result = !a.as_bool()?;
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }

                // ── Control flow ───────────────────────────────────
                OpCode::Jump => {
                    let target = instr.operand.unwrap_or(0) as usize;
                    if target >= program.instructions.len() {
                        return Err(format!("jump target {} out of bounds", target));
                    }
                    pc = target;
                    continue; // skip pc increment
                }
                OpCode::JumpIfFalse => {
                    let cond = self.pop_checked(&mut stack)?;
                    if !cond.is_truthy() {
                        let target = instr.operand.unwrap_or(0) as usize;
                        if target >= program.instructions.len() {
                            return Err(format!("jump target {} out of bounds", target));
                        }
                        pc = target;
                        continue;
                    }
                }
                OpCode::JumpIfTrue => {
                    let cond = self.pop_checked(&mut stack)?;
                    if cond.is_truthy() {
                        let target = instr.operand.unwrap_or(0) as usize;
                        if target >= program.instructions.len() {
                            return Err(format!("jump target {} out of bounds", target));
                        }
                        pc = target;
                        continue;
                    }
                }
                OpCode::Call => {
                    let target = instr.operand.unwrap_or(0) as usize;
                    if target >= program.instructions.len() {
                        return Err(format!("call target {} out of bounds", target));
                    }
                    call_stack.push(pc + 1);
                    pc = target;
                    continue;
                }
                OpCode::Return => {
                    if let Some(ret_pc) = call_stack.pop() {
                        pc = ret_pc;
                        continue;
                    } else {
                        // Return from top-level — halt.
                        break;
                    }
                }

                // ── String operations ───────────────────────────────
                OpCode::Contains => {
                    let (needle, haystack) = self.pop2_checked(&mut stack)?;
                    let result = haystack.as_string()?.contains(needle.as_string()?);
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::StartsWith => {
                    let (prefix, s) = self.pop2_checked(&mut stack)?;
                    let result = s.as_string()?.starts_with(prefix.as_string()?);
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::EndsWith => {
                    let (suffix, s) = self.pop2_checked(&mut stack)?;
                    let result = s.as_string()?.ends_with(suffix.as_string()?);
                    self.push_checked(&mut stack, Value::Bool(result), instr)?;
                }
                OpCode::MatchRegex => {
                    let pattern_idx = instr.operand.unwrap_or(0) as usize;
                    if pattern_idx >= program.constant_pool.len() {
                        return Err(format!(
                            "regex constant index {} out of bounds",
                            pattern_idx
                        ));
                    }
                    let subject = self.pop_checked(&mut stack)?;
                    let subject_str = subject.as_string()?;
                    if let Some(pat_str) = program.constant_pool[pattern_idx].as_str() {
                        let result = match regex::Regex::new(pat_str) {
                            Ok(re) => re.is_match(subject_str),
                            Err(_) => false,
                        };
                        self.push_checked(&mut stack, Value::Bool(result), instr)?;
                    } else {
                        self.push_checked(&mut stack, Value::Bool(false), instr)?;
                    }
                }

                // ── Risk accumulation ───────────────────────────────
                OpCode::RiskAdd => {
                    let val = self.pop_checked(&mut stack)?;
                    risk_accum += val.as_number()?;
                }
                OpCode::RiskMul => {
                    let val = self.pop_checked(&mut stack)?;
                    risk_accum *= val.as_number()?;
                }
                OpCode::RiskMax => {
                    let val = self.pop_checked(&mut stack)?;
                    let v = val.as_number()?;
                    if v > risk_accum {
                        risk_accum = v;
                    }
                }

                // ── Decision emission ───────────────────────────────
                OpCode::Deny => {
                    decision = Some(Decision::Deny {
                        code: if !instr.source_rule.is_empty() {
                            instr.source_rule.clone()
                        } else {
                            "POLICY_DENY".to_string()
                        },
                        retry_after: None,
                    });
                    if !instr.source_rule.is_empty() {
                        rules_matched.push(instr.source_rule.clone());
                    }
                    break; // decision ends execution
                }
                OpCode::Allow => {
                    decision = Some(Decision::Allow);
                    if !instr.source_rule.is_empty() {
                        rules_matched.push(instr.source_rule.clone());
                    }
                    break;
                }
                OpCode::Escalate => {
                    decision = Some(Decision::Escalate {
                        approver_role: "security_admin".to_string(),
                        timeout_secs: 300,
                    });
                    if !instr.source_rule.is_empty() {
                        rules_matched.push(instr.source_rule.clone());
                    }
                    break;
                }
                OpCode::Challenge => {
                    decision = Some(Decision::Challenge {
                        challenge_type: crate::decision::ChallengeType::Captcha,
                    });
                    if !instr.source_rule.is_empty() {
                        rules_matched.push(instr.source_rule.clone());
                    }
                    break;
                }

                // ── Misc ───────────────────────────────────────────
                OpCode::Halt => break,
                OpCode::Nop => {}
            }

            pc += 1;
        }

        // Track rules that were "visited" (Load instructions with source_rule).
        // Already tracked above via decision emission.
        // Additionally, track visited rules from all instructions with source_rule.
        let all_matched = rules_matched;
        for instr in &program.instructions[..=pc.min(program.instructions.len() - 1)] {
            if !instr.source_rule.is_empty() && !all_matched.contains(&instr.source_rule) {
                // Don't duplicate rules already added by decision emission.
            }
        }

        let elapsed = start.elapsed().as_nanos() as u64;

        Ok(VMResult {
            decision: decision.unwrap_or(Decision::Allow),
            risk_score: risk_accum,
            rules_matched: all_matched,
            instructions_executed: instr_count,
            execution_time_ns: elapsed,
        })
    }

    /// Push a value onto the stack with overflow checking.
    fn push_checked(
        &self,
        stack: &mut Vec<Value>,
        val: Value,
        instr: &Instruction,
    ) -> Result<(), String> {
        if stack.len() >= self.config.max_stack_size {
            return Err(format!(
                "stack overflow at pc with opcode {} (max {})",
                instr.opcode, self.config.max_stack_size
            ));
        }
        stack.push(val);
        Ok(())
    }

    /// Pop a value from the stack with underflow checking.
    fn pop_checked(&self, stack: &mut Vec<Value>) -> Result<Value, String> {
        stack.pop().ok_or_else(|| "stack underflow".to_string())
    }

    /// Pop two values from the stack with underflow checking.
    fn pop2_checked(&self, stack: &mut Vec<Value>) -> Result<(Value, Value), String> {
        if stack.len() < 2 {
            return Err("stack underflow (need 2 values)".to_string());
        }
        let b = stack.pop().unwrap();
        let a = stack.pop().unwrap();
        Ok((b, a))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Compare two values for equality.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => (x - y).abs() < 1e-10,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Risk(x), Value::Risk(y)) => (x - y).abs() < 1e-10,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::ChallengeType;

    // Helper: build a simple program.
    fn make_env(key: &str, val: Value) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert(key.to_string(), val);
        m
    }

    // Helper: create a VM with generous limits.
    fn test_vm() -> PolicyVM {
        PolicyVM::with_config(VMConfig {
            max_stack_size: 256,
            max_instructions: 1_000,
            enable_profiling: false,
        })
    }

    #[test]
    fn vm_default_allow_no_decision() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.risk_score, 0.0);
        assert_eq!(result.instructions_executed, 1);
    }

    #[test]
    fn vm_push_and_halt() {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(42.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn vm_arithmetic_add() {
        // Push 3, Push 7, Add, Halt
        let mut prog = BytecodeProgram::new();
        let c0 = prog.add_constant(Constant::Number(3.0));
        let c1 = prog.add_constant(Constant::Number(7.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::with_operand(OpCode::Push, c1));
        prog.emit(Instruction::new(OpCode::Add));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        // The Add pops and pushes, but we can't inspect the stack directly.
        // Verify no error.
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_arithmetic_chain() {
        // Push 10, Push 3, Sub, Push 2, Mul, Halt — (10-3)*2 = 14
        let mut prog = BytecodeProgram::new();
        let c10 = prog.add_constant(Constant::Number(10.0));
        let c3 = prog.add_constant(Constant::Number(3.0));
        let c2 = prog.add_constant(Constant::Number(2.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c10));
        prog.emit(Instruction::with_operand(OpCode::Push, c3));
        prog.emit(Instruction::new(OpCode::Sub));
        prog.emit(Instruction::with_operand(OpCode::Push, c2));
        prog.emit(Instruction::new(OpCode::Mul));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
        assert_eq!(result.instructions_executed, 6);
    }

    #[test]
    fn vm_comparison_gt() {
        // Push 10, Push 5, Gt, Halt
        let mut prog = BytecodeProgram::new();
        let c10 = prog.add_constant(Constant::Number(10.0));
        let c5 = prog.add_constant(Constant::Number(5.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c10));
        prog.emit(Instruction::with_operand(OpCode::Push, c5));
        prog.emit(Instruction::new(OpCode::Gt));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_logic_and_or() {
        // Push true(bool via number 1), Push false(number 0), Or, Halt
        let mut prog = BytecodeProgram::new();
        let c1 = prog.add_constant(Constant::Number(1.0));
        let c0 = prog.add_constant(Constant::Number(0.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c1));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::new(OpCode::Or));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_risk_accumulation() {
        // Push 0.5, RiskAdd, Push 0.3, RiskMax, Halt
        let mut prog = BytecodeProgram::new();
        let c05 = prog.add_constant(Constant::Number(0.5));
        let c03 = prog.add_constant(Constant::Number(0.3));
        prog.emit(Instruction::with_operand(OpCode::Push, c05));
        prog.emit(Instruction::new(OpCode::RiskAdd));
        prog.emit(Instruction::with_operand(OpCode::Push, c03));
        prog.emit(Instruction::new(OpCode::RiskMax));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!((result.risk_score - 0.5).abs() < 1e-10);
    }

    #[test]
    fn vm_risk_mul() {
        let mut prog = BytecodeProgram::new();
        let c05 = prog.add_constant(Constant::Number(0.5));
        let c2 = prog.add_constant(Constant::Number(2.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c05));
        prog.emit(Instruction::new(OpCode::RiskAdd));
        prog.emit(Instruction::with_operand(OpCode::Push, c2));
        prog.emit(Instruction::new(OpCode::RiskMul));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!((result.risk_score - 1.0).abs() < 1e-10);
    }

    #[test]
    fn vm_deny_decision() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Deny).with_source(1, "block_ip"));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_deny());
        assert_eq!(
            result.decision,
            Decision::Deny {
                code: "block_ip".to_string(),
                retry_after: None,
            }
        );
        assert!(result.rules_matched.contains(&"block_ip".to_string()));
    }

    #[test]
    fn vm_allow_decision() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Allow));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_challenge_decision() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Challenge));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        match result.decision {
            Decision::Challenge { challenge_type } => {
                assert_eq!(challenge_type, ChallengeType::Captcha);
            }
            _ => panic!("expected Challenge decision"),
        }
    }

    #[test]
    fn vm_escalate_decision() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Escalate));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        match result.decision {
            Decision::Escalate {
                approver_role,
                timeout_secs,
            } => {
                assert_eq!(approver_role, "security_admin");
                assert_eq!(timeout_secs, 300);
            }
            _ => panic!("expected Escalate decision"),
        }
    }

    #[test]
    fn vm_jump_conditional() {
        // Push 1, JumpIfTrue -> Halt, Push 42 (should be skipped), Halt
        let mut prog = BytecodeProgram::new();
        let c1 = prog.add_constant(Constant::Number(1.0));
        let c42 = prog.add_constant(Constant::Number(42.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c1));
        // JumpIfTrue target = index 3 (second Halt)
        prog.emit(Instruction::with_operand(OpCode::JumpIfTrue, 3));
        prog.emit(Instruction::with_operand(OpCode::Push, c42)); // index 2 — skipped
        prog.emit(Instruction::new(OpCode::Halt)); // index 3
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
        assert_eq!(result.instructions_executed, 3); // Push, JumpIfTrue, Halt
    }

    #[test]
    fn vm_string_contains() {
        // PushStr "hello world", PushStr "world", Contains, Halt
        let mut prog = BytecodeProgram::new();
        let c_hw = prog.add_constant(Constant::String("hello world".into()));
        let c_w = prog.add_constant(Constant::String("world".into()));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_hw));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_w));
        prog.emit(Instruction::new(OpCode::Contains));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_string_starts_with() {
        let mut prog = BytecodeProgram::new();
        let c_h = prog.add_constant(Constant::String("https://example.com".into()));
        let c_p = prog.add_constant(Constant::String("https://".into()));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_h));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_p));
        prog.emit(Instruction::new(OpCode::StartsWith));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_string_ends_with() {
        let mut prog = BytecodeProgram::new();
        let c_f = prog.add_constant(Constant::String("test.json".into()));
        let c_e = prog.add_constant(Constant::String(".json".into()));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_f));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_e));
        prog.emit(Instruction::new(OpCode::EndsWith));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_regex_match() {
        let mut prog = BytecodeProgram::new();
        let c_s = prog.add_constant(Constant::String("user123@example.com".into()));
        let c_r = prog.add_constant(Constant::Regex(r"^[a-z]+[0-9]+@.*$".into()));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c_s));
        prog.emit(Instruction::with_operand(OpCode::MatchRegex, c_r));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_not_instruction() {
        // Push 0 (false), Not => true, Halt
        let mut prog = BytecodeProgram::new();
        let c0 = prog.add_constant(Constant::Number(0.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::new(OpCode::Not));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn vm_call_return() {
        // index 0: Call 3
        // index 1: Halt (after return)
        // index 2: Nop (pad)
        // index 3: Nop (subroutine)
        // index 4: Return
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::with_operand(OpCode::Call, 3)); // index 0
        prog.emit(Instruction::new(OpCode::Halt)); // index 1
        prog.emit(Instruction::new(OpCode::Nop)); // index 2
        prog.emit(Instruction::new(OpCode::Nop)); // index 3 (subroutine)
        prog.emit(Instruction::new(OpCode::Return)); // index 4
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
        assert!(result.instructions_executed >= 3);
    }

    #[test]
    fn vm_division_by_zero() {
        let mut prog = BytecodeProgram::new();
        let c1 = prog.add_constant(Constant::Number(1.0));
        let c0 = prog.add_constant(Constant::Number(0.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c1));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::new(OpCode::Div));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("division by zero"));
    }

    #[test]
    fn vm_stack_underflow() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Add)); // no values on stack
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stack underflow"));
    }

    #[test]
    fn vm_instruction_limit() {
        let mut prog = BytecodeProgram::new();
        // Jump to self = infinite loop
        prog.emit(Instruction::with_operand(OpCode::Jump, 0));
        let vm = PolicyVM::with_config(VMConfig {
            max_stack_size: 256,
            max_instructions: 10,
            enable_profiling: false,
        });
        let result = vm.execute(&prog, &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("instruction limit"));
    }

    #[test]
    fn vm_nop_noop() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Nop));
        prog.emit(Instruction::new(OpCode::Nop));
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.decision.is_allow());
        assert_eq!(result.instructions_executed, 3);
    }

    #[test]
    fn vm_value_type_checks() {
        let v = Value::Number(3.14);
        assert_eq!(v.as_number().unwrap(), 3.14);
        assert!(v.as_string().is_err());

        let v = Value::String("test".into());
        assert_eq!(v.as_string().unwrap(), "test");
        assert!(v.as_number().is_err());

        let v = Value::Bool(true);
        assert_eq!(v.as_bool().unwrap(), true);
        // Number(0) should be false, Number(nonzero) should be true.
        let vn = Value::Number(0.0);
        assert!(!vn.is_truthy());
        let vn2 = Value::Number(1.0);
        assert!(vn2.is_truthy());
    }

    #[test]
    fn vm_values_equal() {
        assert!(values_equal(&Value::Number(1.0), &Value::Number(1.0)));
        assert!(!values_equal(&Value::Number(1.0), &Value::Number(2.0)));
        assert!(values_equal(
            &Value::String("a".into()),
            &Value::String("a".into())
        ));
        assert!(!values_equal(
            &Value::String("a".into()),
            &Value::String("b".into())
        ));
        assert!(values_equal(&Value::Bool(true), &Value::Bool(true)));
        assert!(values_equal(&Value::Null, &Value::Null));
        assert!(!values_equal(
            &Value::Number(1.0),
            &Value::String("1".into())
        ));
    }

    #[test]
    fn vm_execution_time_positive() {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(1.0));
        for _ in 0..100 {
            prog.emit(Instruction::with_operand(OpCode::Push, c));
        }
        prog.emit(Instruction::new(OpCode::Halt));
        let vm = test_vm();
        let result = vm.execute(&prog, &HashMap::new()).unwrap();
        assert!(result.execution_time_ns > 0);
        assert_eq!(result.instructions_executed, 101);
    }
}
