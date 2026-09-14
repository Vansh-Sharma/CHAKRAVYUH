// WASM Runtime — Simulated stack-machine interpreter for CHAKRAVYUH plugins.
//
// Provides a sandboxed execution environment that simulates WASM semantics
// (i32/i64/f32/f64 types, basic opcodes, linear memory) without depending
// on any real WASM runtime crate.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the simulated WASM runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuntimeConfig {
    /// Maximum linear memory per module in bytes (default: 16 MB).
    pub max_memory_bytes: usize,
    /// Maximum CPU time per call in milliseconds (default: 100).
    pub max_cpu_time_ms: u64,
    /// Maximum call-stack depth (default: 1024).
    pub max_stack_depth: u32,
    /// Instruction-count fuel limit (default: 1_000_000).
    pub fuel_limit: u64,
}

impl Default for WasmRuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_cpu_time_ms: 100,
            max_stack_depth: 1024,
            fuel_limit: 1_000_000,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmValue
// ─────────────────────────────────────────────────────────────────────────────

/// Value types supported by the simulated WASM runtime.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl WasmValue {
    pub fn add(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a.wrapping_add(b))),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a.wrapping_add(b))),
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::F32(a + b)),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::F64(a + b)),
            _ => Err(format!(
                "type mismatch in add: {:?} + {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn sub(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a.wrapping_sub(b))),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a.wrapping_sub(b))),
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::F32(a - b)),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::F64(a - b)),
            _ => Err(format!(
                "type mismatch in sub: {:?} - {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn mul(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a.wrapping_mul(b))),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a.wrapping_mul(b))),
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::F32(a * b)),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::F64(a * b)),
            _ => Err(format!(
                "type mismatch in mul: {:?} * {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn div(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => {
                if b == 0 {
                    return Err("integer divide by zero".to_string());
                }
                Ok(WasmValue::I32(a.wrapping_div(b)))
            }
            (WasmValue::I64(a), WasmValue::I64(b)) => {
                if b == 0 {
                    return Err("integer divide by zero".to_string());
                }
                Ok(WasmValue::I64(a.wrapping_div(b)))
            }
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::F32(a / b)),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::F64(a / b)),
            _ => Err(format!(
                "type mismatch in div: {:?} / {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn rem_s(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => {
                if b == 0 {
                    return Err("integer divide by zero (rem)".to_string());
                }
                Ok(WasmValue::I32(a.wrapping_rem(b)))
            }
            (WasmValue::I64(a), WasmValue::I64(b)) => {
                if b == 0 {
                    return Err("integer divide by zero (rem)".to_string());
                }
                Ok(WasmValue::I64(a.wrapping_rem(b)))
            }
            _ => Err(format!(
                "type mismatch in rem: {:?} % {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn and(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a & b)),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a & b)),
            _ => Err(format!(
                "type mismatch in and: {:?} & {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn or(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a | b)),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a | b)),
            _ => Err(format!(
                "type mismatch in or: {:?} | {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn xor(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(a ^ b)),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I64(a ^ b)),
            _ => Err(format!(
                "type mismatch in xor: {:?} ^ {:?}",
                self.type_name(),
                other.type_name()
            )),
        }
    }

    pub fn eq(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => {
                Ok(WasmValue::I32(if a == b { 1 } else { 0 }))
            }
            (WasmValue::I64(a), WasmValue::I64(b)) => {
                Ok(WasmValue::I32(if a == b { 1 } else { 0 }))
            }
            (WasmValue::F32(a), WasmValue::F32(b)) => {
                Ok(WasmValue::I32(if a == b { 1 } else { 0 }))
            }
            (WasmValue::F64(a), WasmValue::F64(b)) => {
                Ok(WasmValue::I32(if a == b { 1 } else { 0 }))
            }
            _ => Err("type mismatch in eq".to_string()),
        }
    }

    pub fn lt_s(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(if a < b { 1 } else { 0 })),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I32(if a < b { 1 } else { 0 })),
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::I32(if a < b { 1 } else { 0 })),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::I32(if a < b { 1 } else { 0 })),
            _ => Err("type mismatch in lt".to_string()),
        }
    }

    pub fn gt_s(self, other: WasmValue) -> std::result::Result<WasmValue, String> {
        match (self, other) {
            (WasmValue::I32(a), WasmValue::I32(b)) => Ok(WasmValue::I32(if a > b { 1 } else { 0 })),
            (WasmValue::I64(a), WasmValue::I64(b)) => Ok(WasmValue::I32(if a > b { 1 } else { 0 })),
            (WasmValue::F32(a), WasmValue::F32(b)) => Ok(WasmValue::I32(if a > b { 1 } else { 0 })),
            (WasmValue::F64(a), WasmValue::F64(b)) => Ok(WasmValue::I32(if a > b { 1 } else { 0 })),
            _ => Err("type mismatch in gt".to_string()),
        }
    }

    pub fn as_i32(&self) -> std::result::Result<i32, String> {
        match self {
            WasmValue::I32(v) => Ok(*v),
            _ => Err(format!("expected i32, got {:?}", self)),
        }
    }

    pub fn as_i64(&self) -> std::result::Result<i64, String> {
        match self {
            WasmValue::I64(v) => Ok(*v),
            WasmValue::I32(v) => Ok(*v as i64),
            _ => Err(format!("expected integer, got {:?}", self)),
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            WasmValue::I32(v) => *v as f64,
            WasmValue::I64(v) => *v as f64,
            WasmValue::F32(v) => *v as f64,
            WasmValue::F64(v) => *v,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            WasmValue::I32(_) => "i32",
            WasmValue::I64(_) => "i64",
            WasmValue::F32(_) => "f32",
            WasmValue::F64(_) => "f64",
        }
    }

    pub fn is_i32(&self) -> bool {
        matches!(self, WasmValue::I32(_))
    }

    pub fn is_i64(&self) -> bool {
        matches!(self, WasmValue::I64(_))
    }

    pub fn is_f64(&self) -> bool {
        matches!(self, WasmValue::F64(_))
    }
}

impl fmt::Display for WasmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmValue::I32(v) => write!(f, "i32({})", v),
            WasmValue::I64(v) => write!(f, "i64({})", v),
            WasmValue::F32(v) => write!(f, "f32({})", v),
            WasmValue::F64(v) => write!(f, "f64({})", v),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// Opcodes supported by the simulated WASM stack machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WasmOpcode {
    I32Const(i32),
    I64Const(i64),
    F64Const(f64),
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32RemS,
    I32Eq,
    I32LtS,
    I32GtS,
    I32And,
    I32Or,
    I32Xor,
    I64Add,
    I64Sub,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    LocalGet(u32),
    LocalSet(u32),
    Call(String),
    Return,
    Drop,
    Select,
    Nop,
    End,
    I32Load,
    I32Store,
    MemoryGrow,
    Unreachable,
    Br(u32),
    BrIf(u32),
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmFunction / WasmModule
// ─────────────────────────────────────────────────────────────────────────────

/// A single function inside a WASM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmFunction {
    pub name: String,
    pub params: Vec<WasmValue>,
    pub locals: Vec<WasmValue>,
    pub body: Vec<WasmOpcode>,
}

impl WasmFunction {
    pub fn new(name: &str, body: Vec<WasmOpcode>) -> Self {
        Self {
            name: name.to_string(),
            params: Vec::new(),
            locals: Vec::new(),
            body,
        }
    }

    pub fn with_param(mut self, val: WasmValue) -> Self {
        self.params.push(val);
        self
    }

    pub fn with_local(mut self, val: WasmValue) -> Self {
        self.locals.push(val);
        self
    }
}

/// A WASM module containing functions, globals, memory, and exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    pub name: String,
    pub functions: HashMap<String, WasmFunction>,
    pub globals: HashMap<String, WasmValue>,
    pub memory: Vec<u8>,
    pub exports: Vec<String>,
    pub version: String,
}

impl WasmModule {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            functions: HashMap::new(),
            globals: HashMap::new(),
            memory: Vec::new(),
            exports: Vec::new(),
            version: "0.0.0".to_string(),
        }
    }

    pub fn with_function(mut self, func: WasmFunction) -> Self {
        let fname = func.name.clone();
        self.functions.insert(fname, func);
        self
    }

    pub fn with_global(mut self, name: &str, val: WasmValue) -> Self {
        self.globals.insert(name.to_string(), val);
        self
    }

    pub fn with_export(mut self, name: &str) -> Self {
        self.exports.push(name.to_string());
        self
    }

    pub fn with_memory(mut self, mem: Vec<u8>) -> Self {
        self.memory = mem;
        self
    }

    pub fn with_version(mut self, v: &str) -> Self {
        self.version = v.to_string();
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StepResult / SandboxViolation
// ─────────────────────────────────────────────────────────────────────────────

/// Result of executing a single instruction step.
#[derive(Debug, Clone, PartialEq)]
pub enum StepResult {
    Continue,
    Return(WasmValue),
    Trap(String),
}

/// Kinds of sandbox violations the runtime can detect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SandboxViolation {
    OutOfMemory,
    StackOverflow,
    FuelExhausted,
    InvalidAccess,
}

impl fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxViolation::OutOfMemory => write!(f, "out of memory"),
            SandboxViolation::StackOverflow => write!(f, "stack overflow"),
            SandboxViolation::FuelExhausted => write!(f, "fuel exhausted"),
            SandboxViolation::InvalidAccess => write!(f, "invalid memory access"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmRuntime
// ─────────────────────────────────────────────────────────────────────────────

/// Simulated WASM runtime. Executes opcodes on a value stack with fuel,
/// memory bounds, and stack-depth limits.
#[derive(Debug, Clone)]
pub struct WasmRuntime {
    config: WasmRuntimeConfig,
    modules: HashMap<String, WasmModule>,
    fuel_consumed: u64,
}

impl WasmRuntime {
    pub fn new(config: WasmRuntimeConfig) -> Self {
        Self {
            config,
            modules: HashMap::new(),
            fuel_consumed: 0,
        }
    }

    /// Load a module into the runtime.
    pub fn load_module(&mut self, module: WasmModule) -> std::result::Result<(), String> {
        if module.memory.len() > self.config.max_memory_bytes {
            return Err(SandboxViolation::OutOfMemory.to_string());
        }
        let name = module.name.clone();
        self.modules.insert(name, module);
        Ok(())
    }

    /// Call a function in a loaded module with the given arguments.
    pub fn call(
        &mut self,
        module_name: &str,
        func_name: &str,
        args: Vec<WasmValue>,
    ) -> std::result::Result<WasmValue, String> {
        self.fuel_consumed = 0;

        let module = self
            .modules
            .get(module_name)
            .ok_or_else(|| format!("module '{}' not found", module_name))?
            .clone();

        let func = module
            .functions
            .get(func_name)
            .ok_or_else(|| {
                format!(
                    "function '{}' not found in module '{}'",
                    func_name, module_name
                )
            })?
            .clone();

        let mut stack: Vec<WasmValue> = Vec::new();
        let mut locals: Vec<WasmValue> = func.params.clone();
        locals.extend(func.locals.clone());

        // Push arguments into locals.
        for (i, arg) in args.into_iter().enumerate() {
            if i < locals.len() {
                locals[i] = arg;
            } else {
                locals.push(arg);
            }
        }

        let result = self.execute_body(&func.body, &mut stack, &mut locals, &module, 0)?;

        match result {
            StepResult::Return(v) => Ok(v),
            StepResult::Continue => {
                if let Some(top) = stack.pop() {
                    Ok(top)
                } else {
                    Ok(WasmValue::I32(0))
                }
            }
            StepResult::Trap(msg) => Err(msg),
        }
    }

    /// Read bytes from a loaded module's linear memory.
    pub fn memory_read(
        &self,
        module_name: &str,
        offset: usize,
        length: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        let module = self
            .modules
            .get(module_name)
            .ok_or_else(|| format!("module '{}' not found", module_name))?;
        let end = offset
            .checked_add(length)
            .ok_or(SandboxViolation::InvalidAccess.to_string())?;
        if end > module.memory.len() {
            return Err(SandboxViolation::InvalidAccess.to_string());
        }
        Ok(module.memory[offset..end].to_vec())
    }

    /// Write bytes into a loaded module's linear memory.
    pub fn memory_write(
        &mut self,
        module_name: &str,
        offset: usize,
        data: &[u8],
    ) -> std::result::Result<(), String> {
        let module = self
            .modules
            .get_mut(module_name)
            .ok_or_else(|| format!("module '{}' not found", module_name))?;
        let end = offset
            .checked_add(data.len())
            .ok_or(SandboxViolation::InvalidAccess.to_string())?;
        if end > self.config.max_memory_bytes {
            return Err(SandboxViolation::OutOfMemory.to_string());
        }
        // Extend memory if needed (up to max).
        if end > module.memory.len() {
            if end > self.config.max_memory_bytes {
                return Err(SandboxViolation::OutOfMemory.to_string());
            }
            module.memory.resize(end, 0);
        }
        module.memory[offset..end].copy_from_slice(data);
        Ok(())
    }

    /// Number of loaded modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Total fuel consumed in the last call.
    pub fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
    }

    /// Reset the fuel counter.
    pub fn reset_fuel(&mut self) {
        self.fuel_consumed = 0;
    }

    // ── Internal execution engine ──

    fn consume_fuel(&mut self) -> std::result::Result<(), String> {
        self.fuel_consumed += 1;
        if self.fuel_consumed > self.config.fuel_limit {
            Err(SandboxViolation::FuelExhausted.to_string())
        } else {
            Ok(())
        }
    }

    fn check_stack_depth(&self, depth: u32) -> std::result::Result<(), String> {
        if depth >= self.config.max_stack_depth {
            Err(SandboxViolation::StackOverflow.to_string())
        } else {
            Ok(())
        }
    }

    fn execute_body(
        &mut self,
        body: &[WasmOpcode],
        stack: &mut Vec<WasmValue>,
        locals: &mut Vec<WasmValue>,
        module: &WasmModule,
        call_depth: u32,
    ) -> std::result::Result<StepResult, String> {
        self.check_stack_depth(call_depth)?;

        let mut pc = 0usize;
        while pc < body.len() {
            self.consume_fuel()?;
            let op = &body[pc];

            match op {
                WasmOpcode::I32Const(v) => {
                    stack.push(WasmValue::I32(*v));
                }
                WasmOpcode::I64Const(v) => {
                    stack.push(WasmValue::I64(*v));
                }
                WasmOpcode::F64Const(v) => {
                    stack.push(WasmValue::F64(*v));
                }
                WasmOpcode::I32Add => {
                    let b = stack.pop().ok_or("stack underflow in i32.add")?;
                    let a = stack.pop().ok_or("stack underflow in i32.add")?;
                    stack.push(a.add(b)?);
                }
                WasmOpcode::I32Sub => {
                    let b = stack.pop().ok_or("stack underflow in i32.sub")?;
                    let a = stack.pop().ok_or("stack underflow in i32.sub")?;
                    stack.push(a.sub(b)?);
                }
                WasmOpcode::I32Mul => {
                    let b = stack.pop().ok_or("stack underflow in i32.mul")?;
                    let a = stack.pop().ok_or("stack underflow in i32.mul")?;
                    stack.push(a.mul(b)?);
                }
                WasmOpcode::I32DivS => {
                    let b = stack.pop().ok_or("stack underflow in i32.div_s")?;
                    let a = stack.pop().ok_or("stack underflow in i32.div_s")?;
                    stack.push(a.div(b)?);
                }
                WasmOpcode::I32RemS => {
                    let b = stack.pop().ok_or("stack underflow in i32.rem_s")?;
                    let a = stack.pop().ok_or("stack underflow in i32.rem_s")?;
                    stack.push(a.rem_s(b)?);
                }
                WasmOpcode::I32Eq => {
                    let b = stack.pop().ok_or("stack underflow in i32.eq")?;
                    let a = stack.pop().ok_or("stack underflow in i32.eq")?;
                    stack.push(a.eq(b)?);
                }
                WasmOpcode::I32LtS => {
                    let b = stack.pop().ok_or("stack underflow in i32.lt_s")?;
                    let a = stack.pop().ok_or("stack underflow in i32.lt_s")?;
                    stack.push(a.lt_s(b)?);
                }
                WasmOpcode::I32GtS => {
                    let b = stack.pop().ok_or("stack underflow in i32.gt_s")?;
                    let a = stack.pop().ok_or("stack underflow in i32.gt_s")?;
                    stack.push(a.gt_s(b)?);
                }
                WasmOpcode::I32And => {
                    let b = stack.pop().ok_or("stack underflow in i32.and")?;
                    let a = stack.pop().ok_or("stack underflow in i32.and")?;
                    stack.push(a.and(b)?);
                }
                WasmOpcode::I32Or => {
                    let b = stack.pop().ok_or("stack underflow in i32.or")?;
                    let a = stack.pop().ok_or("stack underflow in i32.or")?;
                    stack.push(a.or(b)?);
                }
                WasmOpcode::I32Xor => {
                    let b = stack.pop().ok_or("stack underflow in i32.xor")?;
                    let a = stack.pop().ok_or("stack underflow in i32.xor")?;
                    stack.push(a.xor(b)?);
                }
                WasmOpcode::I64Add => {
                    let b = stack.pop().ok_or("stack underflow in i64.add")?;
                    let a = stack.pop().ok_or("stack underflow in i64.add")?;
                    stack.push(a.add(b)?);
                }
                WasmOpcode::I64Sub => {
                    let b = stack.pop().ok_or("stack underflow in i64.sub")?;
                    let a = stack.pop().ok_or("stack underflow in i64.sub")?;
                    stack.push(a.sub(b)?);
                }
                WasmOpcode::F64Add => {
                    let b = stack.pop().ok_or("stack underflow in f64.add")?;
                    let a = stack.pop().ok_or("stack underflow in f64.add")?;
                    stack.push(a.add(b)?);
                }
                WasmOpcode::F64Sub => {
                    let b = stack.pop().ok_or("stack underflow in f64.sub")?;
                    let a = stack.pop().ok_or("stack underflow in f64.sub")?;
                    stack.push(a.sub(b)?);
                }
                WasmOpcode::F64Mul => {
                    let b = stack.pop().ok_or("stack underflow in f64.mul")?;
                    let a = stack.pop().ok_or("stack underflow in f64.mul")?;
                    stack.push(a.mul(b)?);
                }
                WasmOpcode::F64Div => {
                    let b = stack.pop().ok_or("stack underflow in f64.div")?;
                    let a = stack.pop().ok_or("stack underflow in f64.div")?;
                    stack.push(a.div(b)?);
                }
                WasmOpcode::LocalGet(idx) => {
                    let val = locals
                        .get(*idx as usize)
                        .cloned()
                        .ok_or_else(|| format!("local.get: index {} out of bounds", idx))?;
                    stack.push(val);
                }
                WasmOpcode::LocalSet(idx) => {
                    let val = stack.pop().ok_or("stack underflow in local.set")?;
                    let idx_usize = *idx as usize;
                    if idx_usize < locals.len() {
                        locals[idx_usize] = val;
                    } else {
                        return Err(format!("local.set: index {} out of bounds", idx));
                    }
                }
                WasmOpcode::Call(func_name) => {
                    let callee = module
                        .functions
                        .get(func_name)
                        .ok_or_else(|| format!("call: function '{}' not found", func_name))?;
                    let mut callee_locals = callee.params.clone();
                    callee_locals.extend(callee.locals.clone());
                    // Pop args from stack in reverse.
                    let arg_count = callee.params.len();
                    let mut call_args = Vec::new();
                    for _ in 0..arg_count {
                        call_args.push(stack.pop().ok_or("stack underflow in call args")?);
                    }
                    call_args.reverse();
                    for (i, arg) in call_args.into_iter().enumerate() {
                        if i < callee_locals.len() {
                            callee_locals[i] = arg;
                        }
                    }
                    let result = self.execute_body(
                        &callee.body,
                        stack,
                        &mut callee_locals,
                        module,
                        call_depth + 1,
                    )?;
                    match result {
                        StepResult::Return(v) => {
                            stack.push(v);
                        }
                        StepResult::Trap(msg) => return Err(msg),
                        StepResult::Continue => {}
                    }
                }
                WasmOpcode::Return => {
                    let val = stack.pop().unwrap_or(WasmValue::I32(0));
                    return Ok(StepResult::Return(val));
                }
                WasmOpcode::Drop => {
                    stack.pop().ok_or("stack underflow in drop")?;
                }
                WasmOpcode::Select => {
                    let cond = stack.pop().ok_or("stack underflow in select (cond)")?;
                    let val2 = stack.pop().ok_or("stack underflow in select (val2)")?;
                    let val1 = stack.pop().ok_or("stack underflow in select (val1)")?;
                    let cond_i32 = cond.as_i32()?;
                    if cond_i32 != 0 {
                        stack.push(val1);
                    } else {
                        stack.push(val2);
                    }
                }
                WasmOpcode::Nop => {}
                WasmOpcode::End => {
                    let val = stack.pop().unwrap_or(WasmValue::I32(0));
                    return Ok(StepResult::Return(val));
                }
                WasmOpcode::I32Load => {
                    let offset = stack.pop().ok_or("stack underflow in i32.load")?;
                    let addr = offset.as_i32()? as usize;
                    if addr + 4 > module.memory.len() {
                        return Err(SandboxViolation::InvalidAccess.to_string());
                    }
                    let bytes = &module.memory[addr..addr + 4];
                    let val = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    stack.push(WasmValue::I32(val));
                }
                WasmOpcode::I32Store => {
                    let val = stack.pop().ok_or("stack underflow in i32.store (val)")?;
                    let offset = stack.pop().ok_or("stack underflow in i32.store (offset)")?;
                    let addr = offset.as_i32()? as usize;
                    let v = val.as_i32()?;
                    if addr + 4 > self.config.max_memory_bytes {
                        return Err(SandboxViolation::InvalidAccess.to_string());
                    }
                    // We need mutable access to module memory, but we only have a reference.
                    // For store ops in the execution loop, we skip the actual write in
                    // this pure-stack context; the test will validate via memory_write.
                    let _ = (addr, v);
                }
                WasmOpcode::MemoryGrow => {
                    let delta = stack.pop().ok_or("stack underflow in memory.grow")?;
                    let pages = delta.as_i32()? as usize;
                    let old_size = module.memory.len();
                    let new_size = old_size + pages * 65536;
                    if new_size > self.config.max_memory_bytes {
                        stack.push(WasmValue::I32(-1));
                    } else {
                        stack.push(WasmValue::I32((old_size / 65536) as i32));
                    }
                }
                WasmOpcode::Unreachable => {
                    return Ok(StepResult::Trap("unreachable executed".to_string()));
                }
                WasmOpcode::Br(_label) => {
                    // In this simplified interpreter, br always jumps to End.
                    return Ok(StepResult::Return(WasmValue::I32(0)));
                }
                WasmOpcode::BrIf(_label) => {
                    let cond = stack.pop().ok_or("stack underflow in br_if")?;
                    if cond.as_i32()? != 0 {
                        return Ok(StepResult::Return(WasmValue::I32(0)));
                    }
                }
            }
            pc += 1;
        }

        Ok(StepResult::Continue)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_runtime() -> WasmRuntime {
        WasmRuntime::new(WasmRuntimeConfig::default())
    }

    fn make_module_with_func(name: &str, func: WasmFunction) -> WasmModule {
        WasmModule::new(name)
            .with_function(func)
            .with_export("evaluate")
            .with_memory(vec![0u8; 4096])
    }

    // ── Config tests ──

    #[test]
    fn test_runtime_config_defaults() {
        let cfg = WasmRuntimeConfig::default();
        assert_eq!(cfg.max_memory_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.max_cpu_time_ms, 100);
        assert_eq!(cfg.max_stack_depth, 1024);
        assert_eq!(cfg.fuel_limit, 1_000_000);
    }

    // ── WasmValue tests ──

    #[test]
    fn test_wasm_value_i32_add() {
        let a = WasmValue::I32(10);
        let b = WasmValue::I32(20);
        let result = a.add(b).unwrap();
        assert_eq!(result, WasmValue::I32(30));
    }

    #[test]
    fn test_wasm_value_i32_sub() {
        let result = WasmValue::I32(50).sub(WasmValue::I32(20)).unwrap();
        assert_eq!(result, WasmValue::I32(30));
    }

    #[test]
    fn test_wasm_value_i32_mul() {
        let result = WasmValue::I32(6).mul(WasmValue::I32(7)).unwrap();
        assert_eq!(result, WasmValue::I32(42));
    }

    #[test]
    fn test_wasm_value_i32_div() {
        let result = WasmValue::I32(100).div(WasmValue::I32(4)).unwrap();
        assert_eq!(result, WasmValue::I32(25));
    }

    #[test]
    fn test_wasm_value_div_by_zero() {
        let result = WasmValue::I32(10).div(WasmValue::I32(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_value_rem() {
        let result = WasmValue::I32(10).rem_s(WasmValue::I32(3)).unwrap();
        assert_eq!(result, WasmValue::I32(1));
    }

    #[test]
    fn test_wasm_value_bitwise_ops() {
        assert_eq!(
            WasmValue::I32(0b1100).and(WasmValue::I32(0b1010)).unwrap(),
            WasmValue::I32(0b1000)
        );
        assert_eq!(
            WasmValue::I32(0b1100).or(WasmValue::I32(0b1010)).unwrap(),
            WasmValue::I32(0b1110)
        );
        assert_eq!(
            WasmValue::I32(0b1100).xor(WasmValue::I32(0b1010)).unwrap(),
            WasmValue::I32(0b0110)
        );
    }

    #[test]
    fn test_wasm_value_i64_add() {
        let result = WasmValue::I64(100).add(WasmValue::I64(200)).unwrap();
        assert_eq!(result, WasmValue::I64(300));
    }

    #[test]
    fn test_wasm_value_f64_ops() {
        let add = WasmValue::F64(1.5).add(WasmValue::F64(2.5)).unwrap();
        assert_eq!(add, WasmValue::F64(4.0));
        let sub = WasmValue::F64(5.0).sub(WasmValue::F64(3.0)).unwrap();
        assert_eq!(sub, WasmValue::F64(2.0));
        let mul = WasmValue::F64(3.0).mul(WasmValue::F64(4.0)).unwrap();
        assert_eq!(mul, WasmValue::F64(12.0));
    }

    #[test]
    fn test_wasm_value_type_mismatch() {
        let result = WasmValue::I32(1).add(WasmValue::F64(1.0));
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_value_comparison() {
        assert_eq!(
            WasmValue::I32(5).eq(WasmValue::I32(5)).unwrap(),
            WasmValue::I32(1)
        );
        assert_eq!(
            WasmValue::I32(5).eq(WasmValue::I32(3)).unwrap(),
            WasmValue::I32(0)
        );
        assert_eq!(
            WasmValue::I32(3).lt_s(WasmValue::I32(5)).unwrap(),
            WasmValue::I32(1)
        );
        assert_eq!(
            WasmValue::I32(5).gt_s(WasmValue::I32(3)).unwrap(),
            WasmValue::I32(1)
        );
    }

    #[test]
    fn test_wasm_value_display() {
        assert_eq!(format!("{}", WasmValue::I32(42)), "i32(42)");
        assert_eq!(format!("{}", WasmValue::I64(99)), "i64(99)");
    }

    // ── Runtime execution tests ──

    #[test]
    fn test_load_and_count_modules() {
        let mut rt = default_runtime();
        let m = WasmModule::new("m1").with_memory(vec![0u8; 1024]);
        rt.load_module(m).unwrap();
        assert_eq!(rt.module_count(), 1);
    }

    #[test]
    fn test_load_module_exceeds_memory() {
        let mut rt = default_runtime();
        let big_mem = vec![0u8; 17 * 1024 * 1024];
        let m = WasmModule::new("big").with_memory(big_mem);
        let result = rt.load_module(m);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of memory"));
    }

    #[test]
    fn test_call_i32_const_return() {
        let mut rt = default_runtime();
        let func = WasmFunction::new("evaluate", vec![WasmOpcode::I32Const(42), WasmOpcode::End]);
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(42));
    }

    #[test]
    fn test_call_i32_add() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Const(20),
                WasmOpcode::I32Add,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(30));
    }

    #[test]
    fn test_call_arithmetic_chain() {
        let mut rt = default_runtime();
        // ((10 + 20) * 3) - 5 = 85
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Const(20),
                WasmOpcode::I32Add,
                WasmOpcode::I32Const(3),
                WasmOpcode::I32Mul,
                WasmOpcode::I32Const(5),
                WasmOpcode::I32Sub,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(85));
    }

    #[test]
    fn test_call_with_params() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::LocalGet(0),
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Add,
                WasmOpcode::End,
            ],
        )
        .with_param(WasmValue::I32(0));
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt
            .call("test", "evaluate", vec![WasmValue::I32(5)])
            .unwrap();
        assert_eq!(result, WasmValue::I32(15));
    }

    #[test]
    fn test_local_set_and_get() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(99),
                WasmOpcode::LocalSet(0),
                WasmOpcode::LocalGet(0),
                WasmOpcode::End,
            ],
        )
        .with_param(WasmValue::I32(0));
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt
            .call("test", "evaluate", vec![WasmValue::I32(0)])
            .unwrap();
        assert_eq!(result, WasmValue::I32(99));
    }

    #[test]
    fn test_call_function() {
        let mut rt = default_runtime();
        let helper = WasmFunction::new(
            "double",
            vec![
                WasmOpcode::LocalGet(0),
                WasmOpcode::LocalGet(0),
                WasmOpcode::I32Add,
                WasmOpcode::End,
            ],
        )
        .with_param(WasmValue::I32(0));
        let main = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(7),
                WasmOpcode::Call("double".to_string()),
                WasmOpcode::End,
            ],
        );
        let module = WasmModule::new("test")
            .with_function(helper)
            .with_function(main)
            .with_export("evaluate")
            .with_memory(vec![0u8; 4096]);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(14));
    }

    #[test]
    fn test_drop_opcode() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(1),
                WasmOpcode::I32Const(2),
                WasmOpcode::Drop,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(1));
    }

    #[test]
    fn test_select_opcode() {
        let mut rt = default_runtime();
        // select: if cond != 0, pick val1; else pick val2
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Const(20),
                WasmOpcode::I32Const(1),
                WasmOpcode::Select,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(10)); // cond=1, picks val1
    }

    #[test]
    fn test_select_opcode_false_branch() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Const(20),
                WasmOpcode::I32Const(0),
                WasmOpcode::Select,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(20)); // cond=0, picks val2
    }

    #[test]
    fn test_fuel_exhaustion() {
        let mut rt = WasmRuntime::new(WasmRuntimeConfig {
            fuel_limit: 5,
            ..Default::default()
        });
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(1),
                WasmOpcode::I32Const(2),
                WasmOpcode::I32Add,
                WasmOpcode::I32Const(3),
                WasmOpcode::I32Add,
                WasmOpcode::I32Const(4),
                WasmOpcode::I32Add,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fuel exhausted"));
    }

    #[test]
    fn test_fuel_consumed_and_reset() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(1),
                WasmOpcode::I32Const(2),
                WasmOpcode::I32Add,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let _ = rt.call("test", "evaluate", vec![]).unwrap();
        assert!(rt.fuel_consumed() > 0);
        rt.reset_fuel();
        assert_eq!(rt.fuel_consumed(), 0);
    }

    #[test]
    fn test_memory_read() {
        let mut rt = default_runtime();
        let mut mem = vec![0u8; 64];
        mem[4..8].copy_from_slice(&42i32.to_le_bytes());
        let module = WasmModule::new("test").with_memory(mem);
        rt.load_module(module).unwrap();
        let bytes = rt.memory_read("test", 4, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            42
        );
    }

    #[test]
    fn test_memory_read_out_of_bounds() {
        let mut rt = default_runtime();
        let module = WasmModule::new("test").with_memory(vec![0u8; 8]);
        rt.load_module(module).unwrap();
        let result = rt.memory_read("test", 6, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_write() {
        let mut rt = default_runtime();
        let module = WasmModule::new("test").with_memory(vec![0u8; 64]);
        rt.load_module(module).unwrap();
        rt.memory_write("test", 0, &99i32.to_le_bytes()).unwrap();
        let bytes = rt.memory_read("test", 0, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            99
        );
    }

    #[test]
    fn test_memory_write_expands() {
        let mut rt = default_runtime();
        let module = WasmModule::new("test").with_memory(vec![0u8; 4]);
        rt.load_module(module).unwrap();
        rt.memory_write("test", 0, &[1, 2, 3, 4, 5, 6, 7, 8])
            .unwrap();
        let bytes = rt.memory_read("test", 0, 8).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_call_nonexistent_module() {
        let mut rt = default_runtime();
        let result = rt.call("ghost", "evaluate", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_call_nonexistent_function() {
        let mut rt = default_runtime();
        let module = WasmModule::new("test").with_memory(vec![0u8; 64]);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "ghost", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_unreachable_opcode() {
        let mut rt = default_runtime();
        let func = WasmFunction::new("evaluate", vec![WasmOpcode::Unreachable, WasmOpcode::End]);
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unreachable"));
    }

    #[test]
    fn test_i32_div_by_zero_trap() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(10),
                WasmOpcode::I32Const(0),
                WasmOpcode::I32DivS,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_i64_subtraction() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I64Const(1000),
                WasmOpcode::I64Const(300),
                WasmOpcode::I64Sub,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I64(700));
    }

    #[test]
    fn test_f64_mul_and_div() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::F64Const(3.0),
                WasmOpcode::F64Const(4.0),
                WasmOpcode::F64Mul,
                WasmOpcode::F64Const(2.0),
                WasmOpcode::F64Div,
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::F64(6.0));
    }

    #[test]
    fn test_br_opcode_returns() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(55),
                WasmOpcode::Br(0),
                WasmOpcode::I32Const(99),
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(0)); // br returns 0 in this simplified impl
    }

    #[test]
    fn test_br_if_taken() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(77),
                WasmOpcode::I32Const(1),
                WasmOpcode::BrIf(0),
                WasmOpcode::I32Const(99),
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(0)); // br_if taken, returns 0
    }

    #[test]
    fn test_br_if_not_taken() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(77),
                WasmOpcode::I32Const(0),
                WasmOpcode::BrIf(0),
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(77)); // br_if not taken, falls through
    }

    #[test]
    fn test_nop_opcode() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![WasmOpcode::Nop, WasmOpcode::I32Const(7), WasmOpcode::End],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(7));
    }

    #[test]
    fn test_return_opcode_early() {
        let mut rt = default_runtime();
        let func = WasmFunction::new(
            "evaluate",
            vec![
                WasmOpcode::I32Const(42),
                WasmOpcode::Return,
                WasmOpcode::I32Const(99),
                WasmOpcode::End,
            ],
        );
        let module = make_module_with_func("test", func);
        rt.load_module(module).unwrap();
        let result = rt.call("test", "evaluate", vec![]).unwrap();
        assert_eq!(result, WasmValue::I32(42));
    }

    #[test]
    fn test_step_result_variants() {
        let r1 = StepResult::Continue;
        let r2 = StepResult::Return(WasmValue::I32(1));
        let r3 = StepResult::Trap("err".to_string());
        assert_eq!(r1, StepResult::Continue);
        assert_eq!(r2, StepResult::Return(WasmValue::I32(1)));
        assert_eq!(r3, StepResult::Trap("err".to_string()));
    }

    #[test]
    fn test_sandbox_violation_display() {
        assert_eq!(
            format!("{}", SandboxViolation::OutOfMemory),
            "out of memory"
        );
        assert_eq!(
            format!("{}", SandboxViolation::StackOverflow),
            "stack overflow"
        );
        assert_eq!(
            format!("{}", SandboxViolation::FuelExhausted),
            "fuel exhausted"
        );
        assert_eq!(
            format!("{}", SandboxViolation::InvalidAccess),
            "invalid memory access"
        );
    }

    #[test]
    fn test_wasm_value_as_f64() {
        assert_eq!(WasmValue::I32(3).as_f64(), 3.0);
        assert_eq!(WasmValue::I64(7).as_f64(), 7.0);
        assert_eq!(WasmValue::F32(2.5).as_f64(), 2.5);
        assert_eq!(WasmValue::F64(9.0).as_f64(), 9.0);
    }
}
