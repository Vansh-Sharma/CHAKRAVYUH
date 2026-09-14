// Bytecode instruction set and program representation for the CHAKRAVYUH policy VM.
//
// Defines the stack-based instruction set architecture (OpCode), individual
// instructions with source mapping, the BytecodeProgram container, and
// binary serialization with a magic header for integrity checks.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Magic bytes and format version ──────────────────────────────────────

/// Magic bytes identifying a compiled CHAKRAVYUH policy binary.
pub const MAGIC: &[u8; 5] = b"CVPOL";
/// Current bytecode format version.
pub const FORMAT_VERSION: u8 = 1;

// ── OpCode enumeration ─────────────────────────────────────────────────

/// All opcodes understood by the policy VM.
///
/// Backed by u8 so it serializes compactly. Operand interpretation depends
/// on the variant — see `Instruction` for the pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OpCode {
    // ── Stack manipulation ──────────────────────────────────────────
    /// Push a numeric literal (operand is index into constant pool).
    Push = 0x00,
    /// Push a string literal (operand is index into constant pool).
    PushStr = 0x01,
    /// Load a variable from the environment (operand is slot index).
    Load = 0x02,
    /// Store top of stack to a variable slot (operand is slot index).
    Store = 0x03,

    // ── Arithmetic ─────────────────────────────────────────────────
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,
    Mod = 0x14,

    // ── Comparisons ────────────────────────────────────────────────
    Gt = 0x20,
    Lt = 0x21,
    Ge = 0x22,
    Le = 0x23,
    Eq = 0x24,
    Ne = 0x25,

    // ── Logic ──────────────────────────────────────────────────────
    And = 0x30,
    Or = 0x31,
    Not = 0x32,

    // ── Control flow ────────────────────────────────────────────────
    /// Unconditional jump (operand is target instruction index).
    Jump = 0x40,
    /// Pop top, jump if false.
    JumpIfFalse = 0x41,
    /// Pop top, jump if true.
    JumpIfTrue = 0x42,
    /// Call a subroutine at the given instruction index.
    Call = 0x43,
    /// Return from subroutine.
    Return = 0x44,

    // ── String operations ───────────────────────────────────────────
    /// Pop string, regex-match against constant pool entry.
    MatchRegex = 0x50,
    /// Pop haystack, pop needle (or constant); push bool.
    Contains = 0x51,
    /// Pop string, check prefix.
    StartsWith = 0x52,
    /// Pop string, check suffix.
    EndsWith = 0x53,

    // ── Risk accumulation ───────────────────────────────────────────
    /// Add top-of-stack to current risk accumulator.
    RiskAdd = 0x60,
    /// Multiply risk accumulator by top-of-stack.
    RiskMul = 0x61,
    /// Set risk accumulator to max(acc, top).
    RiskMax = 0x62,

    // ── Decision emission ───────────────────────────────────────────
    /// Emit a Deny decision; halt execution.
    Deny = 0x70,
    /// Emit an Allow decision; halt execution.
    Allow = 0x71,
    /// Emit an Escalate decision; halt execution.
    Escalate = 0x72,
    /// Emit a Challenge decision; halt execution.
    Challenge = 0x73,

    // ── Misc ────────────────────────────────────────────────────────
    /// Stop the VM.
    Halt = 0xF0,
    /// No operation (for alignment / dead slots).
    Nop = 0xFF,
}

impl OpCode {
    /// Total number of opcodes — useful for pre-allocated dispatch tables.
    pub const COUNT: usize = 256;

    /// Convert a raw byte into an OpCode. Unknown bytes map to Nop.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => OpCode::Push,
            0x01 => OpCode::PushStr,
            0x02 => OpCode::Load,
            0x03 => OpCode::Store,
            0x10 => OpCode::Add,
            0x11 => OpCode::Sub,
            0x12 => OpCode::Mul,
            0x13 => OpCode::Div,
            0x14 => OpCode::Mod,
            0x20 => OpCode::Gt,
            0x21 => OpCode::Lt,
            0x22 => OpCode::Ge,
            0x23 => OpCode::Le,
            0x24 => OpCode::Eq,
            0x25 => OpCode::Ne,
            0x30 => OpCode::And,
            0x31 => OpCode::Or,
            0x32 => OpCode::Not,
            0x40 => OpCode::Jump,
            0x41 => OpCode::JumpIfFalse,
            0x42 => OpCode::JumpIfTrue,
            0x43 => OpCode::Call,
            0x44 => OpCode::Return,
            0x50 => OpCode::MatchRegex,
            0x51 => OpCode::Contains,
            0x52 => OpCode::StartsWith,
            0x53 => OpCode::EndsWith,
            0x60 => OpCode::RiskAdd,
            0x61 => OpCode::RiskMul,
            0x62 => OpCode::RiskMax,
            0x70 => OpCode::Deny,
            0x71 => OpCode::Allow,
            0x72 => OpCode::Escalate,
            0x73 => OpCode::Challenge,
            0xF0 => OpCode::Halt,
            _ => OpCode::Nop,
        }
    }

    /// Return the human-readable mnemonic for this opcode.
    pub fn mnemonic(self) -> &'static str {
        match self {
            OpCode::Push => "PUSH",
            OpCode::PushStr => "PUSH_STR",
            OpCode::Load => "LOAD",
            OpCode::Store => "STORE",
            OpCode::Add => "ADD",
            OpCode::Sub => "SUB",
            OpCode::Mul => "MUL",
            OpCode::Div => "DIV",
            OpCode::Mod => "MOD",
            OpCode::Gt => "GT",
            OpCode::Lt => "LT",
            OpCode::Ge => "GE",
            OpCode::Le => "LE",
            OpCode::Eq => "EQ",
            OpCode::Ne => "NE",
            OpCode::And => "AND",
            OpCode::Or => "OR",
            OpCode::Not => "NOT",
            OpCode::Jump => "JMP",
            OpCode::JumpIfFalse => "JMP_F",
            OpCode::JumpIfTrue => "JMP_T",
            OpCode::Call => "CALL",
            OpCode::Return => "RET",
            OpCode::MatchRegex => "MATCH_RE",
            OpCode::Contains => "CONTAINS",
            OpCode::StartsWith => "STARTSWITH",
            OpCode::EndsWith => "ENDSWITH",
            OpCode::RiskAdd => "RISK_ADD",
            OpCode::RiskMul => "RISK_MUL",
            OpCode::RiskMax => "RISK_MAX",
            OpCode::Deny => "DENY",
            OpCode::Allow => "ALLOW",
            OpCode::Escalate => "ESCALATE",
            OpCode::Challenge => "CHALLENGE",
            OpCode::Halt => "HALT",
            OpCode::Nop => "NOP",
        }
    }

    /// Returns true if this opcode expects an operand.
    pub fn has_operand(self) -> bool {
        matches!(
            self,
            OpCode::Push
                | OpCode::PushStr
                | OpCode::Load
                | OpCode::Store
                | OpCode::Jump
                | OpCode::JumpIfFalse
                | OpCode::JumpIfTrue
                | OpCode::Call
                | OpCode::MatchRegex
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

// ── Instruction ─────────────────────────────────────────────────────────

/// A single instruction in the bytecode stream.
///
/// Each instruction pairs an opcode with an optional operand and source
/// mapping information (line number and originating rule name) for
//  diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to perform.
    pub opcode: OpCode,
    /// Optional operand — meaning depends on opcode.
    pub operand: Option<u32>,
    /// Source line number in the original YAML policy (1-based).
    pub line_number: u32,
    /// Name of the source rule that generated this instruction.
    pub source_rule: String,
}

impl Instruction {
    /// Create a new instruction with the given opcode and no operand.
    pub fn new(opcode: OpCode) -> Self {
        Self {
            opcode,
            operand: None,
            line_number: 0,
            source_rule: String::new(),
        }
    }

    /// Create a new instruction with an operand.
    pub fn with_operand(opcode: OpCode, operand: u32) -> Self {
        Self {
            opcode,
            operand: Some(operand),
            line_number: 0,
            source_rule: String::new(),
        }
    }

    /// Set the source mapping for this instruction.
    pub fn with_source(mut self, line: u32, rule: impl Into<String>) -> Self {
        self.line_number = line;
        self.source_rule = rule.into();
        self
    }

    /// Approximate size of this instruction when serialized.
    pub fn serialized_size(&self) -> usize {
        // 1 byte opcode + optional 4-byte operand
        if self.opcode.has_operand() {
            5
        } else {
            1
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(op) = self.operand {
            write!(f, "{:<12} {}", self.opcode.mnemonic(), op)?;
        } else {
            write!(f, "{:<12}", self.opcode.mnemonic())?;
        }
        if !self.source_rule.is_empty() {
            write!(f, "  ; {} (line {})", self.source_rule, self.line_number)?;
        }
        Ok(())
    }
}

// ── BytecodeProgram ────────────────────────────────────────────────────

/// A compiled policy bytecode program.
///
/// Contains the instruction stream, a constant pool for literals, the
/// entry point, and computed metadata such as max stack depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeProgram {
    /// Ordered sequence of instructions.
    pub instructions: Vec<Instruction>,
    /// Constants referenced by Push/PushStr/MatchRegex instructions.
    pub constant_pool: Vec<Constant>,
    /// Instruction index where execution begins (usually 0).
    pub entry_point: u32,
    /// Maximum stack depth needed for this program (computed by compiler).
    pub max_stack_size: u32,
    /// Total number of rules encoded in this program.
    pub rule_count: u32,
    /// Ordered list of variable names, where index = slot number.
    /// Used by the VM to map env keys to the correct slot positions.
    pub variable_slots: Vec<String>,
}

/// A constant value stored in the constant pool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Constant {
    Number(f64),
    String(String),
    Regex(String),
}

impl Constant {
    /// Returns the constant as a numeric value, or None.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Constant::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the constant as a string reference, or None.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Constant::String(s) | Constant::Regex(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constant::Number(n) => write!(f, "{}", n),
            Constant::String(s) => write!(f, "\"{}\"", s),
            Constant::Regex(s) => write!(f, "/{}/", s),
        }
    }
}

impl BytecodeProgram {
    /// Create an empty bytecode program.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            constant_pool: Vec::new(),
            entry_point: 0,
            max_stack_size: 16,
            rule_count: 0,
            variable_slots: Vec::new(),
        }
    }

    /// Add an instruction to the program, returning its index.
    pub fn emit(&mut self, instr: Instruction) -> u32 {
        let idx = self.instructions.len() as u32;
        self.instructions.push(instr);
        idx
    }

    /// Add a constant to the pool, returning its index.
    pub fn add_constant(&mut self, c: Constant) -> u32 {
        // Deduplicate constants to save space.
        if let Some(existing) = self.constant_pool.iter().position(|x| x == &c) {
            return existing as u32;
        }
        let idx = self.constant_pool.len() as u32;
        self.constant_pool.push(c);
        idx
    }

    /// Number of instructions in the program.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of constants in the constant pool.
    pub fn constant_count(&self) -> usize {
        self.constant_pool.len()
    }

    /// Reference to the constant pool.
    pub fn constants(&self) -> &[Constant] {
        &self.constant_pool
    }

    /// Approximate serialized size in bytes (excluding header).
    pub fn estimated_size(&self) -> usize {
        let instr_size: usize = self.instructions.iter().map(|i| i.serialized_size()).sum();
        let const_size: usize = self
            .constant_pool
            .iter()
            .map(|c| match c {
                Constant::Number(_) => 9, // type(1) + f64(8)
                Constant::String(s) => 1 + 4 + s.len(),
                Constant::Regex(s) => 1 + 4 + s.len(),
            })
            .sum();
        instr_size + const_size + 4 + 4 // entry_point + max_stack_size
    }

    /// Validate the bytecode program for structural integrity.
    pub fn validate(&self) -> Result<(), String> {
        if self.entry_point as usize >= self.instructions.len() {
            return Err(format!(
                "entry point {} exceeds instruction count {}",
                self.entry_point,
                self.instructions.len()
            ));
        }
        for (idx, instr) in self.instructions.iter().enumerate() {
            if instr.opcode.has_operand() {
                if instr.operand.is_none() {
                    return Err(format!(
                        "instruction {} ({}) requires an operand but has none",
                        idx, instr.opcode
                    ));
                }
            }
            // Check jump targets are in bounds.
            if matches!(
                instr.opcode,
                OpCode::Jump | OpCode::JumpIfFalse | OpCode::JumpIfTrue | OpCode::Call
            ) {
                if let Some(target) = instr.operand {
                    if target as usize >= self.instructions.len() {
                        return Err(format!(
                            "instruction {} ({}) jump target {} out of bounds (max {})",
                            idx,
                            instr.opcode,
                            target,
                            self.instructions.len()
                        ));
                    }
                }
            }
            // Check constant pool references are in bounds.
            if matches!(
                instr.opcode,
                OpCode::Push | OpCode::PushStr | OpCode::MatchRegex
            ) {
                if let Some(ci) = instr.operand {
                    if ci as usize >= self.constant_pool.len() {
                        return Err(format!(
                            "instruction {} ({}) constant index {} out of bounds (max {})",
                            idx,
                            instr.opcode,
                            ci,
                            self.constant_pool.len()
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Serialize the bytecode program to a binary byte vector.
    ///
    /// Binary format:
    ///   [5 bytes] magic "CVPOL"
    ///   [1 byte]  format version
    ///   [4 bytes] instruction count (u32 LE)
    ///   [4 bytes] constant pool count (u32 LE)
    ///   [4 bytes] entry point (u32 LE)
    ///   [4 bytes] max stack size (u32 LE)
    ///   [4 bytes] rule count (u32 LE)
    ///   [variable] instructions
    ///   [variable] constants
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + 1 + 24 + self.estimated_size());

        // Header.
        buf.extend_from_slice(MAGIC);
        buf.push(FORMAT_VERSION);

        // Counts.
        buf.extend_from_slice(&(self.instructions.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(self.constant_pool.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.entry_point.to_le_bytes());
        buf.extend_from_slice(&self.max_stack_size.to_le_bytes());
        buf.extend_from_slice(&self.rule_count.to_le_bytes());

        // Instructions.
        for instr in &self.instructions {
            buf.push(instr.opcode as u8);
            if instr.opcode.has_operand() {
                buf.extend_from_slice(&instr.operand.unwrap_or(0).to_le_bytes());
            }
        }

        // Constant pool.
        for constant in &self.constant_pool {
            match constant {
                Constant::Number(n) => {
                    buf.push(0); // type tag
                    buf.extend_from_slice(&n.to_le_bytes());
                }
                Constant::String(s) => {
                    buf.push(1); // type tag
                    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
                    buf.extend_from_slice(s.as_bytes());
                }
                Constant::Regex(s) => {
                    buf.push(2); // type tag
                    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
                    buf.extend_from_slice(s.as_bytes());
                }
            }
        }

        buf
    }

    /// Deserialize a bytecode program from binary bytes.
    ///
    /// Returns an error string on malformed input.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("data too short for magic header".into());
        }
        if &data[0..5] != MAGIC {
            return Err(format!(
                "invalid magic: expected {:?}, got {:?}",
                MAGIC,
                &data[0..5]
            ));
        }
        if data.len() < 6 {
            return Err("data too short for format version".into());
        }
        let version = data[5];
        if version != FORMAT_VERSION {
            return Err(format!(
                "unsupported format version {} (expected {})",
                version, FORMAT_VERSION
            ));
        }

        let mut offset = 6;
        let read_u32 = |data: &[u8], off: &mut usize| -> Result<u32, String> {
            if *off + 4 > data.len() {
                return Err("unexpected EOF reading u32".into());
            }
            let val = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
            *off += 4;
            Ok(val)
        };

        let instr_count = read_u32(data, &mut offset)? as usize;
        let const_count = read_u32(data, &mut offset)? as usize;
        let entry_point = read_u32(data, &mut offset)?;
        let max_stack_size = read_u32(data, &mut offset)?;
        let rule_count = read_u32(data, &mut offset)?;

        // Read instructions.
        let mut instructions = Vec::with_capacity(instr_count);
        for _ in 0..instr_count {
            if offset >= data.len() {
                return Err("unexpected EOF reading instruction".into());
            }
            let opcode = OpCode::from_byte(data[offset]);
            offset += 1;
            let operand = if opcode.has_operand() {
                let op = read_u32(data, &mut offset)?;
                Some(op)
            } else {
                None
            };
            instructions.push(Instruction {
                opcode,
                operand,
                line_number: 0,
                source_rule: String::new(),
            });
        }

        // Read constant pool.
        let mut constant_pool = Vec::with_capacity(const_count);
        for _ in 0..const_count {
            if offset >= data.len() {
                return Err("unexpected EOF reading constant tag".into());
            }
            let tag = data[offset];
            offset += 1;
            match tag {
                0 => {
                    // Number.
                    if offset + 8 > data.len() {
                        return Err("unexpected EOF reading number constant".into());
                    }
                    let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
                    let val = f64::from_le_bytes(bytes);
                    offset += 8;
                    constant_pool.push(Constant::Number(val));
                }
                1 | 2 => {
                    // String or Regex.
                    let len = read_u32(data, &mut offset)? as usize;
                    if offset + len > data.len() {
                        return Err("unexpected EOF reading string constant".into());
                    }
                    let s = String::from_utf8_lossy(&data[offset..offset + len]).into_owned();
                    offset += len;
                    if tag == 1 {
                        constant_pool.push(Constant::String(s));
                    } else {
                        constant_pool.push(Constant::Regex(s));
                    }
                }
                _ => return Err(format!("unknown constant tag {}", tag)),
            }
        }

        Ok(Self {
            instructions,
            constant_pool,
            entry_point,
            max_stack_size,
            rule_count,
            variable_slots: Vec::new(),
        })
    }

    /// Produce a disassembly listing (human-readable).
    pub fn disassemble(&self) -> String {
        let mut out = String::new();
        out.push_str("; Constant Pool\n");
        for (idx, c) in self.constant_pool.iter().enumerate() {
            out.push_str(&format!("  #{} = {}\n", idx, c));
        }
        out.push_str("; Instructions\n");
        for (idx, instr) in self.instructions.iter().enumerate() {
            out.push_str(&format!("  {:04}: {}\n", idx, instr));
        }
        out
    }
}

impl Default for BytecodeProgram {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_roundtrip_byte() {
        let opcodes = [
            OpCode::Push,
            OpCode::PushStr,
            OpCode::Load,
            OpCode::Store,
            OpCode::Add,
            OpCode::Sub,
            OpCode::Mul,
            OpCode::Div,
            OpCode::Mod,
            OpCode::Gt,
            OpCode::Lt,
            OpCode::Ge,
            OpCode::Le,
            OpCode::Eq,
            OpCode::Ne,
            OpCode::And,
            OpCode::Or,
            OpCode::Not,
            OpCode::Jump,
            OpCode::JumpIfFalse,
            OpCode::JumpIfTrue,
            OpCode::Call,
            OpCode::Return,
            OpCode::MatchRegex,
            OpCode::Contains,
            OpCode::StartsWith,
            OpCode::EndsWith,
            OpCode::RiskAdd,
            OpCode::RiskMul,
            OpCode::RiskMax,
            OpCode::Deny,
            OpCode::Allow,
            OpCode::Escalate,
            OpCode::Challenge,
            OpCode::Halt,
            OpCode::Nop,
        ];
        for op in &opcodes {
            let byte = *op as u8;
            let recovered = OpCode::from_byte(byte);
            assert_eq!(*op, recovered, "roundtrip failed for {:?}", op);
        }
    }

    #[test]
    fn opcode_unknown_byte_maps_to_nop() {
        assert_eq!(OpCode::from_byte(0xFE), OpCode::Nop);
        assert_eq!(OpCode::from_byte(0x05), OpCode::Nop);
    }

    #[test]
    fn opcode_mnemonic_display() {
        assert_eq!(OpCode::Add.mnemonic(), "ADD");
        assert_eq!(OpCode::JumpIfFalse.mnemonic(), "JMP_F");
        assert_eq!(format!("{}", OpCode::Halt), "HALT");
    }

    #[test]
    fn opcode_has_operand() {
        assert!(OpCode::Push.has_operand());
        assert!(OpCode::Jump.has_operand());
        assert!(!OpCode::Add.has_operand());
        assert!(!OpCode::Halt.has_operand());
        assert!(!OpCode::Nop.has_operand());
    }

    #[test]
    fn instruction_creation() {
        let i1 = Instruction::new(OpCode::Add);
        assert!(!i1.opcode.has_operand());
        assert!(i1.operand.is_none());

        let i2 = Instruction::with_operand(OpCode::Push, 3);
        assert_eq!(i2.operand, Some(3));

        let i3 = Instruction::with_operand(OpCode::Jump, 10).with_source(42, "rate_limit_rule");
        assert_eq!(i3.line_number, 42);
        assert_eq!(i3.source_rule, "rate_limit_rule");
    }

    #[test]
    fn instruction_display() {
        let i = Instruction::with_operand(OpCode::Push, 0).with_source(5, "test_rule");
        let s = format!("{}", i);
        assert!(s.contains("PUSH"));
        assert!(s.contains("test_rule"));
    }

    #[test]
    fn constant_accessors() {
        let num = Constant::Number(3.14);
        assert_eq!(num.as_number(), Some(3.14));
        assert!(num.as_str().is_none());

        let s = Constant::String("hello".into());
        assert!(s.as_number().is_none());
        assert_eq!(s.as_str(), Some("hello"));

        let r = Constant::Regex("[0-9]+".into());
        assert_eq!(r.as_str(), Some("[0-9]+"));
    }

    #[test]
    fn bytecode_program_emit() {
        let mut prog = BytecodeProgram::new();
        let c0 = prog.add_constant(Constant::Number(1.0));
        let c1 = prog.add_constant(Constant::Number(2.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::with_operand(OpCode::Push, c1));
        prog.emit(Instruction::new(OpCode::Add));
        prog.emit(Instruction::new(OpCode::Halt));
        assert_eq!(prog.instruction_count(), 4);
        assert_eq!(prog.constant_pool.len(), 2);
    }

    #[test]
    fn bytecode_program_dedup_constants() {
        let mut prog = BytecodeProgram::new();
        let i0 = prog.add_constant(Constant::String("hello".into()));
        let i1 = prog.add_constant(Constant::String("hello".into()));
        let i2 = prog.add_constant(Constant::String("world".into()));
        assert_eq!(i0, i1);
        assert_ne!(i0, i2);
        assert_eq!(prog.constant_pool.len(), 2);
    }

    #[test]
    fn bytecode_serialization_roundtrip() {
        let mut prog = BytecodeProgram::new();
        let c0 = prog.add_constant(Constant::Number(0.85));
        let c1 = prog.add_constant(Constant::String("injection".into()));
        let c2 = prog.add_constant(Constant::Regex(".*malware.*".into()));
        prog.emit(Instruction::with_operand(OpCode::Push, c0));
        prog.emit(Instruction::with_operand(OpCode::PushStr, c1));
        prog.emit(Instruction::new(OpCode::Eq));
        prog.emit(Instruction::with_operand(OpCode::JumpIfFalse, 0));
        prog.emit(Instruction::with_operand(OpCode::MatchRegex, c2));
        prog.emit(Instruction::new(OpCode::Halt));
        prog.rule_count = 3;
        prog.max_stack_size = 32;

        let bytes = prog.to_bytes();
        assert!(bytes.len() >= 5 + 1 + 24);
        assert_eq!(&bytes[0..5], MAGIC);

        let recovered = BytecodeProgram::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.instructions.len(), 6);
        assert_eq!(recovered.constant_pool.len(), 3);
        assert_eq!(recovered.rule_count, 3);
        assert_eq!(recovered.max_stack_size, 32);

        // Verify magic correctness of opcodes.
        for (orig, recov) in prog.instructions.iter().zip(recovered.instructions.iter()) {
            assert_eq!(orig.opcode, recov.opcode);
            assert_eq!(orig.operand, recov.operand);
        }
    }

    #[test]
    fn bytecode_deserialize_bad_magic() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let result = BytecodeProgram::from_bytes(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid magic"));
    }

    #[test]
    fn bytecode_deserialize_short_data() {
        let result = BytecodeProgram::from_bytes(&[0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn bytecode_deserialize_wrong_version() {
        let mut data = MAGIC.to_vec();
        data.push(99); // wrong version
        let result = BytecodeProgram::from_bytes(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported format version"));
    }

    #[test]
    fn bytecode_validate_success() {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(1.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c));
        prog.emit(Instruction::new(OpCode::Halt));
        assert!(prog.validate().is_ok());
    }

    #[test]
    fn bytecode_validate_missing_operand() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::new(OpCode::Push)); // Push requires operand
        prog.emit(Instruction::new(OpCode::Halt));
        let result = prog.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires an operand"));
    }

    #[test]
    fn bytecode_validate_jump_out_of_bounds() {
        let mut prog = BytecodeProgram::new();
        prog.emit(Instruction::with_operand(OpCode::Jump, 999));
        prog.emit(Instruction::new(OpCode::Halt));
        let result = prog.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }

    #[test]
    fn bytecode_validate_entry_point() {
        let prog = BytecodeProgram {
            instructions: vec![Instruction::new(OpCode::Halt)],
            constant_pool: vec![],
            entry_point: 5,
            max_stack_size: 16,
            rule_count: 0,
            variable_slots: vec![],
        };
        let result = prog.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("entry point"));
    }

    #[test]
    fn disassemble_output() {
        let mut prog = BytecodeProgram::new();
        let c = prog.add_constant(Constant::Number(42.0));
        prog.emit(Instruction::with_operand(OpCode::Push, c).with_source(1, "rule_1"));
        prog.emit(Instruction::new(OpCode::Halt));
        let listing = prog.disassemble();
        assert!(listing.contains("Constant Pool"));
        assert!(listing.contains("Instructions"));
        assert!(listing.contains("PUSH"));
        assert!(listing.contains("rule_1"));
    }
}
