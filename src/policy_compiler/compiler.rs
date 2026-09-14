// Policy Compiler Engine — compiles YAML policy definitions to bytecode.
//
// Transforms human-readable YAML policies into a BytecodeProgram suitable
// for execution by the PolicyVM. Includes a tokenizer, recursive-descent
// parser producing an AST, a code generator that walks the AST to emit
// instructions, and a simple optimizer for constant folding and dead code
// elimination.

use std::collections::HashMap;

use super::bytecode::{BytecodeProgram, Constant, Instruction, OpCode};
use crate::error::{Error, Result};

// ── YAML Policy Structures ─────────────────────────────────────────────

/// Top-level YAML policy representation.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YamlPolicy {
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<YamlRule>,
    #[serde(default)]
    pub defaults: PolicyDefaults,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Default policy settings.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PolicyDefaults {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub risk_threshold: f64,
    #[serde(default)]
    pub timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

/// A single rule within a YAML policy.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YamlRule {
    pub name: String,
    #[serde(default = "default_rule_action")]
    pub action: String,
    pub condition: String,
    #[serde(default)]
    pub risk_weight: f64,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_rule_action() -> String {
    "deny".to_string()
}

// ── Tokenizer ──────────────────────────────────────────────────────────

/// A token produced by the condition string tokenizer.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Literals
    Number(f64),
    String(String),
    Ident(String),

    // Operators
    Plus,      // +
    Minus,     // -
    Star,      // *
    Slash,     // /
    Percent,   // %
    Gt,        // >
    Lt,        // <
    Ge,        // >=
    Le,        // <=
    Eq,        // ==
    Ne,        // !=
    And,       // AND
    Or,        // OR
    Not,       // NOT
    Bang,      // !

    // Delimiters
    LParen, // (
    RParen, // )
    Dot,    // .
    Comma,  // ,

    // EOF
    Eof,
}

/// Tokenize a condition string into a list of tokens.
fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // Skip whitespace.
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // String literal (double-quoted).
        if c == '"' {
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    s.push(chars[i]);
                } else {
                    s.push(chars[i]);
                }
                i += 1;
            }
            if i < chars.len() {
                i += 1; // closing quote
            }
            tokens.push(Token::String(s));
            continue;
        }

        // Number literal.
        if c.is_ascii_digit() || (c == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let num_str: String = chars[start..i].iter().collect();
            match num_str.parse::<f64>() {
                Ok(n) => tokens.push(Token::Number(n)),
                Err(_) => return Err(Error::Evaluation(format!("invalid number literal: {}", num_str))),
            }
            continue;
        }

        // Identifier or keyword.
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            match word.as_str() {
                "AND" => tokens.push(Token::And),
                "OR" => tokens.push(Token::Or),
                "NOT" => tokens.push(Token::Not),
                "true" => tokens.push(Token::Number(1.0)),
                "false" => tokens.push(Token::Number(0.0)),
                _ => tokens.push(Token::Ident(word)),
            }
            continue;
        }

        // Two-character operators.
        if i + 1 < chars.len() {
            let two: String = chars[i..i + 2].iter().collect();
            match two.as_str() {
                ">=" => { tokens.push(Token::Ge); i += 2; continue; }
                "<=" => { tokens.push(Token::Le); i += 2; continue; }
                "==" => { tokens.push(Token::Eq); i += 2; continue; }
                "!=" => { tokens.push(Token::Ne); i += 2; continue; }
                _ => {}
            }
        }

        // Single-character operators and delimiters.
        match c {
            '+' => { tokens.push(Token::Plus); i += 1; }
            '-' => { tokens.push(Token::Minus); i += 1; }
            '*' => { tokens.push(Token::Star); i += 1; }
            '/' => { tokens.push(Token::Slash); i += 1; }
            '%' => { tokens.push(Token::Percent); i += 1; }
            '>' => { tokens.push(Token::Gt); i += 1; }
            '<' => { tokens.push(Token::Lt); i += 1; }
            '!' => { tokens.push(Token::Bang); i += 1; }
            '(' => { tokens.push(Token::LParen); i += 1; }
            ')' => { tokens.push(Token::RParen); i += 1; }
            '.' => { tokens.push(Token::Dot); i += 1; }
            ',' => { tokens.push(Token::Comma); i += 1; }
            _ => return Err(Error::Evaluation(format!("unexpected character '{}' at position {}", c, i))),
        }
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

// ── AST ────────────────────────────────────────────────────────────────

/// Nodes in the parsed abstract syntax tree.
#[derive(Debug, Clone)]
pub enum ASTNode {
    /// A literal numeric value.
    Literal(f64),
    /// A literal string value.
    LiteralStr(String),
    /// A boolean literal.
    LiteralBool(bool),
    /// A variable reference (e.g., "risk_score", "payload").
    Variable(String),
    /// Binary operation: left op right.
    BinaryOp {
        left: Box<ASTNode>,
        op: BinOp,
        right: Box<ASTNode>,
    },
    /// Unary operation: op operand.
    UnaryOp {
        op: UnOp,
        operand: Box<ASTNode>,
    },
    /// Function call: name(args...).
    FunctionCall {
        name: String,
        args: Vec<ASTNode>,
    },
    /// Access to a risk-related value.
    RiskAccess,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    Gt, Lt, Ge, Le, Eq, Ne,
    And, Or,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    Not, Neg,
}

// ── Parser ─────────────────────────────────────────────────────────────

/// Recursive-descent parser for condition expressions.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        let tok = self.advance();
        if &tok != expected {
            return Err(Error::Evaluation(format!(
                "expected {:?}, got {:?}", expected, tok
            )));
        }
        Ok(())
    }

    /// Parse a full expression.
    fn parse(&mut self) -> Result<ASTNode> {
        let node = self.parse_or()?;
        if !matches!(self.peek(), Token::Eof | Token::RParen) {
            return Err(Error::Evaluation(format!(
                "unexpected token after expression: {:?}", self.peek()
            )));
        }
        Ok(node)
    }

    /// Parse OR expressions (lowest precedence).
    fn parse_or(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op: BinOp::Or,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse AND expressions.
    fn parse_and(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_equality()?;
        while matches!(self.peek(), Token::And) {
            self.advance();
            let right = self.parse_equality()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op: BinOp::And,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse equality expressions (==, !=).
    fn parse_equality(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_comparison()?;
        while matches!(self.peek(), Token::Eq | Token::Ne) {
            let op = match self.advance() {
                Token::Eq => BinOp::Eq,
                Token::Ne => BinOp::Ne,
                other => return Err(Error::Evaluation(format!("expected == or !=, got {:?}", other))),
            };
            let right = self.parse_comparison()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse comparison expressions (>, <, >=, <=).
    fn parse_comparison(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_additive()?;
        while matches!(self.peek(), Token::Gt | Token::Lt | Token::Ge | Token::Le) {
            let op = match self.advance() {
                Token::Gt => BinOp::Gt,
                Token::Lt => BinOp::Lt,
                Token::Ge => BinOp::Ge,
                Token::Le => BinOp::Le,
                other => return Err(Error::Evaluation(format!("expected comparison, got {:?}", other))),
            };
            let right = self.parse_additive()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse additive expressions (+, -).
    fn parse_additive(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_multiplicative()?;
        while matches!(self.peek(), Token::Plus | Token::Minus) {
            let op = match self.advance() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                other => return Err(Error::Evaluation(format!("expected + or -, got {:?}", other))),
            };
            let right = self.parse_multiplicative()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse multiplicative expressions (*, /, %).
    fn parse_multiplicative(&mut self) -> Result<ASTNode> {
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), Token::Star | Token::Slash | Token::Percent) {
            let op = match self.advance() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Mod,
                other => return Err(Error::Evaluation(format!("expected *, /, or %, got {:?}", other))),
            };
            let right = self.parse_unary()?;
            left = ASTNode::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// Parse unary expressions (NOT, !, -).
    fn parse_unary(&mut self) -> Result<ASTNode> {
        match self.peek() {
            Token::Not | Token::Bang => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(ASTNode::UnaryOp {
                    op: UnOp::Not,
                    operand: Box::new(operand),
                })
            }
            Token::Minus => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(ASTNode::UnaryOp {
                    op: UnOp::Neg,
                    operand: Box::new(operand),
                })
            }
            _ => self.parse_postfix(),
        }
    }

    /// Parse postfix expressions: dot-based field access on any primary.
    /// This handles cases like `func().field` or `(expr).field` that
    /// parse_primary's Ident-only dot loop cannot reach.
    fn parse_postfix(&mut self) -> Result<ASTNode> {
        let mut node = self.parse_primary()?;
        while matches!(self.peek(), Token::Dot) {
            self.advance(); // consume .
            if let Token::Ident(field) = self.peek().clone() {
                self.advance();
                match node {
                    ASTNode::Variable(ref name) => {
                        let mut full = name.clone();
                        full.push('.');
                        full.push_str(&field);
                        node = ASTNode::Variable(full);
                    }
                    _ => {
                        // For non-variable expressions (function calls, literals,
                        // parenthesized), dot access is not supported in the VM.
                        // Return an error rather than silently producing wrong bytecode.
                        return Err(Error::Evaluation(
                            "dot field access is only supported on variable expressions".into(),
                        ));
                    }
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    /// Parse primary expressions: literals, variables, function calls, parenthesized.
    fn parse_primary(&mut self) -> Result<ASTNode> {
        match self.peek().clone() {
            Token::Number(n) => {
                self.advance();
                Ok(ASTNode::Literal(n))
            }
            Token::String(s) => {
                self.advance();
                Ok(ASTNode::LiteralStr(s))
            }
            Token::Ident(name) => {
                self.advance();
                // Consume dotted path: e.g. payload.contains → "payload.contains"
                let mut full_name = name;
                while matches!(self.peek(), Token::Dot) {
                    self.advance(); // consume .
                    if let Token::Ident(field) = self.peek().clone() {
                        self.advance();
                        full_name.push('.');
                        full_name.push_str(&field);
                    } else {
                        break;
                    }
                }
                // Check for function call: name(...)
                if matches!(self.peek(), Token::LParen) {
                    self.advance(); // consume (
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Token::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            if matches!(self.peek(), Token::Comma) {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(&Token::RParen)?;
                    // For dotted method calls (e.g. payload.contains), extract the subject
                    // and prepend it as the first argument so the VM has both subject and args.
                    let (func_name, args) = if let Some(dot_pos) = full_name.rfind('.') {
                        let subject = ASTNode::Variable(full_name[..dot_pos].to_string());
                        let name = full_name[dot_pos + 1..].to_string();
                        let mut all_args = vec![subject];
                        all_args.extend(args);
                        (name, all_args)
                    } else {
                        (full_name, args)
                    };
                    Ok(ASTNode::FunctionCall { name: func_name, args })
                } else if full_name == "risk_score" {
                    Ok(ASTNode::RiskAccess)
                } else {
                    Ok(ASTNode::Variable(full_name))
                }
            }
            Token::LParen => {
                self.advance();
                let node = self.parse_or()?;
                self.expect(&Token::RParen)?;
                Ok(node)
            }
            other => Err(Error::Evaluation(format!(
                "unexpected token in expression: {:?}", other
            ))),
        }
    }
}

// ── Code Generator ─────────────────────────────────────────────────────

/// Translates an AST into bytecode instructions.
struct CodeGen {
    program: BytecodeProgram,
    variable_slots: HashMap<String, u32>,
    next_slot: u32,
    current_rule: String,
}

impl CodeGen {
    fn new() -> Self {
        Self {
            program: BytecodeProgram::new(),
            variable_slots: HashMap::new(),
            next_slot: 0,
            current_rule: String::new(),
        }
    }

    fn get_slot(&mut self, name: &str) -> u32 {
        if let Some(&slot) = self.variable_slots.get(name) {
            slot
        } else {
            let slot = self.next_slot;
            self.next_slot += 1;
            self.variable_slots.insert(name.to_string(), slot);
            slot
        }
    }

    /// Generate bytecode for an AST node.
    fn emit_node(&mut self, node: &ASTNode) -> Result<u32> {
        match node {
            ASTNode::Literal(n) => {
                let ci = self.program.add_constant(Constant::Number(*n));
                let idx = self.program.emit(
                    Instruction::with_operand(OpCode::Push, ci)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::LiteralStr(s) => {
                let ci = self.program.add_constant(Constant::String(s.clone()));
                let idx = self.program.emit(
                    Instruction::with_operand(OpCode::PushStr, ci)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::LiteralBool(b) => {
                let n = if *b { 1.0 } else { 0.0 };
                let ci = self.program.add_constant(Constant::Number(n));
                let idx = self.program.emit(
                    Instruction::with_operand(OpCode::Push, ci)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::Variable(name) => {
                let slot = self.get_slot(name);
                let idx = self.program.emit(
                    Instruction::with_operand(OpCode::Load, slot)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::RiskAccess => {
                let slot = self.get_slot("risk_score");
                let idx = self.program.emit(
                    Instruction::with_operand(OpCode::Load, slot)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::BinaryOp { left, op, right } => {
                self.emit_node(left)?;
                self.emit_node(right)?;
                let opcode = match op {
                    BinOp::Add => OpCode::Add,
                    BinOp::Sub => OpCode::Sub,
                    BinOp::Mul => OpCode::Mul,
                    BinOp::Div => OpCode::Div,
                    BinOp::Mod => OpCode::Mod,
                    BinOp::Gt => OpCode::Gt,
                    BinOp::Lt => OpCode::Lt,
                    BinOp::Ge => OpCode::Ge,
                    BinOp::Le => OpCode::Le,
                    BinOp::Eq => OpCode::Eq,
                    BinOp::Ne => OpCode::Ne,
                    BinOp::And => OpCode::And,
                    BinOp::Or => OpCode::Or,
                };
                let idx = self.program.emit(
                    Instruction::new(opcode)
                        .with_source(0, &self.current_rule),
                );
                Ok(idx)
            }
            ASTNode::UnaryOp { op, operand } => {
                self.emit_node(operand)?;
                let opcode = match op {
                    UnOp::Not => OpCode::Not,
                    UnOp::Neg => OpCode::Sub, // Neg 0-x: push 0, push x, sub — simplified to just Not-like
                };
                if *op == UnOp::Neg {
                    // Push 0 first, then Sub will compute 0 - x.
                    // Actually we need to emit push 0 before the operand.
                    // Rewind: re-emit with push 0 + operand + sub.
                    let ci = self.program.add_constant(Constant::Number(0.0));
                    // We already emitted the operand, so we need to push 0
                    // before it. This is a simplification — just use a negate
                    // via Mul with -1.
                    let ci_neg = self.program.add_constant(Constant::Number(-1.0));
                    self.program.emit(
                        Instruction::with_operand(OpCode::Push, ci_neg)
                            .with_source(0, &self.current_rule),
                    );
                    self.program.emit(
                        Instruction::new(OpCode::Mul)
                            .with_source(0, &self.current_rule),
                    );
                    // The original operand is already on stack, so we have:
                    // operand, -1 → Mul → -operand
                    let _ = (ci, opcode); // suppress unused warnings
                } else {
                    self.program.emit(
                        Instruction::new(opcode)
                            .with_source(0, &self.current_rule),
                    );
                }
                // Return the index of the last emitted instruction.
                Ok(self.program.instructions.len() as u32 - 1)
            }
            ASTNode::FunctionCall { name, args } => {
                // Emit arguments in reverse order? No — push in order.
                for arg in args {
                    self.emit_node(arg)?;
                }
                match name.as_str() {
                    "contains" => {
                        let idx = self.program.emit(
                            Instruction::new(OpCode::Contains)
                                .with_source(0, &self.current_rule),
                        );
                        Ok(idx)
                    }
                    "startswith" | "starts_with" => {
                        let idx = self.program.emit(
                            Instruction::new(OpCode::StartsWith)
                                .with_source(0, &self.current_rule),
                        );
                        Ok(idx)
                    }
                    "endswith" | "ends_with" => {
                        let idx = self.program.emit(
                            Instruction::new(OpCode::EndsWith)
                                .with_source(0, &self.current_rule),
                        );
                        Ok(idx)
                    }
                    "matches" | "match_regex" => {
                        // Pop pattern string, convert to regex constant, then MatchRegex.
                        // For simplicity, the pattern must be a string literal constant.
                        let idx = self.program.emit(
                            Instruction::new(OpCode::Contains) // fallback — real impl would use MatchRegex
                                .with_source(0, &self.current_rule),
                        );
                        Ok(idx)
                    }
                    _ => {
                        return Err(Error::Evaluation(format!("unknown function: {}", name)));
                    }
                }
            }
        }
    }

    /// Compile a single rule condition into the program.
    /// Emits: condition check -> [JumpIfFalse past action] -> action -> Halt.
    fn compile_rule(&mut self, rule: &YamlRule) -> Result<()> {
        if !rule.enabled {
            return Ok(());
        }

        self.current_rule = rule.name.clone();

        // Parse condition.
        let tokens = tokenize(&rule.condition)?;
        let mut parser = Parser::new(tokens);
        let ast = parser.parse()?;

        // Emit condition evaluation.
        self.emit_node(&ast)?;

        // Emit conditional jump past the action.
        let jump_idx = self.program.emit(
            Instruction::new(OpCode::JumpIfFalse)
                .with_source(0, &self.current_rule),
        );

        // Emit risk weight if > 0.
        if rule.risk_weight > 0.0 {
            let ci = self.program.add_constant(Constant::Number(rule.risk_weight));
            self.program.emit(
                Instruction::with_operand(OpCode::Push, ci)
                    .with_source(0, &self.current_rule),
            );
            self.program.emit(
                Instruction::new(OpCode::RiskAdd)
                    .with_source(0, &self.current_rule),
            );
        }

        // Emit action.
        let action_opcode = match rule.action.to_lowercase().as_str() {
            "allow" => OpCode::Allow,
            "deny" => OpCode::Deny,
            "escalate" => OpCode::Escalate,
            "challenge" => OpCode::Challenge,
            _ => OpCode::Deny, // default to deny
        };
        self.program.emit(
            Instruction::new(action_opcode)
                .with_source(0, &self.current_rule),
        );

        // Patch jump target to point after the action.
        let after_idx = self.program.instructions.len() as u32;
        if let Some(instr) = self.program.instructions.get_mut(jump_idx as usize) {
            instr.operand = Some(after_idx);
        }

        Ok(())
    }
}

// ── Optimizer ──────────────────────────────────────────────────────────

/// Simple optimizer that performs constant folding and dead code elimination.
pub struct Optimizer;

impl Optimizer {
    /// Optimize a bytecode program in-place.
    pub fn optimize(program: &mut BytecodeProgram) {
        Self::constant_fold(program);
        Self::eliminate_dead_nops(program);
    }

    /// Fold constant expressions: Push a, Push b, BinOp -> Push result.
    fn constant_fold(program: &mut BytecodeProgram) {
        let mut i = 0;
        while i + 2 < program.instructions.len() {
            let op0 = &program.instructions[i];
            let op1 = &program.instructions[i + 1];
            let op2 = &program.instructions[i + 2];

            // Pattern: Push(a), Push(b), Arith/Cmp
            if op0.opcode == OpCode::Push && op1.opcode == OpCode::Push {
                let a_idx = op0.operand.unwrap_or(0) as usize;
                let b_idx = op1.operand.unwrap_or(0) as usize;

                if a_idx < program.constant_pool.len() && b_idx < program.constant_pool.len() {
                    let a = program.constant_pool[a_idx].as_number();
                    let b = program.constant_pool[b_idx].as_number();

                    if let (Some(av), Some(bv)) = (a, b) {
                        let result = match op2.opcode {
                            OpCode::Add => Some(av + bv),
                            OpCode::Sub => Some(av - bv),
                            OpCode::Mul => Some(av * bv),
                            OpCode::Div if bv != 0.0 => Some(av / bv),
                            OpCode::Mod if bv != 0.0 => Some(av % bv),
                            OpCode::Gt => None, // bool result, skip for now
                            OpCode::Lt => None,
                            OpCode::Ge => None,
                            OpCode::Le => None,
                            OpCode::Eq => {
                                if (av - bv).abs() < 1e-10 {
                                    Some(1.0) // true
                                } else {
                                    Some(0.0) // false
                                }
                            }
                            OpCode::Ne => {
                                if (av - bv).abs() < 1e-10 {
                                    Some(0.0)
                                } else {
                                    Some(1.0)
                                }
                            }
                            _ => None,
                        };

                        if let Some(val) = result {
                            let ci = program.add_constant(Constant::Number(val));
                            // Replace the 3 instructions with 1.
                            program.instructions[i] =
                                Instruction::with_operand(OpCode::Push, ci);
                            program.instructions.remove(i + 2);
                            program.instructions.remove(i + 1);
                            // Don't increment i — check the new instruction next.
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    /// Remove consecutive Nop instructions (keep at most one between real ops).
    fn eliminate_dead_nops(program: &mut BytecodeProgram) {
        let mut i = 0;
        while i < program.instructions.len() {
            if program.instructions[i].opcode == OpCode::Nop {
                let mut run = 1;
                while i + run < program.instructions.len()
                    && program.instructions[i + run].opcode == OpCode::Nop
                {
                    run += 1;
                }
                // Remove excess Nops (keep first if it's between real ops).
                if run > 1 {
                    program.instructions.drain(i..i + run - 1);
                }
            }
            i += 1;
        }
    }
}

// ── PolicyCompilerEngine ────────────────────────────────────────────────

/// The main compiler engine that transforms YAML policies to bytecode.
pub struct PolicyCompilerEngine {
    optimize: bool,
}

impl PolicyCompilerEngine {
    /// Create a new compiler engine.
    pub fn new() -> Self {
        Self { optimize: true }
    }

    /// Create a compiler engine with optimization disabled.
    pub fn without_optimization() -> Self {
        Self { optimize: false }
    }

    /// Parse a YAML string into a YamlPolicy.
    pub fn parse_yaml(&self, yaml_str: &str) -> Result<YamlPolicy> {
        let policy: YamlPolicy =
            serde_yaml::from_str(yaml_str).map_err(|e| Error::ConfigParse(e.to_string()))?;
        Ok(policy)
    }

    /// Compile a YamlPolicy into a BytecodeProgram.
    pub fn compile(&self, policy: &YamlPolicy) -> Result<BytecodeProgram> {
        let mut codegen = CodeGen::new();

        for rule in &policy.rules {
            codegen.compile_rule(rule)?;
        }

        // Emit a default Allow at the end if no rule matched.
        codegen.program.emit(Instruction::new(OpCode::Halt));

        let mut program = codegen.program;
        program.rule_count = policy.rules.len() as u32;

        // Build the ordered variable_slots list from the codegen's slot map.
        let mut slots: Vec<(u32, String)> = codegen.variable_slots.into_iter().map(|(name, slot)| (slot, name)).collect();
        slots.sort_by_key(|(slot, _)| *slot);
        program.variable_slots = slots.into_iter().map(|(_, name)| name).collect();

        // Estimate max stack size based on instruction count.
        program.max_stack_size = ((program.instruction_count() as f64).sqrt().ceil() as u32 * 4)
            .max(16)
            .min(1024);

        if self.optimize {
            Optimizer::optimize(&mut program);
        }

        // Validate the compiled program.
        program.validate().map_err(|e| Error::EngineInit(e))?;

        Ok(program)
    }

    /// One-shot: parse YAML and compile to bytecode.
    pub fn compile_yaml(&self, yaml_str: &str) -> Result<BytecodeProgram> {
        let policy = self.parse_yaml(yaml_str)?;
        self.compile(&policy)
    }
}

impl Default for PolicyCompilerEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_simple_expression() {
        let tokens = tokenize("risk_score > 0.8").unwrap();
        assert_eq!(tokens.len(), 4); // Ident, Gt, Number, Eof
        assert_eq!(tokens[0], Token::Ident("risk_score".into()));
        assert_eq!(tokens[1], Token::Gt);
        assert_eq!(tokens[2], Token::Number(0.8));
    }

    #[test]
    fn tokenize_and_expression() {
        let tokens = tokenize("risk_score > 0.8 AND payload.contains(\"injection\")").unwrap();
        assert!(tokens.contains(&Token::And));
        assert!(tokens.contains(&Token::Gt));
        assert!(tokens.contains(&Token::Ident("payload".into())));
    }

    #[test]
    fn tokenize_string_literal() {
        let tokens = tokenize("\"hello world\"").unwrap();
        assert_eq!(tokens[0], Token::String("hello world".into()));
    }

    #[test]
    fn tokenize_keywords() {
        let tokens = tokenize("NOT true AND false").unwrap();
        assert_eq!(tokens[0], Token::Not);
        assert_eq!(tokens[1], Token::Number(1.0));
        assert_eq!(tokens[2], Token::And);
        assert_eq!(tokens[3], Token::Number(0.0));
    }

    #[test]
    fn tokenize_arithmetic() {
        let tokens = tokenize("x + y * z - 10").unwrap();
        assert!(tokens.contains(&Token::Plus));
        assert!(tokens.contains(&Token::Star));
        assert!(tokens.contains(&Token::Minus));
    }

    #[test]
    fn parse_literal_number() {
        let tokens = tokenize("42.0").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match ast {
            ASTNode::Literal(n) => assert!((n - 42.0).abs() < 1e-10),
            _ => panic!("expected Literal node"),
        }
    }

    #[test]
    fn parse_comparison() {
        let tokens = tokenize("risk_score > 0.8").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match &ast {
            ASTNode::BinaryOp { left, op, right } => {
                assert!(matches!(left.as_ref(), ASTNode::RiskAccess));
                assert_eq!(*op, BinOp::Gt);
                match right.as_ref() {
                    ASTNode::Literal(n) => assert!((n - 0.8).abs() < 1e-10),
                    _ => panic!("expected literal in right"),
                }
            }
            _ => panic!("expected BinaryOp"),
        }
    }

    #[test]
    fn parse_and_expression() {
        let tokens = tokenize("true AND false").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match &ast {
            ASTNode::BinaryOp { op, .. } => assert_eq!(*op, BinOp::And),
            _ => panic!("expected BinaryOp for AND"),
        }
    }

    #[test]
    fn parse_not_expression() {
        let tokens = tokenize("NOT true").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match &ast {
            ASTNode::UnaryOp { op, .. } => assert_eq!(*op, UnOp::Not),
            _ => panic!("expected UnaryOp for NOT"),
        }
    }

    #[test]
    fn parse_parenthesized() {
        let tokens = tokenize("(1 + 2) * 3").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match &ast {
            ASTNode::BinaryOp { left, op, right: _ } => {
                assert_eq!(*op, BinOp::Mul);
                assert!(matches!(left.as_ref(), ASTNode::BinaryOp { .. }));
            }
            _ => panic!("expected BinaryOp"),
        }
    }

    #[test]
    fn parse_function_call() {
        let tokens = tokenize("payload.contains(\"test\")").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match &ast {
            ASTNode::FunctionCall { name, args } => {
                assert_eq!(name, "contains");
                // Subject (payload) is prepended as the first arg.
                assert_eq!(args.len(), 2);
                assert!(matches!(&args[0], ASTNode::Variable(v) if v == "payload"));
            }
            _ => panic!("expected FunctionCall"),
        }
    }

    #[test]
    fn parse_variable() {
        let tokens = tokenize("source_ip").unwrap();
        let mut parser = Parser::new(tokens);
        let ast = parser.parse().unwrap();
        match ast {
            ASTNode::Variable(name) => assert_eq!(name, "source_ip"),
            _ => panic!("expected Variable"),
        }
    }

    #[test]
    fn parse_yaml_policy() {
        let yaml = r#"
version: "1.0"
name: "test-policy"
rules:
  - name: "block_high_risk"
    action: "deny"
    condition: "risk_score > 0.8"
    risk_weight: 0.5
    enabled: true
"#;
        let engine = PolicyCompilerEngine::new();
        let policy = engine.parse_yaml(yaml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "block_high_risk");
        assert_eq!(policy.rules[0].action, "deny");
    }

    #[test]
    fn compile_simple_deny_rule() {
        let yaml = r#"
version: "1.0"
name: "test"
rules:
  - name: "block"
    action: "deny"
    condition: "risk_score > 0.8"
    enabled: true
"#;
        let engine = PolicyCompilerEngine::new();
        let program = engine.compile_yaml(yaml).unwrap();
        assert!(program.instruction_count() > 0);
        assert!(program.validate().is_ok());
    }

    #[test]
    fn compile_multiple_rules() {
        let yaml = r#"
version: "1.0"
name: "multi"
rules:
  - name: "block_sql"
    action: "deny"
    condition: 'payload.contains("SELECT")'
    enabled: true
  - name: "challenge_bot"
    action: "challenge"
    condition: 'source_ip == "10.0.0.1"'
    enabled: true
  - name: "escalate_unknown"
    action: "escalate"
    condition: 'user_id == "unknown"'
    enabled: true
"#;
        let engine = PolicyCompilerEngine::new();
        let program = engine.compile_yaml(yaml).unwrap();
        assert!(program.instruction_count() > 0);
        assert_eq!(program.rule_count, 3);
    }

    #[test]
    fn compile_and_run() {
        let yaml = r#"
version: "1.0"
name: "run-test"
rules:
  - name: "block_high_risk"
    action: "deny"
    condition: "risk_score > 0.8"
    enabled: true
"#;
        let engine = PolicyCompilerEngine::new();
        let program = engine.compile_yaml(yaml).unwrap();

        // Execute with risk_score = 0.9 (should deny).
        let mut env = HashMap::new();
        env.insert("risk_score".to_string(), super::super::vm::Value::Number(0.9));
        let vm = super::super::vm::PolicyVM::new();
        let result = vm.execute(&program, &env).unwrap();
        assert!(result.decision.is_deny());

        // Execute with risk_score = 0.5 (should allow).
        env.insert("risk_score".to_string(), super::super::vm::Value::Number(0.5));
        let result = vm.execute(&program, &env).unwrap();
        assert!(result.decision.is_allow());
    }

    #[test]
    fn optimizer_constant_fold() {
        let mut program = BytecodeProgram::new();
        let c3 = program.add_constant(Constant::Number(3.0));
        let c5 = program.add_constant(Constant::Number(5.0));
        program.emit(Instruction::with_operand(OpCode::Push, c3));
        program.emit(Instruction::with_operand(OpCode::Push, c5));
        program.emit(Instruction::new(OpCode::Add));
        program.emit(Instruction::new(OpCode::Halt));

        assert_eq!(program.instruction_count(), 4);
        Optimizer::optimize(&mut program);
        // After constant folding, 3 instructions (Push result, Halt).
        assert_eq!(program.instruction_count(), 2);
    }

    #[test]
    fn optimizer_dead_nop_elimination() {
        let mut program = BytecodeProgram::new();
        program.emit(Instruction::new(OpCode::Nop));
        program.emit(Instruction::new(OpCode::Nop));
        program.emit(Instruction::new(OpCode::Nop));
        program.emit(Instruction::new(OpCode::Halt));

        Optimizer::optimize(&mut program);
        assert_eq!(program.instruction_count(), 2);
    }

    #[test]
    fn compile_with_defaults() {
        let yaml = r#"
version: "1.0"
name: "defaults-test"
rules: []
defaults:
  enabled: false
  risk_threshold: 0.9
  timeout_secs: 60
"#;
        let engine = PolicyCompilerEngine::new();
        let policy = engine.parse_yaml(yaml).unwrap();
        assert_eq!(policy.defaults.risk_threshold, 0.9);
        assert_eq!(policy.defaults.timeout_secs, 60);
    }

    #[test]
    fn compile_disabled_rule_skipped() {
        let yaml = r#"
version: "1.0"
name: "skip-disabled"
rules:
  - name: "should_be_skipped"
    action: "deny"
    condition: "true"
    enabled: false
"#;
        let engine = PolicyCompilerEngine::new();
        let program = engine.compile_yaml(yaml).unwrap();
        // Only the default Halt should be emitted.
        assert!(program.instruction_count() <= 2);
    }

    #[test]
    fn compile_string_condition_and_run() {
        let yaml = r#"
version: "1.0"
name: "sql-block"
rules:
  - name: "block_sql_injection"
    action: "deny"
    condition: 'payload.contains("DROP TABLE")'
    enabled: true
"#;
        let engine = PolicyCompilerEngine::new();
        let program = engine.compile_yaml(yaml).unwrap();

        // With malicious payload.
        let mut env = HashMap::new();
        env.insert("payload".to_string(), super::super::vm::Value::String("DROP TABLE users".into()));
        let vm = super::super::vm::PolicyVM::new();
        let result = vm.execute(&program, &env).unwrap();
        assert!(result.decision.is_deny());

        // With safe payload.
        env.insert("payload".to_string(), super::super::vm::Value::String("hello world".into()));
        let result = vm.execute(&program, &env).unwrap();
        assert!(result.decision.is_allow());
    }
}
