// ANANTA Orchestration Validator — Constraint Solving & Policy Validation
//
// Validates full security orchestration plans against a constraint satisfaction
// framework, policy DSL, schema evolution rules, conflict detection, and
// blueprint integrity checks.
//
// Core algorithms:
//   - AC-3 arc consistency for constraint propagation
//   - Backtracking search with forward checking for solutions
//   - Recursive descent parser for the policy DSL
//   - Topological sort for DAG cycle detection
//   - Floyd–Warshall transitive closure for dependency reachability

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: Constraint Solver (AC-3 + Backtracking)
// ═══════════════════════════════════════════════════════════════════════════

/// A discrete or continuous domain for a constraint variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Domain {
    /// Finite set of discrete values (e.g., {"shield", "stealth"}).
    Discrete(Vec<String>),
    /// Continuous range [min, max] with optional step.
    Continuous { min: f64, max: f64, step: Option<f64> },
    /// Boolean domain.
    Boolean,
}

impl Domain {
    /// Returns true if the domain contains no values.
    pub fn is_empty(&self) -> bool {
        match self {
            Domain::Discrete(vals) => vals.is_empty(),
            Domain::Continuous { min, max, .. } => min > max,
            Domain::Boolean => false,
        }
    }

    /// Returns the cardinality (approximate for continuous domains).
    pub fn size(&self) -> usize {
        match self {
            Domain::Discrete(vals) => vals.len(),
            Domain::Continuous { min, max, step } => {
                if let Some(s) = step {
                    if *s <= 0.0 {
                        return usize::MAX;
                    }
                    let count = ((max - min) / s).ceil() as usize;
                    count.saturating_add(1)
                } else {
                    usize::MAX
                }
            }
            Domain::Boolean => 2,
        }
    }

    /// Restrict a continuous domain to a narrower range, returning false if
    /// the result is empty.
    pub fn narrow(&mut self, new_min: f64, new_max: f64) -> bool {
        match self {
            Domain::Continuous { min, max, .. } => {
                *min = min.max(new_min);
                *max = max.min(new_max);
                *min <= *max
            }
            _ => true,
        }
    }

    /// Remove a discrete value from the domain. Returns true if the value
    /// was present and removed.
    pub fn remove_discrete(&mut self, val: &str) -> bool {
        if let Domain::Discrete(ref mut vals) = self {
            let before = vals.len();
            vals.retain(|v| v != val);
            vals.len() < before
        } else {
            false
        }
    }

    /// Retain only discrete values satisfying a predicate.
    pub fn retain_discrete<F>(&mut self, pred: F)
    where
        F: Fn(&str) -> bool,
    {
        if let Domain::Discrete(ref mut vals) = self {
            vals.retain(|v| pred(v));
        }
    }
}

/// A variable in the constraint satisfaction problem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintVariable {
    /// Unique variable name (e.g., "ring.shield.trust").
    pub name: String,
    /// The current domain of this variable.
    pub domain: Domain,
    /// Optional current assigned value.
    pub assigned: Option<serde_json::Value>,
}

impl ConstraintVariable {
    pub fn new(name: &str, domain: Domain) -> Self {
        Self {
            name: name.to_string(),
            domain,
            assigned: None,
        }
    }

    pub fn is_assigned(&self) -> bool {
        self.assigned.is_some()
    }

    /// Get all possible values as JSON values. For continuous domains with
    /// no step, returns the [min, max] range as a two-element array.
    pub fn domain_values(&self) -> Vec<serde_json::Value> {
        match &self.domain {
            Domain::Discrete(vals) => vals.iter().map(|v| serde_json::json!(v)).collect(),
            Domain::Boolean => vec![serde_json::json!(false), serde_json::json!(true)],
            Domain::Continuous { min, max, step } => {
                if let Some(s) = step {
                    let mut vals = Vec::new();
                    let mut v = *min;
                    while v <= *max + s * 1e-9 {
                        vals.push(serde_json::json!(v));
                        v += s;
                    }
                    if vals.is_empty() {
                        vals.push(serde_json::json!(*min));
                    }
                    vals
                } else {
                    vec![serde_json::json!([*min, *max])]
                }
            }
        }
    }
}

/// Comparison operators used in constraints.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl std::fmt::Display for CmpOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmpOp::Eq => write!(f, "=="),
            CmpOp::Neq => write!(f, "!="),
            CmpOp::Gt => write!(f, ">"),
            CmpOp::Gte => write!(f, ">="),
            CmpOp::Lt => write!(f, "<"),
            CmpOp::Lte => write!(f, "<="),
        }
    }
}

/// A constraint between one or more variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    /// `left op right` where both are variable names.
    Comparison {
        left: String,
        op: CmpOp,
        right: String,
    },
    /// `variable op literal_value`.
    LiteralComparison {
        variable: String,
        op: CmpOp,
        value: serde_json::Value,
    },
    /// Range constraint: `variable` in `[min, max]`.
    Range {
        variable: String,
        min: f64,
        max: f64,
    },
    /// Dependency: if `if_var` takes any value in `if_values`, then
    /// `then_var` must take a value in `then_values`.
    Dependency {
        if_var: String,
        if_values: Vec<String>,
        then_var: String,
        then_values: Vec<String>,
    },
    /// Not-equal pair: two variables must not be equal.
    NotEqual {
        left: String,
        right: String,
    },
    /// Arbitrary predicate evaluated against the full assignment.
    /// The predicate receives a map of variable name → JSON value.
    Predicate {
        name: String,
        variables: Vec<String>,
    },
}

impl Constraint {
    /// Returns the set of variable names referenced by this constraint.
    pub fn variables(&self) -> HashSet<&str> {
        match self {
            Constraint::Comparison { left, right, .. } => {
                let mut s = HashSet::new();
                s.insert(left.as_str());
                s.insert(right.as_str());
                s
            }
            Constraint::LiteralComparison { variable, .. } => {
                let mut s = HashSet::new();
                s.insert(variable.as_str());
                s
            }
            Constraint::Range { variable, .. } => {
                let mut s = HashSet::new();
                s.insert(variable.as_str());
                s
            }
            Constraint::Dependency {
                if_var,
                then_var,
                ..
            } => {
                let mut s = HashSet::new();
                s.insert(if_var.as_str());
                s.insert(then_var.as_str());
                s
            }
            Constraint::NotEqual { left, right } => {
                let mut s = HashSet::new();
                s.insert(left.as_str());
                s.insert(right.as_str());
                s
            }
            Constraint::Predicate { variables, .. } => {
                variables.iter().map(|v| v.as_str()).collect()
            }
        }
    }
}

/// The result of constraint solving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    /// Map from variable name to its assigned value.
    pub assignments: HashMap<String, serde_json::Value>,
    /// Whether a solution was found.
    pub satisfiable: bool,
    /// Variables that remain unassigned (partial solution).
    pub unassigned: Vec<String>,
}

/// Constraint Satisfaction Problem solver using AC-3 + backtracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSolver {
    /// All variables in the problem.
    pub variables: HashMap<String, ConstraintVariable>,
    /// All constraints.
    pub constraints: Vec<Constraint>,
    /// Maximum backtracking steps before giving up.
    pub max_backtracks: u64,
}

impl ConstraintSolver {
    /// Create a new solver with the given variables and constraints.
    pub fn new(
        variables: Vec<ConstraintVariable>,
        constraints: Vec<Constraint>,
    ) -> Self {
        let var_map: HashMap<String, ConstraintVariable> = variables
            .into_iter()
            .map(|v| (v.name.clone(), v))
            .collect();
        Self {
            variables: var_map,
            constraints,
            max_backtracks: 10_000,
        }
    }

    /// Run AC-3 arc consistency to prune domains.
    /// Returns `Ok(true)` if consistent, `Ok(false)` if a domain was wiped,
    /// and `Err` on unexpected state.
    pub fn ac3(&mut self) -> bool {
        // Initialize the work queue with all arcs (constraint, variable) pairs.
        let mut queue: VecDeque<(String, String)> = VecDeque::new();
        for constraint in &self.constraints {
            let vars: Vec<&str> = constraint.variables().into_iter().collect();
            for i in 0..vars.len() {
                for j in 0..vars.len() {
                    if i != j {
                        queue.push_back((vars[i].to_string(), vars[j].to_string()));
                    }
                }
            }
        }

        while let Some((xi, xj)) = queue.pop_front() {
 if self.revise(&xi, &xj) {
                if self.variables.get(&xi).map_or(true, |v| v.domain.is_empty()) {
                    return false;
                }
                // Re-enqueue all arcs (xk, xi) where xk ≠ xj.
                let neighbors = self.neighbors(&xi);
                for xk in neighbors {
                    if xk != xj {
                        queue.push_back((xk, xi.clone()));
                    }
                }
            }
        }
        true
    }

    /// Revise the domain of `xi` by removing values that have no
    /// supporting value in `xj` for any constraint involving both.
    fn revise(&mut self, xi: &str, xj: &str) -> bool {
        let mut revised = false;
        let constraints_involving_both: Vec<&Constraint> = self
            .constraints
            .iter()
            .filter(|c| {
                let vars = c.variables();
                vars.contains(xi) && vars.contains(xj)
            })
            .collect();

        if constraints_involving_both.is_empty() {
            return false;
        }

        // Pre-extract xj domain before borrowing mutably.
        let xj_domain = self
            .variables
            .get(xj)
            .map(|v| v.domain_values())
            .unwrap_or_default();

        // For discrete domains, check each value.
        if let Some(xi_var) = self.variables.get(xi) {
            if let Domain::Discrete(ref values) = xi_var.domain {
                let original_len = values.len();
                let retained: Vec<_> = values.iter().filter(|vi| {
                    let vi_json = serde_json::json!(vi);
                    for vj in &xj_domain {
                        if self.values_consistent(xi, &vi_json, xj, vj, &constraints_involving_both) {
                            return true;
                        }
                    }
                    false
                }).cloned().collect();
                let retained_len = retained.len();
                if let Some(xi_var) = self.variables.get_mut(xi) {
                    if let Domain::Discrete(ref mut values) = xi_var.domain {
                        *values = retained;
                    }
                }
                revised = retained_len < original_len;
            }
        }
        revised
    }

    /// Check if two specific value assignments are consistent with the given constraints.
    fn values_consistent(
        &self,
        xi_name: &str,
        xi_val: &serde_json::Value,
        xj_name: &str,
        xj_val: &serde_json::Value,
        constraints: &[&Constraint],
    ) -> bool {
        for constraint in constraints {
            let mut assignments = HashMap::new();
            assignments.insert(xi_name.to_string(), xi_val.clone());
            assignments.insert(xj_name.to_string(), xj_val.clone());
            if !self.check_constraint(constraint, &assignments) {
                return false;
            }
        }
        true
    }

    /// Check a single constraint against a (possibly partial) assignment.
    pub fn check_constraint(
        &self,
        constraint: &Constraint,
        assignment: &HashMap<String, serde_json::Value>,
    ) -> bool {
        match constraint {
            Constraint::Comparison { left, op, right } => {
                let lv = assignment.get(left);
                let rv = assignment.get(right);
                match (lv, rv) {
                    (Some(l), Some(r)) => compare_values(l, r, *op),
                    _ => true, // unassigned → not violated yet
                }
            }
            Constraint::LiteralComparison { variable, op, value } => {
                if let Some(v) = assignment.get(variable) {
                    compare_values(v, value, *op)
                } else {
                    true
                }
            }
            Constraint::Range { variable, min, max } => {
                if let Some(v) = assignment.get(variable) {
                    if let Some(n) = v.as_f64() {
                        n >= *min && n <= *max
                    } else {
                        true
                    }
                } else {
                    true
                }
            }
            Constraint::Dependency {
                if_var,
                if_values,
                then_var,
                then_values,
            } => {
                let iv = assignment.get(if_var);
                let tv = assignment.get(then_var);
                match (iv, tv) {
                    (Some(iv), Some(tv)) => {
                        let iv_str = iv.as_str().unwrap_or("");
                        let tv_str = tv.as_str().unwrap_or("");
                        if if_values.iter().any(|v| v == iv_str) {
                            then_values.iter().any(|v| v == tv_str)
                        } else {
                            true
                        }
                    }
                    _ => true,
                }
            }
            Constraint::NotEqual { left, right } => {
                let lv = assignment.get(left);
                let rv = assignment.get(right);
                match (lv, rv) {
                    (Some(l), Some(r)) => l != r,
                    _ => true,
                }
            }
            Constraint::Predicate { .. } => {
                // Predicates are externally evaluated; unassigned → not violated.
                true
            }
        }
    }

    /// Get all variable names that share a constraint with `var`.
    fn neighbors(&self, var: &str) -> Vec<String> {
        let mut neighbors = HashSet::new();
        for c in &self.constraints {
            let vars: HashSet<&str> = c.variables();
            if vars.contains(var) {
                for v in vars {
                    if v != var {
                        neighbors.insert(v.to_string());
                    }
                }
            }
        }
        neighbors.into_iter().collect()
    }

    /// Solve the CSP using AC-3 followed by backtracking with forward checking.
    pub fn solve(&mut self) -> Solution {
        // Phase 1: Arc consistency.
        if !self.ac3() {
            return Solution {
                assignments: HashMap::new(),
                satisfiable: false,
                unassigned: self.variables.keys().cloned().collect(),
            };
        }

        // Phase 2: Backtracking search.
        let mut assignment: HashMap<String, serde_json::Value> = HashMap::new();
        let mut backtracks = 0u64;
        let ordered_vars: Vec<String> = self
            .variables
            .keys()
            .cloned()
            .collect();

        if self.backtrack(&mut assignment, &ordered_vars, 0, &mut backtracks) {
            let assigned_names: HashSet<String> = assignment.keys().cloned().collect();
            let unassigned: Vec<String> = ordered_vars
                .into_iter()
                .filter(|v| !assigned_names.contains(v))
                .collect();
            Solution {
                assignments: assignment,
                satisfiable: true,
                unassigned,
            }
        } else {
            Solution {
                assignments: HashMap::new(),
                satisfiable: false,
                unassigned: ordered_vars,
            }
        }
    }

    /// Recursive backtracking with forward checking.
    fn backtrack(
        &mut self,
        assignment: &mut HashMap<String, serde_json::Value>,
        variables: &[String],
        index: usize,
        backtracks: &mut u64,
    ) -> bool {
        if index >= variables.len() {
            return true; // All variables assigned.
        }

        let var_name = &variables[index];
        let domain_values = if let Some(v) = self.variables.get(var_name) {
            v.domain_values()
        } else {
            return true; // Unknown variable — skip.
        };

        for value in &domain_values {
            assignment.insert(var_name.clone(), value.clone());

            // Forward check: verify all constraints with fully-assigned variables.
            let consistent = self.constraints.iter().all(|c| {
                self.check_constraint(c, assignment)
            });

            if consistent {
                if self.backtrack(assignment, variables, index + 1, backtracks) {
                    return true;
                }
            }

            assignment.remove(var_name);
            *backtracks += 1;
            if *backtracks > self.max_backtracks {
                return false;
            }
        }
        false
    }
}

/// Compare two JSON values using the given comparison operator.
pub fn compare_values(left: &serde_json::Value, right: &serde_json::Value, op: CmpOp) -> bool {
    // Numeric comparison.
    if let (Some(l), Some(r)) = (left.as_f64(), right.as_f64()) {
        return match op {
            CmpOp::Eq => (l - r).abs() < 1e-9,
            CmpOp::Neq => (l - r).abs() >= 1e-9,
            CmpOp::Gt => l > r,
            CmpOp::Gte => l >= r,
            CmpOp::Lt => l < r,
            CmpOp::Lte => l <= r,
        };
    }
    // String comparison.
    if let (Some(l), Some(r)) = (left.as_str(), right.as_str()) {
        return match op {
            CmpOp::Eq => l == r,
            CmpOp::Neq => l != r,
            CmpOp::Gt => l > r,
            CmpOp::Gte => l >= r,
            CmpOp::Lt => l < r,
            CmpOp::Lte => l <= r,
        };
    }
    // Boolean comparison.
    if let (Some(l), Some(r)) = (left.as_bool(), right.as_bool()) {
        return match op {
            CmpOp::Eq => l == r,
            CmpOp::Neq => l != r,
            CmpOp::Gt => l && !r,
            CmpOp::Gte => l >= r,
            CmpOp::Lt => !l && r,
            CmpOp::Lte => l <= r,
        };
    }
    // Fallback: equality check only.
    match op {
        CmpOp::Eq => left == right,
        CmpOp::Neq => left != right,
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: Policy Language Parser & Evaluator
// ═══════════════════════════════════════════════════════════════════════════

/// Policy directive kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyKind {
    Require,
    Forbid,
    Ensure,
}

impl std::fmt::Display for PolicyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyKind::Require => write!(f, "REQUIRE"),
            PolicyKind::Forbid => write!(f, "FORBID"),
            PolicyKind::Ensure => write!(f, "ENSURE"),
        }
    }
}

/// Policy priority levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl PolicyPriority {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => PolicyPriority::Low,
            "medium" => PolicyPriority::Medium,
            "high" => PolicyPriority::High,
            "critical" => PolicyPriority::Critical,
            _ => PolicyPriority::Medium,
        }
    }
}

/// A parsed duration value (e.g., "24h", "30m", "7d").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duration {
    pub seconds: u64,
}

impl Duration {
    pub fn from_str(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (num_str, unit) = if s.ends_with("ms") {
            (&s[..s.len() - 2], "ms")
        } else {
            let last = s.chars().last()?;
            (&s[..s.len() - 1], match last {
                's' => "s",
                'm' => "m",
                'h' => "h",
                'd' => "d",
                _ => return None,
            })
        };
        let num: f64 = num_str.parse().ok()?;
        let seconds = match unit {
            "ms" => (num / 1000.0) as u64,
            "s" => num as u64,
            "m" => (num * 60.0) as u64,
            "h" => (num * 3600.0) as u64,
            "d" => (num * 86400.0) as u64,
            _ => return None,
        };
        Some(Duration { seconds })
    }

    /// Parse a value that could be a duration or a number.
    pub fn parse_value(s: &str) -> Option<PolicyValue> {
        if let Some(dur) = Duration::from_str(s) {
            return Some(PolicyValue::Duration(dur));
        }
        if let Ok(n) = s.parse::<f64>() {
            return Some(PolicyValue::Number(n));
        }
        let lower = s.to_lowercase();
        match lower.as_str() {
            "true" => Some(PolicyValue::Boolean(true)),
            "false" => Some(PolicyValue::Boolean(false)),
            _ => Some(PolicyValue::String(s.to_string())),
        }
    }
}

/// A value that can appear in a policy expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyValue {
    Number(f64),
    String(String),
    Boolean(bool),
    Duration(Duration),
    Identifier(String),
}

/// A binary boolean operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
}

/// An AST node for the policy DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyExpr {
    /// Atomic comparison: `field op value`
    Comparison {
        field: String,
        op: CmpOp,
        value: PolicyValue,
    },
    /// Negation: `NOT expr`
    Not(Box<PolicyExpr>),
    /// Binary boolean: `expr AND/OR expr`
    Binary {
        left: Box<PolicyExpr>,
        op: BoolOp,
        right: Box<PolicyExpr>,
    },
    /// Literal boolean.
    Literal(bool),
    /// Always true (no condition specified).
    Always,
}

/// A fully parsed policy statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatement {
    /// Unique policy identifier.
    pub id: String,
    /// REQUIRE / FORBID / ENSURE.
    pub kind: PolicyKind,
    /// The subject being constrained (e.g., "ring.shield.trust").
    pub target: String,
    /// The comparison constraint on the target.
    pub constraint: CmpOp,
    pub threshold: PolicyValue,
    /// Optional WHEN condition.
    pub when: Option<PolicyExpr>,
    /// Optional UNLESS condition.
    pub unless: Option<PolicyExpr>,
    /// Policy priority.
    pub priority: PolicyPriority,
    /// Original raw text for debugging.
    pub raw: String,
}

/// Errors that can occur during policy parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyParseError {
    UnexpectedToken(String),
    ExpectedKeyword(String),
    InvalidComparison(String),
    InvalidValue(String),
    IncompleteStatement(String),
    UnknownField(String),
}

impl std::fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyParseError::UnexpectedToken(t) => write!(f, "unexpected token: {}", t),
            PolicyParseError::ExpectedKeyword(k) => write!(f, "expected keyword: {}", k),
            PolicyParseError::InvalidComparison(c) => write!(f, "invalid comparison: {}", c),
            PolicyParseError::InvalidValue(v) => write!(f, "invalid value: {}", v),
            PolicyParseError::IncompleteStatement(s) => write!(f, "incomplete statement: {}", s),
            PolicyParseError::UnknownField(field) => write!(f, "unknown field: {}", field),
        }
    }
}

/// A simple recursive-descent parser for the policy DSL.
pub struct PolicyParser;

impl PolicyParser {
    /// Parse a single policy statement from raw text.
    pub fn parse(input: &str) -> Result<PolicyStatement, PolicyParseError> {
        let tokens = Self::tokenize(input);
        let mut pos = 0usize;
        let raw = input.trim().to_string();

        // Parse kind: REQUIRE / FORBID / ENSURE.
        let (kind, new_pos) = Self::parse_kind(&tokens, pos)?;
        pos = new_pos;

        // Parse target field (dotted identifier).
        let (target, new_pos) = Self::parse_field(&tokens, pos)?;
        pos = new_pos;

        // Parse comparison operator.
        let (constraint, new_pos) = Self::parse_cmp_op(&tokens, pos)?;
        pos = new_pos;

        // Parse threshold value.
        let (threshold, new_pos) = Self::parse_value_token(&tokens, pos)?;
        pos = new_pos;

        // Parse optional WHEN condition.
        let mut when = None;
        let mut unless = None;
        let mut priority = PolicyPriority::Medium;

        while pos < tokens.len() {
            let tok = tokens[pos].to_uppercase();
            if tok == "WHEN" {
                pos += 1;
                let (expr, new_pos) = Self::parse_expr(&tokens, pos, &[])?;
                pos = new_pos;
                when = Some(expr);
            } else if tok == "UNLESS" {
                pos += 1;
                let (expr, new_pos) = Self::parse_expr(&tokens, pos, &[])?;
                pos = new_pos;
                unless = Some(expr);
            } else if tok == "PRIORITY" {
                pos += 1;
                if pos < tokens.len() {
                    priority = PolicyPriority::from_str(&tokens[pos]);
                    pos += 1;
                }
            } else {
                pos += 1; // Skip unknown trailing tokens.
            }
        }

        // Generate a deterministic ID from the raw text.
        let id = format!("pol_{:08x}", crate::ananta::crypto::hashing::hash_bytes(raw.as_bytes(), &crate::ananta::config::HashAlgorithm::Sha256).bytes.iter().take(4).fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(*b as u32)));



        Ok(PolicyStatement {
            id,
            kind,
            target,
            constraint,
            threshold,
            when,
            unless,
            priority,
            raw,
        })
    }

    /// Tokenize input into a flat list of tokens.
    fn tokenize(input: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let chars: Vec<char> = input.chars().collect();

        let mut i = 0usize;
        while i < chars.len() {
            let c = chars[i];
            if in_quotes {
                if c == '"' {
                    in_quotes = false;
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                } else {
                    current.push(c);
                }
            } else if c == '"' {
                in_quotes = true;
            } else if c.is_whitespace() {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            } else if ">=<=".contains(c) && (i + 1 < chars.len() && chars[i + 1] == '=') {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                current.push(c);
                current.push(chars[i + 1]);
                tokens.push(current.clone());
                current.clear();
                i += 1;
            } else if "><!".contains(c) && (i + 1 < chars.len() && chars[i + 1] == '=') {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                current.push(c);
                current.push(chars[i + 1]);
                tokens.push(current.clone());
                current.clear();
                i += 1;
            } else if "><!".contains(c) {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                tokens.push(c.to_string());
            } else if c == '(' || c == ')' {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                tokens.push(c.to_string());
            } else {
                current.push(c);
            }
            i += 1;
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    fn parse_kind(
        tokens: &[String],
        pos: usize,
    ) -> Result<(PolicyKind, usize), PolicyParseError> {
        if pos >= tokens.len() {
            return Err(PolicyParseError::IncompleteStatement(
                "expected policy kind".into(),
            ));
        }
        let kind = match tokens[pos].to_uppercase().as_str() {
            "REQUIRE" => PolicyKind::Require,
            "FORBID" => PolicyKind::Forbid,
            "ENSURE" => PolicyKind::Ensure,
            other => {
                return Err(PolicyParseError::ExpectedKeyword(format!(
                    "REQUIRE/FORBID/ENSURE, got {}",
                    other
                )))
            }
        };
        Ok((kind, pos + 1))
    }

    fn parse_field(
        tokens: &[String],
        pos: usize,
    ) -> Result<(String, usize), PolicyParseError> {
        if pos >= tokens.len() {
            return Err(PolicyParseError::IncompleteStatement(
                "expected field name".into(),
            ));
        }
        // Support dotted identifiers like "ring.shield.trust".
        // These come as separate tokens, so we need to collect them.
        let mut field_parts = Vec::new();
        let mut p = pos;
        while p < tokens.len() {
            let t = &tokens[p];
            // Stop if we hit a comparison operator or keyword.
            if [">", "<", ">=", "<=", "==", "!=", "WHEN", "UNLESS", "PRIORITY"]
                .contains(&t.as_str())
            {
                break;
            }
            field_parts.push(t.clone());
            p += 1;
            // If next token is a dot, skip it and continue.
            if p < tokens.len() && tokens[p] == "." {
                p += 1;
            } else {
                break;
            }
        }
        if field_parts.is_empty() {
            return Err(PolicyParseError::UnknownField(
                "no field found after policy kind".into(),
            ));
        }
        Ok((field_parts.join("."), p))
    }

    fn parse_cmp_op(
        tokens: &[String],
        pos: usize,
    ) -> Result<(CmpOp, usize), PolicyParseError> {
        if pos >= tokens.len() {
            return Err(PolicyParseError::InvalidComparison(
                "expected comparison operator".into(),
            ));
        }
        let op = match tokens[pos].as_str() {
            ">" => CmpOp::Gt,
            ">=" => CmpOp::Gte,
            "<" => CmpOp::Lt,
            "<=" => CmpOp::Lte,
            "==" => CmpOp::Eq,
            "!=" => CmpOp::Neq,
            other => {
                return Err(PolicyParseError::InvalidComparison(format!(
                    "unknown operator: {}",
                    other
                )))
            }
        };
        Ok((op, pos + 1))
    }

    fn parse_value_token(
        tokens: &[String],
        pos: usize,
    ) -> Result<(PolicyValue, usize), PolicyParseError> {
        if pos >= tokens.len() {
            return Err(PolicyParseError::InvalidValue(
                "expected value after operator".into(),
            ));
        }
        let val = Duration::parse_value(&tokens[pos]).ok_or_else(|| {
            PolicyParseError::InvalidValue(tokens[pos].clone())
        })?;
        Ok((val, pos + 1))
    }

    /// Parse a boolean expression (used for WHEN/UNLESS clauses).
    fn parse_expr(
        tokens: &[String],
        pos: usize,
        stop_at: &[&str],
    ) -> Result<(PolicyExpr, usize), PolicyParseError> {
        if pos >= tokens.len() || stop_at.contains(&tokens[pos].as_str()) {
            return Ok((PolicyExpr::Always, pos));
        }
        let (left, new_pos) = Self::parse_atom(tokens, pos, stop_at)?;
        let mut pos = new_pos;
        #[allow(clippy::never_loop)]
        while pos < tokens.len() {
            let upper = tokens[pos].to_uppercase();
            if stop_at.contains(&tokens[pos].as_str()) {
                break;
            }
            if upper == "AND" {
                pos += 1;
                let (right, new_pos) = Self::parse_atom(tokens, pos, stop_at)?;
                pos = new_pos;
                return Ok((
                    PolicyExpr::Binary {
                        left: Box::new(left),
                        op: BoolOp::And,
                        right: Box::new(right),
                    },
                    pos,
                ));
            } else if upper == "OR" {
                pos += 1;
                let (right, new_pos) = Self::parse_atom(tokens, pos, stop_at)?;
                pos = new_pos;
                return Ok((
                    PolicyExpr::Binary {
                        left: Box::new(left),
                        op: BoolOp::Or,
                        right: Box::new(right),
                    },
                    pos,
                ));
            } else {
                break;
            }
        }
        Ok((left, pos))
    }

    fn parse_atom(
        tokens: &[String],
        pos: usize,
        stop_at: &[&str],
    ) -> Result<(PolicyExpr, usize), PolicyParseError> {
        if pos >= tokens.len() {
            return Err(PolicyParseError::IncompleteStatement(
                "expected expression".into(),
            ));
        }
        let upper = tokens[pos].to_uppercase();
        if upper == "NOT" {
            let pos = pos + 1;
            let (inner, new_pos) = Self::parse_atom(tokens, pos, stop_at)?;
            return Ok((PolicyExpr::Not(Box::new(inner)), new_pos));
        }
        if tokens[pos] == "(" {
            let pos = pos + 1;
            let (expr, new_pos) = Self::parse_expr(tokens, pos, &[")"])?;
            let end_pos = if new_pos < tokens.len() && tokens[new_pos] == ")" {
                new_pos + 1
            } else {
                new_pos
            };
            return Ok((expr, end_pos));
        }
        // Otherwise, parse as a comparison: field op value.
        let (field, new_pos) = Self::parse_field(tokens, pos)?;
        let pos = new_pos;
        if pos >= tokens.len() || stop_at.contains(&tokens[pos].as_str()) {
            // Bare identifier — treat as a boolean check (truthy).
            return Ok((
                PolicyExpr::Comparison {
                    field,
                    op: CmpOp::Eq,
                    value: PolicyValue::Boolean(true),
                },
                pos,
            ));
        }
        let (op, new_pos) = Self::parse_cmp_op(tokens, pos)?;
        let pos = new_pos;
        let (value, new_pos) = Self::parse_value_token(tokens, pos)?;
        Ok((
            PolicyExpr::Comparison { field, op, value },
            new_pos,
        ))
    }
}

/// Evaluate a policy expression against the current system state.
pub fn evaluate_policy_expr(
    expr: &PolicyExpr,
    state: &HashMap<String, serde_json::Value>,
) -> bool {
    match expr {
        PolicyExpr::Comparison { field, op, value } => {
            let state_val = state.get(field.as_str()).cloned().unwrap_or(serde_json::Value::Null);
            let policy_json = match value {
                PolicyValue::Number(n) => serde_json::json!(*n),
                PolicyValue::String(s) => serde_json::json!(s),
                PolicyValue::Boolean(b) => serde_json::json!(*b),
                PolicyValue::Duration(d) => serde_json::json!(d.seconds as f64),
                PolicyValue::Identifier(id) => state
                    .get(id.as_str())
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            };
            compare_values(&state_val, &policy_json, *op)
        }
        PolicyExpr::Not(inner) => !evaluate_policy_expr(inner, state),
        PolicyExpr::Binary { left, op, right } => {
            let l = evaluate_policy_expr(left, state);
            match op {
                BoolOp::And => l && evaluate_policy_expr(right, state),
                BoolOp::Or => l || evaluate_policy_expr(right, state),
            }
        }
        PolicyExpr::Literal(b) => *b,
        PolicyExpr::Always => true,
    }
}

/// Evaluate a full policy statement against system state.
/// Returns `Some(true)` if the policy is satisfied, `Some(false)` if violated,
/// or `None` if the policy does not apply (WHEN condition is false or UNLESS is true).
pub fn evaluate_policy(
    policy: &PolicyStatement,
    state: &HashMap<String, serde_json::Value>,
) -> Option<bool> {
    // Check WHEN condition — if false, policy doesn't apply.
    if let Some(ref when_expr) = policy.when {
        if !evaluate_policy_expr(when_expr, state) {
            return None;
        }
    }
    // Check UNLESS condition — if true, policy is exempted.
    if let Some(ref unless_expr) = policy.unless {
        if evaluate_policy_expr(unless_expr, state) {
            return None;
        }
    }

    // Evaluate the main constraint.
    let state_val = state
        .get(policy.target.as_str())
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let threshold_json = match &policy.threshold {
        PolicyValue::Number(n) => serde_json::json!(*n),
        PolicyValue::String(s) => serde_json::json!(s),
        PolicyValue::Boolean(b) => serde_json::json!(*b),
        PolicyValue::Duration(d) => serde_json::json!(d.seconds as f64),
        PolicyValue::Identifier(id) => state
            .get(id.as_str())
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    };

    let satisfied = compare_values(&state_val, &threshold_json, policy.constraint);

    match policy.kind {
        PolicyKind::Require => Some(satisfied),
        PolicyKind::Forbid => Some(!satisfied),
        PolicyKind::Ensure => Some(satisfied),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: Schema Evolution
// ═══════════════════════════════════════════════════════════════════════════

/// Semantic version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(SemVer {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Field types supported in schemas.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldType {
    Float,
    Int,
    String,
    Boolean,
    Duration,
    Enum(Vec<String>),
}

/// A field definition in a schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub default_value: Option<serde_json::Value>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub description: String,
}

/// A schema version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub version: SemVer,
    pub name: String,
    pub fields: BTreeMap<String, FieldDef>,
    pub created_at: String,
}

impl SchemaVersion {
    pub fn new(version: SemVer, name: &str) -> Self {
        Self {
            version,
            name: name.to_string(),
            fields: BTreeMap::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_field(&mut self, field: FieldDef) {
        self.fields.insert(field.name.clone(), field);
    }
}

/// The kind of change between two schema versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SchemaChangeKind {
    FieldAdded,
    FieldRemoved,
    FieldTypeChanged,
    ConstraintTightened,
    ConstraintRelaxed,
    DefaultChanged,
    NonBreaking,
}

/// A detected schema change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaChange {
    pub field_name: String,
    pub kind: SchemaChangeKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub breaking: bool,
    pub description: String,
}

/// A migration step between schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationStep {
    /// Add a new field with a default value.
    AddField { name: String, default: serde_json::Value },
    /// Remove a field.
    RemoveField { name: String },
    /// Rename a field.
    RenameField { old_name: String, new_name: String },
    /// Convert a field's type.
    ConvertType {
        name: String,
        from_type: String,
        to_type: String,
        transform: String, // Description of the transformation.
    },
    /// Clamp values to a new range.
    ClampValues { name: String, min: f64, max: f64 },
    /// Set a default for previously null values.
    SetDefault { name: String, default: serde_json::Value },
}

/// Validates schema evolution and computes migration paths.
pub struct SchemaEvolutionValidator;

impl SchemaEvolutionValidator {
    /// Detect all changes between two schema versions.
    pub fn diff(old: &SchemaVersion, new: &SchemaVersion) -> Vec<SchemaChange> {
        let mut changes = Vec::new();

        // Check for removed fields.
        for (name, old_field) in &old.fields {
            if !new.fields.contains_key(name) {
                changes.push(SchemaChange {
                    field_name: name.clone(),
                    kind: SchemaChangeKind::FieldRemoved,
                    old_value: Some(format!("{:?}", old_field.field_type)),
                    new_value: None,
                    breaking: true,
                    description: format!("Field '{}' was removed", name),
                });
            }
        }

        // Check for added and modified fields.
        for (name, new_field) in &new.fields {
            if let Some(old_field) = old.fields.get(name) {
                // Field exists in both — check for type changes.
                if old_field.field_type != new_field.field_type {
                    changes.push(SchemaChange {
                        field_name: name.clone(),
                        kind: SchemaChangeKind::FieldTypeChanged,
                        old_value: Some(format!("{:?}", old_field.field_type)),
                        new_value: Some(format!("{:?}", new_field.field_type)),
                        breaking: true,
                        description: format!(
                            "Field '{}' type changed from {:?} to {:?}",
                            name, old_field.field_type, new_field.field_type
                        ),
                    });
                }
                // Check for tightened constraints.
                let tightened_min = match (old_field.min_value, new_field.min_value) {
                    (Some(o), Some(n)) if n > o => Some(format!("min: {} -> {}", o, n)),
                    _ => None,
                };
                let tightened_max = match (old_field.max_value, new_field.max_value) {
                    (Some(o), Some(n)) if n < o => Some(format!("max: {} -> {}", o, n)),
                    _ => None,
                };
                if tightened_min.is_some() || tightened_max.is_some() {
                    let desc = format!(
                        "Field '{}' constraints tightened: {}",
                        name,
                        tightened_min
                            .as_deref()
                            .unwrap_or("")
                            .trim_end_matches(" -> ")
                    );
                    changes.push(SchemaChange {
                        field_name: name.clone(),
                        kind: SchemaChangeKind::ConstraintTightened,
                        old_value: tightened_min.or(tightened_max),
                        new_value: None,
                        breaking: true,
                        description: desc,
                    });
                }
                // Check for relaxed constraints.
                let relaxed_min = match (old_field.min_value, new_field.min_value) {
                    (Some(o), Some(n)) if n < o => true,
                    _ => false,
                };
                let relaxed_max = match (old_field.max_value, new_field.max_value) {
                    (Some(o), Some(n)) if n > o => true,
                    _ => false,
                };
                if relaxed_min || relaxed_max {
                    changes.push(SchemaChange {
                        field_name: name.clone(),
                        kind: SchemaChangeKind::ConstraintRelaxed,
                        old_value: None,
                        new_value: None,
                        breaking: false,
                        description: format!("Field '{}' constraints relaxed", name),
                    });
                }
                // Check for required flag changes (required → optional is ok,
                // optional → required is breaking).
                if !old_field.required && new_field.required {
                    changes.push(SchemaChange {
                        field_name: name.clone(),
                        kind: SchemaChangeKind::ConstraintTightened,
                        old_value: Some("optional".to_string()),
                        new_value: Some("required".to_string()),
                        breaking: true,
                        description: format!(
                            "Field '{}' changed from optional to required",
                            name
                        ),
                    });
                }
                // Check default value changes.
                if old_field.default_value != new_field.default_value {
                    changes.push(SchemaChange {
                        field_name: name.clone(),
                        kind: SchemaChangeKind::DefaultChanged,
                        old_value: old_field
                            .default_value
                            .as_ref()
                            .map(|v| v.to_string()),
                        new_value: new_field
                            .default_value
                            .as_ref()
                            .map(|v| v.to_string()),
                        breaking: false,
                        description: format!("Field '{}' default changed", name),
                    });
                }
            } else {
                // New field added.
                changes.push(SchemaChange {
                    field_name: name.clone(),
                    kind: SchemaChangeKind::FieldAdded,
                    old_value: None,
                    new_value: Some(format!("{:?}", new_field.field_type)),
                    breaking: !new_field.required, // Adding an optional field is non-breaking.
                    description: format!("Field '{}' was added", name),
                });
            }
        }

        changes
    }

    /// Compute a migration plan from old schema to new schema.
    pub fn compute_migration(old: &SchemaVersion, new: &SchemaVersion) -> Vec<MigrationStep> {
        let mut steps = Vec::new();

        // Handle removed fields.
        for name in old.fields.keys() {
            if !new.fields.contains_key(name) {
                steps.push(MigrationStep::RemoveField {
                    name: name.clone(),
                });
            }
        }

        // Handle type changes.
        for (name, new_field) in &new.fields {
            if let Some(old_field) = old.fields.get(name) {
                if old_field.field_type != new_field.field_type {
                    steps.push(MigrationStep::ConvertType {
                        name: name.clone(),
                        from_type: format!("{:?}", old_field.field_type),
                        to_type: format!("{:?}", new_field.field_type),
                        transform: format!(
                            "Convert field '{}' from {:?} to {:?}",
                            name, old_field.field_type, new_field.field_type
                        ),
                    });
                }
            }
        }

        // Handle constraint changes via clamping.
        for (name, new_field) in &new.fields {
            if let Some(old_field) = old.fields.get(name) {
                let needs_clamp =
                    (new_field.min_value.is_some() && new_field.min_value != old_field.min_value)
 || (new_field.max_value.is_some() && new_field.max_value != old_field.max_value);
                if needs_clamp {
                    steps.push(MigrationStep::ClampValues {
                        name: name.clone(),
                        min: new_field.min_value.unwrap_or(f64::NEG_INFINITY),
                        max: new_field.max_value.unwrap_or(f64::INFINITY),
                    });
                }
            }
        }

        // Handle added fields with defaults.
        for (name, new_field) in &new.fields {
            if !old.fields.contains_key(name) {
                let default = new_field
                    .default_value
                    .clone()
                    .unwrap_or(serde_json::Value::Null);
                steps.push(MigrationStep::AddField {
                    name: name.clone(),
                    default,
                });
                // If the field is now required but was just added,
                // set the default explicitly.
                if new_field.required && new_field.default_value.is_none() {
                    steps.push(MigrationStep::SetDefault {
                        name: name.clone(),
                        default: serde_json::Value::Null,
                    });
                }
            }
        }

        steps
    }

    /// Validate that a data record conforms to the given schema.
    pub fn validate_data(
        schema: &SchemaVersion,
        data: &serde_json::Value,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        let obj = match data.as_object() {
            Some(o) => o,
            None => {
                errors.push("data is not a JSON object".to_string());
                return errors;
            }
        };

        for (name, field) in &schema.fields {
            if field.required && !obj.contains_key(name) {
                errors.push(format!("required field '{}' is missing", name));
                continue;
            }
            if let Some(value) = obj.get(name) {
                if !Self::check_type(value, &field.field_type) {
                    errors.push(format!(
                        "field '{}' has wrong type: expected {:?}, got {}",
                        name,
                        field.field_type,
                        value
                    ));
                }
                if let Some(n) = value.as_f64() {
                    if let Some(min) = field.min_value {
                        if n < min {
                            errors.push(format!(
                                "field '{}' value {} is below minimum {}",
                                name, n, min
                            ));
                        }
                    }
                    if let Some(max) = field.max_value {
                        if n > max {
                            errors.push(format!(
                                "field '{}' value {} exceeds maximum {}",
                                name, n, max
                            ));
                        }
                    }
                }
            }
        }
        errors
    }

    fn check_type(value: &serde_json::Value, expected: &FieldType) -> bool {
        match expected {
            FieldType::Float | FieldType::Int => value.is_number(),
            FieldType::String => value.is_string(),
            FieldType::Boolean => value.is_boolean(),
            FieldType::Duration => value.is_string() || value.is_number(),
            FieldType::Enum(variants) => value
                .as_str()
                        .map(|s| variants.iter().any(|v| v == s))
                        .unwrap_or(false),
        }
    }

    /// Check if a version transition is breaking.
    pub fn is_breaking_transition(old: &SchemaVersion, new: &SchemaVersion) -> bool {
        Self::diff(old, new).iter().any(|c| c.breaking)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: Policy Conflict Detection
// ═══════════════════════════════════════════════════════════════════════════

/// The type of policy conflict detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictType {
    /// Two policies have contradictory constraints on the same target.
    Contradiction,
    /// One policy is subsumed (redundant) by another.
    Redundancy,
    /// Two policies with the same priority conflict.
    PriorityClash,
}

/// A detected policy conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConflict {
    pub conflict_type: ConflictType,
    pub policy_a: String,
    pub policy_b: String,
    pub target: String,
    pub description: String,
    /// Suggested resolution strategy.
    pub resolution: ConflictResolution,
}

/// Suggested conflict resolution strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Both policies have equal priority — cannot auto-resolve.
    PriorityClash,
    /// Use the policy with higher priority.
    HigherPriorityWins,
    /// Use the most restrictive policy.
    MostRestrictiveWins,
    /// Use the most permissive policy.
    MostPermissiveWins,
    /// Both policies are contradictory — manual resolution needed.
    ManualResolutionRequired,
    /// Remove the redundant policy.
    RemoveRedundant,
}

/// Detects and resolves conflicts between security policies.
pub struct PolicyConflictDetector;

impl PolicyConflictDetector {
    /// Analyze a set of policies for conflicts.
    pub fn detect_conflicts(policies: &[PolicyStatement]) -> Vec<PolicyConflict> {
        let mut conflicts = Vec::new();
        for i in 0..policies.len() {
            for j in (i + 1)..policies.len() {
                if let Some(conflict) =
                    Self::check_pair(&policies[i], &policies[j])
                {
                    conflicts.push(conflict);
                }
            }
        }
        conflicts
    }

    /// Check a pair of policies for conflicts.
    fn check_pair(a: &PolicyStatement, b: &PolicyStatement) -> Option<PolicyConflict> {
        // Only check policies targeting the same field.
        if a.target != b.target {
            return None;
        }

        // Check for contradictions.
        if let Some(desc) = Self::find_contradiction(a, b) {
            let resolution = if a.priority == b.priority {
                ConflictResolution::PriorityClash
            } else if a.kind == PolicyKind::Forbid || b.kind == PolicyKind::Forbid {
                ConflictResolution::MostRestrictiveWins
            } else {
                ConflictResolution::HigherPriorityWins
            };
            return Some(PolicyConflict {
                conflict_type: ConflictType::Contradiction,
                policy_a: a.id.clone(),
                policy_b: b.id.clone(),
                target: a.target.clone(),
                description: desc,
                resolution,
            });
        }

        // Check for redundancy.
        if let Some(desc) = Self::find_redundancy(a, b) {
            return Some(PolicyConflict {
                conflict_type: ConflictType::Redundancy,
                policy_a: a.id.clone(),
                policy_b: b.id.clone(),
                target: a.target.clone(),
                description: desc,
                resolution: ConflictResolution::RemoveRedundant,
            });
        }

        None
    }

    /// Detect if two policies on the same target are contradictory.
    fn find_contradiction(a: &PolicyStatement, b: &PolicyStatement) -> Option<String> {
        // Same kind, same target, incompatible constraints.
        if a.kind == PolicyKind::Require && b.kind == PolicyKind::Require {
            if Self::constraints_incompatible(a, b) {
                return Some(format!(
                    "Contradictory REQUIRE: {} {} {} vs {} {} {}",
                    a.target, a.constraint, Self::value_str(&a.threshold),
                    b.target, b.constraint, Self::value_str(&b.threshold)
                ));
            }
        }
        if a.kind == PolicyKind::Forbid && b.kind == PolicyKind::Forbid {
            if Self::forbid_ranges_overlap(a, b) {
                return Some(format!(
                    "Overlapping FORBID: {} {} {} and {} {} {}",
                    a.target, a.constraint, Self::value_str(&a.threshold),
                    b.target, b.constraint, Self::value_str(&b.threshold)
                ));
            }
        }
        // REQUIRE X > 0.8 and FORBID X > 0.6 (forbid range contains require range).
        if (a.kind == PolicyKind::Require && b.kind == PolicyKind::Forbid)
            || (a.kind == PolicyKind::Forbid && b.kind == PolicyKind::Require)
        {
            let (req, fbd) = if a.kind == PolicyKind::Require {
                (a, b)
            } else {
                (b, a)
            };
            if Self::require_forbids_require(req, fbd) {
                return Some(format!(
                    "REQUIRE and FORBID conflict on {}: REQUIRE {} {}, FORBID {} {}",
                    req.target, req.constraint, Self::value_str(&req.threshold),
                    fbd.constraint, Self::value_str(&fbd.threshold)
                ));
            }
        }
        None
    }

    /// Check if two REQUIRE constraints on the same target are incompatible.
    fn constraints_incompatible(a: &PolicyStatement, b: &PolicyStatement) -> bool {
        let a_num = Self::extract_number(&a.threshold);
        let b_num = Self::extract_number(&b.threshold);
        match (a_num, b_num) {
            (Some(an), Some(bn)) => {
                // a: X > 0.8 and b: X < 0.6 — impossible.
                match (a.constraint, b.constraint) {
                    (CmpOp::Gt, CmpOp::Lt) => an >= bn,
                    (CmpOp::Gt, CmpOp::Lte) => an >= bn,
                    (CmpOp::Gte, CmpOp::Lt) => an > bn,
                    (CmpOp::Gte, CmpOp::Lte) => an > bn,
                    (CmpOp::Lt, CmpOp::Gt) => an <= bn,
                    (CmpOp::Lte, CmpOp::Gt) => an <= bn,
                    (CmpOp::Lt, CmpOp::Gte) => an < bn,
                    (CmpOp::Lte, CmpOp::Gte) => an < bn,
                    (CmpOp::Eq, CmpOp::Neq) => (an - bn).abs() < 1e-9,
                    (CmpOp::Neq, CmpOp::Eq) => (an - bn).abs() < 1e-9,
                    (CmpOp::Eq, CmpOp::Eq) => (an - bn).abs() >= 1e-9,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Check if two FORBID constraints overlap (meaning nothing is allowed).
    fn forbid_ranges_overlap(a: &PolicyStatement, b: &PolicyStatement) -> bool {
        let a_num = Self::extract_number(&a.threshold);
        let b_num = Self::extract_number(&b.threshold);
        match (a_num, b_num) {
            (Some(an), Some(bn)) => {
                // FORBID X < 0.4 and FORBID X > 0.6 → gap at [0.4, 0.6] is ok.
                // FORBID X < 0.6 and FORBID X > 0.4 → total overlap.
                let a_lower = match a.constraint {
                    CmpOp::Lt | CmpOp::Lte => Some((f64::NEG_INFINITY, an)),
                    CmpOp::Gt | CmpOp::Gte => Some((an, f64::INFINITY)),
                    CmpOp::Eq => Some((an, an)),
                    _ => None,
                };
                let b_lower = match b.constraint {
                    CmpOp::Lt | CmpOp::Lte => Some((f64::NEG_INFINITY, bn)),
                    CmpOp::Gt | CmpOp::Gte => Some((bn, f64::INFINITY)),
                    CmpOp::Eq => Some((bn, bn)),
                    _ => None,
                };
                match (a_lower, b_lower) {
                    (Some((a_lo, a_hi)), Some((b_lo, b_hi))) => {
                        // Ranges overlap if neither is completely outside the other.
                        // Total coverage: a covers (-inf, X] and b covers [Y, inf) where X >= Y.
                        a_lo <= b_hi && b_lo <= a_hi
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Check if a REQUIRE is entirely within the FORBID range.
    fn require_forbids_require(req: &PolicyStatement, fbd: &PolicyStatement) -> bool {
        let r_num = Self::extract_number(&req.threshold);
        let f_num = Self::extract_number(&fbd.threshold);
        match (r_num, f_num) {
            (Some(rn), Some(fn_)) => {
                // REQUIRE X > 0.8, FORBID X > 0.6 → everything > 0.8 is also > 0.6.
                match (req.constraint, fbd.constraint) {
                    (CmpOp::Gt, CmpOp::Gt) => rn >= fn_,
                    (CmpOp::Gt, CmpOp::Gte) => rn > fn_,
                    (CmpOp::Gte, CmpOp::Gt) => rn > fn_,
                    (CmpOp::Gte, CmpOp::Gte) => rn >= fn_,
                    // REQUIRE X < 0.4, FORBID X < 0.6 → 0.4 is within forbid range.
                    (CmpOp::Lt, CmpOp::Lt) => rn <= fn_,
                    (CmpOp::Lt, CmpOp::Lte) => rn < fn_,
                    (CmpOp::Lte, CmpOp::Lt) => rn < fn_,
                    (CmpOp::Lte, CmpOp::Lte) => rn <= fn_,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Check if one policy subsumes (makes redundant) another.
    fn find_redundancy(a: &PolicyStatement, b: &PolicyStatement) -> Option<String> {
        if a.kind != b.kind {
            return None;
        }
        let a_num = Self::extract_number(&a.threshold);
        let b_num = Self::extract_number(&b.threshold);
        match (a_num, b_num) {
            (Some(an), Some(bn)) => {
                // Same direction, same kind: the tighter one subsumes the looser.
                match (a.constraint, b.constraint) {
                    (CmpOp::Gt, CmpOp::Gt) | (CmpOp::Gte, CmpOp::Gte) => {
                        if an >= bn {
                            return Some(format!(
                                "Policy {} ({}) {} {} is subsumed by {} ({}) {} {}",
                                b.id, b.kind, b.target, Self::value_str(&b.threshold),
                                a.id, a.kind, a.target, Self::value_str(&a.threshold)
                            ));
                        }
                    }
                    (CmpOp::Lt, CmpOp::Lt) | (CmpOp::Lte, CmpOp::Lte) => {
                        if an <= bn {
                            return Some(format!(
                                "Policy {} ({}) {} {} is subsumed by {} ({}) {} {}",
                                b.id, b.kind, b.target, Self::value_str(&b.threshold),
                                a.id, a.kind, a.target, Self::value_str(&a.threshold)
                            ));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        None
    }

    fn extract_number(val: &PolicyValue) -> Option<f64> {
        match val {
            PolicyValue::Number(n) => Some(*n),
            PolicyValue::Duration(d) => Some(d.seconds as f64),
            _ => None,
        }
    }

    fn value_str(val: &PolicyValue) -> String {
        match val {
            PolicyValue::Number(n) => format!("{}", n),
            PolicyValue::String(s) => s.clone(),
            PolicyValue::Boolean(b) => format!("{}", b),
            PolicyValue::Duration(d) => format!("{}s", d.seconds),
            PolicyValue::Identifier(i) => i.clone(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: Orchestration Blueprint Validation
// ═══════════════════════════════════════════════════════════════════════════

/// Resource requirements for a pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub memory_mb: u64,
    pub cpu_cores: f64,
    pub max_concurrent_connections: u32,
    pub storage_mb: u64,
}

impl ResourceRequirements {
    pub fn minimal() -> Self {
        Self {
            memory_mb: 64,
            cpu_cores: 0.1,
            max_concurrent_connections: 10,
            storage_mb: 10,
        }
    }

    /// Merge (add) two resource requirements together.
    pub fn merge(&self, other: &ResourceRequirements) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: self.memory_mb + other.memory_mb,
            cpu_cores: self.cpu_cores + other.cpu_cores,
            max_concurrent_connections: self
                .max_concurrent_connections
                .max(other.max_concurrent_connections),
            storage_mb: self.storage_mb + other.storage_mb,
        }
    }

    /// Check if this requirement exceeds the given limits.
    pub fn exceeds(&self, limits: &ResourceLimits) -> Vec<String> {
        let mut violations = Vec::new();
        if self.memory_mb > limits.max_memory_mb {
            violations.push(format!(
                "memory {}MB exceeds limit {}MB",
                self.memory_mb, limits.max_memory_mb
            ));
        }
        if self.cpu_cores > limits.max_cpu_cores {
            violations.push(format!(
                "CPU {} cores exceeds limit {}",
                self.cpu_cores, limits.max_cpu_cores
            ));
        }
        if self.max_concurrent_connections > limits.max_connections {
            violations.push(format!(
                "connections {} exceeds limit {}",
                self.max_concurrent_connections, limits.max_connections
            ));
        }
        if self.storage_mb > limits.max_storage_mb {
            violations.push(format!(
                "storage {}MB exceeds limit {}MB",
                self.storage_mb, limits.max_storage_mb
            ));
        }
        violations
    }
}

/// System resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub max_cpu_cores: f64,
    pub max_connections: u32,
    pub max_storage_mb: u64,
}

/// A single node in the orchestration blueprint DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintNode {
    pub id: String,
    pub name: String,
    pub component_type: String,
    pub dependencies: Vec<String>,
    pub resource_requirements: ResourceRequirements,
    pub min_trust_level: f64,
    pub configuration: HashMap<String, serde_json::Value>,
}

/// The full orchestration blueprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationBlueprint {
    pub id: String,
    pub name: String,
    pub version: SemVer,
    pub nodes: Vec<BlueprintNode>,
    pub resource_limits: ResourceLimits,
    pub global_min_trust: f64,
    pub created_at: String,
}

/// A validation issue found in a blueprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintIssue {
    pub severity: IssueSeverity,
    pub node_id: Option<String>,
    pub category: String,
    pub message: String,
}

/// Severity of a validation issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Warning,
    Error,
    Critical,
}

/// Result of blueprint validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintValidationResult {
    pub valid: bool,
    pub issues: Vec<BlueprintIssue>,
    pub total_nodes: usize,
    pub dependency_depth: usize,
    pub total_resource_requirements: ResourceRequirements,
}

/// Validates orchestration blueprints for correctness and safety.
pub struct BlueprintValidator;

impl BlueprintValidator {
    /// Validate a full orchestration blueprint.
    pub fn validate(blueprint: &OrchestrationBlueprint) -> BlueprintValidationResult {
        let mut issues = Vec::new();

        // Build node lookup.
        let node_map: HashMap<&str, &BlueprintNode> = blueprint
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n))
            .collect();

        // 1. Check for duplicate node IDs.
        let mut seen_ids = HashSet::new();
        for node in &blueprint.nodes {
            if !seen_ids.insert(&node.id) {
                issues.push(BlueprintIssue {
                    severity: IssueSeverity::Error,
                    node_id: Some(node.id.clone()),
                    category: "duplicate_id".to_string(),
                    message: format!("Duplicate node ID: {}", node.id),
                });
            }
        }

        // 2. Check for circular dependencies.
        if let Some(cycle) = Self::detect_cycle(&blueprint.nodes) {
            issues.push(BlueprintIssue {
                severity: IssueSeverity::Critical,
                node_id: None,
                category: "circular_dependency".to_string(),
                message: format!("Circular dependency detected: {}", cycle),
            });
        }

        // 3. Check dependency references.
        for node in &blueprint.nodes {
            for dep in &node.dependencies {
                if !node_map.contains_key(dep.as_str()) {
                    issues.push(BlueprintIssue {
                        severity: IssueSeverity::Error,
                        node_id: Some(node.id.clone()),
                        category: "missing_dependency".to_string(),
                        message: format!(
                            "Node '{}' depends on '{}' which does not exist",
                            node.id, dep
                        ),
                    });
                }
            }
        }

        // 4. Compute total resource requirements and check against limits.
        let total_resources = blueprint
            .nodes
            .iter()
            .fold(ResourceRequirements::minimal(), |acc, n| {
                acc.merge(&n.resource_requirements)
            });
        let resource_violations = total_resources.exceeds(&blueprint.resource_limits);
        for v in &resource_violations {
            issues.push(BlueprintIssue {
                severity: IssueSeverity::Error,
                node_id: None,
                category: "resource_limit".to_string(),
                message: v.clone(),
            });
        }

        // 5. Check per-node resource requirements.
        for node in &blueprint.nodes {
            let violations = node.resource_requirements.exceeds(&blueprint.resource_limits);
            for v in &violations {
                issues.push(BlueprintIssue {
                    severity: IssueSeverity::Warning,
                    node_id: Some(node.id.clone()),
                    category: "node_resource".to_string(),
                    message: format!("Node '{}': {}", node.id, v),
                });
            }
        }

        // 6. Check trust chain integrity.
        for node in &blueprint.nodes {
            if node.min_trust_level < blueprint.global_min_trust {
                issues.push(BlueprintIssue {
                    severity: IssueSeverity::Warning,
                    node_id: Some(node.id.clone()),
                    category: "trust_threshold".to_string(),
                    message: format!(
                        "Node '{}' min trust {:.2} is below global minimum {:.2}",
                        node.id, node.min_trust_level, blueprint.global_min_trust
                    ),
                });
            }
        }

        // 7. Compute dependency depth.
        let depth = Self::compute_max_depth(&blueprint.nodes);

        // 8. Check for nodes with no dependents (leaf nodes) and no dependencies (root nodes).
        let has_roots = blueprint
            .nodes
            .iter()
            .any(|n| n.dependencies.is_empty());
        if !has_roots && !blueprint.nodes.is_empty() {
            issues.push(BlueprintIssue {
                severity: IssueSeverity::Warning,
                node_id: None,
                category: "no_root".to_string(),
                message: "No root node (node with no dependencies) found".to_string(),
            });
        }

        let valid = !issues.iter().any(|i| {
            i.severity == IssueSeverity::Error || i.severity == IssueSeverity::Critical
        });

        BlueprintValidationResult {
            valid,
            issues,
            total_nodes: blueprint.nodes.len(),
            dependency_depth: depth,
            total_resource_requirements: total_resources,
        }
    }

    /// Detect cycles in the dependency graph using Kahn's algorithm.
    /// Returns the cycle description if found, or None if the graph is a DAG.
    pub fn detect_cycle(nodes: &[BlueprintNode]) -> Option<String> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        let node_ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();

        for node in nodes {
            in_degree.entry(node.id.as_str()).or_insert(0);
            for dep in &node.dependencies {
                if node_ids.contains(dep.as_str()) {
                    *in_degree.entry(node.id.as_str()).or_insert(0) += 1;
                    adj.entry(dep.as_str())
                        .or_insert_with(Vec::new)
                        .push(node.id.as_str());
                }
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited_count = 0usize;
        while let Some(node) = queue.pop_front() {
            visited_count += 1;
            if let Some(neighbors) = adj.get(node) {
                for &neighbor in neighbors {
                    let degree = in_degree.get_mut(neighbor).unwrap();
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        if visited_count < nodes.len() {
            let remaining: Vec<String> = in_degree
                .iter()
                .filter(|(_, &d)| d > 0)
                .map(|(&id, _)| id.to_string())
                .collect();
            Some(format!("Cycle involving nodes: {}", remaining.join(" -> ")))
        } else {
            None
        }
    }

    /// Compute the maximum depth of the dependency DAG using topological sort.
    /// Root nodes (no dependencies) have depth 1. Each dependency layer adds 1.
    pub fn compute_max_depth(nodes: &[BlueprintNode]) -> usize {
        let mut depths: HashMap<&str, usize> = HashMap::new();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        let node_ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();

        for node in nodes {
            in_degree.entry(node.id.as_str()).or_insert(0);
            for dep in &node.dependencies {
                if node_ids.contains(dep.as_str()) {
                    *in_degree.entry(node.id.as_str()).or_insert(0) += 1;
                    adj.entry(dep.as_str())
                        .or_insert_with(Vec::new)
                        .push(node.id.as_str());
                }
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();

        for &root in &queue {
            depths.insert(root, 1);
        }

        let mut max_depth = 0usize;
        while let Some(node) = queue.pop_front() {
            let node_depth = depths[node];
            max_depth = max_depth.max(node_depth);
            if let Some(neighbors) = adj.get(node) {
                for &neighbor in neighbors {
                    let current = depths.get(neighbor).copied().unwrap_or(0);
                    depths.insert(neighbor, current.max(node_depth + 1));
                    let degree = in_degree.get_mut(neighbor).unwrap();
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }
        max_depth
    }

    /// Verify trust chain integrity: every node's trust level must meet
    /// the minimum requirements of all nodes that depend on it.
    pub fn verify_trust_chain(
        blueprint: &OrchestrationBlueprint,
        trust_levels: &HashMap<String, f64>,
    ) -> Vec<BlueprintIssue> {
        let mut issues = Vec::new();
        for node in &blueprint.nodes {
            let node_trust = trust_levels
                .get(&node.id)
                .copied()
                .unwrap_or(0.0);
            if node_trust < node.min_trust_level {
                issues.push(BlueprintIssue {
                    severity: IssueSeverity::Error,
                    node_id: Some(node.id.clone()),
                    category: "trust_violation".to_string(),
                    message: format!(
                        "Node '{}' trust {:.3} below required {:.3}",
                        node.id, node_trust, node.min_trust_level
                    ),
                });
            }
            if node_trust < blueprint.global_min_trust {
                issues.push(BlueprintIssue {
                    severity: IssueSeverity::Critical,
                    node_id: Some(node.id.clone()),
                    category: "global_trust_violation".to_string(),
                    message: format!(
                        "Node '{}' trust {:.3} below global minimum {:.3}",
                        node.id, node_trust, blueprint.global_min_trust
                    ),
                });
            }
        }
        issues
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: Comprehensive Validation Engine
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregates all validation results into a single report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub constraint_satisfiable: bool,
    pub policy_violations: Vec<PolicyViolation>,
    pub policy_conflicts: Vec<PolicyConflict>,
    pub schema_issues: Vec<String>,
    pub blueprint_issues: Vec<BlueprintIssue>,
    pub overall_valid: bool,
    pub timestamp: String,
}

/// A policy violation found during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy_id: String,
    pub target: String,
    pub expected: String,
    pub actual: serde_json::Value,
    pub severity: String,
}

/// The main validation engine that ties all subsystems together.
pub struct OrchestrationValidator {
    pub solver: ConstraintSolver,
    pub policies: Vec<PolicyStatement>,
    pub blueprint: Option<OrchestrationBlueprint>,
    pub schema: Option<SchemaVersion>,
}

impl OrchestrationValidator {
    /// Create a new validator with the given constraint solver and policies.
    pub fn new(solver: ConstraintSolver, policies: Vec<PolicyStatement>) -> Self {
        Self {
            solver,
            policies,
            blueprint: None,
            schema: None,
        }
    }

    /// Set the blueprint to validate.
    pub fn with_blueprint(mut self, blueprint: OrchestrationBlueprint) -> Self {
        self.blueprint = Some(blueprint);
        self
    }

    /// Set the schema to validate against.
    pub fn with_schema(mut self, schema: SchemaVersion) -> Self {
        self.schema = Some(schema);
        self
    }

    /// Run all validations and produce a comprehensive report.
    pub fn validate(&mut self) -> ValidationReport {
        let mut report = ValidationReport {
            constraint_satisfiable: false,
            policy_violations: Vec::new(),
            policy_conflicts: Vec::new(),
            schema_issues: Vec::new(),
            blueprint_issues: Vec::new(),
            overall_valid: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // 1. Solve constraints.
        let solution = self.solver.solve();
        report.constraint_satisfiable = solution.satisfiable;

        // 2. Detect policy conflicts.
        report.policy_conflicts = PolicyConflictDetector::detect_conflicts(&self.policies);

        // 3. Validate blueprint if present.
        if let Some(ref blueprint) = self.blueprint {
            let result = BlueprintValidator::validate(blueprint);
            report.blueprint_issues = result.issues;
        }

        // 4. Validate schema if present.
        if let Some(ref schema) = self.schema {
            // Self-validation: check schema has at least one field.
            if schema.fields.is_empty() {
                report.schema_issues.push(
                    "Schema has no fields defined".to_string(),
                );
            }
        }

        report.overall_valid = report.constraint_satisfiable
            && report.policy_conflicts.is_empty()
            && report
                .blueprint_issues
                .iter()
                .all(|i| i.severity == IssueSeverity::Warning)
            && report.schema_issues.is_empty();

        report
    }

    /// Evaluate all policies against the given state and return violations.
    pub fn evaluate_policies(
        &self,
        state: &HashMap<String, serde_json::Value>,
    ) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();
        for policy in &self.policies {
            if let Some(false) = evaluate_policy(policy, state) {
                violations.push(PolicyViolation {
                    policy_id: policy.id.clone(),
                    target: policy.target.clone(),
                    expected: format!("{} {} {}", policy.kind, policy.constraint,
                        PolicyConflictDetector::value_str(&policy.threshold)),
                    actual: state
                        .get(policy.target.as_str())
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                    severity: match policy.priority {
                        PolicyPriority::Critical => "critical".to_string(),
                        PolicyPriority::High => "high".to_string(),
                        PolicyPriority::Medium => "medium".to_string(),
                        PolicyPriority::Low => "low".to_string(),
                    },
                });
            }
        }
        violations
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constraint Solver Tests ───────────────────────────────────────────

    fn make_simple_solver() -> ConstraintSolver {
        let vars = vec![
            ConstraintVariable::new(
                "ring.shield.trust",
                Domain::Continuous { min: 0.0, max: 1.0, step: Some(0.1) },
            ),
            ConstraintVariable::new(
                "ring.learning.trust",
                Domain::Continuous { min: 0.0, max: 1.0, step: Some(0.1) },
            ),
            ConstraintVariable::new(
                "pipeline.mode",
                Domain::Discrete(vec!["strict".to_string(), "relaxed".to_string()]),
            ),
        ];
        let constraints = vec![
            Constraint::LiteralComparison {
                variable: "ring.shield.trust".to_string(),
                op: CmpOp::Gte,
                value: serde_json::json!(0.5),
            },
            Constraint::Range {
                variable: "ring.shield.trust".to_string(),
                min: 0.0,
                max: 1.0,
            },
        ];
        ConstraintSolver::new(vars, constraints)
    }

    #[test]
    fn test_domain_not_empty() {
        let d = Domain::Discrete(vec!["a".to_string()]);
        assert!(!d.is_empty());
        let d2 = Domain::Discrete(vec![]);
        assert!(d2.is_empty());
    }

    #[test]
    fn test_domain_size() {
        let d = Domain::Boolean;
        assert_eq!(d.size(), 2);
        let d2 = Domain::Discrete(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(d2.size(), 2);
    }

    #[test]
    fn test_domain_narrow() {
        let mut d = Domain::Continuous { min: 0.0, max: 1.0, step: None };
        assert!(d.narrow(0.3, 0.7));
        assert!(!d.narrow(0.8, 0.9)); // 0.7 < 0.8 → empty
    }

    #[test]
    fn test_domain_remove_discrete() {
        let mut d = Domain::Discrete(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ]);
        assert!(d.remove_discrete("b"));
        assert!(!d.remove_discrete("z"));
        assert_eq!(d.size(), 2);
    }

    #[test]
    fn test_compare_values_numeric() {
        assert!(compare_values(&serde_json::json!(5.0), &serde_json::json!(3.0), CmpOp::Gt));
        assert!(compare_values(&serde_json::json!(3.0), &serde_json::json!(3.0), CmpOp::Gte));
        assert!(!compare_values(&serde_json::json!(3.0), &serde_json::json!(5.0), CmpOp::Gte));
        assert!(compare_values(&serde_json::json!(1.0), &serde_json::json!(1.0), CmpOp::Eq));
        assert!(compare_values(&serde_json::json!(1.0), &serde_json::json!(2.0), CmpOp::Neq));
    }

    #[test]
    fn test_compare_values_string() {
        assert!(compare_values(&serde_json::json!("b"), &serde_json::json!("a"), CmpOp::Gt));
        assert!(compare_values(&serde_json::json!("a"), &serde_json::json!("a"), CmpOp::Eq));
    }

    #[test]
    fn test_compare_values_boolean() {
        assert!(compare_values(&serde_json::json!(true), &serde_json::json!(false), CmpOp::Gt));
        assert!(!compare_values(&serde_json::json!(false), &serde_json::json!(true), CmpOp::Gt));
    }

    #[test]
    fn test_solver_simple_satisfiable() {
        let mut solver = make_simple_solver();
        let solution = solver.solve();
        assert!(solution.satisfiable);
    }

    #[test]
    fn test_solver_unsatisfiable() {
        let vars = vec![ConstraintVariable::new(
            "x",
            Domain::Continuous { min: 0.0, max: 0.5, step: Some(0.1) },
        )];
        let constraints = vec![Constraint::LiteralComparison {
            variable: "x".to_string(),
            op: CmpOp::Gt,
            value: serde_json::json!(1.0),
        }];
        let mut solver = ConstraintSolver::new(vars, constraints);
        // AC-3 won't find this unsatisfiable (continuous domain),
        // but backtracking will.
        let solution = solver.solve();
        assert!(!solution.satisfiable);
    }

    #[test]
    fn test_solver_not_equal() {
        let vars = vec![
            ConstraintVariable::new("a", Domain::Discrete(vec!["x".to_string(), "y".to_string()])),
            ConstraintVariable::new("b", Domain::Discrete(vec!["x".to_string(), "y".to_string()])),
        ];
        let constraints = vec![Constraint::NotEqual {
            left: "a".to_string(),
            right: "b".to_string(),
        }];
        let mut solver = ConstraintSolver::new(vars, constraints);
        let solution = solver.solve();
        assert!(solution.satisfiable);
        let a = solution.assignments.get("a").unwrap().as_str().unwrap();
        let b = solution.assignments.get("b").unwrap().as_str().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_ac3_removes_inconsistent() {
        let vars = vec![
            ConstraintVariable::new("a", Domain::Discrete(vec!["x".to_string(), "y".to_string()])),
            ConstraintVariable::new("b", Domain::Discrete(vec!["x".to_string()])),
        ];
        let constraints = vec![Constraint::NotEqual {
            left: "a".to_string(),
            right: "b".to_string(),
        }];
        let mut solver = ConstraintSolver::new(vars, constraints);
        let consistent = solver.ac3();
        // After AC-3, "a" should only have "y" since "x" != "x" fails.
        assert!(consistent);
        if let Some(a_var) = solver.variables.get("a") {
            if let Domain::Discrete(ref vals) = a_var.domain {
                assert!(!vals.contains(&"x".to_string()));
            }
        }
    }

    // ── Policy Parser Tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_require() {
        let stmt = PolicyParser::parse(
            "REQUIRE ring.shield.trust > 0.8 WHEN risk.level >= 0.5"
        ).unwrap();
        assert_eq!(stmt.kind, PolicyKind::Require);
        assert_eq!(stmt.target, "ring.shield.trust");
        assert_eq!(stmt.constraint, CmpOp::Gt);
        assert!(stmt.when.is_some());
    }

    #[test]
    fn test_parse_forbid_unless() {
        let stmt = PolicyParser::parse(
            "FORBID ring.learning.data_retention > 86400 UNLESS compliance.gdpr.granted == true"
        ).unwrap();
        assert_eq!(stmt.kind, PolicyKind::Forbid);
        assert!(stmt.unless.is_some());
    }

    #[test]
    fn test_parse_ensure_priority() {
        let stmt = PolicyParser::parse(
            "ENSURE anomaly_detection.sensitivity >= 0.9 PRIORITY high"
        ).unwrap();
        assert_eq!(stmt.kind, PolicyKind::Ensure);
        assert_eq!(stmt.priority, PolicyPriority::High);
    }

    #[test]
    fn test_parse_duration_value() {
        let stmt = PolicyParser::parse(
            "REQUIRE session.timeout > 24h"
        ).unwrap();
        match stmt.threshold {
            PolicyValue::Duration(d) => assert_eq!(d.seconds, 86400),
            _ => panic!("Expected duration value"),
        }
    }

    #[test]
    fn test_evaluate_policy_expr_comparison() {
        let mut state = HashMap::new();
        state.insert(
            "ring.shield.trust".to_string(),
            serde_json::json!(0.9),
        );
        let expr = PolicyExpr::Comparison {
            field: "ring.shield.trust".to_string(),
            op: CmpOp::Gt,
            value: PolicyValue::Number(0.8),
        };
        assert!(evaluate_policy_expr(&expr, &state));
    }

    #[test]
    fn test_evaluate_policy_expr_and_or() {
        let mut state = HashMap::new();
        state.insert("a".to_string(), serde_json::json!(true));
        state.insert("b".to_string(), serde_json::json!(false));
        let expr = PolicyExpr::Binary {
            left: Box::new(PolicyExpr::Comparison {
                field: "a".to_string(),
                op: CmpOp::Eq,
                value: PolicyValue::Boolean(true),
            }),
            op: BoolOp::Or,
            right: Box::new(PolicyExpr::Comparison {
                field: "b".to_string(),
                op: CmpOp::Eq,
                value: PolicyValue::Boolean(true),
            }),
        };
        assert!(evaluate_policy_expr(&expr, &state));
    }

    #[test]
    fn test_evaluate_policy_not() {
        let mut state = HashMap::new();
        state.insert("a".to_string(), serde_json::json!(false));
        let expr = PolicyExpr::Not(Box::new(PolicyExpr::Comparison {
            field: "a".to_string(),
            op: CmpOp::Eq,
            value: PolicyValue::Boolean(true),
        }));
        assert!(evaluate_policy_expr(&expr, &state));
    }

    #[test]
    fn test_evaluate_policy_when_condition() {
        let stmt = PolicyParser::parse(
            "REQUIRE x > 0.8 WHEN y >= 1.0"
        ).unwrap();
        let mut state = HashMap::new();
        state.insert("x".to_string(), serde_json::json!(0.5));
        state.insert("y".to_string(), serde_json::json!(0.5));
        // WHEN condition is false → policy doesn't apply → None.
        assert_eq!(evaluate_policy(&stmt, &state), None);
    }

    // ── Schema Evolution Tests ───────────────────────────────────────────

    fn make_v1_schema() -> SchemaVersion {
        let mut schema = SchemaVersion::new(SemVer::new(1, 0, 0), "pipeline_config");
        schema.add_field(FieldDef {
            name: "trust_threshold".to_string(),
            field_type: FieldType::Float,
            required: true,
            default_value: Some(serde_json::json!(0.5)),
            min_value: Some(0.0),
            max_value: Some(1.0),
            description: "Trust threshold".to_string(),
        });
        schema.add_field(FieldDef {
            name: "mode".to_string(),
            field_type: FieldType::Enum(vec!["strict".to_string(), "relaxed".to_string()]),
            required: true,
            default_value: Some(serde_json::json!("strict")),
            min_value: None,
            max_value: None,
            description: "Operation mode".to_string(),
        });
        schema
    }

    fn make_v2_schema() -> SchemaVersion {
        let mut schema = SchemaVersion::new(SemVer::new(2, 0, 0), "pipeline_config");
        schema.add_field(FieldDef {
            name: "trust_threshold".to_string(),
            field_type: FieldType::Float,
            required: true,
            default_value: Some(serde_json::json!(0.7)),
            min_value: Some(0.5),
            max_value: Some(1.0),
            description: "Trust threshold (raised minimum)".to_string(),
        });
        schema.add_field(FieldDef {
            name: "mode".to_string(),
            field_type: FieldType::Enum(vec![
                "strict".to_string(),
                "relaxed".to_string(),
                "stealth".to_string(),
            ]),
            required: true,
            default_value: Some(serde_json::json!("strict")),
            min_value: None,
            max_value: None,
            description: "Operation mode".to_string(),
        });
        schema.add_field(FieldDef {
            name: "data_retention_hours".to_string(),
            field_type: FieldType::Int,
            required: false,
            default_value: Some(serde_json::json!(24)),
            min_value: Some(1.0),
            max_value: Some(720.0),
            description: "Data retention in hours".to_string(),
        });
        schema
    }

    #[test]
    fn test_schema_diff_detects_added_field() {
        let v1 = make_v1_schema();
        let v2 = make_v2_schema();
        let changes = SchemaEvolutionValidator::diff(&v1, &v2);
        let added: Vec<_> = changes.iter().filter(|c| c.kind == SchemaChangeKind::FieldAdded).collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].field_name, "data_retention_hours");
    }

    #[test]
    fn test_schema_diff_detects_tightened() {
        let v1 = make_v1_schema();
        let v2 = make_v2_schema();
        let changes = SchemaEvolutionValidator::diff(&v1, &v2);
        let tightened: Vec<_> = changes
            .iter()
            .filter(|c| c.kind == SchemaChangeKind::ConstraintTightened)
            .collect();
        assert!(!tightened.is_empty());
    }

    #[test]
    fn test_schema_migration_steps() {
        let v1 = make_v1_schema();
        let v2 = make_v2_schema();
        let steps = SchemaEvolutionValidator::compute_migration(&v1, &v2);
        assert!(!steps.is_empty());
        let has_add = steps.iter().any(|s| matches!(s, MigrationStep::AddField { .. }));
        assert!(has_add);
    }

    #[test]
    fn test_schema_validate_data() {
        let schema = make_v1_schema();
        let good_data = serde_json::json!({
            "trust_threshold": 0.8,
            "mode": "strict"
        });
        let errors = SchemaEvolutionValidator::validate_data(&schema, &good_data);
        assert!(errors.is_empty());

        let bad_data = serde_json::json!({
            "trust_threshold": -1.0,
            "mode": "strict"
        });
        let errors = SchemaEvolutionValidator::validate_data(&schema, &bad_data);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_schema_validate_missing_required() {
        let schema = make_v1_schema();
        let data = serde_json::json!({ "mode": "strict" });
        let errors = SchemaEvolutionValidator::validate_data(&schema, &data);
        assert!(errors.iter().any(|e| e.contains("missing")));
    }

    #[test]
    fn test_semver_parse() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    // ── Conflict Detection Tests ─────────────────────────────────────────

    #[test]
    fn test_detect_contradiction() {
        let mut p1 = PolicyParser::parse("REQUIRE x > 0.8").unwrap();
        let mut p2 = PolicyParser::parse("REQUIRE x < 0.6").unwrap();
        p1.target = "x".to_string();
        p2.target = "x".to_string();
        let policies = vec![p1, p2];
        let conflicts = PolicyConflictDetector::detect_conflicts(&policies);
        assert!(!conflicts.is_empty());
        assert_eq!(conflicts[0].conflict_type, ConflictType::Contradiction);
    }

    #[test]
    fn test_detect_redundancy() {
        let mut p1 = PolicyParser::parse("REQUIRE x > 0.9").unwrap();
        let mut p2 = PolicyParser::parse("REQUIRE x > 0.7").unwrap();
        p1.target = "x".to_string();
        p2.target = "x".to_string();
        let conflicts = PolicyConflictDetector::detect_conflicts(&[p1, p2]);
        let redundancies: Vec<_> = conflicts
            .iter()
            .filter(|c| c.conflict_type == ConflictType::Redundancy)
            .collect();
        assert!(!redundancies.is_empty());
    }

    #[test]
    fn test_no_conflict_different_targets() {
        let p1 = PolicyParser::parse("REQUIRE x > 0.8").unwrap();
        let p2 = PolicyParser::parse("REQUIRE y > 0.8").unwrap();
        let conflicts = PolicyConflictDetector::detect_conflicts(&[p1, p2]);
        assert!(conflicts.is_empty());
    }

    // ── Blueprint Validation Tests ───────────────────────────────────────

    fn make_simple_blueprint() -> OrchestrationBlueprint {
        OrchestrationBlueprint {
            id: "bp-001".to_string(),
            name: "test_blueprint".to_string(),
            version: SemVer::new(1, 0, 0),
            nodes: vec![
                BlueprintNode {
                    id: "ingress".to_string(),
                    name: "Ingress Filter".to_string(),
                    component_type: "filter".to_string(),
                    dependencies: vec![],
                    resource_requirements: ResourceRequirements {
                        memory_mb: 128,
                        cpu_cores: 0.5,
                        max_concurrent_connections: 100,
                        storage_mb: 10,
                    },
                    min_trust_level: 0.8,
                    configuration: HashMap::new(),
                },
                BlueprintNode {
                    id: "shield".to_string(),
                    name: "Shield Analyzer".to_string(),
                    component_type: "analyzer".to_string(),
                    dependencies: vec!["ingress".to_string()],
                    resource_requirements: ResourceRequirements {
                        memory_mb: 256,
                        cpu_cores: 1.0,
                        max_concurrent_connections: 50,
                        storage_mb: 100,
                    },
                    min_trust_level: 0.9,
                    configuration: HashMap::new(),
                },
            ],
            resource_limits: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_cores: 8.0,
                max_connections: 10000,
                max_storage_mb: 10000,
            },
            global_min_trust: 0.7,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_blueprint_valid() {
        let bp = make_simple_blueprint();
        let result = BlueprintValidator::validate(&bp);
        assert!(result.valid);
        assert_eq!(result.total_nodes, 2);
    }

    #[test]
    fn test_blueprint_cycle_detection() {
        let mut bp = make_simple_blueprint();
        bp.nodes[0].dependencies = vec!["shield".to_string()];
        bp.nodes[1].dependencies = vec!["ingress".to_string()];
        let cycle = BlueprintValidator::detect_cycle(&bp.nodes);
        assert!(cycle.is_some());
    }

    #[test]
    fn test_blueprint_no_cycle() {
        let bp = make_simple_blueprint();
        let cycle = BlueprintValidator::detect_cycle(&bp.nodes);
        assert!(cycle.is_none());
    }

    #[test]
    fn test_blueprint_missing_dependency() {
        let mut bp = make_simple_blueprint();
        bp.nodes[1].dependencies = vec!["nonexistent".to_string()];
        let result = BlueprintValidator::validate(&bp);
        let has_missing = result
            .issues
            .iter()
            .any(|i| i.category == "missing_dependency");
        assert!(has_missing);
    }

    #[test]
    fn test_blueprint_resource_exceeded() {
        let mut bp = make_simple_blueprint();
        bp.resource_limits = ResourceLimits {
            max_memory_mb: 64, // Less than 128 + 256
            max_cpu_cores: 0.1,
            max_connections: 1,
            max_storage_mb: 1,
        };
        let result = BlueprintValidator::validate(&bp);
        assert!(!result.valid);
        let has_resource = result
            .issues
            .iter()
            .any(|i| i.category == "resource_limit");
        assert!(has_resource);
    }

    #[test]
    fn test_trust_chain_verification() {
        let bp = make_simple_blueprint();
        let mut trust = HashMap::new();
        trust.insert("ingress".to_string(), 0.9);
        trust.insert("shield".to_string(), 0.5); // Below min 0.9
        let issues = BlueprintValidator::verify_trust_chain(&bp, &trust);
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.category == "trust_violation"));
    }

    #[test]
    fn test_orchestration_validator_full() {
        let solver = make_simple_solver();
        let policies = vec![
            PolicyParser::parse("REQUIRE ring.shield.trust > 0.5").unwrap(),
        ];
        let bp = make_simple_blueprint();
        let validator = OrchestrationValidator::new(solver, policies)
            .with_blueprint(bp);
        let mut validator = validator;
        let report = validator.validate();
        assert!(report.constraint_satisfiable);
    }

    #[test]
    fn test_duration_parse() {
        let d = Duration::from_str("24h").unwrap();
        assert_eq!(d.seconds, 86400);
        let d2 = Duration::from_str("30m").unwrap();
        assert_eq!(d2.seconds, 1800);
        let d3 = Duration::from_str("7d").unwrap();
        assert_eq!(d3.seconds, 604800);
        let d4 = Duration::from_str("500ms").unwrap();
        assert_eq!(d4.seconds, 0);
        let d5 = Duration::from_str("45s").unwrap();
        assert_eq!(d5.seconds, 45);
    }

    #[test]
    fn test_blueprint_depth() {
        let bp = make_simple_blueprint();
        let depth = BlueprintValidator::compute_max_depth(&bp.nodes);
        assert_eq!(depth, 2);
    }

    #[test]
    fn test_constraint_variables() {
        let v = ConstraintVariable::new(
            "test.var",
            Domain::Discrete(vec!["a".to_string(), "b".to_string()]),
        );
        assert!(!v.is_assigned());
        assert_eq!(v.domain_values().len(), 2);
    }
}
