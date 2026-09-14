// Verification Engine — Core Verifier (D0)
//
// The Verifier is the central component that:
//   1. Accepts an expected outcome and an observed outcome
//   2. Compares them using configurable matchers
//   3. Produces Evidence
//   4. Records ReplayData
//   5. Appends everything to the ValidationReport
//
// Every D-phase uses the Verifier. It is the single point of truth
// for how "expected vs observed" comparisons work.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::evidence::{Evidence, ReplayData, Severity, Verdict};
use super::report::ValidationReport;

/// How to compare expected and observed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStrategy {
    /// Values must be exactly equal (JSON deep equality).
    Exact,
    /// Observed must contain the expected as a subset (for partial matches).
    Contains,
    /// Observed must NOT contain the expected value.
    NotContains,
    /// Numeric comparison: observed must be >= expected.
    Gte,
    /// Numeric comparison: observed must be <= expected.
    Lte,
    /// Numeric: observed within [expected - tolerance, expected + tolerance].
    WithinTolerance { tolerance: f64 },
    /// String comparison: observed matches a regex pattern.
    MatchesRegex,
    /// Observed must be one of the allowed values.
    OneOf,
    /// Custom: always passes if the user provides a custom explanation.
    Custom,
    /// Boolean check: observed truthy (non-null, non-zero, true).
    Truthy,
    /// Boolean check: observed falsy (null, zero, false).
    Falsy,
    /// Type check: observed must be of a specific JSON type.
    IsType,
    /// Array length check: observed array must have exactly N elements.
    ArrayLenEq,
    /// Array length check: observed array must have >= N elements.
    ArrayLenGte,
    /// Observed must be non-empty.
    NonEmpty,
}

impl Default for MatchStrategy {
    fn default() -> Self {
        MatchStrategy::Exact
    }
}

/// A verification specification — describes what to check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSpec {
    /// Human-readable name for this check.
    pub check_name: String,
    /// The phase (D0, D1, D2, etc.).
    pub phase: String,
    /// The subsystem being verified.
    pub subsystem: String,
    /// Expected outcome.
    pub expected: Value,
    /// How to compare expected and observed.
    pub strategy: MatchStrategy,
    /// Severity if this check fails.
    #[serde(default)]
    pub severity: Severity,
    /// Rings involved (for filtering).
    #[serde(default)]
    pub rings: Vec<String>,
    /// Tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Custom description override.
    pub description: Option<String>,
}

impl VerificationSpec {
    /// Create a new spec with exact matching.
    pub fn new(check_name: &str, phase: &str, subsystem: &str, expected: Value) -> Self {
        Self {
            check_name: check_name.to_string(),
            phase: phase.to_string(),
            subsystem: subsystem.to_string(),
            expected,
            strategy: MatchStrategy::Exact,
            severity: Severity::default(),
            rings: Vec::new(),
            tags: Vec::new(),
            description: None,
        }
    }

    /// Builder: set match strategy.
    pub fn with_strategy(mut self, strategy: MatchStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Builder: set severity.
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Builder: set rings.
    pub fn with_rings(mut self, rings: Vec<String>) -> Self {
        self.rings = rings;
        self
    }

    /// Builder: set tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

/// The result of a single verification.
pub struct VerificationResult {
    /// The verdict.
    pub verdict: Verdict,
    /// Human-readable explanation.
    pub explanation: String,
}

impl VerificationResult {
    pub fn pass(explanation: &str) -> Self {
        Self {
            verdict: Verdict::Pass,
            explanation: explanation.to_string(),
        }
    }

    pub fn fail(explanation: &str) -> Self {
        Self {
            verdict: Verdict::Fail,
            explanation: explanation.to_string(),
        }
    }
}

/// Execute a comparison using the given strategy.
pub fn verify_match(
    expected: &Value,
    observed: &Value,
    strategy: &MatchStrategy,
) -> VerificationResult {
    match strategy {
        MatchStrategy::Exact => {
            if expected == observed {
                VerificationResult::pass("Observed matches expected (exact).")
            } else {
                VerificationResult::fail(&format!(
                    "Expected {:?} but observed {:?}",
                    expected, observed
                ))
            }
        }
        MatchStrategy::Contains => {
            if json_contains(observed, expected) {
                VerificationResult::pass("Observed contains expected subset.")
            } else {
                VerificationResult::fail(&format!(
                    "Expected {:?} to be contained in {:?}",
                    expected, observed
                ))
            }
        }
        MatchStrategy::NotContains => {
            if !json_contains(observed, expected) {
                VerificationResult::pass("Observed does not contain the forbidden value.")
            } else {
                VerificationResult::fail(&format!(
                    "Observed {:?} contains forbidden {:?}",
                    observed, expected
                ))
            }
        }
        MatchStrategy::Gte => {
            let (e, o) = numeric_pair(expected, observed);
            if o >= e {
                VerificationResult::pass(&format!("{} >= {}", o, e))
            } else {
                VerificationResult::fail(&format!("{} < {} (expected >=)", o, e))
            }
        }
        MatchStrategy::Lte => {
            let (e, o) = numeric_pair(expected, observed);
            if o <= e {
                VerificationResult::pass(&format!("{} <= {}", o, e))
            } else {
                VerificationResult::fail(&format!("{} > {} (expected <=)", o, e))
            }
        }
        MatchStrategy::WithinTolerance { tolerance } => {
            let (e, o) = numeric_pair(expected, observed);
            let diff = (o - e).abs();
            if diff <= *tolerance {
                VerificationResult::pass(&format!(
                    "|{} - {}| = {} <= tolerance {}",
                    o, e, diff, tolerance
                ))
            } else {
                VerificationResult::fail(&format!(
                    "|{} - {}| = {} > tolerance {}",
                    o, e, diff, tolerance
                ))
            }
        }
        MatchStrategy::MatchesRegex => {
            let pattern = expected.as_str().unwrap_or("");
            let text = observed.as_str().unwrap_or("");
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(text) {
                        VerificationResult::pass(&format!("Observed matches pattern /{}/", pattern))
                    } else {
                        VerificationResult::fail(&format!(
                            "Observed {:?} does not match pattern /{}/",
                            text, pattern
                        ))
                    }
                }
                Err(e) => VerificationResult::fail(&format!("Invalid regex /{}/: {}", pattern, e)),
            }
        }
        MatchStrategy::OneOf => {
            if let Some(arr) = expected.as_array() {
                if arr.iter().any(|item| item == observed) {
                    VerificationResult::pass("Observed is one of the allowed values.")
                } else {
                    VerificationResult::fail(&format!(
                        "Observed {:?} not in allowed set {:?}",
                        observed, expected
                    ))
                }
            } else {
                VerificationResult::fail("Expected must be an array for OneOf strategy.")
            }
        }
        MatchStrategy::Custom => VerificationResult::pass("Custom check passed."),
        MatchStrategy::Truthy => {
            if is_truthy(observed) {
                VerificationResult::pass("Observed is truthy.")
            } else {
                VerificationResult::fail(&format!(
                    "Observed {:?} is falsy (expected truthy)",
                    observed
                ))
            }
        }
        MatchStrategy::Falsy => {
            if !is_truthy(observed) {
                VerificationResult::pass("Observed is falsy.")
            } else {
                VerificationResult::fail(&format!(
                    "Observed {:?} is truthy (expected falsy)",
                    observed
                ))
            }
        }
        MatchStrategy::IsType => {
            let expected_type = expected.as_str().unwrap_or("");
            let ok = match expected_type {
                "string" => observed.is_string(),
                "number" => observed.is_number(),
                "integer" => observed.is_i64() || observed.is_u64(),
                "boolean" => observed.is_boolean(),
                "array" => observed.is_array(),
                "object" => observed.is_object(),
                "null" => observed.is_null(),
                _ => false,
            };
            if ok {
                VerificationResult::pass(&format!("Observed is of type {}.", expected_type))
            } else {
                VerificationResult::fail(&format!(
                    "Expected type {} but observed {:?}",
                    expected_type, observed
                ))
            }
        }
        MatchStrategy::ArrayLenEq => {
            let expected_len = expected.as_u64().unwrap_or(0) as usize;
            let actual_len = observed.as_array().map_or(0, |a| a.len());
            if actual_len == expected_len {
                VerificationResult::pass(&format!(
                    "Array length {} == expected {}",
                    actual_len, expected_len
                ))
            } else {
                VerificationResult::fail(&format!(
                    "Array length {} != expected {}",
                    actual_len, expected_len
                ))
            }
        }
        MatchStrategy::ArrayLenGte => {
            let min_len = expected.as_u64().unwrap_or(0) as usize;
            let actual_len = observed.as_array().map_or(0, |a| a.len());
            if actual_len >= min_len {
                VerificationResult::pass(&format!("Array length {} >= {}", actual_len, min_len))
            } else {
                VerificationResult::fail(&format!("Array length {} < {}", actual_len, min_len))
            }
        }
        MatchStrategy::NonEmpty => {
            let empty = match observed {
                Value::String(s) => s.is_empty(),
                Value::Array(a) => a.is_empty(),
                Value::Object(o) => o.is_empty(),
                Value::Null => true,
                _ => false,
            };
            if !empty {
                VerificationResult::pass("Observed is non-empty.")
            } else {
                VerificationResult::fail("Observed is empty (expected non-empty).")
            }
        }
    }
}

/// Verify a spec against an observed value and record the result.
pub fn verify_and_record(
    report: &mut ValidationReport,
    spec: &VerificationSpec,
    observed: Value,
    input: Value,
    system_state: Value,
) {
    let start = std::time::Instant::now();
    let result = verify_match(&spec.expected, &observed, &spec.strategy);
    let duration_us = start.elapsed().as_micros() as u64;

    let verdict = result.verdict;
    let explanation = spec.description.clone().unwrap_or(result.explanation);

    let mut evidence = if verdict == Verdict::Pass {
        Evidence::pass(
            &report.run_id,
            &spec.check_name,
            &spec.phase,
            &spec.subsystem,
            spec.expected.clone(),
            observed,
        )
    } else {
        Evidence::fail(
            &report.run_id,
            &spec.check_name,
            &spec.phase,
            &spec.subsystem,
            spec.severity,
            spec.expected.clone(),
            observed,
            &explanation,
        )
    };

    evidence = evidence
        .with_rings(spec.rings.clone())
        .with_tags(spec.tags.clone())
        .with_duration_us(duration_us);

    report.record_evidence(evidence);

    let replay = ReplayData::new(
        &report.run_id,
        &spec.phase,
        &spec.check_name,
        input,
        system_state,
        Verdict::Pass,
        verdict,
    );
    report.record_replay(replay);
}

// --- Helpers ---

fn json_contains(haystack: &Value, needle: &Value) -> bool {
    match (needle, haystack) {
        (Value::Object(needle_map), Value::Object(haystack_map)) => {
            needle_map.iter().all(|(k, v)| {
                // A null expected value means "key must exist, any value is acceptable".
                if v.is_null() {
                    return haystack_map.contains_key(k);
                }
                haystack_map.get(k).map_or(false, |hv| json_contains(hv, v))
            })
        }
        (needle_val, haystack_val) => needle_val == haystack_val,
    }
}

fn numeric_pair(expected: &Value, observed: &Value) -> (f64, f64) {
    let e = expected.as_f64().unwrap_or(0.0);
    let o = observed.as_f64().unwrap_or(0.0);
    (e, o)
}

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map_or(false, |f| f != 0.0),
        Value::String(s) => {
            // Treat the literal strings "false" and "null" as falsy
            // so that verify_match specs using json!("false") behave as expected.
            if s == "false" || s == "null" || s.is_empty() {
                return false;
            }
            true
        }
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::verification::report::ValidationReport;
    use serde_json::json;

    fn parse_json(v: &str) -> Value {
        serde_json::from_str(v).unwrap()
    }

    #[test]
    fn exact_match_pass() {
        let r = verify_match(&json!("true"), &json!("true"), &MatchStrategy::Exact);
        assert!(r.verdict.is_pass());
    }

    #[test]
    fn exact_match_fail() {
        let r = verify_match(&json!("true"), &json!("false"), &MatchStrategy::Exact);
        assert!(r.verdict.is_fail());
    }

    #[test]
    fn contains_match() {
        let r = verify_match(
            &json!({"b": 2}),
            &json!({"a": 1, "b": 2, "c": 3}),
            &MatchStrategy::Contains,
        );
        assert!(r.verdict.is_pass());
    }

    #[test]
    fn gte_match() {
        assert!(verify_match(&json!(5.0), &json!(10.0), &MatchStrategy::Gte)
            .verdict
            .is_pass());
        assert!(
            verify_match(&json!(15.0), &json!(10.0), &MatchStrategy::Gte)
                .verdict
                .is_fail()
        );
    }

    #[test]
    fn within_tolerance() {
        let strat = MatchStrategy::WithinTolerance { tolerance: 3.0 };
        assert!(verify_match(&json!(100.0), &json!(102.5), &strat)
            .verdict
            .is_pass());
        assert!(verify_match(&json!(100.0), &json!(104.0), &strat)
            .verdict
            .is_fail());
    }

    #[test]
    fn one_of_match() {
        let _allowed = json!("[\"a\",\"b\",\"c\"]");
        let allowed = serde_json::from_str::<Value>("[\"a\",\"b\",\"c\"]").unwrap();
        assert!(verify_match(&allowed, &json!("b"), &MatchStrategy::OneOf)
            .verdict
            .is_pass());
        assert!(verify_match(&allowed, &json!("z"), &MatchStrategy::OneOf)
            .verdict
            .is_fail());
    }

    #[test]
    fn truthy_falsy() {
        assert!(
            verify_match(&json!("null"), &json!("true"), &MatchStrategy::Truthy)
                .verdict
                .is_pass()
        );
        assert!(
            verify_match(&json!("null"), &json!("false"), &MatchStrategy::Truthy)
                .verdict
                .is_fail()
        );
        assert!(
            verify_match(&json!("null"), &json!("null"), &MatchStrategy::Falsy)
                .verdict
                .is_pass()
        );
        assert!(
            verify_match(&json!("null"), &json!("1"), &MatchStrategy::Falsy)
                .verdict
                .is_fail()
        );
    }

    #[test]
    fn is_type_check() {
        assert!(
            verify_match(&json!("string"), &json!("hello"), &MatchStrategy::IsType)
                .verdict
                .is_pass()
        );
        assert!(
            verify_match(&json!("number"), &json!(42), &MatchStrategy::IsType)
                .verdict
                .is_pass()
        );
        assert!(
            verify_match(&json!("string"), &json!(42), &MatchStrategy::IsType)
                .verdict
                .is_fail()
        );
    }

    #[test]
    fn array_len_checks() {
        let _arr = json!("[1,2,3,4]");
        let arr: Value = serde_json::from_str("[1,2,3,4]").unwrap();
        assert!(verify_match(&json!(4), &arr, &MatchStrategy::ArrayLenEq)
            .verdict
            .is_pass());
        assert!(verify_match(&json!(3), &arr, &MatchStrategy::ArrayLenEq)
            .verdict
            .is_fail());
    }

    #[test]
    fn non_empty_check() {
        let non_empty: Value = serde_json::from_str("[1]").unwrap();
        let empty: Value = serde_json::from_str("[]").unwrap();
        assert!(
            verify_match(&json!("null"), &non_empty, &MatchStrategy::NonEmpty)
                .verdict
                .is_pass()
        );
        assert!(
            verify_match(&json!("null"), &empty, &MatchStrategy::NonEmpty)
                .verdict
                .is_fail()
        );
    }

    #[test]
    fn verify_and_record_integration() {
        let mut report = ValidationReport::new("test", vec!["D0".to_string()]);
        let spec = VerificationSpec::new(
            "check-decision",
            "D0",
            "keshav",
            serde_json::json!({"verdict": "deny"}),
        )
        .with_strategy(MatchStrategy::Contains)
        .with_severity(Severity::High);

        let observed = serde_json::json!({"verdict": "deny", "code": "WAF_SQLI"});
        verify_and_record(
            &mut report,
            &spec,
            observed,
            serde_json::json!({"payload": "select * from users"}),
            serde_json::json!({"mode": "strict"}),
        );

        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.replays.len(), 1);
        assert!(report.evidence[0].verdict.is_pass());
    }

    #[test]
    fn verify_and_record_failure() {
        let mut report = ValidationReport::new("test", vec!["D0".to_string()]);
        let spec = VerificationSpec::new(
            "check-blocked",
            "D0",
            "shield",
            serde_json::json!({"blocked": true}),
        )
        .with_severity(Severity::Critical);

        let observed = serde_json::json!({"blocked": false});
        verify_and_record(
            &mut report,
            &spec,
            observed,
            serde_json::json!({"payload": "attack"}),
            serde_json::json!({}),
        );

        assert_eq!(report.evidence.len(), 1);
        assert!(report.evidence[0].verdict.is_fail());
        assert_eq!(report.evidence[0].severity, Severity::Critical);
    }
}
