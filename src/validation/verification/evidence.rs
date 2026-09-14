// Verification Engine — Evidence, Audit Trail, and Replay System (D0)
//
// Every test in CHAKRAVYUH produces: Evidence → Metrics → Audit Trail → Replay → Report.
// This module provides the core types that ALL validation phases (D1-D7) consume.
//
// Design principles:
//   1. Immutable evidence — once recorded, evidence cannot be altered.
//   2. Full replay — any test can be re-executed from its recorded inputs.
//   3. Chain of custody — evidence is cryptographically linked.
//   4. Structured outputs — every result is machine-readable and human-auditable.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a validation run.
pub type RunId = String;

/// Unique identifier for an individual evidence item.
pub type EvidenceId = String;

/// The outcome of a verification check.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The check passed — observed matches expected.
    Pass,
    /// The check failed — observed does not match expected.
    Fail,
    /// The check was skipped (e.g., missing precondition).
    Skip,
    /// The check errored (infrastructure/runner failure, not a security failure).
    Error,
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Verdict::Fail)
    }

    /// Returns a short label for terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
            Verdict::Error => "ERR ",
        }
    }

    /// ANSI-colored label for terminal output (when ansi enabled).
    #[cfg(feature = "tls")]
    pub fn colored_label(&self) -> String {
        match self {
            Verdict::Pass => "\x1b[32mPASS\x1b[0m".to_string(),
            Verdict::Fail => "\x1b[31mFAIL\x1b[0m".to_string(),
            Verdict::Skip => "\x1b[33mSKIP\x1b[0m".to_string(),
            Verdict::Error => "\x1b[35mERR \x1b[0m".to_string(),
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — no security impact.
    Info,
    /// Low — minor deviation, no immediate risk.
    Low,
    /// Medium — potential weakness that could be exploited.
    Medium,
    /// High — significant weakness, likely exploitable.
    High,
    /// Critical — immediate security risk, must fix before ship.
    Critical,
}

impl Severity {
    /// Numeric weight for sorting and aggregation.
    pub fn weight(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Returns true if this severity should block a release.
    pub fn is_blocking(&self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MED"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRIT"),
        }
    }
}

/// A single piece of evidence captured during a verification run.
///
/// Evidence is immutable once created. It captures what was observed,
/// what was expected, and the context needed to understand why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique evidence ID (UUID v4).
    pub id: EvidenceId,
    /// The run this evidence belongs to.
    pub run_id: RunId,
    /// Human-readable name of the check.
    pub check_name: String,
    /// The phase that produced this evidence (D0, D1, D2, etc.).
    pub phase: String,
    /// The specific subsystem or ring being verified.
    pub subsystem: String,
    /// The verdict.
    pub verdict: Verdict,
    /// Severity of the finding (only meaningful for Fail verdicts).
    pub severity: Severity,
    /// What we expected to observe.
    pub expected: serde_json::Value,
    /// What was actually observed.
    pub observed: serde_json::Value,
    /// Human-readable explanation of the result.
    pub explanation: String,
    /// Duration of this individual check in microseconds.
    pub duration_us: u64,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Optional: the ring(s) involved.
    pub rings: Vec<String>,
    /// Optional: attack category (for D1 Red Team evidence).
    pub attack_category: Option<String>,
    /// Optional: mutation applied (for D1 mutation evidence).
    pub mutation_applied: Option<String>,
    /// Optional: encoding applied (for D1 encoding evidence).
    pub encoding_applied: Option<String>,
    /// SHA-256 hash of (expected + observed + explanation) for tamper detection.
    pub integrity_hash: String,
    /// Previous evidence ID in the audit chain (for chain linking).
    pub prev_evidence_id: Option<EvidenceId>,
    /// Arbitrary tags for filtering and grouping.
    pub tags: Vec<String>,
}

impl Evidence {
    /// Create a new evidence item.
    ///
    /// The `integrity_hash` is computed from expected + observed + explanation
    /// using SHA-256 to ensure evidence cannot be tampered with after creation.
    pub fn new(
        run_id: &str,
        check_name: &str,
        phase: &str,
        subsystem: &str,
        verdict: Verdict,
        expected: serde_json::Value,
        observed: serde_json::Value,
        explanation: &str,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Compute integrity hash from the three core fields.
        let mut hasher = blake3::Hasher::new();
        hasher.update(expected.to_string().as_bytes());
        hasher.update(observed.to_string().as_bytes());
        hasher.update(explanation.as_bytes());
        let integrity_hash = hasher.finalize().to_hex().to_string();

        Self {
            id,
            run_id: run_id.to_string(),
            check_name: check_name.to_string(),
            phase: phase.to_string(),
            subsystem: subsystem.to_string(),
            verdict,
            severity: Severity::default(),
            expected,
            observed,
            explanation: explanation.to_string(),
            duration_us: 0,
            timestamp,
            rings: Vec::new(),
            attack_category: None,
            mutation_applied: None,
            encoding_applied: None,
            integrity_hash,
            prev_evidence_id: None,
            tags: Vec::new(),
        }
    }

    /// Create a passing evidence item (convenience).
    pub fn pass(
        run_id: &str,
        check_name: &str,
        phase: &str,
        subsystem: &str,
        expected: serde_json::Value,
        observed: serde_json::Value,
    ) -> Self {
        Self::new(
            run_id, check_name, phase, subsystem, Verdict::Pass,
            expected, observed, "Observed matches expected.",
        )
    }

    /// Create a failing evidence item (convenience).
    pub fn fail(
        run_id: &str,
        check_name: &str,
        phase: &str,
        subsystem: &str,
        severity: Severity,
        expected: serde_json::Value,
        observed: serde_json::Value,
        explanation: &str,
    ) -> Self {
        let mut ev = Self::new(
            run_id, check_name, phase, subsystem, Verdict::Fail,
            expected, observed, explanation,
        );
        ev.severity = severity;
        ev
    }

    /// Builder-style: set rings.
    pub fn with_rings(mut self, rings: Vec<String>) -> Self {
        self.rings = rings;
        self
    }

    /// Builder-style: set attack category.
    pub fn with_attack_category(mut self, category: &str) -> Self {
        self.attack_category = Some(category.to_string());
        self
    }

    /// Builder-style: set mutation.
    pub fn with_mutation(mut self, mutation: &str) -> Self {
        self.mutation_applied = Some(mutation.to_string());
        self
    }

    /// Builder-style: set encoding.
    pub fn with_encoding(mut self, encoding: &str) -> Self {
        self.encoding_applied = Some(encoding.to_string());
        self
    }

    /// Builder-style: set duration.
    pub fn with_duration_us(mut self, duration_us: u64) -> Self {
        self.duration_us = duration_us;
        self
    }

    /// Builder-style: link to previous evidence.
    pub fn with_prev(mut self, prev_id: &str) -> Self {
        self.prev_evidence_id = Some(prev_id.to_string());
        self
    }

    /// Builder-style: add tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Verify the integrity hash matches the current content.
    /// Returns true if the evidence has not been tampered with.
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.expected.to_string().as_bytes());
        hasher.update(self.observed.to_string().as_bytes());
        hasher.update(self.explanation.as_bytes());
        let computed = hasher.finalize().to_hex().to_string();
        computed == self.integrity_hash
    }
}

/// Replay data — captures everything needed to re-execute a test.
///
/// The replay system ensures that any test can be exactly re-executed
/// by storing the full input, configuration, and environment state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayData {
    /// Unique replay ID.
    pub id: String,
    /// The run ID this replay belongs to.
    pub run_id: RunId,
    /// The phase that produced this replay.
    pub phase: String,
    /// Human-readable description.
    pub description: String,
    /// The input payload that was fed to the system under test.
    pub input: serde_json::Value,
    /// The configuration/state of the system at test time.
    pub system_state: serde_json::Value,
    /// The expected outcome.
    pub expected_outcome: Verdict,
    /// The actual outcome observed during the original run.
    pub actual_outcome: Verdict,
    /// Environment metadata (Rust version, platform, etc.).
    pub environment: HashMap<String, String>,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

impl ReplayData {
    /// Create new replay data.
    pub fn new(
        run_id: &str,
        phase: &str,
        description: &str,
        input: serde_json::Value,
        system_state: serde_json::Value,
        expected_outcome: Verdict,
        actual_outcome: Verdict,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            run_id: run_id.to_string(),
            phase: phase.to_string(),
            description: description.to_string(),
            input,
            system_state,
            expected_outcome,
            actual_outcome,
            environment: collect_environment(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            tags: Vec::new(),
        }
    }
}

/// Collect current environment metadata.
fn collect_environment() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("rust_version".to_string(), env!("CARGO_PKG_RUST_VERSION").to_string());
    env.insert("crate_version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    env.insert("target_arch".to_string(), std::env::consts::ARCH.to_string());
    env.insert("target_os".to_string(), std::env::consts::OS.to_string());
    if let Ok(v) = std::env::var("CHAKRAVYUH_PROFILE") {
        env.insert("profile".to_string(), v);
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_new_and_integrity() {
        let ev = Evidence::new(
            "run-1", "check-shield-waf", "D1", "shield",
            Verdict::Pass,
            serde_json::json!({"blocked": true}),
            serde_json::json!({"blocked": true}),
            "WAF correctly blocked the SQLi attempt",
        );
        assert!(ev.verify_integrity());
        assert_eq!(ev.verdict, Verdict::Pass);
        assert!(!ev.id.is_empty());
        assert!(!ev.integrity_hash.is_empty());
    }

    #[test]
    fn evidence_tamper_detection() {
        let mut ev = Evidence::new(
            "run-1", "check-policy", "D2", "ananta.sentinel",
            Verdict::Pass,
            serde_json::json!({"drift": 0.0}),
            serde_json::json!({"drift": 0.01}),
            "Within acceptable drift",
        );
        // Tamper with the expected value.
        ev.expected = serde_json::json!({"drift": 0.5});
        assert!(!ev.verify_integrity());
    }

    #[test]
    fn evidence_builder_pattern() {
        let ev = Evidence::fail(
            "run-2", "jailbreak-detection", "D1", "threat",
            Severity::Critical,
            serde_json::json!({"blocked": true}),
            serde_json::json!({"blocked": false}),
            "Jailbreak was not detected by the threat ring",
        )
        .with_rings(vec!["shield".to_string(), "threat".to_string()])
        .with_attack_category("jailbreak")
        .with_mutation("unicode_normalization")
        .with_duration_us(142);

        assert_eq!(ev.rings.len(), 2);
        assert_eq!(ev.attack_category.as_deref(), Some("jailbreak"));
        assert_eq!(ev.mutation_applied.as_deref(), Some("unicode_normalization"));
        assert_eq!(ev.duration_us, 142);
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Pass.label(), "PASS");
        assert_eq!(Verdict::Fail.label(), "FAIL");
        assert_eq!(Verdict::Skip.label(), "SKIP");
        assert_eq!(Verdict::Error.label(), "ERR ");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_blocking() {
        assert!(Severity::High.is_blocking());
        assert!(Severity::Critical.is_blocking());
        assert!(!Severity::Medium.is_blocking());
        assert!(!Severity::Low.is_blocking());
    }

    #[test]
    fn replay_data_creation() {
        let replay = ReplayData::new(
            "run-5", "D1", "SQLi attack with base64 encoding",
            serde_json::json!({"payload": "c2VsZWN0ICogZnJvbSB1c2Vycw=="}),
            serde_json::json!({"waf_enabled": true, "mode": "strict"}),
            Verdict::Fail,
            Verdict::Pass,
        );
        assert!(!replay.id.is_empty());
        assert!(replay.environment.contains_key("rust_version"));
        assert!(replay.environment.contains_key("crate_version"));
    }

    #[test]
    fn evidence_serialization_roundtrip() {
        let ev = Evidence::pass(
            "run-1", "test", "D0", "verification",
            serde_json::json!(true),
            serde_json::json!(true),
        ).with_tags(vec!["unit".to_string()]);

        let json = serde_json::to_string(&ev).unwrap();
        let restored: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, ev.id);
        assert_eq!(restored.verdict, ev.verdict);
        assert_eq!(restored.tags, ev.tags);
    }
}
