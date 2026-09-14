// Decision types — the output of every CHAKRAVYUH evaluation.
//
// Every ring returns a Verdict. Keshav combines ring verdicts into
// a final Decision. Every Decision is logged as a DecisionRecord.

use serde::{Deserialize, Serialize};

/// The final decision for a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    /// Request is allowed to proceed.
    Allow,

    /// Request is blocked.
    Deny {
        /// Machine-readable code (e.g., "WAF_SQL_INJECTION")
        code: String,
        /// Seconds to wait before retrying (for rate limits)
        retry_after: Option<u32>,
    },

    /// Request requires a challenge (CAPTCHA, JS challenge, etc.)
    Challenge { challenge_type: ChallengeType },

    /// Request requires human approval before proceeding.
    #[serde(rename = "escalate")]
    Escalate {
        /// Who needs to approve
        approver_role: String,
        /// Timeout in seconds
        timeout_secs: u64,
    },
}

impl Decision {
    /// Returns true if the decision allows the request to proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Returns true if the decision blocks the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// Returns a string representation suitable for HTTP status codes.
    pub fn http_status(&self) -> u16 {
        match self {
            Decision::Allow => 200,
            Decision::Deny { .. } => 403,
            Decision::Challenge { .. } => 401,
            Decision::Escalate { .. } => 202,
        }
    }
}

/// Type of challenge required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// JavaScript challenge (proof-of-work)
    Javascript,
    /// CAPTCHA challenge
    Captcha,
    /// Two-factor authentication
    TwoFactor,
    /// Email verification
    EmailVerification,
}

/// A risk score returned by Keshav-Risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall: f64,
    pub threat: f64,
    pub identity: f64,
    pub behavior: f64,
    pub memory: f64,
    pub execution: f64,
    pub context: f64,
    pub confidence: f64,
}

impl Default for RiskScore {
    fn default() -> Self {
        Self {
            overall: 0.0,
            threat: 0.0,
            identity: 0.0,
            behavior: 0.0,
            memory: 0.0,
            execution: 0.0,
            context: 0.0,
            confidence: 1.0,
        }
    }
}

/// Trait for ring verdicts.
pub trait Verdict {
    fn decision(&self) -> &Decision;
    fn latency_ms(&self) -> f64;
}

/// A complete decision record, logged for every evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub request_id: String,
    pub timestamp: String, // ISO 8601
    pub source: DecisionSource,
    pub risk_score: RiskScore,
    pub rings_evaluated: Vec<u8>,
    pub ring_verdicts: serde_json::Value,
    pub policy_applied: Option<String>,
    pub final_decision: Decision,
    pub reasoning: String,
    pub latency_ms: f64,
    pub keshav_version: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionSource {
    pub ip: String,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub api_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_serialization() {
        let d = Decision::Deny {
            code: "WAF_SQL_INJECTION".into(),
            retry_after: None,
        };
        let json = serde_json::to_string(&d).unwrap();
        let d2: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn test_decision_helpers() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_deny());

        let deny = Decision::Deny {
            code: "X".into(),
            retry_after: None,
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
    }

    #[test]
    fn test_http_status() {
        assert_eq!(Decision::Allow.http_status(), 200);
        assert_eq!(
            Decision::Deny {
                code: "X".into(),
                retry_after: None
            }
            .http_status(),
            403
        );
    }
}
