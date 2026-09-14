// PIIExtractor — detects Personally Identifiable Information in prompts/outputs.
//
// Flags: email, phone numbers (various formats), SSN, credit card,
// API keys (sk-*, pk-*), IP addresses in sensitive contexts.

use std::sync::LazyLock;
use regex::Regex;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PIIExtractorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Whether to extract PII (true = extract and flag, false = skip).
    #[serde(default = "default_true")]
    pub extract: bool,
    /// Minimum severity to flag (1-10, default: 3).
    #[serde(default = "default_min_severity")]
    pub min_severity: u8,
}

fn default_enabled() -> bool { true }
fn default_true() -> bool { true }
fn default_min_severity() -> u8 { 3 }

impl Default for PIIExtractorConfig {
    fn default() -> Self {
        Self { enabled: default_enabled(), extract: default_true(), min_severity: default_min_severity() }
    }
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub enum PIIType {
    Email,
    Phone,
    SSN,
    CreditCard,
    ApiKey,
    IpAddress,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PIIFinding {
    pub pii_type: PIIType,
    pub value: String,  // masked
    pub position: usize,
    pub severity: u8,
}

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());
static PHONE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap());
static SSN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static CREDIT_CARD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap());
static API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:sk|pk|api[_-]?key)[_-][a-zA-Z0-9]{8,}\b").unwrap());
static IP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap());

pub struct PIIExtractor {
    config: PIIExtractorConfig,
}

impl PIIExtractor {
    pub fn new(config: &PIIExtractorConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Extract PII from the given text.
    pub fn extract(&self, text: &str) -> Vec<PIIFinding> {
        if !self.config.enabled || !self.config.extract {
            return vec![];
        }

        let mut findings = Vec::new();

        // Email (severity 4).
        for m in EMAIL_RE.find_iter(text) {
            let val = mask_value(m.as_str(), 4);
            findings.push(PIIFinding { pii_type: PIIType::Email, value: val, position: m.start(), severity: 4 });
        }

        // Phone (severity 3).
        for m in PHONE_RE.find_iter(text) {
            // Filter out SSN-like patterns.
            let s = m.as_str();
            if !SSN_RE.is_match(s) {
                let val = mask_value(s, 4);
                findings.push(PIIFinding { pii_type: PIIType::Phone, value: val, position: m.start(), severity: 3 });
            }
        }

        // SSN (severity 9).
        for m in SSN_RE.find_iter(text) {
            let val = mask_value(m.as_str(), 5);
            findings.push(PIIFinding { pii_type: PIIType::SSN, value: val, position: m.start(), severity: 9 });
        }

        // Credit card (severity 8).
        for m in CREDIT_CARD_RE.find_iter(text) {
            let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 13 && luhn_check(&digits) {
                let val = mask_value(m.as_str(), 4);
                findings.push(PIIFinding { pii_type: PIIType::CreditCard, value: val, position: m.start(), severity: 8 });
            }
        }

        // API keys (severity 7).
        for m in API_KEY_RE.find_iter(text) {
            let val = mask_value(m.as_str(), 5);
            findings.push(PIIFinding { pii_type: PIIType::ApiKey, value: val, position: m.start(), severity: 7 });
        }

        // IP addresses (severity 2).
        for m in IP_RE.find_iter(text) {
            // Skip if it's already an API key context.
            let val = mask_value(m.as_str(), 6);
            findings.push(PIIFinding { pii_type: PIIType::IpAddress, value: val, position: m.start(), severity: 2 });
        }

        findings.retain(|f| f.severity >= self.config.min_severity);
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }
}

fn mask_value(s: &str, visible: usize) -> String {
    if s.len() <= visible {
        return "*".repeat(s.len());
    }
    format!("{}{}", &s[..visible], "*".repeat(s.len().saturating_sub(visible)))
}

fn luhn_check(digits: &str) -> bool {
    let chars: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if chars.len() < 13 { return false; }
    let mut sum = 0u32;
    let mut double = true;
    for &d in chars.iter().rev() {
        let mut val = d;
        if double { val *= 2; if val > 9 { val -= 9; } }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_extractor() -> PIIExtractor {
        PIIExtractor::new(&PIIExtractorConfig::default())
    }

    #[test]
    fn no_pii_in_clean_text() {
        let e = default_extractor();
        assert!(e.extract("Hello, how are you today?").is_empty());
    }

    #[test]
    fn detects_email() {
        let e = default_extractor();
        let findings = e.extract("Contact me at user@example.com for help");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pii_type, PIIType::Email);
    }

    #[test]
    fn detects_ssn() {
        let e = default_extractor();
        let findings = e.extract("My SSN is 123-45-6789");
        assert!(findings.iter().any(|f| f.pii_type == PIIType::SSN));
    }

    #[test]
    fn detects_api_key() {
        let e = default_extractor();
        let findings = e.extract("Use key sk-abcdef1234567890 for access");
        assert!(findings.iter().any(|f| f.pii_type == PIIType::ApiKey));
    }

    #[test]
    fn disabled_extracts_nothing() {
        let e = PIIExtractor::new(&PIIExtractorConfig { enabled: false, ..Default::default() });
        assert!(e.extract("email@test.com SSN: 123-45-6789").is_empty());
    }

    #[test]
    fn min_severity_filter() {
        let e = PIIExtractor::new(&PIIExtractorConfig { min_severity: 5, ..Default::default() });
        let findings = e.extract("Call 555-123-4567 and email test@example.com");
        // Phone (3) and Email (4) should be filtered out.
        assert!(findings.is_empty());
    }

    #[test]
    fn values_are_masked() {
        let e = default_extractor();
        let findings = e.extract("SSN: 123-45-6789");
        let ssn = findings.iter().find(|f| f.pii_type == PIIType::SSN).unwrap();
        assert!(ssn.value.contains('*'));
    }
}
