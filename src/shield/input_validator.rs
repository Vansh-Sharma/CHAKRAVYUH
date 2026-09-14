// Input Validator — Shield Ring Engine #1
//
// Validates that incoming requests conform to expected schema and format.
// Catches malformed, oversized, or structurally invalid requests before
// they consume resources in deeper engines.
//
// Latency Budget: 0.5ms p99
// Architecture Principle: Fail Secure (invalid input = DENY)

use crate::shield::{EngineResult, ShieldRequest};
use crate::{decision::Decision, Result};

/// Configuration for the Input Validator engine.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct InputValidatorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_max_prompt_length")]
    pub max_prompt_length: usize,

    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,

    #[serde(default = "default_max_messages")]
    pub max_messages: usize,

    #[serde(default)]
    pub required_fields: Vec<String>,
}

fn default_enabled() -> bool {
    true
}
fn default_max_prompt_length() -> usize {
    32_000
}
fn default_max_tokens() -> usize {
    8_000
}
fn default_max_messages() -> usize {
    100
}

impl Default for InputValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_prompt_length: default_max_prompt_length(),
            max_tokens: default_max_tokens(),
            max_messages: default_max_messages(),
            required_fields: vec!["model".into(), "messages".into()],
        }
    }
}

/// The Input Validator engine.
pub struct InputValidator {
    config: InputValidatorConfig,
}

impl InputValidator {
    pub fn new(shield_config: &crate::config::ShieldConfig) -> Result<Self> {
        Ok(Self {
            config: shield_config.input_validator.clone(),
        })
    }

    /// Evaluate the request.
    ///
    /// Returns ALLOW if the request is structurally valid, DENY otherwise.
    pub fn evaluate(&self, request: &ShieldRequest) -> EngineResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return EngineResult {
                engine_name: "input_validator".into(),
                decision: Decision::Allow,
                reason: "engine disabled".into(),
                latency_ms: 0.0,
                metadata: serde_json::json!({"enabled": false}),
            };
        }

        // Check 1: Required fields present
        for field in &self.config.required_fields {
            if request.body.get(field).is_none() {
                return EngineResult {
                    engine_name: "input_validator".into(),
                    decision: Decision::Deny {
                        code: "MISSING_REQUIRED_FIELD".into(),
                        retry_after: None,
                    },
                    reason: format!("Missing required field: {}", field),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({"missing_field": field}),
                };
            }
        }

        // Check 2: Messages array present and not too long
        if let Some(messages) = request.body.get("messages").and_then(|m| m.as_array()) {
            if messages.len() > self.config.max_messages {
                return EngineResult {
                    engine_name: "input_validator".into(),
                    decision: Decision::Deny {
                        code: "TOO_MANY_MESSAGES".into(),
                        retry_after: None,
                    },
                    reason: format!(
                        "Message count {} exceeds maximum of {}",
                        messages.len(),
                        self.config.max_messages
                    ),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({
                        "message_count": messages.len(),
                        "max": self.config.max_messages,
                    }),
                };
            }

            // Check 3: Total prompt length
            let total_len: usize = messages
                .iter()
                .map(|m| {
                    m.get("content")
                        .and_then(|c| c.as_str())
                        .map(|s| s.len())
                        .unwrap_or(0)
                })
                .sum();

            if total_len > self.config.max_prompt_length {
                return EngineResult {
                    engine_name: "input_validator".into(),
                    decision: Decision::Deny {
                        code: "PROMPT_TOO_LONG".into(),
                        retry_after: None,
                    },
                    reason: format!(
                        "Prompt length {} exceeds maximum of {}",
                        total_len, self.config.max_prompt_length
                    ),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({
                        "prompt_length": total_len,
                        "max": self.config.max_prompt_length,
                    }),
                };
            }

            // Check 4: No null bytes or control characters (except \n, \r, \t)
            for msg in messages {
                if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                    for (i, c) in content.chars().enumerate() {
                        if c == '\0' || (c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                            return EngineResult {
                                engine_name: "input_validator".into(),
                                decision: Decision::Deny {
                                    code: "INVALID_CHARACTER".into(),
                                    retry_after: None,
                                },
                                reason: format!("Control character at position {} in message", i),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                metadata: serde_json::json!({
                                    "position": i,
                                    "char_code": c as u32,
                                }),
                            };
                        }
                    }
                }
            }
        }

        EngineResult {
            engine_name: "input_validator".into(),
            decision: Decision::Allow,
            reason: "valid input".into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({"status": "valid"}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(body: serde_json::Value) -> ShieldRequest {
        ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: Some("test/1.0".into()),
            api_key: Some("k".into()),
            user_id: Some("u".into()),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: Default::default(),
            body,
        }
    }

    #[test]
    fn test_valid_request() {
        let config = InputValidatorConfig::default();
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_missing_required_field() {
        let config = InputValidatorConfig::default();
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_prompt_too_long() {
        let config = InputValidatorConfig {
            max_prompt_length: 10,
            ..Default::default()
        };
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "This is a very long prompt that exceeds the limit"}]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_null_byte_rejected() {
        let config = InputValidatorConfig::default();
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello\0World"}]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_newline_allowed() {
        let config = InputValidatorConfig::default();
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Line 1\nLine 2\nLine 3"}]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_too_many_messages() {
        let config = InputValidatorConfig {
            max_messages: 2,
            ..Default::default()
        };
        let engine = InputValidator { config };
        let req = make_request(serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "1"},
                {"role": "assistant", "content": "2"},
                {"role": "user", "content": "3"}
            ]
        }));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }
}
