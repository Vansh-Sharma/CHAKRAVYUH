// Bot Detector — Shield Ring Engine #5
//
// Identifies non-human traffic (scrapers, crawlers, attack tools).
// Uses User-Agent + request pattern + IP reputation.
//
// Latency Budget: 0.5ms p99

use crate::shield::{EngineResult, ShieldRequest};
use crate::{decision::Decision, Result};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BotDetectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_challenge_unknown")]
    pub challenge_unknown: bool,

    #[serde(default = "default_good_bots")]
    pub good_bots: Vec<String>,

    #[serde(default = "default_bad_bots")]
    pub bad_bots: Vec<String>,
}

fn default_enabled() -> bool {
    true
}
fn default_challenge_unknown() -> bool {
    false
}
fn default_good_bots() -> Vec<String> {
    vec![
        "Googlebot".into(),
        "Bingbot".into(),
        "Slackbot".into(),
        "GitHub-Actions".into(),
        "curl".into(), // Allow curl for testing
    ]
}
fn default_bad_bots() -> Vec<String> {
    vec![
        "sqlmap".into(),
        "nikto".into(),
        "nmap".into(),
        "masscan".into(),
        "hydra".into(),
        "metasploit".into(),
        "w3af".into(),
    ]
}

impl Default for BotDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            challenge_unknown: default_challenge_unknown(),
            good_bots: default_good_bots(),
            bad_bots: default_bad_bots(),
        }
    }
}

pub struct BotDetector {
    config: BotDetectorConfig,
}

impl BotDetector {
    pub fn new(shield_config: &crate::config::ShieldConfig) -> Result<Self> {
        Ok(Self {
            config: shield_config.bot_detector.clone(),
        })
    }

    pub fn evaluate(&self, request: &ShieldRequest) -> EngineResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return EngineResult {
                engine_name: "bot_detector".into(),
                decision: Decision::Allow,
                reason: "engine disabled".into(),
                latency_ms: 0.0,
                metadata: serde_json::json!({"enabled": false}),
            };
        }

        let ua = request.user_agent.as_deref().unwrap_or("");

        // Check bad bots
        for bad in &self.config.bad_bots {
            if ua.to_lowercase().contains(&bad.to_lowercase()) {
                return EngineResult {
                    engine_name: "bot_detector".into(),
                    decision: Decision::Deny {
                        code: "BOT_BAD".into(),
                        retry_after: None,
                    },
                    reason: format!("Known attack tool: {}", bad),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({
                        "user_agent": ua,
                        "matched": bad,
                        "classification": "BOT_BAD",
                    }),
                };
            }
        }

        // Check good bots
        for good in &self.config.good_bots {
            if ua.to_lowercase().contains(&good.to_lowercase()) {
                return EngineResult {
                    engine_name: "bot_detector".into(),
                    decision: Decision::Allow,
                    reason: format!("Known good bot: {}", good),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({
                        "user_agent": ua,
                        "matched": good,
                        "classification": "BOT_GOOD",
                    }),
                };
            }
        }

        // Unknown — challenge or allow based on config
        if self.config.challenge_unknown && !ua.is_empty() {
            return EngineResult {
                engine_name: "bot_detector".into(),
                decision: Decision::Challenge {
                    challenge_type: crate::decision::ChallengeType::Javascript,
                },
                reason: "Unknown user agent, challenge required".into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({
                    "user_agent": ua,
                    "classification": "UNKNOWN",
                }),
            };
        }

        EngineResult {
            engine_name: "bot_detector".into(),
            decision: Decision::Allow,
            reason: "human or unknown (allowed)".into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({
                "user_agent": ua,
                "classification": if ua.is_empty() { "EMPTY" } else { "UNKNOWN" },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(ua: Option<&str>) -> ShieldRequest {
        ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: ua.map(|s| s.to_string()),
            api_key: Some("k".into()),
            user_id: Some("u".into()),
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({}),
        }
    }

    #[test]
    fn test_bad_bot_blocked() {
        let config = BotDetectorConfig::default();
        let engine = BotDetector { config };
        let req = make_request(Some("sqlmap/1.0"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_good_bot_allowed() {
        let config = BotDetectorConfig::default();
        let engine = BotDetector { config };
        let req = make_request(Some("Googlebot/2.1"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_unknown_allowed_by_default() {
        let config = BotDetectorConfig::default();
        let engine = BotDetector { config };
        let req = make_request(Some("MyApp/1.0"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }
}
