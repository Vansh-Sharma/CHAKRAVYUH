// Shield Ring — Perimeter Defense
//
// Ring 1 of the CHAKRAVYUH 9-ring architecture.
// Sits at the outermost trust boundary. Filters, rate-limits, and
// validates all incoming requests before they reach deeper rings.
//
// Engines (Phase 1 scope):
//   1. Input Validator    — schema and format validation
//   2. Rate Limiter       — per-source token bucket
//   3. DoS Protector      — anomaly-based flood detection
//   4. Geo Fencer         — IP-based geographic restrictions
//   5. Bot Detector       — bot/scraper signature matching
//   6. WAF Engine         — common attack pattern filtering
//
// Latency Budget: <2ms p99 for Shield-only evaluation
// Architecture Principle: Fail Secure (default deny on error)

pub mod bot_detector;
pub mod dos_protector;
pub mod geo_fencer;
pub mod input_validator;
pub mod rate_limiter;
pub mod rate_limiter_storage;
pub mod waf_engine;

use std::sync::Arc;

use crate::{
    decision::{Decision, Verdict},
    Config, Result,
};

/// The Shield Ring — outermost security layer.
///
/// Holds all 6 engines and coordinates their evaluation.
/// Each engine runs independently; the most restrictive verdict wins.
#[derive(Clone)]
pub struct ShieldRing {
    #[allow(dead_code)]
    config: Arc<Config>,
    input_validator: Arc<input_validator::InputValidator>,
    rate_limiter: Arc<rate_limiter::RateLimiter>,
    dos_protector: Arc<dos_protector::DosProtector>,
    geo_fencer: Arc<geo_fencer::GeoFencer>,
    bot_detector: Arc<bot_detector::BotDetector>,
    waf_engine: Arc<waf_engine::WafEngine>,
}

impl ShieldRing {
    /// Create a new Shield Ring with the given configuration.
    ///
    /// Initializes all 6 engines. Engines that are disabled in config
    /// are initialized in pass-through mode (always return ALLOW).
    pub fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self {
            input_validator: Arc::new(input_validator::InputValidator::new(&config.shield)?),
            rate_limiter: Arc::new(rate_limiter::RateLimiter::new(&config.shield)?),
            dos_protector: Arc::new(dos_protector::DosProtector::new(&config.shield)?),
            geo_fencer: Arc::new(geo_fencer::GeoFencer::new(&config.shield)?),
            bot_detector: Arc::new(bot_detector::BotDetector::new(&config.shield)?),
            waf_engine: Arc::new(waf_engine::WafEngine::new(&config.shield)?),
            config,
        })
    }

    /// Evaluate a request through all Shield engines.
    ///
    /// Returns the most restrictive verdict from any engine.
    /// If all engines pass, returns ALLOW.
    /// Latency target: <2ms p99.
    pub fn evaluate(&self, request: &ShieldRequest) -> ShieldVerdict {
        let start = std::time::Instant::now();

        let verdicts = vec![
            self.input_validator.evaluate(request),
            self.rate_limiter.evaluate(request),
            self.dos_protector.evaluate(request),
            self.geo_fencer.evaluate(request),
            self.bot_detector.evaluate(request),
            self.waf_engine.evaluate(request),
        ];

        // Most restrictive wins (Principle 2: Fail Secure)
        let final_decision = verdicts
            .iter()
            .map(|v| v.decision.clone())
            .max_by_key(|d| match d {
                Decision::Deny { .. } => 3,
                Decision::Challenge { .. } => 2,
                Decision::Escalate { .. } => 1,
                Decision::Allow => 0,
            })
            .unwrap_or(Decision::Deny {
                code: "SHIELD_NO_ENGINES".into(),
                retry_after: None,
            });

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        ShieldVerdict {
            decision: final_decision,
            engine_results: verdicts,
            latency_ms,
        }
    }
}

/// A request as seen by the Shield Ring.
///
/// This is the raw, unprocessed request before any ring evaluation.
/// Shield is the first ring, so it receives the raw request.
#[derive(Debug, Clone)]
pub struct ShieldRequest {
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub api_key: Option<String>,
    pub user_id: Option<String>,
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: serde_json::Value,
}

impl ShieldRequest {
    /// Extract the prompt text from the request body, if present.
    ///
    /// Handles OpenAI-compatible chat completion format.
    pub fn prompt_text(&self) -> Option<String> {
        let messages = self.body.get("messages")?.as_array()?;
        let mut parts = Vec::new();
        for msg in messages {
            let role = msg.get("role")?.as_str().unwrap_or("");
            let content = msg.get("content")?.as_str().unwrap_or("");
            parts.push(format!("{}: {}", role, content));
        }
        Some(parts.join("\n"))
    }
}

/// The verdict returned by the Shield Ring.
#[derive(Debug, Clone)]
pub struct ShieldVerdict {
    pub decision: Decision,
    pub engine_results: Vec<EngineResult>,
    pub latency_ms: f64,
}

impl Verdict for ShieldVerdict {
    fn decision(&self) -> &Decision {
        &self.decision
    }

    fn latency_ms(&self) -> f64 {
        self.latency_ms
    }
}

/// Per-engine result.
#[derive(Debug, Clone)]
pub struct EngineResult {
    pub engine_name: String,
    pub decision: Decision,
    pub reason: String,
    pub latency_ms: f64,
    pub metadata: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request(prompt: &str) -> ShieldRequest {
        ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: Some("test-client/1.0".into()),
            api_key: Some("test-key".into()),
            user_id: Some("test-user".into()),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: Default::default(),
            body: serde_json::json!({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": prompt}]
            }),
        }
    }

    #[test]
    fn test_prompt_extraction() {
        let req = make_test_request("Hello, world");
        let prompt = req.prompt_text().unwrap();
        assert!(prompt.contains("Hello, world"));
        assert!(prompt.contains("user:"));
    }

    #[test]
    fn test_empty_prompt_extraction() {
        let req = ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: None,
            api_key: None,
            user_id: None,
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({}),
        };
        assert!(req.prompt_text().is_none());
    }
}
