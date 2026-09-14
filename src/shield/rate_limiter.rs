// Rate Limiter — Shield Ring Engine #2
//
// Token bucket rate limiting per source identifier.
//
// Backend is pluggable via the `RateLimitStorage` trait:
//   - `memory` (default): in-process HashMap. Zero deps, lost on restart.
//   - `redis`: shared across instances, survives restarts (requires
//      `--features redis`).
//
// Latency Budget: 0.5ms p99 (in-memory), 2ms p99 (Redis-backed)

use crate::shield::{rate_limiter_storage::RateLimitStorage, EngineResult, ShieldRequest};
use crate::{decision::Decision, Result};
use std::sync::Arc;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RateLimiterConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Backend name: "memory" (default) or "redis" (requires --features redis).
    #[serde(default = "default_backend")]
    pub backend: String,

    /// Redis URL used when `backend == "redis"`.
    /// Example: `redis://127.0.0.1:6379`. Ignored for `memory` backend.
    #[serde(default)]
    pub redis_url: Option<String>,

    #[serde(default)]
    pub limits: RateLimits,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RateLimits {
    #[serde(default = "default_per_ip")]
    pub per_ip: String, // e.g., "100/min"

    #[serde(default = "default_per_api_key")]
    pub per_api_key: String,

    #[serde(default = "default_per_user")]
    pub per_user: String,
}

fn default_enabled() -> bool {
    true
}
fn default_backend() -> String {
    "memory".into()
}
fn default_per_ip() -> String {
    "100/min".into()
}
fn default_per_api_key() -> String {
    "1000/min".into()
}
fn default_per_user() -> String {
    "500/min".into()
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            per_ip: default_per_ip(),
            per_api_key: default_per_api_key(),
            per_user: default_per_user(),
        }
    }
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            backend: default_backend(),
            redis_url: None,
            limits: RateLimits::default(),
        }
    }
}

/// Parse rate strings like "100/min" or "10/sec" into (capacity, refill_per_sec).
fn parse_rate(s: &str) -> (f64, f64) {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return (100.0, 100.0 / 60.0); // default
    }
    let count: f64 = parts[0].trim().parse().unwrap_or(100.0);
    let refill = match parts[1].trim().to_lowercase().as_str() {
        "sec" | "s" => count,
        "min" | "m" => count / 60.0,
        "hour" | "h" => count / 3600.0,
        _ => count / 60.0,
    };
    (count, refill)
}

pub struct RateLimiter {
    config: RateLimiterConfig,
    storage: Arc<dyn RateLimitStorage>,
}

impl RateLimiter {
    pub fn new(shield_config: &crate::config::ShieldConfig) -> Result<Self> {
        let config = shield_config.rate_limiter.clone();

        let storage: Box<dyn RateLimitStorage> =
            crate::shield::rate_limiter_storage::build_storage(
                &config.backend,
                config.redis_url.as_deref(),
            )
            .map_err(crate::error::Error::RateLimiterStorage)?;

        Ok(Self {
            config,
            storage: Arc::from(storage),
        })
    }

    /// Construct with a custom storage backend. Used by tests that want
    /// to inject a fake backend without going through the factory.
    pub fn with_storage(
        shield_config: &crate::config::ShieldConfig,
        storage: Arc<dyn RateLimitStorage>,
    ) -> Self {
        Self {
            config: shield_config.rate_limiter.clone(),
            storage,
        }
    }

    pub fn evaluate(&self, request: &ShieldRequest) -> EngineResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return EngineResult {
                engine_name: "rate_limiter".into(),
                decision: Decision::Allow,
                reason: "engine disabled".into(),
                latency_ms: 0.0,
                metadata: serde_json::json!({"enabled": false}),
            };
        }

        // Check IP-based limit
        let (cap, refill) = parse_rate(&self.config.limits.per_ip);
        let ip_key = format!("ip:{}", request.source_ip);
        let ip_allowed = self.storage.try_consume(&ip_key, cap, refill);

        if !ip_allowed {
            return EngineResult {
                engine_name: "rate_limiter".into(),
                decision: Decision::Deny {
                    code: "RATE_LIMIT_IP".into(),
                    retry_after: Some(60),
                },
                reason: format!(
                    "IP {} exceeded rate limit {}",
                    request.source_ip, self.config.limits.per_ip
                ),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({"limit_type": "ip", "limit": self.config.limits.per_ip}),
            };
        }

        // Check API key limit if present
        if let Some(api_key) = &request.api_key {
            let (cap, refill) = parse_rate(&self.config.limits.per_api_key);
            let key_key = format!("key:{}", api_key);
            if !self.storage.try_consume(&key_key, cap, refill) {
                return EngineResult {
                    engine_name: "rate_limiter".into(),
                    decision: Decision::Deny {
                        code: "RATE_LIMIT_API_KEY".into(),
                        retry_after: Some(60),
                    },
                    reason: format!(
                        "API key exceeded rate limit {}",
                        self.config.limits.per_api_key
                    ),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({"limit_type": "api_key", "limit": self.config.limits.per_api_key}),
                };
            }
        }

        // Check user limit if present
        if let Some(user_id) = &request.user_id {
            let (cap, refill) = parse_rate(&self.config.limits.per_user);
            let user_key = format!("user:{}", user_id);
            if !self.storage.try_consume(&user_key, cap, refill) {
                return EngineResult {
                    engine_name: "rate_limiter".into(),
                    decision: Decision::Deny {
                        code: "RATE_LIMIT_USER".into(),
                        retry_after: Some(60),
                    },
                    reason: format!(
                        "User {} exceeded rate limit {}",
                        user_id, self.config.limits.per_user
                    ),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({"limit_type": "user", "limit": self.config.limits.per_user}),
                };
            }
        }

        EngineResult {
            engine_name: "rate_limiter".into(),
            decision: Decision::Allow,
            reason: "within rate limits".into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({"checked": ["ip", "api_key", "user"]}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shield::rate_limiter_storage::MemoryStorage;

    fn make_request() -> ShieldRequest {
        ShieldRequest {
            source_ip: "1.2.3.4".into(),
            user_agent: Some("test/1.0".into()),
            api_key: Some("k".into()),
            user_id: Some("u".into()),
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({}),
        }
    }

    fn make_engine(limits: RateLimits) -> RateLimiter {
        let config = RateLimiterConfig {
            enabled: true,
            backend: "memory".into(),
            redis_url: None,
            limits,
        };
        let shield_config = crate::config::ShieldConfig {
            rate_limiter: config,
            ..Default::default()
        };
        RateLimiter::with_storage(&shield_config, Arc::new(MemoryStorage::new()))
    }

    #[test]
    fn test_rate_limit_triggered() {
        let engine = make_engine(RateLimits {
            per_ip: "3/min".into(),
            per_api_key: "100/min".into(),
            per_user: "100/min".into(),
        });

        // First 3 should pass
        for _ in 0..3 {
            let result = engine.evaluate(&make_request());
            assert!(matches!(result.decision, Decision::Allow), "Expected Allow");
        }

        // 4th should be denied
        let result = engine.evaluate(&make_request());
        assert!(
            matches!(result.decision, Decision::Deny { .. }),
            "Expected Deny"
        );
    }

    #[test]
    fn test_parse_rate() {
        let (cap, refill) = parse_rate("100/min");
        assert_eq!(cap, 100.0);
        assert!((refill - 100.0 / 60.0).abs() < 0.001);

        let (cap, refill) = parse_rate("10/sec");
        assert_eq!(cap, 10.0);
        assert!((refill - 10.0).abs() < 0.001);
    }
}
