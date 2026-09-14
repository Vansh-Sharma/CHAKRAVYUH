// DoS Protector — Shield Ring Engine #3
//
// Detects anomalous traffic patterns indicating denial-of-service attacks.
// Uses per-source-IP statistical baseline comparison (5-sigma threshold).
//
// IMPORTANT: traffic is tracked PER SOURCE IP, not globally. A global
// traffic window would cause legitimate users to be blocked during any
// traffic spike (flash crowd, marketing campaign, etc.), which is a
// false-positive bug, not DoS protection.
//
// Latency Budget: 1ms p99

use crate::shield::{EngineResult, ShieldRequest};
use crate::{decision::Decision, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DosProtectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_baseline_window")]
    pub baseline_window: u64, // seconds

    #[serde(default = "default_threshold_sigma")]
    pub threshold_sigma: f64,

    #[serde(default = "default_block_duration")]
    pub block_duration: u64, // seconds

    /// Minimum requests before anomaly detection kicks in.
    /// Below this count, we don't have enough data to call something anomalous.
    #[serde(default = "default_min_requests")]
    pub min_requests: usize,

    /// Maximum requests per minute from a single IP before auto-block.
    /// This is a hard ceiling — even if the statistical detector doesn't fire,
    /// hitting this many requests in 60 seconds is always suspicious.
    #[serde(default = "default_hard_limit_per_min")]
    pub hard_limit_per_min: usize,
}

fn default_enabled() -> bool {
    true
}
fn default_baseline_window() -> u64 {
    3600
}
fn default_threshold_sigma() -> f64 {
    5.0
}
fn default_block_duration() -> u64 {
    300
}
fn default_min_requests() -> usize {
    100
}
fn default_hard_limit_per_min() -> usize {
    600 // 10 req/sec sustained for 60s = definitely a problem
}

impl Default for DosProtectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            baseline_window: default_baseline_window(),
            threshold_sigma: default_threshold_sigma(),
            block_duration: default_block_duration(),
            min_requests: default_min_requests(),
            hard_limit_per_min: default_hard_limit_per_min(),
        }
    }
}

/// Per-IP traffic history.
#[derive(Debug, Default)]
struct TrafficWindow {
    requests: VecDeque<Instant>,
}

impl TrafficWindow {
    fn record(&mut self, now: Instant) {
        self.requests.push_back(now);
        // Prune entries older than the baseline window (1 hour default).
        let cutoff = now - Duration::from_secs(3600);
        while let Some(front) = self.requests.front() {
            if *front < cutoff {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }

    fn requests_in_last(&self, secs: u64) -> usize {
        let cutoff = Instant::now() - Duration::from_secs(secs);
        self.requests.iter().filter(|t| **t > cutoff).count()
    }

    /// Baseline rate in requests/second over the full observed window.
    /// Returns 0.0 if we don't have enough data yet (< 1 second of history).
    fn baseline_rate(&self) -> f64 {
        if self.requests.len() < 2 {
            return 0.0;
        }
        let window_secs = self
            .requests
            .back()
            .unwrap()
            .duration_since(*self.requests.front().unwrap())
            .as_secs_f64();
        if window_secs < 1.0 {
            return 0.0;
        }
        self.requests.len() as f64 / window_secs
    }
}

pub struct DosProtector {
    config: DosProtectorConfig,
    /// Per-IP traffic history.
    traffic: Mutex<HashMap<String, TrafficWindow>>,
    /// IPs currently blocked, with the time they were blocked.
    blocked_ips: Mutex<Vec<(String, Instant)>>,
}

impl DosProtector {
    pub fn new(shield_config: &crate::config::ShieldConfig) -> Result<Self> {
        Ok(Self {
            config: shield_config.dos_protector.clone(),
            traffic: Mutex::new(HashMap::new()),
            blocked_ips: Mutex::new(Vec::new()),
        })
    }

    pub fn evaluate(&self, request: &ShieldRequest) -> EngineResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return EngineResult {
                engine_name: "dos_protector".into(),
                decision: Decision::Allow,
                reason: "engine disabled".into(),
                latency_ms: 0.0,
                metadata: serde_json::json!({"enabled": false}),
            };
        }

        // Skip protection for the "unknown" IP — it means no proxy header
        // was present and we have no real client identity. Rate limiting
        // 0.0.0.0 would block ALL such traffic, which is wrong.
        if request.source_ip == "0.0.0.0" || request.source_ip.is_empty() {
            return EngineResult {
                engine_name: "dos_protector".into(),
                decision: Decision::Allow,
                reason: "no source IP — skipping DoS check".into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({"skipped": true}),
            };
        }

        // Check if IP is already blocked
        {
            let mut blocked = self.blocked_ips.lock().unwrap();
            let now = Instant::now();
            blocked.retain(|(_, t)| {
                now.duration_since(*t) < Duration::from_secs(self.config.block_duration)
            });
            if blocked.iter().any(|(ip, _)| ip == &request.source_ip) {
                return EngineResult {
                    engine_name: "dos_protector".into(),
                    decision: Decision::Deny {
                        code: "DOS_BLOCKED".into(),
                        retry_after: Some(self.config.block_duration as u32),
                    },
                    reason: "IP blocked due to DoS detection".to_string(),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({"blocked": true}),
                };
            }
        }

        // Record this request and get per-IP stats
        let (recent_count, baseline_rate) = {
            let mut traffic = self.traffic.lock().unwrap();
            let window = traffic.entry(request.source_ip.clone()).or_default();
            window.record(Instant::now());
            (window.requests_in_last(60), window.baseline_rate())
        };

        // Hard limit: if an IP sends more than hard_limit_per_min in 60s,
        // block immediately — no statistics needed.
        if recent_count > self.config.hard_limit_per_min {
            let mut blocked = self.blocked_ips.lock().unwrap();
            blocked.push((request.source_ip.clone(), Instant::now()));
            return EngineResult {
                engine_name: "dos_protector".into(),
                decision: Decision::Deny {
                    code: "DOS_HARD_LIMIT".into(),
                    retry_after: Some(self.config.block_duration as u32),
                },
                reason: format!(
                    "Hard rate limit exceeded: {} requests in 60s (limit: {})",
                    recent_count, self.config.hard_limit_per_min
                ),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({
                    "recent_count": recent_count,
                    "hard_limit": self.config.hard_limit_per_min,
                }),
            };
        }

        // Statistical anomaly: only fire if we have enough history.
        // recent_rate = requests in last 60s / 60
        let recent_rate = recent_count as f64 / 60.0;
        let threshold = baseline_rate + self.config.threshold_sigma * (baseline_rate.sqrt() + 1.0);

        if recent_count > self.config.min_requests && baseline_rate > 0.0 && recent_rate > threshold
        {
            let mut blocked = self.blocked_ips.lock().unwrap();
            blocked.push((request.source_ip.clone(), Instant::now()));

            return EngineResult {
                engine_name: "dos_protector".into(),
                decision: Decision::Deny {
                    code: "DOS_DETECTED".into(),
                    retry_after: Some(self.config.block_duration as u32),
                },
                reason: format!(
                    "DoS detected: recent rate {:.1}/s vs baseline {:.1}/s (threshold {:.1}/s)",
                    recent_rate, baseline_rate, threshold
                ),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({
                    "recent_rate": recent_rate,
                    "baseline_rate": baseline_rate,
                    "threshold": threshold,
                    "block_duration_sec": self.config.block_duration,
                }),
            };
        }

        EngineResult {
            engine_name: "dos_protector".into(),
            decision: Decision::Allow,
            reason: "normal traffic".into(),
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({
                "recent_rate": recent_rate,
                "baseline_rate": baseline_rate,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(ip: &str) -> ShieldRequest {
        ShieldRequest {
            source_ip: ip.into(),
            user_agent: Some("test/1.0".into()),
            api_key: None,
            user_id: None,
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({}),
        }
    }

    #[test]
    fn test_baseline_calculation() {
        let mut window = TrafficWindow::default();
        let now = Instant::now();
        // Simulate 10 requests over 10 seconds
        for i in 0..10 {
            window.record(now - Duration::from_secs(10 - i));
        }
        let rate = window.baseline_rate();
        assert!(rate > 0.5 && rate < 2.0, "Expected ~1 req/s, got {}", rate);
    }

    #[test]
    fn test_single_request_does_not_block() {
        // Regression: a single request from a new IP must NOT be flagged.
        let config = DosProtectorConfig::default();
        let protector = DosProtector {
            config,
            traffic: Mutex::new(HashMap::new()),
            blocked_ips: Mutex::new(Vec::new()),
        };
        let req = make_request("1.2.3.4");
        let result = protector.evaluate(&req);
        assert!(
            matches!(result.decision, Decision::Allow),
            "single request should be allowed, got {:?}",
            result.decision
        );
    }

    #[test]
    fn test_unknown_ip_skipped() {
        // The 0.0.0.0 placeholder must be skipped, not blocked.
        let config = DosProtectorConfig::default();
        let protector = DosProtector {
            config,
            traffic: Mutex::new(HashMap::new()),
            blocked_ips: Mutex::new(Vec::new()),
        };
        let req = make_request("0.0.0.0");
        let result = protector.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_hard_limit_triggers_block() {
        // Sending more than hard_limit_per_min requests in 60s should block.
        let config = DosProtectorConfig {
            hard_limit_per_min: 5,
            min_requests: 1000, // disable statistical detector
            ..Default::default()
        };
        let protector = DosProtector {
            config,
            traffic: Mutex::new(HashMap::new()),
            blocked_ips: Mutex::new(Vec::new()),
        };
        // Send 5 requests (under limit)
        for _ in 0..5 {
            let req = make_request("5.6.7.8");
            let result = protector.evaluate(&req);
            assert!(matches!(result.decision, Decision::Allow));
        }
        // 6th request should trigger hard limit
        let req = make_request("5.6.7.8");
        let result = protector.evaluate(&req);
        assert!(
            matches!(result.decision, Decision::Deny { .. }),
            "6th request should be blocked by hard limit"
        );
    }

    #[test]
    fn test_different_ips_are_independent() {
        // Requests from different IPs should not affect each other.
        let config = DosProtectorConfig {
            hard_limit_per_min: 3,
            min_requests: 1000,
            ..Default::default()
        };
        let protector = DosProtector {
            config,
            traffic: Mutex::new(HashMap::new()),
            blocked_ips: Mutex::new(Vec::new()),
        };
        // 3 requests from IP A — all allowed
        for _ in 0..3 {
            let req = make_request("10.0.0.1");
            assert!(matches!(protector.evaluate(&req).decision, Decision::Allow));
        }
        // 3 requests from IP B — all allowed (independent of A)
        for _ in 0..3 {
            let req = make_request("10.0.0.2");
            assert!(matches!(protector.evaluate(&req).decision, Decision::Allow));
        }
        // 4th from A — blocked
        let req = make_request("10.0.0.1");
        assert!(matches!(
            protector.evaluate(&req).decision,
            Decision::Deny { .. }
        ));
        // 4th from B — blocked
        let req = make_request("10.0.0.2");
        assert!(matches!(
            protector.evaluate(&req).decision,
            Decision::Deny { .. }
        ));
    }
}
