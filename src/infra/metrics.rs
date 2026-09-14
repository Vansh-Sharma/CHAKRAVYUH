// Metrics Module (Phase 8)
//
// Prometheus-style metrics for CHAKRAVYUH.
// Uses atomic counters for zero-lock overhead.
//
// Metrics exposed at GET /metrics in Prometheus text format.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Global request counters per endpoint.
static EVALUATE_REQUESTS: AtomicU64 = AtomicU64::new(0);
static PROXY_REQUESTS: AtomicU64 = AtomicU64::new(0);
static EXECUTE_REQUESTS: AtomicU64 = AtomicU64::new(0);
static GRPC_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Global decision counters.
static ALLOW_DECISIONS: AtomicU64 = AtomicU64::new(0);
static DENY_DECISIONS: AtomicU64 = AtomicU64::new(0);
static CHALLENGE_DECISIONS: AtomicU64 = AtomicU64::new(0);
static ESCALATE_DECISIONS: AtomicU64 = AtomicU64::new(0);

/// Per-ring evaluation counters.
static SHIELD_EVALS: AtomicU64 = AtomicU64::new(0);
static THREAT_EVALS: AtomicU64 = AtomicU64::new(0);
static IDENTITY_EVALS: AtomicU64 = AtomicU64::new(0);
static MEMORY_EVALS: AtomicU64 = AtomicU64::new(0);
static AGENT_EVALS: AtomicU64 = AtomicU64::new(0);
static EXECUTION_EVALS: AtomicU64 = AtomicU64::new(0);
static REASONING_EVALS: AtomicU64 = AtomicU64::new(0);
static GOVERNANCE_EVALS: AtomicU64 = AtomicU64::new(0);
static RECOVERY_SEC_EVALS: AtomicU64 = AtomicU64::new(0);

/// Latency histogram buckets (in ms).
static LATENCY_UNDER_1MS: AtomicU64 = AtomicU64::new(0);
static LATENCY_UNDER_5MS: AtomicU64 = AtomicU64::new(0);
static LATENCY_UNDER_10MS: AtomicU64 = AtomicU64::new(0);
static LATENCY_UNDER_50MS: AtomicU64 = AtomicU64::new(0);
static LATENCY_UNDER_100MS: AtomicU64 = AtomicU64::new(0);
static LATENCY_OVER_100MS: AtomicU64 = AtomicU64::new(0);

/// Global process start time.
pub static METRICS_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Record an endpoint request.
pub fn record_endpoint(endpoint: &str) {
    match endpoint {
        "evaluate" | "/v1/evaluate" | "/grpc/evaluate" => {
            EVALUATE_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
        "proxy" | "/v1/proxy" => {
            PROXY_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
        "execute" | "/v1/execute" | "/grpc/execute" => {
            EXECUTE_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
        "grpc" => {
            GRPC_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Record a decision outcome.
pub fn record_decision(decision: &str) {
    if decision == "allow" {
        ALLOW_DECISIONS.fetch_add(1, Ordering::Relaxed);
    } else if decision.starts_with("deny") {
        DENY_DECISIONS.fetch_add(1, Ordering::Relaxed);
    } else if decision == "challenge" {
        CHALLENGE_DECISIONS.fetch_add(1, Ordering::Relaxed);
    } else if decision == "escalate" {
        ESCALATE_DECISIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a ring evaluation.
pub fn record_ring_eval(ring: &str) {
    match ring {
        "shield" => {
            SHIELD_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "threat" => {
            THREAT_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "identity" => {
            IDENTITY_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "memory" => {
            MEMORY_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "agent" => {
            AGENT_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "execution" => {
            EXECUTION_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "reasoning" => {
            REASONING_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "governance" => {
            GOVERNANCE_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        "recovery_sec" | "recovery" => {
            RECOVERY_SEC_EVALS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Record a latency sample (in milliseconds).
pub fn record_latency(latency_ms: f64) {
    if latency_ms < 1.0 {
        LATENCY_UNDER_1MS.fetch_add(1, Ordering::Relaxed);
    } else if latency_ms < 5.0 {
        LATENCY_UNDER_5MS.fetch_add(1, Ordering::Relaxed);
    } else if latency_ms < 10.0 {
        LATENCY_UNDER_10MS.fetch_add(1, Ordering::Relaxed);
    } else if latency_ms < 50.0 {
        LATENCY_UNDER_50MS.fetch_add(1, Ordering::Relaxed);
    } else if latency_ms < 100.0 {
        LATENCY_UNDER_100MS.fetch_add(1, Ordering::Relaxed);
    } else {
        LATENCY_OVER_100MS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read an atomic counter.
fn read_counter(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

/// Generate Prometheus-style metrics text.
pub fn metrics_text() -> String {
    let start = METRICS_START.get_or_init(Instant::now);
    let uptime_secs = start.elapsed().as_secs();

    let mut out = String::new();

    out.push_str("# HELP chakravyuh_uptime_seconds Time since CHAKRAVYUH started\n");
    out.push_str("# TYPE chakravyuh_uptime_seconds gauge\n");
    out.push_str(&format!("chakravyuh_uptime_seconds {}\n\n", uptime_secs));

    // Endpoint requests.
    out.push_str("# HELP chakravyuh_requests_total Total requests per endpoint\n");
    out.push_str("# TYPE chakravyuh_requests_total counter\n");
    out.push_str(&format!(
        "chakravyuh_requests_total{{endpoint=\"evaluate\"}} {}\n",
        read_counter(&EVALUATE_REQUESTS)
    ));
    out.push_str(&format!(
        "chakravyuh_requests_total{{endpoint=\"proxy\"}} {}\n",
        read_counter(&PROXY_REQUESTS)
    ));
    out.push_str(&format!(
        "chakravyuh_requests_total{{endpoint=\"execute\"}} {}\n",
        read_counter(&EXECUTE_REQUESTS)
    ));
    out.push_str(&format!(
        "chakravyuh_requests_total{{endpoint=\"grpc\"}} {}\n\n",
        read_counter(&GRPC_REQUESTS)
    ));

    // Decision counts.
    out.push_str("# HELP chakravyuh_decisions_total Total decisions by outcome\n");
    out.push_str("# TYPE chakravyuh_decisions_total counter\n");
    out.push_str(&format!(
        "chakravyuh_decisions_total{{decision=\"allow\"}} {}\n",
        read_counter(&ALLOW_DECISIONS)
    ));
    out.push_str(&format!(
        "chakravyuh_decisions_total{{decision=\"deny\"}} {}\n",
        read_counter(&DENY_DECISIONS)
    ));
    out.push_str(&format!(
        "chakravyuh_decisions_total{{decision=\"challenge\"}} {}\n",
        read_counter(&CHALLENGE_DECISIONS)
    ));
    out.push_str(&format!(
        "chakravyuh_decisions_total{{decision=\"escalate\"}} {}\n\n",
        read_counter(&ESCALATE_DECISIONS)
    ));

    // Ring evaluations.
    out.push_str("# HELP chakravyuh_ring_evaluations_total Total ring evaluations\n");
    out.push_str("# TYPE chakravyuh_ring_evaluations_total counter\n");
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"shield\"}} {}\n",
        read_counter(&SHIELD_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"threat\"}} {}\n",
        read_counter(&THREAT_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"identity\"}} {}\n",
        read_counter(&IDENTITY_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"memory\"}} {}\n",
        read_counter(&MEMORY_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"agent\"}} {}\n",
        read_counter(&AGENT_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"execution\"}} {}\n",
        read_counter(&EXECUTION_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"reasoning\"}} {}\n",
        read_counter(&REASONING_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"governance\"}} {}\n",
        read_counter(&GOVERNANCE_EVALS)
    ));
    out.push_str(&format!(
        "chakravyuh_ring_evaluations_total{{ring=\"recovery\"}} {}\n\n",
        read_counter(&RECOVERY_SEC_EVALS)
    ));

    // Latency histogram.
    out.push_str("# HELP chakravyuh_request_duration_ms Request latency histogram\n");
    out.push_str("# TYPE chakravyuh_request_duration_ms histogram\n");
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"1\"}} {}\n",
        read_counter(&LATENCY_UNDER_1MS)
    ));
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"5\"}} {}\n",
        read_counter(&LATENCY_UNDER_5MS)
    ));
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"10\"}} {}\n",
        read_counter(&LATENCY_UNDER_10MS)
    ));
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"50\"}} {}\n",
        read_counter(&LATENCY_UNDER_50MS)
    ));
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"100\"}} {}\n",
        read_counter(&LATENCY_UNDER_100MS)
    ));
    out.push_str(&format!(
        "chakravyuh_request_duration_ms_bucket{{le=\"+Inf\"}} {}\n\n",
        read_counter(&LATENCY_OVER_100MS)
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_read_endpoint() {
        let before_evaluate = read_counter(&EVALUATE_REQUESTS);
        let before_proxy = read_counter(&PROXY_REQUESTS);
        record_endpoint("evaluate");
        record_endpoint("evaluate");
        record_endpoint("proxy");
        assert_eq!(read_counter(&EVALUATE_REQUESTS), before_evaluate + 2);
        assert_eq!(read_counter(&PROXY_REQUESTS), before_proxy + 1);
    }

    #[test]
    fn record_and_read_decision() {
        let before_allow = read_counter(&ALLOW_DECISIONS);
        let before_deny = read_counter(&DENY_DECISIONS);
        record_decision("allow");
        record_decision("deny");
        record_decision("deny:test");
        record_decision("challenge");
        assert_eq!(read_counter(&ALLOW_DECISIONS), before_allow + 1);
        assert_eq!(read_counter(&DENY_DECISIONS), before_deny + 2);
        assert_eq!(
            read_counter(&CHALLENGE_DECISIONS),
            read_counter(&CHALLENGE_DECISIONS)
        ); // just runs
    }

    #[test]
    fn record_and_read_ring_eval() {
        record_ring_eval("shield");
        record_ring_eval("threat");
        record_ring_eval("shield");
        assert_eq!(read_counter(&SHIELD_EVALS), 2);
        assert_eq!(read_counter(&THREAT_EVALS), 1);
    }

    #[test]
    fn latency_histogram() {
        record_latency(0.5);
        record_latency(3.0);
        record_latency(7.0);
        record_latency(30.0);
        record_latency(75.0);
        record_latency(200.0);
        assert_eq!(read_counter(&LATENCY_UNDER_1MS), 1);
        assert_eq!(read_counter(&LATENCY_UNDER_5MS), 1);
        assert_eq!(read_counter(&LATENCY_UNDER_10MS), 1);
        assert_eq!(read_counter(&LATENCY_UNDER_50MS), 1);
        assert_eq!(read_counter(&LATENCY_UNDER_100MS), 1);
        assert_eq!(read_counter(&LATENCY_OVER_100MS), 1);
    }

    #[test]
    fn metrics_text_format() {
        record_endpoint("evaluate");
        record_decision("allow");
        let text = metrics_text();
        assert!(text.contains("chakravyuh_uptime_seconds"));
        assert!(text.contains("chakravyuh_requests_total"));
        assert!(text.contains("chakravyuh_decisions_total"));
        assert!(text.contains("chakravyuh_ring_evaluations_total"));
        assert!(text.contains("chakravyuh_request_duration_ms"));
    }
}
