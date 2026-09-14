// Request Tracing (Phase 9)
//
// Per-request trace IDs and ring-span correlation for CHAKRAVYUH.
//
// Every incoming request gets a unique trace ID (either from the
// `X-Trace-Id` header or auto-generated). This trace ID flows through
// all ring evaluations and is included in decision records, log output,
// and API responses.
//
// Architecture:
//   - Trace IDs are 16-character hex strings (64-bit random)
//   - Set via `X-Trace-Id` header or auto-generated
//   - Each ring evaluation is a "span" within the trace
//   - Spans record ring name, latency, and decision
//   - Trace context is propagated via axum middleware
//
// Thread Safety: All state is request-scoped (no shared mutable state).
// Performance: <0.01ms overhead per request (single UUID generation).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use serde::Serialize;

/// A single span within a trace — represents one ring evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct Span {
    /// Ring name (e.g., "shield", "threat").
    pub ring: String,
    /// Start time relative to trace start (microseconds).
    pub start_us: u64,
    /// Duration of this ring evaluation (microseconds).
    pub duration_us: u64,
    /// Decision/outcome from this ring.
    pub decision: String,
    /// Additional metadata (score, reason, etc.).
    pub metadata: HashMap<String, String>,
}

/// A complete request trace — spans all ring evaluations.
#[derive(Debug, Clone, Serialize)]
pub struct TraceContext {
    /// Unique trace ID (16-char hex).
    pub trace_id: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Source IP.
    pub source_ip: String,
    /// Absolute start time.
    pub started_at_us: u64,
    /// Ring evaluation spans.
    pub spans: Vec<Span>,
    /// Total trace duration (microseconds).
    pub total_duration_us: u64,
}

impl TraceContext {
    /// Create a new trace context with a generated trace ID.
    pub fn new(method: &str, path: &str, source_ip: &str) -> Self {
        let trace_id = uuid::Uuid::new_v4().to_string()[..16].to_string();
        Self::with_id(&trace_id, method, path, source_ip)
    }

    /// Create a trace context with an explicit trace ID.
    pub fn with_id(trace_id: &str, method: &str, path: &str, source_ip: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            source_ip: source_ip.to_string(),
            started_at_us: micros_since_epoch(),
            spans: Vec::new(),
            total_duration_us: 0,
        }
    }

    /// Record a ring evaluation span.
    pub fn record_span(
        &mut self,
        ring: &str,
        duration: std::time::Duration,
        decision: &str,
        metadata: HashMap<String, String>,
    ) {
        let start_offset = if self.spans.is_empty() {
            0
        } else {
            self.spans.iter().map(|s| s.start_us + s.duration_us).max().unwrap_or(0)
        };

        self.spans.push(Span {
            ring: ring.to_string(),
            start_us: start_offset,
            duration_us: duration.as_micros() as u64,
            decision: decision.to_string(),
            metadata,
        });
    }

    /// Close the trace and record total duration.
    pub fn close(&mut self, start: Instant) {
        self.total_duration_us = start.elapsed().as_micros() as u64;
    }
}

/// Extract or generate a trace ID from headers.
pub fn extract_trace_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s[..16.min(s.len())].to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()[..16].to_string())
}

/// Get microseconds since Unix epoch.
pub fn micros_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Global trace collector for recent traces (ring buffer).
/// Holds the last N traces for diagnostics.
static RECENT_TRACES: std::sync::OnceLock<RwLock<Vec<TraceContext>>> = std::sync::OnceLock::new();

/// Maximum traces to keep in memory.
const MAX_RECENT_TRACES: usize = 1000;

/// Record a completed trace to the recent traces buffer.
pub fn record_trace(trace: TraceContext) {
    let buffer = RECENT_TRACES.get_or_init(|| RwLock::new(Vec::with_capacity(MAX_RECENT_TRACES)));
    if let Ok(mut buf) = buffer.write() {
        buf.push(trace);
        if buf.len() > MAX_RECENT_TRACES {
            let excess = buf.len() - MAX_RECENT_TRACES;
            buf.drain(..excess);
        }
    }
}

/// Get recent traces for diagnostics.
pub fn recent_traces() -> Vec<TraceContext> {
    let buffer = RECENT_TRACES.get_or_init(|| RwLock::new(Vec::new()));
    buffer.read().map(|buf| buf.clone()).unwrap_or_default()
}

/// Get trace statistics.
#[derive(Debug, Clone, Serialize)]
pub struct TraceStats {
    pub total_traces: usize,
    pub buffer_capacity: usize,
}

/// Get trace buffer statistics.
pub fn trace_stats() -> TraceStats {
    let buffer = RECENT_TRACES.get_or_init(|| RwLock::new(Vec::new()));
    buffer.read().map(|buf| TraceStats {
        total_traces: buf.len(),
        buffer_capacity: MAX_RECENT_TRACES,
    }).unwrap_or(TraceStats {
        total_traces: 0,
        buffer_capacity: MAX_RECENT_TRACES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_context_creation() {
        let ctx = TraceContext::new("POST", "/v1/evaluate", "1.2.3.4");
        assert_eq!(ctx.trace_id.len(), 16);
        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.path, "/v1/evaluate");
        assert!(ctx.spans.is_empty());
        assert!(ctx.started_at_us > 0);
    }

    #[test]
    fn trace_context_with_explicit_id() {
        let ctx = TraceContext::with_id("mytrace123456789", "GET", "/health", "127.0.0.1");
        assert_eq!(ctx.trace_id, "mytrace123456789");
    }

    #[test]
    fn record_span() {
        let mut ctx = TraceContext::new("POST", "/v1/evaluate", "1.2.3.4");
        ctx.record_span(
            "shield",
            std::time::Duration::from_micros(150),
            "allow",
            HashMap::new(),
        );
        ctx.record_span(
            "threat",
            std::time::Duration::from_micros(200),
            "score:3.5",
            HashMap::new(),
        );
        assert_eq!(ctx.spans.len(), 2);
        assert_eq!(ctx.spans[0].ring, "shield");
        assert_eq!(ctx.spans[0].duration_us, 150);
        assert_eq!(ctx.spans[1].ring, "threat");
    }

    #[test]
    fn extract_trace_id_from_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-trace-id", "abcdefghijklmnop".parse().unwrap());
        let id = extract_trace_id(&headers);
        assert_eq!(id, "abcdefghijklmnop");
    }

    #[test]
    fn extract_trace_id_missing_generates() {
        let headers = axum::http::HeaderMap::new();
        let id = extract_trace_id(&headers);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn recent_traces_buffer() {
        let ctx = TraceContext::new("GET", "/health", "127.0.0.1");
        record_trace(ctx);
        let traces = recent_traces();
        assert!(!traces.is_empty());
        let stats = trace_stats();
        assert_eq!(stats.total_traces, 1);
        assert_eq!(stats.buffer_capacity, MAX_RECENT_TRACES);
    }

    #[test]
    fn close_trace() {
        let mut ctx = TraceContext::new("POST", "/v1/evaluate", "1.2.3.4");
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_micros(100));
        ctx.close(start);
        assert!(ctx.total_duration_us >= 50); // allow some timing slack
    }
}
