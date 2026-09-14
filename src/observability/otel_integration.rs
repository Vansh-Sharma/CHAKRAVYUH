// OpenTelemetry Integration for CHAKRAVYUH Observability Platform
//
// Provides OTel-compatible data structures, a batch export coordinator,
// fluent builders for spans/metrics, and bridge functions that convert
// existing infra::trace and infra::metrics data into OTel types.
//
// No external OTel SDK dependency — uses std-only wire format.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────
// OtelConfig
// ────────────────────────────────────────────────────────────────

/// Configuration for the OpenTelemetry exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelConfig {
    /// OTel collector gRPC endpoint (default: localhost:4317).
    pub endpoint: String,
    /// Service name reported in all OTel telemetry.
    pub service_name: String,
    /// Head-based sampling rate [0.0, 1.0].
    pub sample_rate: f64,
    /// Maximum batch size before auto-flush.
    pub batch_size: usize,
    /// Export request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether OTel export is enabled.
    pub enabled: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "chakravyuh".to_string(),
            sample_rate: 1.0,
            batch_size: 512,
            timeout_ms: 5000,
            enabled: true,
        }
    }
}

// ────────────────────────────────────────────────────────────────
// OtelSpanStatus
// ────────────────────────────────────────────────────────────────

/// Status of an OTel span.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OtelSpanStatus {
    /// Span completed successfully.
    Ok,
    /// Span completed with an error.
    Error { message: String },
}

impl OtelSpanStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, OtelSpanStatus::Ok)
    }
}

// ────────────────────────────────────────────────────────────────
// OtelLogSeverity
// ────────────────────────────────────────────────────────────────

/// Severity level for OTel log records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum OtelLogSeverity {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warn = 4,
    Error = 5,
    Fatal = 6,
}

impl OtelLogSeverity {
    /// Convert to the OTel numeric severity value.
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }

    /// Convert to a short string label.
    pub fn as_str(&self) -> &'static str {
        match self {
            OtelLogSeverity::Trace => "TRACE",
            OtelLogSeverity::Debug => "DEBUG",
            OtelLogSeverity::Info => "INFO",
            OtelLogSeverity::Warn => "WARN",
            OtelLogSeverity::Error => "ERROR",
            OtelLogSeverity::Fatal => "FATAL",
        }
    }
}

impl std::fmt::Display for OtelLogSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ────────────────────────────────────────────────────────────────
// OtelMetricValue
// ────────────────────────────────────────────────────────────────

/// Value types supported by OTel metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OtelMetricValue {
    /// Monotonically increasing counter.
    Counter(f64),
    /// Point-in-time gauge value.
    Gauge(f64),
    /// Histogram with explicit bucket boundaries and counts.
    Histogram {
        value: f64,
        buckets: Vec<f64>,
        counts: Vec<u64>,
    },
}

impl OtelMetricValue {
    /// Get the primary numeric value regardless of type.
    pub fn value(&self) -> f64 {
        match self {
            OtelMetricValue::Counter(v) => *v,
            OtelMetricValue::Gauge(v) => *v,
            OtelMetricValue::Histogram { value, .. } => *value,
        }
    }
}

// ────────────────────────────────────────────────────────────────
// OtelResource
// ────────────────────────────────────────────────────────────────

/// Describes the producing entity for all telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelResource {
    /// Service name.
    pub service_name: String,
    /// Service version.
    pub service_version: String,
    /// Deployment environment.
    pub deployment_environment: String,
    /// Additional resource attributes.
    pub attributes: HashMap<String, String>,
}

impl Default for OtelResource {
    fn default() -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            "telemetry.sdk.name".to_string(),
            "chakravyuh-otel".to_string(),
        );
        attrs.insert("telemetry.sdk.language".to_string(), "rust".to_string());
        Self {
            service_name: "chakravyuh".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            deployment_environment: "production".to_string(),
            attributes: attrs,
        }
    }
}

// ────────────────────────────────────────────────────────────────
// OtelSpan
// ────────────────────────────────────────────────────────────────

/// A single OpenTelemetry span representing an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpan {
    /// Unique trace ID (hex-encoded, 32 chars).
    pub trace_id: String,
    /// Unique span ID (hex-encoded, 16 chars).
    pub span_id: String,
    /// Parent span ID (hex-encoded, 16 chars) if this is a child span.
    pub parent_span_id: Option<String>,
    /// Operation name.
    pub name: String,
    /// Start time (Unix epoch, nanos).
    pub start_time_ns: u64,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
    /// Span status.
    pub status: OtelSpanStatus,
    /// Span attributes.
    pub attributes: HashMap<String, String>,
    /// Span kind (client, server, internal, producer, consumer).
    pub kind: String,
}

impl OtelSpan {
    /// Create a new span with the given name and generated IDs.
    pub fn new(name: &str) -> Self {
        Self {
            trace_id: hex_id(16),
            span_id: hex_id(8),
            parent_span_id: None,
            name: name.to_string(),
            start_time_ns: nanos_since_epoch(),
            duration_ns: 0,
            status: OtelSpanStatus::Ok,
            attributes: HashMap::new(),
            kind: "internal".to_string(),
        }
    }

    /// Set the span as a child of another span.
    pub fn with_parent(mut self, parent: &OtelSpan) -> Self {
        self.parent_span_id = Some(parent.span_id.clone());
        self.trace_id = parent.trace_id.clone();
        self
    }

    /// Set the span kind.
    pub fn with_kind(mut self, kind: &str) -> Self {
        self.kind = kind.to_string();
        self
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the span status.
    pub fn with_status(mut self, status: OtelSpanStatus) -> Self {
        self.status = status;
        self
    }

    /// Mark the span as completed with the given duration.
    pub fn finish(&mut self, duration: Duration) {
        self.duration_ns = duration.as_nanos() as u64;
    }

    /// End time in nanoseconds.
    pub fn end_time_ns(&self) -> u64 {
        self.start_time_ns.saturating_add(self.duration_ns)
    }
}

// ────────────────────────────────────────────────────────────────
// OtelMetric
// ────────────────────────────────────────────────────────────────

/// A single OpenTelemetry metric data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelMetric {
    /// Metric name.
    pub name: String,
    /// Metric description.
    pub description: String,
    /// Unit (e.g., "ms", "By", "1").
    pub unit: String,
    /// Metric value.
    pub value: OtelMetricValue,
    /// Timestamp (Unix epoch seconds).
    pub timestamp: f64,
    /// Metric attributes / labels.
    pub attributes: HashMap<String, String>,
}

impl OtelMetric {
    /// Create a new counter metric.
    pub fn counter(name: &str, value: f64) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            unit: "1".to_string(),
            value: OtelMetricValue::Counter(value),
            timestamp: unix_epoch_secs(),
            attributes: HashMap::new(),
        }
    }

    /// Create a new gauge metric.
    pub fn gauge(name: &str, value: f64) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            unit: "1".to_string(),
            value: OtelMetricValue::Gauge(value),
            timestamp: unix_epoch_secs(),
            attributes: HashMap::new(),
        }
    }

    /// Create a new histogram metric.
    pub fn histogram(name: &str, value: f64, buckets: Vec<f64>) -> Self {
        let counts = compute_histogram_counts(value, &buckets);
        Self {
            name: name.to_string(),
            description: String::new(),
            unit: "ms".to_string(),
            value: OtelMetricValue::Histogram {
                value,
                buckets,
                counts,
            },
            timestamp: unix_epoch_secs(),
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the unit.
    pub fn with_unit(mut self, unit: &str) -> Self {
        self.unit = unit.to_string();
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }
}

// ────────────────────────────────────────────────────────────────
// OtelLog
// ────────────────────────────────────────────────────────────────

/// A single OpenTelemetry log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelLog {
    /// Unix epoch timestamp (seconds).
    pub timestamp: f64,
    /// Log severity level.
    pub severity: OtelLogSeverity,
    /// Log body / message.
    pub body: String,
    /// Trace ID if associated with a trace.
    pub trace_id: Option<String>,
    /// Span ID if associated with a span.
    pub span_id: Option<String>,
    /// Log attributes.
    pub attributes: HashMap<String, String>,
}

impl OtelLog {
    /// Create a new log record.
    pub fn new(severity: OtelLogSeverity, body: &str) -> Self {
        Self {
            timestamp: unix_epoch_secs(),
            severity,
            body: body.to_string(),
            trace_id: None,
            span_id: None,
            attributes: HashMap::new(),
        }
    }

    /// Associate this log with a trace context.
    pub fn with_trace(mut self, trace_id: &str, span_id: &str) -> Self {
        self.trace_id = Some(trace_id.to_string());
        self.span_id = Some(span_id.to_string());
        self
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

// ────────────────────────────────────────────────────────────────
// OtelBatch — wire format for export
// ────────────────────────────────────────────────────────────────

/// A batch of OTel telemetry ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelBatch {
    /// Resource information.
    pub resource: OtelResource,
    /// Spans in this batch.
    pub spans: Vec<OtelSpan>,
    /// Metrics in this batch.
    pub metrics: Vec<OtelMetric>,
    /// Logs in this batch.
    pub logs: Vec<OtelLog>,
}

impl OtelBatch {
    /// Create an empty batch with the default resource.
    pub fn new() -> Self {
        Self {
            resource: OtelResource::default(),
            spans: Vec::new(),
            metrics: Vec::new(),
            logs: Vec::new(),
        }
    }

    /// Create a batch with a custom resource.
    pub fn with_resource(resource: OtelResource) -> Self {
        Self {
            resource,
            spans: Vec::new(),
            metrics: Vec::new(),
            logs: Vec::new(),
        }
    }

    /// Add a span to the batch.
    pub fn add_span(&mut self, span: OtelSpan) {
        self.spans.push(span);
    }

    /// Add a metric to the batch.
    pub fn add_metric(&mut self, metric: OtelMetric) {
        self.metrics.push(metric);
    }

    /// Add a log to the batch.
    pub fn add_log(&mut self, log: OtelLog) {
        self.logs.push(log);
    }

    /// Total number of items in this batch.
    pub fn len(&self) -> usize {
        self.spans.len() + self.metrics.len() + self.logs.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the batch.
    pub fn clear(&mut self) {
        self.spans.clear();
        self.metrics.clear();
        self.logs.clear();
    }

    /// Serialize the batch to JSON for export.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Serialize to a compact JSON byte vector.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize a batch from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for OtelBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────
// OtelExporter — batch coordinator
// ────────────────────────────────────────────────────────────────

/// Coordinates batching and would export OTel telemetry to a collector.
/// In this std-only implementation, it accumulates data and provides
/// serialization; actual HTTP/gRPC export would need tokio + reqwest.
#[derive(Debug)]
pub struct OtelExporter {
    config: OtelConfig,
    resource: OtelResource,
    pending: Mutex<OtelBatch>,
    exported_count: Mutex<u64>,
}

impl OtelExporter {
    /// Create a new exporter with default configuration.
    pub fn new() -> Self {
        Self::with_config(OtelConfig::default())
    }

    /// Create a new exporter with custom configuration.
    pub fn with_config(config: OtelConfig) -> Self {
        Self {
            resource: OtelResource {
                service_name: config.service_name.clone(),
                ..OtelResource::default()
            },
            config,
            pending: Mutex::new(OtelBatch::new()),
            exported_count: Mutex::new(0),
        }
    }

    /// Set the resource attributes.
    pub fn set_resource(&mut self, resource: OtelResource) {
        self.resource = resource;
    }

    /// Export a span.
    pub fn export_span(&self, mut span: OtelSpan) {
        if !self.should_sample() {
            return;
        }
        span.trace_id = format!("{:032x}", simple_hash(&span.trace_id));
        if let Ok(mut batch) = self.pending.lock() {
            batch.add_span(span);
        }
    }

    /// Export a metric.
    pub fn export_metric(&self, metric: OtelMetric) {
        if let Ok(mut batch) = self.pending.lock() {
            batch.add_metric(metric);
        }
    }

    /// Export a log.
    pub fn export_log(&self, log: OtelLog) {
        if let Ok(mut batch) = self.pending.lock() {
            batch.add_log(log);
        }
    }

    /// Flush the pending batch and return it as JSON.
    pub fn flush(&self) -> String {
        let mut json = String::new();
        if let Ok(mut batch) = self.pending.lock() {
            batch.resource = self.resource.clone();
            json = batch.to_json();
            batch.clear();
            if let Ok(mut count) = self.exported_count.lock() {
                *count += 1;
            }
        }
        json
    }

    /// Return a snapshot of the pending batch (without clearing).
    pub fn snapshot_batch(&self) -> OtelBatch {
        if let Ok(batch) = self.pending.lock() {
            OtelBatch {
                resource: self.resource.clone(),
                spans: batch.spans.clone(),
                metrics: batch.metrics.clone(),
                logs: batch.logs.clone(),
            }
        } else {
            OtelBatch::new()
        }
    }

    /// Whether the current batch has reached the configured size.
    pub fn should_flush(&self) -> bool {
        if let Ok(batch) = self.pending.lock() {
            batch.len() >= self.config.batch_size
        } else {
            false
        }
    }

    /// Total number of flush operations performed.
    pub fn exported_count(&self) -> u64 {
        self.exported_count.lock().map(|c| *c).unwrap_or(0)
    }

    /// Current pending item count.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Head-based sampling decision.
    fn should_sample(&self) -> bool {
        let rate = self.config.sample_rate;
        rate >= 1.0 || pseudo_random() < rate
    }
}

impl Default for OtelExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────
// SpanBuilder — fluent API for constructing spans
// ────────────────────────────────────────────────────────────────

/// Fluent builder for OtelSpan.
#[derive(Debug, Clone)]
pub struct SpanBuilder {
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    name: String,
    kind: String,
    attributes: HashMap<String, String>,
    status: OtelSpanStatus,
}

impl SpanBuilder {
    /// Start a new span builder.
    pub fn new(name: &str) -> Self {
        Self {
            trace_id: hex_id(16),
            span_id: hex_id(8),
            parent_span_id: None,
            name: name.to_string(),
            kind: "internal".to_string(),
            attributes: HashMap::new(),
            status: OtelSpanStatus::Ok,
        }
    }

    /// Set the trace ID explicitly.
    pub fn trace_id(mut self, id: &str) -> Self {
        self.trace_id = id.to_string();
        self
    }

    /// Set the span ID explicitly.
    pub fn span_id(mut self, id: &str) -> Self {
        self.span_id = id.to_string();
        self
    }

    /// Set the parent span ID.
    pub fn parent(mut self, parent_id: &str) -> Self {
        self.parent_span_id = Some(parent_id.to_string());
        self
    }

    /// Set the span kind.
    pub fn kind(mut self, kind: &str) -> Self {
        self.kind = kind.to_string();
        self
    }

    /// Add an attribute.
    pub fn attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the span status.
    pub fn status(mut self, status: OtelSpanStatus) -> Self {
        self.status = status;
        self
    }

    /// Build the final OtelSpan.
    pub fn build(self) -> OtelSpan {
        OtelSpan {
            trace_id: self.trace_id,
            span_id: self.span_id,
            parent_span_id: self.parent_span_id,
            name: self.name,
            start_time_ns: nanos_since_epoch(),
            duration_ns: 0,
            status: self.status,
            attributes: self.attributes,
            kind: self.kind,
        }
    }
}

// ────────────────────────────────────────────────────────────────
// MetricBuilder — fluent API for constructing metrics
// ────────────────────────────────────────────────────────────────

/// Fluent builder for OtelMetric.
#[derive(Debug, Clone)]
pub struct MetricBuilder {
    name: String,
    description: String,
    unit: String,
    value: Option<OtelMetricValue>,
    attributes: HashMap<String, String>,
}

impl MetricBuilder {
    /// Start building a new metric.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            unit: "1".to_string(),
            value: None,
            attributes: HashMap::new(),
        }
    }

    /// Set a description.
    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set the unit.
    pub fn unit(mut self, unit: &str) -> Self {
        self.unit = unit.to_string();
        self
    }

    /// Set as a counter value.
    pub fn counter(mut self, value: f64) -> Self {
        self.value = Some(OtelMetricValue::Counter(value));
        self
    }

    /// Set as a gauge value.
    pub fn gauge(mut self, value: f64) -> Self {
        self.value = Some(OtelMetricValue::Gauge(value));
        self
    }

    /// Set as a histogram value.
    pub fn histogram(mut self, value: f64, buckets: Vec<f64>) -> Self {
        let counts = compute_histogram_counts(value, &buckets);
        self.value = Some(OtelMetricValue::Histogram {
            value,
            buckets,
            counts,
        });
        self
    }

    /// Add an attribute.
    pub fn attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Build the final OtelMetric. Returns None if no value was set.
    pub fn build(self) -> Option<OtelMetric> {
        let value = self.value?;
        Some(OtelMetric {
            name: self.name,
            description: self.description,
            unit: self.unit,
            value,
            timestamp: unix_epoch_secs(),
            attributes: self.attributes,
        })
    }
}

// ────────────────────────────────────────────────────────────────
// Bridge: convert infra::trace TraceContext to OTel types
// ────────────────────────────────────────────────────────────────

/// Convert an infra::trace::TraceContext into a list of OtelSpans.
/// This bridges the existing tracing infrastructure to OTel format.
pub fn convert_trace_context(trace: &crate::infra::trace::TraceContext) -> Vec<OtelSpan> {
    let trace_id = trace.trace_id.clone();
    let mut spans = Vec::new();

    for (i, ring_span) in trace.spans.iter().enumerate() {
        let parent_id = if i > 0 {
            Some(format!(
                "{:016x}",
                simple_hash(&format!("{}-{}", trace_id, i - 1))
            ))
        } else {
            None
        };

        spans.push(OtelSpan {
            trace_id: trace_id.clone(),
            span_id: format!("{:016x}", simple_hash(&format!("{}-{}", trace_id, i))),
            parent_span_id: parent_id,
            name: format!("ring.{}", ring_span.ring),
            start_time_ns: trace
                .started_at_us
                .saturating_add(ring_span.start_us)
                .saturating_mul(1000),
            duration_ns: ring_span.duration_us.saturating_mul(1000),
            status: if ring_span.decision.starts_with("deny")
                || ring_span.decision.starts_with("error")
            {
                OtelSpanStatus::Error {
                    message: ring_span.decision.clone(),
                }
            } else {
                OtelSpanStatus::Ok
            },
            attributes: ring_span.metadata.clone(),
            kind: "internal".to_string(),
        });
    }

    // Add a root span for the overall request.
    spans.insert(
        0,
        OtelSpan {
            trace_id: trace_id.clone(),
            span_id: format!("{:016x}", simple_hash(&trace_id)),
            parent_span_id: None,
            name: format!("{}.{}", trace.method, trace.path),
            start_time_ns: trace.started_at_us.saturating_mul(1000),
            duration_ns: trace.total_duration_us.saturating_mul(1000),
            status: OtelSpanStatus::Ok,
            attributes: {
                let mut m = HashMap::new();
                m.insert("http.method".to_string(), trace.method.clone());
                m.insert("http.path".to_string(), trace.path.clone());
                m.insert("source.ip".to_string(), trace.source_ip.clone());
                m
            },
            kind: "server".to_string(),
        },
    );

    spans
}

/// Convert an infra::trace::Span directly to an OtelSpan.
pub fn convert_span(ring_span: &crate::infra::trace::Span, trace_id: &str) -> OtelSpan {
    OtelSpan {
        trace_id: trace_id.to_string(),
        span_id: format!(
            "{:016x}",
            simple_hash(&format!("{}-{}", trace_id, ring_span.ring))
        ),
        parent_span_id: None,
        name: format!("ring.{}", ring_span.ring),
        start_time_ns: ring_span.start_us.saturating_mul(1000),
        duration_ns: ring_span.duration_us.saturating_mul(1000),
        status: if ring_span.decision.starts_with("deny") || ring_span.decision.starts_with("error")
        {
            OtelSpanStatus::Error {
                message: ring_span.decision.clone(),
            }
        } else {
            OtelSpanStatus::Ok
        },
        attributes: ring_span.metadata.clone(),
        kind: "internal".to_string(),
    }
}

// ────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────

/// Generate a random hex ID of the given byte length.
fn hex_id(byte_len: usize) -> String {
    let mut s = String::with_capacity(byte_len * 2);
    let seed = nanos_since_epoch();
    let mut state = seed as u64;
    for _ in 0..byte_len * 2 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let nibble = (state >> 32) & 0xF;
        s.push(match nibble % 16 {
            0..=9 => (b'0' + nibble as u8) as char,
            _ => (b'a' + (nibble - 10) as u8) as char,
        });
    }
    s
}

/// Get nanoseconds since Unix epoch.
fn nanos_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Get seconds since Unix epoch as f64.
fn unix_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Simple deterministic hash for generating IDs.
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

/// Pseudo-random float in [0, 1) using system time.
fn pseudo_random() -> f64 {
    let seed = nanos_since_epoch();
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    (state & 0xFFFF_FFFF) as f64 / 4_294_967_295.0
}

/// Compute histogram bucket counts from a value and boundaries.
/// Counts are cumulative: count[i] = number of samples <= buckets[i].
fn compute_histogram_counts(value: f64, buckets: &[f64]) -> Vec<u64> {
    let mut counts = vec![0u64; buckets.len()];
    for (i, &boundary) in buckets.iter().enumerate() {
        if value <= boundary {
            counts[i] = 1;
        }
    }
    // Make cumulative
    let mut cumulative = 0u64;
    for c in counts.iter_mut() {
        cumulative = cumulative.saturating_add(*c);
        *c = cumulative;
    }
    counts
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn otel_config_default() {
        let cfg = OtelConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "http://localhost:4317");
        assert_eq!(cfg.service_name, "chakravyuh");
        assert_eq!(cfg.sample_rate, 1.0);
        assert_eq!(cfg.batch_size, 512);
    }

    #[test]
    fn otel_config_serde_roundtrip() {
        let cfg = OtelConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let restored: OtelConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.enabled, cfg.enabled);
        assert_eq!(restored.endpoint, cfg.endpoint);
        assert_eq!(restored.service_name, cfg.service_name);
    }

    #[test]
    fn otel_span_new() {
        let span = OtelSpan::new("test.operation");
        assert_eq!(span.name, "test.operation");
        assert_eq!(span.trace_id.len(), 32);
        assert_eq!(span.span_id.len(), 16);
        assert!(span.parent_span_id.is_none());
        assert!(span.status.is_ok());
        assert_eq!(span.kind, "internal");
    }

    #[test]
    fn otel_span_with_parent() {
        let parent = OtelSpan::new("parent");
        let child = OtelSpan::new("child").with_parent(&parent);
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(
            child.parent_span_id.as_deref(),
            Some(parent.span_id.as_str())
        );
    }

    #[test]
    fn otel_span_with_kind() {
        let span = OtelSpan::new("server.req").with_kind("server");
        assert_eq!(span.kind, "server");
    }

    #[test]
    fn otel_span_with_attribute() {
        let span = OtelSpan::new("op")
            .with_attribute("http.method", "GET")
            .with_attribute("http.path", "/health");
        assert_eq!(span.attributes.get("http.method").unwrap(), "GET");
        assert_eq!(span.attributes.get("http.path").unwrap(), "/health");
    }

    #[test]
    fn otel_span_with_status_error() {
        let span = OtelSpan::new("op").with_status(OtelSpanStatus::Error {
            message: "timeout".to_string(),
        });
        assert!(!span.status.is_ok());
    }

    #[test]
    fn otel_span_finish() {
        let mut span = OtelSpan::new("op");
        span.finish(Duration::from_millis(50));
        assert_eq!(span.duration_ns, 50_000_000);
        assert!(span.end_time_ns() > span.start_time_ns);
    }

    #[test]
    fn otel_span_serde_roundtrip() {
        let span = OtelSpan::new("test")
            .with_attribute("key", "value")
            .with_status(OtelSpanStatus::Ok);
        let json = serde_json::to_string(&span).expect("serialize");
        let restored: OtelSpan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.name, "test");
        assert_eq!(restored.attributes.get("key").unwrap(), "value");
    }

    #[test]
    fn otel_span_status_debug() {
        let ok = OtelSpanStatus::Ok;
        let err = OtelSpanStatus::Error {
            message: "fail".into(),
        };
        assert!(format!("{:?}", ok).contains("Ok"));
        assert!(format!("{:?}", err).contains("Error"));
    }

    // ── OtelMetric tests ──

    #[test]
    fn otel_metric_counter() {
        let m = OtelMetric::counter("requests_total", 42.0);
        assert_eq!(m.name, "requests_total");
        match m.value {
            OtelMetricValue::Counter(v) => assert_eq!(v, 42.0),
            _ => panic!("expected Counter"),
        }
    }

    #[test]
    fn otel_metric_gauge() {
        let m = OtelMetric::gauge("active_connections", 15.0);
        match m.value {
            OtelMetricValue::Gauge(v) => assert_eq!(v, 15.0),
            _ => panic!("expected Gauge"),
        }
    }

    #[test]
    fn otel_metric_histogram() {
        let buckets = vec![1.0, 5.0, 10.0, 50.0];
        let m = OtelMetric::histogram("latency_ms", 7.5, buckets.clone());
        match &m.value {
            OtelMetricValue::Histogram {
                value,
                buckets: b,
                counts,
            } => {
                assert_eq!(*value, 7.5);
                assert_eq!(b.len(), 4);
                // value=7.5: only fits in bucket 10.0 and 50.0
                assert_eq!(counts[0], 0); // 7.5 > 1.0
                assert_eq!(counts[1], 0); // 7.5 > 5.0
                assert_eq!(counts[2], 1); // 7.5 <= 10.0
                assert!(counts.len() == 4);
            }
            _ => panic!("expected Histogram"),
        }
    }

    #[test]
    fn otel_metric_with_attribute() {
        let m = OtelMetric::counter("req", 1.0).with_attribute("method", "POST");
        assert_eq!(m.attributes.get("method").unwrap(), "POST");
    }

    #[test]
    fn otel_metric_value_extractor() {
        assert_eq!(OtelMetricValue::Counter(10.0).value(), 10.0);
        assert_eq!(OtelMetricValue::Gauge(5.0).value(), 5.0);
        assert_eq!(
            OtelMetricValue::Histogram {
                value: 3.0,
                buckets: vec![],
                counts: vec![]
            }
            .value(),
            3.0
        );
    }

    #[test]
    fn otel_metric_serde_roundtrip() {
        let m = OtelMetric::counter("test_counter", 100.0).with_attribute("env", "prod");
        let json = serde_json::to_string(&m).expect("serialize");
        let restored: OtelMetric = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.name, "test_counter");
    }

    // ── OtelLog tests ──

    #[test]
    fn otel_log_new() {
        let log = OtelLog::new(OtelLogSeverity::Info, "request received");
        assert_eq!(log.severity, OtelLogSeverity::Info);
        assert_eq!(log.body, "request received");
        assert!(log.trace_id.is_none());
    }

    #[test]
    fn otel_log_with_trace() {
        let log = OtelLog::new(OtelLogSeverity::Error, "failed").with_trace("abc123", "def456");
        assert_eq!(log.trace_id.as_deref(), Some("abc123"));
        assert_eq!(log.span_id.as_deref(), Some("def456"));
    }

    #[test]
    fn otel_log_with_attribute() {
        let log =
            OtelLog::new(OtelLogSeverity::Warn, "rate limit").with_attribute("ip", "10.0.0.1");
        assert_eq!(log.attributes.get("ip").unwrap(), "10.0.0.1");
    }

    #[test]
    fn otel_log_severity_ordering() {
        assert!(OtelLogSeverity::Trace < OtelLogSeverity::Debug);
        assert!(OtelLogSeverity::Debug < OtelLogSeverity::Info);
        assert!(OtelLogSeverity::Info < OtelLogSeverity::Warn);
        assert!(OtelLogSeverity::Warn < OtelLogSeverity::Error);
        assert!(OtelLogSeverity::Error < OtelLogSeverity::Fatal);
    }

    #[test]
    fn otel_log_severity_display() {
        assert_eq!(OtelLogSeverity::Info.to_string(), "INFO");
        assert_eq!(OtelLogSeverity::Error.to_string(), "ERROR");
        assert_eq!(OtelLogSeverity::Fatal.to_string(), "FATAL");
    }

    #[test]
    fn otel_log_serde_roundtrip() {
        let log = OtelLog::new(OtelLogSeverity::Error, "test error");
        let json = serde_json::to_string(&log).expect("serialize");
        let restored: OtelLog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.severity, OtelLogSeverity::Error);
        assert_eq!(restored.body, "test error");
    }

    // ── OtelBatch tests ──

    #[test]
    fn otel_batch_new() {
        let batch = OtelBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(batch.spans.is_empty());
    }

    #[test]
    fn otel_batch_add_items() {
        let mut batch = OtelBatch::new();
        batch.add_span(OtelSpan::new("s1"));
        batch.add_metric(OtelMetric::counter("m1", 1.0));
        batch.add_log(OtelLog::new(OtelLogSeverity::Info, "l1"));
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.spans.len(), 1);
        assert_eq!(batch.metrics.len(), 1);
        assert_eq!(batch.logs.len(), 1);
    }

    #[test]
    fn otel_batch_clear() {
        let mut batch = OtelBatch::new();
        batch.add_span(OtelSpan::new("s1"));
        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn otel_batch_to_json() {
        let mut batch = OtelBatch::new();
        batch.add_span(OtelSpan::new("test"));
        let json = batch.to_json();
        assert!(json.contains("test"));
        assert!(json.contains("spans"));
    }

    #[test]
    fn otel_batch_from_json_roundtrip() {
        let mut batch = OtelBatch::new();
        batch.add_span(OtelSpan::new("roundtrip").with_attribute("k", "v"));
        let json = batch.to_json();
        let restored: OtelBatch = OtelBatch::from_json(&json).expect("deserialize");
        assert_eq!(restored.spans.len(), 1);
        assert_eq!(restored.spans[0].name, "roundtrip");
    }

    #[test]
    fn otel_batch_json_bytes() {
        let mut batch = OtelBatch::new();
        batch.add_metric(OtelMetric::gauge("g1", 42.0));
        let bytes = batch.to_json_bytes();
        assert!(!bytes.is_empty());
        let restored: OtelBatch = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(restored.metrics.len(), 1);
    }

    #[test]
    fn otel_batch_with_resource() {
        let resource = OtelResource {
            service_name: "custom-svc".to_string(),
            service_version: "2.0.0".to_string(),
            deployment_environment: "staging".to_string(),
            attributes: HashMap::new(),
        };
        let batch = OtelBatch::with_resource(resource);
        assert_eq!(batch.resource.service_name, "custom-svc");
    }

    // ── OtelExporter tests ──

    #[test]
    fn otel_exporter_new() {
        let exporter = OtelExporter::new();
        assert_eq!(exporter.pending_count(), 0);
        assert_eq!(exporter.exported_count(), 0);
    }

    #[test]
    fn otel_exporter_export_span() {
        let exporter = OtelExporter::with_config(OtelConfig {
            sample_rate: 1.0,
            ..OtelConfig::default()
        });
        exporter.export_span(OtelSpan::new("test"));
        assert_eq!(exporter.pending_count(), 1);
    }

    #[test]
    fn otel_exporter_export_metric() {
        let exporter = OtelExporter::new();
        exporter.export_metric(OtelMetric::counter("test", 1.0));
        assert_eq!(exporter.pending_count(), 1);
    }

    #[test]
    fn otel_exporter_export_log() {
        let exporter = OtelExporter::new();
        exporter.export_log(OtelLog::new(OtelLogSeverity::Info, "hello"));
        assert_eq!(exporter.pending_count(), 1);
    }

    #[test]
    fn otel_exporter_flush() {
        let exporter = OtelExporter::new();
        exporter.export_span(OtelSpan::new("test"));
        exporter.export_metric(OtelMetric::counter("m", 1.0));
        let json = exporter.flush();
        assert!(json.contains("spans"));
        assert!(json.contains("metrics"));
        assert!(exporter.exported_count() >= 1);
        assert_eq!(exporter.pending_count(), 0);
    }

    #[test]
    fn otel_exporter_snapshot_does_not_clear() {
        let exporter = OtelExporter::new();
        exporter.export_span(OtelSpan::new("test"));
        let snap = exporter.snapshot_batch();
        assert_eq!(snap.spans.len(), 1);
        assert_eq!(exporter.pending_count(), 1); // not cleared
    }

    #[test]
    fn otel_exporter_should_flush() {
        let exporter = OtelExporter::with_config(OtelConfig {
            batch_size: 2,
            ..OtelConfig::default()
        });
        exporter.export_span(OtelSpan::new("s1"));
        assert!(!exporter.should_flush());
        exporter.export_span(OtelSpan::new("s2"));
        assert!(exporter.should_flush());
    }

    // ── SpanBuilder tests ──

    #[test]
    fn span_builder_basic() {
        let span = SpanBuilder::new("http.request")
            .kind("server")
            .attribute("method", "GET")
            .status(OtelSpanStatus::Ok)
            .build();
        assert_eq!(span.name, "http.request");
        assert_eq!(span.kind, "server");
        assert_eq!(span.attributes.get("method").unwrap(), "GET");
    }

    #[test]
    fn span_builder_with_parent() {
        let parent = SpanBuilder::new("parent").build();
        let child = SpanBuilder::new("child")
            .parent(&parent.span_id)
            .trace_id(&parent.trace_id)
            .build();
        assert_eq!(
            child.parent_span_id.as_deref(),
            Some(parent.span_id.as_str())
        );
        assert_eq!(child.trace_id, parent.trace_id);
    }

    #[test]
    fn span_builder_error_status() {
        let span = SpanBuilder::new("fail")
            .status(OtelSpanStatus::Error {
                message: "connection refused".to_string(),
            })
            .build();
        assert!(!span.status.is_ok());
    }

    // ── MetricBuilder tests ──

    #[test]
    fn metric_builder_counter() {
        let m = MetricBuilder::new("requests")
            .description("total requests")
            .unit("1")
            .counter(42.0)
            .attribute("method", "GET")
            .build()
            .expect("should build");
        assert_eq!(m.name, "requests");
        assert_eq!(m.unit, "1");
    }

    #[test]
    fn metric_builder_gauge() {
        let m = MetricBuilder::new("connections")
            .gauge(10.0)
            .build()
            .expect("should build");
        match m.value {
            OtelMetricValue::Gauge(v) => assert_eq!(v, 10.0),
            _ => panic!("expected Gauge"),
        }
    }

    #[test]
    fn metric_builder_histogram() {
        let m = MetricBuilder::new("latency")
            .histogram(5.0, vec![1.0, 5.0, 10.0])
            .build()
            .expect("should build");
        match m.value {
            OtelMetricValue::Histogram { value, .. } => assert_eq!(value, 5.0),
            _ => panic!("expected Histogram"),
        }
    }

    #[test]
    fn metric_builder_no_value_returns_none() {
        let result = MetricBuilder::new("empty").build();
        assert!(result.is_none());
    }

    // ── Bridge conversion tests ──

    #[test]
    fn convert_trace_context_basic() {
        let mut trace_ctx =
            crate::infra::trace::TraceContext::new("POST", "/v1/evaluate", "1.2.3.4");
        trace_ctx.record_span(
            "shield",
            Duration::from_micros(150),
            "allow",
            HashMap::new(),
        );
        trace_ctx.record_span("threat", Duration::from_micros(200), "deny:attack", {
            let mut m = HashMap::new();
            m.insert("score".to_string(), "9.5".to_string());
            m
        });
        trace_ctx.total_duration_us = 500;

        let spans = convert_trace_context(&trace_ctx);
        assert_eq!(spans.len(), 3); // 1 root + 2 ring spans
        assert_eq!(spans[0].name, "POST./v1/evaluate");
        assert_eq!(spans[0].kind, "server");
        assert_eq!(spans[1].name, "ring.shield");
        assert_eq!(spans[2].name, "ring.threat");
        // The threat span should have Error status because decision starts with "deny"
        assert!(!spans[2].status.is_ok());
        // All spans should share the same trace_id
        assert_eq!(spans[0].trace_id, spans[1].trace_id);
        assert_eq!(spans[1].trace_id, spans[2].trace_id);
    }

    #[test]
    fn convert_span_single() {
        let ring_span = crate::infra::trace::Span {
            ring: "shield".to_string(),
            start_us: 1000,
            duration_us: 500,
            decision: "allow".to_string(),
            metadata: HashMap::new(),
        };
        let otel = convert_span(&ring_span, "traceabc");
        assert_eq!(otel.trace_id, "traceabc");
        assert_eq!(otel.name, "ring.shield");
        assert!(otel.status.is_ok());
        assert_eq!(otel.duration_ns, 500_000);
    }

    #[test]
    fn convert_span_error_decision() {
        let ring_span = crate::infra::trace::Span {
            ring: "threat".to_string(),
            start_us: 0,
            duration_us: 1000,
            decision: "deny:jailbreak".to_string(),
            metadata: HashMap::new(),
        };
        let otel = convert_span(&ring_span, "trace123");
        assert!(!otel.status.is_ok());
    }

    #[test]
    fn convert_empty_trace_context() {
        let trace_ctx = crate::infra::trace::TraceContext::new("GET", "/health", "127.0.0.1");
        let spans = convert_trace_context(&trace_ctx);
        assert_eq!(spans.len(), 1); // only root span
    }

    // ── Helper tests ──

    #[test]
    fn simple_hash_deterministic() {
        let h1 = simple_hash("hello");
        let h2 = simple_hash("hello");
        let h3 = simple_hash("world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn hex_id_length() {
        assert_eq!(hex_id(8).len(), 16);
        assert_eq!(hex_id(16).len(), 32);
        assert_eq!(hex_id(4).len(), 8);
    }

    #[test]
    fn compute_histogram_counts_basic() {
        let buckets = vec![1.0, 5.0, 10.0];
        let counts = compute_histogram_counts(7.5, &buckets);
        // 7.5 <= 1.0? no (0), 7.5 <= 5.0? no (0), 7.5 <= 10.0? yes (1)
        // Cumulative: [0, 0, 1]
        assert_eq!(counts[0], 0);
        assert_eq!(counts[1], 0);
        assert_eq!(counts[2], 1);
    }

    #[test]
    fn compute_histogram_counts_all_buckets() {
        let buckets = vec![1.0, 5.0, 10.0];
        let counts = compute_histogram_counts(0.5, &buckets);
        // OTel histograms use cumulative counts
        assert_eq!(counts[0], 1);
        assert_eq!(counts[1], 2);
        assert_eq!(counts[2], 3);
    }

    #[test]
    fn compute_histogram_counts_none() {
        let buckets = vec![1.0, 5.0, 10.0];
        let counts = compute_histogram_counts(15.0, &buckets);
        assert_eq!(counts[0], 0);
        assert_eq!(counts[1], 0);
        assert_eq!(counts[2], 0);
    }

    #[test]
    fn otel_resource_default() {
        let res = OtelResource::default();
        assert_eq!(res.service_name, "chakravyuh");
        assert!(!res.service_version.is_empty());
        assert_eq!(res.deployment_environment, "production");
        assert!(res.attributes.contains_key("telemetry.sdk.name"));
    }
}
