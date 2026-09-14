// Production Hardening (Phase 7 → Phase 9)
//
// Production-grade infrastructure for CHAKRAVYUH:
//   Phase 7:
//     1. Graceful Shutdown — SIGTERM/SIGINT handler that drains connections
//     2. Deep Health Checks — per-ring health with latency + error tracking
//     3. Request Timeout — tower middleware for request timeout
//     4. Readiness/Liveness probes — Kubernetes-style probes
//   Phase 8:
//     5. Prometheus Metrics — atomic counters for requests, decisions, latency
//   Phase 9:
//     6. Config File Watcher — auto-reload policy on file changes
//     7. Request Tracing — trace IDs, ring-span correlation
//     8. Audit Trail — tamper-evident hash chain for decisions
//     9. API Key Auth — HMAC-SHA256 signed keys with per-key rate limits
//
// Thread Safety: All monitoring state is internally synchronized.

pub mod api_keys;
pub mod audit;
pub mod config_watcher;
pub mod health;
pub mod metrics;
pub mod shutdown;
pub mod trace;

pub use api_keys::{ApiKeyConfig, ApiKeyInfo, ApiKeyManager, ApiKeyMeta, AuthResult, Permission};
pub use audit::{AuditConfig, AuditEntry, AuditTrail};
pub use config_watcher::{ConfigWatcherConfig, ConfigWatcherHandle, spawn_config_watcher};
pub use health::{is_alive, is_ready, record_request, request_counts, RingHealth, RingHealthTracker, SystemHealth, StoreHealthReport};
pub use metrics::{metrics_text, record_decision, record_endpoint, record_latency, record_ring_eval};
pub use shutdown::ShutdownState;
pub use trace::{TraceContext, extract_trace_id, recent_traces, record_trace, trace_stats};
