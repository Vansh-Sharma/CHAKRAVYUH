// Performance Framework — D5 Module Root
//
// Provides load generation, metrics collection, profiling,
// and performance report generation for CHAKRAVYUH validation.
//
// Architecture:
//   load_generator.rs   — Synthetic request generation with configurable mix
//   metrics_collector.rs — Latency, throughput, and error-rate analysis
//   profiler.rs         — RAII-based code-region profiling
//   report_gen.rs       — Performance report with target checking

pub mod load_generator;
pub mod metrics_collector;
pub mod profiler;
pub mod report_gen;

pub use load_generator::{LoadConfig, LoadGenerator, Request, RequestType};
pub use metrics_collector::{
    LatencySummary, MetricsCollector, MetricsConfig, PerformanceSample, ThroughputPoint,
};
pub use profiler::{Profiler, RegionGuard, RegionSummary};
pub use report_gen::{PerformanceReport, PerformanceTargets, TargetsMet, generate_report, check_targets};
