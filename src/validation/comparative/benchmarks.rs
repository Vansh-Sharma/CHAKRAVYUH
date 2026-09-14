// Comparative Research Lab — Benchmark Definitions (D7)
//
// Defines what to measure, not how to measure it.
// Benchmarks are versioned, tagged, and composable.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The category of a benchmark.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkCategory {
    /// Detection accuracy — how many attacks are caught.
    Detection,
    /// False positive rate — how many benign requests are blocked.
    FalsePositive,
    /// Latency — response time under load.
    Latency,
    /// Throughput — requests per second.
    Throughput,
    /// Drift resistance — how well the system resists drift.
    DriftResistance,
    /// Recovery speed — how fast the system recovers from faults.
    RecoverySpeed,
    /// Coverage — how many attack vectors are covered.
    Coverage,
    /// Memory efficiency — memory usage per request.
    MemoryEfficiency,
    /// Trust accuracy — how accurate the trust model is.
    TrustAccuracy,
    /// Comparative — head-to-head against alternatives.
    Comparative,
}

impl std::fmt::Display for BenchmarkCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkCategory::Detection => write!(f, "detection"),
            BenchmarkCategory::FalsePositive => write!(f, "false_positive"),
            BenchmarkCategory::Latency => write!(f, "latency"),
            BenchmarkCategory::Throughput => write!(f, "throughput"),
            BenchmarkCategory::DriftResistance => write!(f, "drift_resistance"),
            BenchmarkCategory::RecoverySpeed => write!(f, "recovery_speed"),
            BenchmarkCategory::Coverage => write!(f, "coverage"),
            BenchmarkCategory::MemoryEfficiency => write!(f, "memory_efficiency"),
            BenchmarkCategory::TrustAccuracy => write!(f, "trust_accuracy"),
            BenchmarkCategory::Comparative => write!(f, "comparative"),
        }
    }
}

/// A single benchmark definition — what to measure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkDef {
    /// Unique benchmark ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Category.
    pub category: BenchmarkCategory,
    /// Description of what this benchmark measures.
    pub description: String,
    /// The metric name(s) this benchmark produces.
    pub metric_names: Vec<String>,
    /// Higher-is-better or lower-is-better.
    pub direction: Direction,
    /// Tags for filtering.
    pub tags: Vec<String>,
    /// The system/approach this benchmark applies to.
    pub system: String,
    /// Version of the system.
    pub version: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

/// Whether higher or lower values are better.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    HigherIsBetter,
    LowerIsBetter,
}

impl BenchmarkDef {
    pub fn new(
        name: &str,
        category: BenchmarkCategory,
        description: &str,
        metric_names: Vec<String>,
        direction: Direction,
        system: &str,
        version: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            category,
            description: description.to_string(),
            metric_names,
            direction,
            tags: Vec::new(),
            system: system.to_string(),
            version: version.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// A set of benchmarks that should be run together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuite {
    pub id: String,
    pub name: String,
    pub description: String,
    pub benchmarks: Vec<BenchmarkDef>,
    pub version: String,
    pub created_at: String,
}

impl BenchmarkSuite {
    pub fn new(name: &str, description: &str, version: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            benchmarks: Vec::new(),
            version: version.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_benchmark(&mut self, def: BenchmarkDef) {
        self.benchmarks.push(def);
    }

    pub fn benchmarks_by_category(&self, cat: BenchmarkCategory) -> Vec<&BenchmarkDef> {
        self.benchmarks.iter().filter(|b| b.category == cat).collect()
    }
}

/// The result of running a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Which benchmark was run.
    pub benchmark_id: String,
    /// The system/approach that was benchmarked.
    pub system: String,
    /// Version of the system.
    pub version: String,
    /// Metric name → measured value.
    pub metrics: HashMap<String, f64>,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Environment metadata.
    pub environment: HashMap<String, String>,
    /// Run ID this result belongs to.
    pub run_id: String,
    /// Tags.
    pub tags: Vec<String>,
}

impl BenchmarkResult {
    pub fn new(
        benchmark_id: &str,
        system: &str,
        version: &str,
        run_id: &str,
    ) -> Self {
        Self {
            benchmark_id: benchmark_id.to_string(),
            system: system.to_string(),
            version: version.to_string(),
            metrics: HashMap::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            environment: std::collections::HashMap::new(),
            run_id: run_id.to_string(),
            tags: Vec::new(),
        }
    }

    pub fn with_metric(mut self, name: &str, value: f64) -> Self {
        self.metrics.insert(name.to_string(), value);
        self
    }

    pub fn get(&self, name: &str) -> Option<f64> {
        self.metrics.get(name).copied()
    }
}

/// Built-in benchmark definitions for CHAKRAVYUH.
pub fn chakravyuh_benchmarks() -> BenchmarkSuite {
    let mut suite = BenchmarkSuite::new(
        "chakravyuh-core",
        "Core CHAKRAVYUH benchmarks for release validation",
        env!("CARGO_PKG_VERSION"),
    );

    let v = env!("CARGO_PKG_VERSION");

    // Detection benchmarks.
    suite.add_benchmark(
        BenchmarkDef::new(
            "sqli-detection-rate",
            BenchmarkCategory::Detection,
            "SQL injection detection rate across 1000 mutated payloads",
            vec!["detection_rate".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["owasp".to_string(), "sqli".to_string()])
    );

    suite.add_benchmark(
        BenchmarkDef::new(
            "xss-detection-rate",
            BenchmarkCategory::Detection,
            "Cross-site scripting detection rate across 1000 mutated payloads",
            vec!["detection_rate".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["owasp".to_string(), "xss".to_string()])
    );

    suite.add_benchmark(
        BenchmarkDef::new(
            "jailbreak-detection-rate",
            BenchmarkCategory::Detection,
            "Jailbreak detection rate across all 10 mutation strategies",
            vec!["detection_rate".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["llm".to_string(), "jailbreak".to_string()])
    );

    suite.add_benchmark(
        BenchmarkDef::new(
            "prompt-injection-detection-rate",
            BenchmarkCategory::Detection,
            "Prompt injection detection rate (LLM01) with 5 encoding strategies",
            vec!["detection_rate".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["llm".to_string(), "prompt_injection".to_string()])
    );

    // False positive benchmarks.
    suite.add_benchmark(
        BenchmarkDef::new(
            "benign-false-positive-rate",
            BenchmarkCategory::FalsePositive,
            "False positive rate on 1000 benign requests",
            vec!["fp_rate".to_string()],
            Direction::LowerIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["accuracy".to_string()])
    );

    // Latency benchmarks.
    suite.add_benchmark(
        BenchmarkDef::new(
            "p99-latency-under-load",
            BenchmarkCategory::Latency,
            "P99 latency at 1000 RPS",
            vec!["p99_us".to_string(), "p95_us".to_string(), "mean_us".to_string()],
            Direction::LowerIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["performance".to_string(), "latency".to_string()])
    );

    // Throughput benchmarks.
    suite.add_benchmark(
        BenchmarkDef::new(
            "max-throughput",
            BenchmarkCategory::Throughput,
            "Maximum sustainable RPS with <1% error rate",
            vec!["max_rps".to_string(), "error_rate".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["performance".to_string(), "throughput".to_string()])
    );

    // Drift resistance.
    suite.add_benchmark(
        BenchmarkDef::new(
            "drift-detection-sensitivity",
            BenchmarkCategory::DriftResistance,
            "Minimum detectable policy drift magnitude",
            vec!["min_detectable_drift".to_string()],
            Direction::LowerIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["ananta".to_string(), "drift".to_string()])
    );

    // Recovery speed.
    suite.add_benchmark(
        BenchmarkDef::new(
            "ring-recovery-time",
            BenchmarkCategory::RecoverySpeed,
            "Time from ring failure to full trust recovery",
            vec!["recovery_ms".to_string()],
            Direction::LowerIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["resilience".to_string(), "recovery".to_string()])
    );

    // Coverage.
    suite.add_benchmark(
        BenchmarkDef::new(
            "attack-vector-coverage",
            BenchmarkCategory::Coverage,
            "Percentage of OWASP LLM Top 10 attack vectors covered",
            vec!["coverage_pct".to_string()],
            Direction::HigherIsBetter,
            "chakravyuh", v,
        ).with_tags(vec!["owasp".to_string(), "coverage".to_string()])
    );

    suite
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_def_creation() {
        let b = BenchmarkDef::new(
            "test-bench", BenchmarkCategory::Detection,
            "test desc", vec!["rate".to_string()],
            Direction::HigherIsBetter, "test", "1.0.0",
        );
        assert_eq!(b.name, "test-bench");
        assert_eq!(b.category, BenchmarkCategory::Detection);
        assert!(!b.id.is_empty());
    }

    #[test]
    fn benchmark_suite() {
        let mut suite = BenchmarkSuite::new("test", "desc", "1.0.0");
        suite.add_benchmark(BenchmarkDef::new(
            "a", BenchmarkCategory::Latency, "d",
            vec!["p99".to_string()], Direction::LowerIsBetter, "s", "v",
        ));
        suite.add_benchmark(BenchmarkDef::new(
            "b", BenchmarkCategory::Latency, "d",
            vec!["p50".to_string()], Direction::LowerIsBetter, "s", "v",
        ));
        assert_eq!(suite.benchmarks.len(), 2);
        assert_eq!(suite.benchmarks_by_category(BenchmarkCategory::Latency).len(), 2);
        assert_eq!(suite.benchmarks_by_category(BenchmarkCategory::Detection).len(), 0);
    }

    #[test]
    fn benchmark_result() {
        let r = BenchmarkResult::new("bench-1", "chakravyuh", "1.0.0", "run-1")
            .with_metric("detection_rate", 0.95)
            .with_metric("fp_rate", 0.02);
        assert_eq!(r.get("detection_rate"), Some(0.95));
        assert_eq!(r.get("nonexistent"), None);
    }

    #[test]
    fn chakravyuh_benchmarks_not_empty() {
        let suite = chakravyuh_benchmarks();
        assert!(suite.benchmarks.len() >= 10);
        let cats: std::collections::HashSet<_> = suite.benchmarks.iter().map(|b| b.category).collect();
        assert!(cats.contains(&BenchmarkCategory::Detection));
        assert!(cats.contains(&BenchmarkCategory::Latency));
        assert!(cats.contains(&BenchmarkCategory::Throughput));
    }

    #[test]
    fn benchmark_serialization() {
        let b = BenchmarkDef::new(
            "ser-test", BenchmarkCategory::RecoverySpeed, "d",
            vec!["ms".to_string()], Direction::LowerIsBetter, "s", "v",
        );
        let json = serde_json::to_string(&b).unwrap();
        let restored: BenchmarkDef = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, b.name);
    }
}
