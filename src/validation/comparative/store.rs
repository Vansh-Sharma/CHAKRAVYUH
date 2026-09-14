// Comparative Research Lab — Benchmark Store (D7)
//
// Persists benchmark results and comparison snapshots.
// Enables time-series analysis of performance evolution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::benchmarks::{
    BenchmarkCategory, BenchmarkDef, BenchmarkResult, BenchmarkSuite, Direction,
};
use super::comparison::{ComparisonReport, ComparisonSnapshot};

/// Query filter for benchmark results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Query {
    pub system: Option<String>,
    pub version: Option<String>,
    pub category: Option<BenchmarkCategory>,
    pub tags: Vec<String>,
    pub run_id: Option<String>,
    pub since: Option<String>, // RFC 3339
    pub until: Option<String>, // RFC 3339
    pub limit: Option<usize>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_system(mut self, s: &str) -> Self {
        self.system = Some(s.to_string());
        self
    }
    pub fn with_version(mut self, v: &str) -> Self {
        self.version = Some(v.to_string());
        self
    }
    pub fn with_category(mut self, c: BenchmarkCategory) -> Self {
        self.category = Some(c);
        self
    }
    pub fn with_tag(mut self, t: &str) -> Self {
        self.tags.push(t.to_string());
        self
    }
    pub fn with_limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Filter a list of results by this query.
    pub fn filter<'a>(&self, results: &'a [BenchmarkResult]) -> Vec<&'a BenchmarkResult> {
        let mut filtered: Vec<&BenchmarkResult> = results.iter().collect();

        if let Some(ref sys) = self.system {
            filtered.retain(|r| r.system == *sys);
        }
        if let Some(ref ver) = self.version {
            filtered.retain(|r| r.version == *ver);
        }
        if let Some(ref run) = self.run_id {
            filtered.retain(|r| r.run_id == *run);
        }
        if let Some(limit) = self.limit {
            filtered.truncate(limit);
        }

        filtered
    }
}

/// Persistent store for benchmark results and snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchmarkStore {
    /// All stored results.
    pub results: Vec<BenchmarkResult>,
    /// All stored snapshots.
    pub snapshots: Vec<ComparisonSnapshot>,
    /// Benchmark definitions registry.
    pub definitions: Vec<BenchmarkDef>,
    /// Direction map (metric_name -> direction).
    pub direction_map: HashMap<String, Direction>,
}

impl BenchmarkStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a benchmark result.
    pub fn record_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    /// Record a batch of results.
    pub fn record_results(&mut self, results: Vec<BenchmarkResult>) {
        self.results.extend(results);
    }

    /// Save a comparison snapshot.
    pub fn save_snapshot(&mut self, snapshot: ComparisonSnapshot) {
        self.snapshots.push(snapshot);
    }

    /// Register a benchmark definition.
    pub fn register_definition(&mut self, def: BenchmarkDef) {
        // Update direction map.
        for metric in &def.metric_names {
            self.direction_map.insert(metric.clone(), def.direction);
        }
        self.definitions.push(def);
    }

    /// Register an entire suite.
    pub fn register_suite(&mut self, suite: &BenchmarkSuite) {
        for def in &suite.benchmarks {
            self.register_definition(def.clone());
        }
    }

    /// Query stored results.
    pub fn query<'a>(&'a self, query: &Query) -> Vec<&'a BenchmarkResult> {
        query.filter(&self.results)
    }

    /// Get the latest snapshot for a given version.
    pub fn latest_snapshot(&self, version: &str) -> Option<&ComparisonSnapshot> {
        self.snapshots
            .iter()
            .filter(|s| s.version == version)
            .last()
    }

    /// Get all snapshots for a version.
    pub fn snapshots_for_version(&self, version: &str) -> Vec<&ComparisonSnapshot> {
        self.snapshots
            .iter()
            .filter(|s| s.version == version)
            .collect()
    }

    /// Compare the latest snapshot of two versions.
    pub fn compare_versions(
        &self,
        baseline_version: &str,
        current_version: &str,
    ) -> Result<ComparisonReport, String> {
        let baseline = self
            .latest_snapshot(baseline_version)
            .ok_or_else(|| format!("No snapshot found for version {}", baseline_version))?;
        let current = self
            .latest_snapshot(current_version)
            .ok_or_else(|| format!("No snapshot found for version {}", current_version))?;

        Ok(ComparisonReport::compare(
            &baseline.results,
            &current.results,
            &self.direction_map,
        ))
    }

    /// Export the entire store as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Import a store from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("JSON parse failed: {}", e))
    }

    /// Save store to a file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| format!("Failed to write {}: {}", path.display(), e))
    }

    /// Load store from a file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        Self::from_json(&json)
    }

    /// Get the directory path for benchmark data.
    pub fn default_store_path() -> PathBuf {
        PathBuf::from("./benchmark_data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(bench_id: &str, version: &str, rate: f64) -> BenchmarkResult {
        BenchmarkResult::new(bench_id, "chakravyuh", version, "run-1")
            .with_metric("detection_rate", rate)
    }

    #[test]
    fn store_record_and_query() {
        let mut store = BenchmarkStore::new();
        store.record_result(make_result("b1", "1.0.0", 0.85));
        store.record_result(make_result("b1", "1.0.0", 0.90));
        store.record_result(make_result("b1", "2.0.0", 0.95));

        let q = Query::new().with_version("1.0.0");
        assert_eq!(store.query(&q).len(), 2);

        let q2 = Query::new().with_version("2.0.0");
        assert_eq!(store.query(&q2).len(), 1);
    }

    #[test]
    fn store_snapshot_and_compare() {
        let mut store = BenchmarkStore::new();
        store
            .direction_map
            .insert("detection_rate".to_string(), Direction::HigherIsBetter);

        let snap1 =
            ComparisonSnapshot::new("1.0.0", "run-1", vec![make_result("b1", "1.0.0", 0.85)]);
        let snap2 =
            ComparisonSnapshot::new("2.0.0", "run-2", vec![make_result("b1", "2.0.0", 0.95)]);

        store.save_snapshot(snap1);
        store.save_snapshot(snap2);

        let report = store.compare_versions("1.0.0", "2.0.0").unwrap();
        assert_eq!(report.deltas.len(), 1);
        assert!(report.deltas[0].is_improvement);
    }

    #[test]
    fn store_json_roundtrip() {
        let mut store = BenchmarkStore::new();
        store.record_result(make_result("b1", "1.0.0", 0.85));

        let json = store.to_json().unwrap();
        let restored = BenchmarkStore::from_json(&json).unwrap();
        assert_eq!(restored.results.len(), 1);
    }

    #[test]
    fn store_missing_version() {
        let store = BenchmarkStore::new();
        let result = store.compare_versions("1.0.0", "2.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn query_with_limit() {
        let mut store = BenchmarkStore::new();
        for i in 0..10 {
            store.record_result(make_result(&format!("b{}", i), "1.0.0", 0.5));
        }
        let q = Query::new().with_version("1.0.0").with_limit(3);
        assert_eq!(store.query(&q).len(), 3);
    }
}
