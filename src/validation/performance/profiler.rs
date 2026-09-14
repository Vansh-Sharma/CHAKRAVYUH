// Performance Framework — Profiler (D5)
//
// RAII-based code-region profiler. Wrap a code section with
// `profiler.start_region("name")` and the elapsed time is recorded
// when the guard is dropped.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// A named profiling region with accumulated timing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingRegion {
    /// Name of the region.
    pub name: String,
    /// Individual entry durations in microseconds.
    pub entries: Vec<u64>,
    /// Total accumulated time in microseconds.
    pub total_us: u64,
    /// Number of times the region was entered.
    pub call_count: u64,
}

/// Computed summary for a profiling region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionSummary {
    /// Name of the region.
    pub name: String,
    /// Total time spent in this region (us).
    pub total_us: u64,
    /// Number of calls.
    pub call_count: u64,
    /// Average time per call (us).
    pub avg_us: f64,
    /// Maximum single-call time (us).
    pub max_us: u64,
    /// Minimum single-call time (us).
    pub min_us: u64,
    /// Percentage of total profiling time.
    pub pct_of_total: f64,
}

/// RAII guard that records elapsed time on drop.
pub struct RegionGuard<'a> {
    profiler: &'a mut Profiler,
    name: String,
    start: Instant,
}

impl RegionGuard<'_> {
    /// Explicitly record the region and consume the guard.
    /// If not called, the Drop impl handles it.
    pub fn finish(self) {
        let elapsed = self.start.elapsed().as_micros() as u64;
        self.profiler.record_region(&self.name, elapsed);
        // Prevent Drop from double-recording.
        std::mem::forget(self);
    }
}

impl Drop for RegionGuard<'_> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_micros() as u64;
        self.profiler.record_region(&self.name, elapsed);
    }
}

/// Code-region profiler that accumulates timing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profiler {
    regions: HashMap<String, ProfilingRegion>,
}

impl Profiler {
    /// Create a new empty profiler.
    pub fn new() -> Self {
        tracing::debug!("Profiler initialized");
        Self {
            regions: HashMap::new(),
        }
    }

    /// Start profiling a named code region.
    /// Returns a guard that records the elapsed time on drop.
    pub fn start_region(&mut self, name: &str) -> RegionGuard<'_> {
        RegionGuard {
            profiler: self,
            name: name.to_string(),
            start: Instant::now(),
        }
    }

    /// Record a region entry directly (used by RegionGuard).
    pub fn record_region(&mut self, name: &str, elapsed_us: u64) {
        let region = self.regions.entry(name.to_string()).or_insert_with(|| {
            ProfilingRegion {
                name: name.to_string(),
                entries: Vec::new(),
                total_us: 0,
                call_count: 0,
            }
        });
        region.entries.push(elapsed_us);
        region.total_us += elapsed_us;
        region.call_count += 1;
    }

    /// Get the summary for a specific region, if it exists.
    pub fn region_summary(&self, name: &str) -> Option<RegionSummary> {
        let region = self.regions.get(name)?;
        let total_all = self.total_time_us();
        let pct = if total_all > 0 {
            region.total_us as f64 / total_all as f64 * 100.0
        } else {
            0.0
        };
        let (min_us, max_us) = region
            .entries
            .iter()
            .copied()
            .fold((u64::MAX, 0u64), |(mn, mx), v| (mn.min(v), mx.max(v)));
        let min_us = if region.entries.is_empty() { 0 } else { min_us };
        let avg_us = if region.call_count > 0 {
            region.total_us as f64 / region.call_count as f64
        } else {
            0.0
        };

        Some(RegionSummary {
            name: region.name.clone(),
            total_us: region.total_us,
            call_count: region.call_count,
            avg_us,
            max_us,
            min_us,
            pct_of_total: pct,
        })
    }

    /// Get summaries for all regions.
    pub fn all_summaries(&self) -> Vec<RegionSummary> {
        self.regions
            .keys()
            .filter_map(|name| self.region_summary(name))
            .collect()
    }

    /// Get the hottest (most total time) regions, sorted descending.
    pub fn hottest_regions(&self, limit: usize) -> Vec<RegionSummary> {
        let mut summaries = self.all_summaries();
        summaries.sort_by(|a, b| b.total_us.cmp(&a.total_us));
        summaries.truncate(limit);
        summaries
    }

    /// Total profiling time across all regions.
    pub fn total_time_us(&self) -> u64 {
        self.regions.values().map(|r| r.total_us).sum()
    }

    /// Number of distinct regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Clear all profiling data.
    pub fn clear(&mut self) {
        self.regions.clear();
        tracing::debug!("Profiler cleared");
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn region_guard_records_on_drop() {
        let mut profiler = Profiler::new();
        {
            let _guard = profiler.start_region("test-region");
            thread::sleep(Duration::from_millis(5));
        }
        let summary = profiler.region_summary("test-region");
        assert!(summary.is_some());
        let s = summary.unwrap();
        assert_eq!(s.call_count, 1);
        assert!(s.total_us >= 4_000); // at least 4ms
        assert!(s.min_us >= 4_000);
        assert!(s.max_us >= 4_000);
    }

    #[test]
    fn multiple_entries_accumulate() {
        let mut profiler = Profiler::new();
        for _ in 0..5 {
            let _guard = profiler.start_region("loop-region");
            thread::sleep(Duration::from_millis(2));
        }
        let s = profiler.region_summary("loop-region").unwrap();
        assert_eq!(s.call_count, 5);
        assert!(s.total_us >= 10_000);
        assert!(s.avg_us >= 2_000.0);
    }

    #[test]
    fn hottest_regions_sorted() {
        let mut profiler = Profiler::new();
        {
            let _guard = profiler.start_region("fast");
            thread::sleep(Duration::from_millis(1));
        }
        {
            let _guard = profiler.start_region("slow");
            thread::sleep(Duration::from_millis(10));
        }
        {
            let _guard = profiler.start_region("medium");
            thread::sleep(Duration::from_millis(3));
        }
        let hottest = profiler.hottest_regions(2);
        assert_eq!(hottest.len(), 2);
        assert_eq!(hottest[0].name, "slow");
        assert_eq!(hottest[1].name, "medium");
    }

    #[test]
    fn missing_region_returns_none() {
        let profiler = Profiler::new();
        assert!(profiler.region_summary("nonexistent").is_none());
    }

    #[test]
    fn clear_resets_all_data() {
        let mut profiler = Profiler::new();
        {
            let _guard = profiler.start_region("temp");
            thread::sleep(Duration::from_millis(1));
        }
        assert!(profiler.region_count() > 0);
        profiler.clear();
        assert_eq!(profiler.region_count(), 0);
        assert!(profiler.region_summary("temp").is_none());
    }

    #[test]
    fn explicit_finish_prevents_double_count() {
        let mut profiler = Profiler::new();
        {
            let guard = profiler.start_region("explicit");
            thread::sleep(Duration::from_millis(2));
            guard.finish();
        }
        // Should only have 1 entry, not 2.
        let s = profiler.region_summary("explicit").unwrap();
        assert_eq!(s.call_count, 1);
    }
}
