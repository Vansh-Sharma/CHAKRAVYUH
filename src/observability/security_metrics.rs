// Security Metrics — Real-time metrics for the CHAKRAVYUH security gateway
//
// Provides:
//   - ReservoirHistogram: real percentile computation from sorted bucket boundaries
//   - SecurityMetricsCollector: per-ring latencies, decision tracking, FP/FN rates,
//     IP blocking, throughput, error rates
//   - All math uses real linear interpolation for percentiles
//
// No external crate dependencies — uses std + serde only.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────
// ReservoirHistogram — real percentile computation
// ────────────────────────────────────────────────────────────────────

/// A fixed-boundary histogram that records values into sorted bucket ranges
/// and computes percentiles using linear interpolation between bucket midpoints.
///
/// Buckets are defined by sorted boundaries. For example, boundaries [1, 5, 10, 50, 100]
/// create ranges: (-inf, 1], (1, 5], (5, 10], (10, 50], (50, 100], (100, +inf).
/// Values are recorded into the appropriate bucket based on which boundary they
/// fall between.
///
/// Percentile computation uses linear interpolation within the bucket that contains
/// the target percentile position in the cumulative distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservoirHistogram {
    /// Sorted bucket boundary values (e.g., [1.0, 5.0, 10.0, 50.0, 100.0]).
    pub buckets: Vec<f64>,
    /// Count of observations in each bucket.
    /// buckets.len() + 1 entries: underflow + one per boundary + overflow.
    pub counts: Vec<u64>,
}

impl ReservoirHistogram {
    /// Create a new histogram with the given sorted bucket boundaries.
    /// Boundaries must be sorted in ascending order with no duplicates.
    pub fn new(buckets: Vec<f64>) -> Self {
        let mut sorted = buckets;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted.dedup_by(|a, b| a == b);
        let num_ranges = sorted.len() + 1; // underflow + each boundary + overflow
        Self {
            buckets: sorted,
            counts: vec![0u64; num_ranges],
        }
    }

    /// Create a histogram with default latency boundaries (ms).
    pub fn latency_default() -> Self {
        Self::new(vec![
            0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
        ])
    }

    /// Record a value into the histogram.
    pub fn record(&mut self, value: f64) {
        let idx = match self
            .buckets
            .binary_search_by(|b| b.partial_cmp(&value).unwrap_or(std::cmp::Ordering::Greater))
        {
            Ok(i) => i + 1,                         // value == boundary → goes into next bucket
            Err(i) => i.min(self.counts.len() - 1), // underflow if before first, overflow if after last
        };
        self.counts[idx] = self.counts[idx].saturating_add(1);
    }

    /// Compute the percentile of the distribution using linear interpolation.
    /// `p` should be in [0.0, 100.0].
    ///
    /// The percentile is computed by finding the cumulative count position
    /// and interpolating between bucket boundaries.
    pub fn percentile(&self, p: f64) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let p_clamped = p.max(0.0).min(100.0);
        let target_rank = (p_clamped / 100.0) * (total as f64);

        let mut cumulative = 0.0_f64;
        for (i, &cnt) in self.counts.iter().enumerate() {
            let prev_cumulative = cumulative;
            cumulative += cnt as f64;

            if cumulative >= target_rank {
                if cnt == 0 {
                    return self.bucket_lower_bound(i);
                }

                // Linear interpolation within this bucket
                let fraction = if cumulative > prev_cumulative {
                    (target_rank - prev_cumulative) / (cumulative - prev_cumulative)
                } else {
                    0.0
                };

                let lower = self.bucket_lower_bound(i);
                let upper = self.bucket_upper_bound(i);
                return lower + fraction * (upper - lower);
            }
        }

        // Fallback: return the upper bound of the overflow bucket
        if self.buckets.is_empty() {
            return 0.0;
        }
        *self.buckets.last().unwrap()
    }

    /// p50 latency.
    pub fn p50(&self) -> f64 {
        self.percentile(50.0)
    }

    /// p95 latency.
    pub fn p95(&self) -> f64 {
        self.percentile(95.0)
    }

    /// p99 latency.
    pub fn p99(&self) -> f64 {
        self.percentile(99.0)
    }

    /// Arithmetic mean of the distribution (approximate from bucket midpoints).
    pub fn mean(&self) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let mut sum = 0.0_f64;
        for (i, &cnt) in self.counts.iter().enumerate() {
            if cnt > 0 {
                let lower = self.bucket_lower_bound(i);
                let upper = self.bucket_upper_bound(i);
                let midpoint = (lower + upper) / 2.0;
                sum += midpoint * cnt as f64;
            }
        }
        sum / total as f64
    }

    /// Approximate minimum value (lower bound of first non-empty bucket).
    pub fn min(&self) -> f64 {
        for (i, &cnt) in self.counts.iter().enumerate() {
            if cnt > 0 {
                return self.bucket_lower_bound(i);
            }
        }
        0.0
    }

    /// Approximate maximum value (upper bound of last non-empty bucket).
    pub fn max(&self) -> f64 {
        for i in (0..self.counts.len()).rev() {
            if self.counts[i] > 0 {
                return self.bucket_upper_bound(i);
            }
        }
        0.0
    }

    /// Total number of recorded observations.
    pub fn count(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Approximate standard deviation (from bucket midpoints).
    pub fn std_dev(&self) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let mean_val = self.mean();
        let mut sum_sq_diff = 0.0_f64;
        for (i, &cnt) in self.counts.iter().enumerate() {
            if cnt > 0 {
                let lower = self.bucket_lower_bound(i);
                let upper = self.bucket_upper_bound(i);
                let midpoint = (lower + upper) / 2.0;
                let diff = midpoint - mean_val;
                sum_sq_diff += diff * diff * cnt as f64;
            }
        }
        (sum_sq_diff / total as f64).sqrt()
    }

    /// Merge another histogram's counts into this one.
    /// Both histograms must have the same bucket boundaries.
    pub fn merge(&mut self, other: &ReservoirHistogram) -> bool {
        if self.buckets != other.buckets {
            return false;
        }
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a = a.saturating_add(*b);
        }
        true
    }

    /// Clear all counts.
    pub fn clear(&mut self) {
        for c in self.counts.iter_mut() {
            *c = 0;
        }
    }

    /// Lower bound of bucket range at index `i`.
    /// Bucket 0 (underflow) lower bound is 0.
    /// Bucket i (i >= 1) lower bound is buckets[i-1].
    fn bucket_lower_bound(&self, i: usize) -> f64 {
        if i == 0 {
            0.0
        } else if i <= self.buckets.len() {
            self.buckets[i - 1]
        } else {
            self.buckets.last().copied().unwrap_or(0.0)
        }
    }

    /// Upper bound of bucket range at index `i`.
    /// Bucket i (i < buckets.len()) upper bound is buckets[i].
    /// Overflow bucket (last) has unbounded upper; we use 2x last boundary.
    fn bucket_upper_bound(&self, i: usize) -> f64 {
        if i < self.buckets.len() {
            self.buckets[i]
        } else {
            self.buckets.last().copied().unwrap_or(0.0) * 2.0
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// RingLatencyStats
// ────────────────────────────────────────────────────────────────────

/// Per-ring latency statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingLatencyStats {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub mean: f64,
    pub min: f64,
    pub max: f64,
    pub std_dev: f64,
    pub count: u64,
}

// ────────────────────────────────────────────────────────────────────
// DecisionDistribution
// ────────────────────────────────────────────────────────────────────

/// Decision outcome distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionDistribution {
    pub allow: u64,
    pub deny: u64,
    pub challenge: u64,
    pub escalate: u64,
    pub total: u64,
    pub allow_pct: f64,
    pub deny_pct: f64,
}

// ────────────────────────────────────────────────────────────────────
// IpBlockEntry
// ────────────────────────────────────────────────────────────────────

/// An IP address block record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockEntry {
    pub ip: String,
    pub block_count: u64,
    pub last_blocked: String,
}

// ────────────────────────────────────────────────────────────────────
// SecurityMetricsCollector
// ────────────────────────────────────────────────────────────────────

/// Collects and aggregates security-specific metrics for the gateway.
///
/// Thread safety: All mutable state is protected by std::sync::Mutex.
pub struct SecurityMetricsCollector {
    /// Per-ring latency histograms.
    ring_histograms: std::sync::Mutex<HashMap<String, ReservoirHistogram>>,
    /// Per-ring per-outcome decision counters: ring -> outcome -> count.
    decision_counters: std::sync::Mutex<HashMap<String, HashMap<String, u64>>>,
    /// False positive tracker: (ring, ip, reason, timestamp).
    false_positives: std::sync::Mutex<Vec<(String, String, String, f64)>>,
    /// False negative tracker: (ring, ip, reason, timestamp).
    false_negatives: std::sync::Mutex<Vec<(String, String, String, f64)>>,
    /// IP block tracker: ip -> (block_count, last_blocked_timestamp).
    ip_blocks: std::sync::Mutex<HashMap<String, (u64, f64)>>,
    /// Throughput tracker: circular buffer of timestamps.
    throughput_buffer: std::sync::Mutex<Vec<f64>>,
    /// Error count for error rate calculation.
    error_count: std::sync::Mutex<u64>,
    /// Total requests counter.
    total_requests: std::sync::Mutex<u64>,
    /// Retention window in seconds.
    retention_window_secs: u64,
    /// Maximum throughput buffer size.
    max_throughput_buffer: usize,
}

impl SecurityMetricsCollector {
    /// Create a new metrics collector with default settings.
    pub fn new() -> Self {
        Self::with_retention(3600)
    }

    /// Create a new metrics collector with a custom retention window.
    pub fn with_retention(retention_window_secs: u64) -> Self {
        Self {
            ring_histograms: std::sync::Mutex::new(HashMap::new()),
            decision_counters: std::sync::Mutex::new(HashMap::new()),
            false_positives: std::sync::Mutex::new(Vec::new()),
            false_negatives: std::sync::Mutex::new(Vec::new()),
            ip_blocks: std::sync::Mutex::new(HashMap::new()),
            throughput_buffer: std::sync::Mutex::new(Vec::new()),
            error_count: std::sync::Mutex::new(0),
            total_requests: std::sync::Mutex::new(0),
            retention_window_secs,
            max_throughput_buffer: 10_000,
        }
    }

    /// Record a ring evaluation latency.
    pub fn record_ring_latency(&self, ring: &str, latency_ms: f64) {
        if let Ok(mut histos) = self.ring_histograms.lock() {
            let histogram = histos
                .entry(ring.to_string())
                .or_insert_with(ReservoirHistogram::latency_default);
            histogram.record(latency_ms);
        }
        if let Ok(mut total) = self.total_requests.lock() {
            *total = total.saturating_add(1);
        }
        if let Ok(mut buf) = self.throughput_buffer.lock() {
            let now = unix_epoch_secs();
            buf.push(now);
            if buf.len() > self.max_throughput_buffer {
                let drain_count = buf.len() - self.max_throughput_buffer;
                buf.drain(..drain_count);
            }
        }
    }

    /// Record a decision outcome for a ring.
    pub fn record_decision_outcome(&self, ring: &str, outcome: &str) {
        let normalized_outcome = if outcome.starts_with("deny") {
            "deny".to_string()
        } else {
            outcome.to_string()
        };
        if let Ok(mut counters) = self.decision_counters.lock() {
            let ring_counts = counters
                .entry(ring.to_string())
                .or_insert_with(HashMap::new);
            let entry = ring_counts.entry(normalized_outcome.clone()).or_insert(0);
            *entry = entry.saturating_add(1);
        }
    }

    /// Record a false positive: a deny that should have been allow.
    pub fn record_false_positive(&self, ring: &str, ip: &str, reason: &str) {
        let entry = (
            ring.to_string(),
            ip.to_string(),
            reason.to_string(),
            unix_epoch_secs(),
        );
        if let Ok(mut fp) = self.false_positives.lock() {
            fp.push(entry);
            self.prune_old_entries(&mut fp);
        }
    }

    /// Record a false negative: an allow that should have been deny.
    pub fn record_false_negative(&self, ring: &str, ip: &str, reason: &str) {
        let entry = (
            ring.to_string(),
            ip.to_string(),
            reason.to_string(),
            unix_epoch_secs(),
        );
        if let Ok(mut fneg) = self.false_negatives.lock() {
            fneg.push(entry);
            self.prune_old_entries(&mut fneg);
        }
    }

    /// Record an IP block event.
    pub fn record_ip_block(&self, ip: &str) {
        let now = unix_epoch_secs();
        if let Ok(mut blocks) = self.ip_blocks.lock() {
            let entry = blocks.entry(ip.to_string()).or_insert((0, now));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
        }
    }

    /// Record an error.
    pub fn record_error(&self) {
        if let Ok(mut count) = self.error_count.lock() {
            *count = count.saturating_add(1);
        }
        if let Ok(mut total) = self.total_requests.lock() {
            *total = total.saturating_add(1);
        }
    }

    /// Get latency statistics for a specific ring.
    pub fn ring_latency_stats(&self, ring: &str) -> RingLatencyStats {
        if let Ok(histos) = self.ring_histograms.lock() {
            if let Some(hist) = histos.get(ring) {
                return RingLatencyStats {
                    p50: hist.p50(),
                    p95: hist.p95(),
                    p99: hist.p99(),
                    mean: hist.mean(),
                    min: hist.min(),
                    max: hist.max(),
                    std_dev: hist.std_dev(),
                    count: hist.count(),
                };
            }
        }
        RingLatencyStats {
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
            mean: 0.0,
            min: 0.0,
            max: 0.0,
            std_dev: 0.0,
            count: 0,
        }
    }

    /// Get the overall decision distribution across all rings.
    pub fn decision_distribution(&self) -> DecisionDistribution {
        let mut allow: u64 = 0;
        let mut deny: u64 = 0;
        let mut challenge: u64 = 0;
        let mut escalate: u64 = 0;

        if let Ok(counters) = self.decision_counters.lock() {
            for ring_counts in counters.values() {
                allow = allow.saturating_add(*ring_counts.get("allow").unwrap_or(&0));
                deny = deny.saturating_add(*ring_counts.get("deny").unwrap_or(&0));
                challenge = challenge.saturating_add(*ring_counts.get("challenge").unwrap_or(&0));
                escalate = escalate.saturating_add(*ring_counts.get("escalate").unwrap_or(&0));
            }
        }

        let total = allow
            .saturating_add(deny)
            .saturating_add(challenge)
            .saturating_add(escalate);
        let allow_pct = if total > 0 {
            (allow as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let deny_pct = if total > 0 {
            (deny as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        DecisionDistribution {
            allow,
            deny,
            challenge,
            escalate,
            total,
            allow_pct,
            deny_pct,
        }
    }

    /// Compute the false positive rate: false_positives / (false_positives + true_deny).
    pub fn false_positive_rate(&self) -> f64 {
        let fp_count = self
            .false_positives
            .lock()
            .map(|fp| fp.len() as u64)
            .unwrap_or(0);
        let deny_count = self
            .decision_counters
            .lock()
            .map(|counters| {
                counters
                    .values()
                    .map(|rc| *rc.get("deny").unwrap_or(&0))
                    .sum::<u64>()
            })
            .unwrap_or(0);

        let denominator = fp_count.saturating_add(deny_count);
        if denominator == 0 {
            return 0.0;
        }
        fp_count as f64 / denominator as f64
    }

    /// Get a summary of all rings with their stats.
    pub fn per_ring_summary(&self) -> HashMap<String, RingLatencyStats> {
        let mut summary = HashMap::new();
        if let Ok(histos) = self.ring_histograms.lock() {
            for (ring, hist) in histos.iter() {
                summary.insert(
                    ring.clone(),
                    RingLatencyStats {
                        p50: hist.p50(),
                        p95: hist.p95(),
                        p99: hist.p99(),
                        mean: hist.mean(),
                        min: hist.min(),
                        max: hist.max(),
                        std_dev: hist.std_dev(),
                        count: hist.count(),
                    },
                );
            }
        }
        summary
    }

    /// Get top N blocked IPs by block count.
    pub fn top_blocked_ips(&self, n: usize) -> Vec<IpBlockEntry> {
        let mut entries: Vec<IpBlockEntry> = Vec::new();
        if let Ok(blocks) = self.ip_blocks.lock() {
            for (ip, &(count, last_blocked)) in blocks.iter() {
                entries.push(IpBlockEntry {
                    ip: ip.clone(),
                    block_count: count,
                    last_blocked: format!("{}", last_blocked),
                });
            }
        }
        entries.sort_by(|a, b| b.block_count.cmp(&a.block_count));
        entries.truncate(n);
        entries
    }

    /// Compute throughput: requests per second over the retention window.
    pub fn throughput_per_second(&self) -> f64 {
        if let Ok(buf) = self.throughput_buffer.lock() {
            if buf.is_empty() {
                return 0.0;
            }
            let now = unix_epoch_secs();
            let cutoff = now - self.retention_window_secs as f64;
            // Count entries within the window
            let count = buf.iter().filter(|&&t| t > cutoff).count();
            let window_secs = (now
                - buf
                    .iter()
                    .cloned()
                    .filter(|&t| t > cutoff)
                    .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                    .unwrap_or(now))
            .max(1.0);
            count as f64 / window_secs
        } else {
            0.0
        }
    }

    /// Compute error rate: errors / total requests.
    pub fn error_rate(&self) -> f64 {
        let errors = self.error_count.lock().map(|e| *e).unwrap_or(0);
        let total = self.total_requests.lock().map(|t| *t).unwrap_or(0);
        if total == 0 {
            return 0.0;
        }
        errors as f64 / total as f64
    }

    /// Get all ring names that have been recorded.
    pub fn all_rings(&self) -> Vec<String> {
        let mut rings = Vec::new();
        if let Ok(histos) = self.ring_histograms.lock() {
            rings = histos.keys().cloned().collect();
        }
        rings
    }

    /// Prune entries older than the retention window.
    fn prune_old_entries(&self, entries: &mut Vec<(String, String, String, f64)>) {
        let cutoff = unix_epoch_secs() - self.retention_window_secs as f64;
        entries.retain(|&(_, _, _, ts)| ts > cutoff);
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        if let Ok(mut histos) = self.ring_histograms.lock() {
            histos.clear();
        }
        if let Ok(mut counters) = self.decision_counters.lock() {
            counters.clear();
        }
        if let Ok(mut fp) = self.false_positives.lock() {
            fp.clear();
        }
        if let Ok(mut fneg) = self.false_negatives.lock() {
            fneg.clear();
        }
        if let Ok(mut blocks) = self.ip_blocks.lock() {
            blocks.clear();
        }
        if let Ok(mut buf) = self.throughput_buffer.lock() {
            buf.clear();
        }
        if let Ok(mut ec) = self.error_count.lock() {
            *ec = 0;
        }
        if let Ok(mut tr) = self.total_requests.lock() {
            *tr = 0;
        }
    }
}

impl Default for SecurityMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper: get current unix epoch seconds.
fn unix_epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReservoirHistogram tests ──

    #[test]
    fn histogram_new_empty() {
        let h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        assert_eq!(h.count(), 0);
        assert_eq!(h.buckets.len(), 3);
        assert_eq!(h.counts.len(), 4); // underflow + 3 ranges + overflow
    }

    #[test]
    fn histogram_new_deduplicates() {
        let h = ReservoirHistogram::new(vec![1.0, 1.0, 5.0, 5.0]);
        assert_eq!(h.buckets.len(), 2);
        assert_eq!(h.counts.len(), 3);
    }

    #[test]
    fn histogram_record_single() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        h.record(3.0);
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn histogram_record_many() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        for _ in 0..100 {
            h.record(3.0);
        }
        assert_eq!(h.count(), 100);
    }

    #[test]
    fn histogram_record_negative() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        h.record(-5.0);
        assert_eq!(h.count(), 1);
        assert_eq!(h.counts[0], 1); // underflow bucket
    }

    #[test]
    fn histogram_record_overflow() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        h.record(100.0);
        assert_eq!(h.count(), 1);
        // Overflow bucket is the last one
        assert_eq!(h.counts[3], 1);
    }

    #[test]
    fn histogram_percentile_empty() {
        let h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        assert_eq!(h.percentile(50.0), 0.0);
    }

    #[test]
    fn histogram_p50_basic() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        // All values in the (1, 5] bucket
        for _ in 0..100 {
            h.record(3.0);
        }
        let p50 = h.p50();
        assert!(
            p50 > 1.0 && p50 <= 5.0,
            "p50 should be in (1, 5] range, got {}",
            p50
        );
    }

    #[test]
    fn histogram_p95_with_distribution() {
        let mut h = ReservoirHistogram::latency_default();
        // Most values are low latency
        for _ in 0..90 {
            h.record(1.0);
        }
        // Some values are higher
        for _ in 0..9 {
            h.record(50.0);
        }
        // One very high value
        h.record(500.0);

        let p95 = h.p95();
        let p99 = h.p99();
        assert!(p95 > 1.0, "p95 should be above 1ms, got {}", p95);
        assert!(
            p99 > p95,
            "p99 should be above p95: p99={}, p95={}",
            p99,
            p95
        );
    }

    #[test]
    fn histogram_p99_is_higher_than_p50() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0, 50.0, 100.0]);
        for _ in 0..50 {
            h.record(2.0);
        }
        for _ in 0..30 {
            h.record(15.0);
        }
        for _ in 0..15 {
            h.record(60.0);
        }
        for _ in 0..5 {
            h.record(200.0);
        }
        let p50 = h.p50();
        let p95 = h.p95();
        let p99 = h.p99();
        assert!(p50 <= p95, "p50={} should be <= p95={}", p50, p95);
        assert!(p95 <= p99, "p95={} should be <= p99={}", p95, p99);
    }

    #[test]
    fn histogram_percentile_clamped() {
        let mut h = ReservoirHistogram::new(vec![10.0]);
        h.record(5.0);
        // Percentile at 0% and 100% should not panic
        let p0 = h.percentile(0.0);
        let p100 = h.percentile(100.0);
        assert!(p0 >= 0.0);
        assert!(p100 >= p0);
    }

    #[test]
    fn histogram_mean_empty() {
        let h = ReservoirHistogram::new(vec![1.0]);
        assert_eq!(h.mean(), 0.0);
    }

    #[test]
    fn histogram_mean_single_bucket() {
        let mut h = ReservoirHistogram::new(vec![10.0]);
        h.record(5.0);
        let mean = h.mean();
        // Bucket 0 (underflow, range [0, 10)), midpoint = 5.0
        assert_eq!(mean, 5.0);
    }

    #[test]
    fn histogram_mean_distributed() {
        let mut h = ReservoirHistogram::new(vec![5.0, 10.0]);
        h.record(2.0); // underflow bucket [0, 5), midpoint 2.5
        h.record(7.0); // bucket [5, 10), midpoint 7.5
        let mean = h.mean();
        let expected = (2.5 + 7.5) / 2.0;
        assert!(
            (mean - expected).abs() < 0.01,
            "mean={}, expected={}",
            mean,
            expected
        );
    }

    #[test]
    fn histogram_min_max_empty() {
        let h = ReservoirHistogram::new(vec![1.0, 10.0]);
        assert_eq!(h.min(), 0.0);
        assert_eq!(h.max(), 0.0);
    }

    #[test]
    fn histogram_min_max() {
        let mut h = ReservoirHistogram::new(vec![1.0, 10.0, 100.0]);
        h.record(0.5); // underflow
        h.record(5.0); // [1, 10)
        h.record(50.0); // [10, 100)
        h.record(200.0); // overflow
        assert_eq!(h.min(), 0.0);
        // Max from overflow: 2x last boundary = 200.0
        assert_eq!(h.max(), 200.0);
    }

    #[test]
    fn histogram_std_dev() {
        let mut h = ReservoirHistogram::new(vec![5.0, 10.0]);
        for _ in 0..100 {
            h.record(7.0); // all in same bucket
        }
        let sd = h.std_dev();
        // All values same bucket midpoint → std_dev should be very small
        assert!(
            sd < 1.0,
            "std_dev should be near 0 for uniform values, got {}",
            sd
        );
    }

    #[test]
    fn histogram_merge_compatible() {
        let mut h1 = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        let mut h2 = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        h1.record(2.0);
        h2.record(7.0);
        assert!(h1.merge(&h2));
        assert_eq!(h1.count(), 2);
    }

    #[test]
    fn histogram_merge_incompatible() {
        let mut h1 = ReservoirHistogram::new(vec![1.0, 5.0]);
        let h2 = ReservoirHistogram::new(vec![1.0, 10.0]);
        assert!(!h1.merge(&h2));
    }

    #[test]
    fn histogram_clear() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0]);
        h.record(2.0);
        h.record(3.0);
        assert_eq!(h.count(), 2);
        h.clear();
        assert_eq!(h.count(), 0);
    }

    #[test]
    fn histogram_latency_default() {
        let h = ReservoirHistogram::latency_default();
        assert_eq!(h.buckets.len(), 12);
        assert_eq!(h.counts.len(), 13);
        assert_eq!(h.buckets[0], 0.1);
    }

    #[test]
    fn histogram_serde_roundtrip() {
        let mut h = ReservoirHistogram::new(vec![1.0, 5.0, 10.0]);
        h.record(3.0);
        h.record(7.0);
        let json = serde_json::to_string(&h).expect("serialize");
        let restored: ReservoirHistogram = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.count(), 2);
        assert_eq!(restored.buckets, h.buckets);
    }

    // ── SecurityMetricsCollector tests ──

    #[test]
    fn collector_new() {
        let c = SecurityMetricsCollector::new();
        assert_eq!(c.all_rings().len(), 0);
        assert_eq!(c.false_positive_rate(), 0.0);
        assert_eq!(c.throughput_per_second(), 0.0);
        assert_eq!(c.error_rate(), 0.0);
    }

    #[test]
    fn collector_record_ring_latency() {
        let c = SecurityMetricsCollector::new();
        c.record_ring_latency("shield", 2.5);
        c.record_ring_latency("shield", 5.0);
        c.record_ring_latency("threat", 10.0);

        let shield_stats = c.ring_latency_stats("shield");
        assert_eq!(shield_stats.count, 2);

        let threat_stats = c.ring_latency_stats("threat");
        assert_eq!(threat_stats.count, 1);

        let unknown_stats = c.ring_latency_stats("memory");
        assert_eq!(unknown_stats.count, 0);
    }

    #[test]
    fn collector_ring_latency_percentiles() {
        let c = SecurityMetricsCollector::new();
        // Record many values
        for i in 0..100 {
            c.record_ring_latency("shield", i as f64 * 0.1); // 0.0 to 9.9 ms
        }
        let stats = c.ring_latency_stats("shield");
        assert_eq!(stats.count, 100);
        assert!(stats.mean > 0.0);
        assert!(stats.p99 >= stats.p95);
        assert!(stats.p95 >= stats.p50);
        assert!(stats.std_dev >= 0.0);
    }

    #[test]
    fn collector_record_decision_outcome() {
        let c = SecurityMetricsCollector::new();
        c.record_decision_outcome("shield", "allow");
        c.record_decision_outcome("shield", "allow");
        c.record_decision_outcome("shield", "deny:attack");
        c.record_decision_outcome("shield", "challenge");
        c.record_decision_outcome("shield", "escalate");

        let dist = c.decision_distribution();
        assert_eq!(dist.allow, 2);
        assert_eq!(dist.deny, 1);
        assert_eq!(dist.challenge, 1);
        assert_eq!(dist.escalate, 1);
        assert_eq!(dist.total, 5);
        assert!((dist.allow_pct - 40.0).abs() < 0.01);
        assert!((dist.deny_pct - 20.0).abs() < 0.01);
    }

    #[test]
    fn collector_decision_distribution_empty() {
        let c = SecurityMetricsCollector::new();
        let dist = c.decision_distribution();
        assert_eq!(dist.total, 0);
        assert_eq!(dist.allow_pct, 0.0);
    }

    #[test]
    fn collector_false_positive_rate() {
        let c = SecurityMetricsCollector::new();
        // Record some deny decisions
        for _ in 0..10 {
            c.record_decision_outcome("shield", "deny:blocked");
        }
        // Record some false positives
        for _ in 0..2 {
            c.record_false_positive("shield", "10.0.0.1", "benign pattern");
        }

        let rate = c.false_positive_rate();
        // FP = 2, deny = 10, rate = 2 / (2 + 10) = 0.1666...
        assert!(
            (rate - 2.0 / 12.0).abs() < 0.001,
            "FP rate={}, expected~0.1667",
            rate
        );
    }

    #[test]
    fn collector_false_positive_rate_zero() {
        let c = SecurityMetricsCollector::new();
        assert_eq!(c.false_positive_rate(), 0.0);
    }

    #[test]
    fn collector_record_false_negative() {
        let c = SecurityMetricsCollector::new();
        c.record_false_negative("threat", "10.0.0.1", "missed attack");
        // Should not panic; FN tracking is for future alerting integration
        let _ = c.false_positive_rate(); // just ensure it doesn't break
    }

    #[test]
    fn collector_ip_block_tracking() {
        let c = SecurityMetricsCollector::new();
        c.record_ip_block("10.0.0.1");
        c.record_ip_block("10.0.0.1");
        c.record_ip_block("10.0.0.2");

        let top = c.top_blocked_ips(5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].ip, "10.0.0.1");
        assert_eq!(top[0].block_count, 2);
        assert_eq!(top[1].ip, "10.0.0.2");
        assert_eq!(top[1].block_count, 1);
    }

    #[test]
    fn collector_ip_block_limit() {
        let c = SecurityMetricsCollector::new();
        for i in 0..20 {
            c.record_ip_block(&format!("10.0.0.{}", i));
        }
        let top = c.top_blocked_ips(5);
        assert_eq!(top.len(), 5);
    }

    #[test]
    fn collector_throughput_basic() {
        let c = SecurityMetricsCollector::new();
        // Record some latencies to populate throughput buffer
        for _ in 0..10 {
            c.record_ring_latency("shield", 1.0);
            // Small sleep to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let tps = c.throughput_per_second();
        assert!(tps > 0.0, "throughput should be positive, got {}", tps);
    }

    #[test]
    fn collector_throughput_empty() {
        let c = SecurityMetricsCollector::new();
        assert_eq!(c.throughput_per_second(), 0.0);
    }

    #[test]
    fn collector_error_rate() {
        let c = SecurityMetricsCollector::new();
        // Record some requests as errors
        for _ in 0..3 {
            c.record_error();
        }
        // Record some normal requests
        c.record_ring_latency("shield", 1.0);
        c.record_ring_latency("shield", 2.0);

        let rate = c.error_rate();
        // 3 errors, 5 total
        let expected = 3.0 / 5.0;
        assert!(
            (rate - expected).abs() < 0.01,
            "error_rate={}, expected={}",
            rate,
            expected
        );
    }

    #[test]
    fn collector_error_rate_zero() {
        let c = SecurityMetricsCollector::new();
        assert_eq!(c.error_rate(), 0.0);
    }

    #[test]
    fn collector_all_rings() {
        let c = SecurityMetricsCollector::new();
        c.record_ring_latency("shield", 1.0);
        c.record_ring_latency("threat", 2.0);
        c.record_ring_latency("memory", 3.0);
        let rings = c.all_rings();
        assert_eq!(rings.len(), 3);
        assert!(rings.contains(&"shield".to_string()));
        assert!(rings.contains(&"threat".to_string()));
        assert!(rings.contains(&"memory".to_string()));
    }

    #[test]
    fn collector_per_ring_summary() {
        let c = SecurityMetricsCollector::new();
        c.record_ring_latency("shield", 1.0);
        c.record_ring_latency("shield", 2.0);
        c.record_ring_latency("threat", 10.0);

        let summary = c.per_ring_summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary.get("shield").unwrap().count, 2);
        assert_eq!(summary.get("threat").unwrap().count, 1);
    }

    #[test]
    fn collector_reset() {
        let c = SecurityMetricsCollector::new();
        c.record_ring_latency("shield", 1.0);
        c.record_decision_outcome("shield", "allow");
        c.record_ip_block("10.0.0.1");
        c.record_false_positive("shield", "10.0.0.1", "test");

        c.reset();

        assert_eq!(c.all_rings().len(), 0);
        let dist = c.decision_distribution();
        assert_eq!(dist.total, 0);
        assert_eq!(c.top_blocked_ips(10).len(), 0);
        assert_eq!(c.error_rate(), 0.0);
    }

    #[test]
    fn collector_with_custom_retention() {
        let c = SecurityMetricsCollector::with_retention(60);
        c.record_ring_latency("shield", 1.0);
        assert_eq!(c.ring_latency_stats("shield").count, 1);
    }

    #[test]
    fn ring_latency_stats_serde() {
        let stats = RingLatencyStats {
            p50: 1.5,
            p95: 10.0,
            p99: 50.0,
            mean: 3.0,
            min: 0.1,
            max: 100.0,
            std_dev: 5.0,
            count: 1000,
        };
        let json = serde_json::to_string(&stats).expect("serialize");
        let restored: RingLatencyStats = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.p50, 1.5);
        assert_eq!(restored.count, 1000);
    }

    #[test]
    fn decision_distribution_serde() {
        let dist = DecisionDistribution {
            allow: 100,
            deny: 20,
            challenge: 5,
            escalate: 1,
            total: 126,
            allow_pct: 79.365,
            deny_pct: 15.873,
        };
        let json = serde_json::to_string(&dist).expect("serialize");
        let restored: DecisionDistribution = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.allow, 100);
        assert_eq!(restored.total, 126);
    }

    #[test]
    fn ip_block_entry_serde() {
        let entry = IpBlockEntry {
            ip: "192.168.1.1".to_string(),
            block_count: 10,
            last_blocked: "1234567890.0".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: IpBlockEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.ip, "192.168.1.1");
        assert_eq!(restored.block_count, 10);
    }

    #[test]
    fn histogram_boundary_edge_cases() {
        let mut h = ReservoirHistogram::new(vec![5.0]);
        h.record(5.0); // exactly on boundary
        h.record(5.0);
        assert_eq!(h.count(), 2);
    }

    #[test]
    fn histogram_single_boundary() {
        let mut h = ReservoirHistogram::new(vec![10.0]);
        for v in [0.5, 3.0, 7.0, 15.0, 100.0] {
            h.record(v);
        }
        assert_eq!(h.count(), 5);
        // All values should be distributed across buckets
        let total: u64 = h.counts.iter().sum();
        assert_eq!(total, 5);
    }
}
