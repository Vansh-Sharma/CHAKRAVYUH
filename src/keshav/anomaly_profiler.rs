// Keshav-Learn — Anomaly Profiler
//
// Builds behavioral profiles of sources (IPs, users, agents) over time.
// Detects anomalies by comparing current behavior against historical baselines.
//
// Profile dimensions:
//   1. Request rate — requests per minute per source
//   2. Deny rate — fraction of requests denied per source
//   3. Tool diversity — unique tools used per agent
//   4. Prompt entropy — text complexity variation (proxy for prompt injection risk)
//   5. Temporal pattern — time-of-day usage patterns
//
// Anomaly detection uses statistical deviation from baseline:
//   - Z-score based: current_value vs mean + N*stddev
//   - Drift detection: exponential moving average tracking
//
// The AnomalyProfiler is used by:
//   - Keshav-Risk: adds behavioral_anomaly_score to RiskSignals
//   - Keshav-Decide: can trigger Challenge/Escalate on anomaly
//   - Cross-Ring Intel: shares anomaly data with peer rings
//
// Thread Safety: RwLock-protected.
// Latency Budget: <0.2ms per profile update/read

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use chrono::Timelike;

/// A source identifier for profiling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SourceId {
    /// An IP address.
    Ip(String),
    /// A user ID.
    User(String),
    /// An agent ID.
    Agent(String),
    /// An API key.
    ApiKey(String),
}

impl SourceId {
    fn key(&self) -> String {
        match self {
            SourceId::Ip(s) => format!("ip:{}", s),
            SourceId::User(s) => format!("user:{}", s),
            SourceId::Agent(s) => format!("agent:{}", s),
            SourceId::ApiKey(s) => format!("key:{}", s),
        }
    }
}

/// Behavioral metrics for a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralMetrics {
    /// Number of requests observed.
    pub request_count: u64,
    /// Number of denied requests.
    pub deny_count: u64,
    /// Unique tools used (agent sources).
    pub unique_tools: usize,
    /// Sum of prompt lengths (for computing average).
    pub total_prompt_length: u64,
    /// Sum of squared prompt lengths (for variance).
    pub total_prompt_length_sq: u64,
    /// Number of unique prompts seen.
    pub unique_prompts: u64,
    /// Last seen timestamp (seconds since epoch).
    pub last_seen_secs: i64,
    /// First seen timestamp.
    pub first_seen_secs: i64,
    /// Hour-of-day distribution (0-23 -> count).
    pub hourly_distribution: [u64; 24],
}

impl Default for BehavioralMetrics {
    fn default() -> Self {
        Self {
            request_count: 0,
            deny_count: 0,
            unique_tools: 0,
            total_prompt_length: 0,
            total_prompt_length_sq: 0,
            unique_prompts: 0,
            last_seen_secs: 0,
            first_seen_secs: chrono::Utc::now().timestamp(),
            hourly_distribution: [0; 24],
        }
    }
}

impl BehavioralMetrics {
    /// Deny rate (0.0-1.0).
    pub fn deny_rate(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            self.deny_count as f64 / self.request_count as f64
        }
    }

    /// Average prompt length.
    pub fn avg_prompt_length(&self) -> f64 {
        if self.unique_prompts == 0 {
            0.0
        } else {
            self.total_prompt_length as f64 / self.unique_prompts as f64
        }
    }

    /// Prompt length standard deviation.
    pub fn prompt_length_stddev(&self) -> f64 {
        if self.unique_prompts < 2 {
            0.0
        } else {
            let mean = self.avg_prompt_length();
            let variance =
                (self.total_prompt_length_sq as f64 / self.unique_prompts as f64) - (mean * mean);
            variance.sqrt().max(0.0)
        }
    }

    /// Most active hour.
    pub fn peak_hour(&self) -> u8 {
        self.hourly_distribution
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(h, _)| h as u8)
            .unwrap_or(0)
    }
}

/// Anomaly assessment result.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyAssessment {
    /// The source being assessed.
    pub source_key: String,
    /// Overall anomaly score (0.0-10.0).
    pub anomaly_score: f64,
    /// Per-dimension scores.
    pub dimensions: AnomalyDimensions,
    /// Whether this source is considered anomalous.
    pub is_anomalous: bool,
    /// Human-readable summary.
    pub summary: String,
}

/// Per-dimension anomaly scores.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyDimensions {
    pub request_rate_zscore: f64,
    pub deny_rate_zscore: f64,
    pub tool_diversity_zscore: f64,
    pub prompt_entropy_zscore: f64,
    pub temporal_zscore: f64,
}

impl Default for AnomalyDimensions {
    fn default() -> Self {
        Self {
            request_rate_zscore: 0.0,
            deny_rate_zscore: 0.0,
            tool_diversity_zscore: 0.0,
            prompt_entropy_zscore: 0.0,
            temporal_zscore: 0.0,
        }
    }
}

/// Anomaly Profiler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyProfilerConfig {
    /// Z-score threshold for anomaly detection (default: 2.0).
    #[serde(default = "default_zscore_threshold")]
    pub zscore_threshold: f64,
    /// Maximum number of source profiles to retain.
    #[serde(default = "default_max_profiles")]
    pub max_profiles: usize,
    /// Minimum requests before a source gets a full profile.
    #[serde(default = "default_min_requests")]
    pub min_requests_for_profile: u64,
    /// Exponential decay factor for aging old data (0.0-1.0).
    #[serde(default = "default_decay_factor")]
    pub decay_factor: f64,
}

fn default_zscore_threshold() -> f64 {
    2.0
}
fn default_max_profiles() -> usize {
    50_000
}
fn default_min_requests() -> u64 {
    3
}
fn default_decay_factor() -> f64 {
    0.99
}

impl Default for AnomalyProfilerConfig {
    fn default() -> Self {
        Self {
            zscore_threshold: default_zscore_threshold(),
            max_profiles: default_max_profiles(),
            min_requests_for_profile: default_min_requests(),
            decay_factor: default_decay_factor(),
        }
    }
}

/// The Anomaly Profiler — tracks behavioral profiles and detects anomalies.
pub struct AnomalyProfiler {
    config: AnomalyProfilerConfig,
    /// Per-source behavioral metrics.
    profiles: RwLock<HashMap<String, BehavioralMetrics>>,
    /// Global aggregates for computing population-level baselines.
    global: RwLock<BehavioralMetrics>,
}

impl AnomalyProfiler {
    pub fn new(config: AnomalyProfilerConfig) -> Self {
        Self {
            config,
            profiles: RwLock::new(HashMap::new()),
            global: RwLock::new(BehavioralMetrics::default()),
        }
    }

    /// Record a request observation for a source.
    pub fn observe(
        &self,
        source: &SourceId,
        denied: bool,
        prompt_length: usize,
        tool_name: Option<&str>,
    ) {
        let key = source.key();
        let now = chrono::Utc::now().timestamp();
        let hour = (chrono::Utc::now().hour()) as usize;

        {
            let mut profiles = self.profiles.write().unwrap();
            let mut global = self.global.write().unwrap();

            // Apply decay and update existing profile.
            if let Some(metrics) = profiles.get_mut(&key) {
                metrics.request_count =
                    (metrics.request_count as f64 * self.config.decay_factor) as u64 + 1;
                metrics.deny_count =
                    (metrics.deny_count as f64 * self.config.decay_factor) as u64 + (denied as u64);
                metrics.total_prompt_length += prompt_length as u64;
                metrics.total_prompt_length_sq += (prompt_length * prompt_length) as u64;
                metrics.unique_prompts += 1;
                metrics.last_seen_secs = now;
                metrics.hourly_distribution[hour] += 1;
                if let Some(_tool) = tool_name {
                    // Unique tool tracking is approximate (increment on each tool use;
                    // exact deduplication would require a set per source).
                    metrics.unique_tools = metrics.unique_tools.saturating_add(1);
                }
            } else {
                let mut metrics = BehavioralMetrics::default();
                metrics.request_count = 1;
                metrics.deny_count = denied as u64;
                metrics.total_prompt_length = prompt_length as u64;
                metrics.total_prompt_length_sq = (prompt_length * prompt_length) as u64;
                metrics.unique_prompts = 1;
                metrics.last_seen_secs = now;
                metrics.first_seen_secs = now;
                metrics.hourly_distribution[hour] = 1;
                if tool_name.is_some() {
                    metrics.unique_tools = 1;
                }
                profiles.insert(key.clone(), metrics);
            }

            // Update global aggregates (with decay).
            global.request_count =
                (global.request_count as f64 * self.config.decay_factor) as u64 + 1;
            global.deny_count =
                (global.deny_count as f64 * self.config.decay_factor) as u64 + (denied as u64);
            global.last_seen_secs = now;

            // Enforce max profiles (evict least recently seen).
            if profiles.len() > self.config.max_profiles {
                profiles.retain(|_, m| {
                    (now - m.last_seen_secs) < 3600 // keep last hour
                });
            }
        }
    }

    /// Assess whether a source's current behavior is anomalous.
    pub fn assess(&self, source: &SourceId) -> AnomalyAssessment {
        let key = source.key();
        let profiles = self.profiles.read().unwrap();
        let global = self.global.read().unwrap();

        let metrics = profiles.get(&key);

        if metrics.is_none()
            || metrics.unwrap().request_count < self.config.min_requests_for_profile
        {
            return AnomalyAssessment {
                source_key: key,
                anomaly_score: 0.0,
                dimensions: AnomalyDimensions::default(),
                is_anomalous: false,
                summary: "insufficient data for profiling".to_string(),
            };
        }

        let m = metrics.unwrap();
        let g = &*global;

        // Compute per-dimension z-scores.
        let global_deny_rate = if g.request_count > 0 {
            g.deny_count as f64 / g.request_count as f64
        } else {
            0.0
        };
        let global_stddev = global_deny_rate * (1.0 - global_deny_rate).sqrt().max(0.01);
        let deny_rate_zscore = if global_stddev > 0.001 {
            (m.deny_rate() - global_deny_rate) / global_stddev
        } else {
            0.0
        };

        let request_rate_zscore = if g.request_count > 0 {
            let avg_requests = g.request_count as f64 / profiles.len().max(1) as f64;
            ((m.request_count as f64) - avg_requests) / avg_requests.sqrt().max(1.0)
        } else {
            0.0
        };

        // Tool diversity anomaly: unusually high tool count for this source type.
        let avg_tools = profiles.values().map(|p| p.unique_tools).sum::<usize>() as f64
            / profiles.len().max(1) as f64;
        let tool_diversity_zscore = if avg_tools > 0.0 {
            (m.unique_tools as f64 - avg_tools) / avg_tools.sqrt().max(1.0)
        } else {
            0.0
        };

        // Prompt entropy: high stddev relative to mean suggests inconsistent prompts.
        let prompt_entropy_zscore = if m.avg_prompt_length() > 0.0 {
            m.prompt_length_stddev() / m.avg_prompt_length()
        } else {
            0.0
        };

        // Temporal anomaly: activity outside typical hours.
        let peak_hour = m.peak_hour() as usize;
        let current_hour = chrono::Utc::now().hour() as usize;
        let temporal_zscore = if m.hourly_distribution[peak_hour] > 0 {
            let ratio = m
                .hourly_distribution
                .get(current_hour)
                .copied()
                .unwrap_or(0) as f64
                / m.hourly_distribution[peak_hour] as f64;
            if ratio < 0.1 {
                -2.0
            } else if ratio > 2.0 {
                2.0
            } else {
                0.0
            }
        } else {
            0.0
        };

        let dimensions = AnomalyDimensions {
            request_rate_zscore,
            deny_rate_zscore,
            tool_diversity_zscore,
            prompt_entropy_zscore,
            temporal_zscore,
        };

        // Composite anomaly score: weighted sum of absolute z-scores.
        let anomaly_score = (request_rate_zscore.abs() * 0.20
            + deny_rate_zscore.abs() * 0.35  // deny rate is most important
            + tool_diversity_zscore.abs() * 0.15
            + prompt_entropy_zscore.abs() * 0.15
            + temporal_zscore.abs() * 0.15)
            .clamp(0.0, 10.0);

        let is_anomalous = anomaly_score >= self.config.zscore_threshold;

        let mut reasons = Vec::new();
        if deny_rate_zscore.abs() > self.config.zscore_threshold {
            reasons.push(format!("deny_rate_z={:.1}", deny_rate_zscore));
        }
        if request_rate_zscore.abs() > self.config.zscore_threshold {
            reasons.push(format!("request_rate_z={:.1}", request_rate_zscore));
        }
        if tool_diversity_zscore.abs() > self.config.zscore_threshold {
            reasons.push(format!("tool_div_z={:.1}", tool_diversity_zscore));
        }
        if prompt_entropy_zscore > self.config.zscore_threshold {
            reasons.push(format!("prompt_entropy={:.1}", prompt_entropy_zscore));
        }
        if temporal_zscore.abs() > self.config.zscore_threshold {
            reasons.push(format!("temporal_z={:.1}", temporal_zscore));
        }

        let summary = if reasons.is_empty() {
            "normal behavior".to_string()
        } else {
            format!("anomalies: {}", reasons.join(", "))
        };

        AnomalyAssessment {
            source_key: key,
            anomaly_score,
            dimensions,
            is_anomalous,
            summary,
        }
    }

    /// Get a source's profile.
    pub fn profile(&self, source: &SourceId) -> Option<BehavioralMetrics> {
        let profiles = self.profiles.read().unwrap();
        profiles.get(&source.key()).cloned()
    }

    /// Get total number of profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.read().unwrap().len()
    }

    /// Get global aggregate metrics.
    pub fn global_metrics(&self) -> BehavioralMetrics {
        self.global.read().unwrap().clone()
    }

    /// Prune old profiles (not seen in the last N seconds).
    pub fn prune(&self, max_age_secs: i64) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut profiles = self.profiles.write().unwrap();
        let before = profiles.len();
        profiles.retain(|_, m| (now - m.last_seen_secs) < max_age_secs);
        before - profiles.len()
    }
}

impl Clone for AnomalyProfiler {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            profiles: RwLock::new(self.profiles.read().unwrap().clone()),
            global: RwLock::new(self.global.read().unwrap().clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profiler() -> AnomalyProfiler {
        AnomalyProfiler::new(AnomalyProfilerConfig::default())
    }

    fn ip_source(ip: &str) -> SourceId {
        SourceId::Ip(ip.to_string())
    }

    #[test]
    fn observe_and_profile() {
        let cfg = AnomalyProfilerConfig {
            decay_factor: 1.0, // disable decay for test determinism
            ..Default::default()
        };
        let p = AnomalyProfiler::new(cfg);
        let src = ip_source("1.2.3.4");
        p.observe(&src, false, 100, None);
        p.observe(&src, false, 120, None);
        p.observe(&src, true, 80, None);
        let profile = p.profile(&src).unwrap();
        assert_eq!(profile.request_count, 3);
        assert_eq!(profile.deny_count, 1);
        assert_eq!(profile.unique_prompts, 3);
    }

    #[test]
    fn normal_behavior_low_anomaly() {
        let cfg = AnomalyProfilerConfig {
            decay_factor: 1.0,
            ..Default::default()
        };
        let p = AnomalyProfiler::new(cfg);
        let src = ip_source("10.0.0.1");
        for _ in 0..10 {
            p.observe(&src, false, 50, Some("file_read"));
        }
        let assessment = p.assess(&src);
        assert!(assessment.anomaly_score < 3.0);
        assert!(!assessment.is_anomalous);
    }

    #[test]
    fn high_deny_rate_triggers_anomaly() {
        let cfg = AnomalyProfilerConfig {
            decay_factor: 1.0,
            ..Default::default()
        };
        let p = AnomalyProfiler::new(cfg);
        let normal_src = ip_source("10.0.0.1");
        // Establish baseline with normal traffic.
        for _ in 0..20 {
            p.observe(&normal_src, false, 50, None);
        }
        // Create a source with high deny rate.
        let sus_src = ip_source("10.0.0.2");
        for _ in 0..15 {
            p.observe(&sus_src, true, 50, None);
        }
        let assessment = p.assess(&sus_src);
        // High deny rate should contribute to anomaly score.
        assert!(assessment.anomaly_score > 0.0);
    }

    #[test]
    fn global_metrics() {
        let cfg = AnomalyProfilerConfig {
            decay_factor: 1.0,
            ..Default::default()
        };
        let p = AnomalyProfiler::new(cfg);
        let s1 = ip_source("1.1.1.1");
        let s2 = ip_source("2.2.2.2");
        p.observe(&s1, false, 50, None);
        p.observe(&s2, true, 60, None);
        let global = p.global_metrics();
        assert_eq!(global.request_count, 2);
        assert_eq!(global.deny_count, 1);
    }

    #[test]
    fn deny_rate_calculation() {
        let m = BehavioralMetrics {
            request_count: 100,
            deny_count: 15,
            ..Default::default()
        };
        assert!((m.deny_rate() - 0.15).abs() < 0.001);
    }

    #[test]
    fn prompt_length_stats() {
        let m = BehavioralMetrics {
            unique_prompts: 2,
            total_prompt_length: 200,      // avg=100
            total_prompt_length_sq: 20000, // variance = 10000/2 - 10000 = 0
            ..Default::default()
        };
        assert_eq!(m.avg_prompt_length(), 100.0);
        assert!(m.prompt_length_stddev() < 0.1);
    }
}
