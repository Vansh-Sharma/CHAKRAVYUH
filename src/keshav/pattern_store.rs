// Keshav-Learn — Pattern Store
//
// Persists attack patterns, signatures, and learned rules for recall.
//
// Phase 9: Persistent PatternStore
//   The PatternStore now optionally backs to the persistent Store trait
//   (Phase 7 storage layer). Patterns are serialized to JSON and stored
//   with key prefix "chakravyuh:pattern:{id}". On startup, patterns are
//   restored from the store. This ensures learned patterns survive
//   restarts without manual export/import.
//
// Pattern types:
//   1. SignaturePattern — static string/regex signatures from Threat Ring
//   2. BehavioralPattern — sequences of actions that indicate attack chains
//   3. ThresholdPattern — learned optimal thresholds per ring/context
//   4. FeedbackPattern — aggregated feedback lessons
//
// Thread Safety: RwLock-protected.
// Latency Budget: <0.1ms per lookup (in-memory hash map)
// Persistence: Async best-effort (store failures are logged, never block)

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Types of stored patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// Static string/regex signature.
    Signature,
    /// Behavioral action sequence.
    Behavioral,
    /// Learned threshold values.
    Threshold,
    /// Feedback-derived rule.
    FeedbackRule,
    /// Auto-learned from feedback/patterns.
    Learned,
}

/// Priority of a pattern (higher = more important).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternPriority {
    pub level: u8, // 0-255
    pub weight: f64, // 0.0-1.0 in composite scoring
}

impl Default for PatternPriority {
    fn default() -> Self {
        Self { level: 100, weight: 0.5 }
    }
}

/// A stored pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Unique pattern ID.
    pub id: String,
    /// Pattern type.
    pub pattern_type: PatternType,
    /// Human-readable name.
    pub name: String,
    /// Which ring(s) this pattern applies to.
    pub rings: Vec<String>,
    /// The pattern content (regex, JSON sequence, etc.).
    pub pattern: String,
    /// Priority/weight.
    pub priority: PatternPriority,
    /// Tags for categorization and search.
    pub tags: Vec<String>,
    /// Number of times this pattern matched.
    pub match_count: u64,
    /// Number of times this pattern was a true positive.
    pub true_positive_count: u64,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last match timestamp.
    pub last_matched_at: Option<String>,
    /// Whether this pattern is active.
    pub active: bool,
    /// Confidence score (0.0-1.0) — how reliable this pattern is.
    pub confidence: f64,
    /// Source of this pattern (manual, learned, imported).
    pub source: PatternSource,
}

/// Where a pattern came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternSource {
    /// Manually added by operator.
    Manual,
    /// Auto-learned from feedback.
    Learned,
    /// Imported from external threat feed.
    Imported,
    /// Derived from cross-ring intelligence.
    CrossRing,
}

impl Pattern {
    /// Precision rate (true positives / total matches).
    pub fn precision(&self) -> f64 {
        if self.match_count == 0 {
            0.0
        } else {
            self.true_positive_count as f64 / self.match_count as f64
        }
    }

    /// Record a match.
    pub fn record_match(&mut self, is_true_positive: bool) {
        self.match_count += 1;
        if is_true_positive {
            self.true_positive_count += 1;
        }
        self.last_matched_at = Some(chrono::Utc::now().to_rfc3339());
    }
}

/// Pattern Store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStoreConfig {
    /// Maximum number of patterns to store.
    #[serde(default = "default_max_patterns")]
    pub max_patterns: usize,
    /// Minimum confidence for auto-activation of learned patterns.
    #[serde(default = "default_min_confidence")]
    pub min_confidence_for_activation: f64,
    /// Minimum match count before confidence is considered reliable.
    #[serde(default = "default_min_matches")]
    pub min_matches_for_confidence: u64,
}

fn default_max_patterns() -> usize { 100_000 }
fn default_min_confidence() -> f64 { 0.7 }
fn default_min_matches() -> u64 { 10 }

impl Default for PatternStoreConfig {
    fn default() -> Self {
        Self {
            max_patterns: default_max_patterns(),
            min_confidence_for_activation: default_min_confidence(),
            min_matches_for_confidence: default_min_matches(),
        }
    }
}

/// Store key prefix for persisted patterns.
const STORE_PREFIX: &str = "chakravyuh:pattern:";

/// The Pattern Store — long-term memory for Keshav-Learn.
///
/// Phase 9: When a persistent Store is provided, all mutations (add, remove,
/// record_match) are also written to the backing store. On construction,
/// patterns are restored from the store. The in-memory map is always the
/// primary read path for performance; the store is the durability layer.
pub struct PatternStore {
    config: PatternStoreConfig,
    patterns: RwLock<HashMap<String, Pattern>>,
    /// Optional persistent store backend (Phase 9).
    store: Option<std::sync::Arc<dyn crate::storage::Store>>,
}

impl PatternStore {
    pub fn new(config: PatternStoreConfig) -> Self {
        Self {
            config,
            patterns: RwLock::new(HashMap::new()),
            store: None,
        }
    }

    /// Create a PatternStore with persistent storage backing (Phase 9).
    /// Automatically restores patterns from the store on construction.
    pub fn with_store(config: PatternStoreConfig, store: std::sync::Arc<dyn crate::storage::Store>) -> Self {
        let ps = Self {
            config,
            patterns: RwLock::new(HashMap::new()),
            store: Some(store.clone()),
        };
        ps.restore_from_store(store.as_ref());
        ps
    }

    /// Restore patterns from the persistent store.
    fn restore_from_store(&self, store: &dyn crate::storage::Store) {
        let keys = store.keys(STORE_PREFIX);
        if keys.is_empty() {
            tracing::info!("PatternStore: no persisted patterns to restore");
            return;
        }

        let mut patterns = self.patterns.write().unwrap();
        let mut restored = 0usize;
        let mut failed = 0usize;

        for key in &keys {
            if let Some(bytes) = store.get(key) {
                match serde_json::from_slice::<Pattern>(&bytes) {
                    Ok(pattern) => {
                        patterns.insert(pattern.id.clone(), pattern);
                        restored += 1;
                    }
                    Err(e) => {
                        tracing::warn!(key = %key, error = %e, "PatternStore: failed to deserialize pattern");
                        failed += 1;
                    }
                }
            }
        }

        tracing::info!(
            restored = restored, failed = failed,
            "PatternStore: restored patterns from persistent store"
        );
    }

    /// Persist a single pattern to the store (best-effort).
    fn persist_to_store(&self, pattern: &Pattern) {
        if let Some(ref store) = self.store {
            match serde_json::to_vec(pattern) {
                Ok(bytes) => {
                    let key = format!("{}{}", STORE_PREFIX, pattern.id);
                    if !store.set(&key, &bytes) {
                        tracing::warn!(pattern_id = %pattern.id, "PatternStore: failed to persist pattern");
                    }
                }
                Err(e) => {
                    tracing::warn!(pattern_id = %pattern.id, error = %e, "PatternStore: failed to serialize pattern");
                }
            }
        }
    }

    /// Delete a pattern from the store (best-effort).
    fn delete_from_store(&self, id: &str) {
        if let Some(ref store) = self.store {
            let key = format!("{}{}", STORE_PREFIX, id);
            if !store.delete(&key) {
                tracing::warn!(pattern_id = %id, "PatternStore: failed to delete pattern from store");
            }
        }
    }

    /// Add a new pattern.
    pub fn add(&self, pattern: Pattern) {
        let pid = pattern.id.clone();
        let mut patterns = self.patterns.write().unwrap();
        patterns.insert(pattern.id.clone(), pattern);
        drop(patterns);
        // Persist after releasing the lock (best-effort).
        if let Some(p) = self.patterns.read().unwrap().get(&pid) {
            self.persist_to_store(p);
        }
    }

    /// Get a pattern by ID.
    pub fn get(&self, id: &str) -> Option<Pattern> {
        self.patterns.read().unwrap().get(id).cloned()
    }

    /// Remove a pattern by ID.
    pub fn remove(&self, id: &str) -> bool {
        let mut patterns = self.patterns.write().unwrap();
        let removed = patterns.remove(id).is_some();
        drop(patterns);
        if removed {
            self.delete_from_store(id);
        }
        removed
    }

    /// Search patterns by ring and/or tags.
    pub fn search(&self, ring: Option<&str>, tags: &[&str], pattern_type: Option<PatternType>) -> Vec<Pattern> {
        let patterns = self.patterns.read().unwrap();
        patterns.values()
            .filter(|p| {
                if let Some(r) = ring {
                    if !p.rings.iter().any(|pr| pr == r) {
                        return false;
                    }
                }
                if let Some(ref pt) = pattern_type {
                    if p.pattern_type != *pt {
                        return false;
                    }
                }
                for tag in tags {
                    if !p.tags.iter().any(|t| t == tag) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Record a match for a pattern.
    pub fn record_match(&self, pattern_id: &str, is_true_positive: bool) {
        let mut patterns = self.patterns.write().unwrap();
        if let Some(pattern) = patterns.get_mut(pattern_id) {
            pattern.record_match(is_true_positive);
            // Auto-deactivate low-precision patterns after enough data.
            if pattern.match_count >= self.config.min_matches_for_confidence
                && pattern.precision() < 0.1
                && pattern.confidence < 0.3
            {
                pattern.active = false;
                tracing::warn!(
                    pattern_id = %pattern_id,
                    precision = pattern.precision(),
                    "pattern auto-deactivated due to low precision"
                );
            }
            let to_persist = pattern.clone();
            drop(patterns);
            self.persist_to_store(&to_persist);
        }
    }

    /// Export all patterns as JSON string.
    pub fn export_json(&self) -> crate::Result<String> {
        let patterns = self.patterns.read().unwrap();
        let values: Vec<&Pattern> = patterns.values().collect();
        serde_json::to_string_pretty(&values)
            .map_err(|e| crate::error::Error::Other(format!("pattern export failed: {}", e)))
    }

    /// Import patterns from JSON string.
    pub fn import_json(&self, json: &str) -> crate::Result<usize> {
        let imported: Vec<Pattern> = serde_json::from_str(json)
            .map_err(|e| crate::error::Error::Other(format!("pattern import failed: {}", e)))?;

        let mut patterns = self.patterns.write().unwrap();
        let mut count = 0;
        for pattern in imported {
            patterns.insert(pattern.id.clone(), pattern);
            count += 1;
        }

        tracing::info!(imported = count, "patterns imported to PatternStore");
        Ok(count)
    }

    /// Get statistics.
    pub fn stats(&self) -> PatternStoreStats {
        let patterns = self.patterns.read().unwrap();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut active = 0;
        let mut total_matches = 0;
        let mut total_tp = 0;

        for p in patterns.values() {
            *by_type.entry(format!("{:?}", p.pattern_type)).or_insert(0) += 1;
            *by_source.entry(format!("{:?}", p.source)).or_insert(0) += 1;
            if p.active { active += 1; }
            total_matches += p.match_count;
            total_tp += p.true_positive_count;
        }

        let overall_precision = if total_matches > 0 {
            total_tp as f64 / total_matches as f64
        } else {
            0.0
        };

        PatternStoreStats {
            total_patterns: patterns.len(),
            active_patterns: active,
            total_matches,
            overall_precision,
            by_type,
            by_source,
        }
    }

    /// Total pattern count.
    pub fn count(&self) -> usize {
        self.patterns.read().unwrap().len()
    }
}

/// Pattern store statistics.
#[derive(Debug, Clone, Serialize)]
pub struct PatternStoreStats {
    pub total_patterns: usize,
    pub active_patterns: usize,
    pub total_matches: u64,
    pub overall_precision: f64,
    pub by_type: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
}

impl Clone for PatternStore {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            patterns: RwLock::new(self.patterns.read().unwrap().clone()),
            store: self.store.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> PatternStore {
        PatternStore::new(PatternStoreConfig::default())
    }

    fn make_pattern(id: &str, name: &str, ring: &str) -> Pattern {
        Pattern {
            id: id.to_string(),
            pattern_type: PatternType::Signature,
            name: name.to_string(),
            rings: vec![ring.to_string()],
            pattern: "ignore previous instructions".to_string(),
            priority: PatternPriority::default(),
            tags: vec!["jailbreak".to_string()],
            match_count: 0,
            true_positive_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_matched_at: None,
            active: true,
            confidence: 0.8,
            source: PatternSource::Manual,
        }
    }

    #[test]
    fn add_and_get() {
        let s = make_store();
        s.add(make_pattern("sig-1", "Jailbreak DAN", "threat"));
        let p = s.get("sig-1").unwrap();
        assert_eq!(p.name, "Jailbreak DAN");
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn remove_pattern() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test", "threat"));
        assert!(s.remove("sig-1"));
        assert!(!s.remove("sig-1"));
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn search_by_ring() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test1", "threat"));
        s.add(make_pattern("sig-2", "test2", "shield"));
        s.add(make_pattern("sig-3", "test3", "threat"));
        let results = s.search(Some("threat"), &[], None);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_by_type() {
        let s = make_store();
        let mut p1 = make_pattern("sig-1", "test", "threat");
        p1.pattern_type = PatternType::Behavioral;
        s.add(p1);
        s.add(make_pattern("sig-2", "test", "shield"));
        let results = s.search(None, &[], Some(PatternType::Behavioral));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_tags() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test", "threat"));
        let mut p2 = make_pattern("sig-2", "test", "shield");
        p2.tags = vec!["injection".to_string()];
        s.add(p2);
        let results = s.search(None, &["injection"], None);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn record_match_updates_stats() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test", "threat"));
        s.record_match("sig-1", true);
        s.record_match("sig-1", true);
        s.record_match("sig-1", false);
        let p = s.get("sig-1").unwrap();
        assert_eq!(p.match_count, 3);
        assert_eq!(p.true_positive_count, 2);
        assert!((p.precision() - 0.666).abs() < 0.01);
        assert!(p.last_matched_at.is_some());
    }

    #[test]
    fn export_import_roundtrip() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test1", "threat"));
        s.add(make_pattern("sig-2", "test2", "shield"));

        let json = s.export_json().unwrap();
        let s2 = make_store();
        let count = s2.import_json(&json).unwrap();
        assert_eq!(count, 2);
        assert_eq!(s2.count(), 2);
        assert!(s2.get("sig-1").is_some());
    }

    #[test]
    fn stats() {
        let s = make_store();
        s.add(make_pattern("sig-1", "test", "threat"));
        s.add(make_pattern("sig-2", "test", "shield"));
        let stats = s.stats();
        assert_eq!(stats.total_patterns, 2);
        assert_eq!(stats.active_patterns, 2);
    }

    #[test]
    fn persistent_store_roundtrip() {
        let backend = crate::storage::MemoryStore::new();
        let arc_store: std::sync::Arc<dyn crate::storage::Store> = std::sync::Arc::new(backend);

        // Write patterns to store-backed PatternStore.
        let s1 = PatternStore::with_store(PatternStoreConfig::default(), arc_store.clone());
        s1.add(make_pattern("sig-1", "test1", "threat"));
        s1.add(make_pattern("sig-2", "test2", "shield"));
        s1.record_match("sig-1", true);
        assert_eq!(s1.count(), 2);

        // Verify persistence: create a new store-backed PatternStore.
        let s2 = PatternStore::with_store(PatternStoreConfig::default(), arc_store.clone());
        assert_eq!(s2.count(), 2);
        let p = s2.get("sig-1").unwrap();
        assert_eq!(p.match_count, 1); // persisted from record_match

        // Remove persists too.
        s1.remove("sig-2");
        let s3 = PatternStore::with_store(PatternStoreConfig::default(), arc_store.clone());
        assert_eq!(s3.count(), 1);
        assert!(s3.get("sig-1").is_some());
        assert!(s3.get("sig-2").is_none());
    }
}
