// Persistent Storage Layer (Phase 7)
//
// Provides a trait-based abstraction for persisting Keshav-Learn state
// across restarts. Two backends:
//   1. MemoryStore — default, in-process (loses state on restart)
//   2. RedisStore — persistent, shared across instances (requires `redis` feature)
//
// Architectural Guarantee:
//   Storage is OPTIONAL. If the store fails, Keshav-Learn degrades to
//   in-memory mode. No storage failure can block the decision pipeline.
//
// Thread Safety: All operations are internally synchronized.

pub mod memory_store;
pub mod redis_store;

use std::sync::RwLock;

pub use memory_store::MemoryStore;

/// A persistent key-value store for Keshav-Learn state.
///
/// Operations that fail return None (degrade gracefully).
/// The store is never on the critical path for decisions.
pub trait Store: Send + Sync {
    /// Get a value by key. Returns None if missing or on error.
    fn get(&self, key: &str) -> Option<Vec<u8>>;

    /// Set a value. Returns false on error.
    fn set(&self, key: &str, value: &[u8]) -> bool;

    /// Delete a key. Returns false on error.
    fn delete(&self, key: &str) -> bool;

    /// Check if a key exists.
    fn exists(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Get all keys with a given prefix.
    fn keys(&self, prefix: &str) -> Vec<String>;

    /// Health check — can the store be reached?
    fn health_check(&self) -> StoreHealth;
}

/// Storage health status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreHealth {
    pub backend: String,
    pub reachable: bool,
    pub latency_ms: f64,
    pub detail: String,
}

/// Configuration for the storage layer.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StorageConfig {
    /// Backend type: "memory" or "redis".
    #[serde(default = "default_backend")]
    pub backend: String,

    /// Redis connection URL (only for backend = "redis").
    #[serde(default)]
    pub redis_url: String,

    /// Redis key prefix (namespace).
    #[serde(default = "default_prefix")]
    pub redis_prefix: String,

    /// Connection timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_backend() -> String { "memory".into() }
fn default_prefix() -> String { "chakravyuh:".into() }
fn default_timeout_ms() -> u64 { 1000 }

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            redis_url: "redis://127.0.0.1:6379".into(),
            redis_prefix: default_prefix(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// Create a store from configuration.
/// Falls back to MemoryStore if the configured backend fails.
pub fn create_store(config: &StorageConfig) -> Box<dyn Store> {
    match config.backend.as_str() {
        "redis" => {
            #[cfg(feature = "redis")]
            {
                match redis_store::RedisStore::new(config) {
                    Ok(store) => {
                        tracing::info!(url = %config.redis_url, "storage: Redis backend connected");
                        Box::new(store)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "storage: Redis connection failed, falling back to memory");
                        Box::new(MemoryStore::new())
                    }
                }
            }
            #[cfg(not(feature = "redis"))]
            {
                tracing::warn!("storage: redis backend requested but `redis` feature not enabled; using memory");
                Box::new(MemoryStore::new())
            }
        }
        _ => {
            tracing::info!("storage: using in-memory backend (state lost on restart)");
            Box::new(MemoryStore::new())
        }
    }
}

/// A cached store wrapper that adds an in-memory L1 cache
/// in front of any Store backend (L2).
pub struct CachedStore<S: Store> {
    l1: RwLock<std::collections::HashMap<String, Vec<u8>>>,
    l2: S,
    max_cache_entries: usize,
}

impl<S: Store> CachedStore<S> {
    pub fn new(l2: S, max_cache_entries: usize) -> Self {
        Self {
            l1: RwLock::new(std::collections::HashMap::with_capacity(max_cache_entries)),
            l2,
            max_cache_entries,
        }
    }
}

impl<S: Store> Store for CachedStore<S> {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        // Try L1 cache first.
        let l1 = self.l1.read().ok()?;
        if let Some(val) = l1.get(key) {
            return Some(val.clone());
        }
        drop(l1);
        // Fall through to L2.
        let val = self.l2.get(key);
        if let Some(ref v) = val {
            if let Ok(mut l1) = self.l1.write() {
                if l1.len() < self.max_cache_entries {
                    l1.insert(key.to_string(), v.clone());
                }
            }
        }
        val
    }

    fn set(&self, key: &str, value: &[u8]) -> bool {
        if let Ok(mut l1) = self.l1.write() {
            if l1.len() < self.max_cache_entries {
                l1.insert(key.to_string(), value.to_vec());
            }
        }
        self.l2.set(key, value)
    }

    fn delete(&self, key: &str) -> bool {
        if let Ok(mut l1) = self.l1.write() {
            l1.remove(key);
        }
        self.l2.delete(key)
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        self.l2.keys(prefix)
    }

    fn health_check(&self) -> StoreHealth {
        self.l2.health_check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_basic() {
        let store = MemoryStore::new();
        assert!(store.get("key").is_none());
        assert!(store.set("key", b"value"));
        assert_eq!(store.get("key"), Some(b"value".to_vec()));
        assert!(store.delete("key"));
        assert!(store.get("key").is_none());
    }

    #[test]
    fn memory_store_keys_prefix() {
        let store = MemoryStore::new();
        store.set("chakravyuh:feedback:1", b"a");
        store.set("chakravyuh:feedback:2", b"b");
        store.set("chakravyuh:pattern:1", b"c");
        let keys = store.keys("chakravyuh:feedback:");
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn memory_store_health() {
        let store = MemoryStore::new();
        let health = store.health_check();
        assert!(health.reachable);
        assert_eq!(health.backend, "memory");
    }

    #[test]
    fn cached_store_l1_hit() {
        let inner = MemoryStore::new();
        let cached = CachedStore::new(inner, 100);
        cached.set("key", b"value");
        assert_eq!(cached.get("key"), Some(b"value".to_vec()));
    }

    #[test]
    fn default_config_memory() {
        let cfg = StorageConfig::default();
        assert_eq!(cfg.backend, "memory");
        let store = create_store(&cfg);
        let health = store.health_check();
        assert_eq!(health.backend, "memory");
    }
}
