// MemoryStore — in-process key-value store.
//
// Thread-safe via Mutex. Data is lost on process restart.
// This is the default backend and the fallback for Redis failures.

use std::collections::HashMap;
use std::sync::Mutex;

use super::{Store, StoreHealth};

pub struct MemoryStore {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let data = self.data.lock().ok()?;
        data.get(key).cloned()
    }

    fn set(&self, key: &str, value: &[u8]) -> bool {
        if let Ok(mut data) = self.data.lock() {
            data.insert(key.to_string(), value.to_vec());
            true
        } else {
            false
        }
    }

    fn delete(&self, key: &str) -> bool {
        if let Ok(mut data) = self.data.lock() {
            data.remove(key).is_some()
        } else {
            false
        }
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        data.keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn health_check(&self) -> StoreHealth {
        let start = std::time::Instant::now();
        let reachable = self.data.lock().is_ok();
        StoreHealth {
            backend: "memory".into(),
            reachable,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            detail: if reachable {
                format!("{} keys", self.data.lock().map(|d| d.len()).unwrap_or(0))
            } else {
                "lock poisoned".into()
            },
        }
    }
}
