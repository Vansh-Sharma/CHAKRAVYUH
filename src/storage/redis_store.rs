// RedisStore — Redis-backed persistent key-value store.
//
// Requires the `redis` Cargo feature. Uses the `redis` crate's
// async API via tokio runtime for connections. Gracefully degrades
// if Redis is unreachable — all operations return None/false.
//
// Key prefixing: All keys are namespaced with the configured prefix
// (default: "chakravyuh:") to avoid collisions.

use super::{StorageConfig, Store, StoreHealth};

#[cfg(feature = "redis")]
use redis::Commands;

pub struct RedisStore {
    #[cfg(feature = "redis")]
    client: redis::Client,
    #[cfg(feature = "redis")]
    prefix: String,
    #[cfg(not(feature = "redis"))]
    _marker: std::marker::PhantomData<()>,
}

#[cfg(feature = "redis")]
impl RedisStore {
    pub fn new(config: &StorageConfig) -> crate::Result<Self> {
        let client = redis::Client::open(config.redis_url.as_str())
            .map_err(|e| crate::error::Error::Other(format!("Redis connection error: {}", e)))?;

        // Verify connectivity with a PING.
        let mut conn = client.get_connection()
            .map_err(|e| crate::error::Error::Other(format!("Redis get_connection error: {}", e)))?;
        let _: String = redis::cmd("PING")
            .query(&mut conn)
            .map_err(|e| crate::error::Error::Other(format!("Redis PING failed: {}", e)))?;

        Ok(Self {
            client,
            prefix: config.redis_prefix.clone(),
        })
    }

    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }
}

#[cfg(feature = "redis")]
impl Store for RedisStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let rk = self.prefixed_key(key);
        let mut conn = self.client.get_connection().ok()?;
        let result: Option<Vec<u8>> = conn.get(&*rk).ok();
        result
    }

    fn set(&self, key: &str, value: &[u8]) -> bool {
        let rk = self.prefixed_key(key);
        let mut conn = match self.client.get_connection() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Redis SET failed");
                return false;
            }
        };
        conn.set_ex::<&str, &[u8], ()>(&*rk, value, 86400).is_ok() // 24h TTL default
    }

    fn delete(&self, key: &str) -> bool {
        let rk = self.prefixed_key(key);
        let mut conn = match self.client.get_connection() {
            Ok(c) => c,
            Err(_) => return false,
        };
        conn.del(&*rk).ok().map(|v: u64| v > 0).unwrap_or(false)
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        let rk = format!("{}{}*", self.prefix, prefix);
        let mut conn = match self.client.get_connection() {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let result: Vec<String> = conn.keys(&*rk).unwrap_or_default();
        // Strip prefix.
        result.iter()
            .map(|k| k.strip_prefix(&self.prefix).unwrap_or(k).to_string())
            .collect()
    }

    fn health_check(&self) -> StoreHealth {
        let start = std::time::Instant::now();
        let reachable = self.client.get_connection().and_then(|mut conn| {
            let _: String = redis::cmd("PING").query(&mut conn)?;
            Ok(())
        }).is_ok();
        StoreHealth {
            backend: "redis".into(),
            reachable,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            detail: if reachable { "connected".into() } else { "unreachable".into() },
        }
    }
}

#[cfg(not(feature = "redis"))]
impl RedisStore {
    pub fn new(_config: &StorageConfig) -> crate::Result<Self> {
        Err(crate::error::Error::Other(
            "RedisStore requires the `redis` Cargo feature".into()
        ))
    }
}

#[cfg(not(feature = "redis"))]
impl Store for RedisStore {
    fn get(&self, _key: &str) -> Option<Vec<u8>> { None }
    fn set(&self, _key: &str, _value: &[u8]) -> bool { false }
    fn delete(&self, _key: &str) -> bool { false }
    fn keys(&self, _prefix: &str) -> Vec<String> { vec![] }
    fn health_check(&self) -> StoreHealth {
        StoreHealth {
            backend: "redis(disabled)".into(),
            reachable: false,
            latency_ms: 0.0,
            detail: "redis feature not enabled".into(),
        }
    }
}
