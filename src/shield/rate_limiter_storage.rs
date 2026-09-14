// Storage backends for the Rate Limiter.
//
// The Rate Limiter is designed to be backend-agnostic. A pluggable
// storage trait lets operators choose between:
//
//   - `memory`: in-process HashMap. Default. Zero external deps.
//                Lost on restart. Suitable for single-instance dev/test
//                and small production deployments.
//
//   - `redis`:   external Redis instance. Survives restarts, shared
//                across multiple CHAKRAVYUH instances (horizontal scale).
//                Requires the `redis` cargo feature.
//
// Architectural note: the trait is synchronous on purpose. The Rate
// Limiter's latency budget is 0.5ms p99 (memory) / 2ms p99 (redis),
// and making the trait async would force every consumer to be async
// too — including the Shield Ring's `evaluate` method, which is on
// the hot path for every request. The Redis backend uses a blocking
// connection on a dedicated thread pool via `tokio::task::spawn_blocking`
// at the call site (see `rate_limiter.rs`).
//
// Latency Budget: 0.5ms p99 (memory), 2ms p99 (redis)

use std::time::Instant;

/// A token bucket entry stored in the backend.
///
/// We do NOT store `Instant` in the backend for Redis (Redis values
/// must be serializable). Instead, we store the token count and the
/// last-refill timestamp as epoch millis, and reconstruct the `Bucket`
/// on each access. The memory backend just stores the `Bucket` directly.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    pub tokens: f64,
    pub last_refill: Instant,
}

impl Bucket {
    pub fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Refill the bucket based on elapsed time since the last refill.
    pub fn refill(&mut self, capacity: f64, refill_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
    }

    /// Try to consume one token. Returns true if allowed, false if denied.
    pub fn try_consume(&mut self, capacity: f64, refill_per_sec: f64) -> bool {
        self.refill(capacity, refill_per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Backend storage for the Rate Limiter.
///
/// Implementations must be Send + Sync (the rate limiter is shared
/// across request handler tasks via `Arc<RateLimiter>`). All methods
/// are synchronous — see module docs for rationale.
pub trait RateLimitStorage: Send + Sync + std::fmt::Debug {
    /// Try to consume one token from the bucket identified by `key`.
    ///
    /// If the bucket does not exist, it is created with the given
    /// `capacity` and seeded with `capacity` tokens (i.e., the first
    /// request always succeeds unless capacity is 0).
    ///
    /// Returns `true` if a token was consumed (request allowed),
    /// `false` if the bucket is empty (request denied).
    fn try_consume(&self, key: &str, capacity: f64, refill_per_sec: f64) -> bool;

    /// Number of buckets currently tracked. Used for diagnostics.
    /// Backends that cannot answer this efficiently may return 0.
    fn bucket_count(&self) -> usize {
        0
    }
}

// ---------------------------------------------------------------------------
// In-memory storage (default backend)
// ---------------------------------------------------------------------------

/// In-process HashMap-backed storage. Default backend.
///
/// Lost on restart. Suitable for single-instance dev/test deployments
/// and small production deployments where restart frequency is low
/// and rate-limit state does not need to survive across instances.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    buckets: std::sync::Mutex<std::collections::HashMap<String, Bucket>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RateLimitStorage for MemoryStorage {
    fn try_consume(&self, key: &str, capacity: f64, refill_per_sec: f64) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(capacity));
        bucket.try_consume(capacity, refill_per_sec)
    }

    fn bucket_count(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Redis storage (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "redis")]
mod redis_storage {
    use super::{Bucket, RateLimitStorage};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Redis-backed storage. Survives restarts and is shared across
    /// multiple CHAKRAVYUH instances when scaled horizontally.
    ///
    /// Uses a single blocking Redis connection guarded by a Mutex.
    /// The Rate Limiter's `evaluate` method runs the storage call on
    /// `tokio::task::spawn_blocking` so the async runtime is never
    /// blocked on Redis I/O.
    ///
    /// Bucket state is stored as a Redis HASH at key `chakravyuh:ratelimit:<key>`
    /// with fields:
    ///   - `tokens`:   current token count (f64 as string)
    ///   - `last_refill`: epoch millis of last refill
    ///
    /// The refill computation happens client-side (in this crate), so
    /// Redis only needs to do `HGETALL` + `HSET` per request. Atomicity
    /// is not enforced across instances — small drift between instances
    /// is acceptable for rate limiting (worst case: a few extra requests
    /// slip through during the synchronization window).
    pub struct RedisStorage {
        conn: Mutex<redis::Connection>,
        key_prefix: String,
    }

    impl std::fmt::Debug for RedisStorage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisStorage")
                .field("key_prefix", &self.key_prefix)
                .field("conn", &"<redis::Connection>")
                .finish()
        }
    }

    impl RedisStorage {
        /// Connect to Redis at the given URL (e.g., `redis://127.0.0.1:6379`).
        pub fn connect(url: &str) -> Result<Self, String> {
            let client = redis::Client::open(url).map_err(|e| format!("redis open: {e}"))?;
            let conn = client
                .get_connection()
                .map_err(|e| format!("redis connect: {e}"))?;
            Ok(Self {
                conn: Mutex::new(conn),
                key_prefix: "chakravyuh:ratelimit".into(),
            })
        }

        /// Connect with a custom key prefix (useful for multi-tenant deployments).
        pub fn connect_with_prefix(url: &str, prefix: &str) -> Result<Self, String> {
            let mut s = Self::connect(url)?;
            s.key_prefix = prefix.into();
            Ok(s)
        }

        fn redis_key(&self, key: &str) -> String {
            format!("{}:{}", self.key_prefix, key)
        }
    }

    impl RateLimitStorage for RedisStorage {
        fn try_consume(&self, key: &str, capacity: f64, refill_per_sec: f64) -> bool {
            let mut conn = match self.conn.lock() {
                Ok(c) => c,
                Err(e) => {
                    // Mutex poisoned — fail secure (deny).
                    tracing::error!(error = %e, "rate-limiter redis conn mutex poisoned");
                    return false;
                }
            };

            let rkey = self.redis_key(key);

            // Read existing bucket state.
            let result: redis::RedisResult<(Option<f64>, Option<u64>)> = redis::cmd("HMGET")
                .arg(&rkey)
                .arg("tokens")
                .arg("last_refill")
                .query(&mut *conn);

            let (tokens_opt, last_refill_opt) = match result {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, key = key, "rate-limiter redis HMGET failed");
                    return false;
                }
            };

            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            let mut bucket = match (tokens_opt, last_refill_opt) {
                (Some(t), Some(last)) => Bucket {
                    tokens: t,
                    // Reconstruct Instant by going back `now - last` millis.
                    // This is approximate — clock skew between this process
                    // and Redis is not relevant because we only use this
                    // `Instant` for elapsed-time computation in refill().
                    last_refill: Instant::now()
                        - Duration::from_millis(now_millis.saturating_sub(last)),
                },
                _ => Bucket::new(capacity),
            };

            let allowed = bucket.try_consume(capacity, refill_per_sec);

            // Write back.
            let _: redis::RedisResult<()> = redis::cmd("HSET")
                .arg(&rkey)
                .arg("tokens")
                .arg(bucket.tokens)
                .arg("last_refill")
                .arg(now_millis)
                .query(&mut *conn)
                .map_err(|e| {
                    tracing::warn!(error = %e, key = key, "rate-limiter redis HSET failed");
                    e
                });

            // Optionally expire the key after a quiet period to avoid
            // unbounded growth. 1 hour is conservative.
            let _ = redis::cmd("EXPIRE")
                .arg(&rkey)
                .arg(3600)
                .query::<()>(&mut *conn);

            allowed
        }
    }

    use std::time::{Duration, Instant};
}

#[cfg(feature = "redis")]
pub use redis_storage::RedisStorage;

// ---------------------------------------------------------------------------
// Factory: build the configured backend
// ---------------------------------------------------------------------------

/// Construct a storage backend by name.
///
/// - `"memory"` (default): always available
/// - `"redis"`: requires `redis` cargo feature; `redis_url` must be set
///
/// Returns `Err` if a backend is requested but unavailable.
pub fn build_storage(
    backend: &str,
    redis_url: Option<&str>,
) -> Result<Box<dyn RateLimitStorage>, String> {
    match backend {
        "memory" | "" => Ok(Box::new(MemoryStorage::new())),
        #[cfg(feature = "redis")]
        "redis" => {
            let url = redis_url
                .ok_or_else(|| "redis backend selected but no redis_url configured".to_string())?;
            let storage = crate::shield::rate_limiter_storage::RedisStorage::connect(url)?;
            Ok(Box::new(storage))
        }
        #[cfg(not(feature = "redis"))]
        "redis" => {
            // `redis_url` is intentionally not used here — we surface it
            // in the error message so operators see what they tried to set.
            Err(format!(
                "redis backend selected (url={:?}) but chakravyuh was not built with --features redis",
                redis_url
            ))
        }
        other => Err(format!("unknown rate_limiter backend: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_storage_allows_first_request() {
        let s = MemoryStorage::new();
        assert!(s.try_consume("ip:1.2.3.4", 100.0, 100.0 / 60.0));
    }

    #[test]
    fn memory_storage_denies_after_capacity_exhausted() {
        let s = MemoryStorage::new();
        for _ in 0..3 {
            assert!(s.try_consume("ip:1.2.3.4", 3.0, 3.0 / 60.0));
        }
        assert!(!s.try_consume("ip:1.2.3.4", 3.0, 3.0 / 60.0));
    }

    #[test]
    fn memory_storage_keys_are_independent() {
        let s = MemoryStorage::new();
        for _ in 0..3 {
            assert!(s.try_consume("ip:1.2.3.4", 3.0, 3.0 / 60.0));
        }
        // Different IP — should be allowed (independent bucket).
        assert!(s.try_consume("ip:5.6.7.8", 3.0, 3.0 / 60.0));
    }

    #[test]
    fn memory_storage_tracks_bucket_count() {
        let s = MemoryStorage::new();
        assert_eq!(s.bucket_count(), 0);
        s.try_consume("a", 1.0, 1.0);
        s.try_consume("b", 1.0, 1.0);
        assert_eq!(s.bucket_count(), 2);
    }

    #[test]
    fn build_storage_defaults_to_memory() {
        let s = build_storage("", None).expect("default backend builds");
        assert!(s.try_consume("test", 1.0, 1.0));
    }

    #[test]
    fn build_storage_rejects_unknown_backend() {
        let err = build_storage("magic", None).unwrap_err();
        assert!(err.contains("unknown rate_limiter backend"));
    }

    #[test]
    #[cfg(not(feature = "redis"))]
    fn build_storage_rejects_redis_when_feature_off() {
        let err = build_storage("redis", Some("redis://localhost:6379")).unwrap_err();
        assert!(err.contains("not built with --features redis"));
    }
}
