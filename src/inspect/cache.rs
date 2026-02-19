use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::types::InspectData;

/// Cached inspect result including oracle attestation.
#[derive(Clone)]
pub struct CachedInspect {
    pub data: InspectData,
    pub item_detail: Option<String>,
    pub oracle_signature: Option<String>,
    inserted_at: Instant,
}

/// Thread-safe LRU cache for inspect results, keyed by inspect link.
///
/// Float data is immutable and inspect links change on trade,
/// so entries naturally invalidate. TTL provides an additional safety net.
pub struct InspectCache {
    inner: Mutex<LruCache<String, CachedInspect>>,
    ttl: Duration,
}

impl InspectCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity must be > 0"),
            )),
            ttl,
        }
    }

    /// Look up a cached inspect result. Returns `None` if missing or expired.
    pub fn get(&self, inspect_link: &str) -> Option<CachedInspect> {
        let mut cache = self.inner.lock().unwrap();
        let entry = cache.get(inspect_link)?;
        if entry.inserted_at.elapsed() > self.ttl {
            cache.pop(inspect_link);
            return None;
        }
        Some(entry.clone())
    }

    /// Insert an inspect result into the cache.
    pub fn insert(
        &self,
        inspect_link: String,
        data: InspectData,
        item_detail: Option<String>,
        oracle_signature: Option<String>,
    ) {
        let entry = CachedInspect {
            data,
            item_detail,
            oracle_signature,
            inserted_at: Instant::now(),
        };
        let mut cache = self.inner.lock().unwrap();
        cache.put(inspect_link, entry);
    }

    /// Returns (current_len, capacity) for diagnostics.
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.inner.lock().unwrap();
        (cache.len(), cache.cap().get())
    }
}
