//! Per-inode encrypted rendered-content cache.

use crate::cache_crypto::{CacheKey, EncCacheEntry};
use log::error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct CachedContent {
    entry: EncCacheEntry,
    expires_at: Instant,
}

pub struct ContentCache {
    key: Arc<CacheKey>,
    by_inode: Mutex<HashMap<u64, CachedContent>>,
}

impl ContentCache {
    pub fn new(key: Arc<CacheKey>) -> Self {
        ContentCache {
            key,
            by_inode: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, ino: u64) -> Option<Vec<u8>> {
        // Take a clone of the encrypted entry under the lock, then decrypt
        // outside the lock. Decrypt time scales with payload size and we
        // don't want concurrent FUSE reads to serialize on it.
        let entry = {
            let mut by_inode = self.by_inode.lock().unwrap();
            let cached = by_inode.get(&ino)?;
            if cached.expires_at <= Instant::now() {
                by_inode.remove(&ino);
                return None;
            }
            cached.entry.clone()
        };
        match self.key.open(&entry) {
            Ok(plaintext) => Some(plaintext),
            Err(e) => {
                error!("ContentCache decrypt failed for inode {ino}: {e}");
                // Take the lock again briefly just to evict.
                let mut by_inode = self.by_inode.lock().unwrap();
                by_inode.remove(&ino);
                None
            }
        }
    }

    pub fn put(&self, ino: u64, plaintext: &[u8], ttl: Duration) {
        let entry = self.key.seal(plaintext);
        let mut by_inode = self.by_inode.lock().unwrap();
        by_inode.insert(
            ino,
            CachedContent {
                entry,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn clear_all(&self) {
        let mut by_inode = self.by_inode.lock().unwrap();
        by_inode.clear();
    }

    /// Test-only: return a copy of the raw `(nonce, ciphertext)` bytes for an entry.
    #[doc(hidden)]
    pub fn raw_bytes_for_test(&self, ino: u64) -> Option<Vec<u8>> {
        let by_inode = self.by_inode.lock().unwrap();
        by_inode.get(&ino).map(|c| {
            let mut out = Vec::with_capacity(12 + c.entry.ciphertext.len());
            out.extend_from_slice(&c.entry.nonce);
            out.extend_from_slice(&c.entry.ciphertext);
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_crypto::CacheKey;
    use std::sync::Arc;
    use std::time::Duration;

    fn cache() -> ContentCache {
        ContentCache::new(Arc::new(CacheKey::new()))
    }

    #[test]
    fn put_get_roundtrip() {
        let c = cache();
        c.put(42, b"hello world", Duration::from_secs(60));
        assert_eq!(c.get(42).unwrap(), b"hello world");
    }

    #[test]
    fn miss_returns_none() {
        let c = cache();
        assert!(c.get(99).is_none());
    }

    #[test]
    fn ttl_zero_immediately_misses() {
        let c = cache();
        c.put(1, b"data", Duration::from_secs(0));
        assert!(c.get(1).is_none());
    }

    #[test]
    fn clear_all_drops_entries() {
        let c = cache();
        c.put(1, b"a", Duration::from_secs(60));
        c.put(2, b"b", Duration::from_secs(60));
        c.clear_all();
        assert!(c.get(1).is_none());
        assert!(c.get(2).is_none());
    }

    #[test]
    fn cache_holds_ciphertext_not_plaintext() {
        let c = cache();
        let secret = b"SUPERSECRET_TOKEN_42";
        c.put(7, secret, Duration::from_secs(60));
        let raw = c.raw_bytes_for_test(7).expect("entry present");
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "plaintext leaked into ContentCache bytes"
        );
    }
}
