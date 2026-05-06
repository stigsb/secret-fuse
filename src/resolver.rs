use crate::cache_crypto::{CacheKey, EncCacheEntry};
use log::error;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("invalid op:// URI: {0}")]
    InvalidUri(String),
    #[error("op CLI failed: {0}")]
    OpFailed(String),
    #[error("op CLI not found — install 1Password CLI: https://developer.1password.com/docs/cli/")]
    OpNotFound,
    #[error("op CLI timed out after {0} seconds")]
    Timeout(u64),
}

struct CachedSecret {
    entry: EncCacheEntry,
    expires_at: Instant,
}

pub struct SecretResolver {
    ttl: Duration,
    op_timeout: Duration,
    key: Arc<CacheKey>,
    cache: Mutex<HashMap<String, CachedSecret>>,
}

impl SecretResolver {
    pub fn new(ttl: Duration, op_timeout: Duration, key: Arc<CacheKey>) -> Self {
        SecretResolver {
            ttl,
            op_timeout,
            key,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, uri: &str) -> Result<String, ResolveError> {
        if !uri.starts_with("op://") {
            return Err(ResolveError::InvalidUri(uri.to_string()));
        }

        // Cache hit path
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(uri) {
                if entry.expires_at > Instant::now() {
                    match self.key.open(&entry.entry) {
                        Ok(plaintext) => {
                            return match String::from_utf8(plaintext) {
                                Ok(s) => Ok(s),
                                Err(e) => {
                                    let mut bad = e.into_bytes();
                                    bad.zeroize();
                                    Err(ResolveError::OpFailed("utf8: invalid bytes".to_string()))
                                }
                            };
                        }
                        Err(e) => {
                            error!("cache decrypt failed for {uri}: {e}; refetching");
                            cache.remove(uri);
                        }
                    }
                }
            }
        }

        // Miss → fetch and store
        let value = self.fetch_from_op(uri)?;
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                uri.to_string(),
                CachedSecret {
                    entry: self.key.seal(value.as_bytes()),
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }
        Ok(value)
    }

    fn fetch_from_op(&self, uri: &str) -> Result<String, ResolveError> {
        let mut child = Command::new("op")
            .args(["read", uri])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ResolveError::OpNotFound
                } else {
                    ResolveError::OpFailed(e.to_string())
                }
            })?;

        let timeout_secs = self.op_timeout.as_secs();
        match child.wait_timeout(self.op_timeout) {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| ResolveError::OpFailed(e.to_string()))?;
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(ResolveError::OpFailed(stderr.to_string()));
                }
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(ResolveError::Timeout(timeout_secs))
            }
            Err(e) => Err(ResolveError::OpFailed(e.to_string())),
        }
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Inject a value into the cache (testing only).
    #[allow(dead_code)]
    pub fn inject_cache(&self, uri: &str, value: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            uri.to_string(),
            CachedSecret {
                entry: self.key.seal(value.as_bytes()),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Test-only: return a copy of the raw `(nonce, ciphertext)` bytes for an entry.
    #[doc(hidden)]
    pub fn raw_cache_bytes_for_test(&self, uri: &str) -> Option<Vec<u8>> {
        let cache = self.cache.lock().unwrap();
        cache.get(uri).map(|e| {
            let mut out = Vec::with_capacity(12 + e.entry.ciphertext.len());
            out.extend_from_slice(&e.entry.nonce);
            out.extend_from_slice(&e.entry.ciphertext);
            out
        })
    }
}
