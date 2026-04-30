use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    value: String,
    expires_at: Instant,
}

pub struct SecretResolver {
    ttl: Duration,
    cache: Mutex<HashMap<String, CachedSecret>>,
}

impl SecretResolver {
    pub fn new(ttl: Duration) -> Self {
        SecretResolver {
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, uri: &str) -> Result<String, ResolveError> {
        if !uri.starts_with("op://") {
            return Err(ResolveError::InvalidUri(uri.to_string()));
        }

        // Check cache
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(uri) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.value.clone());
                }
            }
        }

        // Fetch from op CLI
        let value = self.fetch_from_op(uri)?;

        // Store in cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                uri.to_string(),
                CachedSecret {
                    value: value.clone(),
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }

        Ok(value)
    }

    fn fetch_from_op(&self, uri: &str) -> Result<String, ResolveError> {
        let output = Command::new("op")
            .args(["read", uri])
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ResolveError::OpNotFound
                } else {
                    ResolveError::OpFailed(e.to_string())
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ResolveError::OpFailed(stderr.to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Inject a value into the cache (for testing).
    pub fn inject_cache(&self, uri: &str, value: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            uri.to_string(),
            CachedSecret {
                value: value.to_string(),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}
