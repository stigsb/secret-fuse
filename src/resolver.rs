use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

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
    value: SecretString,
    expires_at: Instant,
}

pub struct SecretResolver {
    ttl: Duration,
    op_timeout: Duration,
    cache: Mutex<HashMap<String, CachedSecret>>,
}

impl SecretResolver {
    pub fn new(ttl: Duration, op_timeout: Duration) -> Self {
        SecretResolver {
            ttl,
            op_timeout,
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
                    return Ok(entry.value.expose_secret().to_string());
                }
            }
        }

        // Fetch from op CLI
        let value = self.fetch_from_op(uri)?;

        // Store in cache as SecretString (zeroized on drop)
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                uri.to_string(),
                CachedSecret {
                    value: SecretString::from(value.clone()),
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
                let output = child.wait_with_output()
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
        cache.clear(); // Each CachedSecret's SecretString is zeroized on drop
    }

    /// Inject a value into the cache (for testing).
    #[allow(dead_code)]
    pub fn inject_cache(&self, uri: &str, value: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            uri.to_string(),
            CachedSecret {
                value: SecretString::from(value.to_string()),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}
