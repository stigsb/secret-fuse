# Encrypted-at-rest cache + macOS auto-lock — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the existing plaintext caches in `SecretResolver` and `SecretFs` with ChaCha20-Poly1305-encrypted entries under a process-local key, and add a macOS thread that wipes both caches on screen lock and system sleep.

**Architecture:** A new `cache_crypto` module owns a `CacheKey` (32 random bytes, zeroized on drop). A new `content_cache` module pulls the per-file rendered content out of `SecretFs` into a shared `Arc<ContentCache>`, so a `LockWatcher` thread can wipe it without holding `&mut SecretFs` (which `fuser` consumes). On macOS, `lock_watcher` runs a `CFRunLoop` thread, registers a `CFNotificationCenter` observer for `com.apple.screenIsLocked`, and an `IORegisterForSystemPower` callback for `kIOMessageSystemWillSleep`. On Linux, it logs and no-ops.

**Tech Stack:** Rust 2024, `chacha20poly1305 = "0.10"`, `rand = "0.8"`, `core-foundation = "0.10"` (macOS only), raw IOKit + CFNotificationCenter FFI via `extern "C"`. Existing crates: `zeroize`, `secrecy`, `fuser`, `minijinja`, `signal-hook`.

**Reference:** `docs/superpowers/specs/2026-05-06-encrypted-cache-design.md`.

**Test discipline:** Existing tests run with `cargo test -- --test-threads=1` (env-var mocking of the `op` CLI). All new tests honor that constraint. After every code change, run the affected test file plus `cargo build` before committing.

---

## File Structure

| Path | Status | Responsibility |
| ---- | ------ | -------------- |
| `Cargo.toml` | modify | add deps |
| `src/cache_crypto.rs` | **new** | `CacheKey`, `EncCacheEntry`, seal/open |
| `src/content_cache.rs` | **new** | per-inode encrypted rendered-content cache, implements `Lockable` |
| `src/lock_watcher.rs` | **new** | `Lockable` trait + `LockWatcher` (macOS impl + non-macOS stub) |
| `src/resolver.rs` | modify | use `Arc<CacheKey>`, store `EncCacheEntry`, impl `Lockable` |
| `src/fs.rs` | modify | drop per-file cache field, use `Arc<ContentCache>` |
| `src/config.rs` | modify | add `AutoLockConfig` |
| `src/main.rs` | modify | wire `CacheKey` + `ContentCache` + `LockWatcher` into startup |
| `src/lib.rs` | modify | declare new modules |
| `tests/resolver_test.rs` | modify | constructor signature change |
| `tests/fs_test.rs` | modify | constructor signature change |
| `tests/template_test.rs` | modify | constructor signature change |
| `tests/cache_crypto_test.rs` | **new** | unit tests for crypto (could also live inline) |
| `docs/usage.md` | modify | document `auto_lock` config + manual acceptance steps |

The `cache_crypto` and `content_cache` tests live inline (`#[cfg(test)] mod tests`) for a small surface; that matches existing inline test usage in `harden.rs` would-be tests. Lock-watcher cross-platform trait test also lives inline.

---

## Task 1: Add Cargo dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the new dependencies**

Modify `Cargo.toml` so the `[dependencies]` block adds these three lines (alphabetical placement OK; concrete diff is to insert in the existing block, not replace it):

```toml
chacha20poly1305 = "0.10"
rand = "0.8"
```

And add a new macOS-only target block (or extend the existing one) with:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
oslog = "0.2"
core-foundation = "0.10"
core-foundation-sys = "0.8"
```

(The existing macOS target block already has `oslog`; add the two `core-foundation*` lines to it.)

- [ ] **Step 2: Verify it builds**

Run: `cargo build`
Expected: clean build, `Compiling chacha20poly1305 …`, `Compiling core-foundation …` lines present.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add chacha20poly1305, rand, core-foundation for encrypted cache"
```

---

## Task 2: Implement `cache_crypto` module

**Files:**
- Create: `src/cache_crypto.rs`
- Modify: `src/lib.rs` (declare the module)

- [ ] **Step 1: Declare the module**

Add to `src/lib.rs`:

```rust
pub mod cache_crypto;
pub mod config;
pub mod fs;
pub mod resolver;
pub mod template;
```

- [ ] **Step 2: Write the failing tests**

Create `src/cache_crypto.rs` containing only the tests (implementation comes next). The compiler will reject this — that is the failing-test state.

```rust
//! Process-local encryption key + AEAD wrappers for at-rest cache entries.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = CacheKey::new();
        let plaintext = b"hello secret world";
        let entry = key.seal(plaintext);
        let opened = key.open(&entry).expect("decrypt");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn seal_produces_unique_nonce_per_call() {
        let key = CacheKey::new();
        let a = key.seal(b"same plaintext");
        let b = key.seal(b"same plaintext");
        assert_ne!(a.nonce, b.nonce, "nonces must differ");
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must differ");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = CacheKey::new();
        let mut entry = key.seal(b"payload");
        entry.ciphertext[0] ^= 0x01;
        assert!(matches!(key.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = CacheKey::new();
        let mut entry = key.seal(b"payload");
        entry.nonce[0] ^= 0x01;
        assert!(matches!(key.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = CacheKey::new();
        let key_b = CacheKey::new();
        let entry = key_a.seal(b"only-a-can-read");
        assert!(matches!(key_b.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = CacheKey::new();
        let entry = key.seal(b"");
        assert_eq!(key.open(&entry).unwrap(), b"");
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib cache_crypto -- --test-threads=1`
Expected: compilation error referencing `CacheKey`, `CryptoError`. Build fails — that's the red state.

- [ ] **Step 4: Implement the module**

Replace the file contents (keeping the test module at the bottom) with:

```rust
//! Process-local encryption key + AEAD wrappers for at-rest cache entries.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed (tag mismatch)")]
    Decrypt,
}

/// 32-byte process-local key. Zeroized on drop. Safe to share via `Arc`.
pub struct CacheKey {
    inner: Zeroizing<[u8; 32]>,
}

impl CacheKey {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        CacheKey {
            inner: Zeroizing::new(bytes),
        }
    }

    pub fn seal(&self, plaintext: &[u8]) -> EncCacheEntry {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.inner.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        // ChaCha20Poly1305::encrypt only fails on AEAD invariant violation
        // (e.g. plaintext too large for u32). Our plaintexts are bounded by
        // file/secret sizes; a panic here would indicate a bug.
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("ChaCha20-Poly1305 encrypt must not fail on bounded plaintext");
        EncCacheEntry {
            nonce: nonce_bytes,
            ciphertext,
        }
    }

    pub fn open(&self, entry: &EncCacheEntry) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.inner.as_ref()));
        let nonce = Nonce::from_slice(&entry.nonce);
        cipher
            .decrypt(nonce, entry.ciphertext.as_ref())
            .map_err(|_| CryptoError::Decrypt)
    }
}

impl Default for CacheKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted cache payload. Both fields zeroize on drop for hygiene.
#[derive(Debug)]
pub struct EncCacheEntry {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Drop for EncCacheEntry {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

#[cfg(test)]
mod tests {
    // (test module from Step 2 — keep as-is)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib cache_crypto -- --test-threads=1`
Expected: 6 tests pass.

Run: `cargo build`
Expected: clean build (no new warnings).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/cache_crypto.rs src/lib.rs
git commit -m "feat: add cache_crypto module with ChaCha20-Poly1305 sealed cache entries"
```

---

## Task 3: Refactor `SecretResolver` to use `CacheKey`

**Files:**
- Modify: `src/resolver.rs`
- Modify: `tests/resolver_test.rs`

The resolver currently stores a `SecretString` per cache entry. We replace that with `EncCacheEntry`. The public `resolve()` signature does not change.

- [ ] **Step 1: Update the test file constructors and add a no-plaintext property test**

Replace the body of `tests/resolver_test.rs` with:

```rust
use secret_fuse::cache_crypto::CacheKey;
use secret_fuse::resolver::SecretResolver;
use std::sync::Arc;
use std::time::Duration;

fn mock_op_path() -> String {
    let mock_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bin");
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{current_path}", mock_dir.display())
}

fn make_resolver(ttl_secs: u64) -> SecretResolver {
    SecretResolver::new(
        Duration::from_secs(ttl_secs),
        Duration::from_secs(30),
        Arc::new(CacheKey::new()),
    )
}

#[test]
fn test_cache_hit() {
    let resolver = make_resolver(300);
    resolver.inject_cache("op://test/item/field", "cached-value");

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "cached-value");
}

// SAFETY: tests run with --test-threads=1 (see CLAUDE.md).

#[test]
fn test_cache_expiry() {
    unsafe {
        std::env::set_var("PATH", mock_op_path());
        std::env::set_var("MOCK_OP_RESPONSE", "refreshed-value");
        std::env::set_var("MOCK_OP_EXIT_CODE", "0");
    }

    let resolver = make_resolver(0);
    resolver.inject_cache("op://test/item/field", "old-value");

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "refreshed-value");
}

#[test]
fn test_cache_miss_fetches_from_op() {
    unsafe {
        std::env::set_var("PATH", mock_op_path());
        std::env::set_var("MOCK_OP_RESPONSE", "fetched-secret");
        std::env::set_var("MOCK_OP_EXIT_CODE", "0");
    }

    let resolver = make_resolver(300);
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "fetched-secret");
}

#[test]
fn test_op_failure() {
    unsafe {
        std::env::set_var("PATH", mock_op_path());
        std::env::set_var("MOCK_OP_RESPONSE", "");
        std::env::set_var("MOCK_OP_EXIT_CODE", "1");
        std::env::set_var("MOCK_OP_STDERR", "not signed in");
    }

    let resolver = make_resolver(300);
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not signed in"), "error was: {err}");
}

#[test]
fn test_clear_cache() {
    unsafe {
        std::env::set_var("PATH", mock_op_path());
        std::env::set_var("MOCK_OP_RESPONSE", "after-clear");
        std::env::set_var("MOCK_OP_EXIT_CODE", "0");
    }

    let resolver = make_resolver(300);
    resolver.inject_cache("op://test/item/field", "value");

    resolver.clear_cache();

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "after-clear");
}

#[test]
fn test_invalid_uri() {
    let resolver = make_resolver(300);
    let result = resolver.resolve("not-a-valid-uri");
    assert!(result.is_err());
}

#[test]
fn test_cache_holds_ciphertext_not_plaintext() {
    let resolver = make_resolver(300);
    let secret = "SUPERSECRET_TOKEN_42";
    resolver.inject_cache("op://test/item/field", secret);

    let raw = resolver
        .raw_cache_bytes_for_test("op://test/item/field")
        .expect("entry present");
    let needle = secret.as_bytes();
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "plaintext leaked into cache bytes"
    );
}

#[test]
fn test_lockable_clears_cache() {
    use secret_fuse::lock_watcher::Lockable;
    let resolver = make_resolver(300);
    resolver.inject_cache("op://test/item/field", "value");
    resolver.on_lock();
    assert!(resolver.raw_cache_bytes_for_test("op://test/item/field").is_none());
}
```

(The last test imports `Lockable` from `lock_watcher`, which gets created in Task 7. To keep this task self-contained, gate that test on `cfg(feature = "lock_watcher_built")` or accept that the test file will fail to compile until Task 7. **Practical choice:** comment the `test_lockable_clears_cache` body out for now and uncomment in Task 7. The Step-3 verification below skips that test.)

Actually simpler: leave the test body uncommented but **don't run resolver tests until after Task 7**. Task 3 verification uses `cargo build --tests` and runs only the tests that compile.

- [ ] **Step 2: Run tests to confirm red**

Run: `cargo build --tests 2>&1 | head -30`
Expected: compilation errors about `SecretResolver::new` arity, `raw_cache_bytes_for_test` missing, `lock_watcher::Lockable` missing.

- [ ] **Step 3: Rewrite `src/resolver.rs`**

Replace the entire file with:

```rust
use crate::cache_crypto::{CacheKey, EncCacheEntry};
use log::error;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

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
                            let plaintext = Zeroizing::new(plaintext);
                            return String::from_utf8(plaintext.to_vec())
                                .map_err(|e| ResolveError::OpFailed(format!("utf8: {e}")));
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
```

- [ ] **Step 4: Build only (resolver tests still reference `lock_watcher::Lockable`, which is added in Task 7)**

Run: `cargo build --lib`
Expected: clean build of the library.

Run: `cargo test --lib resolver -- --test-threads=1`
Expected: clean (the `#[cfg(test)] mod tests` inside `resolver.rs` doesn't exist; nothing to run).

The `tests/resolver_test.rs` integration tests will not yet compile because of the `Lockable` import. That's expected — we'll re-enable in Task 7 and verify then. We don't run integration tests this step.

- [ ] **Step 5: Update `tests/template_test.rs` constructor calls**

Open `tests/template_test.rs`. Find every `SecretResolver::new(Duration::from_secs(N), Duration::from_secs(M))` call and replace with `SecretResolver::new(Duration::from_secs(N), Duration::from_secs(M), std::sync::Arc::new(secret_fuse::cache_crypto::CacheKey::new()))`. Also add `use secret_fuse::cache_crypto::CacheKey;` and `use std::sync::Arc;` at the top if not present.

(Pattern: introduce a small helper at the top of the file:)

```rust
use secret_fuse::cache_crypto::CacheKey;
// ...existing imports...
use std::sync::Arc;
use std::time::Duration;

fn make_resolver() -> Arc<secret_fuse::resolver::SecretResolver> {
    Arc::new(secret_fuse::resolver::SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Arc::new(CacheKey::new()),
    ))
}
```

Then replace each `let resolver = Arc::new(SecretResolver::new(... , ...));` block with `let resolver = make_resolver();` (preserve the `Duration` arg if a test deliberately uses a non-default; in `template_test.rs` they all use defaults — verify with `grep` before editing).

- [ ] **Step 6: Run template tests**

Run: `cargo test --test template_test -- --test-threads=1`
Expected: all template tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/resolver.rs tests/resolver_test.rs tests/template_test.rs
git commit -m "feat(resolver): encrypt cached secrets at rest with CacheKey"
```

---

## Task 4: Implement `content_cache` module

**Files:**
- Create: `src/content_cache.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Declare the module**

Modify `src/lib.rs` to add `pub mod content_cache;` (alphabetical placement).

```rust
pub mod cache_crypto;
pub mod config;
pub mod content_cache;
pub mod fs;
pub mod resolver;
pub mod template;
```

- [ ] **Step 2: Write the failing tests**

Create `src/content_cache.rs` with the test module first:

```rust
//! Per-inode encrypted rendered-content cache.

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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib content_cache -- --test-threads=1`
Expected: compilation error referencing `ContentCache`.

- [ ] **Step 4: Implement the module**

Replace the file contents with:

```rust
//! Per-inode encrypted rendered-content cache.

use crate::cache_crypto::{CacheKey, EncCacheEntry};
use crate::lock_watcher::Lockable;
use log::error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

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
        let mut by_inode = self.by_inode.lock().unwrap();
        let entry = by_inode.get(&ino)?;
        if entry.expires_at <= Instant::now() {
            by_inode.remove(&ino);
            return None;
        }
        match self.key.open(&entry.entry) {
            Ok(plaintext) => {
                // Wrap in Zeroizing so any failure path zeros the buffer.
                let plaintext = Zeroizing::new(plaintext);
                Some(plaintext.to_vec())
            }
            Err(e) => {
                error!("ContentCache decrypt failed for inode {ino}: {e}");
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

impl Lockable for ContentCache {
    fn on_lock(&self) {
        self.clear_all();
    }
}

// (test module from Step 2)
```

This file imports `crate::lock_watcher::Lockable`, which doesn't exist yet — meaning `cargo test` will still fail. Move the `Lockable` impl out into a stub trait inline for now and replace it in Task 7. Concretely: at the top of `content_cache.rs`, declare:

```rust
// Temporary inline trait — replaced by `crate::lock_watcher::Lockable` in Task 7.
trait LockableLocal { fn on_lock(&self); }
```

Then `impl LockableLocal for ContentCache { fn on_lock(&self) { self.clear_all(); } }`. In Task 7 we delete `LockableLocal` and switch to `crate::lock_watcher::Lockable`.

(If you'd rather keep the plan linear, you can also defer adding the `Lockable` impl until Task 7; the cache itself works without it. The test module in this task does not exercise `Lockable`.)

**Use the deferred approach: in this task, do NOT impl any `Lockable` trait. Add `impl Lockable for ContentCache` in Task 7.** Remove the `use crate::lock_watcher::Lockable;` import for now.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib content_cache -- --test-threads=1`
Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/content_cache.rs
git commit -m "feat: add ContentCache for encrypted-at-rest rendered file content"
```

---

## Task 5: Refactor `SecretFs` to use `Arc<ContentCache>`

**Files:**
- Modify: `src/fs.rs`
- Modify: `tests/fs_test.rs`

The current `FsNode::File` holds its own `Mutex<Option<CachedContent>>`. We move all caching to a shared `Arc<ContentCache>` keyed by inode.

- [ ] **Step 1: Update `tests/fs_test.rs` constructor**

Replace the `test_fs()` helper to construct an `Arc<ContentCache>` and pass it to `SecretFs::new`:

```rust
use secret_fuse::cache_crypto::CacheKey;
use secret_fuse::config::{FileEntry, FileSource};
use secret_fuse::content_cache::ContentCache;
use secret_fuse::fs::SecretFs;
use secret_fuse::resolver::SecretResolver;
use secret_fuse::template::TemplateEngine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn test_fs() -> SecretFs {
    let key = Arc::new(CacheKey::new());
    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Arc::clone(&key),
    ));
    let engine = Arc::new(TemplateEngine::new(resolver));
    let content_cache = Arc::new(ContentCache::new(key));

    let mut files = HashMap::new();
    files.insert(
        "app/.env".to_string(),
        FileEntry {
            source: FileSource::Content("DB=test".to_string()),
        },
    );
    files.insert(
        "app/nested/config.json".to_string(),
        FileEntry {
            source: FileSource::Content("{}".to_string()),
        },
    );
    files.insert(
        "top-level.txt".to_string(),
        FileEntry {
            source: FileSource::Content("hello".to_string()),
        },
    );

    SecretFs::new(files, engine, content_cache)
}
```

The rest of the file (the `#[test]` functions) stays unchanged.

- [ ] **Step 2: Build and confirm red**

Run: `cargo build --tests 2>&1 | head -20`
Expected: error about `SecretFs::new` arity.

- [ ] **Step 3: Modify `src/fs.rs`**

Two changes: (1) remove the per-file `cache` field on `FsNode::File`; (2) take and use `Arc<ContentCache>`.

Replace the top of `src/fs.rs` (the imports, `CONTENT_TTL`, `FsNode`, `CachedContent`, and `SecretFs` struct + `new()`) with:

```rust
// FUSE filesystem implementation
use crate::config::{FileEntry, FileSource};
use crate::content_cache::ContentCache;
use crate::template::TemplateEngine;
use fuser::{
    FileAttr, FileType, Filesystem, INodeNo, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, Request,
};
use fuser::{FileHandle, FopenFlags, Generation, OpenFlags, WriteFlags};
use log::error;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const CONTENT_TTL: Duration = Duration::from_secs(300);
const ATTR_TTL: Duration = Duration::from_secs(1);

// ─── Filesystem tree ──────────────────────────────────────────────────────────

enum FsNode {
    Dir { children: HashMap<String, u64> },
    File { entry: FileEntry },
}

pub struct SecretFs {
    nodes: HashMap<u64, FsNode>,
    next_ino: u64,
    engine: Arc<TemplateEngine>,
    content_cache: Arc<ContentCache>,
}

impl SecretFs {
    pub fn new(
        files: HashMap<String, FileEntry>,
        engine: Arc<TemplateEngine>,
        content_cache: Arc<ContentCache>,
    ) -> Self {
        let mut fs = SecretFs {
            nodes: HashMap::new(),
            next_ino: 2,
            engine,
            content_cache,
        };

        fs.nodes.insert(
            1,
            FsNode::Dir {
                children: HashMap::new(),
            },
        );

        for (path, entry) in files {
            fs.insert_path(&path, entry);
        }

        fs
    }

    // ... existing helpers (alloc_inode, insert_path, is_dir, lookup_child,
    //     list_children) stay unchanged BUT the FsNode::File pattern arms
    //     no longer reference `cache`. Update the matches accordingly.
```

For `insert_path`, change the file insertion to:

```rust
        // Insert the file
        let file_name = parts[parts.len() - 1].to_string();
        let file_ino = self.alloc_inode();
        self.nodes.insert(file_ino, FsNode::File { entry });
        if let Some(FsNode::Dir { children }) = self.nodes.get_mut(&parent_ino) {
            children.insert(file_name, file_ino);
        }
```

For `get_content`:

```rust
    fn get_content(&self, ino: u64) -> Option<Vec<u8>> {
        let node = self.nodes.get(&ino)?;
        match node {
            FsNode::Dir { .. } => None,
            FsNode::File { entry } => {
                if let Some(cached) = self.content_cache.get(ino) {
                    return Some(cached);
                }

                let result = match &entry.source {
                    FileSource::Content(s) => Ok(s.clone()),
                    FileSource::Template(s) => {
                        self.engine.render_string(s).map_err(|e| e.to_string())
                    }
                    FileSource::TemplateFile(path) => {
                        self.engine.render_file(path).map_err(|e| e.to_string())
                    }
                    FileSource::Secret(uri) => {
                        self.engine.render_secret(uri).map_err(|e| e.to_string())
                    }
                };

                match result {
                    Ok(content) => {
                        let bytes = content.into_bytes();
                        self.content_cache.put(ino, &bytes, CONTENT_TTL);
                        Some(bytes)
                    }
                    Err(e) => {
                        error!("failed to render content for inode {ino}: {e}");
                        None
                    }
                }
            }
        }
    }
```

Also: **delete** the `CachedContent` struct and its `Drop` impl from `fs.rs` (now lives in `content_cache.rs`). Remove the `use zeroize::Zeroize;` import if it's no longer needed in this file.

Search the rest of `fs.rs` for any other `FsNode::File { entry, cache }` pattern — there will be matches in other methods. Replace each with `FsNode::File { entry }`.

- [ ] **Step 4: Run fs tests**

Run: `cargo build --tests 2>&1 | grep -E "^error" | head`
Expected: no errors.

Run: `cargo test --test fs_test -- --test-threads=1`
Expected: all 7 fs tests pass (`test_root_dir_exists`, `test_lookup_top_level_file`, etc.).

- [ ] **Step 5: Commit**

```bash
git add src/fs.rs tests/fs_test.rs
git commit -m "feat(fs): move per-file cache to shared Arc<ContentCache>"
```

---

## Task 6: Add `AutoLockConfig` to `config.rs`

**Files:**
- Modify: `src/config.rs`
- Modify: `tests/config_test.rs`

- [ ] **Step 1: Write failing tests**

Append to `tests/config_test.rs` (or create the file if absent):

```rust
#[test]
fn test_auto_lock_defaults_to_enabled_when_omitted() {
    let yaml = r#"
mountpoint: /tmp/x
files:
  foo:
    content: bar
"#;
    let cfg = secret_fuse::config::Config::from_str(yaml).expect("parse");
    assert!(cfg.auto_lock.on_screen_lock);
    assert!(cfg.auto_lock.on_sleep);
}

#[test]
fn test_auto_lock_partial_block_keeps_other_default() {
    let yaml = r#"
mountpoint: /tmp/x
files:
  foo:
    content: bar
auto_lock:
  on_sleep: false
"#;
    let cfg = secret_fuse::config::Config::from_str(yaml).expect("parse");
    assert!(cfg.auto_lock.on_screen_lock);
    assert!(!cfg.auto_lock.on_sleep);
}
```

- [ ] **Step 2: Run tests, expect compile failure**

Run: `cargo test --test config_test -- --test-threads=1`
Expected: error about `auto_lock` field on `Config`.

- [ ] **Step 3: Modify `src/config.rs`**

Add the `AutoLockConfig` type. Insert after `FileSource`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AutoLockConfig {
    #[serde(default = "yes")]
    pub on_screen_lock: bool,
    #[serde(default = "yes")]
    pub on_sleep: bool,
}

fn yes() -> bool {
    true
}

impl Default for AutoLockConfig {
    fn default() -> Self {
        AutoLockConfig {
            on_screen_lock: true,
            on_sleep: true,
        }
    }
}
```

Add `auto_lock: AutoLockConfig` to the `Config` struct:

```rust
#[derive(Debug)]
pub struct Config {
    pub mountpoint: PathBuf,
    pub cache_ttl: u64,
    pub op_timeout: u64,
    pub auto_lock: AutoLockConfig,
    pub files: HashMap<String, FileEntry>,
}
```

Add it to `RawConfig` with `#[serde(default)]`:

```rust
#[derive(Deserialize)]
struct RawConfig {
    mountpoint: String,
    #[serde(default = "default_cache_ttl")]
    cache_ttl: u64,
    #[serde(default = "default_op_timeout")]
    op_timeout: u64,
    #[serde(default)]
    auto_lock: AutoLockConfig,
    files: HashMap<String, RawFileEntry>,
}
```

In `parse()`, propagate it into `Config`:

```rust
        Ok(Config {
            mountpoint,
            cache_ttl: raw.cache_ttl,
            op_timeout: raw.op_timeout,
            auto_lock: raw.auto_lock,
            files,
        })
```

- [ ] **Step 4: Run config tests**

Run: `cargo test --test config_test -- --test-threads=1`
Expected: all config tests pass (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs tests/config_test.rs
git commit -m "feat(config): add auto_lock block (on_screen_lock, on_sleep)"
```

---

## Task 7: Add `Lockable` trait + non-macOS `LockWatcher` stub + cross-platform test

This task ships the trait and the stub-only watcher so the resolver / content_cache integration tests gated on `Lockable` can compile and run. Task 8 fills in the macOS impl.

**Files:**
- Create: `src/lock_watcher.rs`
- Modify: `src/lib.rs`
- Modify: `src/resolver.rs` (add `Lockable` impl)
- Modify: `src/content_cache.rs` (add `Lockable` impl)
- Modify: `tests/lock_watcher_test.rs` (new — cross-platform trait test)
- Modify: `tests/resolver_test.rs` (re-enable `test_lockable_clears_cache`)

- [ ] **Step 1: Declare module and write the trait test**

Add `pub mod lock_watcher;` to `src/lib.rs` (alphabetical placement).

Create `tests/lock_watcher_test.rs`:

```rust
use secret_fuse::lock_watcher::Lockable;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingTarget(AtomicUsize);

impl Lockable for CountingTarget {
    fn on_lock(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_on_lock_dispatches_to_target() {
    let t = Arc::new(CountingTarget(AtomicUsize::new(0)));
    let dyn_t: Arc<dyn Lockable> = t.clone();
    dyn_t.on_lock();
    assert_eq!(t.0.load(Ordering::SeqCst), 1);
}

#[test]
fn test_lock_watcher_spawn_and_shutdown_on_unsupported_platform_is_noop() {
    use secret_fuse::lock_watcher::{LockConfig, LockWatcher};
    let target: Arc<dyn Lockable> = Arc::new(CountingTarget(AtomicUsize::new(0)));
    let watcher = LockWatcher::spawn(
        vec![target.clone()],
        LockConfig {
            on_screen_lock: true,
            on_sleep: true,
        },
    );
    watcher.shutdown();
    // No assertion on count — on macOS this returns without firing events,
    // on Linux it's a no-op stub.
}
```

- [ ] **Step 2: Run, confirm red**

Run: `cargo build --tests 2>&1 | head`
Expected: errors about `lock_watcher` module / `Lockable` / `LockWatcher` / `LockConfig`.

- [ ] **Step 3: Implement `src/lock_watcher.rs` (cross-platform skeleton + non-macOS stub)**

```rust
//! Auto-lock watcher: wipes registered cache targets on screen lock / system sleep.
//!
//! macOS implementation lives in `mac.rs`; other platforms get a no-op stub.

use std::sync::Arc;

pub trait Lockable: Send + Sync {
    fn on_lock(&self);
}

#[derive(Debug, Clone, Copy)]
pub struct LockConfig {
    pub on_screen_lock: bool,
    pub on_sleep: bool,
}

#[cfg(target_os = "macos")]
mod mac;

pub struct LockWatcher {
    #[cfg(target_os = "macos")]
    inner: Option<mac::MacWatcher>,
    #[cfg(not(target_os = "macos"))]
    _phantom: (),
}

impl LockWatcher {
    pub fn spawn(targets: Vec<Arc<dyn Lockable>>, cfg: LockConfig) -> Self {
        #[cfg(target_os = "macos")]
        {
            let inner = mac::MacWatcher::start(targets, cfg);
            return LockWatcher { inner };
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (targets, cfg);
            log::warn!(
                "auto_lock: not supported on this platform yet (macOS-only); per-secret TTL still applies."
            );
            LockWatcher { _phantom: () }
        }
    }

    pub fn shutdown(self) {
        #[cfg(target_os = "macos")]
        if let Some(inner) = self.inner {
            inner.stop();
        }
    }
}
```

Create `src/lock_watcher/mac.rs` as a placeholder (Task 8 fills it in):

```rust
//! macOS lock watcher — stub. Full implementation lands in Task 8.

use super::{LockConfig, Lockable};
use std::sync::Arc;

pub(super) struct MacWatcher;

impl MacWatcher {
    pub(super) fn start(_targets: Vec<Arc<dyn Lockable>>, _cfg: LockConfig) -> Option<Self> {
        log::warn!("auto_lock: macOS implementation pending — caches will only expire on TTL.");
        None
    }

    pub(super) fn stop(self) {}
}
```

Note: the `#[cfg(target_os = "macos")] mod mac;` resolution requires either `src/lock_watcher.rs` + `src/lock_watcher/mac.rs` (file-as-directory split). If you keep `lock_watcher.rs` as a single file, you must use `pub mod lock_watcher;` in `lib.rs` AND a sibling directory `src/lock_watcher/`. Rust supports this layout: `src/lock_watcher.rs` is the module file and `src/lock_watcher/mac.rs` is its submodule.

If your editor / Cargo prefers the alternate layout, use `src/lock_watcher/mod.rs` instead of `src/lock_watcher.rs`. Both work; pick whichever the existing project conventions match (this codebase uses single-file modules elsewhere, so `src/lock_watcher.rs` + `src/lock_watcher/mac.rs` is fine).

- [ ] **Step 4: Add `Lockable` impls**

In `src/resolver.rs` add:

```rust
use crate::lock_watcher::Lockable;

impl Lockable for SecretResolver {
    fn on_lock(&self) {
        self.clear_cache();
    }
}
```

In `src/content_cache.rs` add:

```rust
use crate::lock_watcher::Lockable;

impl Lockable for ContentCache {
    fn on_lock(&self) {
        self.clear_all();
    }
}
```

- [ ] **Step 5: Run all tests**

Run: `cargo test -- --test-threads=1`
Expected: every test from prior tasks plus the two new lock-watcher tests pass. The previously-deferred `test_lockable_clears_cache` in `resolver_test.rs` now compiles and passes.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/lock_watcher.rs src/lock_watcher/mac.rs \
        src/resolver.rs src/content_cache.rs \
        tests/lock_watcher_test.rs
git commit -m "feat: add Lockable trait + LockWatcher skeleton (macOS impl pending)"
```

---

## Task 8: macOS lock watcher implementation

**Files:**
- Modify: `src/lock_watcher/mac.rs`

This task installs:
1. A `CFNotificationCenter` observer for `com.apple.screenIsLocked` (distributed, system-wide).
2. An `IORegisterForSystemPower` callback for `kIOMessageSystemWillSleep`.

Both run on a dedicated thread driving `CFRunLoopRun()`. Targets are dispatched on the runloop thread (synchronously); they hold no FS locks for long, so this is safe.

- [ ] **Step 1: Write the smoke test**

Append to `tests/lock_watcher_test.rs`:

```rust
#[cfg(target_os = "macos")]
#[test]
#[ignore] // requires running on macOS desktop session
fn test_macos_spawn_returns_and_shutdown_joins() {
    use secret_fuse::lock_watcher::{LockConfig, LockWatcher, Lockable};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    struct Noop;
    impl Lockable for Noop {
        fn on_lock(&self) {}
    }

    let target: Arc<dyn Lockable> = Arc::new(Noop);
    let started = Instant::now();
    let watcher = LockWatcher::spawn(
        vec![target],
        LockConfig {
            on_screen_lock: true,
            on_sleep: true,
        },
    );
    // Give the runloop a moment to register observers.
    std::thread::sleep(Duration::from_millis(100));
    watcher.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown took too long"
    );
}
```

This test is `#[ignore]`d so CI doesn't run it; you run it manually with `cargo test --test lock_watcher_test -- --ignored --test-threads=1`.

- [ ] **Step 2: Implement `src/lock_watcher/mac.rs`**

Replace the file with:

```rust
//! macOS lock watcher. Listens for screen lock and system sleep on a
//! dedicated `CFRunLoop` thread and dispatches `Lockable::on_lock()`.

use super::{LockConfig, Lockable};
use core_foundation::base::TCFType;
use core_foundation::runloop::{
    CFRunLoop, CFRunLoopAddSource, CFRunLoopGetCurrent, CFRunLoopRun, CFRunLoopSourceRef,
    CFRunLoopStop, kCFRunLoopDefaultMode,
};
use core_foundation::string::{CFString, CFStringRef};
use log::{info, warn};
use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// ─── CFNotificationCenter FFI ─────────────────────────────────────────────────

type CFNotificationCenterRef = *mut c_void;
type CFNotificationCallback = unsafe extern "C" fn(
    center: CFNotificationCenterRef,
    observer: *mut c_void,
    name: CFStringRef,
    object: *const c_void,
    user_info: *const c_void,
);

#[repr(u32)]
#[allow(non_camel_case_types)]
enum CFNotificationSuspensionBehavior {
    DeliverImmediately = 4,
}

unsafe extern "C" {
    fn CFNotificationCenterGetDistributedCenter() -> CFNotificationCenterRef;
    fn CFNotificationCenterAddObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
        callback: CFNotificationCallback,
        name: CFStringRef,
        object: *const c_void,
        suspension_behavior: u32,
    );
    fn CFNotificationCenterRemoveEveryObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
    );
}

// ─── IOKit power-management FFI ───────────────────────────────────────────────

type io_object_t = u32;
type io_connect_t = u32;
type io_service_t = u32;
type IONotificationPortRef = *mut c_void;
type IOServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut c_void,
    service: io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
);

const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE0000280;

unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        the_port_ref: *mut IONotificationPortRef,
        callback: IOServiceInterestCallback,
        notifier: *mut io_object_t,
    ) -> io_connect_t;
    fn IODeregisterForSystemPower(notifier: *mut io_object_t) -> i32;
    fn IONotificationPortGetRunLoopSource(
        notify: IONotificationPortRef,
    ) -> CFRunLoopSourceRef;
    fn IONotificationPortDestroy(notify: IONotificationPortRef);
    fn IOAllowPowerChange(kernel_port: io_connect_t, notification_id: isize) -> i32;
}

// ─── Watcher ──────────────────────────────────────────────────────────────────

/// Heap-allocated context shared between observer callbacks and the runloop thread.
struct Context {
    targets: Vec<Arc<dyn Lockable>>,
    root_port: io_connect_t,
}

impl Context {
    fn dispatch(&self) {
        for t in &self.targets {
            t.on_lock();
        }
    }
}

pub(super) struct MacWatcher {
    runloop: CFRunLoop,
    thread: Option<thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}

impl MacWatcher {
    pub(super) fn start(
        targets: Vec<Arc<dyn Lockable>>,
        cfg: LockConfig,
    ) -> Option<Self> {
        if !cfg.on_screen_lock && !cfg.on_sleep {
            return None;
        }

        // Channel to ship the spawned thread's runloop handle back to the parent.
        let (tx, rx) = std::sync::mpsc::channel::<CFRunLoop>();
        let stopping = Arc::new(AtomicBool::new(false));
        let stopping_thread = Arc::clone(&stopping);

        // Move-into-thread: targets, cfg.
        let thread = thread::Builder::new()
            .name("secret-fuse-lock-watcher".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::thread_main(targets, cfg, &stopping_thread, tx);
                }));
                if let Err(e) = result {
                    warn!("lock watcher thread panicked: {e:?}; falling back to TTL");
                }
            })
            .ok()?;

        // Wait briefly for the runloop handle to come back. If the thread
        // never sends one, give up.
        let runloop = rx.recv_timeout(std::time::Duration::from_secs(2)).ok()?;

        info!("auto_lock: macOS lock watcher started");
        Some(MacWatcher {
            runloop,
            thread: Some(thread),
            stopping,
        })
    }

    fn thread_main(
        targets: Vec<Arc<dyn Lockable>>,
        cfg: LockConfig,
        stopping: &AtomicBool,
        runloop_tx: std::sync::mpsc::Sender<CFRunLoop>,
    ) {
        // Heap-allocate the shared context; raw pointer is what the C callbacks
        // get. We free it after CFRunLoopRun returns.
        let context = Box::new(Context {
            targets,
            root_port: 0,
        });
        let context_ptr: *mut Context = Box::into_raw(context);

        // ─ Screen-lock observer ─
        if cfg.on_screen_lock {
            unsafe {
                let center = CFNotificationCenterGetDistributedCenter();
                if center.is_null() {
                    warn!("auto_lock: CFNotificationCenter unavailable; screen-lock disabled");
                } else {
                    let name = CFString::from_static_string("com.apple.screenIsLocked");
                    CFNotificationCenterAddObserver(
                        center,
                        context_ptr as *const c_void,
                        screen_locked_callback,
                        name.as_concrete_TypeRef(),
                        ptr::null(),
                        CFNotificationSuspensionBehavior::DeliverImmediately as u32,
                    );
                }
            }
        }

        // ─ Sleep observer ─
        let mut io_notify: IONotificationPortRef = ptr::null_mut();
        let mut io_notifier: io_object_t = 0;
        if cfg.on_sleep {
            unsafe {
                let root_port = IORegisterForSystemPower(
                    context_ptr as *mut c_void,
                    &mut io_notify,
                    sleep_callback,
                    &mut io_notifier,
                );
                if root_port == 0 {
                    warn!("auto_lock: IORegisterForSystemPower failed; sleep wipe disabled");
                } else {
                    (*context_ptr).root_port = root_port;
                    let source = IONotificationPortGetRunLoopSource(io_notify);
                    if !source.is_null() {
                        CFRunLoopAddSource(
                            CFRunLoopGetCurrent(),
                            source,
                            kCFRunLoopDefaultMode,
                        );
                    }
                }
            }
        }

        // Send our runloop handle back to the parent. Get-current is safe;
        // CFRunLoop wraps a non-owning ref.
        let runloop = unsafe { CFRunLoop::wrap_under_get_rule(CFRunLoopGetCurrent()) };
        let _ = runloop_tx.send(runloop);

        // Drive the runloop. Returns when CFRunLoopStop is called from
        // shutdown(), or when the runloop exhausts sources (shouldn't happen).
        unsafe { CFRunLoopRun() };

        // ─ Tear down ─
        if cfg.on_screen_lock {
            unsafe {
                let center = CFNotificationCenterGetDistributedCenter();
                if !center.is_null() {
                    CFNotificationCenterRemoveEveryObserver(center, context_ptr as *const c_void);
                }
            }
        }
        if cfg.on_sleep && !io_notify.is_null() {
            unsafe {
                IODeregisterForSystemPower(&mut io_notifier);
                IONotificationPortDestroy(io_notify);
            }
        }

        // Reclaim the context.
        let _ = unsafe { Box::from_raw(context_ptr) };

        let _ = stopping; // touched for ordering
    }

    pub(super) fn stop(mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        unsafe {
            CFRunLoopStop(self.runloop.as_concrete_TypeRef());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        info!("auto_lock: macOS lock watcher stopped");
    }
}

unsafe extern "C" fn screen_locked_callback(
    _center: CFNotificationCenterRef,
    observer: *mut c_void,
    _name: CFStringRef,
    _object: *const c_void,
    _user_info: *const c_void,
) {
    if observer.is_null() {
        return;
    }
    let ctx = unsafe { &*(observer as *const Context) };
    log::info!("auto_lock: screen locked — wiping caches");
    ctx.dispatch();
}

unsafe extern "C" fn sleep_callback(
    refcon: *mut c_void,
    _service: io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
) {
    if refcon.is_null() {
        return;
    }
    let ctx = unsafe { &*(refcon as *const Context) };
    if message_type == K_IO_MESSAGE_SYSTEM_WILL_SLEEP {
        log::info!("auto_lock: system will sleep — wiping caches");
        ctx.dispatch();
        // Acknowledge the sleep request so macOS doesn't wait for us.
        unsafe {
            IOAllowPowerChange(ctx.root_port, message_argument as isize);
        }
    }
}
```

This file uses `core_foundation::runloop::{CFRunLoop, CFRunLoopAddSource, ...}`. Verify these are exported by your `core-foundation = "0.10"` version with `cargo doc --open -p core-foundation` if needed. If `kCFRunLoopDefaultMode` is not exposed, fetch it via `extern "C" { static kCFRunLoopDefaultMode: CFStringRef; }`.

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: clean build on macOS. (On Linux this file is gated by `cfg(target_os = "macos")` so it isn't compiled.)

- [ ] **Step 4: Run the cross-platform tests + ignored macOS smoke test**

Run: `cargo test --test lock_watcher_test -- --test-threads=1`
Expected: 2 cross-platform tests pass.

Run: `cargo test --test lock_watcher_test -- --ignored --test-threads=1`
Expected: `test_macos_spawn_returns_and_shutdown_joins` passes within 5s.

- [ ] **Step 5: Commit**

```bash
git add src/lock_watcher/mac.rs tests/lock_watcher_test.rs
git commit -m "feat(lock_watcher): macOS impl — CFNotificationCenter + IOKit sleep"
```

---

## Task 9: Wire it all together in `main.rs`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Update `cmd_mount` to construct everything**

Replace the body of `cmd_mount` (the existing function) with:

```rust
fn cmd_mount(config_path: PathBuf) {
    use crate::cache_crypto::CacheKey;
    use crate::content_cache::ContentCache;
    use crate::lock_watcher::{LockConfig, LockWatcher, Lockable};

    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    match std::process::Command::new("op").arg("--version").output() {
        Ok(output) if output.status.success() => {
            info!(
                "1Password CLI: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            eprintln!(
                "Error: 1Password CLI (op) not found. Install it: https://developer.1password.com/docs/cli/"
            );
            std::process::exit(1);
        }
    }

    harden::harden_process();

    // Process-local cache key shared between resolver and content cache.
    let key = Arc::new(CacheKey::new());
    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(config.cache_ttl),
        Duration::from_secs(config.op_timeout),
        Arc::clone(&key),
    ));
    let engine = Arc::new(TemplateEngine::new(Arc::clone(&resolver)));
    let content_cache = Arc::new(ContentCache::new(Arc::clone(&key)));
    let mountpoint = config.mountpoint.clone();
    let filesystem =
        fs::SecretFs::new(config.files, Arc::clone(&engine), Arc::clone(&content_cache));

    // Auto-lock watcher (macOS only; no-op stub elsewhere).
    let lock_targets: Vec<Arc<dyn Lockable>> = vec![
        Arc::clone(&resolver) as Arc<dyn Lockable>,
        Arc::clone(&content_cache) as Arc<dyn Lockable>,
    ];
    let lock_watcher = LockWatcher::spawn(
        lock_targets,
        LockConfig {
            on_screen_lock: config.auto_lock.on_screen_lock,
            on_sleep: config.auto_lock.on_sleep,
        },
    );

    // SIGHUP clears caches (existing behaviour).
    let sighup_resolver = Arc::clone(&resolver);
    let sighup_content = Arc::clone(&content_cache);
    let mut signals = Signals::new([SIGHUP]).expect("failed to register SIGHUP handler");
    std::thread::spawn(move || {
        for _ in signals.forever() {
            info!("SIGHUP received, clearing caches");
            sighup_resolver.clear_cache();
            sighup_content.clear_all();
        }
    });

    eprintln!("Mounting secret-fuse at {}", mountpoint.display());
    eprintln!("Press Ctrl-C to unmount and exit. Send SIGHUP to clear caches.");

    if let Err(e) = fs::mount(filesystem, &mountpoint) {
        eprintln!("Error: {e}");
        // Best-effort: shut down the watcher even on mount failure.
        lock_watcher.shutdown();
        std::process::exit(1);
    }

    lock_watcher.shutdown();
}
```

Also update the `cmd_check` function: it currently constructs a resolver too. Replace its construction with one that includes a fresh key:

```rust
    use crate::cache_crypto::CacheKey;
    let key = Arc::new(CacheKey::new());
    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Arc::clone(&key),
    ));
```

Add the new module declarations near the existing `mod` declarations:

```rust
mod cache_crypto;
mod config;
mod content_cache;
mod fs;
mod harden;
mod lock_watcher;
mod resolver;
mod service;
mod template;
```

(Note: `lib.rs` already declares them `pub`; `main.rs` also needs them as `mod` for the binary crate.)

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: clean build.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test -- --test-threads=1`
Expected: every test passes (config, fs, resolver, template, cache_crypto, content_cache, lock_watcher cross-platform).

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): wire CacheKey, ContentCache, and LockWatcher into mount"
```

---

## Task 10: Manual acceptance + docs

**Files:**
- Modify: `docs/usage.md`

- [ ] **Step 1: Document the new config block in `docs/usage.md`**

Append a section:

````markdown
## Auto-lock

`secret-fuse` wipes its in-memory caches automatically on macOS when the
screen is locked or the system goes to sleep. You can tune this in your
config:

```yaml
auto_lock:
  on_screen_lock: true   # default
  on_sleep: true         # default
```

Set either to `false` to opt out. If the `auto_lock` block is omitted
entirely, both default to `true`.

On Linux, `secret-fuse` parses the config but does not yet act on these
events; cache contents will only expire on TTL or on `SIGHUP`. Linux
support is planned.

### Manual verification

1. `cargo run -- --config fixtures/inline_config.yaml mount /tmp/sf`
2. `cat /tmp/sf/<a templated file>` — observe an `op` invocation in logs.
3. `cat /tmp/sf/<same file>` — no `op` (cache hit).
4. Lock screen with `Ctrl+Cmd+Q`, wait a moment, unlock.
5. `cat /tmp/sf/<same file>` — observe a fresh `op` invocation. (If your
   1Password vault is also locked, you'll see an `op` failure error, which
   is the expected behaviour.)
````

- [ ] **Step 2: Run the manual acceptance steps yourself**

Follow the steps above. Confirm cache wipe behaviour visually in the logs (`info!("auto_lock: screen locked — wiping caches")`).

If running headless / over SSH where you cannot lock the screen, simulate the notification by running this in a separate terminal:

```bash
osascript -e 'tell application "System Events" to keystroke "q" using {control down, command down}'
```

(or post the notification directly via `python3 -c "from Foundation import NSDistributedNotificationCenter; NSDistributedNotificationCenter.defaultCenter().postNotificationName_object_('com.apple.screenIsLocked', None)"` — note that distributed notifications may require a logged-in GUI session to deliver).

- [ ] **Step 3: Commit**

```bash
git add docs/usage.md
git commit -m "docs(usage): document auto_lock config and manual verification"
```

---

## Self-review (already performed; placed last for record)

- **Spec coverage:** Encryption-at-rest (resolver + content) → Tasks 2–5.
  Lock watcher trait + macOS impl → Tasks 7–8. Config → Task 6. Wiring →
  Task 9. Manual acceptance + docs → Task 10. Threat model and tests
  match spec sections. ✅
- **Placeholder scan:** No `TBD` / `TODO` / "implement later" left in
  task bodies. ✅
- **Type consistency:** `CacheKey`, `EncCacheEntry`, `ContentCache`,
  `Lockable`, `LockConfig`, `LockWatcher` referenced consistently. ✅
- **Known small risks (not blockers):**
  - `core-foundation 0.10` API surface for `kCFRunLoopDefaultMode` —
    Task 8 includes a fallback note (`extern "C"` declaration) if not
    re-exported.
  - `tests/resolver_test.rs` references `Lockable` before Task 7 lands;
    Task 3 explicitly defers running that integration test until Task 7
    (build-only verification in Task 3).

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-05-06-encrypted-cache.md`.
