# Encrypted-at-rest cache + auto-lock on screen lock/sleep

**Status:** design
**Date:** 2026-05-06

## Goal

Raise the bar for in-memory secret protection in `secret-fuse` beyond the
current "zeroize on drop + mlockall" baseline by:

1. Encrypting every cached secret-bearing value at rest in process memory,
   under a process-local random key. Plaintext exists only on the stack
   for the duration of a single read or render.
2. Wiping all caches in response to user-session lifecycle events that
   indicate the user is no longer present: macOS screen lock and system
   sleep.

Linux support for lock/sleep events is out of scope for this change and
will be added in a follow-up.

## Non-goals

- Defeating an attacker with root or `ptrace` capabilities. The existing
  `harden.rs` raises the bar against same-user processes; encryption-at-rest
  raises it further but is not a substitute for hardware-backed isolation.
- Periodic key rotation ("Boojum"-style rekeying). Skipped for v1; can be
  added later because the encrypt/decrypt boundary is the only touch point.
- Hardware-backed keys (Secure Enclave / TPM). Considered and rejected for
  v1 in favor of the simpler process-local key.
- Changing the public type of `SecretResolver::resolve()` to a guard type.
  The minijinja callback returns a plain `String`, so the guard would be
  dropped immediately and provide no real benefit.

## Threat model delta

| Attack                                              | Before | After |
| --------------------------------------------------- | ------ | ----- |
| Process memory dump while caches hold plaintext     | secrets readable | secrets ciphertext only |
| Process memory dump after a screen-lock event       | TTL-bounded staleness | empty caches; needs fresh `op` fetch |
| Process memory dump after sleep/wake               | TTL-bounded staleness | empty caches |
| Root attacker with `ptrace`/process_vm_readv access | exposed                | unchanged (still exposed; key is in process) |
| Cold-boot attack on RAM                             | exposed                | unchanged (key still in RAM) |

The protection is meaningful because it eliminates the two most plausible
non-root scenarios: a forensic snapshot of the running daemon, and the
"I locked my laptop and walked away" scenario.

## Architecture

A new module `src/cache_crypto.rs` owns a process-local 32-byte key and
exposes `seal` / `open` operations. Both existing caches store ciphertext
plus per-entry nonce instead of plaintext.

A new module `src/lock_watcher.rs` (macOS impl + Linux stub) runs a
dedicated thread on macOS that listens for screen-lock and sleep events,
calling registered `Lockable` targets when they fire.

The fs's per-file content cache is extracted into a dedicated
`ContentCache` struct held behind an `Arc`, so it can be shared between
`SecretFs` (which `fuser::mount2` consumes by value) and the watcher.
The resolver is already an `Arc<SecretResolver>` in `main.rs`, so it
needs no structural change.

```
                   ┌─────────────────┐
                   │  CacheKey (32B) │  Zeroizing, mlock'd
                   └────────┬────────┘
                            │ Arc
              ┌─────────────┴─────────────┐
              ▼                           ▼
   ┌─────────────────────┐     ┌─────────────────────┐
   │  SecretResolver     │     │  ContentCache       │
   │  cache: HashMap<    │     │  by_inode: HashMap< │
   │   String,           │     │   u64,              │
   │   EncCacheEntry>    │     │   Mutex<Option<     │
   │                     │     │     EncCacheEntry>>>│
   └─────────────────────┘     └─────────────────────┘
              ▲                           ▲
              │ Arc<SecretResolver>       │ Arc<ContentCache>
              │                           │ (also held by SecretFs)
              └─────────────┬─────────────┘
                            │ Arc<dyn Lockable>
                            │
                  ┌─────────┴──────────┐
                  │  LockWatcher       │  macOS thread
                  │  (CFRunLoop +      │
                  │   IOKit power)     │
                  └────────────────────┘
```

## Components

### `src/cache_crypto.rs`

```rust
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed (tag mismatch)")]
    Decrypt,
}

pub struct CacheKey {
    inner: Zeroizing<[u8; 32]>,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncCacheEntry {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // includes 16-byte Poly1305 tag
}

impl CacheKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        CacheKey { inner: Zeroizing::new(key) }
    }

    pub fn seal(&self, plaintext: &[u8]) -> EncCacheEntry { /* ChaCha20-Poly1305 */ }

    pub fn open(&self, entry: &EncCacheEntry) -> Result<Vec<u8>, CryptoError> { /* ... */ }
}
```

- Cipher: ChaCha20-Poly1305 (RustCrypto `chacha20poly1305` crate).
- Nonce: random 12 bytes per `seal()`. Collision probability is negligible
  at our cache scale.
- AAD: empty for v1. (Could later bind to URI / file path if useful.)
- Key zeroizes on drop via `Zeroizing`. `EncCacheEntry` zeroizes its
  ciphertext on drop for hygiene; this is defense in depth, since the
  cleartext was never in `ciphertext`.

### `src/resolver.rs` changes

```rust
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
    pub fn new(ttl: Duration, op_timeout: Duration, key: Arc<CacheKey>) -> Self;
    pub fn resolve(&self, uri: &str) -> Result<String, ResolveError>; // unchanged signature
    pub fn clear_cache(&self);                                        // unchanged
}

impl Lockable for SecretResolver {
    fn on_lock(&self) { self.clear_cache() }
}
```

- On cache hit: `key.open(entry)`, wrap plaintext in `Zeroizing<Vec<u8>>`,
  convert to `String`, return. The wrapper is dropped on function exit.
- On cache miss: fetch via `op`, `key.seal(value.as_bytes())`, insert
  `EncCacheEntry`. The plaintext `String` returned to the caller is
  unchanged and still lives only as long as the caller needs it.
- On `open()` failure: log `error!`, drop the bad entry, fall through to
  the miss path (refetch from `op`).

### `src/content_cache.rs` (new)

Per-inode rendered-content cache, shared between `SecretFs` and the
watcher. Pulling this out of `SecretFs` is required because
`fuser::mount2` takes the `Filesystem` impl by value and FUSE methods
take `&mut self`, so the watcher cannot hold a usable reference to
`SecretFs` itself.

```rust
struct CachedContent {
    entry: EncCacheEntry,
    expires_at: Instant,
}

pub struct ContentCache {
    key: Arc<CacheKey>,
    by_inode: Mutex<HashMap<u64, Option<CachedContent>>>,
}

impl ContentCache {
    pub fn new(key: Arc<CacheKey>) -> Self;
    pub fn get(&self, ino: u64) -> Option<Vec<u8>>;       // decrypts on hit, honors TTL
    pub fn put(&self, ino: u64, plaintext: &[u8], ttl: Duration);
    pub fn clear_all(&self);
}

impl Lockable for ContentCache {
    fn on_lock(&self) { self.clear_all() }
}
```

### `src/fs.rs` changes

- `FsNode::File` no longer carries a `cache` field. The fs holds an
  `Arc<ContentCache>` and looks up by inode.
- `SecretFs::new` takes `Arc<TemplateEngine>` and `Arc<ContentCache>`
  (no longer takes `key` directly — the cache owns the key).
- `SecretFs::get_content(ino)` consults `ContentCache::get(ino)`, falls
  through to render + `ContentCache::put` on miss.
- The `Drop` impl that zeroizes `data: Vec<u8>` is removed (data lived
  in `CachedContent`, which now lives in `ContentCache`; the
  `EncCacheEntry` zeroize-on-drop covers it).

### `src/lock_watcher.rs`

```rust
pub trait Lockable: Send + Sync {
    fn on_lock(&self);
}

pub struct LockConfig {
    pub on_screen_lock: bool, // default true
    pub on_sleep: bool,       // default true
}

pub struct LockWatcher {
    // platform-specific internals (thread join handle, stop channel)
}

impl LockWatcher {
    pub fn spawn(targets: Vec<Arc<dyn Lockable>>, cfg: LockConfig) -> Self;
    pub fn shutdown(self);
}
```

- macOS implementation:
  - Spawns one thread.
  - In the thread: get the current `CFRunLoop`, register
    `NSDistributedNotificationCenter` observers for
    `com.apple.screenIsLocked` (and `…IsUnlocked` if we want to log
    transitions; we do not act on unlock).
  - For sleep: `IORegisterForSystemPower` callback for
    `kIOMessageSystemWillSleep`. The callback acknowledges the sleep
    request via `IOAllowPowerChange` after invoking targets.
  - The observer/callback closures call `target.on_lock()` for each
    registered target.
  - Drives `CFRunLoopRun()`. Shutdown signals via `CFRunLoopStop` plus a
    flag, then joins the thread.
  - The whole spawn body is wrapped in `catch_unwind`; a panic in the
    thread is logged and the watcher silently goes idle. Caches still
    expire on TTL.
- Non-macOS implementation:
  - `spawn()` returns a no-op watcher. Logs `WARN auto_lock: not
    supported on this platform yet (macOS-only); per-secret TTL still
    applies.` exactly once at startup.

### Crates added

- `chacha20poly1305 = "0.10"` (RustCrypto)
- `rand = "0.8"` (`OsRng` for key + nonce generation)
- macOS only:
  - `objc2 = "0.5"`
  - `objc2-foundation = "0.2"`
  - `core-foundation = "0.10"`
  - IOKit FFI: prefer raw `extern "C"` declarations over a heavier crate
    (only need `IORegisterForSystemPower`, `IODeregisterForSystemPower`,
    `IOAllowPowerChange`).

## Configuration

`src/config.rs` gains an `auto_lock` block:

```yaml
cache_ttl: 300
op_timeout: 10

auto_lock:                 # optional; secure-by-default
  on_screen_lock: true     # default true
  on_sleep: true           # default true
```

Rust shape:

```rust
#[derive(Deserialize, Debug, Clone)]
pub struct AutoLockConfig {
    #[serde(default = "yes")] pub on_screen_lock: bool,
    #[serde(default = "yes")] pub on_sleep: bool,
}
fn yes() -> bool { true }

impl Default for AutoLockConfig {
    fn default() -> Self { Self { on_screen_lock: true, on_sleep: true } }
}
```

Added to `Config` with `#[serde(default)]`. Validation works on every
platform; behavior is gated by platform inside `LockWatcher::spawn`.

## Lifecycle / data flow

### Startup (`main.rs`)

1. `harden_process()` (unchanged).
2. `let key = Arc::new(CacheKey::new());`
3. `let resolver = Arc::new(SecretResolver::new(ttl, op_timeout, Arc::clone(&key)));`
4. `let content_cache = Arc::new(ContentCache::new(Arc::clone(&key)));`
5. `let fs = SecretFs::new(files, engine, Arc::clone(&content_cache));`
   (`fuser::mount2` takes ownership of `fs` by value — fine, the cache
   it uses lives behind an `Arc`.)
6. `let watcher = LockWatcher::spawn(
       vec![resolver.clone() as Arc<dyn Lockable>,
            content_cache.clone() as Arc<dyn Lockable>],
       cfg,
   );`
7. `fuser::mount2(fs, ...)` blocks as today.
8. On unmount/SIGINT: `watcher.shutdown()`, then drop everything (key
   zeroizes when the last `Arc<CacheKey>` is dropped).

### Cache write (resolver miss)

```
op CLI stdout → String
  └─→ key.seal(bytes) → EncCacheEntry { nonce, ciphertext }
       └─→ HashMap.insert(uri, { entry, expires_at })
  └─→ return String to caller (template engine consumes; drops on stack)
```

### Cache read (resolver hit)

```
HashMap.get(uri) → &EncCacheEntry
  └─→ key.open(entry) → Vec<u8>  (wrap as Zeroizing immediately)
       └─→ String::from_utf8 → return
       └─→ Zeroizing buffer drops at function exit (zeroized)
```

Plaintext lifetime: one `resolve()` call.

### Lock event

```
[CFRunLoop thread]
NSDistributedNotificationCenter receives "com.apple.screenIsLocked"
  └─→ observer callback fires
  └─→ for target in targets: target.on_lock()
       ├─→ SecretResolver::clear_cache()   (HashMap entries dropped)
       └─→ ContentCache::clear_all()       (by_inode map drained)
```

Subsequent reads behave like a cold start: `op` is invoked, and if the
1Password vault is also locked the user sees a normal `op` failure error.

## Error handling

- **`CacheKey::open()` failure** — should be unreachable at runtime with a
  correct implementation. Treated as a cache miss: `error!`-log, drop the
  entry, refetch.
- **Lock-watcher spawn failure** (Objective-C class lookup, IOKit
  registration) — `warn!`-log, fall back to TTL-only behavior. Daemon
  continues to serve files.
- **Lock-watcher thread panic** — caught with `catch_unwind`, logged,
  watcher goes silent. Caches still wipe on TTL.
- **Config errors** — surfaced via existing `Config::load()` path; the
  `check` subcommand catches them.
- **Existing error paths** (`ResolveError::*`, template errors) — unchanged.

## Testing

Existing tests must continue to pass after the refactor (`cargo test --
--test-threads=1`).

### `cache_crypto.rs` unit tests

- `seal_open_roundtrip` — encrypt → decrypt → equal plaintext.
- `nonce_uniqueness` — two `seal()`s of the same plaintext yield distinct
  `nonce` and `ciphertext` fields.
- `tampered_ciphertext_fails` — flipping a byte in `ciphertext` causes
  `open()` to return `CryptoError::Decrypt`.
- `tampered_nonce_fails` — same, with `nonce`.
- `wrong_key_fails` — encrypt with key A, decrypt with key B → error.

### Property: no plaintext at rest

- In `resolver.rs` tests: inject a known unique value
  (`"SUPERSECRET_TOKEN_42"`), populate the cache, walk every
  `EncCacheEntry`'s raw `ciphertext` bytes, assert the substring is
  absent.
- Same property test in `content_cache.rs`.

### Resolver / fs / content_cache integration

- Existing tests are the regression bar — must still pass after the type
  changes.
- New: `ContentCache::clear_all` empties the map.
- New: TTL still works after refactor (existing tests likely cover this).

### Lock watcher

- Cross-platform trait test: a fake `Lockable` records calls; ensure
  `on_lock()` triggers the registered side effects (this exercises the
  resolver/fs `Lockable` impls without touching macOS APIs).
- macOS smoke test (`#[cfg(target_os = "macos")] #[ignore]`): asserts
  `LockWatcher::spawn` returns and `shutdown()` joins cleanly within a
  reasonable timeout. No simulated lock event.
- Optional macOS event-injection test
  (`#[cfg(target_os = "macos")] #[ignore]`): post
  `com.apple.screenIsLocked` to the local distributed notification
  center, assert targets observed the call. Skipped if flaky.

### Manual acceptance

Documented in `docs/usage.md` (added during implementation):

1. `cargo run -- --config fixtures/inline_config.yaml mount /tmp/sf`.
2. `cat /tmp/sf/<some-templated-file>` — observe `op` invocation in logs.
3. `cat /tmp/sf/<same-file>` — observe cache hit (no `op`).
4. Lock screen with `Ctrl+Cmd+Q`, unlock.
5. `cat /tmp/sf/<same-file>` — observe fresh `op` invocation.

### Out of scope

- Real `IORegisterForSystemPower` callbacks (would require sleeping the
  test machine).
- Linux D-Bus signals (Linux is stubbed for v1).

## Open questions

None blocking. Tracked for follow-ups:

- Linux `lock_watcher` implementation (logind PrepareForSleep,
  ScreenSaver D-Bus signals).
- Optional periodic rekeying ("Boojum") if forensic-snapshot resistance
  becomes a stated goal.
- Optional global idle timeout (`auto_lock.idle_seconds`) — would track
  last FUSE access and clear caches after N seconds of inactivity.

## Migration

- Existing config files without an `auto_lock` block continue to work
  (defaults to enabled on macOS).
- No persisted state / no on-disk format changes.
- Internal API changes:
  - `SecretResolver::new` takes `Arc<CacheKey>`.
  - `SecretFs::new` takes `Arc<ContentCache>` (no longer takes the
    `key` directly; `ContentCache` owns it).
  - New module `src/content_cache.rs`.
  Both `SecretResolver` and `SecretFs` are crate-internal; `lib.rs` and
  `main.rs` are the only callers.
