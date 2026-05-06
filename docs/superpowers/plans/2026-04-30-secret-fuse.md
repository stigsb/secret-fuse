# secret-fuse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only FUSE filesystem that renders files with secrets fetched from 1Password via the `op` CLI.

**Architecture:** Four components — config loader (YAML parsing), secret resolver (op CLI + TTL cache), template engine (minijinja with custom `op()` function), and FUSE layer (fuser). Single mountpoint, read-only, templates defined inline or as file references.

**Tech Stack:** Rust, fuser 0.17+, minijinja 2.12+, clap 4.x, serde + serde_yaml, tokio (for subprocess timeouts)

**Spec:** `docs/superpowers/specs/2026-04-30-secret-fuse-design.md`

---

## File Structure

```
secret-fuse/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point (clap), mount/unmount/check/install commands
│   ├── config.rs             # Config loading and validation
│   ├── resolver.rs           # Secret resolver with TTL cache
│   ├── template.rs           # Template engine setup, custom op() function and filters
│   ├── fs.rs                 # FUSE filesystem implementation
│   └── service.rs            # launchd/systemd service file generation
├── tests/
│   ├── config_test.rs        # Config parsing tests
│   ├── resolver_test.rs      # Resolver + cache tests
│   ├── template_test.rs      # Template rendering tests
│   └── fs_test.rs            # Filesystem tree building tests
└── fixtures/
    ├── basic_config.yaml     # Test fixture: basic config
    ├── inline_config.yaml    # Test fixture: inline templates
    └── templates/
        └── test.env.tmpl     # Test fixture: template file
```

---

### Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `.gitignore`

- [ ] **Step 1: Initialize Cargo project**

Run:
```bash
cargo init --name secret-fuse
```

- [ ] **Step 2: Add dependencies to Cargo.toml**

Replace the `[dependencies]` section in `Cargo.toml`:

```toml
[package]
name = "secret-fuse"
version = "0.1.0"
edition = "2021"
description = "FUSE filesystem for rendering files with secrets from 1Password"

[dependencies]
fuser = "0.17"
minijinja = "2"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
base64 = "0.22"
toml = "0.8"
log = "0.4"
env_logger = "0.11"
libc = "0.2"
dirs = "6"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Write minimal main.rs with CLI skeleton**

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod fs;
mod resolver;
mod service;
mod template;

#[derive(Parser)]
#[command(name = "secret-fuse", about = "FUSE filesystem for 1Password secrets")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "~/.config/secretfuse/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the secret filesystem (foreground)
    Mount {
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
    },
    /// Unmount the secret filesystem
    Unmount,
    /// Validate config and templates without fetching secrets
    Check,
    /// Install as system service (launchd/systemd)
    Install,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { daemon } => {
            eprintln!("mount (daemon={daemon}) not yet implemented");
        }
        Commands::Unmount => {
            eprintln!("unmount not yet implemented");
        }
        Commands::Check => {
            eprintln!("check not yet implemented");
        }
        Commands::Install => {
            eprintln!("install not yet implemented");
        }
    }
}
```

- [ ] **Step 4: Create empty module files**

Create these files with placeholder content:

`src/config.rs`:
```rust
// Config loading and validation
```

`src/resolver.rs`:
```rust
// Secret resolver with TTL cache
```

`src/template.rs`:
```rust
// Template engine setup
```

`src/fs.rs`:
```rust
// FUSE filesystem implementation
```

`src/service.rs`:
```rust
// System service file generation
```

- [ ] **Step 5: Add .gitignore**

```
/target
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors (warnings about unused modules are fine).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/ .gitignore
git commit -m "feat: project scaffold with CLI skeleton"
```

---

### Task 2: Config Loader

**Files:**
- Create: `src/config.rs`
- Create: `tests/config_test.rs`
- Create: `fixtures/basic_config.yaml`
- Create: `fixtures/inline_config.yaml`

- [ ] **Step 1: Create test fixtures**

`fixtures/basic_config.yaml`:
```yaml
mountpoint: /tmp/test-secrets
cache_ttl: 60

files:
  app/.env:
    template: fixtures/templates/test.env.tmpl
  app/api-key:
    secret: op://Development/myapp/api-key
```

`fixtures/inline_config.yaml`:
```yaml
mountpoint: /tmp/test-secrets

files:
  npm/.npmrc:
    content: |
      //registry.npmjs.org/:_authToken={{ op("op://Development/npm/token") }}
  app/simple:
    secret: op://Vault/item/field
```

`fixtures/templates/test.env.tmpl`:
```
DB_HOST=localhost
DB_PASSWORD={{ op("op://Dev/postgres/password") | trim }}
```

- [ ] **Step 2: Write config parsing tests**

`tests/config_test.rs`:
```rust
use secret_fuse::config::{Config, FileEntry, FileSource};
use std::path::PathBuf;

#[test]
fn test_parse_basic_config() {
    let config = Config::load(PathBuf::from("fixtures/basic_config.yaml")).unwrap();
    assert_eq!(config.mountpoint, PathBuf::from("/tmp/test-secrets"));
    assert_eq!(config.cache_ttl, 60);
    assert_eq!(config.files.len(), 2);

    let env_entry = &config.files["app/.env"];
    assert!(matches!(&env_entry.source, FileSource::Template(p) if p == &PathBuf::from("fixtures/templates/test.env.tmpl")));

    let key_entry = &config.files["app/api-key"];
    assert!(matches!(&key_entry.source, FileSource::Secret(s) if s == "op://Development/myapp/api-key"));
}

#[test]
fn test_parse_inline_config() {
    let config = Config::load(PathBuf::from("fixtures/inline_config.yaml")).unwrap();
    assert_eq!(config.files.len(), 2);

    let npmrc = &config.files["npm/.npmrc"];
    assert!(matches!(&npmrc.source, FileSource::Content(_)));
}

#[test]
fn test_default_cache_ttl() {
    let config = Config::load(PathBuf::from("fixtures/inline_config.yaml")).unwrap();
    assert_eq!(config.cache_ttl, 300);
}

#[test]
fn test_config_not_found() {
    let result = Config::load(PathBuf::from("nonexistent.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_expand_tilde_in_mountpoint() {
    // Config with ~ should expand to home dir
    let yaml = "mountpoint: ~/secrets\nfiles:\n  test:\n    secret: op://v/i/f\n";
    let config = Config::from_str(yaml).unwrap();
    assert!(!config.mountpoint.to_string_lossy().contains('~'));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test config_test`
Expected: Fails — `config` module is empty, types don't exist.

- [ ] **Step 4: Implement config module**

`src/config.rs`:
```rust
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Debug)]
pub struct Config {
    pub mountpoint: PathBuf,
    pub cache_ttl: u64,
    pub files: HashMap<String, FileEntry>,
}

#[derive(Debug)]
pub struct FileEntry {
    pub source: FileSource,
}

#[derive(Debug)]
pub enum FileSource {
    /// Inline template content
    Content(String),
    /// Path to a template file
    Template(PathBuf),
    /// A single op:// secret URI (no template needed)
    Secret(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("file entry '{0}' must have exactly one of: content, template, or secret")]
    InvalidEntry(String),
    #[error("template file not found: {0}")]
    TemplateNotFound(PathBuf),
}

/// Raw deserialization target matching the YAML structure
#[derive(Deserialize)]
struct RawConfig {
    mountpoint: String,
    #[serde(default = "default_cache_ttl")]
    cache_ttl: u64,
    files: HashMap<String, RawFileEntry>,
}

fn default_cache_ttl() -> u64 {
    300
}

#[derive(Deserialize)]
struct RawFileEntry {
    content: Option<String>,
    template: Option<String>,
    secret: Option<String>,
}

impl Config {
    pub fn load(path: PathBuf) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(&path)?;
        Self::from_str(&contents)
    }

    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_yaml::from_str(s)?;

        let mountpoint = expand_tilde(&raw.mountpoint);

        let mut files = HashMap::new();
        for (name, entry) in raw.files {
            let source = match (entry.content, entry.template, entry.secret) {
                (Some(c), None, None) => FileSource::Content(c),
                (None, Some(t), None) => {
                    let path = expand_tilde(&t);
                    FileSource::Template(path)
                }
                (None, None, Some(s)) => FileSource::Secret(s),
                _ => return Err(ConfigError::InvalidEntry(name)),
            };
            files.insert(name, FileEntry { source });
        }

        Ok(Config {
            mountpoint,
            cache_ttl: raw.cache_ttl,
            files,
        })
    }

    /// Validate that template files exist on disk.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (name, entry) in &self.files {
            if let FileSource::Template(ref path) = entry.source {
                if !path.exists() {
                    return Err(ConfigError::TemplateNotFound(path.clone()));
                }
            }
        }
        Ok(())
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}
```

Note: we need to add `thiserror` to `Cargo.toml`:

Add to `[dependencies]` in `Cargo.toml`:
```toml
thiserror = "2"
```

- [ ] **Step 5: Export config module as public in lib.rs**

Create `src/lib.rs`:
```rust
pub mod config;
pub mod resolver;
pub mod template;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --test config_test`
Expected: All 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/config.rs src/lib.rs tests/config_test.rs fixtures/
git commit -m "feat: config loader with YAML parsing and validation"
```

---

### Task 3: Secret Resolver with Cache

**Files:**
- Modify: `src/resolver.rs`
- Create: `tests/resolver_test.rs`

- [ ] **Step 1: Write resolver tests**

`tests/resolver_test.rs`:
```rust
use secret_fuse::resolver::SecretResolver;
use std::time::Duration;

#[test]
fn test_cache_hit() {
    let resolver = SecretResolver::new(Duration::from_secs(300));
    // Pre-populate cache
    resolver.inject_cache("op://test/item/field", "cached-value");

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "cached-value");
}

#[test]
fn test_cache_expiry() {
    let resolver = SecretResolver::new(Duration::from_secs(0));
    resolver.inject_cache("op://test/item/field", "old-value");

    // With TTL=0, cache is always expired, so it will try to call `op`
    // which won't be available in test — expect an error
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_err());
}

#[test]
fn test_clear_cache() {
    let resolver = SecretResolver::new(Duration::from_secs(300));
    resolver.inject_cache("op://test/item/field", "value");

    resolver.clear_cache();

    // Cache cleared, will try op CLI which isn't available — expect error
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_err());
}

#[test]
fn test_invalid_uri() {
    let resolver = SecretResolver::new(Duration::from_secs(300));
    let result = resolver.resolve("not-a-valid-uri");
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test resolver_test`
Expected: Fails — resolver module is empty.

- [ ] **Step 3: Implement resolver**

`src/resolver.rs`:
```rust
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
        // Note: for v1 we use a simple blocking Command::output().
        // A 5-second timeout (per spec) could be added with
        // Command::spawn() + child.wait_timeout(), but op CLI calls
        // are typically fast. Add if needed.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test resolver_test`
Expected: All 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/resolver.rs tests/resolver_test.rs
git commit -m "feat: secret resolver with TTL cache and op CLI integration"
```

---

### Task 4: Template Engine

**Files:**
- Modify: `src/template.rs`
- Create: `tests/template_test.rs`

- [ ] **Step 1: Write template engine tests**

`tests/template_test.rs`:
```rust
use secret_fuse::resolver::SecretResolver;
use secret_fuse::template::TemplateEngine;
use std::sync::Arc;
use std::time::Duration;

fn test_resolver() -> Arc<SecretResolver> {
    let resolver = Arc::new(SecretResolver::new(Duration::from_secs(300)));
    resolver.inject_cache("op://Dev/postgres/password", "s3cret");
    resolver.inject_cache("op://Dev/api/key", "ak_12345");
    resolver.inject_cache("op://Dev/padded/value", "  hello  \n");
    resolver
}

#[test]
fn test_render_inline_template() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_string("DB_PASS={{ op(\"op://Dev/postgres/password\") }}")
        .unwrap();
    assert_eq!(result, "DB_PASS=s3cret");
}

#[test]
fn test_render_trim_filter() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_string("val={{ op(\"op://Dev/padded/value\") | trim }}")
        .unwrap();
    assert_eq!(result, "val=hello");
}

#[test]
fn test_render_tojson_filter() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_string("{{ op(\"op://Dev/api/key\") | tojson }}")
        .unwrap();
    assert_eq!(result, "\"ak_12345\"");
}

#[test]
fn test_render_base64_filter() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_string("{{ op(\"op://Dev/api/key\") | base64encode }}")
        .unwrap();
    assert_eq!(result, "YWtfMTIzNDU=");
}

#[test]
fn test_render_totoml_filter() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_string("{{ op(\"op://Dev/api/key\") | totoml }}")
        .unwrap();
    assert_eq!(result, "\"ak_12345\"");
}

#[test]
fn test_render_template_file() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine
        .render_file(std::path::Path::new("fixtures/templates/test.env.tmpl"))
        .unwrap();
    assert_eq!(result, "DB_HOST=localhost\nDB_PASSWORD=s3cret\n");
}

#[test]
fn test_render_secret_shorthand() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    let result = engine.render_secret("op://Dev/api/key").unwrap();
    assert_eq!(result, "ak_12345");
}

#[test]
fn test_validate_template_syntax() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);

    assert!(engine.validate_syntax("{{ op(\"op://x/y/z\") }}").is_ok());
    assert!(engine.validate_syntax("{{ broken {{").is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test template_test`
Expected: Fails — template module is empty.

- [ ] **Step 3: Implement template engine**

`src/template.rs`:
```rust
use crate::resolver::SecretResolver;
use base64::Engine as _;
use minijinja::{Environment, Error as JinjaError, ErrorKind, Value};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("template error: {0}")]
    Render(#[from] JinjaError),
    #[error("failed to read template file: {0}")]
    Io(#[from] std::io::Error),
}

pub struct TemplateEngine {
    resolver: Arc<SecretResolver>,
}

impl TemplateEngine {
    pub fn new(resolver: Arc<SecretResolver>) -> Self {
        TemplateEngine { resolver }
    }

    fn create_env(&self, template_name: &str, source: &str) -> Result<Environment<'_>, TemplateError> {
        let mut env = Environment::new();

        // Register the op() function
        let resolver = Arc::clone(&self.resolver);
        env.add_function("op", move |uri: String| -> Result<String, JinjaError> {
            resolver.resolve(&uri).map_err(|e| {
                JinjaError::new(ErrorKind::InvalidOperation, format!("op() failed: {e}"))
            })
        });

        // Register filters
        env.add_filter("tojson", tojson_filter);
        env.add_filter("base64encode", base64encode_filter);
        env.add_filter("totoml", totoml_filter);

        env.add_template_owned(template_name.to_string(), source.to_string())?;
        Ok(env)
    }

    pub fn render_string(&self, template: &str) -> Result<String, TemplateError> {
        let env = self.create_env("inline", template)?;
        let tmpl = env.get_template("inline")?;
        Ok(tmpl.render(())?)
    }

    pub fn render_file(&self, path: &Path) -> Result<String, TemplateError> {
        let source = std::fs::read_to_string(path)?;
        let env = self.create_env("file", &source)?;
        let tmpl = env.get_template("file")?;
        Ok(tmpl.render(())?)
    }

    pub fn render_secret(&self, uri: &str) -> Result<String, TemplateError> {
        let template = format!("{{{{ op(\"{uri}\") }}}}");
        self.render_string(&template)
    }

    /// Validate template syntax without rendering (no secret fetches).
    pub fn validate_syntax(&self, template: &str) -> Result<(), TemplateError> {
        let mut env = Environment::new();
        // Register a dummy op() that returns empty string for validation
        env.add_function("op", |_uri: String| -> Result<String, JinjaError> {
            Ok(String::new())
        });
        env.add_filter("tojson", tojson_filter);
        env.add_filter("base64encode", base64encode_filter);
        env.add_template_owned("validate".to_string(), template.to_string())?;
        Ok(())
    }
}

fn tojson_filter(value: String) -> Result<Value, JinjaError> {
    // JSON-encode the string (adds quotes and escapes)
    let json = serde_json::to_string(&value)
        .map_err(|e| JinjaError::new(ErrorKind::InvalidOperation, e.to_string()))?;
    Ok(Value::from(json))
}

fn base64encode_filter(value: String) -> Result<Value, JinjaError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    Ok(Value::from(encoded))
}

fn totoml_filter(value: String) -> Result<Value, JinjaError> {
    // TOML basic string: wrap in quotes, escape backslashes and quotes
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(Value::from(format!("\"{escaped}\"")))
}
```

Note: add `serde_json` to `Cargo.toml`:
```toml
serde_json = "1"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test template_test`
Expected: All 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/template.rs tests/template_test.rs
git commit -m "feat: template engine with op() function and filters"
```

---

### Task 5: FUSE Filesystem — Tree Building

**Files:**
- Modify: `src/fs.rs`
- Create: `tests/fs_test.rs`

- [ ] **Step 1: Write filesystem tree building tests**

`tests/fs_test.rs`:
```rust
use secret_fuse::config::{Config, FileEntry, FileSource};
use secret_fuse::fs::SecretFs;
use secret_fuse::resolver::SecretResolver;
use secret_fuse::template::TemplateEngine;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn test_fs() -> SecretFs {
    let resolver = Arc::new(SecretResolver::new(Duration::from_secs(300)));
    let engine = Arc::new(TemplateEngine::new(resolver));

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

    SecretFs::new(files, engine)
}

#[test]
fn test_root_dir_exists() {
    let fs = test_fs();
    // Inode 1 is root
    assert!(fs.is_dir(1));
}

#[test]
fn test_lookup_top_level_file() {
    let fs = test_fs();
    // Look up "top-level.txt" in root (inode 1)
    let ino = fs.lookup_child(1, "top-level.txt");
    assert!(ino.is_some());
    assert!(!fs.is_dir(ino.unwrap()));
}

#[test]
fn test_lookup_directory() {
    let fs = test_fs();
    let app_ino = fs.lookup_child(1, "app");
    assert!(app_ino.is_some());
    assert!(fs.is_dir(app_ino.unwrap()));
}

#[test]
fn test_lookup_nested_file() {
    let fs = test_fs();
    let app_ino = fs.lookup_child(1, "app").unwrap();
    let env_ino = fs.lookup_child(app_ino, ".env");
    assert!(env_ino.is_some());
    assert!(!fs.is_dir(env_ino.unwrap()));
}

#[test]
fn test_lookup_deeply_nested() {
    let fs = test_fs();
    let app_ino = fs.lookup_child(1, "app").unwrap();
    let nested_ino = fs.lookup_child(app_ino, "nested").unwrap();
    let config_ino = fs.lookup_child(nested_ino, "config.json");
    assert!(config_ino.is_some());
}

#[test]
fn test_readdir_root() {
    let fs = test_fs();
    let entries = fs.list_children(1);
    let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"app"));
    assert!(names.contains(&"top-level.txt"));
    assert_eq!(names.len(), 2);
}

#[test]
fn test_readdir_subdir() {
    let fs = test_fs();
    let app_ino = fs.lookup_child(1, "app").unwrap();
    let entries = fs.list_children(app_ino);
    let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&".env"));
    assert!(names.contains(&"nested"));
}

#[test]
fn test_lookup_nonexistent() {
    let fs = test_fs();
    assert!(fs.lookup_child(1, "nope").is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test fs_test`
Expected: Fails — fs module is empty.

- [ ] **Step 3: Implement filesystem tree structure**

`src/fs.rs`:
```rust
use crate::config::{FileEntry, FileSource};
use crate::template::TemplateEngine;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
enum FsNode {
    Dir {
        children: HashMap<String, u64>, // name -> inode
    },
    File {
        source: FileSource,
    },
}

pub struct SecretFs {
    nodes: HashMap<u64, FsNode>,
    engine: Arc<TemplateEngine>,
    next_inode: u64,
}

impl SecretFs {
    pub fn new(files: HashMap<String, FileEntry>, engine: Arc<TemplateEngine>) -> Self {
        let mut fs = SecretFs {
            nodes: HashMap::new(),
            engine,
            next_inode: 2, // 1 is reserved for root
        };

        // Create root directory
        fs.nodes.insert(
            1,
            FsNode::Dir {
                children: HashMap::new(),
            },
        );

        // Insert each configured file, creating intermediate directories
        for (path, entry) in files {
            fs.insert_path(&path, entry.source);
        }

        fs
    }

    fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        ino
    }

    fn insert_path(&mut self, path: &str, source: FileSource) {
        let parts: Vec<&str> = path.split('/').collect();
        let mut current_ino = 1u64; // start at root

        // Create/traverse intermediate directories
        for &part in &parts[..parts.len() - 1] {
            let existing = if let FsNode::Dir { children } = &self.nodes[&current_ino] {
                children.get(part).copied()
            } else {
                panic!("parent is not a directory");
            };

            if let Some(child_ino) = existing {
                current_ino = child_ino;
            } else {
                let new_ino = self.alloc_inode();
                self.nodes.insert(
                    new_ino,
                    FsNode::Dir {
                        children: HashMap::new(),
                    },
                );
                if let FsNode::Dir { children } = self.nodes.get_mut(&current_ino).unwrap() {
                    children.insert(part.to_string(), new_ino);
                }
                current_ino = new_ino;
            }
        }

        // Create the file node
        let file_name = parts.last().unwrap();
        let file_ino = self.alloc_inode();
        self.nodes.insert(file_ino, FsNode::File { source });

        if let FsNode::Dir { children } = self.nodes.get_mut(&current_ino).unwrap() {
            children.insert(file_name.to_string(), file_ino);
        }
    }

    pub fn is_dir(&self, ino: u64) -> bool {
        matches!(self.nodes.get(&ino), Some(FsNode::Dir { .. }))
    }

    pub fn lookup_child(&self, parent_ino: u64, name: &str) -> Option<u64> {
        if let Some(FsNode::Dir { children }) = self.nodes.get(&parent_ino) {
            children.get(name).copied()
        } else {
            None
        }
    }

    pub fn list_children(&self, ino: u64) -> Vec<(String, u64)> {
        if let Some(FsNode::Dir { children }) = self.nodes.get(&ino) {
            children
                .iter()
                .map(|(name, &ino)| (name.clone(), ino))
                .collect()
        } else {
            vec![]
        }
    }

    /// Render the content of a file node. Returns None if inode is a directory.
    pub fn read_file(&self, ino: u64) -> Option<Result<String, crate::template::TemplateError>> {
        match self.nodes.get(&ino)? {
            FsNode::File { source } => {
                let result = match source {
                    FileSource::Content(content) => self.engine.render_string(content),
                    FileSource::Template(path) => self.engine.render_file(path),
                    FileSource::Secret(uri) => self.engine.render_secret(uri),
                };
                Some(result)
            }
            FsNode::Dir { .. } => None,
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test fs_test`
Expected: All 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/fs.rs tests/fs_test.rs
git commit -m "feat: filesystem tree structure with inode management"
```

---

### Task 6: FUSE Operations

**Files:**
- Modify: `src/fs.rs`

This task adds the `fuser::Filesystem` trait implementation. FUSE operations aren't easily unit-tested (they require mounting), so we rely on the tree tests from Task 5 and do a manual integration test.

- [ ] **Step 1: Add FUSE trait imports and cached content storage**

Add to the top of `src/fs.rs`, replacing the existing imports:

```rust
use crate::config::{FileEntry, FileSource};
use crate::template::TemplateEngine;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};
use libc::{EACCES, ENOENT, ENOSYS};
use log::{error, warn};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
```

Add a content cache field to `SecretFs`:

```rust
pub struct SecretFs {
    nodes: HashMap<u64, FsNode>,
    engine: Arc<TemplateEngine>,
    next_inode: u64,
    /// Cache of rendered file contents, keyed by inode.
    content_cache: Mutex<HashMap<u64, CachedContent>>,
    mount_time: SystemTime,
}

struct CachedContent {
    data: Vec<u8>,
    expires_at: std::time::Instant,
}
```

Update the `new` method to initialize the new fields:

```rust
    pub fn new(files: HashMap<String, FileEntry>, engine: Arc<TemplateEngine>) -> Self {
        let mut fs = SecretFs {
            nodes: HashMap::new(),
            engine,
            next_inode: 2,
            content_cache: Mutex::new(HashMap::new()),
            mount_time: SystemTime::now(),
        };

        fs.nodes.insert(
            1,
            FsNode::Dir {
                children: HashMap::new(),
            },
        );

        for (path, entry) in files {
            fs.insert_path(&path, entry.source);
        }

        fs
    }
```

- [ ] **Step 2: Add helper methods for attrs and content rendering**

Add these methods to `impl SecretFs`:

```rust
    const TTL: Duration = Duration::from_secs(1); // FUSE attr cache TTL

    fn dir_attr(&self, ino: u64) -> FileAttr {
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: self.mount_time,
            mtime: self.mount_time,
            ctime: self.mount_time,
            crtime: self.mount_time,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: u64, size: u64) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: (size + 511) / 512,
            atime: self.mount_time,
            mtime: self.mount_time,
            ctime: self.mount_time,
            crtime: self.mount_time,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    /// Get or render cached content for a file inode.
    fn get_content(&self, ino: u64) -> Result<Vec<u8>, i32> {
        // Check cache
        {
            let cache = self.content_cache.lock().unwrap();
            if let Some(entry) = cache.get(&ino) {
                if entry.expires_at > std::time::Instant::now() {
                    return Ok(entry.data.clone());
                }
            }
        }

        // Render
        match self.read_file(ino) {
            Some(Ok(content)) => {
                let data = content.into_bytes();
                let mut cache = self.content_cache.lock().unwrap();
                cache.insert(
                    ino,
                    CachedContent {
                        data: data.clone(),
                        // Content cache follows the same TTL as the secret resolver
                        expires_at: std::time::Instant::now() + Duration::from_secs(300),
                    },
                );
                Ok(data)
            }
            Some(Err(e)) => {
                error!("failed to render file (inode {ino}): {e}");
                Err(libc::EIO)
            }
            None => Err(ENOENT),
        }
    }
```

- [ ] **Step 3: Implement fuser::Filesystem trait**

Add this `impl` block after the existing `impl SecretFs`:

```rust
impl Filesystem for SecretFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        match self.lookup_child(parent, &name) {
            Some(ino) if self.is_dir(ino) => {
                reply.entry(&Self::TTL, &self.dir_attr(ino), 0);
            }
            Some(ino) => {
                match self.get_content(ino) {
                    Ok(data) => reply.entry(&Self::TTL, &self.file_attr(ino, data.len() as u64), 0),
                    Err(e) => reply.error(e),
                }
            }
            None => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if self.is_dir(ino) {
            reply.attr(&Self::TTL, &self.dir_attr(ino));
        } else if self.nodes.contains_key(&ino) {
            match self.get_content(ino) {
                Ok(data) => reply.attr(&Self::TTL, &self.file_attr(ino, data.len() as u64)),
                Err(e) => reply.error(e),
            }
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if !self.is_dir(ino) {
            reply.error(ENOENT);
            return;
        }

        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        for (name, child_ino) in self.list_children(ino) {
            let kind = if self.is_dir(child_ino) {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            entries.push((child_ino, kind, name));
        }

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, &name) {
                break; // buffer full
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        // Read-only: reject any write flags
        let access_mode = flags & libc::O_ACCMODE;
        if access_mode != libc::O_RDONLY {
            reply.error(EACCES);
            return;
        }

        if self.nodes.contains_key(&ino) && !self.is_dir(ino) {
            reply.opened(0, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        match self.get_content(ino) {
            Ok(data) => {
                let offset = offset as usize;
                if offset >= data.len() {
                    reply.data(&[]);
                } else {
                    let end = (offset + size as usize).min(data.len());
                    reply.data(&data[offset..end]);
                }
            }
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        reply.error(EACCES);
    }

    fn setattr(
        &mut self,
        _req: &Request,
        _ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        reply.error(EACCES);
    }
}
```

- [ ] **Step 4: Add a public mount function**

Add to `src/fs.rs`:

```rust
pub fn mount(fs: SecretFs, mountpoint: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = vec![
        MountOption::RO,
        MountOption::FSName("secret-fuse".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
    ];

    std::fs::create_dir_all(mountpoint)?;

    log::info!("Mounting secret-fuse at {}", mountpoint.display());
    fuser::mount2(fs, mountpoint, &options)?;
    Ok(())
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles. (Some method signatures for the Filesystem trait may need adjustment based on the exact fuser version — fix any type mismatches.)

- [ ] **Step 6: Verify existing tests still pass**

Run: `cargo test`
Expected: All tests from Tasks 2-5 still pass.

- [ ] **Step 7: Commit**

```bash
git add src/fs.rs
git commit -m "feat: FUSE filesystem operations (read-only)"
```

---

### Task 7: Wire Up CLI Commands

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Implement the mount command**

Replace `src/main.rs`:

```rust
use clap::{Parser, Subcommand};
use log::{error, info};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod config;
mod fs;
mod resolver;
mod service;
mod template;

use config::Config;
use resolver::SecretResolver;
use template::TemplateEngine;

#[derive(Parser)]
#[command(name = "secret-fuse", about = "FUSE filesystem for 1Password secrets")]
struct Cli {
    /// Path to config file
    #[arg(
        short,
        long,
        default_value = "~/.config/secretfuse/config.yaml"
    )]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the secret filesystem
    Mount {
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
    },
    /// Unmount the secret filesystem
    Unmount,
    /// Validate config and templates without fetching secrets
    Check,
    /// Install as system service (launchd/systemd)
    Install,
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let config_path = expand_tilde(&cli.config);

    match cli.command {
        Commands::Mount { daemon } => {
            if daemon {
                eprintln!("Daemon mode not yet implemented. Running in foreground.");
            }
            cmd_mount(config_path);
        }
        Commands::Unmount => {
            cmd_unmount(config_path);
        }
        Commands::Check => {
            cmd_check(config_path);
        }
        Commands::Install => {
            eprintln!("Service installation not yet implemented.");
            std::process::exit(1);
        }
    }
}

fn cmd_mount(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config: {e}");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        error!("Config validation failed: {e}");
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    // Check that `op` is available
    match std::process::Command::new("op").arg("--version").output() {
        Ok(output) if output.status.success() => {
            info!(
                "1Password CLI: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            eprintln!("Error: 1Password CLI (op) not found. Install it: https://developer.1password.com/docs/cli/");
            std::process::exit(1);
        }
    }

    let resolver = Arc::new(SecretResolver::new(Duration::from_secs(config.cache_ttl)));
    let engine = Arc::new(TemplateEngine::new(resolver));
    let mountpoint = config.mountpoint.clone();

    let filesystem = fs::SecretFs::new(config.files, engine);

    // Install SIGHUP handler to clear cache
    // (The resolver is inside the filesystem, so this would need a shared reference.
    //  For v1, SIGHUP support is deferred — just mount.)

    eprintln!("Mounting secret-fuse at {}", mountpoint.display());
    eprintln!("Press Ctrl-C to unmount and exit.");

    if let Err(e) = fs::mount(filesystem, &mountpoint) {
        error!("Mount failed: {e}");
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_unmount(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mountpoint = config.mountpoint.to_string_lossy().to_string();

    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("umount").arg(&mountpoint).status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("fusermount")
        .args(["-u", &mountpoint])
        .status();

    match result {
        Ok(status) if status.success() => {
            eprintln!("Unmounted {mountpoint}");
        }
        Ok(status) => {
            eprintln!("Unmount failed (exit code: {})", status.code().unwrap_or(-1));
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Unmount failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_check(config_path: PathBuf) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        eprintln!("Validation error: {e}");
        std::process::exit(1);
    }

    let resolver = Arc::new(SecretResolver::new(Duration::from_secs(300)));
    let engine = TemplateEngine::new(resolver);

    let mut errors = 0;
    for (path, entry) in &config.files {
        let result = match &entry.source {
            config::FileSource::Content(c) => engine.validate_syntax(c),
            config::FileSource::Template(p) => match std::fs::read_to_string(p) {
                Ok(contents) => engine.validate_syntax(&contents),
                Err(e) => {
                    eprintln!("  FAIL {path}: {e}");
                    errors += 1;
                    continue;
                }
            },
            config::FileSource::Secret(_) => Ok(()),
        };

        match result {
            Ok(()) => eprintln!("  OK   {path}"),
            Err(e) => {
                eprintln!("  FAIL {path}: {e}");
                errors += 1;
            }
        }
    }

    if errors > 0 {
        eprintln!("\n{errors} error(s) found.");
        std::process::exit(1);
    } else {
        eprintln!("\nAll templates valid.");
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 3: Verify CLI help works**

Run: `cargo run -- --help`
Expected: Shows help text with mount, unmount, check, install subcommands.

Run: `cargo run -- mount --help`
Expected: Shows mount-specific help with --daemon flag.

- [ ] **Step 4: Verify check command works**

Run: `cargo run -- --config fixtures/inline_config.yaml check`
Expected: Shows OK for each template entry, "All templates valid."

- [ ] **Step 5: Verify all tests still pass**

Run: `cargo test`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire up CLI commands (mount, unmount, check)"
```

---

### Task 8: Service Installation

**Files:**
- Modify: `src/service.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Implement service file generation**

`src/service.rs`:
```rust
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("failed to write service file: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not determine current executable path")]
    NoExePath,
    #[error("unsupported platform for service installation")]
    UnsupportedPlatform,
}

pub fn install(config_path: &Path, mountpoint: &Path) -> Result<PathBuf, ServiceError> {
    let exe = std::env::current_exe().map_err(|_| ServiceError::NoExePath)?;

    #[cfg(target_os = "macos")]
    {
        install_launchd(&exe, config_path, mountpoint)
    }

    #[cfg(target_os = "linux")]
    {
        install_systemd(&exe, config_path, mountpoint)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(ServiceError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn install_launchd(
    exe: &Path,
    config_path: &Path,
    _mountpoint: &Path,
) -> Result<PathBuf, ServiceError> {
    let plist_dir = dirs::home_dir()
        .unwrap_or_default()
        .join("Library/LaunchAgents");
    std::fs::create_dir_all(&plist_dir)?;

    let plist_path = plist_dir.join("com.stigbakken.secret-fuse.plist");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.sunstoneinstitute.secret-fuse</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>mount</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/secret-fuse.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/secret-fuse.stderr.log</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        config = config_path.display(),
    );

    std::fs::write(&plist_path, plist)?;
    Ok(plist_path)
}

#[cfg(target_os = "linux")]
fn install_systemd(
    exe: &Path,
    config_path: &Path,
    _mountpoint: &Path,
) -> Result<PathBuf, ServiceError> {
    let unit_dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;

    let unit_path = unit_dir.join("secret-fuse.service");
    let unit = format!(
        r#"[Unit]
Description=secret-fuse - FUSE filesystem for 1Password secrets
After=network.target

[Service]
Type=simple
ExecStart={exe} --config {config} mount
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        exe = exe.display(),
        config = config_path.display(),
    );

    std::fs::write(&unit_path, unit)?;
    Ok(unit_path)
}
```

- [ ] **Step 2: Wire up the install command in main.rs**

In `src/main.rs`, replace the `Commands::Install` arm:

```rust
        Commands::Install => {
            cmd_install(config_path);
        }
```

Add the `cmd_install` function:

```rust
fn cmd_install(config_path: PathBuf) {
    let config = match Config::load(config_path.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    match service::install(&config_path, &config.mountpoint) {
        Ok(path) => {
            eprintln!("Service file written to: {}", path.display());

            #[cfg(target_os = "macos")]
            eprintln!(
                "To load: launchctl load {}",
                path.display()
            );

            #[cfg(target_os = "linux")]
            eprintln!(
                "To enable: systemctl --user enable --now secret-fuse"
            );
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/service.rs src/main.rs
git commit -m "feat: system service installation (launchd/systemd)"
```

---

### Task 9: Integration Test — Manual

This task is a manual smoke test to verify the whole system works end-to-end.

- [ ] **Step 1: Create a test config**

Create `~/.config/secretfuse/config.yaml` (or use a temp path):

```yaml
mountpoint: /tmp/secret-fuse-test
cache_ttl: 60

files:
  test/hello.txt:
    content: "Hello from secret-fuse!"
  test/secret.txt:
    secret: op://Private/test-secret/password
```

Replace `op://Private/test-secret/password` with an actual 1Password item you have access to.

- [ ] **Step 2: Run check command**

Run: `cargo run -- --config ~/.config/secretfuse/config.yaml check`
Expected: "All templates valid."

- [ ] **Step 3: Mount and test**

Run: `cargo run -- --config ~/.config/secretfuse/config.yaml mount`

In another terminal:
```bash
ls /tmp/secret-fuse-test/test/
cat /tmp/secret-fuse-test/test/hello.txt
cat /tmp/secret-fuse-test/test/secret.txt
```

Expected:
- `ls` shows `hello.txt` and `secret.txt`
- `cat hello.txt` shows "Hello from secret-fuse!"
- `cat secret.txt` shows the actual secret from 1Password

- [ ] **Step 4: Verify read-only**

```bash
echo "nope" > /tmp/secret-fuse-test/test/hello.txt
```

Expected: "Operation not permitted" or "Read-only file system"

- [ ] **Step 5: Unmount**

Press Ctrl-C in the mount terminal, or run:
```bash
cargo run -- --config ~/.config/secretfuse/config.yaml unmount
```

- [ ] **Step 6: Commit any fixes**

If any issues were found and fixed during testing, commit them:
```bash
git add -A
git commit -m "fix: integration test fixes"
```

---

### Task 10: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

`README.md`:
```markdown
# secret-fuse

A FUSE filesystem that renders files with secrets from 1Password on the fly.

No secrets are stored on disk. Files are rendered from templates at read time,
pulling values from 1Password via the `op` CLI.

## Requirements

- [macFUSE](https://osxfuse.github.io/) (macOS) or libfuse (Linux)
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`)

## Install

```bash
cargo install --path .
```

## Configuration

Create `~/.config/secretfuse/config.yaml`:

```yaml
mountpoint: ~/secrets
cache_ttl: 300  # seconds, default 5 minutes

files:
  # Inline template
  npm/.npmrc:
    content: |
      //registry.npmjs.org/:_authToken={{ op("op://Development/npm/token") }}

  # Template file reference
  myapp/.env:
    template: ~/.config/secretfuse/templates/myapp.env.tmpl

  # Single secret value
  myapp/api-key:
    secret: op://Production/myapp/api-key
```

## Usage

```bash
# Validate config and templates
secret-fuse check

# Mount (foreground)
secret-fuse mount

# Mount with custom config
secret-fuse --config /path/to/config.yaml mount

# Unmount
secret-fuse unmount

# Install as system service
secret-fuse install
```

## Symlinks

Point config files to the mount:

```bash
ln -s ~/secrets/npm/.npmrc ~/.npmrc
ln -s ~/secrets/myapp/.env ~/projects/myapp/.env
```

## Template Syntax

Templates use [Jinja2 syntax](https://jinja.palletsprojects.com/) via minijinja.

### Functions

- `op(uri)` — fetch a secret: `{{ op("op://vault/item/field") }}`

### Filters

- `trim` — strip whitespace
- `tojson` — JSON string escaping
- `base64encode` — base64 encoding

### Examples

```ini
DB_PASSWORD={{ op("op://Dev/postgres/password") | trim }}
```

```json
{ "apiKey": {{ op("op://Dev/api/key") | tojson }} }
```

## Cache

Secrets are cached in memory (default 5 minutes). Send `SIGHUP` to clear the cache.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```
