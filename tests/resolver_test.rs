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
fn test_lockable_clears_cache() {
    use secret_fuse::lock_watcher::Lockable;
    let resolver = make_resolver(300);
    resolver.inject_cache("op://test/item/field", "value");
    resolver.on_lock();
    assert!(resolver.raw_cache_bytes_for_test("op://test/item/field").is_none());
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
