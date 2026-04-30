use secret_fuse::resolver::SecretResolver;
use std::time::Duration;

/// Prepend fixtures/bin to PATH so the mock `op` is found first.
fn mock_op_path() -> String {
    let mock_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bin");
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{current_path}", mock_dir.display())
}

#[test]
fn test_cache_hit() {
    let resolver = SecretResolver::new(Duration::from_secs(300), Duration::from_secs(30));
    resolver.inject_cache("op://test/item/field", "cached-value");

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "cached-value");
}

#[test]
fn test_cache_expiry() {
    // Use mock op that returns a known value
    std::env::set_var("PATH", mock_op_path());
    std::env::set_var("MOCK_OP_RESPONSE", "refreshed-value");
    std::env::set_var("MOCK_OP_EXIT_CODE", "0");

    let resolver = SecretResolver::new(Duration::from_secs(0), Duration::from_secs(30));
    resolver.inject_cache("op://test/item/field", "old-value");

    // With TTL=0, cache is always expired, so it re-fetches via mock op
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "refreshed-value");
}

#[test]
fn test_cache_miss_fetches_from_op() {
    std::env::set_var("PATH", mock_op_path());
    std::env::set_var("MOCK_OP_RESPONSE", "fetched-secret");
    std::env::set_var("MOCK_OP_EXIT_CODE", "0");

    let resolver = SecretResolver::new(Duration::from_secs(300), Duration::from_secs(30));

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "fetched-secret");
}

#[test]
fn test_op_failure() {
    std::env::set_var("PATH", mock_op_path());
    std::env::set_var("MOCK_OP_RESPONSE", "");
    std::env::set_var("MOCK_OP_EXIT_CODE", "1");
    std::env::set_var("MOCK_OP_STDERR", "not signed in");

    let resolver = SecretResolver::new(Duration::from_secs(300), Duration::from_secs(30));

    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not signed in"), "error was: {err}");
}

#[test]
fn test_clear_cache() {
    std::env::set_var("PATH", mock_op_path());
    std::env::set_var("MOCK_OP_RESPONSE", "after-clear");
    std::env::set_var("MOCK_OP_EXIT_CODE", "0");

    let resolver = SecretResolver::new(Duration::from_secs(300), Duration::from_secs(30));
    resolver.inject_cache("op://test/item/field", "value");

    resolver.clear_cache();

    // Cache cleared, re-fetches via mock op
    let result = resolver.resolve("op://test/item/field");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "after-clear");
}

#[test]
fn test_invalid_uri() {
    let resolver = SecretResolver::new(Duration::from_secs(300), Duration::from_secs(30));
    let result = resolver.resolve("not-a-valid-uri");
    assert!(result.is_err());
}
