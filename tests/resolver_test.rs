use secret_fuse::resolver::SecretResolver;
use std::time::Duration;

#[test]
fn test_cache_hit() {
    let resolver = SecretResolver::new(Duration::from_secs(300));
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
