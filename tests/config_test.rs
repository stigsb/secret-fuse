use secret_fuse::config::{Config, FileSource};
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
    let yaml = "mountpoint: ~/secrets\nfiles:\n  test:\n    secret: op://v/i/f\n";
    let config = Config::from_str(yaml).unwrap();
    assert!(!config.mountpoint.to_string_lossy().contains('~'));
}
