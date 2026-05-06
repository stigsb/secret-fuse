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

#[test]
fn test_root_dir_exists() {
    let fs = test_fs();
    assert!(fs.is_dir(1));
}

#[test]
fn test_lookup_top_level_file() {
    let fs = test_fs();
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
