use secret_fuse::resolver::SecretResolver;
use secret_fuse::template::TemplateEngine;
use std::sync::Arc;
use std::time::Duration;

fn test_resolver() -> Arc<SecretResolver> {
    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
    ));
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
fn test_render_totoml_filter_escapes_control_chars() {
    let resolver = Arc::new(SecretResolver::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
    ));
    let raw = "line1\nline2\twith\ttabs and a \"quote\" and a \\backslash";
    resolver.inject_cache("op://Dev/multiline", raw);
    let engine = TemplateEngine::new(resolver);
    let result = engine
        .render_string("{{ op(\"op://Dev/multiline\") | totoml }}")
        .unwrap();

    let doc = format!("v = {result}\n");
    let parsed: toml::Table = toml::from_str(&doc).expect("totoml output must be valid TOML");
    assert_eq!(parsed["v"].as_str().unwrap(), raw);
}

#[test]
fn test_render_template_file() {
    let resolver = test_resolver();
    let engine = TemplateEngine::new(resolver);
    let result = engine
        .render_file(std::path::Path::new("fixtures/templates/test.env.tmpl"))
        .unwrap();
    assert_eq!(result, "DB_HOST=localhost\nDB_PASSWORD=s3cret");
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
