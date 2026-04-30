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

        let resolver = Arc::clone(&self.resolver);
        env.add_function("op", move |uri: String| -> Result<String, JinjaError> {
            resolver.resolve(&uri).map_err(|e| {
                JinjaError::new(ErrorKind::InvalidOperation, format!("op() failed: {e}"))
            })
        });

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

    pub fn validate_syntax(&self, template: &str) -> Result<(), TemplateError> {
        let mut env = Environment::new();
        env.add_function("op", |_uri: String| -> Result<String, JinjaError> {
            Ok(String::new())
        });
        env.add_filter("tojson", tojson_filter);
        env.add_filter("base64encode", base64encode_filter);
        env.add_filter("totoml", totoml_filter);
        env.add_template_owned("validate".to_string(), template.to_string())?;
        Ok(())
    }
}

fn tojson_filter(value: String) -> Result<Value, JinjaError> {
    let json = serde_json::to_string(&value)
        .map_err(|e| JinjaError::new(ErrorKind::InvalidOperation, e.to_string()))?;
    Ok(Value::from(json))
}

fn base64encode_filter(value: String) -> Result<Value, JinjaError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    Ok(Value::from(encoded))
}

fn totoml_filter(value: String) -> Result<Value, JinjaError> {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(Value::from(format!("\"{escaped}\"")))
}
