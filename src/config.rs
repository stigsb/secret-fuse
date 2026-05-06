use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Debug)]
pub struct Config {
    pub mountpoint: PathBuf,
    pub cache_ttl: u64,
    pub op_timeout: u64,
    pub auto_lock: AutoLockConfig,
    pub files: HashMap<String, FileEntry>,
}

#[derive(Debug)]
pub struct FileEntry {
    pub source: FileSource,
}

#[derive(Debug)]
pub enum FileSource {
    Content(String),
    Template(String),
    TemplateFile(PathBuf),
    Secret(String),
}

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

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error(
        "file entry '{0}' must have exactly one of: content, template, templateFile, or secret"
    )]
    InvalidEntry(String),
    #[error("template file not found: {0}")]
    TemplateNotFound(PathBuf),
}

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

fn default_cache_ttl() -> u64 {
    300
}

fn default_op_timeout() -> u64 {
    30
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFileEntry {
    content: Option<String>,
    template: Option<String>,
    template_file: Option<String>,
    secret: Option<String>,
}

impl Config {
    pub fn load(path: PathBuf) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(&path)?;
        let config_dir = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        Self::parse(&contents, &config_dir)
    }

    #[allow(dead_code, clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        Self::parse(s, Path::new(""))
    }

    fn parse(s: &str, config_dir: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_yaml::from_str(s)?;
        let mountpoint = expand_tilde(&raw.mountpoint);

        let mut files = HashMap::new();
        for (name, entry) in raw.files {
            let source = match (
                entry.content,
                entry.template,
                entry.template_file,
                entry.secret,
            ) {
                (Some(c), None, None, None) => FileSource::Content(c),
                (None, Some(t), None, None) => FileSource::Template(t),
                (None, None, Some(t), None) => {
                    let path = expand_tilde(&t);
                    let path = if path.is_relative() {
                        config_dir.join(path)
                    } else {
                        path
                    };
                    FileSource::TemplateFile(path)
                }
                (None, None, None, Some(s)) => FileSource::Secret(s),
                _ => return Err(ConfigError::InvalidEntry(name)),
            };
            files.insert(name, FileEntry { source });
        }

        Ok(Config {
            mountpoint,
            cache_ttl: raw.cache_ttl,
            op_timeout: raw.op_timeout,
            auto_lock: raw.auto_lock,
            files,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for entry in self.files.values() {
            if let FileSource::TemplateFile(ref path) = entry.source
                && !path.exists()
            {
                return Err(ConfigError::TemplateNotFound(path.clone()));
            }
        }
        Ok(())
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}
