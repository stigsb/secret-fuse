use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
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
    Content(String),
    Template(PathBuf),
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

    pub fn validate(&self) -> Result<(), ConfigError> {
        for (_name, entry) in &self.files {
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
