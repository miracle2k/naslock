use anyhow::{Context, Result};
use directories::BaseDirs;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub keepass: KeepassConfig,
    pub nas: HashMap<String, NasConfig>,
    #[serde(alias = "volumes")]
    pub volume: HashMap<String, VolumeConfig>,
}

#[derive(Debug, Deserialize)]
pub struct KeepassConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Basic,
    #[serde(alias = "api-key")]
    ApiKey,
}

#[derive(Debug, Deserialize)]
pub struct NasConfig {
    pub host: String,
    pub auth_entry: String,
    #[serde(default = "default_auth_method")]
    pub auth_method: AuthMethod,
    #[serde(default = "default_username_field")]
    pub username_field: String,
    #[serde(default = "default_password_field")]
    pub password_field: String,
    #[serde(default)]
    pub skip_tls_verify: bool,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMode {
    Passphrase,
    #[serde(alias = "key-file")]
    Key,
}

#[derive(Debug, Deserialize)]
pub struct VolumeConfig {
    pub nas: String,
    pub dataset: String,
    pub unlock_entry: String,
    #[serde(default = "default_password_field")]
    pub unlock_field: String,
    #[serde(default = "default_unlock_mode")]
    pub unlock_mode: UnlockMode,
    #[serde(default = "default_recursive")]
    pub recursive: bool,
    #[serde(default)]
    pub force: bool,
    #[serde(default, alias = "force_umount", alias = "lock_force")]
    pub lock_force_umount: bool,
    #[serde(default = "default_toggle_attachments")]
    pub toggle_attachments: bool,
}

pub fn default_config_path() -> Result<PathBuf> {
    let base = BaseDirs::new().context("unable to determine home directory")?;
    Ok(base.config_dir().join("naslock").join("config.toml"))
}

pub fn expand_path(path: &Path, base_dir: Option<&Path>) -> PathBuf {
    let expanded = expand_tilde(path);
    if expanded.is_relative() {
        if let Some(base) = base_dir {
            return base.join(expanded);
        }
    }
    expanded
}

fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return path.to_path_buf(),
    };
    if path_str == "~" || path_str.starts_with("~/") {
        if let Some(base) = BaseDirs::new() {
            let mut home = base.home_dir().to_path_buf();
            if path_str.len() > 2 {
                home.push(&path_str[2..]);
            }
            return home;
        }
    }
    path.to_path_buf()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        let base_dir = path.parent();
        cfg.keepass.path = expand_path(&cfg.keepass.path, base_dir);
        if let Some(ref mut key_file) = cfg.keepass.key_file {
            *key_file = expand_path(key_file, base_dir);
        }
        Ok(cfg)
    }
}

fn default_auth_method() -> AuthMethod {
    AuthMethod::Basic
}

fn default_unlock_mode() -> UnlockMode {
    UnlockMode::Passphrase
}

fn default_username_field() -> String {
    "UserName".to_string()
}

fn default_password_field() -> String {
    "Password".to_string()
}

fn default_recursive() -> bool {
    true
}

fn default_toggle_attachments() -> bool {
    true
}
