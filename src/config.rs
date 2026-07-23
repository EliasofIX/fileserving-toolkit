//! FST configuration — loaded once at boot, shared as Arc.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub paths: PathsConfig,
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
    #[serde(default)]
    pub media: MediaConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    pub data_dir: PathBuf,
}

fn default_workers() -> usize {
    2
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathsConfig {
    pub shared_root: PathBuf,
    pub users_root: PathBuf,
    pub upload_state_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserConfig {
    pub username: String,
    pub password_hash: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "user".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl(),
        }
    }
}

fn default_ttl() -> u64 {
    604_800
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransferConfig {
    #[serde(default = "default_buffer")]
    pub buffer_size: usize,
    #[serde(default = "default_large")]
    pub large_threshold: u64,
    #[serde(default = "default_upload_ttl")]
    pub upload_ttl_secs: u64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            buffer_size: default_buffer(),
            large_threshold: default_large(),
            upload_ttl_secs: default_upload_ttl(),
        }
    }
}

fn default_buffer() -> usize {
    8 * 1024 * 1024
}
fn default_large() -> u64 {
    100 * 1024 * 1024
}
fn default_upload_ttl() -> u64 {
    604_800
}

#[derive(Debug, Clone, Deserialize)]
pub struct MediaConfig {
    #[serde(default = "default_ffmpeg")]
    pub ffmpeg: String,
    #[serde(default = "default_ffprobe")]
    pub ffprobe: String,
    #[serde(default)]
    pub cache_dir: PathBuf,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            ffmpeg: default_ffmpeg(),
            ffprobe: default_ffprobe(),
            cache_dir: PathBuf::from("./data/media-cache"),
        }
    }
}

fn default_ffmpeg() -> String {
    "ffmpeg".into()
}
fn default_ffprobe() -> String {
    "ffprobe".into()
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw)?;
        Ok(cfg)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.server.data_dir)?;
        std::fs::create_dir_all(&self.paths.shared_root)?;
        std::fs::create_dir_all(&self.paths.users_root)?;
        std::fs::create_dir_all(&self.paths.upload_state_dir)?;
        if !self.media.cache_dir.as_os_str().is_empty() {
            std::fs::create_dir_all(&self.media.cache_dir)?;
        }
        // Ensure per-user dirs exist for configured users
        for u in &self.auth.users {
            let p = self.paths.users_root.join(&u.username);
            std::fs::create_dir_all(&p)?;
        }
        Ok(())
    }
}
