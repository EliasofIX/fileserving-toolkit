//! Optional ffmpeg helpers — remux / probe only when configured.

use crate::config::MediaConfig;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

#[derive(Clone)]
pub struct Media {
    ffmpeg: String,
    ffprobe: String,
    cache: PathBuf,
    available: bool,
}

impl Media {
    pub async fn new(cfg: &MediaConfig) -> Self {
        let available = which_ok(&cfg.ffmpeg).await && which_ok(&cfg.ffprobe).await;
        if !cfg.cache_dir.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(&cfg.cache_dir);
        }
        Self {
            ffmpeg: cfg.ffmpeg.clone(),
            ffprobe: cfg.ffprobe.clone(),
            cache: cfg.cache_dir.clone(),
            available,
        }
    }

    pub fn available(&self) -> bool {
        self.available
    }

    /// Probe whether browser can likely play natively (h264/aac/mp4/webm heuristics).
    pub async fn needs_remux(&self, path: &Path) -> bool {
        if !self.available {
            return false;
        }
        let out = Command::new(&self.ffprobe)
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=codec_name",
                "-of",
                "default=nw=1:nk=1",
                path.to_str().unwrap_or(""),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await;
        match out {
            Ok(o) => {
                let codec = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
                !matches!(
                    codec.as_str(),
                    "h264" | "avc1" | "vp8" | "vp9" | "av1" | ""
                )
            }
            Err(_) => false,
        }
    }

    /// Remux to fragmented MP4 in cache (stream copy — no re-encode when possible).
    pub async fn remux_mp4(&self, src: &Path) -> Result<PathBuf, String> {
        if !self.available {
            return Err("ffmpeg not available".into());
        }
        let key = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(src.to_string_lossy().as_bytes());
            if let Ok(m) = std::fs::metadata(src) {
                h.update(m.len().to_le_bytes());
                if let Ok(t) = m.modified() {
                    if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                        h.update(d.as_secs().to_le_bytes());
                    }
                }
            }
            hex::encode(h.finalize())
        };
        let out = self.cache.join(format!("{key}.mp4"));
        if out.exists() {
            return Ok(out);
        }
        let tmp = self.cache.join(format!("{key}.tmp.mp4"));
        let status = Command::new(&self.ffmpeg)
            .args([
                "-y",
                "-i",
                src.to_str().unwrap_or(""),
                "-c",
                "copy",
                "-movflags",
                "frag_keyframe+empty_moov+faststart",
                tmp.to_str().unwrap_or(""),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| e.to_string())?;
        if !status.success() {
            // Fallback: light transcode video to h264
            let status2 = Command::new(&self.ffmpeg)
                .args([
                    "-y",
                    "-i",
                    src.to_str().unwrap_or(""),
                    "-c:v",
                    "libx264",
                    "-preset",
                    "veryfast",
                    "-crf",
                    "23",
                    "-c:a",
                    "aac",
                    "-movflags",
                    "frag_keyframe+empty_moov+faststart",
                    tmp.to_str().unwrap_or(""),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map_err(|e| e.to_string())?;
            if !status2.success() {
                return Err("ffmpeg remux/transcode failed".into());
            }
        }
        std::fs::rename(&tmp, &out).map_err(|e| e.to_string())?;
        Ok(out)
    }
}

async fn which_ok(bin: &str) -> bool {
    if bin.is_empty() {
        return false;
    }
    Command::new(bin)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}
