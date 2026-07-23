//! Path resolution: shared root + per-user roots, traversal-safe.

use crate::auth::{Role, Session};
use crate::config::Config;
use serde::Serialize;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String, // virtual path e.g. shared/foo or ~alice/bar
    pub is_dir: bool,
    pub size: u64,
    pub modified: i64,
    pub kind: String, // folder | image | video | audio | file
}

pub struct Storage {
    shared: PathBuf,
    users: PathBuf,
    encryption: bool,
}

impl Storage {
    pub fn new(cfg: &Config) -> Self {
        Self {
            shared: cfg.paths.shared_root.clone(),
            users: cfg.paths.users_root.clone(),
            encryption: cfg.encryption.enabled,
        }
    }

    /// Resolve a virtual path to an absolute filesystem path.
    /// Virtual forms:
    ///   shared/...     → shared_root/...
    ///   ~user/...      → users_root/user/...
    ///   (empty / ".")  → listing roots depends on session
    pub fn resolve(
        &self,
        virtual_path: &str,
        session: Option<&Session>,
    ) -> Result<PathBuf, String> {
        let vp = virtual_path.trim().trim_start_matches('/');
        if vp.is_empty() || vp == "." {
            return Err("cannot resolve root listing as file path".into());
        }

        let (root, rest) = if let Some(rest) = vp.strip_prefix("shared/") {
            (self.shared.clone(), rest)
        } else if vp == "shared" {
            return Ok(self.shared.clone());
        } else if let Some(rest) = vp.strip_prefix('~') {
            let (user, rem) = match rest.split_once('/') {
                Some((u, r)) => (u, r),
                None => (rest, ""),
            };
            if user.is_empty() {
                return Err("bad user path".into());
            }
            // Authorization
            if self.encryption {
                let sess = session.ok_or("unauthorized")?;
                if sess.role != Role::Admin && sess.username != user {
                    return Err("forbidden".into());
                }
            }
            let root = self.users.join(user);
            if rem.is_empty() {
                return Ok(root);
            }
            (root, rem)
        } else {
            return Err("path must start with shared/ or ~username/".into());
        };

        let safe = sanitize_rel(rest)?;
        let full = root.join(&safe);
        // Ensure still under root
        let full_c = full.canonicalize().unwrap_or(full.clone());
        let root_c = root.canonicalize().unwrap_or(root.clone());
        if !full_c.starts_with(&root_c) && full.exists() {
            return Err("path escape denied".into());
        }
        Ok(full)
    }

    pub fn list(
        &self,
        virtual_path: &str,
        session: Option<&Session>,
    ) -> Result<Vec<DirEntry>, String> {
        let vp = virtual_path.trim().trim_start_matches('/');

        // Top-level virtual roots
        if vp.is_empty() || vp == "." {
            return self.list_roots(session);
        }

        let dir = self.resolve(vp, session)?;
        if !dir.is_dir() {
            return Err("not a directory".into());
        }

        let mut out = Vec::new();
        let rd = std::fs::read_dir(&dir).map_err(|e| e.to_string())?;
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            // Hide internal sidecars
            if name.ends_with(".fst-meta")
                || name.ends_with(".fst-idx")
                || name.ends_with(".sk")
                || name.ends_with(".ek")
                || name.ends_with(".part")
                || name.starts_with('.')
            {
                continue;
            }
            let meta = ent.metadata().map_err(|e| e.to_string())?;
            let is_dir = meta.is_dir();
            let size = if is_dir {
                0
            } else if self.encryption {
                crate::crypto::read_plain_size_meta(&ent.path()).unwrap_or(meta.len())
            } else {
                meta.len()
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let kind = if is_dir {
                "folder".into()
            } else {
                classify(&name)
            };
            let child_vp = if vp.ends_with('/') {
                format!("{vp}{name}")
            } else {
                format!("{vp}/{name}")
            };
            out.push(DirEntry {
                name,
                path: child_vp,
                is_dir,
                size,
                modified,
                kind,
            });
        }
        out.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        });
        Ok(out)
    }

    fn list_roots(&self, session: Option<&Session>) -> Result<Vec<DirEntry>, String> {
        let mut out = Vec::new();
        out.push(DirEntry {
            name: "shared".into(),
            path: "shared".into(),
            is_dir: true,
            size: 0,
            modified: 0,
            kind: "folder".into(),
        });

        if let Some(s) = session {
            if s.role == Role::Admin {
                if let Ok(rd) = std::fs::read_dir(&self.users) {
                    for ent in rd.flatten() {
                        if ent.path().is_dir() {
                            let name = ent.file_name().to_string_lossy().to_string();
                            out.push(DirEntry {
                                name: format!("~{name}"),
                                path: format!("~{name}"),
                                is_dir: true,
                                size: 0,
                                modified: 0,
                                kind: "folder".into(),
                            });
                        }
                    }
                }
            } else {
                out.push(DirEntry {
                    name: format!("~{}", s.username),
                    path: format!("~{}", s.username),
                    is_dir: true,
                    size: 0,
                    modified: 0,
                    kind: "folder".into(),
                });
            }
        } else if !self.encryption {
            // No auth: expose shared + all user dirs
            if let Ok(rd) = std::fs::read_dir(&self.users) {
                for ent in rd.flatten() {
                    if ent.path().is_dir() {
                        let name = ent.file_name().to_string_lossy().to_string();
                        out.push(DirEntry {
                            name: format!("~{name}"),
                            path: format!("~{name}"),
                            is_dir: true,
                            size: 0,
                            modified: 0,
                            kind: "folder".into(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn mkdir(&self, virtual_path: &str, session: Option<&Session>) -> Result<(), String> {
        let p = self.resolve(virtual_path, session)?;
        std::fs::create_dir_all(p).map_err(|e| e.to_string())
    }

    pub fn delete(&self, virtual_path: &str, session: Option<&Session>) -> Result<(), String> {
        let p = self.resolve(virtual_path, session)?;
        if p.is_dir() {
            std::fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(&p).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(format!("{}.fst-meta", p.display()));
        }
        Ok(())
    }
}

fn sanitize_rel(rel: &str) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return Err("illegal path component".into()),
        }
    }
    Ok(out)
}

pub fn classify(name: &str) -> String {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "heif" | "avif" | "bmp" | "tif"
        | "tiff" => "image".into(),
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "m4v" | "ts" | "m2ts" | "wmv" | "flv" | "ogv" => {
            "video".into()
        }
        "mp3" | "flac" | "wav" | "aac" | "m4a" | "ogg" | "opus" | "aiff" | "alac" | "wma" => {
            "audio".into()
        }
        _ => "file".into(),
    }
}
