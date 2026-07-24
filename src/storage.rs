//! Path resolution: shared root + per-user roots, traversal-safe.
//! Rejects `..`, absolute escapes, and symlink components under the root.

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
            let root = ensure_canonical_dir(&self.shared)?;
            return Ok(root);
        } else if let Some(rest) = vp.strip_prefix('~') {
            let (user, rem) = match rest.split_once('/') {
                Some((u, r)) => (u, r),
                None => (rest, ""),
            };
            if user.is_empty() || user.contains("..") || user.contains('/') {
                return Err("bad user path".into());
            }
            if self.encryption {
                let sess = session.ok_or("unauthorized")?;
                if sess.role != Role::Admin && sess.username != user {
                    return Err("forbidden".into());
                }
            }
            let root = self.users.join(user);
            if rem.is_empty() {
                return ensure_canonical_dir(&root);
            }
            (root, rem)
        } else {
            return Err("path must start with shared/ or ~username/".into());
        };

        let safe = sanitize_rel(rest)?;
        resolve_under_root(&root, &safe)
    }

    pub fn list(
        &self,
        virtual_path: &str,
        session: Option<&Session>,
    ) -> Result<Vec<DirEntry>, String> {
        let vp = virtual_path.trim().trim_start_matches('/');

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
            if name.ends_with(".fst-meta")
                || name.ends_with(".fst-idx")
                || name.ends_with(".sk")
                || name.ends_with(".ek")
                || name.ends_with(".part")
                || name.starts_with('.')
            {
                continue;
            }
            // Skip symlink entries in listings
            if ent
                .file_type()
                .map(|t| t.is_symlink())
                .unwrap_or(false)
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
                        if ent.path().is_dir()
                            && !ent.file_type().map(|t| t.is_symlink()).unwrap_or(true)
                        {
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
            if let Ok(rd) = std::fs::read_dir(&self.users) {
                for ent in rd.flatten() {
                    if ent.path().is_dir()
                        && !ent.file_type().map(|t| t.is_symlink()).unwrap_or(true)
                    {
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
        let meta = std::fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("symlink denied".into());
        }
        if meta.is_dir() {
            std::fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(&p).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(format!("{}.fst-meta", p.display()));
            let _ = std::fs::remove_file(format!("{}.fst-idx", p.display()));
        }
        Ok(())
    }
}

fn ensure_canonical_dir(root: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("root must not be a symlink".into());
    }
    root.canonicalize().map_err(|e| e.to_string())
}

/// Walk `rel` under `root`, rejecting symlink components. Works for not-yet-created leaves.
fn resolve_under_root(root: &Path, rel: &Path) -> Result<PathBuf, String> {
    let root_c = ensure_canonical_dir(root)?;
    let comps: Vec<_> = rel.components().collect();
    if comps.is_empty() {
        return Ok(root_c);
    }

    let mut cur = root_c.clone();
    for (i, comp) in comps.iter().enumerate() {
        let Component::Normal(name) = comp else {
            return Err("illegal path component".into());
        };
        let next = cur.join(name);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err("symlink denied".into());
                }
                if i + 1 == comps.len() {
                    // Final existing component — canonicalize and contain.
                    let c = next.canonicalize().map_err(|e| e.to_string())?;
                    if !c.starts_with(&root_c) {
                        return Err("path escape denied".into());
                    }
                    return Ok(c);
                }
                if !meta.is_dir() {
                    return Err("not a directory".into());
                }
                cur = next.canonicalize().map_err(|e| e.to_string())?;
                if !cur.starts_with(&root_c) {
                    return Err("path escape denied".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Parent `cur` is canonical and under root; append remaining names lexically.
                if !cur.starts_with(&root_c) {
                    return Err("path escape denied".into());
                }
                let mut out = cur;
                for c in &comps[i..] {
                    let Component::Normal(n) = c else {
                        return Err("illegal path component".into());
                    };
                    out.push(n);
                }
                return Ok(out);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(cur)
}

fn sanitize_rel(rel: &str) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => {
                let s = s.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." {
                    return Err("illegal path component".into());
                }
                if s.chars()
                    .any(|ch| ch.is_control() || ch == '<' || ch == '>' || ch == '"' || ch == '\0')
                {
                    return Err("illegal character in path component".into());
                }
                out.push(s.as_ref());
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_dotdot() {
        assert!(sanitize_rel("a/../b").is_err());
    }

    #[test]
    fn contains_new_leaf() {
        let dir = tempfile_dir();
        let p = resolve_under_root(&dir, Path::new("newfile.txt")).unwrap();
        assert!(p.starts_with(dir.canonicalize().unwrap()));
        assert!(p.ends_with("newfile.txt"));
    }

    #[test]
    fn rejects_symlink_component() {
        let dir = tempfile_dir();
        let outside = tempfile_dir();
        let link = dir.join("escape");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            let err = resolve_under_root(&dir, Path::new("escape/x")).unwrap_err();
            assert!(err.contains("symlink"));
        }
    }

    fn tempfile_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("fst-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
