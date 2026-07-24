//! Reliable single-stream resumable uploads.
//!
//! Protocol:
//!   POST /api/upload/init  { path, size } → { id, offset }
//!   PUT  /api/upload/:id   Header: X-FST-Offset: N  body=bytes → { offset }
//!   POST /api/upload/:id/complete → seals file (encrypt if needed)
//!   GET  /api/upload/:id   → { id, path, size, offset }
//!
//! State persisted under upload_state_dir so process restarts don't lose progress.

use crate::auth::{Role, Session};
use crate::config::Config;
use crate::crypto;
use crate::storage::Storage;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub id: String,
    pub virtual_path: String,
    pub size: u64,
    pub offset: u64,
    pub temp_path: PathBuf,
    pub created: u64,
    /// Last activity (init / chunk write). Used for idle supersede.
    #[serde(default)]
    pub updated: u64,
    /// Set whenever a logged-in user starts the upload. None only in open (no-auth) mode.
    pub owner: Option<String>,
}

pub struct TransferManager {
    state_dir: PathBuf,
    sessions: Mutex<HashMap<String, UploadSession>>,
    /// Virtual paths with an active incomplete upload (one at a time).
    path_locks: Mutex<HashSet<String>>,
    /// Paths currently being sealed by `complete` — not supersedeable.
    finalizing: Mutex<HashSet<String>>,
    ttl_secs: u64,
    buffer_size: usize,
    max_size: u64,
    max_concurrent: usize,
    max_per_user: usize,
    idle_supersede_secs: u64,
    encryption: bool,
    storage: Arc<Storage>,
}

/// Canonical virtual path for locks / conflict detection (matches Storage trimming).
fn normalize_virtual_path(path: &str) -> Result<String, String> {
    let p = path.trim().trim_start_matches('/');
    if p.is_empty() || p == "." {
        return Err("invalid upload path".into());
    }
    let mut parts = Vec::new();
    for seg in p.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err("illegal path component".into());
        }
        validate_path_segment(seg)?;
        parts.push(seg);
    }
    if parts.is_empty() {
        return Err("invalid upload path".into());
    }
    // Roots like `shared` / `~user` are directories — uploads need a filename segment.
    if parts.len() < 2 {
        return Err("upload path must include a filename".into());
    }
    if parts.len() > 64 {
        return Err("upload path too deep".into());
    }
    if let Some(name) = parts.last() {
        reject_reserved_name(name)?;
    }
    Ok(parts.join("/"))
}

fn validate_path_segment(seg: &str) -> Result<(), String> {
    if seg.chars().any(|c| {
        c.is_control() || c == '<' || c == '>' || c == '"' || c == '\0'
    }) {
        return Err("illegal character in path component".into());
    }
    Ok(())
}

fn reject_reserved_name(name: &str) -> Result<(), String> {
    const RESERVED: &[&str] = &[".fst-meta", ".fst-idx", ".sk", ".ek", ".part"];
    if RESERVED.iter().any(|s| name.ends_with(s)) {
        return Err("reserved filename suffix".into());
    }
    Ok(())
}

fn paths_match(a: &str, b: &str) -> bool {
    match (normalize_virtual_path(a), normalize_virtual_path(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

impl TransferManager {
    pub fn new(cfg: &Config, storage: Arc<Storage>) -> Self {
        let mut tm = Self {
            state_dir: cfg.paths.upload_state_dir.clone(),
            sessions: Mutex::new(HashMap::new()),
            path_locks: Mutex::new(HashSet::new()),
            finalizing: Mutex::new(HashSet::new()),
            ttl_secs: cfg.transfer.upload_ttl_secs,
            buffer_size: cfg.transfer.buffer_size,
            max_size: cfg.transfer.max_size,
            max_concurrent: cfg.transfer.max_concurrent,
            max_per_user: cfg.transfer.max_per_user,
            idle_supersede_secs: cfg.transfer.idle_supersede_secs,
            encryption: cfg.encryption.enabled,
            storage,
        };
        let _ = tm.reload();
        tm
    }

    fn reload(&mut self) -> Result<(), String> {
        let rd = std::fs::read_dir(&self.state_dir).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        let mut locks = HashSet::new();
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&p) {
                if let Ok(mut s) = serde_json::from_str::<UploadSession>(&raw) {
                    if let Ok(meta) = std::fs::metadata(&s.temp_path) {
                        s.offset = meta.len().min(s.size);
                    }
                    if s.updated == 0 {
                        s.updated = s.created;
                    }
                    if let Ok(norm) = normalize_virtual_path(&s.virtual_path) {
                        if norm != s.virtual_path {
                            s.virtual_path = norm;
                            let _ = Self::persist(&s, &self.state_dir);
                        }
                    } else {
                        tracing::warn!("dropping upload {} with bad path", s.id);
                        let _ = std::fs::remove_file(&s.temp_path);
                        let _ = std::fs::remove_file(&p);
                        continue;
                    }

                    // Encryption mode requires an owner. Infer from ~user/ or drop.
                    if self.encryption && s.owner.is_none() {
                        if let Some(rest) = s.virtual_path.strip_prefix('~') {
                            let user = rest.split('/').next().unwrap_or("");
                            if !user.is_empty() {
                                s.owner = Some(user.to_string());
                                let _ = Self::persist(&s, &self.state_dir);
                            } else {
                                let _ = std::fs::remove_file(&s.temp_path);
                                let _ = std::fs::remove_file(&p);
                                continue;
                            }
                        } else {
                            // shared/* (or other) without owner — invalidate
                            tracing::warn!(
                                "dropping upload {} missing owner under encryption",
                                s.id
                            );
                            let _ = std::fs::remove_file(&s.temp_path);
                            let _ = std::fs::remove_file(&p);
                            continue;
                        }
                    }

                    // Any persisted session still owns the path until complete()/gc().
                    // Include offset == size (bytes received, awaiting finalize).
                    locks.insert(s.virtual_path.clone());
                    map.insert(s.id.clone(), s);
                }
            }
        }
        *self.sessions.lock() = map;
        *self.path_locks.lock() = locks;
        Ok(())
    }

    fn persist(session: &UploadSession, state_dir: &Path) -> Result<(), String> {
        let p = state_dir.join(format!("{}.json", session.id));
        let raw = serde_json::to_string_pretty(session).map_err(|e| e.to_string())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, raw).map_err(|e| e.to_string())?;
        std::fs::rename(tmp, p).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn drop_session_locked(
        map: &mut HashMap<String, UploadSession>,
        locks: &mut HashSet<String>,
        state_dir: &Path,
        id: &str,
    ) {
        if let Some(s) = map.remove(id) {
            locks.remove(&s.virtual_path);
            let _ = std::fs::remove_file(&s.temp_path);
            let _ = std::fs::remove_file(state_dir.join(format!("{id}.json")));
        }
    }

    /// Whether an existing path session may be replaced by a new init.
    fn can_supersede(
        other: &UploadSession,
        owner: &Option<String>,
        is_admin: bool,
        now: u64,
        idle_secs: u64,
    ) -> bool {
        if is_admin {
            return true;
        }
        let last = if other.updated != 0 {
            other.updated
        } else {
            other.created
        };
        let idle = now.saturating_sub(last) >= idle_secs;

        // Named owner can always restart / change declared size.
        if other.owner.is_some() && other.owner == *owner {
            return true;
        }

        // Open mode (both None): same anonymous workspace may replace an
        // abandoned finalize immediately, but must wait for idle before
        // clobbering a mid-transfer partial.
        if other.owner.is_none() && owner.is_none() {
            return other.offset == other.size || idle;
        }

        // Different named owners / peer vs named: abandoned finalize after idle only.
        // Mid-transfer partials stay with the owner until TTL/gc or an admin.
        // `updated` is refreshed on resume and complete so active work isn't idle.
        other.offset == other.size && idle
    }

    /// Owner may touch an upload. Open-mode (encryption off) allows anyone when owner is None.
    /// Under encryption, a missing owner is always rejected.
    pub fn authorize(&self, sess: &UploadSession, session: Option<&Session>) -> Result<(), String> {
        if self.encryption {
            let owner = sess
                .owner
                .as_deref()
                .ok_or("upload missing owner — restart upload")?;
            let s = session.ok_or("unauthorized")?;
            if owner == s.username {
                Ok(())
            } else {
                Err("forbidden: not upload owner".into())
            }
        } else {
            match (&sess.owner, session) {
                (None, _) => Ok(()),
                (Some(_), None) => Err("unauthorized".into()),
                (Some(owner), Some(s)) => {
                    if owner == &s.username {
                        Ok(())
                    } else {
                        Err("forbidden: not upload owner".into())
                    }
                }
            }
        }
    }

    pub fn init(
        &self,
        virtual_path: &str,
        size: u64,
        session: Option<&Session>,
    ) -> Result<UploadSession, String> {
        if size == 0 {
            return Err("size must be > 0".into());
        }
        if size > self.max_size {
            return Err(format!(
                "file too large: max {} bytes (got {size})",
                self.max_size
            ));
        }
        if self.encryption && session.is_none() {
            return Err("unauthorized".into());
        }

        let virtual_path = normalize_virtual_path(virtual_path)?;

        // Validate destination is writable under sandbox before reserving disk.
        let _dest = self.storage.resolve(&virtual_path, session)?;

        if let Some(parent) = virtual_path.rsplit_once('/').map(|(p, _)| p) {
            if !parent.is_empty() {
                let _ = self.storage.mkdir(parent, session);
            }
        }

        let owner = session.map(|s| s.username.clone());
        let is_admin = session.map(|s| s.role == Role::Admin).unwrap_or(false);
        let now = Self::now();

        // Hold locks for check + reserve so concurrent inits cannot race.
        // Lock order: sessions → path_locks → finalizing
        let mut map = self.sessions.lock();
        let mut locks = self.path_locks.lock();
        let fin = self.finalizing.lock();

        // Resume same owner/path/size — including fully received / finalizing.
        // Refresh activity so a resume is not treated as an abandoned finalize.
        if let Some(id) = map
            .values()
            .find(|s| {
                paths_match(&s.virtual_path, &virtual_path) && s.size == size && s.owner == owner
            })
            .map(|s| s.id.clone())
        {
            let sess = map.get_mut(&id).unwrap();
            sess.updated = now;
            let _ = Self::persist(sess, &self.state_dir);
            return Ok(sess.clone());
        }

        if fin.contains(&virtual_path) {
            return Err("upload already in progress for this path".into());
        }

        // Path held — supersede when same owner, admin, or idle past idle_supersede_secs.
        let conflict_id = map
            .values()
            .find(|s| paths_match(&s.virtual_path, &virtual_path))
            .map(|s| s.id.clone());
        if let Some(cid) = conflict_id {
            let other = map.get(&cid).cloned().unwrap();
            if Self::can_supersede(&other, &owner, is_admin, now, self.idle_supersede_secs) {
                Self::drop_session_locked(&mut map, &mut locks, &self.state_dir, &cid);
            } else {
                return Err("upload already in progress for this path".into());
            }
        } else if locks.contains(&virtual_path) {
            // Orphan lock (no session, not finalizing) — clear it.
            locks.remove(&virtual_path);
        }
        drop(fin);

        if map.len() >= self.max_concurrent {
            return Err(format!(
                "too many concurrent uploads (max {})",
                self.max_concurrent
            ));
        }
        if let Some(ref o) = owner {
            let mine = map.values().filter(|s| s.owner.as_deref() == Some(o)).count();
            if mine >= self.max_per_user {
                return Err(format!(
                    "too many concurrent uploads for user (max {})",
                    self.max_per_user
                ));
            }
        }

        let id = Uuid::new_v4().to_string();
        let temp_path = self.state_dir.join(format!("{id}.part"));
        let us = UploadSession {
            id: id.clone(),
            virtual_path: virtual_path.clone(),
            size,
            offset: 0,
            temp_path: temp_path.clone(),
            created: now,
            updated: now,
            owner,
        };

        // Reserve path + session before releasing locks / doing IO.
        locks.insert(us.virtual_path.clone());
        map.insert(id.clone(), us.clone());
        drop(locks);
        drop(map);

        if let Err(e) = (|| -> Result<(), String> {
            let f = std::fs::File::create(&temp_path).map_err(|e| e.to_string())?;
            f.set_len(size).map_err(|e| e.to_string())?;
            Self::persist(&us, &self.state_dir)?;
            Ok(())
        })() {
            // Roll back reservation on IO failure.
            let mut map = self.sessions.lock();
            let mut locks = self.path_locks.lock();
            map.remove(&id);
            locks.remove(&virtual_path);
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }

        Ok(us)
    }

    pub fn status(
        &self,
        id: &str,
        session: Option<&Session>,
    ) -> Result<UploadSession, String> {
        let sess = self
            .sessions
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| "unknown upload".to_string())?;
        self.authorize(&sess, session)?;
        Ok(sess)
    }

    pub fn write_chunk(
        &self,
        id: &str,
        offset: u64,
        mut body: impl Read,
        session: Option<&Session>,
    ) -> Result<UploadSession, String> {
        let mut map = self.sessions.lock();
        let sess = map.get_mut(id).ok_or("unknown upload")?;
        self.authorize(sess, session)?;
        if self.finalizing.lock().contains(&sess.virtual_path) {
            return Err("upload already finalizing".into());
        }
        if offset != sess.offset {
            return Err(format!(
                "offset mismatch: client={offset} server={}",
                sess.offset
            ));
        }
        if sess.offset >= sess.size {
            return Err("upload already complete".into());
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&sess.temp_path)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;

        let mut buf = vec![0u8; self.buffer_size.min(8 * 1024 * 1024)];
        let remaining = sess.size - sess.offset;
        let mut written: u64 = 0;
        while written < remaining {
            let want = ((remaining - written) as usize).min(buf.len());
            let n = body.read(&mut buf[..want]).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            written += n as u64;
        }
        file.flush().map_err(|e| e.to_string())?;
        let _ = file.sync_data();

        sess.offset += written;
        sess.updated = Self::now();
        Self::persist(sess, &self.state_dir)?;
        Ok(sess.clone())
    }

    pub fn complete(
        &self,
        id: &str,
        session: Option<&Session>,
        auth: &crate::auth::AuthState,
    ) -> Result<String, String> {
        // Claim finalize under lock; bump `updated` so idle peer-supersede
        // cannot drop the temp while the owner is actively retrying complete.
        let sess = {
            let mut map = self.sessions.lock();
            let mut locks = self.path_locks.lock();
            let mut fin = self.finalizing.lock();
            let sess = map.get_mut(id).ok_or("unknown upload")?;
            self.authorize(sess, session)?;
            if sess.offset != sess.size {
                return Err(format!(
                    "incomplete: {} / {} bytes",
                    sess.offset, sess.size
                ));
            }
            if fin.contains(&sess.virtual_path) {
                return Err("upload already finalizing".into());
            }
            sess.updated = Self::now();
            Self::persist(sess, &self.state_dir)?;
            locks.insert(sess.virtual_path.clone());
            fin.insert(sess.virtual_path.clone());
            sess.clone()
        };

        let path = sess.virtual_path.clone();
        let result = (|| -> Result<(), String> {
            let dest = self.storage.resolve(&sess.virtual_path, session)?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }

            if self.encryption {
                let key_user = if sess.virtual_path.starts_with("shared/")
                    || sess.virtual_path == "shared"
                {
                    "shared".to_string()
                } else if let Some(rest) = sess.virtual_path.strip_prefix('~') {
                    rest.split('/').next().unwrap_or("").to_string()
                } else {
                    session
                        .map(|s| s.username.clone())
                        .or(sess.owner.clone())
                        .ok_or("encryption requires session")?
                };
                if key_user.is_empty() {
                    return Err("cannot determine encryption principal".into());
                }
                let ek = auth.user_ek(&key_user)?;
                let secondary = if key_user != "shared" {
                    auth.user_ek("shared").ok()
                } else {
                    None
                };
                crypto::seal_uploaded_file(
                    &sess.temp_path,
                    &dest,
                    &ek,
                    secondary.as_deref(),
                    sess.size,
                )
                .map_err(|e| e.to_string())?;
                let _ = std::fs::remove_file(&sess.temp_path);
            } else {
                std::fs::rename(&sess.temp_path, &dest).map_err(|e| e.to_string())?;
            }
            Ok(())
        })();

        {
            let mut map = self.sessions.lock();
            let mut locks = self.path_locks.lock();
            let mut fin = self.finalizing.lock();
            fin.remove(&path);
            match &result {
                Ok(()) => {
                    map.remove(&sess.id);
                    locks.remove(&path);
                    let _ = std::fs::remove_file(self.state_dir.join(format!("{}.json", sess.id)));
                }
                Err(_) => {
                    // Keep path lock; refresh activity so retries aren't idle-superseded.
                    locks.insert(path.clone());
                    if let Some(s) = map.get_mut(&sess.id) {
                        s.updated = Self::now();
                        let _ = Self::persist(s, &self.state_dir);
                    }
                }
            }
        }

        result.map(|_| path)
    }

    pub fn gc(&self) {
        let now = Self::now();
        let mut map = self.sessions.lock();
        let mut locks = self.path_locks.lock();
        let fin = self.finalizing.lock();
        let expired: Vec<String> = map
            .iter()
            .filter(|(_, s)| {
                if fin.contains(&s.virtual_path) {
                    return false;
                }
                // Expire from last activity, not creation — active chunked
                // uploads must survive beyond upload_ttl_secs.
                let last = if s.updated != 0 { s.updated } else { s.created };
                now.saturating_sub(last) > self.ttl_secs
            })
            .map(|(k, _)| k.clone())
            .collect();
        drop(fin);
        for id in expired {
            if let Some(s) = map.remove(&id) {
                locks.remove(&s.virtual_path);
                let _ = std::fs::remove_file(&s.temp_path);
                let _ = std::fs::remove_file(self.state_dir.join(format!("{id}.json")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;

    fn test_cfg(dir: &Path) -> Config {
        let raw = format!(
            r#"
[server]
bind = "127.0.0.1:0"
workers = 1
data_dir = "{0}"
[paths]
shared_root = "{0}/shared"
users_root = "{0}/users"
upload_state_dir = "{0}/uploads"
[encryption]
enabled = false
[transfer]
buffer_size = 1024
large_threshold = 1024
upload_ttl_secs = 3600
max_size = 1048576
max_concurrent = 4
max_per_user = 4
idle_supersede_secs = 300
[media]
ffmpeg = ""
ffprobe = ""
cache_dir = "{0}/media"
"#,
            dir.display()
        );
        toml::from_str(&raw).unwrap()
    }

    #[test]
    fn reload_locks_fully_received_uploads() {
        let dir = std::env::temp_dir().join(format!("fst-reload-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let cfg = test_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let id = Uuid::new_v4().to_string();
        let temp = dir.join("uploads").join(format!("{id}.part"));
        fs::write(&temp, vec![0u8; 8]).unwrap();
        let sess = UploadSession {
            id: id.clone(),
            virtual_path: "shared/full.bin".into(),
            size: 8,
            offset: 8, // fully received, awaiting complete
            temp_path: temp,
            created: TransferManager::now(),
            updated: TransferManager::now(),
            owner: None,
        };
        TransferManager::persist(&sess, &dir.join("uploads")).unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        assert!(
            tm.path_locks.lock().contains("shared/full.bin"),
            "fully received upload must retain path lock after reload"
        );
        // Same size resumes existing
        let resumed = tm.init("shared/full.bin", 8, None).unwrap();
        assert_eq!(resumed.id, id);
        assert_eq!(resumed.offset, 8);
        // Same owner (open mode) may supersede with a different size
        let replaced = tm.init("shared/full.bin", 16, None).unwrap();
        assert_ne!(replaced.id, id);
        assert_eq!(replaced.size, 16);
        assert_eq!(replaced.offset, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandoned_finalize_superseded_after_idle() {
        let dir = std::env::temp_dir().join(format!("fst-idle-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.idle_supersede_secs = 1;
        cfg.ensure_dirs().unwrap();

        let id = Uuid::new_v4().to_string();
        let temp = dir.join("uploads").join(format!("{id}.part"));
        fs::write(&temp, vec![0u8; 4]).unwrap();
        let past = TransferManager::now().saturating_sub(10);
        let sess = UploadSession {
            id: id.clone(),
            virtual_path: "shared/stale.bin".into(),
            size: 4,
            offset: 4,
            temp_path: temp,
            created: past,
            updated: past,
            owner: Some("alice".into()),
        };
        TransferManager::persist(&sess, &dir.join("uploads")).unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        // Different owner, but abandoned finalize → supersede
        // Open mode: pass None owner — wait, encryption off so owner Some("alice") vs None
        // can_supersede: other.owner != owner (Some(alice) != None), age >= idle, offset==size → true
        let new = tm.init("shared/stale.bin", 4, None).unwrap();
        assert_ne!(new.id, id);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_finalize_activity_blocks_peer_supersede() {
        let dir = std::env::temp_dir().join(format!("fst-fin-act-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.idle_supersede_secs = 1;
        cfg.ensure_dirs().unwrap();

        let id = Uuid::new_v4().to_string();
        let temp = dir.join("uploads").join(format!("{id}.part"));
        fs::write(&temp, vec![0u8; 4]).unwrap();
        let now = TransferManager::now();
        let sess = UploadSession {
            id: id.clone(),
            virtual_path: "shared/retry.bin".into(),
            size: 4,
            offset: 4,
            temp_path: temp,
            created: now.saturating_sub(60),
            // Simulate a recent complete attempt refreshing activity.
            updated: now,
            owner: Some("alice".into()),
        };
        TransferManager::persist(&sess, &dir.join("uploads")).unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        let err = tm.init("shared/retry.bin", 4, None).unwrap_err();
        assert!(err.contains("already in progress"), "{err}");
        assert!(tm.sessions.lock().contains_key(&id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_refreshes_updated() {
        let dir = std::env::temp_dir().join(format!("fst-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.idle_supersede_secs = 1;
        cfg.ensure_dirs().unwrap();

        let id = Uuid::new_v4().to_string();
        let temp = dir.join("uploads").join(format!("{id}.part"));
        fs::write(&temp, vec![0u8; 4]).unwrap();
        let past = TransferManager::now().saturating_sub(60);
        let sess = UploadSession {
            id: id.clone(),
            virtual_path: "shared/resume.bin".into(),
            size: 4,
            offset: 4,
            temp_path: temp,
            created: past,
            updated: past,
            owner: None,
        };
        TransferManager::persist(&sess, &dir.join("uploads")).unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        let resumed = tm.init("shared/resume.bin", 4, None).unwrap();
        assert_eq!(resumed.id, id);
        assert!(resumed.updated > past);
        // Peer-equivalent init still resumes (same owner None) rather than superseding.
        let again = tm.init("shared/resume.bin", 4, None).unwrap();
        assert_eq!(again.id, id);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_mode_does_not_clobber_active_partial() {
        let dir = std::env::temp_dir().join(format!("fst-open-partial-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.idle_supersede_secs = 300;
        cfg.ensure_dirs().unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        let first = tm.init("shared/partial.bin", 100, None).unwrap();
        assert_eq!(first.offset, 0);
        // Second init same path/different size must not wipe an active partial.
        let err = tm.init("shared/partial.bin", 200, None).unwrap_err();
        assert!(err.contains("already in progress"), "{err}");
        assert!(tm.sessions.lock().contains_key(&first.id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_directory_only_upload_paths() {
        assert!(normalize_virtual_path("shared").is_err());
        assert!(normalize_virtual_path("~alice").is_err());
        assert!(normalize_virtual_path("/shared/").is_err());
        assert!(normalize_virtual_path("shared/file.bin").is_ok());
        assert!(normalize_virtual_path("~alice/file.bin").is_ok());
    }

    #[test]
    fn rejects_unsafe_and_reserved_upload_paths() {
        assert!(normalize_virtual_path(r#"shared/"><img>/x.txt"#).is_err());
        assert!(normalize_virtual_path("shared/a<b>/x.txt").is_err());
        assert!(normalize_virtual_path("shared/my..notes/readme.txt").is_ok());
        assert!(normalize_virtual_path("shared/secret.sk").is_err());
        assert!(normalize_virtual_path("shared/nested/file.fst-meta").is_err());
        assert!(normalize_virtual_path("shared/a/./b/c.txt").is_ok());
    }

    #[test]
    fn path_normalization_unifies_locks() {
        let dir = std::env::temp_dir().join(format!("fst-norm-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let cfg = test_cfg(&dir);
        cfg.ensure_dirs().unwrap();
        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);

        let a = tm.init("/shared/foo.bin", 10, None).unwrap();
        assert_eq!(a.virtual_path, "shared/foo.bin");
        // Equivalent path resumes same session
        let b = tm.init("shared/foo.bin", 10, None).unwrap();
        assert_eq!(a.id, b.id);
        // Whitespace + leading slash still same path
        let c = tm.init("  /shared/foo.bin  ", 10, None).unwrap();
        assert_eq!(a.id, c.id);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_partial_not_superseded_by_peer() {
        let dir = std::env::temp_dir().join(format!("fst-partial-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.idle_supersede_secs = 1;
        cfg.ensure_dirs().unwrap();

        let id = Uuid::new_v4().to_string();
        let temp = dir.join("uploads").join(format!("{id}.part"));
        fs::write(&temp, vec![0u8; 2]).unwrap();
        let past = TransferManager::now().saturating_sub(10);
        let sess = UploadSession {
            id: id.clone(),
            virtual_path: "shared/partial.bin".into(),
            size: 100,
            offset: 2, // mid-transfer
            temp_path: temp,
            created: past,
            updated: past,
            owner: Some("alice".into()),
        };
        TransferManager::persist(&sess, &dir.join("uploads")).unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        // Peer (no session / different owner) must not take over mid-transfer.
        let err = tm.init("shared/partial.bin", 100, None).unwrap_err();
        assert!(err.contains("already in progress"), "{err}");
        assert!(tm.sessions.lock().contains_key(&id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_uses_updated_not_created() {
        let dir = std::env::temp_dir().join(format!("fst-gc-{}", Uuid::new_v4()));
        fs::create_dir_all(dir.join("uploads")).unwrap();
        fs::create_dir_all(dir.join("shared")).unwrap();
        fs::create_dir_all(dir.join("users")).unwrap();
        let mut cfg = test_cfg(&dir);
        cfg.transfer.upload_ttl_secs = 5;
        cfg.ensure_dirs().unwrap();

        let now = TransferManager::now();
        let old = now.saturating_sub(60);

        // Long-lived but recently active — must survive gc.
        let alive_id = Uuid::new_v4().to_string();
        let alive_temp = dir.join("uploads").join(format!("{alive_id}.part"));
        fs::write(&alive_temp, vec![0u8; 4]).unwrap();
        TransferManager::persist(
            &UploadSession {
                id: alive_id.clone(),
                virtual_path: "shared/alive.bin".into(),
                size: 100,
                offset: 4,
                temp_path: alive_temp,
                created: old,
                updated: now,
                owner: None,
            },
            &dir.join("uploads"),
        )
        .unwrap();

        // Idle past TTL — must be collected.
        let dead_id = Uuid::new_v4().to_string();
        let dead_temp = dir.join("uploads").join(format!("{dead_id}.part"));
        fs::write(&dead_temp, vec![0u8; 2]).unwrap();
        TransferManager::persist(
            &UploadSession {
                id: dead_id.clone(),
                virtual_path: "shared/dead.bin".into(),
                size: 100,
                offset: 2,
                temp_path: dead_temp.clone(),
                created: old,
                updated: old,
                owner: None,
            },
            &dir.join("uploads"),
        )
        .unwrap();

        let storage = Arc::new(Storage::new(&cfg));
        let tm = TransferManager::new(&cfg, storage);
        tm.gc();

        assert!(tm.sessions.lock().contains_key(&alive_id));
        assert!(!tm.sessions.lock().contains_key(&dead_id));
        assert!(!dead_temp.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
