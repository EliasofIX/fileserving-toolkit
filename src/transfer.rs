//! Reliable single-stream resumable uploads.
//!
//! Protocol:
//!   POST /api/upload/init  { path, size } → { id, offset }
//!   PUT  /api/upload/:id   Header: X-FST-Offset: N  body=bytes → { offset }
//!   POST /api/upload/:id/complete → seals file (encrypt if needed)
//!   GET  /api/upload/:id   → { id, path, size, offset }
//!
//! State persisted under upload_state_dir so process restarts don't lose progress.

use crate::auth::Session;
use crate::config::Config;
use crate::crypto;
use crate::storage::Storage;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub owner: Option<String>,
}

pub struct TransferManager {
    state_dir: PathBuf,
    sessions: Mutex<HashMap<String, UploadSession>>,
    ttl_secs: u64,
    buffer_size: usize,
    encryption: bool,
    storage: Arc<Storage>,
}

impl TransferManager {
    pub fn new(cfg: &Config, storage: Arc<Storage>) -> Self {
        let mut tm = Self {
            state_dir: cfg.paths.upload_state_dir.clone(),
            sessions: Mutex::new(HashMap::new()),
            ttl_secs: cfg.transfer.upload_ttl_secs,
            buffer_size: cfg.transfer.buffer_size,
            encryption: cfg.encryption.enabled,
            storage,
        };
        let _ = tm.reload();
        tm
    }

    fn reload(&mut self) -> Result<(), String> {
        let rd = std::fs::read_dir(&self.state_dir).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&p) {
                if let Ok(mut s) = serde_json::from_str::<UploadSession>(&raw) {
                    // Reconcile offset with actual temp file length
                    if let Ok(meta) = std::fs::metadata(&s.temp_path) {
                        s.offset = meta.len().min(s.size);
                    }
                    map.insert(s.id.clone(), s);
                }
            }
        }
        *self.sessions.lock() = map;
        Ok(())
    }

    fn persist(session: &UploadSession, state_dir: &Path) -> Result<(), String> {
        let p = state_dir.join(format!("{}.json", session.id));
        let raw = serde_json::to_string_pretty(session).map_err(|e| e.to_string())?;
        // Atomic write
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

    pub fn init(
        &self,
        virtual_path: &str,
        size: u64,
        session: Option<&Session>,
    ) -> Result<UploadSession, String> {
        // Ensure parent dir exists
        if let Some(parent) = virtual_path.rsplit_once('/').map(|(p, _)| p) {
            if !parent.is_empty() {
                let _ = self.storage.mkdir(parent, session);
            }
        }

        // Resume existing incomplete upload to same path+size
        {
            let map = self.sessions.lock();
            if let Some(existing) = map.values().find(|s| {
                s.virtual_path == virtual_path
                    && s.size == size
                    && s.offset < s.size
                    && session
                        .map(|sess| s.owner.as_deref() == Some(sess.username.as_str()) || s.owner.is_none())
                        .unwrap_or(true)
            }) {
                return Ok(existing.clone());
            }
        }

        let id = Uuid::new_v4().to_string();
        let temp_path = self.state_dir.join(format!("{id}.part"));
        // Pre-allocate sparsely when possible (best-effort)
        {
            let f = std::fs::File::create(&temp_path).map_err(|e| e.to_string())?;
            let _ = f.set_len(size);
        }

        let us = UploadSession {
            id: id.clone(),
            virtual_path: virtual_path.to_string(),
            size,
            offset: 0,
            temp_path,
            created: Self::now(),
            owner: session.map(|s| s.username.clone()),
        };
        Self::persist(&us, &self.state_dir)?;
        self.sessions.lock().insert(id, us.clone());
        Ok(us)
    }

    pub fn status(&self, id: &str) -> Option<UploadSession> {
        self.sessions.lock().get(id).cloned()
    }

    /// Append bytes at exact offset. Rejects gaps / overlaps beyond offset.
    pub fn write_chunk(
        &self,
        id: &str,
        offset: u64,
        mut body: impl Read,
    ) -> Result<UploadSession, String> {
        let mut map = self.sessions.lock();
        let sess = map.get_mut(id).ok_or("unknown upload")?;
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
        Self::persist(sess, &self.state_dir)?;
        Ok(sess.clone())
    }

    pub fn complete(
        &self,
        id: &str,
        session: Option<&Session>,
        auth: &crate::auth::AuthState,
    ) -> Result<String, String> {
        let sess = {
            let map = self.sessions.lock();
            map.get(id).cloned().ok_or("unknown upload")?
        };
        if sess.offset != sess.size {
            return Err(format!(
                "incomplete: {} / {} bytes",
                sess.offset, sess.size
            ));
        }

        let dest = self.storage.resolve(&sess.virtual_path, session)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        if self.encryption {
            // shared/* → shared keystore; ~user/* → that user's key
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
            crypto::seal_uploaded_file(&sess.temp_path, &dest, &ek, sess.size)
                .map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&sess.temp_path);
        } else {
            std::fs::rename(&sess.temp_path, &dest).map_err(|e| e.to_string())?;
        }

        // Cleanup state
        let _ = std::fs::remove_file(self.state_dir.join(format!("{}.json", sess.id)));
        self.sessions.lock().remove(id);
        Ok(sess.virtual_path)
    }

    pub fn gc(&self) {
        let now = Self::now();
        let mut map = self.sessions.lock();
        let expired: Vec<String> = map
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.created) > self.ttl_secs)
            .map(|(k, _)| k.clone())
            .collect();
        for id in expired {
            if let Some(s) = map.remove(&id) {
                let _ = std::fs::remove_file(&s.temp_path);
                let _ = std::fs::remove_file(self.state_dir.join(format!("{id}.json")));
            }
        }
    }
}
