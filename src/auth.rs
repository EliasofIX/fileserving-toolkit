//! Authentication & sessions. Active only when encryption.enabled.
//!
//! Sessions are persisted under `{data_dir}/sessions/` so a process restart
//! does not force re-login. User ML-KEM secrets are sealed with a server-local
//! key (`keystore/session-seal.key`) — same trust boundary as the data dir.

use crate::config::{Config, UserConfig};
use crate::crypto::{self, UserSecrets};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s {
            "admin" => Role::Admin,
            _ => Role::User,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }
}

#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub role: Role,
    /// Unlocked ML-KEM decapsulation key for this user.
    pub secrets: Arc<UserSecrets>,
    pub expires: SystemTime,
}

#[derive(Serialize, Deserialize)]
struct PersistedSession {
    id: String,
    username: String,
    role: String,
    expires_unix: u64,
    /// base64(nonce || ciphertext) of kem_dk under session seal key
    secrets_blob: String,
}

pub struct AuthState {
    sessions: RwLock<HashMap<String, Session>>,
    ttl: Duration,
    users: Vec<UserConfig>,
    keystore: PathBuf,
    session_dir: PathBuf,
    seal_key: [u8; 32],
    encryption: bool,
    /// Unlocked at boot via FST_SHARED_PASSWORD when encryption is on.
    shared_secrets: RwLock<Option<Arc<UserSecrets>>>,
}

impl AuthState {
    pub fn new(cfg: &Config) -> Self {
        let keystore = crypto::keystore_dir(&cfg.server.data_dir);
        let session_dir = crypto::sessions_dir(&cfg.server.data_dir);
        let seal_key = if cfg.encryption.enabled {
            let _ = std::fs::create_dir_all(&session_dir);
            crypto::load_or_create_session_seal_key(&keystore).unwrap_or_else(|e| {
                tracing::error!("session seal key: {e}");
                [0u8; 32]
            })
        } else {
            [0u8; 32]
        };

        let this = Self {
            sessions: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(cfg.session.ttl_secs),
            users: cfg.auth.users.clone(),
            keystore,
            session_dir,
            seal_key,
            encryption: cfg.encryption.enabled,
            shared_secrets: RwLock::new(None),
        };

        if cfg.encryption.enabled {
            this.load_persisted();
        }
        this
    }

    pub fn requires_auth(&self) -> bool {
        self.encryption
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl.as_secs()
    }

    pub fn keystore_path(&self) -> &PathBuf {
        &self.keystore
    }

    pub fn set_shared_secrets(&self, secrets: UserSecrets) {
        *self.shared_secrets.write() = Some(Arc::new(secrets));
    }

    pub fn shared_secrets(&self) -> Option<Arc<UserSecrets>> {
        self.shared_secrets.read().clone()
    }

    pub fn login(&self, username: &str, password: &str) -> Result<Session, String> {
        if !self.encryption {
            return Err("auth disabled".into());
        }
        let user = self
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| "invalid credentials".to_string())?;

        if user.password_hash.is_empty() {
            return Err("user has no password hash — run: fst hash-password".into());
        }
        let ok = crypto::verify_password(password, &user.password_hash)
            .map_err(|e| e.to_string())?;
        if !ok {
            return Err("invalid credentials".into());
        }

        let ks = &self.keystore;
        let ek_path = ks.join(format!("{username}.ek"));
        if !ek_path.exists() {
            crypto::create_user_keystore(username, password, ks).map_err(|e| e.to_string())?;
        }

        let secrets = crypto::unlock_user_secrets(username, password, ks)
            .map_err(|_| "invalid credentials".to_string())?;

        let id = Uuid::new_v4().to_string();
        let session = Session {
            id: id.clone(),
            username: username.to_string(),
            role: Role::parse(&user.role),
            secrets: Arc::new(secrets),
            expires: SystemTime::now() + self.ttl,
        };
        self.persist(&session)?;
        self.sessions.write().insert(id, session.clone());
        Ok(session)
    }

    pub fn logout(&self, sid: &str) {
        self.sessions.write().remove(sid);
        self.remove_persisted(sid);
    }

    pub fn get(&self, sid: &str) -> Option<Session> {
        let mut map = self.sessions.write();
        let s = map.get(sid)?.clone();
        if SystemTime::now() > s.expires {
            map.remove(sid);
            drop(map);
            self.remove_persisted(sid);
            return None;
        }
        if let Some(s2) = map.get_mut(sid) {
            s2.expires = SystemTime::now() + self.ttl;
            let refreshed = s2.clone();
            drop(map);
            let _ = self.persist(&refreshed);
            return Some(refreshed);
        }
        Some(s)
    }

    pub fn purge_expired(&self) {
        let now = SystemTime::now();
        let mut map = self.sessions.write();
        let expired: Vec<String> = map
            .iter()
            .filter(|(_, s)| s.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            map.remove(id);
        }
        drop(map);
        for id in expired {
            self.remove_persisted(&id);
        }
        // Also sweep orphan files (e.g. from a crash mid-write).
        if let Ok(rd) = std::fs::read_dir(&self.session_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(raw) = std::fs::read_to_string(&p) {
                    if let Ok(ps) = serde_json::from_str::<PersistedSession>(&raw) {
                        if unix_to_system(ps.expires_unix) <= now {
                            let _ = std::fs::remove_file(&p);
                            self.sessions.write().remove(&ps.id);
                        }
                    }
                }
            }
        }
    }

    pub fn user_ek(&self, username: &str) -> Result<Vec<u8>, String> {
        crypto::load_user_ek(username, &self.keystore).map_err(|e| e.to_string())
    }

    /// Pick the DK used to decrypt a virtual path.
    /// ~user files are dual-wrapped to the shared EK; admins decrypt via shared secrets.
    pub fn dek_for_path(
        &self,
        virtual_path: &str,
        session: &Session,
    ) -> Result<Arc<UserSecrets>, String> {
        if virtual_path.starts_with("shared/") || virtual_path == "shared" {
            return self
                .shared_secrets()
                .ok_or_else(|| "shared keystore locked — set FST_SHARED_PASSWORD".into());
        }
        if let Some(rest) = virtual_path.strip_prefix('~') {
            let user = rest.split('/').next().unwrap_or("");
            if user == session.username {
                return Ok(session.secrets.clone());
            }
            if session.role == Role::Admin {
                return self
                    .shared_secrets()
                    .ok_or_else(|| "shared keystore locked — set FST_SHARED_PASSWORD".into());
            }
            return Err("forbidden: cannot decrypt another user's files".into());
        }
        Ok(session.secrets.clone())
    }

    fn load_persisted(&self) {
        let rd = match std::fs::read_dir(&self.session_dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        let now = SystemTime::now();
        let mut loaded = 0usize;
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match self.read_persisted_file(&p) {
                Ok(session) if session.expires > now => {
                    self.sessions
                        .write()
                        .insert(session.id.clone(), session);
                    loaded += 1;
                }
                Ok(session) => {
                    self.remove_persisted(&session.id);
                }
                Err(e) => {
                    tracing::warn!("skipping session {}: {e}", p.display());
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        if loaded > 0 {
            tracing::info!("restored {loaded} login session(s)");
        }
    }

    fn read_persisted_file(&self, path: &Path) -> Result<Session, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let ps: PersistedSession = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let blob = B64.decode(&ps.secrets_blob).map_err(|e| e.to_string())?;
        let kem_dk = crypto::open_with_key(&self.seal_key, &blob).map_err(|e| e.to_string())?;
        Ok(Session {
            id: ps.id,
            username: ps.username,
            role: Role::parse(&ps.role),
            secrets: Arc::new(UserSecrets { kem_dk }),
            expires: unix_to_system(ps.expires_unix),
        })
    }

    fn persist(&self, session: &Session) -> Result<(), String> {
        if self.seal_key == [0u8; 32] && self.encryption {
            return Err("session seal key unavailable".into());
        }
        std::fs::create_dir_all(&self.session_dir).map_err(|e| e.to_string())?;
        let sealed = crypto::seal_with_key(&self.seal_key, &session.secrets.kem_dk)
            .map_err(|e| e.to_string())?;
        let ps = PersistedSession {
            id: session.id.clone(),
            username: session.username.clone(),
            role: session.role.as_str().to_string(),
            expires_unix: system_to_unix(session.expires),
            secrets_blob: B64.encode(sealed),
        };
        let path = self.session_dir.join(format!("{}.json", session.id));
        let tmp = self.session_dir.join(format!("{}.json.tmp", session.id));
        let raw = serde_json::to_string_pretty(&ps).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, raw).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn remove_persisted(&self, sid: &str) {
        let path = self.session_dir.join(format!("{sid}.json"));
        let _ = std::fs::remove_file(path);
        let tmp = self.session_dir.join(format!("{sid}.json.tmp"));
        let _ = std::fs::remove_file(tmp);
    }
}

fn system_to_unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_to_system(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Cookie name for session id.
pub const SESSION_COOKIE: &str = "fst_session";

/// Build Set-Cookie value. Max-Age is intentionally long so the browser keeps
/// the id; the server enforces the real idle TTL (and persists it across restarts).
pub fn session_cookie_value(sid: &str, idle_ttl_secs: u64) -> String {
    // Keep the cookie at least as long as the idle window, and typically much
    // longer so everyday use never drops the browser cookie while the server
    // session is still valid via sliding TTL.
    let max_age = idle_ttl_secs.saturating_mul(8).max(idle_ttl_secs).max(86_400);
    format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    )
}

pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, EncryptionConfig, MediaConfig, PathsConfig, ServerConfig, SessionConfig,
        TransferConfig, UserConfig,
    };
    use crate::crypto;

    fn temp_cfg(dir: &Path) -> Config {
        Config {
            server: ServerConfig {
                bind: "127.0.0.1:0".into(),
                workers: 2,
                data_dir: dir.to_path_buf(),
            },
            paths: PathsConfig {
                shared_root: dir.join("shared"),
                users_root: dir.join("users"),
                upload_state_dir: dir.join("uploads"),
            },
            encryption: EncryptionConfig { enabled: true },
            auth: AuthConfig {
                users: vec![UserConfig {
                    username: "admin".into(),
                    password_hash: crypto::hash_password("secret").unwrap(),
                    role: "admin".into(),
                }],
            },
            session: SessionConfig { ttl_secs: 3600 },
            transfer: TransferConfig::default(),
            media: MediaConfig::default(),
        }
    }

    #[test]
    fn session_survives_restart() {
        let dir = std::env::temp_dir().join(format!("fst-sess-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = temp_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let auth1 = AuthState::new(&cfg);
        let sess = auth1.login("admin", "secret").unwrap();
        let sid = sess.id.clone();
        assert!(auth1.get(&sid).is_some());
        drop(auth1);

        let auth2 = AuthState::new(&cfg);
        let restored = auth2.get(&sid).expect("session restored after restart");
        assert_eq!(restored.username, "admin");
        assert_eq!(restored.secrets.kem_dk, sess.secrets.kem_dk);

        auth2.logout(&sid);
        drop(auth2);

        let auth3 = AuthState::new(&cfg);
        assert!(auth3.get(&sid).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
