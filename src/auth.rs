//! Authentication & sessions. Active only when encryption.enabled.

use crate::config::{Config, UserConfig};
use crate::crypto::{self, UserSecrets};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
}

#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub role: Role,
    /// Unlocked ML-KEM decapsulation key for this user.
    pub secrets: Arc<UserSecrets>,
    pub expires: Instant,
}

pub struct AuthState {
    sessions: RwLock<HashMap<String, Session>>,
    ttl: Duration,
    users: Vec<UserConfig>,
    keystore: PathBuf,
    encryption: bool,
    /// Unlocked at boot via FST_SHARED_PASSWORD when encryption is on.
    shared_secrets: RwLock<Option<Arc<UserSecrets>>>,
}

impl AuthState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(cfg.session.ttl_secs),
            users: cfg.auth.users.clone(),
            keystore: crypto::keystore_dir(&cfg.server.data_dir),
            encryption: cfg.encryption.enabled,
            shared_secrets: RwLock::new(None),
        }
    }

    pub fn requires_auth(&self) -> bool {
        self.encryption
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
            expires: Instant::now() + self.ttl,
        };
        self.sessions.write().insert(id, session.clone());
        Ok(session)
    }

    pub fn logout(&self, sid: &str) {
        self.sessions.write().remove(sid);
    }

    pub fn get(&self, sid: &str) -> Option<Session> {
        let mut map = self.sessions.write();
        let s = map.get(sid)?.clone();
        if Instant::now() > s.expires {
            map.remove(sid);
            return None;
        }
        if let Some(s2) = map.get_mut(sid) {
            s2.expires = Instant::now() + self.ttl;
        }
        Some(s)
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.sessions.write().retain(|_, s| s.expires > now);
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
}

/// Cookie name for session id.
pub const SESSION_COOKIE: &str = "fst_session";
