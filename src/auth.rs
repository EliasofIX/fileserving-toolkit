//! Authentication & sessions. Active only when encryption.enabled.
//!
//! Sessions are persisted under `{data_dir}/sessions/` so a process restart
//! does not force re-login. User ML-KEM secrets are sealed with a server-local
//! key (`keystore/session-seal.key`) — same trust boundary as the data dir.
//! Session metadata (id, username, role, expiry) is bound as AES-GCM AAD.

use crate::config::{Config, UserConfig};
use crate::crypto::{self, UserSecrets};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use parking_lot::{RwLock, RwLockWriteGuard};
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
    /// base64(nonce || ciphertext) of kem_dk; AAD binds id|username|role|expires
    secrets_blob: String,
}

pub struct AuthState {
    sessions: RwLock<HashMap<String, Session>>,
    ttl: Duration,
    users: Vec<UserConfig>,
    keystore: PathBuf,
    session_dir: PathBuf,
    seal_key: Option<[u8; 32]>,
    encryption: bool,
    secure_cookie: bool,
    max_per_user: usize,
    /// Unlocked at boot via FST_SHARED_PASSWORD when encryption is on.
    shared_secrets: RwLock<Option<Arc<UserSecrets>>>,
}

impl AuthState {
    pub fn new(cfg: &Config) -> Self {
        let keystore = crypto::keystore_dir(&cfg.server.data_dir);
        let session_dir = crypto::sessions_dir(&cfg.server.data_dir);

        let seal_key = if cfg.encryption.enabled {
            if let Err(e) = crypto::ensure_sessions_dir(&session_dir) {
                tracing::error!("sessions dir: {e}");
            }
            match crypto::load_or_create_session_seal_key(&keystore) {
                Ok(k) => Some(k),
                Err(e) => {
                    // Do not substitute a zero key and wipe sessions — leave
                    // files untouched and refuse to persist until fixed.
                    tracing::error!(
                        "session seal key unavailable ({e}); persisted logins disabled"
                    );
                    None
                }
            }
        } else {
            None
        };

        let this = Self {
            sessions: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(cfg.session.ttl_secs),
            users: cfg.auth.users.clone(),
            keystore,
            session_dir,
            seal_key,
            encryption: cfg.encryption.enabled,
            secure_cookie: cfg.session.secure_cookie,
            max_per_user: cfg.session.max_per_user.max(1),
            shared_secrets: RwLock::new(None),
        };

        if cfg.encryption.enabled {
            if this.seal_key.is_some() {
                this.load_persisted();
            } else {
                tracing::warn!("skipping session restore — seal key not loaded");
            }
        }
        this
    }

    pub fn requires_auth(&self) -> bool {
        self.encryption
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl.as_secs()
    }

    pub fn secure_cookie(&self) -> bool {
        self.secure_cookie
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
        if self.seal_key.is_none() {
            tracing::error!("login refused: session seal key unavailable");
            return Err("login unavailable".into());
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

        let mut map = self.sessions.write();
        // Persist before eviction so a failed write cannot wipe sibling sessions.
        self.persist_locked(&session, &user.password_hash)?;
        map.insert(id.clone(), session.clone());
        // Never evict the session we just issued (equal expiries / races).
        self.evict_overflow_locked(&mut map, username, self.max_per_user, Some(&id));
        Ok(session)
    }

    pub fn logout(&self, sid: &str) {
        if !is_valid_session_id(sid) {
            return;
        }
        let mut map = self.sessions.write();
        map.remove(sid);
        // Delete while holding the write lock so a concurrent get()/persist
        // cannot resurrect the file after logout.
        self.remove_persisted_path(&self.session_path(sid));
        self.remove_persisted_path(&self.session_tmp_path(sid));
    }

    /// Validate session and slide idle TTL (persists under the session lock).
    pub fn get(&self, sid: &str) -> Option<Session> {
        if !is_valid_session_id(sid) {
            return None;
        }
        let mut map = self.sessions.write();
        let s = map.get(sid)?.clone();
        if SystemTime::now() > s.expires {
            map.remove(sid);
            self.remove_persisted_path(&self.session_path(sid));
            self.remove_persisted_path(&self.session_tmp_path(sid));
            return None;
        }
        // Re-bind role from live config (demotions / removals take effect).
        let Some(user) = self.users.iter().find(|u| u.username == s.username) else {
            map.remove(sid);
            self.remove_persisted_path(&self.session_path(sid));
            self.remove_persisted_path(&self.session_tmp_path(sid));
            return None;
        };
        let role = Role::parse(&user.role);
        let password_hash = user.password_hash.clone();
        if let Some(s2) = map.get_mut(sid) {
            s2.expires = SystemTime::now() + self.ttl;
            s2.role = role;
            let refreshed = s2.clone();
            if let Err(e) = self.persist_locked(&refreshed, &password_hash) {
                tracing::warn!("session persist failed for {sid}: {e}");
            }
            return Some(refreshed);
        }
        Some(s)
    }

    /// Check session without sliding TTL or touching disk (for cookie refresh).
    pub fn peek(&self, sid: &str) -> Option<Session> {
        if !is_valid_session_id(sid) {
            return None;
        }
        let map = self.sessions.read();
        let s = map.get(sid)?.clone();
        if SystemTime::now() > s.expires {
            return None;
        }
        // Drop sessions for users removed from config.
        if !self.users.iter().any(|u| u.username == s.username) {
            return None;
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
            self.remove_persisted_path(&self.session_path(id));
            self.remove_persisted_path(&self.session_tmp_path(id));
        }
        // Sweep orphan disk files. Never remove a live in-memory session
        // based solely on a stale on-disk expiry.
        let live: std::collections::HashSet<String> = map.keys().cloned().collect();
        drop(map);
        if let Ok(rd) = std::fs::read_dir(&self.session_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let stem = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if live.contains(stem) {
                    continue;
                }
                if !is_valid_session_id(stem) {
                    let _ = std::fs::remove_file(&p);
                    continue;
                }
                match self.decode_persisted_file(&p) {
                    Ok(ps) if unix_to_system(ps.expires_unix) <= now => {
                        let _ = std::fs::remove_file(&p);
                    }
                    Ok(_) => {
                        // Unexpired orphan (e.g. crash after write before map
                        // insert) — leave for next boot restore.
                    }
                    Err(_) => {
                        let _ = std::fs::remove_file(&p);
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
            let stem = match p.file_stem().and_then(|s| s.to_str()) {
                Some(s) if is_valid_session_id(s) => s.to_string(),
                _ => {
                    tracing::warn!("removing invalid session filename {}", p.display());
                    let _ = std::fs::remove_file(&p);
                    continue;
                }
            };
            match self.read_persisted_file(&p, &stem) {
                Ok(session) if session.expires > now => {
                    self.sessions
                        .write()
                        .insert(session.id.clone(), session);
                    loaded += 1;
                }
                Ok(_) => {
                    let _ = std::fs::remove_file(&p);
                }
                Err(e) => {
                    // Auth failures (bad AAD / wrong key material) delete the
                    // file; IO errors on an otherwise valid seal key leave it.
                    tracing::warn!("skipping session {}: {e}", p.display());
                    if e.contains("seal open")
                        || e.contains("aad")
                        || e.contains("unknown user")
                        || e.contains("id mismatch")
                        || e.contains("invalid session")
                    {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
        }
        // Enforce per-user caps after restore (config may have been tightened).
        {
            let mut map = self.sessions.write();
            let users: Vec<String> = map
                .values()
                .map(|s| s.username.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            for u in users {
                self.evict_overflow_locked(&mut map, &u, self.max_per_user, None);
            }
            loaded = map.len();
        }
        if loaded > 0 {
            tracing::info!("restored {loaded} login session(s)");
        }
    }

    fn decode_persisted_file(&self, path: &Path) -> Result<PersistedSession, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    }

    fn read_persisted_file(&self, path: &Path, file_stem: &str) -> Result<Session, String> {
        let key = self
            .seal_key
            .ok_or_else(|| "seal key unavailable".to_string())?;
        let ps = self.decode_persisted_file(path)?;
        if ps.id != file_stem || !is_valid_session_id(&ps.id) {
            return Err("id mismatch".into());
        }
        let user = self
            .users
            .iter()
            .find(|u| u.username == ps.username)
            .ok_or_else(|| "unknown user".to_string())?;
        // Role always comes from live config. AAD binds sealed role + credential
        // fingerprint so JSON tampering or password rotation invalidates the blob.
        let cred = cred_fingerprint(&user.password_hash);
        let ks_fp = keystore_fingerprint(&ps.username, &self.keystore);
        let aad = session_aad(
            &ps.id,
            &ps.username,
            &ps.role,
            ps.expires_unix,
            &cred,
            &ks_fp,
        );
        let blob = B64.decode(&ps.secrets_blob).map_err(|e| e.to_string())?;
        let kem_dk =
            crypto::open_with_key_aad(&key, &blob, aad.as_bytes()).map_err(|e| e.to_string())?;
        Ok(Session {
            id: ps.id,
            username: ps.username,
            role: Role::parse(&user.role),
            secrets: Arc::new(UserSecrets { kem_dk }),
            expires: unix_to_system(ps.expires_unix),
        })
    }

    /// Persist while caller holds the sessions write lock.
    fn persist_locked(&self, session: &Session, password_hash: &str) -> Result<(), String> {
        if !is_valid_session_id(&session.id) {
            return Err("invalid session id".into());
        }
        let key = self
            .seal_key
            .ok_or_else(|| "login unavailable".to_string())?;
        crypto::ensure_sessions_dir(&self.session_dir).map_err(|e| e.to_string())?;
        let expires_unix = system_to_unix(session.expires);
        let role = session.role.as_str();
        let cred = cred_fingerprint(password_hash);
        let ks_fp = keystore_fingerprint(&session.username, &self.keystore);
        let aad = session_aad(
            &session.id,
            &session.username,
            role,
            expires_unix,
            &cred,
            &ks_fp,
        );
        let sealed = crypto::seal_with_key_aad(&key, &session.secrets.kem_dk, aad.as_bytes())
            .map_err(|e| e.to_string())?;
        let ps = PersistedSession {
            id: session.id.clone(),
            username: session.username.clone(),
            role: role.to_string(),
            expires_unix,
            secrets_blob: B64.encode(sealed),
        };
        let path = self.session_path(&session.id);
        let tmp = self.session_tmp_path(&session.id);
        let raw = serde_json::to_string(&ps).map_err(|e| e.to_string())?;
        crypto::write_private_file(&tmp, raw.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn evict_overflow_locked(
        &self,
        map: &mut RwLockWriteGuard<'_, HashMap<String, Session>>,
        username: &str,
        keep: usize,
        protect: Option<&str>,
    ) {
        let mut mine: Vec<(String, SystemTime)> = map
            .iter()
            .filter(|(id, s)| s.username == username && protect != Some(id.as_str()))
            .map(|(id, s)| (id.clone(), s.expires))
            .collect();
        let protected = protect
            .filter(|id| map.get(*id).is_some_and(|s| s.username == username))
            .map(|_| 1usize)
            .unwrap_or(0);
        let keep_others = keep.saturating_sub(protected);
        if mine.len() <= keep_others {
            return;
        }
        mine.sort_by_key(|(_, exp)| *exp);
        let drop_n = mine.len() - keep_others;
        for (id, _) in mine.into_iter().take(drop_n) {
            map.remove(&id);
            self.remove_persisted_path(&self.session_path(&id));
            self.remove_persisted_path(&self.session_tmp_path(&id));
        }
    }

    fn session_path(&self, sid: &str) -> PathBuf {
        self.session_dir.join(format!("{sid}.json"))
    }

    fn session_tmp_path(&self, sid: &str) -> PathBuf {
        self.session_dir.join(format!("{sid}.json.tmp"))
    }

    fn remove_persisted_path(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

fn session_aad(
    id: &str,
    username: &str,
    role: &str,
    expires_unix: u64,
    cred_fp: &str,
    keystore_fp: &str,
) -> String {
    format!("fst-sess-v3|{id}|{username}|{role}|{expires_unix}|{cred_fp}|{keystore_fp}")
}

/// Short fingerprint of the configured password hash so rotation invalidates sessions.
fn cred_fingerprint(password_hash: &str) -> String {
    use sha2::{Digest, Sha256};
    let dig = Sha256::digest(password_hash.as_bytes());
    hex::encode(&dig[..16])
}

/// Fingerprint of the on-disk user keystore so `init-keys` rotation invalidates sessions.
fn keystore_fingerprint(username: &str, keystore: &Path) -> String {
    use sha2::{Digest, Sha256};
    let sk = keystore.join(format!("{username}.sk"));
    match std::fs::read(&sk) {
        Ok(bytes) => {
            let dig = Sha256::digest(&bytes);
            hex::encode(&dig[..16])
        }
        Err(_) => "missing".into(),
    }
}

fn is_valid_session_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok()
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
pub fn session_cookie_value(sid: &str, idle_ttl_secs: u64, secure: bool) -> String {
    let max_age = idle_ttl_secs.saturating_mul(8).max(idle_ttl_secs).max(86_400);
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure_flag}"
    )
}

pub fn clear_session_cookie(secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0{secure_flag}")
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
            session: SessionConfig {
                ttl_secs: 3600,
                secure_cookie: false,
                max_per_user: 8,
            },
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

    #[test]
    fn tampered_role_rejected() {
        let dir = std::env::temp_dir().join(format!("fst-tamper-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = temp_cfg(&dir);
        cfg.auth.users.push(UserConfig {
            username: "alice".into(),
            password_hash: crypto::hash_password("secret").unwrap(),
            role: "user".into(),
        });
        cfg.ensure_dirs().unwrap();

        let auth1 = AuthState::new(&cfg);
        let sess = auth1.login("alice", "secret").unwrap();
        let sid = sess.id.clone();
        drop(auth1);

        // Flip role in plaintext JSON — AAD must invalidate the blob.
        let path = dir.join("sessions").join(format!("{sid}.json"));
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["role"] = serde_json::json!("admin");
        std::fs::write(&path, v.to_string()).unwrap();

        let auth2 = AuthState::new(&cfg);
        assert!(auth2.get(&sid).is_none(), "tampered role must not restore");
        assert!(!path.exists(), "bad session file removed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn logout_not_resurrected_by_stale_persist() {
        let dir = std::env::temp_dir().join(format!("fst-logout-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = temp_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let auth = AuthState::new(&cfg);
        let sess = auth.login("admin", "secret").unwrap();
        let sid = sess.id.clone();

        // Simulate: get slides under lock and persists before returning.
        assert!(auth.get(&sid).is_some());
        auth.logout(&sid);
        assert!(auth.get(&sid).is_none());
        assert!(!dir.join("sessions").join(format!("{sid}.json")).exists());

        // Fresh AuthState must not restore a logged-out session.
        drop(auth);
        let auth2 = AuthState::new(&cfg);
        assert!(auth2.get(&sid).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_path_traversal_session_id() {
        assert!(!is_valid_session_id("../keystore/evil"));
        assert!(!is_valid_session_id(""));
        assert!(is_valid_session_id(&Uuid::new_v4().to_string()));
    }

    #[test]
    fn login_does_not_evict_just_issued_session() {
        let dir = std::env::temp_dir().join(format!("fst-evict-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = temp_cfg(&dir);
        cfg.session.max_per_user = 2;
        cfg.ensure_dirs().unwrap();

        let auth = AuthState::new(&cfg);
        let a = auth.login("admin", "secret").unwrap();
        let b = auth.login("admin", "secret").unwrap();
        let c = auth.login("admin", "secret").unwrap();
        assert!(auth.get(&c.id).is_some(), "newest login must remain");
        let alive = [a.id, b.id, c.id]
            .iter()
            .filter(|id| auth.get(id).is_some())
            .count();
        assert_eq!(alive, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keystore_rotation_invalidates_sessions() {
        let dir = std::env::temp_dir().join(format!("fst-ksrot-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = temp_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let auth1 = AuthState::new(&cfg);
        let sess = auth1.login("admin", "secret").unwrap();
        let sid = sess.id.clone();
        drop(auth1);

        crypto::create_user_keystore("admin", "secret", &crypto::keystore_dir(&dir)).unwrap();
        let auth2 = AuthState::new(&cfg);
        assert!(auth2.get(&sid).is_none(), "init-keys must invalidate sessions");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_rotation_invalidates_sessions() {
        let dir = std::env::temp_dir().join(format!("fst-pwrot-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = temp_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let auth1 = AuthState::new(&cfg);
        let sess = auth1.login("admin", "secret").unwrap();
        let sid = sess.id.clone();
        drop(auth1);

        cfg.auth.users[0].password_hash = crypto::hash_password("new-secret").unwrap();
        let auth2 = AuthState::new(&cfg);
        assert!(
            auth2.get(&sid).is_none(),
            "sessions must die when password_hash changes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn demoted_admin_loses_admin_on_get() {
        let dir = std::env::temp_dir().join(format!("fst-role-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = temp_cfg(&dir);
        cfg.ensure_dirs().unwrap();

        let auth = AuthState::new(&cfg);
        let sess = auth.login("admin", "secret").unwrap();
        assert_eq!(sess.role, Role::Admin);
        let sid = sess.id.clone();
        drop(auth);

        // Demote in config and reload.
        cfg.auth.users[0].role = "user".into();
        let auth2 = AuthState::new(&cfg);
        let s = auth2.get(&sid).unwrap();
        assert_eq!(s.role, Role::User);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
