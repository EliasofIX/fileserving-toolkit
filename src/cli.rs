//! Remote CLI client — talk to an FST server like the web UI does.
//!
//! Credentials: env `FST_URL` / `FST_USER` / `FST_PASSWORD`, or
//! `~/.config/fst/credentials.toml`. Sessions cached in `~/.config/fst/session`.

use reqwest::header::AUTHORIZATION;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const CHUNK: u64 = 8 * 1024 * 1024;
const SESSION_FILE: &str = "session";
const CREDENTIALS_FILE: &str = "credentials.toml";

#[derive(Debug, Clone)]
pub struct RemoteOpts {
    pub url: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub credentials: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Credentials {
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SessionCache {
    url: String,
    username: String,
    session: String,
}

#[derive(Debug)]
pub enum CliError {
    Msg(String),
    Http { status: u16, body: String },
    Io(io::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Msg(m) => write!(f, "{m}"),
            CliError::Http { status, body } => {
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    if let Some(e) = v.get("error").and_then(|x| x.as_str()) {
                        return write!(f, "HTTP {status}: {e}");
                    }
                }
                write!(f, "HTTP {status}: {body}")
            }
            CliError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<reqwest::Error> for CliError {
    fn from(e: reqwest::Error) -> Self {
        CliError::Msg(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Msg(e.to_string())
    }
}

impl From<toml::de::Error> for CliError {
    fn from(e: toml::de::Error) -> Self {
        CliError::Msg(e.to_string())
    }
}

pub fn config_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("fst");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("fst");
    }
    PathBuf::from(".fst")
}

fn normalize_base(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

struct Remote {
    http: Client,
    base: String,
    user: Option<String>,
    password: Option<String>,
    session: Option<String>,
    session_path: PathBuf,
    json: bool,
}

impl Remote {
    fn open(opts: &RemoteOpts) -> Result<Self, CliError> {
        let cred_path = opts
            .credentials
            .clone()
            .unwrap_or_else(|| config_dir().join(CREDENTIALS_FILE));
        let file_creds = load_credentials(&cred_path)?;

        let base = opts
            .url
            .clone()
            .or(file_creds.url)
            .ok_or_else(|| {
                CliError::Msg(
                    "server URL required — set FST_URL, --url, or credentials.toml".into(),
                )
            })?;
        let base = normalize_base(&base);

        let user = opts.user.clone().or(file_creds.username);
        let password = opts.password.clone().or(file_creds.password);

        let session_path = config_dir().join(SESSION_FILE);
        let cached = load_session(&session_path)?;
        let session = cached
            .as_ref()
            .and_then(|c| session_token_if_reusable(c, &base, user.as_deref()));

        let http = Client::builder()
            .timeout(Duration::from_secs(600))
            .connect_timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            base,
            user,
            password,
            session,
            session_path,
            json: opts.json,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn login_with(&mut self, user: &str, password: &str) -> Result<(), CliError> {
        let res = self
            .http
            .post(self.url("/api/login"))
            .json(&serde_json::json!({ "username": user, "password": password }))
            .send()
            .await?;
        let status = res.status().as_u16();
        let body = res.text().await?;
        if status != 200 {
            return Err(CliError::Http { status, body });
        }
        let v: Value = serde_json::from_str(&body)?;
        let session = v
            .get("session")
            .and_then(|x| x.as_str())
            .ok_or_else(|| CliError::Msg("login response missing session".into()))?
            .to_string();
        let username = v
            .get("username")
            .and_then(|x| x.as_str())
            .unwrap_or(user)
            .to_string();
        save_session(
            &self.session_path,
            &SessionCache {
                url: self.base.clone(),
                username: username.clone(),
                session: session.clone(),
            },
        )?;
        self.session = Some(session);
        self.user = Some(username);
        Ok(())
    }

    async fn ensure_session(&mut self) -> Result<(), CliError> {
        if self.session.is_some() {
            return Ok(());
        }
        // Open mode (no auth): probe status.
        let st = self
            .http
            .get(self.url("/api/status"))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        let auth_required = st
            .get("auth_required")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        if !auth_required {
            return Ok(());
        }
        let user = self
            .user
            .clone()
            .ok_or_else(|| CliError::Msg("username required — set FST_USER or --user".into()))?;
        let password = self.password.clone().ok_or_else(|| {
            CliError::Msg("password required — set FST_PASSWORD or credentials.toml".into())
        })?;
        self.login_with(&user, &password).await
    }

    async fn send(
        &mut self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, CliError> {
        self.ensure_session().await?;

        let build = |session: Option<&str>, http: &Client, base: &str| {
            let mut req = http.request(method.clone(), format!("{base}{path}"));
            if let Some(s) = session {
                req = req.header(AUTHORIZATION, format!("Bearer {s}"));
            }
            for (k, v) in headers {
                req = req.header(*k, v);
            }
            if let Some(b) = body.clone() {
                req = req.body(b);
            }
            req
        };

        let res = build(self.session.as_deref(), &self.http, &self.base)
            .send()
            .await?;
        if res.status().as_u16() == 401 {
            let user = self.user.clone();
            let password = self.password.clone();
            if let (Some(u), Some(p)) = (user, password) {
                self.login_with(&u, &p).await?;
                return Ok(build(self.session.as_deref(), &self.http, &self.base)
                    .send()
                    .await?);
            }
        }
        Ok(res)
    }

    /// Buffer a response body. Only for small API JSON / upload-status replies —
    /// never use this for file downloads.
    async fn request(
        &mut self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), CliError> {
        let res = self.send(method, path, headers, body).await?;
        let status = res.status().as_u16();
        let bytes = res.bytes().await?.to_vec();
        Ok((status, bytes))
    }

    async fn json_req(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CliError> {
        let headers = if body.is_some() {
            vec![("content-type", "application/json".into())]
        } else {
            vec![]
        };
        let bytes_body = body
            .map(|b| serde_json::to_vec(&b))
            .transpose()
            .map_err(|e| CliError::Msg(e.to_string()))?;
        let (status, bytes) = self.request(method, path, &headers, bytes_body).await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !(200..300).contains(&status) {
            return Err(CliError::Http { status, body: text });
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    fn print_json(&self, v: &Value) {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
    }
}

fn load_credentials(path: &Path) -> Result<Credentials, CliError> {
    if !path.exists() {
        return Ok(Credentials::default());
    }
    ensure_secret_file_perms(path, "credentials")?;
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}

fn load_session(path: &Path) -> Result<Option<SessionCache>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    ensure_secret_file_perms(path, "session")?;
    let s = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&s)?))
}

/// Refuse to load secrets from files that are group/other-readable.
fn ensure_secret_file_perms(path: &Path, kind: &str) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::Msg(format!(
                "{kind} file {} is group/other-readable (mode {:04o}); chmod 600 and retry",
                path.display(),
                mode & 0o777
            )));
        }
    }
    let _ = (path, kind);
    Ok(())
}

/// Only reuse a cached session when URL **and** an explicitly configured
/// username both match. Never reuse a bearer token when `FST_USER` / credentials
/// username is unset — that would let a later job on a shared host inherit the
/// previous login.
fn session_token_if_reusable(
    cached: &SessionCache,
    base: &str,
    configured_user: Option<&str>,
) -> Option<String> {
    if cached.url != base {
        return None;
    }
    match configured_user {
        Some(u) if u == cached.username => Some(cached.session.clone()),
        _ => None,
    }
}

fn reject_symlink(path: &Path, what: &str) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CliError::Msg(format!(
            "{what}: refusing to follow symlink {}",
            path.display()
        ))),
        Ok(_) | Err(_) => Ok(()), // Err(NotFound) is fine for create paths
    }
}

fn open_local_file(path: &Path) -> Result<(std::fs::File, u64), CliError> {
    reject_symlink(path, "put")?;
    let meta = std::fs::metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(CliError::Msg(format!(
            "put: refusing to follow symlink {}",
            path.display()
        )));
    }
    if meta.is_dir() {
        return Err(CliError::Msg("put: local path is a directory".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW — Linux/macOS; rejects symlink races after symlink_metadata.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        return Ok((file, meta.len()));
    }
    #[cfg(not(unix))]
    {
        Ok((std::fs::File::open(path)?, meta.len()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct DownloadPartMeta {
    remote: String,
    url: String,
}

fn save_session(path: &Path, cache: &SessionCache) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let s = serde_json::to_string_pretty(cache)?;
    // Write via temp + rename, then force 0600 so a loose umask cannot leave
    // the session world-readable even briefly after the final name appears.
    let tmp = path.with_extension("session.tmp");
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            use std::io::Write;
            f.write_all(s.as_bytes())?;
            f.flush()?;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, &s)?;
        }
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn clear_session(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn format_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub async fn cmd_login(opts: &RemoteOpts) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let user = remote
        .user
        .clone()
        .ok_or_else(|| CliError::Msg("username required — set FST_USER or --user".into()))?;
    let password = remote.password.clone().ok_or_else(|| {
        CliError::Msg("password required — set FST_PASSWORD or credentials.toml".into())
    })?;
    remote.login_with(&user, &password).await?;
    let me = remote
        .json_req(reqwest::Method::GET, "/api/me", None)
        .await?;
    if remote.json {
        remote.print_json(&me);
    } else {
        let name = me
            .get("username")
            .and_then(|x| x.as_str())
            .unwrap_or(&user);
        let role = me.get("role").and_then(|x| x.as_str()).unwrap_or("?");
        println!("logged in as {name} ({role}) @ {}", remote.base);
    }
    Ok(())
}

pub async fn cmd_logout(opts: &RemoteOpts) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    if remote.session.is_some() {
        let _ = remote
            .json_req(reqwest::Method::POST, "/api/logout", None)
            .await;
    }
    clear_session(&remote.session_path)?;
    if remote.json {
        println!("{{\"ok\":true}}");
    } else {
        println!("logged out");
    }
    Ok(())
}

pub async fn cmd_whoami(opts: &RemoteOpts) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let me = remote
        .json_req(reqwest::Method::GET, "/api/me", None)
        .await?;
    if remote.json {
        remote.print_json(&me);
    } else if me.get("auth").and_then(|x| x.as_bool()) == Some(false) {
        println!("open mode (auth disabled) @ {}", remote.base);
    } else {
        let name = me
            .get("username")
            .and_then(|x| x.as_str())
            .unwrap_or("(none)");
        let role = me.get("role").and_then(|x| x.as_str()).unwrap_or("?");
        println!("{name} ({role}) @ {}", remote.base);
    }
    Ok(())
}

pub async fn cmd_ls(opts: &RemoteOpts, path: Option<String>) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let path = path.unwrap_or_default();
    let q = if path.is_empty() {
        "/api/list".to_string()
    } else {
        format!("/api/list?path={}", urlencoding(&path))
    };
    let v = remote.json_req(reqwest::Method::GET, &q, None).await?;
    if remote.json {
        remote.print_json(&v);
        return Ok(());
    }
    let entries = v
        .get("entries")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for e in entries {
        let name = e.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        let is_dir = e.get("is_dir").and_then(|x| x.as_bool()).unwrap_or(false);
        let size = e.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
        if is_dir {
            println!("{:>10}  {}/", "", name);
        } else {
            println!("{:>10}  {}", format_size(size), name);
        }
    }
    Ok(())
}

pub async fn cmd_mkdir(opts: &RemoteOpts, path: String) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let v = remote
        .json_req(
            reqwest::Method::POST,
            "/api/mkdir",
            Some(serde_json::json!({ "path": path })),
        )
        .await?;
    if remote.json {
        remote.print_json(&v);
    } else {
        println!("ok");
    }
    Ok(())
}

pub async fn cmd_rm(opts: &RemoteOpts, path: String) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let q = format!("/api/delete?path={}", urlencoding(&path));
    let v = remote.json_req(reqwest::Method::DELETE, &q, None).await?;
    if remote.json {
        remote.print_json(&v);
    } else {
        println!("ok");
    }
    Ok(())
}

pub async fn cmd_mv(opts: &RemoteOpts, from: String, to: String) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let v = remote
        .json_req(
            reqwest::Method::POST,
            "/api/rename",
            Some(serde_json::json!({ "from": from, "to": to })),
        )
        .await?;
    if remote.json {
        remote.print_json(&v);
    } else {
        println!("ok");
    }
    Ok(())
}

pub async fn cmd_put(opts: &RemoteOpts, local: PathBuf, remote_path: String) -> Result<(), CliError> {
    let mut remote = Remote::open(opts)?;
    let (mut file, size) = open_local_file(&local)?;

    let init = remote
        .json_req(
            reqwest::Method::POST,
            "/api/upload/init",
            Some(serde_json::json!({ "path": remote_path, "size": size })),
        )
        .await?;
    let id = init
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CliError::Msg("upload init missing id".into()))?
        .to_string();
    let mut offset = init
        .get("offset")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);

    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;

    while offset < size {
        let end = (offset + CHUNK).min(size);
        let n = (end - offset) as usize;
        let mut buf = vec![0u8; n];
        file.read_exact(&mut buf)?;

        let path = format!("/api/upload/{id}");
        let headers = [
            ("x-fst-offset", offset.to_string()),
            ("content-type", "application/octet-stream".into()),
        ];
        let (status, bytes) = remote
            .request(reqwest::Method::PUT, &path, &headers, Some(buf))
            .await?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !(200..300).contains(&status) {
            return Err(CliError::Http { status, body: text });
        }
        let v: Value = serde_json::from_str(&text)?;
        offset = v
            .get("offset")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| CliError::Msg("upload chunk missing offset".into()))?;

        if !remote.json {
            eprint!(
                "\rput {} / {} ({:.0}%)",
                format_size(offset),
                format_size(size),
                (offset as f64 / size.max(1) as f64) * 100.0
            );
            let _ = io::stderr().flush();
        }
    }
    if !remote.json && size > 0 {
        eprintln!();
    }

    let done = remote
        .json_req(
            reqwest::Method::POST,
            &format!("/api/upload/{id}/complete"),
            None,
        )
        .await?;
    if remote.json {
        remote.print_json(&done);
    } else {
        let path = done
            .get("path")
            .and_then(|x| x.as_str())
            .unwrap_or(&remote_path);
        println!("uploaded {path}");
    }
    Ok(())
}

pub async fn cmd_get(
    opts: &RemoteOpts,
    remote_path: String,
    local: Option<PathBuf>,
) -> Result<(), CliError> {
    let dest = match local {
        Some(p) => p,
        None => {
            let name = remote_path
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("download");
            PathBuf::from(name)
        }
    };
    download(opts, &remote_path, &dest, false).await
}

pub async fn cmd_cat(opts: &RemoteOpts, remote_path: String) -> Result<(), CliError> {
    download(opts, &remote_path, Path::new("-"), true).await
}

fn content_range_total(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let cr = headers.get(reqwest::header::CONTENT_RANGE)?.to_str().ok()?;
    // Accept "bytes */N" or "bytes A-B/N".
    let total = cr.rsplit('/').next()?;
    total.parse().ok()
}

fn write_part_marker(part_meta: &Path, remote_path: &str, url: &str) -> Result<(), CliError> {
    let marker = DownloadPartMeta {
        remote: remote_path.to_string(),
        url: url.to_string(),
    };
    std::fs::write(part_meta, serde_json::to_string_pretty(&marker)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(part_meta, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn promote_part(part: &Path, dest: &Path) -> Result<(), CliError> {
    // Replace an existing destination so rename works on platforms that refuse
    // to overwrite (and so a refreshed download doesn't leave a stale file).
    if dest.exists() {
        reject_symlink(dest, "get")?;
        let meta = std::fs::symlink_metadata(dest)?;
        if meta.is_dir() {
            return Err(CliError::Msg(format!(
                "get: destination is a directory: {}",
                dest.display()
            )));
        }
        std::fs::remove_file(dest)?;
    }
    std::fs::rename(part, dest)?;
    Ok(())
}

fn finish_get_output(remote: &Remote, remote_path: &str, dest: &Path, bytes: u64) {
    if remote.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "path": remote_path,
                "local": dest.display().to_string(),
                "bytes": bytes,
            })
        );
    } else {
        println!("saved {}", dest.display());
    }
}

async fn stream_to_part(
    res: reqwest::Response,
    part: &Path,
    mut offset: u64,
    truncate: bool,
    show_progress: bool,
) -> Result<u64, CliError> {
    use futures::StreamExt;
    let mut file = if truncate {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(part)?
    } else {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(part)?
    };
    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CliError::Msg(e.to_string()))?;
        file.write_all(&chunk)?;
        offset += chunk.len() as u64;
        if show_progress {
            eprint!("\rget {}", format_size(offset));
            let _ = io::stderr().flush();
        }
    }
    file.flush()?;
    Ok(offset)
}

async fn download(
    opts: &RemoteOpts,
    remote_path: &str,
    dest: &Path,
    to_stdout: bool,
) -> Result<(), CliError> {
    use futures::StreamExt;

    let mut remote = Remote::open(opts)?;
    let q = format!("/api/file?path={}", urlencoding(remote_path));

    if to_stdout {
        let res = remote.send(reqwest::Method::GET, &q, &[], None).await?;
        let status = res.status().as_u16();
        if status != 200 && status != 206 {
            let body = res.text().await.unwrap_or_default();
            return Err(CliError::Http { status, body });
        }
        let mut out = io::stdout();
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| CliError::Msg(e.to_string()))?;
            out.write_all(&chunk)?;
        }
        out.flush()?;
        return Ok(());
    }

    // Never append into an existing final destination blindly — resume only a
    // part file whose marker records this exact remote path + server URL.
    if dest.exists() {
        reject_symlink(dest, "get")?;
        let meta = std::fs::symlink_metadata(dest)?;
        if meta.is_dir() {
            return Err(CliError::Msg(format!(
                "get: destination is a directory: {}",
                dest.display()
            )));
        }
    }
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let part = PathBuf::from(format!("{}.fst-part", dest.display()));
    let part_meta = PathBuf::from(format!("{}.fst-part.json", dest.display()));
    if part.exists() {
        reject_symlink(&part, "get")?;
    }

    let mut offset = 0u64;
    let can_resume = match std::fs::read_to_string(&part_meta) {
        Ok(s) => match serde_json::from_str::<DownloadPartMeta>(&s) {
            Ok(m) if m.remote == remote_path && m.url == remote.base && part.exists() => {
                offset = std::fs::metadata(&part)?.len();
                true
            }
            _ => false,
        },
        Err(_) => false,
    };
    if !can_resume {
        let _ = std::fs::remove_file(&part);
        let _ = std::fs::remove_file(&part_meta);
        offset = 0;
        write_part_marker(&part_meta, remote_path, &remote.base)?;
    }

    let mut resume_attempted = offset > 0;
    loop {
        let headers: Vec<(&str, String)> = if offset > 0 {
            vec![("range", format!("bytes={offset}-"))]
        } else {
            vec![]
        };
        let res = remote
            .send(reqwest::Method::GET, &q, &headers, None)
            .await?;
        let status = res.status().as_u16();

        if status == 416 && offset > 0 {
            // Promote only when part length == remote total from Content-Range.
            // If the header is missing (older servers), probe with bytes=0-0.
            let mut total = content_range_total(res.headers());
            drop(res);
            if total.is_none() {
                let probe = [("range", "bytes=0-0".into())];
                let probe_res = remote
                    .send(reqwest::Method::GET, &q, &probe, None)
                    .await?;
                total = content_range_total(probe_res.headers());
                drop(probe_res);
            }
            if total == Some(offset) {
                promote_part(&part, dest)?;
                let _ = std::fs::remove_file(&part_meta);
                if !remote.json {
                    eprintln!();
                }
                finish_get_output(&remote, remote_path, dest, offset);
                return Ok(());
            }
            // Stale/oversized part — discard and restart once from zero.
            // If we still don't know the remote size, keep the part and error
            // rather than deleting a possibly complete download.
            if total.is_none() {
                return Err(CliError::Msg(
                    "get: range not satisfiable and remote size unknown — part kept".into(),
                ));
            }
            let _ = std::fs::remove_file(&part);
            let _ = std::fs::remove_file(&part_meta);
            offset = 0;
            write_part_marker(&part_meta, remote_path, &remote.base)?;
            if resume_attempted {
                resume_attempted = false;
                continue;
            }
            return Err(CliError::Msg(
                "get: range not satisfiable and could not recover".into(),
            ));
        }

        if status != 200 && status != 206 {
            let body = res.text().await.unwrap_or_default();
            return Err(CliError::Http { status, body });
        }

        // 200 = full body (truncate part); 206 = append remainder.
        let truncate = status == 200;
        if truncate {
            offset = 0;
        }
        offset = stream_to_part(res, &part, offset, truncate, !remote.json).await?;
        promote_part(&part, dest)?;
        let _ = std::fs::remove_file(&part_meta);
        if !remote.json {
            eprintln!();
        }
        finish_get_output(&remote, remote_path, dest, offset);
        return Ok(());
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                const HEX: &[u8] = b"0123456789ABCDEF";
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

pub fn exit_code(err: &CliError) -> i32 {
    match err {
        CliError::Http { status, body } => {
            if *status == 401 {
                2
            } else if *status == 403 || body.contains("forbidden") {
                3
            } else if *status == 404 || body.contains("not found") {
                4
            } else {
                1
            }
        }
        CliError::Msg(m)
            if m.contains("URL required")
                || m.contains("username required")
                || m.contains("password required") =>
        {
            2
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_slash() {
        assert_eq!(normalize_base("http://x/"), "http://x");
        assert_eq!(normalize_base("http://x"), "http://x");
    }

    #[test]
    fn format_size_basic() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
    }

    #[test]
    fn session_reuse_requires_matching_user() {
        let cached = SessionCache {
            url: "http://fst".into(),
            username: "alice".into(),
            session: "tok-a".into(),
        };
        assert_eq!(
            session_token_if_reusable(&cached, "http://fst", Some("alice")).as_deref(),
            Some("tok-a")
        );
        assert_eq!(
            session_token_if_reusable(&cached, "http://fst", Some("bob")),
            None
        );
        // No configured user → never reuse (shared-host / CI safety).
        assert_eq!(
            session_token_if_reusable(&cached, "http://fst", None),
            None
        );
        assert_eq!(
            session_token_if_reusable(&cached, "http://other", Some("alice")),
            None
        );
    }

    #[test]
    fn content_range_total_parses() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::CONTENT_RANGE,
            reqwest::header::HeaderValue::from_static("bytes */100"),
        );
        assert_eq!(content_range_total(&h), Some(100));
        h.insert(
            reqwest::header::CONTENT_RANGE,
            reqwest::header::HeaderValue::from_static("bytes 0-9/42"),
        );
        assert_eq!(content_range_total(&h), Some(42));
    }

    #[test]
    fn ensure_secret_file_perms_rejects_world_readable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!("fst-perm-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("credentials.toml");
            std::fs::write(&path, "url = \"http://x\"\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ensure_secret_file_perms(&path, "credentials").is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(ensure_secret_file_perms(&path, "credentials").is_ok());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn reject_symlink_detects_links() {
        let dir = std::env::temp_dir().join(format!("fst-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::write(&target, b"x").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(reject_symlink(&link, "put").is_err());
            assert!(reject_symlink(&target, "put").is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
