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
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}

fn load_session(path: &Path) -> Result<Option<SessionCache>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&s)?))
}

/// Only reuse a cached session when URL matches and, if a username is
/// configured, it matches too — otherwise a different `FST_USER` on the same
/// server would silently act as the previous account.
fn session_token_if_reusable(
    cached: &SessionCache,
    base: &str,
    configured_user: Option<&str>,
) -> Option<String> {
    if cached.url != base {
        return None;
    }
    if let Some(u) = configured_user {
        if u != cached.username {
            return None;
        }
    }
    Some(cached.session.clone())
}

fn save_session(path: &Path, cache: &SessionCache) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(cache)?;
    std::fs::write(path, s)?;
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
    let meta = std::fs::metadata(&local)?;
    if meta.is_dir() {
        return Err(CliError::Msg("put: local path is a directory".into()));
    }
    let size = meta.len();

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

    let mut file = std::fs::File::open(&local)?;
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

async fn download(
    opts: &RemoteOpts,
    remote_path: &str,
    dest: &Path,
    to_stdout: bool,
) -> Result<(), CliError> {
    use futures::StreamExt;

    let mut remote = Remote::open(opts)?;
    let q = format!("/api/file?path={}", urlencoding(remote_path));

    let mut offset = 0u64;
    if !to_stdout && dest.exists() {
        offset = std::fs::metadata(dest)?.len();
    }

    let headers: Vec<(&str, String)> = if offset > 0 {
        vec![("range", format!("bytes={offset}-"))]
    } else {
        vec![]
    };

    let res = remote
        .send(reqwest::Method::GET, &q, &headers, None)
        .await?;
    let status = res.status().as_u16();

    if status == 416 {
        if to_stdout {
            return Err(CliError::Msg("empty or complete range".into()));
        }
        if !remote.json {
            println!("saved {}", dest.display());
        } else {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "path": remote_path,
                    "local": dest.display().to_string(),
                    "bytes": offset,
                })
            );
        }
        return Ok(());
    }

    if status != 200 && status != 206 {
        let body = res.text().await.unwrap_or_default();
        return Err(CliError::Http { status, body });
    }

    if to_stdout {
        let mut out = io::stdout();
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| CliError::Msg(e.to_string()))?;
            out.write_all(&chunk)?;
            offset += chunk.len() as u64;
        }
        out.flush()?;
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dest)?;

    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CliError::Msg(e.to_string()))?;
        file.write_all(&chunk)?;
        offset += chunk.len() as u64;
        if !remote.json {
            eprint!("\rget {}", format_size(offset));
            let _ = io::stderr().flush();
        }
    }
    file.flush()?;

    if !remote.json {
        eprintln!();
        println!("saved {}", dest.display());
    } else {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "path": remote_path,
                "local": dest.display().to_string(),
                "bytes": offset,
            })
        );
    }
    Ok(())
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
        CliError::Msg(m) if m.contains("URL required") || m.contains("username required") => 2,
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
        // No configured user (open-mode / whoami-only) may reuse URL match.
        assert_eq!(
            session_token_if_reusable(&cached, "http://fst", None).as_deref(),
            Some("tok-a")
        );
        assert_eq!(
            session_token_if_reusable(&cached, "http://other", Some("alice")),
            None
        );
    }
}
