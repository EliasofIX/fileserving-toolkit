//! HTTP API + static UI serving.

use crate::auth::{AuthState, Session, SESSION_COOKIE};
use crate::config::Config;
use crate::crypto;
use crate::media::Media;
use crate::storage::Storage;
use crate::transfer::TransferManager;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{
    header::{self, HeaderMap, HeaderValue},
    StatusCode,
};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub auth: Arc<AuthState>,
    pub storage: Arc<Storage>,
    pub transfers: Arc<TransferManager>,
    pub media: Arc<Media>,
}

#[derive(Embed)]
#[folder = "web/"]
struct Assets;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/status", get(api_status))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/me", get(api_me))
        .route("/api/list", get(api_list))
        .route("/api/mkdir", post(api_mkdir))
        .route("/api/delete", delete(api_delete))
        .route("/api/upload/init", post(api_upload_init))
        .route("/api/upload/{id}", get(api_upload_status).put(api_upload_put))
        .route("/api/upload/{id}/complete", post(api_upload_complete))
        .route("/api/file", get(api_file))
        .route("/api/stream", get(api_stream))
        .route("/api/media/info", get(api_media_info))
        .route("/", get(static_index))
        .route("/{*path}", get(static_asset))
        .layer(CompressionLayer::new())
        .with_state(state)
}

fn session_from(headers: &HeaderMap, auth: &AuthState) -> Option<Session> {
    if !auth.requires_auth() {
        return None;
    }
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return auth.get(v);
        }
    }
    if let Some(authz) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = authz.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                return auth.get(tok.trim());
            }
        }
    }
    None
}

fn require_auth(headers: &HeaderMap, auth: &AuthState) -> Result<Option<Session>, Response> {
    if !auth.requires_auth() {
        return Ok(None);
    }
    match session_from(headers, auth) {
        Some(s) => Ok(Some(s)),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"unauthorized"})),
        )
            .into_response()),
    }
}

#[derive(Serialize)]
struct StatusResp {
    name: &'static str,
    encryption: bool,
    auth_required: bool,
    ffmpeg: bool,
    large_threshold: u64,
}

async fn api_status(State(st): State<AppState>) -> Json<StatusResp> {
    Json(StatusResp {
        name: "fst",
        encryption: st.cfg.encryption.enabled,
        auth_required: st.auth.requires_auth(),
        ffmpeg: st.media.available(),
        large_threshold: st.cfg.transfer.large_threshold,
    })
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn api_login(State(st): State<AppState>, Json(body): Json<LoginReq>) -> Response {
    match st.auth.login(&body.username, &body.password) {
        Ok(sess) => {
            let cookie = format!(
                "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
                sess.id, st.cfg.session.ttl_secs
            );
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(serde_json::json!({
                    "ok": true,
                    "username": sess.username,
                    "role": match sess.role {
                        crate::auth::Role::Admin => "admin",
                        crate::auth::Role::User => "user",
                    },
                    "session": sess.id,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(s) = session_from(&headers, &st.auth) {
        st.auth.logout(&s.id);
    }
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0");
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}

async fn api_me(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if !st.auth.requires_auth() {
        return Json(serde_json::json!({"auth": false, "username": null})).into_response();
    }
    match session_from(&headers, &st.auth) {
        Some(s) => Json(serde_json::json!({
            "auth": true,
            "username": s.username,
            "role": match s.role {
                crate::auth::Role::Admin => "admin",
                crate::auth::Role::User => "user",
            },
        }))
        .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"auth": true, "username": null})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PathQuery {
    path: Option<String>,
}

async fn api_list(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let path = q.path.unwrap_or_default();
    match st.storage.list(&path, sess.as_ref()) {
        Ok(entries) => Json(serde_json::json!({"path": path, "entries": entries})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct MkdirReq {
    path: String,
}

async fn api_mkdir(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MkdirReq>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.storage.mkdir(&body.path, sess.as_ref()) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let path = q.path.unwrap_or_default();
    match st.storage.delete(&path, sess.as_ref()) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct UploadInit {
    path: String,
    size: u64,
}

async fn api_upload_init(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UploadInit>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.transfers.init(&body.path, body.size, sess.as_ref()) {
        Ok(u) => Json(serde_json::json!({
            "id": u.id,
            "path": u.virtual_path,
            "size": u.size,
            "offset": u.offset,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_upload_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = require_auth(&headers, &st.auth) {
        return r;
    }
    match st.transfers.status(&id) {
        Some(u) => Json(serde_json::json!({
            "id": u.id,
            "path": u.virtual_path,
            "size": u.size,
            "offset": u.offset,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"not found"})),
        )
            .into_response(),
    }
}

async fn api_upload_put(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    if let Err(r) = require_auth(&headers, &st.auth) {
        return r;
    }
    let offset: u64 = headers
        .get("x-fst-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let body = request.into_body();
    // Cap a single request body at 64 MiB — clients chunk large uploads.
    const MAX_CHUNK: usize = 64 * 1024 * 1024;
    let bytes = match axum::body::to_bytes(body, MAX_CHUNK).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    match st.transfers.write_chunk(&id, offset, &bytes[..]) {
        Ok(u) => Json(serde_json::json!({
            "id": u.id,
            "offset": u.offset,
            "size": u.size,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_upload_complete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.transfers.complete(&id, sess.as_ref(), &st.auth) {
        Ok(path) => Json(serde_json::json!({"ok": true, "path": path})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_file(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let path = q.path.unwrap_or_default();
    let fs_path = match st.storage.resolve(&path, sess.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    };
    if !fs_path.is_file() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"not found"})),
        )
            .into_response();
    }

    let name = fs_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let mime = mime_guess::from_path(&name)
        .first_or_octet_stream()
        .to_string();
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());

    if st.cfg.encryption.enabled && crypto::is_encrypted_file(&fs_path) {
        let sess = match &sess {
            Some(s) => s,
            None => return (StatusCode::UNAUTHORIZED, "auth required").into_response(),
        };
        let secrets = match st.auth.dek_for_path(&path, sess) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": e})),
                )
                    .into_response()
            }
        };
        return serve_encrypted(&fs_path, &name, &mime, range, &secrets.kem_dk);
    }

    serve_file_range(fs_path, name, mime, range)
}

fn serve_file_range(
    path: std::path::PathBuf,
    name: String,
    mime: String,
    range: Option<&str>,
) -> Response {
    use axum::body::Bytes;

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let total = meta.len();
    let (status, start, end) = match parse_range(range, total) {
        Ok(v) => v,
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
            res.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{total}")).unwrap(),
            );
            return res;
        }
    };
    let take = end - start + 1;

    let path2 = path.clone();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    let _ = std::thread::Builder::new()
        .name("fst-read".into())
        .spawn(move || {
            let mut f = match std::fs::File::open(&path2) {
                Ok(f) => f,
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
            };
            if let Err(e) = f.seek(SeekFrom::Start(start)) {
                let _ = tx.blocking_send(Err(e));
                return;
            }
            let mut left = take;
            let mut buf = vec![0u8; 1024 * 1024];
            while left > 0 {
                let n = (left as usize).min(buf.len());
                match f.read(&mut buf[..n]) {
                    Ok(0) => break,
                    Ok(r) => {
                        left -= r as u64;
                        if tx
                            .blocking_send(Ok(Bytes::copy_from_slice(&buf[..r])))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
        });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    let mut res = Response::new(body);
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&take.to_string()).unwrap(),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
        );
    }
    if let Ok(v) = HeaderValue::from_str(&format!("inline; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=0"),
    );
    res
}

fn serve_encrypted(
    path: &std::path::Path,
    name: &str,
    mime: &str,
    range: Option<&str>,
    dk: &[u8],
) -> Response {
    use axum::body::Bytes;

    let reader = match crypto::EncryptedReader::open(path, dk) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let total = reader
        .plain_size
        .or_else(|| crypto::read_plain_size_meta(path))
        .unwrap_or(0);
    let (status, start, end) = match parse_range(range, total) {
        Ok(v) => v,
        Err(()) => {
            return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        }
    };
    let take = end - start + 1;

    let path = path.to_path_buf();
    let dk = dk.to_vec();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    std::thread::spawn(move || {
        let mut reader = match crypto::EncryptedReader::open(&path, &dk) {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
                return;
            }
        };
        let mut pos = start;
        while pos <= end {
            let window_end = (pos + crypto::CHUNK_PLAIN).min(end + 1);
            let mut out = Vec::new();
            if let Err(e) = reader.read_plain_range(pos, window_end, &mut out) {
                let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
                return;
            }
            if out.is_empty() {
                break;
            }
            pos += out.len() as u64;
            if tx.blocking_send(Ok(Bytes::from(out))).is_err() {
                break;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    let mut res = Response::new(body);
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&take.to_string()).unwrap(),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
        );
    }
    if let Ok(v) = HeaderValue::from_str(&format!("inline; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    res
}

fn parse_range(range: Option<&str>, total: u64) -> Result<(StatusCode, u64, u64), ()> {
    if total == 0 {
        return Ok((StatusCode::OK, 0, 0));
    }
    let Some(r) = range else {
        return Ok((StatusCode::OK, 0, total - 1));
    };
    let Some(spec) = r.strip_prefix("bytes=") else {
        return Ok((StatusCode::OK, 0, total - 1));
    };
    let (start_s, end_s) = spec.split_once('-').unwrap_or((spec, ""));
    let start: u64 = start_s.parse().unwrap_or(0);
    let end: u64 = if end_s.is_empty() {
        total - 1
    } else {
        end_s.parse().unwrap_or(total - 1).min(total - 1)
    };
    if start > end || start >= total {
        return Err(());
    }
    Ok((StatusCode::PARTIAL_CONTENT, start, end))
}

async fn api_stream(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let sess = match require_auth(&headers, &st.auth) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let path = q.path.unwrap_or_default();
    let fs_path = match st.storage.resolve(&path, sess.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    };

    if st.cfg.encryption.enabled && crypto::is_encrypted_file(&fs_path) {
        return api_file(
            State(st),
            headers,
            Query(PathQuery {
                path: Some(path),
            }),
        )
        .await;
    }

    if st.media.available() && st.media.needs_remux(&fs_path).await {
        if let Ok(cached) = st.media.remux_mp4(&fs_path).await {
            let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
            return serve_file_range(cached, "stream.mp4".into(), "video/mp4".into(), range);
        }
    }

    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let name = fs_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "media".into());
    let mime = mime_guess::from_path(&name)
        .first_or_octet_stream()
        .to_string();
    serve_file_range(fs_path, name, mime, range)
}

async fn api_media_info(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    if let Err(r) = require_auth(&headers, &st.auth) {
        return r;
    }
    let path = q.path.unwrap_or_default();
    let kind = crate::storage::classify(path.rsplit('/').next().unwrap_or(&path));
    Json(serde_json::json!({
        "path": path,
        "kind": kind,
        "ffmpeg": st.media.available(),
    }))
    .into_response()
}

async fn static_index() -> Response {
    serve_asset("index.html")
}

async fn static_asset(Path(path): Path<String>) -> Response {
    serve_asset(&path)
}

fn serve_asset(path: &str) -> Response {
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            ([(header::CONTENT_TYPE, mime)], f.data.to_vec()).into_response()
        }
        None => {
            if let Some(f) = Assets::get("index.html") {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    f.data.to_vec(),
                )
                    .into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}
