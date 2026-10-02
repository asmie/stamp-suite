//! Reflector control API for sessions, keys, limits, status, and shutdown.
//!
//! Requires the `control` feature. See `doc/control-plane.md` for the design.
//! Bind to loopback (default) or configure a bearer token.
//! Key material is write-only: never returned or logged.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use tokio_util::sync::CancellationToken;

use crate::crypto::{HmacKey, HmacKeySet};
use crate::receiver::{RateLimiter, ReflectorCounters, RuntimeCaps};
use crate::session::{SessionManager, SessionSummary};

/// Shared reflector state handed to the control server by `main.rs`
/// (cloned `Arc`s out of `ReceiverSharedState`).
#[derive(Clone)]
pub struct ControlState {
    pub counters: Arc<ReflectorCounters>,
    pub session_manager: Arc<SessionManager>,
    pub start_time: std::time::Instant,
    pub rate_limiter: Arc<RateLimiter>,
    pub hmac_keys: Arc<std::sync::RwLock<Option<HmacKeySet>>>,
    pub caps: Arc<RuntimeCaps>,
    pub shutdown_requested: Arc<AtomicBool>,
    /// Bearer token required on every request when `Some`.
    pub token: Option<String>,
}

/// JSON error body: `{"error": "<message>"}` with the given status.
fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn router(state: ControlState) -> Router {
    Router::new()
        .route("/v1/status", get(get_status))
        .route("/v1/sessions", get(get_sessions))
        .route("/v1/sessions/expire", post(post_expire_session))
        .route("/v1/keys", get(get_keys))
        .route(
            "/v1/keys/default",
            put(put_default_key).delete(delete_default_key),
        )
        .route("/v1/keys/{ssid}", put(put_key).delete(delete_key))
        .route("/v1/caps", get(get_caps).patch(patch_caps))
        .route("/v1/drain", post(post_drain))
        .route("/v1/shutdown", post(post_shutdown))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_token,
        ))
        .with_state(state)
}

/// Constant-time bearer-token check (when a token is configured).
async fn require_token(
    State(s): State<ControlState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Some(expected) = &s.token {
        let ok = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| {
                use subtle::ConstantTimeEq;
                t.as_bytes().ct_eq(expected.as_bytes()).into()
            });
        if !ok {
            return err(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
    }
    next.run(req).await
}

async fn get_status(State(s): State<ControlState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": s.start_time.elapsed().as_secs(),
        "draining": s.session_manager.is_draining(),
        "sessions": s.session_manager.session_count(),
        "session_admission": s.session_manager.admission(),
        "provisioned_sessions": s.session_manager.provisioned_count(),
        "counters": {
            "packets_received": s.counters.packets_received.load(Ordering::Relaxed),
            "packets_reflected": s.counters.packets_reflected.load(Ordering::Relaxed),
            "packets_dropped": s.counters.packets_dropped.load(Ordering::Relaxed),
            "reply_queue_rejected": s.counters.reply_queue_rejected.load(Ordering::Relaxed),
            "queued_replies_cancelled": s.counters.queued_replies_cancelled.load(Ordering::Relaxed),
            "packets_rate_limited": s.counters.packets_rate_limited.load(Ordering::Relaxed),
            // RFC 10052 §5 replay detection.
            "packets_replayed": s.counters.packets_replayed.load(Ordering::Relaxed),
            "packets_reordered": s.counters.packets_reordered.load(Ordering::Relaxed),
        },
    }))
}

/// Wire form of a session-table entry (Instant → idle seconds).
#[derive(serde::Serialize)]
struct SessionDto {
    client: String,
    local: String,
    ssid: u16,
    sender_micro_session_id: Option<u16>,
    session_id: u32,
    packets_received: u32,
    packets_transmitted: u32,
    last_reflected_seq: u32,
    idle_seconds: f64,
}

impl From<SessionSummary> for SessionDto {
    fn from(s: SessionSummary) -> Self {
        Self {
            client: s.client_addr.to_string(),
            local: s.key.local.to_string(),
            ssid: s.key.ssid,
            sender_micro_session_id: s.key.sender_micro_session_id,
            session_id: s.session_id,
            packets_received: s.packets_received,
            packets_transmitted: s.packets_transmitted,
            last_reflected_seq: s.last_reflected_seq,
            idle_seconds: s.last_active.elapsed().as_secs_f64(),
        }
    }
}

async fn get_sessions(State(s): State<ControlState>) -> Json<Vec<SessionDto>> {
    Json(
        s.session_manager
            .session_summaries_extended()
            .into_iter()
            .map(SessionDto::from)
            .collect(),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpireRequest {
    client: std::net::SocketAddr,
    session_id: Option<u32>,
}

async fn post_expire_session(
    State(s): State<ControlState>,
    Json(req): Json<ExpireRequest>,
) -> Response {
    match s
        .session_manager
        .expire_matching(req.client, req.session_id)
    {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "no matching session"),
        Err(message) => err(StatusCode::CONFLICT, message),
    }
}

async fn get_keys(State(s): State<ControlState>) -> Json<serde_json::Value> {
    let guard = s.hmac_keys.read().unwrap_or_else(|e| e.into_inner());
    let (has_default, mut ssids) = match guard.as_ref() {
        Some(set) => (set.has_default(), set.ssids()),
        None => (false, Vec::new()),
    };
    ssids.sort_unstable();
    Json(serde_json::json!({ "default": has_default, "ssids": ssids }))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRequest {
    key_hex: String,
}

impl KeyRequest {
    /// Parses and zeroizes the request's key material. Never log the input.
    fn take_key(mut self) -> Result<HmacKey, crate::crypto::HmacError> {
        use zeroize::Zeroize;
        let parsed = HmacKey::from_hex(&self.key_hex);
        self.key_hex.zeroize();
        parsed
    }
}

async fn put_key(
    State(s): State<ControlState>,
    Path(ssid): Path<u16>,
    Json(req): Json<KeyRequest>,
) -> Response {
    match req.take_key() {
        Ok(key) => {
            let mut guard = s.hmac_keys.write().unwrap_or_else(|e| e.into_inner());
            guard.get_or_insert_with(HmacKeySet::new).insert(ssid, key);
            log::info!("control: key set for ssid={ssid}");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &format!("invalid key: {e}")),
    }
}

async fn delete_key(State(s): State<ControlState>, Path(ssid): Path<u16>) -> Response {
    let mut guard = s.hmac_keys.write().unwrap_or_else(|e| e.into_inner());
    let removed = guard.as_mut().is_some_and(|set| set.remove_ssid(ssid));
    if removed {
        log::info!("control: key removed for ssid={ssid}");
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "no key for that SSID")
    }
}

async fn put_default_key(State(s): State<ControlState>, Json(req): Json<KeyRequest>) -> Response {
    match req.take_key() {
        Ok(key) => {
            let mut guard = s.hmac_keys.write().unwrap_or_else(|e| e.into_inner());
            guard.get_or_insert_with(HmacKeySet::new).set_default(key);
            log::info!("control: default key set");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &format!("invalid key: {e}")),
    }
}

async fn delete_default_key(State(s): State<ControlState>) -> Response {
    let mut guard = s.hmac_keys.write().unwrap_or_else(|e| e.into_inner());
    let removed = guard.as_mut().is_some_and(HmacKeySet::clear_default);
    if removed {
        log::info!("control: default key removed");
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "no default key configured")
    }
}

fn caps_json(s: &ControlState) -> serde_json::Value {
    serde_json::json!({
        "max_pps": s.rate_limiter.rate(),
        "rate_burst": s.rate_limiter.burst(),
        "max_sessions": s.session_manager.max_sessions(),
        "reflected_control_max_count":
            s.caps.reflected_control_max_count.load(Ordering::Relaxed),
        "reflected_control_max_size":
            s.caps.reflected_control_max_size.load(Ordering::Relaxed),
        "reflected_control_min_interval_ns":
            s.caps.reflected_control_min_interval_ns.load(Ordering::Relaxed),
        "reflected_control_max_rate":
            s.caps.reflected_control_max_rate.load(Ordering::Relaxed),
        "reflected_control_max_volume":
            s.caps.reflected_control_max_volume.load(Ordering::Relaxed),
    })
}

async fn get_caps(State(s): State<ControlState>) -> Json<serde_json::Value> {
    Json(caps_json(&s))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsPatch {
    max_pps: Option<u32>,
    rate_burst: Option<u32>,
    max_sessions: Option<usize>,
    reflected_control_max_count: Option<u16>,
    reflected_control_max_size: Option<u16>,
    reflected_control_min_interval_ns: Option<u32>,
    reflected_control_max_rate: Option<u64>,
    reflected_control_max_volume: Option<u32>,
}

async fn patch_caps(State(s): State<ControlState>, Json(p): Json<CapsPatch>) -> Response {
    if p.max_pps.is_some() || p.rate_burst.is_some() {
        let rate = p.max_pps.unwrap_or_else(|| s.rate_limiter.rate());
        let burst = p.rate_burst.unwrap_or_else(|| s.rate_limiter.burst());
        s.rate_limiter.set_rate(rate, burst);
    }
    if let Some(cap) = p.max_sessions {
        s.session_manager.set_max_sessions(cap);
    }
    if let Some(v) = p.reflected_control_max_count {
        s.caps
            .reflected_control_max_count
            .store(v, Ordering::Relaxed);
    }
    if let Some(v) = p.reflected_control_max_size {
        // This is the administrative limit. Each send also checks its route MTU.
        s.caps
            .reflected_control_max_size
            .store(v, Ordering::Relaxed);
    }
    if let Some(v) = p.reflected_control_min_interval_ns {
        s.caps
            .reflected_control_min_interval_ns
            .store(v, Ordering::Relaxed);
    }
    if let Some(v) = p.reflected_control_max_rate {
        s.caps
            .reflected_control_max_rate
            .store(v, Ordering::Relaxed);
    }
    if let Some(v) = p.reflected_control_max_volume {
        s.caps
            .reflected_control_max_volume
            .store(v, Ordering::Relaxed);
    }
    let effective = caps_json(&s);
    log::info!("control: caps updated → {effective}");
    (StatusCode::OK, Json(effective)).into_response()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainRequest {
    draining: bool,
}

async fn post_drain(State(s): State<ControlState>, Json(req): Json<DrainRequest>) -> Response {
    s.session_manager.set_draining(req.draining);
    log::info!(
        "control: drain {}",
        if req.draining { "enabled" } else { "disabled" }
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "draining": req.draining })),
    )
        .into_response()
}

async fn post_shutdown(State(s): State<ControlState>) -> StatusCode {
    log::info!("control: shutdown requested via API");
    s.shutdown_requested.store(true, Ordering::Relaxed);
    StatusCode::ACCEPTED
}

/// Handle to the running control server; dropping it does NOT stop the
/// server — call [`ControlServer::shutdown`].
pub struct ControlServer {
    cancel: CancellationToken,
    local_addr: std::net::SocketAddr,
}

impl ControlServer {
    /// Stops accepting connections and finishes in-flight requests.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// The actually-bound address (resolves port 0 to the ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }
}

/// Parsed control-plane certificate chain and private key.
///
/// Loading DER at startup reports invalid files before serving requests.
pub struct ControlTls {
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl std::fmt::Debug for ControlTls {
    /// Deliberately says nothing about the key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlTls")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl ControlTls {
    /// Loads a PEM certificate chain and private key.
    ///
    /// # Errors
    /// Returns `io::Error` with the relevant flag and path if a file is unreadable
    /// or lacks a certificate or supported private key.
    pub fn load(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<Self, std::io::Error> {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("--control-tls-cert {}: {e}", cert_path.display()),
            )
        })?;
        use rustls::pki_types::pem::PemObject;
        let chain = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("--control-tls-cert {}: {e}", cert_path.display()),
                )
            })?;
        if chain.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "--control-tls-cert {}: no CERTIFICATE block found",
                    cert_path.display()
                ),
            ));
        }

        let key_pem = std::fs::read(key_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("--control-tls-key {}: {e}", key_path.display()),
            )
        })?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "--control-tls-key {}: no usable PRIVATE KEY block found ({e})",
                    key_path.display()
                ),
            )
        })?;

        Ok(Self { chain, key })
    }

    /// Builds the rustls server configuration with an explicit crypto provider.
    /// The `metrics` feature also links aws-lc-rs, so the process default may vary.
    fn server_config(self) -> Result<rustls::ServerConfig, std::io::Error> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(self.chain, self.key)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("control-plane TLS certificate/key rejected: {e}"),
                )
            })?;
        // The control plane speaks HTTP/1.1; advertising it avoids a client
        // negotiating h2 that the router is not being served over.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Binds and spawns the control server, returning bind errors to the caller.
/// Uses HTTPS when `tls` is set; the startup log includes the scheme.
pub async fn init(
    addr: std::net::SocketAddr,
    state: ControlState,
    tls: Option<ControlTls>,
) -> Result<ControlServer, std::io::Error> {
    if !addr.ip().is_loopback() && tls.is_none() {
        log::warn!(
            "control-plane API bound to non-loopback {addr} without TLS — it \
             manages keys and shutdown, and a bearer token crosses the network \
             in clear; set --control-tls-cert/--control-tls-key, or keep it on \
             loopback behind an SSH tunnel or reverse proxy"
        );
    }
    let app = router(state);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    match tls {
        Some(tls) => {
            let config = tls.server_config()?;
            // Bind eagerly so a busy port fails here, like the plaintext path,
            // rather than inside the spawned task where nothing would notice.
            let std_listener = std::net::TcpListener::bind(addr)?;
            std_listener.set_nonblocking(true)?;
            let local_addr = std_listener.local_addr()?;
            let acceptor =
                axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config));
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            });
            tokio::spawn(async move {
                let Ok(server) = axum_server::from_tcp_rustls(std_listener, acceptor) else {
                    log::error!("control-plane TLS listener could not be adopted");
                    return;
                };
                server
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
                    .ok();
            });
            log::info!("control-plane API listening on https://{local_addr}/v1/");
            Ok(ControlServer { cancel, local_addr })
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move { cancel_clone.cancelled().await })
                    .await
                    .ok();
            });
            log::info!("control-plane API listening on http://{local_addr}/v1/");
            Ok(ControlServer { cancel, local_addr })
        }
    }
}

#[cfg(test)]
mod tests;
