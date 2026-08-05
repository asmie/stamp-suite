//! Runtime control-plane REST API (feature "control", reflector only).
//!
//! A localhost axum server for runtime session/key management, cap
//! tuning, live status, and drain/shutdown. Mirrors the lifecycle
//! pattern of `crate::metrics` (bind fail-fast, spawned task,
//! CancellationToken) and the state threading of `crate::snmp`.
//! `doc/control-plane.md` is the authoritative design.
//!
//! Security: bind to loopback (default) or set a bearer token; key
//! material is write-only — never returned, never logged.

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
        "counters": {
            "packets_received": s.counters.packets_received.load(Ordering::Relaxed),
            "packets_reflected": s.counters.packets_reflected.load(Ordering::Relaxed),
            "packets_dropped": s.counters.packets_dropped.load(Ordering::Relaxed),
            "packets_rate_limited": s.counters.packets_rate_limited.load(Ordering::Relaxed),
            // draft-ietf-ippm-asymmetrical-pkts-14 §5 replay detection.
            "packets_replayed": s.counters.packets_replayed.load(Ordering::Relaxed),
            "packets_reordered": s.counters.packets_reordered.load(Ordering::Relaxed),
        },
    }))
}

/// Wire form of a session-table entry (Instant → idle seconds).
#[derive(serde::Serialize)]
struct SessionDto {
    client: String,
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
}

async fn post_expire_session(
    State(s): State<ControlState>,
    Json(req): Json<ExpireRequest>,
) -> Response {
    if s.session_manager.expire_session(req.client) {
        log::info!("control: session expired client={}", req.client);
        StatusCode::OK.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "no session for that client")
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
        s.caps
            .reflected_control_max_size
            .store(v, Ordering::Relaxed);
    }
    if let Some(v) = p.reflected_control_min_interval_ns {
        s.caps
            .reflected_control_min_interval_ns
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

/// A loaded server certificate chain and private key for the control plane.
///
/// Held as parsed DER rather than paths so a bad file fails at startup, next to
/// the operator who wrote the flag, instead of on the first request.
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
    /// Loads a PEM certificate chain and private key from disk.
    ///
    /// # Errors
    /// Returns an `io::Error` describing which file failed and why: unreadable,
    /// containing no certificate, or containing no supported private key. The
    /// messages name the flag so the operator knows which path to fix.
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

    /// Builds the rustls server configuration.
    ///
    /// The crypto provider is passed explicitly rather than taken from rustls's
    /// process-wide default. With the `metrics` feature also enabled this binary
    /// links a second provider (aws-lc-rs, via hyper-rustls), and asking for
    /// "the default" would then depend on which crate installed one first.
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

/// Binds and spawns the control server. Fail-fast on bind errors
/// (`main.rs` exits when the operator asked for a control plane it
/// cannot provide, matching the metrics server contract).
///
/// With `tls` set the listener speaks HTTPS; the scheme in the startup log
/// reflects what is actually being served, so an operator can tell at a glance.
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
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    fn test_state() -> ControlState {
        ControlState {
            counters: Arc::new(crate::receiver::ReflectorCounters::new()),
            session_manager: Arc::new(crate::session::SessionManager::new(None, None)),
            start_time: std::time::Instant::now(),
            rate_limiter: Arc::new(crate::receiver::RateLimiter::with_burst(0, 0)),
            hmac_keys: Arc::new(std::sync::RwLock::new(None)),
            caps: Arc::new(crate::receiver::RuntimeCaps::from_defaults()),
            shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            token: None,
        }
    }

    async fn get_json(app: &axum::Router, path: &str) -> serde_json::Value {
        let res = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "GET {path}");
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    // -----------------------------------------------------------------------
    // TLS. These use a real socket and a real handshake, unlike the
    // tower-oneshot tests above — the point is that the transport works, which
    // an in-process router call cannot show.

    /// Generates a throwaway CA and a leaf certificate signed by it, using
    /// `openssl`. Returns `(ca_cert, leaf_cert, leaf_key)`.
    ///
    /// A CA plus leaf rather than one self-signed certificate, because rustls
    /// correctly refuses a certificate with `CA:TRUE` as a server's end-entity
    /// cert (`CaUsedAsEndEntity`) — a self-signed cert cannot be both the trust
    /// anchor and the leaf. Generated per run rather than committed: a private
    /// key in the repository trips secret scanners and would eventually expire.
    /// Returns `None` when `openssl` is unavailable, so the test skips instead
    /// of failing on a machine that lacks the tool.
    fn generate_test_chain(
        dir: &std::path::Path,
    ) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
        let run = |args: Vec<std::ffi::OsString>| -> bool {
            std::process::Command::new("openssl")
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        let osv = |s: &str| std::ffi::OsString::from(s);
        let osp = |p: &std::path::Path| p.as_os_str().to_os_string();

        let ca_key = dir.join("ca.key");
        let ca_cert = dir.join("ca.pem");
        let leaf_key = dir.join("leaf.key");
        let leaf_csr = dir.join("leaf.csr");
        let leaf_cert = dir.join("leaf.pem");
        let ext_file = dir.join("leaf.ext");

        std::fs::write(
            &ext_file,
            b"basicConstraints=critical,CA:FALSE\n              keyUsage=critical,digitalSignature,keyEncipherment\n              extendedKeyUsage=serverAuth\n              subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
        .ok()?;

        // Self-signed CA.
        if !run(vec![
            osv("req"),
            osv("-x509"),
            osv("-newkey"),
            osv("rsa:2048"),
            osv("-nodes"),
            osv("-keyout"),
            osp(&ca_key),
            osv("-out"),
            osp(&ca_cert),
            osv("-days"),
            osv("3650"),
            osv("-subj"),
            osv("/CN=stamp-suite-test-ca"),
            osv("-addext"),
            osv("basicConstraints=critical,CA:TRUE"),
        ]) {
            return None;
        }
        // Leaf key + CSR.
        if !run(vec![
            osv("req"),
            osv("-newkey"),
            osv("rsa:2048"),
            osv("-nodes"),
            osv("-keyout"),
            osp(&leaf_key),
            osv("-out"),
            osp(&leaf_csr),
            osv("-subj"),
            osv("/CN=localhost"),
        ]) {
            return None;
        }
        // Sign the leaf with the CA, adding the SAN the client will check.
        if !run(vec![
            osv("x509"),
            osv("-req"),
            osv("-in"),
            osp(&leaf_csr),
            osv("-CA"),
            osp(&ca_cert),
            osv("-CAkey"),
            osp(&ca_key),
            osv("-out"),
            osp(&leaf_cert),
            osv("-days"),
            osv("3650"),
            osv("-extfile"),
            osp(&ext_file),
        ]) {
            return None;
        }
        (leaf_cert.exists() && leaf_key.exists() && ca_cert.exists())
            .then_some((ca_cert, leaf_cert, leaf_key))
    }

    #[test]
    fn tls_load_reports_which_file_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.pem");
        let err = ControlTls::load(&missing, &missing).expect_err("missing cert must fail");
        assert!(
            err.to_string().contains("--control-tls-cert"),
            "the error must name the flag: {err}"
        );

        // A readable file that holds no certificate.
        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"not a pem file\n").unwrap();
        let err = ControlTls::load(&junk, &junk).expect_err("a non-PEM cert must fail");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "the error must say what was missing: {err}"
        );
    }

    #[test]
    fn tls_load_rejects_a_cert_without_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let Some((_ca, cert, _key)) = generate_test_chain(dir.path()) else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        // Point the key argument at the certificate: valid PEM, wrong block.
        let err = ControlTls::load(&cert, &cert).expect_err("a cert is not a key");
        assert!(
            err.to_string().contains("--control-tls-key"),
            "the error must name the key flag: {err}"
        );
    }

    #[test]
    fn tls_debug_does_not_leak_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let Some((_ca, cert, key)) = generate_test_chain(dir.path()) else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let tls = ControlTls::load(&cert, &key).expect("generated material must load");
        let rendered = format!("{tls:?}");
        assert!(rendered.contains("certificates"), "got: {rendered}");
        assert!(
            !rendered.to_ascii_lowercase().contains("key"),
            "Debug must not mention key material: {rendered}"
        );
    }

    #[tokio::test]
    async fn tls_serves_https_and_enforces_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let Some((ca_path, cert_path, key_path)) = generate_test_chain(dir.path()) else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let tls = ControlTls::load(&cert_path, &key_path).expect("material must load");

        let mut state = test_state();
        state.token = Some("s3cret".to_string());
        let server = init("127.0.0.1:0".parse().unwrap(), state, Some(tls))
            .await
            .expect("TLS control plane must bind");
        let addr = server.local_addr();

        // Trust the CA that signed the leaf the server presents.
        let cert_pem = std::fs::read(&ca_path).unwrap();
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
            roots.add(cert.unwrap()).unwrap();
        }

        // A blocking rustls client on a worker thread: this exercises the real
        // handshake rather than the router in isolation.
        let request = |token: Option<&'static str>| {
            let roots = roots.clone();
            tokio::task::spawn_blocking(move || {
                let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
                let config = rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                let mut conn =
                    rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
                        .unwrap();
                let mut sock = std::net::TcpStream::connect(addr).unwrap();
                let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

                use std::io::{Read, Write};
                let auth = token
                    .map(|t| format!("Authorization: Bearer {t}\r\n"))
                    .unwrap_or_default();
                let req = format!(
                    "GET /v1/status HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n"
                );
                tls_stream.write_all(req.as_bytes()).unwrap();
                let mut response = Vec::new();
                // A clean close arrives as CloseNotify or an abrupt EOF
                // depending on timing; either is fine once we have the status.
                let _ = tls_stream.read_to_end(&mut response);
                String::from_utf8_lossy(&response).to_string()
            })
        };

        let authorized = request(Some("s3cret")).await.unwrap();
        assert!(
            authorized.starts_with("HTTP/1.1 200"),
            "an authorized HTTPS request must succeed, got: {}",
            authorized.lines().next().unwrap_or_default()
        );
        assert!(
            authorized.contains("\"uptime_seconds\""),
            "the response body must be the status JSON"
        );

        let unauthorized = request(None).await.unwrap();
        assert!(
            unauthorized.starts_with("HTTP/1.1 401"),
            "TLS must not weaken the bearer-token check, got: {}",
            unauthorized.lines().next().unwrap_or_default()
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn status_reports_uptime_and_counters() {
        let app = router(test_state());
        let v = get_json(&app, "/v1/status").await;
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["draining"], false);
        assert!(v["uptime_seconds"].is_number());
        assert_eq!(v["counters"]["packets_received"], 0);
        assert_eq!(v["counters"]["packets_rate_limited"], 0);
        // Replay-detection counters are part of the status surface so the
        // §5 detection is observable without a log-level change.
        assert_eq!(v["counters"]["packets_replayed"], 0);
        assert_eq!(v["counters"]["packets_reordered"], 0);
    }

    #[tokio::test]
    async fn sessions_lists_and_expires() {
        let state = test_state();
        let addr: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
        state.session_manager.get_or_create_session(addr);
        let app = router(state.clone());

        let v = get_json(&app, "/v1/sessions").await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["client"], "10.0.0.1:5000");
        assert!(v[0]["idle_seconds"].is_number());

        let res = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/expire")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client":"10.0.0.1:5000"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(state.session_manager.session_count(), 0);

        // Second expire: gone → 404.
        let res = app
            .oneshot(
                Request::post("/v1/sessions/expire")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client":"10.0.0.1:5000"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn key_lifecycle() {
        let state = test_state();
        let app = router(state.clone());

        // Empty start.
        let v = get_json(&app, "/v1/keys").await;
        assert_eq!(v["default"], false);
        assert_eq!(v["ssids"].as_array().unwrap().len(), 0);

        // Add SSID 42.
        let res = app
            .clone()
            .oneshot(
                Request::put("/v1/keys/42")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"key_hex":"{}"}}"#,
                        "ab".repeat(32)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        {
            let keys = state.hmac_keys.read().unwrap();
            assert!(
                keys.as_ref().unwrap().for_ssid(42).is_some(),
                "key must be visible to the packet path"
            );
        }

        // Default key.
        let res = app
            .clone()
            .oneshot(
                Request::put("/v1/keys/default")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"key_hex":"{}"}}"#,
                        "cd".repeat(32)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let v = get_json(&app, "/v1/keys").await;
        assert_eq!(v["default"], true);
        assert_eq!(v["ssids"], serde_json::json!([42]));

        // Bad hex → 400, state unchanged.
        let res = app
            .clone()
            .oneshot(
                Request::put("/v1/keys/7")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"key_hex":"zz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Unknown body field → 400 (strict validation).
        let res = app
            .clone()
            .oneshot(
                Request::put("/v1/keys/7")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"key_hex":"ab","keyhex_typo":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Delete.
        let res = app
            .clone()
            .oneshot(Request::delete("/v1/keys/42").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let res = app
            .clone()
            .oneshot(Request::delete("/v1/keys/42").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = app
            .oneshot(
                Request::delete("/v1/keys/default")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn caps_patch_round_trip() {
        let state = test_state();
        let app = router(state.clone());

        let v = get_json(&app, "/v1/caps").await;
        assert_eq!(v["max_pps"], 0);
        assert_eq!(v["reflected_control_max_size"], 1500);

        let res = app
            .clone()
            .oneshot(
                Request::patch("/v1/caps")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"max_pps":500,"reflected_control_max_count":8,"max_sessions":100}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(state.rate_limiter.rate(), 500);
        assert_eq!(state.session_manager.max_sessions(), 100);
        assert_eq!(
            state
                .caps
                .reflected_control_max_count
                .load(Ordering::Relaxed),
            8
        );

        let v = get_json(&app, "/v1/caps").await;
        assert_eq!(v["max_pps"], 500);
        assert_eq!(v["reflected_control_max_count"], 8);
        assert_eq!(v["max_sessions"], 100);
        // Untouched field preserved.
        assert_eq!(v["reflected_control_max_size"], 1500);
    }

    #[tokio::test]
    async fn drain_and_shutdown() {
        let state = test_state();
        let app = router(state.clone());

        let res = app
            .clone()
            .oneshot(
                Request::post("/v1/drain")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"draining":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(state.session_manager.is_draining());

        let res = app
            .oneshot(Request::post("/v1/shutdown").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        assert!(state.shutdown_requested.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn token_enforced_when_configured() {
        let mut state = test_state();
        state.token = Some("s3cret".to_string());
        let app = router(state);

        let res = app
            .clone()
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = app
            .clone()
            .oneshot(
                Request::get("/v1/status")
                    .header("authorization", "Bearer wr0ng")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = app
            .oneshot(
                Request::get("/v1/status")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
