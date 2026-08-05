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

/// Binds and spawns the control server. Fail-fast on bind errors
/// (`main.rs` exits when the operator asked for a control plane it
/// cannot provide, matching the metrics server contract).
pub async fn init(
    addr: std::net::SocketAddr,
    state: ControlState,
) -> Result<ControlServer, std::io::Error> {
    if !addr.ip().is_loopback() {
        log::warn!(
            "control-plane API bound to non-loopback {addr} — it manages keys \
             and shutdown; ensure network-level access control or set \
             --control-token-file"
        );
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let app = router(state);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { cancel_clone.cancelled().await })
            .await
            .ok();
    });
    log::info!("control-plane API listening on http://{local_addr}/v1/");
    Ok(ControlServer { cancel, local_addr })
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
