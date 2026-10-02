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
        shutdown: crate::shutdown::CancellationToken::new(),
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

// TLS transport tests using real sockets and handshakes.

/// Generates `(ca_cert, leaf_cert, leaf_key)` with `openssl`.
///
/// Use a separate leaf because rustls rejects CA certificates as server leaves.
/// Generate per run to avoid committed keys and expired fixtures.
/// Returns `None` when `openssl` is unavailable.
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
                rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
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
    // RFC 10052 §5 detection is observable without a log-level change.
    assert_eq!(v["counters"]["packets_replayed"], 0);
    assert_eq!(v["counters"]["packets_reordered"], 0);
}

#[tokio::test]
async fn sessions_lists_and_expires() {
    let state = test_state();
    let addr: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
    state.session_manager.get_or_create_session(addr).unwrap();
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
async fn sessions_expiry_requires_disambiguation_for_shared_source() {
    let state = test_state();
    let key: crate::session::SessionKey = "42,127.0.0.1:4000,127.0.0.1:862,7".parse().unwrap();
    let first = state.session_manager.get_or_create_session(key).unwrap();
    state
        .session_manager
        .get_or_create_session(crate::session::SessionKey { ssid: 43, ..key })
        .unwrap();
    let app = router(state.clone());
    let entries = get_json(&app, "/v1/sessions").await;
    assert_eq!(entries.as_array().unwrap().len(), 2);
    for entry in entries.as_array().unwrap() {
        assert_eq!(entry["local"], "127.0.0.1:862");
        assert_eq!(entry["sender_micro_session_id"], 7);
        assert!(entry["ssid"] == 42 || entry["ssid"] == 43);
    }
    for (body, expected) in [
        (
            serde_json::json!({"client": key.client}),
            StatusCode::CONFLICT,
        ),
        (
            serde_json::json!({"client": key.client, "session_id": first.get_id()}),
            StatusCode::OK,
        ),
        (
            serde_json::json!({"client": key.client, "session_id": first.get_id()}),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/expire")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(state.session_manager.session_count(), 1);
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

/// PATCH stores the administrative cap; the send path enforces route MTU.
#[tokio::test]
async fn caps_patch_updates_administrative_size_limit() {
    let state = test_state();
    let app = router(state.clone());

    let res = app
        .clone()
        .oneshot(
            Request::patch("/v1/caps")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reflected_control_max_size":65535}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["reflected_control_max_size"], 65535,
        "PATCH reports the administrative cap, independent of reply routes"
    );
    assert_eq!(
        state
            .caps
            .reflected_control_max_size
            .load(Ordering::Relaxed),
        65535
    );

    // Lowering the administrative cap works verbatim.
    let res = app
        .clone()
        .oneshot(
            Request::patch("/v1/caps")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reflected_control_max_size":576}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        state
            .caps
            .reflected_control_max_size
            .load(Ordering::Relaxed),
        576
    );
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
    assert!(state.shutdown.is_cancelled());
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
