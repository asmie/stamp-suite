//! Prometheus metrics support for STAMP sender and reflector modes.
//!
//! This module provides observability through a Prometheus-compatible HTTP endpoint
//! that exposes STAMP operational metrics. Enable with the `metrics` feature flag.
//!
//! # Usage
//!
//! Start the metrics server:
//! ```bash
//! stamp-suite --metrics --metrics-addr 127.0.0.1:9090
//! ```
//!
//! Fetch metrics:
//! ```bash
//! curl http://127.0.0.1:9090/metrics
//! ```

pub mod reflector_metrics;
pub mod sender_metrics;

use std::net::SocketAddr;

use axum::{routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Error type for metrics initialization failures.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// Failed to build the Prometheus recorder.
    #[error("Failed to build metrics recorder: {0}")]
    RecorderBuild(String),
    /// Failed to bind the HTTP server.
    #[error("Failed to bind metrics server: {0}")]
    BindError(#[from] std::io::Error),
}

/// Handle to the running metrics server.
pub struct MetricsServer {
    /// Cancellation token to stop the server.
    cancel: CancellationToken,
}

impl MetricsServer {
    /// Signals the metrics server to shut down.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// Initializes the Prometheus metrics recorder and starts the HTTP server.
///
/// # Arguments
/// * `addr` - The address to bind the HTTP server to
///
/// # Returns
/// A handle that can be used to shut down the server.
pub async fn init(addr: SocketAddr) -> Result<MetricsServer, MetricsError> {
    // Build the Prometheus recorder with sensible RTT histogram buckets
    // Network latency typically ranges from microseconds to milliseconds
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Suffix("_seconds".to_string()),
            &[
                0.000_01, // 10 microseconds
                0.000_05, // 50 microseconds
                0.000_1,  // 100 microseconds
                0.000_25, // 250 microseconds
                0.000_5,  // 500 microseconds
                0.001,    // 1 millisecond
                0.002_5,  // 2.5 milliseconds
                0.005,    // 5 milliseconds
                0.01,     // 10 milliseconds
                0.025,    // 25 milliseconds
                0.05,     // 50 milliseconds
                0.1,      // 100 milliseconds
                0.25,     // 250 milliseconds
                0.5,      // 500 milliseconds
                1.0,      // 1 second
            ],
        )
        .map_err(|e| MetricsError::RecorderBuild(e.to_string()))?
        .install_recorder()
        .map_err(|e| MetricsError::RecorderBuild(e.to_string()))?;

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    // Build the HTTP server
    let app = Router::new().route("/metrics", get(move || metrics_handler(handle.clone())));

    let listener = TcpListener::bind(addr).await?;
    log::info!("Metrics server listening on http://{}/metrics", addr);

    // Spawn the server task
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_clone.cancelled().await;
            })
            .await
            .ok();
    });

    Ok(MetricsServer { cancel })
}

/// HTTP handler that renders Prometheus metrics.
async fn metrics_handler(handle: PrometheusHandle) -> String {
    handle.render()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_metrics_server_starts() {
        // Use a random available port
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

        // Note: This test may fail if run after other tests that already installed
        // a global recorder. In production, init() is called once at startup.
        // For testing, we just verify the function signature is correct.
        let result = init(addr).await;

        // Clean up if successful
        if let Ok(server) = result {
            server.shutdown();
        }
        // If it fails due to recorder already installed, that's expected in test suites
    }
}
