//! Process shutdown. SIGINT and SIGTERM (Ctrl-C on Windows) and the control
//! API's shutdown endpoint cancel one token; the reflector backends and the
//! sender stop when it is cancelled. Metrics and control tasks end with the
//! runtime. SNMP uses a child token and cancels its blocking worker when its
//! handle is dropped; its socket operations have bounded cancellation ticks.

pub use tokio_util::sync::CancellationToken;

/// Cancels `token` on SIGINT or SIGTERM (Ctrl-C on non-Unix platforms).
///
/// The handlers are registered before this returns, so a signal that
/// arrives during the rest of startup is not lost to the default handler.
/// Must be called inside a Tokio runtime.
pub fn cancel_on_signal(token: CancellationToken) -> tokio::task::JoinHandle<()> {
    #[cfg(unix)]
    let signals = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        )
    };
    tokio::spawn(async move {
        #[cfg(unix)]
        if let (Ok(mut interrupt), Ok(mut terminate)) = signals {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
                _ = token.cancelled() => return,
            }
            token.cancel();
            return;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => token.cancel(),
            _ = token.cancelled() => {}
        }
    })
}
