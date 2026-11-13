//! One periodic cleanup worker per reflector, with no queued scan requests.

use std::{
    io,
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{session::SessionManager, shutdown::CancellationToken};

pub(super) struct SessionCleanup {
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

fn cleanup_interval(timeout_seconds: u64) -> Option<Duration> {
    (timeout_seconds != 0).then(|| Duration::from_secs((timeout_seconds / 2).max(1)))
}

struct CancelOnPanic(CancellationToken);

impl Drop for CancelOnPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.cancel();
        }
    }
}

impl SessionCleanup {
    pub(super) fn start(
        manager: Arc<SessionManager>,
        timeout_seconds: u64,
        immediate: bool,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        Self::spawn(
            cleanup_interval(timeout_seconds),
            immediate,
            shutdown,
            move || {
                let removed = manager.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {removed} stale sessions");
                }
            },
        )
    }

    fn spawn(
        interval: Option<Duration>,
        immediate: bool,
        shutdown: CancellationToken,
        mut work: impl FnMut() + Send + 'static,
    ) -> io::Result<Self> {
        let Some(interval) = interval else {
            return Ok(Self {
                stop: None,
                worker: None,
            });
        };
        let (stop, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("stamp-cleanup".into())
            .spawn(move || {
                let failure = CancelOnPanic(shutdown);
                if immediate
                    && !failure.0.is_cancelled()
                    && matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty))
                {
                    work();
                }
                loop {
                    match receiver.recv_timeout(interval) {
                        Err(mpsc::RecvTimeoutError::Timeout) if !failure.0.is_cancelled() => work(),
                        _ => break,
                    }
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    /// Wake an idle worker and join any scan already in progress. Call after
    /// receive/transmit processing has stopped; no cleanup outlives this owner.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("session cleanup worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            log::error!("{error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(5);

    struct ReleaseOnDrop(Option<mpsc::Sender<()>>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }

    #[test]
    fn interval_disables_zero_and_preserves_half_timeout_minimum() {
        assert_eq!(cleanup_interval(0), None);
        for seconds in [1, 2, 3] {
            assert_eq!(cleanup_interval(seconds), Some(Duration::from_secs(1)));
        }
        assert_eq!(cleanup_interval(4), Some(Duration::from_secs(2)));
        assert_eq!(cleanup_interval(300), Some(Duration::from_secs(150)));
        assert_eq!(
            cleanup_interval(u64::MAX),
            Some(Duration::from_secs(u64::MAX / 2))
        );
    }

    #[test]
    fn disabled_cleanup_has_no_worker_or_retained_manager() {
        let manager = Arc::new(SessionManager::new(None, None));
        let weak = Arc::downgrade(&manager);
        let mut cleanup =
            SessionCleanup::start(manager, 0, true, CancellationToken::new()).unwrap();
        assert!(cleanup.worker.is_none() && cleanup.stop.is_none());
        assert!(weak.upgrade().is_none());
        cleanup.finish().unwrap();
    }

    #[test]
    fn delayed_worker_expires_idle_sessions_and_retires_queued_owners() {
        for client in ["127.0.0.1:4000", "[::1]:4000"] {
            let manager = Arc::new(SessionManager::new(Some(Duration::ZERO), Some(1)));
            let old = manager
                .get_or_create_session(client.parse::<std::net::SocketAddr>().unwrap())
                .unwrap();
            let copy = Arc::clone(&manager);
            let (done_tx, done_rx) = mpsc::channel();
            let shutdown = CancellationToken::new();
            let mut cleanup = SessionCleanup::spawn(
                Some(Duration::from_millis(1)),
                false,
                shutdown.clone(),
                move || {
                    done_tx.send(copy.cleanup_stale_sessions()).unwrap();
                },
            )
            .unwrap();
            assert_eq!(done_rx.recv_timeout(DEADLOCK_TIMEOUT).unwrap(), 1);
            cleanup.finish().unwrap();
            assert!(!shutdown.is_cancelled());
            assert_eq!(manager.session_count(), 0);
            assert!(old.transmission_guard().is_none());
            cleanup.finish().unwrap(); // Idempotent after joining.
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_scan_leaves_runtime_live_and_stop_prevents_catchup_scans() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut entered_tx = Some(entered_tx);
        let mut cleanup = SessionCleanup::spawn(
            Some(Duration::from_millis(1)),
            true,
            CancellationToken::new(),
            move || {
                worker_calls.fetch_add(1, Ordering::Relaxed);
                if let Some(entered) = entered_tx.take() {
                    let _ = entered.send(());
                    release_rx.recv_timeout(DEADLOCK_TIMEOUT).unwrap();
                }
            },
        )
        .unwrap();
        // Release work before cleanup's Drop during unwinding as well.
        let release = ReleaseOnDrop(Some(release_tx));
        tokio::time::timeout(DEADLOCK_TIMEOUT, entered_rx)
            .await
            .unwrap()
            .unwrap();
        let value = tokio::time::timeout(
            DEADLOCK_TIMEOUT,
            tokio::spawn(async {
                tokio::task::yield_now().await;
                7
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        // Stop while the first scan is blocked, then allow it to finish.
        cleanup.stop.as_ref().unwrap().send(()).unwrap();
        drop(release);
        cleanup.finish().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn panic_stops_only_the_reflector_child_and_is_reported_by_join() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        let mut cleanup =
            SessionCleanup::spawn(Some(Duration::from_secs(3600)), true, child.clone(), || {
                panic!("injected cleanup failure")
            })
            .unwrap();
        tokio::time::timeout(DEADLOCK_TIMEOUT, child.cancelled())
            .await
            .unwrap();
        assert!(!parent.is_cancelled());
        assert!(cleanup.finish().is_err());
        assert!(cleanup.worker.is_none());
    }

    #[test]
    fn drop_wakes_and_joins_an_idle_worker() {
        let manager = Arc::new(SessionManager::new(None, None));
        let weak = Arc::downgrade(&manager);
        let cleanup =
            SessionCleanup::start(manager, u64::MAX, false, CancellationToken::new()).unwrap();
        drop(cleanup);
        assert!(
            weak.upgrade().is_none(),
            "worker must release its captured manager before Drop returns"
        );
    }

    #[test]
    fn cancelled_reflector_does_not_start_a_scan() {
        let child = CancellationToken::new();
        child.cancel();
        let mut cleanup =
            SessionCleanup::spawn(Some(Duration::from_millis(1)), true, child, || {
                panic!("scan started after shutdown")
            })
            .unwrap();
        cleanup.finish().unwrap();
    }
}
