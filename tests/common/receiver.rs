//! Retain the UDP port across startup for fixtures that inspect shared state
//! or configure exact provisioned endpoints. One current-thread runtime owns
//! the receiver. Startup waits for socket metadata setup without sending any
//! traffic; teardown cancels, bounds draining, and joins that thread.
#![allow(dead_code)] // Integration targets use different helper fields/methods.

use stamp_suite::{configuration::Configuration, receiver};
use std::{
    cell::RefCell,
    future::{poll_fn, Future},
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct Receiver {
    pub shared: Arc<receiver::ReceiverSharedState>,
    pub address: SocketAddr,
    task: RefCell<Option<JoinHandle<Result<(), String>>>>,
}

impl Receiver {
    pub fn start(bind: SocketAddr, configure: impl FnOnce(SocketAddr) -> Configuration) -> Self {
        let socket = UdpSocket::bind(bind).expect("bind fixture receiver");
        Self::start_with_socket(socket, configure)
    }

    pub fn start_with_socket(
        socket: UdpSocket,
        configure: impl FnOnce(SocketAddr) -> Configuration,
    ) -> Self {
        let address = socket.local_addr().unwrap();
        let conf = configure(address);
        conf.validate().expect("validate fixture receiver");
        let shared = Arc::new(receiver::create_shared_state(&conf).expect("create fixture state"));
        let task_shared = Arc::clone(&shared);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let task = thread::Builder::new().name("fixture-receiver".into()).spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
                .build().map_err(|e| format!("receiver runtime: {e}"))?;
            runtime.block_on(async {
                let receive = receiver::run_receiver_with_socket(&conf, &task_shared, socket);
                tokio::pin!(receive);
                let mut ready = Some(ready_tx);
                let receive = poll_fn(|cx| {
                    // The nix receiver configures its socket before its first
                    // suspension. Darwin attaches TTL metadata at arrival, so
                    // callers must not send while that setup is still pending.
                    let result = receive.as_mut().poll(cx);
                    if let Some(ready) = ready.take() {
                        // Also unblock on a startup error; stop/assert_running
                        // retain responsibility for reporting that result.
                        let _ = ready.send(());
                    }
                    result
                });
                tokio::pin!(receive);
                tokio::select! {
                    result = &mut receive => result.map_err(|e| e.to_string()),
                    _ = task_shared.shutdown.cancelled() => {
                        tokio::time::timeout(Duration::from_secs(2), receive).await
                            .map_err(|_| "fixture receiver did not stop within two seconds".to_string())?
                            .map_err(|e| e.to_string())
                    }
                }
            })
        }).expect("spawn fixture receiver thread");
        let server = Self {
            shared,
            address,
            task: RefCell::new(Some(task)),
        };
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("fixture receiver did not finish initial socket setup");
        server
    }

    pub fn assert_running(&self) {
        let finished = self.task.borrow().as_ref().unwrap().is_finished();
        if finished {
            let task = self.task.borrow_mut().take().unwrap();
            panic!("fixture receiver exited: {:?}", task.join());
        }
    }

    /// Cancel, drain and join, reporting a startup/runtime/teardown failure.
    /// The thread's runtime and receiver socket are dropped before join returns.
    pub fn stop(mut self) -> Result<(), String> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), String> {
        self.shared.shutdown.cancel();
        match self.task.get_mut().take() {
            Some(task) => task
                .join()
                .map_err(|_| "fixture receiver thread panicked".to_string())?,
            None => Ok(()),
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // Best-effort fallback during unwinding. Tests that assert clean exit
        // call stop explicitly so errors cannot be hidden by Drop.
        let _ = self.stop_inner();
    }
}
