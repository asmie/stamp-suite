//! A spawned stamp-suite process that is always reaped, with a bounded wait.
#![allow(dead_code)] // Each integration target uses a different helper subset.

use std::{
    io::Read,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// A child with piped stdout and stderr, each drained on its own thread. A
/// child that writes a lot (for example with `RUST_LOG=debug`) can therefore
/// never block on a full pipe. Dropping it kills and reaps the child.
pub struct ChildProcess {
    child: Option<Child>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

fn drain(stream: Option<impl Read + Send + 'static>) -> Option<JoinHandle<Vec<u8>>> {
    stream.map(|mut stream| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            bytes
        })
    })
}

impl ChildProcess {
    /// Spawns `command` with stdout and stderr piped.
    pub fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child process");
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        Self {
            child: Some(child),
            stdout,
            stderr,
        }
    }

    pub fn id(&self) -> u32 {
        self.child.as_ref().expect("child still owned").id()
    }

    /// Returns the exit status if the child has already exited.
    pub fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child
            .as_mut()
            .expect("child still owned")
            .try_wait()
            .unwrap()
    }

    /// Waits up to `timeout` for the child to exit and returns its status and
    /// complete output. A child still running at the deadline is killed and
    /// reaped, and the call panics with the end of its stderr.
    pub fn finish(mut self, timeout: Duration) -> Output {
        let deadline = Instant::now() + timeout;
        let mut child = self.child.take().expect("child still owned");
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let join = |handle: Option<JoinHandle<Vec<u8>>>| {
            handle.map(|h| h.join().unwrap()).unwrap_or_default()
        };
        let stdout = join(self.stdout.take());
        let stderr = join(self.stderr.take());
        let Some(status) = status else {
            let tail = &stderr[stderr.len().saturating_sub(4096)..];
            panic!(
                "child did not exit within {timeout:?}; stderr tail:\n{}",
                String::from_utf8_lossy(tail)
            );
        };
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
