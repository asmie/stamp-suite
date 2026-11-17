//! Errors that decide what the send loop tries next.

use super::*;

/// The OS error a datagram send returns when the packet exceeds the route MTU
/// with fragmentation disabled.
#[cfg(unix)]
pub(super) const MESSAGE_TOO_LARGE: i32 = nix::libc::EMSGSIZE;
#[cfg(windows)]
pub(super) const MESSAGE_TOO_LARGE: i32 = windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE;

pub(super) fn is_message_too_large(error: &io::Error) -> bool {
    error.raw_os_error() == Some(MESSAGE_TOO_LARGE)
}

/// Produce the same platform error consumed by the production MTU retry path.
#[cfg(test)]
pub(super) fn message_too_large_error() -> io::Error {
    io::Error::from_raw_os_error(MESSAGE_TOO_LARGE)
}

#[derive(Debug)]
pub(super) struct CosApplyError(io::Error);

impl std::fmt::Display for CosApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot apply reply CoS: {}", self.0)
    }
}

impl std::error::Error for CosApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(any(not(target_os = "linux"), test))]
pub(in crate::receiver) fn cos_apply_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), CosApplyError(error))
}

pub(super) fn is_cos_apply_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<CosApplyError>())
}

/// The mandatory reply fields exceed the payload budget. No routing or CoS
/// fallback can help, so the send loop drops the reply.
#[derive(Debug)]
pub(super) struct ReplyTooLarge(&'static str);

impl std::fmt::Display for ReplyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ReplyTooLarge {}

pub(super) fn reply_too_large(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, ReplyTooLarge(reason))
}

pub(super) fn is_reply_too_large(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<ReplyTooLarge>())
}

/// A local socket setting or route-table query failed. The reply's return
/// path is not at fault, so the send loop drops the reply without setting
/// the Return Path U flag or retargeting it (RFC 9503 §4).
#[derive(Debug)]
pub(super) struct LocalSendError(io::Error);

impl std::fmt::Display for LocalSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local send setup failed: {}", self.0)
    }
}

impl std::error::Error for LocalSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(in crate::receiver) fn local_send_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), LocalSendError(error))
}

pub(super) fn is_local_send_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<LocalSendError>())
}
