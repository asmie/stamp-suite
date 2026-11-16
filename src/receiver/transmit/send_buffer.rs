//! Darwin rejects atomic datagrams larger than SO_SNDBUF, independently of MTU.
use std::io;

// Bound growth to one maximum UDP datagram plus ancillary/accounting space.
const DATAGRAM_BUFFER: usize = 128 * 1024;

#[derive(Default)]
pub(super) struct SendBuffer {
    capacity: Option<usize>,
}

impl SendBuffer {
    pub(super) fn ensure(
        &mut self,
        payload: usize,
        mut get: impl FnMut() -> io::Result<usize>,
        mut set: impl FnMut(usize) -> io::Result<()>,
    ) -> io::Result<()> {
        if payload > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds wire limit",
            ));
        }
        if self.capacity.is_some_and(|size| size >= payload) {
            return Ok(());
        }
        // A failed query, setter or readback must not establish capacity.
        self.capacity = None;
        let mut capacity = get()?;
        if capacity < payload {
            set(DATAGRAM_BUFFER)?;
            capacity = get()?;
            if capacity < payload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP send buffer cannot hold reply",
                ));
            }
        }
        self.capacity = Some(capacity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn small_darwin_buffer_grows_once_and_never_shrinks_or_overrides_mtu() {
        let kernel = Cell::new(9216);
        let writes = Cell::new(0);
        let reads = Cell::new(0);
        let mut buffer = SendBuffer::default();
        for size in [44, 112, 9216, 16_336, 65_527, 44] {
            buffer
                .ensure(
                    size,
                    || {
                        reads.set(reads.get() + 1);
                        Ok(kernel.get())
                    },
                    |value| {
                        assert_eq!(value, DATAGRAM_BUFFER);
                        writes.set(writes.get() + 1);
                        kernel.set(value);
                        Ok(())
                    },
                )
                .unwrap();
            // Models Darwin's independent atomic-send limit. Nothing changes
            // the payload, route MTU, signatures or fragmentation settings.
            assert!(size <= kernel.get());
        }
        assert_eq!(writes.get(), 1);
        assert_eq!(reads.get(), 3);
        assert_eq!(kernel.get(), DATAGRAM_BUFFER);
        let mut large = SendBuffer::default();
        large
            .ensure(
                65_527,
                || Ok(256 * 1024),
                |_| panic!("must not shrink existing buffer"),
            )
            .unwrap();
    }

    #[test]
    fn failed_or_ignored_buffer_updates_never_cache_success() {
        for failure in 0..4 {
            let mut buffer = SendBuffer::default();
            let reads = Cell::new(0);
            let result = buffer.ensure(
                16_336,
                || {
                    reads.set(reads.get() + 1);
                    if failure == 0 || (failure == 2 && reads.get() == 2) {
                        Err(io::ErrorKind::PermissionDenied.into())
                    } else {
                        Ok(9216)
                    }
                },
                |_| {
                    if failure == 1 {
                        Err(io::ErrorKind::PermissionDenied.into())
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            assert!(buffer.capacity.is_none());
            buffer
                .ensure(
                    16_336,
                    || Ok(DATAGRAM_BUFFER),
                    |_| panic!("already sufficient"),
                )
                .unwrap();
        }
        let mut buffer = SendBuffer::default();
        assert_eq!(
            buffer
                .ensure(
                    65_536,
                    || panic!("invalid payload queried"),
                    |_| panic!("invalid payload grew buffer")
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
