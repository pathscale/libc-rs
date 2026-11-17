//! Unikernel stream channel I/O operations.

use crate::clock::Deadline;
use crate::status::{Result, Status};
use crate::trap::{Op, invoke, invoke_unit};

/// Maximum number of bytes transferred in a single `Op::Read` or `Op::Write` trap.
pub const MAX_STREAM_IO: usize = 4096;

/// Opaque handle to a unikernel stream channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Channel(pub u64);

impl Channel {
    /// Control channel.
    pub const CONTROL: Self = Self(0);
    /// Bootstrap channel.
    pub const BOOTSTRAP: Self = Self(1);
    /// Default service channel.
    pub const SERVICE: Self = Self(2);
}

/// Marks `channel` as listening for incoming connections.
pub fn listen(channel: Channel) -> Result<()> {
    invoke_unit(Op::Listen, [channel.0, 0, 0, 0])
}

/// Connects to the unikernel control channel.
pub fn connect_control() -> Result<()> {
    invoke_unit(Op::ConnectControl, [0; 4])
}

/// Accepts a connection on `channel` before `deadline`.
pub fn accept(channel: Channel, deadline: Deadline) -> Result<()> {
    invoke_unit(Op::Accept, [channel.0, deadline.raw_ns(), 0, 0])
}

/// Reads up to `out.len().min(MAX_STREAM_IO)` bytes from `channel` before `deadline`.
pub fn read(channel: Channel, out: &mut [u8], deadline: Deadline) -> Result<usize> {
    if out.is_empty() {
        return Err(Status::Invalid);
    }
    let length = out.len().min(MAX_STREAM_IO);
    let used = invoke(
        Op::Read,
        [
            channel.0,
            out.as_mut_ptr() as u64,
            length as u64,
            deadline.raw_ns(),
        ],
    )?;
    let used = usize::try_from(used).map_err(|_| Status::Protocol)?;
    if used > length {
        return Err(Status::Protocol);
    }
    Ok(used)
}

/// Writes up to `input.len().min(MAX_STREAM_IO)` bytes to `channel` before `deadline`.
pub fn write(channel: Channel, input: &[u8], deadline: Deadline) -> Result<usize> {
    if input.is_empty() {
        return Err(Status::Invalid);
    }
    let length = input.len().min(MAX_STREAM_IO);
    let used = invoke(
        Op::Write,
        [
            channel.0,
            input.as_ptr() as u64,
            length as u64,
            deadline.raw_ns(),
        ],
    )?;
    let used = usize::try_from(used).map_err(|_| Status::Protocol)?;
    if used == 0 || used > length {
        return Err(Status::Protocol);
    }
    Ok(used)
}

/// Reads enough bytes from `channel` to fill `out`, returning [`Status::Closed`] on EOF.
pub fn read_exact(channel: Channel, mut out: &mut [u8], deadline: Deadline) -> Result<()> {
    while !out.is_empty() {
        let n = read(channel, out, deadline)?;
        if n == 0 {
            return Err(Status::Closed);
        }
        out = &mut out[n..];
    }
    Ok(())
}

/// Writes all bytes in `input` to `channel` before `deadline`.
pub fn write_all(channel: Channel, mut input: &[u8], deadline: Deadline) -> Result<()> {
    while !input.is_empty() {
        let n = write(channel, input, deadline)?;
        input = &input[n..];
    }
    Ok(())
}

/// Closes `channel`.
pub fn close(channel: Channel) -> Result<()> {
    invoke_unit(Op::Close, [channel.0, 0, 0, 0])
}

/// Retires [`Channel::BOOTSTRAP`].
pub fn retire_bootstrap() -> Result<()> {
    invoke_unit(Op::RetireBootstrap, [Channel::BOOTSTRAP.0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::trap::with_mock_trap;

    #[test]
    fn read_exact_handles_partial_reads_and_eof() {
        static STEP: AtomicUsize = AtomicUsize::new(0);
        STEP.store(0, Ordering::SeqCst);

        let mut buf = [0u8; 6];
        let res = with_mock_trap(
            |_, op, args| {
                assert_eq!(Op::decode(op), Some(Op::Read));
                let ptr = args[1] as *mut u8;
                let len = args[2] as usize;
                let s = STEP.fetch_add(1, Ordering::SeqCst);
                if s == 0 {
                    assert!(len >= 2);
                    // SAFETY: `ptr` points to `buf` in this test.
                    unsafe {
                        *ptr = 10;
                        *ptr.add(1) = 20;
                    }
                    Ok(2)
                } else {
                    Ok(0)
                }
            },
            || read_exact(Channel::SERVICE, &mut buf, Deadline::IMMEDIATE),
        );
        assert_eq!(res, Err(Status::Closed));
        assert_eq!(&buf[..2], &[10, 20]);
    }

    #[test]
    fn write_all_chunks_across_max_stream_io() {
        static TOTAL_WRITTEN: AtomicUsize = AtomicUsize::new(0);
        TOTAL_WRITTEN.store(0, Ordering::SeqCst);

        let data = [0xABu8; MAX_STREAM_IO + 500];
        let res = with_mock_trap(
            |_, op, args| {
                assert_eq!(Op::decode(op), Some(Op::Write));
                let len = args[2] as usize;
                assert!(len <= MAX_STREAM_IO);
                let chunk = len.min(1024);
                TOTAL_WRITTEN.fetch_add(chunk, Ordering::SeqCst);
                Ok(chunk as u64)
            },
            || write_all(Channel::CONTROL, &data, Deadline::IMMEDIATE),
        );
        assert_eq!(res, Ok(()));
        assert_eq!(TOTAL_WRITTEN.load(Ordering::SeqCst), data.len());
    }
}
