//! I/O multiplexing (`ppoll`, `epoll`, `eventfd`) syscall wrappers.

use core::mem::size_of;

use crate::errno::SysResult;
use crate::fd::RawFd;
use crate::raw::{nr, syscall1, syscall2, syscall4, syscall5};
use crate::time::Timespec;

/// Data other than high-priority data may be read without blocking.
pub const POLLIN: i16 = 0x001;
/// High-priority data may be read without blocking.
pub const POLLPRI: i16 = 0x002;
/// Normal data may be written without blocking.
pub const POLLOUT: i16 = 0x004;
/// An error has occurred on the device or stream.
pub const POLLERR: i16 = 0x008;
/// The device has been disconnected.
pub const POLLHUP: i16 = 0x010;
/// The specified `fd` value is invalid.
pub const POLLNVAL: i16 = 0x020;
/// Stream socket peer closed connection, or shut down writing half of connection.
pub const POLLRDHUP: i16 = 0x2000;

/// The associated file is available for read operations.
pub const EPOLLIN: u32 = 0x001;
/// The associated file is available for write operations.
pub const EPOLLOUT: u32 = 0x004;
/// Error condition happened on the associated file descriptor.
pub const EPOLLERR: u32 = 0x008;
/// Hang up happened on the associated file descriptor.
pub const EPOLLHUP: u32 = 0x010;
/// Stream socket peer closed connection, or shut down writing half of connection.
pub const EPOLLRDHUP: u32 = 0x2000;
/// Sets one-shot behavior for the associated file descriptor.
pub const EPOLLONESHOT: u32 = 1 << 30;
/// Sets Edge Triggered behavior for the associated file descriptor.
pub const EPOLLET: u32 = 1 << 31;
/// Set the close-on-exec (`FD_CLOEXEC`) flag on the new epoll file descriptor.
pub const EPOLL_CLOEXEC: i32 = 0x80000;

/// Add an entry to the interest list of the epoll file descriptor.
pub const EPOLL_CTL_ADD: i32 = 1;
/// Remove (deregister) the target file descriptor from the epoll interest list.
pub const EPOLL_CTL_DEL: i32 = 2;
/// Change the settings associated with `fd` in the interest list.
pub const EPOLL_CTL_MOD: i32 = 3;

/// Provide semaphore-like semantics for reads from the `eventfd`.
pub const EFD_SEMAPHORE: i32 = 1;
/// Set the `O_NONBLOCK` file status flag on the open file description.
pub const EFD_NONBLOCK: i32 = 0x800;
/// Set the close-on-exec (`FD_CLOEXEC`) flag on the new `eventfd` descriptor.
pub const EFD_CLOEXEC: i32 = 0x80000;

/// Kernel `struct pollfd` descriptor entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// AArch64 16-byte `struct epoll_event` layout (`events`, 4-byte pad, 64-bit `data`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EpollEvent {
    pub events: u32,
    pub _pad: u32,
    pub data: u64,
}

const _: () = {
    assert!(size_of::<PollFd>() == 8);
    assert!(size_of::<EpollEvent>() == 16);
};

/// Waits for events on `fds` for up to `timeout_ms` milliseconds (`< 0` waits indefinitely),
/// implemented via the AArch64 `ppoll` syscall.
pub fn poll(fds: &mut [PollFd], timeout_ms: i32) -> SysResult<usize> {
    let mut ts = Timespec::default();
    let ts_ptr = if timeout_ms < 0 {
        core::ptr::null::<Timespec>()
    } else {
        let ms = i64::from(timeout_ms);
        ts.tv_sec = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1_000_000;
        core::ptr::from_ref(&ts)
    };
    let fds_ptr = if fds.is_empty() {
        core::ptr::null_mut::<PollFd>()
    } else {
        fds.as_mut_ptr()
    };
    // SAFETY: `fds_ptr` is valid for `fds.len()` entries and `ts_ptr` is either null or points
    // to the stack `ts` for the duration of the `ppoll` syscall.
    unsafe {
        syscall5(
            nr::PPOLL,
            fds_ptr as usize,
            fds.len(),
            ts_ptr as usize,
            0,
            8,
        )
    }
}

/// Creates a new epoll instance with `flags` (`0` or `EPOLL_CLOEXEC`).
pub fn epoll_create1(flags: i32) -> SysResult<RawFd> {
    // SAFETY: `EPOLL_CREATE1` takes a single scalar flags argument.
    unsafe { syscall1(nr::EPOLL_CREATE1, flags as usize).map(|v| v as RawFd) }
}

/// Controls the interest list of epoll descriptor `epfd`.
pub fn epoll_ctl(epfd: RawFd, op: i32, fd: RawFd, event: Option<&EpollEvent>) -> SysResult<()> {
    let ev_ptr = event.map_or(0, |ev| core::ptr::from_ref(ev) as usize);
    // SAFETY: `ev_ptr` is either 0 (null, e.g. for `EPOLL_CTL_DEL`) or a valid reference to `EpollEvent`.
    unsafe {
        syscall4(
            nr::EPOLL_CTL,
            epfd as usize,
            op as usize,
            fd as usize,
            ev_ptr,
        )?;
    }
    Ok(())
}

/// Waits for I/O events on `epfd` using `epoll_pwait2` with an optional nanosecond `timeout`.
pub fn epoll_wait(
    epfd: RawFd,
    events: &mut [EpollEvent],
    timeout: Option<&Timespec>,
) -> SysResult<usize> {
    let ts_ptr = timeout.map_or(0, |t| core::ptr::from_ref(t) as usize);
    // SAFETY: `events` is a valid mutable slice of `EpollEvent` and `ts_ptr` is null or valid.
    unsafe {
        syscall6_epoll_pwait2(
            epfd as usize,
            events.as_mut_ptr() as usize,
            events.len(),
            ts_ptr,
        )
    }
}

#[inline]
unsafe fn syscall6_epoll_pwait2(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout_ptr: usize,
) -> SysResult<usize> {
    // SAFETY: Caller ensures `events_ptr` and `timeout_ptr` are valid for the kernel read/write.
    unsafe {
        crate::raw::syscall6(
            nr::EPOLL_PWAIT2,
            epfd,
            events_ptr,
            maxevents,
            timeout_ptr,
            0,
            8,
        )
    }
}

/// Creates an `eventfd` object initialized to `initval` with `flags`.
pub fn eventfd(initval: u32, flags: i32) -> SysResult<RawFd> {
    // SAFETY: `EVENTFD2` takes two scalar integer arguments.
    unsafe { syscall2(nr::EVENTFD2, initval as usize, flags as usize).map(|v| v as RawFd) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::with_mock_syscall;

    #[test]
    fn poll_converts_timeout_ms_to_ppoll_timespec() {
        let mut fds = [PollFd {
            fd: 3,
            events: POLLIN,
            revents: 0,
        }];

        let ready = with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::PPOLL);
                assert_eq!(args[1], 1);
                let ts_ptr = args[2] as *const Timespec;
                assert!(!ts_ptr.is_null());
                // SAFETY: `ts_ptr` points to the stack `Timespec` inside `poll`.
                let ts = unsafe { *ts_ptr };
                assert_eq!(
                    ts,
                    Timespec {
                        tv_sec: 1,
                        tv_nsec: 250_000_000,
                    }
                );
                assert_eq!(args[3], 0);
                assert_eq!(args[4], 8);
                let pfd = args[0] as *mut PollFd;
                // SAFETY: `pfd` points to `fds[0]`.
                unsafe {
                    (*pfd).revents = POLLIN;
                }
                Ok(1)
            },
            || poll(&mut fds, 1250).unwrap(),
        );
        assert_eq!(ready, 1);
        assert_eq!(fds[0].revents, POLLIN);

        // Negative timeout passes a null `Timespec` pointer for infinite wait.
        with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::PPOLL);
                assert_eq!(args[2], 0);
                Ok(0)
            },
            || {
                assert_eq!(poll(&mut fds, -1).unwrap(), 0);
            },
        );
    }
}
