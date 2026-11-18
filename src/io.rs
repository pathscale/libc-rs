//! File descriptor I/O, duplication, pipes, `fcntl`, and `ioctl` operations.

use crate::errno::SysResult;
use crate::fd::RawFd;
use crate::raw::{nr, syscall1, syscall2, syscall3, syscall4};

pub const STDIN_FILENO: RawFd = 0;
pub const STDOUT_FILENO: RawFd = 1;
pub const STDERR_FILENO: RawFd = 2;

pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_SETLK: i32 = 6;
pub const F_SETLKW: i32 = 7;
pub const F_DUPFD_CLOEXEC: i32 = 1030;

pub const FD_CLOEXEC: i32 = 1;

pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

pub const TCGETS: u64 = 0x5401;
pub const FIONBIO: u64 = 0x5421;

/// Advisory file-lock record for `fcntl` (`F_SETLK` / `F_SETLKW`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

/// Scatter/gather I/O vector (`struct iovec`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoVec {
    pub iov_base: *mut u8,
    pub iov_len: usize,
}

impl Default for IoVec {
    fn default() -> Self {
        Self {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        }
    }
}

/// Closes an open file descriptor.
pub fn close(fd: RawFd) -> SysResult<()> {
    // SAFETY: `CLOSE` takes a single integer file descriptor.
    unsafe {
        syscall1(nr::CLOSE, fd as usize)?;
    }
    Ok(())
}

/// Reads up to `len` bytes from `fd` into raw pointer `buf`.
///
/// # Safety
///
/// `buf` must be valid for writes of `len` bytes (when `len > 0`).
pub unsafe fn read_raw(fd: RawFd, buf: *mut u8, len: usize) -> SysResult<usize> {
    // SAFETY: Caller guarantees `buf` is valid for `len` writable bytes.
    unsafe { syscall3(nr::READ, fd as usize, buf as usize, len) }
}

/// Reads bytes from `fd` into `buf`, returning the number of bytes read.
pub fn read(fd: RawFd, buf: &mut [u8]) -> SysResult<usize> {
    // SAFETY: `buf` is a valid mutable slice.
    unsafe { read_raw(fd, buf.as_mut_ptr(), buf.len()) }
}

/// Writes up to `len` bytes from raw pointer `buf` to `fd`.
///
/// # Safety
///
/// `buf` must be valid for reads of `len` bytes (when `len > 0`).
pub unsafe fn write_raw(fd: RawFd, buf: *const u8, len: usize) -> SysResult<usize> {
    // SAFETY: Caller guarantees `buf` is valid for `len` readable bytes.
    unsafe { syscall3(nr::WRITE, fd as usize, buf as usize, len) }
}

/// Writes bytes from `buf` to `fd`, returning the number of bytes written.
pub fn write(fd: RawFd, buf: &[u8]) -> SysResult<usize> {
    // SAFETY: `buf` is a valid shared slice.
    unsafe { write_raw(fd, buf.as_ptr(), buf.len()) }
}

/// Reads from `fd` at `offset` into `buf` without changing the file offset.
pub fn pread(fd: RawFd, buf: &mut [u8], offset: i64) -> SysResult<usize> {
    // SAFETY: `buf` is a valid mutable slice.
    unsafe {
        syscall4(
            nr::PREAD64,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            offset as usize,
        )
    }
}

/// Writes `buf` to `fd` at `offset` without changing the file offset.
pub fn pwrite(fd: RawFd, buf: &[u8], offset: i64) -> SysResult<usize> {
    // SAFETY: `buf` is a valid shared slice.
    unsafe {
        syscall4(
            nr::PWRITE64,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            offset as usize,
        )
    }
}

/// Reads from `fd` into scatter buffers `iov`.
///
/// # Safety
///
/// Every [`IoVec`] entry in `iov` must point to valid writable memory for its `iov_len`.
pub unsafe fn readv(fd: RawFd, iov: &[IoVec]) -> SysResult<usize> {
    // SAFETY: Caller guarantees each `IoVec` buffer is writable for `iov_len` bytes.
    unsafe { syscall3(nr::READV, fd as usize, iov.as_ptr() as usize, iov.len()) }
}

/// Writes gather buffers `iov` to `fd`.
///
/// # Safety
///
/// Every [`IoVec`] entry in `iov` must point to valid readable memory for its `iov_len`.
pub unsafe fn writev(fd: RawFd, iov: &[IoVec]) -> SysResult<usize> {
    // SAFETY: Caller guarantees each `IoVec` buffer is readable for `iov_len` bytes.
    unsafe { syscall3(nr::WRITEV, fd as usize, iov.as_ptr() as usize, iov.len()) }
}

/// Creates a unidirectional pipe pair `[read_fd, write_fd]` with `flags`.
pub fn pipe2(flags: i32) -> SysResult<[RawFd; 2]> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid 2-element `i32` array on the stack.
    unsafe {
        syscall2(nr::PIPE2, fds.as_mut_ptr() as usize, flags as u32 as usize)?;
    }
    Ok(fds)
}

/// Duplicates file descriptor `fd` to the lowest-numbered unused descriptor.
pub fn dup(fd: RawFd) -> SysResult<RawFd> {
    // SAFETY: `DUP` takes a single file descriptor.
    let raw = unsafe { syscall1(nr::DUP, fd as usize)? };
    Ok(raw as RawFd)
}

/// Duplicates `oldfd` onto `newfd` (implementing POSIX `dup2` semantics on AArch64).
///
/// When `oldfd == newfd`, validates that `oldfd` is open via `F_GETFD` and returns `newfd`
/// without clearing `FD_CLOEXEC`. Otherwise delegates to `dup3(oldfd, newfd, 0)`.
pub fn dup2(oldfd: RawFd, newfd: RawFd) -> SysResult<RawFd> {
    if oldfd == newfd {
        fcntl_getfd(oldfd)?;
        Ok(newfd)
    } else {
        dup3(oldfd, newfd, 0)
    }
}

/// Duplicates `oldfd` onto `newfd` with `flags` (such as `O_CLOEXEC`).
pub fn dup3(oldfd: RawFd, newfd: RawFd, flags: i32) -> SysResult<RawFd> {
    // SAFETY: `DUP3` takes two file descriptors and integer flags.
    let raw = unsafe {
        syscall3(
            nr::DUP3,
            oldfd as usize,
            newfd as usize,
            flags as u32 as usize,
        )?
    };
    Ok(raw as RawFd)
}

/// Performs a raw `fcntl` command on `fd`.
pub fn fcntl(fd: RawFd, cmd: i32, arg: usize) -> SysResult<i32> {
    // SAFETY: `FCNTL` takes a file descriptor, command code, and argument word.
    let raw = unsafe { syscall3(nr::FCNTL, fd as usize, cmd as u32 as usize, arg)? };
    Ok(raw as i32)
}

/// Reads file descriptor flags (`F_GETFD`).
pub fn fcntl_getfd(fd: RawFd) -> SysResult<i32> {
    fcntl(fd, F_GETFD, 0)
}

/// Sets file descriptor flags (`F_SETFD`).
pub fn fcntl_setfd(fd: RawFd, flags: i32) -> SysResult<()> {
    fcntl(fd, F_SETFD, flags as u32 as usize)?;
    Ok(())
}

/// Reads file status flags (`F_GETFL`).
pub fn fcntl_getfl(fd: RawFd) -> SysResult<i32> {
    fcntl(fd, F_GETFL, 0)
}

/// Sets file status flags (`F_SETFL`).
pub fn fcntl_setfl(fd: RawFd, flags: i32) -> SysResult<()> {
    fcntl(fd, F_SETFL, flags as u32 as usize)?;
    Ok(())
}

/// Duplicates `fd` to a descriptor `>= min_fd` with `FD_CLOEXEC` set (`F_DUPFD_CLOEXEC`).
pub fn fcntl_dupfd_cloexec(fd: RawFd, min_fd: RawFd) -> SysResult<RawFd> {
    fcntl(fd, F_DUPFD_CLOEXEC, min_fd as usize)
}

/// Applies or releases an advisory record lock via `F_SETLK` or `F_SETLKW`.
pub fn fcntl_setlk(fd: RawFd, lock: &Flock, wait: bool) -> SysResult<()> {
    let cmd = if wait { F_SETLKW } else { F_SETLK };
    fcntl(fd, cmd, core::ptr::from_ref(lock) as usize)?;
    Ok(())
}

/// Invokes a device control operation (`ioctl`) on `fd`.
///
/// # Safety
///
/// `arg` must satisfy the pointer/type contract of `request`.
pub unsafe fn ioctl(fd: RawFd, request: u64, arg: usize) -> SysResult<i32> {
    // SAFETY: Caller guarantees `arg` is valid for `request`.
    let raw = unsafe { syscall3(nr::IOCTL, fd as usize, request as usize, arg)? };
    Ok(raw as i32)
}

/// Returns `true` if `fd` refers to a terminal device (`TCGETS`).
#[must_use]
pub fn isatty(fd: RawFd) -> bool {
    let mut termios = [0u8; 64];
    // SAFETY: `termios` is a 64-byte stack buffer sufficient for `struct termios` under `TCGETS`.
    unsafe { ioctl(fd, TCGETS, termios.as_mut_ptr() as usize).is_ok() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::{EBADF, Errno};
    use crate::raw::with_mock_syscall;

    #[test]
    fn dup2_same_fd_validates_with_fcntl_getfd() {
        with_mock_syscall(
            |nr, args| {
                assert_eq!(nr, nr::FCNTL);
                assert_eq!(args[0], 5);
                assert_eq!(args[1], F_GETFD as usize);
                Ok(FD_CLOEXEC as usize)
            },
            || {
                assert_eq!(dup2(5, 5), Ok(5));
            },
        );

        with_mock_syscall(
            |nr, _args| {
                assert_eq!(nr, nr::FCNTL);
                Err(Errno(EBADF))
            },
            || {
                assert_eq!(dup2(9, 9), Err(Errno(EBADF)));
            },
        );
    }

    #[test]
    fn dup2_different_fd_routes_to_dup3() {
        with_mock_syscall(
            |nr, args| {
                assert_eq!(nr, nr::DUP3);
                assert_eq!(args[0], 3);
                assert_eq!(args[1], 7);
                assert_eq!(args[2], 0);
                Ok(7)
            },
            || {
                assert_eq!(dup2(3, 7), Ok(7));
            },
        );
    }
}
