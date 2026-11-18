//! Unikernel system error numbers (`Errno`) and [`SysResult`] alias.

use core::fmt;

/// System call error number (`errno`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Errno(pub i32);

/// Result alias for unikernel system calls returning [`Errno`] on failure.
pub type SysResult<T> = core::result::Result<T, Errno>;

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const EWOULDBLOCK: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const ETXTBSY: i32 = 26;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const EDEADLK: i32 = 35;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOLCK: i32 = 37;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const EPROTO: i32 = 71;
pub const EOVERFLOW: i32 = 75;
pub const EILSEQ: i32 = 84;
pub const ENOTSOCK: i32 = 88;
pub const EDESTADDRREQ: i32 = 89;
pub const EMSGSIZE: i32 = 90;
pub const EPROTOTYPE: i32 = 91;
pub const ENOPROTOOPT: i32 = 92;
pub const EPROTONOSUPPORT: i32 = 93;
pub const EOPNOTSUPP: i32 = 95;
pub const ENOTSUP: i32 = 95;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETDOWN: i32 = 100;
pub const ENETUNREACH: i32 = 101;
pub const ENETRESET: i32 = 102;
pub const ECONNABORTED: i32 = 103;
pub const ECONNRESET: i32 = 104;
pub const ENOBUFS: i32 = 105;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ESHUTDOWN: i32 = 108;
pub const ETIMEDOUT: i32 = 110;
pub const ECONNREFUSED: i32 = 111;
pub const EHOSTUNREACH: i32 = 113;
pub const EALREADY: i32 = 114;
pub const EINPROGRESS: i32 = 115;
pub const ECANCELED: i32 = 125;

impl Errno {
    /// Returns the raw positive integer error code.
    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Returns `true` if the error indicates the operation would block (`EAGAIN` / `EWOULDBLOCK`).
    #[must_use]
    pub const fn would_block(self) -> bool {
        self.0 == EAGAIN
    }

    /// Returns `true` if the error indicates the call was interrupted (`EINTR`).
    #[must_use]
    pub const fn interrupted(self) -> bool {
        self.0 == EINTR
    }

    /// Returns a concise static human-readable description of the error code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self.0 {
            EPERM => "operation not permitted",
            ENOENT => "no such file or directory",
            ESRCH => "no such process",
            EINTR => "interrupted system call",
            EIO => "input/output error",
            ENXIO => "no such device or address",
            E2BIG => "argument list too long",
            ENOEXEC => "exec format error",
            EBADF => "bad file descriptor",
            ECHILD => "no child processes",
            EAGAIN => "resource temporarily unavailable",
            ENOMEM => "out of memory",
            EACCES => "permission denied",
            EFAULT => "bad address",
            EBUSY => "device or resource busy",
            EEXIST => "file exists",
            EXDEV => "Invalid cross-device link",
            ENODEV => "no such device",
            ENOTDIR => "not a directory",
            EISDIR => "is a directory",
            EINVAL => "invalid argument",
            ENFILE => "too many open files in system",
            EMFILE => "too many open files",
            ENOTTY => "inappropriate ioctl for device",
            ETXTBSY => "text file busy",
            EFBIG => "file too large",
            ENOSPC => "no space left on device",
            ESPIPE => "illegal seek",
            EROFS => "read-only file system",
            EMLINK => "too many links",
            EPIPE => "broken pipe",
            EDOM => "numerical argument out of domain",
            ERANGE => "numerical result out of range",
            EDEADLK => "resource deadlock avoided",
            ENAMETOOLONG => "file name too long",
            ENOLCK => "no locks available",
            ENOSYS => "function not implemented",
            ENOTEMPTY => "directory not empty",
            ELOOP => "too many levels of symbolic links",
            EPROTO => "protocol error",
            EOVERFLOW => "value too large for defined data type",
            EILSEQ => "invalid or incomplete multibyte or wide character",
            ENOTSOCK => "socket operation on non-socket",
            EDESTADDRREQ => "destination address required",
            EMSGSIZE => "message too long",
            EPROTOTYPE => "protocol wrong type for socket",
            ENOPROTOOPT => "protocol not available",
            EPROTONOSUPPORT => "protocol not supported",
            EOPNOTSUPP => "operation not supported",
            EAFNOSUPPORT => "address family not supported by protocol",
            EADDRINUSE => "address already in use",
            EADDRNOTAVAIL => "cannot assign requested address",
            ENETDOWN => "network is down",
            ENETUNREACH => "network is unreachable",
            ENETRESET => "network dropped connection on reset",
            ECONNABORTED => "software caused connection abort",
            ECONNRESET => "connection reset by peer",
            ENOBUFS => "no buffer space available",
            EISCONN => "transport endpoint is already connected",
            ENOTCONN => "transport endpoint is not connected",
            ESHUTDOWN => "cannot send after transport endpoint shutdown",
            ETIMEDOUT => "connection timed out",
            ECONNREFUSED => "connection refused",
            EHOSTUNREACH => "no route to host",
            EALREADY => "operation already in progress",
            EINPROGRESS => "operation now in progress",
            ECANCELED => "operation canceled",
            _ => "unknown error",
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (errno {})", self.message(), self.0)
    }
}

impl core::error::Error for Errno {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    struct StackBuf<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> StackBuf<N> {
        const fn new() -> Self {
            Self {
                buf: [0; N],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
        }
    }

    impl<const N: usize> Write for StackBuf<N> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            if self.len + bytes.len() > N {
                return Err(fmt::Error);
            }
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    #[test]
    fn errno_helpers_and_messages() {
        let eagain = Errno(EAGAIN);
        assert_eq!(eagain.raw(), 11);
        assert!(eagain.would_block());
        assert!(!eagain.interrupted());
        assert_eq!(Errno(EWOULDBLOCK), eagain);

        let eintr = Errno(EINTR);
        assert!(eintr.interrupted());
        assert!(!eintr.would_block());

        assert_eq!(Errno(ENOENT).message(), "no such file or directory");
        assert_eq!(Errno(ENOSYS).message(), "function not implemented");
        assert_eq!(Errno(EOPNOTSUPP).message(), "operation not supported");
        assert_eq!(Errno(ENOTSUP).message(), "operation not supported");
        assert_eq!(Errno(9999).message(), "unknown error");

        let mut out = StackBuf::<64>::new();
        write!(&mut out, "{}", Errno(EINVAL)).unwrap();
        assert_eq!(out.as_str(), "invalid argument (errno 22)");
    }
}
