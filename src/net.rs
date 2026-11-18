//! Socket, UNIX domain, and Virtio-Vsock syscall wrappers.

use core::mem::size_of;

use crate::errno::{EINVAL, ENAMETOOLONG, Errno, SysResult};
use crate::fd::RawFd;
use crate::raw::{nr, syscall2, syscall3, syscall4, syscall5, syscall6};

/// Unix domain sockets address family.
pub const AF_UNIX: i32 = 1;
/// Virtio vsock address family.
pub const AF_VSOCK: i32 = 40;

/// Sequenced, reliable, two-way connection-based byte streams.
pub const SOCK_STREAM: i32 = 1;
/// Connectionless, unreliable datagrams.
pub const SOCK_DGRAM: i32 = 2;
/// Set `O_NONBLOCK` on the new open file description.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec (`FD_CLOEXEC`) on the new descriptor.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Socket level for `getsockopt` / `setsockopt`.
pub const SOL_SOCKET: i32 = 1;
/// Allow reuse of local addresses.
pub const SO_REUSEADDR: i32 = 2;
/// Get and clear pending socket error.
pub const SO_ERROR: i32 = 4;
/// Enable keep-alive messages on connection-oriented sockets.
pub const SO_KEEPALIVE: i32 = 9;
/// Receive timeout option.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout option.
pub const SO_SNDTIMEO: i32 = 21;

/// Nonblocking I/O for a single send/recv call.
pub const MSG_DONTWAIT: i32 = 0x40;
/// Wait for full request or error.
pub const MSG_WAITALL: i32 = 0x100;
/// Do not generate `SIGPIPE` on peer close.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// Shut down the reading side of a socket.
pub const SHUT_RD: i32 = 0;
/// Shut down the writing side of a socket.
pub const SHUT_WR: i32 = 1;
/// Shut down both reading and writing sides of a socket.
pub const SHUT_RDWR: i32 = 2;

/// Wildcard vsock context ID.
pub const VMADDR_CID_ANY: u32 = u32::MAX;
/// Local loopback vsock context ID.
pub const VMADDR_CID_LOCAL: u32 = 1;
/// Host hypervisor vsock context ID.
pub const VMADDR_CID_HOST: u32 = 2;

/// Kernel `sockaddr_un` structure for UNIX domain sockets.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockAddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; 108],
}

impl SockAddrUn {
    /// Builds a NUL-terminated [`SockAddrUn`] and its effective `socklen_t` from `path`.
    ///
    /// Reserves 1 trailing NUL byte so `path.len() >= 108` fails with `ENAMETOOLONG`,
    /// and rejects interior NUL bytes or empty paths with `EINVAL`.
    pub fn from_path(path: &[u8]) -> SysResult<(Self, u32)> {
        if path.is_empty() || path.contains(&0) {
            return Err(Errno(EINVAL));
        }
        if path.len() >= 108 {
            return Err(Errno(ENAMETOOLONG));
        }
        let mut addr = Self {
            sun_family: AF_UNIX as u16,
            sun_path: [0u8; 108],
        };
        addr.sun_path[..path.len()].copy_from_slice(path);
        let addrlen = (size_of::<u16>() + path.len() + 1) as u32;
        Ok((addr, addrlen))
    }
}

/// Kernel `sockaddr_vm` structure for `AF_VSOCK` sockets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SockAddrVm {
    pub svm_family: u16,
    pub svm_reserved1: u16,
    pub svm_port: u32,
    pub svm_cid: u32,
    pub svm_flags: u8,
    pub svm_zero: [u8; 3],
}

impl SockAddrVm {
    /// Constructs an `AF_VSOCK` socket address for `(cid, port)`.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_flags: 0,
            svm_zero: [0; 3],
        }
    }
}

const _: () = {
    assert!(size_of::<SockAddrVm>() == 16);
};

/// Creates an endpoint for communication and returns its file descriptor.
pub fn socket(domain: i32, ty: i32, protocol: i32) -> SysResult<RawFd> {
    // SAFETY: `SOCKET` takes three scalar integer arguments.
    unsafe {
        syscall3(nr::SOCKET, domain as usize, ty as usize, protocol as usize).map(|fd| fd as RawFd)
    }
}

/// Creates an unnamed pair of connected sockets.
pub fn socketpair(domain: i32, ty: i32, protocol: i32) -> SysResult<[RawFd; 2]> {
    let mut sv = [0i32; 2];
    // SAFETY: `sv` is a valid 2-element `i32` array on the stack.
    unsafe {
        syscall4(
            nr::SOCKETPAIR,
            domain as usize,
            ty as usize,
            protocol as usize,
            sv.as_mut_ptr() as usize,
        )?;
    }
    Ok(sv)
}

/// Binds `fd` to the raw socket address `[addr..addr + addrlen]`.
///
/// # Safety
///
/// `addr` must point to at least `addrlen` readable bytes containing a valid kernel `sockaddr`.
pub unsafe fn bind_raw(fd: RawFd, addr: *const u8, addrlen: u32) -> SysResult<()> {
    // SAFETY: Caller guarantees `addr` and `addrlen` describe a valid readable buffer.
    unsafe {
        syscall3(nr::BIND, fd as usize, addr as usize, addrlen as usize)?;
    }
    Ok(())
}

/// Binds an `AF_UNIX` socket `fd` to `path`.
pub fn bind_unix(fd: RawFd, path: &[u8]) -> SysResult<()> {
    let (addr, len) = SockAddrUn::from_path(path)?;
    // SAFETY: `addr` is a stack `SockAddrUn` and `len <= size_of::<SockAddrUn>()`.
    unsafe { bind_raw(fd, core::ptr::from_ref(&addr).cast::<u8>(), len) }
}

/// Binds an `AF_VSOCK` socket `fd` to `addr`.
pub fn bind_vsock(fd: RawFd, addr: &SockAddrVm) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrVm` of size 16 bytes.
    unsafe {
        bind_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrVm>() as u32,
        )
    }
}

/// Connects `fd` to the raw socket address `[addr..addr + addrlen]`.
///
/// # Safety
///
/// `addr` must point to at least `addrlen` readable bytes containing a valid kernel `sockaddr`.
pub unsafe fn connect_raw(fd: RawFd, addr: *const u8, addrlen: u32) -> SysResult<()> {
    // SAFETY: Caller guarantees `addr` and `addrlen` describe a valid readable buffer.
    unsafe {
        syscall3(nr::CONNECT, fd as usize, addr as usize, addrlen as usize)?;
    }
    Ok(())
}

/// Connects an `AF_UNIX` socket `fd` to `path`.
pub fn connect_unix(fd: RawFd, path: &[u8]) -> SysResult<()> {
    let (addr, len) = SockAddrUn::from_path(path)?;
    // SAFETY: `addr` is a stack `SockAddrUn` and `len <= size_of::<SockAddrUn>()`.
    unsafe { connect_raw(fd, core::ptr::from_ref(&addr).cast::<u8>(), len) }
}

/// Connects an `AF_VSOCK` socket `fd` to `addr`.
pub fn connect_vsock(fd: RawFd, addr: &SockAddrVm) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrVm` of size 16 bytes.
    unsafe {
        connect_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrVm>() as u32,
        )
    }
}

/// Marks `fd` as a passive socket with maximum pending connection queue `backlog`.
pub fn listen(fd: RawFd, backlog: i32) -> SysResult<()> {
    // SAFETY: `LISTEN` takes scalar descriptor and backlog arguments.
    unsafe {
        syscall2(nr::LISTEN, fd as usize, backlog as usize)?;
    }
    Ok(())
}

/// Accepts a connection on `fd` with `flags`, optionally writing the peer address into `addr`.
///
/// # Safety
///
/// Either `addr` and `addrlen` must both be null, or `addrlen` must point to a valid `u32`
/// initialized to the byte capacity of `addr` and `addr` must be writable for that many bytes.
pub unsafe fn accept4_raw(
    fd: RawFd,
    addr: *mut u8,
    addrlen: *mut u32,
    flags: i32,
) -> SysResult<RawFd> {
    // SAFETY: Caller upholds the pointer validity contract for `addr` and `addrlen`.
    unsafe {
        syscall4(
            nr::ACCEPT4,
            fd as usize,
            addr as usize,
            addrlen as usize,
            flags as usize,
        )
        .map(|v| v as RawFd)
    }
}

/// Accepts a connection on `fd` without peer address capture.
pub fn accept(fd: RawFd) -> SysResult<RawFd> {
    accept4(fd, 0)
}

/// Accepts a connection on `fd` with `flags` (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`) without peer address capture.
pub fn accept4(fd: RawFd, flags: i32) -> SysResult<RawFd> {
    // SAFETY: Null address and length pointers are explicitly allowed by `accept4`.
    unsafe { accept4_raw(fd, core::ptr::null_mut(), core::ptr::null_mut(), flags) }
}

/// Sends `len` bytes from `buf` on connected socket `fd` with `flags`.
///
/// # Safety
///
/// `buf` must be valid for reads of `len` bytes (or `len == 0`).
pub unsafe fn send_raw(fd: RawFd, buf: *const u8, len: usize, flags: i32) -> SysResult<usize> {
    // SAFETY: Caller guarantees `buf` is readable for `len` bytes; `dest_addr = 0, addrlen = 0`
    // is the standard AArch64 `sendto` encoding for `send`.
    unsafe {
        syscall6(
            nr::SENDTO,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            0,
            0,
        )
    }
}

/// Sends `buf` on connected socket `fd` with `flags`.
pub fn send(fd: RawFd, buf: &[u8], flags: i32) -> SysResult<usize> {
    // SAFETY: `buf.as_ptr()` is valid for `buf.len()` bytes.
    unsafe { send_raw(fd, buf.as_ptr(), buf.len(), flags) }
}

/// Receives up to `len` bytes into `buf` from socket `fd` with `flags`.
///
/// # Safety
///
/// `buf` must be valid for writes of `len` bytes (or `len == 0`).
pub unsafe fn recv_raw(fd: RawFd, buf: *mut u8, len: usize, flags: i32) -> SysResult<usize> {
    // SAFETY: Caller guarantees `buf` is writable for `len` bytes; `src_addr = 0, addrlen = 0`
    // is the standard AArch64 `recvfrom` encoding for `recv`.
    unsafe {
        syscall6(
            nr::RECVFROM,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            0,
            0,
        )
    }
}

/// Receives bytes into `buf` from socket `fd` with `flags`.
pub fn recv(fd: RawFd, buf: &mut [u8], flags: i32) -> SysResult<usize> {
    // SAFETY: `buf.as_mut_ptr()` is valid for `buf.len()` writable bytes.
    unsafe { recv_raw(fd, buf.as_mut_ptr(), buf.len(), flags) }
}

/// Sets a raw socket option on `fd`.
///
/// # Safety
///
/// `optval` must be readable for `optlen` bytes (or null if `optlen == 0`).
pub unsafe fn setsockopt_raw(
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *const u8,
    optlen: u32,
) -> SysResult<()> {
    // SAFETY: Caller guarantees `optval` points to `optlen` readable bytes.
    unsafe {
        syscall5(
            nr::SETSOCKOPT,
            fd as usize,
            level as usize,
            optname as usize,
            optval as usize,
            optlen as usize,
        )?;
    }
    Ok(())
}

/// Gets a raw socket option from `fd`.
///
/// # Safety
///
/// `optlen` must point to a valid `u32` initialized to the byte capacity of `optval`,
/// and `optval` must be writable for that many bytes.
pub unsafe fn getsockopt_raw(
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *mut u8,
    optlen: *mut u32,
) -> SysResult<()> {
    // SAFETY: Caller guarantees `optval` and `optlen` are valid writable pointers.
    unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as usize,
            level as usize,
            optname as usize,
            optval as usize,
            optlen as usize,
        )?;
    }
    Ok(())
}

/// Shuts down part or all of a full-duplex connection on `fd`.
pub fn shutdown(fd: RawFd, how: i32) -> SysResult<()> {
    // SAFETY: `SHUTDOWN` takes scalar `fd` and `how` arguments.
    unsafe {
        syscall2(nr::SHUTDOWN, fd as usize, how as usize)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_un_from_path_validates_bounds_and_interior_nul() {
        let (addr, len) = SockAddrUn::from_path(b"/run/test.sock").unwrap();
        assert_eq!(addr.sun_family, AF_UNIX as u16);
        assert_eq!(len, (2 + b"/run/test.sock".len() + 1) as u32);
        assert_eq!(&addr.sun_path[..14], b"/run/test.sock");
        assert_eq!(addr.sun_path[14], 0);

        let max_ok = [b'a'; 107];
        let (_, max_len) = SockAddrUn::from_path(&max_ok).unwrap();
        assert_eq!(max_len, 110);

        let too_long = [b'a'; 108];
        assert_eq!(
            SockAddrUn::from_path(&too_long).unwrap_err(),
            Errno(ENAMETOOLONG)
        );

        assert_eq!(SockAddrUn::from_path(b"").unwrap_err(), Errno(EINVAL));
        assert_eq!(
            SockAddrUn::from_path(b"/tmp/bad\0path").unwrap_err(),
            Errno(EINVAL)
        );
    }

    #[test]
    fn vsock_addr_constructor_sets_family_cid_and_port() {
        let vm = SockAddrVm::new(VMADDR_CID_HOST, 5000);
        assert_eq!(vm.svm_family, AF_VSOCK as u16);
        assert_eq!(vm.svm_cid, VMADDR_CID_HOST);
        assert_eq!(vm.svm_port, 5000);
    }
}
