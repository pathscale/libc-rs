//! Socket, UNIX domain, and Virtio-Vsock syscall wrappers.

use core::mem::size_of;

use crate::errno::{EINVAL, ENAMETOOLONG, Errno, SysResult};
use crate::fd::RawFd;
use crate::raw::{nr, syscall2, syscall3, syscall4, syscall5, syscall6};

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Unix domain sockets address family.
pub const AF_UNIX: i32 = 1;
/// IPv4 Internet protocols address family.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols address family.
pub const AF_INET6: i32 = 10;
/// Virtio vsock address family.
pub const AF_VSOCK: i32 = 40;

/// Dummy protocol for TCP / IP level.
pub const IPPROTO_IP: i32 = 0;
/// Internet Control Message Protocol.
pub const IPPROTO_ICMP: i32 = 1;
/// Transmission Control Protocol.
pub const IPPROTO_TCP: i32 = 6;
/// User Datagram Protocol.
pub const IPPROTO_UDP: i32 = 17;
/// IPv6 header protocol level.
pub const IPPROTO_IPV6: i32 = 41;

/// Sequenced, reliable, two-way connection-based byte streams.
pub const SOCK_STREAM: i32 = 1;
/// Connectionless, unreliable datagrams.
pub const SOCK_DGRAM: i32 = 2;
/// Set `O_NONBLOCK` on the new open file description.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec (`FD_CLOEXEC`) on the new descriptor.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Disable Nagle's algorithm (`IPPROTO_TCP`).
pub const TCP_NODELAY: i32 = 1;
/// Start keepalives after this period (`IPPROTO_TCP`).
pub const TCP_KEEPIDLE: i32 = 4;
/// Interval between keepalives (`IPPROTO_TCP`).
pub const TCP_KEEPINTVL: i32 = 5;
/// Number of keepalives before death (`IPPROTO_TCP`).
pub const TCP_KEEPCNT: i32 = 6;

/// Socket level for `getsockopt` / `setsockopt`.
pub const SOL_SOCKET: i32 = 1;
/// Allow reuse of local addresses.
pub const SO_REUSEADDR: i32 = 2;
/// Get and clear pending socket error.
pub const SO_ERROR: i32 = 4;
/// Send buffer size (`SOL_SOCKET`).
pub const SO_SNDBUF: i32 = 7;
/// Receive buffer size (`SOL_SOCKET`).
pub const SO_RCVBUF: i32 = 8;
/// Enable keep-alive messages on connection-oriented sockets.
pub const SO_KEEPALIVE: i32 = 9;
/// Allow multiple sockets to bind to the same port (`SOL_SOCKET`).
pub const SO_REUSEPORT: i32 = 15;
/// Receive timeout option.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout option.
pub const SO_SNDTIMEO: i32 = 21;

/// Restrict `AF_INET6` socket to IPv6 communications only (`IPPROTO_IPV6`).
pub const IPV6_V6ONLY: i32 = 26;

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

/// IPv4 address (`struct in_addr`) in network byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InAddr {
    pub s_addr: u32,
}

impl InAddr {
    /// Constructs an [`InAddr`] from 4 octets in network byte order.
    #[must_use]
    pub const fn from_octets(octets: [u8; 4]) -> Self {
        Self {
            s_addr: u32::from_ne_bytes(octets),
        }
    }

    /// Returns the 4 octets of this IPv4 address.
    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.s_addr.to_ne_bytes()
    }
}

/// Kernel `sockaddr_in` structure for `AF_INET` sockets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    /// Constructs an `AF_INET` socket address for `(ip, port)` with `port` in host byte order.
    #[must_use]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: InAddr {
                s_addr: u32::from_ne_bytes(ip),
            },
            sin_zero: [0; 8],
        }
    }

    /// Returns the IPv4 octets.
    #[must_use]
    pub const fn ip(&self) -> [u8; 4] {
        self.sin_addr.s_addr.to_ne_bytes()
    }

    /// Returns the port in host byte order.
    #[must_use]
    pub const fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }
}

/// IPv6 address (`struct in6_addr`) in network byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}

/// Kernel `sockaddr_in6` structure for `AF_INET6` sockets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

impl SockAddrIn6 {
    /// Constructs an `AF_INET6` socket address for `(ip, port, flowinfo, scope_id)` with `port` in host byte order.
    #[must_use]
    pub const fn new(ip: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self {
            sin6_family: AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: flowinfo,
            sin6_addr: In6Addr { s6_addr: ip },
            sin6_scope_id: scope_id,
        }
    }

    /// Returns the IPv6 octets.
    #[must_use]
    pub const fn ip(&self) -> [u8; 16] {
        self.sin6_addr.s6_addr
    }

    /// Returns the port in host byte order.
    #[must_use]
    pub const fn port(&self) -> u16 {
        u16::from_be(self.sin6_port)
    }
}

/// Generic socket address storage (`struct sockaddr_storage`, 128 bytes).
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct SockAddrStorage {
    pub ss_family: u16,
    pub ss_data: [u8; 126],
}

impl Default for SockAddrStorage {
    fn default() -> Self {
        Self {
            ss_family: 0,
            ss_data: [0u8; 126],
        }
    }
}

const _: () = {
    assert!(size_of::<SockAddrVm>() == 16);
    assert!(size_of::<InAddr>() == 4);
    assert!(size_of::<SockAddrIn>() == 16);
    assert!(size_of::<In6Addr>() == 16);
    assert!(size_of::<SockAddrIn6>() == 28);
    assert!(size_of::<SockAddrStorage>() == 128);
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

/// Binds an `AF_INET` socket `fd` to `addr`.
pub fn bind_in(fd: RawFd, addr: &SockAddrIn) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrIn` of size 16 bytes.
    unsafe {
        bind_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrIn>() as u32,
        )
    }
}

/// Binds an `AF_INET6` socket `fd` to `addr`.
pub fn bind_in6(fd: RawFd, addr: &SockAddrIn6) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrIn6` of size 28 bytes.
    unsafe {
        bind_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrIn6>() as u32,
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

/// Connects an `AF_INET` socket `fd` to `addr`.
pub fn connect_in(fd: RawFd, addr: &SockAddrIn) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrIn` of size 16 bytes.
    unsafe {
        connect_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrIn>() as u32,
        )
    }
}

/// Connects an `AF_INET6` socket `fd` to `addr`.
pub fn connect_in6(fd: RawFd, addr: &SockAddrIn6) -> SysResult<()> {
    // SAFETY: `addr` is a valid `SockAddrIn6` of size 28 bytes.
    unsafe {
        connect_raw(
            fd,
            core::ptr::from_ref(addr).cast::<u8>(),
            size_of::<SockAddrIn6>() as u32,
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

/// Accepts an `AF_INET` connection on `fd` with `flags`, returning `(client_fd, peer_addr)`.
pub fn accept_in(fd: RawFd, flags: i32) -> SysResult<(RawFd, SockAddrIn)> {
    let mut addr = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    // SAFETY: `addr` and `len` are valid stack variables sized for `SockAddrIn`.
    let client = unsafe {
        accept4_raw(
            fd,
            core::ptr::from_mut(&mut addr).cast::<u8>(),
            core::ptr::from_mut(&mut len),
            flags,
        )?
    };
    Ok((client, addr))
}

/// Accepts an `AF_INET6` connection on `fd` with `flags`, returning `(client_fd, peer_addr)`.
pub fn accept_in6(fd: RawFd, flags: i32) -> SysResult<(RawFd, SockAddrIn6)> {
    let mut addr = SockAddrIn6::default();
    let mut len = size_of::<SockAddrIn6>() as u32;
    // SAFETY: `addr` and `len` are valid stack variables sized for `SockAddrIn6`.
    let client = unsafe {
        accept4_raw(
            fd,
            core::ptr::from_mut(&mut addr).cast::<u8>(),
            core::ptr::from_mut(&mut len),
            flags,
        )?
    };
    Ok((client, addr))
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

/// Sends `buf` to an `AF_INET` destination `addr` on socket `fd` with `flags`.
pub fn sendto_in(fd: RawFd, buf: &[u8], flags: i32, addr: &SockAddrIn) -> SysResult<usize> {
    // SAFETY: `buf` and `addr` are valid references for their respective byte lengths.
    unsafe {
        syscall6(
            nr::SENDTO,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            flags as usize,
            core::ptr::from_ref(addr) as usize,
            size_of::<SockAddrIn>(),
        )
    }
}

/// Sends `buf` to an `AF_INET6` destination `addr` on socket `fd` with `flags`.
pub fn sendto_in6(fd: RawFd, buf: &[u8], flags: i32, addr: &SockAddrIn6) -> SysResult<usize> {
    // SAFETY: `buf` and `addr` are valid references for their respective byte lengths.
    unsafe {
        syscall6(
            nr::SENDTO,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            flags as usize,
            core::ptr::from_ref(addr) as usize,
            size_of::<SockAddrIn6>(),
        )
    }
}

/// Receives a datagram into `buf` on `AF_INET` socket `fd` with `flags`, returning `(bytes_read, src_addr)`.
pub fn recvfrom_in(fd: RawFd, buf: &mut [u8], flags: i32) -> SysResult<(usize, SockAddrIn)> {
    let mut addr = SockAddrIn::default();
    let mut addrlen = size_of::<SockAddrIn>() as u32;
    // SAFETY: `buf`, `addr`, and `addrlen` are valid writable buffers.
    let n = unsafe {
        syscall6(
            nr::RECVFROM,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            flags as usize,
            core::ptr::from_mut(&mut addr) as usize,
            core::ptr::from_mut(&mut addrlen) as usize,
        )?
    };
    Ok((n, addr))
}

/// Receives a datagram into `buf` on `AF_INET6` socket `fd` with `flags`, returning `(bytes_read, src_addr)`.
pub fn recvfrom_in6(fd: RawFd, buf: &mut [u8], flags: i32) -> SysResult<(usize, SockAddrIn6)> {
    let mut addr = SockAddrIn6::default();
    let mut addrlen = size_of::<SockAddrIn6>() as u32;
    // SAFETY: `buf`, `addr`, and `addrlen` are valid writable buffers.
    let n = unsafe {
        syscall6(
            nr::RECVFROM,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            flags as usize,
            core::ptr::from_mut(&mut addr) as usize,
            core::ptr::from_mut(&mut addrlen) as usize,
        )?
    };
    Ok((n, addr))
}

/// Queries the local address bound to `fd`.
///
/// # Safety
///
/// `addrlen` must point to a valid `u32` initialized to the byte capacity of `addr`,
/// and `addr` must be writable for that many bytes.
pub unsafe fn getsockname_raw(fd: RawFd, addr: *mut u8, addrlen: *mut u32) -> SysResult<()> {
    // SAFETY: Caller guarantees `addr` and `addrlen` are valid writable pointers.
    unsafe {
        syscall3(
            nr::GETSOCKNAME,
            fd as usize,
            addr as usize,
            addrlen as usize,
        )?;
    }
    Ok(())
}

/// Queries the peer address connected to `fd`.
///
/// # Safety
///
/// `addrlen` must point to a valid `u32` initialized to the byte capacity of `addr`,
/// and `addr` must be writable for that many bytes.
pub unsafe fn getpeername_raw(fd: RawFd, addr: *mut u8, addrlen: *mut u32) -> SysResult<()> {
    // SAFETY: Caller guarantees `addr` and `addrlen` are valid writable pointers.
    unsafe {
        syscall3(
            nr::GETPEERNAME,
            fd as usize,
            addr as usize,
            addrlen as usize,
        )?;
    }
    Ok(())
}

/// Queries the local `AF_INET` address bound to `fd`.
pub fn getsockname_in(fd: RawFd) -> SysResult<SockAddrIn> {
    let mut addr = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    // SAFETY: `addr` and `len` are valid stack variables sized for `SockAddrIn`.
    unsafe {
        getsockname_raw(
            fd,
            core::ptr::from_mut(&mut addr).cast::<u8>(),
            core::ptr::from_mut(&mut len),
        )?;
    }
    Ok(addr)
}

/// Queries the local `AF_INET6` address bound to `fd`.
pub fn getsockname_in6(fd: RawFd) -> SysResult<SockAddrIn6> {
    let mut addr = SockAddrIn6::default();
    let mut len = size_of::<SockAddrIn6>() as u32;
    // SAFETY: `addr` and `len` are valid stack variables sized for `SockAddrIn6`.
    unsafe {
        getsockname_raw(
            fd,
            core::ptr::from_mut(&mut addr).cast::<u8>(),
            core::ptr::from_mut(&mut len),
        )?;
    }
    Ok(addr)
}

/// Enables or disables `TCP_NODELAY` on `fd`.
pub fn set_tcp_nodelay(fd: RawFd, nodelay: bool) -> SysResult<()> {
    let val: i32 = i32::from(nodelay);
    // SAFETY: `val` is a 4-byte `i32` on the stack.
    unsafe {
        setsockopt_raw(
            fd,
            IPPROTO_TCP,
            TCP_NODELAY,
            core::ptr::from_ref(&val).cast::<u8>(),
            size_of::<i32>() as u32,
        )
    }
}

/// Queries and clears any pending `SO_ERROR` on `fd`.
pub fn get_so_error(fd: RawFd) -> SysResult<i32> {
    let mut err: i32 = 0;
    let mut len = size_of::<i32>() as u32;
    // SAFETY: `err` and `len` are valid stack variables for a 4-byte `i32` option value.
    unsafe {
        getsockopt_raw(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            core::ptr::from_mut(&mut err).cast::<u8>(),
            core::ptr::from_mut(&mut len),
        )?;
    }
    Ok(err)
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

    #[test]
    fn ipv4_and_ipv6_sockaddr_layouts_and_byte_order() {
        let v4 = SockAddrIn::new([127, 0, 0, 1], 8080);
        assert_eq!(v4.sin_family, AF_INET as u16);
        assert_eq!(v4.sin_port, 8080u16.to_be());
        assert_eq!(v4.sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 1]));
        assert_eq!(v4.ip(), [127, 0, 0, 1]);
        assert_eq!(v4.port(), 8080);

        let ip6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6 = SockAddrIn6::new(ip6, 443, 0x1234, 2);
        assert_eq!(v6.sin6_family, AF_INET6 as u16);
        assert_eq!(v6.sin6_port, 443u16.to_be());
        assert_eq!(v6.sin6_flowinfo, 0x1234);
        assert_eq!(v6.sin6_addr.s6_addr, ip6);
        assert_eq!(v6.sin6_scope_id, 2);
        assert_eq!(v6.ip(), ip6);
        assert_eq!(v6.port(), 443);
    }
}
