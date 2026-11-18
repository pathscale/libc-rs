//! Raw AArch64 `svc #0` system call dispatch and syscall numbers.

use crate::errno::{Errno, SysResult};

/// AArch64 unikernel system call numbers.
pub mod nr {
    pub const GETCWD: usize = 17;
    pub const EVENTFD2: usize = 19;
    pub const EPOLL_CREATE1: usize = 20;
    pub const EPOLL_CTL: usize = 21;
    pub const EPOLL_PWAIT: usize = 22;
    pub const DUP: usize = 23;
    pub const DUP3: usize = 24;
    pub const FCNTL: usize = 25;
    pub const IOCTL: usize = 29;
    pub const FLOCK: usize = 32;
    pub const MKDIRAT: usize = 34;
    pub const UNLINKAT: usize = 35;
    pub const SYMLINKAT: usize = 36;
    pub const LINKAT: usize = 37;
    pub const RENAMEAT: usize = 38;
    pub const UMOUNT2: usize = 39;
    pub const MOUNT: usize = 40;
    pub const FTRUNCATE: usize = 46;
    pub const FACCESSAT: usize = 48;
    pub const CHDIR: usize = 49;
    pub const FCHDIR: usize = 50;
    pub const CHROOT: usize = 51;
    pub const FCHMOD: usize = 52;
    pub const FCHMODAT: usize = 53;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const PIPE2: usize = 59;
    pub const GETDENTS64: usize = 61;
    pub const LSEEK: usize = 62;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const READV: usize = 65;
    pub const WRITEV: usize = 66;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const PPOLL: usize = 73;
    pub const READLINKAT: usize = 78;
    pub const NEWFSTATAT: usize = 79;
    pub const FSTAT: usize = 80;
    pub const SYNC: usize = 81;
    pub const FSYNC: usize = 82;
    pub const FDATASYNC: usize = 83;
    pub const TIMERFD_CREATE: usize = 85;
    pub const TIMERFD_SETTIME: usize = 86;
    pub const TIMERFD_GETTIME: usize = 87;
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const WAITID: usize = 95;
    pub const FUTEX: usize = 98;
    pub const NANOSLEEP: usize = 101;
    pub const CLOCK_SETTIME: usize = 112;
    pub const CLOCK_GETTIME: usize = 113;
    pub const CLOCK_GETRES: usize = 114;
    pub const CLOCK_NANOSLEEP: usize = 115;
    pub const SCHED_YIELD: usize = 124;
    pub const KILL: usize = 129;
    pub const TKILL: usize = 130;
    pub const TGKILL: usize = 131;
    pub const SIGALTSTACK: usize = 132;
    pub const RT_SIGACTION: usize = 134;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const RT_SIGRETURN: usize = 139;
    pub const REBOOT: usize = 142;
    pub const SETRESUID: usize = 147;
    pub const GETRESUID: usize = 148;
    pub const SETRESGID: usize = 149;
    pub const GETRESGID: usize = 150;
    pub const SETPGID: usize = 154;
    pub const GETPGID: usize = 155;
    pub const SETSID: usize = 157;
    pub const GETGROUPS: usize = 158;
    pub const SETGROUPS: usize = 159;
    pub const UNAME: usize = 160;
    pub const GETRLIMIT: usize = 163;
    pub const SETRLIMIT: usize = 164;
    pub const GETRUSAGE: usize = 165;
    pub const UMASK: usize = 166;
    pub const PRCTL: usize = 167;
    pub const GETPID: usize = 172;
    pub const GETPPID: usize = 173;
    pub const GETUID: usize = 174;
    pub const GETEUID: usize = 175;
    pub const GETGID: usize = 176;
    pub const GETEGID: usize = 177;
    pub const GETTID: usize = 178;
    pub const SOCKET: usize = 198;
    pub const SOCKETPAIR: usize = 199;
    pub const BIND: usize = 200;
    pub const LISTEN: usize = 201;
    pub const ACCEPT: usize = 202;
    pub const CONNECT: usize = 203;
    pub const GETSOCKNAME: usize = 204;
    pub const GETPEERNAME: usize = 205;
    pub const SENDTO: usize = 206;
    pub const RECVFROM: usize = 207;
    pub const SETSOCKOPT: usize = 208;
    pub const GETSOCKOPT: usize = 209;
    pub const SHUTDOWN: usize = 210;
    pub const MUNMAP: usize = 215;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
    pub const MINCORE: usize = 232;
    pub const MADVISE: usize = 233;
    pub const ACCEPT4: usize = 242;
    pub const WAIT4: usize = 260;
    pub const PRLIMIT64: usize = 261;
    pub const RENAMEAT2: usize = 276;
    pub const GETRANDOM: usize = 278;
    pub const MEMFD_CREATE: usize = 279;
    pub const EXECVEAT: usize = 281;
    pub const CLONE3: usize = 435;
    pub const EPOLL_PWAIT2: usize = 441;
}

/// Decodes a raw `x0` return value from `svc #0` into [`SysResult<usize>`].
///
/// Negative values in `-4095..=-1` represent `-errno`.
pub const fn decode_raw(raw: usize) -> SysResult<usize> {
    let signed = raw as isize;
    if signed >= -4095 && signed < 0 {
        Err(Errno((-signed) as i32))
    } else {
        Ok(raw)
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
mod mock {
    #[cfg(test)]
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    use crate::errno::{ENOSYS, Errno, SysResult};

    pub type SyscallHandler = fn(usize, [usize; 6]) -> SysResult<usize>;

    pub static MOCK_SYSCALL: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    static MOCK_LOCK: AtomicBool = AtomicBool::new(false);

    #[cfg(test)]
    struct LockGuard;

    #[cfg(test)]
    impl Drop for LockGuard {
        fn drop(&mut self) {
            MOCK_SYSCALL.store(0, Ordering::Release);
            MOCK_LOCK.store(false, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub fn with_mock_syscall<R>(handler: SyscallHandler, f: impl FnOnce() -> R) -> R {
        while MOCK_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let _guard = LockGuard;
        MOCK_SYSCALL.store(handler as usize, Ordering::Release);
        f()
    }

    pub fn dispatch(nr: usize, args: [usize; 6]) -> SysResult<usize> {
        let ptr = MOCK_SYSCALL.load(Ordering::Acquire);
        if ptr == 0 {
            return Err(Errno(ENOSYS));
        }
        // SAFETY: `ptr` was stored from a `SyscallHandler` function pointer in `with_mock_syscall`.
        let handler: SyscallHandler = unsafe { core::mem::transmute(ptr) };
        handler(nr, args)
    }
}

#[cfg(test)]
pub(crate) fn with_mock_syscall<R>(
    handler: fn(usize, [usize; 6]) -> SysResult<usize>,
    f: impl FnOnce() -> R,
) -> R {
    mock::with_mock_syscall(handler, f)
}

/// Invokes a 0-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall0(nr: usize) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                lateout("x0") ret,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [0, 0, 0, 0, 0, 0])
    }
}

/// Invokes a 1-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall1(nr: usize, a0: usize) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, 0, 0, 0, 0, 0])
    }
}

/// Invokes a 2-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall2(nr: usize, a0: usize, a1: usize) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                in("x1") a1,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, a1, 0, 0, 0, 0])
    }
}

/// Invokes a 3-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                in("x1") a1,
                in("x2") a2,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, a1, a2, 0, 0, 0])
    }
}

/// Invokes a 4-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, a1, a2, a3, 0, 0])
    }
}

/// Invokes a 5-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall5(
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                in("x4") a4,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, a1, a2, a3, a4, 0])
    }
}

/// Invokes a 6-argument system call.
///
/// # Safety
///
/// The caller must uphold the ABI and memory safety invariants required by syscall `nr`.
#[inline]
pub unsafe fn syscall6(
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> SysResult<usize> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ret: usize;
        // SAFETY: The caller upholds the syscall contract for `nr`.
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") nr,
                inlateout("x0") a0 => ret,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                in("x4") a4,
                in("x5") a5,
                options(nostack, preserves_flags),
            );
        }
        decode_raw(ret)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        mock::dispatch(nr, [a0, a1, a2, a3, a4, a5])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::{EINVAL, ENOSYS};

    #[test]
    fn decode_raw_boundaries() {
        assert_eq!(decode_raw(0), Ok(0));
        assert_eq!(decode_raw(42), Ok(42));
        assert_eq!(decode_raw((-22isize) as usize), Err(Errno(EINVAL)));
        assert_eq!(decode_raw((-4095isize) as usize), Err(Errno(4095)));
        assert_eq!(decode_raw((-4096isize) as usize), Ok((-4096isize) as usize));
    }

    #[test]
    fn default_mock_returns_enosys() {
        let res = unsafe { syscall0(nr::GETPID) };
        assert_eq!(res, Err(Errno(ENOSYS)));
    }
}
