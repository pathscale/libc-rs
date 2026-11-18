//! Raw AArch64 `svc #0` system call dispatch and syscall numbers.

use crate::errno::{Errno, SysResult};

/// AArch64 unikernel system call numbers.
pub mod nr {
    pub const GETCWD: usize = 17;
    pub const EVENTFD2: usize = 19;
    pub const EPOLL_CREATE1: usize = 20;
    pub const EPOLL_CTL: usize = 21;
    pub const DUP: usize = 23;
    pub const DUP3: usize = 24;
    pub const FCNTL: usize = 25;
    pub const IOCTL: usize = 29;
    pub const FLOCK: usize = 32;
    pub const MKDIRAT: usize = 34;
    pub const UNLINKAT: usize = 35;
    pub const LINKAT: usize = 37;
    pub const RENAMEAT: usize = 38;
    pub const FTRUNCATE: usize = 46;
    pub const FACCESSAT: usize = 48;
    pub const CHDIR: usize = 49;
    pub const FCHMOD: usize = 52;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const PIPE2: usize = 59;
    pub const GETDENTS64: usize = 61;
    pub const LSEEK: usize = 62;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const WRITEV: usize = 66;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const PPOLL: usize = 73;
    pub const READLINKAT: usize = 78;
    pub const NEWFSTATAT: usize = 79;
    pub const FSTAT: usize = 80;
    pub const FSYNC: usize = 82;
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const FUTEX: usize = 98;
    pub const CLOCK_SETTIME: usize = 112;
    pub const CLOCK_GETTIME: usize = 113;
    pub const CLOCK_NANOSLEEP: usize = 115;
    pub const SCHED_YIELD: usize = 124;
    pub const KILL: usize = 129;
    pub const RT_SIGACTION: usize = 134;
    pub const RT_SIGRETURN: usize = 139;
    pub const SETPGID: usize = 154;
    pub const SETSID: usize = 157;
    pub const GETRLIMIT: usize = 163;
    pub const SETRLIMIT: usize = 164;
    pub const GETRUSAGE: usize = 165;
    pub const UMASK: usize = 166;
    pub const GETPID: usize = 172;
    pub const GETUID: usize = 174;
    pub const GETEUID: usize = 175;
    pub const GETGID: usize = 176;
    pub const GETEGID: usize = 177;
    pub const GETTID: usize = 178;
    pub const SOCKET: usize = 198;
    pub const SOCKETPAIR: usize = 199;
    pub const BIND: usize = 200;
    pub const LISTEN: usize = 201;
    pub const CONNECT: usize = 203;
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
    pub const GETRANDOM: usize = 278;
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

/// Reads the hardware thread pointer register (`TPIDR_EL0`) on AArch64 EL0 targets,
/// returning `0` on host test targets or before a thread control block is installed.
#[must_use]
#[inline]
pub fn read_thread_pointer() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let tp: usize;
        // SAFETY: `TPIDR_EL0` is readable at EL0 with no memory side effects.
        unsafe {
            core::arch::asm!(
                "mrs {}, tpidr_el0",
                out(reg) tp,
                options(nomem, nostack, preserves_flags),
            );
        }
        tp
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        0
    }
}

/// Reads the AArch64 timer frequency register (`CNTFRQ_EL0`) on EL0 targets.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[must_use]
#[inline]
pub(crate) fn read_cntfrq_el0() -> u64 {
    let hz: u64;
    // SAFETY: `cntfrq_el0` is readable from EL0 when `CNTKCTL_EL1.EL0VCTEN == 1`.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            out(reg) hz,
            options(nomem, nostack, preserves_flags),
        );
    }
    hz
}

/// Reads the AArch64 virtual counter register (`CNTVCT_EL0`) on EL0 targets.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[must_use]
#[inline]
pub(crate) fn read_cntvct_el0() -> u64 {
    let ticks: u64;
    // SAFETY: `cntvct_el0` is readable from EL0 when `CNTKCTL_EL1.EL0VCTEN == 1`.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntvct_el0",
            out(reg) ticks,
            options(nomem, nostack, preserves_flags),
        );
    }
    ticks
}

/// Restorer trampoline invoking `rt_sigreturn` (`nr::RT_SIGRETURN = 139`) for `SA_RESTORER`.
///
/// # Safety
///
/// Must only be invoked by the kernel signal-return path with a valid signal frame on the stack.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn default_sigrestorer() -> ! {
    core::arch::naked_asm!("mov x8, #139", "svc #0", "brk #0",);
}

const _: () = {
    assert!(nr::RT_SIGRETURN == 139);
    assert!(nr::MUNMAP == 215);
    assert!(nr::EXIT == 93);
    assert!(nr::CLONE == 220);
};

/// Triggers an immediate hardware trap (`brk #0`) on AArch64 EL0 targets.
pub(crate) fn trap_abort() -> ! {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `brk #0` immediately traps execution at EL0 without touching memory or stack.
    unsafe {
        core::arch::asm!("brk #0", options(noreturn, nostack, nomem));
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        panic!("abort")
    }
}

/// Clears `TPIDR_EL0`, unmaps the calling detached thread's stack `[map_base, map_base + map_len)`,
/// and terminates the calling thread via `SYS_EXIT` without touching stack memory.
///
/// # Safety
///
/// Must only be called as the final action of a detached thread whose stack mapping is
/// `(map_base, map_len)` and with no live stack references remaining.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn unmap_stack_and_exit(map_base: usize, map_len: usize) -> ! {
    // SAFETY: Caller guarantees no stack memory is accessed after `MUNMAP` and `EXIT` never returns.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, xzr",
            "mov x8, #215",
            "svc #0",
            "mov x0, #0",
            "mov x8, #93",
            "svc #0",
            "brk #0",
            in("x0") map_base,
            in("x1") map_len,
            options(noreturn, nostack),
        );
    }
}

/// Spawns a child thread via `SYS_CLONE` on AArch64 EL0, invoking `child_entry()` when `CLONE`
/// returns `0` in the newly created thread.
///
/// # Safety
///
/// `child_sp` must be 16-byte aligned with `[child_sp - 16, child_sp + 64)` mapped RW,
/// `CLONE_SETTLS` must install a valid TCB in `tls` for `child_entry`, and `parent_tid`/`child_tid`
/// must satisfy `CLONE` flags.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(never)]
pub unsafe fn clone_thread(
    flags: u64,
    child_sp: usize,
    parent_tid: usize,
    tls: usize,
    child_tid: usize,
    child_entry: unsafe extern "C" fn() -> !,
) -> SysResult<usize> {
    let ret: usize;
    // SAFETY: Caller upholds `SYS_CLONE` stack, TLS, and TID pointer invariants.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr::CLONE,
            inlateout("x0") flags as usize => ret,
            in("x1") child_sp,
            in("x2") parent_tid,
            in("x3") tls,
            in("x4") child_tid,
            options(nostack, preserves_flags),
        );
    }
    if ret == 0 {
        // SAFETY: Running on the new child stack with `TPIDR_EL0 == tls`; `child_entry` never returns.
        unsafe { child_entry() }
    }
    decode_raw(ret)
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
