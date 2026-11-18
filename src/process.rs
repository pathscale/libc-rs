//! Process lifecycle, credentials, signals, resource limits, and wait syscalls.

use core::mem::size_of;

use crate::errno::SysResult;
use crate::raw::{nr, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5};
use crate::time::Timeval;

/// Hangup detected on controlling terminal or death of controlling process.
pub const SIGHUP: i32 = 1;
/// Interrupt from keyboard (`Ctrl-C`).
pub const SIGINT: i32 = 2;
/// Quit from keyboard.
pub const SIGQUIT: i32 = 3;
/// Illegal instruction.
pub const SIGILL: i32 = 4;
/// Abort signal.
pub const SIGABRT: i32 = 6;
/// Bus error (bad memory access).
pub const SIGBUS: i32 = 7;
/// Floating-point exception.
pub const SIGFPE: i32 = 8;
/// Kill signal (cannot be caught or ignored).
pub const SIGKILL: i32 = 9;
/// Invalid memory reference (segmentation fault).
pub const SIGSEGV: i32 = 11;
/// Broken pipe: write to pipe with no readers.
pub const SIGPIPE: i32 = 13;
/// Timer signal from `alarm`.
pub const SIGALRM: i32 = 14;
/// Termination signal.
pub const SIGTERM: i32 = 15;
/// Child stopped or terminated.
pub const SIGCHLD: i32 = 17;

/// Do not receive notification when child processes stop.
pub const SA_NOCLDSTOP: usize = 1;
/// Do not transform children into zombies when they terminate.
pub const SA_NOCLDWAIT: usize = 2;
/// Invoke signal-catching function with three arguments instead of one.
pub const SA_SIGINFO: usize = 4;
/// Signal trampoline restorer flag.
pub const SA_RESTORER: usize = 0x0400_0000;
/// Call the signal handler on an alternate signal stack.
pub const SA_ONSTACK: usize = 0x0800_0000;
/// Restart syscalls if interrupted by this signal handler.
pub const SA_RESTART: usize = 0x1000_0000;
/// Do not prevent the signal from being received from within its own handler.
pub const SA_NODEFER: usize = 0x4000_0000;
/// Restore the signal action to the default upon entry to the signal handler.
pub const SA_RESETHAND: usize = 0x8000_0000;

/// Default signal disposition.
pub const SIG_DFL: usize = 0;
/// Ignore signal disposition.
pub const SIG_IGN: usize = 1;

/// Return immediately if no child has exited.
pub const WNOHANG: i32 = 1;
/// Also return if a child has stopped.
pub const WUNTRACED: i32 = 2;

/// CPU time limit in seconds.
pub const RLIMIT_CPU: u32 = 0;
/// Maximum size of the process stack in bytes.
pub const RLIMIT_STACK: u32 = 3;
/// Value one greater than the maximum file descriptor number that can be opened.
pub const RLIMIT_NOFILE: u32 = 7;
/// Unlimited resource limit value.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Return resource usage for the calling process.
pub const RUSAGE_SELF: i32 = 0;
/// Return resource usage for terminated and waited-for children.
pub const RUSAGE_CHILDREN: i32 = -1;

/// Size in bytes of the kernel signal mask (`sigset_t` = 64 bits = 8 bytes).
pub const KERNEL_SIGSET_BYTES: usize = 8;

/// Returns `true` if wait status `s` indicates normal termination (`exit`).
#[must_use]
pub const fn wifexited(s: i32) -> bool {
    (s & 0x7f) == 0
}

/// Extracts the low 8 bits of the exit code from a wait status `s`.
#[must_use]
pub const fn wexitstatus(s: i32) -> i32 {
    (s >> 8) & 0xff
}

/// Extracts the terminating signal number from a wait status `s`.
#[must_use]
pub const fn wtermsig(s: i32) -> i32 {
    s & 0x7f
}

/// 64-bit kernel signal set (`sigset_t`) for `rt_sigaction` and `rt_sigprocmask`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelSigSet {
    pub bits: [u64; 1],
}

/// AArch64 kernel `struct sigaction` layout (32 bytes: `sa_handler`, `sa_flags`, `sa_restorer`, `sa_mask`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelSigAction {
    pub sa_handler: usize,
    pub sa_flags: usize,
    pub sa_restorer: usize,
    pub sa_mask: KernelSigSet,
}

/// Resource soft and hard limits (`struct rlimit`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// Process resource usage statistics (`struct rusage`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rusage {
    pub ru_utime: Timeval,
    pub ru_stime: Timeval,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

const _: () = {
    assert!(size_of::<KernelSigSet>() == KERNEL_SIGSET_BYTES);
    assert!(size_of::<KernelSigAction>() == 32);
    assert!(size_of::<Rlimit>() == 16);
    assert!(size_of::<Rusage>() == 144);
};

/// Terminates the calling thread with exit status `code`.
pub fn exit_thread(code: i32) -> ! {
    // SAFETY: `EXIT` terminates the current thread and does not access memory.
    let _ = unsafe { syscall1(nr::EXIT, code as usize) };
    abort()
}

/// Terminates all threads in the calling process with exit status `code`.
pub fn exit_group(code: i32) -> ! {
    // SAFETY: `EXIT_GROUP` terminates the process and does not access memory.
    let _ = unsafe { syscall1(nr::EXIT_GROUP, code as usize) };
    abort()
}

/// Immediately traps/aborts execution without unwinding.
pub fn abort() -> ! {
    let _ = kill(getpid(), SIGABRT);
    // SAFETY: `EXIT_GROUP` terminates all threads in the calling process.
    let _ = unsafe { syscall1(nr::EXIT_GROUP, 134) };
    crate::raw::trap_abort()
}

/// Returns the process ID (`PID`) of the calling process.
#[must_use]
pub fn getpid() -> i32 {
    // SAFETY: `GETPID` has no memory side effects.
    unsafe { syscall0(nr::GETPID).unwrap_or(0) as i32 }
}

/// Returns the caller's thread ID (`TID`).
#[must_use]
pub fn gettid() -> i32 {
    // SAFETY: `GETTID` has no memory side effects.
    unsafe { syscall0(nr::GETTID).unwrap_or(0) as i32 }
}

/// Returns the real user ID of the calling process.
#[must_use]
pub fn getuid() -> u32 {
    // SAFETY: `GETUID` has no memory side effects.
    unsafe { syscall0(nr::GETUID).unwrap_or(0) as u32 }
}

/// Returns the effective user ID of the calling process.
#[must_use]
pub fn geteuid() -> u32 {
    // SAFETY: `GETEUID` has no memory side effects.
    unsafe { syscall0(nr::GETEUID).unwrap_or(0) as u32 }
}

/// Returns the real group ID of the calling process.
#[must_use]
pub fn getgid() -> u32 {
    // SAFETY: `GETGID` has no memory side effects.
    unsafe { syscall0(nr::GETGID).unwrap_or(0) as u32 }
}

/// Returns the effective group ID of the calling process.
#[must_use]
pub fn getegid() -> u32 {
    // SAFETY: `GETEGID` has no memory side effects.
    unsafe { syscall0(nr::GETEGID).unwrap_or(0) as u32 }
}

/// Sets the process group ID (`pgid`) of the process specified by `pid`.
pub fn setpgid(pid: i32, pgid: i32) -> SysResult<()> {
    // SAFETY: `SETPGID` takes two scalar PID arguments.
    unsafe {
        syscall2(nr::SETPGID, pid as usize, pgid as usize)?;
    }
    Ok(())
}

/// Creates a session and sets the process group ID.
pub fn setsid() -> SysResult<i32> {
    // SAFETY: `SETSID` takes no arguments.
    unsafe { syscall0(nr::SETSID).map(|v| v as i32) }
}

/// Sets the calling process's file mode creation mask (`umask`) and returns the previous mask.
pub fn umask(mask: u32) -> u32 {
    // SAFETY: `UMASK` takes a scalar mode mask and always succeeds.
    unsafe { syscall1(nr::UMASK, mask as usize).unwrap_or(0) as u32 }
}

/// Gets resource limits for `resource`.
pub fn getrlimit(resource: u32) -> SysResult<Rlimit> {
    let mut rlim = Rlimit::default();
    // SAFETY: `rlim` is a valid stack `Rlimit` for the kernel to write into.
    unsafe {
        syscall2(
            nr::GETRLIMIT,
            resource as usize,
            core::ptr::from_mut(&mut rlim) as usize,
        )?;
    }
    Ok(rlim)
}

/// Sets resource limits for `resource` to `rlim`.
pub fn setrlimit(resource: u32, rlim: &Rlimit) -> SysResult<()> {
    // SAFETY: `rlim` is a valid shared reference to an `Rlimit`.
    unsafe {
        syscall2(
            nr::SETRLIMIT,
            resource as usize,
            core::ptr::from_ref(rlim) as usize,
        )?;
    }
    Ok(())
}

/// Gets resource usage measures for `who` (`RUSAGE_SELF` or `RUSAGE_CHILDREN`).
pub fn getrusage(who: i32) -> SysResult<Rusage> {
    let mut usage = Rusage::default();
    // SAFETY: `usage` is a valid stack `Rusage` for the kernel to populate.
    unsafe {
        syscall2(
            nr::GETRUSAGE,
            who as usize,
            core::ptr::from_mut(&mut usage) as usize,
        )?;
    }
    Ok(usage)
}

/// Yields the processor to the scheduler.
pub fn sched_yield() {
    // SAFETY: `SCHED_YIELD` has no memory arguments or unsafe invariants.
    let _ = unsafe { syscall0(nr::SCHED_YIELD) };
}

/// Sends signal `sig` to `pid`.
pub fn kill(pid: i32, sig: i32) -> SysResult<()> {
    // SAFETY: `KILL` takes scalar `pid` and `sig` arguments.
    unsafe {
        syscall2(nr::KILL, pid as usize, sig as usize)?;
    }
    Ok(())
}

/// Examines and changes a signal action using raw pointers.
///
/// # Safety
///
/// `act` must be null or point to a valid kernel `sigaction` of matching `sigsetsize`;
/// `oldact` must be null or point to writable memory for a kernel `sigaction`.
pub unsafe fn rt_sigaction_raw(
    signum: i32,
    act: *const u8,
    oldact: *mut u8,
    sigsetsize: usize,
) -> SysResult<()> {
    // SAFETY: Caller guarantees `act`, `oldact`, and `sigsetsize` are valid.
    unsafe {
        syscall4(
            nr::RT_SIGACTION,
            signum as usize,
            act as usize,
            oldact as usize,
            sigsetsize,
        )?;
    }
    Ok(())
}

/// Examines and changes a signal action using typed [`KernelSigAction`] structures.
///
/// # Safety
///
/// If `act` installs a signal handler function address (`sa_handler` not `SIG_DFL` or `SIG_IGN`),
/// that address must be a valid, async-signal-safe `extern "C"` handler following the target ABI.
pub unsafe fn sigaction(
    signum: i32,
    act: Option<&KernelSigAction>,
    oldact: Option<&mut KernelSigAction>,
) -> SysResult<()> {
    let effective: KernelSigAction;
    let act_ptr = match act {
        Some(a) => {
            let mut tmp = *a;
            if tmp.sa_handler > SIG_IGN && tmp.sa_restorer == 0 {
                tmp.sa_flags |= SA_RESTORER;
                #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                {
                    tmp.sa_restorer = crate::raw::default_sigrestorer as *const () as usize;
                }
                #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
                {
                    tmp.sa_restorer = 1;
                }
            }
            effective = tmp;
            core::ptr::from_ref(&effective).cast::<u8>()
        }
        None => core::ptr::null(),
    };
    let old_ptr = oldact.map_or(core::ptr::null_mut(), |o| {
        core::ptr::from_mut(o).cast::<u8>()
    });
    // SAFETY: `act_ptr` and `old_ptr` are derived from valid `KernelSigAction` references
    // with `KERNEL_SIGSET_BYTES == 8`, and caller guarantees handler safety.
    unsafe { rt_sigaction_raw(signum, act_ptr, old_ptr, KERNEL_SIGSET_BYTES) }
}

/// Creates a child process via `clone(SIGCHLD, 0, 0, 0, 0)`.
pub fn fork() -> SysResult<i32> {
    // SAFETY: `clone` with `flags = SIGCHLD` and zero `sp` duplicates the current process
    // identically to `fork()`.
    unsafe { syscall5(nr::CLONE, SIGCHLD as usize, 0, 0, 0, 0).map(|v| v as i32) }
}

/// Executes the program pointed to by `prog` with argument and environment pointer arrays.
///
/// # Safety
///
/// `prog` must be a valid NUL-terminated C string, and `argv` / `envp` must be valid
/// null-terminated arrays of NUL-terminated C string pointers.
pub unsafe fn execve_raw(
    prog: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> SysResult<()> {
    // SAFETY: Caller guarantees `prog`, `argv`, and `envp` are valid C string tables.
    unsafe {
        syscall3(nr::EXECVE, prog as usize, argv as usize, envp as usize)?;
    }
    Ok(())
}

/// Waits for state changes in a child process via `wait4(pid, status, options, null)` with an
/// optional status out-pointer.
pub fn waitpid_opt(pid: i32, status: Option<&mut i32>, options: i32) -> SysResult<i32> {
    let status_ptr = status.map_or(0, |s| core::ptr::from_mut(s) as usize);
    // SAFETY: `status_ptr` is either null (0) or a valid mutable `i32` reference, and `rusage` is null (0).
    unsafe { syscall4(nr::WAIT4, pid as usize, status_ptr, options as usize, 0).map(|v| v as i32) }
}

/// Waits for state changes in a child process via `wait4(pid, status, options, null)`.
pub fn waitpid(pid: i32, status: &mut i32, options: i32) -> SysResult<i32> {
    waitpid_opt(pid, Some(status), options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::with_mock_syscall;

    #[test]
    fn fork_invokes_clone_with_sigchld_and_wait_macros_decode_status() {
        let child_pid = with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::CLONE);
                assert_eq!(args[0], SIGCHLD as usize);
                assert_eq!(args[1], 0);
                assert_eq!(args[2], 0);
                assert_eq!(args[3], 0);
                assert_eq!(args[4], 0);
                Ok(1234)
            },
            || fork().unwrap(),
        );
        assert_eq!(child_pid, 1234);

        let status_exit_7 = 7 << 8;
        assert!(wifexited(status_exit_7));
        assert_eq!(wexitstatus(status_exit_7), 7);
        assert_eq!(wtermsig(status_exit_7), 0);

        let status_sig_9 = SIGKILL;
        assert!(!wifexited(status_sig_9));
        assert_eq!(wtermsig(status_sig_9), SIGKILL);
    }

    #[test]
    fn kernel_sigaction_layout_restorer_and_waitpid_opt() {
        assert_eq!(size_of::<KernelSigAction>(), 32);

        let act = KernelSigAction {
            sa_handler: 0x1234,
            sa_flags: SA_RESTART,
            sa_restorer: 0,
            sa_mask: KernelSigSet::default(),
        };
        with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::RT_SIGACTION);
                assert_eq!(args[0], SIGTERM as usize);
                assert_eq!(args[3], KERNEL_SIGSET_BYTES);
                let passed = unsafe { &*(args[1] as *const KernelSigAction) };
                assert_ne!(passed.sa_flags & SA_RESTORER, 0);
                assert_ne!(passed.sa_restorer, 0);
                Ok(0)
            },
            || unsafe { sigaction(SIGTERM, Some(&act), None).unwrap() },
        );

        let waited = with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::WAIT4);
                assert_eq!(args[0], 42);
                assert_eq!(args[1], 0);
                assert_eq!(args[2], 0);
                assert_eq!(args[3], 0);
                Ok(42)
            },
            || waitpid_opt(42, None, 0).unwrap(),
        );
        assert_eq!(waited, 42);
    }
}
