//! Pure-Rust thread lifecycle (`spawn_thread`, `ThreadHandle`), per-thread `errno`,
//! and 64-key thread-local storage with exit destructors.

use core::cell::UnsafeCell;
use core::mem::{ManuallyDrop, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::errno::{EDEADLK, EINVAL, ENOMEM, Errno, SysResult};
use crate::heap::{GLOBAL_MMAP_HEAP, c_free};
use crate::mm::{
    MAP_STACK, PAGE_SIZE, PROT_NONE, PROT_READ, PROT_WRITE, mmap_anonymous, mprotect, munmap,
};

pub const MAX_TLS_KEYS: usize = 64;
pub const DEFAULT_STACK_BYTES: usize = 512 * 1024;
pub const MIN_STACK_BYTES: usize = 64 * 1024;

pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

const JOIN_JOINABLE: u32 = 0;
const JOIN_DETACHED: u32 = 1;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const JOIN_EXITING: u32 = 2;

const TLS_KEY_FREE: u8 = 0;
const TLS_KEY_IN_USE: u8 = 1;

#[repr(C, align(64))]
struct ThreadControlBlock {
    errno: UnsafeCell<i32>,
    tls_values: UnsafeCell<[*mut u8; MAX_TLS_KEYS]>,
    child_tid: AtomicU32,
    join_state: AtomicU32,
    stack_map_base: *mut u8,
    stack_map_len: usize,
    entry_fn: Option<extern "C" fn(*mut u8)>,
    entry_arg: *mut u8,
}

impl ThreadControlBlock {
    const fn new() -> Self {
        Self {
            errno: UnsafeCell::new(0),
            tls_values: UnsafeCell::new([null_mut(); MAX_TLS_KEYS]),
            child_tid: AtomicU32::new(0),
            join_state: AtomicU32::new(JOIN_JOINABLE),
            stack_map_base: null_mut(),
            stack_map_len: 0,
            entry_fn: None,
            entry_arg: null_mut(),
        }
    }
}

#[repr(transparent)]
struct SyncTcb(ThreadControlBlock);
// SAFETY: `MAIN_TCB` is only accessed per-thread via `current_tcb()`.
unsafe impl Sync for SyncTcb {}

static MAIN_TCB: SyncTcb = SyncTcb(ThreadControlBlock::new());

#[inline]
fn current_tcb() -> &'static ThreadControlBlock {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let mut tp: usize;
        // SAFETY: `TPIDR_EL0` holds the thread's `ThreadControlBlock` pointer when set.
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack, preserves_flags));
        }
        if tp != 0 {
            // SAFETY: Non-zero `TPIDR_EL0` points to a live `ThreadControlBlock`.
            return unsafe { &*(tp as *const ThreadControlBlock) };
        }
    }
    &MAIN_TCB.0
}

#[must_use]
pub fn errno_cell() -> *mut i32 {
    current_tcb().errno.get()
}

#[must_use]
pub fn current_thread_id() -> u64 {
    core::ptr::from_ref(current_tcb()) as usize as u64
}

static TLS_KEY_STATE: [AtomicU8; MAX_TLS_KEYS] =
    [const { AtomicU8::new(TLS_KEY_FREE) }; MAX_TLS_KEYS];
static TLS_DTORS: [AtomicUsize; MAX_TLS_KEYS] = [const { AtomicUsize::new(0) }; MAX_TLS_KEYS];

#[must_use]
pub fn tls_key_create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Option<usize> {
    let dtor_addr = dtor.map_or(0, |f| f as usize);
    for key in 0..MAX_TLS_KEYS {
        if TLS_KEY_STATE[key]
            .compare_exchange(
                TLS_KEY_FREE,
                TLS_KEY_IN_USE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            TLS_DTORS[key].store(dtor_addr, Ordering::Release);
            // SAFETY: Clearing the calling thread's own TLS slot for the newly allocated key.
            unsafe { (*current_tcb().tls_values.get())[key] = null_mut() };
            return Some(key);
        }
    }
    None
}

pub fn tls_key_delete(key: usize) {
    if key >= MAX_TLS_KEYS {
        return;
    }
    TLS_DTORS[key].store(0, Ordering::Release);
    // SAFETY: Clearing the calling thread's own TLS slot.
    unsafe { (*current_tcb().tls_values.get())[key] = null_mut() };
    TLS_KEY_STATE[key].store(TLS_KEY_FREE, Ordering::Release);
}

#[must_use]
pub fn tls_get(key: usize) -> *mut u8 {
    if key >= MAX_TLS_KEYS || TLS_KEY_STATE[key].load(Ordering::Acquire) != TLS_KEY_IN_USE {
        return null_mut();
    }
    // SAFETY: Reading the calling thread's own TLS slot.
    unsafe { (*current_tcb().tls_values.get())[key] }
}

pub fn tls_set(key: usize, val: *mut u8) -> bool {
    if key >= MAX_TLS_KEYS || TLS_KEY_STATE[key].load(Ordering::Acquire) != TLS_KEY_IN_USE {
        return false;
    }
    // SAFETY: Writing the calling thread's own TLS slot.
    unsafe { (*current_tcb().tls_values.get())[key] = val };
    true
}

pub fn run_current_thread_tls_destructors() {
    let tcb = current_tcb();
    for key in 0..MAX_TLS_KEYS {
        // SAFETY: Accessing the calling thread's own TLS slot.
        let val = unsafe { (*tcb.tls_values.get())[key] };
        if !val.is_null() {
            // SAFETY: Clearing the calling thread's own TLS slot before invoking the destructor.
            unsafe { (*tcb.tls_values.get())[key] = null_mut() };
            if TLS_KEY_STATE[key].load(Ordering::Acquire) == TLS_KEY_IN_USE {
                let addr = TLS_DTORS[key].load(Ordering::Acquire);
                if addr != 0 {
                    // SAFETY: `addr` was stored from an `unsafe extern "C" fn(*mut u8)` in `tls_key_create`.
                    let dtor: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(addr) };
                    // SAFETY: `dtor` accepts `val` for this TLS key.
                    unsafe { dtor(val) };
                }
            }
        }
    }
}

pub struct ThreadHandle {
    tcb: *mut ThreadControlBlock,
}

// SAFETY: `ThreadHandle` owns a thread lifecycle reference synchronized via atomics and futexes.
unsafe impl Send for ThreadHandle {}
// SAFETY: Shared references to `ThreadHandle` only inspect immutable pointer identity.
unsafe impl Sync for ThreadHandle {}

impl ThreadHandle {
    #[must_use]
    pub fn id(&self) -> u64 {
        self.tcb as usize as u64
    }

    #[must_use]
    pub fn is_current(&self) -> bool {
        current_thread_id() == self.id()
    }

    pub fn join(self) -> SysResult<()> {
        if self.is_current() {
            let _ = ManuallyDrop::new(self);
            return Err(Errno(EDEADLK));
        }
        let this = ManuallyDrop::new(self);
        let tcb = this.tcb;
        // SAFETY: `tcb` is valid for the lifetime of this joinable `ThreadHandle`.
        unsafe {
            loop {
                let tid = (*tcb).child_tid.load(Ordering::Acquire);
                if tid == 0 {
                    break;
                }
                crate::sync::futex_wait(&(*tcb).child_tid, tid, None);
            }
            if !(*tcb).stack_map_base.is_null() && (*tcb).stack_map_len > 0 {
                let _ = munmap((*tcb).stack_map_base, (*tcb).stack_map_len);
            }
            c_free(tcb.cast::<u8>());
        }
        Ok(())
    }

    pub fn detach(self) -> SysResult<()> {
        let mut this = ManuallyDrop::new(self);
        this.detach_inner();
        Ok(())
    }

    fn detach_inner(&mut self) {
        let tcb = self.tcb;
        if tcb.is_null() {
            return;
        }
        self.tcb = null_mut();
        // SAFETY: `tcb` is valid until either the worker sees `JOIN_DETACHED` or we wait for `child_tid == 0`.
        unsafe {
            if (*tcb)
                .join_state
                .compare_exchange(
                    JOIN_JOINABLE,
                    JOIN_DETACHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                loop {
                    let tid = (*tcb).child_tid.load(Ordering::Acquire);
                    if tid == 0 {
                        break;
                    }
                    crate::sync::futex_wait(&(*tcb).child_tid, tid, None);
                }
                if !(*tcb).stack_map_base.is_null() && (*tcb).stack_map_len > 0 {
                    let _ = munmap((*tcb).stack_map_base, (*tcb).stack_map_len);
                }
                c_free(tcb.cast::<u8>());
            }
        }
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        self.detach_inner();
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn child_thread_start(tcb_ptr: *mut ThreadControlBlock) -> ! {
    // SAFETY: `tcb_ptr` is the valid `ThreadControlBlock` allocated by `spawn_thread`.
    unsafe {
        if let Some(entry) = (*tcb_ptr).entry_fn {
            entry((*tcb_ptr).entry_arg);
        }
    }
    run_current_thread_tls_destructors();
    // SAFETY: Synchronizing exit disposition with `ThreadHandle::join` / `ThreadHandle::detach`.
    unsafe {
        if (*tcb_ptr).join_state.swap(JOIN_EXITING, Ordering::AcqRel) == JOIN_JOINABLE {
            crate::process::exit_thread(0);
        }
        let map_base = (*tcb_ptr).stack_map_base as usize;
        let map_len = (*tcb_ptr).stack_map_len;
        core::arch::asm!(
            "msr tpidr_el0, xzr",
            "mov x8, {munmap_nr}",
            "svc #0",
            "mov x0, #0",
            "mov x8, {exit_nr}",
            "svc #0",
            "brk #0",
            munmap_nr = const crate::raw::nr::MUNMAP,
            exit_nr = const crate::raw::nr::EXIT,
            in("x0") map_base,
            in("x1") map_len,
            options(noreturn, nostack),
        );
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
unsafe fn raw_clone_thread(
    flags: u64,
    child_sp: usize,
    parent_tid: usize,
    tls: usize,
    child_tid: usize,
) -> SysResult<usize> {
    let ret: usize;
    // SAFETY: Caller sets up a valid `child_sp` with `tcb` at `[child_sp]` and valid TID/TLS pointers.
    unsafe {
        core::arch::asm!(
            "svc #0",
            "cbnz x0, 2f",
            "ldr x0, [sp]",
            "add sp, sp, #16",
            "mov x29, #0",
            "mov x30, #0",
            "bl {child_start}",
            "brk #0",
            "2:",
            child_start = sym child_thread_start,
            in("x8") crate::raw::nr::CLONE,
            inlateout("x0") flags as usize => ret,
            in("x1") child_sp,
            in("x2") parent_tid,
            in("x3") tls,
            in("x4") child_tid,
            options(nostack),
        );
    }
    crate::raw::decode_raw(ret)
}

/// Spawns a new thread executing `entry(arg)` on a guarded stack.
///
/// # Safety
///
/// `entry` and `arg` must satisfy thread-safety invariants for the lifetime of the spawned thread.
pub unsafe fn spawn_thread(
    stack_bytes: usize,
    entry: extern "C" fn(*mut u8),
    arg: *mut u8,
    detached: bool,
) -> SysResult<Option<ThreadHandle>> {
    let usable_stack = stack_bytes
        .max(MIN_STACK_BYTES)
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
        .ok_or(Errno(EINVAL))?;
    let total_map = usable_stack.checked_add(PAGE_SIZE).ok_or(Errno(EINVAL))?;
    let map_base = mmap_anonymous(total_map, PROT_READ | PROT_WRITE, MAP_STACK)?;
    // SAFETY: `map_base` is page-aligned and `[map_base, map_base + PAGE_SIZE)` is within the mapping.
    if let Err(e) = unsafe { mprotect(map_base, PAGE_SIZE, PROT_NONE) } {
        // SAFETY: Unmapping the region just returned by `mmap_anonymous`.
        let _ = unsafe { munmap(map_base, total_map) };
        return Err(e);
    }

    // SAFETY: Allocating a 64-byte aligned `ThreadControlBlock` from `GLOBAL_MMAP_HEAP`.
    let raw_tcb = unsafe { GLOBAL_MMAP_HEAP.alloc_c(size_of::<ThreadControlBlock>(), 64) };
    if raw_tcb.is_null() {
        // SAFETY: Unmapping the stack region on TCB allocation failure.
        let _ = unsafe { munmap(map_base, total_map) };
        return Err(Errno(ENOMEM));
    }
    let tcb = raw_tcb.cast::<ThreadControlBlock>();
    // SAFETY: `tcb` points to a writable, aligned `ThreadControlBlock` allocation.
    unsafe {
        tcb.write(ThreadControlBlock::new());
        (*tcb)
            .child_tid
            .store(if detached { 0 } else { u32::MAX }, Ordering::Relaxed);
        (*tcb).join_state.store(
            if detached {
                JOIN_DETACHED
            } else {
                JOIN_JOINABLE
            },
            Ordering::Relaxed,
        );
        (*tcb).stack_map_base = map_base;
        (*tcb).stack_map_len = total_map;
        (*tcb).entry_fn = Some(entry);
        (*tcb).entry_arg = arg;
    }

    let child_sp = (((map_base as usize) + total_map) & !15usize) - 16;
    // SAFETY: `child_sp` lies at the top of the writable stack region above the guard page.
    unsafe {
        let frame = child_sp as *mut usize;
        frame.write(tcb as usize);
        frame.add(1).write(0);
    }

    let mut flags = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS;
    let (parent_tid_ptr, child_tid_ptr) = if detached {
        (0usize, 0usize)
    } else {
        flags |= CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
        // SAFETY: `tcb` is a valid aligned `ThreadControlBlock`.
        let tid_addr = unsafe { core::ptr::addr_of!((*tcb).child_tid) as usize };
        (tid_addr, tid_addr)
    };

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `child_sp`, `tcb`, and TID pointers are valid for `CLONE`.
    let clone_res =
        unsafe { raw_clone_thread(flags, child_sp, parent_tid_ptr, tcb as usize, child_tid_ptr) };
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    // SAFETY: Invoking mocked/host `CLONE` syscall with validated stack and TCB pointers.
    let clone_res = unsafe {
        crate::raw::syscall5(
            crate::raw::nr::CLONE,
            flags as usize,
            child_sp,
            parent_tid_ptr,
            tcb as usize,
            child_tid_ptr,
        )
    };

    match clone_res {
        Ok(_) if detached => {
            #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
            // SAFETY: Under host mock syscalls no child thread runs, so reclaim simulated stack & TCB cleanly.
            unsafe {
                let _ = munmap(map_base, total_map);
                c_free(tcb.cast::<u8>());
            }
            Ok(None)
        }
        Ok(_) => Ok(Some(ThreadHandle { tcb })),
        Err(e) => {
            // SAFETY: `CLONE` failed before any child thread started; reclaim stack and TCB.
            unsafe {
                let _ = munmap(map_base, total_map);
                c_free(tcb.cast::<u8>());
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::EAGAIN;
    use crate::raw::{nr, with_mock_syscall};
    use core::sync::atomic::AtomicBool;

    #[test]
    fn errno_and_tls_destructors() {
        assert_ne!(current_thread_id(), 0);
        let ptr = errno_cell();
        unsafe {
            let prev = *ptr;
            *ptr = 42;
            assert_eq!(*errno_cell(), 42);
            *ptr = prev;
        }
        static DTOR_CALLED: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn dtor(val: *mut u8) {
            DTOR_CALLED.store(val as usize, Ordering::SeqCst);
        }
        let k = tls_key_create(Some(dtor)).expect("tls key");
        assert!(tls_set(k, core::ptr::dangling_mut::<u8>()));
        assert!(!tls_get(k).is_null());
        run_current_thread_tls_destructors();
        assert_ne!(DTOR_CALLED.load(Ordering::SeqCst), 0);
        assert!(tls_get(k).is_null());
        tls_key_delete(k);
    }

    #[test]
    fn spawn_join_and_clone_error_cleanup() {
        #[repr(align(4096))]
        struct AlignedArena([u8; 256 * 1024]);

        extern "C" fn dummy(_: *mut u8) {}
        static mut ARENA: AlignedArena = AlignedArena([0; 256 * 1024]);
        static OFFSET: AtomicUsize = AtomicUsize::new(0);
        static FAIL_CLONE: AtomicBool = AtomicBool::new(false);
        static MUNMAPS: AtomicUsize = AtomicUsize::new(0);

        OFFSET.store(0, Ordering::SeqCst);
        FAIL_CLONE.store(false, Ordering::SeqCst);
        MUNMAPS.store(0, Ordering::SeqCst);

        with_mock_syscall(
            |sys_nr, args| match sys_nr {
                nr::MMAP => {
                    let len = (args[1] + 4095) & !4095;
                    let off = OFFSET.fetch_add(len, Ordering::SeqCst);
                    if off + len > 256 * 1024 {
                        return Err(Errno(ENOMEM));
                    }
                    // SAFETY: `off + len` lies within `ARENA` while `MOCK_LOCK` serializes mock tests.
                    let ptr = unsafe { core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(off) };
                    Ok(ptr as usize)
                }
                nr::MPROTECT => Ok(0),
                nr::MUNMAP => {
                    MUNMAPS.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
                nr::CLONE if FAIL_CLONE.load(Ordering::SeqCst) => Err(Errno(EAGAIN)),
                nr::CLONE => {
                    let tid = args[4] as *const AtomicU32;
                    if !tid.is_null() {
                        unsafe { (*tid).store(0, Ordering::Release) };
                    }
                    Ok(777)
                }
                _ => Err(Errno(crate::errno::ENOSYS)),
            },
            || {
                let h = unsafe { spawn_thread(MIN_STACK_BYTES, dummy, null_mut(), false) }
                    .expect("spawn")
                    .expect("handle");
                let before = MUNMAPS.load(Ordering::SeqCst);
                h.join().expect("join");
                assert!(MUNMAPS.load(Ordering::SeqCst) > before);

                FAIL_CLONE.store(true, Ordering::SeqCst);
                let before_fail = MUNMAPS.load(Ordering::SeqCst);
                let err = unsafe { spawn_thread(MIN_STACK_BYTES, dummy, null_mut(), false) };
                assert_eq!(err.err(), Some(Errno(EAGAIN)));
                assert!(MUNMAPS.load(Ordering::SeqCst) > before_fail);
            },
        );
    }
}
