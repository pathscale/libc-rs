//! Pure-Rust thread lifecycle (`spawn_thread`, `ThreadHandle`), per-thread `errno`,
//! and 64-key thread-local storage with exit destructors.

use core::cell::UnsafeCell;
use core::mem::{ManuallyDrop, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::errno::{EDEADLK, EINVAL, ENOMEM, Errno, SysResult};
use crate::heap::{GLOBAL_MMAP_HEAP, c_free};
use crate::mm::{
    MAP_STACK, PAGE_SIZE, PROT_NONE, PROT_READ, PROT_WRITE, mmap_anonymous, mprotect, munmap,
};

/// Maximum number of concurrent thread-local storage keys.
pub const MAX_TLS_KEYS: usize = 64;
/// Maximum number of destructor cleanup passes executed at thread exit.
pub const TLS_DESTRUCTOR_ITERATIONS: usize = 4;
/// Default usable thread stack size in bytes (512 KiB).
pub const DEFAULT_STACK_BYTES: usize = 512 * 1024;
/// Minimum usable thread stack size in bytes (64 KiB).
pub const MIN_STACK_BYTES: usize = 64 * 1024;

/// Share virtual memory between parent and child.
pub const CLONE_VM: u64 = 0x0000_0100;
/// Share filesystem information between parent and child.
pub const CLONE_FS: u64 = 0x0000_0200;
/// Share open file descriptor table between parent and child.
pub const CLONE_FILES: u64 = 0x0000_0400;
/// Share signal handlers between parent and child.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// Place child in the same thread group as parent.
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// Share System V `SEM_UNDO` state.
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
/// Set thread-local storage descriptor (`TPIDR_EL0`) for child.
pub const CLONE_SETTLS: u64 = 0x0008_0000;
/// Store child thread ID at `parent_tid` in parent memory.
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// Clear `child_tid` and wake futex on thread exit.
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// Store child thread ID at `child_tid` in child memory.
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

const JOIN_JOINABLE: u32 = 0;
const JOIN_DETACHED: u32 = 1;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const JOIN_EXITING: u32 = 2;

const TLS_KEY_FREE: u8 = 0;
const TLS_KEY_IN_USE: u8 = 1;

/// Per-thread control block pointed to by `TPIDR_EL0` on bare-metal AArch64.
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
    retired_next: AtomicPtr<ThreadControlBlock>,
}

impl ThreadControlBlock {
    const fn new() -> Self {
        Self {
            errno: UnsafeCell::new(0),
            tls_values: UnsafeCell::new([null_mut(); MAX_TLS_KEYS]),
            child_tid: AtomicU32::new(0),
            join_state: AtomicU32::new(JOIN_DETACHED),
            stack_map_base: null_mut(),
            stack_map_len: 0,
            entry_fn: None,
            entry_arg: null_mut(),
            retired_next: AtomicPtr::new(null_mut()),
        }
    }
}

#[repr(transparent)]
struct SyncTcb(ThreadControlBlock);

// SAFETY: Each `ThreadControlBlock` slot is accessed only by its owning thread
// for `errno` and `tls_values`, and via atomic operations for lifecycle state.
unsafe impl Sync for SyncTcb {}

static MAIN_TCB: SyncTcb = SyncTcb(ThreadControlBlock::new());

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
const HOST_SLOTS: usize = 64;

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
static HOST_TOKENS: [AtomicUsize; HOST_SLOTS] = [const { AtomicUsize::new(0) }; HOST_SLOTS];

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
static HOST_TCBS: [SyncTcb; HOST_SLOTS] =
    [const { SyncTcb(ThreadControlBlock::new()) }; HOST_SLOTS];

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline]
fn host_thread_token() -> usize {
    #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
    {
        let val: usize;
        // SAFETY: `tpidrro_el0` holds the per-thread CPU/pthread pointer on Apple Silicon.
        unsafe {
            core::arch::asm!(
                "mrs {}, tpidrro_el0",
                out(reg) val,
                options(nomem, nostack, preserves_flags),
            );
        }
        val & !7usize
    }
    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    {
        let val: usize;
        // SAFETY: `tpidr_el0` holds the per-thread pointer on non-Apple AArch64 hosts.
        unsafe {
            core::arch::asm!(
                "mrs {}, tpidr_el0",
                out(reg) val,
                options(nomem, nostack, preserves_flags),
            );
        }
        val
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        1
    }
}

#[inline]
fn current_tcb() -> &'static ThreadControlBlock {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let raw: usize;
        // SAFETY: Reading `tpidr_el0` is always valid in EL0 on AArch64.
        unsafe {
            core::arch::asm!(
                "mrs {}, tpidr_el0",
                out(reg) raw,
                options(nomem, nostack, preserves_flags),
            );
        }
        if raw == 0 {
            &MAIN_TCB.0
        } else {
            // SAFETY: Non-zero `tpidr_el0` was installed by `CLONE_SETTLS` pointing to a valid `ThreadControlBlock`.
            unsafe { &*(raw as *const ThreadControlBlock) }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let token = host_thread_token();
        if token == 0 {
            return &MAIN_TCB.0;
        }
        let start = (token >> 4) % HOST_SLOTS;
        let mut i = 0;
        while i < HOST_SLOTS {
            let idx = (start + i) % HOST_SLOTS;
            let cur = HOST_TOKENS[idx].load(Ordering::Acquire);
            if cur == token {
                return &HOST_TCBS[idx].0;
            }
            if cur == 0
                && HOST_TOKENS[idx]
                    .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return &HOST_TCBS[idx].0;
            }
            i += 1;
        }
        &MAIN_TCB.0
    }
}

/// Returns a writable pointer to the calling thread's `errno` storage slot.
#[must_use]
pub fn errno_cell() -> *mut i32 {
    current_tcb().errno.get()
}

/// Returns a non-zero identifier unique to the calling thread.
#[must_use]
pub fn current_thread_id() -> u64 {
    core::ptr::from_ref(current_tcb()) as usize as u64
}

static TLS_KEY_STATE: [AtomicU8; MAX_TLS_KEYS] =
    [const { AtomicU8::new(TLS_KEY_FREE) }; MAX_TLS_KEYS];
static TLS_DTORS: [AtomicUsize; MAX_TLS_KEYS] = [const { AtomicUsize::new(0) }; MAX_TLS_KEYS];

#[inline]
fn encode_dtor(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> usize {
    match dtor {
        Some(f) => f as usize,
        None => 0,
    }
}

#[inline]
fn decode_dtor(raw: usize) -> Option<unsafe extern "C" fn(*mut u8)> {
    if raw == 0 {
        None
    } else {
        // SAFETY: `raw` was stored from a valid `unsafe extern "C" fn(*mut u8)` in `tls_key_create`.
        Some(unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8)>(raw) })
    }
}

/// Allocates a thread-local storage key in `0..MAX_TLS_KEYS` with an optional exit destructor.
#[must_use]
pub fn tls_key_create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Option<usize> {
    let encoded = encode_dtor(dtor);
    let mut key = 0;
    while key < MAX_TLS_KEYS {
        if TLS_KEY_STATE[key]
            .compare_exchange(
                TLS_KEY_FREE,
                TLS_KEY_IN_USE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            TLS_DTORS[key].store(encoded, Ordering::Release);
            // SAFETY: Accessing the calling thread's own TLS table slot.
            unsafe {
                (*current_tcb().tls_values.get())[key] = null_mut();
            }
            return Some(key);
        }
        key += 1;
    }
    None
}

/// Releases a previously allocated thread-local storage key and clears its destructor.
pub fn tls_key_delete(key: usize) {
    if key >= MAX_TLS_KEYS {
        return;
    }
    TLS_DTORS[key].store(0, Ordering::Release);
    // SAFETY: Accessing the calling thread's own TLS table slot.
    unsafe {
        (*current_tcb().tls_values.get())[key] = null_mut();
    }
    TLS_KEY_STATE[key].store(TLS_KEY_FREE, Ordering::Release);
}

/// Reads the calling thread's value for thread-local storage `key`.
#[must_use]
pub fn tls_get(key: usize) -> *mut u8 {
    if key >= MAX_TLS_KEYS || TLS_KEY_STATE[key].load(Ordering::Acquire) != TLS_KEY_IN_USE {
        return null_mut();
    }
    // SAFETY: Accessing the calling thread's own TLS table slot.
    unsafe { (*current_tcb().tls_values.get())[key] }
}

/// Writes `val` into the calling thread's slot for thread-local storage `key`.
///
/// Returns `false` if `key >= MAX_TLS_KEYS` or `key` is not currently allocated.
pub fn tls_set(key: usize, val: *mut u8) -> bool {
    if key >= MAX_TLS_KEYS || TLS_KEY_STATE[key].load(Ordering::Acquire) != TLS_KEY_IN_USE {
        return false;
    }
    // SAFETY: Accessing the calling thread's own TLS table slot.
    unsafe {
        (*current_tcb().tls_values.get())[key] = val;
    }
    true
}

/// Executes registered TLS destructors for all non-null TLS values on the calling thread,
/// repeating up to [`TLS_DESTRUCTOR_ITERATIONS`] passes.
pub fn run_current_thread_tls_destructors() {
    let tcb = current_tcb();
    let mut pass = 0;
    while pass < TLS_DESTRUCTOR_ITERATIONS {
        let mut any_ran = false;
        let mut key = 0;
        while key < MAX_TLS_KEYS {
            // SAFETY: Accessing the calling thread's own TLS table slot.
            let val = unsafe { (*tcb.tls_values.get())[key] };
            if !val.is_null() {
                // SAFETY: Clearing the calling thread's own TLS slot before invoking the destructor.
                unsafe {
                    (*tcb.tls_values.get())[key] = null_mut();
                }
                if TLS_KEY_STATE[key].load(Ordering::Acquire) == TLS_KEY_IN_USE {
                    if let Some(dtor) = decode_dtor(TLS_DTORS[key].load(Ordering::Acquire)) {
                        any_ran = true;
                        // SAFETY: `dtor` was registered by the caller of `tls_key_create` to accept `val`.
                        unsafe {
                            dtor(val);
                        }
                    }
                }
            }
            key += 1;
        }
        if !any_ran {
            break;
        }
        pass += 1;
    }
}

static RETIRED_LOCK: AtomicBool = AtomicBool::new(false);
static RETIRED_TCBS: AtomicPtr<ThreadControlBlock> = AtomicPtr::new(null_mut());

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn push_retired_tcb(tcb: *mut ThreadControlBlock) {
    while RETIRED_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let head = RETIRED_TCBS.load(Ordering::Relaxed);
    // SAFETY: `tcb` is a valid detached/retired `ThreadControlBlock` being enqueued under `RETIRED_LOCK`.
    unsafe {
        (*tcb).retired_next.store(head, Ordering::Relaxed);
    }
    RETIRED_TCBS.store(tcb, Ordering::Release);
    RETIRED_LOCK.store(false, Ordering::Release);
}

fn try_pop_retired_tcb() -> *mut ThreadControlBlock {
    if RETIRED_TCBS.load(Ordering::Acquire).is_null() {
        return null_mut();
    }
    while RETIRED_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let head = RETIRED_TCBS.load(Ordering::Acquire);
    let mut claimed = null_mut();
    if !head.is_null() {
        // SAFETY: `head` is non-null and protected by `RETIRED_LOCK`; `child_tid` is an atomic field.
        let tid = unsafe { (*head).child_tid.load(Ordering::Acquire) };
        if tid == 0 {
            // SAFETY: `child_tid == 0` guarantees the kernel and exiting thread are done with `head`.
            let next = unsafe { (*head).retired_next.load(Ordering::Relaxed) };
            RETIRED_TCBS.store(next, Ordering::Release);
            claimed = head;
        }
    }
    RETIRED_LOCK.store(false, Ordering::Release);
    claimed
}

fn alloc_tcb() -> SysResult<*mut ThreadControlBlock> {
    let mut ptr = try_pop_retired_tcb().cast::<u8>();
    if ptr.is_null() {
        // SAFETY: Allocating a 64-byte aligned `ThreadControlBlock` from `GLOBAL_MMAP_HEAP`.
        ptr = unsafe { GLOBAL_MMAP_HEAP.alloc_c(size_of::<ThreadControlBlock>(), 64) };
        if ptr.is_null() {
            return Err(Errno(ENOMEM));
        }
    }
    // SAFETY: `ptr` points to a writable `ThreadControlBlock` allocation.
    let tcb = ptr.cast::<ThreadControlBlock>();
    unsafe {
        tcb.write(ThreadControlBlock::new());
    }
    Ok(tcb)
}

#[inline]
const fn round_up_page(len: usize) -> Option<usize> {
    let mask = PAGE_SIZE - 1;
    match len.checked_add(mask) {
        Some(v) => Some(v & !mask),
        None => None,
    }
}

/// Handle to a joinable thread created by [`spawn_thread`].
///
/// Dropping a [`ThreadHandle`] without calling [`ThreadHandle::join`] or
/// [`ThreadHandle::detach`] automatically detaches the underlying thread.
pub struct ThreadHandle {
    tcb: *mut ThreadControlBlock,
}

// SAFETY: `ThreadHandle` owns a thread lifecycle reference synchronized via atomics and futexes.
unsafe impl Send for ThreadHandle {}
// SAFETY: Shared references to `ThreadHandle` only inspect immutable pointer identity.
unsafe impl Sync for ThreadHandle {}

impl ThreadHandle {
    /// Returns the unique thread identifier matching [`current_thread_id`] on that thread.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.tcb as usize as u64
    }

    /// Returns `true` if `self` refers to the calling thread.
    #[must_use]
    pub fn is_current(&self) -> bool {
        current_thread_id() == self.id()
    }

    /// Waits for the thread to terminate, unmaps its stack, and releases its control block.
    ///
    /// Returns `Err(Errno(EDEADLK))` if called on the current thread.
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
            let map_base = (*tcb).stack_map_base;
            let map_len = (*tcb).stack_map_len;
            if !map_base.is_null() && map_len > 0 {
                let _ = munmap(map_base, map_len);
            }
            c_free(tcb.cast::<u8>());
        }
        Ok(())
    }

    /// Detaches the thread so its resources are reclaimed automatically upon exit.
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
                let map_base = (*tcb).stack_map_base;
                let map_len = (*tcb).stack_map_len;
                if !map_base.is_null() && map_len > 0 {
                    let _ = munmap(map_base, map_len);
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
        let prev = (*tcb_ptr).join_state.swap(JOIN_EXITING, Ordering::AcqRel);
        if prev == JOIN_JOINABLE {
            crate::process::exit_thread(0);
        }

        let map_base = (*tcb_ptr).stack_map_base as usize;
        let map_len = (*tcb_ptr).stack_map_len;
        push_retired_tcb(tcb_ptr);

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

/// Spawns a new OS/unikernel thread executing `entry(arg)` on a fresh guarded stack.
///
/// When `detached` is `false`, returns `Ok(Some(ThreadHandle))`. When `detached` is `true`,
/// returns `Ok(None)` and the thread unmaps its own stack on exit.
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
    let min_usable = if stack_bytes < MIN_STACK_BYTES {
        MIN_STACK_BYTES
    } else {
        stack_bytes
    };
    let usable_stack = round_up_page(min_usable).ok_or(Errno(EINVAL))?;
    let guard_bytes = PAGE_SIZE;
    let total_map = usable_stack.checked_add(guard_bytes).ok_or(Errno(EINVAL))?;

    let map_base = mmap_anonymous(total_map, PROT_READ | PROT_WRITE, MAP_STACK)?;
    // SAFETY: `map_base` is page-aligned and `[map_base, map_base + guard_bytes)` is within the new mapping.
    if let Err(e) = unsafe { mprotect(map_base, guard_bytes, PROT_NONE) } {
        // SAFETY: Unmapping the region just returned by `mmap_anonymous`.
        let _ = unsafe { munmap(map_base, total_map) };
        return Err(e);
    }

    let tcb = match alloc_tcb() {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: Unmapping the stack region on TCB allocation failure.
            let _ = unsafe { munmap(map_base, total_map) };
            return Err(e);
        }
    };

    // SAFETY: Initializing the newly allocated `ThreadControlBlock`.
    unsafe {
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

    let stack_top = ((map_base as usize) + total_map) & !15usize;
    let child_sp = stack_top - 16;
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
        Ok(_) => {
            if detached {
                #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
                // SAFETY: Under host mock syscalls no child thread runs, so reclaim simulated stack & TCB cleanly.
                unsafe {
                    let _ = munmap(map_base, total_map);
                    c_free(tcb.cast::<u8>());
                }
                Ok(None)
            } else {
                Ok(Some(ThreadHandle { tcb }))
            }
        }
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

    #[test]
    fn errno_cell_and_current_thread_id_are_stable() {
        let id1 = current_thread_id();
        let id2 = current_thread_id();
        assert_ne!(id1, 0);
        assert_eq!(id1, id2);

        let ptr = errno_cell();
        assert!(!ptr.is_null());
        unsafe {
            let prev = *ptr;
            *ptr = 42;
            assert_eq!(*errno_cell(), 42);
            *ptr = prev;
        }
    }

    static DTOR_ORDER: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
    static CHAIN_KEY2: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn dtor_stage1(val: *mut u8) {
        DTOR_ORDER[0].store(val as usize, Ordering::SeqCst);
        let k2 = CHAIN_KEY2.load(Ordering::SeqCst);
        if k2 < MAX_TLS_KEYS {
            let _ = tls_set(k2, 0x2222 as *mut u8);
        }
    }

    unsafe extern "C" fn dtor_stage2(val: *mut u8) {
        DTOR_ORDER[1].store(val as usize, Ordering::SeqCst);
    }

    #[test]
    fn tls_keys_and_multi_pass_destructors() {
        assert!(tls_get(MAX_TLS_KEYS).is_null());
        assert!(!tls_set(MAX_TLS_KEYS, core::ptr::dangling_mut::<u8>()));

        DTOR_ORDER[0].store(0, Ordering::SeqCst);
        DTOR_ORDER[1].store(0, Ordering::SeqCst);

        let k1 = tls_key_create(Some(dtor_stage1)).expect("key 1");
        let k2 = tls_key_create(Some(dtor_stage2)).expect("key 2");
        CHAIN_KEY2.store(k2, Ordering::SeqCst);

        assert!(tls_get(k1).is_null());
        assert!(tls_set(k1, 0x1111 as *mut u8));
        assert_eq!(tls_get(k1), 0x1111 as *mut u8);

        run_current_thread_tls_destructors();

        assert!(tls_get(k1).is_null());
        assert!(tls_get(k2).is_null());
        assert_eq!(DTOR_ORDER[0].load(Ordering::SeqCst), 0x1111);
        assert_eq!(DTOR_ORDER[1].load(Ordering::SeqCst), 0x2222);

        tls_key_delete(k1);
        tls_key_delete(k2);
        assert!(!tls_set(k1, 0x3333 as *mut u8));
    }

    extern "C" fn dummy_thread_entry(_arg: *mut u8) {}

    #[test]
    fn spawn_thread_join_detach_and_error_cleanup() {
        #[repr(align(4096))]
        struct TestArena([u8; 512 * 1024]);

        static mut ARENA: TestArena = TestArena([0; 512 * 1024]);
        static OFFSET: AtomicUsize = AtomicUsize::new(0);
        static MPROTECT_CALLS: AtomicUsize = AtomicUsize::new(0);
        static MUNMAP_CALLS: AtomicUsize = AtomicUsize::new(0);
        static FAIL_CLONE: AtomicBool = AtomicBool::new(false);

        OFFSET.store(0, Ordering::SeqCst);
        MPROTECT_CALLS.store(0, Ordering::SeqCst);
        MUNMAP_CALLS.store(0, Ordering::SeqCst);
        FAIL_CLONE.store(false, Ordering::SeqCst);

        with_mock_syscall(
            |sysno, args| match sysno {
                nr::MMAP => {
                    let len = (args[1] + 4095) & !4095;
                    let off = OFFSET.fetch_add(len, Ordering::SeqCst);
                    if off + len > 512 * 1024 {
                        return Err(Errno(ENOMEM));
                    }
                    let ptr = unsafe { core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(off) };
                    unsafe {
                        crate::mem::set_bytes(ptr, 0, len);
                    }
                    Ok(ptr as usize)
                }
                nr::MPROTECT => {
                    MPROTECT_CALLS.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
                nr::MUNMAP => {
                    MUNMAP_CALLS.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
                nr::CLONE => {
                    if FAIL_CLONE.load(Ordering::SeqCst) {
                        return Err(Errno(EAGAIN));
                    }
                    let child_tid_ptr = args[4] as *const AtomicU32;
                    if !child_tid_ptr.is_null() {
                        // Simulate immediate thread completion clearing `child_tid` to 0.
                        unsafe {
                            (*child_tid_ptr).store(0, Ordering::Release);
                        }
                    }
                    Ok(777)
                }
                _ => Err(Errno(crate::errno::ENOSYS)),
            },
            || {
                // 1. Joinable thread spawn + join
                let handle =
                    unsafe { spawn_thread(MIN_STACK_BYTES, dummy_thread_entry, null_mut(), false) }
                        .expect("spawn joinable")
                        .expect("joinable handle");
                assert_ne!(handle.id(), 0);
                assert!(!handle.is_current());
                let munmaps_before = MUNMAP_CALLS.load(Ordering::SeqCst);
                handle.join().expect("join");
                assert!(MUNMAP_CALLS.load(Ordering::SeqCst) > munmaps_before);

                // 2. Joinable thread spawn + detach
                let handle2 =
                    unsafe { spawn_thread(MIN_STACK_BYTES, dummy_thread_entry, null_mut(), false) }
                        .expect("spawn joinable 2")
                        .expect("joinable handle 2");
                // Simulate thread entering `JOIN_EXITING` so `detach()` reclaims stack and TCB immediately.
                unsafe {
                    (*handle2.tcb)
                        .join_state
                        .store(JOIN_EXITING, Ordering::Release);
                }
                let munmaps_before_detach = MUNMAP_CALLS.load(Ordering::SeqCst);
                handle2.detach().expect("detach");
                assert!(MUNMAP_CALLS.load(Ordering::SeqCst) > munmaps_before_detach);

                // 3. Detached-at-birth spawn returns `Ok(None)`
                let detached_res =
                    unsafe { spawn_thread(MIN_STACK_BYTES, dummy_thread_entry, null_mut(), true) }
                        .expect("spawn detached");
                assert!(detached_res.is_none());

                // 4. Failed `CLONE` cleans up mapped stack and TCB
                FAIL_CLONE.store(true, Ordering::SeqCst);
                let munmaps_before_fail = MUNMAP_CALLS.load(Ordering::SeqCst);
                let err =
                    unsafe { spawn_thread(MIN_STACK_BYTES, dummy_thread_entry, null_mut(), false) };
                assert_eq!(err.err(), Some(Errno(EAGAIN)));
                assert!(MUNMAP_CALLS.load(Ordering::SeqCst) > munmaps_before_fail);
            },
        );
    }
}
