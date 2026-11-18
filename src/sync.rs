//! Pure-Rust futex synchronization primitives (`FutexMutex`, `FutexCondvar`, `FutexOnce`)
//! with zero `pthreads` dependencies.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use crate::raw::{nr, syscall4, syscall6};
use crate::time::Timespec;

/// Private futex wait operation (`FUTEX_WAIT | FUTEX_PRIVATE_FLAG`).
pub const FUTEX_WAIT_PRIVATE: i32 = 128;
/// Private futex wake operation (`FUTEX_WAKE | FUTEX_PRIVATE_FLAG`).
pub const FUTEX_WAKE_PRIVATE: i32 = 129;

/// Waits on futex `word` while its value equals `expected`, with an optional relative `timeout`.
pub fn futex_wait(word: &AtomicU32, expected: u32, timeout: Option<&Timespec>) {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let ts_ptr = timeout.map_or(0, |t| core::ptr::from_ref(t) as usize);
        // SAFETY: `word` is a valid 4-byte aligned `AtomicU32` and `ts_ptr` is null or valid.
        let _ = unsafe {
            syscall6(
                nr::FUTEX,
                core::ptr::from_ref(word) as usize,
                FUTEX_WAIT_PRIVATE as usize,
                expected as usize,
                ts_ptr,
                0,
                0,
            )
        };
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = (word, expected, timeout);
        core::hint::spin_loop();
    }
}

/// Wakes at most one waiter blocked on futex `word`.
pub fn futex_wake_one(word: &AtomicU32) -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // SAFETY: `word` is a valid 4-byte aligned `AtomicU32`.
        unsafe {
            syscall4(
                nr::FUTEX,
                core::ptr::from_ref(word) as usize,
                FUTEX_WAKE_PRIVATE as usize,
                1,
                0,
            )
            .unwrap_or(0)
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = word;
        0
    }
}

/// Wakes all waiters blocked on futex `word`.
pub fn futex_wake_all(word: &AtomicU32) -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // SAFETY: `word` is a valid 4-byte aligned `AtomicU32`.
        unsafe {
            syscall4(
                nr::FUTEX,
                core::ptr::from_ref(word) as usize,
                FUTEX_WAKE_PRIVATE as usize,
                i32::MAX as usize,
                0,
            )
            .unwrap_or(0)
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = word;
        0
    }
}

const UNLOCKED: u32 = 0;
const LOCKED_UNCONTENDED: u32 = 1;
const LOCKED_CONTENDED: u32 = 2;

/// Move-safe, zero-allocation 3-state futex mutex (`0` = unlocked, `1` = locked, `2` = contended).
pub struct FutexMutex<T: ?Sized> {
    state: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: `FutexMutex` serializes access to `T` across threads via acquire/release operations.
unsafe impl<T: ?Sized + Send> Sync for FutexMutex<T> {}
// SAFETY: `FutexMutex` can be sent across threads when its payload `T` is `Send`.
unsafe impl<T: ?Sized + Send> Send for FutexMutex<T> {}

impl<T> FutexMutex<T> {
    /// Creates a new unlocked [`FutexMutex`] wrapping `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
            value: UnsafeCell::new(value),
        }
    }

    /// Consumes the mutex and returns its inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: ?Sized> FutexMutex<T> {
    /// Attempts to acquire the mutex without blocking.
    #[must_use]
    pub fn try_lock(&self) -> Option<FutexMutexGuard<'_, T>> {
        if self
            .state
            .compare_exchange(
                UNLOCKED,
                LOCKED_UNCONTENDED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            Some(FutexMutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Acquires the mutex, blocking via futex wait under contention.
    #[must_use]
    pub fn lock(&self) -> FutexMutexGuard<'_, T> {
        if self
            .state
            .compare_exchange(
                UNLOCKED,
                LOCKED_UNCONTENDED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.lock_contended();
        }
        FutexMutexGuard { mutex: self }
    }

    #[cold]
    fn lock_contended(&self) {
        let mut c = self.state.load(Ordering::Relaxed);
        if c == UNLOCKED {
            match self.state.compare_exchange(
                UNLOCKED,
                LOCKED_UNCONTENDED,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(prev) => c = prev,
            }
        }
        loop {
            if c == LOCKED_CONTENDED
                || self
                    .state
                    .compare_exchange(
                        LOCKED_UNCONTENDED,
                        LOCKED_CONTENDED,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_err()
            {
                futex_wait(&self.state, LOCKED_CONTENDED, None);
            }
            if self.state.swap(LOCKED_CONTENDED, Ordering::Acquire) == UNLOCKED {
                return;
            }
            c = LOCKED_CONTENDED;
        }
    }

    /// Releases the mutex without a guard (used by [`FutexCondvar::wait`] and [`FutexMutexGuard`] drop).
    ///
    /// # Safety
    ///
    /// The caller must currently hold the lock on `self` and must not access the protected
    /// value after calling `raw_unlock` without re-acquiring the lock.
    pub unsafe fn raw_unlock(&self) {
        if self.state.swap(UNLOCKED, Ordering::Release) == LOCKED_CONTENDED {
            let _ = futex_wake_one(&self.state);
        }
    }

    /// Returns a mutable reference to the underlying data when holding exclusive `&mut self`.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }
}

/// RAII guard for [`FutexMutex`].
pub struct FutexMutexGuard<'a, T: ?Sized> {
    mutex: &'a FutexMutex<T>,
}

impl<T: ?Sized> Deref for FutexMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The guard holds exclusive access to the mutex value.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T: ?Sized> DerefMut for FutexMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The guard holds exclusive mutable access to the mutex value.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T: ?Sized> Drop for FutexMutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: `self` owns the lock and is being dropped.
        unsafe {
            self.mutex.raw_unlock();
        }
    }
}

/// Move-safe, zero-allocation futex condition variable.
pub struct FutexCondvar {
    seq: AtomicU32,
    waiters: AtomicUsize,
}

impl Default for FutexCondvar {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexCondvar {
    /// Creates a new [`FutexCondvar`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            waiters: AtomicUsize::new(0),
        }
    }

    /// Atomically releases `guard`, waits for a notification on `self`, and re-locks the mutex.
    #[must_use]
    pub fn wait<'a, T: ?Sized>(&self, guard: FutexMutexGuard<'a, T>) -> FutexMutexGuard<'a, T> {
        let mutex = guard.mutex;
        self.waiters.fetch_add(1, Ordering::Relaxed);
        let seq = self.seq.load(Ordering::Acquire);
        core::mem::forget(guard);
        // SAFETY: `guard` was forgotten above, transferring ownership of the lock release here.
        unsafe {
            mutex.raw_unlock();
        }
        futex_wait(&self.seq, seq, None);
        self.waiters.fetch_sub(1, Ordering::Relaxed);
        mutex.lock()
    }

    /// Wakes one waiting thread if any are currently waiting, returning `true` if a waiter was present.
    pub fn notify_one(&self) -> bool {
        let had_waiter = self.waiters.load(Ordering::Acquire) > 0;
        self.seq.fetch_add(1, Ordering::Release);
        if had_waiter {
            let _ = futex_wake_one(&self.seq);
        }
        had_waiter
    }

    /// Wakes all waiting threads, returning the observed waiter count.
    pub fn notify_all(&self) -> usize {
        let waiting = self.waiters.load(Ordering::Acquire);
        self.seq.fetch_add(1, Ordering::Release);
        if waiting > 0 {
            let _ = futex_wake_all(&self.seq);
        }
        waiting
    }
}

const ONCE_INCOMPLETE: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_COMPLETE: u32 = 2;

/// Move-safe, zero-allocation futex one-time initialization primitive.
pub struct FutexOnce {
    state: AtomicU32,
}

impl Default for FutexOnce {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexOnce {
    /// Creates a new uninitialized [`FutexOnce`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(ONCE_INCOMPLETE),
        }
    }

    /// Returns `true` if [`FutexOnce::call_once`] has completed.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ONCE_COMPLETE
    }

    /// Runs `f` exactly once across all callers.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        if self.state.load(Ordering::Acquire) == ONCE_COMPLETE {
            return;
        }
        let mut f = Some(f);
        self.call_once_slow(&mut || {
            if let Some(fun) = f.take() {
                fun();
            }
        });
    }

    #[cold]
    fn call_once_slow(&self, f: &mut dyn FnMut()) {
        loop {
            match self.state.compare_exchange(
                ONCE_INCOMPLETE,
                ONCE_RUNNING,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    f();
                    self.state.store(ONCE_COMPLETE, Ordering::Release);
                    let _ = futex_wake_all(&self.state);
                    return;
                }
                Err(ONCE_COMPLETE) => return,
                Err(ONCE_RUNNING) => {
                    futex_wait(&self.state, ONCE_RUNNING, None);
                }
                Err(_) => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn futex_mutex_lock_try_lock_and_move_by_value() {
        let m = FutexMutex::new(10u64);
        {
            let mut g = m.lock();
            assert!(m.try_lock().is_none());
            *g += 5;
        }
        // Move the mutex by value after locking and unlocking.
        let mut moved = m;
        assert_eq!(*moved.get_mut(), 15);
        *moved.try_lock().unwrap() += 27;
        assert_eq!(moved.into_inner(), 42);
    }

    #[test]
    fn futex_condvar_and_once_operate_without_allocation() {
        let cv = FutexCondvar::new();
        assert!(!cv.notify_one());
        assert_eq!(cv.notify_all(), 0);

        let m = FutexMutex::new(1u32);
        let g = m.lock();
        // On host builds `futex_wait` returns after a spin_loop hint, allowing single-thread verification
        // of wait's unlock + relock sequence.
        let g2 = cv.wait(g);
        assert_eq!(*g2, 1);
        drop(g2);

        let once = FutexOnce::new();
        let mut count = 0usize;
        once.call_once(|| count += 1);
        once.call_once(|| count += 10);
        assert!(once.is_completed());
        assert_eq!(count, 1);
    }
}
