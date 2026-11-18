//! Pure-Rust futex synchronization primitives (`FutexMutex`) with zero `pthreads` dependencies.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

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

    /// Acquires the mutex, spinning briefly before blocking via futex wait under contention.
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
        for _ in 0..32 {
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
            if c != LOCKED_UNCONTENDED {
                break;
            }
            core::hint::spin_loop();
            c = self.state.load(Ordering::Relaxed);
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

    /// Releases the mutex without a guard (used by [`FutexMutexGuard`] drop).
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
        let mut moved = m;
        assert_eq!(*moved.get_mut(), 15);
        *moved.try_lock().unwrap() += 27;
        assert_eq!(moved.into_inner(), 42);
    }
}
