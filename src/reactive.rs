//! Safe `#![no_std]` wrappers for the shared-memory reactive ring (`UkReactiveRing`).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::errno::SysResult;
use crate::raw::{syscall2, syscall5};

const SYS_CLOCK_GETTIME: usize = 113;
const SYS_PRCTL: usize = 167;

pub const UK_PR_REACTIVE_CREATE: usize = 0x5245_0001;
pub const UK_PR_REACTIVE_CTL: usize = 0x5245_0002;
pub const UK_PR_REACTIVE_WAIT: usize = 0x5245_0003;
pub const UK_PR_REACTIVE_WAKE: usize = 0x5245_0004;
pub const UK_PR_REACTIVE_CLOSE: usize = 0x5245_0005;

pub const UK_REACTIVE_CTL_ADD: u32 = 1;
pub const UK_REACTIVE_CTL_MOD: u32 = 2;
pub const UK_REACTIVE_CTL_DEL: u32 = 3;
pub const UK_REACTIVE_CTL_RESYNC: u32 = 4;

const CLOCK_MONOTONIC: usize = 1;

#[repr(C)]
pub struct UkReactiveRingHeader {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub mask: u32,
    pub flags: AtomicU32,
    pub parked: AtomicU32,
    pub user_wake: AtomicU32,
    pub overflow: AtomicU32,
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UkReactiveEvent {
    pub token: u64,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn monotonic_now_ns() -> SysResult<u64> {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { syscall2(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts as *mut Timespec as usize) }?;
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}

pub struct ReactiveRing {
    ring_id: u64,
    va: *mut u8,
    capacity: u32,
}

unsafe impl Send for ReactiveRing {}
unsafe impl Sync for ReactiveRing {}

impl ReactiveRing {
    pub fn create(requested_cap: u32) -> SysResult<Self> {
        let mut va: u64 = 0;
        let mut cap: u32 = 0;
        let ring_id = unsafe {
            syscall5(
                SYS_PRCTL,
                UK_PR_REACTIVE_CREATE,
                &mut va as *mut u64 as usize,
                &mut cap as *mut u32 as usize,
                requested_cap as usize,
                0,
            )
        }? as u64;
        Ok(Self {
            ring_id,
            va: va as *mut u8,
            capacity: cap,
        })
    }

    #[inline]
    fn header(&self) -> &UkReactiveRingHeader {
        unsafe { &*(self.va as *const UkReactiveRingHeader) }
    }

    #[inline]
    fn events_ptr(&self) -> *const UkReactiveEvent {
        unsafe { self.va.add(core::mem::size_of::<UkReactiveRingHeader>()) as *const UkReactiveEvent }
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn add(&self, fd: i32, token: u64, interests: u32) -> SysResult<()> {
        self.ctl(UK_REACTIVE_CTL_ADD, fd, token, interests)
    }

    pub fn modify(&self, fd: i32, token: u64, interests: u32) -> SysResult<()> {
        self.ctl(UK_REACTIVE_CTL_MOD, fd, token, interests)
    }

    pub fn remove(&self, fd: i32) -> SysResult<()> {
        self.ctl(UK_REACTIVE_CTL_DEL, fd, 0, 0)
    }

    fn ctl(&self, op: u32, fd: i32, token: u64, interests: u32) -> SysResult<()> {
        let op_interests = (op as usize) | ((interests as usize) << 32);
        unsafe {
            syscall5(
                SYS_PRCTL,
                UK_PR_REACTIVE_CTL,
                self.ring_id as usize,
                op_interests,
                fd as isize as usize,
                token as usize,
            )
        }
        .map(|_| ())
    }

    /// Drain events and `user_wake` / `overflow` directly from shared memory with ZERO syscalls
    /// in the steady state (calling `UK_REACTIVE_CTL_RESYNC` only if ring overflow occurred).
    pub fn drain(&self, out: &mut [UkReactiveEvent]) -> (usize, bool, bool) {
        let header = self.header();
        let user_wake = header.user_wake.swap(0, Ordering::AcqRel) != 0;
        let overflow = header.overflow.swap(0, Ordering::AcqRel) != 0;

        let mut head = header.head.load(Ordering::Relaxed);
        let tail = header.tail.load(Ordering::Acquire);
        let mask = header.mask;
        let mut count = 0;

        while head != tail && count < out.len() {
            let idx = (head & mask) as usize;
            out[count] = unsafe { self.events_ptr().add(idx).read() };
            head = head.wrapping_add(1);
            count += 1;
        }
        if count > 0 {
            header.head.store(head, Ordering::Release);
        }
        if overflow {
            let _ = self.ctl(UK_REACTIVE_CTL_RESYNC, 0, 0, 0);
            if count < out.len() {
                let mut head2 = header.head.load(Ordering::Relaxed);
                let tail2 = header.tail.load(Ordering::Acquire);
                while head2 != tail2 && count < out.len() {
                    let idx = (head2 & mask) as usize;
                    out[count] = unsafe { self.events_ptr().add(idx).read() };
                    head2 = head2.wrapping_add(1);
                    count += 1;
                }
                if head2 != header.head.load(Ordering::Relaxed) {
                    header.head.store(head2, Ordering::Release);
                }
            }
        }
        (count, user_wake, overflow)
    }

    /// Wake any waiter parked on this ring. ZERO syscalls when uncontended!
    pub fn wake(&self) -> SysResult<()> {
        let header = self.header();
        header.user_wake.store(1, Ordering::SeqCst);
        if header.parked.load(Ordering::SeqCst) != 0 {
            unsafe { syscall5(SYS_PRCTL, UK_PR_REACTIVE_WAKE, self.ring_id as usize, 0, 0, 0) }?;
        }
        Ok(())
    }

    /// Wait up to `timeout_ns` (or indefinitely if `None`) and drain events.
    /// ZERO syscalls if events, `user_wake`, or `overflow` are already present!
    pub fn wait_timeout_ns(
        &self,
        out: &mut [UkReactiveEvent],
        timeout_ns: Option<u64>,
    ) -> SysResult<(usize, bool, bool)> {
        let (count, user_wake, overflow) = self.drain(out);
        if count > 0 || user_wake || overflow {
            return Ok((count, user_wake, overflow));
        }
        if timeout_ns == Some(0) {
            return Ok((0, false, false));
        }

        let deadline_ns = match timeout_ns {
            None => u64::MAX,
            Some(ns) => monotonic_now_ns()?.saturating_add(ns),
        };
        unsafe {
            syscall5(
                SYS_PRCTL,
                UK_PR_REACTIVE_WAIT,
                self.ring_id as usize,
                deadline_ns as usize,
                0,
                0,
            )
        }?;
        Ok(self.drain(out))
    }
}

impl Drop for ReactiveRing {
    fn drop(&mut self) {
        let _ = unsafe { syscall5(SYS_PRCTL, UK_PR_REACTIVE_CLOSE, self.ring_id as usize, 0, 0, 0) };
    }
}
