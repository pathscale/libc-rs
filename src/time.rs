//! Clocks, timestamps, and high-resolution sleep syscalls.

use core::mem::size_of;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::sync::atomic::{AtomicU64, Ordering};

use crate::errno::SysResult;
use crate::raw::{nr, syscall2, syscall4};

/// System-wide real-time clock identifier.
pub const CLOCK_REALTIME: i32 = 0;
/// Monotonic clock identifier (cannot jump backwards).
pub const CLOCK_MONOTONIC: i32 = 1;
/// Flag indicating an absolute target time for `clock_nanosleep`.
pub const TIMER_ABSTIME: i32 = 1;

/// Seconds and nanoseconds timestamp matching the 64-bit kernel `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Seconds and microseconds timestamp matching the 64-bit kernel `struct timeval`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(size_of::<Timeval>() == 16);
};

/// Queries the current value of `clock_id` via the `CLOCK_GETTIME` syscall.
pub fn clock_gettime_syscall(clock_id: i32) -> SysResult<Timespec> {
    let mut ts = Timespec::default();
    // SAFETY: `ts` is a valid, aligned stack `Timespec` for the kernel to write into.
    unsafe {
        syscall2(
            nr::CLOCK_GETTIME,
            clock_id as usize,
            core::ptr::from_mut(&mut ts) as usize,
        )?;
    }
    Ok(ts)
}

/// Queries the current value of `clock_id`.
pub fn clock_gettime(clock_id: i32) -> SysResult<Timespec> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    if clock_id == CLOCK_MONOTONIC {
        static CACHED_HZ: AtomicU64 = AtomicU64::new(0);
        let mut hz = CACHED_HZ.load(Ordering::Relaxed);
        if hz == 0 {
            hz = crate::raw::read_cntfrq_el0();
            if hz != 0 {
                CACHED_HZ.store(hz, Ordering::Relaxed);
            }
        }
        let ticks = crate::raw::read_cntvct_el0();
        if let Some(secs) = ticks.checked_div(hz) {
            let rem = ticks - secs * hz;
            let tv_sec = secs as i64;
            let tv_nsec = ((rem as u128 * 1_000_000_000) / (hz as u128)) as i64;
            return Ok(Timespec { tv_sec, tv_nsec });
        }
    }
    clock_gettime_syscall(clock_id)
}

/// Sets the time of `clock_id` to `ts`.
pub fn clock_settime(clock_id: i32, ts: &Timespec) -> SysResult<()> {
    // SAFETY: `ts` is a valid shared reference to a `Timespec`.
    unsafe {
        syscall2(
            nr::CLOCK_SETTIME,
            clock_id as usize,
            core::ptr::from_ref(ts) as usize,
        )?;
    }
    Ok(())
}

/// Sleeps for the relative interval `req` on `CLOCK_MONOTONIC`, optionally writing
/// any remaining duration into `rem` if interrupted.
pub fn nanosleep(req: &Timespec, rem: Option<&mut Timespec>) -> SysResult<()> {
    let rem_ptr = rem.map_or(0, |r| core::ptr::from_mut(r) as usize);
    // SAFETY: `req` is a valid `Timespec` reference and `rem_ptr` is either 0 (null)
    // or a valid mutable `Timespec` pointer.
    unsafe {
        syscall4(
            nr::CLOCK_NANOSLEEP,
            CLOCK_MONOTONIC as usize,
            0,
            core::ptr::from_ref(req) as usize,
            rem_ptr,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::with_mock_syscall;

    #[test]
    fn clock_gettime_and_nanosleep_pass_expected_arguments() {
        let ts = with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::CLOCK_GETTIME);
                assert_eq!(args[0], CLOCK_MONOTONIC as usize);
                let out = args[1] as *mut Timespec;
                // SAFETY: `out` points to the stack `Timespec` in `clock_gettime`.
                unsafe {
                    *out = Timespec {
                        tv_sec: 42,
                        tv_nsec: 123_456_789,
                    };
                }
                Ok(0)
            },
            || clock_gettime(CLOCK_MONOTONIC).unwrap(),
        );
        assert_eq!(
            ts,
            Timespec {
                tv_sec: 42,
                tv_nsec: 123_456_789,
            }
        );

        const REQ: Timespec = Timespec {
            tv_sec: 1,
            tv_nsec: 500,
        };
        let mut rem = Timespec::default();
        with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::CLOCK_NANOSLEEP);
                assert_eq!(args[0], CLOCK_MONOTONIC as usize);
                assert_eq!(args[1], 0);
                let req_ptr = args[2] as *const Timespec;
                // SAFETY: `req_ptr` points to `REQ`.
                assert_eq!(unsafe { *req_ptr }, REQ);
                assert!(args[3] != 0);
                Ok(0)
            },
            || nanosleep(&REQ, Some(&mut rem)).unwrap(),
        );
    }
}
