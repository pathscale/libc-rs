//! Hardware monotonic clock, sleep, and deadline primitives.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::status::{Result, Status};
use crate::trap::{Op, invoke, invoke_unit};

/// Nanoseconds per second.
pub const NS_PER_SECOND: u64 = 1_000_000_000;

/// Maximum duration of a single `Op::Sleep` trap call (50 ms).
pub const MAX_SLEEP_NS: u64 = 50_000_000;

/// Maximum wait horizon (30 s).
pub const MAX_WAIT_HORIZON_NS: u64 = 30_000_000_000;

static VIRTUAL_COUNTER_HZ: AtomicU32 = AtomicU32::new(0);

/// Converts a hardware counter `ticks` value at frequency `hz` into nanoseconds.
#[must_use]
pub const fn ticks_to_ns(ticks: u64, hz: u32) -> Option<u64> {
    if hz == 0 {
        return None;
    }
    let hz64 = hz as u64;
    let fraction = (ticks % hz64) * NS_PER_SECOND / hz64;
    let secs_ns = match (ticks / hz64).checked_mul(NS_PER_SECOND) {
        Some(v) => v,
        None => return None,
    };
    let ns = match secs_ns.checked_add(fraction) {
        Some(v) => v,
        None => return None,
    };
    if ns <= i64::MAX as u64 {
        Some(ns)
    } else {
        None
    }
}

/// Queries the kernel for the virtual counter frequency and caches it if non-zero.
pub fn negotiate_virtual_counter() -> Option<u32> {
    let hz = invoke(Op::VirtualCounterFrequency, [0; 4])
        .ok()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|&hz| hz != 0)?;
    VIRTUAL_COUNTER_HZ.store(hz, Ordering::Relaxed);
    Some(hz)
}

/// Returns the cached virtual counter frequency in Hz, if negotiated.
#[must_use]
pub fn virtual_counter_hz() -> Option<u32> {
    let hz = VIRTUAL_COUNTER_HZ.load(Ordering::Relaxed);
    if hz == 0 { None } else { Some(hz) }
}

/// Returns the current monotonic timestamp in nanoseconds.
pub fn monotonic_ns() -> Result<u64> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let hz = VIRTUAL_COUNTER_HZ.load(Ordering::Relaxed);
        if hz != 0 {
            let ticks: u64;
            // SAFETY: Reading `cntvct_el0` after `isb` is safe and side-effect free
            // on AArch64 when EL0 counter access is enabled.
            unsafe {
                core::arch::asm!(
                    "isb",
                    "mrs {}, cntvct_el0",
                    out(reg) ticks,
                    options(nostack, nomem),
                );
            }
            return ticks_to_ns(ticks, hz).ok_or(Status::Failed);
        }
    }
    invoke(Op::Monotonic, [0; 4])
}

/// Sleeps for at most [`MAX_SLEEP_NS`] nanoseconds in a single trap call.
pub fn sleep_step_ns(ns: u64) -> Result<()> {
    invoke_unit(Op::Sleep, [ns.min(MAX_SLEEP_NS), 0, 0, 0])
}

/// Sleeps for `total_ns` nanoseconds by chunking into [`MAX_SLEEP_NS`] steps.
pub fn sleep_ns(mut total_ns: u64) -> Result<()> {
    while total_ns > 0 {
        let step = total_ns.min(MAX_SLEEP_NS);
        sleep_step_ns(step)?;
        total_ns -= step;
    }
    Ok(())
}

/// Absolute monotonic deadline in nanoseconds (`0` means immediate).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Deadline(u64);

impl Deadline {
    /// Immediate deadline (non-blocking).
    pub const IMMEDIATE: Self = Self(0);

    /// Constructs a deadline from a raw nanosecond timestamp.
    #[must_use]
    pub const fn from_raw_ns(ns: u64) -> Self {
        Self(ns)
    }

    /// Returns the raw nanosecond timestamp.
    #[must_use]
    pub const fn raw_ns(self) -> u64 {
        self.0
    }

    /// Returns `true` if this deadline is [`Deadline::IMMEDIATE`].
    #[must_use]
    pub const fn is_immediate(self) -> bool {
        self.0 == 0
    }

    /// Computes a deadline `delta_ns` nanoseconds after the current monotonic clock.
    pub fn after_ns(delta_ns: u64) -> Result<Self> {
        monotonic_ns()?
            .checked_add(delta_ns)
            .filter(|&v| v != 0)
            .map(Self)
            .ok_or(Status::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::trap::with_mock_trap;

    #[test]
    fn ticks_to_ns_frequencies_and_precision() {
        assert_eq!(ticks_to_ns(100, 0), None);
        // 24 MHz: 24_000_000 ticks = 1s, 12 ticks = 500 ns
        assert_eq!(ticks_to_ns(24_000_000, 24_000_000), Some(1_000_000_000));
        assert_eq!(ticks_to_ns(12, 24_000_000), Some(500));
        // 62.5 MHz: 62_500_000 ticks = 1s, 1 tick = 16 ns
        assert_eq!(ticks_to_ns(62_500_000, 62_500_000), Some(1_000_000_000));
        assert_eq!(ticks_to_ns(1, 62_500_000), Some(16));
        // 1 GHz: 1 tick = 1 ns
        assert_eq!(ticks_to_ns(123_456_789, 1_000_000_000), Some(123_456_789));
        // Overflow boundary: > i64::MAX ns returns None
        assert_eq!(ticks_to_ns(u64::MAX, 1), None);
        assert_eq!(ticks_to_ns((i64::MAX as u64) + 1, 1_000_000_000), None);
    }

    #[test]
    fn sleep_ns_chunks_into_max_sleep_steps() {
        static TOTAL_SLEPT: AtomicU64 = AtomicU64::new(0);
        static CALLS: AtomicU64 = AtomicU64::new(0);
        TOTAL_SLEPT.store(0, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);

        let res = with_mock_trap(
            |_, op, args| {
                assert_eq!(Op::decode(op), Some(Op::Sleep));
                assert!(args[0] <= MAX_SLEEP_NS);
                TOTAL_SLEPT.fetch_add(args[0], Ordering::SeqCst);
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            },
            || sleep_ns(120_000_000),
        );
        assert_eq!(res, Ok(()));
        assert_eq!(TOTAL_SLEPT.load(Ordering::SeqCst), 120_000_000);
        assert_eq!(CALLS.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn deadline_after_ns_and_immediate() {
        assert!(Deadline::IMMEDIATE.is_immediate());
        assert_eq!(Deadline::from_raw_ns(42).raw_ns(), 42);

        let d = with_mock_trap(
            |_, op, _| match Op::decode(op) {
                Some(Op::Monotonic) => Ok(1_000),
                _ => Err(Status::Invalid),
            },
            || Deadline::after_ns(500),
        );
        assert_eq!(d, Ok(Deadline::from_raw_ns(1_500)));
    }
}
