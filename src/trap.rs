//! Low-level unikernel trap / SVC dispatch ABI.

use crate::status::{Result, Status};

/// Default capability namespace identifier (`"UK\x00\x01"`).
pub const DEFAULT_NAMESPACE: u64 = 0x554b_0001;

/// ABI contract version expected by this crate.
pub const ABI_VERSION: u64 = 1;

/// Unikernel capability operation codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u64)]
pub enum Op {
    Version = 0,
    Monotonic = 1,
    Sleep = 2,
    Entropy = 3,
    Attest = 4,
    Listen = 5,
    ConnectControl = 6,
    Accept = 7,
    Read = 8,
    Write = 9,
    Close = 10,
    RetireBootstrap = 11,
    Exit = 12,
    VirtualCounterFrequency = 14,
    MapCpuControlPages = 15,
    ReserveWorkerCores = 16,
    CpuDoorbell = 17,
}

impl Op {
    /// Decodes a raw `u64` opcode into an [`Op`], returning `None` for unknown codes.
    #[must_use]
    pub const fn decode(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Version),
            1 => Some(Self::Monotonic),
            2 => Some(Self::Sleep),
            3 => Some(Self::Entropy),
            4 => Some(Self::Attest),
            5 => Some(Self::Listen),
            6 => Some(Self::ConnectControl),
            7 => Some(Self::Accept),
            8 => Some(Self::Read),
            9 => Some(Self::Write),
            10 => Some(Self::Close),
            11 => Some(Self::RetireBootstrap),
            12 => Some(Self::Exit),
            14 => Some(Self::VirtualCounterFrequency),
            15 => Some(Self::MapCpuControlPages),
            16 => Some(Self::ReserveWorkerCores),
            17 => Some(Self::CpuDoorbell),
            _ => None,
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
mod mock {
    #[cfg(test)]
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicUsize;
    #[cfg(test)]
    use core::sync::atomic::Ordering;

    use crate::status::Result;

    pub type TrapHandler = fn(u64, u64, [u64; 4]) -> Result<u64>;

    pub static MOCK_HANDLER: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    static MOCK_LOCK: AtomicBool = AtomicBool::new(false);

    #[cfg(test)]
    struct LockGuard;

    #[cfg(test)]
    impl Drop for LockGuard {
        fn drop(&mut self) {
            MOCK_HANDLER.store(0, Ordering::Release);
            MOCK_LOCK.store(false, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub fn with_mock_trap<R>(f: TrapHandler, run: impl FnOnce() -> R) -> R {
        while MOCK_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let _guard = LockGuard;
        MOCK_HANDLER.store(f as usize, Ordering::Release);
        run()
    }
}

#[cfg(test)]
pub(crate) fn with_mock_trap<R>(
    f: fn(u64, u64, [u64; 4]) -> Result<u64>,
    run: impl FnOnce() -> R,
) -> R {
    mock::with_mock_trap(f, run)
}

/// Invokes a unikernel capability in the given `namespace` with `op` and 4 arguments.
pub fn invoke_ns(namespace: u64, op: u64, args: [u64; 4]) -> Result<u64> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let raw: u64;
        let [a, b, c, d] = args;
        // SAFETY: `svc #0` enters the unikernel capability trap handler with
        // registers x0..x8 populated according to the unikernel ABI.
        unsafe {
            core::arch::asm!(
                "svc #0",
                inlateout("x0") op => raw,
                in("x1") a,
                in("x2") b,
                in("x3") c,
                in("x4") d,
                in("x5") 0u64,
                in("x6") 0u64,
                in("x7") 0u64,
                in("x8") namespace,
                options(nostack, preserves_flags),
            );
        }
        crate::status::decode_result(raw)
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let ptr = mock::MOCK_HANDLER.load(core::sync::atomic::Ordering::Acquire);
        if ptr == 0 {
            return Err(Status::Unavailable);
        }
        // SAFETY: `ptr` was stored from a `fn(u64, u64, [u64; 4]) -> Result<u64>`
        // inside `with_mock_trap`.
        let handler: mock::TrapHandler = unsafe { core::mem::transmute(ptr) };
        handler(namespace, op, args)
    }
}

/// Invokes a unikernel capability in [`DEFAULT_NAMESPACE`].
#[inline]
pub fn invoke(op: Op, args: [u64; 4]) -> Result<u64> {
    invoke_ns(DEFAULT_NAMESPACE, op as u64, args)
}

/// Invokes a unikernel capability in [`DEFAULT_NAMESPACE`] and requires a zero return value.
#[inline]
pub fn invoke_unit(op: Op, args: [u64; 4]) -> Result<()> {
    crate::status::expect_zero(invoke(op, args)?)
}

/// Verifies the unikernel ABI version and negotiates the virtual counter frequency.
pub fn check_version() -> Result<()> {
    let version = invoke(Op::Version, [0; 4])?;
    if version != ABI_VERSION {
        return Err(Status::Protocol);
    }
    let _ = crate::clock::negotiate_virtual_counter();
    Ok(())
}

/// Terminates the current unikernel application with `status`.
pub fn exit(status: u8) -> ! {
    let _ = invoke(Op::Exit, [u64::from(status), 0, 0, 0]);
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `brk #0` traps if `Op::Exit` unexpectedly returns.
    unsafe {
        core::arch::asm!("brk #0", options(noreturn, nostack, nomem));
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_decode_covers_hole_and_bounds() {
        assert_eq!(Op::decode(0), Some(Op::Version));
        assert_eq!(Op::decode(12), Some(Op::Exit));
        assert_eq!(Op::decode(13), None);
        assert_eq!(Op::decode(14), Some(Op::VirtualCounterFrequency));
        assert_eq!(Op::decode(17), Some(Op::CpuDoorbell));
        assert_eq!(Op::decode(18), None);
    }

    #[test]
    fn check_version_succeeds_and_rejects_mismatch() {
        let ok = with_mock_trap(
            |ns, op, _| {
                assert_eq!(ns, DEFAULT_NAMESPACE);
                match Op::decode(op) {
                    Some(Op::Version) => Ok(ABI_VERSION),
                    Some(Op::VirtualCounterFrequency) => Ok(24_000_000),
                    _ => Err(Status::Invalid),
                }
            },
            check_version,
        );
        assert_eq!(ok, Ok(()));
        assert_eq!(crate::clock::virtual_counter_hz(), Some(24_000_000));

        let bad = with_mock_trap(
            |_, op, _| match Op::decode(op) {
                Some(Op::Version) => Ok(ABI_VERSION + 1),
                _ => Err(Status::Invalid),
            },
            check_version,
        );
        assert_eq!(bad, Err(Status::Protocol));
    }
}
