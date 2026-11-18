//! Kernel cryptographic entropy (`getrandom`) syscall wrappers.

use crate::errno::{EINTR, EIO, Errno, SysResult};
use crate::raw::{nr, syscall3};

/// Do not block if the entropy pool is not yet initialized.
pub const GRND_NONBLOCK: u32 = 0x01;
/// Draw from the `/dev/random` pool flag.
pub const GRND_RANDOM: u32 = 0x02;

/// Fills up to `out.len()` bytes of `out` using the kernel `getrandom` syscall.
pub fn getrandom(out: &mut [u8], flags: u32) -> SysResult<usize> {
    if out.is_empty() {
        return Ok(0);
    }
    // SAFETY: `out` is a valid mutable byte slice of length `out.len()`.
    unsafe {
        syscall3(
            nr::GETRANDOM,
            out.as_mut_ptr() as usize,
            out.len(),
            flags as usize,
        )
    }
}

/// Fills `out` completely with cryptographic random bytes, retrying on `EINTR`
/// and handling partial fills.
pub fn fill_random(mut out: &mut [u8]) -> SysResult<()> {
    while !out.is_empty() {
        match getrandom(out, 0) {
            Ok(0) => return Err(Errno(EIO)),
            Ok(n) if n <= out.len() => {
                out = &mut out[n..];
            }
            Ok(_) => return Err(Errno(EIO)),
            Err(e) if e.raw() == EINTR => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::raw::with_mock_syscall;

    #[test]
    fn fill_random_retries_eintr_and_short_reads() {
        static STEP: AtomicUsize = AtomicUsize::new(0);
        STEP.store(0, Ordering::SeqCst);

        let mut buf = [0u8; 8];
        with_mock_syscall(
            |sysno, args| {
                assert_eq!(sysno, nr::GETRANDOM);
                let ptr = args[0] as *mut u8;
                let len = args[1];
                assert_eq!(args[2], 0);
                match STEP.fetch_add(1, Ordering::SeqCst) {
                    0 => Err(Errno(EINTR)),
                    1 => {
                        assert_eq!(len, 8);
                        // SAFETY: `ptr` points to the start of `buf` (8 bytes).
                        unsafe {
                            core::ptr::write_bytes(ptr, 0xAA, 3);
                        }
                        Ok(3)
                    }
                    _ => {
                        assert_eq!(len, 5);
                        // SAFETY: `ptr` points to `buf[3..8]` (5 bytes).
                        unsafe {
                            core::ptr::write_bytes(ptr, 0xBB, 5);
                        }
                        Ok(5)
                    }
                }
            },
            || fill_random(&mut buf).unwrap(),
        );
        assert_eq!(buf, [0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]);
    }
}
