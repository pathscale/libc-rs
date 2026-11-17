//! Hardware entropy and attestation document retrieval.

use crate::status::{Result, Status};
use crate::trap::{Op, invoke, invoke_unit};

/// Maximum number of bytes requested per `Op::Entropy` trap.
pub const MAX_ENTROPY_CHUNK: usize = 256;

/// Maximum length of an attestation binding slice.
pub const MAX_ATTEST_BINDING: usize = 2000;

/// Maximum length of an attestation output buffer.
pub const MAX_ATTEST_DOCUMENT: usize = 0x3000;

/// Fills `out` with cryptographic entropy, zeroizing `out` on any error.
pub fn fill(out: &mut [u8]) -> Result<()> {
    for chunk in out.chunks_mut(MAX_ENTROPY_CHUNK) {
        if let Err(e) = invoke_unit(
            Op::Entropy,
            [chunk.as_mut_ptr() as u64, chunk.len() as u64, 0, 0],
        ) {
            out.fill(0);
            return Err(e);
        }
    }
    Ok(())
}

/// Returns an array of `N` random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Requests an attestation document bound to `binding` into `out`, returning bytes written.
pub fn attest(binding: Option<&[u8]>, out: &mut [u8]) -> Result<usize> {
    let (bind_ptr, bind_len) = match binding {
        Some(b) => {
            if b.len() > MAX_ATTEST_BINDING {
                return Err(Status::Invalid);
            }
            (b.as_ptr() as u64, b.len() as u64)
        }
        None => (0, 0),
    };
    if out.is_empty() || out.len() > MAX_ATTEST_DOCUMENT {
        return Err(Status::Invalid);
    }
    let used = invoke(
        Op::Attest,
        [
            bind_ptr,
            bind_len,
            out.as_mut_ptr() as u64,
            out.len() as u64,
        ],
    )?;
    let used = usize::try_from(used).map_err(|_| Status::Protocol)?;
    if used == 0 || used > out.len() {
        return Err(Status::Protocol);
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::trap::with_mock_trap;

    #[test]
    fn fill_chunks_and_zeroizes_on_error() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let mut buf = [0u8; 300];
        let res = with_mock_trap(
            |_, op, args| {
                assert_eq!(Op::decode(op), Some(Op::Entropy));
                let ptr = args[0] as *mut u8;
                let len = args[1] as usize;
                assert!(len <= MAX_ENTROPY_CHUNK);
                let c = CALLS.fetch_add(1, Ordering::SeqCst);
                if c == 0 {
                    // SAFETY: `ptr` points to `buf[..256]` in this test.
                    unsafe {
                        core::ptr::write_bytes(ptr, 0x5A, len);
                    }
                    Ok(0)
                } else {
                    Err(Status::Failed)
                }
            },
            || fill(&mut buf),
        );
        assert_eq!(res, Err(Status::Failed));
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn attest_bounds_checks() {
        let mut out = [0u8; 64];
        let big_binding = [1u8; MAX_ATTEST_BINDING + 1];
        assert_eq!(attest(Some(&big_binding), &mut out), Err(Status::Invalid));
        assert_eq!(attest(None, &mut []), Err(Status::Invalid));
    }
}
