//! Freestanding memory and byte-slice intrinsics.
//!
//! All raw primitives avoid calling `core::ptr::copy` or `write_bytes` and
//! include an empty `asm!("")` compiler barrier inside loops so LLVM's
//! `LoopIdiomRecognize` pass cannot lower them into recursive calls to
//! `memcpy`, `memmove`, or `memset` when the `symbols` feature is enabled.

use core::hint::black_box;
use core::mem::size_of;

#[inline(always)]
fn compiler_barrier() {
    // Zero-instruction barrier preventing LLVM loop-idiom recognition from
    // turning byte/word loops into recursive libc calls.
    unsafe {
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
}

/// Copies `n` bytes from `src` to `dst`.
///
/// # Safety
/// - `src` must be valid for reads of `n` bytes.
/// - `dst` must be valid for writes of `n` bytes.
/// - The memory regions must not overlap.
pub unsafe fn copy_nonoverlapping_bytes(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    let word_size = size_of::<usize>();
    let align_mask = word_size - 1;

    if n >= word_size && ((dst as usize | src as usize) & align_mask) == 0 {
        let word_end = n & !align_mask;
        while i < word_end {
            unsafe {
                let d_word = dst.add(i).cast::<usize>();
                let s_word = src.add(i).cast::<usize>();
                *d_word = *s_word;
            }
            compiler_barrier();
            i += word_size;
        }
    }

    while i < n {
        unsafe {
            *dst.add(i) = *src.add(i);
        }
        compiler_barrier();
        i += 1;
    }

    dst
}

/// Copies `n` bytes from `src` to `dst`. The regions may overlap.
///
/// # Safety
/// - `src` must be valid for reads of `n` bytes.
/// - `dst` must be valid for writes of `n` bytes.
pub unsafe fn copy_bytes(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let d_addr = dst as usize;
    let s_addr = src as usize;

    if d_addr == s_addr || n == 0 {
        return dst;
    }

    if d_addr < s_addr || d_addr >= s_addr.saturating_add(n) {
        return unsafe { copy_nonoverlapping_bytes(dst, src, n) };
    }

    // Overlapping with dst > src: copy backwards from the end.
    let mut i = n;
    while i > 0 {
        i -= 1;
        unsafe {
            *dst.add(i) = *src.add(i);
        }
        compiler_barrier();
    }

    dst
}

/// Fills `n` bytes at `dst` with `byte`.
///
/// # Safety
/// - `dst` must be valid for writes of `n` bytes.
pub unsafe fn set_bytes(dst: *mut u8, byte: u8, n: usize) -> *mut u8 {
    let mut i = 0;
    let word_size = size_of::<usize>();
    let align_mask = word_size - 1;

    if n >= word_size && (dst as usize & align_mask) == 0 {
        let splat = (usize::MAX / 0xFF).wrapping_mul(byte as usize);
        let word_end = n & !align_mask;
        while i < word_end {
            unsafe {
                *dst.add(i).cast::<usize>() = splat;
            }
            compiler_barrier();
            i += word_size;
        }
    }

    while i < n {
        unsafe {
            *dst.add(i) = byte;
        }
        compiler_barrier();
        i += 1;
    }

    dst
}

/// Lexicographically compares `n` bytes at `a` and `b`.
///
/// # Safety
/// - `a` and `b` must each be valid for reads of `n` bytes.
pub unsafe fn compare_bytes(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let av = unsafe { *a.add(i) };
        let bv = unsafe { *b.add(i) };
        if av != bv {
            return (av as i32) - (bv as i32);
        }
        compiler_barrier();
        i += 1;
    }
    0
}

/// Returns the length of a NUL-terminated byte string.
///
/// # Safety
/// - `s` must point to a valid NUL-terminated byte string.
pub unsafe fn c_strlen(s: *const u8) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 {
        compiler_barrier();
        len += 1;
    }
    len
}

/// Returns the length of a NUL-terminated byte string, bounded by `max_len`.
///
/// # Safety
/// - `s` must be valid for reads up to `max_len` bytes or the first NUL byte.
pub unsafe fn c_strnlen(s: *const u8, max_len: usize) -> usize {
    let mut len = 0;
    while len < max_len && unsafe { *s.add(len) } != 0 {
        compiler_barrier();
        len += 1;
    }
    len
}

/// Searches `haystack` from the front for the first occurrence of `needle`.
pub fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Searches `haystack` from the back for the last occurrence of `needle`.
pub fn memrchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    let mut i = haystack.len();
    while i > 0 {
        i -= 1;
        if haystack[i] == needle {
            return Some(i);
        }
    }
    None
}

/// Constant-time byte-slice equality comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < a.len() {
        diff |= black_box(a[i] ^ b[i]);
        i += 1;
    }
    black_box(diff) == 0
}

/// Copies `n` non-overlapping bytes from `src` to `dst` and returns `dst`.
///
/// # Safety
/// - `src` must be valid for reads of `n` bytes, and `dst` for writes of `n` bytes.
/// - The memory regions must not overlap.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: usize,
) -> *mut core::ffi::c_void {
    unsafe { copy_nonoverlapping_bytes(dst.cast::<u8>(), src.cast::<u8>(), n).cast() }
}

/// Copies `n` potentially overlapping bytes from `src` to `dst` and returns `dst`.
///
/// # Safety
/// - `src` must be valid for reads of `n` bytes, and `dst` for writes of `n` bytes.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: usize,
) -> *mut core::ffi::c_void {
    unsafe { copy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n).cast() }
}

/// Fills `n` bytes at `dst` with `c as u8` and returns `dst`.
///
/// # Safety
/// - `dst` must be valid for writes of `n` bytes.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(
    dst: *mut core::ffi::c_void,
    c: core::ffi::c_int,
    n: usize,
) -> *mut core::ffi::c_void {
    unsafe { set_bytes(dst.cast::<u8>(), c as u8, n).cast() }
}

/// Lexicographically compares `n` bytes at `a` and `b`.
///
/// # Safety
/// - `a` and `b` must each be valid for reads of `n` bytes.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(
    a: *const core::ffi::c_void,
    b: *const core::ffi::c_void,
    n: usize,
) -> core::ffi::c_int {
    unsafe { compare_bytes(a.cast::<u8>(), b.cast::<u8>(), n) }
}

/// Compares `n` bytes at `a` and `b` for equality (`0` when equal).
///
/// # Safety
/// - `a` and `b` must each be valid for reads of `n` bytes.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(
    a: *const core::ffi::c_void,
    b: *const core::ffi::c_void,
    n: usize,
) -> core::ffi::c_int {
    unsafe { compare_bytes(a.cast::<u8>(), b.cast::<u8>(), n) }
}

/// Returns the length of a NUL-terminated byte string `s`.
///
/// # Safety
/// - `s` must point to a valid NUL-terminated string.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const core::ffi::c_char) -> usize {
    unsafe { c_strlen(s.cast::<u8>()) }
}

/// Returns the length of a NUL-terminated byte string `s`, bounded by `max_len`.
///
/// # Safety
/// - `s` must be valid for reads up to `max_len` bytes or the first NUL byte.
#[cfg(all(feature = "symbols", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const core::ffi::c_char, max_len: usize) -> usize {
    unsafe { c_strnlen(s.cast::<u8>(), max_len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_aligned_and_unaligned() {
        let mut src = [0u8; 64];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        let mut dst = [0u8; 64];

        unsafe {
            copy_nonoverlapping_bytes(dst.as_mut_ptr(), src.as_ptr(), 64);
        }
        assert_eq!(dst, src);

        let mut unaligned_dst = [0u8; 64];
        unsafe {
            copy_nonoverlapping_bytes(unaligned_dst.as_mut_ptr().add(1), src.as_ptr().add(3), 29);
        }
        assert_eq!(&unaligned_dst[1..30], &src[3..32]);
    }

    #[test]
    fn copy_overlapping_forward_and_backward() {
        let mut buf = [1u8, 2, 3, 4, 5, 6, 7, 8];
        unsafe {
            copy_bytes(buf.as_mut_ptr().add(2), buf.as_ptr(), 5);
        }
        assert_eq!(buf, [1, 2, 1, 2, 3, 4, 5, 8]);

        let mut buf2 = [1u8, 2, 3, 4, 5, 6, 7, 8];
        unsafe {
            copy_bytes(buf2.as_mut_ptr(), buf2.as_ptr().add(2), 5);
        }
        assert_eq!(buf2, [3, 4, 5, 6, 7, 6, 7, 8]);
    }

    #[test]
    fn set_and_compare() {
        let mut buf = [0u8; 31];
        unsafe {
            set_bytes(buf.as_mut_ptr(), 0x5a, 31);
        }
        assert!(buf.iter().all(|&b| b == 0x5a));

        let other = [0x5au8; 31];
        assert_eq!(
            unsafe { compare_bytes(buf.as_ptr(), other.as_ptr(), 31) },
            0
        );

        buf[17] = 0x5b;
        assert!(unsafe { compare_bytes(buf.as_ptr(), other.as_ptr(), 31) } > 0);
        assert!(unsafe { compare_bytes(other.as_ptr(), buf.as_ptr(), 31) } < 0);
    }

    #[test]
    fn c_strings_and_slice_helpers() {
        let s = b"hello\0world";
        assert_eq!(unsafe { c_strlen(s.as_ptr()) }, 5);
        assert_eq!(unsafe { c_strnlen(s.as_ptr(), 3) }, 3);
        assert_eq!(unsafe { c_strnlen(s.as_ptr(), 16) }, 5);

        assert_eq!(memchr(b'l', b"hello"), Some(2));
        assert_eq!(memrchr(b'l', b"hello"), Some(3));
        assert_eq!(memchr(b'z', b"hello"), None);

        assert!(ct_eq(b"secret-key", b"secret-key"));
        assert!(!ct_eq(b"secret-key", b"secret-kez"));
        assert!(!ct_eq(b"short", b"longer"));
    }
}
