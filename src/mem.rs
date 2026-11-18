//! Freestanding memory and byte-slice intrinsics.
//!
//! All raw primitives avoid calling `core::ptr::copy` or `write_bytes` and
//! pass leading pointers through `core::hint::black_box` once at function entry
//! so LLVM's `LoopIdiomRecognize` pass cannot lower them into recursive calls
//! to `memcpy`, `memmove`, `memset`, `memcmp`, or `strlen` when the `symbols`
//! feature is enabled.

use core::hint::black_box;

const LO_U64: u64 = 0x0101_0101_0101_0101;
const HI_U64: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
fn has_zero_byte(word: u64) -> u64 {
    word.wrapping_sub(LO_U64) & !word & HI_U64
}

#[inline(always)]
fn first_match_index_le(mask: u64) -> usize {
    (mask.trailing_zeros() >> 3) as usize
}

#[inline(always)]
fn last_match_index_le(mask: u64) -> usize {
    7 - ((mask.leading_zeros() >> 3) as usize)
}

#[inline(always)]
unsafe fn read_u64_aligned(ptr: *const u8) -> u64 {
    debug_assert_eq!((ptr as usize) & 7, 0);
    unsafe { *ptr.cast::<u64>() }
}

#[inline(always)]
unsafe fn write_u64_aligned(ptr: *mut u8, val: u64) {
    debug_assert_eq!((ptr as usize) & 7, 0);
    unsafe {
        *ptr.cast::<u64>() = val;
    }
}

#[cold]
#[inline(never)]
unsafe fn copy_forward_misaligned(
    dst: *mut u8,
    src: *const u8,
    mut i: usize,
    n: usize,
    src_off: usize,
) -> usize {
    if n - i >= 16 {
        let k = 8 - src_off;
        let rshift = (src_off * 8) as u32;
        let lshift = (k * 8) as u32;
        let mut low: u64 = 0;
        let mut b = 0;
        while b < k {
            low |= (unsafe { *src.add(i + b) } as u64) << (b * 8);
            b += 1;
        }

        while n - i >= 40 {
            unsafe {
                let s_al = src.add(i + k);
                let d_al = dst.add(i);
                let w0 = u64::from_le(read_u64_aligned(s_al));
                let w1 = u64::from_le(read_u64_aligned(s_al.add(8)));
                let w2 = u64::from_le(read_u64_aligned(s_al.add(16)));
                let w3 = u64::from_le(read_u64_aligned(s_al.add(24)));
                write_u64_aligned(d_al, (low | (w0 << lshift)).to_le());
                write_u64_aligned(d_al.add(8), ((w0 >> rshift) | (w1 << lshift)).to_le());
                write_u64_aligned(d_al.add(16), ((w1 >> rshift) | (w2 << lshift)).to_le());
                write_u64_aligned(d_al.add(24), ((w2 >> rshift) | (w3 << lshift)).to_le());
                low = w3 >> rshift;
            }
            i += 32;
        }

        while n - i >= 16 {
            unsafe {
                let w0 = u64::from_le(read_u64_aligned(src.add(i + k)));
                write_u64_aligned(dst.add(i), (low | (w0 << lshift)).to_le());
                low = w0 >> rshift;
            }
            i += 8;
        }
    }
    i
}

/// Copies `n` bytes from `src` to `dst`.
///
/// # Safety
/// - `src` must be valid for reads of `n` bytes.
/// - `dst` must be valid for writes of `n` bytes.
/// - The memory regions must not overlap.
pub unsafe fn copy_nonoverlapping_bytes(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let dst = black_box(dst);
    let src = black_box(src);
    let mut i = 0;

    if n >= 16 {
        let misalign = (dst as usize) & 15;
        if misalign != 0 {
            let prolog = (16 - misalign) & 15;
            while i < prolog {
                unsafe {
                    *dst.add(i) = black_box(*src.add(i));
                }
                i += 1;
            }
        }

        let src_off = (unsafe { src.add(i) } as usize) & 7;
        if src_off == 0 {
            while n - i >= 64 {
                unsafe {
                    let s = src.add(i).cast::<u64>();
                    let d = dst.add(i).cast::<u64>();
                    let w0 = black_box(*s);
                    let w1 = *s.add(1);
                    let w2 = *s.add(2);
                    let w3 = *s.add(3);
                    let w4 = *s.add(4);
                    let w5 = *s.add(5);
                    let w6 = *s.add(6);
                    let w7 = *s.add(7);
                    *d = w0;
                    *d.add(1) = w1;
                    *d.add(2) = w2;
                    *d.add(3) = w3;
                    *d.add(4) = w4;
                    *d.add(5) = w5;
                    *d.add(6) = w6;
                    *d.add(7) = w7;
                }
                i += 64;
            }

            if n - i >= 32 {
                unsafe {
                    let s = src.add(i);
                    let d = dst.add(i);
                    let w0 = read_u64_aligned(s);
                    let w1 = read_u64_aligned(s.add(8));
                    let w2 = read_u64_aligned(s.add(16));
                    let w3 = read_u64_aligned(s.add(24));
                    write_u64_aligned(d, w0);
                    write_u64_aligned(d.add(8), w1);
                    write_u64_aligned(d.add(16), w2);
                    write_u64_aligned(d.add(24), w3);
                }
                i += 32;
            }

            if n - i >= 16 {
                unsafe {
                    let s = src.add(i);
                    let d = dst.add(i);
                    let w0 = read_u64_aligned(s);
                    let w1 = read_u64_aligned(s.add(8));
                    write_u64_aligned(d, w0);
                    write_u64_aligned(d.add(8), w1);
                }
                i += 16;
            }

            if n - i >= 8 {
                unsafe {
                    let w = read_u64_aligned(src.add(i));
                    write_u64_aligned(dst.add(i), w);
                }
                i += 8;
            }
        } else {
            i = unsafe { copy_forward_misaligned(dst, src, i, n, src_off) };
        }
    }

    while i < n {
        unsafe {
            *dst.add(i) = black_box(*src.add(i));
        }
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

    if d_addr < s_addr || d_addr.wrapping_sub(s_addr) >= n {
        return unsafe { copy_nonoverlapping_bytes(dst, src, n) };
    }

    // Overlapping with dst > src: copy backwards from the end using strictly aligned word ops.
    let dst = black_box(dst);
    let src = black_box(src);
    let mut i = n;

    if i >= 16 {
        let end_misalign = (d_addr.wrapping_add(i)) & 15;
        if end_misalign != 0 {
            let target = i - end_misalign;
            while i > target {
                i -= 1;
                unsafe {
                    *dst.add(i) = black_box(*src.add(i));
                }
            }
        }

        let src_off = (s_addr.wrapping_add(i)) & 7;
        if src_off == 0 {
            while i >= 64 {
                i -= 64;
                unsafe {
                    let s = src.add(i).cast::<u64>();
                    let d = dst.add(i).cast::<u64>();
                    let w0 = black_box(*s);
                    let w1 = *s.add(1);
                    let w2 = *s.add(2);
                    let w3 = *s.add(3);
                    let w4 = *s.add(4);
                    let w5 = *s.add(5);
                    let w6 = *s.add(6);
                    let w7 = *s.add(7);
                    *d.add(7) = w7;
                    *d.add(6) = w6;
                    *d.add(5) = w5;
                    *d.add(4) = w4;
                    *d.add(3) = w3;
                    *d.add(2) = w2;
                    *d.add(1) = w1;
                    *d = w0;
                }
            }

            if i >= 32 {
                i -= 32;
                unsafe {
                    let s = src.add(i);
                    let d = dst.add(i);
                    let w0 = read_u64_aligned(s);
                    let w1 = read_u64_aligned(s.add(8));
                    let w2 = read_u64_aligned(s.add(16));
                    let w3 = read_u64_aligned(s.add(24));
                    write_u64_aligned(d.add(24), w3);
                    write_u64_aligned(d.add(16), w2);
                    write_u64_aligned(d.add(8), w1);
                    write_u64_aligned(d, w0);
                }
            }

            if i >= 16 {
                i -= 16;
                unsafe {
                    let s = src.add(i);
                    let d = dst.add(i);
                    let w0 = read_u64_aligned(s);
                    let w1 = read_u64_aligned(s.add(8));
                    write_u64_aligned(d.add(8), w1);
                    write_u64_aligned(d, w0);
                }
            }

            if i >= 8 {
                i -= 8;
                unsafe {
                    let w = read_u64_aligned(src.add(i));
                    write_u64_aligned(dst.add(i), w);
                }
            }
        } else if i >= 16 {
            let k = 8 - src_off;
            let rshift = (src_off * 8) as u32;
            let lshift = (k * 8) as u32;
            let mut high: u64 = 0;
            let mut b = 0;
            while b < src_off {
                high |= (unsafe { *src.add(i - src_off + b) } as u64) << ((k + b) * 8);
                b += 1;
            }

            while i >= 40 {
                unsafe {
                    let s_al = src.add(i - 32 - src_off);
                    let d_al = dst.add(i - 32);
                    let w0 = u64::from_le(read_u64_aligned(s_al));
                    let w1 = u64::from_le(read_u64_aligned(s_al.add(8)));
                    let w2 = u64::from_le(read_u64_aligned(s_al.add(16)));
                    let w3 = u64::from_le(read_u64_aligned(s_al.add(24)));
                    write_u64_aligned(d_al.add(24), ((w3 >> rshift) | high).to_le());
                    write_u64_aligned(d_al.add(16), ((w2 >> rshift) | (w3 << lshift)).to_le());
                    write_u64_aligned(d_al.add(8), ((w1 >> rshift) | (w2 << lshift)).to_le());
                    write_u64_aligned(d_al, ((w0 >> rshift) | (w1 << lshift)).to_le());
                    high = w0 << lshift;
                }
                i -= 32;
            }

            while i >= 16 {
                unsafe {
                    let w = u64::from_le(read_u64_aligned(src.add(i - 8 - src_off)));
                    write_u64_aligned(dst.add(i - 8), ((w >> rshift) | high).to_le());
                    high = w << lshift;
                }
                i -= 8;
            }
        }
    }

    while i > 0 {
        i -= 1;
        unsafe {
            *dst.add(i) = black_box(*src.add(i));
        }
    }

    dst
}

/// Fills `n` bytes at `dst` with `byte`.
///
/// # Safety
/// - `dst` must be valid for writes of `n` bytes.
pub unsafe fn set_bytes(dst: *mut u8, byte: u8, n: usize) -> *mut u8 {
    let dst = black_box(dst);
    let mut i = 0;
    let splat = black_box(LO_U64.wrapping_mul(byte as u64));

    if n >= 16 {
        let misalign = (dst as usize) & 15;
        if misalign != 0 {
            let prolog = (16 - misalign) & 15;
            while i < prolog {
                unsafe {
                    *dst.add(i) = black_box(byte);
                }
                i += 1;
            }
        }

        while n - i >= 64 {
            unsafe {
                let d = dst.add(i);
                write_u64_aligned(d, splat);
                write_u64_aligned(d.add(8), splat);
                write_u64_aligned(d.add(16), splat);
                write_u64_aligned(d.add(24), splat);
                write_u64_aligned(d.add(32), splat);
                write_u64_aligned(d.add(40), splat);
                write_u64_aligned(d.add(48), splat);
                write_u64_aligned(d.add(56), splat);
            }
            i += 64;
        }

        if n - i >= 32 {
            unsafe {
                let d = dst.add(i);
                write_u64_aligned(d, splat);
                write_u64_aligned(d.add(8), splat);
                write_u64_aligned(d.add(16), splat);
                write_u64_aligned(d.add(24), splat);
            }
            i += 32;
        }

        if n - i >= 16 {
            unsafe {
                let d = dst.add(i);
                write_u64_aligned(d, splat);
                write_u64_aligned(d.add(8), splat);
            }
            i += 16;
        }

        if n - i >= 8 {
            unsafe {
                write_u64_aligned(dst.add(i), splat);
            }
            i += 8;
        }
    }

    while i < n {
        unsafe {
            *dst.add(i) = black_box(byte);
        }
        i += 1;
    }

    dst
}

/// Lexicographically compares `n` bytes at `a` and `b`.
///
/// # Safety
/// - `a` and `b` must each be valid for reads of `n` bytes.
pub unsafe fn compare_bytes(a: *const u8, b: *const u8, n: usize) -> i32 {
    let a = black_box(a);
    let b = black_box(b);
    let mut i = 0;

    if n >= 16 {
        while i < n && ((a as usize).wrapping_add(i) & 7) != 0 {
            let av = unsafe { *a.add(i) };
            let bv = unsafe { *b.add(i) };
            if av != bv {
                return (av as i32) - (bv as i32);
            }
            i += 1;
        }

        let b_off = ((b as usize).wrapping_add(i)) & 7;
        if b_off == 0 {
            while n - i >= 8 {
                let wa = unsafe { read_u64_aligned(a.add(i)) };
                let wb = unsafe { read_u64_aligned(b.add(i)) };
                if wa != wb {
                    let diff = u64::from_be(wa) ^ u64::from_be(wb);
                    let idx = (diff.leading_zeros() >> 3) as usize;
                    let av = unsafe { *a.add(i + idx) };
                    let bv = unsafe { *b.add(i + idx) };
                    return (av as i32) - (bv as i32);
                }
                i += 8;
            }
        } else if n - i >= 16 {
            let k = 8 - b_off;
            let rshift = (b_off * 8) as u32;
            let lshift = (k * 8) as u32;
            let mut low: u64 = 0;
            let mut j = 0;
            while j < k {
                low |= (unsafe { *b.add(i + j) } as u64) << (j * 8);
                j += 1;
            }
            while n - i >= 16 {
                let wa = unsafe { read_u64_aligned(a.add(i)) };
                let wb_next = u64::from_le(unsafe { read_u64_aligned(b.add(i + k)) });
                let wb = (low | (wb_next << lshift)).to_le();
                if wa != wb {
                    let diff = u64::from_be(wa) ^ u64::from_be(wb);
                    let idx = (diff.leading_zeros() >> 3) as usize;
                    let av = unsafe { *a.add(i + idx) };
                    let bv = unsafe { *b.add(i + idx) };
                    return (av as i32) - (bv as i32);
                }
                low = wb_next >> rshift;
                i += 8;
            }
        }
    }

    while i < n {
        let av = unsafe { *a.add(i) };
        let bv = unsafe { *b.add(i) };
        if av != bv {
            return (av as i32) - (bv as i32);
        }
        i += 1;
    }
    0
}

/// Returns the length of a NUL-terminated byte string.
///
/// # Safety
/// - `s` must point to a valid NUL-terminated byte string.
pub unsafe fn c_strlen(s: *const u8) -> usize {
    let s = black_box(s);
    let mut len = 0;

    while ((s as usize).wrapping_add(len) & 7) != 0 {
        if unsafe { *s.add(len) } == 0 {
            return len;
        }
        len += 1;
    }

    loop {
        let word = u64::from_le(unsafe { *s.add(len).cast::<u64>() });
        let mask = has_zero_byte(word);
        if mask != 0 {
            return len + first_match_index_le(mask);
        }
        len += 8;
    }
}

/// Returns the length of a NUL-terminated byte string, bounded by `max_len`.
///
/// # Safety
/// - `s` must be valid for reads up to `max_len` bytes or the first NUL byte.
pub unsafe fn c_strnlen(s: *const u8, max_len: usize) -> usize {
    let s = black_box(s);
    let mut len = 0;

    while len < max_len && ((s as usize).wrapping_add(len) & 7) != 0 {
        if unsafe { *s.add(len) } == 0 {
            return len;
        }
        len += 1;
    }

    while max_len - len >= 8 {
        let word = u64::from_le(unsafe { *s.add(len).cast::<u64>() });
        let mask = has_zero_byte(word);
        if mask != 0 {
            return len + first_match_index_le(mask);
        }
        len += 8;
    }

    while len < max_len {
        if unsafe { *s.add(len) } == 0 {
            return len;
        }
        len += 1;
    }
    len
}

/// Searches `haystack` from the front for the first occurrence of `needle`.
pub fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    let n = haystack.len();
    let ptr = black_box(haystack.as_ptr());
    let mut i = 0;
    let splat = LO_U64.wrapping_mul(needle as u64);

    while i < n && ((ptr as usize).wrapping_add(i) & 7) != 0 {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }

    while n - i >= 8 {
        let word = u64::from_le(unsafe { *ptr.add(i).cast::<u64>() }) ^ splat;
        let mask = has_zero_byte(word);
        if mask != 0 {
            return Some(i + first_match_index_le(mask));
        }
        i += 8;
    }

    while i < n {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Searches `haystack` from the back for the last occurrence of `needle`.
pub fn memrchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    let ptr = black_box(haystack.as_ptr());
    let mut i = haystack.len();
    let splat = LO_U64.wrapping_mul(needle as u64);

    while i > 0 && ((ptr as usize).wrapping_add(i) & 7) != 0 {
        i -= 1;
        if haystack[i] == needle {
            return Some(i);
        }
    }

    while i >= 8 {
        i -= 8;
        let word = u64::from_le(unsafe { *ptr.add(i).cast::<u64>() }) ^ splat;
        let mask = has_zero_byte(word);
        if mask != 0 {
            return Some(i + last_match_index_le(mask));
        }
    }

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

    #[test]
    fn bulk_misaligned_offsets_and_overlaps() {
        let mut src = [0u8; 320];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(5);
        }

        for src_off in 0..16 {
            for dst_off in 0..16 {
                for &len in &[0usize, 1, 7, 8, 15, 16, 31, 63, 64, 65, 127, 128, 193, 256] {
                    let mut dst = [0xeeu8; 320];
                    unsafe {
                        copy_nonoverlapping_bytes(
                            dst.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                    }
                    assert_eq!(&dst[..dst_off], &[0xeeu8; 16][..dst_off]);
                    assert_eq!(&dst[dst_off..dst_off + len], &src[src_off..src_off + len]);
                    assert_eq!(&dst[dst_off + len..dst_off + len + 8], &[0xeeu8; 8]);
                }
            }
        }

        for shift in 1..16 {
            for base_off in 0..8 {
                for &len in &[1usize, 7, 8, 15, 16, 31, 64, 97, 128, 192, 256] {
                    let mut buf = src;
                    unsafe {
                        copy_bytes(
                            buf.as_mut_ptr().add(base_off + shift),
                            buf.as_ptr().add(base_off),
                            len,
                        );
                    }
                    assert_eq!(
                        &buf[base_off + shift..base_off + shift + len],
                        &src[base_off..base_off + len]
                    );

                    let mut buf_fwd = src;
                    unsafe {
                        copy_bytes(
                            buf_fwd.as_mut_ptr().add(base_off),
                            buf_fwd.as_ptr().add(base_off + shift),
                            len,
                        );
                    }
                    assert_eq!(
                        &buf_fwd[base_off..base_off + len],
                        &src[base_off + shift..base_off + shift + len]
                    );
                }
            }
        }
    }

    #[test]
    fn swar_strlen_memchr_and_word_compare_edges() {
        let mut buf = [b'x'; 160];
        for off in 0..16 {
            for len in 0..96 {
                buf.fill(b'a');
                if len >= 2 {
                    buf[off + len / 2] = 0x80;
                    buf[off + len - 1] = 0xff;
                }
                buf[off + len] = 0;

                let ptr = unsafe { buf.as_ptr().add(off) };
                assert_eq!(unsafe { c_strlen(ptr) }, len);
                assert_eq!(unsafe { c_strnlen(ptr, len + 16) }, len);
                if len > 0 {
                    assert_eq!(unsafe { c_strnlen(ptr, len - 1) }, len - 1);
                }

                let slice = &buf[off..off + len];
                assert_eq!(memchr(0, &buf[off..off + len + 1]), Some(len));
                assert_eq!(memchr(b'z', slice), None);
                assert_eq!(memrchr(b'z', slice), None);
            }
        }

        let mut hay = [b'.'; 128];
        for off in 0..8 {
            for pos in 0..80 {
                hay.fill(b'.');
                hay[off + pos] = 0xa5;
                let s = &hay[off..off + 80];
                assert_eq!(memchr(0xa5, s), Some(pos));
                assert_eq!(memrchr(0xa5, s), Some(pos));

                let mut other = [b'.'; 128];
                other[off + pos] = 0xa4;
                let a_ptr = unsafe { hay.as_ptr().add(off) };
                assert!(unsafe { compare_bytes(a_ptr, other.as_ptr().add(off), 80) } > 0);
                assert!(unsafe { compare_bytes(other.as_ptr().add(off), a_ptr, 80) } < 0);
                other[off + pos] = 0xa5;
                assert_eq!(
                    unsafe { compare_bytes(a_ptr, other.as_ptr().add(off), 80) },
                    0
                );
            }
        }
    }
}
