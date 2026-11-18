//! Dynamic `mmap_anonymous` slab and page-granularity allocator for unikernel EL0 binaries.

use core::ptr::null_mut;

use crate::sync::FutexMutex;

#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
}

#[inline]
const fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    match value.checked_add(mask) {
        Some(v) => Some(v & !mask),
        None => None,
    }
}

const MMAP_NUM_CLASSES: usize = 8;
const MMAP_CLASS_TOTAL_SIZES: [usize; MMAP_NUM_CLASSES] = [32, 64, 128, 256, 512, 1024, 2048, 4096];
const MMAP_HEADER_BYTES: usize = 16;
const MMAP_LARGE_HEADER_BYTES: usize = 32;
const MMAP_MAX_SMALL_PAYLOAD: usize = 4080;
const MMAP_SLAB_BYTES: usize = 16 * crate::mm::PAGE_SIZE;

const SMALL_MAGIC_BASE: usize = 0xC0DE_5A1B_0000_0000;
const SMALL_MAGIC_MASK: usize = 0xFFFF_FFFF_FFFF_FF00;
const LARGE_MAGIC: usize = 0xC0DE_1A6E_5A1B_0001;

#[inline]
const fn mmap_small_class_index(size: usize) -> Option<usize> {
    let total = match size.checked_add(MMAP_HEADER_BYTES) {
        Some(v) => v,
        None => return None,
    };
    let mut i = 0;
    while i < MMAP_NUM_CLASSES {
        if total <= MMAP_CLASS_TOTAL_SIZES[i] {
            return Some(i);
        }
        i += 1;
    }
    None
}

struct MmapHeapInner {
    free_lists: [*mut FreeNode; MMAP_NUM_CLASSES],
    slab_ptr: *mut u8,
    slab_rem: usize,
}

// SAFETY: `MmapHeapInner` is only accessed while holding `MmapHeap::inner`'s `FutexMutex`.
unsafe impl Send for MmapHeapInner {}

impl MmapHeapInner {
    const fn new() -> Self {
        Self {
            free_lists: [null_mut(); MMAP_NUM_CLASSES],
            slab_ptr: null_mut(),
            slab_rem: 0,
        }
    }

    unsafe fn alloc_small(&mut self, class_idx: usize) -> *mut u8 {
        let block_bytes = MMAP_CLASS_TOTAL_SIZES[class_idx];
        let payload_bytes = block_bytes - MMAP_HEADER_BYTES;
        let head = self.free_lists[class_idx];
        let block_ptr = if !head.is_null() {
            // SAFETY: `head` is a valid free-list node previously carved from a slab.
            unsafe {
                self.free_lists[class_idx] = (*head).next;
            }
            head.cast::<u8>()
        } else {
            if self.slab_rem < block_bytes {
                let slab = match crate::mm::mmap_anonymous(
                    MMAP_SLAB_BYTES,
                    crate::mm::PROT_READ | crate::mm::PROT_WRITE,
                    0,
                ) {
                    Ok(p) if !p.is_null() => p,
                    _ => return null_mut(),
                };
                self.slab_ptr = slab;
                self.slab_rem = MMAP_SLAB_BYTES;
            }
            let p = self.slab_ptr;
            // SAFETY: `self.slab_rem >= block_bytes` guarantees `add(block_bytes)` stays within the slab.
            self.slab_ptr = unsafe { self.slab_ptr.add(block_bytes) };
            self.slab_rem -= block_bytes;
            p
        };

        // SAFETY: `block_ptr` is 16-byte aligned and has at least `block_bytes` writable bytes.
        unsafe {
            let hdr = block_ptr.cast::<usize>();
            hdr.write(SMALL_MAGIC_BASE | class_idx);
            hdr.add(1).write(payload_bytes);
            block_ptr.add(MMAP_HEADER_BYTES)
        }
    }

    unsafe fn free_small(&mut self, block_ptr: *mut u8, class_idx: usize) {
        let node = block_ptr.cast::<FreeNode>();
        // SAFETY: `block_ptr` is the start of a small slab block of size >= 32 bytes.
        unsafe {
            (*node).next = self.free_lists[class_idx];
        }
        self.free_lists[class_idx] = node;
    }
}

/// Dynamic virtual-memory allocator backed by `mmap_anonymous` slabs for small blocks
/// (`<= 4080` bytes) and direct page-granularity `mmap_anonymous`/`munmap` mappings for
/// large or over-aligned allocations.
pub struct MmapHeap {
    inner: FutexMutex<MmapHeapInner>,
}

impl Default for MmapHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapHeap {
    /// Creates a new uninitialized [`MmapHeap`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: FutexMutex::new(MmapHeapInner::new()),
        }
    }

    /// Allocates `size` bytes with alignment `align` (at least 16-byte aligned), recording
    /// C-compatible metadata immediately preceding the returned user pointer.
    ///
    /// # Safety
    ///
    /// Any non-null pointer returned must be released via [`MmapHeap::free_c`] or [`MmapHeap::realloc_c`].
    pub unsafe fn alloc_c(&self, size: usize, align: usize) -> *mut u8 {
        let eff_align = if align < 16 { 16 } else { align };
        if !eff_align.is_power_of_two() {
            return null_mut();
        }
        let req_size = if size == 0 { 1 } else { size };

        if eff_align == 16 && req_size <= MMAP_MAX_SMALL_PAYLOAD {
            if let Some(class_idx) = mmap_small_class_index(req_size) {
                let mut inner = self.inner.lock();
                // SAFETY: `class_idx` is a valid small class index.
                return unsafe { inner.alloc_small(class_idx) };
            }
        }

        // SAFETY: `eff_align` is a power of two >= 16.
        unsafe { Self::alloc_large(req_size, eff_align) }
    }

    unsafe fn alloc_large(size: usize, align: usize) -> *mut u8 {
        let extra = match align.checked_add(MMAP_LARGE_HEADER_BYTES) {
            Some(v) => v,
            None => return null_mut(),
        };
        let raw_needed = match size.checked_add(extra) {
            Some(v) => v,
            None => return null_mut(),
        };
        let map_total_len = match align_up(raw_needed, crate::mm::PAGE_SIZE) {
            Some(v) => v,
            None => return null_mut(),
        };

        let map_base = match crate::mm::mmap_anonymous(
            map_total_len,
            crate::mm::PROT_READ | crate::mm::PROT_WRITE,
            0,
        ) {
            Ok(p) if !p.is_null() => p,
            _ => return null_mut(),
        };

        let base_addr = map_base as usize;
        let min_user_addr = match base_addr.checked_add(MMAP_LARGE_HEADER_BYTES) {
            Some(v) => v,
            None => {
                // SAFETY: `map_base` and `map_total_len` were just returned by `mmap_anonymous`.
                let _ = unsafe { crate::mm::munmap(map_base, map_total_len) };
                return null_mut();
            }
        };
        let user_addr = match align_up(min_user_addr, align) {
            Some(v) => v,
            None => {
                // SAFETY: `map_base` and `map_total_len` were just returned by `mmap_anonymous`.
                let _ = unsafe { crate::mm::munmap(map_base, map_total_len) };
                return null_mut();
            }
        };
        let offset = user_addr - base_addr;
        let usable_size = map_total_len.saturating_sub(offset);
        // SAFETY: `user_addr` lies within `[base_addr + 32, base_addr + map_total_len)`.
        unsafe {
            let user_ptr = map_base.add(offset);
            let hdr = user_ptr.sub(MMAP_LARGE_HEADER_BYTES).cast::<usize>();
            hdr.write(base_addr);
            hdr.add(1).write(map_total_len);
            hdr.add(2).write(LARGE_MAGIC);
            hdr.add(3).write(usable_size);
            user_ptr
        }
    }

    /// Allocates and zero-initializes `nobj * size` bytes.
    ///
    /// # Safety
    ///
    /// Any non-null pointer returned must be released via [`MmapHeap::free_c`] or [`MmapHeap::realloc_c`].
    pub unsafe fn calloc_c(&self, nobj: usize, size: usize) -> *mut u8 {
        let total = match nobj.checked_mul(size) {
            Some(v) => v,
            None => return null_mut(),
        };
        let req_size = if total == 0 { 1 } else { total };
        if req_size <= MMAP_MAX_SMALL_PAYLOAD {
            // SAFETY: `req_size` is validated and alignment is 16.
            let ptr = unsafe { self.alloc_c(req_size, 16) };
            if !ptr.is_null() {
                // SAFETY: `ptr` has at least `req_size` writable bytes.
                unsafe {
                    crate::mem::set_bytes(ptr, 0, req_size);
                }
            }
            return ptr;
        }
        // SAFETY: `req_size > MMAP_MAX_SMALL_PAYLOAD` takes the direct `mmap_anonymous` path.
        unsafe { Self::alloc_large(req_size, 16) }
    }

    /// Frees a pointer previously returned by [`MmapHeap::alloc_c`], [`MmapHeap::calloc_c`],
    /// or [`MmapHeap::realloc_c`]. Passing null is a safe no-op.
    ///
    /// # Safety
    ///
    /// `ptr` must be null or a live pointer allocated by this [`MmapHeap`].
    pub unsafe fn free_c(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: Every pointer allocated by `MmapHeap` is preceded by at least 16 bytes of metadata.
        let hdr = unsafe { ptr.sub(MMAP_HEADER_BYTES).cast::<usize>() };
        let magic = unsafe { hdr.read() };

        if (magic & SMALL_MAGIC_MASK) == SMALL_MAGIC_BASE {
            let class_idx = magic & 0xFF;
            if class_idx < MMAP_NUM_CLASSES {
                let block_ptr = hdr.cast::<u8>();
                let mut inner = self.inner.lock();
                // SAFETY: `block_ptr` is a small slab block for `class_idx`.
                unsafe { inner.free_small(block_ptr, class_idx) };
            }
            return;
        }

        if magic == LARGE_MAGIC {
            // SAFETY: Large allocations store `[base_addr, map_total_len]` in the 16 bytes before `hdr`.
            unsafe {
                let large_hdr = ptr.sub(MMAP_LARGE_HEADER_BYTES).cast::<usize>();
                let base_addr = large_hdr.read();
                let map_total_len = large_hdr.add(1).read();
                let _ = crate::mm::munmap(base_addr as *mut u8, map_total_len);
            }
        }
    }

    /// Resizes an existing allocation to `new_size` bytes.
    ///
    /// # Safety
    ///
    /// `ptr` must be null or a live pointer allocated by this [`MmapHeap`].
    pub unsafe fn realloc_c(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            // SAFETY: Delegating to `alloc_c` with 16-byte alignment.
            return unsafe { self.alloc_c(new_size, 16) };
        }
        if new_size == 0 {
            // SAFETY: Caller guarantees `ptr` is a valid allocation from this heap.
            unsafe { self.free_c(ptr) };
            return null_mut();
        }

        // SAFETY: `ptr` is preceded by a 16-byte metadata header.
        let hdr = unsafe { ptr.sub(MMAP_HEADER_BYTES).cast::<usize>() };
        let magic = unsafe { hdr.read() };
        let old_usable = unsafe { hdr.add(1).read() };

        if (magic & SMALL_MAGIC_MASK) == SMALL_MAGIC_BASE {
            let cur_class = magic & 0xFF;
            if let Some(target_class) = mmap_small_class_index(new_size) {
                if target_class == cur_class {
                    return ptr;
                }
            }
        } else if magic == LARGE_MAGIC
            && new_size <= old_usable
            && new_size > MMAP_MAX_SMALL_PAYLOAD
        {
            return ptr;
        }

        // SAFETY: Allocating replacement buffer of `new_size` bytes.
        let new_ptr = unsafe { self.alloc_c(new_size, 16) };
        if new_ptr.is_null() {
            return null_mut();
        }
        let copy_len = if old_usable < new_size {
            old_usable
        } else {
            new_size
        };
        // SAFETY: Both `ptr` and `new_ptr` are valid non-overlapping buffers of at least `copy_len` bytes.
        unsafe {
            crate::mem::copy_nonoverlapping_bytes(new_ptr, ptr, copy_len);
            self.free_c(ptr);
        }
        new_ptr
    }

    /// POSIX-compatible aligned allocation writing the result into `*out`.
    ///
    /// # Safety
    ///
    /// `out` must be a valid non-null writable pointer to `*mut u8`.
    pub unsafe fn posix_memalign_c(&self, out: *mut *mut u8, align: usize, size: usize) -> i32 {
        if out.is_null() || align < core::mem::size_of::<usize>() || !align.is_power_of_two() {
            return crate::errno::EINVAL;
        }
        // SAFETY: `align` is a power of two.
        let ptr = unsafe { self.alloc_c(size, align) };
        if ptr.is_null() {
            return crate::errno::ENOMEM;
        }
        // SAFETY: `out` was checked for non-null above and caller guarantees writability.
        unsafe {
            out.write(ptr);
        }
        0
    }
}

unsafe impl core::alloc::GlobalAlloc for MmapHeap {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // SAFETY: Forwarding `GlobalAlloc::alloc` to `alloc_c`.
        unsafe { self.alloc_c(layout.size(), layout.align()) }
    }

    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        if layout.align() <= 16 {
            // SAFETY: `calloc_c` returns 16-byte aligned zeroed memory.
            unsafe { self.calloc_c(1, layout.size()) }
        } else {
            // SAFETY: Over-aligned allocation + explicit zeroing when small.
            let ptr = unsafe { self.alloc_c(layout.size(), layout.align()) };
            if !ptr.is_null() && layout.size() <= MMAP_MAX_SMALL_PAYLOAD {
                unsafe {
                    crate::mem::set_bytes(ptr, 0, layout.size());
                }
            }
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        // SAFETY: `ptr` was allocated by `self`.
        unsafe { self.free_c(ptr) }
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        if layout.align() <= 16 {
            // SAFETY: Standard 16-byte aligned reallocation.
            unsafe { self.realloc_c(ptr, new_size) }
        } else {
            // SAFETY: Over-aligned reallocation allocates fresh aligned block, copies, and frees.
            let new_ptr = unsafe { self.alloc_c(new_size, layout.align()) };
            if !new_ptr.is_null() {
                let copy_len = if layout.size() < new_size {
                    layout.size()
                } else {
                    new_size
                };
                unsafe {
                    crate::mem::copy_nonoverlapping_bytes(new_ptr, ptr, copy_len);
                    self.free_c(ptr);
                }
            }
            new_ptr
        }
    }
}

/// Process-wide global [`MmapHeap`] instance used by `c_malloc`, `c_calloc`, `c_realloc`,
/// `c_free`, and `c_posix_memalign`.
pub static GLOBAL_MMAP_HEAP: MmapHeap = MmapHeap::new();

/// Allocates `size` bytes of 16-byte aligned memory from [`GLOBAL_MMAP_HEAP`].
///
/// # Safety
///
/// Returned memory is uninitialized and must be released with [`c_free`] or [`c_realloc`].
pub unsafe fn c_malloc(size: usize) -> *mut u8 {
    // SAFETY: Delegating to `GLOBAL_MMAP_HEAP.alloc_c`.
    unsafe { GLOBAL_MMAP_HEAP.alloc_c(size, 16) }
}

/// Allocates and zero-initializes `nobj * size` bytes from [`GLOBAL_MMAP_HEAP`].
///
/// # Safety
///
/// Returned pointer must be released with [`c_free`] or [`c_realloc`].
pub unsafe fn c_calloc(nobj: usize, size: usize) -> *mut u8 {
    // SAFETY: Delegating to `GLOBAL_MMAP_HEAP.calloc_c`.
    unsafe { GLOBAL_MMAP_HEAP.calloc_c(nobj, size) }
}

/// Resizes the allocation at `ptr` to `new_size` bytes in [`GLOBAL_MMAP_HEAP`].
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `c_malloc`, `c_calloc`,
/// `c_realloc`, or `c_posix_memalign`.
pub unsafe fn c_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    // SAFETY: Delegating to `GLOBAL_MMAP_HEAP.realloc_c`.
    unsafe { GLOBAL_MMAP_HEAP.realloc_c(ptr, new_size) }
}

/// Frees a pointer previously allocated from [`GLOBAL_MMAP_HEAP`].
///
/// # Safety
///
/// `ptr` must be null or a live pointer returned by `c_malloc`, `c_calloc`,
/// `c_realloc`, or `c_posix_memalign`.
pub unsafe fn c_free(ptr: *mut u8) {
    // SAFETY: Delegating to `GLOBAL_MMAP_HEAP.free_c`.
    unsafe { GLOBAL_MMAP_HEAP.free_c(ptr) }
}

/// Allocates `size` bytes aligned to `align` and writes the pointer to `*out`.
///
/// # Safety
///
/// `out` must be a valid writable pointer to `*mut u8`.
pub unsafe fn c_posix_memalign(out: *mut *mut u8, align: usize, size: usize) -> i32 {
    // SAFETY: Delegating to `GLOBAL_MMAP_HEAP.posix_memalign_c`.
    unsafe { GLOBAL_MMAP_HEAP.posix_memalign_c(out, align, size) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn mmap_heap_small_large_realloc_calloc_and_memalign() {
        use crate::errno::{ENOMEM, Errno};
        use crate::raw::{nr, with_mock_syscall};

        #[repr(align(4096))]
        struct AlignedArena([u8; 256 * 1024]);

        static mut ARENA: AlignedArena = AlignedArena([0; 256 * 1024]);
        static OFFSET: AtomicUsize = AtomicUsize::new(0);
        static MUNMAP_COUNT: AtomicUsize = AtomicUsize::new(0);
        static LAST_MUNMAP_LEN: AtomicUsize = AtomicUsize::new(0);

        OFFSET.store(0, Ordering::SeqCst);
        MUNMAP_COUNT.store(0, Ordering::SeqCst);
        LAST_MUNMAP_LEN.store(0, Ordering::SeqCst);

        with_mock_syscall(
            |sysno, args| match sysno {
                nr::MMAP => {
                    let len = args[1];
                    let aligned_len = (len + 4095) & !4095;
                    let start = OFFSET.fetch_add(aligned_len, Ordering::SeqCst);
                    if start + aligned_len > 256 * 1024 {
                        return Err(Errno(ENOMEM));
                    }
                    // SAFETY: `start + aligned_len` is within `ARENA`.
                    let ptr = unsafe { core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(start) };
                    unsafe {
                        crate::mem::set_bytes(ptr, 0, aligned_len);
                    }
                    Ok(ptr as usize)
                }
                nr::MUNMAP => {
                    MUNMAP_COUNT.fetch_add(1, Ordering::SeqCst);
                    LAST_MUNMAP_LEN.store(args[1], Ordering::SeqCst);
                    Ok(0)
                }
                _ => Err(Errno(crate::errno::ENOSYS)),
            },
            || {
                let p1 = unsafe { c_malloc(24) };
                assert!(!p1.is_null());
                assert_eq!((p1 as usize) % 16, 0);
                unsafe {
                    crate::mem::set_bytes(p1, 0xAB, 24);
                    c_free(p1);
                }
                let p2 = unsafe { c_malloc(24) };
                assert_eq!(p1, p2);

                let p_same = unsafe { c_realloc(p2, 40) };
                assert_eq!(p_same, p2);

                let p_grow = unsafe { c_realloc(p_same, 200) };
                assert!(!p_grow.is_null());
                assert_ne!(p_grow, p_same);
                for i in 0..24 {
                    assert_eq!(unsafe { *p_grow.add(i) }, 0xAB);
                }
                unsafe {
                    c_free(p_grow);
                }

                let overflow = unsafe { c_calloc(usize::MAX, 2) };
                assert!(overflow.is_null());
                let zeroed = unsafe { c_calloc(8, 16) };
                assert!(!zeroed.is_null());
                for i in 0..128 {
                    assert_eq!(unsafe { *zeroed.add(i) }, 0);
                }
                unsafe {
                    c_free(zeroed);
                }

                let big = unsafe { c_malloc(8192) };
                assert!(!big.is_null());
                assert_eq!((big as usize) % 16, 0);
                unsafe {
                    *big = 0x55;
                    *big.add(8191) = 0x77;
                    c_free(big);
                }
                assert_eq!(MUNMAP_COUNT.load(Ordering::SeqCst), 1);
                assert!(LAST_MUNMAP_LEN.load(Ordering::SeqCst) >= 8192);

                let mut aligned_out: *mut u8 = null_mut();
                assert_eq!(
                    unsafe { c_posix_memalign(&mut aligned_out, 3, 64) },
                    crate::errno::EINVAL
                );
                assert_eq!(
                    unsafe { c_posix_memalign(&mut aligned_out, 4, 64) },
                    crate::errno::EINVAL
                );
                assert_eq!(unsafe { c_posix_memalign(&mut aligned_out, 4096, 1024) }, 0);
                assert!(!aligned_out.is_null());
                assert_eq!((aligned_out as usize) % 4096, 0);
                unsafe {
                    c_free(aligned_out);
                }
                assert_eq!(MUNMAP_COUNT.load(Ordering::SeqCst), 2);
            },
        );
    }
}
