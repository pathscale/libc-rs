//! Deterministic static BSS segregated-freelist + bump allocator.

use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

const NUM_CLASSES: usize = 9;
const CLASS_SIZES: [usize; NUM_CLASSES] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

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

#[inline]
const fn size_class_index(size: usize, align: usize) -> Option<usize> {
    let required = if size > align { size } else { align };
    let mut i = 0;
    while i < NUM_CLASSES {
        if required <= CLASS_SIZES[i] {
            return Some(i);
        }
        i += 1;
    }
    None
}

struct HeapInner<const BYTES: usize> {
    arena: [u8; BYTES],
    bump: usize,
    last_bump_start: usize,
    last_bump_end: usize,
    free_lists: [*mut FreeNode; NUM_CLASSES],
    allocated: usize,
    peak: usize,
}

impl<const BYTES: usize> HeapInner<BYTES> {
    const fn new() -> Self {
        Self {
            arena: [0; BYTES],
            bump: 0,
            last_bump_start: 0,
            last_bump_end: 0,
            free_lists: [null_mut(); NUM_CLASSES],
            allocated: 0,
            peak: 0,
        }
    }

    fn record_alloc(&mut self, bytes: usize) {
        self.allocated = self.allocated.saturating_add(bytes);
        if self.allocated > self.peak {
            self.peak = self.allocated;
        }
    }

    fn record_dealloc(&mut self, bytes: usize) {
        self.allocated = self.allocated.saturating_sub(bytes);
    }

    unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        if size == 0 {
            return align as *mut u8;
        }
        let align = if align < core::mem::align_of::<FreeNode>() {
            core::mem::align_of::<FreeNode>()
        } else {
            align
        };
        if !align.is_power_of_two() {
            return null_mut();
        }

        if let Some(class_idx) = size_class_index(size, align) {
            let class_size = CLASS_SIZES[class_idx];
            let head = self.free_lists[class_idx];
            if !head.is_null() {
                unsafe {
                    self.free_lists[class_idx] = (*head).next;
                }
                self.record_alloc(class_size);
                return head.cast::<u8>();
            }
            return unsafe { self.bump_alloc(class_size, align.max(class_size.min(16))) };
        }

        unsafe { self.bump_alloc(size, align) }
    }

    unsafe fn bump_alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let base = self.arena.as_mut_ptr() as usize;
        let current = match base.checked_add(self.bump) {
            Some(v) => v,
            None => return null_mut(),
        };
        let aligned = match align_up(current, align) {
            Some(v) => v,
            None => return null_mut(),
        };
        let offset = aligned - base;
        let end = match offset.checked_add(size) {
            Some(v) => v,
            None => return null_mut(),
        };
        if end > BYTES {
            return null_mut();
        }

        self.last_bump_start = offset;
        self.last_bump_end = end;
        self.bump = end;
        self.record_alloc(size);
        unsafe { self.arena.as_mut_ptr().add(offset) }
    }

    unsafe fn dealloc(&mut self, ptr: *mut u8, size: usize, align: usize) {
        if ptr.is_null() || size == 0 {
            return;
        }
        let align = if align < core::mem::align_of::<FreeNode>() {
            core::mem::align_of::<FreeNode>()
        } else {
            align
        };

        if let Some(class_idx) = size_class_index(size, align) {
            let class_size = CLASS_SIZES[class_idx];
            let node = ptr.cast::<FreeNode>();
            unsafe {
                (*node).next = self.free_lists[class_idx];
            }
            self.free_lists[class_idx] = node;
            self.record_dealloc(class_size);
            return;
        }

        let base = self.arena.as_ptr() as usize;
        let offset = (ptr as usize).wrapping_sub(base);
        if offset == self.last_bump_start && self.bump == self.last_bump_end {
            self.bump = self.last_bump_start;
            self.last_bump_end = self.last_bump_start;
        }
        self.record_dealloc(size);
    }
}

/// Static BSS-backed segregated-freelist and bump allocator.
pub struct StaticHeap<const BYTES: usize> {
    lock: AtomicBool,
    inner: UnsafeCell<HeapInner<BYTES>>,
}

unsafe impl<const BYTES: usize> Sync for StaticHeap<BYTES> {}

impl<const BYTES: usize> StaticHeap<BYTES> {
    /// Creates an empty `StaticHeap`.
    pub const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            inner: UnsafeCell::new(HeapInner::new()),
        }
    }

    #[inline]
    fn with_lock<R>(&self, f: impl FnOnce(&mut HeapInner<BYTES>) -> R) -> R {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = unsafe { f(&mut *self.inner.get()) };
        self.lock.store(false, Ordering::Release);
        result
    }

    /// Allocates `size` bytes aligned to `align`. Returns null on exhaustion.
    ///
    /// # Safety
    /// Caller must ensure any returned non-null pointer is freed with matching
    /// `size` and `align`.
    pub unsafe fn alloc_raw(&self, size: usize, align: usize) -> *mut u8 {
        self.with_lock(|inner| unsafe { inner.alloc(size, align) })
    }

    /// Deallocates a block previously returned by `alloc_raw`.
    ///
    /// # Safety
    /// `ptr` must have been allocated from this heap with the same `size` and `align`.
    pub unsafe fn dealloc_raw(&self, ptr: *mut u8, size: usize, align: usize) {
        self.with_lock(|inner| unsafe { inner.dealloc(ptr, size, align) });
    }

    /// Returns currently allocated bytes.
    pub fn allocated_bytes(&self) -> usize {
        self.with_lock(|inner| inner.allocated)
    }

    /// Returns peak allocated bytes observed since initialization.
    pub fn peak_bytes(&self) -> usize {
        self.with_lock(|inner| inner.peak)
    }

    /// Returns remaining uncarved bytes in the static arena.
    pub fn remaining_arena_bytes(&self) -> usize {
        self.with_lock(|inner| BYTES.saturating_sub(inner.bump))
    }
}

impl<const BYTES: usize> Default for StaticHeap<BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<const BYTES: usize> core::alloc::GlobalAlloc for StaticHeap<BYTES> {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe { self.alloc_raw(layout.size(), layout.align()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { self.dealloc_raw(ptr, layout.size(), layout.align()) }
    }
}

/// Declares a `#[global_allocator]` backed by `StaticHeap<BYTES>`.
#[macro_export]
macro_rules! declare_global_heap {
    ($name:ident, $bytes:expr) => {
        #[global_allocator]
        static $name: $crate::heap::StaticHeap<$bytes> = $crate::heap::StaticHeap::new();
    };
}

const MMAP_NUM_CLASSES: usize = 7;
const MMAP_CLASS_TOTAL_SIZES: [usize; MMAP_NUM_CLASSES] = [32, 64, 128, 256, 512, 1024, 2048];
const MMAP_HEADER_BYTES: usize = 16;
const MMAP_LARGE_HEADER_BYTES: usize = 32;
const MMAP_MAX_SMALL_PAYLOAD: usize = 2032;
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
/// (`<= 2032` bytes) and direct page-granularity `mmap_anonymous`/`munmap` mappings for
/// large or over-aligned allocations.
pub struct MmapHeap {
    lock: AtomicBool,
    inner: UnsafeCell<MmapHeapInner>,
}

// SAFETY: Access to `inner` is serialized by the `lock` spinlock.
unsafe impl Sync for MmapHeap {}

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
            lock: AtomicBool::new(false),
            inner: UnsafeCell::new(MmapHeapInner::new()),
        }
    }

    #[inline]
    fn with_lock<R>(&self, f: impl FnOnce(&mut MmapHeapInner) -> R) -> R {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: `lock` is held exclusively by the current thread.
        let result = unsafe { f(&mut *self.inner.get()) };
        self.lock.store(false, Ordering::Release);
        result
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
                return self.with_lock(|inner| {
                    // SAFETY: `class_idx` is a valid small class index.
                    unsafe { inner.alloc_small(class_idx) }
                });
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
        // Large allocations come fresh from `mmap_anonymous` and are already zeroed by the kernel.
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
                self.with_lock(|inner| {
                    // SAFETY: `block_ptr` is a small slab block for `class_idx`.
                    unsafe { inner.free_small(block_ptr, class_idx) };
                });
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
    /// - If `ptr` is null, behaves like `alloc_c(new_size, 16)`.
    /// - If `new_size == 0`, frees `ptr` and returns null.
    /// - If `new_size` fits within the current small size class, returns `ptr` in-place.
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
    /// Validates `align >= size_of::<usize>()` and `align.is_power_of_two()`, returning `0`
    /// on success, `EINVAL` on invalid alignment, or `ENOMEM` on out-of-memory.
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
    use core::alloc::{GlobalAlloc, Layout};

    #[test]
    fn small_size_class_reuse_does_not_exhaust_arena() {
        let heap: StaticHeap<65536> = StaticHeap::new();
        let layout = Layout::from_size_align(64, 8).unwrap();

        for _ in 0..10_000 {
            let p = unsafe { heap.alloc(layout) };
            assert!(!p.is_null());
            unsafe { heap.dealloc(p, layout) };
        }

        assert_eq!(heap.allocated_bytes(), 0);
        assert!(heap.remaining_arena_bytes() >= 65536 - 128);
    }

    #[test]
    fn over_aligned_and_top_of_arena_rewind() {
        let heap: StaticHeap<65536> = StaticHeap::new();
        let aligned = Layout::from_size_align(256, 512).unwrap();
        let p = unsafe { heap.alloc(aligned) };
        assert!(!p.is_null());
        assert_eq!((p as usize) % 512, 0);
        unsafe { heap.dealloc(p, aligned) };

        let large = Layout::from_size_align(8192, 16).unwrap();
        let before = heap.remaining_arena_bytes();
        let big = unsafe { heap.alloc(large) };
        assert!(!big.is_null());
        assert!(heap.remaining_arena_bytes() < before);
        unsafe { heap.dealloc(big, large) };
        assert_eq!(heap.remaining_arena_bytes(), before);
    }

    #[test]
    fn exhaustion_returns_null() {
        let heap: StaticHeap<1024> = StaticHeap::new();
        let too_big = Layout::from_size_align(2048, 8).unwrap();
        let p = unsafe { heap.alloc(too_big) };
        assert!(p.is_null());
    }

    #[test]
    fn mmap_heap_small_large_realloc_calloc_and_memalign() {
        use crate::errno::{ENOMEM, Errno};
        use crate::raw::{nr, with_mock_syscall};
        use core::sync::atomic::AtomicUsize;

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
                // 1. Small malloc + free + slab reuse
                let p1 = unsafe { c_malloc(24) };
                assert!(!p1.is_null());
                assert_eq!((p1 as usize) % 16, 0);
                unsafe {
                    crate::mem::set_bytes(p1, 0xAB, 24);
                    c_free(p1);
                }
                let p2 = unsafe { c_malloc(24) };
                assert_eq!(p1, p2);

                // 2. In-place small realloc within the same class (<= 48 payload in 64-byte class)
                let p_same = unsafe { c_realloc(p2, 40) };
                assert_eq!(p_same, p2);

                // 3. Growing small realloc to a larger small class preserves contents
                let p_grow = unsafe { c_realloc(p_same, 200) };
                assert!(!p_grow.is_null());
                assert_ne!(p_grow, p_same);
                for i in 0..24 {
                    assert_eq!(unsafe { *p_grow.add(i) }, 0xAB);
                }
                unsafe {
                    c_free(p_grow);
                }

                // 4. c_calloc zero-initializes memory and rejects overflow
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

                // 5. Large allocation (> 2032) and direct munmap on free
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

                // 6. posix_memalign validation and 4096-byte alignment
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
