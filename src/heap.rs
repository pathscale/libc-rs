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
}
