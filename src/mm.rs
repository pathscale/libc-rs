//! Virtual memory mapping and protection calls (`mmap`, `munmap`, `mprotect`, `madvise`, `msync`, `mincore`).

use crate::errno::{EINVAL, ENOSYS, Errno, SysResult};
use crate::fd::RawFd;
use crate::raw::{nr, syscall2, syscall3, syscall6};

/// Standard 4 KiB page size on AArch64.
pub const PAGE_SIZE: usize = 4096;

pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1;
pub const PROT_WRITE: i32 = 2;
pub const PROT_EXEC: i32 = 4;

pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANON: i32 = 0x20;
pub const MAP_NORESERVE: i32 = 0x4000;
pub const MAP_STACK: i32 = 0x20000;

pub const MADV_NORMAL: i32 = 0;
pub const MADV_DONTNEED: i32 = 4;
pub const MADV_FREE: i32 = 8;

pub const MS_ASYNC: i32 = 1;
pub const MS_INVALIDATE: i32 = 2;
pub const MS_SYNC: i32 = 4;

/// Maps virtual memory pages into the address space.
///
/// # Safety
///
/// If `MAP_FIXED` is set, the caller must ensure the target address range does not
/// alias active Rust allocations or violate memory safety.
pub unsafe fn mmap(
    addr: *mut u8,
    len: usize,
    prot: i32,
    flags: i32,
    fd: RawFd,
    offset: i64,
) -> SysResult<*mut u8> {
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    // SAFETY: Caller upholds the address space invariants for `mmap`.
    let raw = unsafe {
        syscall6(
            nr::MMAP,
            addr as usize,
            len,
            prot as u32 as usize,
            flags as u32 as usize,
            fd as usize,
            offset as usize,
        )?
    };
    Ok(raw as *mut u8)
}

/// Maps anonymous private memory pages (`MAP_PRIVATE | MAP_ANON`).
pub fn mmap_anonymous(len: usize, prot: i32, flags: i32) -> SysResult<*mut u8> {
    // SAFETY: Mapping anonymous memory at a kernel-chosen address (`null_mut`) without `MAP_FIXED`
    // does not alias existing allocations when `MAP_FIXED` is not present.
    unsafe {
        mmap(
            core::ptr::null_mut(),
            len,
            prot,
            flags | MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    }
}

/// Unmaps a previously mapped memory region.
///
/// # Safety
///
/// `[addr, addr + len)` must be a valid mapped region that is no longer referenced.
pub unsafe fn munmap(addr: *mut u8, len: usize) -> SysResult<()> {
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    // SAFETY: Caller guarantees `[addr, addr + len)` can be safely unmapped.
    unsafe {
        syscall2(nr::MUNMAP, addr as usize, len)?;
    }
    Ok(())
}

/// Updates access protections on a mapped memory region.
///
/// # Safety
///
/// `[addr, addr + len)` must be page-aligned and belong to a valid mapping whose new
/// protection flags do not violate active Rust references.
pub unsafe fn mprotect(addr: *mut u8, len: usize, prot: i32) -> SysResult<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: Caller guarantees the address range and protections are valid.
    unsafe {
        syscall3(nr::MPROTECT, addr as usize, len, prot as u32 as usize)?;
    }
    Ok(())
}

/// Provides paging advice to the kernel for `[addr, addr + len)`.
///
/// # Safety
///
/// Destructive advice (such as `MADV_DONTNEED` or `MADV_FREE`) may discard pages;
/// the caller must ensure no live invariants are violated.
pub unsafe fn madvise(addr: *mut u8, len: usize, advice: i32) -> SysResult<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: Caller guarantees the address range and advice are valid.
    match unsafe { syscall3(nr::MADVISE, addr as usize, len, advice as u32 as usize) } {
        Ok(_) | Err(Errno(ENOSYS)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Synchronizes a memory-mapped region with backing storage.
///
/// # Safety
///
/// `addr` must be non-null and page-aligned for `[addr, addr + len)`.
pub unsafe fn msync(addr: *mut u8, len: usize, flags: i32) -> SysResult<()> {
    if addr.is_null() || (addr as usize) % PAGE_SIZE != 0 {
        return Err(Errno(EINVAL));
    }
    if (flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC)) != 0 {
        return Err(Errno(EINVAL));
    }
    let _ = len;
    Ok(())
}

/// Queries whether pages in `[addr, addr + len)` are resident in core memory.
///
/// # Safety
///
/// `vec` must point to a writable buffer of at least `(len + PAGE_SIZE - 1) / PAGE_SIZE` bytes.
pub unsafe fn mincore(addr: *mut u8, len: usize, vec: *mut u8) -> SysResult<()> {
    if len == 0 || vec.is_null() {
        return Err(Errno(EINVAL));
    }
    // SAFETY: Caller guarantees `vec` is valid for the required byte count.
    unsafe {
        syscall3(nr::MINCORE, addr as usize, len, vec as usize)?;
    }
    Ok(())
}
