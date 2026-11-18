//! Filesystem metadata, path resolution, and directory iteration.

use core::mem::{MaybeUninit, offset_of, size_of};

use crate::errno::{EINVAL, ENAMETOOLONG, Errno, SysResult};
use crate::fd::{AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_NOFOLLOW, RawFd};
use crate::raw::{nr, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5};

pub const PATH_MAX: usize = 4096;

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_ACCMODE: i32 = 3;

pub const O_CREAT: i32 = 0x40;
pub const O_EXCL: i32 = 0x80;
pub const O_NOCTTY: i32 = 0x100;
pub const O_TRUNC: i32 = 0x200;
pub const O_APPEND: i32 = 0x400;
pub const O_NONBLOCK: i32 = 0x800;
pub const O_DSYNC: i32 = 0x1000;
pub const O_DIRECT: i32 = 0x4000;
pub const O_LARGEFILE: i32 = 0x8000;
pub const O_DIRECTORY: i32 = 0x10000;
pub const O_NOFOLLOW: i32 = 0x20000;
pub const O_NOATIME: i32 = 0x40000;
pub const O_CLOEXEC: i32 = 0x80000;
pub const O_PATH: i32 = 0x200000;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub const F_OK: i32 = 0;
pub const X_OK: i32 = 1;
pub const W_OK: i32 = 2;
pub const R_OK: i32 = 4;

pub const S_IFMT: u32 = 0o17_0000;
pub const S_IFSOCK: u32 = 0o14_0000;
pub const S_IFLNK: u32 = 0o12_0000;
pub const S_IFREG: u32 = 0o10_0000;
pub const S_IFBLK: u32 = 0o06_0000;
pub const S_IFDIR: u32 = 0o04_0000;
pub const S_IFCHR: u32 = 0o02_0000;
pub const S_IFIFO: u32 = 0o01_0000;

pub const LOCK_SH: i32 = 1;
pub const LOCK_EX: i32 = 2;
pub const LOCK_NB: i32 = 4;
pub const LOCK_UN: i32 = 8;

pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_SYNCHRONOUS: u64 = 16;
pub const MS_REMOUNT: u64 = 32;
pub const MS_NOATIME: u64 = 1024;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;

pub const MNT_FORCE: i32 = 1;
pub const MNT_DETACH: i32 = 2;
pub const MNT_EXPIRE: i32 = 4;
pub const UMOUNT_NOFOLLOW: i32 = 8;

/// 128-byte AArch64 file metadata structure (`struct stat`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub unused: [u32; 2],
}

const _: () = {
    assert!(size_of::<Stat>() == 128);
    assert!(offset_of!(Stat, st_size) == 48);
    assert!(offset_of!(Stat, st_atime) == 72);
};

/// Invokes `f` with a pointer to a NUL-terminated path buffer.
///
/// - Rejects empty paths or paths with interior NUL bytes with `EINVAL`.
/// - If `path` already ends with a single trailing NUL (`b'\0'`) and has length `<= PATH_MAX`,
///   passes `path.as_ptr()` directly without copying.
/// - Otherwise copies `path` into a stack `[0u8; PATH_MAX]` buffer and appends `0`.
pub fn with_c_path<R>(path: &[u8], f: impl FnOnce(*const u8) -> SysResult<R>) -> SysResult<R> {
    if path.is_empty() {
        return Err(Errno(EINVAL));
    }
    if let Some((&last, prefix)) = path.split_last() {
        if last == 0 {
            if prefix.is_empty() || prefix.contains(&0) {
                return Err(Errno(EINVAL));
            }
            if path.len() > PATH_MAX {
                return Err(Errno(ENAMETOOLONG));
            }
            return f(path.as_ptr());
        }
    }
    if path.contains(&0) {
        return Err(Errno(EINVAL));
    }
    if path.len() >= PATH_MAX {
        return Err(Errno(ENAMETOOLONG));
    }
    if path.len() < 256 {
        let mut buf = [0u8; 256];
        buf[..path.len()].copy_from_slice(path);
        return f(buf.as_ptr());
    }
    with_c_path_long(path, f)
}

#[cold]
fn with_c_path_long<R>(path: &[u8], f: impl FnOnce(*const u8) -> SysResult<R>) -> SysResult<R> {
    let mut buf = [0u8; PATH_MAX];
    buf[..path.len()].copy_from_slice(path);
    f(buf.as_ptr())
}

/// Converts a NUL-terminated C string pointer bounded by [`PATH_MAX`] into a byte slice.
///
/// # Safety
///
/// `ptr` must be non-null and point to a valid NUL-terminated byte sequence within `PATH_MAX` bytes.
pub unsafe fn cstr_slice<'a>(ptr: *const u8) -> SysResult<&'a [u8]> {
    if ptr.is_null() {
        return Err(Errno(EINVAL));
    }
    let mut len = 0usize;
    while len < PATH_MAX {
        // SAFETY: Caller guarantees `ptr` is readable up to the terminating NUL within `PATH_MAX`.
        let b = unsafe { *ptr.add(len) };
        if b == 0 {
            // SAFETY: `[ptr, ptr + len)` was verified to be initialized bytes before NUL.
            return Ok(unsafe { core::slice::from_raw_parts(ptr, len) });
        }
        len += 1;
    }
    Err(Errno(ENAMETOOLONG))
}

/// Opens a file relative to `dirfd`.
pub fn openat(dirfd: RawFd, path: &[u8], flags: i32, mode: u32) -> SysResult<RawFd> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` points to a valid NUL-terminated buffer.
        let raw = unsafe {
            syscall4(
                nr::OPENAT,
                dirfd as usize,
                c_path as usize,
                flags as u32 as usize,
                mode as usize,
            )?
        };
        Ok(raw as RawFd)
    })
}

/// Opens a file relative to the current working directory (`AT_FDCWD`).
pub fn open(path: &[u8], flags: i32, mode: u32) -> SysResult<RawFd> {
    openat(AT_FDCWD, path, flags, mode)
}

/// Queries file metadata relative to `dirfd`.
pub fn statat(dirfd: RawFd, path: &[u8], flags: i32) -> SysResult<Stat> {
    with_c_path(path, |c_path| {
        let mut st = MaybeUninit::<Stat>::zeroed();
        // SAFETY: `c_path` is a valid C string and `st` is a writable 128-byte `Stat` buffer.
        unsafe {
            syscall4(
                nr::NEWFSTATAT,
                dirfd as usize,
                c_path as usize,
                st.as_mut_ptr() as usize,
                flags as u32 as usize,
            )?;
            Ok(st.assume_init())
        }
    })
}

/// Queries file metadata (following symbolic links).
pub fn stat(path: &[u8]) -> SysResult<Stat> {
    statat(AT_FDCWD, path, 0)
}

/// Queries file metadata without following symbolic links (`AT_SYMLINK_NOFOLLOW`).
pub fn lstat(path: &[u8]) -> SysResult<Stat> {
    statat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)
}

/// Queries file metadata for an open file descriptor `fd`.
pub fn fstat(fd: RawFd) -> SysResult<Stat> {
    let mut st = MaybeUninit::<Stat>::zeroed();
    // SAFETY: `st` is a writable 128-byte `Stat` buffer.
    unsafe {
        syscall2(nr::FSTAT, fd as usize, st.as_mut_ptr() as usize)?;
        Ok(st.assume_init())
    }
}

/// Repositions the read/write file offset of `fd`.
pub fn lseek(fd: RawFd, offset: i64, whence: i32) -> SysResult<i64> {
    // SAFETY: `LSEEK` takes integer arguments only.
    let raw = unsafe {
        syscall3(
            nr::LSEEK,
            fd as usize,
            offset as usize,
            whence as u32 as usize,
        )?
    };
    Ok(raw as i64)
}

/// Truncates or extends a file referred to by `fd` to `length` bytes.
pub fn ftruncate(fd: RawFd, length: i64) -> SysResult<()> {
    // SAFETY: `FTRUNCATE` takes a file descriptor and byte length.
    unsafe {
        syscall2(nr::FTRUNCATE, fd as usize, length as usize)?;
    }
    Ok(())
}

/// Synchronizes all modified in-core data and metadata of `fd` to storage.
pub fn fsync(fd: RawFd) -> SysResult<()> {
    // SAFETY: `FSYNC` takes a single file descriptor.
    unsafe {
        syscall1(nr::FSYNC, fd as usize)?;
    }
    Ok(())
}

/// Changes permissions of an open file descriptor `fd`.
pub fn fchmod(fd: RawFd, mode: u32) -> SysResult<()> {
    // SAFETY: `FCHMOD` takes a file descriptor and mode bits.
    unsafe {
        syscall2(nr::FCHMOD, fd as usize, mode as usize)?;
    }
    Ok(())
}

/// Creates a directory relative to `dirfd`.
pub fn mkdirat(dirfd: RawFd, path: &[u8], mode: u32) -> SysResult<()> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid NUL-terminated path.
        unsafe {
            syscall3(nr::MKDIRAT, dirfd as usize, c_path as usize, mode as usize)?;
        }
        Ok(())
    })
}

/// Creates a directory relative to the current working directory.
pub fn mkdir(path: &[u8], mode: u32) -> SysResult<()> {
    mkdirat(AT_FDCWD, path, mode)
}

/// Unlinks a file or directory relative to `dirfd`.
pub fn unlinkat(dirfd: RawFd, path: &[u8], flags: i32) -> SysResult<()> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid NUL-terminated path.
        unsafe {
            syscall3(
                nr::UNLINKAT,
                dirfd as usize,
                c_path as usize,
                flags as u32 as usize,
            )?;
        }
        Ok(())
    })
}

/// Removes a directory entry relative to the current working directory.
pub fn unlink(path: &[u8]) -> SysResult<()> {
    unlinkat(AT_FDCWD, path, 0)
}

/// Removes an empty directory relative to the current working directory.
pub fn rmdir(path: &[u8]) -> SysResult<()> {
    unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
}

/// Renames a filesystem entry between `olddir` and `newdir`.
pub fn renameat(olddir: RawFd, oldpath: &[u8], newdir: RawFd, newpath: &[u8]) -> SysResult<()> {
    with_c_path(oldpath, |c_old| {
        with_c_path(newpath, |c_new| {
            // SAFETY: Both `c_old` and `c_new` are valid NUL-terminated paths.
            unsafe {
                syscall4(
                    nr::RENAMEAT,
                    olddir as usize,
                    c_old as usize,
                    newdir as usize,
                    c_new as usize,
                )?;
            }
            Ok(())
        })
    })
}

/// Renames a filesystem entry relative to the current working directory.
pub fn rename(oldpath: &[u8], newpath: &[u8]) -> SysResult<()> {
    renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

/// Creates a hard link between `olddir`/`oldpath` and `newdir`/`newpath`.
pub fn linkat(
    olddir: RawFd,
    oldpath: &[u8],
    newdir: RawFd,
    newpath: &[u8],
    flags: i32,
) -> SysResult<()> {
    with_c_path(oldpath, |c_old| {
        with_c_path(newpath, |c_new| {
            // SAFETY: Both `c_old` and `c_new` are valid NUL-terminated paths.
            unsafe {
                syscall5(
                    nr::LINKAT,
                    olddir as usize,
                    c_old as usize,
                    newdir as usize,
                    c_new as usize,
                    flags as u32 as usize,
                )?;
            }
            Ok(())
        })
    })
}

/// Creates a hard link relative to the current working directory.
pub fn link(oldpath: &[u8], newpath: &[u8]) -> SysResult<()> {
    linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

/// Reads the target of a symbolic link relative to `dirfd` into `out`.
pub fn readlinkat<'a>(dirfd: RawFd, path: &[u8], out: &'a mut [u8]) -> SysResult<&'a [u8]> {
    if out.is_empty() {
        return Err(Errno(EINVAL));
    }
    let n = with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid C string and `out` is a writable byte buffer.
        unsafe {
            syscall4(
                nr::READLINKAT,
                dirfd as usize,
                c_path as usize,
                out.as_mut_ptr() as usize,
                out.len(),
            )
        }
    })?;
    let len = n.min(out.len());
    Ok(&out[..len])
}

/// Reads the target of a symbolic link relative to the current working directory into `out`.
pub fn readlink<'a>(path: &[u8], out: &'a mut [u8]) -> SysResult<&'a [u8]> {
    readlinkat(AT_FDCWD, path, out)
}

/// Checks accessibility of `path` relative to `dirfd`.
pub fn faccessat(dirfd: RawFd, path: &[u8], mode: i32, flags: i32) -> SysResult<()> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid NUL-terminated path.
        unsafe {
            syscall4(
                nr::FACCESSAT,
                dirfd as usize,
                c_path as usize,
                mode as u32 as usize,
                flags as u32 as usize,
            )?;
        }
        Ok(())
    })
}

/// Checks accessibility of `path` relative to the current working directory.
pub fn access(path: &[u8], mode: i32) -> SysResult<()> {
    faccessat(AT_FDCWD, path, mode, 0)
}

/// Applies or removes an advisory lock on open file `fd`.
pub fn flock(fd: RawFd, operation: i32) -> SysResult<()> {
    // SAFETY: `FLOCK` takes a file descriptor and integer operation flags.
    unsafe {
        syscall2(nr::FLOCK, fd as usize, operation as u32 as usize)?;
    }
    Ok(())
}

/// Queries the current working directory into `out`, returning the slice without the trailing NUL.
pub fn getcwd(out: &mut [u8]) -> SysResult<&[u8]> {
    if out.is_empty() {
        return Err(Errno(EINVAL));
    }
    // SAFETY: `out` is a writable slice of `out.len()` bytes.
    let n = unsafe { syscall2(nr::GETCWD, out.as_mut_ptr() as usize, out.len())? };
    let used = n.min(out.len());
    let slice = &out[..used];
    if let Some(pos) = slice.iter().position(|&b| b == 0) {
        Ok(&slice[..pos])
    } else {
        Ok(slice)
    }
}

/// Changes the current working directory to `path`.
pub fn chdir(path: &[u8]) -> SysResult<()> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid NUL-terminated path.
        unsafe {
            syscall1(nr::CHDIR, c_path as usize)?;
        }
        Ok(())
    })
}

fn with_opt_c_path<R>(
    opt_path: Option<&[u8]>,
    f: impl FnOnce(*const u8) -> SysResult<R>,
) -> SysResult<R> {
    match opt_path {
        Some(path) => with_c_path(path, f),
        None => f(core::ptr::null()),
    }
}

/// Mounts a filesystem at `target`.
pub fn mount(
    source: Option<&[u8]>,
    target: &[u8],
    fstype: Option<&[u8]>,
    flags: u64,
    data: Option<&[u8]>,
) -> SysResult<()> {
    with_opt_c_path(source, |c_src| {
        with_c_path(target, |c_target| {
            with_opt_c_path(fstype, |c_fstype| {
                with_opt_c_path(data, |c_data| {
                    // SAFETY: All non-null pointers are valid NUL-terminated stack/caller buffers.
                    unsafe {
                        syscall5(
                            nr::MOUNT,
                            c_src as usize,
                            c_target as usize,
                            c_fstype as usize,
                            flags as usize,
                            c_data as usize,
                        )?;
                    }
                    Ok(())
                })
            })
        })
    })
}

/// Unmounts the filesystem mounted at `target` with `flags` (`MNT_FORCE`, `MNT_DETACH`, etc.).
pub fn umount2(target: &[u8], flags: i32) -> SysResult<()> {
    with_c_path(target, |c_target| {
        // SAFETY: `c_target` is a valid NUL-terminated path.
        unsafe {
            syscall2(nr::UMOUNT2, c_target as usize, flags as u32 as usize)?;
        }
        Ok(())
    })
}

/// Changes the root directory of the calling process to `path`.
pub fn chroot(path: &[u8]) -> SysResult<()> {
    with_c_path(path, |c_path| {
        // SAFETY: `c_path` is a valid NUL-terminated path.
        unsafe {
            syscall1(nr::CHROOT, c_path as usize)?;
        }
        Ok(())
    })
}

/// Commits all filesystem caches to disk (`sync`).
pub fn sync_all_filesystems() {
    // SAFETY: `SYNC` takes no arguments and always succeeds.
    let _ = unsafe { syscall0(nr::SYNC) };
}

/// Reads raw `linux_dirent64` entries from directory `fd` into `buf`.
pub fn getdents64(fd: RawFd, buf: &mut [u8]) -> SysResult<usize> {
    // SAFETY: `buf` is a valid writable byte slice.
    unsafe {
        syscall3(
            nr::GETDENTS64,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    }
}

/// Borrowed view of a single `linux_dirent64` directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntryRef<'a> {
    pub ino: u64,
    pub off: i64,
    pub file_type: u8,
    pub name: &'a [u8],
}

/// Iterator over packed `linux_dirent64` records in a byte slice.
#[derive(Clone, Debug)]
pub struct DirentIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

/// Parses packed `linux_dirent64` records from the `filled` prefix returned by [`getdents64`].
#[must_use]
pub fn parse_dirents(filled: &[u8]) -> DirentIter<'_> {
    DirentIter {
        buf: filled,
        offset: 0,
    }
}

impl<'a> Iterator for DirentIter<'a> {
    type Item = DirEntryRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let rem = &self.buf[self.offset..];
        if rem.len() < 19 {
            self.offset = self.buf.len();
            return None;
        }
        let ino = u64::from_ne_bytes([
            rem[0], rem[1], rem[2], rem[3], rem[4], rem[5], rem[6], rem[7],
        ]);
        let off = i64::from_ne_bytes([
            rem[8], rem[9], rem[10], rem[11], rem[12], rem[13], rem[14], rem[15],
        ]);
        let reclen = u16::from_ne_bytes([rem[16], rem[17]]) as usize;
        if reclen < 19 || reclen > rem.len() {
            self.offset = self.buf.len();
            return None;
        }
        let file_type = rem[18];
        let name_region = &rem[19..reclen];
        let name_len = name_region
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_region.len());
        self.offset += reclen;
        Some(DirEntryRef {
            ino,
            off,
            file_type,
            name: &name_region[..name_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::with_mock_syscall;

    #[test]
    fn stat_layout_matches_aarch64_abi() {
        assert_eq!(size_of::<Stat>(), 128);
        assert_eq!(offset_of!(Stat, st_dev), 0);
        assert_eq!(offset_of!(Stat, st_ino), 8);
        assert_eq!(offset_of!(Stat, st_mode), 16);
        assert_eq!(offset_of!(Stat, st_nlink), 20);
        assert_eq!(offset_of!(Stat, st_uid), 24);
        assert_eq!(offset_of!(Stat, st_gid), 28);
        assert_eq!(offset_of!(Stat, st_rdev), 32);
        assert_eq!(offset_of!(Stat, st_size), 48);
        assert_eq!(offset_of!(Stat, st_blksize), 56);
        assert_eq!(offset_of!(Stat, st_blocks), 64);
        assert_eq!(offset_of!(Stat, st_atime), 72);
        assert_eq!(offset_of!(Stat, st_mtime), 88);
        assert_eq!(offset_of!(Stat, st_ctime), 104);
    }

    #[test]
    fn with_c_path_validates_and_avoids_copy_when_nul_terminated() {
        assert_eq!(with_c_path(b"", |_| Ok(())), Err(Errno(EINVAL)));
        assert_eq!(with_c_path(b"\0", |_| Ok(())), Err(Errno(EINVAL)));
        assert_eq!(with_c_path(b"a\0b", |_| Ok(())), Err(Errno(EINVAL)));
        assert_eq!(with_c_path(b"a\0b\0", |_| Ok(())), Err(Errno(EINVAL)));

        let pre_nul = b"/etc/hosts\0";
        let ptr_seen = with_c_path(pre_nul, Ok).unwrap();
        assert_eq!(ptr_seen, pre_nul.as_ptr());

        let slice_no_nul = b"/etc/hosts";
        with_c_path(slice_no_nul, |p| {
            assert_ne!(p, slice_no_nul.as_ptr());
            let decoded = unsafe { cstr_slice(p)? };
            assert_eq!(decoded, slice_no_nul);
            Ok(())
        })
        .unwrap();

        let too_long = [b'x'; PATH_MAX];
        assert_eq!(with_c_path(&too_long, |_| Ok(())), Err(Errno(ENAMETOOLONG)));
    }

    #[test]
    fn parse_dirents_decodes_records() {
        let mut buf = [0u8; 48];
        // Record 1: ino=10, off=24, reclen=24, type=4 (DT_DIR), name="."
        buf[0..8].copy_from_slice(&10u64.to_ne_bytes());
        buf[8..16].copy_from_slice(&24i64.to_ne_bytes());
        buf[16..18].copy_from_slice(&24u16.to_ne_bytes());
        buf[18] = 4;
        buf[19] = b'.';
        buf[20] = 0;

        // Record 2: ino=42, off=48, reclen=24, type=8 (DT_REG), name="abc"
        buf[24..32].copy_from_slice(&42u64.to_ne_bytes());
        buf[32..40].copy_from_slice(&48i64.to_ne_bytes());
        buf[40..42].copy_from_slice(&24u16.to_ne_bytes());
        buf[42] = 8;
        buf[43..46].copy_from_slice(b"abc");
        buf[46] = 0;

        let mut iter = parse_dirents(&buf);
        let first = iter.next().unwrap();
        assert_eq!(
            first,
            DirEntryRef {
                ino: 10,
                off: 24,
                file_type: 4,
                name: b".",
            }
        );
        let second = iter.next().unwrap();
        assert_eq!(
            second,
            DirEntryRef {
                ino: 42,
                off: 48,
                file_type: 8,
                name: b"abc",
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn getcwd_strips_trailing_nul() {
        with_mock_syscall(
            |nr, args| {
                assert_eq!(nr, nr::GETCWD);
                let out_ptr = args[0] as *mut u8;
                let data = b"/work\0";
                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
                }
                Ok(data.len())
            },
            || {
                let mut buf = [0u8; 32];
                let path = getcwd(&mut buf).unwrap();
                assert_eq!(path, b"/work");
            },
        );
    }
}
