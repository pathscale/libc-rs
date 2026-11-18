//! File descriptor types (`RawFd`, `BorrowedFd`, `OwnedFd`) and `*at` flags.

use core::marker::PhantomData;
use core::mem::ManuallyDrop;

/// Raw file descriptor integer.
pub type RawFd = i32;

/// Special `dirfd` value indicating the current working directory.
pub const AT_FDCWD: RawFd = -100;
/// Do not follow symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// Remove directory instead of unlinking file.
pub const AT_REMOVEDIR: i32 = 0x200;
/// Operate on the `dirfd` itself when path is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// Borrowed file descriptor tied to lifetime `'fd`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct BorrowedFd<'fd> {
    fd: RawFd,
    _lt: PhantomData<&'fd ()>,
}

impl<'fd> BorrowedFd<'fd> {
    /// Wraps a raw file descriptor in a [`BorrowedFd`] without taking ownership.
    ///
    /// # Safety
    ///
    /// `fd` must remain an open, valid file descriptor for the duration of `'fd`.
    #[must_use]
    pub const unsafe fn borrow_raw(fd: RawFd) -> Self {
        Self {
            fd,
            _lt: PhantomData,
        }
    }

    /// Returns the underlying [`RawFd`].
    #[must_use]
    pub const fn as_raw_fd(self) -> RawFd {
        self.fd
    }
}

/// Owned file descriptor that closes the underlying descriptor on drop.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    /// Takes ownership of a raw file descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be an open, valid file descriptor uniquely owned by the caller.
    #[must_use]
    pub const unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Returns the underlying [`RawFd`] without releasing ownership.
    #[must_use]
    pub const fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Consumes this [`OwnedFd`], returning the underlying [`RawFd`] without closing it.
    #[must_use]
    pub const fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        let _ = ManuallyDrop::new(self);
        fd
    }

    /// Borrows this descriptor as a [`BorrowedFd`].
    #[must_use]
    pub const fn as_fd(&self) -> BorrowedFd<'_> {
        BorrowedFd {
            fd: self.fd,
            _lt: PhantomData,
        }
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = crate::io::close(self.fd);
    }
}
