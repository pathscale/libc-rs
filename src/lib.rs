//! `libc-rs` -- pure-Rust `#![no_std]` native application runtime, compiler memory
//! intrinsics, and syscall substrate for unikernel environments.
//!
//! Unlike POSIX or Linux `libc` implementations, `libc-rs` carries no C code,
//! no `pthreads`, and no legacy POSIX bloat.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod errno;
pub mod fd;
pub mod fs;
pub mod heap;
pub mod io;
pub mod math;
pub mod mem;
pub mod mm;
pub mod net;
pub mod poll;
pub mod process;
pub mod rand;
pub mod raw;
pub mod startup;
pub mod sync;
pub mod thread;
pub mod time;

pub use errno::{Errno, SysResult};
