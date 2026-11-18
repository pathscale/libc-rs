//! `libc-rs` — pure-Rust `#![no_std]` native application runtime, compiler memory
//! intrinsics, and typed capability call substrate for unikernel environments.
//!
//! Unlike POSIX or Linux `libc` implementations, `libc-rs` carries no C code,
//! no `pthreads`, and no legacy POSIX bloat.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod boot;
pub mod channel;
pub mod clock;
pub mod cpu;
pub mod entropy;
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
pub mod rt;
pub mod startup;
pub mod status;
pub mod sync;
pub mod thread;
pub mod time;
pub mod trap;

pub use status::{Result, Status};
pub use trap::{ABI_VERSION, DEFAULT_NAMESPACE, Op, check_version, exit};
