//! `libc-rs` — pure-Rust `#![no_std]` native application runtime, compiler memory
//! intrinsics, and typed capability call substrate for unikernel environments.
//!
//! Unlike POSIX or Linux `libc` implementations, `libc-rs` carries no C code,
//! no thread-local `errno`, no `pthreads`, and no legacy POSIX surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod boot;
pub mod channel;
pub mod clock;
pub mod cpu;
pub mod entropy;
pub mod heap;
pub mod mem;
pub mod rt;
pub mod status;
pub mod trap;

pub use status::{Result, Status};
pub use trap::{ABI_VERSION, DEFAULT_NAMESPACE, Op, check_version, exit};
