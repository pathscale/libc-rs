//! `libc-rs` — pure-Rust `#![no_std]` native application runtime, compiler memory
//! intrinsics, and typed capability call substrate for unikernel environments.
//!
//! Unlike POSIX or Linux `libc` implementations, `libc-rs` carries no C code,
//! no thread-local `errno`, no `pthreads`, and no legacy POSIX surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// ABI contract version for the native unikernel application interface.
pub const ABI_VERSION: u64 = 1;
