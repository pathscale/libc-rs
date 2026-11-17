# libc-rs

`libc-rs` is a pure-Rust `#![no_std]` native application runtime, compiler memory-intrinsic provider, and typed capability call substrate for unikernel environments.

It intentionally is **not** POSIX or Linux `libc`:

- **Zero C source or prebuilt C archives** (`no libc.a`, `no crt1.o`, `no libunwind.a`)
- **Typed `Result<T, Status>` capability calls** instead of global or thread-local `errno`
- **No `pthreads` or legacy POSIX surface**: explicit single-address-space and tickless unikernel primitives

## Modules

- `status`: `Status` error enum and `Result<T>` alias
- `trap`: `Op`, `DEFAULT_NAMESPACE`, `ABI_VERSION`, `invoke`, `invoke_ns`, `check_version`, `exit`
- `clock`: `Deadline`, `monotonic_ns`, `sleep_ns`, `ticks_to_ns`
- `cpu`: `CpuControlPage`, `CpuTopology`, `WorkerReservation`, `CpuControlTable`, `yield_cpu`
- `channel`: `Channel` (`CONTROL`, `BOOTSTRAP`, `SERVICE`), `listen`, `connect_control`, `accept`, `read`, `write`, `read_exact`, `write_all`, `close`, `retire_bootstrap`
- `entropy`: `fill`, `random_array`, `attest`
- `mem`: freestanding `copy_nonoverlapping_bytes`, `copy_bytes`, `set_bytes`, `compare_bytes`, `c_strlen`, `c_strnlen`, `memchr`, `memrchr`, `ct_eq`
- `heap`: `StaticHeap<BYTES>` segregated-freelist + bump allocator and `declare_global_heap!`
- `boot`: bounds-checked EL0 stack (`argc`, `argv`, `envp`, `auxv`) parser
- `rt`: `ElfNote24`, `declare_native_note!`, `native_entry!`

## Features

- `alloc` *(default)*: enables `extern crate alloc`
- `symbols`: exports freestanding C-ABI `memcpy`, `memmove`, `memset`, `memcmp`, `bcmp`, `strlen`, and `strnlen` symbols

## Target

Targets `aarch64-unknown-none` for unikernel EL0 binaries, while supporting host targets (`cargo test`) via deterministic mock trap hooks.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
