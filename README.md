# libc-rs

`libc-rs` is a pure-Rust `#![no_std]` native runtime, compiler memory-intrinsic provider, and typed capability call substrate built specifically for unikernel execution environments.

It intentionally is **not** POSIX or Linux compatible:

- **Zero C source or prebuilt C archives** (`no libc.a`, `no crt1.o`, `no libunwind.a`)
- **Typed `Result<T, Status>` capability calls** instead of global/thread-local `errno`
- **No `pthreads` or POSIX legacy surface**: single-address-space and explicit tickless core / event primitives tailored directly to unikernel execution

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
