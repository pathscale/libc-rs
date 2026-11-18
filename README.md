# libc-rs

`libc-rs` is a pure-Rust `#![no_std]` native application runtime, compiler memory-intrinsic provider, and syscall substrate for unikernel environments.

It intentionally is **not** POSIX or Linux `libc`:

- **Zero C source or prebuilt C archives** (`no libc.a`, `no crt1.o`, `no libunwind.a`)
- **Typed `SysResult<T>` (`Errno`) syscall wrappers** without legacy POSIX bloat
- **No `pthreads`**: explicit single-address-space and tickless unikernel primitives

## Modules

- `errno`: `Errno` error code newtype, `SysResult<T>` alias, and standard error constants
- `raw`: AArch64 `svc #0` raw syscall dispatch (`nr`, `decode_raw`, `syscall0`..`syscall6`) and EL0 hardware entry/thread/restorer stubs (`raw` is the sole inline-asm boundary)
- `fd`: `RawFd`, `BorrowedFd`, `OwnedFd`, and `*at` flags
- `mm`: `mmap`, `mmap_anonymous`, `munmap`, `mprotect`, `madvise`, `msync`, `mincore`
- `io`: `read`, `write`, `pread`, `pwrite`, `writev`, `lseek`, `close`, `dup`, `dup2`, `dup3`, `pipe2`, `fcntl`, `ioctl`, `flock`
- `fs`: `Stat`, `openat`, `fstat`, `fstatat`, `mkdirat`, `unlinkat`, `renameat`, `linkat`, `readlinkat`, `getcwd`, `chdir`, `ftruncate`, `fchmod`, `fsync`, `getdents64`
- `net`: `SockAddrUn`, `SockAddrVm`, `socket`, `socketpair`, `bind_unix`, `bind_vsock`, `listen`, `accept4`, `connect_unix`, `connect_vsock`, `setsockopt`, `getsockopt`, `shutdown`
- `poll`: `PollFd`, `EpollEvent`, `ppoll`, `epoll_create1`, `epoll_ctl`, `epoll_pwait2`, `eventfd2`
- `process`: `exit_thread`, `exit_group`, `abort`, `getpid`, `gettid`, `getuid`, `geteuid`, `getgid`, `getegid`, `setpgid`, `setsid`, `umask`, `fork`, `execve_raw`, `waitpid`, `waitpid_opt`, `kill`, `sigaction`, `getrlimit`, `setrlimit`, `getrusage`, `sched_yield`
- `sync`: `FutexMutex`, `FutexMutexGuard`, `futex_wait`, `futex_wake_one`, `futex_wake_all`
- `thread`: `ThreadHandle`, `spawn_thread`, `current_thread_id`, `errno_cell`, `tls_key_create`, `tls_key_delete`, `tls_get`, `tls_set`, `run_current_thread_tls_destructors`
- `time`: `Timespec`, `Timeval`, `clock_gettime`, `clock_settime`, `nanosleep`
- `rand`: `getrandom`, `fill_random`
- `startup`: `init_from_stack`, `aux_summary`, `getauxval`, `page_size`, `args_vec`, `getenv_vec`, `setenv_bytes`, `environ_vec`, `process_entry!`, `declare_native_note!`
- `math`: freestanding `floor`, `ceil`, `trunc`, `ln`, `powf` (pure-Rust IEEE-754 rounding and transcendentals)
- `heap`: `MmapHeap` (`GLOBAL_MMAP_HEAP`, `c_malloc`, `c_calloc`, `c_realloc`, `c_free`, `c_posix_memalign`)
- `mem`: freestanding `copy_nonoverlapping_bytes`, `copy_bytes`, `set_bytes`, `compare_bytes`, `c_strlen`, `c_strnlen`, `memchr`, `memrchr`, `ct_eq`

## Features

- `alloc` *(default)*: enables `extern crate alloc`
- `symbols`: exports freestanding C-ABI `memcpy`, `memmove`, `memset`, `memcmp`, `bcmp`, `strlen`, and `strnlen` symbols

## Target

Targets `aarch64-unknown-none` for unikernel EL0 binaries, while supporting host targets (`cargo test`) via deterministic mock syscall hooks.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
