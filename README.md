# libc-rs

`libc-rs` is a pure-Rust `#![no_std]` native application runtime, compiler memory-intrinsic provider, and typed capability call substrate for unikernel environments.

It intentionally is **not** POSIX or Linux `libc`:

- **Zero C source or prebuilt C archives** (`no libc.a`, `no crt1.o`, `no libunwind.a`)
- **Typed `Result<T, Status>` capability calls** instead of global or thread-local `errno`
- **No `pthreads` or legacy POSIX surface**: explicit single-address-space and tickless unikernel primitives

## Modules

### Unikernel Host Syscall & Runtime Surface

- `errno`: `Errno` error code newtype, `SysResult<T>` alias, and standard error constants
- `raw`: AArch64 `svc #0` raw syscall dispatch (`nr`, `decode_raw`, `syscall0`..`syscall6`)
- `fd`: `RawFd`, `BorrowedFd`, `OwnedFd`, and `*at` flags
- `mm`: `mmap`, `mmap_anonymous`, `munmap`, `mprotect`, `madvise`, `msync`, `mincore`
- `io`: `read`, `write`, `pread`, `pwrite`, `readv`, `writev`, `lseek`, `close`, `dup`, `dup2`, `dup3`, `pipe2`, `fcntl`, `ioctl`, `flock`
- `fs`: `Stat`, `openat`, `fstat`, `fstatat`, `mkdirat`, `unlinkat`, `renameat`, `symlinkat`, `readlinkat`, `getcwd`, `chdir`, `ftruncate`, `fsync`, `fdatasync`, `getdents64`, `memfd_create`
- `net`: `SockAddrIn`, `SockAddrUn`, `SockAddrVm`, `socket`, `socketpair`, `bind`, `listen`, `accept4`, `connect`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `shutdown`
- `poll`: `PollFd`, `EpollEvent`, `ppoll`, `epoll_create1`, `epoll_ctl`, `epoll_pwait2`, `eventfd2`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime`
- `process`: `exit_thread`, `exit_group`, `abort`, `getpid`, `getppid`, `gettid`, `getuid`, `geteuid`, `getgid`, `getegid`, `fork`, `execve_raw`, `execveat_raw`, `waitpid`, `kill`, `sigaction`, `getrlimit`, `setrlimit`, `getrusage`, `sched_yield`
- `sync`: `FutexMutex`, `FutexCondvar`, `FutexOnce`, `futex_wait`, `futex_wake_one`, `futex_wake_all`
- `thread`: `ThreadHandle`, `spawn_thread`, `current_thread_id`, `errno_cell`, `tls_key_create`, `tls_key_delete`, `tls_get`, `tls_set`, `run_current_thread_tls_destructors`
- `time`: `Timespec`, `Timeval`, `clock_gettime`, `clock_settime`, `nanosleep`
- `rand`: `getrandom`, `fill_random`
- `startup`: `init_from_stack`, `aux_summary`, `getauxval`, `page_size`, `args_vec`, `getenv_vec`, `setenv_bytes`, `environ_vec`, `process_entry!`
- `math`: freestanding `floor`, `ceil`, `trunc`, `sqrt`, `ln`, `exp`, `powf` (hardware AArch64 `frint*`/`fsqrt` + pure-Rust IEEE-754 transcendentals)
- `heap`: `MmapHeap` (`GLOBAL_MMAP_HEAP`, `c_malloc`, `c_calloc`, `c_realloc`, `c_free`, `c_posix_memalign`) and `StaticHeap<BYTES>` (`declare_global_heap!`)
- `mem`: freestanding `copy_nonoverlapping_bytes`, `copy_bytes`, `set_bytes`, `compare_bytes`, `c_strlen`, `c_strnlen`, `memchr`, `memrchr`, `ct_eq`

### Enclave Capability Surface

- `status`: `Status` error enum and `Result<T>` alias
- `trap`: `Op`, `DEFAULT_NAMESPACE`, `ABI_VERSION`, `invoke`, `invoke_ns`, `check_version`, `exit`
- `clock`: `Deadline`, `monotonic_ns`, `sleep_ns`, `ticks_to_ns`
- `cpu`: `CpuControlPage`, `CpuTopology`, `WorkerReservation`, `CpuControlTable`, `yield_cpu`
- `channel`: `Channel` (`CONTROL`, `BOOTSTRAP`, `SERVICE`), `listen`, `connect_control`, `accept`, `read`, `write`, `read_exact`, `write_all`, `close`, `retire_bootstrap`
- `entropy`: `fill`, `random_array`, `attest`
- `boot`: bounds-checked EL0 stack (`argc`, `argv`, `envp`, `auxv`) parser
- `rt`: `ElfNote24`, `declare_native_note!`, `native_entry!`

## Features

- `alloc` *(default)*: enables `extern crate alloc`
- `symbols`: exports freestanding C-ABI `memcpy`, `memmove`, `memset`, `memcmp`, `bcmp`, `strlen`, and `strnlen` symbols

## Target

Targets `aarch64-unknown-none` for unikernel EL0 binaries, while supporting host targets (`cargo test`) via deterministic mock trap hooks.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
