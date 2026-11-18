//! Process startup state (`argc`, `argv`, `environ`, `auxv`) and `_start` entry macro.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::boot::{
    AT_ENTRY, AT_EXECFN, AT_HWCAP, AT_HWCAP2, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_RANDOM,
    AuxSummary, parse_stack_words,
};
#[cfg(feature = "alloc")]
use crate::errno::{EINVAL, Errno, SysResult};
#[cfg(feature = "alloc")]
use crate::mem::{c_strlen, memchr};
#[cfg(feature = "alloc")]
use crate::sync::FutexMutex;

/// Maximum number of `u64` stack words inspected by [`init_from_stack`].
pub const MAX_STACK_WORDS: usize = 4096;

/// Default page size when `AT_PAGESZ` is absent or startup state has not been initialized.
pub const DEFAULT_PAGE_SIZE: usize = 4096;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static ARGC: AtomicUsize = AtomicUsize::new(0);
static ARGV_PTR: AtomicUsize = AtomicUsize::new(0);
static ENVP_PTR: AtomicUsize = AtomicUsize::new(0);

static AUX_PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);
static AUX_HWCAP: AtomicU64 = AtomicU64::new(0);
static AUX_HWCAP2: AtomicU64 = AtomicU64::new(0);
static AUX_PHDR: AtomicU64 = AtomicU64::new(0);
static AUX_PHENT: AtomicU64 = AtomicU64::new(0);
static AUX_PHNUM: AtomicU64 = AtomicU64::new(0);
static AUX_ENTRY: AtomicU64 = AtomicU64::new(0);
static AUX_RANDOM: AtomicU64 = AtomicU64::new(0);
static AUX_EXECFN: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "alloc")]
type EnvPairs = Vec<(Vec<u8>, Vec<u8>)>;

#[cfg(feature = "alloc")]
static ENV_TABLE: FutexMutex<Option<EnvPairs>> = FutexMutex::new(None);

/// Parses the initial EL0 process stack at `sp` (`argc`, `argv`, `envp`, `auxv`) and records
/// process startup state.
///
/// # Safety
///
/// `sp` must be null or point to a valid EL0 initial stack image readable up to the terminating
/// `AT_NULL` auxiliary vector entry (bounded by [`MAX_STACK_WORDS`] words), and string pointers
/// in `argv` / `envp` must remain valid NUL-terminated strings while accessed.
pub unsafe fn init_from_stack(sp: *const u64) {
    // SAFETY: Caller guarantees `sp` is null or valid for `parse_stack_words`.
    if let Some((argc, argv, envp, aux)) = unsafe { parse_stack_words(sp, MAX_STACK_WORDS) } {
        ARGC.store(argc, Ordering::Relaxed);
        ARGV_PTR.store(argv as usize, Ordering::Relaxed);
        ENVP_PTR.store(envp as usize, Ordering::Relaxed);

        AUX_PAGE_SIZE.store(aux.page_size, Ordering::Relaxed);
        AUX_HWCAP.store(aux.hwcap, Ordering::Relaxed);
        AUX_HWCAP2.store(aux.hwcap2, Ordering::Relaxed);
        AUX_PHDR.store(aux.phdr_addr, Ordering::Relaxed);
        AUX_PHENT.store(aux.phent_size, Ordering::Relaxed);
        AUX_PHNUM.store(aux.phnum, Ordering::Relaxed);
        AUX_ENTRY.store(aux.entry_addr, Ordering::Relaxed);
        AUX_RANDOM.store(aux.random_addr, Ordering::Relaxed);
        AUX_EXECFN.store(aux.execfn_addr, Ordering::Relaxed);

        #[cfg(feature = "alloc")]
        {
            *ENV_TABLE.lock() = None;
        }

        INITIALIZED.store(true, Ordering::Release);
    }
}

/// Returns the decoded [`AuxSummary`] captured at process startup.
#[must_use]
pub fn aux_summary() -> AuxSummary {
    if !INITIALIZED.load(Ordering::Acquire) {
        return AuxSummary {
            page_size: DEFAULT_PAGE_SIZE,
            ..AuxSummary::default()
        };
    }
    let page_sz = AUX_PAGE_SIZE.load(Ordering::Relaxed);
    AuxSummary {
        page_size: if page_sz == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            page_sz
        },
        hwcap: AUX_HWCAP.load(Ordering::Relaxed),
        hwcap2: AUX_HWCAP2.load(Ordering::Relaxed),
        phdr_addr: AUX_PHDR.load(Ordering::Relaxed),
        phent_size: AUX_PHENT.load(Ordering::Relaxed),
        phnum: AUX_PHNUM.load(Ordering::Relaxed),
        entry_addr: AUX_ENTRY.load(Ordering::Relaxed),
        random_addr: AUX_RANDOM.load(Ordering::Relaxed),
        execfn_addr: AUX_EXECFN.load(Ordering::Relaxed),
    }
}

/// Looks up a value from the auxiliary vector by tag `key`.
///
/// `AT_PAGESZ` defaults to `4096` even if [`init_from_stack`] has not been called.
#[must_use]
pub fn getauxval(key: u64) -> u64 {
    let summary = aux_summary();
    match key {
        AT_PAGESZ => summary.page_size as u64,
        AT_HWCAP => summary.hwcap,
        AT_HWCAP2 => summary.hwcap2,
        AT_PHDR => summary.phdr_addr,
        AT_PHENT => summary.phent_size,
        AT_PHNUM => summary.phnum,
        AT_ENTRY => summary.entry_addr,
        AT_RANDOM => summary.random_addr,
        AT_EXECFN => summary.execfn_addr,
        _ => 0,
    }
}

/// Returns the active system page size in bytes (defaulting to `4096`).
#[must_use]
pub fn page_size() -> usize {
    aux_summary().page_size
}

/// Returns the command-line arguments (`argv[0..argc]`) as byte vectors.
#[cfg(feature = "alloc")]
#[must_use]
pub fn args_vec() -> Vec<Vec<u8>> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return Vec::new();
    }
    let argc = ARGC.load(Ordering::Relaxed);
    let argv = ARGV_PTR.load(Ordering::Relaxed) as *const *const u8;
    if argc == 0 || argv.is_null() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(argc);
    let mut i = 0usize;
    while i < argc {
        // SAFETY: `argv` was validated by `parse_stack_words` to have `argc` non-null entries.
        let ptr = unsafe { *argv.add(i) };
        if ptr.is_null() {
            break;
        }
        // SAFETY: Each `argv[i]` points to a NUL-terminated C string on the initial stack.
        let len = unsafe { c_strlen(ptr) };
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        let mut arg = Vec::with_capacity(len);
        arg.extend_from_slice(slice);
        out.push(arg);
        i += 1;
    }
    out
}

#[cfg(feature = "alloc")]
fn ensure_env_initialized(guard: &mut Option<EnvPairs>) -> &mut EnvPairs {
    if guard.is_none() {
        let mut entries: EnvPairs = Vec::new();
        if INITIALIZED.load(Ordering::Acquire) {
            let envp = ENVP_PTR.load(Ordering::Relaxed) as *const *const u8;
            if !envp.is_null() {
                let mut idx = 0usize;
                loop {
                    // SAFETY: `envp` was validated by `parse_stack_words` to be NULL-terminated.
                    let ptr = unsafe { *envp.add(idx) };
                    if ptr.is_null() {
                        break;
                    }
                    // SAFETY: Each `envp[idx]` points to a NUL-terminated `KEY=VALUE` string.
                    let len = unsafe { c_strlen(ptr) };
                    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
                    if let Some(eq_pos) = memchr(b'=', bytes) {
                        let key = bytes[..eq_pos].to_vec();
                        let val = bytes[eq_pos + 1..].to_vec();
                        if let Some((_, existing_val)) = entries
                            .iter_mut()
                            .find(|(k, _)| k.as_slice() == key.as_slice())
                        {
                            *existing_val = val;
                        } else {
                            entries.push((key, val));
                        }
                    }
                    idx += 1;
                }
            }
        }
        *guard = Some(entries);
    }
    guard.as_mut().unwrap()
}

/// Looks up the environment variable `name` and returns a cloned byte vector of its value.
#[cfg(feature = "alloc")]
#[must_use]
pub fn getenv_vec(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || memchr(b'=', name).is_some() || memchr(0, name).is_some() {
        return None;
    }
    let mut guard = ENV_TABLE.lock();
    let table = ensure_env_initialized(&mut guard);
    table
        .iter()
        .find(|(k, _)| k.as_slice() == name)
        .map(|(_, v)| v.clone())
}

/// Inserts or updates the environment variable `name` with `value`.
///
/// Returns `Err(Errno(EINVAL))` if `name` is empty, contains `'='`, or contains an interior NUL,
/// or if `value` contains an interior NUL.
#[cfg(feature = "alloc")]
pub fn setenv_bytes(name: &[u8], value: &[u8], overwrite: bool) -> SysResult<()> {
    if name.is_empty()
        || memchr(b'=', name).is_some()
        || memchr(0, name).is_some()
        || memchr(0, value).is_some()
    {
        return Err(Errno(EINVAL));
    }

    let mut guard = ENV_TABLE.lock();
    let table = ensure_env_initialized(&mut guard);
    if let Some((_, existing_val)) = table.iter_mut().find(|(k, _)| k.as_slice() == name) {
        if overwrite {
            existing_val.clear();
            existing_val.extend_from_slice(value);
        }
        return Ok(());
    }

    let mut k = Vec::with_capacity(name.len());
    k.extend_from_slice(name);
    let mut v = Vec::with_capacity(value.len());
    v.extend_from_slice(value);
    table.push((k, v));
    Ok(())
}

/// Returns all environment variables as `KEY=VALUE` byte vectors.
#[cfg(feature = "alloc")]
#[must_use]
pub fn environ_vec() -> Vec<Vec<u8>> {
    let mut guard = ENV_TABLE.lock();
    let table = ensure_env_initialized(&mut guard);
    let mut out = Vec::with_capacity(table.len());
    for (k, v) in table.iter() {
        let mut entry = Vec::with_capacity(k.len() + 1 + v.len());
        entry.extend_from_slice(k);
        entry.push(b'=');
        entry.extend_from_slice(v);
        out.push(entry);
    }
    out
}

/// Emits a freestanding `aarch64-unknown-none` process entry point (`_start`), stack initializer,
/// and panic handler that exits via `exit_group` / `abort`.
#[macro_export]
macro_rules! process_entry {
    ($main_fn:path) => {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "mov x0, sp",
                "bl {entry}",
                "brk #0",
                entry = sym _libc_rs_start_rust,
            );
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        extern "C" fn _libc_rs_start_rust(sp: *const u64) -> ! {
            // SAFETY: `sp` is the initial EL0 stack pointer passed from `_start`.
            unsafe {
                $crate::startup::init_from_stack(sp);
            }
            let code = $crate::rt::EntryOutcome::into_exit_code($main_fn());
            $crate::process::exit_group(code as i32)
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        #[panic_handler]
        fn _libc_rs_process_panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::process::abort()
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::{AT_NULL, HWCAP_AES, HWCAP_CRC32};

    #[test]
    fn startup_parses_stack_args_env_and_auxv() {
        let arg0 = b"/bin/app\0";
        let arg1 = b"--flag\0";
        let env0 = b"PATH=/bin\0";
        let env1 = b"MODE=fast\0";

        let stack: [u64; 15] = [
            2,
            arg0.as_ptr() as u64,
            arg1.as_ptr() as u64,
            0,
            env0.as_ptr() as u64,
            env1.as_ptr() as u64,
            0,
            AT_PAGESZ,
            16384,
            AT_HWCAP,
            HWCAP_AES | HWCAP_CRC32,
            AT_ENTRY,
            0x4000_1000,
            AT_NULL,
            0,
        ];

        // SAFETY: `stack` is a valid synthetic initial EL0 stack image with valid C string pointers.
        unsafe {
            init_from_stack(stack.as_ptr());
        }

        assert_eq!(page_size(), 16384);
        assert_eq!(getauxval(AT_PAGESZ), 16384);
        assert_eq!(getauxval(AT_HWCAP), HWCAP_AES | HWCAP_CRC32);
        assert_eq!(getauxval(AT_ENTRY), 0x4000_1000);
        assert_eq!(getauxval(999), 0);

        #[cfg(feature = "alloc")]
        {
            let args = args_vec();
            assert_eq!(args.len(), 2);
            assert_eq!(args[0].as_slice(), b"/bin/app");
            assert_eq!(args[1].as_slice(), b"--flag");

            assert_eq!(getenv_vec(b"PATH").as_deref(), Some(&b"/bin"[..]));
            assert_eq!(getenv_vec(b"MODE").as_deref(), Some(&b"fast"[..]));
            assert_eq!(getenv_vec(b"MISSING"), None);

            // Do not overwrite when `overwrite == false`.
            setenv_bytes(b"MODE", b"slow", false).unwrap();
            assert_eq!(getenv_vec(b"MODE").as_deref(), Some(&b"fast"[..]));

            // Overwrite when `overwrite == true`.
            setenv_bytes(b"MODE", b"turbo", true).unwrap();
            assert_eq!(getenv_vec(b"MODE").as_deref(), Some(&b"turbo"[..]));

            // Insert new variable.
            setenv_bytes(b"NEW_VAR", b"123", true).unwrap();
            assert_eq!(getenv_vec(b"NEW_VAR").as_deref(), Some(&b"123"[..]));

            // Reject invalid names.
            assert_eq!(setenv_bytes(b"", b"v", true), Err(Errno(EINVAL)));
            assert_eq!(setenv_bytes(b"BAD=NAME", b"v", true), Err(Errno(EINVAL)));
            assert_eq!(setenv_bytes(b"BAD\0NAME", b"v", true), Err(Errno(EINVAL)));
            assert_eq!(setenv_bytes(b"GOOD", b"bad\0val", true), Err(Errno(EINVAL)));

            let env_all = environ_vec();
            assert!(env_all.iter().any(|e| e.as_slice() == b"PATH=/bin"));
            assert!(env_all.iter().any(|e| e.as_slice() == b"MODE=turbo"));
            assert!(env_all.iter().any(|e| e.as_slice() == b"NEW_VAR=123"));
        }
    }
}
