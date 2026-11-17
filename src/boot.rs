//! Bounds-checked EL0 initial stack (`argc`, `argv`, `envp`, `auxv`) parser.

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_HWCAP: u64 = 16;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;

pub const HWCAP_AES: u64 = 1 << 3;
pub const HWCAP_PMULL: u64 = 1 << 4;
pub const HWCAP_SHA1: u64 = 1 << 5;
pub const HWCAP_SHA2: u64 = 1 << 6;
pub const HWCAP_CRC32: u64 = 1 << 7;
pub const HWCAP_ATOMICS: u64 = 1 << 8;
pub const HWCAP_SHA512: u64 = 1 << 21;

/// Raw auxiliary vector entry on the initial EL0 stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuxEntry {
    pub key: u64,
    pub value: u64,
}

/// Decoded summary of known auxiliary vector tags.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuxSummary {
    pub page_size: usize,
    pub hwcap: u64,
    pub hwcap2: u64,
    pub phdr_addr: u64,
    pub phent_size: u64,
    pub phnum: u64,
    pub entry_addr: u64,
    pub random_addr: u64,
    pub execfn_addr: u64,
}

/// Parses an auxiliary vector slice, stopping at `AT_NULL`.
pub fn parse_auxv(entries: &[AuxEntry]) -> AuxSummary {
    let mut summary = AuxSummary::default();
    for entry in entries {
        match entry.key {
            AT_NULL => break,
            AT_PHDR => summary.phdr_addr = entry.value,
            AT_PHENT => summary.phent_size = entry.value,
            AT_PHNUM => summary.phnum = entry.value,
            AT_PAGESZ => summary.page_size = entry.value as usize,
            AT_ENTRY => summary.entry_addr = entry.value,
            AT_HWCAP => summary.hwcap = entry.value,
            AT_RANDOM => summary.random_addr = entry.value,
            AT_HWCAP2 => summary.hwcap2 = entry.value,
            AT_EXECFN => summary.execfn_addr = entry.value,
            _ => {}
        }
    }
    summary
}

/// Parses a serialized initial EL0 stack bounded by `max_words`.
///
/// Returns `(argc, argv_ptr, envp_ptr, aux_summary)` or `None` if `sp` is null
/// or the stack terminates before `AT_NULL` within `max_words`.
///
/// # Safety
/// - `sp` must be null or valid for reads of up to `max_words` `u64` words.
pub unsafe fn parse_stack_words(
    sp: *const u64,
    max_words: usize,
) -> Option<(usize, *const *const u8, *const *const u8, AuxSummary)> {
    if sp.is_null() || max_words < 4 {
        return None;
    }

    let argc = unsafe { *sp } as usize;
    let mut idx = 1usize;

    // argv[0..argc] + terminating NULL
    let argv_ptr = unsafe { sp.add(idx).cast::<*const u8>() };
    let mut seen_argv = 0usize;
    while idx < max_words {
        let word = unsafe { *sp.add(idx) };
        idx += 1;
        if word == 0 {
            if seen_argv != argc {
                return None;
            }
            break;
        }
        seen_argv += 1;
        if seen_argv > argc {
            return None;
        }
    }
    if seen_argv != argc || idx >= max_words {
        return None;
    }

    // envp[...] + terminating NULL
    let envp_ptr = unsafe { sp.add(idx).cast::<*const u8>() };
    let mut found_env_end = false;
    while idx < max_words {
        let word = unsafe { *sp.add(idx) };
        idx += 1;
        if word == 0 {
            found_env_end = true;
            break;
        }
    }
    if !found_env_end {
        return None;
    }

    // auxv key/value pairs terminated by AT_NULL
    let mut summary = AuxSummary::default();
    while idx + 1 < max_words {
        let key = unsafe { *sp.add(idx) };
        let value = unsafe { *sp.add(idx + 1) };
        idx += 2;
        if key == AT_NULL {
            return Some((argc, argv_ptr, envp_ptr, summary));
        }
        match key {
            AT_PHDR => summary.phdr_addr = value,
            AT_PHENT => summary.phent_size = value,
            AT_PHNUM => summary.phnum = value,
            AT_PAGESZ => summary.page_size = value as usize,
            AT_ENTRY => summary.entry_addr = value,
            AT_HWCAP => summary.hwcap = value,
            AT_RANDOM => summary.random_addr = value,
            AT_HWCAP2 => summary.hwcap2 = value,
            AT_EXECFN => summary.execfn_addr = value,
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_stack_and_rejects_truncated() {
        let stack: [u64; 14] = [
            2,         // argc
            0x1000,    // argv[0]
            0x2000,    // argv[1]
            0,         // argv NULL
            0x3000,    // envp[0]
            0,         // envp NULL
            AT_PAGESZ, // auxv[0].key
            4096,      // auxv[0].value
            AT_HWCAP,  // auxv[1].key
            HWCAP_AES | HWCAP_ATOMICS,
            AT_RANDOM, // auxv[2].key
            0xdead_beef,
            AT_NULL, // auxv[3].key
            0,       // auxv[3].value
        ];

        let parsed = unsafe { parse_stack_words(stack.as_ptr(), stack.len()) };
        let (argc, _argv, _envp, aux) = parsed.expect("valid stack should parse");
        assert_eq!(argc, 2);
        assert_eq!(aux.page_size, 4096);
        assert_eq!(aux.hwcap, HWCAP_AES | HWCAP_ATOMICS);
        assert_eq!(aux.random_addr, 0xdead_beef);

        // Truncated before AT_NULL must return None.
        assert!(unsafe { parse_stack_words(stack.as_ptr(), stack.len() - 2) }.is_none());
    }
}
