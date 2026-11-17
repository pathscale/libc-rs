//! ELF native personality note and freestanding entry/panic-handler macros.

/// 24-byte ELF note header + 4-byte owner + 4-byte version descriptor.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfNote24 {
    pub namesz: u32,
    pub descsz: u32,
    pub kind: u32,
    pub name: [u8; 8],
    pub desc: u32,
}

const _: () = assert!(core::mem::size_of::<ElfNote24>() == 24);

/// Constructs a 24-byte `ElfNote24` for a 4-byte owner tag.
pub const fn make_elf_note(owner: [u8; 4], kind: u32, version: u32) -> ElfNote24 {
    ElfNote24 {
        namesz: 5,
        descsz: 4,
        kind,
        name: [owner[0], owner[1], owner[2], owner[3], 0, 0, 0, 0],
        desc: version,
    }
}

/// Emits a `.note.uk_native` ELF note static.
#[macro_export]
macro_rules! declare_native_note {
    ($static_name:ident, $owner:expr, $kind:expr, $version:expr) => {
        #[used]
        #[unsafe(link_section = ".note.uk_native")]
        static $static_name: $crate::rt::ElfNote24 =
            $crate::rt::make_elf_note($owner, $kind, $version);
    };
}

/// Trait allowing `native_entry!` to accept `fn() -> Result<()>` or `fn() -> u8`.
pub trait EntryOutcome {
    fn into_exit_code(self) -> u8;
}

impl EntryOutcome for () {
    fn into_exit_code(self) -> u8 {
        0
    }
}

impl EntryOutcome for u8 {
    fn into_exit_code(self) -> u8 {
        self
    }
}

impl<E> EntryOutcome for core::result::Result<(), E> {
    fn into_exit_code(self) -> u8 {
        match self {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }
}

/// Emits `_start() -> !` and an `aarch64-unknown-none` `#[panic_handler]`.
#[macro_export]
macro_rules! native_entry {
    ($main_fn:path) => {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            let code = $crate::rt::EntryOutcome::into_exit_code($main_fn());
            $crate::trap::exit(code)
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        #[panic_handler]
        fn _libc_rs_panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::trap::exit(2)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_note_layout_is_24_bytes() {
        let note = make_elf_note(*b"UKRN", 1, 1);
        assert_eq!(core::mem::size_of::<ElfNote24>(), 24);
        assert_eq!(note.namesz, 5);
        assert_eq!(note.descsz, 4);
        assert_eq!(note.kind, 1);
        assert_eq!(note.name, [b'U', b'K', b'R', b'N', 0, 0, 0, 0]);
        assert_eq!(note.desc, 1);
    }
}
