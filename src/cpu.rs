//! Per-CPU control pages, topology, worker reservation, and doorbell signaling.

use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::status::{Result, Status};
use crate::trap::{Op, invoke, invoke_unit};

/// Expected version of [`CpuControlPage`].
pub const USER_CPU_PAGE_VERSION: u32 = 1;

/// Maximum number of CPUs supported in [`CpuControlTable`].
pub const MAX_CPUS: usize = 256;

/// CPU is online.
pub const CPU_PAGE_ONLINE: u64 = 1 << 0;
/// CPU is reserved for worker execution.
pub const CPU_PAGE_WORKER_RESERVED: u64 = 1 << 1;
/// CPU is operating in tickless mode.
pub const CPU_PAGE_TICKLESS: u64 = 1 << 2;
/// Preemption is pending on this CPU.
pub const CPU_PAGE_PREEMPT_PENDING: u64 = 1 << 3;
/// CPU is parked in idle.
pub const CPU_PAGE_IDLE_PARKED: u64 = 1 << 4;

/// User-space CPU state: actively running.
pub const USER_CPU_RUNNING: u64 = 0;
/// User-space CPU state: spinning.
pub const USER_CPU_SPINNING: u64 = 1;
/// User-space CPU state: armed for `WFE` wakeup.
pub const USER_CPU_WFE_ARMED: u64 = 2;
/// User-space CPU state: inside a critical section.
pub const USER_CPU_CRITICAL_SECTION: u64 = 3;

/// 128-byte cache-line-aligned per-CPU shared control page.
#[derive(Debug)]
#[repr(C, align(128))]
pub struct CpuControlPage {
    pub version: u32,
    pub cpu_id: u32,
    pub flags: AtomicU64,
    pub heartbeat_ticks: AtomicU64,
    pub slice_deadline_ns: AtomicU64,
    pub runqueue_depth: AtomicU32,
    pub active_flavor: AtomicU32,
    pub migration_epoch: AtomicU64,
    pub doorbell_seq: AtomicU64,
    _kernel_pad: u64,

    pub user_state: AtomicU64,
    pub user_work_depth: AtomicU64,
    pub user_doorbell_pending: AtomicU64,
    pub preempt_defer_until_ticks: AtomicU64,
    _user_pad: [u64; 4],
}

const _: () = {
    assert!(size_of::<CpuControlPage>() == 128);
    assert!(align_of::<CpuControlPage>() == 128);
    assert!(offset_of!(CpuControlPage, version) == 0);
    assert!(offset_of!(CpuControlPage, cpu_id) == 4);
    assert!(offset_of!(CpuControlPage, flags) == 8);
    assert!(offset_of!(CpuControlPage, heartbeat_ticks) == 16);
    assert!(offset_of!(CpuControlPage, slice_deadline_ns) == 24);
    assert!(offset_of!(CpuControlPage, runqueue_depth) == 32);
    assert!(offset_of!(CpuControlPage, active_flavor) == 36);
    assert!(offset_of!(CpuControlPage, migration_epoch) == 40);
    assert!(offset_of!(CpuControlPage, doorbell_seq) == 48);
    assert!(offset_of!(CpuControlPage, user_state) == 64);
    assert!(offset_of!(CpuControlPage, user_work_depth) == 72);
    assert!(offset_of!(CpuControlPage, user_doorbell_pending) == 80);
    assert!(offset_of!(CpuControlPage, preempt_defer_until_ticks) == 88);
};

impl CpuControlPage {
    /// Creates a zero-initialized [`CpuControlPage`] for `cpu_id`.
    #[must_use]
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            version: USER_CPU_PAGE_VERSION,
            cpu_id,
            flags: AtomicU64::new(0),
            heartbeat_ticks: AtomicU64::new(0),
            slice_deadline_ns: AtomicU64::new(0),
            runqueue_depth: AtomicU32::new(0),
            active_flavor: AtomicU32::new(0),
            migration_epoch: AtomicU64::new(0),
            doorbell_seq: AtomicU64::new(0),
            _kernel_pad: 0,
            user_state: AtomicU64::new(USER_CPU_RUNNING),
            user_work_depth: AtomicU64::new(0),
            user_doorbell_pending: AtomicU64::new(0),
            preempt_defer_until_ticks: AtomicU64::new(0),
            _user_pad: [0; 4],
        }
    }

    /// Returns `true` if [`CPU_PAGE_ONLINE`] is set.
    #[must_use]
    pub fn is_online(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & CPU_PAGE_ONLINE) != 0
    }

    /// Returns `true` if [`CPU_PAGE_TICKLESS`] is set.
    #[must_use]
    pub fn is_tickless(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & CPU_PAGE_TICKLESS) != 0
    }

    /// Returns `true` if [`CPU_PAGE_PREEMPT_PENDING`] is set.
    #[must_use]
    pub fn preempt_pending(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & CPU_PAGE_PREEMPT_PENDING) != 0
    }

    /// Sets `user_doorbell_pending` and returns `true` if the target CPU is in [`USER_CPU_WFE_ARMED`].
    #[must_use]
    pub fn try_notify_user_wfe(&self) -> bool {
        self.user_doorbell_pending.store(1, Ordering::Release);
        self.user_state.load(Ordering::Acquire) == USER_CPU_WFE_ARMED
    }
}

/// CPU and NUMA node topology decoded from `tpidrro_el0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CpuTopology {
    pub cpu_id: u16,
    pub numa_node: u16,
}

/// Encodes `(cpu_id, numa_node)` into the `tpidrro_el0` format.
#[must_use]
pub const fn encode_tpidrro(cpu_id: u16, numa_node: u16) -> u64 {
    (cpu_id as u64) | ((numa_node as u64) << 16)
}

/// Decodes a raw `tpidrro_el0` value into [`CpuTopology`].
#[must_use]
pub const fn decode_tpidrro(raw: u64) -> CpuTopology {
    CpuTopology {
        cpu_id: (raw & 0xffff) as u16,
        numa_node: ((raw >> 16) & 0xffff) as u16,
    }
}

/// Returns the current CPU topology from `tpidrro_el0` on AArch64 bare-metal targets.
#[must_use]
pub fn current_topology() -> Option<CpuTopology> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let raw: u64;
        // SAFETY: Reading `tpidrro_el0` is safe and side-effect free at EL0.
        unsafe {
            core::arch::asm!("mrs {}, tpidrro_el0", out(reg) raw, options(nostack, nomem));
        }
        Some(decode_tpidrro(raw))
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        None
    }
}

/// Bitmask request for reserving worker CPU cores (CPU 0 is never allowed).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct WorkerReservation {
    pub cpu_mask: [u64; 4],
    pub flags: u64,
}

impl WorkerReservation {
    /// Creates an empty [`WorkerReservation`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cpu_mask: [0; 4],
            flags: 0,
        }
    }

    /// Adds `cpu` to the reservation mask, rejecting CPU 0 and CPUs `>= 256`.
    pub fn add_cpu(&mut self, cpu: u16) -> Result<()> {
        if cpu == 0 || usize::from(cpu) >= MAX_CPUS {
            return Err(Status::Invalid);
        }
        let word = usize::from(cpu / 64);
        let bit = cpu % 64;
        self.cpu_mask[word] |= 1u64 << bit;
        Ok(())
    }

    /// Returns `true` if `cpu` is present in the reservation mask.
    #[must_use]
    pub const fn contains(&self, cpu: u16) -> bool {
        if cpu as usize >= MAX_CPUS {
            return false;
        }
        let word = (cpu / 64) as usize;
        let bit = cpu % 64;
        (self.cpu_mask[word] & (1u64 << bit)) != 0
    }

    /// Returns `true` if CPU 0 is not set in the reservation mask.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        (self.cpu_mask[0] & 1) == 0
    }
}

/// Mapped table of per-CPU control pages.
#[derive(Clone, Copy, Debug)]
pub struct CpuControlTable {
    pages: &'static [CpuControlPage; MAX_CPUS],
}

impl CpuControlTable {
    /// Maps the per-CPU control page table at `desired_va` with `flags`.
    pub fn map(desired_va: usize, flags: u64) -> Result<Self> {
        let va = invoke(Op::MapCpuControlPages, [desired_va as u64, flags, 0, 0])?;
        let ptr = va as usize as *const [CpuControlPage; MAX_CPUS];
        if ptr.is_null() || (ptr as usize) % align_of::<CpuControlPage>() != 0 {
            return Err(Status::Protocol);
        }
        // SAFETY: The kernel mapped `MAX_CPUS` aligned `CpuControlPage` entries at `va`.
        let pages = unsafe { &*ptr };
        if pages[0].version != USER_CPU_PAGE_VERSION {
            return Err(Status::Protocol);
        }
        Ok(Self { pages })
    }

    /// Returns a reference to the control page for `cpu`.
    pub fn page(&self, cpu: u16) -> Result<&CpuControlPage> {
        self.pages.get(usize::from(cpu)).ok_or(Status::Invalid)
    }

    /// Notifies `cpu` via user-space `SEV` if `WFE`-armed, or via a kernel doorbell otherwise.
    pub fn notify(&self, cpu: u16) -> Result<()> {
        let page = self.page(cpu)?;
        if page.try_notify_user_wfe() {
            send_event();
            Ok(())
        } else {
            let mask = 1u64 << (cpu % 64);
            let word_index = u64::from(cpu / 64);
            ring_doorbell_mask(mask, word_index, 0)
        }
    }

    /// Arms `USER_CPU_WFE_ARMED` on `cpu`'s control page and waits once if no doorbell is pending.
    ///
    /// Consumes and clears `user_doorbell_pending` when returning `true`.
    pub fn park_once(&self, cpu: u16) -> Result<bool> {
        let page = self.page(cpu)?;
        if page.user_doorbell_pending.swap(0, Ordering::AcqRel) != 0 {
            return Ok(true);
        }
        arm_local_event();
        page.user_state.store(USER_CPU_WFE_ARMED, Ordering::SeqCst);
        let ready = page.user_doorbell_pending.swap(0, Ordering::AcqRel) != 0;
        if !ready {
            wait_for_event_once();
        }
        page.user_state.store(USER_CPU_RUNNING, Ordering::Release);
        Ok(ready || page.user_doorbell_pending.swap(0, Ordering::AcqRel) != 0)
    }
}

#[inline]
fn arm_local_event() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `sevl` sets only the local PE event register.
    unsafe {
        core::arch::asm!("sevl", options(nostack, nomem));
    }
}

#[inline]
fn wait_for_event_once() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: Paired with `USER_CPU_WFE_ARMED` and producer `SEV` / doorbell SGI.
    unsafe {
        core::arch::asm!("wfe", options(nostack, nomem));
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn send_event() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `dsb ishst; sev` wakes cores waiting in `wfe`.
    unsafe {
        core::arch::asm!("dsb ishst", "sev", options(nostack, nomem));
    }
}

/// Reserves worker cores specified by `req`.
pub fn reserve_workers(req: &WorkerReservation) -> Result<u32> {
    if !req.is_valid() {
        return Err(Status::Invalid);
    }
    let count = invoke(
        Op::ReserveWorkerCores,
        [core::ptr::from_ref(req) as u64, 0, 0, 0],
    )?;
    u32::try_from(count).map_err(|_| Status::Protocol)
}

/// Rings the kernel CPU doorbell for the CPUs selected by `mask` in `word_index`.
pub fn ring_doorbell_mask(mask: u64, word_index: u64, flags: u64) -> Result<()> {
    if word_index >= 4 || mask == 0 {
        return Err(Status::Invalid);
    }
    invoke_unit(Op::CpuDoorbell, [mask, word_index, flags, 0])
}

/// Hints to the CPU that the current thread is spinning.
#[inline]
pub fn yield_cpu() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    // SAFETY: `yield` is an unprivileged hint instruction.
    unsafe {
        core::arch::asm!("yield", options(nostack, preserves_flags));
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::trap::with_mock_trap;

    #[test]
    fn tpidrro_round_trip() {
        let raw = encode_tpidrro(17, 3);
        let topo = decode_tpidrro(raw);
        assert_eq!(
            topo,
            CpuTopology {
                cpu_id: 17,
                numa_node: 3
            }
        );
    }

    #[test]
    fn worker_reservation_rejects_cpu_zero_and_oob() {
        let mut req = WorkerReservation::new();
        assert_eq!(req.add_cpu(0), Err(Status::Invalid));
        assert_eq!(req.add_cpu(256), Err(Status::Invalid));
        assert_eq!(req.add_cpu(65), Ok(()));
        assert!(req.contains(65));
        assert!(!req.contains(0));
        assert!(req.is_valid());

        req.cpu_mask[0] |= 1;
        assert!(!req.is_valid());
        assert_eq!(reserve_workers(&req), Err(Status::Invalid));
    }

    #[test]
    fn try_notify_and_doorbell_routing() {
        let page = CpuControlPage::new(5);
        assert!(!page.try_notify_user_wfe());
        assert_eq!(page.user_doorbell_pending.load(Ordering::Acquire), 1);

        page.user_state.store(USER_CPU_WFE_ARMED, Ordering::Release);
        page.user_doorbell_pending.store(0, Ordering::Release);
        assert!(page.try_notify_user_wfe());
        assert_eq!(page.user_doorbell_pending.load(Ordering::Acquire), 1);

        static LAST_MASK: AtomicU64 = AtomicU64::new(0);
        static LAST_WORD: AtomicU64 = AtomicU64::new(0);
        let res = with_mock_trap(
            |_, op, args| {
                assert_eq!(Op::decode(op), Some(Op::CpuDoorbell));
                LAST_MASK.store(args[0], Ordering::SeqCst);
                LAST_WORD.store(args[1], Ordering::SeqCst);
                Ok(0)
            },
            || ring_doorbell_mask(1u64 << 3, 2, 0),
        );
        assert_eq!(res, Ok(()));
        assert_eq!(LAST_MASK.load(Ordering::SeqCst), 1u64 << 3);
        assert_eq!(LAST_WORD.load(Ordering::SeqCst), 2);
    }
}
