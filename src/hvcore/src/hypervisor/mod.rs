//! This module implements the platform agnostic hypervisor core.

#[cfg(not(test))]
pub mod allocator;
mod amd;
mod apic_id;
pub mod gdt_tss;
mod host;
mod intel;
pub mod interrupt_handlers;
pub mod paging_structures;
pub mod panic;
pub mod platform_ops;
mod registers;
mod segment;
mod serial_logger;
mod support;
mod switch_stack;
mod x86_instructions;

use alloc::vec::Vec;
use spin::Once;
use x86::cpuid::cpuid;

use crate::{GdtTss, PagingStructures, hypervisor::registers::Registers};

use self::interrupt_handlers::InterruptDescriptorTable;

/// Hyperjacks the current system by virtualizing all logical processors on this
/// system.
pub fn virtualize_system(shared_host: SharedHostData) {
    serial_logger::init(log::LevelFilter::Info);
    log::info!("Virtualizing the all processors");

    apic_id::init();
    let _ = SHARED_HOST_DATA.call_once(|| shared_host);

    // Virtualize each logical processor.
    platform_ops::get().run_on_all_processors(|| {
        // Take a snapshot of current register values. This will be the initial
        // state of the guest _including RIP_. This means that the guest starts execution
        // right after this function call. Think of it as the setjmp() C standard
        // function.
        let registers = Registers::capture_current();

        // In the first run, our hypervisor is not installed and the branch is
        // taken. After starting the guest, the second run, the hypervisor is already
        // installed and we will bail out.
        if !is_our_hypervisor_present() {
            log::info!("Virtualizing the current processor");

            // We are about to execute host code with newly allocated stack.
            // This is required because the guest will start executing with the
            // current stack. If we do not change the stack for the host, as soon
            // as the guest starts, it will smash host's stack.
            switch_stack::jump_with_new_stack(host::main, &registers);
        }
        log::info!("Virtualized the current processor");
    });

    log::info!("Virtualized the all processors");
}

/// A collection of data that the host depends on for its entire lifespan.
#[derive(Debug, Default)]
pub struct SharedHostData {
    /// The paging structures for the host. If `None`, the current paging
    /// structure is used for both the host and the guest.
    pub pt: Option<PagingStructures>,

    /// The IDT for the host. If `None`, the current IDT is used for both the
    /// host and the guest.
    pub idt: Option<InterruptDescriptorTable>,

    /// The GDT and TSS for the host for each logical processor. If `None`,
    /// the current GDTs and TSSes are used for both the host and the guest.
    pub gdts: Option<Vec<GdtTss>>,
}

static SHARED_HOST_DATA: Once<SharedHostData> = Once::new();

const HV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
const HV_CPUID_INTERFACE: u32 = 0x4000_0001;
const OUR_HV_VENDOR_NAME_EBX: u32 = u32::from_ne_bytes(*b"Bare");
const OUR_HV_VENDOR_NAME_ECX: u32 = u32::from_ne_bytes(*b"viso");
const OUR_HV_VENDOR_NAME_EDX: u32 = u32::from_ne_bytes(*b"r!  ");

/// Tests whether the current processor is already virtualized by our hypervisor.
fn is_our_hypervisor_present() -> bool {
    let regs = cpuid!(HV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == OUR_HV_VENDOR_NAME_EBX)
        && (regs.ecx == OUR_HV_VENDOR_NAME_ECX)
        && (regs.edx == OUR_HV_VENDOR_NAME_EDX)
}
