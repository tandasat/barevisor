mod amd;
mod apic;
mod capture_registers;
pub mod gdt_tss;
mod intel;
pub mod paging_structures;
pub mod panic;
pub mod platform_ops;
mod segment;
mod support;
mod switch_stack;
mod vmm;
mod x86_instructions;

use core::sync::atomic::{AtomicU8, Ordering};

use alloc::{boxed::Box, vec::Vec};
use spin::Once;
use x86::cpuid::cpuid;

use crate::hypervisor::{
    self,
    apic::{apic_id, cpu_id_from, APIC_ID_MAP},
    capture_registers::GuestRegisters,
    paging_structures::PagingStructures,
};

#[derive(Debug, Default)]
pub struct SharedData {
    pub host_pt: Option<PagingStructures>,
    pub host_idt: Option<Box<u64>>,
    pub host_gdt_and_tss: Option<Vec<Box<hypervisor::gdt_tss::GdtTss>>>,
}

/// A collection of data that the hypervisor depends on for its entire lifespan.
pub(crate) static HV_SHARED_DATA: Once<SharedData> = Once::new();

static PROCESSOR_COUNT: AtomicU8 = AtomicU8::new(0);

// TODO: consider making it generic <T: SystemOps> instead of Box<dyn SystemOps>.
pub fn virtualize_system(hv_data: SharedData) {
    init_logger(log::LevelFilter::Debug);
    log::info!("Virtualizing the all processors");

    platform_ops::get().run_on_all_processors(|| {
        let mut map = APIC_ID_MAP.write();
        assert!(map
            .insert(apic_id(), PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed))
            .is_none());
    });

    let _ = HV_SHARED_DATA.call_once(|| hv_data);

    platform_ops::get().run_on_all_processors(|| {
        let regs = GuestRegisters::new();
        if !is_our_hypervisor_present() {
            let params = vmm::VCpuParameters {
                processor_id: cpu_id_from(apic_id()).unwrap(),
                regs,
            };
            log::info!("Virtualizing the processor {}", params.processor_id);
            switch_stack::jump_with_new_stack(&params, vmm::main);
        }
        log::info!("Virtualized the processor");
    });

    log::info!("Virtualized the all processors");
}

const HV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
const HV_CPUID_INTERFACE: u32 = 0x4000_0001;
const OUR_HV_VENDOR_NAME: u32 = 0x2143_4347; // "GCC!"

fn is_our_hypervisor_present() -> bool {
    let regs = cpuid!(HV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == OUR_HV_VENDOR_NAME)
        && (regs.ecx == OUR_HV_VENDOR_NAME)
        && (regs.edx == OUR_HV_VENDOR_NAME)
}

#[cfg(test)]
fn init_logger(level: log::LevelFilter) {
    env_logger::builder().filter_level(level).init();
}

#[cfg(not(test))]
fn init_logger(level: log::LevelFilter) {
    com_logger::builder().base(0x3f8).filter(level).setup();
}
