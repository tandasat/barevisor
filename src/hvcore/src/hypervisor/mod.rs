mod amd;
mod init;
mod intel;
mod switch_stack;
mod vmm;

use core::sync::atomic::{AtomicU8, Ordering};

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use spin::{Once, RwLock};
use x86::cpuid::cpuid;

use crate::utils::{
    self, capture_registers::GuestRegisters, paging_structures::PagingStructures, platform,
};

#[derive(Debug, Default)]
pub struct SharedData {
    pub host_pt: Option<PagingStructures>,
    pub host_idt: Option<Box<u64>>,
    pub host_gdt_and_tss: Option<Vec<Box<utils::gdt_tss::GdtTss>>>,
}

/// A collection of data that the hypervisor depends on for its entire lifespan.
pub(crate) static HV_SHARED_DATA: Once<SharedData> = Once::new();

static PROCESSOR_COUNT: AtomicU8 = AtomicU8::new(0);

//const ARRAY_REPEAT_VALUE: AtomicU16 = AtomicU16::new(u16::MAX);
//let sipi_vectors = [ARRAY_REPEAT_VALUE; 64];
//static APIC_ID_MAP: [AtomicU8; 255] =

//-------------------------

type ApicId = u8;
type ProcessorId = u8;
static APIC_ID_MAP: RwLock<BTreeMap<ApicId, ProcessorId>> = RwLock::new(BTreeMap::new());

/// Gets an APIC ID.
fn apic_id() -> ApicId {
    // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
    // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
    (x86::cpuid::cpuid!(0x1).ebx >> 24) as _
}

pub(crate) fn cpu_id_from(apic_id: ApicId) -> Option<ProcessorId> {
    let map = APIC_ID_MAP.read();
    log::info!("ID={apic_id}, {map:#x?}");
    map.get(&apic_id).copied()
}

//-------------------------

// TODO: consider making it generic <T: SystemOps> instead of Box<dyn SystemOps>.
pub fn virtualize_system(hv_data: SharedData) {
    init_logger(log::LevelFilter::Debug);
    log::info!("Virtualizing the all processors");

    platform::ops().run_on_all_processors(|| {
        let mut map = APIC_ID_MAP.write();
        assert!(map
            .insert(apic_id(), PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed))
            .is_none());
    });

    let _ = HV_SHARED_DATA.call_once(|| hv_data);

    platform::ops().run_on_all_processors(|| {
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

pub(crate) trait Architecture {
    type Extension: Extension + Default;
    type VirtualMachine: VirtualMachine + Default;
}

pub trait Extension {
    fn enable(&mut self);
}

pub(crate) trait VirtualMachine {
    fn new(id: u8) -> Self;
    fn activate(&mut self);
    fn initialize(&mut self, regs: &GuestRegisters);
    fn run(&mut self) -> VmExitReason;
    fn regs(&mut self) -> &mut GuestRegisters;
}

pub(crate) struct InstrInterceptionQualification {
    pub(crate) next_rip: u64,
}

pub(crate) enum VmExitReason {
    Cpuid(InstrInterceptionQualification),
    Rdmsr(InstrInterceptionQualification),
    Wrmsr(InstrInterceptionQualification),
    XSetBv(InstrInterceptionQualification),
    Init,
    Sipi,
    NothingToDo,
}
