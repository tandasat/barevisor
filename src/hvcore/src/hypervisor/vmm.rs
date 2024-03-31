use x86::{
    controlregs::{Cr4, Xcr0},
    cpuid::cpuid,
};

use crate::hypervisor::{
    capture_registers::GuestRegisters,
    x86_instructions::{cr4, cr4_write, rdmsr, wrmsr, xsetbv},
    HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME,
};

use super::{amd::Amd, intel::Intel};

pub(crate) trait Architecture {
    type Extension: Extension + Default;
    type VirtualMachine: VirtualMachine + Default;
}

pub(crate) trait Extension {
    fn enable(&mut self);
}

pub(crate) trait VirtualMachine {
    fn new(id: u8) -> Self;
    fn activate(&mut self);
    fn initialize(&mut self, regs: &GuestRegisters);
    fn run(&mut self) -> VmExitReason;
    fn regs(&mut self) -> &mut GuestRegisters;
}

pub(crate) struct InstructionInfo {
    pub(crate) next_rip: u64,
}

pub(crate) enum VmExitReason {
    Cpuid(InstructionInfo),
    Rdmsr(InstructionInfo),
    Wrmsr(InstructionInfo),
    XSetBv(InstructionInfo),
    InitSignal,
    StartupIpi,
    NestedPageFault,
}

#[repr(C)]
pub(crate) struct VCpuParameters {
    pub(crate) processor_id: u8,
    pub(crate) regs: GuestRegisters,
}

pub(crate) fn main(params: &VCpuParameters) -> ! {
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        virtualize_core::<Intel>(params)
    } else {
        virtualize_core::<Amd>(params)
    }
}

fn virtualize_core<T: Architecture>(params: &VCpuParameters) -> ! {
    log::info!("Initializing the VM");

    let mut vt = T::Extension::default();
    vt.enable();

    // Create a new (empty) VM instance and tell the processor to operate on it.
    let vm = &mut T::VirtualMachine::new(params.processor_id);
    vm.activate();
    vm.initialize(&params.regs);

    log::info!("Starting the VM");
    loop {
        // Then, run the VM until events we (hypervisor) need to handle.
        match vm.run() {
            VmExitReason::Cpuid(info) => handle_cpuid(vm, &info),
            VmExitReason::Rdmsr(info) => handle_rdmsr(vm, &info),
            VmExitReason::Wrmsr(info) => handle_wrmsr(vm, &info),
            VmExitReason::XSetBv(info) => handle_xsetbv(vm, &info),
            VmExitReason::InitSignal | VmExitReason::StartupIpi | VmExitReason::NestedPageFault => {
            }
        }
    }
}

fn handle_cpuid<T: VirtualMachine>(vm: &mut T, info: &InstructionInfo) {
    let leaf = vm.regs().rax as u32;
    let sub_leaf = vm.regs().rcx as u32;
    log::trace!("CPUID {leaf:#x?} {sub_leaf:#x?}");
    let mut regs = cpuid!(leaf, sub_leaf);

    // Indicate that the hypervisor is present relevant CPUID is asked.
    if leaf == HV_CPUID_VENDOR_AND_MAX_FUNCTIONS {
        regs.ebx = OUR_HV_VENDOR_NAME;
        regs.ecx = OUR_HV_VENDOR_NAME;
        regs.edx = OUR_HV_VENDOR_NAME;
    } else if leaf == 1 {
        // CPUID.1.ECX[5] indicates if VT-x is supported. Clear this on this
        // processor to prevent other hypervisor tries to use it.
        // See: Table 3-10. Feature Information Returned in the ECX Register
        regs.ecx &= !(1 << 5);
    } else if leaf == HV_CPUID_INTERFACE {
        regs.eax = 0;
    }

    vm.regs().rax = u64::from(regs.eax);
    vm.regs().rbx = u64::from(regs.ebx);
    vm.regs().rcx = u64::from(regs.ecx);
    vm.regs().rdx = u64::from(regs.edx);
    vm.regs().rip = info.next_rip;
}

fn handle_rdmsr<T: VirtualMachine>(vm: &mut T, info: &InstructionInfo) {
    let msr = vm.regs().rcx as u32;
    log::trace!("RDMSR {msr:#x?}");
    let value = rdmsr(msr);

    vm.regs().rax = value & 0xffff_ffff;
    vm.regs().rdx = value >> 32;
    vm.regs().rip = info.next_rip;
}

fn handle_wrmsr<T: VirtualMachine>(vm: &mut T, info: &InstructionInfo) {
    let msr = vm.regs().rcx as u32;
    let value = (vm.regs().rax & 0xffff_ffff) | ((vm.regs().rdx & 0xffff_ffff) << 32);
    log::trace!("WRMSR {msr:#x?} {value:#x?}");
    wrmsr(msr, value);

    vm.regs().rip = info.next_rip;
}

fn handle_xsetbv<T: VirtualMachine>(vm: &mut T, info: &InstructionInfo) {
    let regs = vm.regs();
    let xcr: u32 = regs.rcx as u32;
    let value = (regs.rax & 0xffff_ffff) | ((regs.rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);
    xsetbv(xcr, value);

    regs.rip = info.next_rip;
}
