use x86::{
    controlregs::{Cr4, Xcr0},
    cpuid::cpuid,
};

use crate::hypervisor::{
    registers::Registers,
    x86_instructions::{cr4, cr4_write, rdmsr, wrmsr, xsetbv},
    HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME_EBX,
    OUR_HV_VENDOR_NAME_ECX, OUR_HV_VENDOR_NAME_EDX,
};

use super::{amd::Amd, intel::Intel};

pub(crate) trait Architecture {
    type Extension: Extension + Default;
    type VirtualMachine: VirtualMachine;
}

pub(crate) trait Extension {
    fn enable(&mut self);
}

pub(crate) trait VirtualMachine {
    fn new(id: u8) -> Self;
    fn activate(&mut self);
    fn initialize(&mut self, registers: &Registers);
    fn run(&mut self) -> VmExitReason;
    fn regs(&mut self) -> &mut Registers;
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
    pub(crate) registers: Registers,
}

/// The entry point of the hypervisor.
pub(crate) fn main(params: &VCpuParameters) -> ! {
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        virtualize_core::<Intel>(params)
    } else {
        virtualize_core::<Amd>(params)
    }
}

// Enables a virtualization extension, sets up and runs the VM indefinitely.
fn virtualize_core<T: Architecture>(params: &VCpuParameters) -> ! {
    log::info!("Initializing the VM");

    // Enable processor's virtualization features.
    let mut vt = T::Extension::default();
    vt.enable();

    // Create a new (empty) VM instance and set up its initial state.
    let vm = &mut T::VirtualMachine::new(params.processor_id);
    vm.activate();
    vm.initialize(&params.registers);

    // Then, run the VM until events that the hypervisor (this code) needs to
    // handle occurs.
    log::info!("Starting the VM");
    loop {
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

    if leaf == HV_CPUID_VENDOR_AND_MAX_FUNCTIONS {
        // If the hypervisor vendor name is asked, return our hypervisor name.
        regs.ebx = OUR_HV_VENDOR_NAME_EBX;
        regs.ecx = OUR_HV_VENDOR_NAME_ECX;
        regs.edx = OUR_HV_VENDOR_NAME_EDX;
    } else if leaf == 1 {
        // On the Intel processor, CPUID.1.ECX[5] indicates if VT-x is supported.
        // Clear this to prevent other hypervisor tries to use it. On AMD, it is
        // a reserved bit.
        // See: Table 3-10. Feature Information Returned in the ECX Register
        regs.ecx &= !(1 << 5);
    } else if leaf == HV_CPUID_INTERFACE {
        // If the VM asks whether Hyper-V enlightenment is supported, say no.
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
    let xcr: u32 = vm.regs().rcx as u32;
    let value = (vm.regs().rax & 0xffff_ffff) | ((vm.regs().rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);
    xsetbv(xcr, value);

    vm.regs().rip = info.next_rip;
}
