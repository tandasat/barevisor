use x86::{
    controlregs::{Cr4, Xcr0},
    cpuid::cpuid,
    vmx::vmcs,
};

use crate::{
    hypervisor::{
        init::handle_init_signal,
        intel::vmcs::{vmread, vmwrite},
        VmExitReason, HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME,
    },
    utils::{
        capture_registers::GuestRegisters,
        x86_instructions::{cr4, cr4_write, rdmsr, wrmsr, xsetbv},
    },
};

use crate::hypervisor::Extension;

use super::{amd::Amd, intel::Intel, InstrInterceptionQualification, VirtualMachine};

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

fn virtualize_core<T: super::Architecture>(params: &VCpuParameters) -> ! {
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
            VmExitReason::Init => handle_init_signal(vm),
            VmExitReason::Sipi => handle_sipi_signal(vm),
            VmExitReason::NothingToDo => {}
        }
    }
}

fn handle_cpuid<T: VirtualMachine>(vm: &mut T, info: &InstrInterceptionQualification) {
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

fn handle_rdmsr<T: VirtualMachine>(vm: &mut T, info: &InstrInterceptionQualification) {
    let msr = vm.regs().rcx as u32;
    log::trace!("RDMSR {msr:#x?}");
    let value = rdmsr(msr);

    vm.regs().rax = value & 0xffff_ffff;
    vm.regs().rdx = value >> 32;
    vm.regs().rip = info.next_rip;
}

fn handle_wrmsr<T: VirtualMachine>(vm: &mut T, info: &InstrInterceptionQualification) {
    let msr = vm.regs().rcx as u32;
    let value = (vm.regs().rax & 0xffff_ffff) | ((vm.regs().rdx & 0xffff_ffff) << 32);
    log::trace!("WRMSR {msr:#x?} {value:#x?}");
    wrmsr(msr, value);

    vm.regs().rip = info.next_rip;
}

fn handle_xsetbv<T: VirtualMachine>(vm: &mut T, info: &InstrInterceptionQualification) {
    let regs = vm.regs();
    let xcr: u32 = regs.rcx as u32;
    let value = (regs.rax & 0xffff_ffff) | ((regs.rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);
    xsetbv(xcr, value);

    regs.rip = info.next_rip;
}

/// Represents the activity state of a logical processor in VMX operation.
#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum GuestActivityState {
    /// The logical processor is executing instructions normally.
    Active = 0x00000000,

    /// The logical processor is inactive because it executed the HLT instruction.
    Hlt = 0x00000001,

    /// The logical processor is inactive because it incurred a triple fault
    /// or some other serious error.
    Shutdown = 0x00000002,

    /// The logical processor is inactive because it is waiting for a startup-IPI (SIPI).
    WaitForSipi = 0x00000003,
}

fn handle_sipi_signal<T: VirtualMachine>(vm: &mut T) {
    let vector = vmread(vmcs::ro::EXIT_QUALIFICATION);

    vmwrite(vmcs::guest::CS_SELECTOR, vector << 8);
    vmwrite(vmcs::guest::CS_BASE, vector << 12);
    vm.regs().rip = 0;
    vmwrite(vmcs::guest::RIP, vm.regs().rip);

    vmwrite(
        vmcs::guest::ACTIVITY_STATE,
        GuestActivityState::Active as u32,
    );
}
