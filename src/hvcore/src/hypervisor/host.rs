use x86::{
    controlregs::{Cr4, Xcr0},
    cpuid::cpuid,
};

use crate::hypervisor::{
    apic_id,
    registers::Registers,
    x86_instructions::{cr4, cr4_write, rdmsr, wrmsr, xsetbv},
    HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME_EBX,
    OUR_HV_VENDOR_NAME_ECX, OUR_HV_VENDOR_NAME_EDX,
};

use super::{amd::Amd, intel::Intel};

/// The entry point of the hypervisor.
pub(crate) fn main(registers: &Registers) -> ! {
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        virtualize_core::<Intel>(registers)
    } else {
        virtualize_core::<Amd>(registers)
    }
}

// Enables the virtualization extension, sets up and runs the guest indefinitely.
fn virtualize_core<Arch: Architecture>(registers: &Registers) -> ! {
    log::info!("Initializing the guest");

    // Enable processor's virtualization features.
    let mut vt = Arch::VirtualizationExtension::default();
    vt.enable();

    // Create a new (empty) guest instance and set up its initial state.
    let id = apic_id::processor_id_from(apic_id::get()).unwrap();
    let guest = &mut Arch::Guest::new(id);
    guest.activate();
    guest.initialize(registers);

    // Then, run the guest until events that the hypervisor (this code) needs to
    // handle occurs.
    log::info!("Starting the guest");
    loop {
        match guest.run() {
            VmExitReason::Cpuid(info) => handle_cpuid(guest, &info),
            VmExitReason::Rdmsr(info) => handle_rdmsr(guest, &info),
            VmExitReason::Wrmsr(info) => handle_wrmsr(guest, &info),
            VmExitReason::XSetBv(info) => handle_xsetbv(guest, &info),
            VmExitReason::InitSignal | VmExitReason::StartupIpi | VmExitReason::NestedPageFault => {
            }
        }
    }
}

fn handle_cpuid<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let leaf = guest.regs().rax as u32;
    let sub_leaf = guest.regs().rcx as u32;
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
        // If the guest asks whether Hyper-V enlightenment is supported, say no.
        regs.eax = 0;
    }

    guest.regs().rax = u64::from(regs.eax);
    guest.regs().rbx = u64::from(regs.ebx);
    guest.regs().rcx = u64::from(regs.ecx);
    guest.regs().rdx = u64::from(regs.edx);
    guest.regs().rip = info.next_rip;
}

fn handle_rdmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    log::trace!("RDMSR {msr:#x?}");
    let value = rdmsr(msr);

    guest.regs().rax = value & 0xffff_ffff;
    guest.regs().rdx = value >> 32;
    guest.regs().rip = info.next_rip;
}

fn handle_wrmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    log::trace!("WRMSR {msr:#x?} {value:#x?}");
    wrmsr(msr, value);

    guest.regs().rip = info.next_rip;
}

fn handle_xsetbv<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let xcr: u32 = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);
    xsetbv(xcr, value);

    guest.regs().rip = info.next_rip;
}

pub(crate) trait Architecture {
    type VirtualizationExtension: Extension;
    type Guest: Guest;
}

pub(crate) trait Extension: Default {
    fn enable(&mut self);
}

pub(crate) trait Guest {
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
