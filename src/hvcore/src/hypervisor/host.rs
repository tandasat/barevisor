//! This module implements architecture agnostic parts of the host code.

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
    // The processor runs on the setup for the host until launching the guest.
    // For example, if specified, the IDT may be that of the host, which only
    // panics on any exception and interrupt.
    //
    // Even if the existing IDT remains to be used (eg, the Windows driver setup),
    // interrupts should be disabled to ensure that the system registers do not
    // change while copying them one by one to the guest initial state.
    unsafe { x86::irq::disable() };

    // Start the host on the current processor.
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        virtualize_core::<Intel>(registers)
    } else {
        virtualize_core::<Amd>(registers)
    }
}

/// Enables the virtualization extension, sets up and runs the guest indefinitely.
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

    log::info!("Starting the guest");
    loop {
        // Then, run the guest until events that the host needs to handle occurs.
        // Some of events are handled within the architecture specific code and
        // nothing to do here.
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
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    if leaf == 1 {
        // On the Intel processor, CPUID.1.ECX[5] indicates if VT-x is supported.
        // Clear this to prevent other hypervisor tries to use it. On AMD, it is
        // a reserved bit.
        // See: Table 3-10. Feature Information Returned in the ECX Register
        cpuid_result.ecx &= !(1 << 5);
    } else if leaf == HV_CPUID_VENDOR_AND_MAX_FUNCTIONS {
        // If the hypervisor vendor name is asked, return our hypervisor name,
        // so that `is_our_hypervisor_present` can detect the presence.
        cpuid_result.ebx = OUR_HV_VENDOR_NAME_EBX;
        cpuid_result.ecx = OUR_HV_VENDOR_NAME_ECX;
        cpuid_result.edx = OUR_HV_VENDOR_NAME_EDX;
    } else if leaf == HV_CPUID_INTERFACE {
        // Return non "Hv#1" into EAX. This indicate that our hypervisor does NOT
        // conform to the Microsoft hypervisor interface. This prevents the guest
        // from using the interface for optimum performance, but simplifies
        // implementation of our hypervisor. This is required only when testing
        // in the virtualization platform that supports the Microsoft hypervisor
        // interface, such as VMware, and not required for a baremetal.
        // See: Hypervisor Top Level Functional Specification
        cpuid_result.eax = 0;
    }

    guest.regs().rax = u64::from(cpuid_result.eax);
    guest.regs().rbx = u64::from(cpuid_result.ebx);
    guest.regs().rcx = u64::from(cpuid_result.ecx);
    guest.regs().rdx = u64::from(cpuid_result.edx);
    guest.regs().rip = info.next_rip;
}

/// Handles the `RDMSR` instruction for the range not covered by MSR bitmaps.
fn handle_rdmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    log::trace!("RDMSR {msr:#x?}");

    // Passthrough any MSR access. Beware of that VM-exit occurs even for an
    // invalid MSR access which causes #GP(0).
    // See: 26.1.1 Relative Priority of Faults and VM Exits
    //
    // One solution is to catch the exception and inject it into the guest.
    let value = rdmsr(msr);

    guest.regs().rax = value & 0xffff_ffff;
    guest.regs().rdx = value >> 32;
    guest.regs().rip = info.next_rip;
}

/// Handles the `WRMSR` instruction for the range not covered by MSR bitmaps.
fn handle_wrmsr<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let msr = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    log::trace!("WRMSR {msr:#x?} {value:#x?}");

    // See the comment in `handle_rdmsr`.
    wrmsr(msr, value);

    guest.regs().rip = info.next_rip;
}

// Handles the `XSETBV` instruction.
fn handle_xsetbv<T: Guest>(guest: &mut T, info: &InstructionInfo) {
    let xcr: u32 = guest.regs().rcx as u32;
    let value = (guest.regs().rax & 0xffff_ffff) | ((guest.regs().rdx & 0xffff_ffff) << 32);
    let value = Xcr0::from_bits(value).unwrap();
    log::trace!("XSETBV {xcr:#x?} {value:#x?}");

    // The host CR4 might not have this bit, which is required for executing the
    // `XSETBV` instruction. Set this bit and run the instruction.
    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);

    // XCR may be invalid and this instruction may cause #GP(0). See the comment
    // in `handle_rdmsr`.
    xsetbv(xcr, value);

    guest.regs().rip = info.next_rip;
}

/// Represents a processor architecture that implements hardware-assisted virtualization.
pub(crate) trait Architecture {
    type VirtualizationExtension: Extension;
    type Guest: Guest;
}

/// Represents an implementation of a hardware-assisted virtualization extension.
pub(crate) trait Extension: Default {
    /// Enables the hardware-assisted virtualization extension.
    fn enable(&mut self);
}

/// Represents an implementation of a guest.
pub(crate) trait Guest {
    /// Creates an empty uninitialized guest, which must be activated with
    /// `activate` first.
    fn new(id: usize) -> Self;

    /// Tells the processor to operate on this guest. Must be called before any
    /// other functions are used.
    fn activate(&mut self);

    /// Initializes the guest based on `registers` and the current system register
    /// values.
    fn initialize(&mut self, registers: &Registers);

    /// Runs the guest until VM-exit occurs.
    fn run(&mut self) -> VmExitReason;

    /// Gets a reference to some of guest registers.
    fn regs(&mut self) -> &mut Registers;
}

/// The reasons of VM-exit and additional information.
pub(crate) enum VmExitReason {
    Cpuid(InstructionInfo),
    Rdmsr(InstructionInfo),
    Wrmsr(InstructionInfo),
    XSetBv(InstructionInfo),
    InitSignal,
    StartupIpi,
    NestedPageFault,
}

pub(crate) struct InstructionInfo {
    /// The next RIP of the guest in case the current instruction is emulated.
    pub(crate) next_rip: u64,
}
