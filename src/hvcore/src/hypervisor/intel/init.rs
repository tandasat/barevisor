//! Provides VMX signal handling and control register adjustment.
//!
//! Includes functionality for responding to INIT signals in a virtualized environment and adjusting
//! control registers (CR0, CR4) to meet VMX operation requirements. Essential for virtual machine initialization
//! and maintaining correct processor states.
//! Credits to Satoshi Tanada: https://github.com/tandasat/MiniVisorPkg/blob/master/Sources/HostMain.c

use {
    super::vmx::GuestActivityState,
    crate::{
        hypervisor::intel::vmcs::{vmread, vmwrite},
        hypervisor::x86_instructions::rdmsr,
    },
    x86::{
        bits64::rflags,
        controlregs::{cr2_write, Cr0},
        debugregs::{dr0_write, dr1_write, dr2_write, dr3_write, dr6_write, Dr6},
        msr::{IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1},
        segmentation::{CodeSegmentType, DataSegmentType, SystemDescriptorTypes64},
        vmx::vmcs::{self, control::SecondaryControls},
    },
    x86_64::registers::control::Cr4Flags,
};

/// Handles the INIT signal by initializing processor state according to Intel SDM.
///
/// Initializes the guest's processor state to mimic the state after receiving an INIT signal, including
/// setting registers and segment selectors to their startup values. This ensures the guest VM is correctly
/// initialized in line with the MP initialization protocol.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers.
///
/// # Returns
///
/// Returns `ExitType::Continue` to indicate the VM should continue execution post-initialization.
pub(crate) fn handle_init_signal<T: crate::hypervisor::VirtualMachine>(vm: &mut T) {
    //
    // Initializes the processor to the state after INIT as described in the Intel SDM.
    //

    //
    // See: Table 9-1. IA-32 and Intel 64 Processor States Following Power-up, Reset, or INIT
    //
    vm.regs().rflags = rflags::RFlags::FLAGS_A1.bits();
    vmwrite(vmcs::guest::RFLAGS, vm.regs().rflags);
    vm.regs().rip = 0xfff0u64;
    vmwrite(vmcs::guest::RIP, vm.regs().rip);
    vmwrite(vmcs::control::CR0_READ_SHADOW, 0u64);
    unsafe { cr2_write(0) };
    vmwrite(vmcs::guest::CR3, 0u64);
    vmwrite(vmcs::control::CR4_READ_SHADOW, 0u64);

    //
    // Actual guest CR0 and CR4 must fulfill requirements for VMX. Apply those.
    //
    vmwrite(vmcs::guest::CR0, adjust_guest_cr0(Cr0::CR0_EXTENSION_TYPE));
    vmwrite(vmcs::guest::CR4, adjust_cr4());

    //
    // Set the CS segment registers to their initial state (ExecuteReadAccessed).
    //
    let mut access_rights = VmxSegmentAccessRights(0);
    access_rights.set_segment_type(CodeSegmentType::ExecuteReadAccessed as u32);
    access_rights.set_descriptor_type(true);
    access_rights.set_present(true);

    vmwrite(vmcs::guest::CS_SELECTOR, 0xf000u64);
    vmwrite(vmcs::guest::CS_BASE, 0xffff_0000u64);
    vmwrite(vmcs::guest::CS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, access_rights.0);

    //
    // Set the SS segment registers to their initial state (ReadWriteAccessed).
    //
    access_rights.set_segment_type(DataSegmentType::ReadWriteAccessed as u32);
    vmwrite(vmcs::guest::SS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::SS_BASE, 0u64);
    vmwrite(vmcs::guest::SS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, access_rights.0);

    //
    // Set the DS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::DS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::DS_BASE, 0u64);
    vmwrite(vmcs::guest::DS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, access_rights.0);

    //
    // Set the ES segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::ES_SELECTOR, 0u64);
    vmwrite(vmcs::guest::ES_BASE, 0u64);
    vmwrite(vmcs::guest::ES_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, access_rights.0);

    //
    // Set the FS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::FS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::FS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, access_rights.0);

    //
    // Set the GS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::GS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, access_rights.0);

    //
    // Execute CPUID instruction on the host and retrieve the result
    //
    let extended_model_id = get_cpuid_feature_info().extended_model_id();
    vm.regs().rdx = 0x600 | ((extended_model_id as u64) << 16);
    vm.regs().rax = 0x0;
    vm.regs().rbx = 0x0;
    vm.regs().rcx = 0x0;
    vm.regs().rsi = 0x0;
    vm.regs().rdi = 0x0;
    vm.regs().rbp = 0x0;

    // RSP
    vm.regs().rsp = 0x0u64;
    vmwrite(vmcs::guest::RSP, vm.regs().rsp);

    //
    // Handle GDTR and IDTR
    //
    vmwrite(vmcs::guest::GDTR_BASE, 0u64);
    vmwrite(vmcs::guest::GDTR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::IDTR_BASE, 0u64);
    vmwrite(vmcs::guest::IDTR_LIMIT, 0xffffu64);

    //
    // Handle LDTR
    //
    access_rights.set_segment_type(SystemDescriptorTypes64::LDT as u32);
    access_rights.set_descriptor_type(false);
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::LDTR_BASE, 0u64);
    vmwrite(vmcs::guest::LDTR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, access_rights.0);

    //
    // Handle TR
    //
    access_rights.set_segment_type(SystemDescriptorTypes64::TssBusy as u32);
    vmwrite(vmcs::guest::TR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::TR_BASE, 0u64);
    vmwrite(vmcs::guest::TR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, access_rights.0);

    //
    // DR0, DR1, DR2, DR3, DR6, DR7
    //
    unsafe {
        dr0_write(0);
        dr1_write(0);
        dr2_write(0);
        dr3_write(0);
        dr6_write(Dr6::from_bits_unchecked(0xffff0ff0));
    };
    vmwrite(vmcs::guest::DR7, 0x400u64);

    //
    // Set the guest registers r8-r15 to 0.
    //
    vm.regs().r8 = 0u64;
    vm.regs().r9 = 0u64;
    vm.regs().r10 = 0u64;
    vm.regs().r11 = 0u64;
    vm.regs().r12 = 0u64;
    vm.regs().r13 = 0u64;
    vm.regs().r14 = 0u64;
    vm.regs().r15 = 0u64;

    //
    // Those registers are supposed to be cleared but that is not implemented here.
    //  - IA32_XSS
    //  - BNDCFGU
    //  - BND0-BND3
    //  - IA32_BNDCFGS

    //
    // Set Guest EFER, FS_BASE and GS_BASE to 0.
    //
    vmwrite(vmcs::guest::IA32_EFER_FULL, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);

    //
    // Set IA32E_MODE_GUEST to 0. from_bits_truncate will fail
    //
    let mut vmentry_controls = vmread(vmcs::control::VMENTRY_CONTROLS);
    vmentry_controls &= !(vmcs::control::EntryControls::IA32E_MODE_GUEST.bits() as u64); // Clear the IA32E_MODE_GUEST bit
    vmwrite(vmcs::control::VMENTRY_CONTROLS, vmentry_controls);

    //
    // Invalidate TLB for current VPID
    //
    //invvpid_single_context(vmread(vmcs::control::VPID) as _);

    //
    // Set the activity state to "Wait for SIPI".
    //
    vmwrite(
        vmcs::guest::ACTIVITY_STATE,
        GuestActivityState::WaitForSipi as u32,
    );
}

/// Adjusts guest CR0 considering UnrestrictedGuest feature and fixed MSRs.
///
/// Modifies the guest's CR0 register to ensure it meets VMX operation constraints, particularly
/// when the UnrestrictedGuest feature is enabled. Adjusts for protection and paging enable bits.
///
/// # Arguments
///
/// - `cr0`: The original CR0 register value from the guest.
///
/// # Returns
///
/// Returns the adjusted CR0 value as a `u64`.
fn adjust_guest_cr0(cr0: Cr0) -> u64 {
    // Adjust the CR0 register according to the fixed0 and fixed1 MSR values.
    let mut new_cr0 = adjust_cr0(cr0);

    // Read the secondary processor-based VM-execution controls to check for UnrestrictedGuest support.
    let secondary_proc_based_ctls2 = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let unrestricted_guest =
        secondary_proc_based_ctls2 as u32 & SecondaryControls::UNRESTRICTED_GUEST.bits() != 0;

    if unrestricted_guest {
        // if the guest is unrestricted, only set these bits if the guest requested them to be set
        new_cr0 &= !(Cr0::CR0_PROTECTED_MODE | Cr0::CR0_ENABLE_PAGING);
        new_cr0 |= cr0 & (Cr0::CR0_PROTECTED_MODE | Cr0::CR0_ENABLE_PAGING);
    }

    new_cr0.bits() as u64
}

/// Adjusts guest CR0 considering UnrestrictedGuest feature and fixed MSRs.
///
/// Modifies the guest's CR0 register to ensure it meets VMX operation constraints, particularly
/// when the UnrestrictedGuest feature is enabled. Adjusts for protection and paging enable bits.
///
/// # Arguments
///
/// - `cr0`: The original CR0 register value from the guest.
///
/// # Returns
///
/// Returns the adjusted CR0 value as a `u64`.
fn adjust_cr0(cr0: Cr0) -> Cr0 {
    let fixed0_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED0) as usize);
    let fixed1_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED1) as usize);
    (cr0 & fixed1_cr0) | fixed0_cr0
}

/// Adjusts CR4 for VMX operation, considering fixed bit requirements.
///
/// Sets or clears CR4 bits based on the IA32_VMX_CR4_FIXED0/1 MSRs to ensure the register
/// meets VMX operation constraints.
///
/// # Returns
///
/// Returns the adjusted CR4 value as a `u64`.
fn adjust_cr4() -> u64 {
    let fixed0_cr4 = Cr4Flags::from_bits_truncate(rdmsr(IA32_VMX_CR4_FIXED0));
    let zero_cr4 = Cr4Flags::empty();
    let new_cr4 =
        (zero_cr4 & Cr4Flags::from_bits_truncate(rdmsr(IA32_VMX_CR4_FIXED1))) | fixed0_cr4;
    new_cr4.bits()
}

/// Retrieves CPU feature information using the CPUID instruction.
///
/// Executes the CPUID instruction to obtain various feature information about the processor,
/// which can be used for further adjustments and checks in the virtualization context.
///
/// # Returns
///
/// Returns a `FeatureInfo` struct containing the CPU feature information.
fn get_cpuid_feature_info() -> x86::cpuid::FeatureInfo {
    let cpuid = x86::cpuid::CpuId::new();
    cpuid.get_feature_info().unwrap()
}

bitfield::bitfield! {
    /// Represents the VMX Segment Access Rights, as detailed in Intel's Software Developer's Manual,
    /// specifically in Section 25.4.1 Guest Register State.
    ///
    /// This struct encapsulates the access rights associated with a segment selector in a VMX operation,
    /// which includes properties such as the segment type, privilege level, and presence. These rights are
    /// crucial for the proper setup and control of guest and host segments in virtualization environments.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual.
    #[derive(Clone, Copy)]
    pub struct VmxSegmentAccessRights(u32);
    impl Debug;

    /// Extracts or sets the segment type (bits 3:0). This field specifies the type of segment or gate descriptor,
    /// including data, code, system segments, etc. The exact meaning of these bits varies based on the descriptor
    /// type (system, code, or data).
    pub segment_type, set_segment_type: 3, 0;

    /// Indicates the descriptor type (bit 4). A value of 0 signifies a system descriptor (like LDT or TSS),
    /// while 1 signifies a code or data descriptor. This distinction affects the interpretation of other fields
    /// in the descriptor.
    pub descriptor_type, set_descriptor_type: 4;

    /// Represents the Descriptor Privilege Level (DPL, bits 6:5). This specifies the privilege level of the segment,
    /// ranging from 0 (highest privilege, kernel) to 3 (lowest privilege, user applications).
    pub descriptor_privilege_level, set_descriptor_privilege_level: 6, 5;

    /// Indicates whether the segment is present (bit 7). If this bit is cleared, any attempt to access the segment
    /// results in a segment not present exception (#NP). This bit is used to control loading of segments that
    /// might not be currently available in memory.
    pub present, set_present: 7;

    /// Reserved bits (11:8). These bits are reserved and should not be modified. They are present for alignment
    /// and future compatibility.

    /// Available for use by system software (bit 12). This bit is available for use by system software and does not
    /// have a defined meaning in the VMX operation. It can be used by hypervisors to store additional information.
    pub available, set_available: 12;

    /// Indicates 64-bit mode active (for CS only, bit 13). For the CS segment, setting this bit indicates that
    /// the segment is running in 64-bit mode (long mode). This bit is ignored for other segment types.
    pub long_mode, set_long_mode: 13;

    /// Default operation size (D/B, bit 14). For code segments, this bit controls the default operation size
    /// (0 for 16-bit, 1 for 32-bit). For stack segments (SS), it controls the stack pointer size.
    pub default_big, set_default_big: 14;

    /// Granularity (bit 15). When set, the segment limit is scaled by 4K, allowing for larger segments.
    /// This bit is used in conjunction with the segment limit field to determine the actual size of the segment.
    pub granularity, set_granularity: 15;

    /// Indicates if the segment is unusable (bit 16). If set, the segment cannot be used for memory access.
    /// An unusable segment is typically one that has been loaded with a null selector.
    pub unusable, set_unusable: 16;

    // Reserved bits (31:17). These bits are reserved for future use and should always be cleared to ensure
    // compatibility with future processors.
}
