use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
};
use x86::{bits64::rflags::RFlags, current::paging::BASE_PAGE_SIZE, vmx::vmcs};

use crate::hypervisor::{platform_ops, support::zeroed_box, x86_instructions::rdmsr};

#[derive(Default)]
pub(crate) struct Vmcs {
    ptr: Box<VmcsRaw>,
}

impl Vmcs {
    pub(crate) fn new() -> Self {
        let mut vmcs = zeroed_box::<VmcsRaw>();
        vmcs.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as _;
        Self { ptr: vmcs }
    }
}

impl core::ops::Deref for Vmcs {
    type Target = VmcsRaw;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

impl core::ops::DerefMut for Vmcs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ptr
    }
}

/// The region of memory that the logical processor uses to represent a virtual
/// CPU. Called virtual-machine control data structure (VMCS).
///
/// See: 25.2 FORMAT OF THE VMCS REGION
#[derive(derivative::Derivative)]
#[derivative(Default, Debug)]
#[repr(C, align(4096))]
pub(crate) struct VmcsRaw {
    revision_id: u32,
    abort_indicator: u32,
    #[derivative(Default(value = "[0; 4088]"), Debug = "ignore")]
    data: [u8; 4088],
}
const _: () = assert!(core::mem::size_of::<VmcsRaw>() == BASE_PAGE_SIZE);

/// The wrapper of the VMCLEAR instruction.
pub(crate) fn vmclear(vmcs_region: &mut VmcsRaw) {
    let va = vmcs_region as *const _;
    let pa = platform_ops::get().pa(va as *const _);

    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmclear(pa).unwrap() };
}

/// The wrapper of the VMPTRLD instruction.
pub(crate) fn vmptrld(vmcs_region: &mut VmcsRaw) {
    let va = vmcs_region as *const _;
    let pa = platform_ops::get().pa(va as *const _);

    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmptrld(pa).unwrap() }
}

/// The wrapper of the VMREAD instruction.
pub(crate) fn vmread(encoding: u32) -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmread(encoding) }.unwrap()
}

/// The wrapper of the VMREAD instruction. Returns zero on error.
fn vmread_relaxed(encoding: u32) -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmread(encoding) }.unwrap_or(0)
}

/// The wrapper of the VMWRITE instruction.
pub(crate) fn vmwrite<T: Into<u64>>(encoding: u32, value: T)
where
    u64: From<T>,
{
    let value = u64::from(value);
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmwrite(encoding, value) }
        .unwrap_or_else(|_| panic!("Could not write {value:x?} to {encoding:x?}"));
}

/// Checks that the latest VMX instruction succeeded.
///
/// See: 31.2 CONVENTIONS
pub(crate) fn vmx_succeed(flags: RFlags) -> Result<(), String> {
    if flags.contains(RFlags::FLAGS_ZF) {
        // See: 31.4 VM INSTRUCTION ERROR NUMBERS
        Err(format!(
            "VmFailValid with {}",
            vmread(vmcs::ro::VM_INSTRUCTION_ERROR)
        ))
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err("VmFailInvalid".to_string())
    } else {
        Ok(())
    }
}

impl core::fmt::Debug for Vmcs {
    #[rustfmt::skip]
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, format: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Dump the current VMCS. Not that this is not exhaustive.
        format.debug_struct("Vmcs")
        .field("Current VMCS", &(self as *const _))
        .field("Revision ID", &self.revision_id)

        // 16-Bit Guest-State Fields
        .field("Guest ES Selector                              ", &vmread_relaxed(vmcs::guest::ES_SELECTOR))
        .field("Guest CS Selector                              ", &vmread_relaxed(vmcs::guest::CS_SELECTOR))
        .field("Guest SS Selector                              ", &vmread_relaxed(vmcs::guest::SS_SELECTOR))
        .field("Guest DS Selector                              ", &vmread_relaxed(vmcs::guest::DS_SELECTOR))
        .field("Guest FS Selector                              ", &vmread_relaxed(vmcs::guest::FS_SELECTOR))
        .field("Guest GS Selector                              ", &vmread_relaxed(vmcs::guest::GS_SELECTOR))
        .field("Guest LDTR Selector                            ", &vmread_relaxed(vmcs::guest::LDTR_SELECTOR))
        .field("Guest TR Selector                              ", &vmread_relaxed(vmcs::guest::TR_SELECTOR))
        .field("Guest interrupt status                         ", &vmread_relaxed(vmcs::guest::INTERRUPT_STATUS))
        .field("PML index                                      ", &vmread_relaxed(vmcs::guest::PML_INDEX))

        // 64-Bit Guest-State Fields
        .field("VMCS link pointer                              ", &vmread_relaxed(vmcs::guest::LINK_PTR_FULL))
        .field("Guest IA32_DEBUGCTL                            ", &vmread_relaxed(vmcs::guest::IA32_DEBUGCTL_FULL))
        .field("Guest IA32_PAT                                 ", &vmread_relaxed(vmcs::guest::IA32_PAT_FULL))
        .field("Guest IA32_EFER                                ", &vmread_relaxed(vmcs::guest::IA32_EFER_FULL))
        .field("Guest IA32_PERF_GLOBAL_CTRL                    ", &vmread_relaxed(vmcs::guest::IA32_PERF_GLOBAL_CTRL_FULL))
        .field("Guest PDPTE0                                   ", &vmread_relaxed(vmcs::guest::PDPTE0_FULL))
        .field("Guest PDPTE1                                   ", &vmread_relaxed(vmcs::guest::PDPTE1_FULL))
        .field("Guest PDPTE2                                   ", &vmread_relaxed(vmcs::guest::PDPTE2_FULL))
        .field("Guest PDPTE3                                   ", &vmread_relaxed(vmcs::guest::PDPTE3_FULL))
        .field("Guest IA32_BNDCFGS                             ", &vmread_relaxed(vmcs::guest::IA32_BNDCFGS_FULL))
        .field("Guest IA32_RTIT_CTL                            ", &vmread_relaxed(vmcs::guest::IA32_RTIT_CTL_FULL))

        // 32-Bit Guest-State Fields
        .field("Guest ES Limit                                 ", &vmread_relaxed(vmcs::guest::ES_LIMIT))
        .field("Guest CS Limit                                 ", &vmread_relaxed(vmcs::guest::CS_LIMIT))
        .field("Guest SS Limit                                 ", &vmread_relaxed(vmcs::guest::SS_LIMIT))
        .field("Guest DS Limit                                 ", &vmread_relaxed(vmcs::guest::DS_LIMIT))
        .field("Guest FS Limit                                 ", &vmread_relaxed(vmcs::guest::FS_LIMIT))
        .field("Guest GS Limit                                 ", &vmread_relaxed(vmcs::guest::GS_LIMIT))
        .field("Guest LDTR Limit                               ", &vmread_relaxed(vmcs::guest::LDTR_LIMIT))
        .field("Guest TR Limit                                 ", &vmread_relaxed(vmcs::guest::TR_LIMIT))
        .field("Guest GDTR limit                               ", &vmread_relaxed(vmcs::guest::GDTR_LIMIT))
        .field("Guest IDTR limit                               ", &vmread_relaxed(vmcs::guest::IDTR_LIMIT))
        .field("Guest ES access rights                         ", &vmread_relaxed(vmcs::guest::ES_ACCESS_RIGHTS))
        .field("Guest CS access rights                         ", &vmread_relaxed(vmcs::guest::CS_ACCESS_RIGHTS))
        .field("Guest SS access rights                         ", &vmread_relaxed(vmcs::guest::SS_ACCESS_RIGHTS))
        .field("Guest DS access rights                         ", &vmread_relaxed(vmcs::guest::DS_ACCESS_RIGHTS))
        .field("Guest FS access rights                         ", &vmread_relaxed(vmcs::guest::FS_ACCESS_RIGHTS))
        .field("Guest GS access rights                         ", &vmread_relaxed(vmcs::guest::GS_ACCESS_RIGHTS))
        .field("Guest LDTR access rights                       ", &vmread_relaxed(vmcs::guest::LDTR_ACCESS_RIGHTS))
        .field("Guest TR access rights                         ", &vmread_relaxed(vmcs::guest::TR_ACCESS_RIGHTS))
        .field("Guest interruptibility state                   ", &vmread_relaxed(vmcs::guest::INTERRUPTIBILITY_STATE))
        .field("Guest activity state                           ", &vmread_relaxed(vmcs::guest::ACTIVITY_STATE))
        .field("Guest SMBASE                                   ", &vmread_relaxed(vmcs::guest::SMBASE))
        .field("Guest IA32_SYSENTER_CS                         ", &vmread_relaxed(vmcs::guest::IA32_SYSENTER_CS))
        .field("VMX-preemption timer value                     ", &vmread_relaxed(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE))

        // Natural-Width Guest-State Fields
        .field("Guest CR0                                      ", &vmread_relaxed(vmcs::guest::CR0))
        .field("Guest CR3                                      ", &vmread_relaxed(vmcs::guest::CR3))
        .field("Guest CR4                                      ", &vmread_relaxed(vmcs::guest::CR4))
        .field("Guest ES Base                                  ", &vmread_relaxed(vmcs::guest::ES_BASE))
        .field("Guest CS Base                                  ", &vmread_relaxed(vmcs::guest::CS_BASE))
        .field("Guest SS Base                                  ", &vmread_relaxed(vmcs::guest::SS_BASE))
        .field("Guest DS Base                                  ", &vmread_relaxed(vmcs::guest::DS_BASE))
        .field("Guest FS Base                                  ", &vmread_relaxed(vmcs::guest::FS_BASE))
        .field("Guest GS Base                                  ", &vmread_relaxed(vmcs::guest::GS_BASE))
        .field("Guest LDTR base                                ", &vmread_relaxed(vmcs::guest::LDTR_BASE))
        .field("Guest TR base                                  ", &vmread_relaxed(vmcs::guest::TR_BASE))
        .field("Guest GDTR base                                ", &vmread_relaxed(vmcs::guest::GDTR_BASE))
        .field("Guest IDTR base                                ", &vmread_relaxed(vmcs::guest::IDTR_BASE))
        .field("Guest DR7                                      ", &vmread_relaxed(vmcs::guest::DR7))
        .field("Guest RSP                                      ", &vmread_relaxed(vmcs::guest::RSP))
        .field("Guest RIP                                      ", &vmread_relaxed(vmcs::guest::RIP))
        .field("Guest RFLAGS                                   ", &vmread_relaxed(vmcs::guest::RFLAGS))
        .field("Guest pending debug exceptions                 ", &vmread_relaxed(vmcs::guest::PENDING_DBG_EXCEPTIONS))
        .field("Guest IA32_SYSENTER_ESP                        ", &vmread_relaxed(vmcs::guest::IA32_SYSENTER_ESP))
        .field("Guest IA32_SYSENTER_EIP                        ", &vmread_relaxed(vmcs::guest::IA32_SYSENTER_EIP))

        // 16-Bit Host-State Fields
        .field("Host ES Selector                               ", &vmread_relaxed(vmcs::host::ES_SELECTOR))
        .field("Host CS Selector                               ", &vmread_relaxed(vmcs::host::CS_SELECTOR))
        .field("Host SS Selector                               ", &vmread_relaxed(vmcs::host::SS_SELECTOR))
        .field("Host DS Selector                               ", &vmread_relaxed(vmcs::host::DS_SELECTOR))
        .field("Host FS Selector                               ", &vmread_relaxed(vmcs::host::FS_SELECTOR))
        .field("Host GS Selector                               ", &vmread_relaxed(vmcs::host::GS_SELECTOR))
        .field("Host TR Selector                               ", &vmread_relaxed(vmcs::host::TR_SELECTOR))

        // 64-Bit Host-State Fields
        .field("Host IA32_PAT                                  ", &vmread_relaxed(vmcs::host::IA32_PAT_FULL))
        .field("Host IA32_EFER                                 ", &vmread_relaxed(vmcs::host::IA32_EFER_FULL))
        .field("Host IA32_PERF_GLOBAL_CTRL                     ", &vmread_relaxed(vmcs::host::IA32_PERF_GLOBAL_CTRL_FULL))

        // 32-Bit Host-State Fields
        .field("Host IA32_SYSENTER_CS                          ", &vmread_relaxed(vmcs::host::IA32_SYSENTER_CS))

        // Natural-Width Host-State Fields
        .field("Host CR0                                       ", &vmread_relaxed(vmcs::host::CR0))
        .field("Host CR3                                       ", &vmread_relaxed(vmcs::host::CR3))
        .field("Host CR4                                       ", &vmread_relaxed(vmcs::host::CR4))
        .field("Host FS Base                                   ", &vmread_relaxed(vmcs::host::FS_BASE))
        .field("Host GS Base                                   ", &vmread_relaxed(vmcs::host::GS_BASE))
        .field("Host TR base                                   ", &vmread_relaxed(vmcs::host::TR_BASE))
        .field("Host GDTR base                                 ", &vmread_relaxed(vmcs::host::GDTR_BASE))
        .field("Host IDTR base                                 ", &vmread_relaxed(vmcs::host::IDTR_BASE))
        .field("Host IA32_SYSENTER_ESP                         ", &vmread_relaxed(vmcs::host::IA32_SYSENTER_ESP))
        .field("Host IA32_SYSENTER_EIP                         ", &vmread_relaxed(vmcs::host::IA32_SYSENTER_EIP))
        .field("Host RSP                                       ", &vmread_relaxed(vmcs::host::RSP))
        .field("Host RIP                                       ", &vmread_relaxed(vmcs::host::RIP))

        // 16-Bit Control Fields
        .field("Virtual-processor identifier                   ", &vmread_relaxed(vmcs::control::VPID))
        .field("Posted-interrupt notification vector           ", &vmread_relaxed(vmcs::control::POSTED_INTERRUPT_NOTIFICATION_VECTOR))
        .field("EPTP index                                     ", &vmread_relaxed(vmcs::control::EPTP_INDEX))

        // 64-Bit Control Fields
        .field("Address of I/O bitmap A                        ", &vmread_relaxed(vmcs::control::IO_BITMAP_A_ADDR_FULL))
        .field("Address of I/O bitmap B                        ", &vmread_relaxed(vmcs::control::IO_BITMAP_B_ADDR_FULL))
        .field("Address of MSR bitmaps                         ", &vmread_relaxed(vmcs::control::MSR_BITMAPS_ADDR_FULL))
        .field("VM-exit MSR-store address                      ", &vmread_relaxed(vmcs::control::VMEXIT_MSR_STORE_ADDR_FULL))
        .field("VM-exit MSR-load address                       ", &vmread_relaxed(vmcs::control::VMEXIT_MSR_LOAD_ADDR_FULL))
        .field("VM-entry MSR-load address                      ", &vmread_relaxed(vmcs::control::VMENTRY_MSR_LOAD_ADDR_FULL))
        .field("Executive-VMCS pointer                         ", &vmread_relaxed(vmcs::control::EXECUTIVE_VMCS_PTR_FULL))
        .field("PML address                                    ", &vmread_relaxed(vmcs::control::PML_ADDR_FULL))
        .field("TSC offset                                     ", &vmread_relaxed(vmcs::control::TSC_OFFSET_FULL))
        .field("Virtual-APIC address                           ", &vmread_relaxed(vmcs::control::VIRT_APIC_ADDR_FULL))
        .field("APIC-access address                            ", &vmread_relaxed(vmcs::control::APIC_ACCESS_ADDR_FULL))
        .field("Posted-interrupt descriptor address            ", &vmread_relaxed(vmcs::control::POSTED_INTERRUPT_DESC_ADDR_FULL))
        .field("VM-function controls                           ", &vmread_relaxed(vmcs::control::VM_FUNCTION_CONTROLS_FULL))
        .field("EPT pointer                                    ", &vmread_relaxed(vmcs::control::EPTP_FULL))
        .field("EOI-exit bitmap 0                              ", &vmread_relaxed(vmcs::control::EOI_EXIT0_FULL))
        .field("EOI-exit bitmap 1                              ", &vmread_relaxed(vmcs::control::EOI_EXIT1_FULL))
        .field("EOI-exit bitmap 2                              ", &vmread_relaxed(vmcs::control::EOI_EXIT2_FULL))
        .field("EOI-exit bitmap 3                              ", &vmread_relaxed(vmcs::control::EOI_EXIT3_FULL))
        .field("EPTP-list address                              ", &vmread_relaxed(vmcs::control::EPTP_LIST_ADDR_FULL))
        .field("VMREAD-bitmap address                          ", &vmread_relaxed(vmcs::control::VMREAD_BITMAP_ADDR_FULL))
        .field("VMWRITE-bitmap address                         ", &vmread_relaxed(vmcs::control::VMWRITE_BITMAP_ADDR_FULL))
        .field("Virtualization-exception information address   ", &vmread_relaxed(vmcs::control::VIRT_EXCEPTION_INFO_ADDR_FULL))
        .field("XSS-exiting bitmap                             ", &vmread_relaxed(vmcs::control::XSS_EXITING_BITMAP_FULL))
        .field("ENCLS-exiting bitmap                           ", &vmread_relaxed(vmcs::control::ENCLS_EXITING_BITMAP_FULL))
        .field("Sub-page-permission-table pointer              ", &vmread_relaxed(vmcs::control::SUBPAGE_PERM_TABLE_PTR_FULL))
        .field("TSC multiplier                                 ", &vmread_relaxed(vmcs::control::TSC_MULTIPLIER_FULL))

        // 32-Bit Control Fields
        .field("Pin-based VM-execution controls                ", &vmread_relaxed(vmcs::control::PINBASED_EXEC_CONTROLS))
        .field("Primary processor-based VM-execution controls  ", &vmread_relaxed(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS))
        .field("Exception bitmap                               ", &vmread_relaxed(vmcs::control::EXCEPTION_BITMAP))
        .field("Page-fault error-code mask                     ", &vmread_relaxed(vmcs::control::PAGE_FAULT_ERR_CODE_MASK))
        .field("Page-fault error-code match                    ", &vmread_relaxed(vmcs::control::PAGE_FAULT_ERR_CODE_MATCH))
        .field("CR3-target count                               ", &vmread_relaxed(vmcs::control::CR3_TARGET_COUNT))
        .field("Primary VM-exit controls                       ", &vmread_relaxed(vmcs::control::VMEXIT_CONTROLS))
        .field("VM-exit MSR-store count                        ", &vmread_relaxed(vmcs::control::VMEXIT_MSR_STORE_COUNT))
        .field("VM-exit MSR-load count                         ", &vmread_relaxed(vmcs::control::VMEXIT_MSR_LOAD_COUNT))
        .field("VM-entry controls                              ", &vmread_relaxed(vmcs::control::VMENTRY_CONTROLS))
        .field("VM-entry MSR-load count                        ", &vmread_relaxed(vmcs::control::VMENTRY_MSR_LOAD_COUNT))
        .field("VM-entry interruption-information field        ", &vmread_relaxed(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD))
        .field("VM-entry exception error code                  ", &vmread_relaxed(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE))
        .field("VM-entry instruction length                    ", &vmread_relaxed(vmcs::control::VMENTRY_INSTRUCTION_LEN))
        .field("TPR threshold                                  ", &vmread_relaxed(vmcs::control::TPR_THRESHOLD))
        .field("Secondary processor-based VM-execution controls", &vmread_relaxed(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS))
        .field("PLE_Gap                                        ", &vmread_relaxed(vmcs::control::PLE_GAP))
        .field("PLE_Window                                     ", &vmread_relaxed(vmcs::control::PLE_WINDOW))

        // Natural-Width Control Fields
        .field("CR0 guest/host mask                            ", &vmread_relaxed(vmcs::control::CR0_GUEST_HOST_MASK))
        .field("CR4 guest/host mask                            ", &vmread_relaxed(vmcs::control::CR4_GUEST_HOST_MASK))
        .field("CR0 read shadow                                ", &vmread_relaxed(vmcs::control::CR0_READ_SHADOW))
        .field("CR4 read shadow                                ", &vmread_relaxed(vmcs::control::CR4_READ_SHADOW))
        .field("CR3-target value 0                             ", &vmread_relaxed(vmcs::control::CR3_TARGET_VALUE0))
        .field("CR3-target value 1                             ", &vmread_relaxed(vmcs::control::CR3_TARGET_VALUE1))
        .field("CR3-target value 2                             ", &vmread_relaxed(vmcs::control::CR3_TARGET_VALUE2))
        .field("CR3-target value 3                             ", &vmread_relaxed(vmcs::control::CR3_TARGET_VALUE3))

        // 16-Bit Read-Only Data Fields

        // 64-Bit Read-Only Data Fields
        .field("Guest-physical address                         ", &vmread_relaxed(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL))

        // 32-Bit Read-Only Data Fields
        .field("VM-instruction error                           ", &vmread_relaxed(vmcs::ro::VM_INSTRUCTION_ERROR))
        .field("Exit reason                                    ", &vmread_relaxed(vmcs::ro::EXIT_REASON))
        .field("VM-exit interruption information               ", &vmread_relaxed(vmcs::ro::VMEXIT_INTERRUPTION_INFO))
        .field("VM-exit interruption error code                ", &vmread_relaxed(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE))
        .field("IDT-vectoring information field                ", &vmread_relaxed(vmcs::ro::IDT_VECTORING_INFO))
        .field("IDT-vectoring error code                       ", &vmread_relaxed(vmcs::ro::IDT_VECTORING_ERR_CODE))
        .field("VM-exit instruction length                     ", &vmread_relaxed(vmcs::ro::VMEXIT_INSTRUCTION_LEN))
        .field("VM-exit instruction information                ", &vmread_relaxed(vmcs::ro::VMEXIT_INSTRUCTION_INFO))

        // Natural-Width Read-Only Data Fields
        .field("Exit qualification                             ", &vmread_relaxed(vmcs::ro::EXIT_QUALIFICATION))
        .field("I/O RCX                                        ", &vmread_relaxed(vmcs::ro::IO_RCX))
        .field("I/O RSI                                        ", &vmread_relaxed(vmcs::ro::IO_RSI))
        .field("I/O RDI                                        ", &vmread_relaxed(vmcs::ro::IO_RDI))
        .field("I/O RIP                                        ", &vmread_relaxed(vmcs::ro::IO_RIP))
        .field("Guest-linear address                           ", &vmread_relaxed(vmcs::ro::GUEST_LINEAR_ADDR))
        .finish_non_exhaustive()
    }
}
