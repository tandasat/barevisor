use alloc::boxed::Box;
use x86::controlregs::{Cr0, Cr4};

use crate::{
    hypervisor::intel::init::handle_init_signal,
    hypervisor::{
        platform_ops,
        support::zeroed_box,
        x86_instructions::{cr0, cr0_write, cr4, cr4_write, rdmsr, wrmsr},
    },
};

pub(crate) struct Vmx {
    vmxon_region: Vmxon,
    enabled: bool,
}

impl crate::hypervisor::Extension for Vmx {
    fn enable(&mut self) {
        self.enable_();
    }
}

impl Default for Vmx {
    fn default() -> Self {
        Self::new()
    }
}

impl Vmx {
    pub(crate) fn new() -> Self {
        Self {
            vmxon_region: Vmxon::new(),
            enabled: false,
        }
    }

    pub(crate) fn enable_(&mut self) {
        assert!(!self.enabled);
        Self::adjust_cr0();
        Self::adjust_cr4();
        Self::adjust_feature_control_msr();
        vmxon(self.vmxon_region.ptr.as_mut());
        self.enabled = true;
    }

    /// Updates the CR0 to satisfy the requirement for entering VMX operation.
    fn adjust_cr0() {
        // In order to enter VMX operation, some bits in CR0 (and CR4) have to be
        // set or cleared as indicated by the FIXED0 and FIXED1 MSRs. The rule is
        // summarized as below (taking CR0 as an example):
        //
        //        IA32_VMX_CR0_FIXED0 IA32_VMX_CR0_FIXED1 Meaning
        // Bit X  1                   (Always 1)          The bit X of CR0 is fixed to 1
        // Bit X  0                   1                   The bit X of CR0 is flexible
        // Bit X  (Always 0)          0                   The bit X of CR0 is fixed to 0
        //
        // Some UEFI implementations do not fullfil those requirements for CR0 and
        // need adjustments. The requirements for CR4 are always satisfied as far
        // as the author has experimented (although not guaranteed).
        //
        // See: A.7 VMX-FIXED BITS IN CR0
        // See: A.8 VMX-FIXED BITS IN CR4
        let fixed0cr0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
        let fixed1cr0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);
        let mut new_cr0 = cr0().bits() as u64;
        new_cr0 &= fixed1cr0;
        new_cr0 |= fixed0cr0;
        let new_cr0 = unsafe { Cr0::from_bits_unchecked(new_cr0 as usize) };
        cr0_write(new_cr0);
    }

    /// Updates the CR4 to satisfy the requirement for entering VMX operation.
    fn adjust_cr4() {
        let fixed0cr4 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED0);
        let fixed1cr4 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED1);
        let mut new_cr4 = cr4().bits() as u64;
        new_cr4 &= fixed1cr4;
        new_cr4 |= fixed0cr4;
        let new_cr4 = unsafe { Cr4::from_bits_unchecked(new_cr4 as usize) };
        cr4_write(new_cr4);
    }

    /// Updates an MSR to satisfy the requirement for entering VMX operation.
    fn adjust_feature_control_msr() {
        const IA32_FEATURE_CONTROL_LOCK_BIT_FLAG: u64 = 1 << 0;
        const IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG: u64 = 1 << 2;

        // If the lock bit is cleared, set it along with the VMXON-outside-SMX
        // operation bit. Without those two bits, the VMXON instruction fails. They
        // are normally set but not always, for example, Bochs with OVMF does not.
        // See: 23.7 ENABLING AND ENTERING VMX OPERATION
        let feature_control = rdmsr(x86::msr::IA32_FEATURE_CONTROL);
        if (feature_control & IA32_FEATURE_CONTROL_LOCK_BIT_FLAG) == 0 {
            wrmsr(
                x86::msr::IA32_FEATURE_CONTROL,
                feature_control
                    | IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG
                    | IA32_FEATURE_CONTROL_LOCK_BIT_FLAG,
            );
        }
    }
}

impl Drop for Vmx {
    fn drop(&mut self) {
        if self.enabled {
            vmxoff();
        }
    }
}
#[derive(Default)]

struct Vmxon {
    ptr: Box<VmxonRaw>,
}

impl Vmxon {
    fn new() -> Self {
        let mut vmxon = zeroed_box::<VmxonRaw>();
        vmxon.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as _;
        Self { ptr: vmxon }
    }
}

/// The region of memory that the logical processor uses to support VMX
/// operation.
///
/// See: 25.11.5 VMXON Region
#[derive(derivative::Derivative)]
#[derivative(Debug, Default)]
#[repr(C, align(4096))]
struct VmxonRaw {
    revision_id: u32,
    #[derivative(Debug = "ignore")]
    #[derivative(Default(value = "[0; 4092]"))]
    data: [u8; 4092],
}

/// The wrapper of the VMXON instruction.
fn vmxon(vmxon_region: &mut VmxonRaw) {
    let va = vmxon_region as *const _;
    let pa = platform_ops::get().pa(va as *const _);

    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmxon(pa).unwrap() };
}

/// The wrapper of the VMXOFF instruction.
fn vmxoff() {
    // Safety: this project runs at CPL0.
    unsafe { x86::current::vmx::vmxoff().unwrap() };
}

// ------------------- VM -------------

use core::arch::global_asm;
use spin::once::Once;
use x86::{
    current::rflags::RFlags,
    segmentation::{cs, ds, es, fs, gs, ss, SegmentSelector},
    vmx::vmcs,
};

use crate::{
    hypervisor::{
        capture_registers::GuestRegisters,
        segment::SegmentDescriptor,
        support::Page,
        x86_instructions::{cr3, lar, ldtr, lsl, sgdt, sidt, tr},
    },
    hypervisor::{
        intel::vmcs::{vmread, vmwrite, vmx_succeed},
        InstrInterceptionQualification, VmExitReason, HV_SHARED_DATA,
    },
};

use super::{
    epts::Epts,
    vmcs::{vmclear, vmptrld, Vmcs},
};

pub(crate) struct SharedVmData {
    pub(crate) msr_bitmaps: Box<Page>,
    pub(crate) epts: Box<Epts>,
}

/// A collection of data that the hypervisor depends on for its entire lifespan.
pub(crate) static SHARED_VM_DATA: Once<SharedVmData> = Once::new();

#[derive(Default)]
pub(crate) struct Vm {
    pub(crate) regs: GuestRegisters,
    id: usize,
    vmcs: Vmcs,
}

impl crate::hypervisor::VirtualMachine for Vm {
    fn new(id: u8) -> Self {
        let _ = SHARED_VM_DATA.call_once(|| {
            let mut epts = zeroed_box::<Epts>();
            epts.build_identify();

            SharedVmData {
                msr_bitmaps: zeroed_box::<Page>(),
                epts,
            }
        });

        Self {
            regs: GuestRegisters::default(),
            id: id as usize,
            vmcs: Vmcs::new(),
        }
    }
    fn activate(&mut self) {
        self.activate_();
    }
    fn initialize(&mut self, regs: &GuestRegisters) {
        self.regs = *regs;
        self.initialize_();
    }
    fn run(&mut self) -> VmExitReason {
        self.run_()
    }
    fn regs(&mut self) -> &mut GuestRegisters {
        &mut self.regs
    }
}

impl Vm {
    pub(crate) fn activate_(&mut self) {
        vmclear(&mut self.vmcs);
        vmptrld(&mut self.vmcs);
    }

    // Set the initial VM state from the current system state.
    pub(crate) fn initialize_(&self) {
        self.initialize_control();
        self.initialize_guest();
        self.initialize_host();
    }

    pub(crate) fn run_(&mut self) -> VmExitReason {
        const VMX_EXIT_REASON_INIT: u16 = 3;
        const VMX_EXIT_REASON_SIPI: u16 = 4;
        const VMX_EXIT_REASON_CPUID: u16 = 10;
        const VMX_EXIT_REASON_RDMSR: u16 = 31;
        const VMX_EXIT_REASON_WRMSR: u16 = 32;
        const VMX_EXIT_REASON_XSETBV: u16 = 55;

        vmwrite(vmcs::guest::RIP, self.regs.rip);
        vmwrite(vmcs::guest::RSP, self.regs.rsp);
        vmwrite(vmcs::guest::RFLAGS, self.regs.rflags);

        // Execute the VM until VM-exit occurs.
        log::trace!("Entering the VM");
        log::trace!("{:#x?}", self.regs);
        let flags = unsafe { run_vmx_vm(&mut self.regs) };
        if let Err(err) = vmx_succeed(RFlags::from_raw(flags)) {
            panic!("{err}");
        }
        self.regs.rip = vmread(vmcs::guest::RIP);
        self.regs.rsp = vmread(vmcs::guest::RSP);
        self.regs.rflags = vmread(vmcs::guest::RFLAGS);

        log::trace!("Exited the VM");
        log::trace!("{:#x?}", self.regs);

        // Return VM-exit reason.
        match vmread(vmcs::ro::EXIT_REASON) as u16 {
            VMX_EXIT_REASON_INIT => {
                handle_init_signal(self);
                VmExitReason::NothingToDo
            }

            VMX_EXIT_REASON_SIPI => {
                self.handle_sipi_signal();
                VmExitReason::NothingToDo
            }
            VMX_EXIT_REASON_CPUID => VmExitReason::Cpuid(InstrInterceptionQualification {
                next_rip: self.regs.rip + vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN),
            }),
            VMX_EXIT_REASON_RDMSR => VmExitReason::Rdmsr(InstrInterceptionQualification {
                next_rip: self.regs.rip + vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN),
            }),
            VMX_EXIT_REASON_WRMSR => VmExitReason::Wrmsr(InstrInterceptionQualification {
                next_rip: self.regs.rip + vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN),
            }),
            VMX_EXIT_REASON_XSETBV => VmExitReason::XSetBv(InstrInterceptionQualification {
                next_rip: self.regs.rip + vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN),
            }),
            _ => {
                log::error!("{:#x?}", self.vmcs);
                panic!(
                    "Unhandled VM-exit reason: {:?}",
                    vmread(vmcs::ro::EXIT_REASON)
                )
            }
        }
    }

    fn initialize_control(&self) {
        vmwrite(
            vmcs::control::VMEXIT_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::VmExit,
                vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as _,
            ),
        );
        vmwrite(
            vmcs::control::VMENTRY_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::VmEntry,
                vmcs::control::EntryControls::IA32E_MODE_GUEST.bits() as _,
            ),
        );
        vmwrite(
            vmcs::control::PINBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(VmxControl::PinBased, 0),
        );
        vmwrite(
            vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::ProcessorBased,
                (vmcs::control::PrimaryControls::USE_MSR_BITMAPS
                    | vmcs::control::PrimaryControls::SECONDARY_CONTROLS)
                    .bits() as _,
            ),
        );
        vmwrite(
            vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::ProcessorBased2,
                (vmcs::control::SecondaryControls::ENABLE_EPT
                    | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST
                    | vmcs::control::SecondaryControls::ENABLE_RDTSCP
                    | vmcs::control::SecondaryControls::ENABLE_INVPCID
                    | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS)
                    .bits() as _,
            ),
        );

        let shared_vm_data = SHARED_VM_DATA.get().unwrap();
        let va = shared_vm_data.msr_bitmaps.as_ref() as *const _;
        let pa = platform_ops::get().pa(va as *const _);
        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, pa);
        vmwrite(vmcs::control::EPTP_FULL, shared_vm_data.epts.eptp().0);
    }

    fn initialize_guest(&self) {
        let idtr = sidt();
        let gdtr = sgdt();

        // TODO: "as u*" vs "as _"
        // FIXME: snapshot should include those registers

        // SS reported as 0x0 on VMware time to time. What the heck?
        let ss = ss();
        log::warn!("{:x}", ss.bits());
        let ss = if ss.bits() == 0 {
            SegmentSelector::from_raw(0x18)
        } else {
            ss
        };

        vmwrite(vmcs::guest::ES_SELECTOR, es().bits());
        vmwrite(vmcs::guest::CS_SELECTOR, cs().bits());
        vmwrite(vmcs::guest::SS_SELECTOR, ss.bits());
        vmwrite(vmcs::guest::DS_SELECTOR, ds().bits());
        vmwrite(vmcs::guest::FS_SELECTOR, fs().bits());
        vmwrite(vmcs::guest::GS_SELECTOR, gs().bits());
        vmwrite(vmcs::guest::TR_SELECTOR, tr().bits());
        vmwrite(vmcs::guest::LDTR_SELECTOR, ldtr().bits());

        vmwrite(vmcs::guest::ES_LIMIT, lsl(es()));
        vmwrite(vmcs::guest::CS_LIMIT, lsl(cs()));
        vmwrite(vmcs::guest::SS_LIMIT, lsl(ss));
        vmwrite(vmcs::guest::DS_LIMIT, lsl(ds()));
        vmwrite(vmcs::guest::FS_LIMIT, lsl(fs()));
        vmwrite(vmcs::guest::GS_LIMIT, lsl(gs()));
        vmwrite(vmcs::guest::TR_LIMIT, lsl(tr()));
        //vmwrite(vmcs::guest::LDTR_LIMIT, lsl(ldtr())); // TODO: check

        vmwrite(
            vmcs::guest::ES_ACCESS_RIGHTS,
            Self::access_rights(lar(es())),
        );
        vmwrite(
            vmcs::guest::CS_ACCESS_RIGHTS,
            Self::access_rights(lar(cs())),
        );
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, Self::access_rights(lar(ss)));
        vmwrite(
            vmcs::guest::DS_ACCESS_RIGHTS,
            Self::access_rights(lar(ds())),
        );
        vmwrite(
            vmcs::guest::FS_ACCESS_RIGHTS,
            Self::access_rights(lar(fs())),
        );
        vmwrite(
            vmcs::guest::GS_ACCESS_RIGHTS,
            Self::access_rights(lar(gs())),
        );
        vmwrite(
            vmcs::guest::TR_ACCESS_RIGHTS,
            Self::access_rights(lar(tr())),
        );
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, Self::access_rights(0));

        vmwrite(vmcs::guest::FS_BASE, rdmsr(x86::msr::IA32_FS_BASE));
        vmwrite(vmcs::guest::GS_BASE, rdmsr(x86::msr::IA32_GS_BASE));
        vmwrite(
            vmcs::guest::TR_BASE,
            SegmentDescriptor::try_from_gdtr(&gdtr, tr())
                .unwrap()
                .base(),
        );
        //vmwrite(
        //    vmcs::guest::LDTR_BASE,
        //    SegmentDescriptor::try_from_gdtr(&gdtr, ldtr())
        //        .unwrap()
        //        .base(),
        //);

        vmwrite(vmcs::guest::GDTR_BASE, gdtr.base as u64);
        vmwrite(vmcs::guest::GDTR_LIMIT, gdtr.limit);
        vmwrite(vmcs::guest::IDTR_BASE, idtr.base as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, idtr.limit);

        vmwrite(
            vmcs::guest::IA32_DEBUGCTL_FULL,
            rdmsr(x86::msr::IA32_DEBUGCTL),
        );
        vmwrite(
            vmcs::guest::IA32_SYSENTER_CS,
            rdmsr(x86::msr::IA32_SYSENTER_CS),
        );
        vmwrite(
            vmcs::guest::IA32_SYSENTER_EIP,
            rdmsr(x86::msr::IA32_SYSENTER_EIP),
        );
        vmwrite(
            vmcs::guest::IA32_SYSENTER_ESP,
            rdmsr(x86::msr::IA32_SYSENTER_ESP),
        );

        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        vmwrite(vmcs::guest::CR0, cr0().bits() as u64);
        vmwrite(vmcs::guest::CR3, cr3());
        vmwrite(vmcs::guest::CR4, cr4().bits() as u64);

        vmwrite(vmcs::guest::DR7, unsafe { x86::debugregs::dr7() }.0 as u64);

        vmwrite(vmcs::guest::RSP, self.regs.rsp);
        vmwrite(vmcs::guest::RIP, self.regs.rip);
        vmwrite(vmcs::guest::RFLAGS, self.regs.rflags);
    }

    fn initialize_host(&self) {
        let gdtr = sgdt();

        let shared_data = HV_SHARED_DATA.get().unwrap();
        let cr3 = if let Some(host_pt) = &shared_data.host_pt {
            host_pt.ptr.as_ref() as *const crate::hypervisor::paging_structures::PagingStructuresRaw
                as u64
        } else {
            cr3()
        };
        let gdt_base = if let Some(host_gdt_and_tss) = &shared_data.host_gdt_and_tss {
            let x = &host_gdt_and_tss[self.id].gdt[0];
            x as *const _ as u64
        } else {
            gdtr.base as u64
        };
        let tr = if let Some(host_gdt_and_tss) = &shared_data.host_gdt_and_tss {
            host_gdt_and_tss[self.id].tr.unwrap()
        } else {
            tr()
        };
        let tss_base = if let Some(host_gdt_and_tss) = &shared_data.host_gdt_and_tss {
            let x = host_gdt_and_tss[self.id].tss.as_ref();
            let x = x.unwrap();
            x.as_ref() as *const _ as u64
        } else {
            SegmentDescriptor::try_from_gdtr(&gdtr, tr).unwrap().base()
        };
        let idt_base = if let Some(_host_idt) = &shared_data.host_idt {
            unimplemented!()
        } else {
            let idtr = sidt();
            idtr.base as u64
        };

        vmwrite(vmcs::host::ES_SELECTOR, es().bits() & !0x7);
        vmwrite(vmcs::host::CS_SELECTOR, cs().bits() & !0x7);
        vmwrite(vmcs::host::SS_SELECTOR, ss().bits() & !0x7);
        vmwrite(vmcs::host::DS_SELECTOR, ds().bits() & !0x7);
        vmwrite(vmcs::host::FS_SELECTOR, fs().bits() & !0x7);
        vmwrite(vmcs::host::GS_SELECTOR, gs().bits() & !0x7);
        vmwrite(vmcs::host::TR_SELECTOR, tr.bits() & !0x7);

        vmwrite(vmcs::host::CR0, cr0().bits() as u64); // TODO: "as u*" vs "as _"
        vmwrite(vmcs::host::CR3, cr3);
        vmwrite(vmcs::host::CR4, cr4().bits() as u64);

        vmwrite(vmcs::host::FS_BASE, rdmsr(x86::msr::IA32_FS_BASE));
        vmwrite(vmcs::host::GS_BASE, rdmsr(x86::msr::IA32_GS_BASE));
        vmwrite(vmcs::host::TR_BASE, tss_base);
        vmwrite(vmcs::host::GDTR_BASE, gdt_base);
        vmwrite(vmcs::host::IDTR_BASE, idt_base);
    }

    /// Returns an adjust value for the control field according to the
    /// capability MSR.
    fn adjust_vmx_control(control: VmxControl, requested_value: u64) -> u64 {
        const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

        // This determines the right VMX capability MSR based on the value of
        // IA32_VMX_BASIC. This is required to fullfil the following requirements:
        //
        // "It is necessary for software to consult only one of the capability MSRs
        //  to determine the allowed settings of the pin based VM-execution controls:"
        // See: A.3.1 Pin-Based VM-Execution Controls
        let vmx_basic = rdmsr(x86::msr::IA32_VMX_BASIC);
        let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

        let cap_msr = match (control, true_cap_msr_supported) {
            (VmxControl::PinBased, true) => x86::msr::IA32_VMX_TRUE_PINBASED_CTLS,
            (VmxControl::PinBased, false) => x86::msr::IA32_VMX_PINBASED_CTLS,
            (VmxControl::ProcessorBased, true) => x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS,
            (VmxControl::ProcessorBased, false) => x86::msr::IA32_VMX_PROCBASED_CTLS,
            (VmxControl::VmExit, true) => x86::msr::IA32_VMX_TRUE_EXIT_CTLS,
            (VmxControl::VmExit, false) => x86::msr::IA32_VMX_EXIT_CTLS,
            (VmxControl::VmEntry, true) => x86::msr::IA32_VMX_TRUE_ENTRY_CTLS,
            (VmxControl::VmEntry, false) => x86::msr::IA32_VMX_ENTRY_CTLS,
            // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
            // IA32_VMX_PROCBASED_CTLS2 unconditionally.
            (VmxControl::ProcessorBased2, _) => x86::msr::IA32_VMX_PROCBASED_CTLS2,
            (VmxControl::ProcessorBased3, _) => {
                const IA32_VMX_PROCBASED_CTLS3: u32 = 0x492;

                let allowed1 = rdmsr(IA32_VMX_PROCBASED_CTLS3);
                let effective_value = requested_value & allowed1;
                assert!(
                    effective_value | requested_value == effective_value,
                    "One or more requested features are not supported: {effective_value:#x?} : {requested_value:#x?} "
                );
                return effective_value;
            }
        };

        // Each bit of the following VMCS values might have to be set or cleared
        // according to the value indicated by the VMX capability MSRs.
        //  - pin-based VM-execution controls,
        //  - primary processor-based VM-execution controls,
        //  - secondary processor-based VM-execution controls.
        //
        // The VMX capability MSR is composed of two 32bit values, the lower 32bits
        // indicate bits can be 0, and the higher 32bits indicates bits can be 1.
        // In other words, if those bits are "cleared", corresponding bits MUST BE 1
        // and MUST BE 0 respectively. The below summarizes the interpretation:
        //
        //        Lower bits (allowed 0) Higher bits (allowed 1) Meaning
        // Bit X  1                      1                       The bit X is flexible
        // Bit X  1                      0                       The bit X is fixed to 0
        // Bit X  0                      1                       The bit X is fixed to 1
        //
        // The following code enforces this logic by setting bits that must be 1,
        // and clearing bits that must be 0.
        //
        // See: A.3.1 Pin-Based VM-Execution Controls
        // See: A.3.2 Primary Processor-Based VM-Execution Controls
        // See: A.3.3 Secondary Processor-Based VM-Execution Controls
        let capabilities = rdmsr(cap_msr);
        let allowed0 = capabilities as u32;
        let allowed1 = (capabilities >> 32) as u32;
        let requested_value = u32::try_from(requested_value).unwrap();
        let mut effective_value = requested_value;
        effective_value |= allowed0;
        effective_value &= allowed1;
        assert!(
            effective_value | requested_value == effective_value,
            "One or more requested features are not supported for {control:?}: {effective_value:#x?} vs {requested_value:#x?}"
        );
        u64::from(effective_value)
    }

    fn access_rights(access_rights: u32) -> u32 {
        const VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG: u32 = 1 << 16;

        if access_rights == 0 {
            return VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG;
        }

        (access_rights >> 8) & 0b1111_0000_1111_1111
    }

    fn _eptp_from_nested_cr3(value: u64) -> u64 {
        const EPT_POINTER_MEMORY_TYPE_WRITE_BACK: u64 = 6 /* << 0 */;
        const EPT_POINTER_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        assert!(value.trailing_zeros() >= 12);
        value | EPT_POINTER_PAGE_WALK_LENGTH_4 | EPT_POINTER_MEMORY_TYPE_WRITE_BACK
    }

    fn handle_sipi_signal(&mut self) {
        let vector = vmread(vmcs::ro::EXIT_QUALIFICATION);

        vmwrite(vmcs::guest::CS_SELECTOR, vector << 8);
        vmwrite(vmcs::guest::CS_BASE, vector << 12);
        self.regs.rip = 0;
        vmwrite(vmcs::guest::RIP, self.regs.rip);

        vmwrite(
            vmcs::guest::ACTIVITY_STATE,
            GuestActivityState::Active as u32,
        );
    }
}

extern "efiapi" {
    /// Runs the VM until VM-exit occurs.
    fn run_vmx_vm(registers: &mut GuestRegisters) -> u64;
}
global_asm!(include_str!("../capture_registers.inc"));
global_asm!(include_str!("run_vmx_vm.S"));

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    ProcessorBased3,
    VmExit,
    VmEntry,
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
