use alloc::boxed::Box;
use core::arch::global_asm;
use spin::once::Once;
use x86::{
    current::rflags::RFlags,
    segmentation::{cs, ds, es, fs, gs, ss, SegmentSelector},
    vmx::vmcs,
};

use crate::{
    hypervisor::HV_SHARED_DATA,
    intel::vmcs::{vmread, vmwrite, vmx_succeed},
    utils::{
        capture_registers::GuestRegisters,
        platform,
        segment::SegmentDescriptor,
        support::{zeroed_box, Page},
        x86_instructions::{cr0, cr3, cr4, lar, ldtr, lsl, rdmsr, sgdt, sidt, tr},
    },
};

use super::{
    epts::Epts,
    vmcs::{vmclear, vmptrld, Vmcs},
};

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
            VMX_EXIT_REASON_INIT => VmExitReason::Init,
            VMX_EXIT_REASON_SIPI => VmExitReason::Sipi,
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
                panic!("Unhandled VM-exit reason: {:?}", vmread(vmcs::ro::EXIT_REASON))
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
        let pa = platform::ops().pa(va as *const _);
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

        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, Self::access_rights(lar(es())));
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, Self::access_rights(lar(cs())));
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, Self::access_rights(lar(ss)));
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, Self::access_rights(lar(ds())));
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, Self::access_rights(lar(fs())));
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, Self::access_rights(lar(gs())));
        vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, Self::access_rights(lar(tr())));
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

        vmwrite(vmcs::guest::IA32_DEBUGCTL_FULL, rdmsr(x86::msr::IA32_DEBUGCTL));
        vmwrite(vmcs::guest::IA32_SYSENTER_CS, rdmsr(x86::msr::IA32_SYSENTER_CS));
        vmwrite(vmcs::guest::IA32_SYSENTER_EIP, rdmsr(x86::msr::IA32_SYSENTER_EIP));
        vmwrite(vmcs::guest::IA32_SYSENTER_ESP, rdmsr(x86::msr::IA32_SYSENTER_ESP));

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
            host_pt.ptr.as_ref() as *const crate::utils::paging_structures::PagingStructuresRaw
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
}

extern "efiapi" {
    /// Runs the VM until VM-exit occurs.
    fn run_vmx_vm(registers: &mut GuestRegisters) -> u64;
}
global_asm!(include_str!("../utils/capture_registers.inc"));
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
