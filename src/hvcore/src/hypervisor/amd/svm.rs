use core::{
    arch::global_asm,
    hint::spin_loop,
    ptr::addr_of,
    sync::atomic::{AtomicU16, Ordering},
};

use alloc::boxed::Box;
use bit_field::BitField;
use spin::{Once, RwLock};
use x86::{
    bits64::paging::BASE_PAGE_SHIFT,
    controlregs::cr3_write,
    cpuid::cpuid,
    msr::IA32_APIC_BASE,
    segmentation::{cs, ds, es, ss},
};

use crate::hypervisor::{
    capture_registers::GuestRegisters,
    platform_ops, processor_id_from,
    vmm::{Extension, InstructionInfo, VirtualMachine, VmExitReason},
    x86_instructions::{cr0, cr3, cr4, rdmsr, sgdt, sidt, wrmsr},
    HV_SHARED_DATA,
};

use super::npts::NestedPageTables;

struct SharedVmData {
    npt: RwLock<NestedPageTables>,
    sipi_vectors: [AtomicU16; 0xff],
}

/// A collection of data that the hypervisor depends on for its entire lifespan.
static SHARED_VM_DATA: Once<SharedVmData> = Once::new();

impl SharedVmData {
    fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ARRAY_REPEAT_VALUE: AtomicU16 = AtomicU16::new(u16::MAX);
        let sipi_vectors = [ARRAY_REPEAT_VALUE; 0xff];

        let mut npt = NestedPageTables::new();
        npt.build_identity();

        let apic_base_raw = rdmsr(IA32_APIC_BASE);
        assert!(
            !apic_base_raw.get_bit(10),
            "x2APIC is enabled but not supported"
        );
        assert!(apic_base_raw.get_bit(11), "APIC is disabled");
        let apic_base = apic_base_raw & !0xfff;

        npt.split_2mb(apic_base);

        Self {
            npt: RwLock::new(npt),
            sipi_vectors,
        }
    }
}

#[derive(Default)]
pub(crate) struct Svm {
    //enabled: bool,
}

impl Extension for Svm {
    fn enable(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        // Enable SVM. We assume the processor is compatible with this.
        // See: 15.4 Enabling SVM
        wrmsr(x86::msr::IA32_EFER, rdmsr(x86::msr::IA32_EFER) | EFER_SVME);
    }
}

#[derive(Debug, PartialEq)]
enum GuestActivityState {
    Active,
    WaitForSipi,
}

impl Default for GuestActivityState {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(derivative::Derivative)]
#[derivative(Debug, Default)]
pub(crate) struct Vm {
    id: usize,
    vmcb: Box<Vmcb>,
    vmcb_pa: u64,
    host_vmcb: Box<Vmcb>,
    host_vmcb_pa: u64,
    #[derivative(Debug = "ignore")]
    host_state: Box<HostStateArea>,
    registers: GuestRegisters,
    activity_state: GuestActivityState,
}

impl VirtualMachine for Vm {
    fn new(id: u8) -> Self {
        let _ = SHARED_VM_DATA.call_once(SharedVmData::new);

        let mut vm = Self {
            id: id as usize,
            ..Default::default()
        };

        vm.vmcb_pa = platform_ops::get().pa(addr_of!(*vm.vmcb) as _);
        vm.host_vmcb_pa = platform_ops::get().pa(addr_of!(*vm.host_vmcb) as _);
        if cfg!(feature = "uefi") && vm.id == 0 {
            vm.intercept_apic_write(true);
        }
        vm
    }
    fn activate(&mut self) {
        const SVM_MSR_VM_HSAVE_PA: u32 = 0xc001_0117;

        // Need to specify the address of the host state-save area before executing
        // the VMRUN instruction. The host state-save area is where the processor
        // saves the host (ie, current) register values on execution of `VMRUN`.
        //
        // "The VMRUN instruction saves some host processor state information in
        //  the host state-save area in main memory at the physical address
        //  specified in the VM_HSAVE_PA MSR".
        // See: 15.5.1 Basic Operation
        let pa = platform_ops::get().pa(addr_of!(*self.host_state) as _);
        wrmsr(SVM_MSR_VM_HSAVE_PA, pa);
    }

    fn initialize(&mut self, regs: &GuestRegisters) {
        self.registers = *regs;
        self.initialize_control();
        self.initialize_guest();
        self.initialize_host();
    }

    fn run(&mut self) -> VmExitReason {
        const VMEXIT_EXCEPTION_SX: u64 = 0x5e;
        const VMEXIT_CPUID: u64 = 0x72;
        const VMEXIT_NPF: u64 = 0x400;

        self.vmcb.state_save_area.rax = self.registers.rax;
        self.vmcb.state_save_area.rip = self.registers.rip;
        self.vmcb.state_save_area.rsp = self.registers.rsp;
        self.vmcb.state_save_area.rflags = self.registers.rflags;

        log::trace!("Entering the VM {}", self.id);
        log::trace!("{:#x?}", self.registers);

        // Run the VM until the #VMEXIT occurs.
        unsafe { run_vm_svm(&mut self.registers, self.vmcb_pa, self.host_vmcb_pa) };

        // #VMEXIT occurred. Copy the guest register values from VMCB so that
        // `self.registers` is complete and up to date.
        self.registers.rax = self.vmcb.state_save_area.rax;
        self.registers.rip = self.vmcb.state_save_area.rip;
        self.registers.rsp = self.vmcb.state_save_area.rsp;
        self.registers.rflags = self.vmcb.state_save_area.rflags;

        log::trace!("Exited the VM {}", self.id);
        log::trace!("{:#x?}", self.registers);

        // We might have requested flushing TLB. Clear the request.
        self.vmcb.control_area.tlb_control = TlbControl::DoNotFlush as _;

        // Handle #VMEXIT by translating it to the `VmExitReason` type.
        //
        // "On #VMEXIT, the processor:
        //  (...)
        //  - Saves the reason for exiting the guest in the VMCB's EXITCODE field."
        // See: 15.6 #VMEXIT
        //
        // For the list of possible exit codes,
        // See: Appendix C SVM Intercept Exit Codes
        match self.vmcb.control_area.exit_code {
            VMEXIT_EXCEPTION_SX => {
                self.handle_security_exception();
                VmExitReason::InitSignal
            }
            VMEXIT_NPF => {
                self.handle_nested_page_fault();
                VmExitReason::NestedPageFault
            }
            VMEXIT_CPUID => VmExitReason::Cpuid(InstructionInfo {
                next_rip: self.vmcb.control_area.nrip,
            }),
            _ => {
                log::error!("{:#x?}", self.vmcb);
                panic!(
                    "Unhandled VM-exit reason: {:?}",
                    self.vmcb.control_area.exit_code
                )
            }
        }
    }

    fn regs(&mut self) -> &mut GuestRegisters {
        &mut self.registers
    }
}

/// Table 15-9. TLB Control Byte Encodings
#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TlbControl {
    DoNotFlush = 0x0,
    FlushAll = 0x1,
    FlushGuests = 0x3,
    FlushGuestsNonGlobal = 0x7,
}

impl Vm {
    fn handle_security_exception(&mut self) {
        assert!(self.id != 0);
        self.handle_init_signal();
        let vector = self.wait_for_sipi();
        self.handle_sipi(vector);
    }

    fn handle_init_signal(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        assert!(self.id != 0);
        log::trace!("INIT");

        // Extension Type
        // Not Write-through
        // Cache Disabled
        let previous_cr0 = cr0().bits();
        let new_cr0 = 1u64 << 4
            | (previous_cr0.get_bit(29) as u64) << 29
            | (previous_cr0.get_bit(30) as u64) << 30;
        self.vmcb.state_save_area.cr0 = new_cr0;
        self.vmcb.state_save_area.cr2 = 0;
        self.vmcb.state_save_area.cr3 = 0;
        self.vmcb.state_save_area.cr4 = 0;
        self.vmcb.state_save_area.rflags = 1u64 << 1;
        self.vmcb.state_save_area.efer = EFER_SVME;
        self.vmcb.state_save_area.rip = 0xfff0;
        self.vmcb.state_save_area.cs_selector = 0xf000;
        self.vmcb.state_save_area.cs_base = 0xffff0000;
        self.vmcb.state_save_area.cs_limit = 0xffff;
        self.vmcb.state_save_area.cs_attrib = 0x9b;
        self.vmcb.state_save_area.ds_selector = 0;
        self.vmcb.state_save_area.ds_base = 0;
        self.vmcb.state_save_area.ds_limit = 0xffff;
        self.vmcb.state_save_area.ds_attrib = 0x93;
        self.vmcb.state_save_area.es_selector = 0;
        self.vmcb.state_save_area.es_base = 0;
        self.vmcb.state_save_area.es_limit = 0xffff;
        self.vmcb.state_save_area.es_attrib = 0x93;
        self.vmcb.state_save_area.fs_selector = 0;
        self.vmcb.state_save_area.fs_base = 0;
        self.vmcb.state_save_area.fs_limit = 0xffff;
        self.vmcb.state_save_area.fs_attrib = 0x93;
        self.vmcb.state_save_area.gs_selector = 0;
        self.vmcb.state_save_area.gs_base = 0;
        self.vmcb.state_save_area.gs_limit = 0xffff;
        self.vmcb.state_save_area.gs_attrib = 0x93;
        self.vmcb.state_save_area.ds_selector = 0;
        self.vmcb.state_save_area.ds_base = 0;
        self.vmcb.state_save_area.ds_limit = 0xffff;
        self.vmcb.state_save_area.ds_attrib = 0x93;
        self.vmcb.state_save_area.gdtr_base = 0;
        self.vmcb.state_save_area.gdtr_limit = 0xffff;
        self.vmcb.state_save_area.idtr_base = 0;
        self.vmcb.state_save_area.idtr_limit = 0xffff;
        self.vmcb.state_save_area.ldtr_selector = 0;
        self.vmcb.state_save_area.ldtr_base = 0;
        self.vmcb.state_save_area.ldtr_limit = 0xffff;
        self.vmcb.state_save_area.ldtr_attrib = 0x82;
        self.vmcb.state_save_area.tr_selector = 0;
        self.vmcb.state_save_area.tr_base = 0;
        self.vmcb.state_save_area.tr_limit = 0xffff;
        self.vmcb.state_save_area.tr_attrib = 0x8b;
        self.registers.rax = 0;
        self.registers.rdx = cpuid!(0x1).eax as _;
        self.registers.rbx = 0;
        self.registers.rcx = 0;
        self.registers.rbp = 0;
        self.vmcb.state_save_area.rsp = 0;
        self.registers.rdi = 0;
        self.registers.rsi = 0;
        self.registers.r8 = 0;
        self.registers.r9 = 0;
        self.registers.r10 = 0;
        self.registers.r11 = 0;
        self.registers.r12 = 0;
        self.registers.r13 = 0;
        self.registers.r14 = 0;
        self.registers.r15 = 0;
        unsafe {
            x86::debugregs::dr0_write(0);
            x86::debugregs::dr1_write(0);
            x86::debugregs::dr2_write(0);
            x86::debugregs::dr3_write(0);
        };
        self.vmcb.state_save_area.dr6 = 0xffff0ff0;
        self.vmcb.state_save_area.dr7 = 0x400;

        // TLB and clean bits

        self.activity_state = GuestActivityState::WaitForSipi;
    }

    fn wait_for_sipi(&mut self) -> u8 {
        assert!(self.id != 0);
        assert!(self.activity_state == GuestActivityState::WaitForSipi);

        let shared_vm_data = SHARED_VM_DATA.get().unwrap();
        let sipi_vector = &shared_vm_data.sipi_vectors[self.id];
        while sipi_vector.load(Ordering::Relaxed) == u16::MAX {
            spin_loop();
        }
        sipi_vector.swap(u16::MAX, Ordering::Relaxed) as _
    }

    fn handle_sipi(&mut self, vector: u8) {
        assert!(self.id != 0);
        assert!(self.activity_state == GuestActivityState::WaitForSipi);
        log::trace!("SIPI vector {vector:#x?}");

        self.vmcb.state_save_area.cs_selector = (vector as u16) << 8;
        self.vmcb.state_save_area.cs_base = (vector as u64) << 12;
        self.vmcb.state_save_area.rip = 0;
        self.registers.rip = 0;
        self.activity_state = GuestActivityState::Active;
    }

    fn intercept_apic_write(&mut self, enable: bool) {
        assert!(self.id == 0);

        let apic_base_raw = rdmsr(IA32_APIC_BASE);
        let apic_base = apic_base_raw & !0xfff;
        let pt_index = apic_base.get_bits(12..=20) as usize; // [20:12]

        let shared_vm_data = SHARED_VM_DATA.get().unwrap();
        let mut npt = shared_vm_data.npt.write();
        let pt = npt.pt();
        pt.0.entries[pt_index].set_writable(!enable);

        // Other processors will have stale TLB entries as we do not do TLB
        // shootdown. It is fine because APIC writes we want to see are done by
        // this processors. We need to handle #VMEXIT(NFP) on other processors
        // if it happens.
        self.vmcb.control_area.tlb_control = TlbControl::FlushAll as _;
    }

    fn handle_nested_page_fault(&mut self) {
        let instructions = unsafe {
            core::slice::from_raw_parts(
                self.vmcb.control_area.guest_instruction_bytes.as_ptr(),
                self.vmcb.control_area.num_of_bytes_fetched as _,
            )
        };

        let (value, dest_linear_addr) = match instructions {
            [0x45, 0x89, 0x65, 0x00, ..] => {
                // MOV DWORD PTR [R13+00],R12D
                self.registers.rip += 4;
                let dest_linear_addr = self.registers.r13;
                let value = self.registers.r12 as u32;
                (value, dest_linear_addr)
            }
            [0x41, 0x89, 0x14, 0x00, ..] => {
                // MOV DWORD PTR [R8+RAX],EDX
                self.registers.rip += 4;
                let dest_linear_addr = self.registers.r8 + self.registers.rax;
                let value = self.registers.rdx as u32;
                (value, dest_linear_addr)
            }
            [0xc7, 0x81, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ..] => {
                // MOV DWORD PTR [RCX+000000B0],00000000
                self.registers.rip += 10;
                let dest_linear_addr = self.registers.rcx + 0xb0;
                let value = 0u32;
                (value, dest_linear_addr)
            }
            [0x89, 0x90, 0x00, 0x03, 0x00, 0x00, ..] => {
                // MOV DWORD PTR [RAX+00000300],EDX
                self.registers.rip += 6;
                let dest_linear_addr = self.registers.rax + 0x300;
                let value = self.registers.rdx as u32;
                (value, dest_linear_addr)
            }
            [0x89, 0x88, 0x10, 0x03, 0x00, 0x00, ..] => {
                // MOV DWORD PTR [RAX+00000310],ECX
                self.registers.rip += 6;
                let dest_linear_addr = self.registers.rax + 0x310;
                let value = self.registers.rcx as u32;
                (value, dest_linear_addr)
            }
            _ => {
                log::error!("{:#x?}", self.registers);
                panic!("Unhandled APIC access instructions: {:02x?}", instructions);
            }
        };

        let faulting_gpa = self.vmcb.control_area.exit_info2;
        let apic_register = faulting_gpa & 0xfff;
        let message_type = value.get_bits(8..=10);
        log::trace!("VA:{dest_linear_addr:#x} / PA:{faulting_gpa:#x} <= {value:#x}");

        // If the faulting access is not because of sending Startup IPI (0b110)
        // via the Interrupt Command Register Low (0x300), do the write access
        // the guest wanted to do and bail out.
        if !(apic_register == 0x300 && message_type == 0b110) {
            // Safety: GPA is same as PA in our NTPs, and the faulting address
            // is always the local APIC page, which is writable in the host
            // address space.
            unsafe { *(faulting_gpa as *mut u32) = value };
            return;
        }

        // The BSP is trying to send Startup IPI. This must not be allowed because
        // SVM does not intercept it or deliver #VMEXIT. We need to prevent the
        // BSP from sending it and emulate the effect in software instead.

        // Figure 16-18. Interrupt Command Register (APIC Offset 300h–310h)
        assert!(!value.get_bit(11), "Destination Mode must be 'Physical'");
        assert!(
            value.get_bits(18..=19) == 0b00,
            "Destination Shorthand must be 'Destination'"
        );

        // Safety: GPA is same as PA in our NTPs, and the faulting address
        // is always the local APIC page, which is writable in the host
        // address space.
        let icr_high_addr = (faulting_gpa & !0xfff) | 0x310;
        let icr_high_value = unsafe { *(icr_high_addr as *mut u32) };

        // Collect necessary bits to emulate, that is, vector and destination.
        let vector = value.get_bits(0..=7) as u8;
        let apic_id = icr_high_value.get_bits(24..=31) as u8;
        let processor_id = processor_id_from(apic_id).unwrap() as usize;
        log::info!("SIPI to {apic_id} with vector {vector:#x?}");

        // Update the global object with the obtained vector value. APs should
        // be spinning based on this value and exit the spin once we update the
        // value here.
        let shared_vm_data = SHARED_VM_DATA.get().unwrap();
        let sipi_vector = &shared_vm_data.sipi_vectors[processor_id];
        assert!(sipi_vector.swap(vector as _, Ordering::Relaxed) == u16::MAX);
    }

    fn initialize_control(&mut self) {
        const SVM_INTERCEPT_MISC1_CPUID: u32 = 1 << 18;
        const SVM_INTERCEPT_MISC2_VMRUN: u32 = 1 << 0;
        const SVM_NP_ENABLE_NP_ENABLE: u64 = 1 << 0;

        self.vmcb.control_area.intercept_misc1 = SVM_INTERCEPT_MISC1_CPUID;
        self.vmcb.control_area.intercept_misc2 = SVM_INTERCEPT_MISC2_VMRUN;
        self.vmcb.control_area.pause_filter_count = u16::MAX;

        // Address Space Identifier (ASID) is useful when the given logical processor
        // runs more than one guests. We do not but still need to set non-zero value.
        // See: 15.16 TLB Control
        self.vmcb.control_area.guest_asid = 1;

        // Enable nested paging. This is done by:
        // - Setting the NP_ENABLE bit in VMCB, and
        // - Setting the base address of the nested PML4
        //
        // See: 15.25.3 Enabling Nested Paging
        let shared_vm_data = SHARED_VM_DATA.get().unwrap();
        let nested_pml4_addr = shared_vm_data.npt.read().ptr.as_ref() as *const _;
        self.vmcb.control_area.np_enable = SVM_NP_ENABLE_NP_ENABLE;
        self.vmcb.control_area.ncr3 = platform_ops::get().pa(nested_pml4_addr as _);

        // Convert #INIT to #SX. One cannot simply intercept #INIT because even
        // if we do, #INIT is still pending and will be delivered anyway.
        const SVM_MSR_VM_CR: u32 = 0xc001_0114;
        const R_INIT: u64 = 1 << 1;
        wrmsr(SVM_MSR_VM_CR, rdmsr(SVM_MSR_VM_CR) | R_INIT);

        const SECURITY_EXCEPTION: u32 = 1 << 30;
        self.vmcb.control_area.intercept_exception = SECURITY_EXCEPTION;
    }

    fn initialize_guest(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        let idtr = sidt();
        let gdtr = sgdt();
        let guest_gdt = gdtr.base as u64;

        self.vmcb.state_save_area.es_selector = es().bits();
        self.vmcb.state_save_area.cs_selector = cs().bits();
        self.vmcb.state_save_area.ss_selector = ss().bits();
        self.vmcb.state_save_area.ds_selector = ds().bits();
        self.vmcb.state_save_area.es_attrib = get_segment_access_right(guest_gdt, es().bits());
        self.vmcb.state_save_area.cs_attrib = get_segment_access_right(guest_gdt, cs().bits());
        self.vmcb.state_save_area.ss_attrib = get_segment_access_right(guest_gdt, ss().bits());
        self.vmcb.state_save_area.ds_attrib = get_segment_access_right(guest_gdt, ds().bits());
        self.vmcb.state_save_area.es_limit = get_segment_limit(guest_gdt, es().bits());
        self.vmcb.state_save_area.cs_limit = get_segment_limit(guest_gdt, cs().bits());
        self.vmcb.state_save_area.ss_limit = get_segment_limit(guest_gdt, ss().bits());
        self.vmcb.state_save_area.ds_limit = get_segment_limit(guest_gdt, ds().bits());
        self.vmcb.state_save_area.gdtr_base = gdtr.base as _;
        self.vmcb.state_save_area.gdtr_limit = u32::from(gdtr.limit);
        self.vmcb.state_save_area.idtr_base = idtr.base as _;
        self.vmcb.state_save_area.idtr_limit = u32::from(idtr.limit);
        self.vmcb.state_save_area.efer = rdmsr(x86::msr::IA32_EFER) | EFER_SVME;
        self.vmcb.state_save_area.cr0 = cr0().bits() as _;
        self.vmcb.state_save_area.cr3 = cr3();
        self.vmcb.state_save_area.cr4 = cr4().bits() as _;
        self.vmcb.state_save_area.rip = self.registers.rip;
        self.vmcb.state_save_area.rsp = self.registers.rsp;
        self.vmcb.state_save_area.rflags = self.registers.rflags;
        self.vmcb.state_save_area.rax = self.registers.rax;
        self.vmcb.state_save_area.gpat = rdmsr(x86::msr::IA32_PAT);

        // VMSAVE copies some of the current register values into VMCB. Take
        // advantage of it.
        unsafe { asm_vmsave(self.vmcb_pa) };
    }

    fn initialize_host(&mut self) {
        let shared_data = HV_SHARED_DATA.get().unwrap();
        let ops = platform_ops::get();

        if let Some(host_pt) = &shared_data.host_pt {
            let pml4 = host_pt.ptr.as_ref() as *const _;
            unsafe { cr3_write(ops.pa(pml4 as _)) };
            log::debug!("Updated CR3");
        }

        if let Some(host_gdt_and_tss) = &shared_data.host_gdt_and_tss {
            host_gdt_and_tss[self.id].apply().unwrap();
            log::debug!("Updated GDTR");
        }

        if let Some(_host_idt) = &shared_data.host_idt {
            log::debug!("Updated IDTR");
            unimplemented!();
        }

        // Save some of the current register values as host state. They are
        // restored shortly after #VMEXIT.
        unsafe { asm_vmsave(self.host_vmcb_pa) };
    }
}

/// The virtual machine control block (VMCB), which describes a virtual machine
/// (guest) to be executed.
///
/// See: Appendix B Layout of VMCB
#[derive(Debug, Default)]
#[repr(C, align(4096))]
struct Vmcb {
    control_area: ControlArea,
    state_save_area: StateSaveArea,
}
const _: () = assert!(core::mem::size_of::<Vmcb>() == 0x1000);

/// The "metadata" area where we can specify what operations to intercept and
/// can read details of #VMEXIT.
///
/// See: Table B-1. VMCB Layout, Control Area
#[derive(derivative::Derivative)]
#[derivative(Debug, Default)]
#[repr(C)]
struct ControlArea {
    intercept_cr_read: u16,   // +0x000
    intercept_cr_write: u16,  // +0x002
    intercept_dr_read: u16,   // +0x004
    intercept_dr_write: u16,  // +0x006
    intercept_exception: u32, // +0x008
    intercept_misc1: u32,     // +0x00c
    intercept_misc2: u32,     // +0x010
    intercept_misc3: u32,     // +0x014
    #[derivative(Debug = "ignore", Default(value = "[0; 36]"))]
    _padding1: [u8; 0x03c - 0x018], // +0x018
    pause_filter_threshold: u16, // +0x03c
    pause_filter_count: u16,  // +0x03e
    iopm_base_pa: u64,        // +0x040
    msrpm_base_pa: u64,       // +0x048
    tsc_offset: u64,          // +0x050
    guest_asid: u32,          // +0x058
    tlb_control: u32,         // +0x05c
    vintr: u64,               // +0x060
    interrupt_shadow: u64,    // +0x068
    exit_code: u64,           // +0x070
    exit_info1: u64,          // +0x078
    exit_info2: u64,          // +0x080
    exit_int_info: u64,       // +0x088
    np_enable: u64,           // +0x090
    avic_apic_bar: u64,       // +0x098
    guest_pa_pf_ghcb: u64,    // +0x0a0
    event_inj: u64,           // +0x0a8
    ncr3: u64,                // +0x0b0
    lbr_virtualization_enable: u64, // +0x0b8
    vmcb_clean: u64,          // +0x0c0
    nrip: u64,                // +0x0c8
    num_of_bytes_fetched: u8, // +0x0d0
    guest_instruction_bytes: [u8; 15], // +0x0d1
    avic_apic_backing_page_pointer: u64, // +0x0e0
    #[derivative(Debug = "ignore")]
    _padding2: u64, // +0x0e8
    avic_logical_table_pointer: u64, // +0x0f0
    avic_physical_table_pointer: u64, // +0x0f8
    #[derivative(Debug = "ignore")]
    _padding3: u64, // +0x100
    vmcb_save_state_pointer: u64, // +0x108
    #[derivative(Debug = "ignore", Default(value = "[0; 720]"))]
    _padding4: [u8; 0x3e0 - 0x110], // +0x110
    reserved_for_host: [u8; 0x20], // +0x3e0
}
const _: () = assert!(core::mem::size_of::<ControlArea>() == 0x400);

/// The ares to specify and read guest register values.
///
/// See: Table B-2. VMCB Layout, State Save Area
#[derive(derivative::Derivative)]
#[derivative(Debug, Default)]
#[repr(C)]
struct StateSaveArea {
    es_selector: u16,   // +0x000
    es_attrib: u16,     // +0x002
    es_limit: u32,      // +0x004
    es_base: u64,       // +0x008
    cs_selector: u16,   // +0x010
    cs_attrib: u16,     // +0x012
    cs_limit: u32,      // +0x014
    cs_base: u64,       // +0x018
    ss_selector: u16,   // +0x020
    ss_attrib: u16,     // +0x022
    ss_limit: u32,      // +0x024
    ss_base: u64,       // +0x028
    ds_selector: u16,   // +0x030
    ds_attrib: u16,     // +0x032
    ds_limit: u32,      // +0x034
    ds_base: u64,       // +0x038
    fs_selector: u16,   // +0x040
    fs_attrib: u16,     // +0x042
    fs_limit: u32,      // +0x044
    fs_base: u64,       // +0x048
    gs_selector: u16,   // +0x050
    gs_attrib: u16,     // +0x052
    gs_limit: u32,      // +0x054
    gs_base: u64,       // +0x058
    gdtr_selector: u16, // +0x060 (Reserved)
    gdtr_attrib: u16,   // +0x062 (Reserved)
    gdtr_limit: u32,    // +0x064
    gdtr_base: u64,     // +0x068
    ldtr_selector: u16, // +0x070 (Reserved)
    ldtr_attrib: u16,   // +0x072 (Reserved)
    ldtr_limit: u32,    // +0x074
    ldtr_base: u64,     // +0x078
    idtr_selector: u16, // +0x080
    idtr_attrib: u16,   // +0x082
    idtr_limit: u32,    // +0x084
    idtr_base: u64,     // +0x088
    tr_selector: u16,   // +0x090
    tr_attrib: u16,     // +0x092
    tr_limit: u32,      // +0x094
    tr_base: u64,       // +0x098
    #[derivative(Debug = "ignore", Default(value = "[0; 43]"))]
    _padding1: [u8; 0x0cb - 0x0a0], // +0x0a0
    cpl: u8,            // +0x0cb
    #[derivative(Debug = "ignore")]
    _padding2: u32, // +0x0cc
    efer: u64,          // +0x0d0
    #[derivative(Debug = "ignore", Default(value = "[0; 112]"))]
    _padding3: [u8; 0x148 - 0x0d8], // +0x0d8
    cr4: u64,           // +0x148
    cr3: u64,           // +0x150
    cr0: u64,           // +0x158
    dr7: u64,           // +0x160
    dr6: u64,           // +0x168
    rflags: u64,        // +0x170
    rip: u64,           // +0x178
    #[derivative(Debug = "ignore", Default(value = "[0; 88]"))]
    _padding4: [u8; 0x1d8 - 0x180], // +0x180
    rsp: u64,           // +0x1d8
    s_cet: u64,         // +0x1e0
    ssp: u64,           // +0x1e8
    isst_addr: u64,     // +0x1f0
    rax: u64,           // +0x1f8
    star: u64,          // +0x200
    lstar: u64,         // +0x208
    cstar: u64,         // +0x210
    sf_mask: u64,       // +0x218
    kernel_gs_base: u64, // +0x220
    sysenter_cs: u64,   // +0x228
    sysenter_esp: u64,  // +0x230
    sysenter_eip: u64,  // +0x238
    cr2: u64,           // +0x240
    #[derivative(Debug = "ignore", Default(value = "[0; 32]"))]
    _padding5: [u8; 0x268 - 0x248], // +0x248
    gpat: u64,          // +0x268
    dbg_ctl: u64,       // +0x270
    br_from: u64,       // +0x278
    br_to: u64,         // +0x280
    last_excep_from: u64, // +0x288
    last_excep_to: u64, // +0x290
    #[derivative(Debug = "ignore", Default(value = "[0; 71]"))]
    _padding6: [u8; 0x2df - 0x298], // +0x298
    spec_ctl: u64,      // +0x2e0
}
const _: () = assert!(core::mem::size_of::<StateSaveArea>() == 0x2e8);

/// 4KB block of memory where the host state is saved to on VMRUN and loaded
/// from on #VMEXIT.
///
/// See: 15.30.4 VM_HSAVE_PA MSR (C001_0117h)
// doc_markdown: clippy confused with "VM_HSAVE_PA"
#[allow(clippy::doc_markdown)]
#[repr(C, align(4096))]
struct HostStateArea([u8; 0x1000]);
const _: () = assert!(core::mem::size_of::<HostStateArea>() == 0x1000);

impl Default for HostStateArea {
    fn default() -> Self {
        Self([0; 4096])
    }
}

extern "efiapi" {
    /// Runs the guest until #VMEXIT occurs.
    fn run_vm_svm(registers: &mut GuestRegisters, vmcb_pa: u64, host_vmcb_pa: u64);

    /// Saves registers to VMCS
    fn asm_vmsave(vmcb_pa: u64);
}
global_asm!(include_str!("../capture_registers.inc"));
global_asm!(include_str!("svm_run_vm.S"));

/// Returns the access rights of the given segment for SVM.
fn get_segment_access_right(table_base: u64, selector: u16) -> u16 {
    let descriptor_value = get_segment_descriptor_value(table_base, selector);

    // First, get the AVL, L, D/B and G bits, while excluding the "Seg. Limit 19:16"
    // bits. Then, get the Type, S, DPL and P bits. Finally, return those bits
    // without the "Seg. Limit 19:16" bits.
    // See: Figure 3-8. Segment Descriptor
    let ar = (descriptor_value >> 40) as u16;
    let upper_ar = (ar >> 4) & 0b1111_0000_0000;
    let lower_ar = ar & 0b1111_1111;
    lower_ar | upper_ar
}

/// Returns the segment descriptor casted as a 64bit integer for the given
/// selector.
fn get_segment_descriptor_value(table_base: u64, selector: u16) -> u64 {
    let sel = x86::segmentation::SegmentSelector::from_raw(selector);
    let descriptor_addr = table_base + u64::from(sel.index() * 8);
    let ptr = descriptor_addr as *const u64;
    unsafe { *ptr }
}

/// Returns the limit of the given segment.
fn get_segment_limit(table_base: u64, selector: u16) -> u32 {
    let sel = x86::segmentation::SegmentSelector::from_raw(selector);
    if sel.index() == 0 && (sel.bits() >> 2) == 0 {
        return 0; // unusable
    }
    let descriptor_value = get_segment_descriptor_value(table_base, selector);
    let limit_low = descriptor_value & 0xffff;
    let limit_high = (descriptor_value >> (32 + 16)) & 0xF;
    let mut limit = limit_low | (limit_high << 16);
    if ((descriptor_value >> (32 + 23)) & 0x01) != 0 {
        limit = ((limit + 1) << BASE_PAGE_SHIFT) - 1;
    }
    limit as u32
}
