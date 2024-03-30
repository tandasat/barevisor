use alloc::boxed::Box;
use x86::controlregs::{Cr0, Cr4};

use crate::utils::{
    platform,
    support::zeroed_box,
    x86_instructions::{cr0, cr0_write, cr4, cr4_write, rdmsr, wrmsr},
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
    let pa = platform::ops().pa(va as *const _);

    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmxon(pa).unwrap() };
}

/// The wrapper of the VMXOFF instruction.
fn vmxoff() {
    // Safety: this project runs at CPL0.
    unsafe { x86::current::vmx::vmxoff().unwrap() };
}
