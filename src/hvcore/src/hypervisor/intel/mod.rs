use super::host::Architecture;

mod epts;
mod guest;
mod mtrr;
mod vmx;

/// The Intel processor implements VMX as a virtualization extension.
pub(crate) struct Intel;

impl Architecture for Intel {
    type VirtualizationExtension = vmx::Vmx;
    type Guest = guest::VmxGuest;
}
