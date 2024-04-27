use super::host::Architecture;

mod epts;
mod guest;
mod mtrr;
mod vmx;

pub(crate) struct Intel;

impl Architecture for Intel {
    type VirtualizationExtension = vmx::Vmx;
    type Guest = guest::VmxGuest;
}
