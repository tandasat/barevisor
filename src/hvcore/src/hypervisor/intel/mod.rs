use super::vmm::Architecture;

mod epts;
mod mtrr;
mod vmcs;
mod vmx;

pub(crate) struct Intel;

impl Architecture for Intel {
    type Extension = vmx::Vmx;
    type VirtualMachine = vmx::Vm;
}
