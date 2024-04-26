use super::vmm::Architecture;

mod epts;
mod mtrr;
mod vmx;
mod vmx_vm;

pub(crate) struct Intel;

impl Architecture for Intel {
    type Extension = vmx::Vmx;
    type VirtualMachine = vmx_vm::Vm;
}
