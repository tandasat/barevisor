pub mod epts;
pub mod mtrr;
pub mod vm;
pub mod vmcs;
pub mod vmx;

pub(crate) struct Intel;

impl crate::hypervisor::Architecture for Intel {
    type Extension = vmx::Vmx;
    type VirtualMachine = vm::Vm;
}
