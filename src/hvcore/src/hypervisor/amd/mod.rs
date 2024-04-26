use super::vmm::Architecture;

mod npts;
mod svm;
mod svm_vm;

pub(crate) struct Amd;

impl Architecture for Amd {
    type Extension = svm::Svm;
    type VirtualMachine = svm_vm::Vm;
}
