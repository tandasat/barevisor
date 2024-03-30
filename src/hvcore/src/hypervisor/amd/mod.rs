use super::vmm::Architecture;

pub(crate) mod svm;

pub(crate) struct Amd;

impl Architecture for Amd {
    type Extension = svm::Svm;
    type VirtualMachine = svm::Vm;
}
