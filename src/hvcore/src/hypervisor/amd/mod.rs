pub(crate) mod svm;

pub(crate) struct Amd;

impl crate::hypervisor::Architecture for Amd {
    type Extension = svm::Svm;
    type VirtualMachine = svm::Vm;
}
