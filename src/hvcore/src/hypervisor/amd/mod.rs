use super::vmm::Architecture;

mod npts;
mod svm;

pub(crate) struct Amd;

impl Architecture for Amd {
    type Extension = svm::Svm;
    type VirtualMachine = svm::Vm;
}
