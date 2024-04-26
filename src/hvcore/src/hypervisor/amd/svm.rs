use crate::hypervisor::{
    vmm::Extension,
    x86_instructions::{rdmsr, wrmsr},
};

#[derive(Default)]
pub(crate) struct Svm;

impl Extension for Svm {
    fn enable(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        // Enable SVM. We assume the processor is compatible with this.
        // See: 15.4 Enabling SVM
        wrmsr(x86::msr::IA32_EFER, rdmsr(x86::msr::IA32_EFER) | EFER_SVME);
    }
}
