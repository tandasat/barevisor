use super::host::Architecture;

mod guest;
mod npts;
mod svm;

/// The AMD processor implements SVM as a virtualization extension.
pub(crate) struct Amd;

impl Architecture for Amd {
    type VirtualizationExtension = svm::Svm;
    type Guest = guest::SvmGuest;
}
