use super::host::Architecture;

mod guest;
mod npts;
mod svm;

pub(crate) struct Amd;

impl Architecture for Amd {
    type VirtualizationExtension = svm::Svm;
    type Guest = guest::SvmGuest;
}
