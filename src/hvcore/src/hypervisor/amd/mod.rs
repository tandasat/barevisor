//! This module implements Intel SVM based virtualization. Code comments refer
//! to AMD64 Architecture Programmer's Manual Volume 2: System Programming
//! revision 3.42 at
//! <https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf>.

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
