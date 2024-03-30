#![no_std]

extern crate alloc;

pub mod hypervisor;
pub mod utils;

pub use hypervisor::virtualize_system;
pub use hypervisor::SharedData;
pub use utils::gdt_tss::GdtTss;
pub use utils::paging_structures::PagingStructures;
pub use utils::panic::panic_impl;
pub use utils::platform::init as init_ops;
pub use utils::platform::ops;
pub use utils::system_ops::SystemOps;
