#![no_std]

extern crate alloc;

pub mod hypervisor;

#[cfg(not(test))]
pub use hypervisor::allocator;
pub use hypervisor::gdt_tss::GdtTss;
pub use hypervisor::interrupt_handlers::InterruptDescriptorTable;
pub use hypervisor::paging_structures::PagingStructures;
pub use hypervisor::panic::panic_impl;
pub use hypervisor::platform_ops;
pub use hypervisor::virtualize_system;
pub use hypervisor::SharedHostData;
