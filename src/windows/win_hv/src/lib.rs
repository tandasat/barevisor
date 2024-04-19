#![doc = include_str!("../../README.md")]
#![no_std]

extern crate alloc;

mod eprintln;
mod ops;

use alloc::boxed::Box;
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS};

#[cfg(not(test))]
use wdk_alloc::WDKAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

#[link_section = "INIT"]
#[export_name = "DriverEntry"]
extern "system" fn driver_entry(
    _driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    eprintln!("Loading win_hv.sys");

    hv::init_ops(Box::new(ops::WindowsOps {}));
    hv::virtualize_system(hv::SharedData::default());

    eprintln!("Loaded win_hv.sys");
    STATUS_SUCCESS
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    eprintln!("{info}");
    if unsafe { *wdk_sys::KdDebuggerNotPresent } == 0 {
        wdk::dbg_break();
    }
    hv::panic_impl(info)
}
