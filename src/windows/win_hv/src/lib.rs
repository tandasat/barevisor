#![doc = include_str!("../../README.md")]
#![no_std]

extern crate alloc;

mod eprintln;
mod ops;

use alloc::boxed::Box;
use wdk_sys::{
    ntddk::ExAllocatePool2, DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, POOL_FLAG_NON_PAGED,
    STATUS_SUCCESS,
};

#[link_section = "INIT"]
#[export_name = "DriverEntry"]
extern "system" fn driver_entry(
    _driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    const POOL_TAG: u32 = u32::from_ne_bytes(*b"Bare");
    eprintln!("Loading win_hv.sys");

    let ptr = unsafe {
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            hv::allocator::ALLOCATION_BYTES as _,
            POOL_TAG,
        )
    };
    hv::allocator::init(ptr.cast::<u8>());
    hv::platform_ops::init(Box::new(ops::WindowsOps {}));
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
