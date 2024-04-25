#![no_main]
#![no_std]

extern crate alloc;

mod ops;
mod println;

use alloc::{boxed::Box, vec::Vec};
use hv::{GdtTss, PagingStructures};
use uefi::{
    prelude::*,
    table::boot::{AllocateType, MemoryType},
};
use x86::bits64::task::TaskStateSegment;

#[entry]
fn main(image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    println::init(&system_table);
    println!("Loading uefi_hv.efi");

    let ptr = system_table
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            hv::allocator::ALLOCATION_PAGES,
        )
        .unwrap_or(0) as *mut u8;
    hv::allocator::init(ptr);

    hv::init_ops(Box::new(ops::UefiOps::new(&system_table)));

    if let Err(e) = zap_relocations(system_table.boot_services()) {
        println!("Failed to zap relocations: {e}");
        return e.status();
    }

    // Update an GDT for each processors to include a TSS.
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        hv::ops().run_on_all_processors(|| {
            let new_gdt = Box::leak(Box::new(GdtTss::new_from_current()));
            new_gdt
                .append_tss(Box::new(TaskStateSegment::new()))
                .apply()
                .unwrap();
        });
    }

    // Create a host GDT and TSS for each processor from the current GDT and TSS.
    let gdt_tss = Box::new(GdtTss::new_from_current());
    let mut host_gdt_and_tss = Vec::<Box<GdtTss>>::new();
    for _ in 0..hv::ops().processor_count() {
        host_gdt_and_tss.push(gdt_tss.clone());
    }

    // Build the host page tables.
    let mut host_pt = PagingStructures::new();
    host_pt.build_identity();

    let hv_data = hv::SharedData {
        host_idt: None,
        host_pt: Some(host_pt),
        host_gdt_and_tss: Some(host_gdt_and_tss),
    };
    hv::virtualize_system(hv_data);

    println!("Loaded uefi_hv.efi");
    Status::SUCCESS
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    hv::panic_impl(info)
}

// Directly taken from https://github.com/memN0ps/illusion-rs/
fn zap_relocations(boot_service: &BootServices) -> uefi::Result<()> {
    // Obtain the current loaded image protocol.
    let loaded_image = boot_service
        .open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(
            boot_service.image_handle(),
        )?;

    // Extract the image base address and size.
    let (image_base, image_size) = loaded_image.info();
    let image_base = image_base as u64;
    let image_range = image_base..image_base + image_size;

    // Log the image base address range for debugging purposes.
    println!("Image base: {image_range:#x?}");

    // Unsafe block to directly modify the PE header of the loaded image.
    // This operation nullifies the relocation table to prevent UEFI from
    // applying relocations to the hypervisor code.
    unsafe {
        *((image_base + 0x128) as *mut u32) = 0; // Zero out the relocation table offset.
        *((image_base + 0x12c) as *mut u32) = 0; // Zero out the relocation table size.
    }

    Ok(())
}
