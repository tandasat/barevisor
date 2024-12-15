#![doc = include_str!("../../README.md")]
#![no_main]
#![no_std]

extern crate alloc;

mod ops;
mod println;

use alloc::{boxed::Box, vec::Vec};
use hv::{GdtTss, PagingStructures};
use uefi::{
    prelude::*,
    proto::{loaded_image::LoadedImage, pi::mp::MpServices},
    table::boot::{AllocateType, MemoryType},
};
use x86::bits64::task::TaskStateSegment;

#[entry]
fn main(image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    println::init(&system_table);
    println!("Loading uefi_hv.efi");

    // Initialize the global allocator with pre-allocated buffer.
    let ptr = system_table
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            hv::allocator::ALLOCATION_PAGES,
        )
        .unwrap_or(0) as *mut u8;
    if ptr.is_null() {
        println!("Memory allocation failed");
        return Status::OUT_OF_RESOURCES;
    }
    hv::allocator::init(ptr);

    // Register the platform specific API.
    hv::platform_ops::init(Box::new(ops::UefiOps::new(&system_table)));

    // Prevent relocation. See the function comment.
    if let Err(e) = zap_relocation_table(&system_table) {
        println!("zap_relocation_table failed: {e}");
        return e.status();
    }

    // On Intel processors, update an GDT for each processors to include a TSS.
    // Intel processors requires a host GDT to use a TSS. UEFI's default GDT does
    // not use a TSS and needs the update.
    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() == "GenuineIntel" {
        hv::platform_ops::get().run_on_all_processors(|| {
            let new_gdt = Box::leak(Box::new(GdtTss::new_from_current()));
            new_gdt.append_tss(TaskStateSegment::new()).apply().unwrap();
        });
    }

    // The UEFI version of the hypervisor needs to have its own IDT, GDT, TSS and
    // paging structures. Create them and use them for the host. Unlike the Windows
    // version, the current IDT, GDT, TSS and paging structures are destroyed as
    // the system transition to the runtime-phase. Thus, the host cannot depend
    // on them and needs its own data structures.
    match create_shared_host_data(&system_table) {
        Ok(shared_host) => hv::virtualize_system(shared_host),
        Err(e) => {
            println!("create_shared_host_data failed: {e}");
            return e.status();
        }
    }

    println!("Loaded uefi_hv.efi");
    Status::SUCCESS
}

/// Creates `hv::SharedHostData`.
// - GDT and TSS are clones of the current.
// - IDT is as implemented in `hv::InterruptDescriptorTable`.
// - Paging structures are identity mapped and all RWX.
fn create_shared_host_data(system_table: &SystemTable<Boot>) -> uefi::Result<hv::SharedHostData> {
    /// Gets the number of usable logical processors on this system.
    fn processor_count(system_table: &SystemTable<Boot>) -> uefi::Result<u32> {
        let bs = system_table.boot_services();
        let handle = bs.get_handle_for_protocol::<MpServices>()?;
        let mp_services = bs.open_protocol_exclusive::<MpServices>(handle)?;
        Ok(u32::try_from(mp_services.get_number_of_processors().unwrap().enabled).unwrap())
    }

    // Each logical processor needs to have its own GDT, so clone the current
    // GDT and TSS for each processor.
    let gdt_tss = GdtTss::new_from_current();
    let mut host_gdt_tss = Vec::<GdtTss>::new();
    for _ in 0..processor_count(system_table)? {
        host_gdt_tss.push(gdt_tss.clone());
    }

    let host_idt = hv::InterruptDescriptorTable::new(host_gdt_tss[0].cs);

    let mut host_pt = PagingStructures::new();
    host_pt.build_identity();

    Ok(hv::SharedHostData {
        pt: Some(host_pt),
        idt: Some(host_idt),
        gdts: Some(host_gdt_tss),
    })
}

/// Prevents relocation of current module by zapping the Relocation Table in
/// the PE header.
// UEFI keeps the list of runtime drivers and applies patches into their code and
// data according to their relocation information in the PE headers when the system
// translations from physical-mode to virtual-mode (ie during transition to the
// runtime-phase) by updating paging structures. This breaks the host code,
// because the host keeps running with its own paging structures that were copied
// when the system is in physical-mode, and thus, expecting the same memory layout
// for its entire life. The dirty but easiest way to avoid this issue is to nullify
// the relocation information and prevents UEFI from patching this module. The
// other way to avoid this issue is to load the hypervisor as shellcode (ie, not
// being an UEFI runtime driver).
fn zap_relocation_table(system_table: &SystemTable<Boot>) -> uefi::Result<()> {
    const NT_RELOCATION_DIRECTORY_RVA: u64 = 0x128;
    const NT_RELOCATION_DIRECTORY_SIZE: u64 = 0x12c;

    let bs = system_table.boot_services();
    let loaded_image = bs.open_protocol_exclusive::<LoadedImage>(bs.image_handle())?;
    let (image_base, image_size) = loaded_image.info();
    let image_base = image_base as u64;
    let image_range = image_base..image_base + image_size;
    println!("Image base: {image_range:#x?}");

    unsafe {
        *((image_base + NT_RELOCATION_DIRECTORY_RVA) as *mut u32) = 0;
        *((image_base + NT_RELOCATION_DIRECTORY_SIZE) as *mut u32) = 0;
    }
    Ok(())
}

#[cfg(not(any(test, doc)))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    hv::panic_impl(info)
}
