//! The hypervisor vendor checker for UEFI.
//!
//! ```shell
//! fs1:\> check_hv_vendor.efi
//! Executing CPUID(0x40000000) on all logical processors
//! CPU 0: Barevisor!
//! CPU 1: Barevisor!
//! CPU 2: Barevisor!
//! CPU 3: Barevisor!
//! ```

#![no_main]
#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::string::String;
use uefi::{prelude::*, println, proto::pi::mp::MpServices, table::system_table_boot};

static PROCESSOR_COUNT: AtomicUsize = AtomicUsize::new(0);

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    if let Err(e) = uefi::helpers::init(&mut system_table) {
        return e.status();
    }

    println!("Executing CPUID(0x40000000) on all logical processors");
    if let Err(e) = run_on_all_processors(|| {
        let core_id = PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed);
        let regs = raw_cpuid::cpuid!(0x4000_0000);
        let mut vec = regs.ebx.to_le_bytes().to_vec();
        vec.extend(regs.ecx.to_le_bytes());
        vec.extend(regs.edx.to_le_bytes());
        let vendor = if vec.iter().all(|&byte| (0x20..=0x7e).contains(&byte)) {
            String::from_utf8(vec).unwrap()
        } else {
            String::new()
        };
        println!("CPU{core_id:2}: {vendor}");
    }) {
        println!("{e}");
        return e.status();
    }

    Status::SUCCESS
}

fn run_on_all_processors(callback: fn()) -> uefi::Result<()> {
    let st = system_table_boot().unwrap();
    let bs = st.boot_services();
    let handle = bs.get_handle_for_protocol::<MpServices>()?;
    let mp_services = bs.open_protocol_exclusive::<MpServices>(handle)?;

    callback();

    // The API may return NOT_STARTED if there is no AP on the system. Treat it
    // as ok and all other failures as error.
    if let Err(e) = mp_services.startup_all_aps(true, run_callback, callback as *mut _, None, None)
    {
        if e.status() != Status::NOT_STARTED {
            return Err(e);
        }
    }
    Ok(())
}

extern "efiapi" fn run_callback(context: *mut core::ffi::c_void) {
    let callback: fn() = unsafe { core::mem::transmute(context) };
    callback();
}

#[cfg(not(any(test, doc)))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("{info}");
    loop {
        core::hint::spin_loop();
    }
}
