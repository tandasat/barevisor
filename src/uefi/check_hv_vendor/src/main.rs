#![no_main]
#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::string::String;
use uefi::{prelude::*, proto::pi::mp::MpServices};
use uefi_services::{println, system_table};

static PROCESSOR_COUNT: AtomicUsize = AtomicUsize::new(0);

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    match uefi_services::init(&mut system_table) {
        Ok(event_opt) => {
            if let Some(event) = event_opt {
                // Do not leak the event. This would cause UAF otherwise.
                system_table.boot_services().close_event(event).unwrap();
            }
        }
        Err(e) => return e.status(),
    };

    println!("Executing CPUID(0x40000000) on all logical processors");
    if let Err(e) = run_on_all_processors(|| {
        let core_id = PROCESSOR_COUNT.fetch_add(1, Ordering::Relaxed);
        let regs = raw_cpuid::cpuid!(0x4000_0000);
        let mut vec = regs.ebx.to_le_bytes().to_vec();
        vec.extend(regs.ecx.to_le_bytes());
        vec.extend(regs.edx.to_le_bytes());
        println!(
            "CPU{:2}: {}",
            core_id,
            String::from_utf8_lossy(vec.as_slice())
        );
    }) {
        println!("{e}");
        return e.status();
    }

    Status::SUCCESS
}

fn run_on_all_processors(callback: fn()) -> uefi::Result<()> {
    let st = system_table();
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

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("{info}");
    loop {}
}
