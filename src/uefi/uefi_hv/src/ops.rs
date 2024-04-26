use core::ffi::c_void;

use hv::platform_ops::PlatformOps;
use uefi::{prelude::*, proto::pi::mp::MpServices};

pub(crate) struct UefiOps {
    system_table: SystemTable<Boot>,
}

impl UefiOps {
    pub(crate) fn new(system_table: &SystemTable<Boot>) -> Self {
        Self {
            system_table: unsafe { system_table.unsafe_clone() },
        }
    }
}

impl PlatformOps for UefiOps {
    fn processor_count(&self) -> u32 {
        let bs = self.system_table.boot_services();
        let handle = bs.get_handle_for_protocol::<MpServices>().unwrap();
        let mp_services = bs.open_protocol_exclusive::<MpServices>(handle).unwrap();
        u32::try_from(mp_services.get_number_of_processors().unwrap().enabled).unwrap()
    }

    fn run_on_all_processors(&self, callback: fn()) {
        let bs = self.system_table.boot_services();
        let handle = bs.get_handle_for_protocol::<MpServices>().unwrap();
        let mp_services = bs.open_protocol_exclusive::<MpServices>(handle).unwrap();

        callback();

        // The API may return NOT_STARTED if there is no AP on the system. Treat
        // it as ok and all other failures as error.
        if let Err(e) =
            mp_services.startup_all_aps(true, run_callback, callback as *mut _, None, None)
        {
            assert!(e.status() == Status::NOT_STARTED, "{e}");
        }
    }

    fn pa(&self, va: *const c_void) -> u64 {
        va as _
    }
}

extern "efiapi" fn run_callback(context: *mut c_void) {
    let callback: fn() = unsafe { core::mem::transmute(context) };
    callback();
}
