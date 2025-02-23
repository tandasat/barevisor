use core::ffi::c_void;

use hv::platform_ops::PlatformOps;
use uefi::{prelude::*, proto::pi::mp::MpServices};

pub(crate) struct UefiOps;

impl PlatformOps for UefiOps {
    fn run_on_all_processors(&self, callback: fn()) {
        let handle = boot::get_handle_for_protocol::<MpServices>().unwrap();
        let mp_services = boot::open_protocol_exclusive::<MpServices>(handle).unwrap();

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
