pub trait PlatformOps {
    fn processor_count(&self) -> u32;
    fn run_on_all_processors(&self, callback: fn());
    fn pa(&self, va: *const core::ffi::c_void) -> u64;
}

use alloc::boxed::Box;

static mut PLATFORM_OPS: Option<&dyn PlatformOps> = None;

// FIXME: consider nullifying this after setup.
pub fn init(ops: Box<dyn PlatformOps>) {
    unsafe { PLATFORM_OPS = Some(Box::leak(ops)) };
}

pub fn get() -> &'static dyn PlatformOps {
    *unsafe { PLATFORM_OPS.as_ref() }.unwrap()
}
