use alloc::boxed::Box;

/// A set of platform specific API to be called during the host setup phase.
pub trait PlatformOps {
    /// Runs `callback` on all logical processors one by one.
    // This function cannot be called in a nested manner.
    fn run_on_all_processors(&self, callback: fn());

    // Returns a physical address of a linear address specified by `va`.
    fn pa(&self, va: *const core::ffi::c_void) -> u64;
}

/// Initializes the platform specific API as provided by `ops`.
// NOTE: We can or should release this once the host is set up.
pub fn init(ops: Box<dyn PlatformOps>) {
    unsafe { PLATFORM_OPS = Some(Box::leak(ops)) };
}

/// Returns the platform specific API.
pub fn get() -> &'static dyn PlatformOps {
    *unsafe { PLATFORM_OPS.as_ref() }.unwrap()
}

static mut PLATFORM_OPS: Option<&dyn PlatformOps> = None;
