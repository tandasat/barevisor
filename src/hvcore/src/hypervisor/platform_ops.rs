use alloc::{boxed::Box, sync::Arc};
use spin::Once;

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
    let ops = Arc::new(ops);
    PLATFORM_OPS.call_once(|| Ops { ops });
}

/// Returns the platform specific API.
pub fn get() -> Arc<Box<dyn PlatformOps>> {
    PLATFORM_OPS.get().unwrap().ops.clone()
}

struct Ops {
    ops: Arc<Box<dyn PlatformOps>>,
}
unsafe impl Send for Ops {}
unsafe impl Sync for Ops {}

static PLATFORM_OPS: Once<Ops> = Once::new();
