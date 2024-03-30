use alloc::boxed::Box;

use crate::SystemOps;

static mut PLATFORM_OPS: Option<&dyn SystemOps> = None;

// FIXME: consider nullifying this after setup.
pub fn init(ops: Box<dyn SystemOps>) {
    unsafe { PLATFORM_OPS = Some(Box::leak(ops)) };
}

pub fn ops() -> &'static dyn SystemOps {
    *unsafe { PLATFORM_OPS.as_ref() }.unwrap()
}
