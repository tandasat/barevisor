use core::alloc::Layout;

use alloc::{alloc::handle_alloc_error, boxed::Box};
use x86::bits64::paging::BASE_PAGE_SIZE;

pub fn zeroed_box<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}

/// The structure representing a single memory page (4KB).
//
// This does not _always_ have to be allocated at the page aligned address, but
// very often it is, so let us specify the alignment.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub struct Page([u8; BASE_PAGE_SIZE]);
