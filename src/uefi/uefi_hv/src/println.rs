use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use uefi::table::{Boot, SystemTable};

pub(crate) fn init(system_table: &SystemTable<Boot>) {
    SYSTEM_TABLE.store(system_table.as_ptr().cast_mut(), Ordering::Release);
}

static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn system_table() -> SystemTable<Boot> {
    let ptr = SYSTEM_TABLE.load(Ordering::Acquire);
    unsafe { SystemTable::from_ptr(ptr) }.unwrap()
}

/// Debug prints a message to stdout with a newline.
#[macro_export]
macro_rules! println {
    () => {
        ($crate::print!("\n"));
    };

    ($($arg:tt)*) => {
        ($crate::print!("{}\n", format_args!($($arg)*)))
    };
}

/// Debug prints a message to stdout without a newline.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        ($crate::println::print(format_args!($($arg)*)))
    };
}

#[doc(hidden)]
pub(crate) fn print(args: core::fmt::Arguments<'_>) {
    core::fmt::Write::write_fmt(&mut system_table().stdout(), args).unwrap();
}
