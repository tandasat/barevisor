use alloc::ffi::CString;
use wdk_sys::{ntddk::DbgPrintEx, DPFLTR_ERROR_LEVEL, _DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID};

#[macro_export]
macro_rules! eprintln {
    () => {
      ($crate::print!("\n"));
    };

    ($($arg:tt)*) => {
      ($crate::print!("{}\n", format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
      ($crate::eprintln::_print(format_args!($($arg)*)))
    };
}

#[doc(hidden)]
pub(crate) fn _print(args: core::fmt::Arguments<'_>) {
    let fmt = CString::new("%s").unwrap();
    let msg = CString::new(alloc::format!("{args}")).unwrap();

    let _ = unsafe {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID as _,
            DPFLTR_ERROR_LEVEL,
            fmt.as_ptr(),
            msg.as_ptr(),
        )
    };
}
