use core::fmt::Write;

use spin::Mutex;
use wdk_sys::{ntddk::DbgPrintEx, DPFLTR_ERROR_LEVEL, _DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID};

/// Debug prints a message to a kernel debugger with a newline.
#[macro_export]
macro_rules! eprintln {
    () => {
        ($crate::print!("\n"));
    };

    ($($arg:tt)*) => {
        ($crate::print!("{}\n", format_args!($($arg)*)))
    };
}

/// Debug prints a message to a kernel debugger without a newline.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        ($crate::eprintln::print(format_args!($($arg)*)))
    };
}

#[doc(hidden)]
pub(crate) fn print(args: core::fmt::Arguments<'_>) {
    Write::write_fmt(&mut *DEBUG_PRINTER.lock(), args).unwrap();
}

static DEBUG_PRINTER: Mutex<DbgOutput> = Mutex::new(DbgOutput);

struct DbgOutput;

impl Write for DbgOutput {
    fn write_str(&mut self, msg: &str) -> core::fmt::Result {
        if !msg.is_ascii() {
            return Err(core::fmt::Error);
        }

        // Avoid heap allocation so the eprint(ln) macros are usable before
        // initializing the allocator.
        let mut buffer = [0u8; 256];
        let length = core::cmp::min(buffer.len() - 1, msg.len());
        buffer[..length].copy_from_slice(msg.as_bytes());
        let msg_ptr = buffer.as_mut_ptr().cast::<i8>();
        let _ = unsafe {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID as _,
                DPFLTR_ERROR_LEVEL,
                c"%s".as_ptr(),
                msg_ptr,
            )
        };
        Ok(())
    }
}
