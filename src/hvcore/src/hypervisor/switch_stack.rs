use alloc::alloc::handle_alloc_error;
use core::{alloc::Layout, arch::global_asm};

use crate::hypervisor::support::Page;

use super::registers::Registers;

/// Switches the current stack to newly allocated 0x40000-byte space and jumps
/// to `destination`.
pub(crate) fn jump_with_new_stack(destination: fn(&Registers) -> !, registers: &Registers) -> ! {
    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();
    let stack = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x8;
    log::trace!("Stack range: {:#x?}", (stack as u64..stack_base));

    unsafe { switch_stack(registers, destination as *const () as _, stack_base) };
}

unsafe extern "C" {
    /// Jumps to the landing code with the new stack pointer.
    unsafe fn switch_stack(registers: &Registers, destination: usize, stack_base: u64) -> !;
}
global_asm!(
    r#"
    .align 16
    .global switch_stack
    switch_stack:
        xchg    bx, bx
        mov     rsp, r8
        jmp     rdx
"#
);
