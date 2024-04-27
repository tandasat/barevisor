use alloc::alloc::handle_alloc_error;
use core::{alloc::Layout, arch::global_asm};

use crate::hypervisor::support::Page;

use super::vmm::VCpuParameters;

/// Installs the hypervisor on the current processor.
pub(crate) fn jump_with_new_stack(
    params: &VCpuParameters,
    destination: fn(&VCpuParameters) -> !,
) -> ! {
    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();
    let stack = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x8;
    log::trace!("Stack range: {:#x?}", (stack as u64..stack_base));

    unsafe { switch_stack(params, destination as *const () as _, stack_base) };
}

extern "C" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(regs: &VCpuParameters, landing_code: usize, stack_base: u64) -> !;
}
global_asm!(
    r#"
    .global switch_stack
    switch_stack:
        xchg    bx, bx
        mov     rsp, r8
        jmp     rdx
"#
);
