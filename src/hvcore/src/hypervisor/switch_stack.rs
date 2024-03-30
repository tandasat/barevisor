use alloc::alloc::handle_alloc_error;
use core::{alloc::Layout, arch::global_asm};

use crate::utils::support::Page;

/// Installs the hypervisor on the current processor.
pub(crate) fn jump_with_new_stack(
    params: &super::vmm::VCpuParameters,
    destination: fn(&super::vmm::VCpuParameters) -> !,
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

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(regs: &super::vmm::VCpuParameters, landing_code: usize, stack_base: u64) -> !;
}
global_asm!(include_str!("switch_stack.S"));
