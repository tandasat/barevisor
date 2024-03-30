;// The module containing the `switch_stack` function.

;// Jumps to the landing code with the new stack pointer.
;//
;// fn switch_stack(regs: &GuestRegisters, landing_code: usize, stack_base: u64) -> !;
.global switch_stack
switch_stack:
    xchg    bx, bx
    mov     rsp, r8
    jmp     rdx
