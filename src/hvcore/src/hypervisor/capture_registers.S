# The module implements the `capture_registers` function.

# Captures current register values.
#
# extern "C" fn capture_registers(registers: &mut GuestRegisters);
.align 16
.global capture_registers
capture_registers:
    # Capture general purpose and volatile XMM registers.
    mov     [rcx + registers_rax], rax
    mov     [rcx + registers_rbx], rbx
    mov     [rcx + registers_rcx], rcx
    mov     [rcx + registers_rdx], rdx
    mov     [rcx + registers_rsi], rsi
    mov     [rcx + registers_rdi], rdi
    mov     [rcx + registers_rbp], rbp
    mov     [rcx + registers_r8],  r8
    mov     [rcx + registers_r9],  r9
    mov     [rcx + registers_r10], r10
    mov     [rcx + registers_r11], r11
    mov     [rcx + registers_r12], r12
    mov     [rcx + registers_r13], r13
    mov     [rcx + registers_r14], r14
    mov     [rcx + registers_r15], r15
    movaps  xmmword ptr [rcx + registers_xmm0], xmm0
    movaps  xmmword ptr [rcx + registers_xmm1], xmm1
    movaps  xmmword ptr [rcx + registers_xmm2], xmm2
    movaps  xmmword ptr [rcx + registers_xmm3], xmm3
    movaps  xmmword ptr [rcx + registers_xmm4], xmm4
    movaps  xmmword ptr [rcx + registers_xmm5], xmm5

    # Capture RFLAGS.
    pushfq
    pop     rax
    mov     [rcx + registers_rflags], rax

    # Capture RSP _before_ calling to this function.
    mov     rax, rsp
    add     rax, 8
    mov     [rcx + registers_rsp], rax

    # Capture the return address from the stack.
    mov     rax, [rsp]
    mov     [rcx + registers_rip], rax

    ret
