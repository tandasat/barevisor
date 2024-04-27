;// The module containing the `run_svm_guest` function.



.global asm_vmsave
asm_vmsave:
    mov     rax, rcx
    vmsave  rax
    ret

;// Runs the guest until #VMEXIT occurs.
;//
;// This function works as follows:
;// 1. saves host general purpose register values to stack.
;// 2. loads guest general purpose register values from `GuestRegisters`.
;// 3. executes the VMRUN instruction that
;//     1. saves host register values to the host state area, as specified by
;//        the VM_HSAVE_PA MSR.
;//     2. loads guest register values from the VMCB.
;//     3. starts running code in guest-mode until #VMEXIT.
;// 4. on #VMEXIT, the processor
;//     1. saves guest register values to the VMCB.
;//     2. loads host register values from the host state area.
;//        Some registers are reset to hard-coded values. For example, interrupts
;//        are always disabled.
;//     3. updates VMCB's EXITCODE field with the reason of #VMEXIT.
;//     4. starts running code in host-mode.
;// 5. saves guest general purpose register values to `GuestRegisters`.
;// 6. loads host general purpose register values from stack.
;//
;// Note that state switch implemented here is not complete, and some register
;// values are "leaked" to the other side, for example, XMM registers, and those
;// that are managed with VMSAVE and VMLOAD instructions.
;//
;// See: 15.5 VMRUN Instruction
;//      15.6 #VMEXIT
;//
;// extern "C" fn run_svm_guest(registers: &mut GuestRegisters, vmcb_pa: u64);
.global run_svm_guest
run_svm_guest:
    xchg    bx, bx

    ;// Save current (host) general purpose registers onto stack.
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    ;// Save current (host) XMM registers onto stack too.
    sub     rsp, 0x60
    movaps  xmmword ptr [rsp], xmm0
    movaps  xmmword ptr [rsp + 0x10], xmm1
    movaps  xmmword ptr [rsp + 0x20], xmm2
    movaps  xmmword ptr [rsp + 0x30], xmm3
    movaps  xmmword ptr [rsp + 0x40], xmm4
    movaps  xmmword ptr [rsp + 0x50], xmm5

    ;// Copy `registers` and `vmcb_pa` for use. Then, save
    ;// `registers` at the top of stack so that after #VMEXIT, we can find it.
    mov     r15, rcx    ;// r15 <= `registers`
    mov     rax, rdx    ;// rax <= `vmcb_pa`
    push    rcx         ;// [rsp] <= `registers` (#1)

    ;// Restore guest general purpose and XMM registers from `registers` and try VMRESUME.
    movaps  xmm0, [r15 + registers_xmm0]
    movaps  xmm1, [r15 + registers_xmm1]
    movaps  xmm2, [r15 + registers_xmm2]
    movaps  xmm3, [r15 + registers_xmm3]
    movaps  xmm4, [r15 + registers_xmm4]
    movaps  xmm5, [r15 + registers_xmm5]

    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]

    ;// Run the guest until #VMEXIT occurs.
    vmload  rax     ;// Load registers from VMCB
    vmrun   rax
    vmsave  rax     ;// Save guest registers to VMCB

    ;// #VMEXIT occurred. Save current (guest) general purpose and XMM registers.
    xchg    bx, bx
    xchg    r15, [rsp]  ;// r15 <= `registers` and [rsp] <= guest r15
    mov     [r15 + registers_rbx], rbx
    mov     [r15 + registers_rcx], rcx
    mov     [r15 + registers_rdx], rdx
    mov     [r15 + registers_rsi], rsi
    mov     [r15 + registers_rdi], rdi
    mov     [r15 + registers_rbp], rbp
    mov     [r15 + registers_r8],  r8
    mov     [r15 + registers_r9],  r9
    mov     [r15 + registers_r10], r10
    mov     [r15 + registers_r11], r11
    mov     [r15 + registers_r12], r12
    mov     [r15 + registers_r13], r13
    mov     [r15 + registers_r14], r14
    mov     rax, [rsp]  ;// rax <= guest R15
    mov     [r15 + registers_r15], rax
    movaps  [r15 + registers_xmm0], xmm0
    movaps  [r15 + registers_xmm1], xmm1
    movaps  [r15 + registers_xmm2], xmm2
    movaps  [r15 + registers_xmm3], xmm3
    movaps  [r15 + registers_xmm4], xmm4
    movaps  [r15 + registers_xmm5], xmm5

.Exit:
    ;// Discard the stack value pushed at #1.
    pop     rax

    movaps  xmm5, xmmword ptr [rsp + 0x50]
    movaps  xmm4, xmmword ptr [rsp + 0x40]
    movaps  xmm3, xmmword ptr [rsp + 0x30]
    movaps  xmm2, xmmword ptr [rsp + 0x20]
    movaps  xmm1, xmmword ptr [rsp + 0x10]
    movaps  xmm0, xmmword ptr [rsp]
    add     rsp, 0x60

    ;// Restore host general purpose registers from stack.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    ;// From the host VMCS, restore some of register values that are not restored
    ;// with #VMEXIT.
    mov     rax, r8
    vmload  rax

    ret
