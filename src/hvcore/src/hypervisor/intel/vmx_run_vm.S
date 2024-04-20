;// The module containing the `vmx_run_vm` function.

;// Runs the guest until VM-exit occurs.
;//
;// This function works as follows:
;// 1. saves host register values to stack.
;// 2. loads guest register values from `GuestRegisters`.
;// 3. executes the VMLAUNCH or VMRESUME instruction that
;//     1. saves host register values to the VMCS.
;//     2. loads guest register values from the VMCS.
;//     3. starts running code in VMX non-root operation until VM-exit.
;// 4. on VM-exit, the processor
;//     1. saves guest register values to the VMCS.
;//     2. loads host register values from the VMCS. Some registers are reset to
;//        hard-coded values. For example, interrupts are always disabled.
;//     3. updates VM-exit information fields in VMCS to record causes of VM-exit.
;//     4. starts running code in the VMX root operation.
;// 5. saves guest register values to `GuestRegisters`.
;// 6. loads host register values from stack.
;//
;// On VM-exit, the processor comes back to this function (at "VmExit") because
;// the host RIP is configured so.
;//
;// extern "efiapi" fn vmx_run_vm(registers: &mut GuestRegisters) -> u64;
.global vmx_run_vm
vmx_run_vm:
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

    ;// Copy `registers` for use. Then, save it at the top of stack so that after
    ;// VM-exit, we can find it.
    mov     r15, rcx    ;// r15 <= `registers`
    push    rcx         ;// [rsp] <= `registers` (#1)

    ;// Restore guest general purpose and XMM registers from `registers` and try VMRESUME.
    movaps  xmm0, [r15 + registers_xmm0]
    movaps  xmm1, [r15 + registers_xmm1]
    movaps  xmm2, [r15 + registers_xmm2]
    movaps  xmm3, [r15 + registers_xmm3]
    movaps  xmm4, [r15 + registers_xmm4]
    movaps  xmm5, [r15 + registers_xmm5]
    mov     rax, [r15 + registers_rax]
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
    vmresume

    ;// VMRESUME failed. Save flags on stack as next VMREAD will overwrite it.
    pushf

    ;// If the failure is due to "VMRESUME with non-launched VMCS" (5), continue
    ;// and perform VMLAUNCH instead. It occurs on the first time.
    mov     r15, 0x4400 ;// VM-instruction error
    vmread  r15, r15
    cmp     r15, 5
    jz      .Launch
    popf                ;// Restore flags from stack
    jmp     .VmEntryFailure

.Launch:
    pop     r15         ;// Discard flags from stack
    ;// The VM has never launched with the current VMCS. Configure the host RSP
    ;// and RIP first. Then, restore the rest of guest general purpose registers
    ;// and run the guest until VM-exit occurs.
    xchg    bx, bx
    mov     r15, 0x6C14 ;// Host RSP
    vmwrite r15, rsp
    lea     r14, [rip + .VmExit]
    mov     r15, 0x6C16 ;// Host RIP
    vmwrite r15, r14
    mov     r15, [rsp]  ;// r15 <= `registers`
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]
    vmlaunch

.VmEntryFailure:
    ;// VMLAUNCH or VMRESUME failed. If it were successful, VM-exit should have
    ;// led to "VmExit", not here.
    jmp     .Exit

.VmExit:
    ;// VM-exit occurred. Save current (guest) general purpose and XMM registers.
    xchg    bx, bx
    xchg    r15, [rsp]  ;// r15 <= `registers` and [rsp] <= guest r15
    mov     [r15 + registers_rax], rax
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

    ;// Return the rflags value.
    pushfq
    pop     rax
    ret
