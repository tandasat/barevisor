.macro INTERRUPT_HANDLER
    .align 16
    .global asm_interrupt_handler\@
    asm_interrupt_handler\@:
        push    0
        push    \@
        jmp     asm_interrupt_handler_common
.endm

.macro INTERRUPT_HANDLER_WITH_ERROR_CODE
    .align 16
    .global asm_interrupt_handler\@
    asm_interrupt_handler\@:
        push    \@
        jmp     asm_interrupt_handler_common
.endm

.align 16
.global asm_interrupt_handler_common
asm_interrupt_handler_common:
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
    mov     rcx, rsp

    mov     r15, rsp
    and     rsp, 0xfffffffffffffff0
    sub     rsp, 0x60
    movaps  [rsp +    0], xmm0
    movaps  [rsp + 0x10], xmm1
    movaps  [rsp + 0x20], xmm2
    movaps  [rsp + 0x30], xmm3
    movaps  [rsp + 0x40], xmm4
    movaps  [rsp + 0x50], xmm5

    sub     rsp, 0x20
    call    handle_host_exception
    add     rsp, 0x20

    movaps  xmm5, [rsp + 0x50]
    movaps  xmm4, [rsp + 0x40]
    movaps  xmm3, [rsp + 0x30]
    movaps  xmm2, [rsp + 0x20]
    movaps  xmm1, [rsp + 0x10]
    movaps  xmm0, [rsp +    0]
    add     rsp, 0x60
    mov     rsp, r15

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

    add     rsp, 0x10
    iretq

.align 16
.global asm_interrupt_handler_common_end
asm_interrupt_handler_common_end:
.fill 0x80, 1, 0

INTERRUPT_HANDLER   ;// Interrupt 0-7
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER_WITH_ERROR_CODE   ;// Interrupt 8
INTERRUPT_HANDLER
INTERRUPT_HANDLER_WITH_ERROR_CODE   ;// Interrupt 10-14
INTERRUPT_HANDLER_WITH_ERROR_CODE
INTERRUPT_HANDLER_WITH_ERROR_CODE
INTERRUPT_HANDLER_WITH_ERROR_CODE
INTERRUPT_HANDLER_WITH_ERROR_CODE
INTERRUPT_HANDLER   ;// Interrupt 15-16
INTERRUPT_HANDLER
INTERRUPT_HANDLER_WITH_ERROR_CODE   ;// Interrupt 17
INTERRUPT_HANDLER   ;// Interrupt 18-20
INTERRUPT_HANDLER
INTERRUPT_HANDLER
INTERRUPT_HANDLER_WITH_ERROR_CODE   ;// Interrupt 21
.rept   234
INTERRUPT_HANDLER
.endr
