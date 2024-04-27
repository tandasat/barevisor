use core::arch::global_asm;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct Registers {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rbp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rflags: u64,
    pub(crate) rsp: u64,
    pub(crate) rip: u64,
    pub(crate) xmm0: Xmm,
    pub(crate) xmm1: Xmm,
    pub(crate) xmm2: Xmm,
    pub(crate) xmm3: Xmm,
    pub(crate) xmm4: Xmm,
    pub(crate) xmm5: Xmm,
}
const _: () = assert!(core::mem::size_of::<Registers>() == 0xf0);

impl Registers {
    #[inline(always)]
    pub(crate) fn capture_current() -> Self {
        let mut registers = Registers::default();
        unsafe { capture_registers(&mut registers) };
        registers
    }
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Xmm {
    pub(crate) low: u64,
    pub(crate) hight: u64,
}

extern "C" {
    /// Captures current register values.
    fn capture_registers(registers: &mut Registers);
}
global_asm!(include_str!("capture_registers.inc"));
global_asm!(include_str!("capture_registers.S"));
