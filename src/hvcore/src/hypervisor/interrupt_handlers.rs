//! This module implements initialization of the host IDT and host interrupt handlers.

use core::arch::global_asm;

use alloc::boxed::Box;
use x86::{bits64::rflags::RFlags, dtables::DescriptorTablePointer, segmentation::SegmentSelector};

use crate::hypervisor::x86_instructions::cr2;

use super::support::zeroed_box;

/// Logical representation of the IDT.
#[derive(Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub struct InterruptDescriptorTable {
    ptr: Box<InterruptDescriptorTableRaw>,
}

impl InterruptDescriptorTable {
    pub fn new(cs: SegmentSelector) -> Self {
        // Build the IDT. Each interrupt handler (ie. asm_interrupt_handlerN) is
        // 16 byte long and can be located from asm_interrupt_handler0.
        let mut idt = zeroed_box::<InterruptDescriptorTableRaw>();
        for i in 0..idt.0.len() {
            let handler = asm_interrupt_handler0 as usize + 0x10 * i;
            idt.0[i] = InterruptDescriptorTableEntry::new(handler, cs);
        }

        Self { ptr: idt }
    }

    pub(crate) fn idtr(&self) -> DescriptorTablePointer<u64> {
        let mut idtr = DescriptorTablePointer::<u64>::default();
        let base = self.ptr.as_ref() as *const _;
        idtr.base = base as _;
        idtr.limit = u16::try_from(core::mem::size_of_val(self.ptr.as_ref()) - 1).unwrap();
        idtr
    }
}

#[derive(Debug)]
#[repr(C, align(4096))]
pub struct InterruptDescriptorTableRaw([InterruptDescriptorTableEntry; 0x100]);
const _: () = assert!(core::mem::size_of::<InterruptDescriptorTableRaw>() == 4096);

#[derive(Debug)]
#[repr(C, align(16))]
pub struct InterruptDescriptorTableEntry {
    offset_low: u16,
    selector: u16,
    reserved_1: u8,
    gate_type: u8,
    offset_high: u16,
    offset_upper: u32,
    reserved_2: u32,
}
const _: () = assert!(core::mem::size_of::<InterruptDescriptorTableEntry>() == 16);

impl InterruptDescriptorTableEntry {
    fn new(handler: usize, cs: SegmentSelector) -> Self {
        // P=1, DPL=00b, S=0, type=1110b => type_attr=1000_1110b => 0x8E
        const INTERRUPT_GATE: u8 = 0x8E;
        Self {
            offset_low: handler as _,
            selector: cs.bits(),
            reserved_1: 0,
            gate_type: INTERRUPT_GATE,
            offset_high: (handler >> 16) as _,
            offset_upper: (handler >> 32) as _,
            reserved_2: 0,
        }
    }
}

/// The layout of the stack passed to [`handle_host_exception`].
#[derive(Debug)]
#[repr(C)]
struct HostExceptionStack {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    exception_number: u64, // Software saved (see interrupt_handler.S)
    error_code: u64,       // Software or hardware saved (see interrupt_handler.S)
    rip: u64,              // Hardware saved
    cs: u64,               // Hardware saved
    rflags: RFlags,        // Hardware saved
    rsp: u64,              // Hardware saved
    ss: u64,               // Hardware saved
}

/// The host interrupt handler.
#[unsafe(no_mangle)]
extern "C" fn handle_host_exception(stack: *mut HostExceptionStack) {
    assert!(!stack.is_null());
    let stack = unsafe { &*stack };
    panic!(
        "Exception {} occurred in host: {stack:#x?}, cr2: {:#x?}",
        stack.exception_number,
        cr2(),
    );
}

global_asm!(include_str!("interrupt_handlers.S"));
unsafe extern "C" {
    unsafe fn asm_interrupt_handler0();
}
