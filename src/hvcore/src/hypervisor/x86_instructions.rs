//! The module containing wrapper functions for x86 instructions.
//!
//! Those instructions provided by the `x86` crate as `unsafe` functions, due to
//! the fact that those require certain preconditions. The wrappers provided by
//! this module encapsulate those `unsafe`-ness since this project always
//! satisfies the preconditions and safe to call them at any context.

use core::arch::asm;

use x86::{
    bits64::rflags::RFlags,
    controlregs::{Cr0, Cr4, Xcr0},
    dtables::DescriptorTablePointer,
    segmentation::SegmentSelector,
};

/// Reads an MSR.
pub(crate) fn rdmsr(msr: u32) -> u64 {
    unsafe { x86::msr::rdmsr(msr) }
}

/// Writes a value to an MSR.
pub(crate) fn wrmsr(msr: u32, value: u64) {
    unsafe { x86::msr::wrmsr(msr, value) };
}

/// Reads the CR0 register.
pub(crate) fn cr0() -> Cr0 {
    let value: usize;
    unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)) };
    unsafe { Cr0::from_bits_unchecked(value) }
}

/// Writes a value to the CR0 register.
pub(crate) fn cr0_write(val: Cr0) {
    unsafe { x86::controlregs::cr0_write(val) };
}

/// Reads the CR3 register.
pub(crate) fn cr3() -> u64 {
    unsafe { x86::controlregs::cr3() }
}

/// Reads the CR4 register.
pub(crate) fn cr4() -> Cr4 {
    let value: usize;
    unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags)) };
    unsafe { Cr4::from_bits_unchecked(value) }
}

/// Writes a value to the CR4 register.
pub(crate) fn cr4_write(val: Cr4) {
    unsafe { x86::controlregs::cr4_write(val) };
}

/// Write a value to the IDTR register.
pub(crate) fn lidt(idtr: &DescriptorTablePointer<u64>) {
    unsafe { x86::dtables::lidt(idtr) };
}

/// Reads the IDTR register.
pub(crate) fn sidt() -> DescriptorTablePointer<u64> {
    let mut idtr = DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sidt(&mut idtr) };
    idtr
}

/// Reads the GDTR.
pub(crate) fn sgdt() -> DescriptorTablePointer<u64> {
    let mut gdtr = DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sgdt(&mut gdtr) };
    gdtr
}

//
pub(crate) fn lsl(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut limit: u64;
    unsafe {
        asm!(
            "lsl {}, {}",
            "pushfq",
            "pop {}",
            out(reg) limit,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
        );
    };
    if RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF) {
        limit as _
    } else {
        0
    }
}

/// LAR-Load Access Rights Byte
pub(crate) fn lar(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut access_rights: u64;
    unsafe {
        asm!(
            "lar {}, {}",
            "pushfq",
            "pop {}",
            out(reg) access_rights,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
        );
    };
    if RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF) {
        access_rights as _
    } else {
        0
    }
}

pub(crate) fn xsetbv(xcr: u32, val: Xcr0) {
    assert!(xcr == 0);
    unsafe { x86::controlregs::xcr0_write(val) };
}

pub(crate) fn tr() -> SegmentSelector {
    unsafe { x86::task::tr() }
}

pub(crate) fn ldtr() -> SegmentSelector {
    unsafe { x86::dtables::ldtr() }
}
