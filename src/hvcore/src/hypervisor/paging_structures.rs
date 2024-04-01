use alloc::boxed::Box;
use core::ptr::addr_of;
use x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE};

use super::{platform_ops, support::zeroed_box};

#[derive(Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub struct PagingStructures {
    pub ptr: Box<PagingStructuresRaw>,
}

impl PagingStructures {
    pub fn new() -> Self {
        Self {
            ptr: zeroed_box::<PagingStructuresRaw>(),
        }
    }
}

impl Default for PagingStructures {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
#[repr(C, align(4096))]
pub struct PagingStructuresRaw {
    pub(crate) pml4: Pml4,
    pub(crate) pdpt: Pdpt,
    pub(crate) pd: [Pd; 512],
    pub(crate) pt: Pt,
}

pub(crate) fn build_identity_(ps: &mut PagingStructuresRaw, npt: bool) {
    let ops = platform_ops::get();
    let user = npt;

    let pml4 = &mut ps.pml4;
    pml4.0.entries[0].set_present(true);
    pml4.0.entries[0].set_writable(true);
    pml4.0.entries[0].set_user(true);
    pml4.0.entries[0].set_pfn(ops.pa(addr_of!(ps.pdpt) as _) >> BASE_PAGE_SHIFT);

    let mut pa = 0;
    for (i, pdpte) in ps.pdpt.0.entries.iter_mut().enumerate() {
        pdpte.set_present(true);
        pdpte.set_writable(true);
        pdpte.set_user(user);
        pdpte.set_pfn(ops.pa(addr_of!(ps.pd[i]) as _) >> BASE_PAGE_SHIFT);
        for pde in &mut ps.pd[i].0.entries {
            pde.set_present(true);
            pde.set_writable(true);
            pde.set_user(user);
            pde.set_large(true);
            pde.set_pfn(pa >> BASE_PAGE_SHIFT);
            pa += LARGE_PAGE_SIZE as u64;
        }
    }
}

impl PagingStructuresRaw {
    pub fn build_identity(&mut self) {
        build_identity_(self, false);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pml4(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pdpt(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pd(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pt(#[allow(dead_code)] pub(crate) Table);

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Table {
    pub(crate) entries: [Entry; 512],
}

bitfield::bitfield! {
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub user, set_user: 2;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
}
