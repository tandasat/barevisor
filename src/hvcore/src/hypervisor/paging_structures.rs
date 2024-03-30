use alloc::boxed::Box;
use bit_field::BitField;
use core::ptr::addr_of;
use x86::{
    bits32::paging::BASE_PAGE_SIZE,
    current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE},
};

use super::{platform_ops, support::zeroed_box};

#[derive(Debug, Clone)]
pub struct NestedPageTables {
    pub ptr: Box<PagingStructuresRaw>,
}

impl NestedPageTables {
    pub fn new() -> Self {
        Self {
            ptr: zeroed_box::<PagingStructuresRaw>(),
        }
    }

    pub(crate) fn split_2mb(&mut self, pa: u64) {
        let pdpt_index = pa.get_bits(30..=38) as usize; // [38:30]
        let pd_index = pa.get_bits(21..=29) as usize; // [29:21]
        let pde = &mut self.ptr.pd[pdpt_index].0.entries[pd_index];
        NestedPageTables::split_2mb_(pde, &mut self.ptr.pt);
    }

    pub(crate) fn pt(&mut self) -> &mut Pt {
        &mut self.ptr.pt
    }

    fn split_2mb_(pde: &mut Entry, pt: &mut Pt) {
        assert!(pde.present());
        assert!(pde.writable());
        assert!(pde.user());
        assert!(pde.large());

        let mut pfn = pde.pfn();
        for pte in &mut pt.0.entries {
            assert!(!pte.present());
            pte.set_present(true);
            pte.set_writable(true);
            pte.set_user(true);
            pte.set_large(false);
            pte.set_pfn(pfn);
            pfn += BASE_PAGE_SIZE as u64;
        }

        let pt_pa = platform_ops::get().pa(pt as *mut _ as _);
        pde.set_pfn(pt_pa >> BASE_PAGE_SHIFT);

        pde.set_present(true);
        pde.set_writable(true);
        pde.set_user(true);
        pde.set_large(false);
    }
}

impl Default for NestedPageTables {
    fn default() -> Self {
        Self::new()
    }
}

impl NestedPageTables {
    pub fn build_identity(&mut self) {
        build_identity_(self.ptr.as_mut(), true);
    }
}

// TODO: reconsider this -Raw approach. I probably like explicit Box<Foo> better
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub struct PagingStructuresRaw {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: [Pd; 512],
    pt: Pt,
}

fn build_identity_(ps: &mut PagingStructuresRaw, npt: bool) {
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
