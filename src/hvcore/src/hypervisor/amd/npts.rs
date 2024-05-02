use alloc::boxed::Box;
use bit_field::BitField;
use x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE};

use crate::hypervisor::{
    paging_structures::{build_identity_, Entry, PagingStructuresRaw, Pt},
    platform_ops,
    support::zeroed_box,
};

#[derive(Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub(crate) struct NestedPageTables {
    ptr: Box<PagingStructuresRaw>,
}

impl NestedPageTables {
    pub(crate) fn new() -> Self {
        Self {
            ptr: zeroed_box::<PagingStructuresRaw>(),
        }
    }

    pub(crate) fn split_2mb(&mut self, pa: u64) {
        let pdpt_index = pa.get_bits(30..=38) as usize; // [38:30]
        let pd_index = pa.get_bits(21..=29) as usize; // [29:21]
        let pde = &mut self.ptr.pd[pdpt_index].0.entries[pd_index];
        NestedPageTables::split_2mb_(pde, &mut self.ptr.pt_apic);
    }

    pub(crate) fn apic_pt(&mut self) -> &mut Pt {
        &mut self.pt_apic
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

impl NestedPageTables {
    pub(crate) fn build_identity(&mut self) {
        build_identity_(self.as_mut(), true);
    }
}
