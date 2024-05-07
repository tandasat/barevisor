use alloc::boxed::Box;
use bit_field::BitField;
use x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE};

use crate::hypervisor::{
    paging_structures::{build_identity_internal, Entry, PagingStructuresRaw, Pt},
    platform_ops,
    support::zeroed_box,
    x86_instructions::rdmsr,
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

    pub(crate) fn build_identity(&mut self) {
        build_identity_internal(self.as_mut(), true);
    }

    pub(crate) fn apic_pt(&mut self) -> &mut Pt {
        &mut self.pt_apic
    }

    /// Splits the 2MB NTP entry for the APIC base page into 4KB entries.
    pub(crate) fn split_apic_page(&mut self) {
        let apic_base_raw = rdmsr(x86::msr::IA32_APIC_BASE);
        assert!(!apic_base_raw.get_bit(10), "x2APIC is enabled");
        assert!(apic_base_raw.get_bit(11), "APIC is disabled");
        let apic_base = apic_base_raw & !0xfff;

        let pdpt_index = apic_base.get_bits(30..=38) as usize; // [38:30]
        let pd_index = apic_base.get_bits(21..=29) as usize; // [29:21]
        let pde = &mut self.ptr.pd[pdpt_index].0.entries[pd_index];
        Self::split_2mb(pde, &mut self.ptr.pt_apic);
    }

    /// Update the `pde` to point to `pt` to split the page from 2MB to 4KBs.
    fn split_2mb(pde: &mut Entry, pt: &mut Pt) {
        assert!(pde.present());
        assert!(pde.large());

        let writable = pde.writable();
        let user = pde.user();
        let mut pfn = pde.pfn();
        for pte in &mut pt.0.entries {
            assert!(!pte.present());
            pte.set_present(true);
            pte.set_writable(writable);
            pte.set_user(user);
            pte.set_large(false);
            pte.set_pfn(pfn);
            pfn += BASE_PAGE_SIZE as u64;
        }

        let pt_pa = platform_ops::get().pa(pt as *mut _ as _);
        pde.set_pfn(pt_pa >> BASE_PAGE_SHIFT);
        pde.set_large(false);
    }
}
