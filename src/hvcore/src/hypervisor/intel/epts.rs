use core::ptr::addr_of;

use x86::bits64::paging::{
    BASE_PAGE_SHIFT, BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE, PML4_SLOT_SIZE,
};

use crate::{hypervisor::intel::mtrr::MemoryType, hypervisor::platform_ops};

use super::mtrr::Mtrr;

#[repr(C, align(4096))]
pub(crate) struct Epts {
    pml4: Pml4,
    pdpt: [Pdpt; 512],
    pd: [Pd; 512],
    pt: Pt,
}

impl Epts {
    pub(crate) fn build_identity(&mut self) {
        let mtrr = Mtrr::new();
        log::trace!("{mtrr:#x?}");
        log::trace!("Initializing EPTs");

        let ops = platform_ops::get();

        let mut pa = 0u64;

        // First, initialize the entry 0 of PML4 and sub tables, covering up to
        // 512GB. This area includes physical memory backed by DRAM. Translations
        // are managed by 4KB EPT PTs for the first 2MB, and by 2MB EPT PDs for
        // the rest to reflect MTRR memory types into EPT memory types.
        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(ops.pa(addr_of!(self.pdpt[0]) as _) >> BASE_PAGE_SHIFT);
        for (i, pdpte) in self.pdpt[0].0.entries.iter_mut().enumerate() {
            // Initialize each PDPT.
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(ops.pa(addr_of!(self.pd[i]) as _) >> BASE_PAGE_SHIFT);

            // Initialize each PD.
            for pde in &mut self.pd[i].0.entries {
                if pa == 0 {
                    // First 2MB. Managed by 4KB EPT PTs.

                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(ops.pa(addr_of!(self.pt) as _) >> BASE_PAGE_SHIFT);

                    // Initialize each PT.
                    for pte in &mut self.pt.0.entries {
                        let memory_type =
                            mtrr.find(pa..pa + BASE_PAGE_SIZE as u64)
                                .unwrap_or_else(|| {
                                    panic!("Could not resolve a memory type for {pa:#x?}")
                                });
                        pte.set_readable(true);
                        pte.set_writable(true);
                        pte.set_executable(true);
                        pte.set_memory_type(memory_type as u64);
                        pte.set_pfn(pa >> BASE_PAGE_SHIFT);
                        pa += BASE_PAGE_SIZE as u64;
                    }
                } else {
                    // The rest. Managed by 2MB EPT PDs.
                    let memory_type =
                        mtrr.find(pa..pa + LARGE_PAGE_SIZE as u64)
                            .unwrap_or_else(|| {
                                log::warn!("Could not resolve a memory type for {pa:#x?}");
                                // Failing back to uncacheable as the safest option.
                                MemoryType::Uncachable
                            });
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }

        // Initialize remaining 511 PML4 entries with 1GB EPT PDPTs. This area
        // is for MMIO. We can use 1GB pages as we assume that MTRR configuration
        // is compatible with the 1GB page glanularity.
        assert!(pa == PML4_SLOT_SIZE as u64);
        for (pml4_index, pml4e) in self.pml4.0.entries.iter_mut().enumerate().skip(1) {
            pml4e.set_readable(true);
            pml4e.set_writable(true);
            pml4e.set_executable(true);
            pml4e.set_pfn(ops.pa(addr_of!(self.pdpt[pml4_index]) as _) >> BASE_PAGE_SHIFT);

            // Initialize each PDPT with 1GB pages.
            for pdpte in &mut self.pdpt[pml4_index].0.entries {
                let memory_type = mtrr
                    .find(pa..pa + HUGE_PAGE_SIZE as u64)
                    .unwrap_or_else(|| panic!("Could not resolve a memory type for {pa:#x?}"));
                pdpte.set_readable(true);
                pdpte.set_writable(true);
                pdpte.set_executable(true);
                pdpte.set_memory_type(memory_type as u64);
                pdpte.set_large(true);
                pdpte.set_pfn(pa >> BASE_PAGE_SHIFT);
                pa += HUGE_PAGE_SIZE as u64;
            }
        }
    }

    /// Returns an EPT pointer for this EPT.
    pub(crate) fn eptp(&self) -> EptPointer {
        let mut eptp = EptPointer::default();
        let ept_pml4_pa = platform_ops::get().pa(addr_of!(*self) as *const _);
        eptp.set_pfn(ept_pml4_pa >> BASE_PAGE_SHIFT);

        // Lower 12-bits of EPTP is made up of flags. We use the write-back memory
        // type for accessing to any of EPT paging-structures, as it is most
        // efficient.
        // See: 29.3.7.1 Memory Type Used for Accessing EPT Paging Structures
        eptp.set_memory_type(MemoryType::WriteBack as _);

        // "This value is 1 less than the EPT page-walk length."
        // "The EPT translation mechanism (...) uses a page-walk length of 4".
        // See: Table 25-9. Format of Extended-Page-Table Pointer
        // See: 29.3.2 EPT Translation Mechanism
        eptp.set_page_levels_minus_one(3);
        eptp
    }
}

bitfield::bitfield! {
    /// A 64-bit VMCS field value to teach the processor how to walk EPTs.
    // It is equivalent to the CR3 in the normal
    // paging structure walk, in a sense that EPTP points to the base address
    // of the structures to walk, ie, EPTs.
    // See: 25.6.11 Extended-Page-Table Pointer (EPTP)
    // See: Table 25-9. Format of Extended-Page-Table Pointer
    #[derive(Clone, Copy, Default)]
    pub struct EptPointer(u64);
    impl Debug;
    memory_type, set_memory_type: 2, 0;
    page_levels_minus_one, set_page_levels_minus_one: 5, 3;
    enable_access_dirty, set_enable_access_dirty: 6;
    enable_sss, set_enable_sss: 7;
    pfn, set_pfn: 51, 12;
}

#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

#[derive(Debug, Clone, Copy)]
struct Pd(Table);

#[derive(Debug, Clone, Copy)]
struct Pt(Table);

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct Table {
    entries: [Entry; 512],
}

bitfield::bitfield! {
    /// Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
    #[derive(Clone, Copy)]
    struct Entry(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    large, set_large: 7;
    pfn, set_pfn: 51, 12;
}
