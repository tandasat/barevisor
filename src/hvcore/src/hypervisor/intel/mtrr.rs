use core::{arch::asm, ops::Range};

use alloc::vec::Vec;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use x86::bits64::paging::BASE_PAGE_SHIFT;

use crate::hypervisor::x86_instructions::rdmsr;

#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
pub(crate) enum MemoryType {
    Uncachable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
    UncachableMinus = 7,
}

#[derive(Debug)]
pub(crate) struct Mtrr {
    default_memory_type: MemoryType,
    fixed: Vec<MemoryTypeRange>,
    variable: Vec<MemoryTypeRange>,
}

impl Mtrr {
    pub(crate) fn new() -> Self {
        let raw_mtrrs = RawMtrrs::new();
        log::trace!("{raw_mtrrs:#x?}");
        Self {
            default_memory_type: raw_mtrrs.default_memory_type,
            fixed: Self::convert_from_raw_fixed(&raw_mtrrs.fixed),
            variable: Self::convert_from_raw_variable(&raw_mtrrs.variable),
        }
    }

    pub(crate) fn find(&self, range: Range<u64>) -> Option<MemoryType> {
        // Look up the fixed range MTRRs if the range start within 1MB (which is managed
        // by the fixed range MTRRs), since the fixed range MTRRs are priority over
        // the variable range MTRRs.
        if range.start < 0x10_0000 {
            // If the range crosses the 1MB boundary, report error. For simplicity,
            // we do not attempt to resolve the memory type of the range that spans both
            // fixed and variable range MTRRs. The caller should query a memory type for
            // a shorter range instead. That is almost always required anyway since
            // lowest 1MB has variety of memory types through fixed range MTRRs.
            if range.end > 0x10_0000 {
                return None;
            }
            return self.find_from_fixed(range);
        }
        // Otherwise, look up the variable range MTRRs.
        self.find_from_variable(range)
    }

    fn find_from_fixed(&self, range: Range<u64>) -> Option<MemoryType> {
        // Return the memory type of the first range that contains the given range.
        // Within `self.fixed` there is no overlap of ranges, so the first match
        // is the only match.
        self.fixed
            .iter()
            .find(|mtrr| mtrr.range.contains(&range.start) && mtrr.range.contains(&(range.end - 1)))
            .map(|found| found.memory_type)
    }

    fn find_from_variable(&self, range: Range<u64>) -> Option<MemoryType> {
        let mut return_memory_type = None::<MemoryType>;
        for mtrr in &self.variable {
            if mtrr.range.contains(&range.start) {
                // If the entire range is not managed by this single entry, bail out.
                // This means the given range is managed by multiple conflicting MTRR
                // settings. The caller needs to call this function with smaller range.
                if !mtrr.range.contains(&(range.end - 1)) {
                    return None;
                }

                // Use if the current matching entry is for UC, as the UC memory type
                // takes precedence.
                if mtrr.memory_type == MemoryType::Uncachable {
                    return Some(mtrr.memory_type);
                }

                // The WT memory type takes precedence over the WB memory type.
                if let Some(memory_type) = return_memory_type {
                    if memory_type == MemoryType::WriteBack
                        && mtrr.memory_type == MemoryType::WriteThrough
                    {
                        return_memory_type = Some(mtrr.memory_type);
                    }
                } else {
                    // Overwise, use the last matching MTRR's memory type.
                    return_memory_type = Some(mtrr.memory_type);
                }
            }
        }

        // Use the default type if none of MTRRs controls any page in this range.
        if return_memory_type.is_none() {
            return_memory_type = Some(self.default_memory_type);
        }
        return_memory_type
    }

    fn convert_from_raw_fixed(raw_fixed_mtrrs: &[RawFixedMtrr]) -> Vec<MemoryTypeRange> {
        const FIXED_MTRR_RANGES: [FixedMtrrRangeInfo; 11] = [
            FixedMtrrRangeInfo::new(0x0, 0x10000),
            FixedMtrrRangeInfo::new(0x80000, 0x4000),
            FixedMtrrRangeInfo::new(0xA0000, 0x4000),
            FixedMtrrRangeInfo::new(0xC0000, 0x1000),
            FixedMtrrRangeInfo::new(0xC8000, 0x1000),
            FixedMtrrRangeInfo::new(0xD0000, 0x1000),
            FixedMtrrRangeInfo::new(0xD8000, 0x1000),
            FixedMtrrRangeInfo::new(0xE0000, 0x1000),
            FixedMtrrRangeInfo::new(0xE8000, 0x1000),
            FixedMtrrRangeInfo::new(0xF0000, 0x1000),
            FixedMtrrRangeInfo::new(0xF8000, 0x1000),
        ];

        assert!(raw_fixed_mtrrs.len() == FIXED_MTRR_RANGES.len());

        let mut combined_ranges = Vec::<MemoryTypeRange>::new();
        for (i, fixed_raw) in raw_fixed_mtrrs.iter().enumerate() {
            let range = &FIXED_MTRR_RANGES[i];
            for (j, byte) in fixed_raw.value.to_be_bytes().iter().enumerate() {
                let memory_type = <MemoryType as FromPrimitive>::from_u8(*byte).unwrap();
                let base = range.base + (range.size * (j as u64));
                let range = MemoryTypeRange {
                    memory_type,
                    range: (base..base + range.size),
                };
                Self::update_combined_ranges(&mut combined_ranges, range);
            }
        }
        combined_ranges
    }

    fn convert_from_raw_variable(raw_variable_mtrrs: &[RawVariableMtrr]) -> Vec<MemoryTypeRange> {
        let mut combined_ranges = Vec::<MemoryTypeRange>::new();

        for raw_variable in raw_variable_mtrrs {
            const IA32_MTRR_PHYSMASK_VALID_FLAG: u64 = 1 << 11;

            if raw_variable.mask & IA32_MTRR_PHYSMASK_VALID_FLAG != 0 {
                let pfn = raw_variable.mask >> BASE_PAGE_SHIFT;
                let length = Self::bit_scan_forward(pfn);
                let size_in_pages = 1u64 << length;
                let size_in_bytes = size_in_pages << BASE_PAGE_SHIFT;

                let memory_type =
                    <MemoryType as FromPrimitive>::from_u64(raw_variable.base & 0xff).unwrap();
                let base = raw_variable.base & !0xfff;
                let range = MemoryTypeRange {
                    memory_type,
                    range: (base..base + size_in_bytes),
                };
                Self::update_combined_ranges(&mut combined_ranges, range);
            }
        }

        combined_ranges
    }

    fn bit_scan_forward(value: u64) -> u64 {
        let result: u64;
        unsafe { asm!("bsf {}, {}", out(reg) result, in(reg) value) };
        result
    }

    fn update_combined_ranges(combined_ranges: &mut Vec<MemoryTypeRange>, range: MemoryTypeRange) {
        if let Some(last_range) = combined_ranges.last_mut() {
            // Combine this entry if it is contiguous from the previous entry
            // with the same memory type.
            if last_range.memory_type == range.memory_type {
                if last_range.range.end == range.range.start {
                    last_range.range.end = range.range.end;
                    return;
                } else if last_range.range.start == range.range.end {
                    last_range.range.start = range.range.start;
                    return;
                }
            }
        }

        combined_ranges.push(range);
    }
}

#[derive(Debug)]
struct MemoryTypeRange {
    memory_type: MemoryType,
    range: Range<u64>,
}

struct FixedMtrrRangeInfo {
    base: u64,
    size: u64,
}

impl FixedMtrrRangeInfo {
    const fn new(base: u64, size: u64) -> Self {
        Self { base, size }
    }
}

#[derive(Debug)]
struct RawMtrrs {
    default_memory_type: MemoryType,
    fixed: Vec<RawFixedMtrr>,
    variable: Vec<RawVariableMtrr>,
}

impl RawMtrrs {
    fn new() -> Self {
        const IA32_MTRR_DEF_TYPE_FIXED_RANGE_MTRR_ENABLE_FLAG: u64 = 1 << 10;
        const IA32_MTRR_DEF_TYPE_MTRR_ENABLE_FLAG: u64 = 1 << 11;

        const FIXED_MTRRS: [u32; 11] = [
            x86::msr::IA32_MTRR_FIX64K_00000,
            x86::msr::IA32_MTRR_FIX16K_80000,
            x86::msr::IA32_MTRR_FIX16K_A0000,
            x86::msr::IA32_MTRR_FIX4K_C0000,
            x86::msr::IA32_MTRR_FIX4K_C8000,
            x86::msr::IA32_MTRR_FIX4K_D0000,
            x86::msr::IA32_MTRR_FIX4K_D8000,
            x86::msr::IA32_MTRR_FIX4K_E0000,
            x86::msr::IA32_MTRR_FIX4K_E8000,
            x86::msr::IA32_MTRR_FIX4K_F0000,
            x86::msr::IA32_MTRR_FIX4K_F8000,
        ];

        const VARIABLE_MTRRS: [u32; 20] = [
            x86::msr::IA32_MTRR_PHYSBASE0,
            x86::msr::IA32_MTRR_PHYSMASK0,
            x86::msr::IA32_MTRR_PHYSBASE1,
            x86::msr::IA32_MTRR_PHYSMASK1,
            x86::msr::IA32_MTRR_PHYSBASE2,
            x86::msr::IA32_MTRR_PHYSMASK2,
            x86::msr::IA32_MTRR_PHYSBASE3,
            x86::msr::IA32_MTRR_PHYSMASK3,
            x86::msr::IA32_MTRR_PHYSBASE4,
            x86::msr::IA32_MTRR_PHYSMASK4,
            x86::msr::IA32_MTRR_PHYSBASE5,
            x86::msr::IA32_MTRR_PHYSMASK5,
            x86::msr::IA32_MTRR_PHYSBASE6,
            x86::msr::IA32_MTRR_PHYSMASK6,
            x86::msr::IA32_MTRR_PHYSBASE7,
            x86::msr::IA32_MTRR_PHYSMASK7,
            x86::msr::IA32_MTRR_PHYSBASE8,
            x86::msr::IA32_MTRR_PHYSMASK8,
            x86::msr::IA32_MTRR_PHYSBASE9,
            x86::msr::IA32_MTRR_PHYSMASK9,
        ];

        // For simplicity, panic when the system does not support MTRRs or enable
        // fixed range MTRRs.
        let default_type = rdmsr(x86::msr::IA32_MTRR_DEF_TYPE);

        assert!(
            (default_type & IA32_MTRR_DEF_TYPE_MTRR_ENABLE_FLAG) != 0,
            "MTRRs not enabled"
        );
        assert!(
            (default_type & IA32_MTRR_DEF_TYPE_FIXED_RANGE_MTRR_ENABLE_FLAG) != 0,
            "Fixed range MTRRs not enabled"
        );
        let default_memory_type =
            <MemoryType as FromPrimitive>::from_u64(default_type & 0b111).unwrap();

        // Read all fixed range MTRRs.
        let mut fixed = Vec::<RawFixedMtrr>::new();
        for msr in FIXED_MTRRS {
            fixed.push(RawFixedMtrr { value: rdmsr(msr) });
        }

        // Get how many variable range MTRRs is supported on this system and read
        // them.
        let capabilities = rdmsr(x86::msr::IA32_MTRRCAP);
        let variable_mtrr_count = (capabilities & 0b1111_1111) as usize;

        let mut variable = Vec::<RawVariableMtrr>::new();
        for i in (0..VARIABLE_MTRRS.len()).step_by(2) {
            if i < variable_mtrr_count * 2 {
                variable.push(RawVariableMtrr {
                    base: rdmsr(VARIABLE_MTRRS[i]),
                    mask: rdmsr(VARIABLE_MTRRS[i + 1]),
                });
            }
        }

        Self {
            default_memory_type,
            fixed,
            variable,
        }
    }
}

#[derive(Debug)]
struct RawFixedMtrr {
    value: u64,
}

#[derive(Debug)]
struct RawVariableMtrr {
    base: u64,
    mask: u64,
}
