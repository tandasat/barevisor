use bit_field::BitField;
use x86::{
    dtables::DescriptorTablePointer,
    segmentation::{SegmentSelector, SystemDescriptorTypes64},
};

#[derive(thiserror_no_std::Error, Debug)]
pub(crate) enum SegmentError {
    #[error("`{selector}` points to the null descriptor")]
    NullDescriptor { selector: SegmentSelector },

    #[error("`{selector}` points to LDT where parsing is unimplemented")]
    LdtAccess { selector: SegmentSelector },

    #[error("`{index}` points to outside GDT")]
    OutOfGdtAccess { index: usize },

    #[error("`{index}` points to `{entry}`, which is invalid as a descriptor")]
    InvalidGdtEntry { index: usize, entry: u64 },
}

pub(crate) struct SegmentDescriptor {
    low64: SegmentDescriptorRaw,
    upper_base: Option<u32>,
}

impl SegmentDescriptor {
    pub(crate) fn try_from_gdtr(
        gdtr: &DescriptorTablePointer<u64>,
        selector: SegmentSelector,
    ) -> Result<Self, SegmentError> {
        if selector.contains(SegmentSelector::TI_LDT) {
            return Err(SegmentError::LdtAccess { selector });
        }

        let index = selector.index() as usize;
        if index == 0 {
            return Err(SegmentError::NullDescriptor { selector });
        }

        let gdt = unsafe {
            core::slice::from_raw_parts(gdtr.base.cast::<u64>(), usize::from(gdtr.limit + 1) / 8)
        };

        let raw = gdt
            .get(index)
            .ok_or(SegmentError::OutOfGdtAccess { index })?;

        let low64 = SegmentDescriptorRaw::from(*raw);
        let upper_base = if low64.is_16byte() {
            let index: usize = index + 1;

            let raw = gdt
                .get(index)
                .ok_or(SegmentError::OutOfGdtAccess { index })?;

            let Ok(upper_base) = u32::try_from(*raw) else {
                return Err(SegmentError::InvalidGdtEntry { index, entry: *raw });
            };

            Some(upper_base)
        } else {
            None
        };
        Ok(Self { low64, upper_base })
    }

    pub(crate) fn base(&self) -> u64 {
        if let Some(upper_base) = self.upper_base {
            self.low64.base() as u64 | u64::from(upper_base) << 32
        } else {
            self.low64.base() as _
        }
    }
}

/// Raw representation of a segment descriptor.
/// See: 3.4.5 Segment Descriptors
struct SegmentDescriptorRaw {
    raw: u64,
}

impl SegmentDescriptorRaw {
    // "In 64-bit mode, the TSS descriptor is expanded to 16 bytes (...)."
    // See: 8.2.3 TSS Descriptor in 64-bit mode
    fn is_16byte(&self) -> bool {
        let high32 = self.raw.get_bits(32..);
        let system = high32.get_bit(12); // descriptor type
        let type_ = high32.get_bits(8..=11) as u8;
        !system
            && (type_ == SystemDescriptorTypes64::TssAvailable as u8
                || type_ == SystemDescriptorTypes64::TssBusy as u8)
    }

    fn base(&self) -> u32 {
        let low32 = self.raw.get_bits(..=31);
        let high32 = self.raw.get_bits(32..);

        let base_high = high32.get_bits(24..=31) << 24;
        let base_middle = high32.get_bits(0..=7) << 16;
        let base_low = low32.get_bits(16..=31);
        u32::try_from(base_high | base_middle | base_low).unwrap()
    }
}

impl From<u64> for SegmentDescriptorRaw {
    fn from(raw: u64) -> Self {
        Self { raw }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base() {
        /*
            kd> dg 0 60
                                                                P Si Gr Pr Lo
            Sel        Base              Limit          Type    l ze an es ng Flags
            ---- ----------------- ----------------- ---------- - -- -- -- -- --------
            0000 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
            0008 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
            0010 00000000`00000000 00000000`00000000 Code RE Ac 0 Nb By P  Lo 0000029b
            0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
            0020 00000000`00000000 00000000`ffffffff Code RE Ac 3 Bg Pg P  Nl 00000cfb
            0028 00000000`00000000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
            0030 00000000`00000000 00000000`00000000 Code RE Ac 3 Nb By P  Lo 000002fb
            0038 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
            0040 00000000`71e7b000 00000000`00000067 TSS32 Busy 0 Nb By P  Nl 0000008b
            0048 00000000`0000ffff 00000000`0000f805 <Reserved> 0 Nb By Np Nl 00000000
            0050 00000000`00000000 00000000`00003c00 Data RW Ac 3 Bg By P  Nl 000004f3
            0058 Unable to get descriptor
            0060 Unable to get descriptor
        */
        let gdt = [
            0x0000000000000000u64,
            0x0000000000000000,
            0x00209b0000000000,
            0x0040930000000000,
            0x00cffb000000ffff,
            0x00cff3000000ffff,
            0x0020fb0000000000,
            0x0000000000000000,
            0x71008be7b0000067,
            0x00000000fffff805,
            0x0040f30000003c00,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];

        let cs = SegmentSelector::from_raw(0x10);
        let ss = SegmentSelector::from_raw(0x18);
        let ds = SegmentSelector::from_raw(0x2b);
        let tr = SegmentSelector::from_raw(0x40);
        let fs = SegmentSelector::from_raw(0x53);

        let gdtr = DescriptorTablePointer::<u64>::new_from_slice(&gdt);

        assert_eq!(SegmentDescriptor::try_from_gdtr(&gdtr, cs).unwrap().base(), 0);
        assert_eq!(SegmentDescriptor::try_from_gdtr(&gdtr, ss).unwrap().base(), 0);
        assert_eq!(SegmentDescriptor::try_from_gdtr(&gdtr, ds).unwrap().base(), 0);
        assert_eq!(SegmentDescriptor::try_from_gdtr(&gdtr, tr).unwrap().base(), 0xfffff80571e7b000);
        assert_eq!(SegmentDescriptor::try_from_gdtr(&gdtr, fs).unwrap().base(), 0);
    }
}
