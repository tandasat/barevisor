//! This module implements management of GDT with TSS. TSS is used because Intel
//! processors require the host GDT to have a valid TSS.

use alloc::{boxed::Box, vec::Vec};
use x86::{
    bits64::task::TaskStateSegment,
    dtables::{lgdt, DescriptorTablePointer},
    segmentation::{
        cs, BuildDescriptor, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
    },
    task::{load_tr, tr},
};

use super::segment::SegmentDescriptor;

type Gdtr = DescriptorTablePointer<u64>;

#[derive(Clone, Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub struct GdtTss {
    ptr: Box<GdtTssRaw>,
}

impl GdtTss {
    pub fn new_from_current() -> Self {
        Self {
            ptr: Box::new(GdtTssRaw::new_from_current()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GdtTssRaw {
    pub gdt: Vec<u64>,
    pub cs: SegmentSelector,
    pub tss: Option<TaskStateSegment>,
    pub tr: Option<SegmentSelector>,
}

#[derive(thiserror::Error, Clone, Copy, Debug)]
pub enum GdtTssError {
    #[error("TSS already in use in the current GDT")]
    TssAlreadyInUse,
}

impl GdtTssRaw {
    pub fn new_from_current() -> Self {
        let gdtr = Self::sgdt();

        let gdt =
            unsafe { core::slice::from_raw_parts(gdtr.base, usize::from(gdtr.limit + 1) / 8) }
                .to_vec();

        let tr = unsafe { tr() };
        let tr = if tr.bits() == 0 { None } else { Some(tr) };

        let tss = if let Some(tr) = tr {
            let sg = SegmentDescriptor::try_from_gdtr(&gdtr, tr).unwrap();
            let tss = sg.base() as *mut TaskStateSegment;
            Some(unsafe { *tss })
        } else {
            None
        };

        let cs = cs();
        Self { gdt, cs, tss, tr }
    }

    pub fn append_tss(&mut self, tss: TaskStateSegment) -> &Self {
        if self.tss.is_some() || self.tr.is_some() {
            return self;
        }

        let index = self.gdt.len() as u16;
        self.tr = Some(SegmentSelector::new(index, x86::Ring::Ring0));
        self.tss = Some(tss);

        let tss = self.tss.as_ref().unwrap();
        self.gdt.push(Self::task_segment_descriptor(tss).as_u64());
        self.gdt.push(0);

        self
    }

    pub fn apply(&self) -> Result<(), GdtTssError> {
        if unsafe { tr() }.bits() != 0 {
            return Err(GdtTssError::TssAlreadyInUse);
        }

        let gdtr = Gdtr::new_from_slice(&self.gdt);
        unsafe { lgdt(&gdtr) };

        if let Some(tr) = self.tr {
            unsafe { load_tr(tr) };
        }

        Ok(())
    }

    /// Builds a segment descriptor from the task state segment.
    // FIXME: Just define our own one and properly represent 128 bit width descriptor.
    fn task_segment_descriptor(tss: &TaskStateSegment) -> Descriptor {
        let base = tss as *const _ as _;
        let limit = core::mem::size_of_val(tss) as u64 - 1;
        <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(base, limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish()
    }

    fn sgdt() -> Gdtr {
        let mut gdtr = Gdtr::default();
        unsafe { x86::dtables::sgdt(&mut gdtr) };
        gdtr
    }
}
