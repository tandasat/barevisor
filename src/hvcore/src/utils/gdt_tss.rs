use alloc::{boxed::Box, vec::Vec};
use x86::{
    bits64::task::TaskStateSegment,
    dtables::{lgdt, DescriptorTablePointer},
    segmentation::{
        BuildDescriptor, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
    },
    task::{load_tr, tr},
};

use super::segment::SegmentDescriptor;

type Gdtr = DescriptorTablePointer<u64>;

#[derive(Clone, Debug)]
pub struct GdtTss {
    pub gdt: Vec<u64>,
    pub tss: Option<Box<TaskStateSegment>>,
    pub tr: Option<SegmentSelector>,
}

#[derive(thiserror_no_std::Error, Clone, Copy, Debug)]
pub enum GdtTssError {
    #[error("TSS already in use in the current GDT")]
    TssAlreadyInUse,
    //#[error("TSS does not exist in this GDT")]
    //NotFound,
}

impl GdtTss {
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
            Some(unsafe { Box::from_raw(tss) })
        } else {
            None
        };

        Self { gdt, tss, tr }
    }

    pub fn append_tss(&mut self, tss: Box<TaskStateSegment>) -> &Self {
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
