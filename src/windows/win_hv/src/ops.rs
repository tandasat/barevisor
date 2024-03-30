use wdk_sys::{
    ntddk::{
        KeGetCurrentIrql, KeGetProcessorNumberFromIndex, KeQueryActiveProcessorCountEx,
        KeRevertToUserGroupAffinityThread, KeSetSystemGroupAffinityThread, MmGetPhysicalAddress,
    },
    ALL_PROCESSOR_GROUPS, APC_LEVEL, GROUP_AFFINITY, NT_SUCCESS, PAGED_CODE, PROCESSOR_NUMBER,
};

pub(crate) struct WindowsOps {}

impl hv::PlatformOps for WindowsOps {
    fn processor_count(&self) -> u32 {
        unsafe { KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS as _) }
    }

    fn run_on_all_processors(&self, callback: fn()) {
        PAGED_CODE!();

        for index in 0..self.processor_count() {
            let mut processor_number = PROCESSOR_NUMBER::default();
            let status = unsafe { KeGetProcessorNumberFromIndex(index, &mut processor_number) };
            assert!(NT_SUCCESS(status));

            let mut old_affinity = GROUP_AFFINITY::default();
            let mut affinity: wdk_sys::_GROUP_AFFINITY = GROUP_AFFINITY {
                Group: processor_number.Group,
                Mask: 1 << processor_number.Number,
                Reserved: [0, 0, 0],
            };
            unsafe { KeSetSystemGroupAffinityThread(&mut affinity, &mut old_affinity) };

            callback();

            unsafe { KeRevertToUserGroupAffinityThread(&mut old_affinity) };
        }
    }

    fn pa(&self, va: *const core::ffi::c_void) -> u64 {
        unsafe { MmGetPhysicalAddress(va as *mut _).QuadPart as u64 }
    }
}
