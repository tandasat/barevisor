pub trait SystemOps {
    fn processor_count(&self) -> u32;
    fn run_on_all_processors(&self, callback: fn());
    fn pa(&self, va: *const core::ffi::c_void) -> u64;
}
