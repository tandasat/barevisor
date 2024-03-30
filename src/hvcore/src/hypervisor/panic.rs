pub fn panic_impl(info: &core::panic::PanicInfo<'_>) -> ! {
    log::error!("{info}");
    loop {
        unsafe {
            x86::irq::disable();
            x86::halt();
        };
    }
}
