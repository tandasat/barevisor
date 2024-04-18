//! The hypervisor vendor checker for Windows.

fn main() {
    println!("Executing CPUID(0x40000000) on all logical processors");
    for core_id in core_affinity::get_core_ids().unwrap() {
        assert!(core_affinity::set_for_current(core_id));
        let regs = raw_cpuid::cpuid!(0x4000_0000);
        let mut vec = regs.ebx.to_le_bytes().to_vec();
        vec.extend(regs.ecx.to_le_bytes());
        vec.extend(regs.edx.to_le_bytes());
        println!(
            "CPU{:2}: {}",
            core_id.id,
            String::from_utf8_lossy(vec.as_slice())
        );
    }
}
