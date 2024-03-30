use alloc::collections::BTreeMap;
use spin::RwLock;

type ApicId = u8;
type ProcessorId = u8;
pub(crate) static APIC_ID_MAP: RwLock<BTreeMap<ApicId, ProcessorId>> = RwLock::new(BTreeMap::new());

/// Gets an APIC ID.
pub(crate) fn apic_id() -> ApicId {
    // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
    // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
    (x86::cpuid::cpuid!(0x1).ebx >> 24) as _
}

pub(crate) fn cpu_id_from(apic_id: ApicId) -> Option<ProcessorId> {
    let map = APIC_ID_MAP.read();
    map.get(&apic_id).copied()
}
