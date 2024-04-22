// https://github.com/iankronquist/rustyvisor/tree/83b53ac104d85073858ba83326a28a6e08d1af12/pcuart
// https://wiki.osdev.org/Serial_Ports

use core::{fmt::Write, ptr::addr_of, sync::atomic::AtomicU8};
use spin::{Mutex, Once};
use x86::bits64::rflags;

static LOGGER: Once<SerialLogger> = Once::new();

pub(crate) fn init(level: log::LevelFilter) -> u64 {
    let logger = LOGGER.call_once(SerialLogger::new);
    log::set_logger(logger).unwrap();
    log::set_max_level(level);

    let addr = { addr_of!(logger.port.lock().blocks) };
    addr as _
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(u16)]
enum SerialPort {
    Com1 = 0x3f8,
    Com2 = 0x2f8,
    Com3 = 0x3e8,
    Com4 = 0x2e8,
}

struct SerialLogger {
    port: Mutex<Uart>,
}

impl SerialLogger {
    fn new() -> Self {
        Self {
            port: Mutex::new(Uart::new(SerialPort::Com1, 115200)),
        }
    }
}

impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let apic_id = apic_id();
            // Disable interrupt while acquiring the mutex, to avoid VM-exit
            // from the VM and the VMM reentering this code.
            let _int_guard = InterruptDisabled::new();
            let mut uart = self.port.lock();
            Uart::init(uart.port, 115200);
            //let _ = writeln!(uart, "{}", record.args());
            let _ = writeln!(uart, "#{apic_id}:{:5}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

#[repr(C)]
struct Block {
    block: [u8; 32],
}
impl Default for Block {
    fn default() -> Self {
        Self { block: [0; 32] }
    }
}

#[repr(C, align(4096))]
struct Uart {
    blocks: [Block; 128],
    index: AtomicU8,
    port: u16,
}

impl Uart {
    fn new(port: SerialPort, baud_rate: u64) -> Self {
        let port = port as u16;
        Self::init(port, baud_rate);
        Self {
            blocks: core::array::from_fn(|_| Block::default()),
            index: AtomicU8::new(0),
            port,
        }
    }

    pub fn init(port: u16, baud_rate: u64) {
        const UART_OFFSET_DIVISOR_LATCH_LOW: u16 = 0;
        const UART_OFFSET_INTERRUPT_ENABLE: u16 = 1;
        const UART_OFFSET_DIVISOR_LATCH_HIGH: u16 = 1;
        const UART_OFFSET_FIFO_CONTROL: u16 = 2;
        const UART_OFFSET_LINE_CONTROL: u16 = 3;
        const UART_OFFSET_MODEM_CONTROL: u16 = 4;

        outb(port + UART_OFFSET_INTERRUPT_ENABLE, 0);
        outb(port + UART_OFFSET_LINE_CONTROL, 0x80);

        let divider = 115200 / baud_rate;
        let dlab_low = divider as u8;
        let dlab_high = (divider >> 8) as u8;
        outb(port + UART_OFFSET_DIVISOR_LATCH_LOW, dlab_low);
        outb(port + UART_OFFSET_DIVISOR_LATCH_HIGH, dlab_high);
        outb(port + UART_OFFSET_LINE_CONTROL, 0x3);
        outb(port + UART_OFFSET_FIFO_CONTROL, 0xc7);
        outb(port + UART_OFFSET_MODEM_CONTROL, 0xb);

        outb(port + UART_OFFSET_INTERRUPT_ENABLE, 0x1);
    }
}

impl core::fmt::Write for Uart {
    fn write_str(&mut self, msg: &str) -> Result<(), core::fmt::Error> {
        const UART_OFFSET_LINE_STATUS: u16 = 5;
        const UART_OFFSET_LINE_STATUS_THRE: u8 = 1u8 << 5;
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;

        for data in msg.bytes() {
            while (inb(self.port + UART_OFFSET_LINE_STATUS) & UART_OFFSET_LINE_STATUS_THRE) == 0 {
                core::hint::spin_loop();
            }
            outb(self.port + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER, data);
        }

        if msg.len() != 1 {
            let mut i = self
                .index
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if i == 128 {
                i = 0;
                self.index.store(1, core::sync::atomic::Ordering::Relaxed);
            }
            let block = &mut self.blocks[i as usize].block;
            let length = core::cmp::min(31, msg.len());
            unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), block.as_mut_ptr(), length) };
        }
        Ok(())
    }
}

fn outb(port: u16, data: u8) {
    unsafe { x86::io::outb(port, data) }
}

fn inb(port: u16) -> u8 {
    unsafe { x86::io::inb(port) }
}

fn apic_id() -> u8 {
    // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
    // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
    (x86::cpuid::cpuid!(0x1).ebx >> 24) as _
}

struct InterruptDisabled {
    enabled: bool,
}

impl InterruptDisabled {
    fn new() -> Self {
        let enabled = x86::bits64::rflags::read().contains(rflags::RFlags::FLAGS_IF);
        unsafe { x86::irq::disable() };
        Self { enabled }
    }
}

impl Drop for InterruptDisabled {
    fn drop(&mut self) {
        if self.enabled {
            unsafe { x86::irq::enable() };
        }
    }
}
