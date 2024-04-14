use core::fmt::Write;
use spin::Mutex;

static LOGGER: UartLogger = UartLogger::new(UartComPort::Com1);

pub(crate) fn init(level: log::LevelFilter) {
    LOGGER.init();
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(level))
        .unwrap();
}

pub struct UartLogger {
    port: Mutex<Uart>,
}

impl UartLogger {
    /// Creates a new UART logger which will use the given port.
    pub const fn new(port: UartComPort) -> Self {
        Self {
            port: Mutex::new(Uart::new(port)),
        }
    }
    /// Configures the UART to use an 115200 baud rate.
    pub fn init(&self) {
        self.port.lock().init(UartBaudRate::Baud115200);
    }
}

impl log::Log for UartLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let _ = write!(
                self.port.lock(),
                "{:>5}: {} ({}:{})\n",
                record.level(),
                record.args(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                /*
                "{}: {}\r\n",
                record.level(),
                record.args()
                */
            );
        }
    }

    fn flush(&self) {}
}

/// The port to be used by the UART object.
#[derive(Copy, Clone)]
#[repr(u16)]
pub enum UartComPort {
    /// COM1 port, with IO port 0x3f8
    Com1 = 0x3f8,
    /// COM2 port, with IO port 0x2f8
    Com2 = 0x2f8,
    /// COM3 port, with IO port 0x3e8
    Com3 = 0x3e8,
    /// COM4 port, with IO port 0x4e8
    Com4 = 0x2e8,
}

/// A UART object.
#[derive(Default)]
pub struct Uart {
    io_port_base: u16,
}

/// The baud rate for the UART.
#[derive(Copy, Clone)]
pub enum UartBaudRate {
    /// Configure the UART to use an 115200 baud rate.
    Baud115200 = 115200,
    /// Configure the UART to use a 9600 baud rate.
    Baud9600 = 9600,
}

impl Uart {
    /// Creates a new UART on the given COM port.
    pub const fn new(com: UartComPort) -> Self {
        Self {
            io_port_base: com as u16,
        }
    }

    /// Configures the UART with the given baud rate.
    pub fn init(&self, baud_rate: UartBaudRate) {
        const UART_OFFSET_DIVISOR_LATCH_LOW: u16 = 0;
        const UART_OFFSET_INTERRUPT_ENABLE: u16 = 1;
        const UART_OFFSET_DIVISOR_LATCH_HIGH: u16 = 1;
        const UART_OFFSET_FIFO_CONTROL: u16 = 2;
        const UART_OFFSET_LINE_CONTROL: u16 = 3;
        const UART_OFFSET_MODEM_CONTROL: u16 = 4;

        outb(self.io_port_base + UART_OFFSET_INTERRUPT_ENABLE, 0x00);
        outb(self.io_port_base + UART_OFFSET_LINE_CONTROL, 0x80);

        let divider = 115200 / (baud_rate as u64);
        let dlab_low = divider as u8;
        let dlab_high = (divider >> 8) as u8;
        outb(self.io_port_base + UART_OFFSET_DIVISOR_LATCH_LOW, dlab_low);
        outb(
            self.io_port_base + UART_OFFSET_DIVISOR_LATCH_HIGH,
            dlab_high,
        );
        outb(self.io_port_base + UART_OFFSET_LINE_CONTROL, 0x03);
        outb(self.io_port_base + UART_OFFSET_FIFO_CONTROL, 0xc7);
        outb(self.io_port_base + UART_OFFSET_MODEM_CONTROL, 0x0b);

        // FIXME: to zero
        outb(self.io_port_base + UART_OFFSET_INTERRUPT_ENABLE, 0x01);
    }
}

impl core::fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        const UART_OFFSET_LINE_STATUS: u16 = 5;
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;

        for c in s.bytes() {
            while (inb(self.io_port_base + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
            outb(
                self.io_port_base + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER,
                c,
            );
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
