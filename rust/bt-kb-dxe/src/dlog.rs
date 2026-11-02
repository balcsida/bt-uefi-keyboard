//! The driver's log. Never the console: that would scribble over firmware
//! setup screens. Lines go to
//! - RAM, copied into the volatile variable `BtKbLog` (vendor GUID
//!   [`VENDOR`]): `btlog` or `dmpstore BtKbLog` in the UEFI shell, or
//!   `/sys/firmware/efi/efivars/BtKbLog-5223227b-...` in Linux after boot.
//!   The first [`HEAD`] bytes (the start: how and when the driver loaded,
//!   bring-up) stay; after them a ring keeps the newest [`RING`] bytes,
//!   and repeats are counted rather than written (`uefi_bt::logbuf`);
//! - under a hypervisor only, QEMU's debug console at I/O port 0x402 (the
//!   port OVMF uses for its own debug output; an isa-debugcon at 0xE9
//!   hung OVMF on QEMU's q35 machine). Bare metal never gets port writes.

use core::fmt::{self, Write};

use log::{Level, LevelFilter, Metadata, Record};
use uefi::boot::Tpl;
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{cstr16, guid};

use uefi_bt::logbuf::{LogBuf, MAX_LINE};

use crate::cell::{current_tpl, TplCell};

pub const VENDOR: VariableVendor = VariableVendor(guid!("5223227b-ac96-454e-9bca-f15199748a3c"));

/// Head and ring together stay under 6 KB, well within the variable sizes
/// firmware allows (OVMF 8 KB; Secure Boot updates need far more).
const HEAD: usize = 1600;
const RING: usize = 4300;
const FLUSH_INTERVAL_MS: u64 = 1000;

struct State {
    buf: LogBuf<HEAD, RING>,
    dirty: bool,
    debugcon: bool,
    last_flush_ms: u64,
}

static LOG: TplCell<State> =
    TplCell::new(Tpl::NOTIFY, State { buf: LogBuf::new(), dirty: false, debugcon: false, last_flush_ms: 0 });

/// One line, without allocating.
struct Line {
    buf: [u8; MAX_LINE],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

fn hypervisor_present() -> bool {
    // CPUID leaf 1, ECX bit 31: "running under a hypervisor".
    #[allow(unused_unsafe)]
    let leaf = unsafe { core::arch::x86_64::__cpuid(1) };
    leaf.ecx & (1 << 31) != 0
}

fn debugcon_write(bytes: &[u8]) {
    for &b in bytes {
        // SAFETY: port 0x402 is QEMU's debug console; only used under a
        // hypervisor, where writing it has no other effect.
        unsafe { core::arch::asm!("out dx, al", in("dx") 0x402u16, in("al") b, options(nomem, nostack, preserves_flags)) };
    }
}

pub fn init() {
    let debugcon = hypervisor_present();
    LOG.with(|state| state.debugcon = debugcon);
    log::set_logger(&LOGGER).ok();
    log::set_max_level(LevelFilter::Info);
}

/// Append one line (a newline is added).
pub fn line(args: fmt::Arguments) {
    let mut message = Line { buf: [0; MAX_LINE], len: 0 };
    let _ = write!(message, "{args}");
    let now = uefi_bt::clock::now_ms();
    LOG.with(|state| {
        let debugcon = state.debugcon;
        let sink = |text: &[u8]| {
            if debugcon {
                debugcon_write(text);
            }
        };
        if state.buf.add(now, &message.buf[..message.len], sink) {
            state.dirty = true;
        }
    });
}

/// Sink for uefi-bt's own messages.
pub fn say(args: fmt::Arguments) {
    line(format_args!("  {args}"));
}

/// Copy the ring into the `BtKbLog` variable: always if `force`, otherwise
/// at most once a second. Only at or below TPL_CALLBACK, where SetVariable
/// is allowed.
pub fn flush(force: bool) {
    if current_tpl() > Tpl::CALLBACK {
        return;
    }
    let now = uefi_bt::clock::now_ms();
    let snapshot = LOG.with(|state| {
        if !state.dirty || (!force && now.saturating_sub(state.last_flush_ms) < FLUSH_INTERVAL_MS) {
            return None;
        }
        state.dirty = false;
        state.last_flush_ms = now;
        Some(state.buf.snapshot())
    });
    if let Some(data) = snapshot {
        let attributes = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let _ = runtime::set_variable(cstr16!("BtKbLog"), &VENDOR, attributes, &data);
    }
}

/// Panic hook: keep the message in a non-volatile variable (`BtKbPanic`),
/// since the machine restarts right after.
pub fn persist_panic(message: &str) {
    line(format_args!("PANIC: {message}"));
    if current_tpl() <= Tpl::CALLBACK {
        let attributes =
            VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let _ = runtime::set_variable(cstr16!("BtKbPanic"), &VENDOR, attributes, message.as_bytes());
        flush(true);
    }
}

struct Logger;

static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Ours at Info; the host stack's only from Warn up.
        let ours = metadata.target().starts_with("bt_kb_dxe") || metadata.target().starts_with("uefi_bt");
        metadata.level() <= if ours { Level::Info } else { Level::Warn }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = match record.level() {
                Level::Error => "E",
                Level::Warn => "W",
                Level::Info => "I",
                Level::Debug => "D",
                Level::Trace => "T",
            };
            line(format_args!("{level} {}", record.args()));
        }
    }

    fn flush(&self) {}
}
