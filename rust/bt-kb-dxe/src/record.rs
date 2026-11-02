//! This boot's record (`uefi_bt::bootrec`), kept in the non-volatile
//! variable `BtKbLastBoot` so it survives boots that never reach an OS. The
//! next boot logs it as "previous boot: ...".
//!
//! Writes are rationed, since every one costs flash:
//! - milestones (first connection and keys, a disconnect, a new hotkey, a
//!   failure, 15 s healthy) are written at most every 2 s;
//! - counts alone (key reports, repeated hotkeys) wait for a heartbeat at
//!   30 s, 60 s, 120 s, ... after the driver loaded;
//! - the OS start is always written (that write ends the boot's record);
//! - at most [`MAX_WRITES`] writes per boot in all.
//!
//! A normal boot without a key press writes once, at the OS start.

use alloc::string::String;

use uefi::boot::Tpl;
use uefi::runtime::{self, VariableAttributes};
use uefi::{cstr16, CStr16};
use uefi_bt::bootrec::{sanitize, BootRecord, MAX_LEN, OS_STARTED};

use crate::cell::TplCell;
use crate::dlog::VENDOR;

const NAME: &CStr16 = cstr16!("BtKbLastBoot");
const MIN_GAP_MS: u64 = 2000;
const FIRST_HEARTBEAT_MS: u64 = 30_000;
pub const MAX_WRITES: u32 = 40;

struct State {
    record: Option<BootRecord>,
    dirty: bool,
    urgent: bool,
    writes: u32,
    last_write_ms: Option<u64>,
    next_heartbeat_ms: u64,
}

static STATE: TplCell<State> = TplCell::new(
    Tpl::CALLBACK,
    State { record: None, dirty: false, urgent: false, writes: 0, last_write_ms: None, next_heartbeat_ms: FIRST_HEARTBEAT_MS },
);

fn attributes() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS
}

/// The previous boot's record, as it was last written, with a note if that
/// boot never reached an OS.
pub fn previous() -> Option<String> {
    let mut buf = [0u8; MAX_LEN + 1];
    let (data, _) = runtime::get_variable(NAME, &VENDOR, &mut buf).ok()?;
    let mut text = sanitize(data);
    if !text.contains(OS_STARTED) {
        text.push_str(" (no OS start recorded: that boot ended in a reset, a power-off or a hang)");
    }
    Some(text)
}

/// Start this boot's record. Nothing is written yet.
pub fn init(loaded_at_ms: u64, from_shell: bool) {
    STATE.with(|s| s.record = Some(BootRecord { loaded_at_ms, from_shell, ..BootRecord::default() }));
}

/// Change the record. `change` returns whether that was a milestone,
/// written within about 2 s; anything else waits for the next heartbeat.
pub fn update(change: impl FnOnce(&mut BootRecord) -> bool) {
    STATE.with(|s| {
        if let Some(record) = s.record.as_mut() {
            s.urgent |= change(record);
            s.dirty = true;
        }
    });
}

/// The driver gave up (bring-up failed, or a fatal error later): record
/// why, at once, since no tick will write it.
pub fn failed(now_ms: u64, why: &str) {
    update(|r| {
        r.failure = Some((now_ms, String::from(why)));
        true
    });
    write_now(now_ms);
}

/// Write the record if it is due (called from the timer tick).
pub fn tick(now_ms: u64) {
    let text = STATE.with(|s| {
        let gap_ok = s.last_write_ms.is_none_or(|at| now_ms >= at + MIN_GAP_MS);
        let heartbeat = now_ms >= s.next_heartbeat_ms;
        if !s.dirty || !(s.urgent && gap_ok || heartbeat) {
            return None;
        }
        while s.next_heartbeat_ms <= now_ms {
            s.next_heartbeat_ms *= 2;
        }
        take_text(s, now_ms, false)
    });
    if let Some(text) = text {
        write(&text);
    }
}

/// Write the record now, whatever the ration (the OS start, a failed
/// bring-up).
pub fn write_now(now_ms: u64) {
    if let Some(text) = STATE.with(|s| take_text(s, now_ms, true)) {
        write(&text);
    }
}

fn take_text(s: &mut State, now_ms: u64, forced: bool) -> Option<String> {
    if s.writes >= MAX_WRITES && !forced {
        return None;
    }
    let record = s.record.as_mut()?;
    record.updated_ms = now_ms;
    s.dirty = false;
    s.urgent = false;
    s.writes += 1;
    s.last_write_ms = Some(now_ms);
    Some(record.render())
}

fn write(text: &str) {
    if let Err(e) = runtime::set_variable(NAME, &VENDOR, attributes(), text.as_bytes()) {
        log::warn!("writing the boot record failed: {:?}", e.status());
    }
}
