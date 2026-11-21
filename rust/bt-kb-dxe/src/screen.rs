//! The pairing screen (the `pairing` feature): a few lines of text on the
//! firmware's console, for the one moment this driver has something to
//! show: a passkey. Plain text through the Simple Text Output protocol,
//! which works on a graphics console and a serial one alike.
//!
//! Device names come from the air; `uefi_bt::adv` has reduced them to
//! printable ASCII before they get here.

use core::fmt::Write;

use uefi::system;

use crate::pair::{Stage, LEGACY};

/// Why pairing is offered at this boot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// No keyboard is paired with this PC.
    Unpaired,
    /// `bt-kb-dxe.pair` asked for a new pairing.
    Requested,
}

/// The row of the line that counts down. It comes before the line about
/// the pairing itself, which may be longer than the screen is wide.
const COUNTDOWN_ROW: usize = 9;

fn console<T>(pick: impl Fn(&uefi_raw::table::system::SystemTable) -> *mut T) -> bool {
    // SAFETY: the system table is valid while boot services are.
    uefi::table::system_table_raw().is_some_and(|st| unsafe { !st.as_ref().boot_services.is_null() && !pick(st.as_ref()).is_null() })
}

/// There is a console to write to. (A driver loaded from a Driver####
/// entry starts before the firmware connects its consoles.)
pub fn available() -> bool {
    console(|st| st.stdout)
}

fn waiting_line(out: &mut uefi::proto::console::text::Output, seconds: u64) {
    let _ = write!(out, "  The PC goes on booting in {seconds:3} s. A key on another keyboard skips the wait.");
}

/// Draw the whole screen. `wait_s`: how long the boot still waits for a
/// pairing, if it does.
pub fn draw(stage: &Stage, why: Why, wait_s: Option<u64>) {
    if !available() {
        return;
    }
    system::with_stdout(|out| {
        let _ = out.clear();
        let _ = writeln!(out, "Bluetooth keyboard (bt-kb-dxe)\n");
        let _ = writeln!(
            out,
            "  {}\n",
            match why {
                Why::Unpaired => "No Bluetooth keyboard is paired with this PC yet.",
                Why::Requested => "A new pairing of the Bluetooth keyboard was asked for.",
            }
        );
        let _ = writeln!(out, "  To pair one, put it into pairing mode now: on most keyboards, hold the");
        let _ = writeln!(out, "  Bluetooth button until its light blinks.");
        if LEGACY {
            let _ = writeln!(out, "  (This build allows LE legacy pairing, which a device in radio range can");
            let _ = writeln!(out, "  fake: pair where nobody else's devices are near.)");
        } else {
            let _ = writeln!(out, "\n");
        }
        // Rows 8 to 10: the countdown between two empty lines.
        let _ = writeln!(out);
        if let Some(seconds) = wait_s {
            waiting_line(out, seconds);
        }
        let _ = writeln!(out, "\n");
        let _ = match stage {
            Stage::Off | Stage::Searching => writeln!(out, "  Looking for a keyboard in pairing mode ..."),
            Stage::Connecting { name } => writeln!(out, "  Found \"{name}\". Connecting ..."),
            Stage::Passkey { name, passkey } => {
                writeln!(out, "  On \"{name}\", type the passkey {passkey:06} and press Enter (within 30 s).")
            }
            Stage::Failed { name, why } => writeln!(out, "  Pairing with \"{name}\" failed: {why}."),
            Stage::Paired { name } => writeln!(out, "  Paired with \"{name}\". It works from now on, also at the next boots."),
            Stage::Over => writeln!(out, "  No keyboard was paired."),
        };
    });
}

/// One line about the pairing, without touching the rest of the screen:
/// for a driver loaded from a UEFI shell, whose output stays.
pub fn line(stage: &Stage) {
    if !available() {
        return;
    }
    system::with_stdout(|out| {
        let _ = match stage {
            Stage::Off => Ok(()),
            Stage::Searching => writeln!(out, "bt-kb-dxe: looking for a keyboard in pairing mode ..."),
            Stage::Connecting { name } => writeln!(out, "bt-kb-dxe: found \"{name}\"; connecting ..."),
            Stage::Passkey { name, passkey } => {
                writeln!(out, "bt-kb-dxe: on \"{name}\", type the passkey {passkey:06} and press Enter (within 30 s).")
            }
            Stage::Failed { name, why } => writeln!(out, "bt-kb-dxe: pairing with \"{name}\" failed: {why}."),
            Stage::Paired { name } => writeln!(out, "bt-kb-dxe: paired with \"{name}\"."),
            Stage::Over => writeln!(out, "bt-kb-dxe: no keyboard was paired."),
        };
    });
}

/// Rewrite the line that counts down, in place.
pub fn countdown(seconds: u64) {
    if !available() {
        return;
    }
    system::with_stdout(|out| {
        if out.set_cursor_position(0, COUNTDOWN_ROW).is_ok() {
            waiting_line(out, seconds);
        }
    });
}

/// A key was pressed on the firmware's console (and is used up).
pub fn key_pressed() -> bool {
    console(|st| st.stdin) && system::with_stdin(|stdin| matches!(stdin.read_key(), Ok(Some(_))))
}
