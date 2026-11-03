//! bt-kb-log (`btlog` in the UEFI shell): prints what bt-kb-dxe keeps in
//! its variables: its log of this boot (`BtKbLog`: the start, then the
//! newest lines, updated about once a second), the boot-loop counter, the last crash,
//! and whether a keyboard layout is remembered. `btlog >a file.txt` saves
//! it to a file.
//!
//! With a TPM 2.0 it also sums up the measured boot so far: PCR 7, which
//! PCRs 0–7 have their separator, and the size of the event log.
//! `btlog -eventlog FILE` writes the event log itself (crypto-agile
//! format, as Linux's `binary_bios_measurements`) to FILE on this volume
//! (a shell-style `fs0:` in front is ignored), for `scripts/eventlog.py`.
//!
//! The variables can be written by any OS, so only printable ASCII is
//! shown; anything else becomes `?`.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;

use uefi::prelude::*;
use uefi::runtime::{self, VariableVendor};
use uefi::{cstr16, guid, println, CStr16};
use uefi_bt::eventlog::{self, pcr_list};
use uefi_bt::{app, tcg};

const VENDOR: VariableVendor = VariableVendor(guid!("5223227b-ac96-454e-9bca-f15199748a3c"));
const BOOT_LIMIT: u8 = 3;

fn read(name: &CStr16) -> Option<alloc::boxed::Box<[u8]>> {
    runtime::get_variable_boxed(name, &VENDOR).ok().map(|(data, _)| data)
}

/// Printable ASCII and newlines; everything else as `?`.
fn text(data: &[u8]) -> String {
    data.iter()
        .filter(|&&b| b != 0 && b != b'\r')
        .map(|&b| if b == b'\n' || (0x20..0x7F).contains(&b) { char::from(b) } else { '?' })
        .collect()
}

/// The TPM summary, and with `-eventlog FILE` the event log written out.
fn tpm(eventlog_file: Option<&str>) -> Status {
    let Some(mut tcg) = tcg::open() else {
        println!("TPM: none (no TPM 2.0)");
        return if eventlog_file.is_some() { Status::NOT_FOUND } else { Status::SUCCESS };
    };
    match tcg::read_pcr(&mut tcg, 7) {
        Ok(value) => println!("TPM: PCR 7 (SHA-256) = {}", tcg::hex(&value)),
        Err(e) => println!("TPM: reading PCR 7 failed: {e}"),
    }
    let log = match tcg::event_log(&mut tcg) {
        Ok(log) => log,
        Err(why) => {
            println!("TPM: no event log: {why}");
            return if eventlog_file.is_some() { Status::NOT_FOUND } else { Status::SUCCESS };
        }
    };
    if let Some(parsed) = eventlog::parse(log) {
        println!(
            "TPM: event log of {} events ({} bytes); separators measured for PCRs {}",
            parsed.events.len(),
            log.len(),
            pcr_list(parsed.separators())
        );
    }
    if let Some(file) = eventlog_file {
        // Always on btlog's own volume: a shell-style `fs0:` in front is
        // dropped.
        let file = match file.split_once(':') {
            Some((volume, rest)) if !volume.contains('\\') => rest,
            _ => file,
        };
        match app::write_file(file, log) {
            Ok(()) => println!("TPM: event log written to {file}"),
            Err(e) => {
                println!("TPM: writing the event log failed: {e}");
                return Status::ABORTED;
            }
        }
    }
    Status::SUCCESS
}

/// `-unseal-test` (offline tests only): try to unseal the driver's sealed
/// bond from here, once with the expected PCR values (PolicyPCR checks
/// them) and once without (the policy itself decides). Never prints the
/// key.
#[cfg(feature = "unseal-test")]
fn unseal_test() -> Status {
    use uefi_bt::seal::{self, Sealed};
    let Ok(text) = app::read_file("bt-kb-dxe.sealed") else {
        println!("unseal-test: no bt-kb-dxe.sealed next to btlog");
        return Status::NOT_FOUND;
    };
    let Some(mut sealed) = core::str::from_utf8(&text).ok().and_then(|t| Sealed::parse(t).ok()) else {
        println!("unseal-test: bt-kb-dxe.sealed doesn't parse");
        return Status::VOLUME_CORRUPTED;
    };
    let Some(mut tcg) = tcg::open() else {
        println!("unseal-test: no TPM");
        return Status::NOT_FOUND;
    };
    let mut refused = 0;
    for with_values in [true, false] {
        if !with_values {
            sealed.expected.clear();
        }
        let mut rng = tcg::session_rng(&mut tcg);
        match seal::unseal(&mut *tcg, &sealed, &mut rng) {
            Ok(_) => println!("unseal-test: UNSEALED from the shell ({}): the policy doesn't protect the bond", if with_values { "with the expected values" } else { "without" }),
            Err(e) => {
                refused += 1;
                println!("unseal-test: refused {}: {}", if with_values { "with the expected values" } else { "without them" }, e.reason());
            }
        }
    }
    if refused == 2 { Status::SUCCESS } else { Status::SECURITY_VIOLATION }
}

#[entry]
fn main() -> Status {
    let args = app::args();
    match args.iter().map(String::as_str).collect::<alloc::vec::Vec<_>>().as_slice() {
        [] => {}
        ["-eventlog", file] => return tpm(Some(file)),
        #[cfg(feature = "unseal-test")]
        ["-unseal-test"] => return unseal_test(),
        _ => {
            println!("usage: btlog [-eventlog FILE]");
            return Status::INVALID_PARAMETER;
        }
    }
    match read(cstr16!("BtKbLog")) {
        Some(log) => {
            println!("--- bt-kb-dxe log of this boot (BtKbLog, {} bytes)", log.len());
            for line in text(&log).lines() {
                println!("{line}");
            }
        }
        None => println!("No driver log (BtKbLog): bt-kb-dxe hasn't run during this boot."),
    }
    match read(cstr16!("BtKbBoots")).as_deref() {
        Some([count, ..]) if *count >= BOOT_LIMIT => {
            println!("Boot-loop counter (BtKbBoots): {count}: the driver has switched itself off.");
        }
        Some([count, ..]) => println!("Boot-loop counter (BtKbBoots): {count} of {BOOT_LIMIT}"),
        _ => {}
    }
    if let Some(panic) = read(cstr16!("BtKbPanic")) {
        println!("Last crash (BtKbPanic): {}", text(&panic).trim_end());
    }
    let layout = if read(cstr16!("BtKbGatt")).is_some() { "yes" } else { "no" };
    println!("Keyboard layout remembered (BtKbGatt): {layout}");
    tpm(None)
}
