//! bt-kb-log (`btlog` in the UEFI shell): prints what bt-kb-dxe keeps in
//! its variables: its log of this boot (`BtKbLog`: the start, then the
//! newest lines, updated about once a second), the boot-loop counter, the last crash,
//! and whether a keyboard layout is remembered. `btlog >a file.txt` saves
//! it to a file.
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
use uefi_bt as _; // panic handler

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

#[entry]
fn main() -> Status {
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
    Status::SUCCESS
}
