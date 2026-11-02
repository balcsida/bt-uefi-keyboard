//! Boot-loop protection for when this driver runs at every boot.
//!
//! A non-volatile counter (`BtKbBoots`) goes up each time the driver starts
//! and back to zero when the boot gets as far as an OS (ExitBootServices),
//! or once the driver has run for 15 s without trouble. If the driver ever
//! hangs or keeps crashing the machine early in the boot, the counter
//! reaches [`LIMIT`] and the driver stops loading, so the machine boots
//! without it.
//!
//! Re-enable by deleting the variable: in Linux,
//! `chattr -i /sys/firmware/efi/efivars/BtKbBoots-5223227b-ac96-454e-9bca-f15199748a3c`
//! and then `rm` it; in the UEFI shell,
//! `dmpstore -d BtKbBoots -guid 5223227b-ac96-454e-9bca-f15199748a3c`.

use uefi::cstr16;
use uefi::runtime::{self, VariableAttributes};

use crate::dlog::VENDOR;

pub const LIMIT: u8 = 3;

fn attributes() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS
}

fn read() -> u8 {
    let mut buf = [0u8; 1];
    match runtime::get_variable(cstr16!("BtKbBoots"), &VENDOR, &mut buf) {
        Ok((data, _)) if !data.is_empty() => data[0],
        _ => 0,
    }
}

/// Count this start. `Err(count)` if the driver should not run.
pub fn count_start() -> Result<u8, u8> {
    let count = read();
    if count >= LIMIT {
        return Err(count);
    }
    let _ = runtime::set_variable(cstr16!("BtKbBoots"), &VENDOR, attributes(), &[count + 1]);
    Ok(count + 1)
}

/// The boot reached an OS, or the driver ran long enough to trust it.
pub fn clear() {
    // Spare the flash: most boots find it at zero already the second time.
    if read() != 0 {
        let _ = runtime::set_variable(cstr16!("BtKbBoots"), &VENDOR, attributes(), &[0]);
    }
}
