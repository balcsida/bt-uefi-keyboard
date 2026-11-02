//! The keyboard's GATT layout, kept between boots in the non-volatile
//! variable `BtKbGatt` (encoding: `uefi_bt::gatt_cache`). With it, keys
//! work as soon as the link is encrypted, about 0.5 s after the keyboard
//! wakes, instead of after the 2–3.5 s discovery.
//!
//! The session checks the record against the keyboard once per driver
//! start and replaces it if it no longer matches. To make the driver
//! discover again, delete the variable (Linux: `chattr -i` and `rm`
//! `/sys/firmware/efi/efivars/BtKbGatt-5223227b-ac96-454e-9bca-f15199748a3c`).

use uefi::runtime::{self, VariableAttributes};
use uefi::{cstr16, CStr16};
use uefi_bt::bond::ExportedBond;
use uefi_bt::gatt_cache::{GattCache, LEN};

use crate::dlog::VENDOR;
use crate::session::{Found, Layout};

const NAME: &CStr16 = cstr16!("BtKbGatt");

fn attributes() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS
}

fn stored(buf: &mut [u8; LEN + 1]) -> Option<&[u8]> {
    runtime::get_variable(NAME, &VENDOR, buf).ok().map(|(data, _)| &*data)
}

/// The remembered layout, if there is one for this bond's keyboard.
pub fn load(bond: &ExportedBond) -> Option<Found> {
    let mut buf = [0u8; LEN + 1];
    let record = GattCache::decode(stored(&mut buf)?)?;
    if record.peer != bond.peer || record.peer_is_random != bond.peer_is_random {
        return None;
    }
    Some(Found {
        cccd: record.cccd,
        output: record.output,
        reference: record.reference,
        layout: Layout { input: record.input, report: record.report },
        verified: false,
    })
}

/// Remember a layout; the variable is written only if it changed.
pub fn store(found: &Found) {
    let Some(cfg) = crate::config() else { return };
    let record = GattCache {
        peer: cfg.bond.peer,
        peer_is_random: cfg.bond.peer_is_random,
        input: found.layout.input,
        cccd: found.cccd,
        reference: found.reference,
        output: found.output,
        report: found.layout.report,
    };
    let Some(data) = record.encode() else {
        log::warn!("this keyboard's layout can't be remembered between boots");
        return;
    };
    let mut buf = [0u8; LEN + 1];
    if stored(&mut buf) == Some(&data[..]) {
        return;
    }
    match runtime::set_variable(NAME, &VENDOR, attributes(), &data) {
        Ok(()) => log::info!("keyboard layout remembered for the next boots"),
        Err(e) => log::warn!("remembering the keyboard layout failed: {:?}", e.status()),
    }
}

/// Drop a layout that no longer matches the keyboard.
pub fn forget() {
    let _ = runtime::delete_variable(NAME, &VENDOR);
}
