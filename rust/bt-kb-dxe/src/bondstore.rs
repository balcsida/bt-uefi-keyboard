//! Where the keyboard's bond comes from (stage 3 of the security
//! hardening; README, Security). No plaintext link key stays on the FAT
//! ESP, and only bonds this build was made for count.
//!
//! - **Trust:** a bond counts only if its digest (`ExportedBond::digest`)
//!   is one this build pins (`TRUSTED_BONDS`, from `BT_KB_BOND_DIGESTS`). A
//!   bond file someone dropped on the ESP for another device is ignored.
//! - **Import:** a trusted `*.bond` file next to the driver (from
//!   `board-install.sh`) is copied into the variable `BtKbBond`. The
//!   variable has no RUNTIME_ACCESS, so the OS can neither read nor write
//!   it; only pre-boot code can. Once it reads back right, the file is
//!   deleted from the ESP.
//! - **Later boots** read `BtKbBond`, and check it against the build again.
//! - **Re-pairing:** export the new bond, rebuild (the build then trusts
//!   it), reinstall. The driver imports the new file over the old bond.
//! - **Forgetting:** `bt-kb-dxe.forget` next to the driver
//!   (`board-install.sh --remove`) makes it delete `BtKbBond` and the
//!   marker, and not start. The OS can't delete a boot-services-only
//!   variable; a UEFI shell can (`dmpstore -d BtKbBond -guid ...`).

use alloc::string::String;

use log::{error, info, warn};
use uefi::runtime::{self, VariableAttributes};
use uefi::{cstr16, CStr16};
use uefi_bt::app;
use uefi_bt::bond::{wipe_bytes, ExportedBond, RECORD_LEN};

use crate::dlog::VENDOR;

const NAME: &CStr16 = cstr16!("BtKbBond");
pub const MARKER: &str = "bt-kb-dxe.forget";

/// Where this boot's bond came from, for the log and the boot record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Imported from a file on the ESP, which is gone now.
    Imported,
    /// From a file on the ESP that couldn't be imported (it stays).
    File,
    /// From the boot-services-only variable.
    Stored,
}

impl Source {
    pub fn text(self) -> &'static str {
        match self {
            Self::Imported => "imported from the ESP",
            Self::File => "from the ESP (not imported)",
            Self::Stored => "stored",
        }
    }
}

fn attributes() -> VariableAttributes {
    // No RUNTIME_ACCESS: hidden from the OS.
    VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS
}

fn trusted(bond: &ExportedBond, pins: &[[u8; 32]]) -> bool {
    pins.contains(&bond.digest())
}

fn read_stored() -> Option<ExportedBond> {
    let mut buf = [0u8; RECORD_LEN + 1];
    let bond = runtime::get_variable(NAME, &VENDOR, &mut buf).ok().and_then(|(data, attrs)| {
        // A variable someone made with other attributes isn't ours.
        (attrs == attributes()).then(|| ExportedBond::from_record(data).ok()).flatten()
    });
    wipe_bytes(&mut buf);
    bond
}

/// Copy the bond into the variable; `true` once it reads back right.
fn store(bond: &ExportedBond) -> bool {
    let mut record = bond.record();
    let written = runtime::set_variable(NAME, &VENDOR, attributes(), &record);
    let mut back = [0u8; RECORD_LEN + 1];
    let same = written.is_ok()
        && matches!(runtime::get_variable(NAME, &VENDOR, &mut back), Ok((data, attrs)) if data == record && attrs == attributes());
    wipe_bytes(&mut record);
    wipe_bytes(&mut back);
    if let Err(e) = written {
        error!("storing the bond failed: {:?}", e.status());
    }
    same
}

/// The `bt-kb-dxe.forget` marker: delete the stored bond and the marker.
fn forget() {
    match runtime::delete_variable(NAME, &VENDOR) {
        Ok(()) => info!("stored bond deleted, as asked by {MARKER}"),
        Err(e) if e.status() == uefi::Status::NOT_FOUND => info!("{MARKER}: there was no stored bond"),
        Err(e) => error!("deleting the stored bond failed: {:?}", e.status()),
    }
    if let Err(e) = app::delete_file(MARKER) {
        warn!("deleting {MARKER} failed: {e}");
    }
}

/// This boot's bond.
pub fn load(pins: &[[u8; 32]]) -> Result<(ExportedBond, Source), String> {
    if app::read_file(MARKER).is_ok() {
        forget();
        return Err(alloc::format!("the bond was forgotten as asked ({MARKER}); not starting"));
    }
    if pins.is_empty() {
        return Err(String::from(
            "this build trusts no bond: build it with BT_KB_BOND_DIGESTS (scripts/build-rust.sh does that from qemu/keys/*.bond)",
        ));
    }
    // A trusted file on the ESP: imported, then deleted.
    for name in app::files_with_suffix(".bond").unwrap_or_default() {
        let mut data = match app::read_file(&name) {
            Ok(data) => data,
            Err(e) => {
                warn!("{e}: couldn't read it");
                continue;
            }
        };
        let parsed = core::str::from_utf8(&data).ok().map(ExportedBond::parse);
        wipe_bytes(&mut data);
        let mut bond = match parsed {
            Some(Ok(bond)) => bond,
            _ => {
                warn!("{name} isn't a bond file; ignoring it");
                continue;
            }
        };
        if !trusted(&bond, pins) {
            error!("{name} is a bond this driver wasn't built for (another device, or re-paired without a rebuild): ignoring it");
            bond.wipe();
            continue;
        }
        if !store(&bond) {
            error!("the bond couldn't be stored in NVRAM: using {name}, which stays on the ESP");
            return Ok((bond, Source::File));
        }
        match app::delete_file(&name) {
            Ok(()) => info!("bond imported into a variable the OS can't read; {name} deleted from the ESP"),
            Err(e) => error!("bond imported, but deleting {name} failed ({e}): the link key is still on the ESP"),
        }
        return Ok((bond, Source::Imported));
    }
    match read_stored() {
        Some(bond) if trusted(&bond, pins) => Ok((bond, Source::Stored)),
        Some(mut bond) => {
            bond.wipe();
            Err(String::from(
                "the stored bond isn't one this driver was built for (re-paired? install the new bond: sudo scripts/board-install.sh)",
            ))
        }
        None => Err(String::from("no bond: no trusted *.bond file next to the driver, and none stored (sudo scripts/board-install.sh)")),
    }
}
