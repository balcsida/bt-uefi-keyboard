//! Shell-app helpers: arguments, files next to the app, MediaTek bring-up,
//! hand-off and recovery.

use alloc::string::String;
use alloc::vec::Vec;

use mtk_bt::{FirmwareImage, FirmwareName, Mtk};
use uefi::fs::{FileSystem, PathBuf};
use uefi::proto::device_path::text::{AllowShortcuts, DisplayOnly};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::shell_params::ShellParameters;
use uefi::{CString16, boot};

use crate::{DrainReport, HciInterface, MTK_VENDOR_ID, UsbHci};

/// Shell arguments, without the program name.
pub fn args() -> Vec<String> {
    boot::open_protocol_exclusive::<ShellParameters>(boot::image_handle())
        .map(|params| params.args().skip(1).map(String::from).collect())
        .unwrap_or_default()
}

/// This image's file on its volume, e.g. `\EFI\btkb\bt-kb-dxe.efi`; empty
/// if the firmware doesn't say.
pub fn image_path() -> String {
    boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .ok()
        .and_then(|img| img.file_path().and_then(|p| p.to_string16(DisplayOnly(true), AllowShortcuts(false)).ok()))
        .map(|s| String::from(&s))
        .unwrap_or_default()
}

/// Directory of this image on its volume, e.g. `\` or `\EFI\BtKb\`.
pub fn image_dir() -> String {
    let path = image_path();
    match path.rfind('\\') {
        Some(at) => String::from(&path[..=at]),
        None => String::from("\\"),
    }
}

/// A directory from [`image_dir`] in the form uefi-rs accepts for listing:
/// without the trailing separator, which it rejects as an empty path
/// component (`\EFI\btkb\` fails, `\EFI\btkb` works). The root stays `\`.
pub fn listing_path(dir: &str) -> &str {
    match dir.trim_end_matches('\\') {
        "" => "\\",
        trimmed => trimmed,
    }
}

/// The first file next to this image whose name ends in `suffix` (any
/// case), in name order: `first_file_with_suffix(".bond")` finds the bond
/// that scripts/export-bond.sh exported, whatever the keyboard's address.
pub fn first_file_with_suffix(suffix: &str) -> Result<String, String> {
    let dir = image_dir();
    let sfs = boot::get_image_file_system(boot::image_handle()).map_err(|e| alloc::format!("no file system: {e:?}"))?;
    // Dropped before returning: uefi-rs opens the volume exclusively, and
    // `read_file` opens it again.
    let mut fs = FileSystem::new(sfs);
    let path = CString16::try_from(listing_path(&dir)).map_err(|_| String::from("bad directory name"))?;
    let entries = fs.read_dir(PathBuf::from(path)).map_err(|e| alloc::format!("listing {dir} failed: {e}"))?;
    let wanted = suffix.to_ascii_lowercase();
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|info| String::from(info.file_name()))
        .filter(|name| name.to_ascii_lowercase().ends_with(&wanted))
        .collect();
    names.sort();
    names.into_iter().next().ok_or_else(|| alloc::format!("no *{suffix} file in {dir}"))
}

/// Read a file from this image's volume; relative paths are relative to the image.
pub fn read_file(name: &str) -> Result<Vec<u8>, String> {
    let full = if name.starts_with('\\') { String::from(name) } else { image_dir() + name };
    let sfs = boot::get_image_file_system(boot::image_handle()).map_err(|e| alloc::format!("{e:?}"))?;
    let mut fs = FileSystem::new(sfs);
    let path = CString16::try_from(full.as_str()).map_err(|_| String::from("bad path"))?;
    fs.read(PathBuf::from(path)).map_err(|e| match e {
        uefi::fs::Error::Io(io) => alloc::format!("{full}: {:?}", io.uefi_error.status()),
        other => alloc::format!("{full}: {other}"),
    })
}

/// Write a file on this image's volume (replacing it); relative paths are
/// relative to the image.
pub fn write_file(name: &str, data: &[u8]) -> Result<(), String> {
    let full = if name.starts_with('\\') { String::from(name) } else { image_dir() + name };
    let sfs = boot::get_image_file_system(boot::image_handle()).map_err(|e| alloc::format!("{e:?}"))?;
    let mut fs = FileSystem::new(sfs);
    let path = CString16::try_from(full.as_str()).map_err(|_| String::from("bad path"))?;
    fs.write(PathBuf::from(path), data).map_err(|e| match e {
        uefi::fs::Error::Io(io) => alloc::format!("{full}: {:?}", io.uefi_error.status()),
        other => alloc::format!("{full}: {other}"),
    })
}

pub fn print_interface(index: usize, i: &HciInterface) {
    crate::say!(
        "  [{index}] {:04X}:{:04X} interface {}, event EP {:#04x} ({} B), ACL in {:#04x}, out {:#04x}{}",
        i.vendor_id,
        i.product_id,
        i.interface_number,
        i.int_in,
        i.int_in_max_packet,
        i.bulk_in,
        i.bulk_out,
        if i.vendor_id == MTK_VENDOR_ID { "  (MediaTek)" } else { "" }
    );
    if let Some(path) = &i.path {
        crate::say!("      {path}");
    }
}

pub fn report_drain(when: &str, r: &DrainReport) {
    if !r.is_empty() {
        crate::say!(
            "{when}: discarded {} events and {} ACL packets the controller still had queued ({} ms)",
            r.events, r.acl, r.ms
        );
    }
}

/// Counters and the last packets, for when something went wrong.
pub fn print_diagnostics(hci: &UsbHci) {
    crate::say!("--- Diagnostics");
    hci.stats.print();
    print_pipe_stats(hci);
    hci.trace.print();
    crate::say!("---");
}

pub fn print_pipe_stats(hci: &UsbHci) {
    match hci.pipe_stats() {
        Some(p) => crate::say!(
            "  Event pipe: {} packets, max {} bytes buffered, {} overflows, {} errors{}",
            p.packets,
            p.max_buffered,
            p.overflows,
            p.errors,
            if p.errors > 0 { alloc::format!(" (last USB status {:#x})", p.last_error) } else { String::new() }
        ),
        None => crate::say!("  Event pipe: not running (synchronous reads)"),
    }
}

/// Discard whatever is queued, then HCI_Reset (reading the ACL pipe while
/// waiting), so the host stack starts from a clean controller.
pub fn clean_start(hci: &mut UsbHci) -> Result<(), String> {
    match hci.drain(20, 500) {
        Ok(r) => report_drain("After Bluetooth on", &r),
        Err(e) => return Err(alloc::format!("Draining the controller failed: {e:?}")),
    }
    let mut ret = [0u8; 8];
    match hci.command(crate::HCI_OP_RESET, &[], &mut ret, 2000) {
        Ok(n) if n >= 1 && ret[0] == 0 => Ok(()),
        Ok(_) => Err(alloc::format!("HCI_Reset returned status {:#04x}", ret[0])),
        Err(e) => Err(alloc::format!("HCI_Reset failed: {e:?}")),
    }
}

pub struct BringUpError {
    pub message: String,
    /// The controller, once anything has been sent to it, for diagnostics
    /// and the hand-off. `None` if nothing needs undoing.
    pub mtk: Option<Mtk<UsbHci>>,
}

fn fail(message: String, mtk: Option<Mtk<UsbHci>>) -> BringUpError {
    BringUpError { message, mtk }
}

/// Find the MediaTek HCI interface, check the firmware (uploading only if
/// allowed), turn Bluetooth on and reset the controller. Prints what it does.
pub fn bring_up_mediatek(fw: &FirmwareImage<'_>, allow_upload: bool, verbose: bool) -> Result<Mtk<UsbHci>, BringUpError> {
    let (interfaces, scanned) =
        crate::find_hci_interfaces().map_err(|e| fail(alloc::format!("USB enumeration failed: {e:?}"), None))?;
    let Some(intf) = interfaces.into_iter().find(|i| i.vendor_id == MTK_VENDOR_ID) else {
        return Err(fail(alloc::format!("No MediaTek Bluetooth interface found ({scanned} USB interfaces scanned)."), None));
    };
    print_interface(0, &intf);
    let mut hci = UsbHci::open(intf).map_err(|e| fail(alloc::format!("Opening the interface failed: {e:?}"), None))?;
    hci.verbose = verbose;

    // Whatever an earlier owner left behind goes first, before any command.
    match hci.drain(20, 300) {
        Ok(r) => report_drain("Before setup", &r),
        Err(e) => return Err(fail(alloc::format!("Draining the controller failed: {e:?}"), Some(Mtk::new(hci)))),
    }
    let mut mtk = Mtk::new(hci);

    let info = match mtk.chip_info() {
        Ok(info) => info,
        Err(e) => return Err(fail(alloc::format!("Reading chip ID failed: {e}"), Some(mtk))),
    };
    if info.chip_id != 0x7922 {
        return Err(fail(alloc::format!("Chip {:#06x}: only the MT7922 has been looked at so far.", info.chip_id), None));
    }
    if let Some(name) = FirmwareName::for_chip(info.chip_id, info.fw_version, info.fw_flavor) {
        crate::say!("Chip: {:#06x}, expects {name}", info.chip_id);
    }

    let loaded = match mtk.load_firmware(fw, allow_upload) {
        Ok(r) => r,
        // Only the status query was sent; Linux uploads at its next setup.
        Err(mtk_bt::Error::NotLoaded { section }) => {
            return Err(fail(
                alloc::format!("Firmware section {section} is not loaded on the chip. Nothing was uploaded; rerun with -upload to send it."),
                None,
            ));
        }
        Err(e) => return Err(fail(alloc::format!("Firmware check failed: {e}"), Some(mtk))),
    };
    crate::say!(
        "Firmware: {}/{} sections already loaded, {} uploaded",
        loaded.sections_already_loaded, loaded.sections_checked, loaded.sections_downloaded
    );
    if let Err(e) = mtk.enable() {
        return Err(fail(alloc::format!("Turning Bluetooth on failed: {e}"), Some(mtk)));
    }
    if let Err(e) = clean_start(&mut mtk.transport) {
        return Err(fail(e, Some(mtk)));
    }
    Ok(mtk)
}

/// Give the controller back: HCI_Reset and WMT FUNC_CTRL off, as Linux does
/// at shutdown. If it doesn't answer, or its firmware crashed, and
/// `allow_reset` is set, do the MT7922 subsystem reset (Linux's recovery
/// after a firmware crash), so the chip is sane before anything resets the
/// USB port. Linux's reset drops the firmware, so Linux re-uploads it (about
/// 20 s) at its next setup. Returns true if the controller answered normally.
pub fn hand_off(hci: &mut UsbHci, allow_reset: bool) -> bool {
    if hci.firmware_crashed() {
        crate::say!("Handoff: the controller firmware crashed; waiting for the crash dump to end");
        // Linux allows the dump 5 s.
        let _ = hci.drain(300, 5000);
    } else {
        let _ = hci.drain(20, 300);
        let mut ret = [0u8; 8];
        match hci.command(crate::HCI_OP_RESET, &[], &mut ret, 1500) {
            Ok(n) if n >= 1 && ret[0] == 0 => {
                let mut mtk = Mtk::new(&mut *hci);
                mtk.event_timeout_ms = 2000;
                match mtk.disable() {
                    Ok(_) => {
                        crate::say!("Handoff: HCI_Reset + function off: ok");
                        return true;
                    }
                    Err(e) => crate::say!("Handoff: function off failed: {e}"),
                }
            }
            Ok(_) => crate::say!("Handoff: HCI_Reset returned status {:#04x}", ret[0]),
            Err(e) => crate::say!("Handoff: HCI_Reset failed: {e:?}"),
        }
    }

    if !allow_reset {
        crate::say!("Not resetting the controller (-recover not given). If Linux can't use it afterwards,");
        crate::say!("only a mains power cycle is known to help.");
        return false;
    }
    crate::say!("Recovery: MT7922 subsystem reset (Linux's recovery after a firmware crash)...");
    let mut mtk = Mtk::new(&mut *hci);
    mtk.event_timeout_ms = 2000;
    match mtk.subsys_reset_7922() {
        Ok(()) => crate::say!("  done: the chip reports its ID again. Linux sets it up again, uploading firmware if needed."),
        Err(e) => crate::say!("  failed: {e}"),
    }
    false
}

#[cfg(test)]
mod tests {
    use super::listing_path;

    #[test]
    fn listing_paths() {
        assert_eq!(listing_path("\\EFI\\btkb\\"), "\\EFI\\btkb");
        assert_eq!(listing_path("\\EFI\\btkb"), "\\EFI\\btkb");
        assert_eq!(listing_path("\\"), "\\");
        assert_eq!(listing_path(""), "\\");
    }
}
