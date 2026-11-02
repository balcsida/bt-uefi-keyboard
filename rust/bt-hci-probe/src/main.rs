//! bt-hci-probe: milestone 1 for the MediaTek MT7922 Bluetooth controller,
//! as a UEFI shell app.
//!
//! Default run: find the HCI interface (cached descriptors only), drain
//! whatever the controller still has queued, read the chip ID, parse the
//! firmware file and ask the chip whether each section is loaded (a status
//! query; no firmware data), stop if one is missing unless `-upload`, turn
//! Bluetooth on, run basic HCI queries, then HCI_Reset and turn Bluetooth
//! off again (as Linux does at shutdown) unless `-keep`. On any failure it
//! prints the last packets and hands the controller back; with `-recover`
//! it falls back to the MT7922 subsystem reset if the controller doesn't
//! answer.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use mtk_bt::{FirmwareImage, FirmwareName, Mtk};
use uefi::prelude::*;
use uefi::println;
use uefi_bt::app::{args, hand_off, print_diagnostics, print_interface, read_file, report_drain};
use uefi_bt::{clock, UsbHci, MTK_VENDOR_ID};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_FW: &str = "BT_RAM_CODE_MT7922_1_1_hdr.bin";
const HCI_TIMEOUT_MS: u32 = 2000;

#[derive(Default)]
struct Options {
    list: bool,
    parse_only: bool,
    chip_id_only: bool,
    allow_upload: bool,
    keep: bool,
    verbose: bool,
    subsys_reset: bool,
    recover: bool,
    index: usize,
    fw: Option<String>,
}

fn usage() {
    println!("bt-hci-probe {VERSION} - MediaTek MT79xx Bluetooth bring-up probe\n");
    println!("usage: bt-hci-probe [options]");
    println!("  -list          list Bluetooth USB interfaces and exit (sends nothing)");
    println!("  -parse         parse the firmware file and exit (sends nothing)");
    println!("  -chipid        read the chip ID registers and exit");
    println!("  -fw <file>     firmware file on this volume (default {DEFAULT_FW} next to the app)");
    println!("  -upload        allow uploading firmware sections the chip reports missing");
    println!("  -keep          leave Bluetooth on at exit (default: HCI_Reset + function off)");
    println!("  -reset7922     MT7922 subsystem reset before setup (drops loaded firmware)");
    println!("  -recover       if the controller stops answering, do the MT7922 subsystem reset");
    println!("                 before exiting (Linux's recovery after a firmware crash)");
    println!("  -index <n>     use the n-th MediaTek interface (default 0)");
    println!("  -v             dump WMT and HCI traffic");
}

fn parse_options(args: &[String]) -> Option<Options> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-list" => o.list = true,
            "-parse" => o.parse_only = true,
            "-chipid" => o.chip_id_only = true,
            "-upload" => o.allow_upload = true,
            "-keep" => o.keep = true,
            "-reset7922" => o.subsys_reset = true,
            "-recover" => o.recover = true,
            // Undocumented: checks that a panic returns to the shell.
            "-panic-test" => panic!("test panic requested with -panic-test"),
            "-v" => o.verbose = true,
            "-fw" => o.fw = Some(it.next()?.clone()),
            "-index" => o.index = it.next()?.parse().ok()?,
            _ => return None,
        }
    }
    Some(o)
}

fn print_firmware(name: &str, size: usize, fw: &FirmwareImage<'_>) {
    println!(
        "Firmware: {name}, {size} bytes, build {}, platform {}, hw {:#06x} sw {:#06x}",
        fw.build_time, fw.platform, fw.hw_ver, fw.sw_ver
    );
    for (i, s) in fw.sections().enumerate() {
        println!(
            "  section {i}: type {:#010x}, offset {:#x}, load {:#010x}, {} bytes{}",
            s.sec_type,
            s.offset,
            s.dl_addr,
            s.dl_size,
            if s.dl_size == 0 { " (not sent)" } else { "" }
        );
    }
    println!("  full upload: {} bytes in {} chunks", fw.download_bytes(), fw.download_chunks());
}

fn run_hci_queries(hci: &mut UsbHci) -> bool {
    let mut ret = [0u8; 256];
    match hci.command(uefi_bt::HCI_OP_RESET, &[], &mut ret, HCI_TIMEOUT_MS) {
        Ok(n) if n >= 1 && ret[0] == 0 => println!("HCI_Reset: ok"),
        other => {
            println!("HCI_Reset: failed ({other:?})");
            return false;
        }
    }

    match hci.command(uefi_bt::HCI_OP_READ_LOCAL_VERSION, &[], &mut ret, HCI_TIMEOUT_MS) {
        Ok(n) if n >= 9 && ret[0] == 0 => println!(
            "Local version: HCI {:#04x} rev {:#06x}, LMP {:#04x} subversion {:#06x}, manufacturer {:#06x}",
            ret[1],
            u16::from_le_bytes([ret[2], ret[3]]),
            ret[4],
            u16::from_le_bytes([ret[7], ret[8]]),
            u16::from_le_bytes([ret[5], ret[6]])
        ),
        other => println!("Read_Local_Version: failed ({other:?})"),
    }

    match hci.command(uefi_bt::HCI_OP_READ_BD_ADDR, &[], &mut ret, HCI_TIMEOUT_MS) {
        Ok(n) if n >= 7 && ret[0] == 0 => println!(
            "BD_ADDR: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            ret[6], ret[5], ret[4], ret[3], ret[2], ret[1]
        ),
        other => println!("Read_BD_ADDR: failed ({other:?})"),
    }

    match hci.command(uefi_bt::HCI_OP_LE_READ_BUFFER_SIZE, &[], &mut ret, HCI_TIMEOUT_MS) {
        Ok(n) if n >= 4 && ret[0] == 0 => {
            println!("LE ACL buffers: {} x {} bytes", ret[3], u16::from_le_bytes([ret[1], ret[2]]))
        }
        other => println!("LE_Read_Buffer_Size: failed ({other:?})"),
    }

    if let Ok(n) = hci.command(uefi_bt::HCI_OP_READ_LOCAL_NAME, &[], &mut ret, HCI_TIMEOUT_MS) {
        if n >= 2 && ret[0] == 0 {
            let name = &ret[1..n];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            println!("Local name: \"{}\"", core::str::from_utf8(&name[..end]).unwrap_or("?"));
        }
    }
    true
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let Some(opts) = parse_options(&args()) else {
        usage();
        return Status::INVALID_PARAMETER;
    };

    println!("bt-hci-probe {VERSION}");
    clock::calibrate();
    let start = clock::now_ms();

    // The firmware file is only parsed here; nothing is sent to the chip.
    let fw_name = opts.fw.clone().unwrap_or_else(|| String::from(DEFAULT_FW));
    let fw_data = if opts.list || opts.chip_id_only {
        Vec::new()
    } else {
        match read_file(&fw_name) {
            Ok(data) => data,
            Err(e) => {
                println!("Cannot read firmware file {e}");
                return Status::NOT_FOUND;
            }
        }
    };
    let fw = if fw_data.is_empty() {
        None
    } else {
        match FirmwareImage::parse(&fw_data) {
            Ok(fw) => {
                print_firmware(&fw_name, fw_data.len(), &fw);
                Some(fw)
            }
            Err(e) => {
                println!("{fw_name} is not a valid MT79xx image: {e}");
                return Status::VOLUME_CORRUPTED;
            }
        }
    };
    if opts.parse_only {
        return Status::SUCCESS;
    }

    let (interfaces, scanned) = match uefi_bt::find_hci_interfaces() {
        Ok(found) => found,
        Err(e) => {
            println!("USB enumeration failed: {e:?}");
            return Status::DEVICE_ERROR;
        }
    };
    println!("Bluetooth USB interfaces: {} (of {scanned} USB interfaces)", interfaces.len());
    for (i, intf) in interfaces.iter().enumerate() {
        print_interface(i, intf);
    }
    if opts.list {
        return Status::SUCCESS;
    }

    let Some(intf) = interfaces.iter().filter(|i| i.vendor_id == MTK_VENDOR_ID).nth(opts.index) else {
        println!("No MediaTek Bluetooth interface found (index {}).", opts.index);
        return Status::NOT_FOUND;
    };
    let mut hci = match UsbHci::open(intf.clone()) {
        Ok(hci) => hci,
        Err(e) => {
            println!("Opening the interface failed: {e:?}");
            return Status::DEVICE_ERROR;
        }
    };
    hci.verbose = opts.verbose;

    // Whatever an earlier owner left queued goes first, before any command.
    let drained = hci.drain(20, 300);
    let mut mtk = Mtk::new(hci);
    match drained {
        Ok(r) => report_drain("Before setup", &r),
        Err(e) => return fail(&mut mtk, &opts, &alloc::format!("Draining the controller failed: {e:?}")),
    }

    let info = match mtk.chip_info() {
        Ok(info) => info,
        Err(e) => return fail(&mut mtk, &opts, &alloc::format!("Reading chip ID failed: {e}")),
    };
    let expected = FirmwareName::for_chip(info.chip_id, info.fw_version, info.fw_flavor);
    match expected {
        Some(name) => println!(
            "Chip: {:#06x}, firmware version register {:#010x}, flavor {}, expects {name}",
            info.chip_id, info.fw_version, info.fw_flavor
        ),
        None => println!("Chip: {:#06x}, firmware version register {:#010x}", info.chip_id, info.fw_version),
    }
    if info.chip_id != 0x7922 {
        println!("Only the MT7922 has been looked at so far; stopping.");
        return Status::UNSUPPORTED;
    }
    if opts.chip_id_only {
        println!("Total: {} ms", clock::now_ms() - start);
        return Status::SUCCESS;
    }
    let fw = fw.expect("firmware parsed above");

    if opts.subsys_reset {
        println!("MT7922 subsystem reset...");
        if let Err(e) = mtk.subsys_reset_7922() {
            return fail(&mut mtk, &opts, &alloc::format!("Subsystem reset failed: {e}"));
        }
    }

    let phase = clock::now_ms();
    let loaded = mtk.load_firmware(&fw, opts.allow_upload);
    let s = mtk.stats;
    match &loaded {
        Ok(r) => println!(
            "Firmware sections: {} checked, {} already loaded, {} uploaded ({} chunks), {} busy retries, {} ms, {} WMT commands, {} event polls ({} flagged short)",
            r.sections_checked,
            r.sections_already_loaded,
            r.sections_downloaded,
            r.chunks_sent,
            r.busy_retries,
            clock::now_ms() - phase,
            s.wmt_commands,
            s.event_polls,
            s.short_polls
        ),
        // Only the status query was sent; Linux uploads at its next setup.
        Err(mtk_bt::Error::NotLoaded { section }) => {
            println!("Section {section} is not loaded on the chip. Nothing was uploaded; rerun with -upload to send it.");
            return Status::NOT_STARTED;
        }
        Err(e) => return fail(&mut mtk, &opts, &alloc::format!("Firmware check failed: {e}")),
    }

    match mtk.enable() {
        Ok(event) => match event.status {
            Some(status) => println!("Bluetooth function on (event flag {:#04x}, status {status:#06x})", event.flag),
            None => println!("Bluetooth function on (event flag {:#04x})", event.flag),
        },
        Err(e) => return fail(&mut mtk, &opts, &alloc::format!("Turning Bluetooth on failed: {e}")),
    }
    match mtk.transport.drain(20, 500) {
        Ok(r) => report_drain("After Bluetooth on", &r),
        Err(e) => return fail(&mut mtk, &opts, &alloc::format!("Draining the controller failed: {e:?}")),
    }

    if !run_hci_queries(&mut mtk.transport) {
        return fail(&mut mtk, &opts, "HCI queries failed");
    }
    if !opts.keep {
        hand_off(&mut mtk.transport, opts.recover);
    }
    println!("Total: {} ms", clock::now_ms() - start);
    Status::SUCCESS
}

/// Print what went wrong and the last packets, then hand the controller back.
fn fail(mtk: &mut Mtk<UsbHci>, opts: &Options, message: &str) -> Status {
    println!("{message}");
    print_diagnostics(&mtk.transport);
    hand_off(&mut mtk.transport, opts.recover);
    Status::DEVICE_ERROR
}
