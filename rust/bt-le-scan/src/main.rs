//! bt-le-scan: milestone 2 as a UEFI shell app. Brings up the MediaTek
//! controller (no firmware upload unless `-upload`), resets it from a clean
//! state, runs the TrouBLE host on top of it and does an LE scan, listing
//! every advertiser and whether the bonded keyboard showed up.
//!
//! Every phase is bounded: a watchdog stops the run if the host stack has
//! not started scanning within 10 s, and on any failure the app prints the
//! last packets and hands the controller back (with `-recover`, falling back
//! to the MT7922 subsystem reset if it doesn't answer).

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use bt_hci::controller::ExternalController;
use bt_hci::param::{AddrKind, FilterDuplicates, LeAdvEventKind, LeAdvReportsIter};
use embassy_futures::select::{select3, Either3};
use embassy_time::{Duration, Instant, Timer};
use mtk_bt::{FirmwareImage, Mtk};
use trouble_host::prelude::*;
use uefi::prelude::*;
use uefi::{println, system};
use uefi_bt::app::{args, bring_up_mediatek, hand_off, print_diagnostics, print_pipe_stats, read_file};
use uefi_bt::embassy::{AclMode, UsbHciTransport};
use uefi_bt::{clock, UsbHci};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_FW: &str = "BT_RAM_CODE_MT7922_1_1_hdr.bin";
const DEFAULT_SECONDS: u64 = 30;
const DEFAULT_TARGET: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0]; // C0:00:00:00:00:01, little-endian
const MAX_DEVICES: usize = 64;
/// The host stack must have started scanning this long after it starts.
const SETUP_LIMIT_SECS: u64 = 10;

struct Options {
    seconds: u64,
    active: bool,
    all: bool,
    target: [u8; 6],
    fw: String,
    allow_upload: bool,
    keep: bool,
    verbose: bool,
    recover: bool,
    /// Report every advertising packet instead of one per advertiser.
    dups: bool,
}

fn usage() {
    println!("bt-le-scan {VERSION} - LE scan with TrouBLE on a MediaTek MT79xx controller\n");
    println!("usage: bt-le-scan [options]");
    println!("  -t <seconds>   scan time (default {DEFAULT_SECONDS})");
    println!("  -active        active scan (asks for scan responses, often with names)");
    println!("  -addr <addr>   bonded device to look for (default C0:00:00:00:00:01)");
    println!("  -all           print every report, not just new devices");
    println!("  -dups          let the controller report duplicates (default: one report per advertiser)");
    println!("  -fw <file>     firmware file next to the app (default {DEFAULT_FW})");
    println!("  -upload        allow uploading firmware sections the chip reports missing");
    println!("  -keep          leave Bluetooth on at exit");
    println!("  -recover       if the controller stops answering, do the MT7922 subsystem reset");
    println!("                 before exiting (Linux's recovery after a firmware crash)");
    println!("  -v             dump HCI traffic and the host stack's debug log");
    println!("Any key on this console stops the scan early.");
}

/// "C0:00:00:00:00:01" -> little-endian bytes.
fn parse_addr(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut addr = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        addr[5 - i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(addr)
}

fn parse_options(args: &[String]) -> Option<Options> {
    let mut o = Options {
        seconds: DEFAULT_SECONDS,
        active: false,
        all: false,
        target: DEFAULT_TARGET,
        fw: String::from(DEFAULT_FW),
        allow_upload: false,
        keep: false,
        verbose: false,
        recover: false,
        dups: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-t" => o.seconds = it.next()?.parse().ok()?,
            "-active" => o.active = true,
            "-all" => o.all = true,
            "-addr" => o.target = parse_addr(it.next()?)?,
            "-fw" => o.fw = it.next()?.clone(),
            "-upload" => o.allow_upload = true,
            "-keep" => o.keep = true,
            "-v" => o.verbose = true,
            "-recover" => o.recover = true,
            "-dups" => o.dups = true,
            _ => return None,
        }
    }
    Some(o)
}

fn addr_text(a: &[u8; 6]) -> String {
    alloc::format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", a[5], a[4], a[3], a[2], a[1], a[0])
}

fn addr_kind_name(kind: AddrKind) -> &'static str {
    match kind.as_raw() {
        0 => "public",
        1 => "random",
        2 => "public id",
        3 => "random id",
        _ => "?",
    }
}

fn event_name(kind: LeAdvEventKind) -> &'static str {
    match kind {
        LeAdvEventKind::AdvInd => "ADV_IND",
        LeAdvEventKind::AdvDirectInd => "ADV_DIRECT_IND",
        LeAdvEventKind::AdvScanInd => "ADV_SCAN_IND",
        LeAdvEventKind::AdvNonconnInd => "ADV_NONCONN_IND",
        LeAdvEventKind::ScanRsp => "SCAN_RSP",
    }
}

/// What the AD structures say: local name, appearance, HID service.
#[derive(Default, Clone)]
struct AdInfo {
    name: Option<String>,
    appearance: Option<u16>,
    hid: bool,
}

fn parse_ad(mut data: &[u8]) -> AdInfo {
    let mut info = AdInfo::default();
    while data.len() >= 2 {
        let len = usize::from(data[0]);
        if len == 0 || len + 1 > data.len() {
            break;
        }
        let (ty, value) = (data[1], &data[2..=len]);
        match ty {
            0x08 | 0x09 => info.name = core::str::from_utf8(value).ok().map(String::from),
            0x19 if value.len() >= 2 => info.appearance = Some(u16::from_le_bytes([value[0], value[1]])),
            0x02 | 0x03 => info.hid |= value.chunks_exact(2).any(|u| u16::from_le_bytes([u[0], u[1]]) == 0x1812),
            _ => {}
        }
        data = &data[len + 1..];
    }
    info
}

struct Seen {
    addr: [u8; 6],
    kind: u8,
    reports: u32,
    events: u8,
    rssi: i8,
    ad: AdInfo,
}

struct ScanLog {
    target: [u8; 6],
    all: bool,
    verbose: bool,
    devices: RefCell<Vec<Seen>>,
    total: RefCell<u32>,
    target_printed: RefCell<u32>,
}

impl ScanLog {
    fn line(&self, prefix: &str, addr: &[u8; 6], kind: AddrKind, rssi: i8, event: LeAdvEventKind, ad: &AdInfo) {
        let mut text = alloc::format!(
            "{prefix}{} ({}) {rssi:4} dBm  {}",
            addr_text(addr),
            addr_kind_name(kind),
            event_name(event)
        );
        if let Some(name) = &ad.name {
            text += &alloc::format!("  \"{name}\"");
        }
        if ad.hid {
            text += "  HID";
        }
        if let Some(a) = ad.appearance {
            text += &alloc::format!("  appearance {a:#06x}");
        }
        if *addr == self.target {
            text += "   <== bonded keyboard";
        }
        println!("{text}");
    }
}

impl EventHandler for ScanLog {
    fn on_adv_reports(&self, reports: LeAdvReportsIter) {
        for report in reports.flatten() {
            *self.total.borrow_mut() += 1;
            let addr: [u8; 6] = report.addr.raw().try_into().unwrap_or([0; 6]);
            let ad = parse_ad(report.data);
            let event_bit = 1u8 << (report.event_kind as u8);

            let mut devices = self.devices.borrow_mut();
            let index = devices.iter().position(|d| d.addr == addr && d.kind == report.addr_kind.as_raw());
            let is_new = index.is_none();
            if let Some(i) = index {
                let d = &mut devices[i];
                d.reports += 1;
                d.rssi = report.rssi;
                d.events |= event_bit;
                if d.ad.name.is_none() {
                    d.ad.name = ad.name.clone();
                }
                d.ad.hid |= ad.hid;
                d.ad.appearance = d.ad.appearance.or(ad.appearance);
            } else if devices.len() < MAX_DEVICES {
                devices.push(Seen {
                    addr,
                    kind: report.addr_kind.as_raw(),
                    reports: 1,
                    events: event_bit,
                    rssi: report.rssi,
                    ad: ad.clone(),
                });
            }
            drop(devices);

            if addr == self.target && *self.target_printed.borrow() < 5 {
                *self.target_printed.borrow_mut() += 1;
                self.line("  * ", &addr, report.addr_kind, report.rssi, report.event_kind, &ad);
                if self.verbose {
                    uefi_bt::dump("data:", report.data, 31);
                }
            } else if is_new || self.all {
                self.line(if is_new { "  + " } else { "    " }, &addr, report.addr_kind, report.rssi, report.event_kind, &ad);
            }
        }
    }
}

fn print_summary(log: &ScanLog) {
    let devices = log.devices.borrow();
    println!("\nScan summary: {} reports from {} devices", log.total.borrow(), devices.len());
    let names = ["ADV_IND", "ADV_DIRECT_IND", "ADV_SCAN_IND", "ADV_NONCONN_IND", "SCAN_RSP"];
    let mut seen_target = false;
    for d in devices.iter() {
        let mut text = alloc::format!(
            "  {} ({}) {:4} reports, last {:4} dBm,",
            addr_text(&d.addr),
            addr_kind_name(AddrKind::new(d.kind)),
            d.reports,
            d.rssi
        );
        for (i, n) in names.iter().enumerate() {
            if d.events & (1 << i) != 0 {
                text += " ";
                text += n;
            }
        }
        if let Some(name) = &d.ad.name {
            text += &alloc::format!("  \"{name}\"");
        }
        if d.ad.hid {
            text += "  HID";
        }
        if d.addr == log.target {
            text += "   <== bonded keyboard";
            seen_target = true;
        }
        println!("{text}");
    }
    println!(
        "Bonded keyboard {}: {}",
        addr_text(&log.target),
        if seen_target { "SEEN" } else { "not seen (press a key on it during the scan)" }
    );
}

fn key_pressed() -> bool {
    system::with_stdin(|stdin| matches!(stdin.read_key(), Ok(Some(_))))
}

type Ctrl<'a> = ExternalController<UsbHciTransport<'a>, 10>;

async fn scan_for(
    central: &mut Central<'_, Ctrl<'_>, DefaultPacketPool>,
    opts: &Options,
    scanning: &Cell<bool>,
) -> Result<(), String> {
    let mut scanner = Scanner::new(central);
    // Duplicate filtering keeps the event load low: one report per advertiser.
    let filter_duplicates = if opts.dups { FilterDuplicates::Disabled } else { FilterDuplicates::Enabled };
    let config = ScanConfig { active: opts.active, filter_duplicates, ..ScanConfig::default() };
    let _session = scanner.scan(&config).await.map_err(|e| alloc::format!("starting the scan failed: {e:?}"))?;
    scanning.set(true);
    println!(
        "Scanning ({}{}) for {} s. Press a key on the Bluetooth keyboard to wake it; any key here stops.",
        if opts.active { "active" } else { "passive" },
        if opts.dups { ", all duplicates" } else { ", one report per advertiser" },
        opts.seconds
    );
    let end = Instant::now() + Duration::from_secs(opts.seconds);
    while Instant::now() < end {
        if key_pressed() {
            println!("Stopped by key press.");
            break;
        }
        Timer::after(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Ends the run if the host stack hasn't started scanning in time, or the
/// scan overruns. TrouBLE has no timeouts of its own, so a controller that
/// stops answering would otherwise hang the app.
async fn watchdog(scanning: &Cell<bool>, scan_secs: u64) -> String {
    let start = Instant::now();
    let setup_limit = Duration::from_secs(SETUP_LIMIT_SECS);
    let overall = Duration::from_secs(scan_secs + SETUP_LIMIT_SECS + 5);
    loop {
        Timer::after(Duration::from_millis(100)).await;
        if !scanning.get() && start.elapsed() > setup_limit {
            return alloc::format!("Watchdog: the host stack did not start scanning within {SETUP_LIMIT_SECS} s");
        }
        if start.elapsed() > overall {
            return String::from("Watchdog: the scan did not end on time");
        }
    }
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let Some(opts) = parse_options(&args()) else {
        usage();
        return Status::INVALID_PARAMETER;
    };
    log::set_max_level(if opts.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Warn });
    println!("bt-le-scan {VERSION}");
    clock::calibrate();

    let fw_data = match read_file(&opts.fw) {
        Ok(data) => data,
        Err(e) => {
            println!("Cannot read firmware file {e}");
            return Status::NOT_FOUND;
        }
    };
    let fw = match FirmwareImage::parse(&fw_data) {
        Ok(fw) => fw,
        Err(e) => {
            println!("{} is not a valid MT79xx image: {e}", opts.fw);
            return Status::VOLUME_CORRUPTED;
        }
    };

    let mtk = match bring_up_mediatek(&fw, opts.allow_upload, opts.verbose) {
        Ok(mtk) => mtk,
        Err(e) => {
            println!("{}", e.message);
            if let Some(mut mtk) = e.mtk {
                print_diagnostics(&mtk.transport);
                hand_off(&mut mtk.transport, opts.recover);
            }
            return Status::DEVICE_ERROR;
        }
    };
    println!("Controller reset; starting the BLE host (TrouBLE)");

    // TrouBLE gets the interface through a RefCell; we take it back afterwards
    // for the hand-off.
    let hci = RefCell::new(mtk.transport);
    // If TrouBLE panics, the panic handler hands the controller back.
    uefi_bt::emergency::register(&hci, opts.recover);
    let log = ScanLog {
        target: opts.target,
        all: opts.all,
        verbose: opts.verbose,
        devices: RefCell::new(Vec::new()),
        total: RefCell::new(0),
        target_printed: RefCell::new(0),
    };
    let scanning = Cell::new(false);
    let start = clock::now_ms();
    let outcome = {
        // Nothing gets connected while scanning, so connection data is
        // dropped; the ACL pipe is still read.
        let controller: Ctrl<'_> = ExternalController::new(UsbHciTransport::new(&hci, AclMode::Discard));
        let mut resources: HostResources<DefaultPacketPool, 1, 1> = HostResources::new();
        let stack = trouble_host::new(controller, &mut resources).build();
        let mut runner = stack.runner();
        let mut central = stack.central();
        embassy_futures::block_on(async {
            match select3(
                runner.run_with_handler(&log),
                scan_for(&mut central, &opts, &scanning),
                watchdog(&scanning, opts.seconds),
            )
            .await
            {
                Either3::First(Ok(())) => Err(String::from("host runner stopped")),
                Either3::First(Err(e)) => Err(alloc::format!("host runner failed: {e:?}")),
                Either3::Second(result) => result,
                Either3::Third(message) => Err(message),
            }
        })
    };

    uefi_bt::emergency::unregister();
    let mut mtk: Mtk<UsbHci> = Mtk::new(hci.into_inner());
    let ok = match &outcome {
        Ok(()) => {
            print_summary(&log);
            print_pipe_stats(&mtk.transport);
            if mtk.transport.stats.events_malformed > 0 {
                println!("  {} malformed events dropped", mtk.transport.stats.events_malformed);
            }
            true
        }
        Err(e) => {
            println!("{e}");
            print_diagnostics(&mtk.transport);
            false
        }
    };
    println!("Total: {} ms", clock::now_ms() - start);
    if !ok || !opts.keep {
        hand_off(&mut mtk.transport, opts.recover);
    }
    if ok { Status::SUCCESS } else { Status::DEVICE_ERROR }
}
