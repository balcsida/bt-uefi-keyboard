//! bt-kb-probe: milestone 3 as a UEFI shell app.
//!
//! Brings up the MediaTek controller (no firmware upload unless `-upload`),
//! imports the keyboard's bond exported from BlueZ, waits for the keyboard to
//! connect (it advertises after a key press) and encrypts the link with the
//! stored key. Then it reads the HID Report Map to find the keyboard report's
//! layout and shows key reports in two phases: report protocol (what Linux
//! and Windows use), then boot protocol. Afterwards it leaves the keyboard's
//! notification settings and protocol mode as it found them, disconnects
//! and hands the controller back.
//!
//! Every phase has a time limit (watchdog), and on any failure the app
//! prints the last packets and hands the controller back; with `-recover` it
//! falls back to the MT7922 subsystem reset if the controller doesn't answer.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use core::cell::{Cell, RefCell};

use bt_hci::controller::ExternalController;
use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use mtk_bt::{FirmwareImage, Mtk};
use trouble_host::prelude::*;
use uefi::prelude::*;
use uefi::println;
use uefi_bt::app::{args, bring_up_mediatek, hand_off, print_diagnostics, print_pipe_stats, read_file};
use uefi_bt::bond::{addr_text, ExportedBond};
use uefi_bt::hid::{find_keyboard_report, KeyField, KeyboardReport};
use uefi_bt::embassy::{AclMode, UsbHciTransport};
use uefi_bt::{clock, UsbHci};

mod keys;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_FW: &str = "BT_RAM_CODE_MT7922_1_1_hdr.bin";
const DEFAULT_BOND: &str = "C00000000001.bond";
const DEFAULT_SECONDS: u64 = 25;
const DEFAULT_CONNECT_SECONDS: u64 = 30;

const UUID_HID_SERVICE: u16 = 0x1812;
const UUID_PROTOCOL_MODE: u16 = 0x2A4E;
const UUID_BOOT_KEYBOARD_INPUT: u16 = 0x2A22;
const UUID_REPORT_MAP: u16 = 0x2A4B;
const UUID_REPORT: u16 = 0x2A4D;
const REPORT_TYPE_INPUT: u8 = 1;
const PROTOCOL_BOOT: u8 = 0;
const PROTOCOL_REPORT: u8 = 1;

type Ctrl<'a> = ExternalController<UsbHciTransport<'a>, 10>;
type Pool = DefaultPacketPool;

struct Options {
    seconds: u64,
    connect_seconds: u64,
    bond: String,
    fw: String,
    allow_upload: bool,
    recover: bool,
    verbose: bool,
    check: bool,
    att: bool,
}

fn usage() {
    println!("bt-kb-probe {VERSION} - connect to the bonded keyboard and show its key reports\n");
    println!("usage: bt-kb-probe [options]");
    println!("  -t <seconds>   length of each typing phase, report then boot protocol (default {DEFAULT_SECONDS})");
    println!("  -wait <s>      how long to wait for the keyboard to connect (default {DEFAULT_CONNECT_SECONDS})");
    println!("  -bond <file>   bond exported by scripts/export-bond.sh (default {DEFAULT_BOND} next to the app)");
    println!("  -fw <file>     firmware file next to the app (default {DEFAULT_FW})");
    println!("  -check         load the bond and firmware files, then stop (touches no hardware)");
    println!("  -upload        allow uploading firmware sections the chip reports missing");
    println!("  -recover       if the controller stops answering, do the MT7922 subsystem reset");
    println!("  -no-att        don't trace ATT/SMP packets (traced by default)");
    println!("  -v             dump HCI traffic and the host stack's debug log");
}

fn parse_options(args: &[String]) -> Option<Options> {
    let mut o = Options {
        seconds: DEFAULT_SECONDS,
        connect_seconds: DEFAULT_CONNECT_SECONDS,
        bond: String::from(DEFAULT_BOND),
        fw: String::from(DEFAULT_FW),
        allow_upload: false,
        recover: false,
        verbose: false,
        check: false,
        att: true,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-t" => o.seconds = it.next()?.parse().ok()?,
            "-wait" => o.connect_seconds = it.next()?.parse().ok()?,
            "-bond" => o.bond = it.next()?.clone(),
            "-fw" => o.fw = it.next()?.clone(),
            "-check" => o.check = true,
            "-upload" => o.allow_upload = true,
            "-recover" => o.recover = true,
            "-v" => o.verbose = true,
            "-no-att" => o.att = false,
            _ => return None,
        }
    }
    Some(o)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Host stack setup, then waiting for the keyboard to connect.
    Connecting,
    Encrypting,
    Discovering,
    TypingReport,
    TypingBoot,
    Closing,
}

/// Ends the run if a phase overstays. TrouBLE has no timeouts of its own.
async fn watchdog(phase: &Cell<Phase>, opts: &Options) -> String {
    let mut current = phase.get();
    let mut since = Instant::now();
    loop {
        Timer::after(Duration::from_millis(100)).await;
        if phase.get() != current {
            current = phase.get();
            since = Instant::now();
        }
        let limit = match current {
            Phase::Connecting => opts.connect_seconds + 10,
            Phase::Encrypting => 10,
            Phase::Discovering => 30,
            Phase::TypingReport | Phase::TypingBoot => opts.seconds + 10,
            Phase::Closing => 10,
        };
        if since.elapsed() > Duration::from_secs(limit) {
            return alloc::format!("Watchdog: stuck in {current:?} for {limit} s");
        }
    }
}

#[derive(Default)]
struct Outcome {
    layout: Option<KeyboardReport>,
    report: keys::Decoder,
    boot: keys::Decoder,
    boot_mode_accepted: Option<bool>,
}

async fn session(
    stack: &Stack<'_, Ctrl<'_>, Pool>,
    central: &mut Central<'_, Ctrl<'_>, Pool>,
    bond: &ExportedBond,
    opts: &Options,
    phase: &Cell<Phase>,
    outcome: &RefCell<Outcome>,
) -> Result<(), String> {
    let kind = if bond.peer_is_random { AddrKind::RANDOM } else { AddrKind::PUBLIC };
    let target = [Address::new(kind, BdAddr::new(bond.peer))];
    let config = ConnectConfig {
        scan_config: ScanConfig { filter_accept_list: &target, ..ScanConfig::default() },
        connect_params: RequestedConnParams {
            min_connection_interval: Duration::from_millis(15),
            max_connection_interval: Duration::from_millis(30),
            max_latency: 0,
            min_event_length: Duration::from_secs(0),
            max_event_length: Duration::from_secs(0),
            supervision_timeout: Duration::from_secs(4),
        },
    };
    println!(
        "Waiting up to {} s for {}: press a key on the keyboard to wake it.",
        opts.connect_seconds,
        addr_text(&bond.peer)
    );
    let conn = match with_timeout(Duration::from_secs(opts.connect_seconds), central.connect(&config)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(alloc::format!("Connecting failed: {e:?}")),
        Err(_) => {
            return Err(alloc::format!(
                "The keyboard did not connect within {} s. Was a key pressed on it?",
                opts.connect_seconds
            ));
        }
    };
    println!("Connected");

    // From here on the keyboard is connected: always disconnect on the way out.
    let result = connected(stack, &conn, opts, phase, outcome).await;
    phase.set(Phase::Closing);
    if conn.is_connected() {
        conn.disconnect();
        let _ = with_timeout(Duration::from_secs(3), async {
            loop {
                if let ConnectionEvent::Disconnected { reason } = conn.next().await {
                    println!("Disconnected ({reason:?})");
                    break;
                }
            }
        })
        .await;
    }
    result
}

async fn connected(
    stack: &Stack<'_, Ctrl<'_>, Pool>,
    conn: &Connection<'_, Pool>,
    opts: &Options,
    phase: &Cell<Phase>,
    outcome: &RefCell<Outcome>,
) -> Result<(), String> {
    phase.set(Phase::Encrypting);
    conn.request_security().map_err(|e| alloc::format!("Requesting encryption failed: {e:?}"))?;
    loop {
        match conn.next().await {
            ConnectionEvent::Encrypted { security_level, .. } | ConnectionEvent::PairingComplete { security_level, .. } => {
                println!("Link encrypted with the stored key ({security_level:?})");
                break;
            }
            ConnectionEvent::PairingFailed(e) => return Err(alloc::format!("Encryption failed: {e:?}")),
            ConnectionEvent::BondLost => return Err(String::from("The keyboard rejected the stored key (bond lost)")),
            ConnectionEvent::Disconnected { reason } => return Err(alloc::format!("The keyboard disconnected: {reason:?}")),
            ConnectionEvent::RequestConnectionParams(req) => {
                let _ = req.accept(None, stack).await;
            }
            _ => {}
        }
    }

    phase.set(Phase::Discovering);
    let client = GattClient::<Ctrl<'_>, Pool, 8>::new(stack, conn)
        .await
        .map_err(|e| alloc::format!("Starting the GATT client failed: {e:?}"))?;
    match select3(client.task(), hid(&client, opts, phase, outcome), watch_connection(stack, conn)).await {
        Either3::First(result) => Err(alloc::format!("The GATT client stopped: {result:?}")),
        Either3::Second(result) => result,
        Either3::Third(message) => Err(message),
    }
}

/// Connection events while the HID session runs: accept parameter requests
/// (keyboards ask for their preferred interval), and notice a disconnection.
async fn watch_connection(stack: &Stack<'_, Ctrl<'_>, Pool>, conn: &Connection<'_, Pool>) -> String {
    loop {
        match conn.next().await {
            ConnectionEvent::Disconnected { reason } => return alloc::format!("The keyboard disconnected: {reason:?}"),
            ConnectionEvent::RequestConnectionParams(req) => {
                let _ = req.accept(None, stack).await;
            }
            _ => {}
        }
    }
}

fn layout_text(layout: &KeyboardReport) -> String {
    let keys = match layout.keys {
        KeyField::Array { bit, count, size } => alloc::format!("{count} key slots of {size} bits at bit {bit}"),
        KeyField::Bitmap { bit, first_usage, count } => {
            alloc::format!("a {count}-key bitmap from usage {first_usage:#04x} at bit {bit}")
        }
    };
    alloc::format!(
        "report ID {}, {} bits; modifiers {}; {keys}",
        layout.report_id.map(|id| alloc::format!("{id}")).unwrap_or_else(|| String::from("none")),
        layout.bits,
        layout.modifiers_bit.map(|b| alloc::format!("at bit {b}")).unwrap_or_else(|| String::from("none"))
    )
}

/// Show key reports from `listener` until `seconds` have passed.
async fn show_reports<const MTU: usize>(
    listener: &mut trouble_host::gatt::NotificationListener<'_, MTU>,
    seconds: u64,
    mut handle: impl FnMut(&[u8]),
) {
    let end = Instant::now() + Duration::from_secs(seconds);
    loop {
        match select(listener.next(), Timer::at(end)).await {
            Either::First(notification) => handle(notification.as_ref()),
            Either::Second(()) => break,
        }
    }
}

async fn hid(
    client: &GattClient<'_, Ctrl<'_>, Pool, 8>,
    opts: &Options,
    phase: &Cell<Phase>,
    outcome: &RefCell<Outcome>,
) -> Result<(), String> {
    let services = client
        .services_by_uuid(&Uuid::new_short(UUID_HID_SERVICE))
        .await
        .map_err(|e| alloc::format!("HID service discovery failed: {e:?}"))?;
    let service = services.first().ok_or_else(|| String::from("The keyboard has no HID service"))?;
    let chars = client
        .characteristics::<32>(service)
        .await
        .map_err(|e| alloc::format!("Characteristic discovery failed: {e:?}"))?;
    let find = |uuid: u16| chars.iter().find(|c| c.uuid == Uuid::new_short(uuid));
    let mode = find(UUID_PROTOCOL_MODE).ok_or_else(|| String::from("No Protocol Mode characteristic"))?;
    let boot_input = find(UUID_BOOT_KEYBOARD_INPUT).ok_or_else(|| String::from("No Boot Keyboard Input characteristic"))?;
    let report_map = find(UUID_REPORT_MAP).ok_or_else(|| String::from("No Report Map characteristic"))?;
    println!(
        "HID service: {} characteristics; Protocol Mode {:#06x}, Report Map {:#06x}, Boot Keyboard Input {:#06x}",
        chars.len(),
        mode.handle,
        report_map.handle,
        boot_input.handle
    );

    // The Report Map says where the keys are in the keyboard's report.
    let mut map = [0u8; 1024];
    let map_len = client
        .read_handle(report_map.handle, &mut map)
        .await
        .map_err(|e| alloc::format!("Reading the Report Map failed: {e:?}"))?;
    let layout = find_keyboard_report(&map[..map_len]);
    println!("Report Map: {map_len} bytes");
    if opts.verbose {
        uefi_bt::dump("map:", &map[..map_len], map_len);
    }
    match &layout {
        Some(l) => println!("Keyboard input report: {}", layout_text(l)),
        None => println!("No keyboard input report found in the Report Map"),
    }
    outcome.borrow_mut().layout = layout;

    // Report characteristics: report ID and type from their Report Reference.
    let mut keyboard_input = None;
    for c in chars.iter().filter(|c| c.uuid == Uuid::new_short(UUID_REPORT)) {
        let reference = (c.handle + 1..=c.end_handle).find(|&h| Some(h) != c.cccd_handle);
        let mut value = [0u8; 2];
        let id_type = match reference {
            Some(h) => match client.read_handle(h, &mut value).await {
                Ok(2) => Some((value[0], value[1])),
                _ => None,
            },
            None => None,
        };
        let text = match id_type {
            Some((id, t)) => alloc::format!(
                "ID {id}, {}",
                match t {
                    1 => "input",
                    2 => "output",
                    3 => "feature",
                    _ => "unknown type",
                }
            ),
            None => String::from("no Report Reference"),
        };
        let is_keyboard = match (layout, id_type) {
            (Some(l), Some((id, REPORT_TYPE_INPUT))) => l.report_id.is_none_or(|lid| lid == id) && c.cccd_handle.is_some(),
            _ => false,
        };
        println!(
            "  Report {:#06x}: {text}{}{}",
            c.handle,
            if c.cccd_handle.is_some() { ", notifies" } else { "" },
            if is_keyboard && keyboard_input.is_none() { "   <== keyboard keys" } else { "" }
        );
        if is_keyboard && keyboard_input.is_none() {
            keyboard_input = Some(c);
        }
    }

    // Phase 1: report protocol, the mode the keyboard is in after connecting.
    match (keyboard_input, layout) {
        (Some(input), Some(layout)) => {
            let cccd = input.cccd_handle.expect("checked above");
            let mut original = [0u8; 2];
            let was_on = matches!(client.read_handle(cccd, &mut original).await, Ok(2) if original[0] & 1 != 0);
            let mut listener = client
                .subscribe(input, false)
                .await
                .map_err(|e| alloc::format!("Subscribing to the keyboard report failed: {e:?}"))?;
            phase.set(Phase::TypingReport);
            println!("\n=== REPORT PROTOCOL: type now, for {} s ===", opts.seconds);
            show_reports(&mut listener, opts.seconds, |raw| {
                let mut out = outcome.borrow_mut();
                match layout.decode(raw) {
                    Some((modifiers, held)) => out.report.keys(raw, modifiers, &held),
                    None => println!("  report of {} bytes did not match the layout", raw.len()),
                }
            })
            .await;
            drop(listener);
            // Linux had these notifications on (the keyboard remembers that per
            // host), so only turn them off if they were off.
            if !was_on {
                let _ = client.unsubscribe(input).await;
            }
            println!("Report notifications left {}", if was_on { "on, as they were" } else { "off, as they were" });
        }
        _ => println!("Skipping the report protocol phase: no keyboard report characteristic found"),
    }

    // Phase 2: boot protocol.
    client
        .write_characteristic_without_response(mode, &[PROTOCOL_BOOT])
        .await
        .map_err(|e| alloc::format!("Switching to boot protocol failed: {e:?}"))?;
    let mut value = [0u8; 4];
    let accepted = matches!(client.read_handle(mode.handle, &mut value).await, Ok(n) if n >= 1 && value[0] == PROTOCOL_BOOT);
    outcome.borrow_mut().boot_mode_accepted = Some(accepted);
    println!("Protocol Mode is now {}", if accepted { "boot" } else { "still report: the keyboard ignored the switch" });
    let mut listener = client
        .subscribe(boot_input, false)
        .await
        .map_err(|e| alloc::format!("Subscribing to boot reports failed: {e:?}"))?;
    phase.set(Phase::TypingBoot);
    println!("\n=== BOOT PROTOCOL: type now, for {} s ===", opts.seconds);
    show_reports(&mut listener, opts.seconds, |raw| outcome.borrow_mut().boot.boot_report(raw)).await;
    drop(listener);

    // Leave the keyboard as we found it: boot notifications off, report protocol.
    phase.set(Phase::Closing);
    let off = client.unsubscribe(boot_input).await;
    let report = client.write_characteristic_without_response(mode, &[PROTOCOL_REPORT]).await;
    println!(
        "Restored: boot notifications off {}, report protocol {}",
        if off.is_ok() { "ok" } else { "FAILED" },
        if report.is_ok() { "ok" } else { "FAILED" }
    );
    Ok(())
}

fn load_bond(name: &str) -> Result<ExportedBond, String> {
    let data = read_file(name).map_err(|e| alloc::format!("Cannot read the bond file {e}"))?;
    let text = core::str::from_utf8(&data).map_err(|_| String::from("The bond file is not text"))?;
    ExportedBond::parse(text).map_err(|e| alloc::format!("{name}: {e}"))
}

fn bond_information(bond: &ExportedBond) -> BondInformation {
    let kind = if bond.peer_is_random { AddrKind::RANDOM } else { AddrKind::PUBLIC };
    // No IRK: the keyboard advertises with its identity address, and without
    // one TrouBLE leaves the controller's resolving list alone.
    let identity = Identity { addr: Address::new(kind, BdAddr::new(bond.peer)), irk: None };
    let level = if bond.authenticated() { SecurityLevel::EncryptedAuthenticated } else { SecurityLevel::Encrypted };
    let mut info = BondInformation::new(identity, LongTermKey::from_le_bytes(bond.ltk), level, true);
    info.ediv = bond.ediv;
    info.rand = bond.rand_bytes();
    info.encryption_key_len = bond.enc_size;
    info
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let Some(opts) = parse_options(&args()) else {
        usage();
        return Status::INVALID_PARAMETER;
    };
    log::set_max_level(if opts.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Warn });
    println!("bt-kb-probe {VERSION}");
    clock::calibrate();

    let bond = match load_bond(&opts.bond) {
        Ok(bond) => bond,
        Err(e) => {
            println!("{e}");
            return Status::NOT_FOUND;
        }
    };
    println!("Loaded the {}", bond.summary());
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
    if opts.check {
        println!("Bond and firmware files are fine; -check stops here.");
        return Status::SUCCESS;
    }

    let mut mtk = match bring_up_mediatek(&fw, opts.allow_upload, opts.verbose) {
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

    // The keyboard knows this PC by the controller's address.
    let mut ret = [0u8; 8];
    match mtk.transport.command(uefi_bt::HCI_OP_READ_BD_ADDR, &[], &mut ret, 2000) {
        Ok(n) if n >= 7 && ret[0] == 0 && ret[1..7] == bond.adapter => {}
        Ok(n) if n >= 7 && ret[0] == 0 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&ret[1..7]);
            println!(
                "This controller is {}, but the bond belongs to {}; stopping.",
                addr_text(&addr),
                addr_text(&bond.adapter)
            );
            hand_off(&mut mtk.transport, opts.recover);
            return Status::INVALID_PARAMETER;
        }
        other => {
            println!("Reading the controller address failed: {other:?}");
            print_diagnostics(&mtk.transport);
            hand_off(&mut mtk.transport, opts.recover);
            return Status::DEVICE_ERROR;
        }
    }
    println!("Controller reset; starting the BLE host (TrouBLE)");
    if opts.att {
        println!("Tracing ATT/SMP packets (ms, > sent, < received):");
        mtk.transport.att_trace = true;
    }

    let hci = RefCell::new(mtk.transport);
    uefi_bt::emergency::register(&hci, opts.recover);
    let phase = Cell::new(Phase::Connecting);
    let collected = RefCell::new(Outcome::default());
    let start = clock::now_ms();
    let outcome = {
        let controller: Ctrl<'_> = ExternalController::new(UsbHciTransport::new(&hci, AclMode::Deliver));
        let mut resources: HostResources<Pool, 1, 4> = HostResources::new();
        let stack = trouble_host::new(controller, &mut resources).build();
        match stack.add_bond_information(bond_information(&bond)) {
            Ok(()) => {
                let mut runner = stack.runner();
                let mut central = stack.central();
                let run = async {
                    match select3(
                        runner.run(),
                        session(&stack, &mut central, &bond, &opts, &phase, &collected),
                        watchdog(&phase, &opts),
                    )
                    .await
                    {
                        Either3::First(Ok(())) => Err(String::from("The host runner stopped")),
                        Either3::First(Err(e)) => Err(alloc::format!("The host runner failed: {e:?}")),
                        Either3::Second(result) => result,
                        Either3::Third(message) => Err(message),
                    }
                };
                // The future holds the GATT client and its notification queues;
                // keep it on the heap, not on the firmware's small stack.
                if opts.verbose {
                    println!("Session future: {} bytes (on the heap)", core::mem::size_of_val(&run));
                }
                embassy_futures::block_on(alloc::boxed::Box::pin(run))
            }
            Err(e) => Err(alloc::format!("Importing the bond failed: {e:?}")),
        }
    };
    uefi_bt::emergency::unregister();

    let mut mtk: Mtk<UsbHci> = Mtk::new(hci.into_inner());
    let collected = collected.into_inner();
    println!("\nResults (text read with a US layout):");
    println!(
        "  report protocol: {} reports, typed \"{}\"",
        collected.report.reports,
        keys::escape(&collected.report.typed)
    );
    println!(
        "  boot protocol:   {} reports, typed \"{}\"{}",
        collected.boot.reports,
        keys::escape(&collected.boot.typed),
        match collected.boot_mode_accepted {
            Some(false) => " (the keyboard ignored the switch to boot protocol)",
            _ => "",
        }
    );
    let ok = match &outcome {
        Ok(()) => {
            mtk.transport.stats.print();
            print_pipe_stats(&mtk.transport);
            true
        }
        Err(e) => {
            println!("{e}");
            print_diagnostics(&mtk.transport);
            false
        }
    };
    println!("Total: {} ms", clock::now_ms() - start);
    hand_off(&mut mtk.transport, opts.recover);
    if ok { Status::SUCCESS } else { Status::DEVICE_ERROR }
}
