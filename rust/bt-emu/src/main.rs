//! `bt-emu`: the emulated MT7922 and keyboard, as a program QEMU's
//! `usb-redir` device connects to.
//!
//! ```text
//! bt-emu --socket PATH [--bond FILE] [--state FILE] [--script FILE] [--screen FILE] [--log FILE] [--quiet]
//!        [--timeout SECONDS]
//!
//! qemu ... -chardev socket,id=emu,path=PATH -device usb-redir,chardev=emu
//! ```
//!
//! `--bond`: a bond file as `scripts/export-bond.sh` writes it. It gives
//! the controller's address, the keyboard's address, and the key the
//! keyboard holds for this host. Without it the keyboard has no bond.
//! `--state`: where the keyboard keeps its bond between runs, so that a
//! pairing made in one boot of the guest is still there at the next. If
//! the file exists, the bond in it (or its absence) replaces the one of
//! `--bond`; it is rewritten whenever the keyboard's bond changes.
//! `--script`: what the keyboard's user does (see `script.rs`). The
//! program ends when QEMU closes the connection, and exits with 1 if a
//! step of the script failed.
//! `--screen`: the file QEMU writes the guest's serial console to, for the
//! script's `read-passkey` (the keyboard's user reads the passkey off the
//! PC's screen).

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use bt_emu::radio::{Bond, Config, Radio};
use bt_emu::script::{self, Script};
use bt_emu::usbdev::{FromHost, UsbDev};
use bt_emu::usbredir::{self, Framer};
use bt_emu::{log, note};

#[derive(Default)]
struct Args {
    socket: Option<PathBuf>,
    bond: Option<PathBuf>,
    state: Option<PathBuf>,
    script: Option<PathBuf>,
    screen: Option<PathBuf>,
    log: Option<PathBuf>,
    quiet: bool,
    timeout_s: Option<u64>,
}

fn usage() -> ExitCode {
    eprintln!("usage: bt-emu --socket PATH [--bond FILE] [--state FILE] [--script FILE] [--screen FILE] [--log FILE] [--quiet] [--timeout SECONDS]");
    ExitCode::from(2)
}

fn parse_args() -> Option<Args> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => args.socket = Some(it.next()?.into()),
            "--bond" => args.bond = Some(it.next()?.into()),
            "--state" => args.state = Some(it.next()?.into()),
            "--script" => args.script = Some(it.next()?.into()),
            "--log" => args.log = Some(it.next()?.into()),
            "--quiet" => args.quiet = true,
            "--timeout" => args.timeout_s = Some(it.next()?.parse().ok()?),
            "--screen" => args.screen = Some(it.next()?.into()),
            _ => return None,
        }
    }
    args.socket.is_some().then_some(args)
}

fn config_from_bond(text: &str) -> Result<Config, String> {
    let bond = uefi_bt::bond::ExportedBond::parse(text).map_err(|e| format!("{e}"))?;
    Ok(Config {
        bd_addr: bond.adapter,
        kbd_addr: bond.peer,
        kbd_random: bond.peer_is_random,
        bond: Some(Bond { ediv: bond.ediv, rand: bond.rand_bytes(), ltk: bond.ltk }),
        ..Config::default()
    })
}

fn run(args: Args) -> Result<bool, String> {
    let mut cfg = match &args.bond {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            config_from_bond(&text).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => Config::default(),
    };
    if let Some(text) = args.state.as_ref().and_then(|path| std::fs::read_to_string(path).ok()) {
        cfg.bond = Bond::from_text(&text).map_err(|e| format!("{}: {e}", args.state.as_ref().unwrap().display()))?;
    }
    let mut saved_bond = cfg.bond;
    let steps = match &args.script {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            script::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => Vec::new(),
    };
    let mut script = Script::new(steps).with_screen(args.screen.clone());
    let mut radio = Radio::new(cfg);
    let mut dev = UsbDev::new();

    let socket = args.socket.as_ref().unwrap();
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    note!(
        "bt-emu: an MT7922 at {}, a keyboard at {} ({}); waiting for QEMU on {}",
        uefi_bt::bond::addr_text(&radio.cfg.bd_addr),
        uefi_bt::bond::addr_text(&radio.cfg.kbd_addr),
        if radio.cfg.bond.is_some() { "bonded to this controller" } else { "not bonded" },
        socket.display()
    );
    let (stream, _) = listener.accept().map_err(|e| format!("accepting QEMU's connection: {e}"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("{e}"))?;
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut stream = stream;
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(n) => {
                    if tx.send(Some(buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let start = Instant::now();
    let now_ms = || start.elapsed().as_millis() as u64;
    let mut framer = Framer::default();
    let mut script_wake: Option<u64> = Some(0);
    let mut gone = false;
    while !gone && !script.quit {
        let now = now_ms();
        if args.timeout_s.is_some_and(|limit| now >= limit * 1000) {
            note!("bt-emu: time limit reached");
            break;
        }
        let wake = [radio.next_deadline(), script_wake].into_iter().flatten().fold(now + 50, u64::min);
        match rx.recv_timeout(Duration::from_millis(wake.saturating_sub(now))) {
            Ok(Some(bytes)) => framer.push(&bytes),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => gone = true,
            Err(RecvTimeoutError::Timeout) => {}
        }
        while let Ok(more) = rx.try_recv() {
            match more {
                Some(bytes) => framer.push(&bytes),
                None => gone = true,
            }
        }
        let now = now_ms();
        radio.advance(now);
        while let Some(packet) = framer.next()? {
            if packet.kind == usbredir::HELLO {
                let caps = usbredir::hello_caps(&packet.body).unwrap_or(0);
                if caps & usbredir::NEEDED_CAPS != usbredir::NEEDED_CAPS {
                    return Err(format!("QEMU's usbredir capabilities ({caps:#x}) lack what this needs ({:#x})", usbredir::NEEDED_CAPS));
                }
                let version = String::from_utf8_lossy(&packet.body[..packet.body.len().min(64)]);
                note!("usb: connected to {} (capabilities {caps:#x})", version.trim_end_matches('\0'));
                writer.write_all(&usbredir::hello("bt-emu 0.1")).map_err(|e| format!("{e}"))?;
                framer.ids64 = true;
                dev.announce();
            } else {
                dev.handle(&packet);
            }
            for message in dev.from_host.drain(..) {
                match message {
                    FromHost::Command(command) => radio.command(&command),
                    FromHost::Acl(packet) => radio.acl_from_host(&packet),
                    FromHost::PowerOff => radio.power_off(),
                }
            }
        }
        script_wake = script.run(now, &mut radio, &mut dev);
        if radio.cfg.bond != saved_bond {
            saved_bond = radio.cfg.bond;
            if let Some(path) = &args.state {
                if let Err(e) = std::fs::write(path, Bond::to_text(&saved_bond)) {
                    note!("bt-emu: writing {} failed: {e}", path.display());
                }
            }
        }
        // What the script or the host just started may be due at once.
        radio.advance(now);
        for event in radio.events.drain(..) {
            dev.push_event(event);
        }
        for packet in radio.acl.drain(..) {
            dev.push_acl(packet);
        }
        dev.flush();
        for wire in dev.out.drain(..) {
            if writer.write_all(&wire).is_err() {
                gone = true;
                break;
            }
        }
    }

    let (s, f) = (&dev.stats, &radio.facts);
    note!(
        "summary: usb: {} control transfers, {} HCI commands, {} WMT commands, {} events, {} ACL packets out, {} ACL transfers in ({} merged, {} packets split, {} requeued after a cancel, {} lost to one), {} reads cancelled, {} requests stalled",
        s.control, f.commands, s.wmt_commands, s.events, s.acl_out, s.acl_in_transfers, s.merged_transfers, s.split_packets, s.requeued, s.lost, s.cancelled_reads, s.stalls
    );
    note!(
        "summary: link: {} connections, {} encryptions ({} refused, {} MIC failures), {} ATT requests, {} key reports sent, {} pairing packets from the host, {} disconnects by the host, {} by the keyboard, {} parameter requests ({} accepted)",
        f.connections, f.encryptions, f.encryptions_refused, f.mic_failures, f.att_requests, f.key_reports_sent, f.smp_from_host, f.host_disconnects, f.kbd_disconnects, f.param_requests, f.param_accepted
    );
    if !f.unknown_commands.is_empty() {
        note!("summary: HCI commands that aren't emulated: {:04x?}", f.unknown_commands);
    }
    let position = match script.line() {
        Some(line) if !script.quit => format!("stopped at line {line}"),
        _ => String::from("ran to its end"),
    };
    note!("summary: script: {position}, {} failed", script.failures);
    Ok(script.line().is_none_or(|_| script.quit) && script.failures == 0)
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else { return usage() };
    if let Err(e) = log::init(args.log.as_deref(), args.quiet) {
        eprintln!("bt-emu: opening the log failed: {e}");
        return ExitCode::from(2);
    }
    match run(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            note!("bt-emu: {e}");
            eprintln!("bt-emu: {e}");
            ExitCode::from(2)
        }
    }
}
