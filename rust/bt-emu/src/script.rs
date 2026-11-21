//! What the keyboard's "user" does, and what the test expects: a small
//! script, one step per line.
//!
//! ```text
//! # comments and empty lines are skipped
//! wait encrypted             wait for a state (30 s at most, or `wait encrypted 5000`)
//! wait connections >= 2      ... or for a counter (see `value` below)
//! sleep 500                  milliseconds
//! wake                       a key that sends nothing: the keyboard wakes and advertises
//! pairing-mode               its pairing button: discoverable, undirected advertising,
//!                            the old bond forgotten
//! passkey 123456             the user types this passkey on the keyboard, and Enter
//! read-passkey 20000         ... the passkey the PC shows: the six digits after the last
//!                            "passkey" on its screen (the file given with --screen, which
//!                            QEMU writes the serial console to), waited for this long
//! wait-screen 20000 Shell>   wait until the PC's screen shows this text
//! type echo hi{enter}        type text; {enter} {esc} {tab} {bs} {del} {up} {down} {left}
//!                            {right} {space} {f1}..{f12}, and {wait:MS} for a pause
//! report 00 51               one keyboard report: modifiers, then the keys held (hex);
//!                            `report 00` releases everything
//! hold 51 3000               a key held for that long (hex usage, ms)
//! media ea                   a media key (consumer usage, hex): the F-row in media mode
//! battery 80                 the battery level changes
//! param-request 20 36 4 200  ask for connection parameters (interval x 1.25 ms, timeout x 10 ms)
//! disconnect 13              the keyboard ends the link with this reason (hex)
//! l2cap 0006 0b 01           a raw L2CAP PDU from the keyboard at once (channel, bytes; hex)
//! attack-type abc            key reports sent whether or not the link is encrypted
//! set encrypt-delay 150      a setting: the delays (connect-delay, encrypt-delay,
//!                            first-report-delay, att-delay, key-interval, supervision),
//!                            the keyboard's habits (param-after, idle, battery-after: ms
//!                            or `off`), what it remembers (bond none|wrong-key), the
//!                            controller (bd-addr, firmware-loaded, encryption-change-v1),
//!                            the next ACL packets' USB transfers (acl-merge N,
//!                            acl-split BYTES), and lose-on-cancel 1 to lose data the
//!                            way a real controller passed through to QEMU does;
//!                            pairing (pairing off|legacy|sc, io keyboard|none,
//!                            key-size N, keys-from-host and keys-from-kbd as the key
//!                            distribution bits, impostor 1 for a "keyboard" that
//!                            pairs without knowing the passkey, pairing-keys-delay MS
//!                            from the encryption to the keyboard's keys)
//! expect encrypted           check a state or counter now; a failure is logged and counted
//! expect smp-from-host = 0
//! note reached the shell     a line in the log
//! quit                       unplug the controller and end the emulator
//! ```
//!
//! A step that fails (a wait that times out, an expectation that doesn't
//! hold) is logged with `FAILED`; a timed-out wait also ends the script,
//! while the emulator goes on serving.

use std::path::PathBuf;

use crate::note;
use crate::radio::Radio;
use crate::smp;
use crate::usbdev::UsbDev;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Ge,
    Le,
}

/// A condition on a named value: `encryptions >= 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub op: Op,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Wait(Check, u64),
    Sleep(u64),
    Wake,
    PairingMode,
    Passkey(u32),
    ReadPasskey(u64),
    WaitScreen(String, u64),
    Type(String),
    Report(u8, Vec<u8>),
    Hold(u8, u64),
    Media(u16),
    Battery(u8),
    ParamRequest(u16, u16, u16, u16),
    Disconnect(u8),
    L2cap(u16, Vec<u8>),
    AttackType(String),
    Set(String, String),
    Expect(Check),
    Note(String),
    Quit,
}

/// One key of typed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Tap { modifiers: u8, usage: u8 },
    Pause(u64),
}

const LEFT_SHIFT: u8 = 0x02;

fn named_key(name: &str) -> Option<u8> {
    Some(match name {
        "enter" => 0x28,
        "esc" => 0x29,
        "bs" => 0x2A,
        "tab" => 0x2B,
        "space" => 0x2C,
        "del" => 0x4C,
        "right" => 0x4F,
        "left" => 0x50,
        "down" => 0x51,
        "up" => 0x52,
        _ => {
            let n: u8 = name.strip_prefix('f')?.parse().ok()?;
            if !(1..=12).contains(&n) {
                return None;
            }
            0x3A + n - 1
        }
    })
}

/// Text as key presses on a US layout, with `{name}` keys and `{wait:MS}`.
pub fn keys_of(text: &str) -> Result<Vec<Key>, String> {
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '{' {
            let end = rest.find('}').ok_or_else(|| format!("no closing brace in {rest:?}"))?;
            let token = &rest[1..end];
            rest = &rest[end + 1..];
            if let Some(ms) = token.strip_prefix("wait:") {
                keys.push(Key::Pause(ms.parse().map_err(|_| format!("bad pause {token:?}"))?));
            } else {
                let usage = named_key(token).ok_or_else(|| format!("no key named {token:?}"))?;
                keys.push(Key::Tap { modifiers: 0, usage });
            }
            continue;
        }
        rest = &rest[c.len_utf8()..];
        let (usage, shift) = uefi_bt::keymap::usage_for_ascii(c).ok_or_else(|| format!("no key on a US layout for {c:?}"))?;
        keys.push(Key::Tap { modifiers: if shift { LEFT_SHIFT } else { 0 }, usage: usage as u8 });
    }
    Ok(keys)
}

fn parse_check(tokens: &[&str]) -> Result<Check, String> {
    match tokens {
        ["disconnected"] => Ok(Check { name: "connected".into(), op: Op::Eq, value: 0 }),
        ["sent"] => Ok(Check { name: "unsent".into(), op: Op::Eq, value: 0 }),
        [name] => Ok(Check { name: (*name).into(), op: Op::Ge, value: 1 }),
        [name, op, value] => {
            let op = match *op {
                "=" | "==" => Op::Eq,
                "!=" => Op::Ne,
                ">=" => Op::Ge,
                "<=" => Op::Le,
                other => return Err(format!("unknown comparison {other:?}")),
            };
            let value = value.parse().or_else(|_| i64::from_str_radix(value.trim_start_matches("0x"), 16)).map_err(|_| format!("bad number {value:?}"))?;
            Ok(Check { name: (*name).into(), op, value })
        }
        _ => Err(format!("can't read the condition {tokens:?}")),
    }
}

fn hex_bytes(tokens: &[&str]) -> Result<Vec<u8>, String> {
    tokens.iter().map(|t| u8::from_str_radix(t, 16).map_err(|_| format!("bad hex byte {t:?}"))).collect()
}

/// Parse a script; errors name the line.
pub fn parse(text: &str) -> Result<Vec<(usize, Step)>, String> {
    let mut steps = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (word, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(w, r)| (w, r.trim_start()));
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let number = |at: usize| -> Result<u64, String> {
            tokens.get(at).ok_or_else(|| String::from("a number is missing"))?.parse().map_err(|_| format!("bad number {:?}", tokens[at]))
        };
        let hex = |at: usize| -> Result<u16, String> {
            u16::from_str_radix(tokens.get(at).ok_or_else(|| String::from("a hex value is missing"))?, 16).map_err(|_| format!("bad hex value {:?}", tokens[at]))
        };
        let step = (|| -> Result<Step, String> {
            Ok(match word {
                "wait" => {
                    // A trailing number after a one-word or three-word
                    // condition is the timeout.
                    let (condition, timeout) = match tokens.len() {
                        2 | 4 => (&tokens[..tokens.len() - 1], number(tokens.len() - 1)?),
                        _ => (&tokens[..], 30_000),
                    };
                    Step::Wait(parse_check(condition)?, timeout)
                }
                "sleep" => Step::Sleep(number(0)?),
                "wake" => Step::Wake,
                "pairing-mode" => Step::PairingMode,
                "passkey" => match tokens.as_slice() {
                    [digits] if digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()) => Step::Passkey(digits.parse().unwrap()),
                    _ => return Err("a passkey is six digits".into()),
                },
                "read-passkey" => Step::ReadPasskey(if tokens.is_empty() { 30_000 } else { number(0)? }),
                "wait-screen" => {
                    let timeout = number(0)?;
                    let text = rest.split_once(char::is_whitespace).map_or("", |(_, t)| t.trim());
                    if text.is_empty() {
                        return Err("wait-screen takes a timeout and the text to wait for".into());
                    }
                    Step::WaitScreen(text.into(), timeout)
                }
                "type" => {
                    keys_of(rest)?;
                    Step::Type(rest.into())
                }
                "report" => {
                    let bytes = hex_bytes(&tokens)?;
                    let (&modifiers, keys) = bytes.split_first().ok_or("a report needs its modifier byte")?;
                    if keys.len() > 10 {
                        return Err("a report has ten key slots".into());
                    }
                    Step::Report(modifiers, keys.to_vec())
                }
                "hold" => Step::Hold(hex(0)? as u8, number(1)?),
                "media" => Step::Media(hex(0)?),
                "battery" => Step::Battery(number(0)? as u8),
                "param-request" => Step::ParamRequest(number(0)? as u16, number(1)? as u16, number(2)? as u16, number(3)? as u16),
                "disconnect" => Step::Disconnect(hex(0)? as u8),
                "l2cap" => Step::L2cap(hex(0)?, hex_bytes(&tokens[1.min(tokens.len())..])?),
                "attack-type" => {
                    keys_of(rest)?;
                    Step::AttackType(rest.into())
                }
                "set" => match tokens.as_slice() {
                    [name, value] => Step::Set((*name).into(), (*value).into()),
                    _ => return Err("set takes a name and a value".into()),
                },
                "expect" => Step::Expect(parse_check(&tokens)?),
                "note" => Step::Note(rest.into()),
                "quit" => Step::Quit,
                other => return Err(format!("unknown step {other:?}")),
            })
        })()
        .map_err(|e| format!("line {}: {e}", index + 1))?;
        steps.push((index + 1, step));
    }
    Ok(steps)
}

/// A named state or counter of the emulation.
pub fn value(name: &str, radio: &Radio, dev: &UsbDev) -> Option<i64> {
    let f = &radio.facts;
    let s = &dev.stats;
    Some(match name {
        "usb" => i64::from(dev.is_configured()),
        "function-on" => i64::from(dev.function_on()),
        "initiating" => i64::from(radio.is_initiating()),
        "advertising" => i64::from(radio.is_advertising()),
        "scanning" => i64::from(radio.is_scanning()),
        "adv-reports" => i64::from(f.adv_reports),
        "pairing-mode" => i64::from(radio.in_pairing_mode()),
        "bonded" => i64::from(radio.cfg.bond.is_some()),
        "pairing-requests" => i64::from(radio.smp.requests),
        "pairings" => i64::from(radio.smp.completed),
        "pairing-failures" => i64::from(radio.smp.failures),
        "last-pairing-failure" => i64::from(radio.smp.last_failure),
        "connected" => i64::from(radio.is_connected()),
        "encrypted" => i64::from(radio.is_encrypted()),
        "unsent" => (radio.unsent() + dev.acl_waiting()) as i64,
        "leds" => radio.leds.map_or(-1, i64::from),
        "keys-notifying" => i64::from(radio.att.notifying(crate::gatt::H_KEYS_CCCD)),
        "commands" => i64::from(f.commands),
        "hci-resets" => i64::from(f.hci_resets),
        "unknown-commands" => f.unknown_commands.len() as i64,
        "connections" => i64::from(f.connections),
        "encryptions" => i64::from(f.encryptions),
        "refused" => i64::from(f.encryptions_refused),
        "mic-failures" => i64::from(f.mic_failures),
        "host-disconnects" => i64::from(f.host_disconnects),
        "kbd-disconnects" => i64::from(f.kbd_disconnects),
        "acl-from-host" => i64::from(f.acl_from_host),
        "att-requests" => i64::from(f.att_requests),
        // How long the host has asked nothing over ATT (-1: it never did).
        "att-quiet-ms" => {
            if f.att_requests == 0 { -1 } else { radio.now().saturating_sub(f.last_att_ms) as i64 }
        }
        "att-errors" => i64::from(radio.att.errors_sent),
        "smp-from-host" => i64::from(f.smp_from_host),
        "key-reports" => i64::from(f.key_reports_sent),
        "param-requests" => i64::from(f.param_requests),
        "param-accepted" => i64::from(f.param_accepted),
        "param-rejected" => i64::from(f.param_rejected),
        "connection-updates" => i64::from(f.connection_updates),
        "wmt-commands" => i64::from(s.wmt_commands),
        "merged" => i64::from(s.merged_transfers),
        "split" => i64::from(s.split_packets),
        "requeued" => i64::from(s.requeued),
        "lost" => i64::from(s.lost),
        "cancelled-reads" => i64::from(s.cancelled_reads),
        "stalls" => i64::from(s.stalls),
        _ => return None,
    })
}

fn holds(check: &Check, radio: &Radio, dev: &UsbDev) -> (bool, Option<i64>) {
    let Some(is) = value(&check.name, radio, dev) else { return (false, None) };
    let ok = match check.op {
        Op::Eq => is == check.value,
        Op::Ne => is != check.value,
        Op::Ge => is >= check.value,
        Op::Le => is <= check.value,
    };
    (ok, Some(is))
}

fn describe(check: &Check) -> String {
    let op = match check.op {
        Op::Eq => "=",
        Op::Ne => "!=",
        Op::Ge => ">=",
        Op::Le => "<=",
    };
    format!("{} {op} {}", check.name, check.value)
}

fn apply_setting(name: &str, value: &str, radio: &mut Radio, dev: &mut UsbDev) -> Result<(), String> {
    let ms = || value.parse::<u64>().map_err(|_| format!("bad number {value:?}"));
    let optional_ms = || if value == "off" { Ok(None) } else { value.parse::<u64>().map(Some).map_err(|_| format!("bad number {value:?}")) };
    match name {
        "connect-delay" => radio.cfg.connect_delay_ms = ms()?,
        "encrypt-delay" => radio.cfg.encrypt_delay_ms = ms()?,
        "first-report-delay" => radio.cfg.first_report_delay_ms = ms()?,
        "att-delay" => radio.cfg.att_delay_ms = ms()?,
        "key-interval" => radio.cfg.key_interval_ms = ms()?,
        "supervision" => radio.cfg.supervision_ms = ms()?,
        "param-after" => radio.cfg.param_request_after_ms = optional_ms()?,
        "idle" => radio.cfg.idle_disconnect_ms = optional_ms()?,
        "battery-after" => radio.cfg.battery_after_ms = optional_ms()?,
        "encryption-change-v1" => radio.cfg.encryption_change_v1 = ms()? != 0,
        "firmware-loaded" => dev.firmware_loaded = ms()? != 0,
        "lose-on-cancel" => dev.lose_on_cancel = ms()? != 0,
        // The controller's own address, as in 02:00:00:00:00:03.
        "bd-addr" => radio.cfg.bd_addr = uefi_bt::bond::parse_addr(value).ok_or_else(|| format!("bad address {value:?}"))?,
        // The next ACL packets' layout in USB transfers.
        "acl-merge" => dev.shaping.merge = ms()? as usize,
        "acl-split" => dev.shaping.split_at = Some(ms()? as usize),
        // How the keyboard pairs.
        "pairing" => {
            radio.smp.settings.method = match value {
                "off" => smp::Method::None,
                "legacy" => smp::Method::Legacy,
                "sc" => smp::Method::SecureConnections,
                _ => return Err(format!("pairing can be off, legacy or sc, not {value:?}")),
            }
        }
        "io" => {
            radio.smp.settings.io = match value {
                "keyboard" => smp::IO_KEYBOARD_ONLY,
                "none" => smp::IO_NO_INPUT_NO_OUTPUT,
                _ => return Err(format!("io can be keyboard or none, not {value:?}")),
            }
        }
        "key-size" => radio.smp.settings.max_key_size = ms()? as u8,
        "keys-from-host" => radio.smp.settings.key_dist.0 = ms()? as u8,
        "keys-from-kbd" => radio.smp.settings.key_dist.1 = ms()? as u8,
        "impostor" => radio.smp.settings.impostor = ms()? != 0,
        "pairing-keys-delay" => radio.cfg.pairing_keys_delay_ms = ms()?,
        // What the keyboard remembers of this host.
        "bond" => {
            let bond = radio.cfg.bond;
            match (value, bond) {
                ("none", _) => radio.set_bond(None),
                ("wrong-key", Some(mut b)) => {
                    b.ltk[0] ^= 0xFF;
                    radio.set_bond(Some(b));
                }
                ("wrong-key", None) => return Err("there is no bond to change".into()),
                _ => return Err(format!("bond can be none or wrong-key, not {value:?}")),
            }
        }
        _ => return Err(format!("unknown setting {name:?}")),
    }
    Ok(())
}

/// What a serial console's output shows as text: without the terminal
/// escape sequences (ESC [ parameters, one final byte).
pub fn screen_text(screen: &[u8]) -> String {
    let mut text = String::new();
    let mut bytes = screen.iter().copied().peekable();
    while let Some(b) = bytes.next() {
        if b == 0x1B && bytes.peek() == Some(&b'[') {
            bytes.next();
            for c in bytes.by_ref() {
                if (0x40..=0x7E).contains(&c) {
                    break;
                }
            }
        } else if b.is_ascii() {
            text.push(b as char);
        }
    }
    text
}

/// The six digits after the last "passkey" in what the PC's screen showed
/// ("123 456" counts too).
pub fn passkey_on_screen(screen: &[u8]) -> Option<u32> {
    let text = screen_text(screen).to_ascii_lowercase();
    let after = &text[text.rfind("passkey")? + "passkey".len()..];
    let start = after.find(|c: char| c.is_ascii_digit())?;
    if start > 60 {
        return None;
    }
    let mut digits = String::new();
    for c in after[start..].chars() {
        match c {
            '0'..='9' => digits.push(c),
            ' ' if !digits.is_empty() && digits.len() < 6 => {}
            _ => break,
        }
    }
    if digits.len() == 6 { digits.parse().ok() } else { None }
}

pub struct Script {
    steps: Vec<(usize, Step)>,
    at: usize,
    /// When the current wait or sleep began.
    since: Option<u64>,
    pub failures: u32,
    pub quit: bool,
    stopped: bool,
    /// The file the PC's screen (its serial console) is written to, and
    /// how much of it earlier steps have read.
    screen: Option<PathBuf>,
    screen_read: usize,
}

impl Script {
    pub fn new(steps: Vec<(usize, Step)>) -> Self {
        Self { steps, at: 0, since: None, failures: 0, quit: false, stopped: false, screen: None, screen_read: 0 }
    }

    pub fn with_screen(mut self, screen: Option<PathBuf>) -> Self {
        self.screen = screen;
        self
    }

    /// Nothing more will run: the end was reached, or a step stopped it.
    pub fn finished(&self) -> bool {
        self.stopped || self.at >= self.steps.len()
    }

    /// The line of the step the script is at, if it isn't through.
    pub fn line(&self) -> Option<usize> {
        self.steps.get(self.at).map(|(line, _)| *line)
    }

    /// Run until a step has to wait. Returns when to look again, if it's
    /// a matter of time.
    pub fn run(&mut self, now: u64, radio: &mut Radio, dev: &mut UsbDev) -> Option<u64> {
        while !self.stopped && self.at < self.steps.len() {
            let (line, step) = self.steps[self.at].clone();
            match step {
                Step::Wait(check, timeout) => {
                    let since = *self.since.get_or_insert(now);
                    let (ok, is) = holds(&check, radio, dev);
                    if is.is_none() {
                        note!("script: line {line}: FAILED: nothing is called {:?}", check.name);
                        self.failures += 1;
                        self.stopped = true;
                        return None;
                    }
                    if !ok {
                        if now.saturating_sub(since) >= timeout {
                            note!("script: line {line}: FAILED: waited {timeout} ms for {} (it is {})", describe(&check), is.unwrap());
                            self.failures += 1;
                            self.stopped = true;
                            return None;
                        }
                        return Some((since + timeout).min(now + 5));
                    }
                    note!("script: {} after {} ms", describe(&check), now.saturating_sub(since));
                }
                Step::Sleep(ms) => {
                    let since = *self.since.get_or_insert(now);
                    if now.saturating_sub(since) < ms {
                        return Some(since + ms);
                    }
                }
                Step::Wake => radio.wake(),
                Step::PairingMode => radio.enter_pairing_mode(),
                Step::Passkey(passkey) => radio.type_passkey(passkey),
                Step::ReadPasskey(timeout) => {
                    let since = *self.since.get_or_insert(now);
                    let Some(path) = &self.screen else {
                        note!("script: line {line}: FAILED: read-passkey needs --screen FILE");
                        self.failures += 1;
                        self.stopped = true;
                        return None;
                    };
                    let screen = std::fs::read(path).unwrap_or_default();
                    match passkey_on_screen(screen.get(self.screen_read..).unwrap_or_default()) {
                        Some(passkey) => {
                            note!("script: the screen shows passkey {passkey:06} ({} ms)", now.saturating_sub(since));
                            self.screen_read = screen.len();
                            radio.type_passkey(passkey);
                        }
                        None if now.saturating_sub(since) >= timeout => {
                            note!("script: line {line}: FAILED: no passkey on the screen after {timeout} ms");
                            self.failures += 1;
                            self.stopped = true;
                            return None;
                        }
                        None => return Some((since + timeout).min(now + 50)),
                    }
                }
                Step::WaitScreen(text, timeout) => {
                    let since = *self.since.get_or_insert(now);
                    let shown = self.screen.as_ref().is_some_and(|path| screen_text(&std::fs::read(path).unwrap_or_default()).contains(&text));
                    if !shown {
                        if now.saturating_sub(since) >= timeout {
                            note!("script: line {line}: FAILED: the screen didn't show {text:?} within {timeout} ms");
                            self.failures += 1;
                            self.stopped = true;
                            return None;
                        }
                        return Some((since + timeout).min(now + 100));
                    }
                    note!("script: the screen shows {text:?} ({} ms)", now.saturating_sub(since));
                }
                Step::Type(text) => {
                    note!("script: typing {text:?}");
                    for key in keys_of(&text).unwrap_or_default() {
                        match key {
                            Key::Tap { modifiers, usage } => radio.tap(modifiers, usage),
                            Key::Pause(ms) => radio.pause(ms),
                        }
                    }
                }
                Step::Report(modifiers, keys) => radio.key_report(modifiers, &keys, None),
                Step::Hold(usage, ms) => {
                    radio.key_report(0, &[usage], Some(ms));
                    radio.key_report(0, &[], None);
                }
                Step::Media(usage) => radio.media_key(usage),
                Step::Battery(percent) => radio.set_battery(percent),
                Step::ParamRequest(min, max, latency, timeout) => radio.request_params(min, max, latency, timeout),
                Step::Disconnect(reason) => radio.kbd_disconnect(reason),
                Step::L2cap(cid, payload) => radio.raw_to_host(cid, payload, false),
                Step::AttackType(text) => {
                    note!("script: typing {text:?} without waiting for encryption");
                    for key in keys_of(&text).unwrap_or_default() {
                        if let Key::Tap { modifiers, usage } = key {
                            radio.key_report_unprotected(modifiers, &[usage]);
                            radio.key_report_unprotected(0, &[]);
                        }
                    }
                }
                Step::Set(name, value) => match apply_setting(&name, &value, radio, dev) {
                    Ok(()) => note!("script: {name} = {value}"),
                    Err(e) => {
                        note!("script: line {line}: FAILED: {e}");
                        self.failures += 1;
                    }
                },
                Step::Expect(check) => match holds(&check, radio, dev) {
                    (true, _) => note!("script: expect {}: ok", describe(&check)),
                    (false, is) => {
                        let is = is.map_or_else(|| String::from("unknown"), |v| v.to_string());
                        note!("script: line {line}: expect {}: FAILED (it is {is})", describe(&check));
                        self.failures += 1;
                    }
                },
                Step::Note(text) => note!("script: {text}"),
                Step::Quit => {
                    self.quit = true;
                    self.stopped = true;
                }
            }
            self.since = None;
            self.at += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::{Bond, Config};

    #[test]
    fn text_becomes_keys() {
        assert_eq!(
            keys_of("aB!{enter}{wait:250}{f2}{up}").unwrap(),
            vec![
                Key::Tap { modifiers: 0, usage: 0x04 },
                Key::Tap { modifiers: LEFT_SHIFT, usage: 0x05 },
                Key::Tap { modifiers: LEFT_SHIFT, usage: 0x1E },
                Key::Tap { modifiers: 0, usage: 0x28 },
                Key::Pause(250),
                Key::Tap { modifiers: 0, usage: 0x3B },
                Key::Tap { modifiers: 0, usage: 0x52 },
            ]
        );
        assert_eq!(named_key("f12"), Some(0x45));
        assert!(keys_of("{f13}").is_err());
        assert!(keys_of("{enter").is_err());
        assert!(keys_of("é").is_err());
    }

    #[test]
    fn scripts_parse() {
        let steps = parse(
            "# a comment\n\nwait encrypted\nwait connections >= 2 5000\nwait sent 100\nsleep 20\ntype echo  hi{enter}\nreport 00 51\nreport 00\n\
             hold 51 3000\nmedia ea\nl2cap 0006 0b 01\nset encrypt-delay 150\nexpect smp-from-host = 0\nexpect leds = 0x02\nnote  done here \nquit\n",
        )
        .unwrap();
        let steps: Vec<Step> = steps.into_iter().map(|(_, s)| s).collect();
        assert_eq!(steps[0], Step::Wait(Check { name: "encrypted".into(), op: Op::Ge, value: 1 }, 30_000));
        assert_eq!(steps[1], Step::Wait(Check { name: "connections".into(), op: Op::Ge, value: 2 }, 5000));
        assert_eq!(steps[2], Step::Wait(Check { name: "unsent".into(), op: Op::Eq, value: 0 }, 100));
        assert_eq!(steps[3], Step::Sleep(20));
        assert_eq!(steps[4], Step::Type("echo  hi{enter}".into()));
        assert_eq!(steps[5], Step::Report(0, vec![0x51]));
        assert_eq!(steps[6], Step::Report(0, vec![]));
        assert_eq!(steps[7], Step::Hold(0x51, 3000));
        assert_eq!(steps[8], Step::Media(0xEA));
        assert_eq!(steps[9], Step::L2cap(6, vec![0x0B, 0x01]));
        assert_eq!(steps[10], Step::Set("encrypt-delay".into(), "150".into()));
        assert_eq!(steps[12], Step::Expect(Check { name: "leds".into(), op: Op::Eq, value: 2 }));
        assert_eq!(steps[13], Step::Note("done here".into()));
        assert_eq!(steps[14], Step::Quit);
        // Errors name the line.
        assert!(parse("sleep 5\nfrobnicate\n").unwrap_err().starts_with("line 2:"));
        assert!(parse("type {nokey}").is_err());
        assert!(parse("report").is_err());
        assert!(parse("expect a b").is_err());
    }

    #[test]
    fn a_script_waits_checks_and_fails_visibly() {
        let mut radio = Radio::new(Config::default());
        let mut dev = UsbDev::new();
        let steps = parse("expect connected = 0\nsleep 100\nwait connected 50\nnote never reached\n").unwrap();
        let mut script = Script::new(steps);
        // The sleep holds it for 100 ms.
        assert_eq!(script.run(1000, &mut radio, &mut dev), Some(1100));
        assert_eq!(script.run(1050, &mut radio, &mut dev), Some(1100));
        // Then the wait, checked every few ms until it times out.
        assert_eq!(script.run(1100, &mut radio, &mut dev), Some(1105));
        assert!(!script.finished());
        assert_eq!(script.run(1150, &mut radio, &mut dev), None);
        assert!(script.finished());
        assert_eq!(script.failures, 1);
    }

    #[test]
    fn the_passkey_is_read_off_the_screen() {
        assert_eq!(passkey_on_screen(b"Type the passkey 012345 on the keyboard, then Enter"), Some(12345));
        assert_eq!(passkey_on_screen(b"\x1b[2J\x1b[01;01HPasskey:\x1b[05;10H  123 456\r\n"), Some(123456));
        // The last one counts; an incomplete one doesn't.
        assert_eq!(passkey_on_screen(b"passkey 111111 ... new passkey 222222"), Some(222222));
        assert_eq!(passkey_on_screen(b"passkey 12345"), None);
        assert_eq!(passkey_on_screen(b"passkey 1234567"), None);
        assert_eq!(passkey_on_screen(b"no such thing 123456"), None);
        assert_eq!(parse("passkey 000042\nread-passkey\nread-passkey 5000").unwrap().into_iter().map(|(_, s)| s).collect::<Vec<_>>(), [
            Step::Passkey(42),
            Step::ReadPasskey(30_000),
            Step::ReadPasskey(5000)
        ]);
        assert!(parse("passkey 12345").is_err());
        assert_eq!(parse("wait-screen 5000 FS0:\\> ").unwrap()[0].1, Step::WaitScreen("FS0:\\>".into(), 5000));
        assert!(parse("wait-screen 5000").is_err());
        assert_eq!(screen_text(b"\x1b[1m\x1b[33mFS0:\\>\x1b[0m echo"), "FS0:\\> echo");
    }

    #[test]
    fn settings() {
        let mut radio = Radio::new(Config { bond: Some(Bond { ediv: 1, rand: [2; 8], ltk: [3; 16] }), ..Config::default() });
        let mut dev = UsbDev::new();
        apply_setting("idle", "off", &mut radio, &mut dev).unwrap();
        apply_setting("acl-merge", "2", &mut radio, &mut dev).unwrap();
        apply_setting("bond", "wrong-key", &mut radio, &mut dev).unwrap();
        assert_eq!((radio.cfg.idle_disconnect_ms, dev.shaping.merge, radio.cfg.bond.unwrap().ltk[0]), (None, 2, 0xFC));
        assert_eq!(value("keys-notifying", &radio, &dev), Some(1));
        apply_setting("bond", "none", &mut radio, &mut dev).unwrap();
        assert_eq!(value("keys-notifying", &radio, &dev), Some(0));
        apply_setting("bd-addr", "02:00:00:00:00:03", &mut radio, &mut dev).unwrap();
        assert_eq!(radio.cfg.bd_addr, [0x03, 0, 0, 0, 0, 0x02]);
        assert!(apply_setting("bd-addr", "nonsense", &mut radio, &mut dev).is_err());
        assert!(apply_setting("volume", "11", &mut radio, &mut dev).is_err());
        assert_eq!(value("no-such-thing", &radio, &dev), None);
    }
}
