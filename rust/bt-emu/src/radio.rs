//! The radio side of the emulated controller: HCI commands and events,
//! one LE link, and the keyboard at its other end.
//!
//! The keyboard behaves as the real one was seen to (Nov 1 to Nov 4):
//! - **Asleep until a key is pressed.** Then it advertises, and the host's
//!   pending connection (LE Create Connection through the accept list)
//!   completes. The link gets handle 0x0200, as on the MT7922.
//! - **Advertising as scanned on Nov 1:** directed to the bonded host
//!   first (ADV_DIRECT_IND, 1.28 s), then undirected (ADV_IND) with the HID
//!   service and the keyboard appearance; its name comes in the scan
//!   response. In pairing mode it is undirected from the start, and says
//!   it is discoverable.
//! - **Pairing** ([`crate::smp`]): only in pairing mode, which forgets the
//!   host it was bonded to (an assumption: the real keyboard was never put
//!   into pairing mode here, since that would have cost its bond). The
//!   user types the passkey the host shows. The link then counts as
//!   encrypted when the host names the pairing's key in LE Enable
//!   Encryption, and the keyboard remembers the new bond once the keys
//!   are exchanged. A new host finds its notifications off.
//! - **Encryption with the bond it has for this host.** LE Enable
//!   Encryption with the right EDIV, Rand and key turns it on. A key the
//!   keyboard doesn't know gives "PIN or key missing" (0x06). The right
//!   EDIV and Rand with a wrong key ends the link (MIC failure, 0x3D).
//! - **Key reports only on an encrypted link.** What was typed before is
//!   kept and sent about 27 ms after the encryption, at one report per
//!   connection event.
//! - **A connection parameter request** over L2CAP signaling about 5 s
//!   after connecting, and a disconnect (0x13) after a minute without keys.
//! - **Its notification switches are per bonded host,** so a bonded host
//!   finds the keyboard report notifying from the start.
//!
//! Nothing is encrypted here: the emulation sits above the link layer, at
//! the HCI. "Encrypted" is a flag on the link that the ATT server and the
//! key reports obey.

use std::collections::VecDeque;

use crate::gatt::{self, AttServer};
use crate::note;
use crate::smp::{Ends, Smp};

/// The handle the MT7922 gives its first LE link.
pub const HANDLE: u16 = 0x0200;
const CID_ATT: u16 = 0x0004;
const CID_SIGNALING: u16 = 0x0005;
const CID_SMP: u16 = 0x0006;
/// The controller's LE buffers, as the MT7922 reports them.
const LE_ACL_LENGTH: u16 = 251;
const LE_ACL_PACKETS: u8 = 32;

const ERR_UNKNOWN_COMMAND: u8 = 0x01;
const ERR_UNKNOWN_CONNECTION: u8 = 0x02;
const ERR_PIN_OR_KEY_MISSING: u8 = 0x06;
const ERR_COMMAND_DISALLOWED: u8 = 0x0C;
const ERR_INVALID_PARAMETERS: u8 = 0x12;
pub const REASON_REMOTE_USER: u8 = 0x13;
const REASON_LOCAL_HOST: u8 = 0x16;
const REASON_MIC_FAILURE: u8 = 0x3D;

/// What the keyboard remembers of its pairing with this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bond {
    pub ediv: u16,
    pub rand: [u8; 8],
    pub ltk: [u8; 16],
}

impl Bond {
    /// A bond, or the lack of one, as the emulator's state file has it:
    /// `none`, or EDIV, Rand and the key in hex.
    pub fn to_text(bond: &Option<Bond>) -> String {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match bond {
            None => String::from("none\n"),
            Some(b) => format!("{:04x} {} {}\n", b.ediv, hex(&b.rand), hex(&b.ltk)),
        }
    }

    pub fn from_text(text: &str) -> Result<Option<Bond>, String> {
        let bytes = |hex: &str| -> Option<Vec<u8>> { (0..hex.len() / 2).map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()).collect() };
        match text.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["none"] => Ok(None),
            [ediv, rand, ltk] => (|| {
                Some(Some(Bond { ediv: u16::from_str_radix(ediv, 16).ok()?, rand: bytes(rand)?.try_into().ok()?, ltk: bytes(ltk)?.try_into().ok()? }))
            })()
            .ok_or_else(|| String::from("not a bond")),
            _ => Err(String::from("not a bond")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The controller's public address, least significant byte first.
    pub bd_addr: [u8; 6],
    /// The keyboard's identity address and whether it is a random one.
    pub kbd_addr: [u8; 6],
    pub kbd_random: bool,
    pub bond: Option<Bond>,
    /// From advertising (with the host initiating) to the connection.
    pub connect_delay_ms: u64,
    /// From LE Enable Encryption to the Encryption Change.
    pub encrypt_delay_ms: u64,
    /// From the Encryption Change to the first key report.
    pub first_report_delay_ms: u64,
    /// From an ATT request to its response.
    pub att_delay_ms: u64,
    /// Between key reports: one connection event.
    pub key_interval_ms: u64,
    pub param_request_after_ms: Option<u64>,
    pub idle_disconnect_ms: Option<u64>,
    pub battery_after_ms: Option<u64>,
    /// How long the keyboard takes to notice a link the host dropped
    /// without saying so (an HCI_Reset).
    pub supervision_ms: u64,
    /// Report encryption with version 1 of the event even if the host
    /// unmasked version 2 (controllers older than Bluetooth 5.3).
    pub encryption_change_v1: bool,
    /// From the encryption of a pairing link to the keyboard's keys: they
    /// go out in its next connection events. With 0 they reach the host
    /// together with the Encryption Change, and may overtake it, since
    /// events and data travel through different USB pipes.
    pub pairing_keys_delay_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bd_addr: [0x02, 0, 0, 0, 0, 0x02],
            kbd_addr: [0x01, 0, 0, 0, 0, 0xC0],
            kbd_random: true,
            bond: None,
            connect_delay_ms: 30,
            encrypt_delay_ms: 60,
            first_report_delay_ms: 27,
            att_delay_ms: 2,
            key_interval_ms: 12,
            param_request_after_ms: Some(5000),
            idle_disconnect_ms: Some(60_000),
            battery_after_ms: Some(2500),
            supervision_ms: 2000,
            encryption_change_v1: false,
            pairing_keys_delay_ms: 15,
        }
    }
}

/// Counters and marks for the script's checks and the summary.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Facts {
    pub commands: u32,
    pub hci_resets: u32,
    pub unknown_commands: Vec<u16>,
    pub connections: u32,
    pub encryptions: u32,
    pub encryptions_refused: u32,
    pub mic_failures: u32,
    pub host_disconnects: u32,
    pub kbd_disconnects: u32,
    pub acl_from_host: u32,
    pub att_requests: u32,
    /// When the last ATT request came (ms).
    pub last_att_ms: u64,
    pub smp_from_host: u32,
    pub key_reports_sent: u32,
    pub other_sent: u32,
    pub param_requests: u32,
    pub param_accepted: u32,
    pub param_rejected: u32,
    pub connection_updates: u32,
    /// Advertising reports sent to a scanning host.
    pub adv_reports: u32,
}

struct Link {
    encrypted: bool,
    /// The host's address type on this link: 0 public, 1 random.
    host_type: u8,
    interval: u16,
    latency: u16,
    timeout: u16,
}

struct Initiating {
    use_accept_list: bool,
    peer_type: u8,
    peer: [u8; 6],
    own_type: u8,
    interval: u16,
    latency: u16,
    timeout: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Timer {
    Connect,
    Encrypt { rand: [u8; 8], ediv: u16, ltk: [u8; 16] },
    ToHost { cid: u16, payload: Vec<u8> },
    ConnectionUpdated { interval: u16, latency: u16, timeout: u16 },
    ParamRequest,
    Idle,
    Battery,
    Pump,
    AdvReport,
    PairingKeys,
}

impl Timer {
    /// Ends with the link.
    fn of_link(&self) -> bool {
        !matches!(self, Self::Connect | Self::Pump | Self::AdvReport)
    }
}

/// A scan the host has running.
struct Scan {
    filter_duplicates: bool,
    /// Kinds of advertising already reported (bit: event type).
    reported: u8,
}

const ADV_IND: u8 = 0x00;
const ADV_DIRECT_IND: u8 = 0x01;
const SCAN_RSP: u8 = 0x04;
/// How long the keyboard advertises directed at its bonded host first.
const DIRECTED_MS: u64 = 1280;
const ADV_INTERVAL_MS: u64 = 100;
pub const KEYBOARD_NAME: &str = "Emulated Keyboard";

/// Something the keyboard wants to send.
struct Outgoing {
    cid: u16,
    payload: Vec<u8>,
    /// Pause after it.
    gap_ms: u64,
    /// Only on an encrypted link (all of the keyboard's own traffic; not
    /// what a test sends to play an attacker).
    secure: bool,
    key_report: bool,
}

pub struct Radio {
    pub cfg: Config,
    pub facts: Facts,
    /// HCI events for the host.
    pub events: VecDeque<Vec<u8>>,
    /// HCI ACL packets for the host.
    pub acl: VecDeque<Vec<u8>>,
    pub att: AttServer,
    /// The keyboard's side of pairing.
    pub smp: Smp,
    /// Pairings whose bond the keyboard has taken over.
    pairings_applied: u32,
    /// What LE Set Random Address last set.
    random_addr: [u8; 6],
    now: u64,
    timers: Vec<(u64, Timer)>,
    // The controller.
    event_mask: u64,
    event_mask_page_2: u64,
    le_event_mask: u64,
    accept_list: Vec<(u8, [u8; 6])>,
    initiating: Option<Initiating>,
    link: Option<Link>,
    rng: u64,
    scan: Option<Scan>,
    /// The last LE Set Scan Parameters asked for scan responses.
    scan_active: bool,
    // The keyboard.
    advertising: bool,
    advertising_since: u64,
    /// Its pairing button was pressed: discoverable, and open to a host
    /// it has no bond with.
    pairing_mode: bool,
    /// The keyboard still believes in a link the host dropped silently.
    advertise_not_before: u64,
    outbox: VecDeque<Outgoing>,
    next_send_at: u64,
    last_activity: u64,
    /// A host-to-keyboard L2CAP PDU still arriving: bytes wanted, bytes.
    reassembly: Option<(usize, Vec<u8>)>,
    signal_id: u8,
    battery: u8,
    /// The LED report as the host last wrote it.
    pub leds: Option<u8>,
    writes_seen: usize,
}

const DEFAULT_EVENT_MASK: u64 = 0x0000_1FFF_FFFF_FFFF;
const DEFAULT_LE_EVENT_MASK: u64 = 0x1F;
const EVENT_DISCONNECTION_COMPLETE: u64 = 1 << 4;
const EVENT_ENCRYPTION_CHANGE: u64 = 1 << 7;
const EVENT_LE_META: u64 = 1 << 61;
const EVENT_2_ENCRYPTION_CHANGE_V2: u64 = 1 << 25;
const LE_CONNECTION_COMPLETE: u8 = 0x01;
const LE_CONNECTION_UPDATE_COMPLETE: u8 = 0x03;
const LE_READ_REMOTE_FEATURES_COMPLETE: u8 = 0x04;
const LE_ENHANCED_CONNECTION_COMPLETE: u8 = 0x0A;

impl Radio {
    pub fn new(cfg: Config) -> Self {
        let att = AttServer::keyboard(cfg.bond.is_some());
        Self {
            cfg,
            facts: Facts::default(),
            events: VecDeque::new(),
            acl: VecDeque::new(),
            att,
            smp: Smp::new(Default::default()),
            pairings_applied: 0,
            random_addr: [0; 6],
            now: 0,
            timers: Vec::new(),
            event_mask: DEFAULT_EVENT_MASK,
            event_mask_page_2: 0,
            le_event_mask: DEFAULT_LE_EVENT_MASK,
            accept_list: Vec::new(),
            initiating: None,
            link: None,
            rng: 0x9E37_79B9_7F4A_7C15,
            scan: None,
            scan_active: false,
            advertising: false,
            advertising_since: 0,
            pairing_mode: false,
            advertise_not_before: 0,
            outbox: VecDeque::new(),
            next_send_at: 0,
            last_activity: 0,
            reassembly: None,
            signal_id: 0,
            battery: 57,
            leds: None,
            writes_seen: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.link.is_some()
    }

    pub fn is_encrypted(&self) -> bool {
        self.link.as_ref().is_some_and(|l| l.encrypted)
    }

    pub fn is_initiating(&self) -> bool {
        self.initiating.is_some()
    }

    pub fn is_advertising(&self) -> bool {
        self.advertising
    }

    pub fn is_scanning(&self) -> bool {
        self.scan.is_some()
    }

    /// Key reports and the like not sent yet.
    pub fn unsent(&self) -> usize {
        self.outbox.len()
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    /// When the next timer is due.
    pub fn next_deadline(&self) -> Option<u64> {
        self.timers.iter().map(|(at, _)| *at).min()
    }

    fn arm(&mut self, at: u64, timer: Timer) {
        self.timers.push((at, timer));
    }

    fn disarm(&mut self, which: impl Fn(&Timer) -> bool) {
        self.timers.retain(|(_, t)| !which(t));
    }

    /// Move the clock to `now`, running what comes due on the way, each
    /// at its own time.
    pub fn advance(&mut self, now: u64) {
        let target = self.now.max(now);
        loop {
            // The earliest due timer; among equals, the one armed first.
            let Some(index) = self.timers.iter().enumerate().filter(|(_, (at, _))| *at <= target).min_by_key(|(i, (at, _))| (*at, *i)).map(|(i, _)| i)
            else {
                break;
            };
            let (at, timer) = self.timers.remove(index);
            self.now = self.now.max(at);
            self.fire(timer);
        }
        self.now = target;
    }

    // ----- HCI: events ---------------------------------------------------

    fn event(&mut self, code: u8, params: &[u8]) {
        let mut ev = vec![code, params.len() as u8];
        ev.extend_from_slice(params);
        self.events.push_back(ev);
    }

    fn complete(&mut self, opcode: u16, ret: &[u8]) {
        let mut p = vec![1];
        p.extend_from_slice(&opcode.to_le_bytes());
        p.extend_from_slice(ret);
        self.event(0x0E, &p);
    }

    fn status(&mut self, opcode: u16, status: u8) {
        let [lo, hi] = opcode.to_le_bytes();
        self.event(0x0F, &[status, 1, lo, hi]);
    }

    fn le_event(&mut self, subevent: u8, params: &[u8]) {
        if self.event_mask & EVENT_LE_META == 0 || self.le_event_mask & (1 << (subevent - 1)) == 0 {
            note!("hci: LE event {subevent:#04x} not sent: the host has it masked");
            return;
        }
        let mut p = vec![subevent];
        p.extend_from_slice(params);
        self.event(0x3E, &p);
    }

    fn connection_complete(&mut self, status: u8, link: Option<&Link>) {
        let [h_lo, h_hi] = HANDLE.to_le_bytes();
        let (interval, latency, timeout) = link.map_or((0, 0, 0), |l| (l.interval, l.latency, l.timeout));
        let peer = if status == 0 { self.cfg.kbd_addr } else { [0; 6] };
        let peer_type = u8::from(status == 0 && self.cfg.kbd_random);
        // Status, handle, role (central), peer address type, peer address.
        let mut p = vec![status, if status == 0 { h_lo } else { 0 }, if status == 0 { h_hi } else { 0 }, 0, peer_type];
        p.extend_from_slice(&peer);
        let enhanced = self.le_event_mask & (1 << (LE_ENHANCED_CONNECTION_COMPLETE - 1)) != 0;
        if enhanced {
            p.extend_from_slice(&[0; 12]); // local and peer resolvable addresses: none
        }
        for v in [interval, latency, timeout] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.push(0); // central clock accuracy
        self.le_event(if enhanced { LE_ENHANCED_CONNECTION_COMPLETE } else { LE_CONNECTION_COMPLETE }, &p);
    }

    fn encryption_change(&mut self, status: u8, on: bool) {
        let [lo, hi] = HANDLE.to_le_bytes();
        if self.event_mask_page_2 & EVENT_2_ENCRYPTION_CHANGE_V2 != 0 && !self.cfg.encryption_change_v1 {
            self.event(0x59, &[status, lo, hi, u8::from(on), if on { 16 } else { 0 }]);
        } else if self.event_mask & EVENT_ENCRYPTION_CHANGE != 0 {
            self.event(0x08, &[status, lo, hi, u8::from(on)]);
        } else {
            note!("hci: Encryption Change not sent: the host has it masked");
        }
    }

    fn disconnection_complete(&mut self, reason: u8) {
        let [lo, hi] = HANDLE.to_le_bytes();
        if self.event_mask & EVENT_DISCONNECTION_COMPLETE != 0 {
            self.event(0x05, &[0, lo, hi, reason]);
        }
    }

    fn random(&mut self) -> u64 {
        // xorshift64*: fixed seed, so runs repeat.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    // ----- HCI: commands -------------------------------------------------

    /// The Bluetooth function was switched off, or the chip reset.
    pub fn power_off(&mut self) {
        self.reset_controller();
    }

    fn reset_controller(&mut self) {
        if self.link.is_some() {
            // The host says nothing to the keyboard: it finds out when its
            // supervision timeout runs out.
            note!("link: dropped by the host without a word; the keyboard notices in {} ms", self.cfg.supervision_ms);
            self.drop_link();
            self.advertise_not_before = self.now + self.cfg.supervision_ms;
        }
        self.event_mask = DEFAULT_EVENT_MASK;
        self.event_mask_page_2 = 0;
        self.le_event_mask = DEFAULT_LE_EVENT_MASK;
        self.accept_list.clear();
        self.initiating = None;
        self.scan = None;
        self.scan_active = false;
        self.disarm(|t| matches!(t, Timer::Connect | Timer::AdvReport));
        self.events.clear();
        self.acl.clear();
        self.pump();
    }

    /// One HCI command packet from the host.
    pub fn command(&mut self, cmd: &[u8]) {
        if cmd.len() < 3 || cmd.len() != 3 + usize::from(cmd[2]) {
            note!("hci: malformed command packet of {} bytes", cmd.len());
            return;
        }
        let opcode = u16::from_le_bytes([cmd[0], cmd[1]]);
        let p = &cmd[3..];
        self.facts.commands += 1;
        let u16_at = |at: usize| u16::from_le_bytes([p[at], p[at + 1]]);
        let handle_ok = |at: usize, radio: &Self| p.len() >= at + 2 && u16_at(at) & 0x0FFF == HANDLE && radio.link.is_some();
        let [h_lo, h_hi] = HANDLE.to_le_bytes();
        match (opcode, p.len()) {
            // Disconnect: handle, reason.
            (0x0406, 3) => {
                if !handle_ok(0, self) {
                    return self.status(opcode, ERR_UNKNOWN_CONNECTION);
                }
                self.status(opcode, 0);
                note!("link: the host disconnects (reason {:#04x})", p[2]);
                self.facts.host_disconnects += 1;
                self.drop_link();
                self.disconnection_complete(REASON_LOCAL_HOST);
                // The keyboard was told, so it can come back at once.
                self.advertise_not_before = self.now + 20;
                self.pump();
            }
            // Read Remote Version Information.
            (0x041D, 2) => {
                if !handle_ok(0, self) {
                    return self.status(opcode, ERR_UNKNOWN_CONNECTION);
                }
                self.status(opcode, 0);
                self.event(0x0C, &[0, h_lo, h_hi, 0x09, 0x06, 0x00, 0x01, 0x00]);
            }
            (0x0C01, 8) => {
                self.event_mask = u64::from_le_bytes(p.try_into().unwrap());
                self.complete(opcode, &[0]);
            }
            (0x0C03, 0) => {
                self.facts.hci_resets += 1;
                note!("hci: Reset");
                self.reset_controller();
                self.complete(opcode, &[0]);
            }
            // Read Local Name.
            (0x0C14, 0) => {
                let mut ret = vec![0u8; 249];
                ret[1..7].copy_from_slice(b"bt-emu");
                self.complete(opcode, &ret);
            }
            // Flow control towards the host, host buffers, LE host support.
            (0x0C31, 1) | (0x0C33, 7) | (0x0C6D, 2) => self.complete(opcode, &[0]),
            // Host Number Of Completed Packets: no answer.
            (0x0C35, _) => {}
            (0x0C63, 8) => {
                self.event_mask_page_2 = u64::from_le_bytes(p.try_into().unwrap());
                self.complete(opcode, &[0]);
            }
            // Read Local Version Information: Bluetooth 5.3, MediaTek.
            (0x1001, 0) => self.complete(opcode, &[0, 0x0C, 0x00, 0x00, 0x0C, 0x46, 0x00, 0x22, 0x79]),
            (0x1002, 0) => {
                let mut ret = vec![0xFF; 65];
                ret[0] = 0;
                self.complete(opcode, &ret);
            }
            // Read Local Supported Features: LE, no BR/EDR.
            (0x1003, 0) => self.complete(opcode, &[0, 0, 0, 0, 0, 0x60, 0, 0, 0]),
            (0x1005, 0) => self.complete(opcode, &[0, 0xFD, 0x03, 0, 8, 0, 0, 0]),
            (0x1009, 0) => {
                let mut ret = vec![0];
                ret.extend_from_slice(&self.cfg.bd_addr);
                self.complete(opcode, &ret);
            }
            (0x2001, 8) => {
                self.le_event_mask = u64::from_le_bytes(p.try_into().unwrap());
                self.complete(opcode, &[0]);
            }
            (0x2002, 0) => {
                let [lo, hi] = LE_ACL_LENGTH.to_le_bytes();
                self.complete(opcode, &[0, lo, hi, LE_ACL_PACKETS]);
            }
            // LE Read Local Supported Features: LE Encryption.
            (0x2003, 0) => self.complete(opcode, &[0, 0x01, 0, 0, 0, 0, 0, 0, 0]),
            // LE Set Random Address.
            (0x2005, 6) => {
                self.random_addr.copy_from_slice(p);
                self.complete(opcode, &[0]);
            }
            // LE Set Scan Parameters: type (1: active), interval, window,
            // own address type, filter policy.
            (0x200B, 7) => {
                if self.scan.is_some() {
                    return self.complete(opcode, &[ERR_COMMAND_DISALLOWED]);
                }
                self.scan_active = p[0] == 1;
                self.complete(opcode, &[0]);
            }
            // LE Set Scan Enable: enable, filter duplicates.
            (0x200C, 2) => {
                self.disarm(|t| *t == Timer::AdvReport);
                self.scan = (p[0] != 0).then_some(Scan { filter_duplicates: p[1] != 0, reported: 0 });
                self.complete(opcode, &[0]);
                if self.scan.is_some() {
                    self.arm(self.now + 20, Timer::AdvReport);
                }
            }
            // LE Create Connection.
            (0x200D, 25) => {
                if self.link.is_some() || self.initiating.is_some() {
                    return self.status(opcode, ERR_COMMAND_DISALLOWED);
                }
                let mut peer = [0u8; 6];
                peer.copy_from_slice(&p[6..12]);
                self.initiating = Some(Initiating {
                    use_accept_list: p[4] == 1,
                    peer_type: p[5],
                    peer,
                    own_type: p[12] & 1,
                    interval: u16_at(13),
                    latency: u16_at(17),
                    timeout: u16_at(19),
                });
                self.status(opcode, 0);
                self.maybe_connect();
            }
            // LE Create Connection Cancel.
            (0x200E, 0) => {
                if self.initiating.take().is_some() {
                    self.disarm(|t| *t == Timer::Connect);
                    self.complete(opcode, &[0]);
                    self.connection_complete(ERR_UNKNOWN_CONNECTION, None);
                } else {
                    self.complete(opcode, &[ERR_COMMAND_DISALLOWED]);
                }
            }
            (0x200F, 0) => self.complete(opcode, &[0, 8]),
            (0x2010, 0) => {
                self.accept_list.clear();
                self.complete(opcode, &[0]);
            }
            (0x2011, 7) | (0x2012, 7) => {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&p[1..7]);
                self.accept_list.retain(|e| *e != (p[0], addr));
                if opcode == 0x2011 {
                    self.accept_list.push((p[0], addr));
                }
                self.complete(opcode, &[0]);
                self.maybe_connect();
            }
            // LE Connection Update: handle, interval min and max, latency,
            // timeout, connection event lengths.
            (0x2013, 14) => {
                if !handle_ok(0, self) {
                    return self.status(opcode, ERR_UNKNOWN_CONNECTION);
                }
                self.status(opcode, 0);
                let update = Timer::ConnectionUpdated { interval: u16_at(2), latency: u16_at(6), timeout: u16_at(8) };
                self.arm(self.now + 30, update);
            }
            // LE Read Remote Features.
            (0x2016, 2) => {
                if !handle_ok(0, self) {
                    return self.status(opcode, ERR_UNKNOWN_CONNECTION);
                }
                self.status(opcode, 0);
                self.le_event(LE_READ_REMOTE_FEATURES_COMPLETE, &[0, h_lo, h_hi, 0x01, 0, 0, 0, 0, 0, 0, 0]);
            }
            // LE Rand.
            (0x2018, 0) => {
                let mut ret = vec![0];
                ret.extend_from_slice(&self.random().to_le_bytes());
                self.complete(opcode, &ret);
            }
            // LE Enable Encryption: handle, Rand, EDIV, key.
            (0x2019, 28) => {
                if !handle_ok(0, self) {
                    return self.status(opcode, ERR_UNKNOWN_CONNECTION);
                }
                self.status(opcode, 0);
                let (mut rand, mut ltk) = ([0u8; 8], [0u8; 16]);
                rand.copy_from_slice(&p[2..10]);
                ltk.copy_from_slice(&p[12..28]);
                self.disarm(|t| matches!(t, Timer::Encrypt { .. }));
                self.arm(self.now + self.cfg.encrypt_delay_ms, Timer::Encrypt { rand, ediv: u16_at(10), ltk });
            }
            // The Long Term Key replies are for the peripheral role only.
            (0x201A, 18) | (0x201B, 2) => self.complete(opcode, &[ERR_COMMAND_DISALLOWED, p[0], p[1]]),
            (0x201C, 0) => self.complete(opcode, &[0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0, 0]),
            // Remote Connection Parameter Request replies, Set Data Length.
            (0x2020, 14) | (0x2021, 3) | (0x2022, 6) => self.complete(opcode, &[0, p[0], p[1]]),
            (0x2023, 0) => self.complete(opcode, &[0, 27, 0, 0x48, 0x01]),
            // Suggested data length, resolving list, address resolution,
            // resolvable address timeout, default PHY.
            (0x2024, 4) | (0x2027, 39) | (0x2028, 7) | (0x2029, 0) | (0x202D, 1) | (0x202E, 2) | (0x2031, 3) => self.complete(opcode, &[0]),
            (0x202A, 0) => self.complete(opcode, &[0, 8]),
            // LE Read PHY: 1M both ways.
            (0x2030, 2) => self.complete(opcode, &[0, p[0], p[1], 1, 1]),
            (known, _) if matches!(known, 0x0406 | 0x0C01 | 0x0C03 | 0x0C63 | 0x2001 | 0x200D | 0x2011 | 0x2013 | 0x2019) => {
                note!("hci: command {known:#06x} with {} parameter bytes: invalid", p.len());
                self.complete(opcode, &[ERR_INVALID_PARAMETERS]);
            }
            _ => {
                note!("hci: command {opcode:#06x} ({} parameter bytes) isn't emulated: unknown command", p.len());
                self.facts.unknown_commands.push(opcode);
                self.complete(opcode, &[ERR_UNKNOWN_COMMAND]);
            }
        }
    }

    // ----- The link ------------------------------------------------------

    fn kbd_address_type(&self) -> u8 {
        u8::from(self.cfg.kbd_random)
    }

    /// The host is initiating to the keyboard, and the keyboard advertises:
    /// the connection comes up shortly.
    fn maybe_connect(&mut self) {
        if !self.advertising || self.link.is_some() || self.timers.iter().any(|(_, t)| *t == Timer::Connect) {
            return;
        }
        let kbd = (self.kbd_address_type(), self.cfg.kbd_addr);
        let wanted = match &self.initiating {
            Some(i) if i.use_accept_list => self.accept_list.contains(&kbd),
            Some(i) => (i.peer_type, i.peer) == kbd,
            None => false,
        };
        if wanted {
            let at = (self.now + self.cfg.connect_delay_ms).max(self.advertise_not_before);
            self.arm(at, Timer::Connect);
        }
    }

    fn start_advertising(&mut self) {
        if self.link.is_some() || self.advertising {
            return;
        }
        self.advertising = true;
        self.advertising_since = self.now;
        note!("kbd: woken, advertising{}", if self.pairing_mode { " (pairing mode: discoverable)" } else { "" });
        self.maybe_connect();
    }

    /// What a scanning host hears from the keyboard right now: the kind of
    /// advertising and its data.
    fn advertisement(&self) -> (u8, Vec<u8>) {
        let directed = self.cfg.bond.is_some() && !self.pairing_mode && self.now.saturating_sub(self.advertising_since) < DIRECTED_MS;
        if directed {
            return (ADV_DIRECT_IND, Vec::new());
        }
        // Flags (limited discoverable in pairing mode; never BR/EDR),
        // appearance: keyboard, 16-bit services: HID.
        let flags = if self.pairing_mode { 0x05 } else { 0x04 };
        (ADV_IND, vec![2, 0x01, flags, 3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18])
    }

    fn adv_report(&mut self, kind: u8, data: &[u8]) {
        // One report: kind, address type, address, data, RSSI.
        let mut p = vec![1, kind, self.kbd_address_type()];
        p.extend_from_slice(&self.cfg.kbd_addr);
        p.push(data.len() as u8);
        p.extend_from_slice(data);
        p.push(0xC9); // -55 dBm
        self.facts.adv_reports += 1;
        self.le_event(0x02, &p);
    }

    /// The keyboard's pairing button: it becomes discoverable and takes a
    /// connection from any host.
    pub fn enter_pairing_mode(&mut self) {
        note!("kbd: pairing button pressed{}", if self.cfg.bond.is_some() { ": the old bond is forgotten" } else { "" });
        self.set_bond(None);
        self.pairing_mode = true;
        self.advertising = false;
        self.start_advertising();
    }

    pub fn in_pairing_mode(&self) -> bool {
        self.pairing_mode
    }

    /// The two addresses of the link, as pairing uses them.
    fn ends(&self) -> Ends {
        let host_type = self.link.as_ref().map_or(0, |l| l.host_type);
        Ends {
            host_type,
            host: if host_type == 0 { self.cfg.bd_addr } else { self.random_addr },
            kbd_type: self.kbd_address_type(),
            kbd: self.cfg.kbd_addr,
        }
    }

    /// Send what the pairing has for the host, and take over the bond of
    /// one that has just completed. The new host's notifications stay off
    /// until it switches them on.
    fn after_smp(&mut self) {
        for pdu in core::mem::take(&mut self.smp.out) {
            self.to_host(CID_SMP, &pdu);
        }
        if self.smp.completed > self.pairings_applied {
            self.pairings_applied = self.smp.completed;
            if let Some(bond) = self.smp.take_bond() {
                self.cfg.bond = Some(bond);
            }
            self.pairing_mode = false;
            self.last_activity = self.now;
        }
    }

    /// The user types the passkey the host shows, and Enter.
    pub fn type_passkey(&mut self, passkey: u32) {
        let ends = self.ends();
        self.smp.enter_passkey(passkey, &ends);
        self.after_smp();
        self.last_activity = self.now;
    }

    fn drop_link(&mut self) {
        self.link = None;
        self.smp.reset();
        self.reassembly = None;
        self.disarm(Timer::of_link);
        // Pairing mode lasts until a host has paired: the keyboard is
        // discoverable again.
        if self.pairing_mode {
            self.start_advertising();
        }
    }

    /// The keyboard ends the link.
    pub fn kbd_disconnect(&mut self, reason: u8) {
        if self.link.is_none() {
            return;
        }
        note!("link: the keyboard disconnects (reason {reason:#04x})");
        self.facts.kbd_disconnects += 1;
        self.drop_link();
        self.disconnection_complete(reason);
        self.pump();
    }

    fn fire(&mut self, timer: Timer) {
        match timer {
            Timer::Connect => {
                if !self.advertising || self.link.is_some() {
                    return;
                }
                let Some(i) = self.initiating.take() else { return };
                self.advertising = false;
                let link = Link { encrypted: false, host_type: i.own_type, interval: i.interval, latency: i.latency, timeout: i.timeout };
                note!("link: connected (handle {HANDLE:#06x}, interval {} x 1.25 ms)", link.interval);
                self.facts.connections += 1;
                self.connection_complete(0, Some(&link));
                self.link = Some(link);
                self.last_activity = self.now;
                if let Some(after) = self.cfg.param_request_after_ms {
                    self.arm(self.now + after, Timer::ParamRequest);
                }
                if let Some(idle) = self.cfg.idle_disconnect_ms {
                    self.arm(self.now + idle, Timer::Idle);
                }
                self.pump();
            }
            Timer::Encrypt { rand, ediv, ltk } => {
                if self.link.is_none() {
                    return;
                }
                // A pairing has just agreed on a key: the host starts
                // encryption with it, and with EDIV and Rand zero.
                if let Some(key) = self.smp.link_key() {
                    if ediv == 0 && rand == [0; 8] && ltk == key {
                        note!("link: encrypted with the key of the pairing");
                        self.facts.encryptions += 1;
                        self.link.as_mut().unwrap().encrypted = true;
                        self.encryption_change(0, true);
                        if self.cfg.pairing_keys_delay_ms == 0 {
                            self.fire(Timer::PairingKeys);
                        } else {
                            self.arm(self.now + self.cfg.pairing_keys_delay_ms, Timer::PairingKeys);
                        }
                    } else {
                        note!("link: the host's key isn't the one the pairing agreed on: MIC failure, link lost");
                        self.facts.mic_failures += 1;
                        self.drop_link();
                        self.disconnection_complete(REASON_MIC_FAILURE);
                    }
                    self.pump();
                    return;
                }
                match self.cfg.bond {
                    Some(b) if b.ediv == ediv && b.rand == rand && b.ltk == ltk => {
                        note!("link: encrypted with the bonded key");
                        self.facts.encryptions += 1;
                        self.link.as_mut().unwrap().encrypted = true;
                        self.encryption_change(0, true);
                        self.next_send_at = self.now + self.cfg.first_report_delay_ms;
                        if let Some(after) = self.cfg.battery_after_ms {
                            self.disarm(|t| *t == Timer::Battery);
                            self.arm(self.now + after, Timer::Battery);
                        }
                        self.pump();
                    }
                    Some(b) if b.ediv == ediv && b.rand == rand => {
                        // Both sides derive session keys from different
                        // long-term keys: the first encrypted packet fails
                        // its integrity check, and the link is gone.
                        note!("link: the host's key differs from the keyboard's: MIC failure, link lost");
                        self.facts.mic_failures += 1;
                        self.drop_link();
                        self.disconnection_complete(REASON_MIC_FAILURE);
                        self.pump();
                    }
                    _ => {
                        note!("link: the keyboard has no key for EDIV {ediv:#06x}: PIN or key missing");
                        self.facts.encryptions_refused += 1;
                        self.encryption_change(ERR_PIN_OR_KEY_MISSING, false);
                    }
                }
            }
            Timer::ToHost { cid, payload } => self.to_host(cid, &payload),
            Timer::ConnectionUpdated { interval, latency, timeout } => {
                let Some(link) = self.link.as_mut() else { return };
                (link.interval, link.latency, link.timeout) = (interval, latency, timeout);
                self.facts.connection_updates += 1;
                let [lo, hi] = HANDLE.to_le_bytes();
                let mut p = vec![0, lo, hi];
                for v in [interval, latency, timeout] {
                    p.extend_from_slice(&v.to_le_bytes());
                }
                self.le_event(LE_CONNECTION_UPDATE_COMPLETE, &p);
            }
            Timer::ParamRequest => self.request_params(20, 36, 4, 200),
            Timer::Idle => {
                let Some(idle) = self.cfg.idle_disconnect_ms else { return };
                if self.link.is_none() {
                    return;
                }
                let due = self.last_activity + idle;
                if self.now >= due {
                    note!("kbd: no key for {idle} ms: going to sleep");
                    self.kbd_disconnect(REASON_REMOTE_USER);
                } else {
                    self.arm(due, Timer::Idle);
                }
            }
            Timer::Battery => {
                if self.is_encrypted() && self.att.notifying(gatt::H_BATTERY_CCCD) {
                    let level = self.battery;
                    self.notify(gatt::H_BATTERY, &[level]);
                    self.facts.other_sent += 1;
                }
            }
            Timer::Pump => self.pump(),
            Timer::PairingKeys => {
                let ends = self.ends();
                self.smp.encrypted(&ends);
                self.after_smp();
            }
            Timer::AdvReport => {
                if self.scan.is_none() {
                    return;
                }
                if self.advertising {
                    let (kind, data) = self.advertisement();
                    let mut kinds = vec![(kind, data)];
                    if kind == ADV_IND && self.scan_active {
                        // The answer to the host's scan request: the name.
                        let mut name = vec![KEYBOARD_NAME.len() as u8 + 1, 0x09];
                        name.extend_from_slice(KEYBOARD_NAME.as_bytes());
                        kinds.push((SCAN_RSP, name));
                    }
                    for (kind, data) in kinds {
                        let scan = self.scan.as_mut().unwrap();
                        if scan.filter_duplicates && scan.reported & (1 << kind) != 0 {
                            continue;
                        }
                        scan.reported |= 1 << kind;
                        self.adv_report(kind, &data);
                    }
                }
                self.arm(self.now + ADV_INTERVAL_MS, Timer::AdvReport);
            }
        }
    }

    // ----- L2CAP ---------------------------------------------------------

    /// One L2CAP PDU from the keyboard to the host, in ACL packets.
    fn to_host(&mut self, cid: u16, payload: &[u8]) {
        if self.link.is_none() {
            return;
        }
        let mut pdu = Vec::with_capacity(4 + payload.len());
        pdu.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        pdu.extend_from_slice(&cid.to_le_bytes());
        pdu.extend_from_slice(payload);
        for (i, chunk) in pdu.chunks(usize::from(LE_ACL_LENGTH)).enumerate() {
            // Packet boundary: 0b10 starts a PDU, 0b01 continues it.
            let flags: u16 = if i == 0 { 0x2000 } else { 0x1000 };
            let mut packet = (HANDLE | flags).to_le_bytes().to_vec();
            packet.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            packet.extend_from_slice(chunk);
            self.acl.push_back(packet);
        }
    }

    fn notify(&mut self, handle: u16, value: &[u8]) {
        let mut pdu = vec![0x1B];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);
        self.to_host(CID_ATT, &pdu);
    }

    /// One HCI ACL packet from the host.
    pub fn acl_from_host(&mut self, packet: &[u8]) {
        let Some((&[a, b, c, d], data)) = packet.split_first_chunk::<4>() else {
            note!("acl: packet of {} bytes from the host", packet.len());
            return;
        };
        let raw = u16::from_le_bytes([a, b]);
        if self.link.is_none() || raw & 0x0FFF != HANDLE || data.len() != usize::from(u16::from_le_bytes([c, d])) {
            note!("acl: packet for handle {:#06x} dropped (no such link, or a bad length)", raw & 0x0FFF);
            return;
        }
        self.facts.acl_from_host += 1;
        // The controller has room again at once.
        let [lo, hi] = HANDLE.to_le_bytes();
        self.event(0x13, &[1, lo, hi, 1, 0]);
        let continues = (raw >> 12) & 0b11 == 0b01;
        if continues {
            let Some((wanted, mut bytes)) = self.reassembly.take() else {
                note!("acl: a continuation without a start: dropped");
                return;
            };
            bytes.extend_from_slice(data);
            if bytes.len() < wanted {
                self.reassembly = Some((wanted, bytes));
                return;
            }
            return self.l2cap_from_host(&bytes);
        }
        if data.len() < 4 {
            note!("acl: a start fragment of {} bytes: dropped", data.len());
            return;
        }
        let wanted = 4 + usize::from(u16::from_le_bytes([data[0], data[1]]));
        if data.len() < wanted {
            self.reassembly = Some((wanted, data.to_vec()));
            return;
        }
        self.l2cap_from_host(data);
    }

    fn l2cap_from_host(&mut self, pdu: &[u8]) {
        let (cid, payload) = (u16::from_le_bytes([pdu[2], pdu[3]]), &pdu[4..]);
        match cid {
            CID_ATT => {
                let encrypted = self.is_encrypted();
                self.facts.att_requests += 1;
                self.facts.last_att_ms = self.now;
                let response = self.att.request(payload, encrypted);
                for write in self.att.writes[self.writes_seen..].to_vec() {
                    match write.handle {
                        gatt::H_LEDS => {
                            self.leds = write.value.first().copied();
                            note!("kbd: LEDs written: {:#04x}", self.leds.unwrap_or(0));
                        }
                        h if self.att.find(h).is_some_and(|a| a.kind == gatt::UUID_CCCD) => {
                            note!("kbd: notification switch {h:#06x} written: {:02x?}", write.value);
                        }
                        h => note!("kbd: attribute {h:#06x} written: {:02x?}", write.value),
                    }
                }
                self.writes_seen = self.att.writes.len();
                if let Some(response) = response {
                    // "Attribute not found" ends every search; anything
                    // else is worth a line.
                    if response.first() == Some(&0x01) && response[4] != gatt::ERR_NOT_FOUND {
                        note!("att: request {:#04x} refused: error {:#04x}", payload.first().copied().unwrap_or(0), response[4]);
                    }
                    if self.cfg.att_delay_ms == 0 {
                        self.to_host(CID_ATT, &response);
                    } else {
                        self.arm(self.now + self.cfg.att_delay_ms, Timer::ToHost { cid: CID_ATT, payload: response });
                    }
                }
            }
            CID_SIGNALING => match (payload.first().copied(), payload.get(1).copied()) {
                // Connection Parameter Update Response.
                (Some(0x13), Some(_)) => {
                    let accepted = payload.get(4..6) == Some(&[0, 0]);
                    note!("kbd: connection parameter request {}", if accepted { "accepted" } else { "rejected" });
                    if accepted {
                        self.facts.param_accepted += 1;
                    } else {
                        self.facts.param_rejected += 1;
                    }
                }
                (Some(code), Some(id)) => {
                    note!("l2cap: signaling code {code:#04x} from the host: command rejected");
                    self.to_host(CID_SIGNALING, &[0x01, id, 2, 0, 0, 0]);
                }
                _ => {}
            },
            CID_SMP => {
                self.facts.smp_from_host += 1;
                note!("smp: the host sent code {:#04x} ({} bytes)", payload.first().copied().unwrap_or(0), payload.len());
                let ends = self.ends();
                self.smp.from_host(payload, self.pairing_mode, &ends);
                self.after_smp();
            }
            other => note!("l2cap: {} bytes on channel {other:#06x} from the host: ignored", payload.len()),
        }
    }

    // ----- The keyboard, as its user and the tests drive it ----------------

    /// Send what is waiting, as far as the link allows; wake the keyboard
    /// if there is something to send and no link.
    fn pump(&mut self) {
        self.disarm(|t| *t == Timer::Pump);
        while let Some(secure) = self.outbox.front().map(|o| o.secure) {
            let Some(encrypted) = self.link.as_ref().map(|l| l.encrypted) else {
                self.start_advertising();
                return;
            };
            if secure && !encrypted {
                return; // kept until the link is encrypted
            }
            if self.now < self.next_send_at {
                self.arm(self.next_send_at, Timer::Pump);
                return;
            }
            let item = self.outbox.pop_front().unwrap();
            self.to_host(item.cid, &item.payload);
            if item.key_report {
                self.facts.key_reports_sent += 1;
                self.last_activity = self.now;
            } else {
                self.facts.other_sent += 1;
            }
            self.next_send_at = self.now + item.gap_ms;
        }
    }

    /// Nothing is sent for this long after what is queued now (the user
    /// stops typing for a moment).
    pub fn pause(&mut self, ms: u64) {
        match self.outbox.back_mut() {
            Some(last) => last.gap_ms += ms,
            None => self.next_send_at = self.next_send_at.max(self.now) + ms,
        }
    }

    /// What the keyboard remembers of this host changes: `None` as after
    /// the keyboard was reset or paired with another computer (its
    /// notification switches go back to off with the bond).
    pub fn set_bond(&mut self, bond: Option<Bond>) {
        if self.cfg.bond.is_some() != bond.is_some() {
            self.att = AttServer::keyboard(bond.is_some());
            self.writes_seen = 0;
        }
        self.cfg.bond = bond;
    }

    /// A key that sends nothing by itself was pressed (Fn, say): the
    /// keyboard wakes up.
    pub fn wake(&mut self) {
        self.last_activity = self.now;
        self.start_advertising();
    }

    /// The keyboard report with these modifiers and keys held (up to ten).
    pub fn key_report(&mut self, modifiers: u8, keys: &[u8], gap_ms: Option<u64>) {
        let mut value = [0u8; 11];
        value[0] = modifiers;
        for (slot, key) in value[1..].iter_mut().zip(keys) {
            *slot = *key;
        }
        let mut payload = vec![0x1B];
        payload.extend_from_slice(&gatt::H_KEYS.to_le_bytes());
        payload.extend_from_slice(&value);
        let gap_ms = gap_ms.unwrap_or(self.cfg.key_interval_ms);
        self.outbox.push_back(Outgoing { cid: CID_ATT, payload, gap_ms, secure: true, key_report: true });
        self.last_activity = self.now;
        self.pump();
    }

    /// A key pressed and released.
    pub fn tap(&mut self, modifiers: u8, key: u8) {
        self.key_report(modifiers, &[key], None);
        self.key_report(0, &[], None);
    }

    /// A media key (consumer usage) pressed and released: what the F-row
    /// sends with the keyboard's Fn lock on.
    pub fn media_key(&mut self, usage: u16) {
        for value in [usage, 0] {
            let mut payload = vec![0x1B];
            payload.extend_from_slice(&gatt::H_CONSUMER.to_le_bytes());
            payload.extend_from_slice(&value.to_le_bytes());
            self.outbox.push_back(Outgoing { cid: CID_ATT, payload, gap_ms: self.cfg.key_interval_ms, secure: true, key_report: false });
        }
        self.last_activity = self.now;
        self.pump();
    }

    pub fn set_battery(&mut self, percent: u8) {
        self.battery = percent;
        if self.is_encrypted() && self.att.notifying(gatt::H_BATTERY_CCCD) {
            self.notify(gatt::H_BATTERY, &[percent]);
        }
    }

    /// The keyboard asks for new connection parameters over L2CAP
    /// signaling (interval in 1.25 ms, timeout in 10 ms).
    pub fn request_params(&mut self, min: u16, max: u16, latency: u16, timeout: u16) {
        if self.link.is_none() {
            return;
        }
        self.signal_id = self.signal_id.wrapping_add(1).max(1);
        let mut pdu = vec![0x12, self.signal_id, 8, 0];
        for v in [min, max, latency, timeout] {
            pdu.extend_from_slice(&v.to_le_bytes());
        }
        note!("kbd: asks for new connection parameters (interval {min}-{max} x 1.25 ms, latency {latency})");
        self.facts.param_requests += 1;
        self.to_host(CID_SIGNALING, &pdu);
    }

    /// Any L2CAP PDU from the keyboard's side, for tests that play a
    /// device that misbehaves. `secure`: wait for encryption like the
    /// keyboard's own traffic; otherwise sent as soon as there is a link.
    pub fn raw_to_host(&mut self, cid: u16, payload: Vec<u8>, secure: bool) {
        self.outbox.push_back(Outgoing { cid, payload, gap_ms: self.cfg.key_interval_ms, secure, key_report: false });
        self.pump();
    }

    /// A key report sent whether or not the link is encrypted: what an
    /// attacker in radio range could do on an unencrypted link.
    pub fn key_report_unprotected(&mut self, modifiers: u8, keys: &[u8]) {
        let mut value = [0u8; 11];
        value[0] = modifiers;
        for (slot, key) in value[1..].iter_mut().zip(keys) {
            *slot = *key;
        }
        let mut payload = vec![0x1B];
        payload.extend_from_slice(&gatt::H_KEYS.to_le_bytes());
        payload.extend_from_slice(&value);
        self.raw_to_host(CID_ATT, payload, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOND: Bond = Bond { ediv: 0x1234, rand: [1, 2, 3, 4, 5, 6, 7, 8], ltk: [0x7E; 16] };

    fn radio() -> Radio {
        Radio::new(Config { bond: Some(BOND), ..Config::default() })
    }

    fn cmd(opcode: u16, params: &[u8]) -> Vec<u8> {
        let mut c = opcode.to_le_bytes().to_vec();
        c.push(params.len() as u8);
        c.extend_from_slice(params);
        c
    }

    /// The host stack's start: reset, masks as TrouBLE sets them.
    fn init(r: &mut Radio) {
        r.command(&cmd(0x0C03, &[]));
        // LE meta, disconnection complete, encryption change.
        r.command(&cmd(0x0C01, &(EVENT_LE_META | EVENT_DISCONNECTION_COMPLETE | EVENT_ENCRYPTION_CHANGE).to_le_bytes()));
        r.command(&cmd(0x0C63, &EVENT_2_ENCRYPTION_CHANGE_V2.to_le_bytes()));
        // Connection complete, enhanced connection complete, update complete.
        r.command(&cmd(0x2001, &0x0000_0000_0000_0205u64.to_le_bytes()));
        r.events.clear();
    }

    fn create_connection(r: &mut Radio) {
        let mut add = vec![1];
        add.extend_from_slice(&r.cfg.kbd_addr.clone());
        r.command(&cmd(0x2010, &[]));
        r.command(&cmd(0x2011, &add));
        let mut p = vec![0x60, 0x00, 0x30, 0x00, 1, 0];
        p.extend_from_slice(&[0; 6]);
        p.push(0);
        for v in [12u16, 24, 0, 400, 0, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        r.command(&cmd(0x200D, &p));
    }

    fn enable_encryption(r: &mut Radio, bond: &Bond) {
        let mut p = HANDLE.to_le_bytes().to_vec();
        p.extend_from_slice(&bond.rand);
        p.extend_from_slice(&bond.ediv.to_le_bytes());
        p.extend_from_slice(&bond.ltk);
        r.command(&cmd(0x2019, &p));
    }

    /// Connected and encrypted, events and data cleared.
    fn session() -> Radio {
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        enable_encryption(&mut r, &BOND);
        r.advance(200);
        assert!(r.is_encrypted());
        r.events.clear();
        r.acl.clear();
        r
    }

    fn att(r: &mut Radio, pdu: &[u8]) {
        let mut packet = HANDLE.to_le_bytes().to_vec();
        packet.extend_from_slice(&(pdu.len() as u16 + 4).to_le_bytes());
        packet.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        packet.extend_from_slice(&CID_ATT.to_le_bytes());
        packet.extend_from_slice(pdu);
        r.acl_from_host(&packet);
    }

    /// The ATT payloads of the ACL packets waiting for the host.
    fn att_out(r: &mut Radio) -> Vec<Vec<u8>> {
        r.acl.drain(..).filter(|p| p[6..8] == CID_ATT.to_le_bytes()).map(|p| p[8..].to_vec()).collect()
    }

    #[test]
    fn bring_up_commands() {
        let mut r = radio();
        r.command(&cmd(0x0C03, &[]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 4, 1, 0x03, 0x0C, 0]));
        r.command(&cmd(0x1009, &[]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 10, 1, 0x09, 0x10, 0, 0x02, 0, 0, 0, 0, 0x02]));
        r.command(&cmd(0x2002, &[]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 7, 1, 0x02, 0x20, 0, 251, 0, 32]));
        // No link yet: a disconnect of the usual handle says so.
        r.command(&cmd(0x0406, &[0x00, 0x02, 0x15]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0F, 4, ERR_UNKNOWN_CONNECTION, 1, 0x06, 0x04]));
        // Something this controller doesn't have.
        r.command(&cmd(0x2041, &[0; 8]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 4, 1, 0x41, 0x20, ERR_UNKNOWN_COMMAND]));
        assert_eq!(r.facts.unknown_commands, vec![0x2041]);
    }

    #[test]
    fn the_keyboard_connects_once_woken_and_wanted() {
        let mut r = radio();
        init(&mut r);
        // Woken, but the host isn't initiating: nothing.
        r.wake();
        r.advance(500);
        assert!(!r.is_connected());
        create_connection(&mut r);
        assert_eq!(r.events.back().unwrap()[..3], [0x0F, 4, 0]);
        r.events.clear();
        r.advance(520);
        assert!(!r.is_connected());
        r.advance(530);
        assert!(r.is_connected());
        // LE Enhanced Connection Complete, as the mask has it: status 0,
        // handle 0x0200, central, random address, the keyboard's address.
        let ev = r.events.pop_front().unwrap();
        assert_eq!(&ev[..7], &[0x3E, 31, 0x0A, 0, 0x00, 0x02, 0]);
        assert_eq!((ev[7], &ev[8..14]), (1, &r.cfg.kbd_addr[..]));
        assert_eq!(uefi_bt::link::link_event(&ev), Some(uefi_bt::link::LinkEvent::Connected { handle: HANDLE, peer: r.cfg.kbd_addr, peer_random: true, central: true }));
        // A second connection attempt meanwhile isn't allowed.
        create_connection(&mut r);
        assert_eq!(r.events.back().unwrap()[..3], [0x0F, 4, ERR_COMMAND_DISALLOWED]);
    }

    #[test]
    fn an_address_that_isnt_on_the_accept_list_doesnt_connect() {
        let mut r = radio();
        init(&mut r);
        r.cfg.kbd_addr = [9, 9, 9, 9, 9, 0xC0];
        let other = Config::default().kbd_addr;
        let mut add = vec![1];
        add.extend_from_slice(&other);
        r.command(&cmd(0x2011, &add));
        let mut p = vec![0x60, 0x00, 0x30, 0x00, 1, 0];
        p.extend_from_slice(&[0; 19]);
        r.command(&cmd(0x200D, &p));
        r.wake();
        r.advance(5000);
        assert!(!r.is_connected());
        // Cancelling: complete, then a connection complete with "unknown
        // connection".
        r.events.clear();
        r.command(&cmd(0x200E, &[]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 4, 1, 0x0E, 0x20, 0]));
        let ev = r.events.pop_front().unwrap();
        assert_eq!(uefi_bt::link::link_event(&ev), Some(uefi_bt::link::LinkEvent::ConnectFailed { status: ERR_UNKNOWN_CONNECTION }));
    }

    #[test]
    fn encryption_only_with_the_keyboards_key() {
        // The right key: version 2 of the event, as unmasked.
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        r.events.clear();
        enable_encryption(&mut r, &BOND);
        assert_eq!(r.events.pop_front(), Some(vec![0x0F, 4, 0, 1, 0x19, 0x20]));
        r.advance(150);
        assert!(!r.is_encrypted());
        r.advance(160);
        assert_eq!(r.events.pop_front(), Some(vec![0x59, 5, 0, 0x00, 0x02, 1, 16]));
        assert!(r.is_encrypted());

        // A key the keyboard doesn't know: refused, the link stays.
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        r.events.clear();
        enable_encryption(&mut r, &Bond { ediv: 0, rand: [0; 8], ltk: [0x55; 16] });
        r.advance(200);
        assert_eq!(r.events.back(), Some(&vec![0x59, 5, ERR_PIN_OR_KEY_MISSING, 0x00, 0x02, 0, 0]));
        assert!(r.is_connected() && !r.is_encrypted());

        // The right EDIV and Rand with another key: the link is lost.
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        r.events.clear();
        enable_encryption(&mut r, &Bond { ltk: [0x55; 16], ..BOND });
        r.advance(200);
        assert_eq!(r.events.back(), Some(&vec![0x05, 4, 0, 0x00, 0x02, REASON_MIC_FAILURE]));
        assert!(!r.is_connected());

        // An older controller: version 1.
        let mut r = Radio::new(Config { bond: Some(BOND), encryption_change_v1: true, ..Config::default() });
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        r.events.clear();
        enable_encryption(&mut r, &BOND);
        r.advance(200);
        assert_eq!(r.events.back(), Some(&vec![0x08, 4, 0, 0x00, 0x02, 1]));
    }

    #[test]
    fn key_reports_wait_for_encryption() {
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        // Typing wakes the keyboard; the reports are kept.
        r.tap(0, 0x04);
        r.advance(100);
        assert!(r.is_connected());
        r.advance(2000);
        assert!(r.acl.is_empty());
        assert_eq!(r.unsent(), 2);
        enable_encryption(&mut r, &BOND);
        r.advance(2060);
        assert!(r.is_encrypted() && r.acl.is_empty());
        // 27 ms after the encryption the press, a connection event later
        // the release.
        r.advance(2087);
        let out = att_out(&mut r);
        assert_eq!(out, vec![vec![0x1B, 0x1A, 0x00, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
        r.advance(2099);
        assert_eq!(att_out(&mut r), vec![vec![0x1B, 0x1A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
        assert_eq!(r.facts.key_reports_sent, 2);
        // The driver's own parser reads them as notifications of 0x001A.
        r.tap(0x02, 0x05);
        r.advance(2200);
        let packet = r.acl.pop_front().unwrap();
        let n = uefi_bt::link::notification(&packet).unwrap();
        assert_eq!((n.conn, n.attribute, n.value[0], n.value[1]), (HANDLE, 0x001A, 0x02, 0x05));
    }

    #[test]
    fn a_test_can_send_a_report_on_an_unencrypted_link() {
        let mut r = radio();
        init(&mut r);
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        r.key_report_unprotected(0, &[0x04]);
        assert_eq!(att_out(&mut r).len(), 1);
        assert_eq!(r.facts.key_reports_sent, 0);
    }

    #[test]
    fn att_requests_are_answered_and_counted() {
        let mut r = session();
        att(&mut r, &[0x0A, 0x1B, 0x00]);
        // Room for the next packet at once; the answer after the delay.
        assert_eq!(r.events.pop_front(), Some(vec![0x13, 5, 1, 0x00, 0x02, 1, 0]));
        assert!(att_out(&mut r).is_empty());
        r.advance(r.now() + 2);
        assert_eq!(att_out(&mut r), vec![vec![0x0B, 0x01, 0x00]]);
        // The LEDs, written without a response.
        att(&mut r, &[0x52, 0x32, 0x00, 0x02]);
        assert_eq!(r.leds, Some(0x02));
        assert_eq!(r.facts.att_requests, 2);
    }

    #[test]
    fn a_request_in_two_fragments() {
        let mut r = session();
        let pdu = [0x0Au8, 0x1B, 0x00];
        let mut first = HANDLE.to_le_bytes().to_vec();
        first.extend_from_slice(&5u16.to_le_bytes());
        first.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        first.extend_from_slice(&CID_ATT.to_le_bytes());
        first.push(pdu[0]);
        let mut second = (HANDLE | 0x1000).to_le_bytes().to_vec();
        second.extend_from_slice(&2u16.to_le_bytes());
        second.extend_from_slice(&pdu[1..]);
        r.acl_from_host(&first);
        r.advance(r.now() + 10);
        assert!(att_out(&mut r).is_empty());
        r.acl_from_host(&second);
        r.advance(r.now() + 10);
        assert_eq!(att_out(&mut r), vec![vec![0x0B, 0x01, 0x00]]);
    }

    #[test]
    fn the_parameter_request_and_its_answer() {
        let mut r = session();
        r.advance(5100);
        // (The battery level went out before it, 2.5 s after the encryption.)
        let sent: Vec<Vec<u8>> = r.acl.drain(..).collect();
        assert_eq!(sent[0][8..], [0x1B, 0x10, 0x00, 57]);
        let request = &sent[1];
        assert_eq!(&request[4..], &[12, 0, 0x05, 0x00, 0x12, 1, 8, 0, 20, 0, 36, 0, 4, 0, 200, 0]);
        // The host accepts: the signaling response, then the update.
        let mut response = HANDLE.to_le_bytes().to_vec();
        response.extend_from_slice(&[10, 0, 6, 0, 0x05, 0x00, 0x13, 1, 2, 0, 0, 0]);
        r.acl_from_host(&response);
        assert_eq!(r.facts.param_accepted, 1);
        let mut p = HANDLE.to_le_bytes().to_vec();
        for v in [20u16, 36, 4, 200, 0, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        r.events.clear();
        r.command(&cmd(0x2013, &p));
        r.advance(r.now() + 40);
        assert_eq!(r.events.back(), Some(&vec![0x3E, 10, 0x03, 0, 0x00, 0x02, 20, 0, 4, 0, 200, 0]));
    }

    #[test]
    fn the_keyboard_sleeps_after_a_minute_and_comes_back_on_a_key() {
        let mut r = session();
        r.advance(30_000);
        r.tap(0, 0x04);
        r.advance(89_000);
        assert!(r.is_connected());
        r.events.clear();
        r.advance(90_100);
        assert!(!r.is_connected());
        assert_eq!(r.events.pop_front(), Some(vec![0x05, 4, 0, 0x00, 0x02, REASON_REMOTE_USER]));
        // The next key wakes it; the host connects and encrypts again, and
        // the key arrives.
        create_connection(&mut r);
        r.tap(0, 0x05);
        r.advance(90_200);
        assert!(r.is_connected());
        enable_encryption(&mut r, &BOND);
        r.acl.clear();
        r.advance(90_400);
        assert_eq!(att_out(&mut r).len(), 2);
    }

    #[test]
    fn the_host_disconnects_or_just_resets() {
        // A proper disconnect: the keyboard can come back at once.
        let mut r = session();
        r.command(&cmd(0x0406, &[0x00, 0x02, 0x13]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0F, 4, 0, 1, 0x06, 0x04]));
        assert_eq!(r.events.pop_front(), Some(vec![0x05, 4, 0, 0x00, 0x02, REASON_LOCAL_HOST]));
        let t = r.now();
        create_connection(&mut r);
        r.tap(0, 0x04);
        r.advance(t + 60);
        assert!(r.is_connected());

        // A reset without it: the keyboard holds on to the dead link for
        // its supervision timeout first.
        let mut r = session();
        r.command(&cmd(0x0C03, &[]));
        assert!(!r.is_connected());
        let t = r.now();
        init(&mut r);
        create_connection(&mut r);
        r.tap(0, 0x04);
        r.advance(t + 1900);
        assert!(!r.is_connected());
        r.advance(t + 2100);
        assert!(r.is_connected());
    }

    #[test]
    fn pairing_packets_from_the_host_are_counted() {
        let mut r = session();
        let mut packet = HANDLE.to_le_bytes().to_vec();
        packet.extend_from_slice(&[11, 0, 7, 0, 0x06, 0x00, 0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]);
        r.acl_from_host(&packet);
        assert_eq!(r.facts.smp_from_host, 1);
        // The keyboard isn't in pairing mode: Pairing Failed, "pairing
        // not supported". Its bond stays.
        assert_eq!(smp_out(&mut r), [vec![0x05, 0x05]]);
        assert_eq!(r.cfg.bond, Some(BOND));
    }

    fn smp(r: &mut Radio, pdu: &[u8]) {
        let mut packet = HANDLE.to_le_bytes().to_vec();
        packet.extend_from_slice(&(pdu.len() as u16 + 4).to_le_bytes());
        packet.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        packet.extend_from_slice(&CID_SMP.to_le_bytes());
        packet.extend_from_slice(pdu);
        r.acl_from_host(&packet);
    }

    /// The Security Manager PDUs waiting for the host.
    fn smp_out(r: &mut Radio) -> Vec<Vec<u8>> {
        let out = r.acl.iter().filter(|p| p[6..8] == CID_SMP.to_le_bytes()).map(|p| p[8..].to_vec()).collect();
        r.acl.clear();
        out
    }

    #[test]
    fn a_host_pairs_and_comes_back_with_the_new_bond() {
        use crate::smp::{c1, s1, LegacyInputs};
        let mut r = radio();
        init(&mut r);
        // The pairing button: the old bond is gone, and with it the
        // notifications its host had switched on.
        r.enter_pairing_mode();
        assert!(r.cfg.bond.is_none() && r.in_pairing_mode());
        assert!(!r.att.notifying(gatt::H_KEYS_CCCD));
        create_connection(&mut r);
        r.advance(100);
        assert!(r.is_connected());
        r.acl.clear();
        // Legacy passkey entry, the host showing 424242.
        let preq = [0x01, 0x00, 0x00, 0x0D, 16, 0x03, 0x03];
        smp(&mut r, &preq);
        let pres: [u8; 7] = smp_out(&mut r)[0].clone().try_into().unwrap();
        assert_eq!(pres, [0x02, 0x02, 0x00, 0x05, 16, 0x03, 0x03]);
        let inputs = LegacyInputs { preq, pres, initiator_type: 0, initiator: r.cfg.bd_addr, responder_type: 1, responder: r.cfg.kbd_addr };
        let mut tk = [0u8; 16];
        tk[..4].copy_from_slice(&424_242u32.to_le_bytes());
        let mrand = [0x11; 16];
        let mut confirm = vec![0x03];
        confirm.extend_from_slice(&c1(&tk, &mrand, &inputs));
        smp(&mut r, &confirm);
        assert!(smp_out(&mut r).is_empty());
        r.type_passkey(424_242);
        let sconfirm: [u8; 16] = smp_out(&mut r)[0][1..].try_into().unwrap();
        let mut random = vec![0x04];
        random.extend_from_slice(&mrand);
        smp(&mut r, &random);
        let srand: [u8; 16] = smp_out(&mut r)[0][1..].try_into().unwrap();
        assert_eq!(c1(&tk, &srand, &inputs), sconfirm);
        // Encryption with the short-term key; then the keys.
        r.events.clear();
        enable_encryption(&mut r, &Bond { ediv: 0, rand: [0; 8], ltk: s1(&tk, &srand, &mrand) });
        r.advance(200);
        assert!(r.is_encrypted());
        let keys = smp_out(&mut r);
        assert_eq!(keys.iter().map(|p| p[0]).collect::<Vec<_>>(), [0x06, 0x07, 0x08, 0x09]);
        assert!(r.cfg.bond.is_none());
        for (code, len) in [(0x06u8, 16usize), (0x07, 10), (0x08, 16), (0x09, 7)] {
            let mut p = vec![code];
            p.extend(std::iter::repeat_n(0x33, len));
            smp(&mut r, &p);
        }
        assert_eq!((r.smp.completed, r.smp.failures), (1, 0));
        let bond = r.cfg.bond.expect("the keyboard remembers the new bond");
        assert_eq!(bond.ltk[..], keys[0][1..]);
        assert_eq!(bond.ediv.to_le_bytes()[..], keys[1][1..3]);
        assert_eq!(bond.rand[..], keys[1][3..]);
        assert!(!r.in_pairing_mode());
        // A new host finds its notifications off.
        assert!(!r.att.notifying(gatt::H_KEYS_CCCD));
        // The next connection is encrypted with the new bond.
        r.kbd_disconnect(REASON_REMOTE_USER);
        r.events.clear();
        create_connection(&mut r);
        r.wake();
        r.advance(r.now() + 100);
        enable_encryption(&mut r, &bond);
        r.advance(r.now() + 200);
        assert!(r.is_encrypted());
    }

    #[test]
    fn the_keyboards_bond_survives_in_the_state_file() {
        let bond = Some(Bond { ediv: 0x12AB, rand: [1, 2, 3, 4, 5, 6, 7, 0xFF], ltk: [0xA5; 16] });
        assert_eq!(Bond::from_text(&Bond::to_text(&bond)), Ok(bond));
        assert_eq!(Bond::from_text(&Bond::to_text(&None)), Ok(None));
        assert!(Bond::from_text("").is_err());
        assert!(Bond::from_text("12ab 0102 a5").is_err());
    }

    #[test]
    fn a_wrong_pairing_key_loses_the_link() {
        use crate::smp::{c1, LegacyInputs};
        let mut r = radio();
        init(&mut r);
        r.smp.settings.io = crate::smp::IO_NO_INPUT_NO_OUTPUT;
        r.enter_pairing_mode();
        create_connection(&mut r);
        r.advance(100);
        r.acl.clear();
        // Just Works, up to the short-term key.
        let preq = [0x01, 0x03, 0x00, 0x01, 16, 0x00, 0x00];
        smp(&mut r, &preq);
        let pres: [u8; 7] = smp_out(&mut r)[0].clone().try_into().unwrap();
        let inputs = LegacyInputs { preq, pres, initiator_type: 0, initiator: r.cfg.bd_addr, responder_type: 1, responder: r.cfg.kbd_addr };
        let mut confirm = vec![0x03];
        confirm.extend_from_slice(&c1(&[0; 16], &[9; 16], &inputs));
        smp(&mut r, &confirm);
        smp(&mut r, &[&[0x04u8][..], &[9; 16]].concat());
        assert!(r.smp.link_key().is_some());
        r.events.clear();
        enable_encryption(&mut r, &Bond { ediv: 0, rand: [0; 8], ltk: [0xEE; 16] });
        r.advance(200);
        assert!(!r.is_connected());
        assert_eq!(r.facts.mic_failures, 1);
        assert!(r.smp.idle());
    }

    #[test]
    fn a_scanning_host_hears_the_keyboard() {
        let mut r = radio();
        init(&mut r);
        // Advertising reports unmasked too, as the host stack has them.
        r.command(&cmd(0x2001, &0x0000_0000_0000_0207u64.to_le_bytes()));
        // An active scan, duplicates filtered.
        r.command(&cmd(0x200B, &[1, 0x60, 0, 0x30, 0, 0, 0]));
        r.command(&cmd(0x200C, &[1, 1]));
        r.events.clear();
        // Nothing while the keyboard sleeps.
        r.advance(1000);
        assert!(r.events.is_empty());
        // Woken: directed at its bonded host first, once (duplicates are
        // filtered), then undirected with the HID service, and its name
        // in the scan response.
        r.wake();
        r.advance(2000);
        assert_eq!(r.events.len(), 1);
        let ev = r.events.pop_front().unwrap();
        assert_eq!(&ev[..6], &[0x3E, 12, 0x02, 1, ADV_DIRECT_IND, 1]);
        assert_eq!((&ev[6..12], ev[12]), (&r.cfg.kbd_addr[..], 0));
        r.advance(2400);
        let kinds: Vec<u8> = r.events.iter().map(|e| e[4]).collect();
        assert_eq!(kinds, vec![ADV_IND, SCAN_RSP]);
        let ind = r.events.pop_front().unwrap();
        assert_eq!(&ind[13..24], &[2, 0x01, 0x04, 3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18]);
        let rsp = r.events.pop_front().unwrap();
        assert_eq!(&rsp[15..15 + KEYBOARD_NAME.len()], KEYBOARD_NAME.as_bytes());
        assert_eq!(r.facts.adv_reports, 3);
        // The scan can't be reconfigured while it runs; stopping ends the reports.
        r.command(&cmd(0x200B, &[0, 0x60, 0, 0x30, 0, 0, 0]));
        assert_eq!(r.events.pop_front(), Some(vec![0x0E, 4, 1, 0x0B, 0x20, ERR_COMMAND_DISALLOWED]));
        r.command(&cmd(0x200C, &[0, 0]));
        r.events.clear();
        r.advance(5000);
        assert!(r.events.is_empty());
    }

    #[test]
    fn pairing_mode_is_undirected_and_discoverable() {
        let mut r = radio();
        init(&mut r);
        r.command(&cmd(0x2001, &0x0000_0000_0000_0207u64.to_le_bytes()));
        // A passive scan that reports duplicates.
        r.command(&cmd(0x200B, &[0, 0x60, 0, 0x30, 0, 0, 0]));
        r.command(&cmd(0x200C, &[1, 0]));
        r.events.clear();
        r.enter_pairing_mode();
        r.advance(350);
        // Every 100 ms, undirected from the start, limited discoverable.
        assert_eq!(r.events.len(), 4);
        assert!(r.events.iter().all(|e| e[4] == ADV_IND && e[13..16] == [2, 0x01, 0x05]));
    }

    #[test]
    fn masked_events_arent_sent() {
        // After a reset the LE events are masked until the host asks.
        let mut r = radio();
        r.command(&cmd(0x0C03, &[]));
        r.events.clear();
        create_connection(&mut r);
        r.wake();
        r.advance(100);
        assert!(r.is_connected());
        assert!(r.events.iter().all(|e| e[0] != 0x3E));
    }
}
