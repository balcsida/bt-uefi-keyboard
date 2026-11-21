//! What may become a keystroke: the driver's own view of the link to the
//! bonded keyboard ([`LinkTap`]), and the guard between the host stack and
//! the controller ([`LinkGuard`]). Both are plain state machines with host
//! tests; the driver feeds them every HCI command, event and ACL packet.
//!
//! The rules:
//! - **Bonded key only.** LE Enable Encryption reaches the controller only
//!   with the bond's LTK, EDIV and Rand ([`check_command`]). As the central,
//!   the host starts every encryption, so the controller never encrypts this
//!   link with any other key.
//! - **No pairing.** The driver never pairs, so Security Manager PDUs (L2CAP
//!   channel 6) are dropped in both directions ([`SmpFilter`]). Without this,
//!   TrouBLE 0.8 starts a fresh Just Works pairing as soon as the bonded key
//!   fails (`conn.request_security()` counts as user-initiated). Anyone who
//!   answers with the keyboard's address could then pair and type.
//! - **Encrypted means encrypted with the bonded key.** The tap treats the
//!   link as encrypted only after an Encryption Change (v1 or v2) with
//!   status 0x00 and encryption on, for the connection to the bonded address
//!   (address type included, central role), after a bonded start on that
//!   connection.
//! - **Nothing from before encryption.** Notifications that arrive before
//!   that are dropped and counted. With `replay_unencrypted` (the driver's
//!   `insecure-replay-unencrypted` feature) they are kept and delivered once
//!   the link is encrypted, as before Nov 3. That re-opens a window in which
//!   a relay or an injector (an unencrypted LE link has no integrity
//!   protection) can type.
//!
//! Pairing in firmware (the driver's `pairing` feature) adds one exception,
//! and only for one connection at a time:
//! - **A pairing link.** The driver names the device it is about to pair
//!   with ([`LinkTap::set_candidate`]). On the connection to that address
//!   pairing packets pass both ways, and one LE Enable Encryption with a
//!   key of the host stack's making (the pairing's short-term key or its
//!   new long-term key) is let through.
//! - **Encrypted isn't trusted yet.** The controller reporting that
//!   encryption gives [`TapEvent::PairingEncrypted`], and no keystrokes:
//!   notifications are still dropped. Only when the driver accepts the
//!   pairing's result ([`LinkTap::accept_pairing`]: authenticated, bonded)
//!   does the device become the keyboard, and the guard get its key.

use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::link::{link_event, LinkEvent, Notification};

const OP_DISCONNECT: u16 = 0x0406;
const OP_LE_ENABLE_ENCRYPTION: u16 = 0x2019;
const OP_LE_LTK_REQUEST_REPLY: u16 = 0x201A;
const CID_SMP: u16 = 0x0006;

/// What the host stack (TrouBLE) holds in place of the link key. The guard
/// puts the real key into LE Enable Encryption on its way to the
/// controller ([`LinkGuard::allow_command`]), so the host stack's memory,
/// which the driver can't wipe when the OS starts, never has it.
pub const STAND_IN_LTK: [u8; 16] = *b"bt-kb-dxe:no-ltk";

/// The bonded key, as LE Enable Encryption carries it (HCI byte order).
pub struct BondKey {
    ediv: u16,
    rand: [u8; 8],
    ltk: [u8; 16],
    /// Cleared by [`BondKey::wipe`]: a wiped key matches nothing, not even
    /// a command of zeros.
    live: bool,
}

impl BondKey {
    pub fn new(ediv: u16, rand: [u8; 8], ltk: [u8; 16]) -> Self {
        Self { ediv, rand, ltk, live: true }
    }

    /// No bond yet: matches nothing.
    pub fn none() -> Self {
        Self { ediv: 0, rand: [0; 8], ltk: [0; 16], live: false }
    }

    /// Overwrite the key; nothing matches it afterwards.
    pub fn wipe(&mut self) {
        self.live = false;
        for b in self.ltk.iter_mut().chain(self.rand.iter_mut()) {
            // SAFETY: a valid, aligned pointer to a byte we own.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(&mut self.ediv, 0) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for BondKey {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Equality without an early exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// Mix `extra` into the answer to LE Rand, if `event` (header included) is
/// one: a Command Complete for opcode 0x2018 with status 0. The host
/// stack seeds its random generator from the controller alone (TrouBLE
/// 0.8: four LE Rand at start-up), and a pairing's passkey, nonces and
/// key pair come from that seed. XORed with random bytes of the driver's
/// own, the seed is at least as good as the better of the two sources.
pub fn mix_le_rand(event: &mut [u8], extra: &[u8; 8]) -> bool {
    match event {
        [0x0E, 12, _, 0x18, 0x20, 0x00, random @ ..] if random.len() == 8 => {
            for (r, x) in random.iter_mut().zip(extra) {
                *r ^= x;
            }
            true
        }
        _ => false,
    }
}

/// What to do with an HCI command the host stack wants to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandCheck {
    Pass,
    /// LE Enable Encryption with the bonded EDIV and Rand and the stand-in
    /// key, for this connection: sent with the real key in its place.
    BondedEncryption { handle: u16 },
    /// LE Enable Encryption with anything else: not sent, unless this
    /// connection is the one a pairing is under way on, and it is the
    /// pairing's first ([`LinkGuard::allow_pairing`]).
    OtherEncryption { handle: u16 },
    /// Not sent.
    Refuse(&'static str),
}

/// Classify an HCI command packet: opcode (2 bytes), length, parameters.
pub fn check_command(cmd: &[u8], key: &BondKey) -> CommandCheck {
    let Some((&[lo, hi, len], params)) = cmd.split_first_chunk::<3>() else { return CommandCheck::Pass };
    match u16::from_le_bytes([lo, hi]) {
        OP_LE_ENABLE_ENCRYPTION => {
            // Handle (2), Rand (8), EDIV (2), LTK (16).
            if usize::from(len) != 28 || params.len() != 28 {
                return CommandCheck::Refuse("a malformed LE Enable Encryption");
            }
            let handle = u16::from_le_bytes([params[0], params[1]]) & 0x0FFF;
            let bonded = key.live
                & ct_eq(&params[2..10], &key.rand)
                & ct_eq(&params[10..12], &key.ediv.to_le_bytes())
                & ct_eq(&params[12..28], &STAND_IN_LTK);
            if bonded { CommandCheck::BondedEncryption { handle } } else { CommandCheck::OtherEncryption { handle } }
        }
        OP_LE_LTK_REQUEST_REPLY => CommandCheck::Refuse("an LE Long Term Key Request Reply (the driver is never a peripheral)"),
        _ => CommandCheck::Pass,
    }
}

/// Drops Security Manager PDUs (L2CAP channel 6) from the ACL packets of
/// one direction, their continuation fragments included.
#[derive(Debug, Default)]
pub struct SmpFilter {
    /// A dropped PDU continues in later fragments: connection, bytes to come
    /// (`usize::MAX`: until the connection's next start fragment).
    dropping: Option<(u16, usize)>,
    pub dropped: u32,
    /// The reason of the last Pairing Failed that passed on a pairing
    /// link ([`SmpFilter::pass_on`]).
    pub pairing_failed: Option<u8>,
    /// What passed on the pairing link, for the log (nothing in it is
    /// secret): bit n is set for Security Manager code n, and the six
    /// bytes of the last Pairing Request or Response (IO capability, OOB,
    /// authentication requirements, key size, keys from the initiator,
    /// keys from the responder).
    pub codes: u16,
    pub features: Option<[u8; 6]>,
}

impl SmpFilter {
    /// A pairing link begins: forget what passed on the last one.
    pub fn new_pairing(&mut self) {
        (self.pairing_failed, self.codes, self.features) = (None, 0, None);
    }

    /// As [`SmpFilter::pass`], except that everything passes on `pairing`,
    /// the connection a pairing is under way on.
    pub fn pass_on(&mut self, packet: &[u8], pairing: Option<u16>) -> bool {
        if let (Some(pairing), Some(&[a, b])) = (pairing, packet.first_chunk::<2>()) {
            if u16::from_le_bytes([a, b]) & 0x0FFF == pairing {
                if self.dropping.is_some_and(|(h, _)| h == pairing) {
                    self.dropping = None;
                }
                // A start fragment on the Security Manager's channel:
                // handle, length, L2CAP length, channel, code, parameters.
                // Pairing Failed (code 5) starts with the reason.
                if let [_, flags, _, _, _, _, 0x06, 0x00, code, ref parameters @ ..] = *packet {
                    if (flags >> 4) & 0b11 != 0b01 {
                        self.codes |= 1 << code.min(15);
                        match (code, parameters) {
                            (0x05, &[reason, ..]) => self.pairing_failed = Some(reason),
                            (0x01 | 0x02, &[a, b, c, d, e, f, ..]) => self.features = Some([a, b, c, d, e, f]),
                            _ => {}
                        }
                    }
                }
                return true;
            }
        }
        self.pass(packet)
    }

    /// Whether an HCI ACL packet (header included) may pass.
    pub fn pass(&mut self, packet: &[u8]) -> bool {
        let Some((&[a, b, c, d], rest)) = packet.split_first_chunk::<4>() else { return true };
        let raw = u16::from_le_bytes([a, b]);
        let handle = raw & 0x0FFF;
        let Some(data) = rest.get(..usize::from(u16::from_le_bytes([c, d]))) else { return true };
        if (raw >> 12) & 0b11 == 0b01 {
            // A continuation fragment.
            match self.dropping {
                Some((h, left)) if h == handle => {
                    let left = left.saturating_sub(data.len());
                    self.dropping = (left > 0).then_some((handle, left));
                    false
                }
                _ => true,
            }
        } else {
            if self.dropping.is_some_and(|(h, _)| h == handle) {
                self.dropping = None;
            }
            let Some((&[l0, l1, c0, c1], _)) = data.split_first_chunk::<4>() else {
                // The L2CAP header itself is split: the channel can't be
                // told, so the PDU goes. Controllers don't do this.
                self.dropped += 1;
                self.dropping = Some((handle, usize::MAX));
                return false;
            };
            if u16::from_le_bytes([c0, c1]) != CID_SMP {
                return true;
            }
            self.dropped += 1;
            let total = 4 + usize::from(u16::from_le_bytes([l0, l1]));
            if total > data.len() {
                self.dropping = Some((handle, total - data.len()));
            }
            false
        }
    }
}

/// Shared by the transport (what the host stack sends) and the driver's
/// tap (what the controller reports). Both run at TPL_CALLBACK, one after
/// the other, so cells are enough.
pub struct LinkGuard {
    key: RefCell<BondKey>,
    /// The connection last given LE Enable Encryption with the bonded key.
    bonded_start: Cell<Option<u16>>,
    /// The connection a pairing is under way on, if any.
    pairing: Cell<Option<u16>>,
    /// ... and it was given LE Enable Encryption with the pairing's key.
    pairing_start: Cell<Option<u16>>,
    /// The connection the host stack asked the controller to end.
    closing: Cell<Option<u16>>,
    smp_out: RefCell<SmpFilter>,
    refused: Cell<u32>,
    last_refusal: Cell<Option<&'static str>>,
}

impl LinkGuard {
    pub fn new(key: BondKey) -> Self {
        Self {
            key: RefCell::new(key),
            bonded_start: Cell::new(None),
            pairing: Cell::new(None),
            pairing_start: Cell::new(None),
            closing: Cell::new(None),
            smp_out: RefCell::new(SmpFilter::default()),
            refused: Cell::new(0),
            last_refusal: Cell::new(None),
        }
    }

    /// For the transport: whether to send this command. LE Enable
    /// Encryption for the bond gets the real key in place of the stand-in
    /// here; the transport wipes the packet once it's sent.
    pub fn allow_command(&self, cmd: &mut [u8]) -> bool {
        if let [lo, hi, 3, h0, h1, _reason] = *cmd {
            if u16::from_le_bytes([lo, hi]) == OP_DISCONNECT {
                self.closing.set(Some(u16::from_le_bytes([h0, h1]) & 0x0FFF));
            }
        }
        let key = self.key.borrow();
        let why = match check_command(cmd, &key) {
            CommandCheck::Pass => return true,
            CommandCheck::BondedEncryption { handle } => {
                cmd[15..31].copy_from_slice(&key.ltk);
                self.bonded_start.set(Some(handle));
                return true;
            }
            // A pairing's key, as the host stack made it: once per
            // pairing link.
            CommandCheck::OtherEncryption { handle } if self.pairing.get() == Some(handle) && self.pairing_start.get().is_none() => {
                self.pairing_start.set(Some(handle));
                return true;
            }
            CommandCheck::OtherEncryption { .. } => "LE Enable Encryption with a key other than the bonded one",
            CommandCheck::Refuse(why) => why,
        };
        self.refused.set(self.refused.get() + 1);
        self.last_refusal.set(Some(why));
        false
    }

    /// For the transport: whether to send this ACL packet.
    pub fn allow_acl(&self, packet: &[u8]) -> bool {
        self.smp_out.borrow_mut().pass_on(packet, self.pairing.get())
    }

    pub fn bonded_start(&self) -> Option<u16> {
        self.bonded_start.get()
    }

    /// A pairing is under way on this connection (the tap says so when
    /// the driver's candidate connects): its pairing packets pass, and one
    /// LE Enable Encryption with the pairing's key.
    pub fn allow_pairing(&self, handle: u16) {
        self.pairing.set(Some(handle));
        self.pairing_start.set(None);
        self.smp_out.borrow_mut().new_pairing();
    }

    /// What the host stack sent on the pairing link: see
    /// [`SmpFilter::codes`].
    pub fn pairing_sent(&self) -> (u16, Option<[u8; 6]>) {
        let out = self.smp_out.borrow();
        (out.codes, out.features)
    }

    /// The host stack told the device that the pairing failed, with this
    /// reason (as in the Pairing Failed packet). TrouBLE 0.8 doesn't
    /// always tell its user (seen on Nov 15: a keyboard that only does
    /// legacy pairing, refused in Secure Connections only mode), so the
    /// driver reads it off the link.
    pub fn pairing_failed(&self) -> Option<u8> {
        self.smp_out.borrow().pairing_failed
    }

    /// The connection pairing packets pass on.
    pub fn pairing(&self) -> Option<u16> {
        self.pairing.get()
    }

    /// The connection given LE Enable Encryption with a pairing's key.
    pub fn pairing_start(&self) -> Option<u16> {
        self.pairing_start.get()
    }

    /// The connection the host stack has asked the controller to end, until
    /// it is gone. The host stack has written it off: TrouBLE 0.8 stops
    /// altogether when an Encryption Change still arrives for it (seen
    /// with the emulated keyboard on Nov 15), so the driver keeps that
    /// event to itself.
    pub fn closing(&self) -> Option<u16> {
        self.closing.get()
    }

    /// The bond a pairing ended in: from now on the only key. (The old
    /// one is wiped as it goes.)
    pub fn set_key(&self, key: BondKey) {
        *self.key.borrow_mut() = key;
    }

    /// A connection began or ended: an earlier bonded start for its
    /// handle no longer counts, nor does a pairing on it.
    pub fn forget(&self, handle: u16) {
        if self.bonded_start.get() == Some(handle) {
            self.bonded_start.set(None);
        }
        if self.pairing.get() == Some(handle) {
            self.pairing.set(None);
            self.pairing_start.set(None);
        }
        if self.closing.get() == Some(handle) {
            self.closing.set(None);
        }
    }

    /// Commands refused so far, and the reason for the last one.
    pub fn refused(&self) -> (u32, Option<&'static str>) {
        (self.refused.get(), self.last_refusal.get())
    }

    /// Outgoing SMP PDUs dropped so far.
    pub fn smp_dropped(&self) -> u32 {
        self.smp_out.borrow().dropped
    }

    /// Overwrite the key; no encryption can be started afterwards.
    pub fn wipe(&self) {
        self.key.borrow_mut().wipe();
    }
}

/// A link-level change the driver acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapEvent {
    Connected { handle: u16 },
    /// A connection attempt ended without a connection.
    ConnectFailed { status: u8 },
    /// Encrypted with the bonded key. `dropped`: notifications that came
    /// before and were dropped.
    Encrypted { handle: u16, v2: bool, dropped: u32 },
    /// The controller reports encryption on, but this connection had no
    /// bonded start: not trusted. Can't happen while the guard is in place.
    Untrusted { handle: u16 },
    EncryptionOff { handle: u16 },
    /// The device the driver wants to pair with has connected.
    PairingConnected { handle: u16 },
    /// That link is encrypted with the key of a pairing. Not trusted for
    /// keystrokes until [`LinkTap::accept_pairing`].
    PairingEncrypted { handle: u16, v2: bool },
    /// `dropped`: notifications dropped since the last encryption (all of
    /// them, if the link never was encrypted).
    Disconnected { handle: u16, reason: u8, dropped: u32 },
}

/// What becomes of one notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Encrypted and the layout is known: decode it now.
    Deliver,
    /// Kept for [`LinkTap::take_replay`].
    Stashed,
    /// The stash is full: dropped (the replay then releases all keys).
    StashFull,
    /// Arrived before the link was encrypted: dropped.
    DroppedUnencrypted,
    /// Not the keyboard's connection.
    Foreign,
}

/// Notifications kept until they can be decoded.
#[derive(Debug, Default)]
pub struct Replay {
    /// (attribute handle, value), oldest first.
    pub reports: Vec<(u16, Vec<u8>)>,
    /// How many of them arrived before the link was encrypted (only with
    /// `replay_unencrypted`).
    pub unencrypted: u32,
    /// Some were dropped: a key release may be among them.
    pub overflowed: bool,
}

struct Stashed {
    attribute: u16,
    value: Vec<u8>,
    encrypted: bool,
}

/// How far a pairing link has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingLink {
    Connected,
    /// Encrypted with the pairing's key; the driver hasn't accepted the
    /// pairing yet.
    Encrypted,
}

/// The driver's view of the link to the bonded keyboard, from raw HCI.
pub struct LinkTap {
    /// The bonded keyboard (address, random); none before a first pairing.
    peer: Option<([u8; 6], bool)>,
    /// The device the driver is about to pair with.
    candidate: Option<([u8; 6], bool)>,
    /// The current connection is a pairing link.
    pairing: Option<PairingLink>,
    replay_unencrypted: bool,
    conn: Option<u16>,
    encrypted: bool,
    stash: Vec<Stashed>,
    stash_overflowed: bool,
    dropped_unencrypted: u32,
}

impl LinkTap {
    /// First discovery takes about 2 s; fast typing gives about 20 reports
    /// a second.
    pub const STASH_LIMIT: usize = 128;

    /// `peer` least significant byte first, as HCI carries it.
    pub fn new(peer: [u8; 6], peer_random: bool, replay_unencrypted: bool) -> Self {
        Self { peer: Some((peer, peer_random)), ..Self::unpaired(replay_unencrypted) }
    }

    /// Without a bonded keyboard: nothing is the keyboard's connection
    /// until a pairing is accepted.
    pub fn unpaired(replay_unencrypted: bool) -> Self {
        Self {
            peer: None,
            candidate: None,
            pairing: None,
            replay_unencrypted,
            conn: None,
            encrypted: false,
            stash: Vec::new(),
            stash_overflowed: false,
            dropped_unencrypted: 0,
        }
    }

    /// The bonded keyboard: address (least significant byte first) and
    /// whether it is a random one.
    pub fn peer(&self) -> Option<([u8; 6], bool)> {
        self.peer
    }

    /// The device the driver is about to connect to and pair with, or
    /// `None` when it has given that up. A connection to it becomes a
    /// pairing link, even if it has the bonded keyboard's address.
    pub fn set_candidate(&mut self, candidate: Option<([u8; 6], bool)>) {
        self.candidate = candidate;
    }

    /// The current connection is a pairing link the driver hasn't
    /// accepted (yet).
    pub fn pairing(&self) -> bool {
        self.conn.is_some() && self.pairing.is_some()
    }

    /// The driver accepts the pairing on the current link: the controller
    /// reported it encrypted with the pairing's key, and the host stack
    /// reported a pairing that authenticated the device and left a bond.
    /// The device is the keyboard from now on, and `key` the only key the
    /// guard lets an encryption start with. `false`, and nothing changes,
    /// if the link isn't a pairing link the controller reported encrypted.
    pub fn accept_pairing(&mut self, guard: &LinkGuard, key: BondKey) -> bool {
        if self.conn.is_none() || self.pairing != Some(PairingLink::Encrypted) || self.candidate.is_none() {
            return false;
        }
        self.peer = self.candidate.take();
        self.pairing = None;
        self.encrypted = true;
        guard.set_key(key);
        true
    }

    pub fn conn(&self) -> Option<u16> {
        self.conn
    }

    /// The keyboard's link is up and encrypted with the bonded key.
    pub fn encrypted(&self) -> bool {
        self.conn.is_some() && self.encrypted
    }

    fn reset(&mut self, conn: Option<u16>) {
        self.conn = conn;
        self.pairing = None;
        self.encrypted = false;
        self.stash.clear();
        self.stash_overflowed = false;
        self.dropped_unencrypted = 0;
    }

    /// Feed one HCI event (header included).
    pub fn on_event(&mut self, event: &[u8], guard: &LinkGuard) -> Option<TapEvent> {
        match link_event(event)? {
            // The candidate first: a keyboard being paired again has the
            // bonded address, and its old key is not what this link is for.
            LinkEvent::Connected { handle, peer, peer_random, central } if central && self.candidate == Some((peer, peer_random)) => {
                self.reset(Some(handle));
                self.pairing = Some(PairingLink::Connected);
                guard.forget(handle);
                guard.allow_pairing(handle);
                Some(TapEvent::PairingConnected { handle })
            }
            LinkEvent::Connected { handle, peer, peer_random, central } if central && self.peer == Some((peer, peer_random)) => {
                self.reset(Some(handle));
                guard.forget(handle);
                Some(TapEvent::Connected { handle })
            }
            LinkEvent::Connected { .. } => None,
            LinkEvent::ConnectFailed { status } => Some(TapEvent::ConnectFailed { status }),
            LinkEvent::Encryption { handle, on, v2 } if Some(handle) == self.conn => {
                if !on {
                    self.encrypted = false;
                    return Some(TapEvent::EncryptionOff { handle });
                }
                match self.pairing {
                    Some(PairingLink::Connected) if guard.pairing_start() == Some(handle) => {
                        self.pairing = Some(PairingLink::Encrypted);
                        Some(TapEvent::PairingEncrypted { handle, v2 })
                    }
                    None if guard.bonded_start() == Some(handle) => {
                        self.encrypted = true;
                        Some(TapEvent::Encrypted { handle, v2, dropped: core::mem::take(&mut self.dropped_unencrypted) })
                    }
                    _ => {
                        self.encrypted = false;
                        Some(TapEvent::Untrusted { handle })
                    }
                }
            }
            LinkEvent::Disconnected { handle, reason } if Some(handle) == self.conn => {
                let dropped = self.dropped_unencrypted;
                self.reset(None);
                guard.forget(handle);
                Some(TapEvent::Disconnected { handle, reason, dropped })
            }
            _ => None,
        }
    }

    /// Decide about one notification. `layout_known`: the input report's
    /// handle and layout are known, so it can be decoded.
    ///
    /// While earlier notifications are still kept, a new one is kept
    /// behind them even if the layout is known by now: delivered at once,
    /// it would overtake them (an Enter in front of its own command line,
    /// seen with the emulated keyboard on Nov 14). The caller replays
    /// them all with [`LinkTap::take_replay`].
    pub fn on_notification(&mut self, n: &Notification<'_>, layout_known: bool) -> Verdict {
        if self.conn != Some(n.conn) {
            return Verdict::Foreign;
        }
        if !self.encrypted {
            if !self.replay_unencrypted {
                self.dropped_unencrypted += 1;
                return Verdict::DroppedUnencrypted;
            }
            return self.stash(n, false);
        }
        if layout_known && self.stash.is_empty() && !self.stash_overflowed { Verdict::Deliver } else { self.stash(n, true) }
    }

    fn stash(&mut self, n: &Notification<'_>, encrypted: bool) -> Verdict {
        if self.stash.len() >= Self::STASH_LIMIT {
            self.stash_overflowed = true;
            return Verdict::StashFull;
        }
        self.stash.push(Stashed { attribute: n.attribute, value: n.value.to_vec(), encrypted });
        Verdict::Stashed
    }

    /// The kept notifications, once the link is encrypted and the layout
    /// known.
    pub fn take_replay(&mut self, layout_known: bool) -> Option<Replay> {
        if !self.encrypted() || !layout_known || (self.stash.is_empty() && !self.stash_overflowed) {
            return None;
        }
        let stash = core::mem::take(&mut self.stash);
        let unencrypted = stash.iter().filter(|s| !s.encrypted).count() as u32;
        Some(Replay {
            reports: stash.into_iter().map(|s| (s.attribute, s.value)).collect(),
            unencrypted,
            overflowed: core::mem::take(&mut self.stash_overflowed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::notification;
    use alloc::vec;

    /// The keyboard: C0:00:00:00:00:01, random static (HCI byte order).
    const PEER: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0];
    const H: u16 = 0x0200;

    fn key() -> BondKey {
        BondKey::new(0x1234, [1, 2, 3, 4, 5, 6, 7, 8], [0x0F; 16])
    }

    /// LE Connection Complete: status, handle, role, peer type, peer address.
    fn connected(handle: u16, role: u8, peer_type: u8, peer: [u8; 6]) -> Vec<u8> {
        let [lo, hi] = handle.to_le_bytes();
        let mut e = vec![0x3E, 0x13, 0x01, 0x00, lo, hi, role, peer_type];
        e.extend_from_slice(&peer);
        e.extend_from_slice(&[0x18, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00]);
        e
    }

    fn enc_change(status: u8, handle: u16, enabled: u8) -> Vec<u8> {
        let [lo, hi] = handle.to_le_bytes();
        vec![0x08, 0x04, status, lo, hi, enabled]
    }

    fn enc_change_v2(status: u8, handle: u16, enabled: u8) -> Vec<u8> {
        let [lo, hi] = handle.to_le_bytes();
        vec![0x59, 0x05, status, lo, hi, enabled, 0x10]
    }

    fn disconnected(handle: u16, reason: u8) -> Vec<u8> {
        let [lo, hi] = handle.to_le_bytes();
        vec![0x05, 0x04, 0x00, lo, hi, reason]
    }

    /// LE Enable Encryption as TrouBLE sends it: the bond's EDIV and Rand,
    /// the stand-in key.
    fn enable_encryption(handle: u16, k: &BondKey) -> Vec<u8> {
        enable_encryption_with(handle, k, &STAND_IN_LTK)
    }

    fn enable_encryption_with(handle: u16, k: &BondKey, ltk: &[u8; 16]) -> Vec<u8> {
        let mut c = vec![0x19, 0x20, 28];
        c.extend_from_slice(&handle.to_le_bytes());
        c.extend_from_slice(&k.rand);
        c.extend_from_slice(&k.ediv.to_le_bytes());
        c.extend_from_slice(ltk);
        c
    }

    /// An ATT notification of the keyboard report (handle 0x001A).
    fn report(handle: u16, key_usage: u8) -> Vec<u8> {
        let [lo, hi] = (handle | 0x2000).to_le_bytes();
        vec![lo, hi, 0x12, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x1B, 0x1A, 0x00, 0x00, key_usage, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// Connected, encrypted with the bonded key.
    fn ready(replay: bool) -> (LinkTap, LinkGuard) {
        let guard = LinkGuard::new(key());
        let mut tap = LinkTap::new(PEER, true, replay);
        assert_eq!(tap.on_event(&connected(H, 0, 1, PEER), &guard), Some(TapEvent::Connected { handle: H }));
        assert!(guard.allow_command(&mut enable_encryption(H, &key())));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: false, dropped: 0 }));
        (tap, guard)
    }

    #[test]
    fn the_guard_puts_the_real_key_in() {
        let guard = LinkGuard::new(key());
        let mut cmd = enable_encryption(H, &key());
        assert!(guard.allow_command(&mut cmd));
        assert_eq!(cmd, enable_encryption_with(H, &key(), &key().ltk));
        // Refused commands are left alone.
        let mut wrong = enable_encryption_with(H, &key(), &[0x0E; 16]);
        assert!(!guard.allow_command(&mut wrong));
        assert_eq!(&wrong[15..31], &[0x0E; 16]);
    }

    #[test]
    fn enable_encryption_only_with_the_bonded_key() {
        let k = key();
        assert_eq!(check_command(&enable_encryption(H, &k), &k), CommandCheck::BondedEncryption { handle: H });
        // An STK from a fresh pairing (EDIV and Rand zero), another EDIV,
        // another Rand: all refused. So is any key but the stand-in, the
        // real one included: the host stack never has it.
        let stk = BondKey::new(0, [0; 8], [0x55; 16]);
        let other_ediv = BondKey::new(0x1235, [1, 2, 3, 4, 5, 6, 7, 8], [0x0F; 16]);
        let other_rand = BondKey::new(0x1234, [1, 2, 3, 4, 5, 6, 7, 9], [0x0F; 16]);
        let guard = LinkGuard::new(key());
        for wrong in [stk, other_ediv, other_rand] {
            assert_eq!(check_command(&enable_encryption(H, &wrong), &k), CommandCheck::OtherEncryption { handle: H });
            assert!(!guard.allow_command(&mut enable_encryption(H, &wrong)));
        }
        for ltk in [k.ltk, [0x0E; 16], [0; 16]] {
            assert_eq!(check_command(&enable_encryption_with(H, &k, &ltk), &k), CommandCheck::OtherEncryption { handle: H });
            assert!(!guard.allow_command(&mut enable_encryption_with(H, &k, &ltk)));
        }
        assert_eq!(guard.refused(), (6, Some("LE Enable Encryption with a key other than the bonded one")));
        // Without a bond nothing counts as the bonded key, not even zeros.
        let none = BondKey::none();
        assert_eq!(check_command(&enable_encryption(H, &BondKey::new(0, [0; 8], [0; 16])), &none), CommandCheck::OtherEncryption { handle: H });
        // Truncated; peripheral-side LTK reply; anything else passes.
        assert!(matches!(check_command(&enable_encryption(H, &k)[..20], &k), CommandCheck::Refuse(_)));
        assert!(matches!(check_command(&[0x1A, 0x20, 0x12, 0, 0], &k), CommandCheck::Refuse(_)));
        assert_eq!(check_command(&[0x03, 0x0C, 0x00], &k), CommandCheck::Pass);
        assert_eq!(check_command(&[0x06, 0x04, 0x03, 0x00, 0x02, 0x13], &k), CommandCheck::Pass);
    }

    #[test]
    fn smp_is_dropped_including_fragments() {
        let mut f = SmpFilter::default();
        // Pairing Request on CID 6, in one packet.
        assert!(!f.pass(&[0x00, 0x22, 0x0B, 0x00, 0x07, 0x00, 0x06, 0x00, 0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]));
        // ATT on CID 4 passes.
        assert!(f.pass(&[0x00, 0x22, 0x06, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0A, 0x01]));
        // A 69-byte SMP PDU (Pairing Public Key) split into a start and two
        // continuations; an ATT PDU on another connection in between passes.
        let mut start = vec![0x00, 0x22, 0x1B, 0x00, 0x41, 0x00, 0x06, 0x00, 0x0C];
        start.extend_from_slice(&[0xAA; 22]);
        assert!(!f.pass(&start));
        assert!(f.pass(&[0x01, 0x22, 0x06, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0A, 0x01]));
        let mut cont = vec![0x00, 0x12, 0x1B, 0x00];
        cont.extend_from_slice(&[0xBB; 27]);
        assert!(!f.pass(&cont));
        let mut last = vec![0x00, 0x12, 0x10, 0x00];
        last.extend_from_slice(&[0xCC; 16]);
        assert!(!f.pass(&last));
        // The PDU is complete: the next continuation isn't SMP's.
        assert!(f.pass(&cont));
        assert_eq!(f.dropped, 2);
        // A start too short to show its channel goes, and so does what
        // follows it, until the next start.
        assert!(!f.pass(&[0x00, 0x22, 0x02, 0x00, 0x05, 0x00]));
        assert!(!f.pass(&[0x00, 0x12, 0x02, 0x00, 0x06, 0x00]));
        assert!(f.pass(&[0x00, 0x22, 0x06, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0A, 0x01]));
    }

    #[test]
    fn encrypted_only_after_a_bonded_start_and_success() {
        let guard = LinkGuard::new(key());
        let mut tap = LinkTap::new(PEER, true, false);
        // Before any connection: ignored.
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), None);
        tap.on_event(&connected(H, 0, 1, PEER), &guard);
        // No bonded start on this connection yet: not trusted.
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Untrusted { handle: H }));
        assert!(!tap.encrypted());
        assert!(guard.allow_command(&mut enable_encryption(H, &key())));
        // A failure status, or encryption off: not encrypted.
        assert_eq!(tap.on_event(&enc_change(0x06, H, 0), &guard), None);
        assert_eq!(tap.on_event(&enc_change(0x06, H, 1), &guard), None);
        assert!(!tap.encrypted());
        assert_eq!(tap.on_event(&enc_change(0, H, 0), &guard), Some(TapEvent::EncryptionOff { handle: H }));
        assert!(!tap.encrypted());
        // Another connection's success doesn't count.
        assert_eq!(tap.on_event(&enc_change(0, 0x0201, 1), &guard), None);
        assert!(!tap.encrypted());
        // Version 2, success, encryption on: encrypted.
        assert_eq!(tap.on_event(&enc_change_v2(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: true, dropped: 0 }));
        assert!(tap.encrypted());
        // Encryption off again (a pause): not encrypted.
        assert_eq!(tap.on_event(&enc_change(0, H, 0), &guard), Some(TapEvent::EncryptionOff { handle: H }));
        assert!(!tap.encrypted());
    }

    #[test]
    fn only_the_bonded_peer_in_the_central_role() {
        let guard = LinkGuard::new(key());
        let mut tap = LinkTap::new(PEER, true, false);
        // Another address; the same address as a public one; the keyboard
        // connecting to us as a central (role 0x01).
        let other = [0x02, 0x00, 0x00, 0x00, 0x00, 0xC0];
        assert_eq!(tap.on_event(&connected(H, 0, 1, other), &guard), None);
        assert_eq!(tap.on_event(&connected(H, 0, 0, PEER), &guard), None);
        assert_eq!(tap.on_event(&connected(H, 1, 1, PEER), &guard), None);
        assert_eq!(tap.conn(), None);
        // Resolved identity address (type 0x03) counts as random.
        assert_eq!(tap.on_event(&connected(H, 0, 3, PEER), &guard), Some(TapEvent::Connected { handle: H }));
    }

    #[test]
    fn a_bonded_start_doesnt_outlive_its_connection() {
        let (mut tap, guard) = ready(false);
        assert_eq!(tap.on_event(&disconnected(H, 0x13), &guard), Some(TapEvent::Disconnected { handle: H, reason: 0x13, dropped: 0 }));
        assert_eq!(guard.bonded_start(), None);
        // The controller reuses the handle for the next connection: its
        // encryption needs its own bonded start.
        tap.on_event(&connected(H, 0, 1, PEER), &guard);
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Untrusted { handle: H }));
    }

    #[test]
    fn reports_before_encryption_are_dropped() {
        let guard = LinkGuard::new(key());
        let mut tap = LinkTap::new(PEER, true, false);
        tap.on_event(&connected(H, 0, 1, PEER), &guard);
        let early = report(H, 0x04);
        let n = notification(&early).unwrap();
        assert_eq!(tap.on_notification(&n, true), Verdict::DroppedUnencrypted);
        assert_eq!(tap.on_notification(&n, false), Verdict::DroppedUnencrypted);
        guard.allow_command(&mut enable_encryption(H, &key()));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: false, dropped: 2 }));
        // Nothing to replay: they are gone.
        assert!(tap.take_replay(true).is_none());
        let later = report(H, 0x05);
        assert_eq!(tap.on_notification(&notification(&later).unwrap(), true), Verdict::Deliver);
    }

    #[test]
    fn reports_after_encryption_wait_for_the_layout() {
        let (mut tap, _guard) = ready(false);
        let a = report(H, 0x04);
        let b = report(H, 0x05);
        assert_eq!(tap.on_notification(&notification(&a).unwrap(), false), Verdict::Stashed);
        assert_eq!(tap.on_notification(&notification(&b).unwrap(), false), Verdict::Stashed);
        assert!(tap.take_replay(false).is_none());
        let replay = tap.take_replay(true).unwrap();
        assert_eq!(replay.reports.len(), 2);
        assert_eq!(replay.reports[0].1[1], 0x04);
        assert_eq!(replay.unencrypted, 0);
        assert!(!replay.overflowed);
        assert!(tap.take_replay(true).is_none());
    }

    #[test]
    fn a_report_doesnt_overtake_the_kept_ones() {
        // Two reports arrive during discovery. The layout becomes known,
        // and a third arrives before the first two were replayed: it has
        // to wait behind them.
        let (mut tap, _guard) = ready(false);
        let (a, b, c) = (report(H, 0x04), report(H, 0x05), report(H, 0x28));
        assert_eq!(tap.on_notification(&notification(&a).unwrap(), false), Verdict::Stashed);
        assert_eq!(tap.on_notification(&notification(&b).unwrap(), false), Verdict::Stashed);
        assert_eq!(tap.on_notification(&notification(&c).unwrap(), true), Verdict::Stashed);
        let replay = tap.take_replay(true).unwrap();
        assert_eq!(replay.reports.iter().map(|(_, value)| value[1]).collect::<alloc::vec::Vec<_>>(), [0x04, 0x05, 0x28]);
        // With nothing kept, reports are delivered as they come.
        assert_eq!(tap.on_notification(&notification(&c).unwrap(), true), Verdict::Deliver);
    }

    /// A Pairing Request (channel 6) on connection `handle`.
    fn smp_packet(handle: u16) -> Vec<u8> {
        let [lo, hi] = (handle | 0x2000).to_le_bytes();
        vec![lo, hi, 0x0B, 0x00, 0x07, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0D, 0x10, 0x03, 0x03]
    }

    /// Another device: C0:00:00:00:00:77, random static.
    const OTHER: [u8; 6] = [0x77, 0x00, 0x00, 0x00, 0x00, 0xC0];

    #[test]
    fn a_pairing_link_is_trusted_only_once_accepted() {
        let guard = LinkGuard::new(BondKey::none());
        let mut tap = LinkTap::unpaired(false);
        // Nobody is the keyboard yet: a connection is nothing to the tap,
        // pairing packets don't pass, no encryption starts.
        assert_eq!(tap.on_event(&connected(H, 0, 1, OTHER), &guard), None);
        assert!(!guard.allow_acl(&smp_packet(H)));
        let stk = BondKey::new(0, [0; 8], [0x55; 16]);
        assert!(!guard.allow_command(&mut enable_encryption_with(H, &stk, &[0x55; 16])));
        assert_eq!(tap.on_event(&disconnected(H, 0x13), &guard), None);

        // The driver picks a candidate; its connection is a pairing link.
        tap.set_candidate(Some((OTHER, true)));
        assert_eq!(tap.on_event(&connected(H, 0, 1, OTHER), &guard), Some(TapEvent::PairingConnected { handle: H }));
        assert!(tap.pairing() && !tap.encrypted());
        assert_eq!(guard.pairing(), Some(H));
        // Pairing packets pass on it, and only on it.
        assert!(guard.allow_acl(&smp_packet(H)));
        assert!(!guard.allow_acl(&smp_packet(H + 1)));
        // A Pairing Failed from the host stack is noticed as it passes.
        assert_eq!(guard.pairing_failed(), None);
        let [lo, hi] = (H | 0x2000).to_le_bytes();
        assert!(guard.allow_acl(&[lo, hi, 0x06, 0x00, 0x02, 0x00, 0x06, 0x00, 0x05, 0x03]));
        assert_eq!(guard.pairing_failed(), Some(0x03));
        guard.allow_pairing(H);
        assert_eq!(guard.pairing_failed(), None);
        // An encryption the driver didn't start isn't the pairing's.
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Untrusted { handle: H }));
        // The pairing's key goes through as the host stack made it, once.
        let mut cmd = enable_encryption_with(H, &stk, &[0x55; 16]);
        assert!(guard.allow_command(&mut cmd));
        assert_eq!(&cmd[15..31], &[0x55; 16]);
        assert!(!guard.allow_command(&mut enable_encryption_with(H, &stk, &[0x56; 16])));
        assert_eq!(tap.on_event(&enc_change_v2(0, H, 1), &guard), Some(TapEvent::PairingEncrypted { handle: H, v2: true }));
        // Encrypted, but not trusted: reports are dropped.
        assert!(!tap.encrypted());
        let r = report(H, 0x04);
        assert_eq!(tap.on_notification(&notification(&r).unwrap(), true), Verdict::DroppedUnencrypted);
        // The driver accepts the pairing: the device is the keyboard now,
        // and its bond the guard's key.
        assert!(tap.accept_pairing(&guard, key()));
        assert!(tap.encrypted() && !tap.pairing());
        assert_eq!(tap.peer(), Some((OTHER, true)));
        assert_eq!(tap.on_notification(&notification(&r).unwrap(), true), Verdict::Deliver);
        // Pairing packets still pass until the link ends (the host stack's
        // own keys may be on their way), but no second pairing key.
        assert!(guard.allow_acl(&smp_packet(H)));
        assert!(!guard.allow_command(&mut enable_encryption_with(H, &stk, &[0x57; 16])));
        assert_eq!(tap.on_event(&disconnected(H, 0x13), &guard), Some(TapEvent::Disconnected { handle: H, reason: 0x13, dropped: 1 }));
        assert_eq!(guard.pairing(), None);
        assert!(!guard.allow_acl(&smp_packet(H)));

        // From here on it is a bonded keyboard like any other.
        assert_eq!(tap.on_event(&connected(H, 0, 1, OTHER), &guard), Some(TapEvent::Connected { handle: H }));
        assert!(!guard.allow_acl(&smp_packet(H)));
        assert!(guard.allow_command(&mut enable_encryption(H, &key())));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: false, dropped: 0 }));
    }

    #[test]
    fn a_pairing_that_isnt_accepted_leaves_nothing() {
        let guard = LinkGuard::new(BondKey::none());
        let mut tap = LinkTap::unpaired(false);
        tap.set_candidate(Some((OTHER, true)));
        // Accepting needs the controller's word that the link is encrypted
        // with the pairing's key.
        assert!(!tap.accept_pairing(&guard, key()));
        tap.on_event(&connected(H, 0, 1, OTHER), &guard);
        assert!(!tap.accept_pairing(&guard, key()));
        let stk = BondKey::new(0, [0; 8], [0x55; 16]);
        assert!(guard.allow_command(&mut enable_encryption_with(H, &stk, &[0x55; 16])));
        // Encryption failed (the device didn't have the key it claimed).
        assert_eq!(tap.on_event(&enc_change(0x06, H, 0), &guard), None);
        assert!(!tap.accept_pairing(&guard, key()));
        assert_eq!(tap.on_event(&disconnected(H, 0x3D), &guard), Some(TapEvent::Disconnected { handle: H, reason: 0x3D, dropped: 0 }));
        assert_eq!(tap.peer(), None);
        // The driver gives the candidate up: it is nobody again.
        tap.set_candidate(None);
        assert_eq!(tap.on_event(&connected(H, 0, 1, OTHER), &guard), None);
        assert!(!guard.allow_acl(&smp_packet(H)));
        // And the guard still has no key.
        assert!(!guard.allow_command(&mut enable_encryption(H, &key())));
    }

    #[test]
    fn pairing_a_bonded_keyboard_again_doesnt_use_its_old_key() {
        let (mut tap, guard) = ready(false);
        tap.on_event(&disconnected(H, 0x13), &guard);
        // The same address, now as the candidate: a pairing link.
        tap.set_candidate(Some((PEER, true)));
        assert_eq!(tap.on_event(&connected(H, 0, 1, PEER), &guard), Some(TapEvent::PairingConnected { handle: H }));
        // The old key on this link isn't the pairing's key, so its
        // encryption isn't trusted.
        assert!(guard.allow_command(&mut enable_encryption(H, &key())));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Untrusted { handle: H }));
        assert!(!tap.encrypted());
        // Given up: the old bond works as before.
        tap.on_event(&disconnected(H, 0x16), &guard);
        tap.set_candidate(None);
        assert_eq!(tap.on_event(&connected(H, 0, 1, PEER), &guard), Some(TapEvent::Connected { handle: H }));
        assert!(guard.allow_command(&mut enable_encryption(H, &key())));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: false, dropped: 0 }));
    }

    #[test]
    fn pairing_packets_pass_whole_on_the_pairing_link() {
        let mut f = SmpFilter::default();
        // A Pairing Public Key in three fragments on the pairing link.
        let mut start = vec![0x00, 0x22, 0x1B, 0x00, 0x41, 0x00, 0x06, 0x00, 0x0C];
        start.extend_from_slice(&[0xAA; 22]);
        let mut cont = vec![0x00, 0x12, 0x1B, 0x00];
        cont.extend_from_slice(&[0xBB; 27]);
        assert!(f.pass_on(&start, Some(H)));
        assert!(f.pass_on(&cont, Some(H)));
        // On another connection it is dropped as ever.
        assert!(!f.pass_on(&start, Some(H + 1)));
        assert!(!f.pass_on(&cont, Some(H + 1)));
        assert_eq!(f.dropped, 1);
        // What passed is noted for the log: the codes, and what a Pairing
        // Response says the device can do. Never a key or a value.
        assert_eq!((f.codes, f.features), (1 << 0x0C, None));
        let response = [0x00, 0x22, 0x0B, 0x00, 0x07, 0x00, 0x06, 0x00, 0x02, 0x02, 0x00, 0x05, 0x10, 0x00, 0x03];
        assert!(f.pass_on(&response, Some(H)));
        assert_eq!((f.codes, f.features), (1 << 0x0C | 1 << 2, Some([0x02, 0x00, 0x05, 0x10, 0x00, 0x03])));
        f.new_pairing();
        assert_eq!((f.codes, f.features, f.pairing_failed), (0, None, None));
    }

    #[test]
    fn the_guard_knows_which_connection_is_being_closed() {
        let guard = LinkGuard::new(key());
        assert_eq!(guard.closing(), None);
        // HCI_Disconnect for 0x0200, reason 0x13: passes, and is noted.
        assert!(guard.allow_command(&mut [0x06, 0x04, 0x03, 0x00, 0x02, 0x13]));
        assert_eq!(guard.closing(), Some(H));
        // Until the connection is gone (the tap forgets its handle then).
        guard.forget(H + 1);
        assert_eq!(guard.closing(), Some(H));
        guard.forget(H);
        assert_eq!(guard.closing(), None);
    }

    #[test]
    fn le_rand_answers_get_the_drivers_randomness_too() {
        let extra = [0xF0, 0x0F, 0xFF, 0x00, 0x01, 0x02, 0x04, 0x08];
        let mut e = vec![0x0E, 12, 1, 0x18, 0x20, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(mix_le_rand(&mut e, &extra));
        assert_eq!(e, [0x0E, 12, 1, 0x18, 0x20, 0x00, 0xF1, 0x0D, 0xFC, 4, 4, 4, 3, 0]);
        // A failed LE Rand, another command's answer, a short event: as is.
        for other in [
            vec![0x0E, 12, 1, 0x18, 0x20, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8],
            vec![0x0E, 12, 1, 0x09, 0x10, 0x00, 1, 2, 3, 4, 5, 6, 7, 8],
            vec![0x0E, 4, 1, 0x18, 0x20, 0x00],
        ] {
            let mut e = other.clone();
            assert!(!mix_le_rand(&mut e, &extra));
            assert_eq!(e, other);
        }
    }

    #[test]
    fn insecure_replay_keeps_the_old_behaviour() {
        let guard = LinkGuard::new(key());
        let mut tap = LinkTap::new(PEER, true, true);
        tap.on_event(&connected(H, 0, 1, PEER), &guard);
        let early = report(H, 0x04);
        assert_eq!(tap.on_notification(&notification(&early).unwrap(), true), Verdict::Stashed);
        // Not delivered before encryption, not even with the feature.
        assert!(tap.take_replay(true).is_none());
        guard.allow_command(&mut enable_encryption(H, &key()));
        assert_eq!(tap.on_event(&enc_change(0, H, 1), &guard), Some(TapEvent::Encrypted { handle: H, v2: false, dropped: 0 }));
        let replay = tap.take_replay(true).unwrap();
        assert_eq!((replay.reports.len(), replay.unencrypted), (1, 1));
    }

    #[test]
    fn foreign_connections_and_overflow() {
        let (mut tap, guard) = ready(false);
        let other = report(0x0201, 0x04);
        assert_eq!(tap.on_notification(&notification(&other).unwrap(), true), Verdict::Foreign);
        let r = report(H, 0x04);
        for _ in 0..LinkTap::STASH_LIMIT {
            assert_eq!(tap.on_notification(&notification(&r).unwrap(), false), Verdict::Stashed);
        }
        assert_eq!(tap.on_notification(&notification(&r).unwrap(), false), Verdict::StashFull);
        let replay = tap.take_replay(true).unwrap();
        assert_eq!(replay.reports.len(), LinkTap::STASH_LIMIT);
        assert!(replay.overflowed);
        // Disconnected: dropped counts restart, the stash is gone.
        assert_eq!(tap.on_event(&disconnected(H, 0x08), &guard), Some(TapEvent::Disconnected { handle: H, reason: 0x08, dropped: 0 }));
        assert!(!tap.encrypted());
    }

    #[test]
    fn a_wiped_key_matches_nothing() {
        let guard = LinkGuard::new(key());
        guard.wipe();
        assert!(!guard.allow_command(&mut enable_encryption(H, &key())));
        // Not even the zeros the wipe left behind.
        assert!(!guard.allow_command(&mut enable_encryption(H, &BondKey::new(0, [0; 8], [0; 16]))));
        assert_eq!(guard.refused().0, 2);
        assert_eq!(guard.bonded_start(), None);
    }
}
