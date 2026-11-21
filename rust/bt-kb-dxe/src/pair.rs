//! Pairing in firmware (the `pairing` feature): find a keyboard that is in
//! pairing mode, connect to it, and pair with a passkey the PC shows and
//! the user types on the keyboard.
//!
//! This is the host-stack side, a part of the session future. It decides
//! nothing about trust by itself:
//! - **Who may be paired with** is what the scan hears (`uefi_bt::adv`):
//!   a claim anyone in range can make.
//! - **The pairing** is TrouBLE's. The driver shows a passkey only (its IO
//!   capability is "display only"), so a device has to take the passkey
//!   as input: passkey entry. Just Works, which authenticates nothing, is
//!   what a device without keys gets, and is refused when its result
//!   comes ([`check`]).
//! - **LE legacy pairing** is refused by the host stack unless the driver
//!   was built with `insecure-legacy-pairing`: with it the passkey proves
//!   nothing against a device that takes part in the pairing (see the
//!   README).
//! - **The link** counts as the keyboard's only when the driver's tap has
//!   seen the controller report it encrypted with this pairing's key
//!   (`uefi_bt::tap`), and the tick has accepted the result
//!   ([`PairShared::result`], [`PairShared::verdict`]).

use alloc::string::String;
use core::cell::{Cell, RefCell};

use bt_hci::param::{AddrKind, BdAddr, FilterDuplicates};
use embassy_futures::select::{select, Either};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use trouble_host::prelude::*;
use uefi_bt::adv::{Candidate, Candidates};
use uefi_bt::bond::{addr_text, wipe_bytes};
use uefi_bt::clock;

use crate::session::{self, Ctrl, Pool, Shared};

/// LE legacy pairing is allowed (the keyboard doesn't do Secure
/// Connections, and the user accepted what that means).
pub const LEGACY: bool = cfg!(feature = "insecure-legacy-pairing");

/// Pairings that may fail before the offer ends for this boot. Every try
/// is a chance of one in a million for somebody guessing the passkey.
pub const ATTEMPTS: u32 = 3;

/// One round of scanning. Duplicates are filtered by the controller (the
/// event pipe carries about 100 small packets a second), so every round
/// reports each advertiser once, and a new round shows who is still there.
const ROUND: Duration = Duration::from_millis(2000);
/// A candidate not heard in the last rounds is gone.
const FRESH_MS: u64 = 3 * 2000 + 500;
const CONNECT_LIMIT: Duration = Duration::from_secs(8);
/// From the connection to the pairing's result, whatever happens.
const PAIRING_LIMIT: Duration = Duration::from_secs(60);
/// How long the passkey may take to be typed: the Security Manager gives
/// up 30 s after the last pairing packet, and nothing goes over the link
/// while the user reads and types. TrouBLE 0.8 doesn't tell its user when
/// that time is up, so the driver counts it too.
const PASSKEY_LIMIT: Duration = Duration::from_secs(30);

/// What the screen shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Stage {
    #[default]
    Off,
    Searching,
    Connecting {
        name: String,
    },
    Passkey {
        name: String,
        passkey: u32,
    },
    Failed {
        name: String,
        why: String,
    },
    Paired {
        name: String,
    },
    /// The offer ended without a pairing.
    Over,
}

/// The result of a pairing, for the tick to accept and store.
pub struct NewBond {
    pub handle: u16,
    pub peer: [u8; 6],
    pub peer_is_random: bool,
    pub ltk: [u8; 16],
    pub ediv: u16,
    pub rand: [u8; 8],
    pub secure_connections: bool,
    pub name: String,
}

impl Drop for NewBond {
    fn drop(&mut self) {
        wipe_bytes(&mut self.ltk);
    }
}

/// Shared between the session future, the timer tick and the screen (all
/// at TPL_CALLBACK, one after the other).
#[derive(Default)]
pub struct PairShared {
    /// Pairing is offered at this boot.
    pub offered: Cell<bool>,
    /// A passkey can be shown and the boot waits for the pairing, or a
    /// UEFI shell is running: connecting may begin.
    pub go: Cell<bool>,
    /// The offer is over for this boot: paired, given up, or stopped.
    pub over: Cell<bool>,
    /// Keyboards in pairing mode the scan has heard (the tick fills it
    /// from the controller's events).
    pub found: RefCell<Candidates>,
    /// The device the session is about to pair with; the tick tells the
    /// tap, which makes its connection a pairing link.
    pub candidate: Cell<Option<([u8; 6], bool)>>,
    /// From the tap: the pairing link, once the controller reported it
    /// encrypted with the pairing's key.
    pub link_encrypted: Cell<Option<u16>>,
    pub stage: RefCell<Stage>,
    /// A finished pairing, for the tick.
    pub result: RefCell<Option<NewBond>>,
    /// The tick's answer to it.
    pub verdict: Cell<Option<bool>>,
    pub failures: Cell<u32>,
    /// A pairing is being tried (the boot waits for it).
    pub busy: Cell<bool>,
    /// From the tick: a Pairing Failed went over the pairing link. `true`:
    /// the host stack sent it; the reason as in the packet.
    pub failed: Cell<Option<(bool, u8)>>,
    /// Advertising reports the scan has brought, for the log.
    pub heard: Cell<u32>,
}

impl PairShared {
    fn show(&self, stage: Stage) {
        *self.stage.borrow_mut() = stage;
    }

    /// End the offer for this boot.
    pub fn end(&self) {
        if !self.over.replace(true) && !matches!(*self.stage.borrow(), Stage::Paired { .. }) {
            self.show(Stage::Over);
        }
    }
}

/// What to call a candidate: its name, or else its address.
fn label(c: &Candidate) -> String {
    match &c.name {
        Some(name) if !name.is_empty() => name.clone(),
        _ => addr_text(&c.addr),
    }
}

/// Offer pairing until a keyboard is paired or the offer is over. The
/// connection of a pairing the tick accepted is returned, encrypted, for
/// the session to serve like any keyboard link.
pub async fn offer(
    stack: &'static Stack<'static, Ctrl, Pool>,
    central: &mut Central<'static, Ctrl, Pool>,
    shared: &'static Shared,
) -> Option<Connection<'static, Pool>> {
    let p = &shared.pairing;
    log::info!(
        "pairing: looking for a keyboard in pairing mode ({})",
        if LEGACY { "LE legacy pairing allowed: built with insecure-legacy-pairing" } else { "Secure Connections only" }
    );
    loop {
        p.busy.set(false);
        p.candidate.set(None);
        if p.over.get() {
            return None;
        }
        if !matches!(*p.stage.borrow(), Stage::Failed { .. }) {
            p.show(Stage::Searching);
        }
        let candidate = find(central, shared).await?;
        let name = label(&candidate);
        log::info!(
            "pairing: {} ({}, {} dBm) says it is a keyboard in pairing mode: connecting",
            addr_text(&candidate.addr),
            if candidate.name.is_some() { name.as_str() } else { "no name heard" },
            candidate.rssi
        );
        p.busy.set(true);
        p.link_encrypted.set(None);
        p.failed.set(None);
        p.candidate.set(Some((candidate.addr, candidate.random)));
        p.show(Stage::Connecting { name: name.clone() });
        match pair_with(stack, central, shared, &candidate, &name).await {
            Ok(conn) => {
                p.busy.set(false);
                return Some(conn);
            }
            Err(why) => {
                log::warn!("pairing with {} failed: {why}", addr_text(&candidate.addr));
                p.failures.set(p.failures.get() + 1);
                p.found.borrow_mut().remove(&candidate.addr, candidate.random);
                if p.failures.get() >= ATTEMPTS {
                    log::warn!("pairing: {ATTEMPTS} attempts failed; not offered again before the next boot");
                    p.show(Stage::Failed { name, why });
                    Timer::after(Duration::from_secs(4)).await;
                    p.end();
                    continue;
                }
                p.show(Stage::Failed { name, why });
                // Long enough to read it; the keyboard has to be heard
                // again before the next try.
                Timer::after(Duration::from_secs(3)).await;
            }
        }
    }
}

/// Scan until a candidate is there and connecting may begin. `None`: the
/// offer is over.
async fn find(central: &mut Central<'static, Ctrl, Pool>, shared: &'static Shared) -> Option<Candidate> {
    let p = &shared.pairing;
    loop {
        // Passive until somebody claims to be a keyboard in pairing mode;
        // then actively, which gets its name (the scan response) too.
        let active = !p.found.borrow().is_empty();
        let config = ScanConfig { active, filter_duplicates: FilterDuplicates::Enabled, ..ScanConfig::default() };
        let mut scanner = Scanner::new(central);
        let scan = match scanner.scan(&config).await {
            Ok(scan) => scan,
            Err(e) => {
                log::warn!("pairing: starting the scan failed: {e:?}");
                Timer::after(Duration::from_secs(1)).await;
                if p.over.get() {
                    return None;
                }
                continue;
            }
        };
        let end = Instant::now() + ROUND;
        loop {
            Timer::after(Duration::from_millis(50)).await;
            if Instant::now() >= end || p.over.get() {
                break;
            }
            let found = p.found.borrow();
            // A passive round ends when somebody is there to ask for a
            // name; an active one when the one to connect to has told it.
            let enough = if active {
                p.go.get() && found.best(clock::now_ms(), FRESH_MS).is_some_and(|c| c.name.is_some())
            } else {
                !found.is_empty()
            };
            if enough {
                break;
            }
        }
        scan.stop().await;
        if p.over.get() {
            return None;
        }
        if active && p.go.get() {
            if let Some(best) = p.found.borrow().best(clock::now_ms(), FRESH_MS) {
                return Some(best.clone());
            }
        }
    }
}

/// A Pairing Failed that went over the link, in words.
fn failure_text(by_host: bool, reason: u8) -> String {
    String::from(match (by_host, reason) {
        (_, 0x01 | 0x04) => "the passkey typed on it wasn't the one shown",
        (_, 0x0B) => "the keys didn't match at the end (the passkey typed wasn't the one shown?)",
        (true, 0x03) if !LEGACY => "it only does LE legacy pairing, which this driver wasn't built to allow (insecure-legacy-pairing)",
        (_, 0x03) => "the two sides can't meet each other's requirements for the pairing",
        (false, 0x05) => "it refused to pair (not in pairing mode?)",
        (_, 0x06) => "the two sides don't agree on a key of 128 bits",
        (true, _) => return alloc::format!("the host stack gave up (reason {reason:#04x})"),
        (false, _) => return alloc::format!("it gave up (reason {reason:#04x})"),
    })
}

fn reason_text(e: &Error) -> String {
    use trouble_host::prelude::PairingFailedReason as Reason;
    String::from(match e {
        Error::Security(Reason::ConfirmValueFailed | Reason::PasskeyEntryFailed) => "the passkey typed on it wasn't the one shown",
        Error::Security(Reason::DHKeyCheckFailed) => "the keys didn't match at the end (the passkey typed wasn't the one shown?)",
        Error::Security(Reason::AuthenticationRequirements) if !LEGACY => {
            "it only does LE legacy pairing, which this driver wasn't built to allow (insecure-legacy-pairing)"
        }
        Error::Security(Reason::AuthenticationRequirements) => "it can't meet the pairing's requirements",
        Error::Security(Reason::PairingNotSupported) => "it refused to pair (not in pairing mode?)",
        Error::Security(Reason::EncryptionKeySize) => "it wants a shorter key than 128 bits",
        Error::Security(Reason::KeyRejected) => "the link couldn't be encrypted with the new key",
        Error::Timeout => "no answer within 30 s (the passkey wasn't typed in time?)",
        other => return alloc::format!("{other:?}"),
    })
}

/// The driver's own conditions on a pairing's result.
fn check(level: SecurityLevel, bond: &Option<BondInformation>, candidate: &Candidate) -> Result<(), String> {
    let Some(bond) = bond else {
        return Err(String::from("it doesn't keep a bond, so it would have to be paired at every boot"));
    };
    // A legacy pairing in which the keyboard hands over no key of its own
    // ends with the short-term key in the "bond" (TrouBLE 0.8 marks that
    // one as not bonded): good for this connection only.
    if !bond.is_bonded {
        return Err(String::from("it handed over no key for later connections, so it would have to be paired at every boot"));
    }
    if level != SecurityLevel::EncryptedAuthenticated || bond.security_level != SecurityLevel::EncryptedAuthenticated {
        return Err(String::from(
            "it paired without the passkey (Just Works), which proves nothing about which device it is",
        ));
    }
    if bond.encryption_key_len != 16 {
        return Err(alloc::format!("its key is {} bytes, not 16", bond.encryption_key_len));
    }
    let kind = if candidate.random { AddrKind::RANDOM } else { AddrKind::PUBLIC };
    if bond.identity.addr.kind != kind || bond.identity.addr.addr.raw() != &candidate.addr[..] {
        return Err(String::from(
            "it says its real address is another one (a private address): this driver can't find such a keyboard again",
        ));
    }
    Ok(())
}

async fn pair_with(
    stack: &'static Stack<'static, Ctrl, Pool>,
    central: &mut Central<'static, Ctrl, Pool>,
    shared: &'static Shared,
    candidate: &Candidate,
    name: &str,
) -> Result<Connection<'static, Pool>, String> {
    let kind = if candidate.random { AddrKind::RANDOM } else { AddrKind::PUBLIC };
    let address = Address::new(kind, BdAddr::new(candidate.addr));
    let identity = Identity { addr: address, irk: None };
    // The host stack's bonds as they are now (stand-ins, no keys). A pairing
    // that fails, or that the driver refuses, must leave nothing of its own
    // among them: the device may name any address as its real one, the
    // bonded keyboard's too, and the host stack files the new key under it.
    let before = stack.with_bond_information(|bonds| bonds.to_vec());
    // A bond the host stack still has for this address (the keyboard is
    // being paired again) would be tried first: it isn't what this is for.
    if before.iter().any(|b| b.identity.match_identity(&identity)) {
        let _ = stack.remove_bond_information(identity);
    }
    let restore = |stack: &'static Stack<'static, Ctrl, Pool>| {
        for bond in stack.with_bond_information(|bonds| bonds.to_vec()) {
            let _ = stack.remove_bond_information(bond.identity);
        }
        for bond in &before {
            let _ = stack.add_bond_information(bond.clone());
        }
    };
    let accept = [address];
    let config = ConnectConfig {
        scan_config: ScanConfig { filter_accept_list: &accept, ..ScanConfig::default() },
        connect_params: session::connect_params(),
    };
    let conn = match with_timeout(CONNECT_LIMIT, central.connect(&config)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            restore(stack);
            return Err(alloc::format!("connecting failed: {e:?}"));
        }
        Err(_) => {
            restore(stack);
            return Err(String::from("it didn't accept a connection (no longer in pairing mode?)"));
        }
    };
    let result = pairing(stack, &conn, shared, candidate, name).await;
    match result {
        Ok(()) => Ok(conn),
        Err(why) => {
            restore(stack);
            if conn.is_connected() {
                conn.disconnect();
                let _ = with_timeout(Duration::from_secs(3), async {
                    loop {
                        if let ConnectionEvent::Disconnected { .. } = conn.next().await {
                            break;
                        }
                    }
                })
                .await;
            }
            Err(why)
        }
    }
}

async fn pairing(
    stack: &'static Stack<'static, Ctrl, Pool>,
    conn: &Connection<'static, Pool>,
    shared: &'static Shared,
    candidate: &Candidate,
    name: &str,
) -> Result<(), String> {
    let p = &shared.pairing;
    let handle = conn.handle().raw();
    conn.set_bondable(true).map_err(|e| alloc::format!("{e:?}"))?;
    conn.request_security().map_err(|e| alloc::format!("starting the pairing failed: {e:?}"))?;
    let started = Instant::now();
    let mut shown: Option<Instant> = None;
    loop {
        if p.over.get() {
            return Err(String::from("stopped"));
        }
        if started.elapsed() > PAIRING_LIMIT {
            return Err(String::from("it took too long"));
        }
        // Once the passkey is typed the rest takes a fraction of a second.
        if shown.is_some_and(|at| at.elapsed() > PASSKEY_LIMIT + Duration::from_secs(1)) {
            return Err(String::from("the passkey wasn't typed on it within 30 s"));
        }
        let event = match select(conn.next(), Timer::after(Duration::from_millis(50))).await {
            Either::First(event) => event,
            Either::Second(()) => {
                // The host stack doesn't report every failure as an
                // event: the tick reads them off the link.
                if let Some((by_host, reason)) = p.failed.get() {
                    return Err(failure_text(by_host, reason));
                }
                continue;
            }
        };
        match event {
            ConnectionEvent::PassKeyDisplay(passkey) => {
                // Not in the log: whoever reads the log variable from the
                // OS learns nothing, the passkey being used up by then,
                // but a passkey has no business there.
                log::info!("pairing: showing the passkey; waiting for it to be typed on the keyboard");
                shown = Some(Instant::now());
                p.show(Stage::Passkey { name: String::from(name), passkey: passkey.value() });
            }
            ConnectionEvent::PassKeyConfirm(_) | ConnectionEvent::PassKeyInput => {
                // Not ours to do: the driver can only show.
                let _ = conn.pass_key_cancel();
                return Err(String::from("it asked for a kind of pairing this driver doesn't do"));
            }
            ConnectionEvent::PairingFailed(e) => return Err(reason_text(&e)),
            ConnectionEvent::Disconnected { reason } => return Err(alloc::format!("it disconnected ({reason:?})")),
            ConnectionEvent::RequestConnectionParams(req) => session::answer(stack, req).await,
            ConnectionEvent::PairingComplete { security_level, bond } => {
                check(security_level, &bond, candidate)?;
                let Some(bond) = bond else { unreachable!() };
                // shortcut: a legacy key handed over with EDIV and Rand both zero is taken for a Secure
                // Connections one (it still works); read the SC bit off the Pairing Response if the label matters.
                let legacy = bond.ediv != 0 || bond.rand != [0; 8];
                if legacy && !LEGACY {
                    return Err(String::from("it paired with LE legacy pairing, which this driver wasn't built to allow"));
                }
                // The tick's part: the tap must have seen this link
                // encrypted with this pairing's key.
                p.verdict.set(None);
                *p.result.borrow_mut() = Some(NewBond {
                    handle,
                    peer: candidate.addr,
                    peer_is_random: candidate.random,
                    ltk: bond.ltk.0.to_le_bytes(),
                    ediv: bond.ediv,
                    rand: bond.rand,
                    secure_connections: !legacy,
                    name: String::from(name),
                });
                let asked = Instant::now();
                let accepted = loop {
                    if let Some(verdict) = p.verdict.take() {
                        break verdict;
                    }
                    if asked.elapsed() > Duration::from_secs(2) {
                        p.result.borrow_mut().take();
                        break false;
                    }
                    Timer::after(Duration::from_millis(5)).await;
                };
                if !accepted {
                    return Err(String::from("the controller never reported this link encrypted with the pairing's key"));
                }
                // From here on the host stack holds a stand-in, as for
                // any bond: the key is the guard's (uefi_bt::tap).
                let _ = stack.remove_bond_information(bond.identity);
                // Without the keyboard's resolving key: it uses the
                // address it was found under.
                let identity = Identity { addr: bond.identity.addr, irk: None };
                let mut stand_in =
                    BondInformation::new(identity, LongTermKey::from_le_bytes(uefi_bt::tap::STAND_IN_LTK), security_level, true);
                stand_in.ediv = bond.ediv;
                stand_in.rand = bond.rand;
                stand_in.encryption_key_len = bond.encryption_key_len;
                if let Err(e) = stack.add_bond_information(stand_in) {
                    log::warn!("pairing: keeping the bond in the host stack failed ({e:?}): it reconnects from the next boot on");
                }
                p.show(Stage::Paired { name: String::from(name) });
                p.over.set(true);
                return Ok(());
            }
            _ => {}
        }
    }
}
