//! The keyboard's side of pairing: the Security Manager Protocol as the
//! responder, with LE legacy pairing and LE Secure Connections. The host
//! shows six digits and the user types them on the keyboard (passkey
//! entry); a "keyboard" without keys to type them on gets Just Works.
//!
//! Written from the Core Specification (Vol 3, Part H) and checked against
//! its sample data, not from the host stack under test: if the driver's
//! stack and this agree on a pairing, both follow the specification.
//!
//! Nothing here encrypts the link: the emulation sits at the HCI. The
//! result of a pairing is the key the host has to name in LE Enable
//! Encryption ([`Smp::link_key`]), and the bond the keyboard remembers.
//!
//! Byte order: every array here is as on the air, least significant byte
//! first, except the Diffie-Hellman key and where a function says so.

use std::io::Read;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use cmac::{Cmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, FieldBytes, PublicKey, SecretKey};

use crate::note;
use crate::radio::Bond;

pub type Key = [u8; 16];

pub const PAIRING_REQUEST: u8 = 0x01;
pub const PAIRING_RESPONSE: u8 = 0x02;
pub const PAIRING_CONFIRM: u8 = 0x03;
pub const PAIRING_RANDOM: u8 = 0x04;
pub const PAIRING_FAILED: u8 = 0x05;
pub const ENCRYPTION_INFORMATION: u8 = 0x06;
pub const CENTRAL_IDENTIFICATION: u8 = 0x07;
pub const IDENTITY_INFORMATION: u8 = 0x08;
pub const IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
pub const SIGNING_INFORMATION: u8 = 0x0A;
pub const SECURITY_REQUEST: u8 = 0x0B;
pub const PAIRING_PUBLIC_KEY: u8 = 0x0C;
pub const PAIRING_DHKEY_CHECK: u8 = 0x0D;

pub const REASON_PASSKEY_ENTRY_FAILED: u8 = 0x01;
pub const REASON_AUTHENTICATION_REQUIREMENTS: u8 = 0x03;
pub const REASON_CONFIRM_VALUE_FAILED: u8 = 0x04;
pub const REASON_PAIRING_NOT_SUPPORTED: u8 = 0x05;
pub const REASON_ENCRYPTION_KEY_SIZE: u8 = 0x06;
pub const REASON_UNSPECIFIED: u8 = 0x08;
pub const REASON_INVALID_PARAMETERS: u8 = 0x0A;
pub const REASON_DHKEY_CHECK_FAILED: u8 = 0x0B;

pub const IO_DISPLAY_ONLY: u8 = 0x00;
pub const IO_DISPLAY_YES_NO: u8 = 0x01;
pub const IO_KEYBOARD_ONLY: u8 = 0x02;
pub const IO_NO_INPUT_NO_OUTPUT: u8 = 0x03;
pub const IO_KEYBOARD_DISPLAY: u8 = 0x04;

const AUTH_BONDING: u8 = 0x01;
const AUTH_MITM: u8 = 0x04;
const AUTH_SC: u8 = 0x08;
const DIST_ENC: u8 = 0x01;
const DIST_ID: u8 = 0x02;

// ----- The cryptographic toolbox (Vol 3, Part H, 2.2) ----------------------

fn reversed<const N: usize>(mut bytes: [u8; N]) -> [u8; N] {
    bytes.reverse();
    bytes
}

fn xor(a: &Key, b: &Key) -> Key {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// The security function e: AES-128.
fn e(key: &Key, data: &Key) -> Key {
    let cipher = Aes128::new(GenericArray::from_slice(&reversed(*key)));
    let mut block = GenericArray::from(reversed(*data));
    cipher.encrypt_block(&mut block);
    reversed(block.into())
}

/// e run backwards.
fn d(key: &Key, data: &Key) -> Key {
    let cipher = Aes128::new(GenericArray::from_slice(&reversed(*key)));
    let mut block = GenericArray::from(reversed(*data));
    cipher.decrypt_block(&mut block);
    reversed(block.into())
}

/// What both sides of a legacy pairing know besides the temporary key:
/// the two pairing PDUs (opcode first, as sent) and the two addresses
/// (type 0 public, 1 random).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyInputs {
    pub preq: [u8; 7],
    pub pres: [u8; 7],
    pub initiator_type: u8,
    pub initiator: [u8; 6],
    pub responder_type: u8,
    pub responder: [u8; 6],
}

impl LegacyInputs {
    /// p1 = pres || preq || rat || iat, and p2 = padding || ia || ra.
    fn p1_p2(&self) -> (Key, Key) {
        let mut p1 = [0u8; 16];
        p1[0] = self.initiator_type;
        p1[1] = self.responder_type;
        p1[2..9].copy_from_slice(&self.preq);
        p1[9..16].copy_from_slice(&self.pres);
        let mut p2 = [0u8; 16];
        p2[0..6].copy_from_slice(&self.responder);
        p2[6..12].copy_from_slice(&self.initiator);
        (p1, p2)
    }
}

/// The legacy confirm value: c1(k, r, ...) = e(k, e(k, r XOR p1) XOR p2).
pub fn c1(k: &Key, r: &Key, inputs: &LegacyInputs) -> Key {
    let (p1, p2) = inputs.p1_p2();
    e(k, &xor(&e(k, &xor(r, &p1)), &p2))
}

/// The random value that gives `confirm` under `k`: c1 run backwards.
/// AES is a permutation once the key is known, so whoever learns the
/// temporary key can open a confirm value it sent earlier to any key it
/// likes. This is what makes legacy passkey entry worthless against a
/// responder that doesn't know the passkey (Rosa, 2013).
pub fn c1_inverse(k: &Key, confirm: &Key, inputs: &LegacyInputs) -> Key {
    let (p1, p2) = inputs.p1_p2();
    xor(&d(k, &xor(&d(k, confirm), &p2)), &p1)
}

/// The legacy short-term key: s1(k, r1, r2) = e(k, r1' || r2'), the less
/// significant halves of both.
pub fn s1(k: &Key, r1: &Key, r2: &Key) -> Key {
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&r2[..8]);
    r[8..].copy_from_slice(&r1[..8]);
    e(k, &r)
}

/// AES-CMAC; key, message and result most significant byte first.
fn aes_cmac(key: &Key, message: &[u8]) -> Key {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("a 16-byte key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The Secure Connections confirm value: f4(U, V, X, Z) =
/// AES-CMAC_X(U || V || Z), with the x coordinates of two public keys.
pub fn f4(u: &[u8; 32], v: &[u8; 32], x: &Key, z: u8) -> Key {
    let mut m = Vec::with_capacity(65);
    m.extend(u.iter().rev());
    m.extend(v.iter().rev());
    m.push(z);
    reversed(aes_cmac(&reversed(*x), &m))
}

/// An address as f5 and f6 take it: the type, then the address, most
/// significant byte first.
pub fn address56(kind: u8, addr: &[u8; 6]) -> [u8; 7] {
    let mut a = [kind, 0, 0, 0, 0, 0, 0];
    for (to, from) in a[1..].iter_mut().zip(addr.iter().rev()) {
        *to = *from;
    }
    a
}

/// The Secure Connections key generation: f5(W, N1, N2, A1, A2) gives the
/// MacKey and the LTK. `w` is the Diffie-Hellman key, most significant
/// byte first.
pub fn f5(w: &[u8; 32], n1: &Key, n2: &Key, a1: &[u8; 7], a2: &[u8; 7]) -> (Key, Key) {
    const SALT: Key = [0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE];
    let t = aes_cmac(&SALT, w);
    let mut m = vec![0u8];
    m.extend_from_slice(b"btle");
    m.extend(n1.iter().rev());
    m.extend(n2.iter().rev());
    m.extend_from_slice(a1);
    m.extend_from_slice(a2);
    m.extend_from_slice(&[0x01, 0x00]);
    let mac_key = aes_cmac(&t, &m);
    m[0] = 1;
    let ltk = aes_cmac(&t, &m);
    (reversed(mac_key), reversed(ltk))
}

/// The Secure Connections check value: f6(W, N1, N2, R, IOcap, A1, A2).
/// `io_cap`: AuthReq, OOB flag, IO capability, in that order.
pub fn f6(w: &Key, n1: &Key, n2: &Key, r: &Key, io_cap: &[u8; 3], a1: &[u8; 7], a2: &[u8; 7]) -> Key {
    let mut m = Vec::with_capacity(65);
    m.extend(n1.iter().rev());
    m.extend(n2.iter().rev());
    m.extend(r.iter().rev());
    m.extend_from_slice(io_cap);
    m.extend_from_slice(a1);
    m.extend_from_slice(a2);
    reversed(aes_cmac(&reversed(*w), &m))
}

/// The passkey as the 128-bit value the functions take.
fn passkey_value(passkey: u32) -> Key {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(&passkey.to_le_bytes());
    k
}

/// Zero the most significant bytes of a key beyond the negotiated size.
fn shortened(mut key: Key, size: u8) -> Key {
    for b in key.iter_mut().skip(usize::from(size)) {
        *b = 0;
    }
    key
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("/dev/urandom");
    bytes
}

/// A P-256 key pair for one pairing.
struct KeyPair {
    secret: SecretKey,
    /// The public key as the Pairing Public Key PDU carries it.
    x: [u8; 32],
    y: [u8; 32],
}

impl KeyPair {
    fn from_secret(secret: SecretKey) -> Self {
        let point = secret.public_key().to_encoded_point(false);
        let x: [u8; 32] = point.x().expect("an uncompressed point").as_slice().try_into().unwrap();
        let y: [u8; 32] = point.y().expect("an uncompressed point").as_slice().try_into().unwrap();
        Self { secret, x: reversed(x), y: reversed(y) }
    }

    fn generate() -> Self {
        loop {
            if let Ok(secret) = SecretKey::from_slice(&random::<32>()) {
                return Self::from_secret(secret);
            }
        }
    }

    /// The Diffie-Hellman key with the peer's public key (coordinates as
    /// in the PDU), most significant byte first; `None` if that isn't a
    /// point on the curve.
    fn dh_key(&self, x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]> {
        let point = EncodedPoint::from_affine_coordinates(&FieldBytes::from(reversed(*x)), &FieldBytes::from(reversed(*y)), false);
        let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))?;
        let shared = (peer.to_projective() * *self.secret.to_nonzero_scalar()).to_affine().to_encoded_point(false);
        shared.x()?.as_slice().try_into().ok()
    }
}

// ----- The responder --------------------------------------------------------

/// What the keyboard can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// It answers a Pairing Request with "pairing not supported".
    None,
    /// LE legacy pairing only, as the real keyboard.
    Legacy,
    SecureConnections,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub method: Method,
    /// Keyboard only: the user types the passkey on it. No input, no
    /// output: Just Works, which authenticates nothing.
    pub io: u8,
    pub max_key_size: u8,
    /// The keys it agrees to exchange: the host's, its own (EncKey 0x01,
    /// IdKey 0x02).
    pub key_dist: (u8, u8),
    /// It doesn't wait for a passkey: it is somebody else's device, which
    /// works the passkey out from the host's own messages (legacy pairing
    /// only; see [`c1_inverse`]).
    pub impostor: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { method: Method::Legacy, io: IO_KEYBOARD_ONLY, max_key_size: 16, key_dist: (DIST_ENC | DIST_ID, DIST_ENC | DIST_ID), impostor: false }
    }
}

/// The two ends of the link, as the pairing functions use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ends {
    pub host_type: u8,
    pub host: [u8; 6],
    pub kbd_type: u8,
    pub kbd: [u8; 6],
}

/// What both pairing methods agree on first.
#[derive(Debug, Clone, Copy)]
struct Agreed {
    preq: [u8; 7],
    pres: [u8; 7],
    key_size: u8,
    /// The user has to type the passkey (else Just Works).
    passkey_entry: bool,
    bonding: bool,
}

impl Agreed {
    /// Keys the host sends, keys the keyboard sends.
    fn dist(&self) -> (u8, u8) {
        (self.pres[5], self.pres[6])
    }
}

struct ScKeys {
    pair: KeyPair,
    host_x: [u8; 32],
    dh_key: [u8; 32],
}

enum State {
    Idle,
    /// Legacy: the host's confirm value and the passkey, in either order.
    LegacyConfirm { agreed: Agreed, mconfirm: Option<Key> },
    LegacyRandom { agreed: Agreed, mconfirm: Key, tk: Option<Key>, srand: Key, sconfirm: Key },
    ScPublicKey { agreed: Agreed },
    /// Secure Connections passkey entry, round by round; Just Works is a
    /// single round without a passkey bit.
    ScConfirm { agreed: Agreed, keys: ScKeys, round: u8, ca: Option<Key> },
    ScRandom { agreed: Agreed, keys: ScKeys, round: u8, ca: Option<Key>, nb: Key },
    ScDhKeyCheck { agreed: Agreed, keys: ScKeys, na: Key, nb: Key },
    /// Waiting for LE Enable Encryption with this key.
    Encrypting { agreed: Agreed, key: Key, sc: bool },
    /// On the encrypted link: the host's keys still to come (PDU codes).
    Keys { awaited: Vec<u8> },
}

pub struct Smp {
    pub settings: Settings,
    state: State,
    /// The passkey the user typed, until a pairing has used it.
    passkey: Option<u32>,
    /// The bond of a pairing that got as far as the keys.
    bond: Option<Bond>,
    pub requests: u32,
    pub completed: u32,
    /// Pairings that failed, and the reason of the last one (as in Pairing
    /// Failed), whichever side gave up.
    pub failures: u32,
    pub last_failure: u8,
    /// PDUs for the host.
    pub out: Vec<Vec<u8>>,
}

fn pdu(code: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![code];
    p.extend_from_slice(body);
    p
}

impl Smp {
    pub fn new(settings: Settings) -> Self {
        Self { settings, state: State::Idle, passkey: None, bond: None, requests: 0, completed: 0, failures: 0, last_failure: 0, out: Vec::new() }
    }

    /// The link is gone: a pairing under way ends with it.
    pub fn reset(&mut self) {
        if !matches!(self.state, State::Idle) {
            note!("smp: the pairing ended with the link");
        }
        self.state = State::Idle;
        self.passkey = None;
        self.bond = None;
    }

    pub fn idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }

    /// The key a pairing under way expects in LE Enable Encryption (with
    /// EDIV and Rand zero): the short-term key, or the Secure Connections
    /// LTK.
    pub fn link_key(&self) -> Option<Key> {
        match &self.state {
            State::Encrypting { key, .. } => Some(*key),
            _ => None,
        }
    }

    /// The bond a finished pairing left, once.
    pub fn take_bond(&mut self) -> Option<Bond> {
        self.bond.take()
    }

    fn fail(&mut self, reason: u8) {
        note!("smp: pairing failed, reason {reason:#04x} (sent to the host)");
        self.out.push(vec![PAIRING_FAILED, reason]);
        self.failures += 1;
        self.last_failure = reason;
        self.state = State::Idle;
        self.passkey = None;
        self.bond = None;
    }

    /// The user typed these six digits on the keyboard, and Enter.
    pub fn enter_passkey(&mut self, passkey: u32, ends: &Ends) {
        note!("kbd: passkey {passkey:06} typed");
        self.passkey = Some(passkey);
        self.advance(ends);
    }

    /// One Security Manager PDU from the host. `accepting`: the keyboard
    /// is in pairing mode.
    pub fn from_host(&mut self, p: &[u8], accepting: bool, ends: &Ends) {
        let Some((&code, body)) = p.split_first() else { return };
        let state = core::mem::replace(&mut self.state, State::Idle);
        self.state = match (state, code) {
            (_, PAIRING_REQUEST) if body.len() == 6 => {
                self.requests += 1;
                self.passkey = None;
                match self.pairing_request(p.try_into().unwrap(), accepting) {
                    Ok(next) => next,
                    Err(reason) => return self.fail(reason),
                }
            }
            (state, PAIRING_FAILED) => {
                let reason = body.first().copied().unwrap_or(REASON_UNSPECIFIED);
                if !matches!(state, State::Idle) {
                    note!("smp: the host gave up the pairing, reason {reason:#04x}");
                    self.failures += 1;
                    self.last_failure = reason;
                    self.passkey = None;
                }
                State::Idle
            }
            (State::LegacyConfirm { agreed, mconfirm: None }, PAIRING_CONFIRM) if body.len() == 16 => {
                State::LegacyConfirm { agreed, mconfirm: Some(body.try_into().unwrap()) }
            }
            (State::LegacyRandom { agreed, mconfirm, tk, srand, sconfirm }, PAIRING_RANDOM) if body.len() == 16 => {
                let mrand: Key = body.try_into().unwrap();
                let inputs = legacy_inputs(&agreed, ends);
                let (tk, srand) = match tk {
                    Some(tk) if c1(&tk, &mrand, &inputs) == mconfirm => (tk, srand),
                    Some(_) => return self.fail(REASON_CONFIRM_VALUE_FAILED),
                    // The impostor: the host has shown its hand, so the
                    // passkey is one of a million, and the confirm value
                    // sent blindly opens to whatever fits it.
                    None => {
                        let Some(found) = (0..=999_999u32).find(|n| c1(&passkey_value(*n), &mrand, &inputs) == mconfirm) else {
                            return self.fail(REASON_CONFIRM_VALUE_FAILED);
                        };
                        note!("smp: impostor: the passkey is {found:06}, worked out from the host's confirm and random values");
                        let tk = passkey_value(found);
                        (tk, c1_inverse(&tk, &sconfirm, &inputs))
                    }
                };
                self.out.push(pdu(PAIRING_RANDOM, &srand));
                let stk = shortened(s1(&tk, &srand, &mrand), agreed.key_size);
                note!("smp: legacy pairing: confirm values match; waiting for encryption with the short-term key");
                State::Encrypting { agreed, key: stk, sc: false }
            }
            (State::ScPublicKey { agreed }, PAIRING_PUBLIC_KEY) if body.len() == 64 => {
                let (x, y): ([u8; 32], [u8; 32]) = (body[..32].try_into().unwrap(), body[32..].try_into().unwrap());
                let pair = KeyPair::generate();
                let Some(dh_key) = pair.dh_key(&x, &y) else {
                    note!("smp: the host's public key isn't on the curve");
                    return self.fail(REASON_DHKEY_CHECK_FAILED);
                };
                let mut body = pair.x.to_vec();
                body.extend_from_slice(&pair.y);
                self.out.push(pdu(PAIRING_PUBLIC_KEY, &body));
                State::ScConfirm { agreed, keys: ScKeys { pair, host_x: x, dh_key }, round: 0, ca: None }
            }
            (State::ScConfirm { agreed, keys, round, ca: None }, PAIRING_CONFIRM) if body.len() == 16 && agreed.passkey_entry => {
                State::ScConfirm { agreed, keys, round, ca: Some(body.try_into().unwrap()) }
            }
            (State::ScRandom { agreed, keys, round, ca, nb }, PAIRING_RANDOM) if body.len() == 16 => {
                let na: Key = body.try_into().unwrap();
                if let Some(ca) = ca {
                    let bit = 0x80 | ((self.passkey.unwrap_or(0) >> round) & 1) as u8;
                    if f4(&keys.host_x, &keys.pair.x, &na, bit) != ca {
                        note!("smp: round {} of 20: the host's confirm value doesn't fit this passkey bit", round + 1);
                        return self.fail(REASON_CONFIRM_VALUE_FAILED);
                    }
                }
                self.out.push(pdu(PAIRING_RANDOM, &nb));
                if agreed.passkey_entry && round < 19 {
                    State::ScConfirm { agreed, keys, round: round + 1, ca: None }
                } else {
                    State::ScDhKeyCheck { agreed, keys, na, nb }
                }
            }
            (State::ScDhKeyCheck { agreed, keys, na, nb }, PAIRING_DHKEY_CHECK) if body.len() == 16 => {
                let (a, b) = (address56(ends.host_type, &ends.host), address56(ends.kbd_type, &ends.kbd));
                let (mac_key, ltk) = f5(&keys.dh_key, &na, &nb, &a, &b);
                let r = if agreed.passkey_entry { passkey_value(self.passkey.unwrap_or(0)) } else { [0; 16] };
                let io_cap = |p: &[u8; 7]| [p[3], p[2], p[1]];
                let ea: Key = body.try_into().unwrap();
                if f6(&mac_key, &na, &nb, &r, &io_cap(&agreed.preq), &a, &b) != ea {
                    return self.fail(REASON_DHKEY_CHECK_FAILED);
                }
                self.out.push(pdu(PAIRING_DHKEY_CHECK, &f6(&mac_key, &nb, &na, &r, &io_cap(&agreed.pres), &b, &a)));
                note!("smp: Secure Connections: both key checks match; waiting for encryption with the new key");
                State::Encrypting { agreed, key: shortened(ltk, agreed.key_size), sc: true }
            }
            (State::Keys { mut awaited }, code) if awaited.first() == Some(&code) => {
                awaited.remove(0);
                if awaited.is_empty() {
                    self.finished();
                    State::Idle
                } else {
                    State::Keys { awaited }
                }
            }
            (State::Idle, code) => {
                note!("smp: code {code:#04x} from the host outside a pairing: ignored");
                State::Idle
            }
            (_, code) => {
                note!("smp: code {code:#04x} ({} bytes) doesn't fit the pairing's state", body.len());
                return self.fail(REASON_UNSPECIFIED);
            }
        };
        self.advance(ends);
    }

    fn pairing_request(&mut self, preq: [u8; 7], accepting: bool) -> Result<State, u8> {
        let s = self.settings;
        let (io, auth, max_key) = (preq[1], preq[3], preq[4]);
        if s.method == Method::None || !accepting {
            note!("smp: Pairing Request refused: the keyboard isn't in pairing mode");
            return Err(REASON_PAIRING_NOT_SUPPORTED);
        }
        let key_size = max_key.min(s.max_key_size);
        if !(7..=16).contains(&key_size) {
            return Err(REASON_ENCRYPTION_KEY_SIZE);
        }
        let sc = s.method == Method::SecureConnections && auth & AUTH_SC != 0;
        // Who shows and who types (Vol 3, Part H, 2.3.5.1): a keyboard
        // types what a host with a display shows; a keyboard without keys
        // for it (or an impostor that says so) gets Just Works.
        let host_shows = matches!(io, IO_DISPLAY_ONLY | IO_DISPLAY_YES_NO | IO_KEYBOARD_DISPLAY);
        let mitm = s.io != IO_NO_INPUT_NO_OUTPUT;
        let passkey_entry = s.io == IO_KEYBOARD_ONLY && host_shows && (mitm || auth & AUTH_MITM != 0);
        if s.io == IO_KEYBOARD_ONLY && !host_shows && auth & AUTH_MITM != 0 && io == IO_KEYBOARD_ONLY {
            // Both would type: not something this keyboard is asked to do.
            return Err(REASON_AUTHENTICATION_REQUIREMENTS);
        }
        let bonding = auth & AUTH_BONDING != 0;
        let our_auth = if bonding { AUTH_BONDING } else { 0 } | if mitm { AUTH_MITM } else { 0 } | if sc { AUTH_SC } else { 0 };
        let pres = [PAIRING_RESPONSE, s.io, 0x00, our_auth, s.max_key_size, preq[5] & s.key_dist.0, preq[6] & s.key_dist.1];
        self.out.push(pres.to_vec());
        let agreed = Agreed { preq, pres, key_size, passkey_entry, bonding };
        note!(
            "smp: Pairing Request (IO {io:#04x}, AuthReq {auth:#04x}): answering with {} and {}",
            if sc { "Secure Connections" } else { "legacy pairing" },
            if passkey_entry { "passkey entry" } else { "Just Works" }
        );
        Ok(if sc { State::ScPublicKey { agreed } } else { State::LegacyConfirm { agreed, mconfirm: None } })
    }

    /// Whatever the keyboard can do by itself now: answer a confirm value
    /// once the passkey has been typed.
    fn advance(&mut self, ends: &Ends) {
        let state = core::mem::replace(&mut self.state, State::Idle);
        self.state = match state {
            State::LegacyConfirm { agreed, mconfirm: Some(mconfirm) } => {
                let tk = match (agreed.passkey_entry, self.settings.impostor, self.passkey) {
                    (false, _, _) => Some(Some([0; 16])),
                    (true, true, _) => Some(None),
                    (true, false, Some(passkey)) => Some(Some(passkey_value(passkey))),
                    (true, false, None) => None,
                };
                match tk {
                    None => State::LegacyConfirm { agreed, mconfirm: Some(mconfirm) },
                    Some(tk) => {
                        let srand: Key = random();
                        // Without the temporary key there is nothing to
                        // compute: any value will do for now.
                        let sconfirm = tk.map_or_else(random, |tk| c1(&tk, &srand, &legacy_inputs(&agreed, ends)));
                        self.out.push(pdu(PAIRING_CONFIRM, &sconfirm));
                        State::LegacyRandom { agreed, mconfirm, tk, srand, sconfirm }
                    }
                }
            }
            State::ScConfirm { agreed, keys, round, ca } => {
                let ready = if agreed.passkey_entry { ca.is_some() && self.passkey.is_some() } else { true };
                if !ready {
                    State::ScConfirm { agreed, keys, round, ca }
                } else {
                    let nb: Key = random();
                    let z = if agreed.passkey_entry { 0x80 | ((self.passkey.unwrap_or(0) >> round) & 1) as u8 } else { 0 };
                    self.out.push(pdu(PAIRING_CONFIRM, &f4(&keys.pair.x, &keys.host_x, &nb, z)));
                    State::ScRandom { agreed, keys, round, ca, nb }
                }
            }
            other => other,
        };
    }

    /// The controller reports the link encrypted with [`Smp::link_key`]:
    /// the keys follow, the keyboard's first.
    pub fn encrypted(&mut self, ends: &Ends) {
        let State::Encrypting { agreed, key, sc } = core::mem::replace(&mut self.state, State::Idle) else { return };
        let (from_host, from_kbd) = agreed.dist();
        if !agreed.bonding {
            note!("smp: paired without bonding: no keys are kept");
            self.finished();
            return;
        }
        if sc {
            self.bond = Some(Bond { ediv: 0, rand: [0; 8], ltk: key });
        } else if from_kbd & DIST_ENC != 0 {
            let bond = Bond { ediv: u16::from_le_bytes(random()), rand: random(), ltk: shortened(random(), agreed.key_size) };
            self.out.push(pdu(ENCRYPTION_INFORMATION, &bond.ltk));
            let mut id = bond.ediv.to_le_bytes().to_vec();
            id.extend_from_slice(&bond.rand);
            self.out.push(pdu(CENTRAL_IDENTIFICATION, &id));
            self.bond = Some(bond);
        }
        if from_kbd & DIST_ID != 0 {
            self.out.push(pdu(IDENTITY_INFORMATION, &random::<16>()));
            let mut id = vec![ends.kbd_type];
            id.extend_from_slice(&ends.kbd);
            self.out.push(pdu(IDENTITY_ADDRESS_INFORMATION, &id));
        }
        let mut awaited = Vec::new();
        if !sc && from_host & DIST_ENC != 0 {
            awaited.extend_from_slice(&[ENCRYPTION_INFORMATION, CENTRAL_IDENTIFICATION]);
        }
        if from_host & DIST_ID != 0 {
            awaited.extend_from_slice(&[IDENTITY_INFORMATION, IDENTITY_ADDRESS_INFORMATION]);
        }
        if awaited.is_empty() {
            self.finished();
        } else {
            self.state = State::Keys { awaited };
        }
    }

    fn finished(&mut self) {
        self.completed += 1;
        self.passkey = None;
        note!("smp: pairing complete{}", if self.bond.is_some() { "; the keyboard remembers the new bond" } else { "" });
    }
}

fn legacy_inputs(agreed: &Agreed, ends: &Ends) -> LegacyInputs {
    LegacyInputs {
        preq: agreed.preq,
        pres: agreed.pres,
        initiator_type: ends.host_type,
        initiator: ends.host,
        responder_type: ends.kbd_type,
        responder: ends.kbd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 128 bits written as in the specification (most significant first),
    /// as the array the functions take.
    fn k(hex: &str) -> Key {
        reversed(be(hex))
    }

    fn be<const N: usize>(hex: &str) -> [u8; N] {
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex.len(), 2 * N, "{hex}");
        core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The sample data of Vol 3, Part H, 2.2.3.
    fn sample_inputs() -> LegacyInputs {
        LegacyInputs {
            preq: reversed(be("07071000000101")),
            pres: reversed(be("05000800000302")),
            initiator_type: 1,
            initiator: reversed(be("A1A2A3A4A5A6")),
            responder_type: 0,
            responder: reversed(be("B1B2B3B4B5B6")),
        }
    }

    #[test]
    fn c1_matches_the_specification() {
        let r = k("5783D52156AD6F0E6388274EC6702EE0");
        let confirm = c1(&[0; 16], &r, &sample_inputs());
        assert_eq!(confirm, k("1e1e3fef878988ead2a74dc5bef13b86"));
        // And backwards: the random value for a given confirm value.
        assert_eq!(c1_inverse(&[0; 16], &confirm, &sample_inputs()), r);
    }

    #[test]
    fn s1_matches_the_specification() {
        let (r1, r2) = (k("000F0E0D0C0B0A091122334455667788"), k("010203040506070899AABBCCDDEEFF00"));
        assert_eq!(s1(&[0; 16], &r1, &r2), k("9a1fe1f0e8b0f49b5b4216ae796da062"));
    }

    // The Secure Connections sample data of Vol 3, Part H, Appendix D.
    const PRIVATE_A: &str = "3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd";
    const PRIVATE_B: &str = "55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd";
    const PUBLIC_A_X: &str = "20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6";
    const PUBLIC_A_Y: &str = "dc809c49 652aeb6d 63329abf 5a52155c 766345c2 8fed3024 741c8ed0 1589d28b";
    const PUBLIC_B_X: &str = "1ea1f0f0 1faf1d96 09592284 f19e4c00 47b58afd 8615a69f 559077b2 2faaa190";
    const PUBLIC_B_Y: &str = "4c55f33e 429dad37 7356703a 9ab85160 472d1130 e28e3676 5f89aff9 15b1214a";
    const DHKEY: &str = "ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698";
    const N1: &str = "d5cb8454d177733effffb2ec712baeab";
    const N2: &str = "a6e8e7cc25a75f6e216583f7ff3dc4cf";
    const MAC_KEY: &str = "2965f176a1084a02fd3f6a20ce636e20";

    #[test]
    fn p256_matches_the_specification() {
        let a = KeyPair::from_secret(SecretKey::from_slice(&be::<32>(PRIVATE_A)).unwrap());
        let b = KeyPair::from_secret(SecretKey::from_slice(&be::<32>(PRIVATE_B)).unwrap());
        assert_eq!((a.x, a.y), (reversed(be(PUBLIC_A_X)), reversed(be(PUBLIC_A_Y))));
        assert_eq!((b.x, b.y), (reversed(be(PUBLIC_B_X)), reversed(be(PUBLIC_B_Y))));
        assert_eq!(a.dh_key(&b.x, &b.y), Some(be(DHKEY)));
        assert_eq!(b.dh_key(&a.x, &a.y), Some(be(DHKEY)));
        // A point that isn't on the curve is refused.
        let mut off = b.y;
        off[0] ^= 1;
        assert_eq!(a.dh_key(&b.x, &off), None);
    }

    #[test]
    fn f4_matches_the_specification() {
        let u: [u8; 32] = reversed(be(PUBLIC_A_X));
        let v: [u8; 32] = reversed(be(PRIVATE_B));
        assert_eq!(f4(&u, &v, &k(N1), 0x00), k("f2c916f107a9bd1cf1eda1bea974872d"));
        // The passkey bit goes into the value.
        assert_ne!(f4(&u, &v, &k(N1), 0x80), f4(&u, &v, &k(N1), 0x81));
    }

    #[test]
    fn f5_and_f6_match_the_specification() {
        let (a1, a2): ([u8; 7], [u8; 7]) = (be("0056123737bfce"), be("00a713702dcfc1"));
        let (mac_key, ltk) = f5(&be(DHKEY), &k(N1), &k(N2), &a1, &a2);
        assert_eq!(mac_key, k(MAC_KEY));
        assert_eq!(ltk, k("6986791169d7cd23980522b594750a38"));
        let r = k("12a3343bb453bb5408da42d20c2d0fc8");
        assert_eq!(f6(&k(MAC_KEY), &k(N1), &k(N2), &r, &[0x01, 0x01, 0x02], &a1, &a2), k("e3c473989cd0e8c5d26c0b09da958f61"));
        assert_eq!(address56(0, &reversed(be("56123737bfce"))), a1);
    }

    // ----- The responder against an initiator written here ----------------

    const ENDS: Ends = Ends { host_type: 0, host: [0x02, 0, 0, 0, 0, 0x02], kbd_type: 1, kbd: [0x01, 0, 0, 0, 0, 0xC0] };
    /// Display only, bonding, MITM, Secure Connections; all keys.
    const PREQ: [u8; 7] = [PAIRING_REQUEST, IO_DISPLAY_ONLY, 0, AUTH_BONDING | AUTH_MITM | AUTH_SC, 16, 0x03, 0x03];

    fn sent(smp: &mut Smp) -> Vec<Vec<u8>> {
        core::mem::take(&mut smp.out)
    }

    fn one(smp: &mut Smp, code: u8) -> Vec<u8> {
        let out = sent(smp);
        assert_eq!(out.len(), 1, "{out:02x?}");
        assert_eq!(out[0][0], code, "{out:02x?}");
        out[0][1..].to_vec()
    }

    fn key(body: &[u8]) -> Key {
        body.try_into().unwrap()
    }

    /// The initiator's side of a legacy pairing up to the short-term key.
    fn legacy_until_stk(smp: &mut Smp, shown: u32, typed: Option<u32>) -> Result<Key, u8> {
        smp.from_host(&PREQ, true, &ENDS);
        let pres: [u8; 7] = sent(smp)[0].clone().try_into().unwrap();
        assert_eq!(pres, [PAIRING_RESPONSE, IO_KEYBOARD_ONLY, 0, AUTH_BONDING | AUTH_MITM, 16, 0x03, 0x03]);
        let inputs = LegacyInputs { preq: PREQ, pres, initiator_type: 0, initiator: ENDS.host, responder_type: 1, responder: ENDS.kbd };
        let (tk, mrand) = (passkey_value(shown), [0x5A; 16]);
        smp.from_host(&pdu(PAIRING_CONFIRM, &c1(&tk, &mrand, &inputs)), true, &ENDS);
        if let Some(typed) = typed {
            // The keyboard waits for its user.
            assert!(smp.out.is_empty());
            smp.enter_passkey(typed, &ENDS);
        }
        let sconfirm = key(&one(smp, PAIRING_CONFIRM));
        smp.from_host(&pdu(PAIRING_RANDOM, &mrand), true, &ENDS);
        let out = sent(smp);
        if out[0][0] == PAIRING_FAILED {
            return Err(out[0][1]);
        }
        let srand = key(&out[0][1..]);
        // What the host checks before it goes on.
        if c1(&tk, &srand, &inputs) != sconfirm {
            return Err(REASON_CONFIRM_VALUE_FAILED);
        }
        Ok(s1(&tk, &srand, &mrand))
    }

    #[test]
    fn legacy_passkey_entry_and_its_keys() {
        let mut smp = Smp::new(Settings::default());
        let stk = legacy_until_stk(&mut smp, 123_456, Some(123_456)).unwrap();
        assert_eq!(smp.link_key(), Some(stk));
        smp.encrypted(&ENDS);
        let out = sent(&mut smp);
        let codes: Vec<u8> = out.iter().map(|p| p[0]).collect();
        assert_eq!(codes, [ENCRYPTION_INFORMATION, CENTRAL_IDENTIFICATION, IDENTITY_INFORMATION, IDENTITY_ADDRESS_INFORMATION]);
        assert_eq!(out[3][1..], [1, 0x01, 0, 0, 0, 0, 0xC0]);
        // The host's own keys, then the pairing is complete.
        for (code, len) in [(ENCRYPTION_INFORMATION, 16), (CENTRAL_IDENTIFICATION, 10), (IDENTITY_INFORMATION, 16)] {
            smp.from_host(&pdu(code, &vec![7; len]), true, &ENDS);
            assert_eq!(smp.completed, 0);
        }
        smp.from_host(&pdu(IDENTITY_ADDRESS_INFORMATION, &[0, 2, 0, 0, 0, 0, 2]), true, &ENDS);
        assert_eq!((smp.completed, smp.failures), (1, 0));
        let bond = smp.take_bond().unwrap();
        assert_eq!(bond.ltk, key(&out[0][1..]));
        assert_eq!((bond.ediv.to_le_bytes(), bond.rand), ([out[1][1], out[1][2]], out[1][3..11].try_into().unwrap()));
        assert!(smp.idle() && smp.link_key().is_none());
    }

    #[test]
    fn a_wrong_passkey_fails_the_legacy_pairing() {
        let mut smp = Smp::new(Settings::default());
        assert_eq!(legacy_until_stk(&mut smp, 123_456, Some(123_457)), Err(REASON_CONFIRM_VALUE_FAILED));
        assert_eq!((smp.failures, smp.last_failure), (1, REASON_CONFIRM_VALUE_FAILED));
        assert!(smp.idle());
    }

    #[test]
    fn an_impostor_pairs_without_the_passkey() {
        // Nobody types anything: the "keyboard" works the passkey out.
        let mut smp = Smp::new(Settings { impostor: true, ..Settings::default() });
        let stk = legacy_until_stk(&mut smp, 271_828, None).unwrap();
        assert_eq!(smp.link_key(), Some(stk));
    }

    #[test]
    fn no_pairing_outside_pairing_mode_or_without_support() {
        let mut smp = Smp::new(Settings::default());
        smp.from_host(&PREQ, false, &ENDS);
        assert_eq!(sent(&mut smp), [vec![PAIRING_FAILED, REASON_PAIRING_NOT_SUPPORTED]]);
        let mut smp = Smp::new(Settings { method: Method::None, ..Settings::default() });
        smp.from_host(&PREQ, true, &ENDS);
        assert_eq!(sent(&mut smp), [vec![PAIRING_FAILED, REASON_PAIRING_NOT_SUPPORTED]]);
        assert_eq!((smp.requests, smp.failures), (1, 1));
        // A key size below what the specification allows.
        let mut smp = Smp::new(Settings { max_key_size: 6, ..Settings::default() });
        smp.from_host(&PREQ, true, &ENDS);
        assert_eq!(sent(&mut smp), [vec![PAIRING_FAILED, REASON_ENCRYPTION_KEY_SIZE]]);
    }

    #[test]
    fn a_keyboard_without_keys_gets_just_works() {
        let mut smp = Smp::new(Settings { io: IO_NO_INPUT_NO_OUTPUT, ..Settings::default() });
        smp.from_host(&PREQ, true, &ENDS);
        let pres = sent(&mut smp)[0].clone();
        // No MITM flag: nothing is authenticated.
        assert_eq!(pres[..4], [PAIRING_RESPONSE, IO_NO_INPUT_NO_OUTPUT, 0, AUTH_BONDING]);
        let inputs = LegacyInputs { preq: PREQ, pres: pres.try_into().unwrap(), initiator_type: 0, initiator: ENDS.host, responder_type: 1, responder: ENDS.kbd };
        let mrand = [3; 16];
        smp.from_host(&pdu(PAIRING_CONFIRM, &c1(&[0; 16], &mrand, &inputs)), true, &ENDS);
        // At once: there is nothing to type.
        let sconfirm = key(&one(&mut smp, PAIRING_CONFIRM));
        smp.from_host(&pdu(PAIRING_RANDOM, &mrand), true, &ENDS);
        let srand = key(&one(&mut smp, PAIRING_RANDOM));
        assert_eq!(c1(&[0; 16], &srand, &inputs), sconfirm);
        assert_eq!(smp.link_key(), Some(s1(&[0; 16], &srand, &mrand)));
    }

    /// The initiator's side of Secure Connections passkey entry.
    fn secure_connections(smp: &mut Smp, shown: u32, typed: u32) -> Result<Key, u8> {
        smp.from_host(&PREQ, true, &ENDS);
        let pres: [u8; 7] = sent(smp)[0].clone().try_into().unwrap();
        assert_eq!(pres[3], AUTH_BONDING | AUTH_MITM | AUTH_SC);
        let host = KeyPair::generate();
        let mut body = host.x.to_vec();
        body.extend_from_slice(&host.y);
        smp.from_host(&pdu(PAIRING_PUBLIC_KEY, &body), true, &ENDS);
        let theirs = one(smp, PAIRING_PUBLIC_KEY);
        let (kx, ky): ([u8; 32], [u8; 32]) = (theirs[..32].try_into().unwrap(), theirs[32..].try_into().unwrap());
        let dh_key = host.dh_key(&kx, &ky).unwrap();
        let (mut na, mut nb) = ([0; 16], [0; 16]);
        for round in 0..20u8 {
            let bit = 0x80 | ((shown >> round) & 1) as u8;
            na = [round + 1; 16];
            smp.from_host(&pdu(PAIRING_CONFIRM, &f4(&host.x, &kx, &na, bit)), true, &ENDS);
            if round == 0 {
                assert!(smp.out.is_empty());
                smp.enter_passkey(typed, &ENDS);
            }
            let cb = key(&one(smp, PAIRING_CONFIRM));
            smp.from_host(&pdu(PAIRING_RANDOM, &na), true, &ENDS);
            let out = sent(smp);
            if out[0][0] == PAIRING_FAILED {
                return Err(out[0][1]);
            }
            nb = key(&out[0][1..]);
            if f4(&kx, &host.x, &nb, bit) != cb {
                return Err(REASON_CONFIRM_VALUE_FAILED);
            }
        }
        let (a, b) = (address56(0, &ENDS.host), address56(1, &ENDS.kbd));
        let (mac_key, ltk) = f5(&dh_key, &na, &nb, &a, &b);
        let r = passkey_value(shown);
        smp.from_host(&pdu(PAIRING_DHKEY_CHECK, &f6(&mac_key, &na, &nb, &r, &[PREQ[3], PREQ[2], PREQ[1]], &a, &b)), true, &ENDS);
        let eb = key(&one(smp, PAIRING_DHKEY_CHECK));
        assert_eq!(eb, f6(&mac_key, &nb, &na, &r, &[pres[3], pres[2], pres[1]], &b, &a));
        Ok(ltk)
    }

    #[test]
    fn secure_connections_passkey_entry_and_its_keys() {
        let mut smp = Smp::new(Settings { method: Method::SecureConnections, ..Settings::default() });
        let ltk = secure_connections(&mut smp, 987_654, 987_654).unwrap();
        assert_eq!(smp.link_key(), Some(ltk));
        smp.encrypted(&ENDS);
        // No key travels: only the keyboard's identity.
        let codes: Vec<u8> = sent(&mut smp).iter().map(|p| p[0]).collect();
        assert_eq!(codes, [IDENTITY_INFORMATION, IDENTITY_ADDRESS_INFORMATION]);
        smp.from_host(&pdu(IDENTITY_INFORMATION, &[7; 16]), true, &ENDS);
        smp.from_host(&pdu(IDENTITY_ADDRESS_INFORMATION, &[0, 2, 0, 0, 0, 0, 2]), true, &ENDS);
        assert_eq!(smp.completed, 1);
        assert_eq!(smp.take_bond(), Some(Bond { ediv: 0, rand: [0; 8], ltk }));
    }

    #[test]
    fn a_wrong_passkey_fails_secure_connections_at_the_first_wrong_bit() {
        let mut smp = Smp::new(Settings { method: Method::SecureConnections, ..Settings::default() });
        // 987654 and 987650 differ in bit 2: rounds 1 and 2 pass.
        assert_eq!(secure_connections(&mut smp, 987_654, 987_650), Err(REASON_CONFIRM_VALUE_FAILED));
        assert_eq!(smp.failures, 1);
    }

    #[test]
    fn a_legacy_host_gets_legacy_pairing_from_a_secure_connections_keyboard() {
        let mut smp = Smp::new(Settings { method: Method::SecureConnections, ..Settings::default() });
        let mut preq = PREQ;
        preq[3] = AUTH_BONDING | AUTH_MITM;
        smp.from_host(&preq, true, &ENDS);
        assert_eq!(sent(&mut smp)[0][3], AUTH_BONDING | AUTH_MITM);
    }

    #[test]
    fn the_host_gives_up() {
        let mut smp = Smp::new(Settings::default());
        smp.from_host(&PREQ, true, &ENDS);
        sent(&mut smp);
        smp.from_host(&[PAIRING_FAILED, REASON_AUTHENTICATION_REQUIREMENTS], true, &ENDS);
        assert!(smp.idle() && smp.out.is_empty());
        assert_eq!((smp.failures, smp.last_failure), (1, REASON_AUTHENTICATION_REQUIREMENTS));
    }
}
