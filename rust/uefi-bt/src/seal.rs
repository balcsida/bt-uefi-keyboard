//! The bond sealed to the TPM (stage 4 of the security hardening; README,
//! Security): `scripts/tpm-seal.sh` seals the bond's 42-byte record
//! ([`crate::bond::ExportedBond::record`]) under the storage root key with
//! a PCR policy, and writes `bt-kb-dxe.sealed`; the driver unseals it here.
//!
//! - **Policy:** PolicyPCR over the PCRs the file lists, with the values
//!   they have while the driver runs. The seal script picks them so the OS
//!   never sees those values (PCR 2 and 7 before their separators, and a
//!   spare PCR the driver extends right after unsealing).
//! - **Session:** a policy session salted with an ECDH secret for the
//!   storage root key (P-256), so someone reading the TPM's bus can't
//!   derive the session key; Unseal's answer comes back XOR-encrypted
//!   with it and its HMAC is checked.
//! - **Cleanup:** what the TPM loaded is flushed on every path; buffers
//!   that held the key or the session secrets are wiped.

use alloc::string::String;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, FieldBytes, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::rng::Rng;
use crate::tpm2::{self, Error, Tpm};

pub const MAGIC: &str = "bt-kb-dxe sealed bond v1";

/// A sealed bond as `bt-kb-dxe.sealed` holds it. Nothing in it is secret;
/// nothing in it needs to be trusted either: the TPM checks the policy,
/// and the unsealed record must still be a bond the driver was built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The storage key it's sealed under (0x81000001).
    pub parent: u32,
    /// That key's name when sealed, to tell a cleared TPM apart.
    pub srk_name: Option<Vec<u8>>,
    /// PCRs in the policy (bit n: PCR n), SHA-256 bank.
    pub pcrs: u32,
    /// The values the policy expects, per PCR, in PCR order.
    pub expected: Vec<(u32, [u8; 32])>,
    /// Whether the driver may keep a copy in its boot-services-only
    /// variable (stage 3) for when unsealing fails.
    pub fallback: bool,
    /// TPM2B_PUBLIC and TPM2B_PRIVATE as tpm2_create writes them.
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// A PCR list such as "2,7,8" as a bitmap of PCRs 0–23.
pub fn parse_pcr_list(s: &str) -> Option<u32> {
    let mut bits = 0u32;
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let n: u32 = part.parse().ok()?;
        if n > 23 {
            return None;
        }
        bits |= 1 << n;
    }
    (bits != 0).then_some(bits)
}

impl Sealed {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(MAGIC) {
            return Err("not a sealed bond file (bad first line)");
        }
        let (mut parent, mut srk_name, mut pcrs, mut fallback) = (tpm2::SRK_HANDLE, None, None, true);
        let (mut public, mut private, mut values) = (None, None, Vec::new());
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or("a line without '='")?;
            match key.trim() {
                "parent" => {
                    let v = value.trim().trim_start_matches("0x");
                    parent = u32::from_str_radix(v, 16).map_err(|_| "bad parent handle")?;
                }
                "srk_name" => srk_name = Some(unhex(value).ok_or("bad srk_name")?),
                "pcrs" => pcrs = Some(parse_pcr_list(value).ok_or("bad pcrs")?),
                "fallback" => {
                    fallback = match value.trim() {
                        "yes" => true,
                        "no" => false,
                        _ => return Err("fallback must be yes or no"),
                    }
                }
                "public" => public = Some(unhex(value).ok_or("bad public")?),
                "private" => private = Some(unhex(value).ok_or("bad private")?),
                k if k.starts_with("pcr") => {
                    let n: u32 = k[3..].parse().map_err(|_| "bad pcrN key")?;
                    let v: [u8; 32] = unhex(value).and_then(|v| v.try_into().ok()).ok_or("a PCR value isn't 32 bytes of hex")?;
                    values.push((n, v));
                }
                _ => {}
            }
        }
        let pcrs = pcrs.ok_or("no pcrs line")?;
        let (public, private) = (public.ok_or("no public line")?, private.ok_or("no private line")?);
        for blob in [&public, &private] {
            if blob.len() < 2 || usize::from(u16::from_be_bytes([blob[0], blob[1]])) != blob.len() - 2 {
                return Err("public or private isn't a TPM2B");
            }
        }
        values.retain(|(n, _)| pcrs & (1 << n) != 0);
        values.sort_by_key(|(n, _)| *n);
        values.dedup_by_key(|(n, _)| *n);
        Ok(Self { parent, srk_name, pcrs, expected: values, fallback, public, private })
    }

    /// SHA-256 of the expected PCR values in PCR order (PolicyPCR's
    /// pcrDigest), or empty unless the file has a value for every PCR in
    /// the policy.
    pub fn expected_digest(&self) -> Vec<u8> {
        if self.expected.len() as u32 != self.pcrs.count_ones() {
            return Vec::new();
        }
        let mut h = Sha256::new();
        self.expected.iter().for_each(|(_, v)| h.update(v));
        h.finalize().to_vec()
    }
}

/// The policy digest of a lone TPM2_PolicyPCR over `pcrs` with `values`
/// (in PCR order): what the sealed object's authPolicy must be.
pub fn policy_pcr_digest(pcrs: u32, values: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    values.iter().for_each(|v| h.update(v));
    let pcr_digest = h.finalize();
    let [a, b, c, _] = pcrs.to_le_bytes();
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(tpm2::TPM_CC_POLICY_PCR.to_be_bytes());
    h.update(1u32.to_be_bytes());
    h.update(tpm2::TPM_ALG_SHA256.to_be_bytes());
    h.update([3, a, b, c]);
    h.update(pcr_digest);
    h.finalize().into()
}

/// The name of an object with SHA-256 as its name algorithm: the
/// algorithm, then the hash of its public area (TPMT_PUBLIC).
pub fn name_of(area: &[u8]) -> Vec<u8> {
    let mut name = Vec::from(tpm2::TPM_ALG_SHA256.to_be_bytes());
    name.extend_from_slice(&Sha256::digest(area));
    name
}

/// KDFa (TPM 2.0 part 1, 11.4.10.2) with HMAC-SHA256: SP 800-108 in
/// counter mode; the label gets its terminating zero here.
pub fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32) -> Zeroizing<Vec<u8>> {
    let len = bits.div_ceil(8) as usize;
    let mut out = Zeroizing::new(Vec::with_capacity(len + 32));
    let mut counter = 1u32;
    while out.len() < len {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key size");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// KDFe (part 1, 11.4.10.3) with SHA-256: the concatenation KDF of SP
/// 800-56A over the shared point's x and the label with its zero.
pub fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8], bits: u32) -> Zeroizing<Vec<u8>> {
    let len = bits.div_ceil(8) as usize;
    let mut out = Zeroizing::new(Vec::with_capacity(len + 32));
    let mut counter = 1u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(counter.to_be_bytes());
        h.update(z);
        h.update(label);
        h.update([0]);
        h.update(party_u);
        h.update(party_v);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn pad32(v: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let v = v.get(v.len().saturating_sub(32)..)?;
    out[32 - v.len()..].copy_from_slice(v);
    Some(out)
}

/// A salt for a session with the P-256 key at (`x`, `y`): the salt, and
/// the encrypted secret StartAuthSession takes (our ephemeral public
/// point, a TPMS_ECC_POINT).
pub fn ecdh_salt(x: &[u8], y: &[u8], rng: &mut Rng) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let (x, y) = (pad32(x)?, pad32(y)?);
    let point = EncodedPoint::from_affine_coordinates(&FieldBytes::from(x), &FieldBytes::from(y), false);
    let tpm_key = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))?;
    let ephemeral = loop {
        let mut bytes = rng.array::<32>();
        let key = SecretKey::from_slice(&bytes);
        bytes.zeroize();
        if let Ok(key) = key {
            break key;
        }
    };
    let shared = (tpm_key.to_projective() * *ephemeral.to_nonzero_scalar()).to_affine().to_encoded_point(false);
    let ours = ephemeral.public_key().to_encoded_point(false);
    let (z, ux, uy) = (shared.x()?, ours.x()?, ours.y()?);
    let salt = kdfe(z, b"SECRET", ux, &x, 256);
    let mut secret = Vec::with_capacity(68);
    for coordinate in [ux, uy] {
        secret.extend_from_slice(&32u16.to_be_bytes());
        secret.extend_from_slice(coordinate);
    }
    Some((salt, secret))
}

/// Why unsealing failed; [`UnsealError::reason`] is short enough for the
/// boot record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealError {
    /// No key at the parent handle (TPM cleared, or never set up).
    NoParent(Error),
    /// Another key than the one it was sealed under (TPM cleared?).
    ParentChanged,
    /// The parent isn't a P-256 key with SHA-256, which salting needs.
    ParentNotEcc,
    /// TPM2_Load refused the sealed object (damaged, or another TPM's).
    Load(Error),
    /// The loaded object isn't the one in the file.
    WrongObject,
    Session(Error),
    /// The PCRs aren't what the policy expects.
    PcrsChanged(Error),
    /// TPM2_Unseal refused it (the policy failed).
    Unseal(Error),
    /// The answer failed its HMAC check.
    Integrity,
}

impl UnsealError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoParent(_) => "no storage key at 0x81000001 (TPM cleared?)",
            Self::ParentChanged => "the storage key changed (TPM cleared?)",
            Self::ParentNotEcc => "the storage key isn't P-256",
            Self::Load(_) => "the TPM refused to load the sealed bond (damaged, or another TPM's)",
            Self::WrongObject => "the sealed bond's public part doesn't match",
            Self::Session(_) => "starting the TPM session failed",
            Self::PcrsChanged(_) => "the PCRs changed since sealing",
            Self::Unseal(e) if e.code() == Some(tpm2::TPM_RC_POLICY_FAIL) => "the TPM policy failed",
            Self::Unseal(_) => "the TPM refused to unseal",
            Self::Integrity => "the TPM's answer failed its integrity check",
        }
    }

    /// The TPM's response code, if the TPM answered with one.
    pub fn tpm_error(&self) -> Option<Error> {
        match *self {
            Self::NoParent(e) | Self::Load(e) | Self::Session(e) | Self::PcrsChanged(e) | Self::Unseal(e) => Some(e),
            _ => None,
        }
    }
}

/// The command HMAC for a session (part 1, 19.6.5): over the command's
/// cpHash (code, the names of the handles that need authorization, the
/// parameters), the new and old nonce and the attributes, keyed with the
/// session key (the entity's authValue isn't added: a policy session
/// without PolicyAuthValue, and an empty authValue anyway).
pub fn command_hmac(session_key: &[u8], code: u32, names: &[&[u8]], parameters: &[u8], nonce_caller: &[u8], nonce_tpm: &[u8], attributes: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(code.to_be_bytes());
    names.iter().for_each(|n| h.update(n));
    h.update(parameters);
    let cp_hash = h.finalize();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("HMAC takes any key size");
    mac.update(&cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[attributes]);
    mac.finalize().into_bytes().into()
}

/// What [`unseal`] got.
pub struct Unsealed {
    pub record: Zeroizing<Vec<u8>>,
    /// Whether the TPM's answer had an HMAC, and it was right. (A TPM
    /// that sends none isn't refused: the record still has to be a
    /// trusted bond, and nobody without the session key can decrypt it.)
    pub hmac_checked: bool,
}

/// Check Unseal's response HMAC, if there is one, and decrypt outData.
pub fn open_response(
    session_key: &[u8],
    response: &tpm2::UnsealResponse,
    nonce_caller: &[u8],
) -> Result<Unsealed, UnsealError> {
    let hmac_checked = !response.hmac.is_empty();
    if hmac_checked {
        let mut h = Sha256::new();
        h.update(0u32.to_be_bytes());
        h.update(tpm2::TPM_CC_UNSEAL.to_be_bytes());
        h.update(&response.parameters[..]);
        let rp_hash = h.finalize();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("HMAC takes any key size");
        mac.update(&rp_hash);
        mac.update(&response.nonce_tpm);
        mac.update(nonce_caller);
        mac.update(&[response.attributes]);
        mac.verify_slice(&response.hmac).map_err(|_| UnsealError::Integrity)?;
    }
    let mask = kdfa(session_key, b"XOR", &response.nonce_tpm, nonce_caller, response.data.len() as u32 * 8);
    let mut record = Zeroizing::new(response.data.to_vec());
    record.iter_mut().zip(mask.iter()).for_each(|(d, m)| *d ^= m);
    Ok(Unsealed { record, hmac_checked })
}

/// Unseal `sealed`: the record it holds, or why not.
pub fn unseal<T: Tpm + ?Sized>(tpm: &mut T, sealed: &Sealed, rng: &mut Rng) -> Result<Unsealed, UnsealError> {
    let (area, name) =
        tpm2::call(tpm, &tpm2::read_public(sealed.parent)).and_then(|r| tpm2::parse_read_public(&r)).map_err(UnsealError::NoParent)?;
    if sealed.srk_name.as_ref().is_some_and(|expected| *expected != name) {
        return Err(UnsealError::ParentChanged);
    }
    let parent = match tpm2::parse_ecc_public(&area) {
        Ok(Some(p)) if p.curve == tpm2::TPM_ECC_NIST_P256 && p.name_alg == tpm2::TPM_ALG_SHA256 => p,
        _ => return Err(UnsealError::ParentNotEcc),
    };
    let (object, object_name) = tpm2::call(tpm, &tpm2::load(sealed.parent, &sealed.private, &sealed.public))
        .and_then(|r| tpm2::parse_load(&r))
        .map_err(UnsealError::Load)?;
    let out = if object_name == name_of(&sealed.public[2..]) {
        unseal_loaded(tpm, sealed, rng, &parent, object, &object_name)
    } else {
        Err(UnsealError::WrongObject)
    };
    let _ = tpm2::call(tpm, &tpm2::flush_context(object));
    out
}

fn unseal_loaded<T: Tpm + ?Sized>(
    tpm: &mut T,
    sealed: &Sealed,
    rng: &mut Rng,
    parent: &tpm2::EccPublic,
    object: u32,
    object_name: &[u8],
) -> Result<Unsealed, UnsealError> {
    let nonce_caller = rng.array::<32>();
    let (salt, secret) = ecdh_salt(&parent.x, &parent.y, rng).ok_or(UnsealError::ParentNotEcc)?;
    let (session, nonce_tpm) = tpm2::call(tpm, &tpm2::start_policy_session(sealed.parent, &nonce_caller, &secret))
        .and_then(|r| tpm2::parse_start_auth_session(&r))
        .map_err(UnsealError::Session)?;
    let session_key = kdfa(&salt, b"ATH", &nonce_tpm, &nonce_caller, 256);
    drop(salt);
    let out = (|| {
        tpm2::call(tpm, &tpm2::policy_pcr(session, &sealed.expected_digest(), sealed.pcrs)).map_err(UnsealError::PcrsChanged)?;
        let nonce = rng.array::<32>();
        let hmac =
            command_hmac(&session_key, tpm2::TPM_CC_UNSEAL, &[object_name], &[], &nonce, &nonce_tpm, tpm2::TPMA_SESSION_ENCRYPT);
        let response = tpm2::call(tpm, &tpm2::unseal(object, session, &nonce, &hmac)).map_err(UnsealError::Unseal)?;
        let parsed = tpm2::parse_unseal(&response).map_err(UnsealError::Unseal)?;
        open_response(&session_key, &parsed, &nonce)
    })();
    // A successful Unseal ended the session (continueSession clear).
    if out.is_err() {
        let _ = tpm2::call(tpm, &tpm2::flush_context(session));
    }
    out
}

/// Hex, for logs and the seal metadata.
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    bytes.iter().for_each(|b| {
        let _ = write!(out, "{b:02x}");
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Expected values from independent implementations: Python's hmac and
    // hashlib for the KDFs, tpm2_policypcr (a trial session on swtpm) for
    // the policy digest.
    #[test]
    fn kdfa_known_answer() {
        let out = kdfa(&[1; 32], b"ATH", &[2; 32], &[3; 32], 256);
        assert_eq!(hex(&out), KDFA_ATH);
        // Longer than one block, and not a whole number of blocks.
        let out = kdfa(b"key", b"XOR", b"newer", b"older", 40 * 8);
        assert_eq!(hex(&out), KDFA_XOR_40);
    }

    #[test]
    fn kdfe_known_answer() {
        assert_eq!(hex(&kdfe(&[4; 32], b"SECRET", &[5; 32], &[6; 32], 256)), KDFE_SECRET);
    }

    const KDFA_ATH: &str = "d61e4115d0e81cb1945ebb5d9b419bee7a4ee232e491f18649e90032a4af1aaa";
    const KDFA_XOR_40: &str = "8dd417d98786df54565f5bab4e789dcd79f35aed2d3168343ea57eac5bf80195a536350ffad8ffa1";
    const KDFE_SECRET: &str = "5b6d662be122c1432e17d95d528b25c2c0b92c31cd24fc14021d0a1c6c399cba";

    #[test]
    fn the_tpm_derives_the_same_salt() {
        // The TPM's side: its private key times our point.
        let tpm_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let public = tpm_key.public_key().to_encoded_point(false);
        let mut rng = Rng::from_seed([9; 32]);
        let (salt, secret) = ecdh_salt(public.x().unwrap(), public.y().unwrap(), &mut rng).unwrap();
        assert_eq!((secret.len(), &secret[..2], &secret[34..36]), (68, &[0, 32][..], &[0, 32][..]));
        let ours = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&secret[2..34]),
            FieldBytes::from_slice(&secret[36..68]),
            false,
        );
        let ours = Option::<PublicKey>::from(PublicKey::from_encoded_point(&ours)).unwrap();
        let shared = (ours.to_projective() * *tpm_key.to_nonzero_scalar()).to_affine().to_encoded_point(false);
        let expected = kdfe(shared.x().unwrap(), b"SECRET", &secret[2..34], public.x().unwrap(), 256);
        assert_eq!(salt, expected);
        // Not a point on the curve.
        assert!(ecdh_salt(&[1; 32], &[2; 32], &mut rng).is_none());
    }

    #[test]
    fn policy_digest_and_names() {
        // One PolicyPCR over PCRs 2, 7 and 8, all zero.
        let d = policy_pcr_digest(1 << 2 | 1 << 7 | 1 << 8, &[[0; 32]; 3]);
        assert_eq!(hex(&d), POLICY_2_7_8_ZERO);
        let name = name_of(b"area");
        assert_eq!((name.len(), &name[..2]), (34, &[0x00, 0x0B][..]));
    }

    const POLICY_2_7_8_ZERO: &str = "d42c4b9209158081d9bae70d7bdc6c929fb6e3d13b122d7f112a3440ca0766c9";

    fn tpm2b(v: &[u8]) -> String {
        let mut b = Vec::from((v.len() as u16).to_be_bytes());
        b.extend_from_slice(v);
        hex(&b)
    }

    fn file(extra: &str) -> String {
        alloc::format!(
            "{MAGIC}\nparent=0x81000001\npcrs=2,7,8\npcr2={}\npcr7={}\npcr8={}\n{extra}public={}\nprivate={}\n",
            hex(&[2; 32]),
            hex(&[7; 32]),
            hex(&[0; 32]),
            tpm2b(b"pub"),
            tpm2b(b"priv")
        )
    }

    #[test]
    fn sealed_file() {
        let s = Sealed::parse(&file("fallback=no\n")).unwrap();
        assert_eq!((s.parent, s.pcrs, s.fallback), (0x8100_0001, 0x184, false));
        assert_eq!(s.expected.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![2, 7, 8]);
        assert_eq!((&s.public[2..], &s.private[2..]), (&b"pub"[..], &b"priv"[..]));
        let mut h = Sha256::new();
        h.update([2; 32]);
        h.update([7; 32]);
        h.update([0; 32]);
        assert_eq!(s.expected_digest(), h.finalize().to_vec());
        assert!(Sealed::parse(&file("")).unwrap().fallback);
        // Without a value for every PCR, PolicyPCR gets no digest to check.
        let partial = file("").replace(&alloc::format!("pcr8={}\n", hex(&[0; 32])), "");
        assert!(Sealed::parse(&partial).unwrap().expected_digest().is_empty());
        for bad in [
            file("").replace(MAGIC, "something else"),
            file("").replace("pcrs=2,7,8", "pcrs=2,7,99"),
            file("").replace("public=0003", "public=0009"),
            file("fallback=maybe\n"),
            file("").replace(&alloc::format!("pcr2={}", hex(&[2; 32])), "pcr2=1234"),
        ] {
            assert!(Sealed::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn response_hmac_and_decryption() {
        let key = [0x55; 32];
        let (nonce_tpm, nonce_caller) = (vec![0xAA; 32], [0xBB; 32]);
        let secret = b"a 42-byte record would be here ...........";
        let mask = kdfa(&key, b"XOR", &nonce_tpm, &nonce_caller, secret.len() as u32 * 8);
        let data: Vec<u8> = secret.iter().zip(mask.iter()).map(|(d, m)| d ^ m).collect();
        let mut parameters = Vec::from((data.len() as u16).to_be_bytes());
        parameters.extend_from_slice(&data);
        let mut h = Sha256::new();
        h.update(0u32.to_be_bytes());
        h.update(tpm2::TPM_CC_UNSEAL.to_be_bytes());
        h.update(&parameters);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&h.finalize());
        mac.update(&nonce_tpm);
        mac.update(&nonce_caller);
        mac.update(&[0x40]);
        let hmac = mac.finalize().into_bytes().to_vec();
        let mut response = tpm2::UnsealResponse {
            parameters: Zeroizing::new(parameters),
            data: Zeroizing::new(data),
            nonce_tpm,
            attributes: 0x40,
            hmac,
        };
        let opened = open_response(&key, &response, &nonce_caller).unwrap();
        assert_eq!((&opened.record[..], opened.hmac_checked), (&secret[..], true));
        // A flipped bit anywhere fails the check.
        response.parameters[5] ^= 1;
        assert_eq!(open_response(&key, &response, &nonce_caller).err(), Some(UnsealError::Integrity));
        response.parameters[5] ^= 1;
        response.attributes = 0x41;
        assert_eq!(open_response(&key, &response, &nonce_caller).err(), Some(UnsealError::Integrity));
        // No HMAC at all: decrypted, but reported as unchecked.
        response.attributes = 0x40;
        response.hmac.clear();
        assert!(!open_response(&key, &response, &nonce_caller).unwrap().hmac_checked);
    }

    #[test]
    fn pcr_lists() {
        assert_eq!(parse_pcr_list("2,7,8"), Some(0x184));
        assert_eq!(parse_pcr_list(" 7 "), Some(0x80));
        assert_eq!(parse_pcr_list(""), None);
        assert_eq!(parse_pcr_list("24"), None);
        assert_eq!(parse_pcr_list("x"), None);
    }
}
