//! TPM 2.0 commands, marshalled by hand for EFI_TCG2_PROTOCOL's
//! SubmitCommand: big-endian, header first (tag, size, command code),
//! and only what the driver needs: reading PCRs, and unsealing a sealed
//! object under the storage root key with a policy session
//! ([`crate::seal`]).

use alloc::vec;
use alloc::vec::Vec;

use zeroize::Zeroizing;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_UNSEAL: u32 = 0x0000_015E;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
pub const TPM_ALG_XOR: u16 = 0x000A;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
pub const TPM_SE_POLICY: u8 = 0x01;
/// TPMA_SESSION: encrypt the response's first parameter.
pub const TPMA_SESSION_ENCRYPT: u8 = 0x40;
/// The storage root key systemd (and `scripts/tpm-seal.sh`) keep here.
pub const SRK_HANDLE: u32 = 0x8100_0001;

/// Why a command didn't work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than its fields, or its size field disagrees.
    Malformed,
    /// The TPM's response code.
    Tpm(u32),
    /// The firmware's TPM interface (SubmitCommand) failed.
    Transport,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed TPM response"),
            Self::Tpm(rc) => write!(f, "TPM response code {rc:#06x}"),
            Self::Transport => write!(f, "the firmware couldn't reach the TPM"),
        }
    }
}

impl Error {
    /// The error number without the handle, session or parameter it
    /// refers to (format-one codes), e.g. TPM_RC_VALUE for any parameter.
    pub fn code(self) -> Option<u32> {
        match self {
            Self::Tpm(rc) if rc & 0x80 != 0 => Some(rc & 0xBF),
            Self::Tpm(rc) => Some(rc),
            _ => None,
        }
    }
}

/// TPM_RC_VALUE (format one): a parameter, such as PolicyPCR's expected
/// PCR digest, doesn't match.
pub const TPM_RC_VALUE: u32 = 0x0084;
/// TPM_RC_POLICY_FAIL (format one): the session's policy isn't the
/// object's.
pub const TPM_RC_POLICY_FAIL: u32 = 0x009D;
/// TPM_RC_HANDLE (format one): no such handle, e.g. no key at 0x81000001.
pub const TPM_RC_HANDLE: u32 = 0x008B;

/// Something that takes TPM commands: the firmware's TCG2 protocol, or in
/// tests swtpm over TCP.
pub trait Tpm {
    /// Send `command`; the response goes into `response`. Returns its
    /// length.
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, Error>;
}

/// Send a command and check the response code. The buffer is wiped when
/// dropped, since a response may carry key material.
pub fn call<T: Tpm + ?Sized>(tpm: &mut T, command: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new(vec![0u8; 1024]);
    let n = tpm.submit(command, &mut buf)?;
    buf.truncate(n.min(1024));
    Response::parse(&buf)?;
    Ok(buf)
}

/// A command being built; [`Command::finish`] fills in its size.
pub struct Command {
    buf: Vec<u8>,
}

impl Command {
    pub fn new(tag: u16, code: u32) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(&code.to_be_bytes());
        Self { buf }
    }

    pub fn u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }

    pub fn u16(mut self, v: u16) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(mut self, v: &[u8]) -> Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// A TPM2B: u16 size, then the bytes.
    pub fn tpm2b(self, v: &[u8]) -> Self {
        let size = u16::try_from(v.len()).unwrap_or(u16::MAX);
        self.u16(size).bytes(&v[..usize::from(size)])
    }

    /// A TPML_PCR_SELECTION with one bank and PCRs 0–23 as a bitmap.
    pub fn pcr_selection(self, alg: u16, pcrs: u32) -> Self {
        let [a, b, c, _] = pcrs.to_le_bytes();
        self.u32(1).u16(alg).u8(3).bytes(&[a, b, c])
    }

    /// The authorization area with one session (TPMS_AUTH_COMMAND).
    pub fn auth(self, session: u32, nonce: &[u8], attributes: u8, hmac: &[u8]) -> Self {
        let size = 4 + 2 + nonce.len() + 1 + 2 + hmac.len();
        self.u32(size as u32).u32(session).tpm2b(nonce).u8(attributes).tpm2b(hmac)
    }

    pub fn finish(mut self) -> Vec<u8> {
        let size = (self.buf.len() as u32).to_be_bytes();
        self.buf[2..6].copy_from_slice(&size);
        self.buf
    }
}

/// A response, read field by field after the header.
pub struct Response<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Response<'a> {
    /// A reader over any marshalled structure (no header).
    pub fn raw(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    /// What hasn't been read yet.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.at.min(self.buf.len())..]
    }

    /// Check the header: the size field must match, the code be success.
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < 10 {
            return Err(Error::Malformed);
        }
        let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        if size < 10 || size > buf.len() {
            return Err(Error::Malformed);
        }
        let rc = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        if rc != 0 {
            return Err(Error::Tpm(rc));
        }
        Ok(Self { buf: &buf[..size], at: 10 })
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let out = self.buf.get(self.at..self.at + n).ok_or(Error::Malformed)?;
        self.at += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }
}

/// TPM2_PCR_Read of `pcrs` (bitmap of PCRs 0–23) in bank `alg`.
pub fn pcr_read(alg: u16, pcrs: u32) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ).pcr_selection(alg, pcrs).finish()
}

/// TPM2_GetRandom.
pub fn get_random(bytes: u16) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM).u16(bytes).finish()
}

pub fn parse_get_random(buf: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(Response::parse(buf)?.tpm2b()?.to_vec())
}

/// TPM2_ReadPublic of a loaded or persistent object.
pub fn read_public(handle: u32) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC).u32(handle).finish()
}

/// ReadPublic's answer: the public area (TPMT_PUBLIC) and the name.
pub fn parse_read_public(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut r = Response::parse(buf)?;
    let area = r.tpm2b()?.to_vec();
    let name = r.tpm2b()?.to_vec();
    Ok((area, name))
}

/// An ECC key's public area, as far as a salt needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublic {
    pub name_alg: u16,
    pub curve: u16,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// The ECC fields of a TPMT_PUBLIC; `None` for another key type.
pub fn parse_ecc_public(area: &[u8]) -> Result<Option<EccPublic>, Error> {
    let mut r = Response::raw(area);
    if r.u16()? != TPM_ALG_ECC {
        return Ok(None);
    }
    let name_alg = r.u16()?;
    let _attributes = r.u32()?;
    let _policy = r.tpm2b()?;
    // TPMT_SYM_DEF_OBJECT: algorithm, then key bits and mode unless NULL.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
        r.u16()?;
    }
    // TPMT_ECC_SCHEME: a hash unless NULL (ECDAA adds a count).
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        r.u16()?;
        if scheme == 0x001A {
            r.u16()?;
        }
    }
    let curve = r.u16()?;
    // TPMT_KDF_SCHEME: a hash unless NULL.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    let x = r.tpm2b()?.to_vec();
    let y = r.tpm2b()?.to_vec();
    Ok(Some(EccPublic { name_alg, curve, x, y }))
}

/// TPM2_Load under `parent` (empty password): `private` and `public` are
/// marshalled TPM2B_PRIVATE and TPM2B_PUBLIC, size fields included, as
/// tpm2_create writes them.
pub fn load(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    Command::new(TPM_ST_SESSIONS, TPM_CC_LOAD).u32(parent).auth(TPM_RS_PW, &[], 0, &[]).bytes(private).bytes(public).finish()
}

/// Load's answer: the object's handle and name.
pub fn parse_load(buf: &[u8]) -> Result<(u32, Vec<u8>), Error> {
    let mut r = Response::parse(buf)?;
    let handle = r.u32()?;
    let _parameter_size = r.u32()?;
    Ok((handle, r.tpm2b()?.to_vec()))
}

/// TPM2_StartAuthSession for a policy session with SHA-256, salted with
/// `encrypted_salt` for `tpm_key` (or unsalted: TPM_RH_NULL and empty),
/// unbound, and XOR parameter encryption.
pub fn start_policy_session(tpm_key: u32, nonce_caller: &[u8], encrypted_salt: &[u8]) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION)
        .u32(tpm_key)
        .u32(TPM_RH_NULL)
        .tpm2b(nonce_caller)
        .tpm2b(encrypted_salt)
        .u8(TPM_SE_POLICY)
        // TPMT_SYM_DEF: XOR with SHA-256 (no mode field for XOR).
        .u16(TPM_ALG_XOR)
        .u16(TPM_ALG_SHA256)
        .u16(TPM_ALG_SHA256)
        .finish()
}

/// StartAuthSession's answer: the session handle and the TPM's nonce.
pub fn parse_start_auth_session(buf: &[u8]) -> Result<(u32, Vec<u8>), Error> {
    let mut r = Response::parse(buf)?;
    let handle = r.u32()?;
    Ok((handle, r.tpm2b()?.to_vec()))
}

/// TPM2_PolicyPCR: the session's policy gets the current values of
/// `pcrs` (SHA-256 bank). With `pcr_digest` non-empty the TPM first checks
/// the values against it, so a change shows up here (TPM_RC_VALUE) rather
/// than as a policy failure at Unseal.
pub fn policy_pcr(session: u32, pcr_digest: &[u8], pcrs: u32) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_POLICY_PCR).u32(session).tpm2b(pcr_digest).pcr_selection(TPM_ALG_SHA256, pcrs).finish()
}

/// TPM2_Unseal of `item`, authorized by policy `session` (which then ends),
/// with the response encrypted (TPMA_SESSION_ENCRYPT). A salted policy
/// session has a session key, so the command carries an HMAC
/// ([`crate::seal::command_hmac`]) even without PolicyAuthValue: libtpms
/// answers an empty one with TPM_RC_BAD_AUTH.
pub fn unseal(item: u32, session: u32, nonce_caller: &[u8], hmac: &[u8]) -> Vec<u8> {
    Command::new(TPM_ST_SESSIONS, TPM_CC_UNSEAL).u32(item).auth(session, nonce_caller, TPMA_SESSION_ENCRYPT, hmac).finish()
}

/// Unseal's answer, still encrypted.
pub struct UnsealResponse {
    /// The response parameters as sent (for the response HMAC).
    pub parameters: Zeroizing<Vec<u8>>,
    /// outData's bytes, encrypted.
    pub data: Zeroizing<Vec<u8>>,
    pub nonce_tpm: Vec<u8>,
    pub attributes: u8,
    pub hmac: Vec<u8>,
}

pub fn parse_unseal(buf: &[u8]) -> Result<UnsealResponse, Error> {
    let mut r = Response::parse(buf)?;
    let size = r.u32()? as usize;
    let parameters = r.bytes(size)?;
    let data = Response::raw(parameters).tpm2b()?;
    Ok(UnsealResponse {
        parameters: Zeroizing::new(parameters.to_vec()),
        data: Zeroizing::new(data.to_vec()),
        nonce_tpm: r.tpm2b()?.to_vec(),
        attributes: r.u8()?,
        hmac: r.tpm2b()?.to_vec(),
    })
}

/// TPM2_FlushContext.
pub fn flush_context(handle: u32) -> Vec<u8> {
    Command::new(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT).u32(handle).finish()
}

/// The values from a PCR_Read response, as (PCR, value), in PCR order.
/// PCRs the TPM didn't return (an inactive bank) are missing.
pub fn parse_pcr_read(buf: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, Error> {
    let mut r = Response::parse(buf)?;
    let _update_counter = r.u32()?;
    let mut selected = Vec::new();
    for _ in 0..r.u32()? {
        let _alg = r.u16()?;
        let size = usize::from(r.u8()?);
        for (i, byte) in r.bytes(size)?.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    selected.push((i * 8 + bit) as u32);
                }
            }
        }
    }
    let count = r.u32()? as usize;
    if count != selected.len() {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for pcr in selected {
        out.push((pcr, r.tpm2b()?.to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pcr_read_command() {
        assert_eq!(
            pcr_read(TPM_ALG_SHA256, 1 << 7),
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x7E, // header, 20 bytes
                0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x80, 0x00, 0x00, // SHA-256, PCR 7
            ]
        );
        // PCRs 0 and 15.
        assert_eq!(&pcr_read(TPM_ALG_SHA256, 1 | 1 << 15)[17..], &[0x01, 0x80, 0x00]);
    }

    fn response(selected: &[u8; 3], values: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 5, 0, 0, 0, 1, 0x00, 0x0B, 3];
        body.extend_from_slice(selected);
        body.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for v in values {
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
        }
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + body.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn pcr_read_response() {
        let r = response(&[0x80, 0, 0], &[&[0x11; 32]]);
        assert_eq!(parse_pcr_read(&r).unwrap(), vec![(7, vec![0x11; 32])]);
        let r = response(&[0x01, 0x80, 0], &[&[0x22; 32], &[0x33; 32]]);
        assert_eq!(parse_pcr_read(&r).unwrap(), vec![(0, vec![0x22; 32]), (15, vec![0x33; 32])]);
        // An inactive bank: nothing selected, nothing returned.
        let r = response(&[0, 0, 0], &[]);
        assert_eq!(parse_pcr_read(&r).unwrap(), vec![]);
    }

    #[test]
    fn bad_responses() {
        // TPM_RC_VALUE (0x0084) from the TPM; a header only; a size field
        // that claims more than there is; a count that disagrees.
        let mut rc = vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x00, 0x84];
        assert_eq!(parse_pcr_read(&rc).unwrap_err(), Error::Tpm(0x84));
        rc[9] = 0;
        assert_eq!(parse_pcr_read(&rc).unwrap_err(), Error::Malformed);
        let mut r = response(&[0x80, 0, 0], &[&[0x11; 32]]);
        r[5] += 1;
        assert_eq!(parse_pcr_read(&r).unwrap_err(), Error::Malformed);
        let r = response(&[0x81, 0, 0], &[&[0x11; 32]]);
        assert_eq!(parse_pcr_read(&r).unwrap_err(), Error::Malformed);
    }
}
