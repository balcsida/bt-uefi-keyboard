//! TPM 2.0 commands, marshalled by hand for EFI_TCG2_PROTOCOL's
//! SubmitCommand: big-endian, header first (tag, size, command code),
//! and only what the driver needs.

use alloc::vec::Vec;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_ALG_SHA256: u16 = 0x000B;

/// Why a response couldn't be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than its fields, or its size field disagrees.
    Malformed,
    /// The TPM's response code.
    Tpm(u32),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed TPM response"),
            Self::Tpm(rc) => write!(f, "TPM response code {rc:#06x}"),
        }
    }
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
