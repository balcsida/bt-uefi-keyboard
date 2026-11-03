//! The bond file written by `scripts/export-bond.sh`: the keyboard's
//! long-term key and its EDIV/Rand, exported from BlueZ.
//!
//! ```text
//! peer=C0:00:00:00:00:01
//! peer_type=static
//! adapter=02:00:00:00:00:02
//! ltk=<32 hex digits, least significant byte first, as BlueZ stores it>
//! ltk_type=1
//! enc_size=16
//! ediv=<decimal>
//! rand=<decimal>
//! irk=<32 hex digits>
//! ```
//!
//! The key is secret: nothing here prints it, and `Debug` leaves it out.
//!
//! [`ExportedBond::record`] is the bond in a fixed binary layout: what the
//! driver keeps in its boot-services-only variable, and what
//! [`ExportedBond::digest`] hashes. A driver build trusts only the bonds
//! whose digests it was built with (`scripts/bond-digest.py` computes them
//! on the OS side; both must agree byte for byte).

use alloc::string::String;
use core::fmt;

/// Record layout version (first byte of [`ExportedBond::record`]).
pub const RECORD_VERSION: u8 = 1;
/// Version, peer (6), peer is random (1), adapter (6), LTK (16), key type,
/// key size, EDIV (2), Rand (8).
pub const RECORD_LEN: usize = 42;
/// Hashed before the record, so a bond digest can't stand for anything else.
const DIGEST_DOMAIN: &[u8] = b"bt-kb-dxe bond v1\0";

pub struct ExportedBond {
    /// Keyboard address, least significant byte first (HCI order).
    pub peer: [u8; 6],
    /// BlueZ's address type: "static" (random static) or "public".
    pub peer_is_random: bool,
    /// The controller the bond belongs to, least significant byte first.
    pub adapter: [u8; 6],
    /// Long-term key in HCI byte order (least significant first).
    pub ltk: [u8; 16],
    /// BlueZ / mgmt key type: 0, 1 legacy; 2, 3 Secure Connections; 4 debug.
    pub ltk_type: u8,
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
}

/// Every way a bond goes away wipes its key, early returns included.
impl Drop for ExportedBond {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for ExportedBond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondError {
    Missing(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for BondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "bond file has no `{key}`"),
            Self::Invalid(key) => write!(f, "bond file has an invalid `{key}`"),
        }
    }
}

/// "C0:00:00:00:00:01" -> least significant byte first.
pub fn parse_addr(text: &str) -> Option<[u8; 6]> {
    let mut addr = [0u8; 6];
    let mut parts = text.split(':');
    for i in 0..6 {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        addr[5 - i] = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(addr)
}

pub fn addr_text(a: &[u8; 6]) -> String {
    alloc::format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", a[5], a[4], a[3], a[2], a[1], a[0])
}

fn parse_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl ExportedBond {
    pub fn parse(text: &str) -> Result<Self, BondError> {
        let get = |key: &'static str| -> Result<&str, BondError> {
            text.lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == key).map(|(_, v)| v.trim()))
                .ok_or(BondError::Missing(key))
        };
        Ok(Self {
            peer: parse_addr(get("peer")?).ok_or(BondError::Invalid("peer"))?,
            peer_is_random: get("peer_type")? != "public",
            adapter: parse_addr(get("adapter")?).ok_or(BondError::Invalid("adapter"))?,
            ltk: parse_hex16(get("ltk")?).ok_or(BondError::Invalid("ltk"))?,
            ltk_type: get("ltk_type")?.parse().map_err(|_| BondError::Invalid("ltk_type"))?,
            enc_size: get("enc_size")?.parse().map_err(|_| BondError::Invalid("enc_size"))?,
            ediv: get("ediv")?.parse().map_err(|_| BondError::Invalid("ediv"))?,
            rand: get("rand")?.parse().map_err(|_| BondError::Invalid("rand"))?,
        })
    }

    /// Legacy pairing keys need EDIV and Rand to start encryption.
    pub fn is_legacy(&self) -> bool {
        self.ltk_type < 2
    }

    pub fn authenticated(&self) -> bool {
        matches!(self.ltk_type, 1 | 3)
    }

    /// Rand in HCI byte order, as LE Enable Encryption takes it.
    pub fn rand_bytes(&self) -> [u8; 8] {
        self.rand.to_le_bytes()
    }

    /// The bond in its fixed binary layout. Holds the key: wipe it after use.
    pub fn record(&self) -> [u8; RECORD_LEN] {
        let mut r = [0u8; RECORD_LEN];
        r[0] = RECORD_VERSION;
        r[1..7].copy_from_slice(&self.peer);
        r[7] = u8::from(self.peer_is_random);
        r[8..14].copy_from_slice(&self.adapter);
        r[14..30].copy_from_slice(&self.ltk);
        r[30] = self.ltk_type;
        r[31] = self.enc_size;
        r[32..34].copy_from_slice(&self.ediv.to_le_bytes());
        r[34..42].copy_from_slice(&self.rand.to_le_bytes());
        r
    }

    /// A record read back; only this version and a sane key are accepted.
    pub fn from_record(r: &[u8]) -> Result<Self, BondError> {
        if r.len() != RECORD_LEN || r[0] != RECORD_VERSION || r[7] > 1 || r[30] > 4 || !(7..=16).contains(&r[31]) {
            return Err(BondError::Invalid("record"));
        }
        let mut bond = Self {
            peer: [0; 6],
            peer_is_random: r[7] == 1,
            adapter: [0; 6],
            ltk: [0; 16],
            ltk_type: r[30],
            enc_size: r[31],
            ediv: u16::from_le_bytes([r[32], r[33]]),
            rand: u64::from_le_bytes(r[34..42].try_into().map_err(|_| BondError::Invalid("record"))?),
        };
        bond.peer.copy_from_slice(&r[1..7]);
        bond.adapter.copy_from_slice(&r[8..14]);
        bond.ltk.copy_from_slice(&r[14..30]);
        Ok(bond)
    }

    /// What a driver build pins for this bond: SHA-256 of a domain tag and
    /// the record. Reveals nothing about the key.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut record = self.record();
        let mut h = sha2::Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(record);
        wipe_bytes(&mut record);
        h.finalize().into()
    }

    /// Overwrite the key material.
    pub fn wipe(&mut self) {
        wipe_bytes(&mut self.ltk);
        // SAFETY: valid, aligned pointers to fields we own.
        unsafe {
            core::ptr::write_volatile(&mut self.ediv, 0);
            core::ptr::write_volatile(&mut self.rand, 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Everything except the key.
    pub fn summary(&self) -> String {
        alloc::format!(
            "bond for {} ({}) on controller {}: {} {} key, {} bytes{}",
            addr_text(&self.peer),
            if self.peer_is_random { "random" } else { "public" },
            addr_text(&self.adapter),
            if self.is_legacy() { "legacy" } else { "Secure Connections" },
            if self.authenticated() { "authenticated" } else { "unauthenticated" },
            self.enc_size,
            if self.is_legacy() { ", with EDIV/Rand" } else { "" }
        )
    }
}

/// Overwrite bytes that held key material, so the compiler can't drop it.
pub fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: a valid pointer to a byte we own.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// SHA-256 of the domain tag and SAMPLE's record, as computed by
    /// `scripts/bond-digest.py` (the two must agree).
    const DIGEST_OF_SAMPLE: &str = "e668fd2ee2a48162567b05a3c0f4c40347e473c0fcfa34dacc6238701596cffd";

    const SAMPLE: &str = "# BlueZ bond for C0:00:00:00:00:01, exported for a test
peer=C0:00:00:00:00:01
peer_type=static
adapter=02:00:00:00:00:02
ltk=0F1E2D3C4B5A69788796A5B4C3D2E1F0
ltk_type=1
enc_size=16
ediv=4660
rand=1311768467463790320
irk=00112233445566778899AABBCCDDEEFF
";

    #[test]
    fn parses_the_exported_file() {
        let bond = ExportedBond::parse(SAMPLE).unwrap();
        assert_eq!(bond.peer, [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0]);
        assert!(bond.peer_is_random);
        assert_eq!(bond.adapter, [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        // Key bytes keep BlueZ's order, which is already HCI order.
        assert_eq!(bond.ltk[0], 0x0F);
        assert_eq!(bond.ltk[15], 0xF0);
        assert!(bond.is_legacy());
        assert!(bond.authenticated());
        assert_eq!(bond.ediv, 0x1234);
        assert_eq!(bond.rand_bytes(), 0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    }

    #[test]
    fn summary_and_debug_never_show_the_key() {
        let bond = ExportedBond::parse(SAMPLE).unwrap();
        for text in [bond.summary(), std::format!("{bond:?}")] {
            assert!(!text.to_uppercase().contains("0F1E2D3C"), "{text}");
            assert!(text.contains("C0:00:00:00:00:01"));
            assert!(text.contains("legacy authenticated"));
        }
    }

    #[test]
    fn record_round_trip_and_digest() {
        let bond = ExportedBond::parse(SAMPLE).unwrap();
        let record = bond.record();
        let back = ExportedBond::from_record(&record).unwrap();
        assert_eq!(back.record(), record);
        // The value scripts/bond-digest.py computes for SAMPLE.
        let hex: std::string::String = bond.digest().iter().map(|b| std::format!("{b:02x}")).collect();
        assert_eq!(hex, DIGEST_OF_SAMPLE);
        // Every field counts.
        let mut other = ExportedBond::parse(SAMPLE).unwrap();
        other.ltk[15] ^= 1;
        assert_ne!(other.digest(), bond.digest());
        let mut other = ExportedBond::parse(SAMPLE).unwrap();
        other.peer_is_random = false;
        assert_ne!(other.digest(), bond.digest());
        let mut other = ExportedBond::parse(SAMPLE).unwrap();
        other.rand += 1;
        assert_ne!(other.digest(), bond.digest());
    }

    #[test]
    fn bad_records_are_rejected() {
        let record = ExportedBond::parse(SAMPLE).unwrap().record();
        assert!(ExportedBond::from_record(&record[..41]).is_err());
        let mut r = record;
        r[0] = 2;
        assert!(ExportedBond::from_record(&r).is_err(), "other version");
        let mut r = record;
        r[31] = 0;
        assert!(ExportedBond::from_record(&r).is_err(), "key size 0");
        let mut r = record;
        r[7] = 2;
        assert!(ExportedBond::from_record(&r).is_err(), "address type");
    }

    #[test]
    fn wipe_clears_the_key() {
        let mut bond = ExportedBond::parse(SAMPLE).unwrap();
        bond.wipe();
        assert_eq!((bond.ltk, bond.ediv, bond.rand), ([0; 16], 0, 0));
    }

    #[test]
    fn bad_files_are_rejected() {
        assert_eq!(ExportedBond::parse("peer=C0:00:00:00:00:01\n").unwrap_err(), BondError::Missing("peer_type"));
        let short_key = SAMPLE.replace("ltk=0F1E2D3C4B5A69788796A5B4C3D2E1F0", "ltk=0F1E");
        assert_eq!(ExportedBond::parse(&short_key).unwrap_err(), BondError::Invalid("ltk"));
        assert_eq!(parse_addr("C0:00:00:00:00"), None);
        assert_eq!(parse_addr("C0:00:00:00:00:01:00"), None);
    }
}
