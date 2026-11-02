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

use alloc::string::String;
use core::fmt;

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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

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
    fn bad_files_are_rejected() {
        assert_eq!(ExportedBond::parse("peer=C0:00:00:00:00:01\n").unwrap_err(), BondError::Missing("peer_type"));
        let short_key = SAMPLE.replace("ltk=0F1E2D3C4B5A69788796A5B4C3D2E1F0", "ltk=0F1E");
        assert_eq!(ExportedBond::parse(&short_key).unwrap_err(), BondError::Invalid("ltk"));
        assert_eq!(parse_addr("C0:00:00:00:00"), None);
        assert_eq!(parse_addr("C0:00:00:00:00:01:00"), None);
    }
}
