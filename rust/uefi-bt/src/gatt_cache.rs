//! What a driver learns from a keyboard's GATT database, in a form that can
//! be kept between boots (bt-kb-dxe stores it in a non-volatile variable).
//!
//! With it, key reports are decoded as soon as the link is encrypted. The
//! HID discovery takes 2–3.5 s at the keyboard's 35 ms connection interval,
//! and without the record every key pressed meanwhile, the one that woke
//! the keyboard included, waits for it.
//!
//! The record is untrusted input (any OS can write the variable), so
//! [`GattCache::decode`] checks every field. The driver also checks it
//! against the keyboard once per start (the Report Reference descriptor)
//! and discovers again if it no longer matches.

use crate::hid::{KeyField, KeyboardReport};

/// Bumped whenever the encoding changes; other versions are ignored.
pub const VERSION: u8 = 1;
/// Encoded size in bytes.
pub const LEN: usize = 30;

/// Largest input report accepted, in bits (an ATT value is at most 512 bytes).
const MAX_BITS: usize = 512 * 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GattCache {
    /// The keyboard's identity address, as in the bond file.
    pub peer: [u8; 6],
    pub peer_is_random: bool,
    /// Value handle of the keyboard input report.
    pub input: u16,
    /// Its notification switch (CCCD).
    pub cccd: u16,
    /// Its Report Reference descriptor: `[report ID, 1 = input]`.
    pub reference: u16,
    /// The LED output report, if the keyboard has one.
    pub output: Option<u16>,
    pub report: KeyboardReport,
}

fn put16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn get16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn small(value: usize) -> Option<u16> {
    u16::try_from(value).ok()
}

impl GattCache {
    /// `None` if a value doesn't fit the encoding (nothing is cached then).
    pub fn encode(&self) -> Option<[u8; LEN]> {
        let mut out = [0u8; LEN];
        out[0] = VERSION;
        out[1..7].copy_from_slice(&self.peer);
        out[7] = u8::from(self.peer_is_random);
        put16(&mut out, 8, self.input);
        put16(&mut out, 10, self.cccd);
        put16(&mut out, 12, self.reference);
        put16(&mut out, 14, self.output.unwrap_or(0));
        if let Some(id) = self.report.report_id {
            out[16] = 1;
            out[17] = id;
        }
        let modifiers = match self.report.modifiers_bit {
            Some(bit) => small(bit).filter(|&b| b != u16::MAX)?,
            None => u16::MAX,
        };
        put16(&mut out, 18, modifiers);
        let (tag, a, b, c) = match self.report.keys {
            KeyField::Array { bit, count, size } => (1, bit, count, size),
            KeyField::Bitmap { bit, first_usage, count } => (2, bit, usize::from(first_usage), count),
        };
        out[20] = tag;
        put16(&mut out, 22, small(a)?);
        put16(&mut out, 24, small(b)?);
        put16(&mut out, 26, small(c)?);
        put16(&mut out, 28, small(self.report.bits)?);
        // Only what `decode` accepts is worth storing.
        Self::decode(&out).filter(|back| back == self)?;
        Some(out)
    }

    /// A stored record, if it is complete, of this version and sane.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != LEN || data[0] != VERSION || data[7] > 1 || data[16] > 1 || data[21] != 0 {
            return None;
        }
        let mut peer = [0u8; 6];
        peer.copy_from_slice(&data[1..7]);
        let (input, cccd, reference) = (get16(data, 8), get16(data, 10), get16(data, 12));
        if input == 0 || cccd == 0 || reference == 0 {
            return None;
        }
        let output = Some(get16(data, 14)).filter(|&h| h != 0);
        let report_id = (data[16] == 1).then_some(data[17]);
        let bits = usize::from(get16(data, 28));
        if bits == 0 || bits > MAX_BITS {
            return None;
        }
        let modifiers_bit = match get16(data, 18) {
            u16::MAX => None,
            bit if usize::from(bit) + 8 <= bits => Some(usize::from(bit)),
            _ => return None,
        };
        let (a, b, c) = (usize::from(get16(data, 22)), get16(data, 24), usize::from(get16(data, 26)));
        let keys = match data[20] {
            1 => {
                let (bit, count, size) = (a, usize::from(b), c);
                if !(1..=16).contains(&size) || count == 0 || bit + count * size > bits {
                    return None;
                }
                KeyField::Array { bit, count, size }
            }
            2 => {
                let (bit, first_usage, count) = (a, b, c);
                if count == 0 || bit + count > bits || usize::from(first_usage) + count > 0x1_0000 {
                    return None;
                }
                KeyField::Bitmap { bit, first_usage, count }
            }
            _ => return None,
        };
        Some(Self {
            peer,
            peer_is_random: data[7] == 1,
            input,
            cccd,
            reference,
            output,
            report: KeyboardReport { report_id, modifiers_bit, keys, bits },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Microsoft Bluetooth Ergonomic Keyboard, as discovered on Nov 1.
    fn ergonomic() -> GattCache {
        GattCache {
            peer: [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0],
            peer_is_random: true,
            input: 0x001A,
            cccd: 0x001B,
            reference: 0x001C,
            output: Some(0x0032),
            report: KeyboardReport {
                report_id: Some(1),
                modifiers_bit: Some(0),
                keys: KeyField::Array { bit: 8, count: 10, size: 8 },
                bits: 88,
            },
        }
    }

    #[test]
    fn round_trip() {
        let record = ergonomic();
        let data = record.encode().unwrap();
        assert_eq!(GattCache::decode(&data), Some(record));
        // Decoding with the stored layout gives the same keys.
        let report = [0x02, 0x04, 0x05, 0, 0, 0, 0, 0, 0, 0, 0];
        let back = GattCache::decode(&data).unwrap();
        assert_eq!(back.report.decode(&report), Some((0x02, alloc::vec![0x04, 0x05])));
    }

    #[test]
    fn bitmap_and_no_ids() {
        let mut record = ergonomic();
        record.output = None;
        record.report = KeyboardReport {
            report_id: None,
            modifiers_bit: None,
            keys: KeyField::Bitmap { bit: 8, first_usage: 0x04, count: 120 },
            bits: 128,
        };
        let data = record.encode().unwrap();
        assert_eq!(GattCache::decode(&data), Some(record));
    }

    #[test]
    fn rejects_damage() {
        let data = ergonomic().encode().unwrap();
        assert!(GattCache::decode(&data[..LEN - 1]).is_none());
        let mut other = data;
        other[0] = VERSION + 1;
        assert!(GattCache::decode(&other).is_none(), "other version");
        let mut other = data;
        put16(&mut other, 8, 0);
        assert!(GattCache::decode(&other).is_none(), "no input handle");
        let mut other = data;
        put16(&mut other, 26, 17);
        assert!(GattCache::decode(&other).is_none(), "17-bit key slots");
        let mut other = data;
        put16(&mut other, 24, 11);
        assert!(GattCache::decode(&other).is_none(), "key slots past the report's end");
        let mut other = data;
        put16(&mut other, 28, 0);
        assert!(GattCache::decode(&other).is_none(), "empty report");
        let mut other = data;
        put16(&mut other, 18, 85);
        assert!(GattCache::decode(&other).is_none(), "modifiers past the report's end");
        let mut other = data;
        other[20] = 3;
        assert!(GattCache::decode(&other).is_none(), "unknown key field");
    }

    #[test]
    fn unencodable_layouts_are_not_cached() {
        let mut record = ergonomic();
        record.report.bits = MAX_BITS + 8;
        assert!(record.encode().is_none());
        let mut record = ergonomic();
        record.report.keys = KeyField::Array { bit: 8, count: 10, size: 32 };
        record.report.bits = 8 + 320;
        assert!(record.encode().is_none());
    }
}
