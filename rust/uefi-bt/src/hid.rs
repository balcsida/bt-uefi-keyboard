//! Just enough of a HID report descriptor parser to find a keyboard's input
//! report: where the modifier byte is and where the pressed keys are (an
//! array of usages, or a bitmap with one bit per key).
//!
//! In HID over GATT (report protocol), each Report characteristic carries
//! one report without its report ID byte, so offsets here exclude it.

use alloc::vec::Vec;

const PAGE_KEYBOARD: u16 = 0x07;
const MAX_REPORT_IDS: usize = 16;

/// Where the pressed keys are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyField {
    /// `count` slots of `size` bits, each holding the usage of a pressed key.
    Array { bit: usize, count: usize, size: usize },
    /// One bit per key, for usages `first_usage..first_usage + count`.
    Bitmap { bit: usize, first_usage: u16, count: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardReport {
    /// `None` if the descriptor uses no report IDs.
    pub report_id: Option<u8>,
    /// Bit offset of the eight modifier bits (LCtrl first), if present.
    pub modifiers_bit: Option<usize>,
    pub keys: KeyField,
    /// Size of the whole input report in bits.
    pub bits: usize,
}

#[derive(Default, Clone, Copy)]
struct Globals {
    usage_page: u16,
    report_size: usize,
    report_count: usize,
    report_id: Option<u8>,
}

#[derive(Default)]
struct Locals {
    usages: Vec<u32>,
    usage_min: Option<u32>,
    usage_max: Option<u32>,
}

impl Locals {
    /// First usage of the item and its page (a 4-byte usage carries its own page).
    fn first(&self, page: u16) -> Option<(u16, u16)> {
        let usage = self.usage_min.or_else(|| self.usages.first().copied())?;
        let page = if usage > 0xFFFF { (usage >> 16) as u16 } else { page };
        Some((page, usage as u16))
    }
}

/// Bit position of the next input field, per report ID.
struct Positions(Vec<(Option<u8>, usize)>);

impl Positions {
    fn get(&mut self, id: Option<u8>) -> &mut usize {
        let index = match self.0.iter().position(|(i, _)| *i == id) {
            Some(index) => index,
            None => {
                self.0.push((id, 0));
                self.0.len() - 1
            }
        };
        &mut self.0[index].1
    }
}

/// Parse `descriptor` and return the first input report with keyboard keys.
pub fn find_keyboard_report(descriptor: &[u8]) -> Option<KeyboardReport> {
    let mut globals = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    let mut locals = Locals::default();
    let mut positions = Positions(Vec::new());
    let mut found: Vec<KeyboardReport> = Vec::new();
    let mut modifiers: Vec<(Option<u8>, usize)> = Vec::new();

    let mut i = 0;
    while i < descriptor.len() {
        let prefix = descriptor[i];
        if prefix == 0xFE {
            // Long item: [0xFE][size][tag][data...]
            let size = usize::from(*descriptor.get(i + 1)?);
            i += 3 + size;
            continue;
        }
        let size = match prefix & 0x03 {
            3 => 4,
            n => usize::from(n),
        };
        let data = descriptor.get(i + 1..i + 1 + size)?;
        let value = data.iter().rev().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        i += 1 + size;

        match (prefix >> 2) & 0x03 {
            // Main items.
            0 => {
                if prefix >> 4 == 0x8 {
                    let id = globals.report_id;
                    let width = globals.report_size * globals.report_count;
                    let bit = *positions.get(id);
                    let constant = value & 0x01 != 0;
                    let variable = value & 0x02 != 0;
                    if !constant {
                        if let Some((page, usage)) = locals.first(globals.usage_page) {
                            if page == PAGE_KEYBOARD {
                                if variable && usage == 0xE0 && globals.report_size == 1 {
                                    modifiers.push((id, bit));
                                } else if variable && globals.report_size == 1 {
                                    found.push(KeyboardReport {
                                        report_id: id,
                                        modifiers_bit: None,
                                        keys: KeyField::Bitmap { bit, first_usage: usage, count: globals.report_count },
                                        bits: 0,
                                    });
                                } else if !variable {
                                    found.push(KeyboardReport {
                                        report_id: id,
                                        modifiers_bit: None,
                                        keys: KeyField::Array { bit, count: globals.report_count, size: globals.report_size },
                                        bits: 0,
                                    });
                                }
                            }
                        }
                    }
                    *positions.get(id) = bit + width;
                }
                locals = Locals::default();
            }
            // Global items.
            1 => match prefix >> 4 {
                0x0 => globals.usage_page = value as u16,
                0x7 => globals.report_size = value as usize,
                0x8 => globals.report_id = Some(value as u8),
                0x9 => globals.report_count = value as usize,
                0xA => stack.push(globals),
                0xB => globals = stack.pop().unwrap_or_default(),
                _ => {}
            },
            // Local items.
            2 => match prefix >> 4 {
                0x0 => locals.usages.push(value),
                0x1 => locals.usage_min = Some(value),
                0x2 => locals.usage_max = Some(value),
                _ => {}
            },
            _ => {}
        }
        if positions.0.len() > MAX_REPORT_IDS {
            return None;
        }
    }

    let mut report = *found.first()?;
    report.modifiers_bit = modifiers.iter().find(|(id, _)| *id == report.report_id).map(|(_, bit)| *bit);
    report.bits = positions.0.iter().find(|(id, _)| *id == report.report_id).map(|(_, bits)| *bits).unwrap_or(0);
    Some(report)
}

fn bits_at(data: &[u8], bit: usize, size: usize) -> Option<u32> {
    let mut value = 0u32;
    for k in 0..size.min(32) {
        let b = bit + k;
        let byte = *data.get(b / 8)?;
        if byte & (1 << (b % 8)) != 0 {
            value |= 1 << k;
        }
    }
    Some(value)
}

impl KeyboardReport {
    /// Modifier bits and the usages of the pressed keys in one report.
    pub fn decode(&self, report: &[u8]) -> Option<(u8, Vec<u16>)> {
        let modifiers = match self.modifiers_bit {
            Some(bit) => bits_at(report, bit, 8)? as u8,
            None => 0,
        };
        let mut keys = Vec::new();
        match self.keys {
            KeyField::Array { bit, count, size } => {
                for slot in 0..count {
                    let usage = bits_at(report, bit + slot * size, size)? as u16;
                    if usage != 0 {
                        keys.push(usage);
                    }
                }
            }
            KeyField::Bitmap { bit, first_usage, count } => {
                for k in 0..count {
                    if bits_at(report, bit + k, 1)? != 0 {
                        keys.push(first_usage + k as u16);
                    }
                }
            }
        }
        Some((modifiers, keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HID spec's boot-compatible keyboard, with report ID 1.
    const BOOT_LIKE: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, // Generic Desktop, Keyboard, Collection, ID 1
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, // modifiers
        0x75, 0x01, 0x95, 0x08, 0x81, 0x02, // 8 x 1 bit, Data Var
        0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved byte, Constant
        0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, // LED output
        0x95, 0x01, 0x75, 0x03, 0x91, 0x01, // LED padding
        0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, // 6 keys
        0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, // Data Array
        0xC0,
    ];

    #[test]
    fn boot_like_keyboard() {
        let report = find_keyboard_report(BOOT_LIKE).unwrap();
        assert_eq!(report.report_id, Some(1));
        assert_eq!(report.modifiers_bit, Some(0));
        assert_eq!(report.keys, KeyField::Array { bit: 16, count: 6, size: 8 });
        assert_eq!(report.bits, 64);
        let (mods, keys) = report.decode(&[0x02, 0x00, 0x04, 0x05, 0, 0, 0, 0]).unwrap();
        assert_eq!(mods, 0x02);
        assert_eq!(keys, std::vec![0x04, 0x05]);
    }

    extern crate std;

    #[test]
    fn eleven_byte_report_without_reserved_byte() {
        // A mouse report first (ID 2) must not shift the keyboard's offsets.
        let descriptor = [
            0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x75, 0x01, 0x95, 0x03,
            0x81, 0x02, 0x75, 0x05, 0x95, 0x01, 0x81, 0x01, 0xC0, // mouse buttons, ID 2
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x75, 0x01, 0x95, 0x08,
            0x81, 0x02, // modifiers
            0x75, 0x08, 0x95, 0x0A, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, // 10 keys, usage max as 2 bytes
            0xC0,
        ];
        let report = find_keyboard_report(&descriptor).unwrap();
        assert_eq!(report.report_id, Some(1));
        assert_eq!(report.modifiers_bit, Some(0));
        assert_eq!(report.keys, KeyField::Array { bit: 8, count: 10, size: 8 });
        assert_eq!(report.bits, 88);
        let (mods, keys) = report.decode(&[0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!((mods, keys), (0, std::vec![0x06]));
    }

    #[test]
    fn bitmap_keys() {
        let descriptor = [
            0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, // modifiers
            0x19, 0x00, 0x29, 0x67, 0x75, 0x01, 0x95, 0x68, 0x81, 0x02, // 104-key bitmap
        ];
        let report = find_keyboard_report(&descriptor).unwrap();
        assert_eq!(report.report_id, None);
        assert_eq!(report.keys, KeyField::Bitmap { bit: 8, first_usage: 0, count: 0x68 });
        // Usage 0x04 ('a') is bit 4 of the bitmap: byte 1, bit 4.
        let mut data = [0u8; 14];
        data[0] = 0x20; // RShift
        data[1] = 0x10;
        let (mods, keys) = report.decode(&data).unwrap();
        assert_eq!((mods, keys), (0x20, std::vec![0x04]));
    }

    #[test]
    fn truncated_descriptors_and_reports_fail_softly() {
        assert_eq!(find_keyboard_report(&BOOT_LIKE[..10]), None);
        assert_eq!(find_keyboard_report(&[0x05]), None);
        let report = find_keyboard_report(BOOT_LIKE).unwrap();
        assert_eq!(report.decode(&[0x02, 0x00, 0x04]), None);
    }
}
