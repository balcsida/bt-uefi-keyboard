//! HID keyboard reports: shown as they arrive, and collected as text.
//!
//! Usages are key positions, not characters. They are read with a US layout,
//! so on a QWERTZ keyboard Y and Z appear swapped.

use alloc::string::String;
use alloc::vec::Vec;
use uefi::println;

const MODIFIERS: [&str; 8] = ["LCtrl", "LShift", "LAlt", "LGui", "RCtrl", "RShift", "RAlt", "RGui"];

/// Character for a usage on a US layout, if it types one.
fn key_char(usage: u16, shift: bool) -> Option<char> {
    const DIGITS: &[u8; 10] = b"1234567890";
    const SHIFTED_DIGITS: &[u8; 10] = b"!@#$%^&*()";
    const PUNCT: &[u8; 11] = b"-=[]\\#;'`,.";
    const SHIFTED_PUNCT: &[u8; 11] = b"_+{}|~:\"~<>";
    let u = usize::from(usage);
    Some(match usage {
        0x04..=0x1D => {
            let c = (b'a' + (usage - 0x04) as u8) as char;
            if shift { c.to_ascii_uppercase() } else { c }
        }
        0x1E..=0x27 => (if shift { SHIFTED_DIGITS } else { DIGITS })[u - 0x1E] as char,
        0x28 => '\n',
        0x2B => '\t',
        0x2C => ' ',
        0x2D..=0x37 => (if shift { SHIFTED_PUNCT } else { PUNCT })[u - 0x2D] as char,
        0x38 => if shift { '?' } else { '/' },
        _ => return None,
    })
}

fn key_name(usage: u16) -> String {
    match usage {
        0x04..=0x27 => String::from(key_char(usage, false).map(|c| c.to_ascii_uppercase()).unwrap_or('?')),
        0x28 => String::from("Enter"),
        0x29 => String::from("Esc"),
        0x2A => String::from("Backspace"),
        0x2B => String::from("Tab"),
        0x2C => String::from("Space"),
        0x2D..=0x38 => String::from(key_char(usage, false).unwrap_or('?')),
        0x39 => String::from("CapsLock"),
        0x3A..=0x45 => alloc::format!("F{}", usage - 0x39),
        0x46 => String::from("PrintScreen"),
        0x47 => String::from("ScrollLock"),
        0x48 => String::from("Pause"),
        0x49 => String::from("Insert"),
        0x4A => String::from("Home"),
        0x4B => String::from("PageUp"),
        0x4C => String::from("Delete"),
        0x4D => String::from("End"),
        0x4E => String::from("PageDown"),
        0x4F => String::from("Right"),
        0x50 => String::from("Left"),
        0x51 => String::from("Down"),
        0x52 => String::from("Up"),
        0x64 => String::from("<>|"),
        0x01 => String::from("ErrorRollOver"),
        _ => alloc::format!("usage {usage:#04x}"),
    }
}

#[derive(Default)]
pub struct Decoder {
    last: Vec<u16>,
    pub reports: u32,
    /// Text typed so far, read with a US layout; Backspace deletes.
    pub typed: String,
}

impl Decoder {
    /// One report: its raw bytes, modifier bits and the usages of the keys
    /// held down. Prints a line and adds newly pressed keys to `typed`.
    pub fn keys(&mut self, raw: &[u8], modifiers: u8, held: &[u16]) {
        self.reports += 1;
        let mut line = String::from("  keys  ");
        for (bit, name) in MODIFIERS.iter().enumerate() {
            if modifiers & (1 << bit) != 0 {
                line += name;
                line += "+";
            }
        }
        let shift = modifiers & 0x22 != 0;
        for (i, &usage) in held.iter().enumerate() {
            if i > 0 {
                line += ",";
            }
            line += &key_name(usage);
            if !self.last.contains(&usage) {
                match (usage, key_char(usage, shift)) {
                    (0x2A, _) => {
                        self.typed.pop();
                    }
                    (_, Some(c)) => self.typed.push(c),
                    _ => {}
                }
            }
        }
        if held.is_empty() {
            line += if modifiers == 0 { "(all keys up)" } else { "(no key)" };
        }
        line += "   [";
        for (i, b) in raw.iter().enumerate() {
            if i > 0 {
                line += " ";
            }
            line += &alloc::format!("{b:02x}");
        }
        line += "]";
        self.last.clear();
        self.last.extend_from_slice(held);
        println!("{line}");
    }

    /// A boot keyboard report: `[modifiers][reserved][six usages]`.
    pub fn boot_report(&mut self, raw: &[u8]) {
        if raw.len() < 8 {
            println!("  boot report of {} bytes (expected 8)", raw.len());
            return;
        }
        let held: Vec<u16> = raw[2..8].iter().filter(|&&u| u != 0).map(|&u| u16::from(u)).collect();
        self.keys(raw, raw[0], &held);
    }
}

/// Typed text for one line: newlines and tabs shown as escapes.
pub fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' => String::from("\\n"),
            '\t' => String::from("\\t"),
            '"' => String::from("\\\""),
            c => String::from(c),
        })
        .collect()
}
