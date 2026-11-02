//! HID keyboard usages to UEFI keys, with modifiers, lock keys and key
//! repeat, the way UsbKbDxe does it: US layout, repeat after 500 ms and
//! then every 20 ms, Ctrl+letter left to the Simple Text Input layer.
//!
//! Pure logic, no UEFI calls, so it is tested on the host.

/// UEFI scan codes.
pub mod scan {
    pub const NULL: u16 = 0x00;
    pub const UP: u16 = 0x01;
    pub const DOWN: u16 = 0x02;
    pub const RIGHT: u16 = 0x03;
    pub const LEFT: u16 = 0x04;
    pub const HOME: u16 = 0x05;
    pub const END: u16 = 0x06;
    pub const INSERT: u16 = 0x07;
    pub const DELETE: u16 = 0x08;
    pub const PAGE_UP: u16 = 0x09;
    pub const PAGE_DOWN: u16 = 0x0A;
    pub const F1: u16 = 0x0B;
    pub const F10: u16 = 0x14;
    pub const F11: u16 = 0x15;
    pub const F12: u16 = 0x16;
    pub const ESC: u16 = 0x17;
    pub const PAUSE: u16 = 0x48;
    pub const F13: u16 = 0x68;
}

/// A UEFI scan code's name, for logs.
pub fn scan_name(code: u16) -> Option<&'static str> {
    const F: [&str; 12] = ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12"];
    const F13: [&str; 12] = ["F13", "F14", "F15", "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23", "F24"];
    Some(match code {
        scan::UP => "Up",
        scan::DOWN => "Down",
        scan::RIGHT => "Right",
        scan::LEFT => "Left",
        scan::HOME => "Home",
        scan::END => "End",
        scan::INSERT => "Insert",
        scan::DELETE => "Delete",
        scan::PAGE_UP => "PageUp",
        scan::PAGE_DOWN => "PageDown",
        scan::F1..=scan::F12 => F[usize::from(code - scan::F1)],
        scan::ESC => "Esc",
        scan::PAUSE => "Pause",
        scan::F13..=0x73 => F13[usize::from(code - scan::F13)],
        _ => return None,
    })
}

/// Keys a firmware may use as boot hotkeys (F-keys, Esc, Delete): the
/// driver logs these when it delivers them. Typing is never logged.
pub fn is_hotkey_like(code: u16) -> bool {
    matches!(code, scan::F1..=scan::F12 | scan::ESC | scan::DELETE | scan::F13..=0x73)
}

/// UEFI control characters.
pub mod chars {
    pub const NULL: u16 = 0x00;
    pub const BACKSPACE: u16 = 0x08;
    pub const TAB: u16 = 0x09;
    pub const CARRIAGE_RETURN: u16 = 0x0D;
}

/// HID modifier byte bits.
pub mod modifier {
    pub const LCTRL: u8 = 0x01;
    pub const LSHIFT: u8 = 0x02;
    pub const LALT: u8 = 0x04;
    pub const LGUI: u8 = 0x08;
    pub const RCTRL: u8 = 0x10;
    pub const RSHIFT: u8 = 0x20;
    pub const RALT: u8 = 0x40;
    pub const RGUI: u8 = 0x80;
    pub const SHIFT: u8 = LSHIFT | RSHIFT;
}

pub const REPEAT_DELAY_MS: u64 = 500;
pub const REPEAT_RATE_MS: u64 = 20;

const USAGE_CAPS_LOCK: u16 = 0x39;
const USAGE_SCROLL_LOCK: u16 = 0x47;
const USAGE_NUM_LOCK: u16 = 0x53;
const MAX_HELD: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Toggles {
    pub caps: bool,
    pub num: bool,
    pub scroll: bool,
}

impl Toggles {
    /// LED byte of a HID keyboard output report: Num, Caps, Scroll.
    pub fn led_bits(self) -> u8 {
        u8::from(self.num) | (u8::from(self.caps) << 1) | (u8::from(self.scroll) << 2)
    }

    /// EFI_KEY_TOGGLE_STATE: valid, scroll 0x01, num 0x02, caps 0x04.
    pub fn efi(self) -> u8 {
        0x80 | u8::from(self.scroll) | (u8::from(self.num) << 1) | (u8::from(self.caps) << 2)
    }

    pub fn from_efi(state: u8) -> Self {
        Self { scroll: state & 0x01 != 0, num: state & 0x02 != 0, caps: state & 0x04 != 0 }
    }
}

/// EFI_KEY_SHIFT_STATE for HID modifier bits (valid bit set).
pub fn efi_shift_state(modifiers: u8) -> u32 {
    use modifier::*;
    let mut state = 0x8000_0000u32;
    for (bit, efi) in [
        (RSHIFT, 0x01),
        (LSHIFT, 0x02),
        (RCTRL, 0x04),
        (LCTRL, 0x08),
        (RALT, 0x10),
        (LALT, 0x20),
        (RGUI, 0x40),
        (LGUI, 0x80),
    ] {
        if modifiers & bit != 0 {
            state |= efi;
        }
    }
    state
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub scan: u16,
    pub unicode: u16,
}

impl Key {
    const fn ch(c: char) -> Self {
        Self { scan: scan::NULL, unicode: c as u16 }
    }

    const fn sc(code: u16) -> Self {
        Self { scan: code, unicode: chars::NULL }
    }
}

const DIGITS: &[u8; 10] = b"1234567890";
const SHIFTED_DIGITS: &[u8; 10] = b"!@#$%^&*()";
// Usages 0x2D..=0x38: - = [ ] \ (non-US #) ; ' ` , . /
const PUNCT: &[u8; 12] = b"-=[]\\#;'`,./";
const SHIFTED_PUNCT: &[u8; 12] = b"_+{}|~:\"~<>?";

/// The UEFI key a usage produces, or `None` for modifiers, lock keys and
/// usages UEFI has no key for.
pub fn translate(usage: u16, modifiers: u8, toggles: Toggles) -> Option<Key> {
    let shift = modifiers & modifier::SHIFT != 0;
    let u = usize::from(usage);
    Some(match usage {
        0x04..=0x1D => {
            let c = b'a' + (usage - 0x04) as u8;
            Key::ch(if shift != toggles.caps { c.to_ascii_uppercase() } else { c } as char)
        }
        0x1E..=0x27 => Key::ch((if shift { SHIFTED_DIGITS } else { DIGITS })[u - 0x1E] as char),
        0x28 | 0x58 => Key { scan: scan::NULL, unicode: chars::CARRIAGE_RETURN },
        0x29 => Key::sc(scan::ESC),
        0x2A => Key { scan: scan::NULL, unicode: chars::BACKSPACE },
        0x2B => Key { scan: scan::NULL, unicode: chars::TAB },
        0x2C => Key::ch(' '),
        0x2D..=0x38 => Key::ch((if shift { SHIFTED_PUNCT } else { PUNCT })[u - 0x2D] as char),
        0x3A..=0x43 => Key::sc(scan::F1 + (usage - 0x3A)),
        0x44 => Key::sc(scan::F11),
        0x45 => Key::sc(scan::F12),
        0x48 => Key::sc(scan::PAUSE),
        0x49 => Key::sc(scan::INSERT),
        0x4A => Key::sc(scan::HOME),
        0x4B => Key::sc(scan::PAGE_UP),
        0x4C => Key::sc(scan::DELETE),
        0x4D => Key::sc(scan::END),
        0x4E => Key::sc(scan::PAGE_DOWN),
        0x4F => Key::sc(scan::RIGHT),
        0x50 => Key::sc(scan::LEFT),
        0x51 => Key::sc(scan::DOWN),
        0x52 => Key::sc(scan::UP),
        0x54 => Key::ch('/'),
        0x55 => Key::ch('*'),
        0x56 => Key::ch('-'),
        0x57 => Key::ch('+'),
        // Keypad: digits with Num Lock (and no Shift), navigation otherwise.
        0x59..=0x63 => {
            let digits = toggles.num && !shift;
            match (usage, digits) {
                (0x59..=0x61, true) => Key::ch((b'1' + (usage - 0x59) as u8) as char),
                (0x62, true) => Key::ch('0'),
                (0x63, true) => Key::ch('.'),
                (0x59, false) => Key::sc(scan::END),
                (0x5A, false) => Key::sc(scan::DOWN),
                (0x5B, false) => Key::sc(scan::PAGE_DOWN),
                (0x5C, false) => Key::sc(scan::LEFT),
                (0x5E, false) => Key::sc(scan::RIGHT),
                (0x5F, false) => Key::sc(scan::HOME),
                (0x60, false) => Key::sc(scan::UP),
                (0x61, false) => Key::sc(scan::PAGE_UP),
                (0x62, false) => Key::sc(scan::INSERT),
                (0x63, false) => Key::sc(scan::DELETE),
                _ => return None, // keypad 5 without Num Lock
            }
        }
        0x64 => Key::ch(if shift { '|' } else { '\\' }),
        0x68..=0x73 => Key::sc(scan::F13 + (usage - 0x68)),
        _ => return None,
    })
}

/// Usage and Shift for a printable ASCII character on a US layout; for
/// typing text in tests and the driver's self-test.
pub fn usage_for_ascii(c: char) -> Option<(u16, bool)> {
    let b = u8::try_from(u32::from(c)).ok()?;
    let find = |table: &[u8], base: u16| table.iter().position(|&t| t == b).map(|i| base + i as u16);
    Some(match b {
        b'a'..=b'z' => (0x04 + u16::from(b - b'a'), false),
        b'A'..=b'Z' => (0x04 + u16::from(b - b'A'), true),
        b'\r' | b'\n' => (0x28, false),
        b'\t' => (0x2B, false),
        b' ' => (0x2C, false),
        _ => {
            if let Some(u) = find(DIGITS, 0x1E) {
                (u, false)
            } else if let Some(u) = find(SHIFTED_DIGITS, 0x1E) {
                (u, true)
            } else if let Some(u) = find(&PUNCT[..5], 0x2D).or_else(|| find(&PUNCT[6..], 0x33)) {
                (u, false)
            } else if let Some(u) = find(&SHIFTED_PUNCT[..5], 0x2D).or_else(|| find(&SHIFTED_PUNCT[6..], 0x33)) {
                (u, true)
            } else {
                return None;
            }
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A key press, or a repeat of the last one.
    Key { key: Key, modifiers: u8, toggles: Toggles, repeat: bool },
    /// Only modifiers changed: a UEFI "partial" key (scan and unicode 0).
    Modifiers { modifiers: u8, toggles: Toggles },
    /// A lock key changed the toggles; the LEDs should follow.
    Toggles(Toggles),
}

#[derive(Debug, Default)]
pub struct KeyboardState {
    held: [u16; MAX_HELD],
    held_len: usize,
    modifiers: u8,
    pub toggles: Toggles,
    /// The key that repeats and when it next does.
    repeat: Option<(u16, u64)>,
}

impl KeyboardState {
    fn is_held(&self, usage: u16) -> bool {
        self.held[..self.held_len].contains(&usage)
    }

    pub fn modifiers(&self) -> u8 {
        self.modifiers
    }

    /// One input report: modifier bits and the usages held down.
    pub fn report(&mut self, modifiers: u8, held: &[u16], now_ms: u64, out: &mut dyn FnMut(Event)) {
        // ErrorRollOver / POSTFail / ErrorUndefined: too many keys; the
        // report says nothing about which. Keep the previous state.
        if held.iter().any(|&u| (0x01..=0x03).contains(&u)) {
            return;
        }
        let modifiers_changed = modifiers != self.modifiers;
        self.modifiers = modifiers;

        let mut pressed = false;
        for &usage in held.iter().filter(|&&u| u != 0) {
            if self.is_held(usage) {
                continue;
            }
            match usage {
                USAGE_CAPS_LOCK | USAGE_NUM_LOCK | USAGE_SCROLL_LOCK => {
                    match usage {
                        USAGE_CAPS_LOCK => self.toggles.caps = !self.toggles.caps,
                        USAGE_NUM_LOCK => self.toggles.num = !self.toggles.num,
                        _ => self.toggles.scroll = !self.toggles.scroll,
                    }
                    out(Event::Toggles(self.toggles));
                    out(Event::Modifiers { modifiers, toggles: self.toggles });
                    pressed = true;
                }
                _ => {
                    if let Some(key) = translate(usage, modifiers, self.toggles) {
                        out(Event::Key { key, modifiers, toggles: self.toggles, repeat: false });
                        self.repeat = Some((usage, now_ms + REPEAT_DELAY_MS));
                        pressed = true;
                    }
                }
            }
        }

        self.held_len = 0;
        for &usage in held.iter().filter(|&&u| u != 0) {
            if self.held_len < MAX_HELD && !self.is_held(usage) {
                self.held[self.held_len] = usage;
                self.held_len += 1;
            }
        }
        if let Some((usage, _)) = self.repeat {
            if !self.is_held(usage) {
                self.repeat = None;
            }
        }
        if modifiers_changed && !pressed {
            out(Event::Modifiers { modifiers, toggles: self.toggles });
        }
    }

    /// Key repeat; call regularly.
    pub fn tick(&mut self, now_ms: u64, out: &mut dyn FnMut(Event)) {
        let Some((usage, at)) = self.repeat else { return };
        if now_ms < at {
            return;
        }
        match translate(usage, self.modifiers, self.toggles) {
            Some(key) => {
                out(Event::Key { key, modifiers: self.modifiers, toggles: self.toggles, repeat: true });
                self.repeat = Some((usage, now_ms + REPEAT_RATE_MS));
            }
            None => self.repeat = None,
        }
    }

    /// The keyboard went away: nothing is held any more.
    pub fn release_all(&mut self) {
        self.held_len = 0;
        self.modifiers = 0;
        self.repeat = None;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn run(state: &mut KeyboardState, modifiers: u8, held: &[u16], now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        state.report(modifiers, held, now, &mut |e| events.push(e));
        events
    }

    fn keys(events: &[Event]) -> std::string::String {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Key { key, .. } if key.unicode != 0 => char::from_u32(u32::from(key.unicode)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn key_names() {
        assert_eq!(scan_name(0x0C), Some("F2"));
        assert_eq!(scan_name(scan::F12), Some("F12"));
        assert_eq!(scan_name(scan::ESC), Some("Esc"));
        assert_eq!(scan_name(0x69), Some("F14"));
        assert_eq!(scan_name(0x74), None);
        assert!(is_hotkey_like(0x0C) && is_hotkey_like(scan::DELETE) && is_hotkey_like(scan::ESC));
        assert!(!is_hotkey_like(scan::UP) && !is_hotkey_like(scan::NULL));
    }

    #[test]
    fn letters_shift_and_caps_lock() {
        let off = Toggles::default();
        let caps = Toggles { caps: true, ..off };
        assert_eq!(translate(0x04, 0, off), Some(Key::ch('a')));
        assert_eq!(translate(0x04, modifier::LSHIFT, off), Some(Key::ch('A')));
        assert_eq!(translate(0x1D, 0, caps), Some(Key::ch('Z')));
        assert_eq!(translate(0x1D, modifier::RSHIFT, caps), Some(Key::ch('z')));
        // Caps Lock leaves digits alone.
        assert_eq!(translate(0x1E, 0, caps), Some(Key::ch('1')));
        assert_eq!(translate(0x1E, modifier::LSHIFT, off), Some(Key::ch('!')));
    }

    #[test]
    fn special_keys() {
        let off = Toggles::default();
        assert_eq!(translate(0x28, 0, off), Some(Key { scan: 0, unicode: 0x0D }));
        assert_eq!(translate(0x2A, 0, off), Some(Key { scan: 0, unicode: 0x08 }));
        assert_eq!(translate(0x29, 0, off), Some(Key::sc(scan::ESC)));
        assert_eq!(translate(0x3A, 0, off), Some(Key::sc(scan::F1)));
        assert_eq!(translate(0x43, 0, off), Some(Key::sc(scan::F10)));
        assert_eq!(translate(0x45, 0, off), Some(Key::sc(scan::F12)));
        assert_eq!(translate(0x52, 0, off), Some(Key::sc(scan::UP)));
        assert_eq!(translate(0x4C, 0, off), Some(Key::sc(scan::DELETE)));
        assert_eq!(translate(0x2F, modifier::LSHIFT, off), Some(Key::ch('{')));
        assert_eq!(translate(0x38, modifier::LSHIFT, off), Some(Key::ch('?')));
        assert_eq!(translate(0xE1, 0, off), None);
        assert_eq!(translate(0x39, 0, off), None);
    }

    #[test]
    fn keypad_follows_num_lock() {
        let num = Toggles { num: true, ..Toggles::default() };
        assert_eq!(translate(0x59, 0, num), Some(Key::ch('1')));
        assert_eq!(translate(0x62, 0, num), Some(Key::ch('0')));
        assert_eq!(translate(0x59, 0, Toggles::default()), Some(Key::sc(scan::END)));
        assert_eq!(translate(0x60, modifier::LSHIFT, num), Some(Key::sc(scan::UP)));
        assert_eq!(translate(0x5D, 0, Toggles::default()), None);
    }

    #[test]
    fn only_new_keys_count() {
        let mut s = KeyboardState::default();
        assert_eq!(keys(&run(&mut s, 0, &[0x04], 0)), "a");
        assert_eq!(keys(&run(&mut s, 0, &[0x04, 0x16], 10)), "s");
        assert_eq!(run(&mut s, 0, &[0x16], 20), std::vec![]);
        assert_eq!(run(&mut s, 0, &[], 30), std::vec![]);
    }

    #[test]
    fn repeat_after_delay_then_at_rate() {
        let mut s = KeyboardState::default();
        run(&mut s, 0, &[0x51], 1000); // Down
        let mut out = Vec::new();
        for t in (1000..=1600).step_by(10) {
            s.tick(t, &mut |e| out.push((t, e)));
        }
        let times: Vec<u64> = out.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, std::vec![1500, 1520, 1540, 1560, 1580, 1600]);
        assert!(out.iter().all(|(_, e)| matches!(e, Event::Key { key, repeat: true, .. } if key.scan == scan::DOWN)));

        // Releasing the key stops the repeat.
        run(&mut s, 0, &[], 1605);
        let mut more = Vec::new();
        s.tick(3000, &mut |e| more.push(e));
        assert!(more.is_empty());
    }

    #[test]
    fn the_last_key_pressed_repeats_and_stops_on_its_release() {
        let mut s = KeyboardState::default();
        run(&mut s, 0, &[0x04], 0);
        run(&mut s, 0, &[0x04, 0x05], 100);
        let mut out = Vec::new();
        s.tick(700, &mut |e| out.push(e));
        assert_eq!(keys(&out), "b");
        // Releasing b while a is still held stops the repeat (as UsbKbDxe does).
        run(&mut s, 0, &[0x04], 710);
        out.clear();
        s.tick(2000, &mut |e| out.push(e));
        assert!(out.is_empty());
    }

    #[test]
    fn modifier_only_changes_are_partial_keys() {
        let mut s = KeyboardState::default();
        let ev = run(&mut s, modifier::LSHIFT, &[], 0);
        assert_eq!(ev, std::vec![Event::Modifiers { modifiers: modifier::LSHIFT, toggles: Toggles::default() }]);
        // A key together with the modifier change gives just the key.
        let ev = run(&mut s, modifier::LSHIFT | modifier::LCTRL, &[0x04], 10);
        assert_eq!(keys(&ev), "A");
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn caps_lock_toggles_and_reports_leds() {
        let mut s = KeyboardState::default();
        let ev = run(&mut s, 0, &[0x39], 0);
        let caps = Toggles { caps: true, ..Toggles::default() };
        assert_eq!(ev[0], Event::Toggles(caps));
        assert_eq!(caps.led_bits(), 0x02);
        assert_eq!(caps.efi(), 0x84);
        run(&mut s, 0, &[], 50);
        assert_eq!(keys(&run(&mut s, 0, &[0x04], 100)), "A");
        // Holding Caps Lock does not toggle again; a second press does.
        run(&mut s, 0, &[], 150);
        run(&mut s, 0, &[0x39], 200);
        assert!(!s.toggles.caps);
    }

    #[test]
    fn rollover_errors_keep_state() {
        let mut s = KeyboardState::default();
        run(&mut s, 0, &[0x04], 0);
        assert_eq!(run(&mut s, 0, &[0x01; 6], 10), std::vec![]);
        // Still holding a: no new press when it is reported again.
        assert_eq!(run(&mut s, 0, &[0x04], 20), std::vec![]);
    }

    #[test]
    fn release_all_stops_repeat() {
        let mut s = KeyboardState::default();
        run(&mut s, modifier::LSHIFT, &[0x04], 0);
        s.release_all();
        let mut out = Vec::new();
        s.tick(5000, &mut |e| out.push(e));
        assert!(out.is_empty());
        assert_eq!(s.modifiers(), 0);
    }

    #[test]
    fn efi_shift_state_bits() {
        assert_eq!(efi_shift_state(0), 0x8000_0000);
        assert_eq!(efi_shift_state(modifier::LSHIFT | modifier::RCTRL), 0x8000_0006);
        assert_eq!(efi_shift_state(modifier::LGUI | modifier::RALT), 0x8000_0090);
        assert_eq!(Toggles::from_efi(0x86), Toggles { caps: true, num: true, scroll: false });
    }

    #[test]
    fn ascii_round_trips_through_usages() {
        for c in (0x20u8..0x7F).map(char::from) {
            let (usage, shift) = usage_for_ascii(c).unwrap_or_else(|| panic!("no usage for {c:?}"));
            let modifiers = if shift { modifier::LSHIFT } else { 0 };
            let key = translate(usage, modifiers, Toggles::default()).unwrap();
            assert_eq!(key.unicode, c as u16, "{c:?} -> usage {usage:#04x}");
        }
        assert_eq!(usage_for_ascii('\n'), Some((0x28, false)));
    }
}
