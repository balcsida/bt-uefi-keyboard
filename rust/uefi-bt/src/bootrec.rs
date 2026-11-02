//! A one-line record of how bt-kb-dxe's boot went, kept in the
//! non-volatile variable `BtKbLastBoot`. Unlike the driver's log (a
//! volatile variable), it outlives boots that never reach an OS: a reset
//! from setup (Save & Exit), a hang, a power-off. The next boot reads it
//! and puts it near the top of its own log.
//!
//! Any OS can write the variable, so [`sanitize`] is all a reader trusts.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// Longest record written or read, in bytes.
pub const MAX_LEN: usize = 360;
/// Kinds of hotkey-like keys counted.
const MAX_HOTKEYS: usize = 4;
/// Failure messages are cut to this many bytes.
const MAX_FAILURE: usize = 90;
/// Ends the record of a boot that reached an OS; a reader that doesn't
/// find it knows the boot ended some other way.
pub const OS_STARTED: &str = "OS started";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BootRecord {
    /// When the driver loaded, in ms after the CPU reset.
    pub loaded_at_ms: u64,
    pub from_shell: bool,
    /// Driver times below are ms since the driver loaded.
    pub ready_ms: Option<u64>,
    pub failure: Option<(u64, String)>,
    /// Links left from before this boot, closed at bring-up.
    pub links_closed: u32,
    pub connections: u32,
    pub first_connection_ms: Option<u64>,
    pub first_keys_ms: Option<u64>,
    /// The controller's Encryption Change event: `Some(true)` for v2.
    pub encryption_v2: Option<bool>,
    pub disconnects: u32,
    pub last_disconnect_reason: Option<u8>,
    pub key_reports: u32,
    /// Hotkey-like keys delivered (F-keys, Esc, Delete), with counts.
    pub hotkeys: Vec<(&'static str, u32)>,
    pub healthy_ms: Option<u64>,
    pub os_started_ms: Option<u64>,
    /// When this record was last written.
    pub updated_ms: u64,
}

/// "9.49 s".
struct Secs(u64);

impl core::fmt::Display for Secs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{:02} s", self.0 / 1000, (self.0 % 1000) / 10)
    }
}

impl BootRecord {
    /// Count one delivery of a hotkey-like key. Returns whether it is the
    /// first of its kind this boot.
    pub fn count_hotkey(&mut self, name: &'static str) -> bool {
        if let Some((_, n)) = self.hotkeys.iter_mut().find(|(k, _)| *k == name) {
            *n += 1;
            return false;
        }
        if self.hotkeys.len() < MAX_HOTKEYS {
            self.hotkeys.push((name, 1));
        }
        true
    }

    /// The record as one line of at most [`MAX_LEN`] bytes.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let origin = if self.from_shell { "from a UEFI shell" } else { "by the firmware" };
        let _ = write!(s, "loaded {} after reset {origin}", Secs(self.loaded_at_ms));
        if self.links_closed > 0 {
            let _ = write!(s, "; closed {} link(s) left from before", self.links_closed);
        }
        match (self.ready_ms, &self.failure) {
            (Some(ms), _) => {
                let _ = write!(s, "; ready +{}", Secs(ms));
            }
            (None, None) => s.push_str("; no controller started"),
            (None, Some(_)) => {}
        }
        if self.connections == 0 {
            if self.ready_ms.is_some() {
                s.push_str("; keyboard never connected");
            }
        } else {
            let _ = write!(s, "; keyboard connected {}x", self.connections);
            if let Some(ms) = self.first_connection_ms {
                let _ = write!(s, ", first +{}", Secs(ms));
            }
            if let Some(ms) = self.first_keys_ms {
                let _ = write!(s, ", keys +{}", Secs(ms));
            }
            match self.encryption_v2 {
                Some(true) => s.push_str(", encryption v2"),
                Some(false) => s.push_str(", encryption v1"),
                None => {}
            }
            let _ = write!(s, "; {} key reports", self.key_reports);
        }
        if self.disconnects > 0 {
            let _ = write!(s, "; {} disconnects", self.disconnects);
            if let Some(reason) = self.last_disconnect_reason {
                let _ = write!(s, " (last reason {reason:#04x})");
            }
        }
        for (i, (name, n)) in self.hotkeys.iter().enumerate() {
            let _ = write!(s, "{}{name} x{n}", if i == 0 { "; " } else { ", " });
        }
        if let Some(ms) = self.healthy_ms {
            let _ = write!(s, "; ran fine at +{}", Secs(ms));
        }
        if let Some((ms, why)) = &self.failure {
            let why = &why.as_bytes()[..why.len().min(MAX_FAILURE)];
            let _ = write!(s, "; failed +{}: {}", Secs(*ms), sanitize(why));
        }
        match self.os_started_ms {
            Some(ms) => {
                let _ = write!(s, "; {OS_STARTED} +{}", Secs(ms));
            }
            None => {
                let _ = write!(s, "; last update +{}", Secs(self.updated_ms));
            }
        }
        if s.len() > MAX_LEN {
            // Cut at a character boundary: the text is ASCII except for
            // anything a failure message carried, and that is sanitized.
            let mut cut = MAX_LEN;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
        }
        s
    }
}

/// A stored record as printable ASCII (anything else becomes `?`), at
/// most [`MAX_LEN`] bytes, without trailing NULs or line breaks.
pub fn sanitize(data: &[u8]) -> String {
    let end = data.iter().rposition(|&b| b != 0 && b != b'\n' && b != b'\r').map_or(0, |i| i + 1);
    data[..end.min(MAX_LEN)]
        .iter()
        .map(|&b| if (0x20..0x7F).contains(&b) { char::from(b) } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_session() {
        let mut r = BootRecord { loaded_at_ms: 9492, ready_ms: Some(217), ..BootRecord::default() };
        r.connections = 1;
        r.first_connection_ms = Some(486);
        r.first_keys_ms = Some(700);
        r.encryption_v2 = Some(true);
        r.key_reports = 172;
        assert!(r.count_hotkey("Delete"));
        for _ in 0..22 {
            assert!(!r.count_hotkey("Delete"));
        }
        r.healthy_ms = Some(15229);
        r.os_started_ms = Some(24829);
        assert_eq!(
            r.render(),
            "loaded 9.49 s after reset by the firmware; ready +0.21 s; keyboard connected 1x, first +0.48 s, keys +0.70 s, \
             encryption v2; 172 key reports; Delete x23; ran fine at +15.22 s; OS started +24.82 s"
        );
    }

    #[test]
    fn boot_without_an_end() {
        let r = BootRecord {
            loaded_at_ms: 10843,
            ready_ms: Some(220),
            links_closed: 1,
            disconnects: 2,
            last_disconnect_reason: Some(0x13),
            updated_ms: 61000,
            ..BootRecord::default()
        };
        let text = r.render();
        assert_eq!(
            text,
            "loaded 10.84 s after reset by the firmware; closed 1 link(s) left from before; ready +0.22 s; \
             keyboard never connected; 2 disconnects (last reason 0x13); last update +61.00 s"
        );
        assert!(!text.contains(OS_STARTED));
    }

    #[test]
    fn failures_are_cut_and_sanitized() {
        let long = alloc::format!("bad\u{7}byte {}", "x".repeat(200));
        let r = BootRecord { from_shell: true, failure: Some((5, long)), ..BootRecord::default() };
        let text = r.render();
        assert!(text.starts_with("loaded 0.00 s after reset from a UEFI shell; failed +0.00 s: bad?byte xxx"));
        assert!(text.len() <= MAX_LEN);
        assert!(text.is_ascii());
    }

    #[test]
    fn no_controller() {
        let r = BootRecord { loaded_at_ms: 320, os_started_ms: Some(6031), ..BootRecord::default() };
        assert_eq!(r.render(), "loaded 0.32 s after reset by the firmware; no controller started; OS started +6.03 s");
    }

    #[test]
    fn at_most_four_hotkey_kinds() {
        let mut r = BootRecord::default();
        for name in ["F1", "F2", "Esc", "Delete", "F12"] {
            r.count_hotkey(name);
        }
        assert_eq!(r.hotkeys.len(), 4);
        assert!(!r.render().contains("F12"));
    }

    #[test]
    fn reading_back() {
        assert_eq!(sanitize(b"ok; OS started +1.00 s\0\0"), "ok; OS started +1.00 s");
        assert_eq!(sanitize(b"a\xffb\tc\n"), "a?b?c");
        assert_eq!(sanitize(&[b'y'; 1000]).len(), MAX_LEN);
        assert_eq!(sanitize(b""), "");
    }
}
