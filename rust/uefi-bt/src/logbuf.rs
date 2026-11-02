//! A log kept in RAM for firmware drivers: the first `HEAD` bytes stay
//! (they tell how and when the driver started), after them a ring keeps the
//! newest `RING` bytes. A message repeated in a row is written
//! [`REPEATS_SHOWN`] times, then only counted, so one noisy warning can't
//! push everything else out.

use alloc::vec::Vec;
use core::fmt::Write;

/// Copies of a message written in a row before the rest are only counted.
pub const REPEATS_SHOWN: u32 = 2;
/// Marks where the ring dropped older lines.
pub const GAP_NOTE: &[u8] = b"    ... (older lines dropped)\n";
/// Longest line kept, newline included; longer ones are cut.
pub const MAX_LINE: usize = 512;

pub struct LogBuf<const HEAD: usize, const RING: usize> {
    head: [u8; HEAD],
    head_len: usize,
    /// A line didn't fit: everything from then on goes to the ring.
    head_closed: bool,
    ring: [u8; RING],
    /// Total bytes ever written to the ring; it holds the last `RING`.
    written: usize,
    /// Hash of the last message (without its time) and how often it came.
    last_hash: u64,
    repeats: u32,
}

/// One line, without allocating.
struct Line {
    buf: [u8; MAX_LINE],
    len: usize,
}

impl Line {
    const fn new() -> Self {
        Self { buf: [0; MAX_LINE], len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    /// End with a newline, replacing the last byte if the line is full.
    fn finish(&mut self) -> &[u8] {
        if self.len == self.buf.len() {
            self.buf[self.len - 1] = b'\n';
        } else {
            self.buf[self.len] = b'\n';
            self.len += 1;
        }
        &self.buf[..self.len]
    }
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

/// FNV-1a, to recognize a repeated message.
fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

impl<const HEAD: usize, const RING: usize> Default for LogBuf<HEAD, RING> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HEAD: usize, const RING: usize> LogBuf<HEAD, RING> {
    pub const fn new() -> Self {
        Self {
            head: [0; HEAD],
            head_len: 0,
            head_closed: false,
            ring: [0; RING],
            written: 0,
            last_hash: 0,
            repeats: 0,
        }
    }

    fn put(&mut self, text: &[u8], sink: &mut impl FnMut(&[u8])) {
        if !self.head_closed && self.head_len + text.len() <= HEAD {
            self.head[self.head_len..self.head_len + text.len()].copy_from_slice(text);
            self.head_len += text.len();
        } else {
            self.head_closed = true;
            for &b in text {
                self.ring[self.written % RING] = b;
                self.written += 1;
            }
        }
        sink(text);
    }

    /// Add `message` as one line stamped with `now_ms`. `sink` gets every
    /// line actually written (a debug console, say). Returns whether
    /// anything was written.
    pub fn add(&mut self, now_ms: u64, message: &[u8], mut sink: impl FnMut(&[u8])) -> bool {
        let message = &message[..message.len().min(MAX_LINE)];
        let key = hash(message);
        if key == self.last_hash {
            self.repeats += 1;
            if self.repeats >= REPEATS_SHOWN {
                return false;
            }
        } else {
            if self.repeats >= REPEATS_SHOWN {
                let mut note = Line::new();
                let _ = write!(note, "{now_ms:>7}   (the line before came {} more times)", self.repeats + 1 - REPEATS_SHOWN);
                self.put(note.finish(), &mut sink);
            }
            self.last_hash = key;
            self.repeats = 0;
        }
        let mut line = Line::new();
        let _ = write!(line, "{now_ms:>7} ");
        line.push(message);
        self.put(line.finish(), &mut sink);
        true
    }

    /// The head, then the ring from its first complete line.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.head_len + GAP_NOTE.len() + RING);
        out.extend_from_slice(&self.head[..self.head_len]);
        let len = self.written.min(RING);
        let start = self.written - len;
        let mut ring = (start..self.written).map(|i| self.ring[i % RING]);
        if start > 0 {
            out.extend_from_slice(GAP_NOTE);
            // The oldest line in the ring has lost its start.
            for b in ring.by_ref() {
                if b == b'\n' {
                    break;
                }
            }
        }
        out.extend(ring);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn text<const H: usize, const R: usize>(log: &LogBuf<H, R>) -> String {
        String::from_utf8(log.snapshot()).unwrap()
    }

    #[test]
    fn head_then_ring() {
        // Each line is "      N message N\n": 18 bytes for N < 10.
        let mut log = LogBuf::<40, 64>::new();
        for n in 0..2u64 {
            log.add(n, alloc::format!("message {n}").as_bytes(), |_| {});
        }
        assert_eq!(text(&log), "      0 message 0\n      1 message 1\n");
        // Head full (36 of 40 bytes): the rest goes to the ring.
        for n in 2..5u64 {
            log.add(n, alloc::format!("message {n}").as_bytes(), |_| {});
        }
        assert_eq!(text(&log), "      0 message 0\n      1 message 1\n      2 message 2\n      3 message 3\n      4 message 4\n");
    }

    #[test]
    fn ring_keeps_the_newest_complete_lines() {
        let mut log = LogBuf::<18, 40>::new();
        for n in 0..6u64 {
            log.add(n, alloc::format!("message {n}").as_bytes(), |_| {});
        }
        // The head keeps line 0; the 40-byte ring holds the end of line 3
        // (dropped as partial) and lines 4 and 5.
        let gap = core::str::from_utf8(GAP_NOTE).unwrap();
        assert_eq!(text(&log), alloc::format!("      0 message 0\n{gap}      4 message 4\n      5 message 5\n"));
    }

    #[test]
    fn repeats_are_counted() {
        let mut log = LogBuf::<0, 400>::new();
        let mut sunk = 0;
        for n in 0..5u64 {
            log.add(n, b"OutOfMemory", |_| sunk += 1);
        }
        log.add(9, b"something else", |_| sunk += 1);
        assert_eq!(
            text(&log),
            "      0 OutOfMemory\n      1 OutOfMemory\n      9   (the line before came 3 more times)\n      9 something else\n"
        );
        assert_eq!(sunk, 4);
        // The same message after another one is new again.
        log.add(10, b"OutOfMemory", |_| {});
        assert!(text(&log).ends_with("     10 OutOfMemory\n"));
    }

    #[test]
    fn long_lines_are_cut_with_a_newline() {
        let mut log = LogBuf::<0, 2000>::new();
        log.add(1, &[b'x'; 900], |_| {});
        let out = log.snapshot();
        assert_eq!(out.len(), MAX_LINE);
        assert_eq!(out.last(), Some(&b'\n'));
    }
}
