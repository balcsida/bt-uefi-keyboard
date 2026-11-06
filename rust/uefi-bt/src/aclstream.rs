//! The controller's ACL pipe as a byte stream. The Bluetooth USB transport
//! doesn't tie HCI packets to USB transfers: one transfer may hold more
//! than one ACL packet, and one packet may span transfers; Linux's btusb
//! reassembles the same way. Until Nov 3 a transfer was taken as one
//! packet, so a second packet in it was lost, and a packet spanning
//! transfers was cut short. (That night a key release went missing on the
//! board, and the key repeated until the next key press; which loss it
//! was, the counters here are to tell.)
//!
//! Pure logic, tested on the host.

use alloc::vec::Vec;

/// The longest ACL packet kept whole: header and 2048 bytes of data (the
/// MT7922's LE buffers are 251 bytes; MediaTek's crash dumps run longer).
pub const MAX_PACKET: usize = 4 + 2048;
/// Bytes kept at most: a few packets' worth.
const CAPACITY: usize = 4 * MAX_PACKET;

/// What happened on the stream, for the logs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamStats {
    /// Transfers that held the end of one packet and the start of another.
    pub shared_transfers: u32,
    /// Packets that spanned transfers.
    pub spanning_packets: u32,
    /// Times bytes were thrown away to get back in step: a header claiming
    /// more than `MAX_PACKET`, or a packet whose rest never came.
    pub resyncs: u32,
}

#[derive(Debug, Default)]
pub struct AclStream {
    bytes: Vec<u8>,
    pub stats: StreamStats,
}

/// The length of the packet starting at `bytes[0]`, once its header is
/// there.
fn packet_len(bytes: &[u8]) -> Option<usize> {
    let header = bytes.get(..4)?;
    Some(4 + usize::from(u16::from_le_bytes([header[2], header[3]])))
}

/// Whether `bytes` can be the start of an ACL packet from the controller:
/// a connection handle, a first or continuing fragment (packet boundary
/// 0b10 or 0b01), and a data length that fits. For data a USB stack
/// reported together with a timeout, which is only taken if it passes.
pub fn plausible_start(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..4) else { return false };
    let raw = u16::from_le_bytes([header[0], header[1]]);
    let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
    raw & 0x0FFF <= 0x0EFF && matches!((raw >> 12) & 0b11, 0b01 | 0b10) && len > 0 && 4 + len <= MAX_PACKET
}

impl AclStream {
    /// Bytes waiting that don't make a whole packet yet (0 if none).
    pub fn pending(&self) -> usize {
        self.bytes.len() - self.complete_bytes()
    }

    /// The bytes of the whole packets at the front.
    fn complete_bytes(&self) -> usize {
        let mut at = 0;
        while let Some(len) = packet_len(&self.bytes[at..]) {
            if len > MAX_PACKET || at + len > self.bytes.len() {
                break;
            }
            at += len;
        }
        at
    }

    /// Add the bytes of one transfer.
    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.pending() > 0 {
            self.stats.spanning_packets += 1;
        }
        if self.bytes.len() + data.len() > CAPACITY {
            // Nothing takes packets out: out of step, start again.
            self.stats.resyncs += 1;
            self.bytes.clear();
        }
        let start = self.bytes.len();
        self.bytes.extend_from_slice(data);
        let end = self.bytes.len();
        // A packet boundary inside this transfer: it held more than one.
        let mut at = 0;
        while let Some(len) = packet_len(&self.bytes[at..]) {
            if len > MAX_PACKET {
                break;
            }
            at += len;
            if at >= end {
                break;
            }
            if at > start {
                self.stats.shared_transfers += 1;
                break;
            }
        }
    }

    /// The next whole packet, copied to `out` (as much as fits). Returns its
    /// full length.
    pub fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        let len = packet_len(&self.bytes)?;
        if len > MAX_PACKET {
            // No packet that long comes from this controller: out of step.
            self.stats.resyncs += 1;
            self.bytes.clear();
            return None;
        }
        if self.bytes.len() < len {
            return None;
        }
        let n = len.min(out.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes.drain(..len);
        Some(len)
    }

    /// The rest of a started packet didn't come: drop what is waiting.
    pub fn give_up(&mut self) {
        if !self.bytes.is_empty() {
            self.stats.resyncs += 1;
            self.bytes.clear();
        }
    }

    /// Forget everything (draining, a new owner).
    pub fn clear(&mut self) {
        self.bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// An ACL start fragment on handle 0x0200 with `data`.
    fn packet(data: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x22];
        p.extend_from_slice(&(data.len() as u16).to_le_bytes());
        p.extend_from_slice(data);
        p
    }

    fn pop(s: &mut AclStream) -> Option<Vec<u8>> {
        let mut out = [0u8; MAX_PACKET];
        s.pop(&mut out).map(|n| out[..n].to_vec())
    }

    #[test]
    fn one_packet_per_transfer() {
        let mut s = AclStream::default();
        let a = packet(&[1; 16]);
        s.push(&a);
        assert_eq!(s.pending(), 0);
        assert_eq!(pop(&mut s), Some(a));
        assert_eq!(pop(&mut s), None);
        assert_eq!(s.stats, StreamStats::default());
    }

    #[test]
    fn two_packets_in_one_transfer() {
        let mut s = AclStream::default();
        let (a, b) = (packet(&[1; 16]), packet(&[2; 11]));
        s.push(&[a.clone(), b.clone()].concat());
        assert_eq!(s.stats.shared_transfers, 1);
        assert_eq!(pop(&mut s), Some(a));
        assert_eq!(pop(&mut s), Some(b));
        assert_eq!(pop(&mut s), None);
    }

    #[test]
    fn a_packet_spanning_transfers() {
        let mut s = AclStream::default();
        let a = packet(&[3; 40]);
        // Not even the header at first, then the middle, then the end.
        s.push(&a[..3]);
        assert_eq!((pop(&mut s), s.pending()), (None, 3));
        s.push(&a[3..20]);
        assert_eq!(pop(&mut s), None);
        s.push(&a[20..]);
        assert_eq!(s.stats.spanning_packets, 2);
        assert_eq!(pop(&mut s), Some(a));
    }

    #[test]
    fn the_end_of_one_and_the_start_of_the_next() {
        let mut s = AclStream::default();
        let (a, b) = (packet(&[4; 20]), packet(&[5; 20]));
        s.push(&a[..5]);
        s.push(&[&a[5..], &b[..7]].concat());
        assert_eq!((s.stats.spanning_packets, s.stats.shared_transfers), (1, 1));
        assert_eq!(pop(&mut s), Some(a));
        assert_eq!((pop(&mut s), s.pending()), (None, 7));
        s.push(&b[7..]);
        assert_eq!(s.stats.spanning_packets, 2);
        assert_eq!(pop(&mut s), Some(b));
    }

    #[test]
    fn out_of_step_and_given_up() {
        let mut s = AclStream::default();
        // A length no packet from this controller has: dropped.
        s.push(&[0x00, 0x22, 0xFF, 0xFF, 1, 2, 3]);
        assert_eq!(pop(&mut s), None);
        assert_eq!((s.stats.resyncs, s.pending()), (1, 0));
        // The next transfer starts fresh.
        let a = packet(&[6; 8]);
        s.push(&a);
        assert_eq!(pop(&mut s), Some(a));
        // A start whose rest never comes.
        s.push(&packet(&[7; 30])[..10]);
        s.give_up();
        assert_eq!((s.stats.resyncs, s.pending()), (2, 0));
        s.give_up();
        assert_eq!(s.stats.resyncs, 2);
    }

    #[test]
    fn a_packet_longer_than_the_buffer_is_taken_out_whole() {
        let mut s = AclStream::default();
        let (a, b) = (packet(&[8; 100]), packet(&[9; 4]));
        s.push(&[a.clone(), b.clone()].concat());
        let mut small = [0u8; 10];
        assert_eq!(s.pop(&mut small), Some(104));
        assert_eq!(small[..], a[..10]);
        assert_eq!(pop(&mut s), Some(b));
    }

    #[test]
    fn nothing_grows_without_bound() {
        let mut s = AclStream::default();
        // Pushed without pops: dropped at the cap, never grown past it.
        for _ in 0..(CAPACITY / 512 + 2) {
            s.push(&[0u8; 512]);
        }
        assert!(s.stats.resyncs >= 1);
        assert!(s.bytes.len() <= CAPACITY);
    }

    #[test]
    fn plausible_starts() {
        assert!(plausible_start(&packet(&[1; 11])));
        // Continuation fragment, handle 0x0200.
        assert!(plausible_start(&[0x00, 0x12, 0x05, 0x00, 1, 2, 3, 4, 5]));
        // Zeros (what a USB stack that didn't copy anything leaves), no
        // data, a reserved boundary, a length too long, too short.
        assert!(!plausible_start(&[0; 16]));
        assert!(!plausible_start(&[0x00, 0x22, 0x00, 0x00]));
        assert!(!plausible_start(&[0x00, 0x32, 0x05, 0x00, 1, 2, 3, 4, 5]));
        assert!(!plausible_start(&[0x00, 0x22, 0xFF, 0xFF]));
        assert!(!plausible_start(&[0x00, 0x22]));
    }
}
