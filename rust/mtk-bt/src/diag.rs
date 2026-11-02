//! What a MediaTek controller sends on the ACL pipe besides connection data.
//!
//! The firmware tags out-of-band data with vendor-reserved ACL handles, each
//! sent as a single complete packet: a crash dump (`0xFC6F`, the last packet
//! ends with `coredump end`) and debug logs and events (`0x05FF`, `0x05FE`,
//! `0x2EFD`). Linux btmtk (`btmtk_usb_recv_acl`) handles the same set.

pub const HANDLE_FW_DUMP: u16 = 0xFC6F;
pub const HANDLE_FW_LOG_1: u16 = 0x05FF;
pub const HANDLE_FW_LOG_2: u16 = 0x05FE;
pub const HANDLE_FW_DEBUG_EVENT: u16 = 0x2EFD;

/// Marker at the end of the last crash dump packet (Linux checks the 12
/// bytes before the final byte).
pub const DUMP_END_MARKER: &[u8] = b"coredump end";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclKind {
    /// Connection data for the 12-bit connection `handle`.
    Data { handle: u16 },
    /// A crash dump packet: the controller firmware has crashed. `last` is
    /// set on the packet that ends the dump.
    FirmwareDump { last: bool },
    /// Firmware debug log or debug event; safe to drop.
    FirmwareDiag,
    /// Shorter than the 4-byte ACL header.
    Malformed,
}

/// Classify one ACL packet from the controller, header included.
pub fn classify_acl(packet: &[u8]) -> AclKind {
    if packet.len() < 4 {
        return AclKind::Malformed;
    }
    match u16::from_le_bytes([packet[0], packet[1]]) {
        HANDLE_FW_DUMP => {
            let tail = &packet[packet.len().saturating_sub(DUMP_END_MARKER.len() + 4)..];
            let last = tail.windows(DUMP_END_MARKER.len()).any(|w| w == DUMP_END_MARKER);
            AclKind::FirmwareDump { last }
        }
        HANDLE_FW_LOG_1 | HANDLE_FW_LOG_2 | HANDLE_FW_DEBUG_EVENT => AclKind::FirmwareDiag,
        raw => AclKind::Data { handle: raw & 0x0FFF },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_data_keeps_the_12_bit_handle() {
        // Handle 0x040 with "first automatically flushable" boundary flags (0x2).
        assert_eq!(classify_acl(&[0x40, 0x20, 0x03, 0x00, 1, 2, 3]), AclKind::Data { handle: 0x040 });
    }

    #[test]
    fn crash_dump_and_its_end_are_recognized() {
        let mut first = std::vec![0x6f, 0xfc, 0x10, 0x00];
        first.extend_from_slice(&[0xAA; 16]);
        assert_eq!(classify_acl(&first), AclKind::FirmwareDump { last: false });

        let mut last = std::vec![0x6f, 0xfc, 0x20, 0x00];
        last.extend_from_slice(b"...register dump...");
        last.extend_from_slice(DUMP_END_MARKER);
        last.push(0);
        assert_eq!(classify_acl(&last), AclKind::FirmwareDump { last: true });
    }

    #[test]
    fn debug_logs_and_events_are_diagnostics() {
        for raw in [HANDLE_FW_LOG_1, HANDLE_FW_LOG_2, HANDLE_FW_DEBUG_EVENT] {
            let [lo, hi] = raw.to_le_bytes();
            assert_eq!(classify_acl(&[lo, hi, 0, 0]), AclKind::FirmwareDiag);
        }
    }

    #[test]
    fn short_packets_are_malformed() {
        assert_eq!(classify_acl(&[0x6f, 0xfc, 0x00]), AclKind::Malformed);
    }
}
