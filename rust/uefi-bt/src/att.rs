//! One-line descriptions of what travels inside HCI ACL packets: ATT (GATT),
//! SMP and LE signaling. For tracing a connection without the host stack's
//! help, e.g. to see notifications nobody subscribed to.

use alloc::string::String;
use core::fmt::Write;

const CID_ATT: u16 = 0x0004;
const CID_SIGNALING: u16 = 0x0005;
const CID_SMP: u16 = 0x0006;

fn hex(out: &mut String, bytes: &[u8], max: usize) {
    for b in bytes.iter().take(max) {
        let _ = write!(out, " {b:02x}");
    }
    if bytes.len() > max {
        let _ = write!(out, " ... ({} bytes)", bytes.len());
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn att_error_name(code: u8) -> &'static str {
    match code {
        0x01 => "invalid handle",
        0x02 => "read not permitted",
        0x03 => "write not permitted",
        0x05 => "insufficient authentication",
        0x06 => "request not supported",
        0x08 => "insufficient authorization",
        0x0A => "attribute not found",
        0x0D => "invalid attribute value length",
        0x0E => "unlikely error",
        0x0F => "insufficient encryption",
        _ => "error",
    }
}

fn att(pdu: &[u8]) -> String {
    let mut s = String::new();
    let Some(&opcode) = pdu.first() else {
        return String::from("ATT (empty)");
    };
    let handle = u16_at(pdu, 1);
    let value = pdu.get(3..).unwrap_or(&[]);
    match (opcode, handle) {
        (0x01, _) if pdu.len() >= 5 => {
            let _ = write!(
                s,
                "ATT error for request {:#04x} on {:#06x}: {:#04x} ({})",
                pdu[1],
                u16_at(pdu, 2).unwrap_or(0),
                pdu[4],
                att_error_name(pdu[4])
            );
        }
        (0x02 | 0x03, Some(mtu)) => {
            let _ = write!(s, "ATT MTU {} {mtu}", if opcode == 0x02 { "request" } else { "response" });
        }
        (0x0A, Some(h)) => {
            let _ = write!(s, "ATT read {h:#06x}");
        }
        (0x0B, _) => {
            s.push_str("ATT read response:");
            hex(&mut s, &pdu[1..], 16);
        }
        (0x12, Some(h)) => {
            let _ = write!(s, "ATT write request {h:#06x} <-");
            hex(&mut s, value, 16);
        }
        (0x13, _) => s.push_str("ATT write response"),
        (0x52, Some(h)) => {
            let _ = write!(s, "ATT write command {h:#06x} <-");
            hex(&mut s, value, 16);
        }
        (0x1B, Some(h)) => {
            let _ = write!(s, "ATT notification {h:#06x}:");
            hex(&mut s, value, 16);
        }
        (0x1D, Some(h)) => {
            let _ = write!(s, "ATT indication {h:#06x}:");
            hex(&mut s, value, 16);
        }
        (0x1E, _) => s.push_str("ATT confirmation"),
        _ => {
            let _ = write!(s, "ATT opcode {opcode:#04x} ({} bytes)", pdu.len());
        }
    }
    s
}

/// Describe one ACL packet (HCI ACL header included). `None` for
/// continuation fragments and anything too short to parse.
pub fn describe(packet: &[u8]) -> Option<String> {
    let flags = u16_at(packet, 0)? >> 12;
    // Packet boundary: 0b00 and 0b10 start a PDU, 0b01 continues one.
    if flags & 0b11 == 0b01 {
        return None;
    }
    let l2cap = packet.get(4..)?;
    let length = usize::from(u16_at(l2cap, 0)?);
    let cid = u16_at(l2cap, 2)?;
    let payload = l2cap.get(4..)?;
    let payload = &payload[..payload.len().min(length)];
    Some(match cid {
        CID_ATT => att(payload),
        CID_SMP => alloc::format!("SMP opcode {:#04x} ({} bytes)", payload.first().copied().unwrap_or(0), payload.len()),
        CID_SIGNALING => alloc::format!("LE signaling code {:#04x} ({} bytes)", payload.first().copied().unwrap_or(0), payload.len()),
        other => alloc::format!("L2CAP CID {other:#06x} ({} bytes)", payload.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ACL start packet for connection 0x0200 carrying `pdu` on `cid`.
    fn acl(cid: u16, pdu: &[u8]) -> std::vec::Vec<u8> {
        extern crate std;
        let mut p = std::vec![0x00, 0x22];
        p.extend_from_slice(&((pdu.len() + 4) as u16).to_le_bytes());
        p.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        p.extend_from_slice(&cid.to_le_bytes());
        p.extend_from_slice(pdu);
        p
    }

    extern crate std;

    #[test]
    fn notifications_show_handle_and_value() {
        let p = acl(CID_ATT, &[0x1B, 0x4C, 0x00, 0x02, 0x00, 0x0B, 0, 0, 0, 0, 0]);
        assert_eq!(describe(&p).unwrap(), "ATT notification 0x004c: 02 00 0b 00 00 00 00 00");
    }

    #[test]
    fn writes_and_errors_are_readable() {
        assert_eq!(describe(&acl(CID_ATT, &[0x52, 0x14, 0x00, 0x00])).unwrap(), "ATT write command 0x0014 <- 00");
        assert_eq!(describe(&acl(CID_ATT, &[0x12, 0x4D, 0x00, 0x01, 0x00])).unwrap(), "ATT write request 0x004d <- 01 00");
        assert_eq!(
            describe(&acl(CID_ATT, &[0x01, 0x12, 0x4D, 0x00, 0x0F])).unwrap(),
            "ATT error for request 0x12 on 0x004d: 0x0f (insufficient encryption)"
        );
    }

    #[test]
    fn other_channels_and_fragments() {
        assert_eq!(describe(&acl(CID_SMP, &[0x0B, 0x0D])).unwrap(), "SMP opcode 0x0b (2 bytes)");
        assert_eq!(describe(&acl(CID_SIGNALING, &[0x12, 0x01])).unwrap(), "LE signaling code 0x12 (2 bytes)");
        // A continuation fragment (boundary flag 0b01) is skipped.
        assert_eq!(describe(&[0x00, 0x12, 0x02, 0x00, 0xAA, 0xBB]), None);
        assert_eq!(describe(&[0x00]), None);
    }
}
