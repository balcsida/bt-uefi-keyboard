//! What the driver watches on the raw HCI link, independent of the host
//! stack: LE connections to the keyboard, encryption, disconnections, and
//! ATT notifications. Key reports are taken straight from here, so none
//! are lost while the host stack is still setting up the connection.

/// A link-level fact from one HCI event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEvent {
    /// LE (Enhanced) Connection Complete with success.
    Connected { handle: u16, peer: [u8; 6], peer_random: bool },
    /// LE (Enhanced) Connection Complete with an error: the attempt ended
    /// without a connection (0x02 after a cancel, 0x3E if the link failed
    /// to come up).
    ConnectFailed { status: u8 },
    /// Encryption Change: `on` if the link is now encrypted. `v2`: the
    /// controller sent version 2 of the event (0x59, with the key size).
    Encryption { handle: u16, on: bool, v2: bool },
    Disconnected { handle: u16, reason: u8 },
}

/// Parse an HCI event (`[code][length][parameters]`).
pub fn link_event(event: &[u8]) -> Option<LinkEvent> {
    let (&code, rest) = event.split_first()?;
    let (&len, params) = rest.split_first()?;
    if params.len() != usize::from(len) {
        return None;
    }
    let handle_at = |at: usize| Some(u16::from_le_bytes([*params.get(at)?, *params.get(at + 1)?]) & 0x0FFF);
    match code {
        // Disconnection Complete: status, handle, reason.
        0x05 if params.len() >= 4 && params[0] == 0 => Some(LinkEvent::Disconnected { handle: handle_at(1)?, reason: params[3] }),
        // Encryption Change (v1 and v2): status, handle, enabled.
        0x08 | 0x59 if params.len() >= 4 && params[0] == 0 => {
            Some(LinkEvent::Encryption { handle: handle_at(1)?, on: params[3] != 0, v2: code == 0x59 })
        }
        // LE Meta: (Enhanced) Connection Complete share the layout up to the
        // peer address: subevent, status, handle, role, peer type, peer address.
        0x3E if params.len() >= 12 && matches!(params[0], 0x01 | 0x0A | 0x29) && params[1] == 0 => {
            let mut peer = [0u8; 6];
            peer.copy_from_slice(&params[6..12]);
            Some(LinkEvent::Connected { handle: handle_at(2)?, peer, peer_random: params[5] & 0x01 != 0 })
        }
        0x3E if params.len() >= 2 && matches!(params[0], 0x01 | 0x0A | 0x29) && params[1] != 0 => {
            Some(LinkEvent::ConnectFailed { status: params[1] })
        }
        _ => None,
    }
}

/// What an event means for an HCI_Disconnect the host sent for one handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectStep {
    /// Command Status 0: the controller is closing the link.
    Accepted,
    /// Command Status 0x02, Unknown Connection Identifier: no such link.
    NoConnection,
    /// Command Status with another error.
    Refused(u8),
    /// Disconnection Complete for the handle; `status` 0 means closed.
    Complete { status: u8, reason: u8 },
}

/// Classify `event` for an HCI_Disconnect (opcode 0x0406) of `handle`.
pub fn disconnect_step(event: &[u8], handle: u16) -> Option<DisconnectStep> {
    match *event {
        [0x0F, 0x04, status, _credits, 0x06, 0x04] => Some(match status {
            0x00 => DisconnectStep::Accepted,
            0x02 => DisconnectStep::NoConnection,
            s => DisconnectStep::Refused(s),
        }),
        [0x05, 0x04, status, lo, hi, reason] if u16::from_le_bytes([lo, hi]) & 0x0FFF == handle => {
            Some(DisconnectStep::Complete { status, reason })
        }
        _ => None,
    }
}

/// An Encryption Change v2 event (0x59) rewritten as version 1 (0x08), for
/// the host stack: TrouBLE 0.8 unmasks v2 (event mask page 2), but handles
/// only v1, so a link encrypted with a v2 report stays unencrypted to it.
/// The two differ only in v2's trailing key size. `None` for anything else.
pub fn encryption_change_as_v1(event: &[u8]) -> Option<[u8; 6]> {
    match *event {
        [0x59, 0x05, status, handle_lo, handle_hi, enabled, _key_size] => {
            Some([0x08, 0x04, status, handle_lo, handle_hi, enabled])
        }
        _ => None,
    }
}

/// An ATT Handle Value Notification inside one ACL packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification<'a> {
    pub conn: u16,
    pub attribute: u16,
    pub value: &'a [u8],
}

/// Parse an HCI ACL packet (header included) carrying a complete ATT
/// notification. Fragments and everything else give `None`.
pub fn notification(packet: &[u8]) -> Option<Notification<'_>> {
    let raw = u16::from_le_bytes([*packet.first()?, *packet.get(1)?]);
    let acl_len = usize::from(u16::from_le_bytes([*packet.get(2)?, *packet.get(3)?]));
    // Packet boundary 0b01 continues an earlier PDU.
    if (raw >> 12) & 0b11 == 0b01 {
        return None;
    }
    let l2cap = packet.get(4..4 + acl_len)?;
    let pdu_len = usize::from(u16::from_le_bytes([*l2cap.first()?, *l2cap.get(1)?]));
    let cid = u16::from_le_bytes([*l2cap.get(2)?, *l2cap.get(3)?]);
    let pdu = l2cap.get(4..)?;
    // Only complete PDUs on the ATT channel.
    if cid != 0x0004 || pdu.len() != pdu_len || pdu.first() != Some(&0x1B) || pdu.len() < 3 {
        return None;
    }
    Some(Notification { conn: raw & 0x0FFF, attribute: u16::from_le_bytes([pdu[1], pdu[2]]), value: &pdu[3..] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_events_from_the_keyboard_trace() {
        // LE Connection Complete laid out per the spec for the keyboard's
        // connection (handle 0x0200 as in the Nov 1 traces, central, random
        // C0:00:00:00:00:01). The traces didn't capture this event itself.
        let conn = [
            0x3E, 0x13, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x18, 0x00, 0x00, 0x00, 0x48,
            0x00, 0x00,
        ];
        assert_eq!(
            link_event(&conn),
            Some(LinkEvent::Connected { handle: 0x200, peer: [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0], peer_random: true })
        );
        assert_eq!(link_event(&[0x08, 0x04, 0x00, 0x00, 0x02, 0x01]), Some(LinkEvent::Encryption { handle: 0x200, on: true, v2: false }));
        // Version 2 adds the key size (16 here).
        assert_eq!(
            link_event(&[0x59, 0x05, 0x00, 0x00, 0x02, 0x01, 0x10]),
            Some(LinkEvent::Encryption { handle: 0x200, on: true, v2: true })
        );
        assert_eq!(link_event(&[0x05, 0x04, 0x00, 0x00, 0x02, 0x13]), Some(LinkEvent::Disconnected { handle: 0x200, reason: 0x13 }));
    }

    #[test]
    fn disconnecting_a_link_left_from_before() {
        // No such link: Command Status 0x02 for opcode 0x0406.
        assert_eq!(disconnect_step(&[0x0F, 0x04, 0x02, 0x01, 0x06, 0x04], 0x200), Some(DisconnectStep::NoConnection));
        // Accepted, then Disconnection Complete: status 0, handle 0x0200,
        // reason 0x16 (terminated by the local host).
        assert_eq!(disconnect_step(&[0x0F, 0x04, 0x00, 0x01, 0x06, 0x04], 0x200), Some(DisconnectStep::Accepted));
        assert_eq!(
            disconnect_step(&[0x05, 0x04, 0x00, 0x00, 0x02, 0x16], 0x200),
            Some(DisconnectStep::Complete { status: 0, reason: 0x16 })
        );
        // Command Disallowed.
        assert_eq!(disconnect_step(&[0x0F, 0x04, 0x0C, 0x01, 0x06, 0x04], 0x200), Some(DisconnectStep::Refused(0x0C)));
        // Another handle's disconnection, another command's status, noise.
        assert_eq!(disconnect_step(&[0x05, 0x04, 0x00, 0x01, 0x02, 0x16], 0x200), None);
        assert_eq!(disconnect_step(&[0x0F, 0x04, 0x00, 0x01, 0x0D, 0x20], 0x200), None);
        assert_eq!(disconnect_step(&[0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00], 0x200), None);
        assert_eq!(disconnect_step(&[], 0x200), None);
    }

    #[test]
    fn encryption_change_v2_for_the_host_stack() {
        // Success, handle 0x0200, encrypted (AES-CCM), 16-byte key.
        assert_eq!(
            encryption_change_as_v1(&[0x59, 0x05, 0x00, 0x00, 0x02, 0x01, 0x10]),
            Some([0x08, 0x04, 0x00, 0x00, 0x02, 0x01])
        );
        // Failure (0x06, key missing) keeps its status.
        assert_eq!(
            encryption_change_as_v1(&[0x59, 0x05, 0x06, 0x00, 0x02, 0x00, 0x00]),
            Some([0x08, 0x04, 0x06, 0x00, 0x02, 0x00])
        );
        // Version 1 and anything malformed stay as they are.
        assert_eq!(encryption_change_as_v1(&[0x08, 0x04, 0x00, 0x00, 0x02, 0x01]), None);
        assert_eq!(encryption_change_as_v1(&[0x59, 0x04, 0x00, 0x00, 0x02, 0x01]), None);
        assert_eq!(encryption_change_as_v1(&[0x59, 0x05, 0x00, 0x00, 0x02, 0x01, 0x10, 0x00]), None);
        assert_eq!(encryption_change_as_v1(&[]), None);
    }

    #[test]
    fn failed_connection_attempts() {
        // LE Connection Complete, status 0x02: LE Create Connection cancelled.
        let mut event = [0u8; 21];
        event[..4].copy_from_slice(&[0x3E, 0x13, 0x01, 0x02]);
        assert_eq!(link_event(&event), Some(LinkEvent::ConnectFailed { status: 0x02 }));
        // Enhanced v1 (0x0A, 31 parameters), status 0x3E.
        let mut event = [0u8; 33];
        event[..4].copy_from_slice(&[0x3E, 0x1F, 0x0A, 0x3E]);
        assert_eq!(link_event(&event), Some(LinkEvent::ConnectFailed { status: 0x3E }));
    }

    #[test]
    fn failures_and_other_events_are_ignored() {
        // Failed encryption (status 0x06, PIN or key missing).
        assert_eq!(link_event(&[0x08, 0x04, 0x06, 0x00, 0x02, 0x00]), None);
        // Command Complete for HCI_Reset.
        assert_eq!(link_event(&[0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00]), None);
        // Wrong length byte.
        assert_eq!(link_event(&[0x05, 0x05, 0x00, 0x00, 0x02, 0x13]), None);
        assert_eq!(link_event(&[]), None);
    }

    #[test]
    fn keyboard_report_notification() {
        // From the Nov 1 trace: key 0x06 on handle 0x001a, connection 0x0200.
        let acl = [
            0x00, 0x22, 0x12, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x1B, 0x1A, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        let n = notification(&acl).unwrap();
        assert_eq!(n.conn, 0x200);
        assert_eq!(n.attribute, 0x001A);
        assert_eq!(n.value, &[0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn non_notifications_are_ignored() {
        // ATT read response, battery level on the signaling channel, a fragment.
        assert_eq!(notification(&[0x00, 0x22, 0x06, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0B, 0x01]), None);
        assert_eq!(notification(&[0x00, 0x22, 0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x1B, 0x10, 0x00, 0x39]), None);
        assert_eq!(notification(&[0x00, 0x12, 0x02, 0x00, 0xAA, 0xBB]), None);
        // Truncated: L2CAP says 14 bytes, only 3 present.
        assert_eq!(notification(&[0x00, 0x22, 0x07, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x1B, 0x1A, 0x00]), None);
    }
}
