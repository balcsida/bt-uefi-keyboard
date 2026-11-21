//! The emulated keyboard's attribute table and its ATT server.
//!
//! The table follows the real keyboard's as traced on Nov 1 (the HID
//! service's handles, report IDs and types, 21 characteristics from
//! 0x0012 to 0x0053; the battery level at 0x0010): the keyboard input
//! report is 0x001A with its notification switch at 0x001B and its Report
//! Reference at 0x001C, the LED output report 0x0032, the Report Map
//! 0x004A. The Report Map itself isn't the real one (only its first 16
//! bytes were traced): it describes the same keyboard report, a modifier
//! byte and ten key slots under report ID 1.
//!
//! As on the real keyboard, the ATT MTU is 23, and the HID service's
//! values can only be read or written on an encrypted link.

pub const UUID_PRIMARY_SERVICE: u16 = 0x2800;
pub const UUID_CHARACTERISTIC: u16 = 0x2803;
pub const UUID_CCCD: u16 = 0x2902;
pub const UUID_REPORT_REFERENCE: u16 = 0x2908;
pub const UUID_HID_SERVICE: u16 = 0x1812;
pub const UUID_BATTERY_SERVICE: u16 = 0x180F;
pub const UUID_REPORT: u16 = 0x2A4D;
pub const UUID_REPORT_MAP: u16 = 0x2A4B;

pub const H_BATTERY: u16 = 0x0010;
pub const H_BATTERY_CCCD: u16 = 0x0011;
pub const H_PROTOCOL_MODE: u16 = 0x0014;
pub const H_CONSUMER: u16 = 0x0016;
pub const H_CONSUMER_CCCD: u16 = 0x0017;
pub const H_KEYS: u16 = 0x001A;
pub const H_KEYS_CCCD: u16 = 0x001B;
pub const H_KEYS_REFERENCE: u16 = 0x001C;
pub const H_LEDS: u16 = 0x0032;
pub const H_REPORT_MAP: u16 = 0x004A;
pub const H_BOOT_KEYS: u16 = 0x004C;
pub const H_BOOT_KEYS_CCCD: u16 = 0x004D;
pub const HID_FIRST: u16 = 0x0012;
pub const HID_LAST: u16 = 0x0053;

pub const MTU: usize = 23;

pub const ERR_INVALID_HANDLE: u8 = 0x01;
pub const ERR_READ_NOT_PERMITTED: u8 = 0x02;
pub const ERR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ERR_INVALID_PDU: u8 = 0x04;
pub const ERR_NOT_SUPPORTED: u8 = 0x06;
pub const ERR_INVALID_OFFSET: u8 = 0x07;
pub const ERR_NOT_FOUND: u8 = 0x0A;
pub const ERR_INVALID_LENGTH: u8 = 0x0D;
pub const ERR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
pub const ERR_UNSUPPORTED_GROUP: u8 = 0x10;

/// The keyboard collection of the real Report Map starts with these 16
/// bytes; the rest is written to describe the same reports: ID 1 with a
/// modifier byte and ten key slots (and the LED output report), ID 0x10
/// with one 16-bit consumer usage (the media keys), and a vendor page.
pub const REPORT_MAP: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID (1)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x05, 0x07, //   Usage Page (Keyboard)
    0x1A, 0xE0, 0x00, //   Usage Minimum (Left Control)
    0x2A, 0xE7, 0x00, //   Usage Maximum (Right GUI)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute): the modifiers
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x1A, 0x00, 0x00, //   Usage Minimum (0)
    0x2A, 0xFF, 0x00, //   Usage Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x0A, //   Report Count (10)
    0x81, 0x00, //   Input (Data, Array): ten key slots
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (Num Lock)
    0x29, 0x05, //   Usage Maximum (Kana)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x05, //   Report Count (5)
    0x91, 0x02, //   Output (Data, Variable, Absolute): the LEDs
    0x75, 0x03, //   Report Size (3)
    0x95, 0x01, //   Report Count (1)
    0x91, 0x01, //   Output (Constant): padding
    0xC0, // End Collection
    0x05, 0x0C, // Usage Page (Consumer)
    0x09, 0x01, // Usage (Consumer Control)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x10, //   Report ID (16)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x03, //   Logical Maximum (0x3FF)
    0x19, 0x00, //   Usage Minimum (0)
    0x2A, 0xFF, 0x03, //   Usage Maximum (0x3FF)
    0x75, 0x10, //   Report Size (16)
    0x95, 0x01, //   Report Count (1)
    0x81, 0x00, //   Input (Data, Array): one media key
    0xC0, // End Collection
    0x06, 0x00, 0xFF, // Usage Page (Vendor 0xFF00)
    0x09, 0x01, // Usage (1)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x27, //   Report ID (0x27)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x09, 0x02, //   Usage (2)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x07, //   Report Count (7)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x85, 0x2A, //   Report ID (0x2A)
    0x09, 0x03, //   Usage (3)
    0x95, 0x03, //   Report Count (3)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0x85, 0x22, //   Report ID (0x22)
    0x09, 0x04, //   Usage (4)
    0x95, 0x08, //   Report Count (8)
    0xB1, 0x02, //   Feature (Data, Variable, Absolute)
    0xC0, // End Collection
];

#[derive(Debug, Clone)]
pub struct Attribute {
    pub handle: u16,
    /// The attribute type (all 16-bit here).
    pub kind: u16,
    pub value: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    /// Needs an encrypted link, as the HID service's values do.
    pub secure: bool,
}

/// What a write did, for the keyboard's behaviour and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    pub handle: u16,
    pub value: Vec<u8>,
    /// A Write Command (no response) rather than a Write Request.
    pub command: bool,
}

pub struct AttServer {
    pub attributes: Vec<Attribute>,
    /// Every accepted write, oldest first.
    pub writes: Vec<Write>,
    /// Requests answered, by opcode (for the log's summary).
    pub requests: u32,
    pub errors_sent: u32,
}

struct Builder {
    attributes: Vec<Attribute>,
    next: u16,
}

impl Builder {
    fn add(&mut self, kind: u16, value: &[u8], readable: bool, writable: bool, secure: bool) -> u16 {
        let handle = self.next;
        self.attributes.push(Attribute { handle, kind, value: value.to_vec(), readable, writable, secure });
        self.next += 1;
        handle
    }

    fn service(&mut self, uuid: u16) -> u16 {
        self.add(UUID_PRIMARY_SERVICE, &uuid.to_le_bytes(), true, false, false)
    }

    /// Declaration and value; returns the value's handle.
    fn characteristic(&mut self, uuid: u16, properties: u8, value: &[u8], secure: bool) -> u16 {
        let value_handle = self.next + 1;
        let mut declaration = vec![properties];
        declaration.extend_from_slice(&value_handle.to_le_bytes());
        declaration.extend_from_slice(&uuid.to_le_bytes());
        self.add(UUID_CHARACTERISTIC, &declaration, true, false, false);
        self.add(uuid, value, properties & PROP_READ != 0, properties & (PROP_WRITE | PROP_WRITE_NO_RESPONSE) != 0, secure)
    }

    fn cccd(&mut self, on: bool, secure: bool) -> u16 {
        self.add(UUID_CCCD, &[u8::from(on), 0], true, true, secure)
    }

    /// A HID report: value, CCCD for input reports, Report Reference.
    fn report(&mut self, id: u8, kind: u8, value: &[u8], notifying: bool) -> u16 {
        let properties = match kind {
            REPORT_INPUT => PROP_READ | PROP_NOTIFY,
            REPORT_OUTPUT => PROP_READ | PROP_WRITE | PROP_WRITE_NO_RESPONSE,
            _ => PROP_READ | PROP_WRITE,
        };
        let handle = self.characteristic(UUID_REPORT, properties, value, true);
        if kind == REPORT_INPUT {
            self.cccd(notifying, true);
        }
        self.add(UUID_REPORT_REFERENCE, &[id, kind], true, false, true);
        handle
    }
}

const PROP_READ: u8 = 0x02;
const PROP_WRITE_NO_RESPONSE: u8 = 0x04;
const PROP_WRITE: u8 = 0x08;
const PROP_NOTIFY: u8 = 0x10;
const PROP_INDICATE: u8 = 0x20;
const REPORT_INPUT: u8 = 1;
const REPORT_OUTPUT: u8 = 2;
const REPORT_FEATURE: u8 = 3;

impl AttServer {
    /// The keyboard's table. `bonded_host`: the host has used the keyboard
    /// before, so the switches it turned on then are still on (the
    /// keyboard keeps them per bonded host): every input report (an OS
    /// subscribes to all seven, Nov 21 trace of BlueZ pairing) and the
    /// battery level notify from the start.
    pub fn keyboard(bonded_host: bool) -> Self {
        let mut b = Builder { attributes: Vec::new(), next: 1 };
        // Generic Access.
        b.service(0x1800);
        b.characteristic(0x2A00, PROP_READ, b"Emulated Keyboard", false);
        b.characteristic(0x2A01, PROP_READ, &0x03C1u16.to_le_bytes(), false); // appearance: keyboard
        b.characteristic(0x2A04, PROP_READ, &[0x0C, 0x00, 0x0C, 0x00, 0x1E, 0x00, 0x2C, 0x01], false);
        b.characteristic(0x2AA6, PROP_READ, &[0], false);
        // Generic Attribute.
        b.service(0x1801);
        b.characteristic(0x2A05, PROP_INDICATE, &[], false);
        b.cccd(false, false);
        // Battery.
        b.service(UUID_BATTERY_SERVICE);
        let battery = b.characteristic(0x2A19, PROP_READ | PROP_NOTIFY, &[57], false);
        b.cccd(bonded_host, false);
        assert_eq!(battery, H_BATTERY);
        // HID.
        assert_eq!(b.service(UUID_HID_SERVICE), HID_FIRST);
        b.characteristic(0x2A4E, PROP_READ | PROP_WRITE_NO_RESPONSE, &[1], true); // Protocol Mode: report
        for id in [0x10, 0x01, 0x27, 0x2C, 0x2D, 0x2E, 0x2F] {
            let size = if id == 0x01 { 11 } else { 2 };
            b.report(id, REPORT_INPUT, &vec![0; size], bonded_host);
        }
        for id in [0x01, 0x2A, 0x2D] {
            b.report(id, REPORT_OUTPUT, &[0], false);
        }
        for id in [0x22, 0x24, 0x2A, 0x2F, 0x01] {
            b.report(id, REPORT_FEATURE, &[0], false);
        }
        assert_eq!(b.characteristic(UUID_REPORT_MAP, PROP_READ, REPORT_MAP, true), H_REPORT_MAP);
        assert_eq!(b.characteristic(0x2A22, PROP_READ | PROP_NOTIFY, &[0; 8], true), H_BOOT_KEYS);
        b.cccd(false, true);
        b.characteristic(0x2A32, PROP_READ | PROP_WRITE | PROP_WRITE_NO_RESPONSE, &[0], true);
        b.characteristic(0x2A4A, PROP_READ, &[0x11, 0x01, 0x00, 0x03], true); // HID Information
        assert_eq!(b.characteristic(0x2A4C, PROP_WRITE_NO_RESPONSE, &[0], true), HID_LAST);
        // Device Information.
        b.service(0x180A);
        b.characteristic(0x2A29, PROP_READ, b"bt-emu", false);
        Self { attributes: b.attributes, writes: Vec::new(), requests: 0, errors_sent: 0 }
    }

    pub fn find(&self, handle: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.handle == handle)
    }

    pub fn value(&self, handle: u16) -> &[u8] {
        self.find(handle).map_or(&[], |a| &a.value)
    }

    /// How many of the seven HID input reports notify.
    pub fn reports_notifying(&self) -> usize {
        let on = |a: &&Attribute| a.kind == UUID_CCCD && (HID_FIRST..H_REPORT_MAP).contains(&a.handle) && a.value.first().is_some_and(|v| v & 1 != 0);
        self.attributes.iter().filter(on).count()
    }

    /// Whether the client switched notifications on at this CCCD.
    pub fn notifying(&self, cccd: u16) -> bool {
        self.value(cccd).first().is_some_and(|v| v & 1 != 0)
    }

    /// The last handle of the service that starts at `handle`.
    fn group_end(&self, handle: u16) -> u16 {
        self.attributes
            .iter()
            .filter(|a| a.kind == UUID_PRIMARY_SERVICE && a.handle > handle)
            .map(|a| a.handle - 1)
            .next()
            .unwrap_or(0xFFFF)
    }

    fn error(&mut self, request: u8, handle: u16, code: u8) -> Vec<u8> {
        self.errors_sent += 1;
        let [lo, hi] = handle.to_le_bytes();
        vec![0x01, request, lo, hi, code]
    }

    fn in_range(&self, start: u16, end: u16) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter().filter(move |a| a.handle >= start && a.handle <= end)
    }

    /// One PDU from the client; the response, if the PDU gets one.
    pub fn request(&mut self, pdu: &[u8], encrypted: bool) -> Option<Vec<u8>> {
        let (&opcode, body) = pdu.split_first()?;
        let u16_at = |at: usize| body.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
        self.requests += 1;
        let range = |server: &mut Self| -> Result<(u16, u16), Vec<u8>> {
            match (u16_at(0), u16_at(2)) {
                (Some(start), Some(end)) if start != 0 && start <= end => Ok((start, end)),
                (Some(start), Some(_)) => Err(server.error(opcode, start, ERR_INVALID_HANDLE)),
                _ => Err(server.error(opcode, 0, ERR_INVALID_PDU)),
            }
        };
        Some(match opcode {
            // Exchange MTU.
            0x02 => vec![0x03, MTU as u8, 0],
            // Find Information: handle and type of each attribute.
            0x04 => {
                let (start, end) = match range(self) {
                    Ok(r) => r,
                    Err(e) => return Some(e),
                };
                let mut out = vec![0x05, 0x01];
                for a in self.in_range(start, end).take((MTU - 2) / 4) {
                    out.extend_from_slice(&a.handle.to_le_bytes());
                    out.extend_from_slice(&a.kind.to_le_bytes());
                }
                if out.len() == 2 { self.error(opcode, start, ERR_NOT_FOUND) } else { out }
            }
            // Find By Type Value: services by UUID.
            0x06 => {
                let (start, end) = match range(self) {
                    Ok(r) => r,
                    Err(e) => return Some(e),
                };
                let (Some(kind), Some(value)) = (u16_at(4), body.get(6..)) else { return Some(self.error(opcode, start, ERR_INVALID_PDU)) };
                let mut out = vec![0x07];
                let found: Vec<u16> = self.in_range(start, end).filter(|a| a.kind == kind && a.value == value).map(|a| a.handle).collect();
                for handle in found.into_iter().take((MTU - 1) / 4) {
                    out.extend_from_slice(&handle.to_le_bytes());
                    let group_end = if kind == UUID_PRIMARY_SERVICE { self.group_end(handle) } else { handle };
                    out.extend_from_slice(&group_end.to_le_bytes());
                }
                if out.len() == 1 { self.error(opcode, start, ERR_NOT_FOUND) } else { out }
            }
            // Read By Type (characteristic declarations, mostly) and Read
            // By Group Type (services).
            0x08 | 0x10 => {
                let (start, end) = match range(self) {
                    Ok(r) => r,
                    Err(e) => return Some(e),
                };
                let Some(kind) = (body.len() == 6).then(|| u16_at(4)).flatten() else {
                    // A 128-bit type: nothing here has one.
                    let code = if body.len() == 20 { ERR_NOT_FOUND } else { ERR_INVALID_PDU };
                    return Some(self.error(opcode, start, code));
                };
                let group = opcode == 0x10;
                if group && kind != UUID_PRIMARY_SERVICE {
                    return Some(self.error(opcode, start, ERR_UNSUPPORTED_GROUP));
                }
                // Handle, value, and the error a read of it would get (0: none).
                let matching: Vec<(u16, Vec<u8>, u8)> = self
                    .in_range(start, end)
                    .filter(|a| a.kind == kind)
                    .map(|a| {
                        let refusal = if !a.readable {
                            ERR_READ_NOT_PERMITTED
                        } else if a.secure && !encrypted {
                            ERR_INSUFFICIENT_ENCRYPTION
                        } else {
                            0
                        };
                        (a.handle, a.value.clone(), refusal)
                    })
                    .collect();
                let Some(first) = matching.first() else { return Some(self.error(opcode, start, ERR_NOT_FOUND)) };
                if first.2 != 0 {
                    return Some(self.error(opcode, first.0, first.2));
                }
                let head = if group { 4 } else { 2 };
                let value_len = first.1.len().min(MTU - 2 - head);
                let entry = head + value_len;
                let mut out = vec![opcode + 1, entry as u8];
                for (handle, value, refusal) in matching.iter().take((MTU - 2) / entry) {
                    // Entries have one length; one that can't be read ends
                    // the list.
                    if value.len().min(MTU - 2 - head) != value_len || *refusal != 0 {
                        break;
                    }
                    out.extend_from_slice(&handle.to_le_bytes());
                    if group {
                        out.extend_from_slice(&self.group_end(*handle).to_le_bytes());
                    }
                    out.extend_from_slice(&value[..value_len]);
                }
                out
            }
            // Read and Read Blob.
            0x0A | 0x0C => {
                let Some(handle) = u16_at(0) else { return Some(self.error(opcode, 0, ERR_INVALID_PDU)) };
                let offset = if opcode == 0x0C {
                    match u16_at(2) {
                        Some(offset) => usize::from(offset),
                        None => return Some(self.error(opcode, handle, ERR_INVALID_PDU)),
                    }
                } else {
                    0
                };
                let Some(a) = self.find(handle) else { return Some(self.error(opcode, handle, ERR_INVALID_HANDLE)) };
                if !a.readable {
                    return Some(self.error(opcode, handle, ERR_READ_NOT_PERMITTED));
                }
                if a.secure && !encrypted {
                    return Some(self.error(opcode, handle, ERR_INSUFFICIENT_ENCRYPTION));
                }
                if offset > a.value.len() {
                    return Some(self.error(opcode, handle, ERR_INVALID_OFFSET));
                }
                let mut out = vec![opcode + 1];
                out.extend_from_slice(&a.value[offset..a.value.len().min(offset + MTU - 1)]);
                out
            }
            // Write Request and Write Command.
            0x12 | 0x52 => {
                let command = opcode == 0x52;
                let Some(handle) = u16_at(0) else { return (!command).then(|| self.error(opcode, 0, ERR_INVALID_PDU)) };
                let value = &body[2..];
                let refusal = match self.find(handle) {
                    None => Some(ERR_INVALID_HANDLE),
                    Some(a) if !a.writable => Some(ERR_WRITE_NOT_PERMITTED),
                    Some(a) if a.secure && !encrypted => Some(ERR_INSUFFICIENT_ENCRYPTION),
                    Some(a) if a.kind == UUID_CCCD && value.len() != 2 => Some(ERR_INVALID_LENGTH),
                    Some(_) => None,
                };
                if let Some(code) = refusal {
                    return (!command).then(|| self.error(opcode, handle, code));
                }
                if let Some(a) = self.attributes.iter_mut().find(|a| a.handle == handle) {
                    a.value = value.to_vec();
                }
                self.writes.push(Write { handle, value: value.to_vec(), command });
                if command {
                    return None;
                }
                vec![0x13]
            }
            // Confirmation of an indication: nothing to say.
            0x1E => return None,
            // Anything else: commands are ignored, requests refused.
            other if other & 0x40 != 0 => return None,
            other => self.error(other, 0, ERR_NOT_SUPPORTED),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uefi_bt::hid::{find_keyboard_report, KeyField};

    fn server() -> AttServer {
        AttServer::keyboard(true)
    }

    #[test]
    fn the_report_map_describes_the_real_keyboards_report() {
        // What the driver logged on the real keyboard: report ID 1, 88
        // bits, modifiers at bit 0, ten key slots of 8 bits at bit 8.
        let report = find_keyboard_report(REPORT_MAP).expect("a keyboard report");
        assert_eq!(report.report_id, Some(1));
        assert_eq!(report.modifiers_bit, Some(0));
        assert_eq!(report.keys, KeyField::Array { bit: 8, count: 10, size: 8 });
        assert_eq!(report.bits, 88);
        // The first 16 bytes are the real map's.
        assert_eq!(&REPORT_MAP[..16], &[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, 0x15, 0x00, 0x25, 0x01, 0x05, 0x07, 0x1A, 0xE0]);
        // Longer than one read, so the client has to read on.
        assert!(REPORT_MAP.len() > 3 * (MTU - 1));
    }

    #[test]
    fn handles_match_the_real_keyboard() {
        let s = server();
        let reference = |h: u16| s.value(h).to_vec();
        // Report References as traced: (descriptor handle, report ID, type).
        for (handle, id, kind) in [
            (0x0018, 0x10, 1), (0x001C, 0x01, 1), (0x0020, 0x27, 1), (0x0024, 0x2C, 1), (0x0028, 0x2D, 1), (0x002C, 0x2E, 1),
            (0x0030, 0x2F, 1), (0x0033, 0x01, 2), (0x0036, 0x2A, 2), (0x0039, 0x2D, 2), (0x003C, 0x22, 3), (0x003F, 0x24, 3),
            (0x0042, 0x2A, 3), (0x0045, 0x2F, 3), (0x0048, 0x01, 3),
        ] {
            assert_eq!(s.find(handle).unwrap().kind, UUID_REPORT_REFERENCE, "{handle:#06x}");
            assert_eq!(reference(handle), vec![id, kind], "{handle:#06x}");
        }
        assert_eq!(s.find(H_KEYS).unwrap().kind, UUID_REPORT);
        assert_eq!(s.find(H_KEYS_CCCD).unwrap().kind, UUID_CCCD);
        assert_eq!(s.find(H_LEDS).unwrap().kind, UUID_REPORT);
        assert_eq!(s.find(H_REPORT_MAP).unwrap().kind, UUID_REPORT_MAP);
        assert_eq!(s.find(H_BOOT_KEYS_CCCD).unwrap().kind, UUID_CCCD);
        assert_eq!(s.find(H_PROTOCOL_MODE).unwrap().kind, 0x2A4E);
        // 21 characteristics in the HID service.
        let declarations = s.attributes.iter().filter(|a| a.kind == UUID_CHARACTERISTIC && (HID_FIRST..=HID_LAST).contains(&a.handle)).count();
        assert_eq!(declarations, 21);
        // A bonded host finds its notifications on; a new one doesn't.
        assert!(s.notifying(H_KEYS_CCCD) && s.notifying(H_BATTERY_CCCD));
        assert!(!AttServer::keyboard(false).notifying(H_KEYS_CCCD));
        assert_eq!((s.reports_notifying(), AttServer::keyboard(false).reports_notifying()), (7, 0));
    }

    #[test]
    fn discovery_as_the_driver_does_it() {
        let mut s = server();
        assert_eq!(s.request(&[0x02, 247, 0], true), Some(vec![0x03, 23, 0]));
        // The HID service by UUID: one range.
        assert_eq!(s.request(&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28, 0x12, 0x18], true), Some(vec![0x07, 0x12, 0x00, 0x53, 0x00]));
        // Characteristic declarations: three per response, 21 in all, then
        // "attribute not found" for the handle after the last declaration.
        let (mut start, mut seen) = (HID_FIRST, 0);
        loop {
            let [lo, hi] = start.to_le_bytes();
            let r = s.request(&[0x08, lo, hi, 0x53, 0x00, 0x03, 0x28], true).unwrap();
            if r[0] == 0x01 {
                assert_eq!(r, vec![0x01, 0x08, 0x53, 0x00, ERR_NOT_FOUND]);
                break;
            }
            assert_eq!((r[0], r[1], r.len()), (0x09, 7, 23));
            seen += 3;
            start = u16::from_le_bytes([r[16], r[17]]) + 1;
        }
        assert_eq!(seen, 21);
        // The descriptors of the keyboard report: CCCD and Report Reference.
        assert_eq!(
            s.request(&[0x04, 0x1B, 0x00, 0x1C, 0x00], true),
            Some(vec![0x05, 0x01, 0x1B, 0x00, 0x02, 0x29, 0x1C, 0x00, 0x08, 0x29])
        );
        // The Report Map: a read, then blobs until a short one.
        let mut map = s.request(&[0x0A, 0x4A, 0x00], true).unwrap()[1..].to_vec();
        assert_eq!(map.len(), 22);
        loop {
            let [lo, hi] = (map.len() as u16).to_le_bytes();
            let r = s.request(&[0x0C, 0x4A, 0x00, lo, hi], true).unwrap();
            assert_eq!(r[0], 0x0D);
            map.extend_from_slice(&r[1..]);
            if r.len() < 23 {
                break;
            }
        }
        assert_eq!(map, REPORT_MAP);
        // The switch is on already; writing it is accepted and recorded.
        assert_eq!(s.request(&[0x0A, 0x1B, 0x00], true), Some(vec![0x0B, 0x01, 0x00]));
        assert_eq!(s.request(&[0x12, 0x1B, 0x00, 0x01, 0x00], true), Some(vec![0x13]));
        assert_eq!(s.writes, vec![Write { handle: 0x001B, value: vec![1, 0], command: false }]);
    }

    #[test]
    fn hid_values_need_encryption() {
        let mut s = server();
        let refused = |handle: u16, opcode: u8| vec![0x01, opcode, handle as u8, 0, ERR_INSUFFICIENT_ENCRYPTION];
        assert_eq!(s.request(&[0x0A, 0x4A, 0x00], false), Some(refused(0x4A, 0x0A)));
        assert_eq!(s.request(&[0x0A, 0x1C, 0x00], false), Some(refused(0x1C, 0x0A)));
        assert_eq!(s.request(&[0x12, 0x1B, 0x00, 0x01, 0x00], false), Some(refused(0x1B, 0x12)));
        // A write command that isn't allowed changes nothing, silently.
        assert_eq!(s.request(&[0x52, 0x32, 0x00, 0x02], false), None);
        assert!(s.writes.is_empty());
        // Services and declarations can be discovered unencrypted, and the
        // battery level read.
        assert_eq!(s.request(&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28, 0x12, 0x18], false).unwrap()[0], 0x07);
        assert_eq!(s.request(&[0x08, 0x12, 0x00, 0x53, 0x00, 0x03, 0x28], false).unwrap()[0], 0x09);
        assert_eq!(s.request(&[0x0A, 0x10, 0x00], false), Some(vec![0x0B, 57]));
        // Encrypted: the LEDs can be written without a response.
        assert_eq!(s.request(&[0x52, 0x32, 0x00, 0x02], true), None);
        assert_eq!(s.writes.last(), Some(&Write { handle: H_LEDS, value: vec![2], command: true }));
    }

    #[test]
    fn errors() {
        let mut s = server();
        assert_eq!(s.request(&[0x0A, 0x00, 0x70], true), Some(vec![0x01, 0x0A, 0x00, 0x70, ERR_INVALID_HANDLE]));
        assert_eq!(s.request(&[0x0C, 0x4A, 0x00, 0xFF, 0x0F], true), Some(vec![0x01, 0x0C, 0x4A, 0x00, ERR_INVALID_OFFSET]));
        assert_eq!(s.request(&[0x12, 0x4A, 0x00, 0x00], true), Some(vec![0x01, 0x12, 0x4A, 0x00, ERR_WRITE_NOT_PERMITTED]));
        assert_eq!(s.request(&[0x12, 0x1B, 0x00, 0x01], true), Some(vec![0x01, 0x12, 0x1B, 0x00, ERR_INVALID_LENGTH]));
        assert_eq!(s.request(&[0x04, 0x00, 0x00, 0x05, 0x00], true), Some(vec![0x01, 0x04, 0x00, 0x00, ERR_INVALID_HANDLE]));
        assert_eq!(s.request(&[0x04, 0x60, 0x00, 0x70, 0x00], true), Some(vec![0x01, 0x04, 0x60, 0x00, ERR_NOT_FOUND]));
        assert_eq!(s.request(&[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28], true), Some(vec![0x01, 0x10, 0x01, 0x00, ERR_UNSUPPORTED_GROUP]));
        // Prepare Write isn't supported; an unknown command is ignored.
        assert_eq!(s.request(&[0x16, 0x1B, 0x00, 0x00, 0x00, 0x01], true), Some(vec![0x01, 0x16, 0x00, 0x00, ERR_NOT_SUPPORTED]));
        assert_eq!(s.request(&[0xD2, 0x01], true), None);
        // All primary services, three to a response.
        let r = s.request(&[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], true).unwrap();
        assert_eq!((r[0], r[1], r.len()), (0x11, 6, 20));
    }
}
