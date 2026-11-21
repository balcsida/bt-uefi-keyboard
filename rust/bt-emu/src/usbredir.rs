//! The usbredir wire protocol (version 0.7), device side: what a "usb-host"
//! sends to QEMU's `usb-redir` device and what it gets back. Only what a
//! Bluetooth controller needs: control, bulk and interrupt transfers.
//!
//! Packets are `type u32, length u32, id` and a body, little-endian. The id
//! is 32 bits until both sides have said in their hello that they do 64.
//! QEMU sends its hello first; ours answers it, and everything after that
//! has 64-bit ids. Body layouts depend on the capabilities both sides
//! have: this side has `connect_device_version`, `ep_info_max_packet_size`,
//! `64bits_ids` and `32bits_bulk_length` (the last three are what QEMU
//! wants before it attaches a device to an xHCI controller).

pub const HELLO: u32 = 0;
pub const DEVICE_CONNECT: u32 = 1;
pub const DEVICE_DISCONNECT: u32 = 2;
pub const RESET: u32 = 3;
pub const INTERFACE_INFO: u32 = 4;
pub const EP_INFO: u32 = 5;
pub const SET_CONFIGURATION: u32 = 6;
pub const GET_CONFIGURATION: u32 = 7;
pub const CONFIGURATION_STATUS: u32 = 8;
pub const SET_ALT_SETTING: u32 = 9;
pub const GET_ALT_SETTING: u32 = 10;
pub const ALT_SETTING_STATUS: u32 = 11;
pub const START_INTERRUPT_RECEIVING: u32 = 15;
pub const STOP_INTERRUPT_RECEIVING: u32 = 16;
pub const INTERRUPT_RECEIVING_STATUS: u32 = 17;
pub const CANCEL_DATA_PACKET: u32 = 21;
pub const FILTER_REJECT: u32 = 22;
pub const FILTER_FILTER: u32 = 23;
pub const DEVICE_DISCONNECT_ACK: u32 = 24;
pub const CONTROL_PACKET: u32 = 100;
pub const BULK_PACKET: u32 = 101;
pub const INTERRUPT_PACKET: u32 = 103;

pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_CANCELLED: u8 = 1;
pub const STATUS_INVAL: u8 = 2;
pub const STATUS_STALL: u8 = 4;

pub const TYPE_CONTROL: u8 = 0;
pub const TYPE_BULK: u8 = 2;
pub const TYPE_INTERRUPT: u8 = 3;
pub const TYPE_INVALID: u8 = 255;

pub const SPEED_HIGH: u8 = 2;

const CAP_CONNECT_DEVICE_VERSION: u32 = 1 << 1;
const CAP_EP_INFO_MAX_PACKET_SIZE: u32 = 1 << 4;
const CAP_64BITS_IDS: u32 = 1 << 5;
const CAP_32BITS_BULK_LENGTH: u32 = 1 << 6;
/// What this side can do.
pub const OUR_CAPS: u32 = CAP_CONNECT_DEVICE_VERSION | CAP_EP_INFO_MAX_PACKET_SIZE | CAP_64BITS_IDS | CAP_32BITS_BULK_LENGTH;
/// What the other side must be able to do for the layouts used here.
pub const NEEDED_CAPS: u32 = OUR_CAPS;

/// Index of an endpoint address in the 32-entry tables: OUT 0-15, IN 16-31.
pub fn ep_index(address: u8) -> usize {
    usize::from((address & 0x80) >> 3 | (address & 0x0F))
}

/// One packet as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: u32,
    pub id: u64,
    pub body: Vec<u8>,
}

/// Cuts the byte stream from QEMU into packets.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
    /// Both hellos are through: ids are 64 bits.
    pub ids64: bool,
}

/// No sane packet is longer (a bulk transfer here is at most a few kB).
const MAX_BODY: usize = 1 << 20;

impl Framer {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole packet. `Err` if the stream can't be usbredir.
    pub fn next(&mut self) -> Result<Option<Packet>, String> {
        let header = if self.ids64 { 16 } else { 12 };
        if self.buf.len() < header {
            return Ok(None);
        }
        let kind = u32::from_le_bytes(self.buf[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(self.buf[4..8].try_into().unwrap()) as usize;
        if length > MAX_BODY {
            return Err(format!("packet type {kind} claims {length} bytes"));
        }
        if self.buf.len() < header + length {
            return Ok(None);
        }
        let id = if self.ids64 {
            u64::from_le_bytes(self.buf[8..16].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(self.buf[8..12].try_into().unwrap()))
        };
        let body = self.buf[header..header + length].to_vec();
        self.buf.drain(..header + length);
        Ok(Some(Packet { kind, id, body }))
    }
}

/// The capabilities in a hello body (version string, then capability words).
pub fn hello_caps(body: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(body.get(64..68)?.try_into().ok()?))
}

fn packet(kind: u32, id: u64, ids64: bool, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    if ids64 {
        out.extend_from_slice(&id.to_le_bytes());
    } else {
        out.extend_from_slice(&(id as u32).to_le_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// Our hello: always with a 32-bit id, as the other side can't know our
/// capabilities before it has read it.
pub fn hello(version: &str) -> Vec<u8> {
    let mut body = [0u8; 68];
    let text = version.as_bytes();
    body[..text.len().min(63)].copy_from_slice(&text[..text.len().min(63)]);
    body[64..68].copy_from_slice(&OUR_CAPS.to_le_bytes());
    packet(HELLO, 0, false, &body)
}

/// One interface of the device: number, class, subclass, protocol.
pub type Interface = (u8, u8, u8, u8);

pub fn interface_info(interfaces: &[Interface]) -> Vec<u8> {
    let mut body = vec![0u8; 4 + 4 * 32];
    body[..4].copy_from_slice(&(interfaces.len() as u32).to_le_bytes());
    for (i, &(number, class, subclass, protocol)) in interfaces.iter().take(32).enumerate() {
        body[4 + i] = number;
        body[36 + i] = class;
        body[68 + i] = subclass;
        body[100 + i] = protocol;
    }
    packet(INTERFACE_INFO, 0, true, &body)
}

/// One endpoint: address, transfer type, interval, interface, max packet.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub address: u8,
    pub kind: u8,
    pub interval: u8,
    pub interface: u8,
    pub max_packet: u16,
}

pub fn ep_info(endpoints: &[Endpoint]) -> Vec<u8> {
    // type[32], interval[32], interface[32], max_packet_size[32] (u16).
    let mut body = vec![0u8; 32 * 3 + 64];
    body[..32].fill(TYPE_INVALID);
    // Endpoint 0, both directions.
    body[ep_index(0x00)] = TYPE_CONTROL;
    body[ep_index(0x80)] = TYPE_CONTROL;
    for ep in endpoints {
        let i = ep_index(ep.address);
        body[i] = ep.kind;
        body[32 + i] = ep.interval;
        body[64 + i] = ep.interface;
        body[96 + 2 * i..98 + 2 * i].copy_from_slice(&ep.max_packet.to_le_bytes());
    }
    packet(EP_INFO, 0, true, &body)
}

pub fn device_connect(speed: u8, class: (u8, u8, u8), vendor: u16, product: u16, version_bcd: u16) -> Vec<u8> {
    let mut body = vec![speed, class.0, class.1, class.2];
    body.extend_from_slice(&vendor.to_le_bytes());
    body.extend_from_slice(&product.to_le_bytes());
    body.extend_from_slice(&version_bcd.to_le_bytes());
    packet(DEVICE_CONNECT, 0, true, &body)
}

pub fn configuration_status(id: u64, status: u8, configuration: u8) -> Vec<u8> {
    packet(CONFIGURATION_STATUS, id, true, &[status, configuration])
}

pub fn alt_setting_status(id: u64, status: u8, interface: u8, alt: u8) -> Vec<u8> {
    packet(ALT_SETTING_STATUS, id, true, &[status, interface, alt])
}

pub fn interrupt_receiving_status(id: u64, status: u8, endpoint: u8) -> Vec<u8> {
    packet(INTERRUPT_RECEIVING_STATUS, id, true, &[status, endpoint])
}

/// A control transfer as QEMU sends it (data follows for OUT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub endpoint: u8,
    pub request: u8,
    pub request_type: u8,
    pub status: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl Control {
    pub fn parse(body: &[u8]) -> Option<Self> {
        let h = body.get(..10)?;
        Some(Self {
            endpoint: h[0],
            request: h[1],
            request_type: h[2],
            status: h[3],
            value: u16::from_le_bytes([h[4], h[5]]),
            index: u16::from_le_bytes([h[6], h[7]]),
            length: u16::from_le_bytes([h[8], h[9]]),
            data: body[10..].to_vec(),
        })
    }

    /// The answer: `data` for an IN transfer (its length is what counts),
    /// nothing for OUT (the length says how much was taken).
    pub fn reply(&self, id: u64, status: u8, data: &[u8]) -> Vec<u8> {
        let is_in = self.request_type & 0x80 != 0;
        let length = if is_in { data.len() as u16 } else { self.length };
        let mut body = vec![self.endpoint, self.request, self.request_type, status];
        body.extend_from_slice(&self.value.to_le_bytes());
        body.extend_from_slice(&self.index.to_le_bytes());
        body.extend_from_slice(&length.to_le_bytes());
        if is_in {
            body.extend_from_slice(data);
        }
        packet(CONTROL_PACKET, id, true, &body)
    }
}

/// A bulk transfer as QEMU sends it: for IN only the length wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bulk {
    pub endpoint: u8,
    pub length: u32,
    pub data: Vec<u8>,
}

impl Bulk {
    pub fn parse(body: &[u8]) -> Option<Self> {
        // endpoint, status, length u16, stream_id u32, length_high u16.
        let h = body.get(..10)?;
        let length = u32::from(u16::from_le_bytes([h[2], h[3]])) | u32::from(u16::from_le_bytes([h[8], h[9]])) << 16;
        Some(Self { endpoint: h[0], length, data: body[10..].to_vec() })
    }
}

/// The answer to a bulk transfer: data for IN, the length taken for OUT.
pub fn bulk_reply(id: u64, endpoint: u8, status: u8, length: u32, data: &[u8]) -> Vec<u8> {
    let mut body = vec![endpoint, status];
    body.extend_from_slice(&(length as u16).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&((length >> 16) as u16).to_le_bytes());
    body.extend_from_slice(data);
    packet(BULK_PACKET, id, true, &body)
}

/// One USB packet from an interrupt IN endpoint (sent unasked, once QEMU
/// has started "interrupt receiving" on it).
pub fn interrupt_in(endpoint: u8, data: &[u8]) -> Vec<u8> {
    let mut body = vec![endpoint, STATUS_SUCCESS];
    body.extend_from_slice(&(data.len() as u16).to_le_bytes());
    body.extend_from_slice(data);
    packet(INTERRUPT_PACKET, 0, true, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_switches_to_64_bit_ids_after_the_hello() {
        // QEMU's hello: 32-bit id.
        let mut qemu_hello = Vec::new();
        qemu_hello.extend_from_slice(&HELLO.to_le_bytes());
        qemu_hello.extend_from_slice(&68u32.to_le_bytes());
        qemu_hello.extend_from_slice(&0u32.to_le_bytes());
        let mut body = [0u8; 68];
        body[..4].copy_from_slice(b"qemu");
        body[64..].copy_from_slice(&0xFFu32.to_le_bytes());
        qemu_hello.extend_from_slice(&body);

        let mut f = Framer::default();
        // Arriving in pieces.
        f.push(&qemu_hello[..7]);
        assert_eq!(f.next(), Ok(None));
        f.push(&qemu_hello[7..]);
        let hello = f.next().unwrap().unwrap();
        assert_eq!((hello.kind, hello.id, hello_caps(&hello.body)), (HELLO, 0, Some(0xFF)));
        f.ids64 = true;

        // A control packet with a 64-bit id, and the start of the next one.
        let ctl = Control { endpoint: 0x80, request: 6, request_type: 0x80, status: 0, value: 0x0100, index: 0, length: 18, data: vec![] };
        let wire = ctl.reply(0x1_0000_0002, STATUS_SUCCESS, &[1, 2, 3]);
        f.push(&wire);
        f.push(&wire[..5]);
        let p = f.next().unwrap().unwrap();
        assert_eq!((p.kind, p.id), (CONTROL_PACKET, 0x1_0000_0002));
        let back = Control::parse(&p.body).unwrap();
        assert_eq!((back.length, back.data), (3, vec![1, 2, 3]));
        assert_eq!(f.next(), Ok(None));
    }

    #[test]
    fn body_sizes_match_the_protocol_structs() {
        let size = |wire: Vec<u8>| wire.len() - 16;
        assert_eq!(hello("x").len() - 12, 68);
        assert_eq!(size(interface_info(&[(0, 0xE0, 1, 1)])), 132);
        assert_eq!(size(ep_info(&[])), 160);
        assert_eq!(size(device_connect(SPEED_HIGH, (0xE0, 1, 1), 0x0E8D, 0x0616, 0x0100)), 10);
        assert_eq!(size(bulk_reply(7, 0x82, STATUS_SUCCESS, 4, &[1, 2, 3, 4])), 14);
        assert_eq!(size(interrupt_in(0x81, &[0; 16])), 20);
    }

    #[test]
    fn endpoint_tables() {
        assert_eq!((ep_index(0x02), ep_index(0x81), ep_index(0x82)), (2, 17, 18));
        let wire = ep_info(&[Endpoint { address: 0x81, kind: TYPE_INTERRUPT, interval: 1, interface: 0, max_packet: 16 }]);
        let body = &wire[16..];
        assert_eq!((body[0], body[16], body[17], body[1]), (TYPE_CONTROL, TYPE_CONTROL, TYPE_INTERRUPT, TYPE_INVALID));
        assert_eq!((body[32 + 17], &body[96 + 34..96 + 36]), (1, &[16u8, 0][..]));
    }

    #[test]
    fn a_long_bulk_length_uses_the_high_word() {
        let wire = bulk_reply(1, 0x02, STATUS_SUCCESS, 0x1_0004, &[]);
        let b = Bulk::parse(&wire[16..]).unwrap();
        assert_eq!((b.endpoint, b.length), (0x02, 0x1_0004));
    }

    #[test]
    fn nonsense_is_refused() {
        let mut f = Framer::default();
        f.push(&[1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0]);
        assert!(f.next().is_err());
    }
}
