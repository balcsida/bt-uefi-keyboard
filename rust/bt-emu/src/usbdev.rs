//! The MT7922's Bluetooth function as a USB device: descriptors, the
//! standard requests, MediaTek's vendor channel on endpoint 0 (WMT and the
//! chip registers), and the three HCI pipes: commands on endpoint 0,
//! events on the interrupt endpoint, ACL data on the bulk endpoints.
//!
//! What the host sends comes out as [`FromHost`]; events and ACL packets
//! for the host go in with [`UsbDev::push_event`] and [`UsbDev::push_acl`].
//!
//! The ACL pipe never loses data. The driver reads it with 1 ms transfers
//! that it cancels when nothing came, and QEMU drops the answer to a
//! transfer it has already cancelled. A cancel that arrives for a transfer
//! this side has answered therefore means the answer was dropped, and its
//! data goes back to the front of the queue.

use std::collections::VecDeque;

use mtk_bt::wmt::{
    OP_FUNC_CTRL, OP_PATCH_DOWNLOAD, PATCH_LAST, PATCH_QUERY, REG_CHIP_ID, REG_CHIP_ID_LEGACY, REG_FW_FLAVOR, REG_FW_VERSION,
    REQTYPE_HCI_COMMAND, REQTYPE_UHW_READ, REQTYPE_UHW_WRITE, REQTYPE_VENDOR_IN, REQ_CHIP_REG_READ, REQ_HCI_COMMAND, REQ_UHW_READ,
    REQ_UHW_WRITE, REQ_WMT_EVENT, UHW_EP_RST_OPT, UHW_MISC, UHW_RST_DONE, UHW_SUBSYS_RST, UHW_UDMA_INT_STA, WMT_EVENT_CODE,
    WMT_EVENT_VALUE, WMT_HCI_OPCODE,
};

use crate::usbredir::{self as redir, Bulk, Control, Endpoint, Packet};
use crate::note;

pub const VENDOR: u16 = 0x0E8D;
pub const PRODUCT: u16 = 0x0616;
pub const EP_EVENTS: u8 = 0x81;
pub const EP_ACL_IN: u8 = 0x82;
pub const EP_ACL_OUT: u8 = 0x02;
const EVENT_PACKET: usize = 16;
const BULK_PACKET: u16 = 512;

const DEVICE_DESCRIPTOR: [u8; 18] = [
    18, 1, 0x00, 0x02, // USB 2.0
    0xE0, 0x01, 0x01, // wireless controller, RF, Bluetooth
    64,   // endpoint 0 packet size
    0x8D, 0x0E, 0x16, 0x06, // 0e8d:0616
    0x00, 0x01, // device version 1.00
    1, 2, 3, // strings: manufacturer, product, serial number
    1, // configurations
];

/// One configuration with the HCI interface: event, ACL in, ACL out. (The
/// chip's two other interfaces, for voice and for MediaTek's isochronous
/// data, aren't emulated.)
const CONFIG_DESCRIPTOR: [u8; 39] = [
    9, 2, 39, 0, 1, 1, 0, 0xE0, 50, // configuration 1: self-powered, remote wakeup, 100 mA
    9, 4, 0, 0, 3, 0xE0, 0x01, 0x01, 0, // interface 0: three endpoints, Bluetooth
    7, 5, EP_EVENTS, 3, EVENT_PACKET as u8, 0, 1, // interrupt IN, 16 bytes
    7, 5, EP_ACL_IN, 2, 0x00, 0x02, 0, // bulk IN, 512 bytes
    7, 5, EP_ACL_OUT, 2, 0x00, 0x02, 0, // bulk OUT, 512 bytes
];

const QUALIFIER_DESCRIPTOR: [u8; 10] = [10, 6, 0x00, 0x02, 0xE0, 0x01, 0x01, 64, 1, 0];
const STRINGS: [&str; 3] = ["MediaTek Inc.", "Wireless_Device (emulated)", "000000000"];

fn string_descriptor(index: u8) -> Option<Vec<u8>> {
    if index == 0 {
        return Some(vec![4, 3, 0x09, 0x04]); // English (US)
    }
    let text = STRINGS.get(usize::from(index) - 1)?;
    let mut d = vec![0, 3];
    for unit in text.encode_utf16() {
        d.extend_from_slice(&unit.to_le_bytes());
    }
    d[0] = d.len() as u8;
    Some(d)
}

/// What arrived from the host for the controller behind the USB function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromHost {
    /// An HCI command packet: opcode, length, parameters.
    Command(Vec<u8>),
    /// An HCI ACL data packet.
    Acl(Vec<u8>),
    /// WMT turned the Bluetooth function off, or the chip was reset: the
    /// controller forgets everything.
    PowerOff,
}

/// How the next ACL packets are laid out in USB transfers (for the tests
/// of the driver's reader; one packet per transfer otherwise).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Shaping {
    /// Hold packets back until this many are queued, then send them in one
    /// transfer. One shot.
    pub merge: usize,
    /// Send the next packet in two transfers, cut after this many bytes.
    /// One shot.
    pub split_at: Option<usize>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub control: u32,
    pub commands: u32,
    pub wmt_commands: u32,
    pub events: u32,
    pub acl_in_transfers: u32,
    pub acl_out: u32,
    pub cancelled_reads: u32,
    /// Answers QEMU dropped because it had cancelled the transfer; their
    /// data was queued again.
    pub requeued: u32,
    /// With `lose_on_cancel`: such answers, lost.
    pub lost: u32,
    pub merged_transfers: u32,
    pub split_packets: u32,
    pub stalls: u32,
}

pub struct UsbDev {
    /// usbredir packets to send to QEMU.
    pub out: Vec<Vec<u8>>,
    pub from_host: Vec<FromHost>,
    pub shaping: Shaping,
    pub stats: Stats,
    /// The firmware patch counts as loaded (as after Linux has run).
    pub firmware_loaded: bool,
    /// Behave like a real controller passed through to QEMU: data that
    /// arrives for a read QEMU has just cancelled is lost, instead of
    /// being queued again. For looking at how the driver copes; no test
    /// in the suite uses it, as what gets lost is a matter of timing.
    pub lose_on_cancel: bool,
    pub configuration: u8,
    function_on: bool,
    wmt_event: Option<Vec<u8>>,
    reg_subsys_rst: u32,
    reg_ep_rst_opt: u32,
    reg_udma_int_sta: u32,
    receiving_events: bool,
    events: VecDeque<Vec<u8>>,
    /// ACL packets for the host, whole.
    acl: VecDeque<Vec<u8>>,
    /// Transfers that go before anything in `acl`: the rest of a split
    /// packet, and answers QEMU dropped.
    acl_front: VecDeque<Vec<u8>>,
    /// Bulk IN transfers the host is waiting on: id, bytes wanted.
    reads: VecDeque<(u64, u32)>,
    /// The last answered bulk IN transfers, in case a cancel shows they
    /// were dropped.
    answered: VecDeque<(u64, Vec<u8>)>,
}

impl Default for UsbDev {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            from_host: Vec::new(),
            shaping: Shaping::default(),
            stats: Stats::default(),
            firmware_loaded: true,
            lose_on_cancel: false,
            configuration: 0,
            function_on: false,
            wmt_event: None,
            reg_subsys_rst: 0,
            reg_ep_rst_opt: 0,
            reg_udma_int_sta: 0,
            receiving_events: false,
            events: VecDeque::new(),
            acl: VecDeque::new(),
            acl_front: VecDeque::new(),
            reads: VecDeque::new(),
            answered: VecDeque::new(),
        }
    }

    /// What tells QEMU about the device: sent once, after the hellos.
    pub fn announce(&mut self) {
        self.send_layout();
        self.out.push(redir::device_connect(redir::SPEED_HIGH, (0xE0, 0x01, 0x01), VENDOR, PRODUCT, 0x0100));
    }

    fn send_layout(&mut self) {
        self.out.push(redir::interface_info(&[(0, 0xE0, 0x01, 0x01)]));
        self.out.push(redir::ep_info(&[
            Endpoint { address: EP_EVENTS, kind: redir::TYPE_INTERRUPT, interval: 1, interface: 0, max_packet: EVENT_PACKET as u16 },
            Endpoint { address: EP_ACL_IN, kind: redir::TYPE_BULK, interval: 0, interface: 0, max_packet: BULK_PACKET },
            Endpoint { address: EP_ACL_OUT, kind: redir::TYPE_BULK, interval: 0, interface: 0, max_packet: BULK_PACKET },
        ]));
    }

    pub fn is_configured(&self) -> bool {
        self.configuration != 0
    }

    pub fn function_on(&self) -> bool {
        self.function_on
    }

    /// An HCI event for the host.
    pub fn push_event(&mut self, event: Vec<u8>) {
        self.events.push_back(event);
        self.flush();
    }

    /// An HCI ACL data packet for the host.
    pub fn push_acl(&mut self, packet: Vec<u8>) {
        self.acl.push_back(packet);
        self.flush();
    }

    /// ACL data not yet taken by the host, in packets and split remainders.
    pub fn acl_waiting(&self) -> usize {
        self.acl.len() + self.acl_front.len()
    }

    /// The next bulk IN transfer's data, if any is due.
    fn next_transfer(&mut self, room: usize) -> Option<Vec<u8>> {
        if let Some(t) = self.acl_front.pop_front() {
            return Some(t);
        }
        if self.shaping.merge > 1 {
            if self.acl.len() < self.shaping.merge {
                return None; // held back until the others are queued
            }
            let total: usize = self.acl.iter().take(self.shaping.merge).map(Vec::len).sum();
            if total <= room {
                let mut t = Vec::with_capacity(total);
                for _ in 0..self.shaping.merge {
                    t.extend_from_slice(&self.acl.pop_front().unwrap());
                }
                self.shaping.merge = 0;
                self.stats.merged_transfers += 1;
                return Some(t);
            }
            self.shaping.merge = 0;
        }
        let mut packet = self.acl.pop_front()?;
        if let Some(at) = self.shaping.split_at.take() {
            if at > 0 && at < packet.len() {
                let rest = packet.split_off(at);
                self.acl_front.push_back(rest);
                self.stats.split_packets += 1;
            }
        }
        Some(packet)
    }

    /// Hand queued events and ACL data to the host as far as it asked.
    pub fn flush(&mut self) {
        if self.receiving_events {
            while let Some(event) = self.events.pop_front() {
                self.stats.events += 1;
                for chunk in event.chunks(EVENT_PACKET) {
                    self.out.push(redir::interrupt_in(EP_EVENTS, chunk));
                }
            }
        }
        while let Some(&(id, wanted)) = self.reads.front() {
            let Some(mut data) = self.next_transfer(wanted as usize) else { break };
            self.reads.pop_front();
            if data.len() > wanted as usize {
                // More than the host asked for: the rest comes next.
                let rest = data.split_off(wanted as usize);
                self.acl_front.push_front(rest);
            }
            self.stats.acl_in_transfers += 1;
            self.out.push(redir::bulk_reply(id, EP_ACL_IN, redir::STATUS_SUCCESS, data.len() as u32, &data));
            // QEMU uses an id again (it is the address of the transfer's
            // place in the guest's ring): an earlier answer under this id
            // has arrived, or QEMU couldn't ask again. Kept, a later
            // cancel would bring back that old data instead of this.
            self.answered.retain(|(answered, _)| *answered != id);
            self.answered.push_back((id, data));
            if self.answered.len() > 64 {
                self.answered.pop_front();
            }
        }
    }

    fn power_off(&mut self) {
        self.function_on = false;
        self.events.clear();
        self.acl.clear();
        self.acl_front.clear();
        self.from_host.push(FromHost::PowerOff);
    }

    /// One packet from QEMU.
    pub fn handle(&mut self, packet: &Packet) {
        match packet.kind {
            redir::CONTROL_PACKET => match Control::parse(&packet.body) {
                Some(control) => self.control(packet.id, &control),
                None => note!("usb: malformed control packet"),
            },
            redir::BULK_PACKET => match Bulk::parse(&packet.body) {
                Some(bulk) if bulk.endpoint == EP_ACL_IN => {
                    self.reads.push_back((packet.id, bulk.length));
                    self.flush();
                }
                Some(bulk) if bulk.endpoint == EP_ACL_OUT => {
                    self.stats.acl_out += 1;
                    let length = bulk.data.len() as u32;
                    self.from_host.push(FromHost::Acl(bulk.data));
                    self.out.push(redir::bulk_reply(packet.id, EP_ACL_OUT, redir::STATUS_SUCCESS, length, &[]));
                }
                Some(bulk) => {
                    note!("usb: bulk transfer on endpoint {:#04x}, which doesn't exist", bulk.endpoint);
                    self.out.push(redir::bulk_reply(packet.id, bulk.endpoint, redir::STATUS_STALL, 0, &[]));
                }
                None => note!("usb: malformed bulk packet"),
            },
            redir::CANCEL_DATA_PACKET => self.cancel(packet.id),
            redir::SET_CONFIGURATION => {
                let configuration = packet.body.first().copied().unwrap_or(0);
                let ok = configuration <= 1;
                if ok {
                    self.configuration = configuration;
                    self.receiving_events = false;
                    note!("usb: configuration {configuration} set");
                    self.send_layout();
                }
                let status = if ok { redir::STATUS_SUCCESS } else { redir::STATUS_STALL };
                self.out.push(redir::configuration_status(packet.id, status, self.configuration));
            }
            redir::GET_CONFIGURATION => {
                self.out.push(redir::configuration_status(packet.id, redir::STATUS_SUCCESS, self.configuration));
            }
            redir::SET_ALT_SETTING => {
                let (interface, alt) = (packet.body.first().copied().unwrap_or(0), packet.body.get(1).copied().unwrap_or(0));
                let status = if interface == 0 && alt == 0 { redir::STATUS_SUCCESS } else { redir::STATUS_STALL };
                self.out.push(redir::alt_setting_status(packet.id, status, interface, 0));
            }
            redir::GET_ALT_SETTING => {
                let interface = packet.body.first().copied().unwrap_or(0);
                self.out.push(redir::alt_setting_status(packet.id, redir::STATUS_SUCCESS, interface, 0));
            }
            redir::START_INTERRUPT_RECEIVING => {
                let endpoint = packet.body.first().copied().unwrap_or(0);
                if endpoint == EP_EVENTS {
                    self.receiving_events = true;
                    self.out.push(redir::interrupt_receiving_status(packet.id, redir::STATUS_SUCCESS, endpoint));
                    self.flush();
                } else {
                    self.out.push(redir::interrupt_receiving_status(packet.id, redir::STATUS_STALL, endpoint));
                }
            }
            redir::STOP_INTERRUPT_RECEIVING => {
                let endpoint = packet.body.first().copied().unwrap_or(0);
                if endpoint == EP_EVENTS {
                    self.receiving_events = false;
                }
                self.out.push(redir::interrupt_receiving_status(packet.id, redir::STATUS_SUCCESS, endpoint));
            }
            redir::RESET => {
                note!("usb: port reset");
                self.configuration = 0;
                self.receiving_events = false;
                self.reads.clear();
            }
            redir::FILTER_FILTER | redir::FILTER_REJECT | redir::DEVICE_DISCONNECT_ACK => {}
            other => note!("usb: usbredir packet type {other} isn't handled"),
        }
    }

    fn cancel(&mut self, id: u64) {
        if let Some(at) = self.reads.iter().position(|&(pending, _)| pending == id) {
            self.reads.remove(at);
            self.stats.cancelled_reads += 1;
            self.out.push(redir::bulk_reply(id, EP_ACL_IN, redir::STATUS_CANCELLED, 0, &[]));
        } else if let Some(at) = self.answered.iter().position(|(answered, _)| *answered == id) {
            // QEMU cancelled before it saw the answer, and has dropped it.
            let (_, data) = self.answered.remove(at).unwrap();
            if self.lose_on_cancel {
                self.stats.lost += 1;
                note!("usb: {} bytes of ACL data lost to a cancelled read", data.len());
                return;
            }
            self.stats.requeued += 1;
            self.acl_front.push_front(data);
            self.flush();
        }
        // Anything else was answered at once (control, bulk OUT): QEMU
        // drops that answer by itself.
    }

    fn control(&mut self, id: u64, c: &Control) {
        self.stats.control += 1;
        let is_in = c.request_type & 0x80 != 0;
        let reg = u32::from(c.value) << 16 | u32::from(c.index);
        let mut reply: Result<Vec<u8>, ()> = Err(());
        match (c.request_type, c.request) {
            // Standard requests.
            (0x80, 6) => {
                let (kind, index) = ((c.value >> 8) as u8, c.value as u8);
                let descriptor = match kind {
                    1 => Some(DEVICE_DESCRIPTOR.to_vec()),
                    2 if index == 0 => Some(CONFIG_DESCRIPTOR.to_vec()),
                    3 => string_descriptor(index),
                    6 => Some(QUALIFIER_DESCRIPTOR.to_vec()),
                    _ => None,
                };
                if let Some(mut d) = descriptor {
                    d.truncate(usize::from(c.length));
                    reply = Ok(d);
                }
            }
            (0x80..=0x82, 0) => reply = Ok(vec![0, 0]), // GET_STATUS
            (0x00..=0x02, 1 | 3) => reply = Ok(Vec::new()), // CLEAR_FEATURE, SET_FEATURE
            // HCI commands, and MediaTek's WMT commands in the same wrapping.
            (REQTYPE_HCI_COMMAND, REQ_HCI_COMMAND) => {
                self.stats.commands += 1;
                if c.data.len() >= 3 && u16::from_le_bytes([c.data[0], c.data[1]]) == WMT_HCI_OPCODE {
                    self.wmt_command(&c.data);
                } else {
                    self.from_host.push(FromHost::Command(c.data.clone()));
                }
                reply = Ok(Vec::new());
            }
            // The WMT event poll: the event, or nothing yet.
            (REQTYPE_VENDOR_IN, REQ_WMT_EVENT) if c.value == WMT_EVENT_VALUE => {
                reply = Ok(self.wmt_event.take().unwrap_or_default());
            }
            (REQTYPE_VENDOR_IN, REQ_CHIP_REG_READ) if c.length == 4 => {
                let value = match reg {
                    REG_CHIP_ID => Some(0x7922),
                    REG_CHIP_ID_LEGACY | REG_FW_FLAVOR | REG_FW_VERSION => Some(0u32),
                    _ => None,
                };
                if let Some(value) = value {
                    reply = Ok(value.to_le_bytes().to_vec());
                }
            }
            (REQTYPE_UHW_READ, REQ_UHW_READ) if c.length == 4 => {
                let value = match reg {
                    UHW_SUBSYS_RST => Some(self.reg_subsys_rst),
                    UHW_UDMA_INT_STA => Some(self.reg_udma_int_sta),
                    UHW_EP_RST_OPT => Some(self.reg_ep_rst_opt),
                    UHW_MISC => Some(UHW_RST_DONE),
                    _ => None,
                };
                if let Some(value) = value {
                    reply = Ok(value.to_le_bytes().to_vec());
                }
            }
            (REQTYPE_UHW_WRITE, REQ_UHW_WRITE) if c.data.len() == 4 => {
                let value = u32::from_le_bytes(c.data[..4].try_into().unwrap());
                match reg {
                    UHW_EP_RST_OPT => self.reg_ep_rst_opt = value,
                    UHW_UDMA_INT_STA => self.reg_udma_int_sta = value,
                    UHW_SUBSYS_RST => {
                        if value & 1 != 0 && self.reg_subsys_rst & 1 == 0 {
                            // The subsystem reset drops the firmware patch.
                            note!("mtk: subsystem reset: the firmware patch is gone");
                            self.firmware_loaded = false;
                            self.wmt_event = None;
                            self.power_off();
                        }
                        self.reg_subsys_rst = value & !1;
                    }
                    _ => {}
                }
                reply = Ok(Vec::new());
            }
            _ => {}
        }
        match reply {
            Ok(data) => self.out.push(c.reply(id, redir::STATUS_SUCCESS, if is_in { &data } else { &[] })),
            Err(()) => {
                self.stats.stalls += 1;
                note!(
                    "usb: control request {:#04x}/{:#04x} value {:#06x} index {:#06x} length {} isn't emulated: stalled",
                    c.request_type, c.request, c.value, c.index, c.length
                );
                self.out.push(c.reply(id, redir::STATUS_STALL, &[]));
            }
        }
    }

    /// A WMT command: `6f fc len | 01 op len16 flag | payload`. The answer
    /// waits for the event poll.
    fn wmt_command(&mut self, data: &[u8]) {
        self.stats.wmt_commands += 1;
        if data.len() < 8 || data[3] != 0x01 {
            note!("mtk: malformed WMT command ({} bytes)", data.len());
            return;
        }
        let (op, flag, payload) = (data[4], data[7], &data[8..]);
        let event = |flag: u8, status: Option<u16>| {
            let extra = if status.is_some() { 2 } else { 0 };
            let mut ev = vec![WMT_EVENT_CODE, 5 + extra, 0x02, op, 1 + extra, 0, flag];
            if let Some(status) = status {
                ev.extend_from_slice(&status.to_be_bytes());
            }
            ev
        };
        match op {
            OP_PATCH_DOWNLOAD if flag == PATCH_QUERY => {
                // 2: this section is loaded; 0: send it.
                self.wmt_event = Some(event(if self.firmware_loaded { 2 } else { 0 }, None));
            }
            OP_PATCH_DOWNLOAD => {
                if flag == PATCH_LAST {
                    self.firmware_loaded = true;
                    note!("mtk: a firmware section was uploaded");
                }
                self.wmt_event = Some(event(0, None));
            }
            OP_FUNC_CTRL => {
                let on = payload.first().is_some_and(|&b| b != 0);
                note!("mtk: Bluetooth function {}", if on { "on" } else { "off" });
                if on {
                    self.function_on = true;
                } else {
                    self.power_off();
                }
                self.wmt_event = Some(event(0, on.then_some(0x0404)));
            }
            other => note!("mtk: WMT op {other:#04x} isn't emulated"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usbredir::{Framer, BULK_PACKET as BULK, CANCEL_DATA_PACKET, CONTROL_PACKET};

    fn control(dev: &mut UsbDev, id: u64, request_type: u8, request: u8, value: u16, index: u16, length: u16, data: &[u8]) -> (u8, Vec<u8>) {
        let mut body = vec![request_type & 0x80, request, request_type, 0];
        body.extend_from_slice(&value.to_le_bytes());
        body.extend_from_slice(&index.to_le_bytes());
        body.extend_from_slice(&length.to_le_bytes());
        body.extend_from_slice(data);
        dev.out.clear();
        dev.handle(&Packet { kind: CONTROL_PACKET, id, body });
        let reply = decode(&dev.out.pop().expect("a reply"));
        assert_eq!((reply.kind, reply.id), (CONTROL_PACKET, id));
        let c = Control::parse(&reply.body).unwrap();
        (c.status, c.data)
    }

    fn decode(wire: &[u8]) -> Packet {
        let mut f = Framer::default();
        f.ids64 = true;
        f.push(wire);
        f.next().unwrap().unwrap()
    }

    fn read(dev: &mut UsbDev, id: u64) {
        let mut body = vec![EP_ACL_IN, 0, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        body[2..4].copy_from_slice(&512u16.to_le_bytes());
        dev.handle(&Packet { kind: BULK, id, body });
    }

    /// The data of the bulk IN answers in `dev.out`, as (id, status, data).
    fn answers(dev: &mut UsbDev) -> Vec<(u64, u8, Vec<u8>)> {
        let out: Vec<_> = dev.out.drain(..).map(|w| decode(&w)).filter(|p| p.kind == BULK).map(|p| (p.id, p.body[1], p.body[10..].to_vec())).collect();
        out
    }

    #[test]
    fn descriptors_are_consistent() {
        let mut dev = UsbDev::new();
        let (status, d) = control(&mut dev, 1, 0x80, 6, 0x0100, 0, 18, &[]);
        assert_eq!((status, d.len(), &d[8..12]), (0, 18, &[0x8D, 0x0E, 0x16, 0x06][..]));
        // The first 8 bytes only, as hosts ask first.
        assert_eq!(control(&mut dev, 2, 0x80, 6, 0x0100, 0, 8, &[]).1.len(), 8);
        let (_, c) = control(&mut dev, 3, 0x80, 6, 0x0200, 0, 255, &[]);
        assert_eq!(usize::from(u16::from_le_bytes([c[2], c[3]])), c.len());
        // Walk it: one interface, three endpoints.
        let (mut at, mut endpoints) = (0, Vec::new());
        while at < c.len() {
            if c[at + 1] == 5 {
                endpoints.push((c[at + 2], c[at + 3], u16::from_le_bytes([c[at + 4], c[at + 5]])));
            }
            at += usize::from(c[at]);
        }
        assert_eq!(endpoints, vec![(0x81, 3, 16), (0x82, 2, 512), (0x02, 2, 512)]);
        let (_, s) = control(&mut dev, 4, 0x80, 6, 0x0301, 0x0409, 255, &[]);
        assert_eq!((usize::from(s[0]), s[1]), (s.len(), 3));
        // An unknown request stalls.
        assert_eq!(control(&mut dev, 5, 0xC0, 0x77, 0, 0, 4, &[]).0, redir::STATUS_STALL);
    }

    #[test]
    fn the_mediatek_bring_up() {
        let mut dev = UsbDev::new();
        // Chip ID.
        let (_, id) = control(&mut dev, 1, 0xC0, REQ_CHIP_REG_READ, (REG_CHIP_ID >> 16) as u16, REG_CHIP_ID as u16, 4, &[]);
        assert_eq!(id, 0x7922u32.to_le_bytes());
        // Nothing to poll yet.
        assert!(control(&mut dev, 2, 0xC0, REQ_WMT_EVENT, WMT_EVENT_VALUE, 0, 64, &[]).1.is_empty());
        // A section query: loaded.
        let mut query = vec![0x6F, 0xFC, 5 + 53, 0x01, OP_PATCH_DOWNLOAD, 54, 0, PATCH_QUERY];
        query.extend_from_slice(&[0; 53]);
        control(&mut dev, 3, 0x20, 0, 0, 0, query.len() as u16, &query);
        assert_eq!(control(&mut dev, 4, 0xC0, REQ_WMT_EVENT, WMT_EVENT_VALUE, 0, 64, &[]).1, [0xE4, 5, 2, 1, 1, 0, 2]);
        // Function on, then off: the controller behind it is told.
        let on = [0x6F, 0xFC, 6, 0x01, OP_FUNC_CTRL, 2, 0, 0, 1];
        control(&mut dev, 5, 0x20, 0, 0, 0, 9, &on);
        assert_eq!(control(&mut dev, 6, 0xC0, REQ_WMT_EVENT, WMT_EVENT_VALUE, 0, 64, &[]).1, [0xE4, 7, 2, 6, 3, 0, 0, 4, 4]);
        assert!(dev.function_on());
        let off = [0x6F, 0xFC, 6, 0x01, OP_FUNC_CTRL, 2, 0, 0, 0];
        control(&mut dev, 7, 0x20, 0, 0, 0, 9, &off);
        assert_eq!(dev.from_host, vec![FromHost::PowerOff]);
        // An ordinary HCI command goes through.
        dev.from_host.clear();
        control(&mut dev, 8, 0x20, 0, 0, 0, 3, &[0x03, 0x0C, 0x00]);
        assert_eq!(dev.from_host, vec![FromHost::Command(vec![0x03, 0x0C, 0x00])]);
    }

    #[test]
    fn events_wait_for_the_interrupt_pipe_and_go_out_in_16_byte_packets() {
        let mut dev = UsbDev::new();
        dev.push_event((0..20).collect());
        assert!(dev.out.is_empty());
        dev.handle(&Packet { kind: redir::START_INTERRUPT_RECEIVING, id: 0, body: vec![EP_EVENTS] });
        let sent: Vec<_> = dev.out.drain(..).map(|w| decode(&w)).collect();
        assert_eq!(sent[0].kind, redir::INTERRUPT_RECEIVING_STATUS);
        assert_eq!(sent[1..].iter().map(|p| p.body.len() - 4).collect::<Vec<_>>(), vec![16, 4]);
    }

    #[test]
    fn a_cancelled_read_loses_nothing() {
        let mut dev = UsbDev::new();
        // A read with nothing to give, cancelled: answered as cancelled.
        read(&mut dev, 10);
        assert!(answers(&mut dev).is_empty());
        dev.handle(&Packet { kind: CANCEL_DATA_PACKET, id: 10, body: vec![] });
        assert_eq!(answers(&mut dev), vec![(10, redir::STATUS_CANCELLED, vec![])]);
        // Data arrives while a read waits: answered at once.
        read(&mut dev, 11);
        dev.push_acl(vec![1, 2, 3]);
        assert_eq!(answers(&mut dev), vec![(11, 0, vec![1, 2, 3])]);
        // The cancel for that read arrives afterwards: QEMU dropped the
        // answer, so the next read gets the same data, before newer data.
        dev.push_acl(vec![4, 5]);
        dev.handle(&Packet { kind: CANCEL_DATA_PACKET, id: 11, body: vec![] });
        read(&mut dev, 12);
        read(&mut dev, 13);
        assert_eq!(answers(&mut dev), vec![(12, 0, vec![1, 2, 3]), (13, 0, vec![4, 5])]);
        assert_eq!((dev.stats.requeued, dev.stats.cancelled_reads), (1, 1));
    }

    #[test]
    fn an_id_used_again_brings_back_the_latest_answer() {
        // QEMU names a transfer by its place in the guest's ring, so ids
        // repeat. Read 7 was answered and arrived; much later read 7 is
        // answered again, and that answer is cancelled: the new data has
        // to come back, not the old (on Nov 15 a key report from before
        // the link was encrypted came back this way, after it).
        let mut dev = UsbDev::new();
        read(&mut dev, 7);
        dev.push_acl(vec![0xAA; 4]);
        assert_eq!(answers(&mut dev), vec![(7, 0, vec![0xAA; 4])]);
        read(&mut dev, 7);
        dev.push_acl(vec![0xBB; 4]);
        assert_eq!(answers(&mut dev), vec![(7, 0, vec![0xBB; 4])]);
        dev.handle(&Packet { kind: CANCEL_DATA_PACKET, id: 7, body: vec![] });
        read(&mut dev, 8);
        assert_eq!(answers(&mut dev), vec![(8, 0, vec![0xBB; 4])]);
        // And that was all there was to bring back.
        dev.handle(&Packet { kind: CANCEL_DATA_PACKET, id: 7, body: vec![] });
        read(&mut dev, 9);
        assert!(answers(&mut dev).is_empty());
    }

    #[test]
    fn transfers_can_be_merged_and_split() {
        let mut dev = UsbDev::new();
        dev.shaping.merge = 2;
        read(&mut dev, 1);
        dev.push_acl(vec![1, 1]);
        assert!(answers(&mut dev).is_empty()); // held back
        dev.push_acl(vec![2, 2, 2]);
        assert_eq!(answers(&mut dev), vec![(1, 0, vec![1, 1, 2, 2, 2])]);
        // Back to one packet per transfer; then one packet in two.
        dev.shaping.split_at = Some(1);
        dev.push_acl(vec![7, 8, 9]);
        dev.push_acl(vec![6]);
        for id in 2..=4 {
            read(&mut dev, id);
        }
        assert_eq!(answers(&mut dev), vec![(2, 0, vec![7]), (3, 0, vec![8, 9]), (4, 0, vec![6])]);
        assert_eq!((dev.stats.merged_transfers, dev.stats.split_packets), (1, 1));
    }
}
