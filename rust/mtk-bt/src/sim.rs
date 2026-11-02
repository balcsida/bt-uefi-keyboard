//! Simulated MediaTek MT7922 behind [`Transport`], for tests.
//!
//! It mirrors the USB I/O contract (control transfers never report the
//! received length; an empty WMT poll leaves the buffer untouched) and records
//! the first protocol violation it sees.

use std::string::String;
use std::vec::Vec;

use crate::wmt::*;

pub struct SimSection {
    pub dl_addr: u32,
    pub dl_size: u32,
    pub expected: Vec<u8>,
    pub loaded: bool,
}

#[derive(Default)]
pub struct Sim {
    // Configuration.
    pub chip_id: u32,
    pub fw_version: u32,
    pub sections: Vec<SimSection>,
    /// "Busy" answers left for queries.
    pub busy_replies: u32,
    /// Empty polls before each event.
    pub empty_polls: u32,
    pub never_reply: bool,
    /// MISC reads until reset-done shows.
    pub reset_done_polls: u32,
    /// Flag short IN replies, as EDK2 does.
    pub report_short: bool,
    pub short_register_reads: bool,

    // State.
    pub(crate) pending: Option<Vec<u8>>,
    pub(crate) empty_polls_left: u32,
    pub(crate) active: Option<usize>,
    pub(crate) received: u32,
    pub function_on: bool,
    pub(crate) reset_in_progress: bool,
    pub(crate) reset_polls: u32,
    pub reg_subsys_rst: u32,
    pub reg_ep_rst_opt: u32,
    pub reg_udma_int_sta: u32,

    // Statistics.
    pub commands: u32,
    pub queries: u32,
    pub chunks: u32,
    pub polls: u32,
    pub func_ctrls: u32,
    pub elapsed_us: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimError;

impl Sim {
    pub fn new() -> Self {
        Self { chip_id: 0x7922, reset_done_polls: 1, report_short: true, ..Self::default() }
    }

    pub fn with_sections(sections: Vec<SimSection>) -> Self {
        Self { sections, ..Self::new() }
    }

    fn fail(&mut self, what: String) {
        if self.error.is_none() {
            self.error = Some(what);
        }
    }

    fn queue_event(&mut self, op: u8, flag: u8, status: Option<u16>) {
        let extra = if status.is_some() { 2 } else { 0 };
        let mut ev = std::vec![WMT_EVENT_CODE, (WMT_HEADER_SIZE + extra) as u8, 0x02, op, (1 + extra) as u8, 0, flag];
        if let Some(status) = status {
            ev.extend_from_slice(&status.to_be_bytes());
        }
        self.pending = Some(ev);
        self.empty_polls_left = self.empty_polls;
    }

    fn handle_patch(&mut self, flag: u8, payload: &[u8]) {
        if flag == PATCH_QUERY {
            if payload.len() != 53 || payload[0] != 0 {
                return self.fail(std::format!("malformed section query, length {}", payload.len()));
            }
            if let Some(active) = self.active {
                return self.fail(std::format!("query while section {active} is open"));
            }
            let addr = u32::from_le_bytes(payload[1..5].try_into().unwrap());
            let size = u32::from_le_bytes(payload[5..9].try_into().unwrap());
            let Some(index) = self.sections.iter().position(|s| s.dl_addr == addr && s.dl_size == size) else {
                return self.fail(std::format!("query for unknown section at {addr:#x}"));
            };
            self.queries += 1;
            if self.sections[index].loaded {
                self.queue_event(OP_PATCH_DOWNLOAD, 2, None);
            } else if self.busy_replies > 0 {
                self.busy_replies -= 1;
                self.queue_event(OP_PATCH_DOWNLOAD, 1, None);
            } else {
                self.active = Some(index);
                self.received = 0;
                self.queue_event(OP_PATCH_DOWNLOAD, 0, None);
            }
            return;
        }

        let Some(index) = self.active else {
            return self.fail(std::format!("data chunk (flag {flag}) without a query"));
        };
        let len = payload.len() as u32;
        let section = &self.sections[index];
        if len == 0 || len > 250 || self.received + len > section.dl_size {
            return self.fail(std::format!("bad chunk length {len}"));
        }
        let expected_flag = if self.received == 0 {
            PATCH_FIRST
        } else if self.received + len == section.dl_size {
            PATCH_LAST
        } else {
            PATCH_CONTINUE
        };
        if flag != expected_flag {
            return self.fail(std::format!("flag {flag} at offset {}, expected {expected_flag}", self.received));
        }
        let at = self.received as usize;
        if section.expected[at..at + payload.len()] != *payload {
            return self.fail(std::format!("chunk data differs at offset {at}"));
        }
        self.received += len;
        self.chunks += 1;
        if self.received == self.sections[index].dl_size {
            self.sections[index].loaded = true;
            self.active = None;
        }
        self.queue_event(OP_PATCH_DOWNLOAD, 0, None);
    }

    fn handle_hci_command(&mut self, data: &[u8]) {
        if data.len() < 3 || data.len() != 3 + usize::from(data[2]) {
            return self.fail(std::format!("bad HCI command framing ({} bytes)", data.len()));
        }
        let opcode = u16::from_le_bytes([data[0], data[1]]);
        if opcode != WMT_HCI_OPCODE {
            return self.fail(std::format!("HCI command {opcode:#06x} is not simulated"));
        }
        if self.pending.is_some() {
            return self.fail(std::format!("WMT op {:#04x} sent before the previous event was read", data[4]));
        }
        if data.len() < 3 + WMT_HEADER_SIZE || data[3] != 0x01 {
            return self.fail(String::from("bad WMT header"));
        }
        let payload = &data[8..];
        let wmt_len = u16::from_le_bytes([data[5], data[6]]);
        if usize::from(wmt_len) != payload.len() + 1 {
            return self.fail(std::format!("WMT length {wmt_len} is not payload + 1"));
        }
        self.commands += 1;
        match data[4] {
            OP_PATCH_DOWNLOAD => self.handle_patch(data[7], payload),
            OP_FUNC_CTRL => {
                if payload.len() != 1 {
                    return self.fail(String::from("FUNC_CTRL payload length"));
                }
                self.function_on = payload[0] != 0;
                self.func_ctrls += 1;
                let status = self.function_on.then_some(0x0404);
                self.queue_event(OP_FUNC_CTRL, 0, status);
            }
            op => self.fail(std::format!("WMT op {op:#04x} is not simulated")),
        }
    }

    fn read_uhw(&mut self, reg: u32) -> u32 {
        match reg {
            UHW_SUBSYS_RST => self.reg_subsys_rst,
            UHW_UDMA_INT_STA => self.reg_udma_int_sta,
            UHW_MISC => {
                if self.reset_in_progress {
                    self.reset_polls += 1;
                    if self.reset_polls >= self.reset_done_polls {
                        self.reset_in_progress = false;
                    }
                }
                if self.reset_in_progress { 0 } else { UHW_RST_DONE }
            }
            _ => {
                self.fail(std::format!("read of UHW register {reg:#x}"));
                0
            }
        }
    }

    fn write_uhw(&mut self, reg: u32, value: u32) {
        match reg {
            UHW_EP_RST_OPT => self.reg_ep_rst_opt = value,
            UHW_UDMA_INT_STA => self.reg_udma_int_sta = value,
            UHW_SUBSYS_RST => {
                if value & 1 != 0 && self.reg_subsys_rst & 1 == 0 {
                    for section in &mut self.sections {
                        section.loaded = false;
                    }
                    self.function_on = false;
                    self.active = None;
                    self.reset_in_progress = true;
                    self.reset_polls = 0;
                }
                self.reg_subsys_rst = value & !1;
            }
            _ => self.fail(std::format!("write of UHW register {reg:#x}")),
        }
    }
}

impl Transport for Sim {
    type Error = SimError;

    fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
        _timeout_ms: u32,
    ) -> Result<bool, SimError> {
        let reg = (u32::from(value) << 16) | u32::from(index);
        match (request_type, request) {
            (REQTYPE_VENDOR_IN, REQ_WMT_EVENT) if value == WMT_EVENT_VALUE => {
                self.polls += 1;
                if data.len() != WMT_EVENT_BUFFER {
                    self.fail(std::format!("event poll with {} bytes", data.len()));
                }
                // Every reply is short: nothing, or a 7-9 byte event.
                if self.never_reply || self.pending.is_none() {
                    return Ok(self.report_short);
                }
                if self.empty_polls_left > 0 {
                    self.empty_polls_left -= 1;
                    return Ok(self.report_short);
                }
                let ev = self.pending.take().unwrap();
                data[..ev.len()].copy_from_slice(&ev);
                Ok(self.report_short)
            }
            (REQTYPE_VENDOR_IN, REQ_CHIP_REG_READ) if data.len() == 4 => {
                let value = match reg {
                    REG_CHIP_ID_LEGACY | REG_FW_FLAVOR => 0,
                    REG_CHIP_ID => self.chip_id,
                    REG_FW_VERSION => self.fw_version,
                    _ => {
                        self.fail(std::format!("read of chip register {reg:#x}"));
                        return Err(SimError);
                    }
                };
                if self.short_register_reads {
                    data[..2].copy_from_slice(&value.to_le_bytes()[..2]);
                    return Ok(self.report_short);
                }
                data.copy_from_slice(&value.to_le_bytes());
                Ok(false)
            }
            (REQTYPE_UHW_READ, REQ_UHW_READ) if data.len() == 4 => {
                let value = self.read_uhw(reg);
                data.copy_from_slice(&value.to_le_bytes());
                Ok(false)
            }
            _ => {
                self.fail(std::format!("unexpected control IN {request_type:#04x}/{request:#04x}"));
                Err(SimError)
            }
        }
    }

    fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        _timeout_ms: u32,
    ) -> Result<(), SimError> {
        match (request_type, request) {
            (REQTYPE_HCI_COMMAND, REQ_HCI_COMMAND) => {
                self.handle_hci_command(data);
                Ok(())
            }
            (REQTYPE_UHW_WRITE, REQ_UHW_WRITE) if data.len() == 4 => {
                let reg = (u32::from(value) << 16) | u32::from(index);
                self.write_uhw(reg, u32::from_le_bytes(data.try_into().unwrap()));
                Ok(())
            }
            _ => {
                self.fail(std::format!("unexpected control OUT {request_type:#04x}/{request:#04x}"));
                Err(SimError)
            }
        }
    }

    fn stall_us(&mut self, us: u32) {
        self.elapsed_us += u64::from(us);
    }
}
