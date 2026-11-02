//! The MediaTek WMT channel over USB endpoint 0, register access, firmware
//! upload and function control, following what Linux btmtk does for USB
//! parts (reimplemented from the protocol description).
//!
//! - WMT commands are HCI vendor command `0xFC6F`, sent as a class control
//!   transfer like any HCI command.
//! - Replies are vendor event `0xE4`, fetched by polling a vendor control IN
//!   request; an empty reply means "not ready yet".
//! - Chip and UHW registers are read and written with vendor requests.

use core::fmt;

use crate::firmware::{FirmwareImage, Section, BIN_INFO_SIZE, CHUNK_SIZE};

pub const REG_CHIP_ID_LEGACY: u32 = 0x8000_0008;
pub const REG_CHIP_ID: u32 = 0x7001_0200;
pub const REG_FW_VERSION: u32 = 0x8002_1004;
pub const REG_FW_FLAVOR: u32 = 0x7001_0020;

pub const UHW_MISC: u32 = 0x7000_2510;
pub const UHW_SUBSYS_RST: u32 = 0x7000_2610;
pub const UHW_UDMA_INT_STA: u32 = 0x7400_0024;
pub const UHW_EP_RST_OPT: u32 = 0x7401_1890;
pub const UHW_EP_RST_IN_OUT: u32 = 0x0001_0001;
pub const UHW_RST_DONE: u32 = 1 << 8;

pub const WMT_HCI_OPCODE: u16 = 0xFC6F;
pub const WMT_EVENT_CODE: u8 = 0xE4;
pub const WMT_HEADER_SIZE: usize = 5;
pub const WMT_EVENT_BUFFER: usize = 64;

pub const OP_PATCH_DOWNLOAD: u8 = 0x01;
pub const OP_FUNC_CTRL: u8 = 0x06;

pub const PATCH_QUERY: u8 = 0;
pub const PATCH_FIRST: u8 = 1;
pub const PATCH_CONTINUE: u8 = 2;
pub const PATCH_LAST: u8 = 3;

// Endpoint 0 requests.
pub const REQTYPE_HCI_COMMAND: u8 = 0x20;
pub const REQ_HCI_COMMAND: u8 = 0x00;
pub const REQTYPE_VENDOR_IN: u8 = 0xC0;
pub const REQ_WMT_EVENT: u8 = 0x01;
pub const WMT_EVENT_VALUE: u16 = 0x0030;
pub const REQ_CHIP_REG_READ: u8 = 0x63;
pub const REQTYPE_UHW_READ: u8 = 0xDE;
pub const REQ_UHW_READ: u8 = 0x01;
pub const REQTYPE_UHW_WRITE: u8 = 0x5E;
pub const REQ_UHW_WRITE: u8 = 0x02;

const CONTROL_TIMEOUT_MS: u32 = 2000;
const QUERY_RETRIES: u32 = 20;
const BUSY_DELAY_US: u32 = 100_000;
const ACTIVATION_DELAY_US: u32 = 100_000;
const RESET_SETTLE_US: u32 = 100_000;
const RESET_POLL_US: u32 = 20_000;
const RESET_TIMEOUT_US: u32 = 1_000_000;

/// Endpoint 0 access plus a delay, shaped like `EFI_USB_IO_PROTOCOL`.
pub trait Transport {
    type Error: fmt::Debug;

    /// Control IN transfer into `data`. The received length is not
    /// reported (UsbIo does not report it either), so callers that must spot
    /// an empty reply pre-fill the buffer. A short reply is not an error:
    /// return `Ok(true)` if the USB stack said it was short (EDK2 does),
    /// `Ok(false)` if it was full-length or the stack does not tell.
    fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<bool, Self::Error>;

    fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout_ms: u32,
    ) -> Result<(), Self::Error>;

    fn stall_us(&mut self, us: u32);

    /// Traffic trace hook: `tag` is `wmt>`, `wmt<`, `reg<`, `uhw<` or `uhw>`.
    fn trace(&mut self, _tag: &str, _data: &[u8]) {}

    /// Called after every uploaded chunk.
    fn progress(&mut self, _section: usize, _sent: u32, _total: u32) {}
}

/// A borrowed transport works too, so code that only has `&mut T` (a
/// hand-off, a panic handler) can still drive the chip.
impl<T: Transport + ?Sized> Transport for &mut T {
    type Error = T::Error;

    fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<bool, Self::Error> {
        (**self).control_in(request_type, request, value, index, data, timeout_ms)
    }

    fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout_ms: u32,
    ) -> Result<(), Self::Error> {
        (**self).control_out(request_type, request, value, index, data, timeout_ms)
    }

    fn stall_us(&mut self, us: u32) {
        (**self).stall_us(us)
    }

    fn trace(&mut self, tag: &str, data: &[u8]) {
        (**self).trace(tag, data)
    }

    fn progress(&mut self, section: usize, sent: u32, total: u32) {
        (**self).progress(section, sent, total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<E> {
    Transport(E),
    /// No WMT event within the event timeout.
    Timeout { op: u8 },
    /// Event for another op, malformed event, or a short register read.
    Protocol(&'static str),
    /// The chip stayed busy for every query.
    Busy { section: usize },
    /// A section needs uploading and that was not allowed. Only the query
    /// was sent for it.
    NotLoaded { section: usize },
    /// The subsystem reset did not report completion.
    ResetTimeout,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "USB transfer failed: {e:?}"),
            Self::Timeout { op } => write!(f, "no WMT event for op {op:#04x}"),
            Self::Protocol(what) => write!(f, "protocol error: {what}"),
            Self::Busy { section } => write!(f, "section {section} still busy after {QUERY_RETRIES} queries"),
            Self::NotLoaded { section } => write!(f, "section {section} is not loaded and upload was not allowed"),
            Self::ResetTimeout => write!(f, "subsystem reset did not complete"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WmtEvent {
    pub op: u8,
    pub flag: u8,
    /// Big-endian word after the WMT header, if the event carried one.
    pub status: Option<u16>,
    pub raw: [u8; WMT_EVENT_BUFFER],
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionState {
    NeedsDownload,
    Busy,
    Loaded,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChipInfo {
    pub chip_id: u32,
    pub fw_version: u32,
    pub fw_flavor: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadResult {
    pub sections_checked: u32,
    pub sections_already_loaded: u32,
    pub sections_downloaded: u32,
    pub chunks_sent: u32,
    pub busy_retries: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub wmt_commands: u32,
    pub event_polls: u32,
    /// Polls the USB stack flagged as short.
    pub short_polls: u32,
}

pub struct Mtk<T: Transport> {
    pub transport: T,
    /// Per WMT command; Linux uses 10 s.
    pub event_timeout_ms: u32,
    /// Between empty event polls; Linux uses 500 us.
    pub poll_interval_us: u32,
    pub stats: Stats,
}

type Res<T, E> = Result<T, Error<E>>;

impl<T: Transport> Mtk<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, event_timeout_ms: 5000, poll_interval_us: 500, stats: Stats::default() }
    }

    fn read_register(&mut self, request_type: u8, request: u8, reg: u32, tag: &str) -> Res<u32, T::Error> {
        let mut buf = [0u8; 4];
        let short = self
            .transport
            .control_in(request_type, request, (reg >> 16) as u16, reg as u16, &mut buf, CONTROL_TIMEOUT_MS)
            .map_err(Error::Transport)?;
        if short {
            return Err(Error::Protocol("short register read"));
        }
        let value = u32::from_le_bytes(buf);
        let mut pair = [0u8; 8];
        pair[..4].copy_from_slice(&reg.to_le_bytes());
        pair[4..].copy_from_slice(&buf);
        self.transport.trace(tag, &pair);
        Ok(value)
    }

    pub fn read_chip_reg(&mut self, reg: u32) -> Res<u32, T::Error> {
        self.read_register(REQTYPE_VENDOR_IN, REQ_CHIP_REG_READ, reg, "reg<")
    }

    pub fn read_uhw_reg(&mut self, reg: u32) -> Res<u32, T::Error> {
        self.read_register(REQTYPE_UHW_READ, REQ_UHW_READ, reg, "uhw<")
    }

    pub fn write_uhw_reg(&mut self, reg: u32, value: u32) -> Res<(), T::Error> {
        let mut pair = [0u8; 8];
        pair[..4].copy_from_slice(&reg.to_le_bytes());
        pair[4..].copy_from_slice(&value.to_le_bytes());
        self.transport.trace("uhw>", &pair);
        self.transport
            .control_out(
                REQTYPE_UHW_WRITE,
                REQ_UHW_WRITE,
                (reg >> 16) as u16,
                reg as u16,
                &value.to_le_bytes(),
                CONTROL_TIMEOUT_MS,
            )
            .map_err(Error::Transport)
    }

    /// Chip ID, firmware version and flavor (read-only register accesses).
    pub fn chip_info(&mut self) -> Res<ChipInfo, T::Error> {
        // MT7663 answers on the legacy register; newer parts on the new one.
        let legacy = self.read_chip_reg(REG_CHIP_ID_LEGACY)?;
        if legacy == 0x7663 {
            return Ok(ChipInfo { chip_id: legacy, ..ChipInfo::default() });
        }
        Ok(ChipInfo {
            chip_id: self.read_chip_reg(REG_CHIP_ID)?,
            fw_version: self.read_chip_reg(REG_FW_VERSION)?,
            fw_flavor: (self.read_chip_reg(REG_FW_FLAVOR)? & 0x80) >> 7,
        })
    }

    /// Send one WMT command and wait for its event.
    pub fn wmt_command(&mut self, op: u8, flag: u8, payload: &[u8]) -> Res<WmtEvent, T::Error> {
        if payload.len() > CHUNK_SIZE {
            return Err(Error::Protocol("WMT payload too long"));
        }
        let mut packet = [0u8; 3 + WMT_HEADER_SIZE + CHUNK_SIZE];
        let wmt_len = (payload.len() + 1) as u16;
        packet[0..2].copy_from_slice(&WMT_HCI_OPCODE.to_le_bytes());
        packet[2] = (WMT_HEADER_SIZE + payload.len()) as u8;
        packet[3] = 0x01; // host to chip
        packet[4] = op;
        packet[5..7].copy_from_slice(&wmt_len.to_le_bytes());
        packet[7] = flag;
        packet[8..8 + payload.len()].copy_from_slice(payload);
        let packet = &packet[..8 + payload.len()];

        self.transport.trace("wmt>", packet);
        self.transport
            .control_out(REQTYPE_HCI_COMMAND, REQ_HCI_COMMAND, 0, 0, packet, CONTROL_TIMEOUT_MS)
            .map_err(Error::Transport)?;
        self.stats.wmt_commands += 1;
        self.wait_event(op)
    }

    /// Poll endpoint 0 for the WMT event. Every poll is short (an event is a
    /// few bytes of the 64 asked for), and UsbIo does not report lengths, so
    /// the buffer is zeroed first and a reply is recognized by a non-zero
    /// event code.
    fn wait_event(&mut self, op: u8) -> Res<WmtEvent, T::Error> {
        let limit_us = u64::from(self.event_timeout_ms) * 1000;
        let mut waited_us = 0u64;
        loop {
            let mut buf = [0u8; WMT_EVENT_BUFFER];
            let short = self
                .transport
                .control_in(REQTYPE_VENDOR_IN, REQ_WMT_EVENT, WMT_EVENT_VALUE, 0, &mut buf, CONTROL_TIMEOUT_MS)
                .map_err(Error::Transport)?;
            self.stats.event_polls += 1;
            if short {
                self.stats.short_polls += 1;
            }

            if buf[0] != 0 {
                let len = 2 + usize::from(buf[1]);
                if len > buf.len() {
                    self.transport.trace("wmt<", &buf);
                    return Err(Error::Protocol("oversized event"));
                }
                self.transport.trace("wmt<", &buf[..len]);
                if buf[0] == WMT_EVENT_CODE {
                    if usize::from(buf[1]) < WMT_HEADER_SIZE {
                        return Err(Error::Protocol("WMT event too short"));
                    }
                    if buf[3] != op {
                        return Err(Error::Protocol("WMT event for another op"));
                    }
                    let status = (usize::from(buf[1]) >= WMT_HEADER_SIZE + 2)
                        .then(|| u16::from_be_bytes([buf[7], buf[8]]));
                    return Ok(WmtEvent { op: buf[3], flag: buf[6], status, raw: buf, len });
                }
                // Some other HCI event came through endpoint 0; keep waiting.
            }

            if waited_us >= limit_us {
                return Err(Error::Timeout { op });
            }
            self.transport.stall_us(self.poll_interval_us);
            waited_us += u64::from(self.poll_interval_us);
        }
    }

    /// Ask whether one section is loaded. A status query; no firmware data.
    pub fn query_section(&mut self, section: &Section<'_>) -> Res<SectionState, T::Error> {
        let mut payload = [0u8; 1 + BIN_INFO_SIZE];
        payload[0] = 0; // legacy download mode
        payload[1..].copy_from_slice(section.bin_info);
        let event = self.wmt_command(OP_PATCH_DOWNLOAD, PATCH_QUERY, &payload)?;
        Ok(match event.flag {
            2 => SectionState::Loaded,
            1 => SectionState::Busy,
            _ => SectionState::NeedsDownload,
        })
    }

    /// Send one section in chunks. Only after `query_section` said
    /// `NeedsDownload` for it.
    pub fn download_section(&mut self, index: usize, section: &Section<'_>, result: &mut LoadResult) -> Res<(), T::Error> {
        let total = section.data.len();
        let mut sent = 0;
        for chunk in section.data.chunks(CHUNK_SIZE) {
            // The first chunk is always "first", even when it is also the last.
            let flag = if sent == 0 {
                PATCH_FIRST
            } else if sent + chunk.len() == total {
                PATCH_LAST
            } else {
                PATCH_CONTINUE
            };
            let event = self.wmt_command(OP_PATCH_DOWNLOAD, flag, chunk)?;
            // "Busy" for a data chunk means the chip lost the download.
            if event.flag == 1 {
                return Err(Error::Protocol("chip reported busy during upload"));
            }
            sent += chunk.len();
            result.chunks_sent += 1;
            self.transport.progress(index, sent as u32, total as u32);
        }
        Ok(())
    }

    /// Query every section and, if allowed, upload the missing ones; then
    /// wait 100 ms for activation, as Linux does.
    pub fn load_firmware(&mut self, fw: &FirmwareImage<'_>, allow_download: bool) -> Res<LoadResult, T::Error> {
        let mut result = LoadResult::default();
        for (index, section) in fw.sections().enumerate() {
            if section.dl_size == 0 {
                continue;
            }
            result.sections_checked += 1;
            let mut retries = QUERY_RETRIES;
            loop {
                match self.query_section(section)? {
                    SectionState::Loaded => {
                        result.sections_already_loaded += 1;
                        break;
                    }
                    SectionState::NeedsDownload => {
                        if !allow_download {
                            return Err(Error::NotLoaded { section: index });
                        }
                        self.download_section(index, section, &mut result)?;
                        result.sections_downloaded += 1;
                        break;
                    }
                    SectionState::Busy => {
                        result.busy_retries += 1;
                        retries -= 1;
                        if retries == 0 {
                            return Err(Error::Busy { section: index });
                        }
                        self.transport.stall_us(BUSY_DELAY_US);
                    }
                }
            }
        }
        self.transport.stall_us(ACTIVATION_DELAY_US);
        Ok(result)
    }

    /// Endpoint reset option, then WMT FUNC_CTRL on. Standard HCI works after this.
    pub fn enable(&mut self) -> Res<WmtEvent, T::Error> {
        self.write_uhw_reg(UHW_EP_RST_OPT, UHW_EP_RST_IN_OUT)?;
        self.wmt_command(OP_FUNC_CTRL, 0, &[1])
    }

    /// WMT FUNC_CTRL off, as Linux sends at shutdown.
    pub fn disable(&mut self) -> Res<WmtEvent, T::Error> {
        self.wmt_command(OP_FUNC_CTRL, 0, &[0])
    }

    /// MT7922 Bluetooth subsystem reset, for recovery after a WMT timeout.
    /// Probably discards the loaded firmware (untested).
    pub fn subsys_reset_7922(&mut self) -> Res<(), T::Error> {
        let value = self.read_uhw_reg(UHW_SUBSYS_RST)?;
        self.write_uhw_reg(UHW_SUBSYS_RST, value | 0x2020)?;
        self.write_uhw_reg(UHW_EP_RST_OPT, UHW_EP_RST_IN_OUT)?;
        let value = self.read_uhw_reg(UHW_SUBSYS_RST)?;
        self.write_uhw_reg(UHW_SUBSYS_RST, value | 1)?;
        self.transport.stall_us(RESET_SETTLE_US);

        let mut waited = 0;
        loop {
            if let Ok(misc) = self.read_uhw_reg(UHW_MISC) {
                if misc & UHW_RST_DONE != 0 {
                    break;
                }
            }
            if waited >= RESET_TIMEOUT_US {
                return Err(Error::ResetTimeout);
            }
            self.transport.stall_us(RESET_POLL_US);
            waited += RESET_POLL_US;
        }

        self.write_uhw_reg(UHW_UDMA_INT_STA, 0xFF)?;
        if self.read_chip_reg(REG_CHIP_ID)? == 0 {
            return Err(Error::Protocol("chip ID reads 0 after reset"));
        }
        Ok(())
    }
}
