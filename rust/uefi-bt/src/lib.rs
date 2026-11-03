//! Bluetooth over USB in UEFI: HCI interface discovery, the MediaTek
//! transport on `EFI_USB_IO_PROTOCOL`, HCI command/event/ACL I/O with
//! diagnostics, and a TSC clock.

#![no_std]

extern crate alloc;

#[macro_use]
pub mod output;
pub mod app;
pub mod att;
pub mod bootrec;
pub mod bond;
pub mod clock;
#[cfg(feature = "embassy")]
pub mod embassy;
pub mod eventlog;
pub mod gatt_cache;
pub mod emergency;
pub mod hid;
pub mod keymap;
pub mod link;
pub mod logbuf;
pub mod pipe;
pub mod rng;
pub mod seal;
pub mod tap;
pub mod tcg;
pub mod tpm2;
pub mod trace;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol, SearchType};
use uefi::proto::device_path::DevicePath;
use uefi::proto::device_path::text::{AllowShortcuts, DisplayOnly};
use uefi::proto::usb::UsbTransferStatus;
use uefi::proto::usb::io::{ControlTransfer, UsbIo};
use mtk_bt::AclKind;
use uefi::{Handle, Identify, Status};

pub use pipe::{stop_event_pipes, PipeStats};

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}
pub use trace::{Dir, HciStats, Trace};
use uefi_raw::protocol::usb::io::UsbIoProtocol;

pub const MTK_VENDOR_ID: u16 = 0x0E8D;
pub const BT_CLASS: (u8, u8, u8) = (0xE0, 0x01, 0x01);

pub const HCI_EVENT_COMMAND_COMPLETE: u8 = 0x0E;
pub const HCI_EVENT_COMMAND_STATUS: u8 = 0x0F;
pub const HCI_MAX_EVENT: usize = 2 + 255;
/// Buffer for one ACL packet: 4-byte header plus up to 1024 bytes.
pub const ACL_BUF: usize = 4 + 1024;
/// Bulk endpoint packet size (high speed).
const BULK_PACKET: usize = 512;

pub const HCI_OP_RESET: u16 = 0x0C03;
pub const HCI_OP_READ_LOCAL_NAME: u16 = 0x0C14;
pub const HCI_OP_READ_LOCAL_VERSION: u16 = 0x1001;
pub const HCI_OP_READ_BD_ADDR: u16 = 0x1009;
pub const HCI_OP_LE_READ_BUFFER_SIZE: u16 = 0x2002;

/// A failed USB transfer: the EFI status plus the USB transfer status bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UsbError {
    pub status: Status,
    pub usb_status: u32,
}

impl fmt::Debug for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (USB status {:#x})", self.status, self.usb_status)
    }
}

impl From<uefi::Error<UsbTransferStatus>> for UsbError {
    fn from(e: uefi::Error<UsbTransferStatus>) -> Self {
        Self { status: e.status(), usb_status: e.data().bits() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HciError {
    Usb(UsbError),
    /// No Command Complete within the timeout.
    Timeout,
    /// Command Status with a non-zero status.
    Rejected(u8),
    /// An event started but did not finish.
    PartialEvent,
    /// The controller sent a MediaTek crash dump on the ACL pipe.
    FirmwareCrashed,
    /// The event pipe lost bytes (ring overflow) or keeps failing, so the
    /// event stream can't be trusted.
    EventPipe,
}

impl From<UsbError> for HciError {
    fn from(e: UsbError) -> Self {
        Self::Usb(e)
    }
}

/// A USB interface that carries HCI (interrupt IN for events, bulk IN/OUT for ACL).
#[derive(Debug, Clone)]
pub struct HciInterface {
    pub handle: Handle,
    pub vendor_id: u16,
    pub product_id: u16,
    pub interface_number: u8,
    pub int_in: u8,
    pub int_in_max_packet: u16,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub path: Option<String>,
}

/// Print `tag` and up to `max` bytes in hex.
pub fn dump(tag: &str, data: &[u8], max: usize) {
    let mut line = String::new();
    for b in data.iter().take(max) {
        let _ = fmt::Write::write_fmt(&mut line, format_args!(" {b:02x}"));
    }
    if data.len() > max {
        let _ = fmt::Write::write_fmt(&mut line, format_args!(" ... ({} bytes)", data.len()));
    }
    crate::say!("    {tag}{line}");
}

fn open_get<P: uefi::proto::ProtocolPointer + ?Sized>(handle: Handle) -> uefi::Result<ScopedProtocol<P>> {
    // SAFETY: GET_PROTOCOL does not take ownership from the USB bus driver;
    // the interface stays valid while the device is attached, which holds for
    // the life of these apps.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams { handle, agent: boot::image_handle(), controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }
}

pub fn device_path_text(handle: Handle) -> Option<String> {
    let path = open_get::<DevicePath>(handle).ok()?;
    let text = path.to_string16(DisplayOnly(false), AllowShortcuts(false)).ok()?;
    Some(String::from(&text))
}

/// Find interfaces with class E0/01/01 that carry the HCI endpoints. Other
/// interfaces with the same class codes carry voice (isochronous) or
/// MediaTek ISO data (interrupt only). Uses cached descriptors only.
/// Returns the interfaces and the number of USB interfaces scanned.
pub fn find_hci_interfaces() -> uefi::Result<(Vec<HciInterface>, usize)> {
    let handles = match boot::locate_handle_buffer(SearchType::ByProtocol(&UsbIo::GUID)) {
        Ok(handles) => handles,
        Err(e) if e.status() == Status::NOT_FOUND => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    };

    let mut found = Vec::new();
    for &handle in handles.iter() {
        let Ok(mut usb) = open_get::<UsbIo>(handle) else { continue };
        if let Some(mut info) = describe(handle, &mut usb) {
            info.path = device_path_text(handle);
            found.push(info);
        }
    }
    Ok((found, handles.len()))
}

/// The HCI endpoints of the USB interface behind `usb` (cached descriptors
/// only, nothing is sent), or `None` if it is not a Bluetooth HCI interface.
/// `path` is left empty.
pub fn describe(handle: Handle, usb: &mut UsbIo) -> Option<HciInterface> {
    let (dev, intf) = (usb.device_descriptor().ok()?, usb.interface_descriptor().ok()?);
    if (intf.interface_class, intf.interface_subclass, intf.interface_protocol) != BT_CLASS {
        return None;
    }
    let mut info = HciInterface {
        handle,
        vendor_id: dev.id_vendor,
        product_id: dev.id_product,
        interface_number: intf.interface_number,
        int_in: 0,
        int_in_max_packet: 0,
        bulk_in: 0,
        bulk_out: 0,
        path: None,
    };
    for index in 0..intf.num_endpoints {
        let Ok(ep) = usb.endpoint_descriptor(index) else { continue };
        let is_in = ep.endpoint_address & 0x80 != 0;
        match ep.attributes & 0x03 {
            0x03 if is_in => {
                info.int_in = ep.endpoint_address;
                info.int_in_max_packet = ep.max_packet_size & 0x7FF;
            }
            0x02 if is_in => info.bulk_in = ep.endpoint_address,
            0x02 => info.bulk_out = ep.endpoint_address,
            _ => {}
        }
    }
    (info.int_in != 0 && info.bulk_in != 0 && info.bulk_out != 0).then_some(info)
}

/// LE advertising report events (legacy, directed, extended). Counted, not traced.
pub fn is_adv_report(event: &[u8]) -> bool {
    event.len() >= 3 && event[0] == 0x3E && matches!(event[2], 0x02 | 0x0B | 0x0D)
}

/// One ACL packet read from bulk IN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclRead {
    /// Full packet length, header included.
    pub len: usize,
    /// Bytes stored in the caller's buffer (less than `len` if it did not fit).
    pub stored: usize,
    pub kind: AclKind,
}

/// What `drain` threw away.
#[derive(Debug, Default, Clone, Copy)]
pub struct DrainReport {
    pub events: u32,
    pub acl: u32,
    pub ms: u64,
    /// Connection handle of the last data packet: a link the controller
    /// kept from before (it keeps links across host resets).
    pub acl_handle: Option<u16>,
}

/// How an HCI_Disconnect sent by [`UsbHci::disconnect`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// There was no such connection.
    NoConnection,
    /// The link was there and is closed now.
    Closed { reason: u8 },
    /// Accepted, but no Disconnection Complete in time (the peer may be
    /// out of range); a reset clears the link anyway.
    NoCompletion,
    /// Refused, or completed with an error status.
    Failed(u8),
}

impl DrainReport {
    pub fn is_empty(&self) -> bool {
        self.events == 0 && self.acl == 0
    }
}

/// An open HCI interface.
pub struct UsbHci {
    /// `None` once closed: every transfer then fails with NOT_STARTED.
    usb: Option<ScopedProtocol<UsbIo>>,
    pub info: HciInterface,
    /// Dump HCI and WMT traffic as it happens.
    pub verbose: bool,
    /// Print a one-line description of every ATT/SMP/signaling packet on
    /// connections, in both directions.
    pub att_trace: bool,
    pub stats: HciStats,
    /// The most recent packets, for diagnostics.
    pub trace: Trace,
    /// Event ring of the asynchronous event transfer, while it runs.
    ring: Option<Box<pipe::EventRing>>,
}

impl Drop for UsbHci {
    fn drop(&mut self) {
        self.close();
    }
}

const CLOSED: UsbError = UsbError { status: Status::NOT_STARTED, usb_status: 0 };

impl UsbHci {
    /// Open the interface and start the asynchronous event transfer. If the
    /// USB stack refuses it, events are read with synchronous transfers.
    pub fn open(info: HciInterface) -> uefi::Result<Self> {
        let usb = open_get::<UsbIo>(info.handle)?;
        Ok(Self::with_protocol(info, usb))
    }

    /// Open the interface as its driver (BY_DRIVER, `agent` being the
    /// driver binding handle), so the firmware asks the driver to stop
    /// before the interface goes away.
    pub fn open_by_driver(info: HciInterface, agent: Handle) -> uefi::Result<Self> {
        // SAFETY: BY_DRIVER is the driver model's exclusive open; the
        // interface stays valid until our binding's Stop() closes it.
        let usb = unsafe {
            boot::open_protocol::<UsbIo>(
                OpenProtocolParams { handle: info.handle, agent, controller: Some(info.handle) },
                OpenProtocolAttributes::ByDriver,
            )?
        };
        Ok(Self::with_protocol(info, usb))
    }

    fn with_protocol(info: HciInterface, usb: ScopedProtocol<UsbIo>) -> Self {
        let mut hci = Self {
            usb: Some(usb),
            info,
            verbose: false,
            att_trace: false,
            stats: HciStats::default(),
            trace: Trace::new(),
            ring: None,
        };
        if let Err(e) = hci.start_event_pipe() {
            crate::say!("Asynchronous event transfer refused ({e:?}); reading events synchronously");
        }
        hci
    }

    /// Stop the event transfer and close the USB protocol. Every transfer
    /// fails afterwards.
    pub fn close(&mut self) {
        self.stop_event_pipe();
        self.usb = None;
    }

    pub fn is_open(&self) -> bool {
        self.usb.is_some()
    }

    fn usb(&mut self) -> Result<&mut UsbIo, UsbError> {
        self.usb.as_deref_mut().ok_or(CLOSED)
    }

    fn raw_protocol(&mut self) -> Option<*mut UsbIoProtocol> {
        // `UsbIo` is a #[repr(transparent)] wrapper around the raw protocol.
        let usb: &mut UsbIo = self.usb.as_deref_mut()?;
        Some((usb as *mut UsbIo).cast())
    }

    /// Queue the asynchronous interrupt transfer on the event endpoint.
    pub fn start_event_pipe(&mut self) -> Result<(), UsbError> {
        if self.ring.is_some() {
            return Ok(());
        }
        let ring = pipe::EventRing::new();
        let protocol = self.raw_protocol().ok_or(CLOSED)?;
        let packet = usize::from(if self.info.int_in_max_packet != 0 { self.info.int_in_max_packet } else { 16 });
        // SAFETY: the protocol is open for as long as `self`, and the ring
        // is kept until `stop_event_pipe` has cancelled the transfer.
        let status = unsafe { pipe::start(protocol, self.info.int_in, packet, &ring) };
        if status.is_error() {
            return Err(UsbError { status, usb_status: 0 });
        }
        self.ring = Some(ring);
        Ok(())
    }

    /// Cancel the asynchronous transfer; only then is the ring freed.
    pub fn stop_event_pipe(&mut self) {
        if self.ring.is_some() {
            if let Some(protocol) = self.raw_protocol() {
                // SAFETY: the transfer was started on this open protocol.
                unsafe { pipe::cancel(protocol, self.info.int_in) };
            }
            self.ring = None;
        }
    }

    pub fn pipe_stats(&self) -> Option<PipeStats> {
        self.ring.as_ref().map(|ring| ring.stats())
    }

    /// Count, trace and print an event the host stack must not see.
    pub fn note_malformed_event(&mut self, event: &[u8], why: &dyn fmt::Debug) {
        self.stats.events_malformed += 1;
        self.trace.record(Dir::Dropped, event);
        crate::say!("    dropped malformed event ({why:?}):");
        dump("   ", event, 32);
    }

    /// True once a MediaTek crash dump has been seen on the ACL pipe.
    pub fn firmware_crashed(&self) -> bool {
        self.stats.fw_dump_packets > 0
    }

    /// EDK2's UsbBusDxe reports a successful but short control IN transfer as
    /// `DEVICE_ERROR` with no USB error bits. Returns `Ok(short)`.
    fn control_in_raw(&mut self, rt: u8, req: u8, value: u16, index: u16, data: &mut [u8], timeout_ms: u32) -> Result<bool, UsbError> {
        match self.usb()?.control_transfer(rt, req, value, index, ControlTransfer::DataIn(data), timeout_ms) {
            Ok(()) => Ok(false),
            Err(e) if e.status() == Status::DEVICE_ERROR && e.data().is_empty() => Ok(true),
            Err(e) => {
                let err = UsbError::from(e);
                crate::say!("    control IN {rt:02x}/{req:02x} value {value:04x} index {index:04x} failed: {err:?}");
                Err(err)
            }
        }
    }

    fn control_out_raw(&mut self, rt: u8, req: u8, value: u16, index: u16, data: &[u8], timeout_ms: u32) -> Result<(), UsbError> {
        let transfer = if data.is_empty() { ControlTransfer::None } else { ControlTransfer::DataOut(data) };
        self.usb()?.control_transfer(rt, req, value, index, transfer, timeout_ms).map_err(|e| {
            let err = UsbError::from(e);
            crate::say!("    control OUT {rt:02x}/{req:02x} value {value:04x} index {index:04x} failed: {err:?}");
            err
        })
    }

    /// Send a raw HCI command packet `[opcode LE16][len][params]`.
    pub fn send_command(&mut self, packet: &[u8]) -> Result<(), UsbError> {
        self.stats.commands += 1;
        if packet.len() >= 2 {
            self.stats.last_command = Some((u16::from_le_bytes([packet[0], packet[1]]), clock::now_ms()));
        }
        self.trace.record(Dir::Cmd, packet);
        if self.verbose {
            dump("hci>", packet, 32);
        }
        self.control_out_raw(0x20, 0x00, 0, 0, packet, 2000)
    }

    /// Send an ACL packet `[handle/flags LE16][len LE16][data]` on bulk OUT.
    pub fn send_acl(&mut self, packet: &[u8]) -> Result<(), UsbError> {
        self.stats.acl_out += 1;
        self.trace.record(Dir::AclOut, packet);
        if self.att_trace {
            if let Some(text) = att::describe(packet) {
                crate::say!("  {:>6} > {text}", clock::now_ms());
            }
        }
        if self.verbose {
            dump("acl>", packet, 32);
        }
        let bulk_out = self.info.bulk_out;
        let sent = self.usb()?.sync_bulk_send(bulk_out, packet, 1000)?;
        if sent != packet.len() {
            return Err(UsbError { status: Status::DEVICE_ERROR, usb_status: 0 });
        }
        Ok(())
    }

    /// Read one ACL packet from bulk IN, reassembled from its header length
    /// and classified (connection data, MediaTek crash dump, debug log).
    /// Packets longer than `buf` are read completely, but only the first
    /// `buf.len()` bytes are kept. `Ok(None)` if nothing arrived within
    /// `timeout_ms`.
    pub fn read_acl(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<Option<AclRead>, UsbError> {
        // Always ask for a whole bulk packet, so a full one can't overflow
        // the transfer (babble), and copy what fits.
        let mut scratch = [0u8; BULK_PACKET];
        let mut header = [0u8; 4];
        let mut got = 0usize;
        let mut need = 4usize;
        while got < need {
            let wait = if got == 0 { timeout_ms.max(1) } else { 200 };
            let bulk_in = self.info.bulk_in;
            let n = match self.usb()?.sync_bulk_receive(bulk_in, &mut scratch, wait as usize) {
                Ok(n) => n,
                Err(e) if e.status() == Status::TIMEOUT && got == 0 => return Ok(None),
                Err(e) => return Err(UsbError::from(e)),
            };
            if n == 0 {
                if got == 0 {
                    return Ok(None); // a stray zero-length packet
                }
                break;
            }
            for (i, &b) in scratch[..n].iter().enumerate() {
                if got + i < header.len() {
                    header[got + i] = b;
                }
                if got + i < buf.len() {
                    buf[got + i] = b;
                }
            }
            got += n;
            if got >= 4 {
                need = 4 + usize::from(u16::from_le_bytes([header[2], header[3]]));
            }
            if n < BULK_PACKET && got < need {
                break; // the device ended the transfer early
            }
        }

        let stored = got.min(buf.len());
        let kind = mtk_bt::classify_acl(&buf[..stored]);
        self.stats.acl_in += 1;
        match kind {
            AclKind::FirmwareDump { last } => {
                self.stats.fw_dump_packets += 1;
                self.stats.fw_dump_complete |= last;
            }
            AclKind::FirmwareDiag => self.stats.fw_diag_packets += 1,
            _ => {}
        }
        if self.att_trace && matches!(kind, AclKind::Data { .. }) {
            if let Some(text) = att::describe(&buf[..stored]) {
                crate::say!("  {:>6} < {text}", clock::now_ms());
            }
        }
        // A crash dump runs to hundreds of packets; keep the first few.
        if !matches!(kind, AclKind::FirmwareDump { .. }) || self.stats.fw_dump_packets <= 3 {
            self.trace.record(Dir::AclIn, &buf[..stored]);
            if self.verbose {
                dump("acl<", &buf[..stored], 24);
            }
        }
        Ok(Some(AclRead { len: got, stored, kind }))
    }

    /// Read and throw away whatever the controller has queued on the event
    /// and ACL pipes, until it has been quiet for `quiet_ms` (at most
    /// `limit_ms`). A previous owner can leave both behind, for example a
    /// live connection's data.
    pub fn drain(&mut self, quiet_ms: u64, limit_ms: u64) -> Result<DrainReport, HciError> {
        let mut buf = [0u8; ACL_BUF];
        let start = clock::now_ms();
        let mut last = start;
        let mut report = DrainReport::default();
        loop {
            let now = clock::now_ms();
            if now - last >= quiet_ms || now - start >= limit_ms {
                break;
            }
            match self.read_event(&mut buf, 1) {
                Ok(_) => {
                    report.events += 1;
                    last = clock::now_ms();
                }
                Err(HciError::Usb(e)) if e.status == Status::TIMEOUT => {}
                Err(e) => return Err(e),
            }
            if let Some(acl) = self.read_acl(&mut buf, 1)? {
                report.acl += 1;
                if let AclKind::Data { handle } = acl.kind {
                    report.acl_handle = Some(handle);
                }
                self.stats.acl_discarded += 1;
                last = clock::now_ms();
            }
        }
        report.ms = clock::now_ms() - start;
        if self.firmware_crashed() {
            return Err(HciError::FirmwareCrashed);
        }
        Ok(report)
    }

    /// Read one complete HCI event from the interrupt endpoint, one
    /// max-size packet at a time, reassembled from the header length.
    /// `Err(TIMEOUT)` if nothing started within `timeout_ms`.
    pub fn read_event(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize, HciError> {
        let need = if self.ring.is_some() { self.pop_event(buf, timeout_ms)? } else { self.read_event_sync(buf, timeout_ms)? };

        let event = &buf[..need];
        self.stats.events += 1;
        self.stats.last_event_ms = Some(clock::now_ms());
        if is_adv_report(event) {
            self.stats.adv_reports += 1;
        } else {
            self.trace.record(Dir::Event, event);
            if self.verbose {
                dump("hci<", event, 32);
            }
        }
        Ok(need)
    }

    /// Wait up to `timeout_ms` for a complete event in the ring.
    fn pop_event(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize, HciError> {
        let start = clock::now_us();
        let ring = self.ring.as_ref().expect("event pipe running");
        loop {
            if ring.broken() || ring.errors() >= 10 {
                return Err(HciError::EventPipe);
            }
            match ring.pop_event(buf) {
                Ok(Some(len)) => return Ok(len),
                Ok(None) => {}
                Err(_) => return Err(HciError::PartialEvent),
            }
            if clock::now_us() - start >= u64::from(timeout_ms) * 1000 {
                return Err(HciError::Usb(UsbError { status: Status::TIMEOUT, usb_status: 0 }));
            }
            boot::stall(Duration::from_micros(50));
        }
    }

    /// Synchronous fallback: one max-size packet at a time, reassembled from
    /// the header length.
    fn read_event_sync(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize, HciError> {
        let packet = usize::from(if self.info.int_in_max_packet != 0 { self.info.int_in_max_packet } else { 16 });
        let mut got = 0;
        let mut need = 2;
        while got < need {
            if got + packet > buf.len() {
                return Err(HciError::PartialEvent);
            }
            // A USB timeout of 0 means "wait forever": never pass it on.
            let wait = if got == 0 { timeout_ms.max(1) } else { 1000 };
            let int_in = self.info.int_in;
            match self.usb().map_err(HciError::Usb)?.sync_interrupt_receive(int_in, &mut buf[got..got + packet], wait as usize) {
                Ok(n) => got += n,
                Err(e) if e.status() == Status::TIMEOUT && got == 0 => {
                    return Err(HciError::Usb(UsbError::from(e)));
                }
                Err(e) if e.status() == Status::TIMEOUT => return Err(HciError::PartialEvent),
                Err(e) => return Err(HciError::Usb(UsbError::from(e))),
            }
            if got >= 2 {
                need = 2 + usize::from(buf[1]);
            }
        }
        Ok(need)
    }

    /// Send an HCI command and wait for its Command Complete. Copies the
    /// return parameters (first byte: HCI status) into `ret` and returns
    /// their length.
    pub fn command(&mut self, opcode: u16, params: &[u8], ret: &mut [u8], timeout_ms: u32) -> Result<usize, HciError> {
        let mut packet = [0u8; 3 + 255];
        packet[..2].copy_from_slice(&opcode.to_le_bytes());
        packet[2] = params.len() as u8;
        packet[3..3 + params.len()].copy_from_slice(params);
        self.send_command(&packet[..3 + params.len()])?;

        let mut buf = [0u8; ACL_BUF];
        let start = clock::now_ms();
        while clock::now_ms() - start < u64::from(timeout_ms) {
            match self.read_event(&mut buf, 10) {
                Ok(len) => {
                    let event = &buf[..len];
                    match event[0] {
                        HCI_EVENT_COMMAND_COMPLETE if event.len() >= 5 && u16::from_le_bytes([event[3], event[4]]) == opcode => {
                            let n = (event.len() - 5).min(ret.len());
                            ret[..n].copy_from_slice(&event[5..5 + n]);
                            return Ok(n);
                        }
                        HCI_EVENT_COMMAND_STATUS
                            if event.len() >= 6 && u16::from_le_bytes([event[4], event[5]]) == opcode && event[2] != 0 =>
                        {
                            return Err(HciError::Rejected(event[2]));
                        }
                        _ if !self.verbose && !is_adv_report(event) => dump("skipped event:", event, 16),
                        _ => {}
                    }
                    continue;
                }
                Err(HciError::Usb(e)) if e.status == Status::TIMEOUT => {}
                Err(e) => return Err(e),
            }
            // Keep the ACL pipe moving while waiting: a controller is
            // suspected of holding back its events while ACL data waits to
            // be read (the Nov 1 MT7922 wedge).
            if self.read_acl(&mut buf, 1)?.is_some() {
                self.stats.acl_discarded += 1;
            }
            if self.firmware_crashed() {
                return Err(HciError::FirmwareCrashed);
            }
        }
        Err(HciError::Timeout)
    }

    /// HCI_Disconnect for `handle` with `reason`, waiting up to
    /// `timeout_ms` for the outcome. ACL data keeps being read meanwhile.
    pub fn disconnect(&mut self, handle: u16, reason: u8, timeout_ms: u32) -> Result<DisconnectOutcome, HciError> {
        use crate::link::{disconnect_step, DisconnectStep};
        let [lo, hi] = handle.to_le_bytes();
        self.send_command(&[0x06, 0x04, 0x03, lo, hi, reason])?;
        let mut accepted = false;
        let mut buf = [0u8; ACL_BUF];
        let start = clock::now_ms();
        while clock::now_ms() - start < u64::from(timeout_ms) {
            match self.read_event(&mut buf, 10) {
                Ok(len) => match disconnect_step(&buf[..len], handle) {
                    Some(DisconnectStep::Accepted) => accepted = true,
                    Some(DisconnectStep::NoConnection) => return Ok(DisconnectOutcome::NoConnection),
                    Some(DisconnectStep::Refused(status)) => return Ok(DisconnectOutcome::Failed(status)),
                    Some(DisconnectStep::Complete { status: 0, reason }) => return Ok(DisconnectOutcome::Closed { reason }),
                    Some(DisconnectStep::Complete { status, .. }) => return Ok(DisconnectOutcome::Failed(status)),
                    None => {}
                },
                Err(HciError::Usb(e)) if e.status == Status::TIMEOUT => {}
                Err(e) => return Err(e),
            }
            if self.read_acl(&mut buf, 1)?.is_some() {
                self.stats.acl_discarded += 1;
            }
            if self.firmware_crashed() {
                return Err(HciError::FirmwareCrashed);
            }
        }
        if accepted { Ok(DisconnectOutcome::NoCompletion) } else { Err(HciError::Timeout) }
    }
}

impl mtk_bt::Transport for UsbHci {
    type Error = UsbError;

    fn control_in(&mut self, rt: u8, req: u8, value: u16, index: u16, data: &mut [u8], timeout_ms: u32) -> Result<bool, UsbError> {
        self.control_in_raw(rt, req, value, index, data, timeout_ms)
    }

    fn control_out(&mut self, rt: u8, req: u8, value: u16, index: u16, data: &[u8], timeout_ms: u32) -> Result<(), UsbError> {
        self.control_out_raw(rt, req, value, index, data, timeout_ms)
    }

    fn stall_us(&mut self, us: u32) {
        boot::stall(Duration::from_micros(u64::from(us)));
    }

    fn trace(&mut self, tag: &str, data: &[u8]) {
        let dir = match tag {
            "wmt>" => Dir::WmtOut,
            "wmt<" => Dir::WmtIn,
            _ => Dir::Reg,
        };
        self.trace.record(dir, data);
        if self.verbose {
            dump(tag, data, 24);
        }
    }

    fn progress(&mut self, section: usize, sent: u32, total: u32) {
        let step = total / 10;
        if sent == total || (step != 0 && sent % step < 250) {
            crate::say!("  section {section}: {sent} / {total} bytes");
        }
    }
}
