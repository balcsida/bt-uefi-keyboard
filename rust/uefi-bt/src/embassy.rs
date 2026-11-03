//! Running async Bluetooth code (TrouBLE) in single-threaded UEFI:
//! an embassy-time driver on the TSC clock, a no-op critical section, and a
//! `bt-hci` transport on top of [`UsbHci`].
//!
//! Futures are driven by a busy-polling executor (`embassy_futures::block_on`),
//! so wakers are never needed for progress: the transport's `read` tries the
//! USB endpoints once per poll and yields when nothing has arrived.

use core::cell::RefCell;
use core::task::Waker;

use bt_hci::event::Event;
use bt_hci::transport::{PacketKind, PacketToController, PacketToHost, Transport};
use bt_hci::FromHciBytes;
use bt_hci_transport::ReadHciError;
use mtk_bt::AclKind;
use uefi::Status;

use crate::tap::LinkGuard;
use crate::{HciError, UsbError, UsbHci, ACL_BUF};

struct UefiTimeDriver;

impl embassy_time_driver::Driver for UefiTimeDriver {
    fn now(&self) -> u64 {
        crate::clock::now_us()
    }

    fn schedule_wake(&self, _at: u64, waker: &Waker) {
        // The executor polls continuously; just make sure nothing waits on us.
        waker.wake_by_ref();
    }
}

embassy_time_driver::time_driver_impl!(static TIME_DRIVER: UefiTimeDriver = UefiTimeDriver);

/// One thread and no callbacks into this code, so there is nothing to exclude.
struct NoInterrupts;

critical_section::set_impl!(NoInterrupts);

// SAFETY: single-threaded, and no UEFI event callbacks touch embassy state.
unsafe impl critical_section::Impl for NoInterrupts {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_state: critical_section::RawRestoreState) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Usb(UsbError),
    Hci(HciError),
    Parse,
    Unsupported,
    /// A MediaTek crash dump arrived: the controller firmware is gone.
    FirmwareCrashed,
    /// The link guard refused to send the command (see `tap::LinkGuard`).
    Refused,
}

/// What to do with connection data from the ACL pipe. The pipe is read in
/// both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    /// Throw it away (no connections, e.g. while only scanning).
    Discard,
    /// Hand it to the host stack.
    Deliver,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for TransportError {}

impl embedded_io::Error for TransportError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl<E: embedded_io::Error> From<ReadHciError<E>> for TransportError {
    fn from(_: ReadHciError<E>) -> Self {
        Self::Parse
    }
}

/// `bt-hci` transport over an open [`UsbHci`]. Borrowed, so the caller gets
/// the interface back for the hand-off once the Bluetooth stack is gone.
pub struct UsbHciTransport<'a> {
    hci: &'a RefCell<UsbHci>,
    pub acl: AclMode,
    /// How long one poll waits for an event.
    pub event_poll_ms: u32,
    /// How long one poll waits for ACL data. Every timed-out bulk read gets
    /// cancelled, and QEMU can lose data arriving during a cancel, so with
    /// connections use fewer, longer reads; events keep arriving in the
    /// event pipe's ring meanwhile.
    pub acl_poll_ms: u32,
}

impl<'a> UsbHciTransport<'a> {
    pub fn new(hci: &'a RefCell<UsbHci>, acl: AclMode) -> Self {
        match acl {
            AclMode::Discard => Self { hci, acl, event_poll_ms: 1, acl_poll_ms: 1 },
            AclMode::Deliver => Self { hci, acl, event_poll_ms: 0, acl_poll_ms: 20 },
        }
    }

    /// One attempt to read an event, then one to read the ACL pipe. The ACL
    /// pipe is always read, also with nothing connected: a controller is
    /// suspected of holding back events while ACL data waits (Nov 1 wedge).
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<(PacketKind, usize)>, TransportError> {
        let mut hci = self.hci.borrow_mut();
        if hci.firmware_crashed() {
            return Err(TransportError::FirmwareCrashed);
        }
        match hci.read_event(buf, self.event_poll_ms) {
            Ok(len) => {
                // TrouBLE `unwrap!`s typed events, so one malformed event
                // (a controller bug, or bytes lost on the way) would panic
                // it. Check with the same parsers and drop what fails.
                if let Err(e) = Event::from_hci_bytes_complete(&buf[..len]) {
                    hci.note_malformed_event(&buf[..len], &e);
                    return Ok(None);
                }
                return Ok(Some((PacketKind::Event, len)));
            }
            Err(HciError::Usb(e)) if e.status == Status::TIMEOUT => {}
            Err(e) => return Err(TransportError::Hci(e)),
        }
        let Some(acl) = hci.read_acl(buf, self.acl_poll_ms).map_err(TransportError::Usb)? else {
            return Ok(None);
        };
        match acl.kind {
            AclKind::FirmwareDump { .. } => Err(TransportError::FirmwareCrashed),
            AclKind::Data { .. } if self.acl == AclMode::Deliver && acl.stored == acl.len => {
                Ok(Some((PacketKind::AclData, acl.len)))
            }
            _ => {
                hci.stats.acl_discarded += 1;
                Ok(None)
            }
        }
    }
}

impl embedded_io::ErrorType for UsbHciTransport<'_> {
    type Error = TransportError;
}

impl Transport for UsbHciTransport<'_> {
    async fn read<'b, P: PacketToHost<'b>>(&self, rx: &'b mut [u8]) -> Result<P, Self::Error> {
        let mut buf = [0u8; ACL_BUF];
        loop {
            if let Some((kind, len)) = self.try_read(&mut buf)? {
                let mut reader = &buf[..len];
                return P::read_hci(kind, &mut reader, rx).map_err(TransportError::from);
            }
            embassy_futures::yield_now().await;
        }
    }

    async fn write<P: PacketToController>(&self, tx: &P) -> Result<(), Self::Error> {
        let mut buf = [0u8; 4 + 1024];
        let size = tx.size();
        if size > buf.len() {
            return Err(TransportError::Unsupported);
        }
        tx.write_hci(&mut buf[..size]).map_err(|_| TransportError::Parse)?;
        let mut hci = self.hci.borrow_mut();
        match P::KIND {
            PacketKind::Cmd => hci.send_command(&buf[..size]).map_err(TransportError::Usb),
            PacketKind::AclData => hci.send_acl(&buf[..size]).map_err(TransportError::Usb),
            _ => Err(TransportError::Unsupported),
        }
    }
}

/// Packets the driver's timer tick has read from the controller, waiting
/// for the host stack. Filled outside of the stack's futures, so reading
/// never blocks: an empty inbox just means "nothing yet, come back next
/// tick".
#[derive(Default)]
pub struct Inbox {
    queue: RefCell<alloc::collections::VecDeque<(PacketKind, alloc::vec::Vec<u8>)>>,
    /// Packets written by the stack, so the tick can tell whether polling
    /// made progress.
    writes: core::cell::Cell<u32>,
    dropped: core::cell::Cell<u32>,
}

impl Inbox {
    /// More than the controller sends in one tick; beyond it the oldest
    /// packet is dropped (and counted).
    pub const CAPACITY: usize = 256;

    pub fn push_event(&self, event: &[u8]) {
        self.push(PacketKind::Event, event);
    }

    pub fn push_acl(&self, packet: &[u8]) {
        self.push(PacketKind::AclData, packet);
    }

    fn push(&self, kind: PacketKind, bytes: &[u8]) {
        let mut queue = self.queue.borrow_mut();
        if queue.len() >= Self::CAPACITY {
            queue.pop_front();
            self.dropped.set(self.dropped.get() + 1);
        }
        queue.push_back((kind, bytes.to_vec()));
    }

    fn pop(&self) -> Option<(PacketKind, alloc::vec::Vec<u8>)> {
        self.queue.borrow_mut().pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.borrow().is_empty()
    }

    pub fn writes(&self) -> u32 {
        self.writes.get()
    }

    pub fn dropped(&self) -> u32 {
        self.dropped.get()
    }
}

/// `bt-hci` transport for the driver: reads come from an [`Inbox`] that the
/// timer tick fills, writes go straight to the controller, through the
/// [`LinkGuard`] if there is one: it refuses encryption with any key but
/// the bonded one, and drops pairing (SMP) packets.
pub struct InboxTransport<'a> {
    hci: &'a RefCell<UsbHci>,
    inbox: &'a Inbox,
    guard: Option<&'a LinkGuard>,
}

impl<'a> InboxTransport<'a> {
    pub fn new(hci: &'a RefCell<UsbHci>, inbox: &'a Inbox) -> Self {
        Self { hci, inbox, guard: None }
    }

    pub fn with_guard(self, guard: &'a LinkGuard) -> Self {
        Self { guard: Some(guard), ..self }
    }
}

impl embedded_io::ErrorType for InboxTransport<'_> {
    type Error = TransportError;
}

impl Transport for InboxTransport<'_> {
    async fn read<'b, P: PacketToHost<'b>>(&self, rx: &'b mut [u8]) -> Result<P, Self::Error> {
        loop {
            if let Some((kind, bytes)) = self.inbox.pop() {
                let mut reader = &bytes[..];
                return P::read_hci(kind, &mut reader, rx).map_err(TransportError::from);
            }
            embassy_futures::yield_now().await;
        }
    }

    async fn write<P: PacketToController>(&self, tx: &P) -> Result<(), Self::Error> {
        let mut buf = [0u8; 4 + 1024];
        let size = tx.size();
        if size > buf.len() {
            return Err(TransportError::Unsupported);
        }
        tx.write_hci(&mut buf[..size]).map_err(|_| TransportError::Parse)?;
        let packet = &buf[..size];
        if let Some(guard) = self.guard {
            match P::KIND {
                // Refused: the host stack gets an error and stops, so the
                // driver fails closed.
                PacketKind::Cmd if !guard.allow_command(packet) => return Err(TransportError::Refused),
                // Dropped silently: a pairing that never gets an answer
                // times out.
                PacketKind::AclData if !guard.allow_acl(packet) => return Ok(()),
                _ => {}
            }
        }
        let mut hci = self.hci.try_borrow_mut().map_err(|_| TransportError::Unsupported)?;
        self.inbox.writes.set(self.inbox.writes.get().wrapping_add(1));
        match P::KIND {
            PacketKind::Cmd => hci.send_command(&buf[..size]).map_err(TransportError::Usb),
            PacketKind::AclData => hci.send_acl(&buf[..size]).map_err(TransportError::Usb),
            _ => Err(TransportError::Unsupported),
        }
    }
}
