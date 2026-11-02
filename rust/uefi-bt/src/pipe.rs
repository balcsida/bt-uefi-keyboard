//! Reading the HCI event endpoint with an asynchronous interrupt transfer,
//! as UsbKbDxe does for keyboards.
//!
//! The USB stack keeps one transfer queued on the endpoint and calls
//! [`event_callback`] for every packet, from a timer at TPL_NOTIFY that can
//! interrupt the main loop at any point. The callback copies the bytes into
//! a ring; the main loop takes complete events out of it.
//!
//! This replaces short synchronous reads that time out and get cancelled
//! thousands of times a second. QEMU's USB passthrough drops a packet that
//! arrives while its transfer is being cancelled, and losing the first piece
//! of a multi-packet event desynchronizes the event stream (the suspected
//! cause of the Nov 1 "malformed Disconnection Complete" panic).
//!
//! The transfer must be cancelled before the image goes away, or the USB
//! stack calls into freed memory: `UsbHci` does it on drop, and
//! [`stop_event_pipes`] does it from the panic handler.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU8, AtomicUsize, Ordering};

use uefi::proto::usb::UsbTransferStatus;
use uefi::Status;
use uefi_raw::protocol::usb::io::UsbIoProtocol;
use uefi_raw::Boolean;

/// Far more than the controller sends between two polls of the main loop.
pub const EVENT_RING: usize = 16 * 1024;

/// Bytes from the event endpoint. One producer (the callback), one consumer
/// (the main loop), so atomics are enough.
pub struct EventRing {
    data: [AtomicU8; EVENT_RING],
    /// Bytes ever written and read; the difference is what is buffered.
    head: AtomicUsize,
    tail: AtomicUsize,
    packets: AtomicU32,
    overflows: AtomicU32,
    errors: AtomicU32,
    last_error: AtomicU32,
    max_buffered: AtomicUsize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PipeStats {
    pub packets: u32,
    pub buffered: usize,
    pub max_buffered: usize,
    pub overflows: u32,
    pub errors: u32,
    pub last_error: u32,
}

impl EventRing {
    pub fn new() -> Box<Self> {
        Box::new(Self {
            data: [const { AtomicU8::new(0) }; EVENT_RING],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            packets: AtomicU32::new(0),
            overflows: AtomicU32::new(0),
            errors: AtomicU32::new(0),
            last_error: AtomicU32::new(0),
            max_buffered: AtomicUsize::new(0),
        })
    }

    pub fn stats(&self) -> PipeStats {
        PipeStats {
            packets: self.packets.load(Ordering::Relaxed),
            buffered: self.head.load(Ordering::Acquire) - self.tail.load(Ordering::Acquire),
            max_buffered: self.max_buffered.load(Ordering::Relaxed),
            overflows: self.overflows.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_error: self.last_error.load(Ordering::Relaxed),
        }
    }

    /// True once bytes were lost: the stream can't be trusted any more.
    pub fn broken(&self) -> bool {
        self.overflows.load(Ordering::Relaxed) > 0
    }

    pub fn errors(&self) -> u32 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Take one complete event (`[code][length][parameters]`) into `buf`.
    /// `Ok(None)` if no complete event is buffered yet; `Err(len)` if the
    /// next event doesn't fit `buf`.
    pub fn pop_event(&self, buf: &mut [u8]) -> Result<Option<usize>, usize> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        let available = head - tail;
        if available < 2 {
            return Ok(None);
        }
        let len = 2 + usize::from(self.data[(tail + 1) % EVENT_RING].load(Ordering::Relaxed));
        if available < len {
            return Ok(None);
        }
        if len > buf.len() {
            return Err(len);
        }
        for (i, b) in buf[..len].iter_mut().enumerate() {
            *b = self.data[(tail + i) % EVENT_RING].load(Ordering::Relaxed);
        }
        self.tail.store(tail + len, Ordering::Release);
        Ok(Some(len))
    }

    fn push(&self, bytes: &[u8]) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let buffered = head - tail;
        if buffered + bytes.len() > EVENT_RING {
            self.overflows.fetch_add(1, Ordering::Relaxed);
            return;
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.data[(head + i) % EVENT_RING].store(b, Ordering::Relaxed);
        }
        self.head.store(head + bytes.len(), Ordering::Release);
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.max_buffered.fetch_max(buffered + bytes.len(), Ordering::Relaxed);
    }
}

/// Called by the USB stack for every completed transfer on the event
/// endpoint, at TPL_NOTIFY.
unsafe extern "efiapi" fn event_callback(
    data: *const c_void,
    data_length: usize,
    context: *const c_void,
    status: UsbTransferStatus,
) -> Status {
    // SAFETY: `context` is the ring the transfer was started with; it is
    // freed only after the transfer has been cancelled.
    let ring = unsafe { &*context.cast::<EventRing>() };
    if !status.is_empty() {
        ring.errors.fetch_add(1, Ordering::Relaxed);
        ring.last_error.store(status.bits(), Ordering::Relaxed);
        return Status::SUCCESS;
    }
    if !data.is_null() && data_length != 0 {
        // SAFETY: the USB stack passes `data_length` readable bytes.
        ring.push(unsafe { core::slice::from_raw_parts(data.cast::<u8>(), data_length) });
    }
    Status::SUCCESS
}

/// The running transfer, so the panic handler can still cancel it.
static ACTIVE_PROTOCOL: AtomicPtr<UsbIoProtocol> = AtomicPtr::new(core::ptr::null_mut());
static ACTIVE_ENDPOINT: AtomicU8 = AtomicU8::new(0);

/// Queue the asynchronous transfer on `endpoint`, delivering into `ring`.
///
/// # Safety
/// `protocol` must be a valid, open USB I/O protocol, and `ring` must stay
/// allocated until [`cancel`] (or [`stop_event_pipes`]) has run.
pub unsafe fn start(protocol: *mut UsbIoProtocol, endpoint: u8, packet_size: usize, ring: &EventRing) -> Status {
    // SAFETY: per the function contract.
    let status = unsafe {
        ((*protocol).async_interrupt_transfer)(
            protocol,
            endpoint,
            Boolean::TRUE,
            1,
            packet_size,
            Some(event_callback),
            (ring as *const EventRing).cast(),
        )
    };
    if !status.is_error() {
        ACTIVE_ENDPOINT.store(endpoint, Ordering::Relaxed);
        ACTIVE_PROTOCOL.store(protocol, Ordering::Release);
    }
    status
}

/// Cancel the asynchronous transfer on `endpoint`.
///
/// # Safety
/// `protocol` must be the open USB I/O protocol the transfer was started on.
pub unsafe fn cancel(protocol: *mut UsbIoProtocol, endpoint: u8) {
    if ACTIVE_PROTOCOL.load(Ordering::Acquire) == protocol {
        ACTIVE_PROTOCOL.store(core::ptr::null_mut(), Ordering::Release);
    }
    // SAFETY: per the function contract. Nothing useful to do if it fails.
    let _ = unsafe {
        ((*protocol).async_interrupt_transfer)(protocol, endpoint, Boolean::FALSE, 0, 0, None, core::ptr::null())
    };
}

/// Cancel whatever event transfer is still running. For the panic handler.
pub fn stop_event_pipes() {
    let protocol = ACTIVE_PROTOCOL.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !protocol.is_null() {
        let endpoint = ACTIVE_ENDPOINT.load(Ordering::Relaxed);
        // SAFETY: the protocol the running transfer was started on; the
        // interface stays open while the app runs.
        let _ = unsafe {
            ((*protocol).async_interrupt_transfer)(protocol, endpoint, Boolean::FALSE, 0, 0, None, core::ptr::null())
        };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// An HCI event `[code][len][params...]` with recognizable contents.
    fn event(code: u8, len: u8, seed: u8) -> Vec<u8> {
        let mut e = std::vec![code, len];
        e.extend((0..len).map(|i| seed.wrapping_add(i)));
        e
    }

    /// Feed a byte stream to the ring in 16-byte USB packets.
    fn push_in_packets(ring: &EventRing, stream: &[u8]) {
        for packet in stream.chunks(16) {
            ring.push(packet);
        }
    }

    #[test]
    fn events_split_across_packets_come_out_whole() {
        let ring = EventRing::new();
        let events = [event(0x0E, 4, 1), event(0x3E, 40, 7), event(0x05, 4, 3), event(0x3E, 14, 9)];
        let stream: Vec<u8> = events.iter().flatten().copied().collect();
        push_in_packets(&ring, &stream);

        let mut buf = [0u8; 300];
        for expected in &events {
            let len = ring.pop_event(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..len], &expected[..]);
        }
        assert_eq!(ring.pop_event(&mut buf), Ok(None));
        assert_eq!(ring.stats().buffered, 0);
    }

    #[test]
    fn an_incomplete_event_waits_for_its_last_packet() {
        let ring = EventRing::new();
        let e = event(0x3E, 40, 5);
        ring.push(&e[..16]);
        ring.push(&e[16..32]);
        let mut buf = [0u8; 300];
        assert_eq!(ring.pop_event(&mut buf), Ok(None));
        ring.push(&e[32..]);
        let len = ring.pop_event(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..len], &e[..]);
    }

    #[test]
    fn the_ring_wraps_around_many_times() {
        let ring = EventRing::new();
        let mut buf = [0u8; 300];
        // ~3.5 MB through a 16 KB ring, with sizes that don't divide it evenly.
        for round in 0..20_000u32 {
            let e = event(0x3E, (round % 250) as u8 + 3, round as u8);
            push_in_packets(&ring, &e);
            let len = ring.pop_event(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..len], &e[..], "round {round}");
        }
        assert!(!ring.broken());
    }

    #[test]
    fn overflow_is_detected_not_hidden() {
        let ring = EventRing::new();
        let packet = [0x3Eu8; 16];
        for _ in 0..(EVENT_RING / 16) {
            ring.push(&packet);
        }
        assert!(!ring.broken());
        ring.push(&packet);
        assert!(ring.broken());
        assert_eq!(ring.stats().overflows, 1);
        assert_eq!(ring.stats().max_buffered, EVENT_RING);
    }

    #[test]
    fn an_event_larger_than_the_buffer_is_reported() {
        let ring = EventRing::new();
        push_in_packets(&ring, &event(0x3E, 200, 0));
        let mut small = [0u8; 64];
        assert_eq!(ring.pop_event(&mut small), Err(202));
    }
}
