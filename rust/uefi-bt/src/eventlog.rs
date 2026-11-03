//! The TCG event log in the crypto-agile format: what EFI_TCG2_PROTOCOL's
//! GetEventLog (format TCG_2) returns, and what Linux shows as
//! `/sys/kernel/security/tpm0/binary_bios_measurements`. Little-endian
//! throughout (unlike TPM commands).
//!
//! The log starts with a header event in the old SHA-1 format, whose data
//! is the "Spec ID Event03" structure listing the digest sizes; every
//! event after it is a TCG_PCR_EVENT2:
//!
//! ```text
//! u32 PCR index, u32 event type,
//! u32 digest count, then per digest: u16 algorithm, digest bytes,
//! u32 event size, event data
//! ```
//!
//! [`Log::replay`] recomputes a PCR from the log's SHA-256 digests, so the
//! driver can check the log against the TPM, and the OS side can predict
//! the value a PCR had at a given point of the boot.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

pub const EV_NO_ACTION: u32 = 0x0000_0003;
pub const EV_SEPARATOR: u32 = 0x0000_0004;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x8000_0004;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;
pub const ALG_SHA256: u16 = 0x000B;

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";
const STARTUP_LOCALITY: &[u8; 16] = b"StartupLocality\0";

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The digest algorithms the log uses, with their sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecId {
    pub digest_sizes: Vec<(u16, u16)>,
}

impl SpecId {
    fn size_of(&self, alg: u16) -> Option<usize> {
        self.digest_sizes.iter().find(|(a, _)| *a == alg).map(|(_, s)| usize::from(*s))
    }
}

/// Parse the header event. Returns the digest sizes and the header's
/// length in bytes.
pub fn parse_header(log: &[u8]) -> Option<(SpecId, usize)> {
    // u32 PCR, u32 type, 20-byte SHA-1 digest, u32 event size, event.
    let size = usize::try_from(u32_at(log, 28)?).ok()?;
    let event = log.get(32..32usize.checked_add(size)?)?;
    if u32_at(log, 4)? != EV_NO_ACTION || event.get(..16)? != SPEC_ID_SIGNATURE {
        return None;
    }
    // Signature, platform class, version (4 bytes), algorithm count.
    let count = usize::try_from(u32_at(event, 24)?).ok()?;
    if count == 0 || count > 16 {
        return None;
    }
    let mut digest_sizes = Vec::with_capacity(count);
    for i in 0..count {
        digest_sizes.push((u16_at(event, 28 + 4 * i)?, u16_at(event, 30 + 4 * i)?));
    }
    Some((SpecId { digest_sizes }, 32 + size))
}

/// How long the TCG_PCR_EVENT2 at the start of `bytes` is: `Ok(length)`,
/// or `Err(n)` when at least `n` bytes are needed to tell. Lets firmware
/// code, which only knows where the last event starts, find the log's end
/// without reading past it.
pub fn event_len(bytes: &[u8], spec: &SpecId) -> Result<usize, usize> {
    let count = u32_at(bytes, 8).ok_or(12usize)?;
    if count > 16 {
        return Ok(0); // not an event; the caller treats 0 as malformed
    }
    let mut at = 12usize;
    for _ in 0..count {
        let alg = u16_at(bytes, at).ok_or(at + 2)?;
        let Some(size) = spec.size_of(alg) else { return Ok(0) };
        at += 2 + size;
    }
    let data = u32_at(bytes, at).ok_or(at + 4)?;
    Ok(at + 4 + data as usize)
}

/// One TCG_PCR_EVENT2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<'a> {
    /// Position in the log, the header not counted (the first event is 0;
    /// `tpm2_eventlog` calls it event 1, see [`Event::number`]).
    pub index: usize,
    /// Byte offset in the log.
    pub offset: usize,
    pub pcr: u32,
    pub event_type: u32,
    pub digests: Vec<(u16, &'a [u8])>,
    pub data: &'a [u8],
}

impl Event<'_> {
    pub fn digest(&self, alg: u16) -> Option<&[u8]> {
        self.digests.iter().find(|(a, _)| *a == alg).map(|(_, d)| *d)
    }

    /// The event's number as `tpm2_eventlog` prints it (the header is 0).
    pub fn number(&self) -> usize {
        self.index + 1
    }

    /// For an image load event (EV_EFI_BOOT_SERVICES_DRIVER/APPLICATION):
    /// where the image was in memory and how long it was. Firmware logs
    /// the buffer it read the file into, not where the image runs, so this
    /// doesn't identify an image; [`Event::image_path`] does.
    pub fn image(&self) -> Option<(u64, u64)> {
        match self.event_type {
            EV_EFI_BOOT_SERVICES_DRIVER | EV_EFI_BOOT_SERVICES_APPLICATION => Some((u64_at(self.data, 0)?, u64_at(self.data, 8)?)),
            _ => None,
        }
    }

    /// For an image load event: the file path in its device path (the
    /// media file path nodes joined, e.g. `\EFI\btkb\bt-kb-dxe.efi`), as
    /// ASCII with anything else replaced by `?`.
    pub fn image_path(&self) -> Option<alloc::string::String> {
        self.image()?;
        let length = usize::try_from(u64_at(self.data, 24)?).ok()?;
        let end = self.data.len().min(32usize.checked_add(length)?);
        let mut path = alloc::string::String::new();
        let mut at = 32;
        while at + 4 <= end {
            let (kind, sub) = (self.data[at], self.data[at + 1]);
            let size = usize::from(u16_at(self.data, at + 2)?);
            if size < 4 || at + size > end {
                break;
            }
            if kind == 0x04 && sub == 0x04 {
                for unit in self.data[at + 4..at + size].chunks_exact(2) {
                    match u16::from_le_bytes([unit[0], unit[1]]) {
                        0 => break,
                        c @ 0x20..0x7F => path.push(char::from(c as u8)),
                        _ => path.push('?'),
                    }
                }
            }
            if kind == 0x7F {
                break;
            }
            at += size;
        }
        (!path.is_empty()).then_some(path)
    }
}

/// A parsed log.
#[derive(Debug, Clone)]
pub struct Log<'a> {
    pub spec: SpecId,
    pub events: Vec<Event<'a>>,
    /// The PCR 0 starting value's last byte (StartupLocality event).
    pub startup_locality: u8,
}

/// Parse a whole log. Stops at the first event that doesn't parse, as
/// firmware leaves the space after the last event uninitialized.
pub fn parse(log: &[u8]) -> Option<Log<'_>> {
    let (spec, mut at) = parse_header(log)?;
    let mut events = Vec::new();
    let mut startup_locality = 0;
    while at < log.len() {
        let rest = &log[at..];
        let Ok(len) = event_len(rest, &spec) else { break };
        if len == 0 || len > rest.len() {
            break;
        }
        let bytes = &rest[..len];
        let count = u32_at(bytes, 8)? as usize;
        let mut digests = Vec::with_capacity(count);
        let mut p = 12;
        for _ in 0..count {
            let alg = u16_at(bytes, p)?;
            let size = spec.size_of(alg)?;
            digests.push((alg, bytes.get(p + 2..p + 2 + size)?));
            p += 2 + size;
        }
        let data = bytes.get(p + 4..)?;
        let event = Event { index: events.len(), offset: at, pcr: u32_at(bytes, 0)?, event_type: u32_at(bytes, 4)?, digests, data };
        if event.event_type == EV_NO_ACTION && event.data.get(..16) == Some(STARTUP_LOCALITY) {
            startup_locality = *event.data.get(16).unwrap_or(&0);
        }
        events.push(event);
        at += len;
    }
    Some(Log { spec, events, startup_locality })
}

impl Log<'_> {
    /// PCRs 0–7 that already have an EV_SEPARATOR, as a bitmap (bit n:
    /// PCR n).
    pub fn separators(&self) -> u8 {
        self.events
            .iter()
            .filter(|e| e.event_type == EV_SEPARATOR && e.pcr < 8)
            .fold(0u8, |acc, e| acc | (1 << e.pcr))
    }

    /// The SHA-256 value of `pcr` after the events before index `until`
    /// (all events if `None`). `None` if an extended event lacks a SHA-256
    /// digest.
    pub fn replay(&self, pcr: u32, until: Option<usize>) -> Option<[u8; 32]> {
        let mut value = [0u8; 32];
        if pcr == 0 {
            value[31] = self.startup_locality;
        }
        for e in self.events.iter().take(until.unwrap_or(usize::MAX)) {
            if e.pcr != pcr || e.event_type == EV_NO_ACTION {
                continue;
            }
            let digest = e.digest(ALG_SHA256)?;
            let mut h = Sha256::new();
            h.update(value);
            h.update(digest);
            value = h.finalize().into();
        }
        Some(value)
    }

    /// The last load event of an image (a driver or an application) whose
    /// file path ends with `path`, compared without regard to case: FAT
    /// isn't case-sensitive.
    pub fn image_event(&self, path: &str) -> Option<&Event<'_>> {
        let wanted = path.to_ascii_lowercase();
        self.events
            .iter()
            .rev()
            .find(|e| e.image_path().is_some_and(|p| !wanted.is_empty() && p.to_ascii_lowercase().ends_with(&wanted)))
    }
}

/// A PCR bitmap as text: "0-2, 4, 7".
pub fn pcr_list(bits: u8) -> alloc::string::String {
    use core::fmt::Write;
    let mut out = alloc::string::String::new();
    let mut n = 0u32;
    while n < 8 {
        if bits & (1 << n) == 0 {
            n += 1;
            continue;
        }
        let start = n;
        while n + 1 < 8 && bits & (1 << (n + 1)) != 0 {
            n += 1;
        }
        let sep = if out.is_empty() { "" } else { ", " };
        let _ = if start == n { write!(out, "{sep}{start}") } else { write!(out, "{sep}{start}-{n}") };
        n += 1;
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    /// A log builder: the header lists SHA-1 and SHA-256.
    pub(crate) struct Builder {
        pub bytes: Vec<u8>,
    }

    impl Builder {
        pub fn new() -> Self {
            let mut spec = Vec::new();
            spec.extend_from_slice(SPEC_ID_SIGNATURE);
            spec.extend_from_slice(&0u32.to_le_bytes()); // platform class
            spec.extend_from_slice(&[0, 2, 0, 2]); // version 2.0, errata, uintn size
            spec.extend_from_slice(&2u32.to_le_bytes());
            spec.extend_from_slice(&[0x04, 0x00, 20, 0x00, 0x0B, 0x00, 32, 0x00]);
            spec.push(0); // vendor info size
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 20]);
            bytes.extend_from_slice(&(spec.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&spec);
            Self { bytes }
        }

        /// An event whose SHA-256 digest is the hash of `data`, as the
        /// firmware measures most events.
        pub fn event(mut self, pcr: u32, event_type: u32, data: &[u8]) -> Self {
            let sha256: [u8; 32] = Sha256::digest(data).into();
            self.bytes.extend_from_slice(&pcr.to_le_bytes());
            self.bytes.extend_from_slice(&event_type.to_le_bytes());
            self.bytes.extend_from_slice(&2u32.to_le_bytes());
            self.bytes.extend_from_slice(&[0x04, 0x00]);
            self.bytes.extend_from_slice(&[0xAB; 20]);
            self.bytes.extend_from_slice(&[0x0B, 0x00]);
            self.bytes.extend_from_slice(&sha256);
            self.bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.bytes.extend_from_slice(data);
            self
        }

        /// An image load event for an image at `base`.
        /// An image load event; `path` becomes a hardware node, then one
        /// media file path node per `\`-separated part, as firmware logs them.
        pub fn image(self, pcr: u32, event_type: u32, base: u64, len: u64, path: &str) -> Self {
            let mut dp = Vec::new();
            dp.extend_from_slice(&[0x01, 0x01, 0x06, 0x00, 0x00, 0x02]); // PCI(0x2,0x0)
            for part in path.split_inclusive('\\') {
                let text: Vec<u16> = part.encode_utf16().chain([0]).collect();
                let size = 4 + 2 * text.len() as u16;
                dp.extend_from_slice(&[0x04, 0x04]);
                dp.extend_from_slice(&size.to_le_bytes());
                text.iter().for_each(|u| dp.extend_from_slice(&u.to_le_bytes()));
            }
            dp.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]); // end of device path
            let mut data = Vec::new();
            data.extend_from_slice(&base.to_le_bytes());
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&(dp.len() as u64).to_le_bytes());
            data.extend_from_slice(&dp);
            self.event(pcr, event_type, &data)
        }
    }

    fn extend(value: [u8; 32], data: &[u8]) -> [u8; 32] {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let mut h = Sha256::new();
        h.update(value);
        h.update(digest);
        h.finalize().into()
    }

    #[test]
    fn header_and_events() {
        let b = Builder::new().event(7, EV_EFI_VARIABLE_DRIVER_CONFIG, b"SecureBoot").event(7, EV_SEPARATOR, &[0; 4]);
        let log = parse(&b.bytes).unwrap();
        assert_eq!(log.spec.digest_sizes, vec![(0x04, 20), (0x0B, 32)]);
        assert_eq!(log.events.len(), 2);
        assert_eq!(log.events[1].event_type, EV_SEPARATOR);
        assert_eq!(log.events[1].digest(ALG_SHA256).unwrap().len(), 32);
        assert_eq!(log.events[0].data, b"SecureBoot");
    }

    #[test]
    fn replay_and_separators() {
        let b = Builder::new()
            .event(7, EV_EFI_VARIABLE_DRIVER_CONFIG, b"SecureBoot")
            .event(7, EV_EFI_VARIABLE_DRIVER_CONFIG, b"PK")
            .event(7, EV_SEPARATOR, &[0; 4])
            .event(7, EV_EFI_VARIABLE_AUTHORITY, b"db cert")
            .event(2, EV_EFI_BOOT_SERVICES_DRIVER, b"driver")
            .event(4, EV_NO_ACTION, b"ignored");
        let log = parse(&b.bytes).unwrap();
        let expected = extend(extend(extend(extend([0; 32], b"SecureBoot"), b"PK"), &[0; 4]), b"db cert");
        assert_eq!(log.replay(7, None), Some(expected));
        // Up to (not including) the separator.
        assert_eq!(log.replay(7, Some(2)), Some(extend(extend([0; 32], b"SecureBoot"), b"PK")));
        assert_eq!(log.replay(4, None), Some([0; 32]), "EV_NO_ACTION isn't extended");
        assert_eq!(log.separators(), 0b1000_0000);
        assert_eq!(pcr_list(log.separators()), "7");
        assert_eq!(pcr_list(0b1111_1111), "0-7");
        assert_eq!(pcr_list(0b1011_0101), "0, 2, 4-5, 7");
        assert_eq!(pcr_list(0), "none");
    }

    #[test]
    fn startup_locality_seeds_pcr0() {
        let mut locality = Vec::from(&STARTUP_LOCALITY[..]);
        locality.push(3);
        let b = Builder::new().event(0, EV_NO_ACTION, &locality).event(0, 0x8, b"S-CRTM");
        let log = parse(&b.bytes).unwrap();
        let mut start = [0u8; 32];
        start[31] = 3;
        assert_eq!(log.replay(0, None), Some(extend(start, b"S-CRTM")));
    }

    #[test]
    fn finds_an_image_by_its_path() {
        let b = Builder::new()
            .image(2, EV_EFI_BOOT_SERVICES_DRIVER, 0x7A7E_D018, 0x7_0000, "\\EFI\\btkb\\bt-kb-dxe.efi")
            .image(4, EV_EFI_BOOT_SERVICES_APPLICATION, 0x7A5D_7018, 0x5_F000, "\\EFI\\limine\\limine_x64.efi")
            .image(2, EV_EFI_BOOT_SERVICES_DRIVER, 0x7A70_0018, 0x7_0000, "\\bt-kb-dxe.efi");
        let log = parse(&b.bytes).unwrap();
        assert_eq!(log.events[0].image_path().as_deref(), Some("\\EFI\\btkb\\bt-kb-dxe.efi"));
        assert_eq!(log.events[0].image(), Some((0x7A7E_D018, 0x7_0000)));
        // The full path, in any case; the last match wins.
        let e = log.image_event("\\efi\\BTKB\\BT-KB-DXE.EFI").unwrap();
        assert_eq!((e.index, e.number(), e.pcr), (0, 1, 2));
        assert_eq!(log.image_event("bt-kb-dxe.efi").unwrap().index, 2);
        assert_eq!(log.image_event("limine_x64.efi").unwrap().pcr, 4);
        assert!(log.image_event("\\EFI\\other\\bt-kb-dxe.efi").is_none());
        assert!(log.image_event("").is_none());
        // Not an image event: no path.
        assert_eq!(parse(&Builder::new().event(7, EV_SEPARATOR, &[0; 4]).bytes).unwrap().events[0].image_path(), None);
    }

    #[test]
    fn event_len_asks_for_what_it_needs() {
        let b = Builder::new().event(7, EV_SEPARATOR, &[0; 4]);
        let (spec, at) = parse_header(&b.bytes).unwrap();
        let event = &b.bytes[at..];
        // Count, then each digest's algorithm, then the event size.
        assert_eq!(event_len(&event[..4], &spec), Err(12));
        assert_eq!(event_len(&event[..12], &spec), Err(14));
        assert_eq!(event_len(&event[..14], &spec), Err(36));
        assert_eq!(event_len(&event[..36], &spec), Err(36 + 32 + 4));
        assert_eq!(event_len(event, &spec), Ok(event.len()));
    }

    #[test]
    fn garbage_is_rejected_or_cut_off() {
        assert!(parse(&[0u8; 10]).is_none());
        let mut b = Builder::new().event(7, EV_SEPARATOR, &[0; 4]);
        // Uninitialized space after the last event: an absurd digest count.
        b.bytes.extend_from_slice(&[0xFF; 64]);
        let log = parse(&b.bytes).unwrap();
        assert_eq!(log.events.len(), 1);
        // An unknown algorithm stops parsing too.
        let mut c = Builder::new().bytes;
        c.extend_from_slice(&[7, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0x12, 0x00]);
        assert_eq!(parse(&c).unwrap().events.len(), 0);
    }
}
