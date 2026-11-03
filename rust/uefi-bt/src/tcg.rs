//! EFI_TCG2_PROTOCOL glue: whether there is a TPM 2.0, commands through
//! SubmitCommand ([`crate::tpm2`]), logged PCR extends, and the raw event
//! log ([`crate::eventlog`]).

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::rng::Rng as EfiRng;
use uefi::proto::tcg::v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg};
use uefi::proto::tcg::{EventType, PcrIndex};
use uefi_raw::protocol::tcg::v2::{Tcg2EventLogBitmap, Tcg2Protocol};
use uefi_raw::Boolean;

use crate::eventlog;
use crate::rng::Rng;
use crate::tpm2;

impl tpm2::Tpm for Tcg {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, tpm2::Error> {
        self.submit_command(command, response).map_err(|_| tpm2::Error::Transport)?;
        let size = response.get(2..6).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize).ok_or(tpm2::Error::Malformed)?;
        Ok(size.min(response.len()))
    }
}

/// Extend `pcr` (every active bank) with the SHA-256 of `action` and log
/// it as an EV_EFI_ACTION event, so a replay of the event log accounts
/// for it.
pub fn log_action(tcg: &mut Tcg, pcr: u32, action: &[u8]) -> uefi::Result {
    let mut buf = [0u8; 160];
    let event = PcrEventInputs::new_in_buffer(&mut buf, PcrIndex(pcr), EventType::EFI_ACTION, action)
        .map_err(|e| uefi::Error::from(e.status()))?;
    tcg.hash_log_extend_event(HashLogExtendEventFlags::empty(), action, event)
}

/// Random bytes for a TPM session: seeded from the CPU, the firmware's
/// EFI_RNG_PROTOCOL if there is one, and the TPM's own GetRandom.
pub fn session_rng(tcg: &mut Tcg) -> Rng {
    let mut firmware = [0u8; 32];
    let have_firmware = boot::get_handle_for_protocol::<EfiRng>()
        .ok()
        .and_then(|h| boot::open_protocol_exclusive::<EfiRng>(h).ok())
        .is_some_and(|mut rng| rng.get_rng(None, &mut firmware).is_ok());
    let tpm = tpm2::call(tcg, &tpm2::get_random(32)).ok().and_then(|r| tpm2::parse_get_random(&r).ok()).unwrap_or_default();
    let rng = Rng::new(&[if have_firmware { &firmware } else { &[] }, &tpm]);
    firmware.fill(0);
    rng
}

/// The TCG2 protocol, if the firmware has one and reports a TPM present.
pub fn open() -> Option<ScopedProtocol<Tcg>> {
    let handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    // SAFETY: GET_PROTOCOL, as every TCG2 consumer opens it; the protocol
    // outlives the short use here.
    let mut tcg = unsafe {
        boot::open_protocol::<Tcg>(
            OpenProtocolParams { handle, agent: boot::image_handle(), controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    tcg.get_capability().ok()?.tpm_present().then_some(tcg)
}

/// A SHA-256 PCR value.
pub fn read_pcr(tcg: &mut Tcg, pcr: u32) -> Result<[u8; 32], tpm2::Error> {
    let mut response = [0u8; 256];
    tcg.submit_command(&tpm2::pcr_read(tpm2::TPM_ALG_SHA256, 1 << pcr), &mut response).map_err(|_| tpm2::Error::Malformed)?;
    let values = tpm2::parse_pcr_read(&response)?;
    match values.as_slice() {
        [(p, value)] if *p == pcr => value.as_slice().try_into().map_err(|_| tpm2::Error::Malformed),
        _ => Err(tpm2::Error::Malformed),
    }
}

/// The event log as the firmware keeps it (crypto-agile format). The
/// firmware reports where it starts and where its last event starts; its
/// end comes from that event's header, read a field at a time so nothing
/// past the log is touched.
pub fn event_log(tcg: &mut Tcg) -> Result<&'static [u8], &'static str> {
    let raw: *mut Tcg2Protocol = (tcg as *mut Tcg).cast();
    let (mut location, mut last, mut truncated) = (0u64, 0u64, Boolean(0));
    // SAFETY: a valid protocol instance and valid out pointers.
    let status = unsafe { ((*raw).get_event_log)(raw, Tcg2EventLogBitmap::TCG_2, &mut location, &mut last, &mut truncated) };
    if status.is_error() {
        return Err("GetEventLog failed");
    }
    if location == 0 {
        return Err("the firmware has no event log");
    }
    if truncated.0 != 0 {
        return Err("the event log is truncated");
    }
    let base = location as usize as *const u8;
    // SAFETY: the header's fixed part (32 bytes) starts the log.
    let fixed = unsafe { core::slice::from_raw_parts(base, 32) };
    let header_len = 32 + u32::from_le_bytes([fixed[28], fixed[29], fixed[30], fixed[31]]) as usize;
    if header_len > 64 * 1024 {
        return Err("the event log header is implausible");
    }
    // SAFETY: the whole header event, by its own size field.
    let header = unsafe { core::slice::from_raw_parts(base, header_len) };
    let (spec, _) = eventlog::parse_header(header).ok_or("the event log has no Spec ID header")?;
    if last <= location {
        return Ok(header);
    }
    let last_offset = usize::try_from(last - location).map_err(|_| "the event log is implausibly long")?;
    if last_offset > 16 * 1024 * 1024 {
        return Err("the event log is implausibly long");
    }
    let mut need = 12;
    let last_len = loop {
        // SAFETY: `need` bytes of the last event, which `event_len` asked
        // for after reading the fields before them.
        let probe = unsafe { core::slice::from_raw_parts(base.add(last_offset), need) };
        match eventlog::event_len(probe, &spec) {
            Ok(0) => return Err("the last event doesn't parse"),
            Ok(len) => break len,
            Err(more) if more > need && more <= 64 * 1024 => need = more,
            Err(_) => return Err("the last event doesn't parse"),
        }
    };
    // SAFETY: the log runs from its start to the end of its last event.
    Ok(unsafe { core::slice::from_raw_parts(base, last_offset + last_len) })
}

/// A value as lowercase hex.
pub fn hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
