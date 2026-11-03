//! The TPM as the driver finds it when it starts (stage 0 of the security
//! hardening): logged, not yet used. It shows where in the measured boot
//! the driver runs:
//! - PCR 7 (SHA-256), read from the TPM;
//! - which PCRs 0–7 already have their EV_SEPARATOR in the event log:
//!   whether the driver runs before or after each separator;
//! - the driver's own load event (found by its file path), numbered as
//!   `tpm2_eventlog` numbers events, and whether replaying the log's PCR 7
//!   events gives the TPM's value.

use log::{info, warn};
use uefi_bt::eventlog::{self, pcr_list};
use uefi_bt::{app, tcg};

/// What [`log_state`] found, for the boot record.
pub struct State {
    /// PCRs 0–7 with a separator already (bit n: PCR n).
    pub separators: u8,
}

fn event_name(event_type: u32) -> &'static str {
    match event_type {
        eventlog::EV_EFI_BOOT_SERVICES_DRIVER => "EV_EFI_BOOT_SERVICES_DRIVER",
        eventlog::EV_EFI_BOOT_SERVICES_APPLICATION => "EV_EFI_BOOT_SERVICES_APPLICATION",
        _ => "an image event",
    }
}

/// Log the TPM's state; `None` without a TPM 2.0.
pub fn log_state() -> Option<State> {
    let Some(mut tcg) = tcg::open() else {
        info!("TPM: none (no EFI_TCG2_PROTOCOL, or no TPM 2.0 present)");
        return None;
    };
    let pcr7 = match tcg::read_pcr(&mut tcg, 7) {
        Ok(value) => {
            info!("TPM: PCR 7 (SHA-256) = {}", tcg::hex(&value));
            Some(value)
        }
        Err(e) => {
            warn!("TPM: reading PCR 7 failed: {e}");
            None
        }
    };
    let log = match tcg::event_log(&mut tcg) {
        Ok(bytes) => bytes,
        Err(why) => {
            warn!("TPM: no event log: {why}");
            return Some(State { separators: 0 });
        }
    };
    let Some(log) = eventlog::parse(log) else {
        warn!("TPM: the event log doesn't parse");
        return Some(State { separators: 0 });
    };
    let separators = log.separators();
    info!(
        "TPM: event log of {} events; EV_SEPARATOR already measured for PCRs {}, not yet for {}",
        log.events.len(),
        pcr_list(separators),
        pcr_list(!separators)
    );
    let path = app::image_path();
    match log.image_event(&path) {
        Some(e) => info!("TPM: this driver's load is event {} ({} in PCR {})", e.number(), event_name(e.event_type), e.pcr),
        None => info!("TPM: no load event for {path} in the log (not measured?)"),
    }
    match (log.replay(7, None), pcr7) {
        (Some(replayed), Some(read)) if replayed == read => info!("TPM: the event log replays PCR 7 to the TPM's value"),
        (Some(replayed), Some(_)) => warn!("TPM: the event log replays PCR 7 to {}, not the TPM's value", tcg::hex(&replayed)),
        _ => {}
    }
    Some(State { separators })
}
