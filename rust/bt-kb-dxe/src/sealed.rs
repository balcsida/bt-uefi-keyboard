//! The bond sealed to the TPM (stage 4 of the security hardening; README,
//! Security), and the spare PCR.
//!
//! - **Unsealing:** `bt-kb-dxe.sealed` next to the driver (from
//!   `scripts/tpm-seal.sh`) is unsealed with [`uefi_bt::seal::unseal`]:
//!   a salted policy session, the answer encrypted. The record it holds
//!   must still be a bond this build trusts.
//! - **The spare PCR** (`SPARE_PCR`, a build setting) is extended right
//!   after, on every boot with a TPM, whether there was anything to unseal
//!   or not: code that runs later sees it changed and can't unseal. The
//!   seal script makes the policy expect it at zero.
//! - **Failures** are logged with the reason and the PCRs that changed;
//!   the driver then falls back to its boot-services-only copy (stage 3)
//!   if the seal allows one. `scripts/tpm-seal.sh --if-needed` reseals
//!   from the OS.

use log::{error, info, warn};
use uefi::proto::tcg::v2::Tcg;
use uefi_bt::app;
use uefi_bt::bond::ExportedBond;
use uefi_bt::seal::{self, Sealed};
use uefi_bt::tcg;

use crate::SPARE_PCR;

pub const FILE: &str = "bt-kb-dxe.sealed";
/// The spare PCR's event: an EV_EFI_ACTION with this text.
pub const CLOSE_ACTION: &[u8] = b"bt-kb-dxe: unseal window closed";

pub enum Outcome {
    /// No TPM 2.0.
    NoTpm,
    /// A TPM, but no sealed bond next to the driver.
    NotSealed,
    /// Unsealed, and a bond this build trusts; `fallback`: whether the
    /// seal allows a boot-services-only copy (stage 3).
    Unsealed { bond: ExportedBond, fallback: bool },
    /// A sealed bond that didn't work, and why (short, for the boot
    /// record).
    Failed { reason: &'static str, fallback: bool },
}

fn close_window(tcg: &mut Tcg) {
    let Some(pcr) = SPARE_PCR else { return };
    match tcg::log_action(tcg, pcr, CLOSE_ACTION) {
        Ok(()) => info!("TPM: PCR {pcr} extended: nothing after the driver can unseal its bond"),
        Err(e) => error!("TPM: extending PCR {pcr} failed: {:?}", e.status()),
    }
}

fn pcrs_text(bits: u32) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    (0..24).filter(|n| bits & (1 << n) != 0).for_each(|n| {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&alloc::format!("{n}"));
    });
    out
}

/// Which of the policy's PCRs don't have the values it expects now.
fn changed_pcrs(tcg: &mut Tcg, sealed: &Sealed) -> u32 {
    sealed
        .expected
        .iter()
        .filter(|(n, value)| tcg::read_pcr(tcg, *n).map_or(true, |now| now != *value))
        .fold(0, |acc, (n, _)| acc | (1 << n))
}

fn unseal(tcg: &mut Tcg, sealed: &Sealed, pins: &[[u8; 32]]) -> Outcome {
    let fallback = sealed.fallback;
    if SPARE_PCR.is_some_and(|p| sealed.pcrs & (1 << p) == 0) || sealed.pcrs & (1 << 2) == 0 {
        warn!(
            "TPM: the seal's policy (PCRs {}) leaves out PCR 2 or the spare PCR: code that runs later may be able to unseal it",
            pcrs_text(sealed.pcrs)
        );
    }
    let changed = changed_pcrs(tcg, sealed);
    let mut rng = tcg::session_rng(tcg);
    if !rng.cpu {
        warn!("TPM: no RDSEED or RDRAND: the session's randomness comes from the firmware and the TPM only");
    }
    match seal::unseal(tcg, sealed, &mut rng) {
        Ok(unsealed) => match ExportedBond::from_record(&unsealed.record) {
            Ok(bond) if pins.contains(&bond.digest()) => {
                info!(
                    "TPM: bond unsealed (policy PCRs {}; salted session, encrypted answer, {})",
                    pcrs_text(sealed.pcrs),
                    if unsealed.hmac_checked { "its HMAC checked" } else { "no HMAC from the TPM" }
                );
                Outcome::Unsealed { bond, fallback }
            }
            Ok(mut bond) => {
                bond.wipe();
                error!("TPM: the sealed bond isn't one this driver was built for: ignoring it");
                Outcome::Failed { reason: "the sealed bond isn't trusted by this build", fallback }
            }
            Err(_) => {
                error!("TPM: the unsealed data isn't a bond record");
                Outcome::Failed { reason: "the unsealed data isn't a bond", fallback }
            }
        },
        Err(e) => {
            let code = e.tpm_error().map(|t| alloc::format!(" ({t})")).unwrap_or_default();
            if changed != 0 {
                error!(
                    "TPM: unsealing failed: {}{code}; PCRs that changed since sealing: {} (reseal from the OS: sudo scripts/tpm-seal.sh)",
                    e.reason(),
                    pcrs_text(changed)
                );
            } else {
                error!("TPM: unsealing failed: {}{code}", e.reason());
            }
            Outcome::Failed { reason: e.reason(), fallback }
        }
    }
}

/// Unseal the bond if there is a sealed one (and `may_unseal`), then
/// extend the spare PCR. Called once, early, on every start.
pub fn run(may_unseal: bool, pins: &[[u8; 32]]) -> Outcome {
    let file = app::read_file(FILE).ok();
    let Some(mut tcg) = tcg::open() else {
        if file.is_some() {
            warn!("TPM: {FILE} is here, but there's no TPM 2.0: using the boot-services copy, if any");
        }
        return Outcome::NoTpm;
    };
    let outcome = match file.as_deref().map(core::str::from_utf8) {
        None => Outcome::NotSealed,
        Some(Err(_)) => Outcome::Failed { reason: "the sealed bond file isn't text", fallback: true },
        Some(Ok(text)) => match Sealed::parse(text) {
            Err(why) => {
                error!("TPM: {FILE}: {why}");
                Outcome::Failed { reason: "the sealed bond file doesn't parse", fallback: true }
            }
            Ok(_) if !may_unseal => Outcome::Failed { reason: "not starting", fallback: true },
            Ok(sealed) => unseal(&mut tcg, &sealed, pins),
        },
    };
    close_window(&mut tcg);
    outcome
}
