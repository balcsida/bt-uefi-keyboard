//! MediaTek MT79xx Bluetooth bring-up over USB: firmware images, the WMT
//! vendor command channel, firmware upload and function control.
//!
//! `no_std`, no allocation. All I/O goes through [`wmt::Transport`], so the
//! same code runs on `EFI_USB_IO_PROTOCOL` and against the simulator in the
//! tests.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod diag;
pub mod firmware;
pub mod wmt;

#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;

pub use diag::{classify_acl, AclKind};
pub use firmware::{FirmwareError, FirmwareImage, FirmwareName, Section};
pub use wmt::{ChipInfo, Error, LoadResult, Mtk, SectionState, Transport, WmtEvent};
