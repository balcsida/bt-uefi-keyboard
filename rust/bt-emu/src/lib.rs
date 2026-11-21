//! An emulated MT7922 Bluetooth controller with a BLE keyboard behind it,
//! for the offline tests.
//!
//! QEMU's `usb-redir` device forwards every USB transfer of one guest
//! device over a socket. This program is the other end: it plays the
//! MT7922's USB function ([`usbdev`]), an HCI controller and a bonded
//! keyboard on its only link ([`radio`], [`gatt`]), following a script of
//! what the "user" does ([`script`]). The driver under test is the real
//! binary, unchanged, in OVMF; nothing here touches a real radio.
//!
//! Layers, top down:
//! - [`script`]: "wait until encrypted, type this, expect that".
//! - [`radio`]: HCI commands and events, the LE link, L2CAP, the
//!   keyboard's behaviour (advertising when woken, key reports only on an
//!   encrypted link, its parameter request, its idle disconnect).
//! - [`gatt`]: the keyboard's attribute table and ATT server.
//! - [`smp`]: the keyboard's side of pairing (legacy and Secure
//!   Connections), for the tests of pairing in firmware.
//! - [`usbdev`]: descriptors, MediaTek's vendor channel, the HCI pipes.
//! - [`usbredir`]: the wire protocol to QEMU.

pub mod gatt;
pub mod log;
pub mod radio;
pub mod script;
pub mod smp;
pub mod usbdev;
pub mod usbredir;

/// One line for the emulator's log (nothing if no log was opened, as in
/// unit tests).
#[macro_export]
macro_rules! note {
    ($($arg:tt)*) => {
        $crate::log::line(format_args!($($arg)*))
    };
}
