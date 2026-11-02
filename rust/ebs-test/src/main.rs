//! ebs-test: what an OS loader does last. Calls ExitBootServices (so every
//! driver's BeforeExitBootServices and ExitBootServices handlers run, among
//! them bt-kb-dxe's controller hand-off) and then powers off through the
//! runtime services.

#![no_main]
#![no_std]

use core::time::Duration;

use uefi::prelude::*;
use uefi::runtime::ResetType;
use uefi::{boot, println};
use uefi_bt as _; // panic handler

#[entry]
fn main() -> Status {
    println!("ebs-test: calling ExitBootServices, then powering off");
    boot::stall(Duration::from_millis(500));
    // SAFETY: nothing of boot services is used afterwards; only the
    // runtime ResetSystem below.
    let _memory_map = unsafe { boot::exit_boot_services(None) };
    uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
}
