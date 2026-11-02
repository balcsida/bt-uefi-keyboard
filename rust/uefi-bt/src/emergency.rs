//! What happens on a panic (with the `panic-handler` feature).
//!
//! uefi-rs's own handler waits 10 s and then shuts the machine down, which
//! is wrong for anything that talks to hardware. This one:
//! 1. reports the panic (and, in a driver, passes the message to the
//!    driver's hook so it survives the reset below),
//! 2. hands the registered controller back (HCI_Reset and function off, or
//!    the MT7922 subsystem reset if allowed and it doesn't answer), if the
//!    current TPL allows USB transfers,
//! 3. cancels the asynchronous event transfer, so the USB stack never calls
//!    into dead code,
//! 4. in an app, exits to the shell; in a driver, which can't return from
//!    here and must not freeze the firmware, restarts the machine.

use core::cell::RefCell;
#[cfg(feature = "panic-handler")]
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use crate::UsbHci;

static HCI: AtomicPtr<RefCell<UsbHci>> = AtomicPtr::new(core::ptr::null_mut());
static ALLOW_RESET: AtomicBool = AtomicBool::new(false);

/// Let the panic handler hand this controller back. Call [`unregister`]
/// before the `RefCell` is moved or dropped.
pub fn register(hci: &RefCell<UsbHci>, allow_reset: bool) {
    ALLOW_RESET.store(allow_reset, Ordering::Relaxed);
    HCI.store((hci as *const RefCell<UsbHci>).cast_mut(), Ordering::Release);
}

pub fn unregister() {
    HCI.store(core::ptr::null_mut(), Ordering::Release);
}

/// Set by drivers: 0 means "app", otherwise a `fn(&str)` that keeps the
/// panic message somewhere that survives a reset.
static DRIVER_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Switch to driver behavior: `persist` gets the panic message, then the
/// machine restarts.
pub fn set_driver_mode(persist: fn(&str)) {
    DRIVER_HOOK.store(persist as usize, Ordering::Release);
}

/// A panic message without allocating.
#[cfg(feature = "panic-handler")]
struct Message {
    buf: [u8; 240],
    len: usize,
}

#[cfg(feature = "panic-handler")]
impl Write for Message {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "panic-handler")]
impl Message {
    fn as_str(&self) -> &str {
        // Cut at a character boundary if the message was truncated.
        let mut end = self.len;
        while core::str::from_utf8(&self.buf[..end]).is_err() {
            end -= 1;
        }
        core::str::from_utf8(&self.buf[..end]).unwrap_or("")
    }
}

/// The TPL the panic happened at.
#[cfg(feature = "panic-handler")]
fn current_tpl() -> uefi::boot::Tpl {
    // SAFETY: raising to HIGH_LEVEL and restoring at once is always allowed.
    let guard = unsafe { uefi::boot::raise_tpl(uefi::boot::Tpl::HIGH_LEVEL) };
    guard.old_tpl()
}

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut message = Message { buf: [0; 240], len: 0 };
    let _ = write!(message, "{info}");
    crate::say!("[PANIC] {}", message.as_str());
    let hook = DRIVER_HOOK.swap(0, Ordering::AcqRel);
    let driver = hook != 0;
    if driver {
        // SAFETY: only `set_driver_mode` stores a non-zero value, a `fn(&str)`.
        let persist: fn(&str) = unsafe { core::mem::transmute::<usize, fn(&str)>(hook) };
        persist(message.as_str());
    }

    // Taken once: a panic during the hand-off below goes straight on.
    let hci = HCI.swap(core::ptr::null_mut(), Ordering::AcqRel);
    let tpl = current_tpl();
    if !hci.is_null() && tpl < uefi::boot::Tpl::NOTIFY {
        // SAFETY: registered and still alive, since panics don't unwind.
        // Nothing of the panicking code runs again, so going around a
        // RefCell borrow that may still be active is acceptable here.
        let hci = unsafe { &mut *(*hci).as_ptr() };
        crate::app::print_diagnostics(hci);
        crate::app::hand_off(hci, ALLOW_RESET.load(Ordering::Relaxed));
    }
    crate::stop_event_pipes();

    if driver {
        // Straight to the screen, whatever the output sink is: someone may
        // be looking at a firmware screen that is about to go away.
        if tpl <= uefi::boot::Tpl::NOTIFY {
            uefi::system::with_stdout(|out| {
                let _ = out.write_str("\r\nBluetooth keyboard driver crashed; restarting in 5 seconds.\r\n");
            });
            uefi::boot::stall(core::time::Duration::from_secs(5));
        }
        crate::say!("[PANIC] calling ResetSystem (cold) at TPL {tpl:?}");
        uefi::runtime::reset(uefi::runtime::ResetType::COLD, uefi::Status::ABORTED, None);
    }

    crate::say!("Exiting to the shell.");
    // SAFETY: ends this image; none of its code runs afterwards.
    let _ = unsafe { uefi::boot::exit(uefi::boot::image_handle(), uefi::Status::ABORTED, 0, core::ptr::null_mut()) };
    loop {
        core::hint::spin_loop();
    }
}
