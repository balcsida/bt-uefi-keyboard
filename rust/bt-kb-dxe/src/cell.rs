//! Shared state in a driver without threads. Our code runs at three task
//! priority levels: TPL_APPLICATION (driver binding Start/Stop, protocol
//! calls from apps), TPL_CALLBACK (our timer) and TPL_NOTIFY (WaitForKey,
//! the USB event callback). Code at a higher TPL can interrupt code at a
//! lower one, never the other way round, so raising the TPL is the lock.

use core::cell::UnsafeCell;

use uefi::boot::{self, Tpl};

/// A value touched at more than one TPL. [`TplCell::with`] raises the TPL
/// to the cell's level for the duration of the closure.
///
/// Rules: never call `with` on a cell from code running above its level,
/// and never call `with` on the same cell from inside its own closure.
pub struct TplCell<T> {
    tpl: Tpl,
    value: UnsafeCell<T>,
}

// SAFETY: there is one CPU and access is serialized by the TPL, see above.
unsafe impl<T> Sync for TplCell<T> {}

impl<T> TplCell<T> {
    pub const fn new(tpl: Tpl, value: T) -> Self {
        Self { tpl, value: UnsafeCell::new(value) }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: callers run at or below `self.tpl` (see the type's rules),
        // so this raise is valid; the guard restores the TPL.
        let _guard = unsafe { boot::raise_tpl(self.tpl) };
        // SAFETY: at `self.tpl` nothing else that uses this cell can run,
        // and `with` is not re-entered for the same cell.
        f(unsafe { &mut *self.value.get() })
    }
}

/// The TPL the caller runs at.
pub fn current_tpl() -> Tpl {
    // SAFETY: raising to HIGH_LEVEL and restoring at once is always allowed.
    let guard = unsafe { boot::raise_tpl(Tpl::HIGH_LEVEL) };
    guard.old_tpl()
}
