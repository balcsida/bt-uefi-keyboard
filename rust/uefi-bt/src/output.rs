//! Where the library's own messages go.
//!
//! Shell apps print to the console. A driver must never do that (it would
//! scribble over the firmware's setup screens), so it redirects the output
//! to its log with [`set_output`].

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 0 means "print to the console".
static OUTPUT: AtomicUsize = AtomicUsize::new(0);

/// Send library messages to `sink` instead of the console.
pub fn set_output(sink: fn(fmt::Arguments)) {
    OUTPUT.store(sink as usize, Ordering::Release);
}

fn console(args: fmt::Arguments) {
    uefi::println!("{args}");
}

#[doc(hidden)]
pub fn emit(args: fmt::Arguments) {
    let sink = OUTPUT.load(Ordering::Acquire);
    if sink == 0 {
        console(args);
    } else {
        // SAFETY: only `set_output` stores a non-zero value, and it stores a
        // `fn(fmt::Arguments)`.
        let sink: fn(fmt::Arguments) = unsafe { core::mem::transmute::<usize, fn(fmt::Arguments)>(sink) };
        sink(args);
    }
}

/// One line of library output (no trailing newline needed).
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {
        $crate::output::emit(format_args!($($arg)*))
    };
}
