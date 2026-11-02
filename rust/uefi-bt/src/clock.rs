//! Monotonic time from the CPU timestamp counter, calibrated against the
//! firmware's `Stall()`.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use uefi::boot;

static TICKS_PER_US: AtomicU64 = AtomicU64::new(0);
static START: AtomicU64 = AtomicU64::new(0);

fn tsc() -> u64 {
    // SAFETY: RDTSC has no preconditions on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Measure the TSC rate over 20 ms. Runs automatically on first use; call
/// it early to keep the 20 ms out of anything timed.
pub fn calibrate() {
    let start = tsc();
    boot::stall(Duration::from_millis(20));
    let per_us = ((tsc() - start) / 20_000).max(1);
    TICKS_PER_US.store(per_us, Ordering::Relaxed);
    START.store(tsc(), Ordering::Relaxed);
}

/// Microseconds since calibration.
pub fn now_us() -> u64 {
    if TICKS_PER_US.load(Ordering::Relaxed) == 0 {
        calibrate();
    }
    let per_us = TICKS_PER_US.load(Ordering::Relaxed);
    tsc().wrapping_sub(START.load(Ordering::Relaxed)) / per_us
}

pub fn now_ms() -> u64 {
    now_us() / 1000
}

/// Milliseconds since the timestamp counter started, which is the last
/// power-on or reset unless the firmware wrote the counter. Places a log
/// line in the whole boot: boot loaders and systemd-analyze ("firmware"
/// time) count the same way.
pub fn since_reset_ms() -> u64 {
    if TICKS_PER_US.load(Ordering::Relaxed) == 0 {
        calibrate();
    }
    tsc() / TICKS_PER_US.load(Ordering::Relaxed) / 1000
}
