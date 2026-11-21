//! The emulator's log: one line per thing that happened, with the time in
//! milliseconds since it started, to a file and (unless quiet) to stderr.
//! The offline tests look for lines here next to the driver's own log.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

struct Logger {
    start: Instant,
    file: Option<File>,
    quiet: bool,
}

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

/// Open the log. Only the first call counts.
pub fn init(path: Option<&Path>, quiet: bool) -> std::io::Result<()> {
    let file = match path {
        Some(path) => Some(File::create(path)?),
        None => None,
    };
    let _ = LOGGER.set(Mutex::new(Logger { start: Instant::now(), file, quiet }));
    Ok(())
}

/// Milliseconds since the log was opened (0 without a log).
pub fn now_ms() -> u64 {
    LOGGER.get().map_or(0, |l| l.lock().unwrap().start.elapsed().as_millis() as u64)
}

pub fn line(args: fmt::Arguments) {
    let Some(logger) = LOGGER.get() else { return };
    let mut l = logger.lock().unwrap();
    let ms = l.start.elapsed().as_millis();
    let text = format!("{ms:>7} {args}\n");
    if let Some(file) = l.file.as_mut() {
        let _ = file.write_all(text.as_bytes());
    }
    if !l.quiet {
        let _ = std::io::stderr().write_all(text.as_bytes());
    }
}
