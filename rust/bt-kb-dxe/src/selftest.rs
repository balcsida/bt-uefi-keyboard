//! Offline self-test of the console path, without the Bluetooth controller.
//!
//! If `bt-kb-dxe.selftest` sits next to the driver, the driver installs its
//! console input device on a vendor device path instead of binding to the
//! controller, waits 3 s, and then types the file's text as HID keyboard
//! reports: one press and one release per character, through the same
//! keymap, key FIFO, Simple Text Input protocols and ConSplitter that real
//! key reports take. A newline is Enter.
//!
//! Special keys: `{esc}` `{f2}` `{enter}` `{tab}` `{bs}` `{up}` `{down}`
//! `{left}` `{right}`, and `{wait:MS}` to pause, e.g. for a setup screen
//! to appear.
//!
//! If the file is just `panic`, the driver panics instead, 3 s after
//! loading, to check the panic path: message kept in `BtKbPanic`, notice
//! on the console, machine reset.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;
use core::time::Duration;

use log::{error, info, warn};
use uefi::boot::{self, EventType, TimerTrigger, Tpl};
use uefi::{Event, Status};
use uefi_bt::keymap::{modifier, usage_for_ascii, KeyboardState};
use uefi_raw::guid;

use crate::cell::TplCell;
use crate::session::Shared;
use crate::textin::{self, Child};

const START_DELAY_MS: u64 = 3000;
const PERIOD: Duration = Duration::from_millis(20);

enum Step {
    /// Modifiers and the one held usage (0 = none).
    Report(u8, u16),
    Wait(u64),
}

struct SelfTest {
    keyboard: KeyboardState,
    steps: VecDeque<Step>,
    start_ms: u64,
    /// No step before this time.
    next_ms: u64,
    sent: usize,
    panic: bool,
    shared: Shared,
    _child: Child,
    _timer: Event,
}

static TEST: TplCell<Option<SelfTest>> = TplCell::new(Tpl::CALLBACK, None);

fn special_key(name: &str) -> Option<u16> {
    Some(match name {
        "esc" => 0x29,
        "f2" => 0x3B,
        "enter" => 0x28,
        "tab" => 0x2B,
        "bs" => 0x2A,
        "up" => 0x52,
        "down" => 0x51,
        "left" => 0x50,
        "right" => 0x4F,
        _ => return None,
    })
}

/// The file's text as steps: a press and a release per key.
fn parse(text: &str) -> (VecDeque<Step>, usize) {
    let mut steps = VecDeque::new();
    let mut keys = 0;
    let mut rest = text;
    let mut press = |steps: &mut VecDeque<Step>, modifiers: u8, usage: u16| {
        steps.push_back(Step::Report(modifiers, usage));
        steps.push_back(Step::Report(0, 0));
        keys += 1;
    };
    while let Some(c) = rest.chars().next() {
        if c == '{' {
            if let Some(end) = rest.find('}') {
                let token = &rest[1..end];
                if let Some(ms) = token.strip_prefix("wait:").and_then(|ms| ms.parse().ok()) {
                    steps.push_back(Step::Wait(ms));
                } else if let Some(usage) = special_key(token) {
                    press(&mut steps, 0, usage);
                } else {
                    warn!("self-test: unknown key {{{token}}}");
                }
                rest = &rest[end + 1..];
                continue;
            }
        }
        if c != '\r' {
            match usage_for_ascii(c) {
                Some((usage, shift)) => press(&mut steps, if shift { modifier::LSHIFT } else { 0 }, usage),
                None => warn!("self-test: no key on a US layout for {c:?}"),
            }
        }
        rest = &rest[c.len_utf8()..];
    }
    (steps, keys)
}

pub fn start(text: Vec<u8>) -> Status {
    let text = alloc::string::String::from_utf8_lossy(&text).into_owned();
    let panic = text.trim() == "panic";
    let (steps, keys) = if panic { (VecDeque::new(), 0) } else { parse(&text) };
    if panic {
        info!("self-test: panicking in {START_DELAY_MS} ms");
    } else {
        info!("self-test: typing {keys} keys, starting in {START_DELAY_MS} ms");
    }

    let child = match Child::install(textin::vendor_path(&guid!("5223227b-ac96-454e-9bca-f15199748a3c"))) {
        Ok(child) => child,
        Err(e) => {
            error!("self-test: installing the console device failed: {e:?}");
            return e.status();
        }
    };
    let child_handle = child.handle;
    // SAFETY: `tick` has the notify signature and uses no context.
    let timer = match unsafe { boot::create_event(EventType::TIMER | EventType::NOTIFY_SIGNAL, Tpl::CALLBACK, Some(tick), None) } {
        Ok(timer) => timer,
        Err(e) => return e.status(),
    };
    let _ = boot::set_timer(&timer, TimerTrigger::Periodic(PERIOD));
    TEST.with(|t| {
        *t = Some(SelfTest {
            keyboard: KeyboardState::default(),
            steps,
            start_ms: uefi_bt::clock::now_ms(),
            next_ms: 0,
            sent: 0,
            panic,
            shared: Shared::default(),
            _child: child,
            _timer: timer,
        });
    });
    let connected = boot::connect_controller(child_handle, &[], None, true);
    info!("self-test: console device connected: {:?}", connected.map_err(|e| e.status()));
    Status::SUCCESS
}

unsafe extern "efiapi" fn tick(_event: Event, _context: Option<NonNull<c_void>>) {
    TEST.with(|test| {
        let Some(t) = test else { return };
        let now = uefi_bt::clock::now_ms();
        if now < t.start_ms + START_DELAY_MS {
            return;
        }
        if t.panic {
            panic!("self-test: panic requested");
        }
        let shared = &t.shared;
        if now >= t.next_ms {
            match t.steps.pop_front() {
                Some(Step::Report(modifiers, usage)) => {
                    let held: &[u16] = if usage == 0 { &[] } else { &[usage] };
                    t.keyboard.report(modifiers, held, now, &mut |e| crate::deliver(shared, e));
                    t.sent += 1;
                    if t.steps.is_empty() {
                        let delivered = textin::CONSOLE.with(|c| c.delivered);
                        info!("self-test: {} reports sent, {delivered} keys queued", t.sent);
                    }
                }
                Some(Step::Wait(ms)) => t.next_ms = now + ms,
                None => {}
            }
        }
        t.keyboard.tick(now, &mut |e| crate::deliver(shared, e));
    });
    crate::dlog::flush(false);
}
