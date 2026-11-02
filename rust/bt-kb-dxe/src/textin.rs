//! Simple Text Input and Simple Text Input Ex for the Bluetooth keyboard,
//! with UsbKbDxe's semantics:
//! - a 32-key FIFO filled by the driver's timer (oldest key dropped when full);
//! - modifier-only "partial" keys queued only after SetState asked for them
//!   (EFI_KEY_STATE_EXPOSED), and skipped by the non-Ex calls;
//! - Ctrl+letter turned into control characters 1..26 by the non-Ex
//!   ReadKeyStroke;
//! - RegisterKeyNotify callbacks run for matching keys, at TPL_CALLBACK.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use uefi::boot::{self, EventType, ScopedProtocol, Tpl};
use uefi::proto::usb::io::UsbIo;
use uefi::{Event, Handle, Status};
use uefi_bt::keymap::{efi_shift_state, Key, Toggles};
use uefi_raw::protocol::console::{
    InputKey, KeyData, KeyNotifyFn, KeyShiftState, KeyState, KeyToggleState, SimpleTextInputExProtocol, SimpleTextInputProtocol,
};
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::{guid, Boolean, Guid};

use crate::cell::TplCell;

/// EFI_CONSOLE_IN_DEVICE_GUID: the tag ConSplitter binds to. ConPlatform
/// would only add it for devices listed in the ConIn variable.
pub const CONSOLE_IN_DEVICE: Guid = guid!("d3b36f2b-d551-11d4-9a46-0090273fc14d");

const FIFO: usize = 32;
const EXPOSED: u8 = 0x40;

struct Registration {
    id: usize,
    key: KeyData,
    func: KeyNotifyFn,
}

pub struct Console {
    keys: [KeyData; FIFO],
    head: usize,
    len: usize,
    registrations: Vec<Registration>,
    next_id: usize,
    /// Partial keys wanted (SetState with EFI_KEY_STATE_EXPOSED).
    exposed: bool,
    /// Toggle state set by SetState, for the driver's timer to apply.
    pub requested_toggles: Option<Toggles>,
    pub delivered: u32,
}

pub static CONSOLE: TplCell<Console> = TplCell::new(
    Tpl::NOTIFY,
    Console {
        keys: [KeyData {
            key: InputKey { scan_code: 0, unicode_char: 0 },
            key_state: KeyState { key_shift_state: KeyShiftState::empty(), key_toggle_state: KeyToggleState::empty() },
        }; FIFO],
        head: 0,
        len: 0,
        registrations: Vec::new(),
        next_id: 1,
        exposed: false,
        requested_toggles: None,
        delivered: 0,
    },
);

fn is_partial(key: &KeyData) -> bool {
    key.key.scan_code == 0 && key.key.unicode_char == 0
}

impl Console {
    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn push(&mut self, key: KeyData) {
        if self.len == FIFO {
            self.head = (self.head + 1) % FIFO;
            self.len -= 1;
        }
        self.keys[(self.head + self.len) % FIFO] = key;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<KeyData> {
        if self.len == 0 {
            return None;
        }
        let key = self.keys[self.head];
        self.head = (self.head + 1) % FIFO;
        self.len -= 1;
        Some(key)
    }

    /// Next full key; partial keys in front of it are dropped.
    fn pop_full(&mut self) -> Option<KeyData> {
        while let Some(key) = self.pop() {
            if !is_partial(&key) {
                return Some(key);
            }
        }
        None
    }

    fn has_full(&self) -> bool {
        (0..self.len).any(|i| !is_partial(&self.keys[(self.head + i) % FIFO]))
    }
}

/// UsbKbDxe's IsKeyRegistered: zero shift/toggle state in a registration
/// means "any".
fn matches(registered: &KeyData, key: &KeyData) -> bool {
    registered.key.scan_code == key.key.scan_code
        && registered.key.unicode_char == key.key.unicode_char
        && (registered.key_state.key_shift_state.is_empty()
            || registered.key_state.key_shift_state == key.key_state.key_shift_state)
        && (registered.key_state.key_toggle_state.is_empty()
            || registered.key_state.key_toggle_state == key.key_state.key_toggle_state)
}

pub fn key_data(key: Key, modifiers: u8, toggles: Toggles) -> KeyData {
    KeyData {
        key: InputKey { scan_code: key.scan, unicode_char: key.unicode },
        key_state: KeyState {
            key_shift_state: KeyShiftState::from_bits_retain(efi_shift_state(modifiers)),
            key_toggle_state: KeyToggleState::from_bits_retain(toggles.efi()),
        },
    }
}

/// Registrations logged per driver run: they show which keys the firmware
/// watches (boot hotkeys, the shell's Ctrl+C) without flooding the log.
const LOGGED_REGISTRATIONS: usize = 12;

/// A registered key, for the log: "F2", "'c' (shift state 0x80000008)",
/// "Delete (shift state 0x80000014, toggle state 0x80)".
fn describe(key: &KeyData) -> alloc::string::String {
    use alloc::format;
    use core::fmt::Write;
    let k = key.key;
    let mut out = match (uefi_bt::keymap::scan_name(k.scan_code), k.unicode_char) {
        (Some(name), 0) => format!("{name}"),
        (Some(name), c) => format!("{name} with char {c:#06x}"),
        (None, 0x0D) => format!("Enter"),
        (None, c @ 0x21..=0x7E) => format!("'{}'", char::from(c as u8)),
        (None, c) => format!("char {c:#06x}"),
    };
    let shift = key.key_state.key_shift_state.bits();
    let toggles = key.key_state.key_toggle_state.bits();
    match (shift, toggles) {
        (0, 0) => {}
        (_, 0) => {
            let _ = write!(out, " (shift state {shift:#x})");
        }
        (0, _) => {
            let _ = write!(out, " (toggle state {toggles:#04x})");
        }
        _ => {
            let _ = write!(out, " (shift state {shift:#x}, toggle state {toggles:#04x})");
        }
    }
    out
}

/// Queue a key from the timer (TPL_CALLBACK) and run matching key
/// notifications. `partial` keys are queued only if asked for. Returns how
/// many notification functions ran.
pub fn push(key: KeyData, partial: bool) -> usize {
    let mut callbacks: [Option<KeyNotifyFn>; 8] = [None; 8];
    let mut count = 0;
    CONSOLE.with(|c| {
        if partial && !c.exposed {
            return;
        }
        c.push(key);
        c.delivered += 1;
        for r in c.registrations.iter().filter(|r| matches(&r.key, &key)) {
            if count < callbacks.len() {
                callbacks[count] = Some(r.func);
                count += 1;
            }
        }
    });
    // Outside the cell: a callback may call back into these protocols.
    for func in callbacks.iter().flatten() {
        // SAFETY: registered through RegisterKeyNotify with this signature.
        let _ = unsafe { func(&key) };
    }
    count
}

unsafe extern "efiapi" fn reset(_this: *mut SimpleTextInputProtocol, _extended: Boolean) -> Status {
    CONSOLE.with(Console::clear);
    Status::SUCCESS
}

unsafe extern "efiapi" fn read_key_stroke(_this: *mut SimpleTextInputProtocol, key: *mut InputKey) -> Status {
    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(data) = CONSOLE.with(Console::pop_full) else { return Status::NOT_READY };
    let mut out = data.key;
    let control = KeyShiftState::LEFT_CONTROL | KeyShiftState::RIGHT_CONTROL;
    if data.key_state.key_shift_state.intersects(control) {
        // ctrl-a = 0x0001 .. ctrl-z = 0x001A, as UsbKbDxe does.
        match out.unicode_char {
            c @ 0x61..=0x7A => out.unicode_char = c - 0x61 + 1,
            c @ 0x41..=0x5A => out.unicode_char = c - 0x41 + 1,
            _ => {}
        }
    }
    // SAFETY: checked non-null; the caller provides the storage.
    unsafe { key.write(out) };
    Status::SUCCESS
}

unsafe extern "efiapi" fn reset_ex(_this: *mut SimpleTextInputExProtocol, _extended: Boolean) -> Status {
    CONSOLE.with(Console::clear);
    Status::SUCCESS
}

unsafe extern "efiapi" fn read_key_stroke_ex(_this: *mut SimpleTextInputExProtocol, key: *mut KeyData) -> Status {
    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }
    match CONSOLE.with(Console::pop) {
        Some(data) => {
            // SAFETY: checked non-null; the caller provides the storage.
            unsafe { key.write(data) };
            Status::SUCCESS
        }
        None => Status::NOT_READY,
    }
}

unsafe extern "efiapi" fn set_state(_this: *mut SimpleTextInputExProtocol, state: *const KeyToggleState) -> Status {
    if state.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null.
    let state = unsafe { *state };
    if !state.contains(KeyToggleState::VALID) {
        return Status::UNSUPPORTED;
    }
    CONSOLE.with(|c| {
        c.exposed = state.bits() & EXPOSED != 0;
        c.requested_toggles = Some(Toggles::from_efi(state.bits()));
    });
    Status::SUCCESS
}

unsafe extern "efiapi" fn register_key_notify(
    _this: *mut SimpleTextInputExProtocol,
    key_data: *const KeyData,
    func: KeyNotifyFn,
    handle: *mut *mut c_void,
) -> Status {
    if key_data.is_null() || handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null.
    let key = unsafe { *key_data };
    let (id, new) = CONSOLE.with(|c| {
        let same_key = |r: &&Registration| matches(&r.key, &key) && matches(&key, &r.key);
        if let Some(r) = c.registrations.iter().filter(same_key).find(|r| r.func as usize == func as usize) {
            return (r.id, false);
        }
        // Another consumer for a key already registered: not worth a line.
        let new_key = !c.registrations.iter().any(|r| same_key(&r));
        let id = c.next_id;
        c.next_id += 1;
        c.registrations.push(Registration { id, key, func });
        (id, new_key)
    });
    if new && id <= LOGGED_REGISTRATIONS {
        log::info!("key notify {id} registered for {}", describe(&key));
    }
    // SAFETY: checked non-null. The handle is an opaque, unique token.
    unsafe { handle.write(id as *mut c_void) };
    Status::SUCCESS
}

unsafe extern "efiapi" fn unregister_key_notify(_this: *mut SimpleTextInputExProtocol, handle: *mut c_void) -> Status {
    let id = handle as usize;
    let removed = CONSOLE.with(|c| {
        let before = c.registrations.len();
        c.registrations.retain(|r| r.id != id);
        c.registrations.len() != before
    });
    if removed { Status::SUCCESS } else { Status::INVALID_PARAMETER }
}

/// EVT_NOTIFY_WAIT for both WaitForKey events; the context is set for the
/// Ex one, which also counts partial keys.
unsafe extern "efiapi" fn wait_for_key(event: Event, context: Option<NonNull<c_void>>) {
    let ex = context.is_some();
    let ready = CONSOLE.with(|c| if ex { c.len > 0 } else { c.has_full() });
    if ready {
        let _ = boot::signal_event(&event);
    }
}

/// A console input device handle: device path, both text input protocols
/// and the ConsoleInDevice tag.
pub struct Child {
    pub handle: Handle,
    path: &'static [u8],
    text_in: &'static mut SimpleTextInputProtocol,
    text_in_ex: &'static mut SimpleTextInputExProtocol,
    events: [Option<Event>; 2],
    /// The USB interface opened BY_CHILD_CONTROLLER, if there is a parent.
    pub parent: Option<ScopedProtocol<UsbIo>>,
}

/// Device path of the parent with a BluetoothLE node for `peer` appended.
pub fn bluetooth_le_path(parent: &[u8], peer: [u8; 6], random: bool) -> Vec<u8> {
    // Drop the parent's end node (type 0x7F, subtype 0xFF, length 4).
    let body = if parent.len() >= 4 && parent[parent.len() - 4..] == [0x7F, 0xFF, 0x04, 0x00] {
        &parent[..parent.len() - 4]
    } else {
        parent
    };
    let mut path = body.to_vec();
    // MSG_BLUETOOTH_LE_DP: messaging (3), subtype 0x1E, length 11.
    path.extend_from_slice(&[0x03, 0x1E, 11, 0]);
    path.extend_from_slice(&peer);
    path.push(u8::from(random));
    path.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);
    path
}

/// Vendor hardware path (for the self-test device, which has no parent).
pub fn vendor_path(guid: &Guid) -> Vec<u8> {
    let mut path = alloc::vec![0x01, 0x04, 20, 0];
    path.extend_from_slice(&guid.to_bytes());
    path.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);
    path
}

impl Child {
    /// Install the protocols on a new handle.
    pub fn install(path: Vec<u8>) -> uefi::Result<Child> {
        // SAFETY: notify functions with the right signature; the Ex event's
        // context is a non-null marker, never dereferenced.
        let wait = unsafe { boot::create_event(EventType::NOTIFY_WAIT, Tpl::NOTIFY, Some(wait_for_key), None)? };
        let wait_ex = unsafe {
            boot::create_event(EventType::NOTIFY_WAIT, Tpl::NOTIFY, Some(wait_for_key), Some(NonNull::<u8>::dangling().cast()))?
        };
        let text_in = Box::leak(Box::new(SimpleTextInputProtocol { reset, read_key_stroke, wait_for_key: wait.as_ptr() }));
        let text_in_ex = Box::leak(Box::new(SimpleTextInputExProtocol {
            reset: reset_ex,
            read_key_stroke_ex,
            wait_for_key_ex: wait_ex.as_ptr(),
            set_state,
            register_key_notify,
            unregister_key_notify,
        }));
        let path: &'static [u8] = Box::leak(path.into_boxed_slice());

        // SAFETY: interfaces are leaked, so they stay valid while installed.
        let handle = unsafe { boot::install_protocol_interface(None, &DevicePathProtocol::GUID, path.as_ptr().cast())? };
        let mut child = Child { handle, path, text_in, text_in_ex, events: [Some(wait), Some(wait_ex)], parent: None };
        // SAFETY: as above; the tag has no interface.
        let installed = unsafe {
            boot::install_protocol_interface(
                Some(handle),
                &SimpleTextInputProtocol::GUID,
                (child.text_in as *const SimpleTextInputProtocol).cast(),
            )
            .and_then(|_| {
                boot::install_protocol_interface(
                    Some(handle),
                    &SimpleTextInputExProtocol::GUID,
                    (child.text_in_ex as *const SimpleTextInputExProtocol).cast(),
                )
            })
            .and_then(|_| boot::install_protocol_interface(Some(handle), &CONSOLE_IN_DEVICE, core::ptr::null()))
        };
        if let Err(e) = installed {
            child.uninstall();
            return Err(e);
        }
        Ok(child)
    }

    /// Uninstall everything (the firmware disconnects ConSplitter first).
    pub fn uninstall(&mut self) {
        self.parent = None;
        // SAFETY: the same interfaces that were installed; failures (not
        // installed) are harmless.
        unsafe {
            let _ = boot::uninstall_protocol_interface(self.handle, &CONSOLE_IN_DEVICE, core::ptr::null());
            let _ = boot::uninstall_protocol_interface(
                self.handle,
                &SimpleTextInputExProtocol::GUID,
                (self.text_in_ex as *const SimpleTextInputExProtocol).cast(),
            );
            let _ = boot::uninstall_protocol_interface(
                self.handle,
                &SimpleTextInputProtocol::GUID,
                (self.text_in as *const SimpleTextInputProtocol).cast(),
            );
            let _ = boot::uninstall_protocol_interface(self.handle, &DevicePathProtocol::GUID, self.path.as_ptr().cast());
        }
        for event in self.events.iter_mut().filter_map(Option::take) {
            let _ = boot::close_event(event);
        }
    }
}
