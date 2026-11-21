//! bt-kb-dxe: a UEFI boot service driver that makes a bonded Bluetooth LE
//! keyboard on a MediaTek MT7922 a console input device, for the UEFI shell
//! and firmware setup screens.
//!
//! - **Binding:** a driver binding for MediaTek Bluetooth USB interfaces,
//!   connected by the driver itself the moment the USB bus driver installs
//!   one (a protocol notify): the bus driver only connects drivers to the
//!   devices the boot manager asks for, keyboards say. Start() checks that
//!   the controller's firmware is already loaded (it never uploads), turns
//!   Bluetooth on and resets the controller, starts the TrouBLE host and
//!   installs a console input device for the keyboard.
//! - **Timer:** everything after that runs from a timer at TPL_CALLBACK,
//!   about every 10 ms: drain HCI events, read ACL data (1 ms), run the
//!   host stack until it is idle, decode key reports, repeat held keys.
//! - **Keys:** read straight off the HCI link (ATT notifications on the
//!   keyboard's input report), only once the link is encrypted with the
//!   bonded key; reports from before that are dropped. The driver never
//!   pairs: encryption with any other key and Security Manager traffic are
//!   refused between the host stack and the controller (`uefi_bt::tap`).
//!   The report layout is remembered between boots (`cache`), so keys work
//!   about 0.5 s after the keyboard wakes rather than after the GATT
//!   discovery.
//! - **One copy:** a second load of the driver unloads itself again.
//! - **Hand-off:** the controller goes back (keyboard disconnected,
//!   HCI_Reset, Bluetooth function off) before an OS starts
//!   (BeforeExitBootServices) and before a reset (reset notification).
//! - **Logging:** never to the console; see `dlog`. Boot-loop protection:
//!   see `safety`.
//! - **Files** next to the driver: the MT7922 firmware image (for the
//!   section check, pinned by SHA-256 at build time), a `*.bond` file from
//!   `scripts/export-bond.sh` until the driver has imported it into a
//!   variable the OS can't read (`bondstore`; only bonds the build pins
//!   count), and,
//!   for the offline self-test, `bt-kb-dxe.selftest`. For test sessions,
//!   `bt-kb-dxe.timelimit` (seconds): when it runs out, the driver hands
//!   the controller back and powers the machine off.

#![no_main]
#![no_std]

extern crate alloc;

mod bondstore;
mod cache;
mod cell;
mod sealed;
mod dlog;
#[cfg(feature = "pairing")]
mod pair;
mod record;
mod safety;
#[cfg(feature = "pairing")]
mod screen;
mod selftest;
mod session;
mod textin;
mod tpm;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_void;
use core::fmt::Write as _;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use core::task::{Context, Waker};
use core::time::Duration;

use bt_hci::controller::ExternalController;
use bt_hci::event::Event as HciEvent;
use bt_hci::FromHciBytes;
use log::{error, info, warn};
use mtk_bt::{AclKind, FirmwareImage, Mtk};
use trouble_host::prelude::{AddrKind, Address, BdAddr, BondInformation, HostResources, Identity, LongTermKey, SecurityLevel, Stack};
use uefi::boot::{self, EventType, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol, SearchType, TimerTrigger, Tpl};
use uefi::prelude::*;
use uefi::proto::device_path::DevicePath;
use uefi::proto::usb::io::UsbIo;
use uefi::{Event, Handle, Identify};
use uefi_bt::bond::{addr_text, ExportedBond};
use uefi_bt::embassy::{Inbox, InboxTransport};
use uefi_bt::keymap::{Event as KeyEvent, Key, KeyboardState};
use uefi_bt::link::{encryption_change_as_v1, notification, Notification};
use uefi_bt::tap::{BondKey, LinkGuard, LinkTap, SmpFilter, TapEvent, Verdict};
use uefi_bt::{app, clock, DisconnectOutcome, HciError, UsbHci, ACL_BUF, HCI_OP_READ_BD_ADDR, MTK_VENDOR_ID};
use uefi_raw::protocol::driver::{ComponentName2Protocol, DriverBindingProtocol};
use uefi_raw::protocol::misc::ResetNotificationProtocol;
use uefi_raw::table::runtime::ResetType;
use uefi_raw::{guid, Char16, Guid};

use cell::{current_tpl, TplCell};
use session::{Ctrl, Pool, Shared};
use textin::Child;

const VERSION: &str = env!("CARGO_PKG_VERSION");
// FIRMWARE_SHA256 and TRUSTED_BONDS, from build.rs.
include!(concat!(env!("OUT_DIR"), "/pins.rs"));
const FW_FILE: &str = "BT_RAM_CODE_MT7922_1_1_hdr.bin";
const SELFTEST_FILE: &str = "bt-kb-dxe.selftest";
const TIME_LIMIT_FILE: &str = "bt-kb-dxe.timelimit";
/// Re-armed after every tick, so ticks never queue up behind each other;
/// with the usual 10 ms firmware timer this gives a tick about every 10 ms.
const TICK: Duration = Duration::from_millis(5);
/// How often the ACL pipe is read while no keyboard is connected.
const IDLE_ACL_INTERVAL_MS: u64 = 100;
/// Running this long without trouble shows the driver doesn't hang the
/// boot: the boot-loop counter goes back to zero.
const HEALTHY_AFTER_MS: u64 = 15_000;
const BEFORE_EXIT_BOOT_SERVICES: Guid = guid!("8be0e274-3970-4b44-80c5-1ab9502f3bfc");
/// Installed (no interface) on the image handle of the copy that runs; a
/// second copy finds it and unloads itself.
const INSTANCE: Guid = guid!("8eba1571-1ea8-4ef1-af24-56a3bd1a4cf1");
/// The connection handle the MT7922 gives the first LE link.
const FIRST_LE_HANDLE: u16 = 0x0200;
/// Deliver key reports that arrived before the link was encrypted, once it
/// is (the behaviour before Nov 3). Off unless the driver is built with the
/// `insecure-replay-unencrypted` feature: an unencrypted LE link has no
/// integrity protection, so those reports may come from anyone in range.
const REPLAY_UNENCRYPTED: bool = cfg!(feature = "insecure-replay-unencrypted");
/// EFI_SHELL_PROTOCOL: present while a UEFI shell runs, so a driver loaded
/// with it there was loaded from the shell, not by the firmware.
const SHELL_PROTOCOL: Guid = guid!("6302d008-7f9b-4f30-87ac-60c9fef5da4e");

struct Config {
    fw: FirmwareImage<'static>,
    /// The bond this boot starts with. None before a first pairing in
    /// firmware (only a build with the `pairing` feature starts without).
    bond: Option<ExportedBond>,
    /// Power off after this many milliseconds (test sessions only).
    time_limit_ms: Option<u64>,
    /// Loaded from a UEFI shell, not by the firmware at boot.
    #[cfg_attr(not(feature = "pairing"), allow(dead_code))]
    from_shell: bool,
    /// Pairing in firmware is offered at this boot, and why.
    #[cfg(feature = "pairing")]
    pairing: Option<screen::Why>,
    /// How long the boot waits for a pairing to begin.
    #[cfg(feature = "pairing")]
    pair_wait_ms: u64,
}

/// Test hook: seconds the boot waits for a pairing to begin.
#[cfg(feature = "pairing")]
const PAIR_WAIT_FILE: &str = "bt-kb-dxe.pairwait";
/// ... and how long it waits without one. Long enough to read the screen
/// and reach for the keyboard's pairing button.
#[cfg(feature = "pairing")]
const PAIR_WAIT_MS: u64 = 30_000;
/// EFI_EVENT_GROUP_READY_TO_BOOT: the boot manager is about to start a
/// boot option. The consoles are up by then, and nothing has been started.
#[cfg(feature = "pairing")]
const READY_TO_BOOT: Guid = guid!("7ce88fb3-4bd7-4679-87a8-a8d8dee50d2b");

/// Set once by the entry point, read-only afterwards.
static CONFIG: AtomicPtr<Config> = AtomicPtr::new(core::ptr::null_mut());

fn config() -> Option<&'static Config> {
    // SAFETY: only ever set to a leaked, never-freed Box.
    unsafe { CONFIG.load(Ordering::Acquire).as_ref() }
}

/// How the firmware's timer and USB stack behave, for the log: the board's
/// AMI stack may differ from OVMF's. Everything counts from the last timing
/// line on.
#[derive(Default)]
struct Timing {
    ticks: u32,
    last_tick_us: u64,
    max_gap_us: u64,
    events: u32,
    /// ACL reads that found nothing (they time out after 1 ms).
    acl_empty: u32,
    acl_empty_us: u64,
    acl_empty_max_us: u64,
    acl_data: u32,
    acl_data_max_us: u64,
    /// Notifications read (and kept from the host stack).
    notifications: u32,
}

/// Microseconds as milliseconds with one decimal.
struct Ms(u64);

impl core::fmt::Display for Ms {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{} ms", self.0 / 1000, (self.0 % 1000) / 100)
    }
}

/// The keyboard's current connection, for the log.
#[derive(Default)]
struct Link {
    connected_ms: u64,
    /// The first key report of this connection was decoded.
    keys_flowing: bool,
}

/// The tick's part in pairing in firmware.
#[cfg(feature = "pairing")]
struct PairingSide {
    /// Random bytes of the driver's own, for the host stack's seed.
    rng: uefi_bt::rng::Rng,
    le_rand_mixed: u32,
    /// The host stack's memory. A pairing's keys were made in it, so it
    /// is wiped at the hand-off of a boot that paired.
    stack_memory: [(*mut u8, usize); 2],
    paired: bool,
    /// The stage last shown (a driver loaded from a shell shows lines).
    shown: pair::Stage,
    /// Data from a pairing link that came before the controller's word
    /// that the link is encrypted (see `hold_acl`).
    held_acl: Vec<Vec<u8>>,
}

struct Driver {
    hci: &'static RefCell<UsbHci>,
    inbox: &'static Inbox,
    shared: &'static Shared,
    future: Option<Pin<Box<dyn Future<Output = ()>>>>,
    timer: Option<Event>,
    child: Option<Child>,
    /// What may become a keystroke: the link as the driver sees it, and the
    /// guard the host stack's packets pass on their way to the controller.
    tap: LinkTap,
    guard: &'static LinkGuard,
    /// The controller's own address: a bond made here belongs to it.
    #[cfg_attr(not(feature = "pairing"), allow(dead_code))]
    adapter: [u8; 6],
    #[cfg(feature = "pairing")]
    pairing: PairingSide,
    /// Pairing (SMP) packets from the keyboard, kept from the host stack.
    smp_in: SmpFilter,
    link: Link,
    /// Set while the controller is borrowed; acted on after the pump.
    violation: Option<String>,
    /// Refusals and SMP drops already logged.
    refusals_logged: u32,
    smp_logged: bool,
    keyboard: KeyboardState,
    dead: bool,
    handed_off: bool,
    started_ms: u64,
    healthy: bool,
    next_idle_acl_ms: u64,
    reports: u32,
    /// The keyboard has connected at least once since the driver started.
    ever_connected: bool,
    /// "Still waiting" notes logged before the first connection.
    wait_notes: u32,
    /// Notifications on handles other than the keyboard report: (handle,
    /// how many were logged).
    other_reports: Vec<(u16, u8)>,
    timing: Timing,
    /// ACL packets the host stack had sent at the last timing line.
    acl_sent_logged: u64,
    /// A timing line to log at the end of this tick (events are handled
    /// while the controller is borrowed).
    timing_due: Option<&'static str>,
}

static STATE: TplCell<Option<Driver>> = TplCell::new(Tpl::CALLBACK, None);
/// ExitBootServices ran: nothing of ours may run any more.
static EXITED: AtomicBool = AtomicBool::new(false);
/// The test-session time limit ran out: power off after the tick.
static POWER_OFF: AtomicBool = AtomicBool::new(false);
static RESET_NOTIFY: AtomicPtr<ResetNotificationProtocol> = AtomicPtr::new(core::ptr::null_mut());
/// Registration for "a USB I/O protocol was installed".
static USB_ARRIVALS: TplCell<Option<SearchType<'static>>> = TplCell::new(Tpl::CALLBACK, None);
/// USB interfaces that appeared after the driver loaded (for the log).
static USB_SEEN: AtomicU32 = AtomicU32::new(0);

#[entry]
fn main() -> Status {
    clock::calibrate();
    dlog::init();
    if boot::locate_handle_buffer(SearchType::ByProtocol(&INSTANCE)).is_ok_and(|h| !h.is_empty()) {
        // The debug console only: the running copy's log variable stays.
        info!("bt-kb-dxe {VERSION} is already running; this copy unloads again");
        return Status::ALREADY_STARTED;
    }
    uefi_bt::output::set_output(dlog::say);
    uefi_bt::emergency::set_driver_mode(dlog::persist_panic);
    let shell = boot::locate_handle_buffer(SearchType::ByProtocol(&SHELL_PROTOCOL)).is_ok_and(|h| !h.is_empty());
    let origin = if shell { "loaded from a UEFI shell" } else { "loaded by the firmware" };
    let loaded_at = clock::since_reset_ms();
    info!("bt-kb-dxe {VERSION} starting from {} ({origin}, {loaded_at} ms after the CPU reset)", app::image_dir());
    record::init(loaded_at, shell);
    let status = load(shell);
    if status.is_success() {
        // SAFETY: a tag without an interface on our own image handle.
        let tagged = unsafe { boot::install_protocol_interface(Some(boot::image_handle()), &INSTANCE, core::ptr::null()) };
        if let Err(e) = tagged {
            warn!("tagging the running copy failed: {:?}", e.status());
        }
    }
    dlog::flush(true);
    status
}

/// The variable a bond paired in firmware is handed to the OS in: volatile,
/// and readable by anyone there, which is why it is encrypted.
#[cfg(feature = "pairing")]
const HAND_OFF: &uefi::CStr16 = uefi::cstr16!("BtKbHandOff");

/// Hand a bond that was paired in firmware to the OS: encrypted to the
/// public key this driver was built with (`uefi_bt::handoff`), for
/// `scripts/bond-handoff.py` to give to the OS's Bluetooth stack. The
/// keyboard holds one key per host, so the OS must use this bond, and
/// can't be left to pair again. At every boot, with a new ephemeral key.
#[cfg(feature = "pairing")]
fn hand_off_bond(bond: &ExportedBond, rng: &mut uefi_bt::rng::Rng) {
    use uefi::runtime::VariableAttributes;
    let Some(recipient) = HANDOFF_KEY else {
        warn!("this build has no hand-off key (BT_KB_HANDOFF_KEY): the OS can't take the bond over, and would have to pair anew");
        return;
    };
    // The message is only as secret as the ephemeral key is random.
    if !rng.cpu {
        error!("no random numbers from the CPU: the bond isn't handed to the OS");
        return;
    }
    let mut record = bond.record();
    let blob = uefi_bt::handoff::seal(&record, &recipient, rng);
    uefi_bt::bond::wipe_bytes(&mut record);
    let Some(blob) = blob else {
        error!("the build's hand-off key isn't a point on P-256: the bond isn't handed to the OS");
        return;
    };
    let attributes = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
    match uefi::runtime::set_variable(HAND_OFF, &dlog::VENDOR, attributes, &blob) {
        Ok(()) => info!("the bond is handed to the OS, encrypted to the build's hand-off key (BtKbHandOff, {} bytes)", blob.len()),
        Err(e) => error!("handing the bond to the OS failed: {:?}", e.status()),
    }
}

/// What this boot has for a bond, and whether it offers pairing: with no
/// bond at all, or when `bt-kb-dxe.pair` asks for a new one.
#[cfg(feature = "pairing")]
fn bond_or_pairing(
    loaded: Result<(ExportedBond, bondstore::Source), String>,
    keep_copy: bool,
) -> (Result<Option<(ExportedBond, bondstore::Source)>, String>, Option<screen::Why>) {
    use bondstore::Source;
    let requested = bondstore::pairing_requested();
    if !keep_copy {
        // A seal with fallback=no allows no copy of the key outside the
        // TPM, and a bond paired here would be one: the driver can't seal.
        if requested {
            warn!("{} is ignored: the sealed bond allows no unsealed copy (fallback=no)", bondstore::PAIR_MARKER);
        }
        return (loaded.map(Some), None);
    }
    let found = match loaded {
        // Installed from the OS just now: newer than anything paired here.
        Ok(found @ (_, Source::Imported | Source::File)) => Some(found),
        older => match bondstore::paired() {
            Some(paired) => Some((paired, Source::Paired)),
            None => match older {
                Ok(found) => Some(found),
                Err(e) => {
                    info!("no bond from an OS: {e}");
                    None
                }
            },
        },
    };
    let why = match (&found, requested) {
        (None, _) => Some(screen::Why::Unpaired),
        (Some(_), true) => Some(screen::Why::Requested),
        (Some(_), false) => None,
    };
    (Ok(found), why)
}

fn load(from_shell: bool) -> Status {
    match record::previous() {
        Some(text) => info!("previous boot: {text}"),
        None => info!("previous boot: no record"),
    }
    let start = safety::count_start();
    match start {
        Ok(n) => info!("start {n} of at most {} before an OS has to boot", safety::LIMIT),
        Err(n) => error!("not starting: {n} starts in a row never reached an OS; delete the BtKbBoots variable to re-enable"),
    }
    let image = boot::image_handle();
    let tpm = tpm::log_state();
    // Stage 4: unseal the bond, then extend the spare PCR. On every start,
    // even one the boot-loop guard stops, so nothing later can unseal.
    let sealed = sealed::run(start.is_ok(), TRUSTED_BONDS);
    record::update(|r| {
        r.tpm_separators = Some(tpm.map(|t| t.separators));
        if let sealed::Outcome::Failed { reason, .. } = sealed {
            r.unseal_failed = Some(reason);
        }
        false
    });
    if start.is_err() {
        return Status::ABORTED;
    }
    let (unsealed, keep_copy) = match sealed {
        sealed::Outcome::Unsealed { bond, fallback } => (Some(bond), fallback),
        sealed::Outcome::Failed { fallback, .. } => (None, fallback),
        sealed::Outcome::NoTpm | sealed::Outcome::NotSealed => (None, true),
    };

    if let Ok(text) = app::read_file(SELFTEST_FILE) {
        return selftest::start(text);
    }

    let fw = match app::read_file(FW_FILE) {
        Ok(data) => data,
        Err(e) => {
            error!("cannot read the firmware image {e}");
            return Status::NOT_FOUND;
        }
    };
    // Secure Boot covers this driver, not the files next to it: the image
    // must be the one the driver was built for, before anything parses it.
    match FIRMWARE_SHA256 {
        Some(pin) if uefi_bt::sha256(&fw) == pin => {}
        Some(_) => {
            error!(
                "{FW_FILE} isn't the image this driver was built for (SHA-256 differs): refusing it. After a \
                 linux-firmware update, rebuild and reinstall the driver"
            );
            record::failed(clock::now_ms(), "the firmware image doesn't match the pinned SHA-256");
            return Status::SECURITY_VIOLATION;
        }
        None => {
            error!("this build pins no firmware image (build it with BT_KB_FIRMWARE set): refusing {FW_FILE}");
            record::failed(clock::now_ms(), "the build pins no firmware image");
            return Status::SECURITY_VIOLATION;
        }
    }
    let fw: &'static [u8] = Box::leak(fw.into_boxed_slice());
    let fw = match FirmwareImage::parse(fw) {
        Ok(fw) => fw,
        Err(e) => {
            error!("{FW_FILE} is not a valid MT79xx image: {e}");
            return Status::VOLUME_CORRUPTED;
        }
    };
    // A forget marker ends this boot's start (`bondstore::load` acts on
    // it), whether or not the build can pair.
    #[cfg(feature = "pairing")]
    let forgetting = app::read_file(bondstore::MARKER).is_ok();
    let loaded = bondstore::load(TRUSTED_BONDS, unsealed, keep_copy);
    #[cfg(feature = "pairing")]
    let (loaded, pairing) = if forgetting { (loaded.map(Some), None) } else { bond_or_pairing(loaded, keep_copy) };
    #[cfg(not(feature = "pairing"))]
    let loaded = loaded.map(Some);
    let bond = match loaded {
        Ok(Some((bond, source))) => {
            record::update(|r| {
                r.bond = Some(source.text());
                false
            });
            info!("{} ({})", bond.summary(), source.text());
            #[cfg(feature = "pairing")]
            if source == bondstore::Source::Paired {
                let mut rng = uefi_bt::tcg::open().map_or_else(|| uefi_bt::rng::Rng::new(&[]), |mut tcg| uefi_bt::tcg::session_rng(&mut tcg));
                hand_off_bond(&bond, &mut rng);
            }
            Some(bond)
        }
        Ok(None) => {
            record::update(|r| {
                r.bond = Some("none");
                false
            });
            None
        }
        Err(e) => {
            error!("{e}");
            record::failed(clock::now_ms(), &e);
            return Status::NOT_FOUND;
        }
    };
    let seconds_in = |file: &str| app::read_file(file).ok().and_then(|data| core::str::from_utf8(&data).ok()?.trim().parse::<u64>().ok());
    let time_limit_ms = seconds_in(TIME_LIMIT_FILE).map(|seconds| seconds * 1000);
    if let Some(limit) = time_limit_ms {
        info!("test session: powering off {} s after the controller starts", limit / 1000);
    }
    #[cfg(feature = "pairing")]
    let pair_wait_ms = {
        match pairing {
            Some(screen::Why::Unpaired) => info!("no keyboard is paired with this PC: pairing is offered at this boot"),
            Some(screen::Why::Requested) => info!("{} asked for a new pairing: offered at this boot", bondstore::PAIR_MARKER),
            None => {}
        }
        if pairing.is_some() {
            record::update(|r| {
                r.pairing = Some("offered, nothing paired");
                false
            });
        }
        seconds_in(PAIR_WAIT_FILE).map_or(PAIR_WAIT_MS, |seconds| seconds.min(300) * 1000)
    };
    CONFIG.store(
        Box::into_raw(Box::new(Config {
            fw,
            bond,
            time_limit_ms,
            from_shell,
            #[cfg(feature = "pairing")]
            pairing,
            #[cfg(feature = "pairing")]
            pair_wait_ms,
        })),
        Ordering::Release,
    );

    if let Err(e) = install_binding(image) {
        error!("installing the driver binding failed: {e:?}");
        return e.status();
    }
    watch_lifecycle();

    // Interfaces that appear from now on (loaded as a Driver#### option,
    // before the boot manager connects USB) ...
    watch_usb();
    // ... and those that already exist (loaded from the shell, say).
    if let Ok(handles) = boot::locate_handle_buffer(SearchType::ByProtocol(&UsbIo::GUID)) {
        for &handle in handles.iter().filter(|&&h| is_candidate(h)) {
            let result = boot::connect_controller(handle, &[Some(image), None], None, false);
            info!("connect to {}: {:?}", path_text(handle), result.map_err(|e| e.status()));
        }
    }
    Status::SUCCESS
}

/// Connect this driver to MediaTek Bluetooth interfaces as soon as the USB
/// bus driver installs them.
fn watch_usb() {
    // SAFETY: `usb_arrived` has the notify signature and uses no context.
    let event = unsafe { boot::create_event(EventType::NOTIFY_SIGNAL, Tpl::CALLBACK, Some(usb_arrived), None) };
    let registered = event.and_then(|event| boot::register_protocol_notify(&UsbIo::GUID, &event).map(|key| (event, key)));
    match registered {
        Ok((event, key)) => {
            USB_ARRIVALS.with(|k| *k = Some(key));
            // The event lives as long as the driver.
            core::mem::forget(event);
        }
        Err(e) => warn!("watching for new USB devices failed: {:?}; relying on the USB bus driver to connect", e.status()),
    }
}

unsafe extern "efiapi" fn usb_arrived(_event: Event, _context: Option<NonNull<c_void>>) {
    if EXITED.load(Ordering::Acquire) {
        return;
    }
    let Some(key) = USB_ARRIVALS.with(|k| *k) else { return };
    loop {
        // Each new handle comes out once, one per call.
        let mut buf = [MaybeUninit::uninit(); 1];
        let Ok(&[handle]) = boot::locate_handle(key, &mut buf) else { break };
        USB_SEEN.fetch_add(1, Ordering::Relaxed);
        if STATE.with(|s| s.is_some()) || !is_candidate(handle) {
            continue;
        }
        let result = boot::connect_controller(handle, &[Some(boot::image_handle()), None], None, false);
        info!("new USB interface {}: connect {:?}", path_text(handle), result.map_err(|e| e.status()));
    }
}

fn bond_information(bond: &ExportedBond) -> BondInformation {
    let kind = if bond.peer_is_random { AddrKind::RANDOM } else { AddrKind::PUBLIC };
    // No IRK: the keyboard advertises with its identity address.
    let identity = Identity { addr: Address::new(kind, BdAddr::new(bond.peer)), irk: None };
    let level = if bond.authenticated() { SecurityLevel::EncryptedAuthenticated } else { SecurityLevel::Encrypted };
    // The stand-in, not the key: the guard puts the key into LE Enable
    // Encryption (uefi_bt::tap::STAND_IN_LTK), and TrouBLE's memory, which
    // the OS gets as it is, never holds it.
    let mut info = BondInformation::new(identity, LongTermKey::from_le_bytes(uefi_bt::tap::STAND_IN_LTK), level, true);
    info.ediv = bond.ediv;
    info.rand = bond.rand_bytes();
    info.encryption_key_len = bond.enc_size;
    info
}

// ---------------------------------------------------------------------------
// Driver binding
// ---------------------------------------------------------------------------

fn install_binding(image: Handle) -> uefi::Result<()> {
    let binding = Box::leak(Box::new(DriverBindingProtocol {
        supported,
        start,
        stop,
        version: 0x10,
        image_handle: image.as_ptr(),
        driver_binding_handle: image.as_ptr(),
    }));
    let name = Box::leak(Box::new(ComponentName2Protocol {
        get_driver_name,
        get_controller_name,
        supported_languages: b"en\0".as_ptr(),
    }));
    // SAFETY: both interfaces are leaked, so they stay valid while installed.
    unsafe {
        boot::install_protocol_interface(Some(image), &DriverBindingProtocol::GUID, (binding as *const DriverBindingProtocol).cast())?;
        boot::install_protocol_interface(Some(image), &ComponentName2Protocol::GUID, (name as *const ComponentName2Protocol).cast())?;
    }
    Ok(())
}

const DRIVER_NAME: &[Char16] = &{
    const TEXT: &[u8] = b"Bluetooth LE keyboard (MediaTek MT7922)\0";
    let mut out = [0u16; TEXT.len()];
    let mut i = 0;
    while i < TEXT.len() {
        out[i] = TEXT[i] as u16;
        i += 1;
    }
    out
};

unsafe extern "efiapi" fn get_driver_name(_this: *const ComponentName2Protocol, _language: *const u8, name: *mut *const Char16) -> Status {
    if name.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null.
    unsafe { name.write(DRIVER_NAME.as_ptr()) };
    Status::SUCCESS
}

unsafe extern "efiapi" fn get_controller_name(
    _this: *const ComponentName2Protocol,
    _controller: uefi_raw::Handle,
    _child: uefi_raw::Handle,
    _language: *const u8,
    _name: *mut *const Char16,
) -> Status {
    Status::UNSUPPORTED
}

fn path_text(handle: Handle) -> String {
    uefi_bt::device_path_text(handle).unwrap_or_else(|| String::from("(no device path)"))
}

fn open_get<P: uefi::proto::ProtocolPointer + ?Sized>(handle: Handle) -> uefi::Result<ScopedProtocol<P>> {
    // SAFETY: GET_PROTOCOL only peeks; the handle outlives this short use.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams { handle, agent: boot::image_handle(), controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }
}

/// Starts that failed at the controller's bring-up during this boot. The
/// firmware calls Start again on every pass that connects drivers (six
/// times in a row in OVMF, seen with the emulated controller on Nov 14),
/// and most reasons don't change within a boot: firmware that isn't
/// loaded, a bond for another controller. After [`START_ATTEMPTS`] the
/// driver leaves the controller alone until the next boot.
static FAILED_STARTS: AtomicU32 = AtomicU32::new(0);
const START_ATTEMPTS: u32 = 2;

/// A MediaTek Bluetooth HCI interface (cached descriptors only).
fn is_candidate(handle: Handle) -> bool {
    let Ok(mut usb) = open_get::<UsbIo>(handle) else { return false };
    uefi_bt::describe(handle, &mut usb).is_some_and(|i| i.vendor_id == MTK_VENDOR_ID)
}

unsafe extern "efiapi" fn supported(
    this: *const DriverBindingProtocol,
    controller: uefi_raw::Handle,
    _remaining: *const uefi_raw::protocol::device_path::DevicePathProtocol,
) -> Status {
    // SAFETY: the firmware passes our binding and a handle.
    let (Some(controller), Some(agent)) = (unsafe { Handle::from_ptr(controller) }, unsafe { Handle::from_ptr((*this).driver_binding_handle) })
    else {
        return Status::INVALID_PARAMETER;
    };
    if STATE.with(|s| s.is_some()) {
        return Status::UNSUPPORTED; // one keyboard controller at a time
    }
    if FAILED_STARTS.load(Ordering::Relaxed) >= START_ATTEMPTS {
        return Status::UNSUPPORTED; // given up for this boot
    }
    // The driver model's test: can we open it BY_DRIVER?
    // SAFETY: closed again when `usb` drops at the end of this function.
    let usb = unsafe {
        boot::open_protocol::<UsbIo>(
            OpenProtocolParams { handle: controller, agent, controller: Some(controller) },
            OpenProtocolAttributes::ByDriver,
        )
    };
    let mut usb = match usb {
        Ok(usb) => usb,
        Err(e) => return e.status(),
    };
    match uefi_bt::describe(controller, &mut usb) {
        Some(info) if info.vendor_id == MTK_VENDOR_ID => Status::SUCCESS,
        _ => Status::UNSUPPORTED,
    }
}

unsafe extern "efiapi" fn start(
    this: *const DriverBindingProtocol,
    controller: uefi_raw::Handle,
    _remaining: *const uefi_raw::protocol::device_path::DevicePathProtocol,
) -> Status {
    // SAFETY: the firmware passes our binding and a handle.
    let (Some(controller), Some(agent)) = (unsafe { Handle::from_ptr(controller) }, unsafe { Handle::from_ptr((*this).driver_binding_handle) })
    else {
        return Status::INVALID_PARAMETER;
    };
    let status = match start_driver(controller, agent) {
        Ok(()) => Status::SUCCESS,
        Err(status) => status,
    };
    dlog::flush(true);
    status
}

fn start_driver(controller: Handle, agent: Handle) -> Result<(), Status> {
    let Some(cfg) = config() else { return Err(Status::NOT_READY) };
    if STATE.with(|s| s.is_some()) {
        return Err(Status::ALREADY_STARTED);
    }
    let info = {
        let mut usb = open_get::<UsbIo>(controller).map_err(|e| e.status())?;
        uefi_bt::describe(controller, &mut usb).ok_or(Status::UNSUPPORTED)?
    };
    info!(
        "starting on {:04X}:{:04X} interface {} at {}",
        info.vendor_id,
        info.product_id,
        info.interface_number,
        path_text(controller)
    );
    let started = clock::now_ms();
    let mut hci = UsbHci::open_by_driver(info, agent).map_err(|e| e.status())?;
    if hci.pipe_stats().is_none() {
        warn!("no asynchronous event transfer; events are read synchronously");
    }
    let adapter = match bring_up(&mut hci, cfg) {
        Ok(adapter) => adapter,
        Err(e) => {
            error!("{e}");
            record::failed(clock::now_ms(), &e);
            app::hand_off(&mut hci, true);
            hci.close();
            if FAILED_STARTS.fetch_add(1, Ordering::Relaxed) + 1 >= START_ATTEMPTS {
                error!("the controller couldn't be started {START_ATTEMPTS} times: leaving it alone until the next boot");
            }
            return Err(Status::DEVICE_ERROR);
        }
    };
    info!("controller ready in {} ms", clock::now_ms() - started);
    let ready = clock::now_ms();
    record::update(|r| {
        r.ready_ms = Some(ready);
        false
    });

    // The host stack, on leaked (driver-lifetime) storage.
    let hci: &'static RefCell<UsbHci> = Box::leak(Box::new(RefCell::new(hci)));
    let inbox: &'static Inbox = Box::leak(Box::default());
    let shared: &'static Shared = Box::leak(Box::default());
    let resources: &'static mut HostResources<Pool, 1, 4> = Box::leak(Box::new(HostResources::new()));
    #[cfg(feature = "pairing")]
    let resources_memory = (core::ptr::from_mut(resources).cast::<u8>(), size_of::<HostResources<Pool, 1, 4>>());
    let key = match &cfg.bond {
        Some(bond) => BondKey::new(bond.ediv, bond.rand_bytes(), bond.ltk),
        None => BondKey::none(),
    };
    let guard: &'static LinkGuard = Box::leak(Box::new(LinkGuard::new(key)));
    let controller_hci: Ctrl = ExternalController::new(InboxTransport::new(hci, inbox).with_guard(guard));
    if REPLAY_UNENCRYPTED {
        warn!("built with insecure-replay-unencrypted: key reports from before the link is encrypted are delivered");
    }
    let stack: &'static Stack<'static, Ctrl, Pool> = Box::leak(Box::new(trouble_host::new(controller_hci, resources).build()));
    if let Some(bond) = &cfg.bond {
        if let Err(e) = stack.add_bond_information(bond_information(bond)) {
            error!("importing the bond failed: {e:?}");
            record::failed(clock::now_ms(), "importing the bond failed");
            app::hand_off(&mut hci.borrow_mut(), true);
            hci.borrow_mut().close();
            return Err(Status::DEVICE_ERROR);
        }
    }
    shared.keyboard.set(cfg.bond.as_ref().map(|bond| (bond.peer, bond.peer_is_random)));
    #[cfg(feature = "pairing")]
    if cfg.pairing.is_some() {
        // The driver can show a passkey, and nothing else: a keyboard has
        // to take it as input (passkey entry). Legacy pairing only if the
        // build allows it.
        stack.set_io_capabilities(trouble_host::prelude::IoCapabilities::DisplayOnly);
        stack.set_secure_connections_only(!pair::LEGACY);
        shared.pairing.offered.set(true);
        // From a shell there is a console, and no boot to hold up.
        shared.pairing.go.set(cfg.from_shell);
        if pair::LEGACY {
            warn!("built with insecure-legacy-pairing: a device in radio range can pair in the keyboard's place while pairing is offered");
        }
    }
    let remembered = cfg.bond.as_ref().and_then(cache::load);
    match &remembered {
        Some(f) => {
            info!("using the keyboard layout remembered from an earlier boot (input report at {:#06x})", f.layout.input);
            shared.layout.set(Some(f.layout));
        }
        None => info!("no remembered keyboard layout: the first connection discovers it"),
    }
    let future: Pin<Box<dyn Future<Output = ()>>> = Box::pin(session::run(stack, shared, remembered));

    // The console input device: parent's device path plus a BluetoothLE
    // node (with the address zero while no keyboard is paired).
    let parent_path = open_get::<DevicePath>(controller).map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    let (peer, peer_is_random) = shared.keyboard.get().unwrap_or(([0; 6], false));
    let path = textin::bluetooth_le_path(&parent_path, peer, peer_is_random);
    let mut child = match Child::install(path) {
        Ok(child) => child,
        Err(e) => {
            error!("installing the console device failed: {e:?}");
            record::failed(clock::now_ms(), "installing the console device failed");
            app::hand_off(&mut hci.borrow_mut(), true);
            hci.borrow_mut().close();
            return Err(e.status());
        }
    };
    // SAFETY: the driver model's child relation; closed when the child goes.
    child.parent = unsafe {
        boot::open_protocol::<UsbIo>(
            OpenProtocolParams { handle: controller, agent, controller: Some(child.handle) },
            OpenProtocolAttributes::ByChildController,
        )
    }
    .ok();
    let child_handle = child.handle;

    // SAFETY: `tick` has the notify signature and uses no context.
    let timer = unsafe { boot::create_event(EventType::TIMER | EventType::NOTIFY_SIGNAL, Tpl::CALLBACK, Some(tick), None) }
        .map_err(|e| e.status())?;
    uefi_bt::emergency::register(hci, true);
    STATE.with(|state| {
        *state = Some(Driver {
            hci,
            inbox,
            shared,
            future: Some(future),
            timer: Some(timer),
            child: Some(child),
            tap: match &cfg.bond {
                Some(bond) => LinkTap::new(bond.peer, bond.peer_is_random, REPLAY_UNENCRYPTED),
                None => LinkTap::unpaired(REPLAY_UNENCRYPTED),
            },
            guard,
            adapter,
            #[cfg(feature = "pairing")]
            pairing: PairingSide {
                rng: uefi_bt::tcg::open().map_or_else(|| uefi_bt::rng::Rng::new(&[]), |mut tcg| uefi_bt::tcg::session_rng(&mut tcg)),
                le_rand_mixed: 0,
                stack_memory: [resources_memory, (core::ptr::from_ref(stack).cast_mut().cast::<u8>(), size_of_val(stack))],
                paired: false,
                shown: pair::Stage::Off,
                held_acl: Vec::new(),
            },
            smp_in: SmpFilter::default(),
            link: Link::default(),
            violation: None,
            refusals_logged: 0,
            smp_logged: false,
            keyboard: KeyboardState::default(),
            dead: false,
            handed_off: false,
            started_ms: clock::now_ms(),
            healthy: false,
            next_idle_acl_ms: 0,
            reports: 0,
            ever_connected: false,
            wait_notes: 0,
            other_reports: Vec::new(),
            timing: Timing::default(),
            acl_sent_logged: 0,
            timing_due: None,
        });
    });
    // ConSplitter (and ConPlatform) pick the keyboard up from here.
    let connected = boot::connect_controller(child_handle, &[], None, true);
    info!("console device {}: connect {:?}", path_text(child_handle), connected.map_err(|e| e.status()));
    // Armed only now, from inside the state: the first tick must find its
    // timer there to re-arm it.
    STATE.with(|state| {
        if let Some(Driver { timer: Some(timer), .. }) = state {
            let _ = boot::set_timer(timer, TimerTrigger::Relative(TICK));
        }
    });
    Ok(())
}

/// The MediaTek sequence (no firmware upload), a clean HCI_Reset, and a
/// check that this is the controller the bond belongs to.
/// Returns the controller's address.
fn bring_up(hci: &mut UsbHci, cfg: &Config) -> Result<[u8; 6], String> {
    let drained = hci.drain(20, 300).map_err(|e| alloc::format!("draining the controller failed: {e:?}"))?;
    if !drained.is_empty() {
        let from = drained.acl_handle.map(|h| alloc::format!(" (data from handle {h:#06x})")).unwrap_or_default();
        info!("discarded {} events and {} ACL packets still queued{from}", drained.events, drained.acl);
    }
    {
        let mut mtk = Mtk::new(&mut *hci);
        let chip = mtk.chip_info().map_err(|e| alloc::format!("reading the chip ID failed: {e}"))?;
        if chip.chip_id != 0x7922 {
            return Err(alloc::format!("chip {:#06x}: only the MT7922 is supported", chip.chip_id));
        }
        match mtk.load_firmware(&cfg.fw, false) {
            Ok(r) => info!("firmware: {}/{} sections already loaded", r.sections_already_loaded, r.sections_checked),
            Err(mtk_bt::Error::NotLoaded { section }) => {
                return Err(alloc::format!(
                    "firmware section {section} is not loaded on the chip (power was cut?). This driver doesn't upload \
                     firmware yet; the OS loads it the next time it uses Bluetooth"
                ));
            }
            Err(e) => return Err(alloc::format!("firmware check failed: {e}")),
        }
        mtk.enable().map_err(|e| alloc::format!("turning Bluetooth on failed: {e}"))?;
    }
    close_old_links(hci, drained.acl_handle);
    app::clean_start(hci)?;
    let mut ret = [0u8; 8];
    match hci.command(HCI_OP_READ_BD_ADDR, &[], &mut ret, 2000) {
        Ok(n) if n >= 7 && ret[0] == 0 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&ret[1..7]);
            match &cfg.bond {
                Some(bond) if bond.adapter != addr => Err(alloc::format!(
                    "this controller is {}, but the bond belongs to {}",
                    addr_text(&addr),
                    addr_text(&bond.adapter)
                )),
                _ => Ok(addr),
            }
        }
        other => Err(alloc::format!("reading the controller address failed: {other:?}")),
    }
}

/// The controller keeps its links across host resets (on Nov 1 a keyboard
/// link outlived Linux handing the controller over). The HCI_Reset that
/// follows would end such a link silently, and the keyboard would only
/// notice after its supervision timeout, seconds later, before it
/// advertises again. Closing it properly first lets it reconnect at once.
/// Tried: the handle of any data still queued, and 0x0200, the handle this
/// controller gives the first LE link (under Linux too).
fn close_old_links(hci: &mut UsbHci, seen: Option<u16>) {
    let mut handles = [seen.unwrap_or(FIRST_LE_HANDLE), FIRST_LE_HANDLE];
    if handles[0] == handles[1] {
        handles[1] = u16::MAX;
    }
    for handle in handles.into_iter().filter(|&h| h != u16::MAX) {
        match hci.disconnect(handle, 0x15, 500) {
            Ok(DisconnectOutcome::NoConnection) => {}
            Ok(DisconnectOutcome::Closed { reason }) => {
                info!("closed a link left from before this boot (handle {handle:#06x}, reason {reason:#04x}): the keyboard can reconnect at once");
                record::update(|r| {
                    r.links_closed += 1;
                    false
                });
            }
            Ok(DisconnectOutcome::NoCompletion) => {
                info!("a link left from before this boot (handle {handle:#06x}) didn't confirm closing; the reset ends it");
            }
            Ok(DisconnectOutcome::Failed(status)) => info!("closing handle {handle:#06x} before the reset: status {status:#04x}"),
            Err(e) => warn!("closing handle {handle:#06x} before the reset failed: {e:?}"),
        }
    }
}

unsafe extern "efiapi" fn stop(
    _this: *const DriverBindingProtocol,
    _controller: uefi_raw::Handle,
    children: usize,
    _child_buffer: *const uefi_raw::Handle,
) -> Status {
    info!("stop ({children} children)");
    STATE.with(|state| {
        let Some(d) = state.as_mut() else { return };
        if children > 0 {
            if let Some(mut child) = d.child.take() {
                child.uninstall();
            }
            return;
        }
        d.shutdown(true);
        if let Some(mut child) = d.child.take() {
            child.uninstall();
        }
        if let Some(timer) = d.timer.take() {
            let _ = boot::close_event(timer);
        }
        uefi_bt::emergency::unregister();
        d.hci.borrow_mut().close();
        // The future points into leaked memory; dropping it would run the
        // host stack's destructors against a closed controller. Leak it too.
        if let Some(future) = d.future.take() {
            core::mem::forget(future);
        }
        *state = None;
    });
    dlog::flush(true);
    Status::SUCCESS
}

// ---------------------------------------------------------------------------
// The timer tick
// ---------------------------------------------------------------------------

unsafe extern "efiapi" fn tick(_event: Event, _context: Option<NonNull<c_void>>) {
    if EXITED.load(Ordering::Acquire) {
        return;
    }
    STATE.with(|state| {
        if let Some(d) = state {
            d.tick();
        }
    });
    dlog::flush(false);
    // Outside the state cell: the reset notification uses it too.
    if POWER_OFF.swap(false, Ordering::AcqRel) {
        dlog::flush(true);
        uefi::runtime::reset(uefi::runtime::ResetType::SHUTDOWN, Status::SUCCESS, None);
    }
}

fn deliver(shared: &Shared, event: KeyEvent) {
    match event {
        KeyEvent::Key { key, modifiers, toggles, repeat } => {
            let notified = textin::push(textin::key_data(key, modifiers, toggles), false);
            if !repeat && uefi_bt::keymap::is_hotkey_like(key.scan) {
                let name = uefi_bt::keymap::scan_name(key.scan).unwrap_or("?");
                info!("key {name} delivered ({notified} key notify functions ran)");
                record::update(|r| r.count_hotkey(name));
            }
        }
        KeyEvent::Modifiers { modifiers, toggles } => {
            textin::push(textin::key_data(Key { scan: 0, unicode: 0 }, modifiers, toggles), true);
        }
        KeyEvent::Toggles(toggles) => shared.leds.set(Some(toggles.led_bits())),
    }
}

impl Driver {
    fn tick(&mut self) {
        if self.dead {
            return;
        }
        let now = clock::now_ms();
        let now_us = clock::now_us();
        if self.timing.last_tick_us != 0 {
            self.timing.max_gap_us = self.timing.max_gap_us.max(now_us.saturating_sub(self.timing.last_tick_us));
        }
        self.timing.last_tick_us = now_us;
        self.timing.ticks += 1;
        // Before the controller's events are read: the connection to the
        // device the session picked has to be a pairing link from its
        // first event on.
        #[cfg(feature = "pairing")]
        self.tap.set_candidate(self.shared.pairing.candidate.get());
        if let Err(why) = self.pump(now) {
            self.fail(&why);
            return;
        }
        self.log_guard();
        // SetState from ConSplitter (another keyboard's Caps Lock, say).
        if let Some(toggles) = textin::CONSOLE.with(|c| c.requested_toggles.take()) {
            if toggles != self.keyboard.toggles {
                self.keyboard.toggles = toggles;
                self.shared.leds.set(Some(toggles.led_bits()));
            }
        }
        self.replay(now);
        let polled = self.poll_session();
        // A refused command stops the host stack in this very poll.
        self.log_guard();
        if let Err(why) = polled {
            self.fail(&why);
            return;
        }
        #[cfg(feature = "pairing")]
        self.pairing_tick(now);
        let shared = self.shared;
        self.keyboard.tick(now, &mut |e| deliver(shared, e));
        // Until the keyboard first connects: a note at 5, 10, 20 and 40 s,
        // so the log shows how long the wait for a key press was.
        if !self.ever_connected && self.wait_notes < 4 {
            let waited = now.saturating_sub(self.started_ms);
            if waited >= 5000 << self.wait_notes {
                self.wait_notes += 1;
                info!("still waiting for the keyboard after {} s: press a key on it", waited / 1000);
            }
        }
        if let Some(limit) = config().and_then(|c| c.time_limit_ms) {
            if now - self.started_ms >= limit {
                info!("test session time limit reached: handing the controller back and powering off");
                self.shutdown(true);
                POWER_OFF.store(true, Ordering::Release);
                return;
            }
        }
        if !self.healthy && now - self.started_ms >= HEALTHY_AFTER_MS {
            self.healthy = true;
            safety::clear();
            info!("running fine for {} s: boot-loop counter cleared", HEALTHY_AFTER_MS / 1000);
            self.timing_due.get_or_insert("first 15 s");
            record::update(|r| {
                r.healthy_ms = Some(now);
                true
            });
        }
        record::tick(now);
        if let Some(at) = self.timing_due.take() {
            self.log_timing(at);
        }
        if let Some(timer) = &self.timer {
            let _ = boot::set_timer(timer, TimerTrigger::Relative(TICK));
        }
    }

    /// What the guard refused or dropped since the last call.
    fn log_guard(&mut self) {
        let (refused, why) = self.guard.refused();
        if refused > self.refusals_logged {
            self.refusals_logged = refused;
            error!("refused to send the controller {}", why.unwrap_or("a command"));
        }
        let smp = self.smp_in.dropped + self.guard.smp_dropped();
        if smp > 0 && !self.smp_logged {
            self.smp_logged = true;
            warn!("dropped a pairing (SMP) packet: this driver only uses the stored key, so it never pairs (counted in the timing lines)");
        }
    }

    /// Everything the controller has: events into the tap and the inbox,
    /// ACL data likewise (every tick while connected, else every 100 ms).
    fn pump(&mut self, now: u64) -> Result<(), String> {
        let mut hci = self.hci.borrow_mut();
        let mut buf = [0u8; ACL_BUF];
        for _ in 0..64 {
            match hci.read_event(&mut buf, 0) {
                Ok(len) => {
                    self.timing.events += 1;
                    #[cfg(feature = "pairing")]
                    self.pairing_event(&mut buf[..len], now);
                    let event = &buf[..len];
                    // TrouBLE `unwrap!`s typed events: never hand it a bad one.
                    if let Err(e) = HciEvent::from_hci_bytes_complete(event) {
                        hci.note_malformed_event(event, &e);
                        continue;
                    }
                    self.tap_event(event, now);
                    // A connection the host stack has asked the controller
                    // to end is written off there: TrouBLE 0.8 stops
                    // altogether if an Encryption Change still comes for
                    // it. The tap has seen it; that is enough.
                    if let [0x08 | 0x59, _, _, h0, h1, ..] = *event {
                        if self.guard.closing() == Some(u16::from_le_bytes([h0, h1]) & 0x0FFF) {
                            continue;
                        }
                    }
                    match encryption_change_as_v1(event) {
                        Some(v1) => self.inbox.push_event(&v1),
                        None => self.inbox.push_event(event),
                    }
                }
                Err(HciError::Usb(e)) if e.status == Status::TIMEOUT => break,
                Err(e) => return Err(alloc::format!("reading HCI events failed: {e:?}")),
            }
        }
        if let Some(why) = self.violation.take() {
            return Err(why);
        }
        #[cfg(feature = "pairing")]
        self.release_held_acl();
        if self.tap.conn().is_none() && now < self.next_idle_acl_ms {
            return Ok(());
        }
        self.next_idle_acl_ms = now + IDLE_ACL_INTERVAL_MS;
        for _ in 0..8 {
            let started_us = clock::now_us();
            let read = hci.read_acl(&mut buf, 1);
            let took_us = clock::now_us().saturating_sub(started_us);
            match &read {
                Ok(Some(_)) => {
                    self.timing.acl_data += 1;
                    self.timing.acl_data_max_us = self.timing.acl_data_max_us.max(took_us);
                }
                Ok(None) => {
                    self.timing.acl_empty += 1;
                    self.timing.acl_empty_us += took_us;
                    self.timing.acl_empty_max_us = self.timing.acl_empty_max_us.max(took_us);
                }
                Err(_) => {}
            }
            match read {
                Ok(Some(acl)) => match acl.kind {
                    AclKind::FirmwareDump { .. } => {
                        return Err(String::from("the controller firmware crashed (crash dump on the ACL pipe)"));
                    }
                    AclKind::Data { .. } if acl.stored == acl.len => {
                        let packet = &buf[..acl.len];
                        // The keyboard's pairing packets never reach the
                        // host stack (see `uefi_bt::tap`).
                        // (Except on a pairing link, while pairing is offered.)
                        if !self.smp_in.pass_on(packet, self.guard.pairing()) {
                            continue;
                        }
                        // Notifications are the tap's alone: the host stack
                        // has no subscriber for them, and queued unread they
                        // used up its packet pool (OutOfMemory, Nov 2). Its
                        // controller-to-host flow control is off, so nothing
                        // needs acknowledging.
                        if let Some(n) = notification(packet) {
                            self.timing.notifications += 1;
                            self.tap_notification(&n, now);
                        } else {
                            #[cfg(feature = "pairing")]
                            if self.hold_acl(packet) {
                                continue;
                            }
                            self.inbox.push_acl(packet);
                        }
                    }
                    _ => hci.stats.acl_discarded += 1,
                },
                Ok(None) => break,
                Err(e) => return Err(alloc::format!("reading ACL data failed: {e:?}")),
            }
        }
        Ok(())
    }

    fn tap_event(&mut self, event: &[u8], now: u64) {
        let Some(change) = self.tap.on_event(event, self.guard) else { return };
        match change {
            TapEvent::Connected { handle } => {
                info!("keyboard connected (handle {handle:#06x})");
                self.link = Link { connected_ms: now, keys_flowing: false };
                self.shared.encrypted.set(None);
                self.ever_connected = true;
                record::update(|r| {
                    r.connections += 1;
                    r.first_connection_ms.get_or_insert(now);
                    true
                });
                self.timing_due = Some("until connected");
            }
            TapEvent::ConnectFailed { status } => {
                let what = match status {
                    0x02 => "cancelled",
                    0x3E => "the link failed to come up",
                    _ => "error",
                };
                info!("a connection attempt ended without a connection (status {status:#04x}: {what})");
            }
            TapEvent::Encrypted { handle, v2, dropped } => {
                let event = if v2 { "Encryption Change v2, passed on as v1" } else { "Encryption Change v1" };
                info!("keyboard link encrypted with the bonded key ({event})");
                if dropped > 0 {
                    warn!("dropped {dropped} key reports that arrived before the link was encrypted");
                }
                self.shared.encrypted.set(Some(handle));
                record::update(|r| {
                    r.encryption_v2.get_or_insert(v2);
                    r.pre_encryption_dropped += dropped;
                    false
                });
                // Bring the keyboard's LEDs in line with our lock state.
                self.shared.leds.set(Some(self.keyboard.toggles.led_bits()));
                self.replay(now);
            }
            TapEvent::Untrusted { handle } => {
                self.shared.encrypted.set(None);
                self.violation = Some(alloc::format!(
                    "the controller reports the keyboard link ({handle:#06x}) encrypted, but not after a start with the bonded key"
                ));
            }
            #[cfg(feature = "pairing")]
            TapEvent::PairingConnected { handle } => {
                info!("pairing: connected to the device (handle {handle:#06x}); pairing packets pass on this link");
                self.shared.pairing.link_encrypted.set(None);
                self.shared.pairing.failed.set(None);
                self.smp_in.pairing_failed = None;
            }
            #[cfg(feature = "pairing")]
            TapEvent::PairingEncrypted { handle, v2 } => {
                let event = if v2 { "Encryption Change v2, passed on as v1" } else { "Encryption Change v1" };
                info!("pairing: link encrypted with the pairing's key ({event}); no keys from it until the pairing is accepted");
                self.shared.pairing.link_encrypted.set(Some(handle));
            }
            #[cfg(not(feature = "pairing"))]
            TapEvent::PairingConnected { .. } | TapEvent::PairingEncrypted { .. } => {}
            TapEvent::EncryptionOff { .. } => {
                info!("keyboard link no longer encrypted: key reports are dropped until it is again");
                self.shared.encrypted.set(None);
                self.keyboard.release_all();
            }
            TapEvent::Disconnected { reason, dropped, .. } => {
                info!("keyboard disconnected (reason {reason:#04x}) after {} key reports", self.reports);
                if dropped > 0 {
                    warn!("{dropped} key reports arrived on that connection before it was encrypted, and were dropped");
                }
                self.shared.encrypted.set(None);
                #[cfg(feature = "pairing")]
                self.shared.pairing.link_encrypted.set(None);
                self.keyboard.release_all();
                record::update(|r| {
                    r.disconnects += 1;
                    r.last_disconnect_reason = Some(reason);
                    r.pre_encryption_dropped += dropped;
                    true
                });
                self.timing_due = Some("while connected");
            }
        }
    }

    /// One event from the controller, before anything else sees it: the
    /// answer to LE Rand gets random bytes of the driver's own mixed in,
    /// and while pairing is offered, advertising reports show which
    /// keyboards are in pairing mode.
    #[cfg(feature = "pairing")]
    fn pairing_event(&mut self, event: &mut [u8], now: u64) {
        let p = &self.shared.pairing;
        if !p.offered.get() {
            return;
        }
        if uefi_bt::tap::mix_le_rand(event, &self.pairing.rng.array()) {
            self.pairing.le_rand_mixed += 1;
            if self.pairing.le_rand_mixed == 4 {
                info!(
                    "pairing: the host stack's random seed is the controller's LE Rand mixed with the driver's own random bytes ({})",
                    if self.pairing.rng.cpu { "from the CPU, and the TPM and firmware if they have any" } else { "no CPU source: time stamps only" }
                );
            }
        }
        if !p.over.get() && p.found.borrow_mut().on_event(event, now) {
            let found = p.found.borrow();
            if let Some(c) = found.best(now, 0) {
                info!(
                    "pairing: heard {} ({}): {}",
                    addr_text(&c.addr),
                    if c.random { "random" } else { "public" },
                    c.name.as_deref().map_or_else(|| String::from("a keyboard in pairing mode"), |n| alloc::format!("\"{n}\""))
                );
            }
        }
    }

    /// Events and data come through different USB pipes, so data the
    /// keyboard sent after an event can arrive before it. Once a pairing's
    /// key has gone to the controller, the keyboard's own keys follow the
    /// encryption at once, and the host stack takes them only after the
    /// Encryption Change (TrouBLE 0.8 fails the pairing otherwise: seen
    /// with the emulated keyboard on Nov 15). So data from the pairing
    /// link is kept back from the encryption's start until the event has
    /// been passed on. `true`: kept.
    #[cfg(feature = "pairing")]
    fn hold_acl(&mut self, packet: &[u8]) -> bool {
        let Some(link) = self.guard.pairing_start() else { return false };
        let Some(&[h0, h1]) = packet.first_chunk::<2>() else { return false };
        if u16::from_le_bytes([h0, h1]) & 0x0FFF != link || self.shared.pairing.link_encrypted.get() == Some(link) {
            return false;
        }
        // Encryption that never comes ends the link; this is only a bound.
        if self.pairing.held_acl.len() >= 32 {
            return false;
        }
        self.pairing.held_acl.push(packet.to_vec());
        true
    }

    /// Pass the kept data on, now that the event it had to follow is in
    /// the host stack's queue; drop it if the link is gone.
    #[cfg(feature = "pairing")]
    fn release_held_acl(&mut self) {
        if self.pairing.held_acl.is_empty() {
            return;
        }
        match self.guard.pairing_start() {
            Some(link) if self.shared.pairing.link_encrypted.get() == Some(link) => {
                info!("pairing: {} data packets had come before the Encryption Change: passed on after it", self.pairing.held_acl.len());
                for packet in self.pairing.held_acl.drain(..) {
                    self.inbox.push_acl(&packet);
                }
            }
            Some(_) => {}
            None => self.pairing.held_acl.clear(),
        }
    }

    /// The tick's part of a pairing: accept its result if the tap agrees,
    /// and (loaded from a shell) show how it is going.
    #[cfg(feature = "pairing")]
    fn pairing_tick(&mut self, now: u64) {
        let shared = self.shared;
        let p = &shared.pairing;
        if !p.offered.get() {
            return;
        }
        // A Pairing Failed in either direction, for the session.
        if p.failed.get().is_none() && self.tap.pairing() {
            let ours = self.guard.pairing_failed().map(|reason| (true, reason));
            p.failed.set(ours.or(self.smp_in.pairing_failed.map(|reason| (false, reason))));
        }
        let result = p.result.borrow_mut().take();
        if let Some(new) = result {
            let accepted = self.accept_pairing(new, now);
            p.verdict.set(Some(accepted));
        }
        if config().is_some_and(|c| c.from_shell) {
            let stage = p.stage.borrow().clone();
            if stage != self.pairing.shown {
                screen::line(&stage);
                self.pairing.shown = stage;
            }
        }
    }

    /// The host stack reports a pairing that authenticated the device and
    /// left a bond. It counts if the controller reported this very link
    /// encrypted after the pairing's key went to it (the tap's word).
    #[cfg(feature = "pairing")]
    fn accept_pairing(&mut self, new: pair::NewBond, now: u64) -> bool {
        let shared = self.shared;
        if self.tap.conn() != Some(new.handle) || shared.pairing.link_encrypted.get() != Some(new.handle) {
            error!("pairing: the host stack reports a pairing on a link the controller didn't report encrypted with its key: refused");
            return false;
        }
        if !self.tap.accept_pairing(self.guard, BondKey::new(new.ediv, new.rand, new.ltk)) {
            error!("pairing: the link isn't a pairing link the controller reported encrypted: refused");
            return false;
        }
        let bond = ExportedBond {
            peer: new.peer,
            peer_is_random: new.peer_is_random,
            adapter: self.adapter,
            ltk: new.ltk,
            // BlueZ's key types: authenticated legacy, authenticated P-256.
            ltk_type: if new.secure_connections { 3 } else { 1 },
            enc_size: 16,
            ediv: new.ediv,
            rand: u64::from_le_bytes(new.rand),
        };
        info!(
            "paired with \"{}\" by passkey ({}): {}",
            new.name,
            if new.secure_connections { "LE Secure Connections" } else { "LE legacy pairing" },
            bond.summary()
        );
        if bondstore::store_paired(&bond) {
            info!("the new bond is stored in a variable the OS can't read; it is used from the next boot on");
        } else {
            error!("the new bond couldn't be stored: it works at this boot only");
        }
        hand_off_bond(&bond, &mut self.pairing.rng);
        // The new keyboard, on this very link.
        shared.keyboard.set(Some((new.peer, new.peer_is_random)));
        shared.layout.set(None);
        cache::forget();
        shared.encrypted.set(Some(new.handle));
        shared.leds.set(Some(self.keyboard.toggles.led_bits()));
        self.link = Link { connected_ms: now, keys_flowing: false };
        self.ever_connected = true;
        self.pairing.paired = true;
        let outcome = if new.secure_connections { "paired (Secure Connections)" } else { "paired (LE legacy pairing)" };
        record::update(|r| {
            r.pairing = Some(outcome);
            r.bond = Some("paired at this boot");
            r.connections += 1;
            r.first_connection_ms.get_or_insert(now);
            true
        });
        true
    }

    fn tap_notification(&mut self, n: &Notification<'_>, now: u64) {
        let layout = self.shared.layout.get();
        if let (Verdict::Deliver, Some(layout)) = (self.tap.on_notification(n, layout.is_some()), layout) {
            if n.attribute == layout.input {
                self.key_report(layout, n.value, now);
            } else {
                self.other_report(n.attribute, n.value);
            }
        }
    }

    /// Reports that arrived on the encrypted link before the report layout
    /// was known (first discovery, or a layout that changed).
    fn replay(&mut self, now: u64) {
        let Some(layout) = self.shared.layout.get() else { return };
        let Some(replay) = self.tap.take_replay(true) else { return };
        if replay.unencrypted > 0 {
            warn!("insecure-replay-unencrypted: delivering {} key reports from before the link was encrypted", replay.unencrypted);
        }
        info!("replaying {} key reports kept until the keyboard layout was known", replay.reports.len());
        for (attribute, value) in replay.reports {
            if attribute == layout.input {
                self.key_report(layout, &value, now);
            } else {
                self.other_report(attribute, &value);
            }
        }
        if replay.overflowed {
            // A dropped release would leave a key held and repeating: let
            // everything go; the keyboard's next report has the true state.
            warn!("too many key reports during connection setup; some were dropped");
            let shared = self.shared;
            self.keyboard.report(0, &[], now, &mut |e| deliver(shared, e));
        }
    }

    /// A notification that isn't the keyboard report (battery level, media
    /// keys, vendor reports): ignored, but the first few per handle are
    /// logged, since some keyboards send F-keys as media keys.
    fn other_report(&mut self, attribute: u16, value: &[u8]) {
        const PER_HANDLE: u8 = 3;
        let logged = match self.other_reports.iter_mut().find(|(h, _)| *h == attribute) {
            Some((_, n)) => n,
            None => {
                if self.other_reports.len() >= 16 {
                    return;
                }
                self.other_reports.push((attribute, 0));
                &mut self.other_reports.last_mut().unwrap().1
            }
        };
        if *logged >= PER_HANDLE {
            return;
        }
        *logged += 1;
        let mut hex = String::new();
        for b in value.iter().take(8) {
            let _ = write!(hex, " {b:02x}");
        }
        let more = if value.len() > 8 { " ..." } else { "" };
        info!("report on handle {attribute:#06x} ignored (not the keyboard report):{hex}{more}");
    }

    fn key_report(&mut self, layout: session::Layout, value: &[u8], now: u64) {
        let Some((modifiers, held)) = layout.report.decode(value) else {
            warn!("key report of {} bytes doesn't match the layout", value.len());
            return;
        };
        self.reports += 1;
        record::update(|r| {
            r.key_reports += 1;
            let first = r.first_keys_ms.is_none();
            r.first_keys_ms.get_or_insert(now);
            first
        });
        if !self.link.keys_flowing {
            self.link.keys_flowing = true;
            info!("first key report decoded {} ms after the keyboard connected", now.saturating_sub(self.link.connected_ms));
            self.timing_due = Some("connection setup");
        }
        let shared = self.shared;
        let suspects = self.keyboard.suspect_lost_releases;
        self.keyboard.report(modifiers, &held, now, &mut |e| deliver(shared, e));
        if self.keyboard.suspect_lost_releases > suspects {
            warn!(
                "a key that had repeated for over {}.{} s stopped only when another key was pressed: its release report \
                 was probably lost ({} so far)",
                uefi_bt::keymap::LOST_RELEASE_HINT_MS / 1000,
                uefi_bt::keymap::LOST_RELEASE_HINT_MS % 1000 / 100,
                self.keyboard.suspect_lost_releases
            );
        }
    }

    /// Poll the host stack until it has nothing left to do this tick.
    fn poll_session(&mut self) -> Result<(), String> {
        let Some(future) = self.future.as_mut() else { return Ok(()) };
        let mut context = Context::from_waker(Waker::noop());
        let mut idle_polls = 0;
        let mut finished = false;
        for _ in 0..64 {
            let writes = self.inbox.writes();
            if future.as_mut().poll(&mut context).is_ready() {
                finished = true;
                break;
            }
            if self.inbox.is_empty() && self.inbox.writes() == writes {
                idle_polls += 1;
                if idle_polls >= 2 {
                    break;
                }
            } else {
                idle_polls = 0;
            }
        }
        if finished {
            self.future = None;
            return Err(String::from("the host stack stopped"));
        }
        Ok(())
    }

    fn fail(&mut self, why: &str) {
        error!("{why}; giving the controller back");
        record::failed(clock::now_ms(), why);
        self.shutdown(true);
    }

    /// Give the controller back: disconnect the keyboard (so it reconnects
    /// to the OS at once), HCI_Reset, Bluetooth function off; with `recover`,
    /// the MT7922 subsystem reset if it doesn't answer.
    /// One line on the timer and USB behaviour since the last one.
    fn log_timing(&mut self, at: &str) {
        let t = core::mem::take(&mut self.timing);
        let mut line = String::new();
        let _ = write!(line, "timing ({at}): {} ticks, gaps up to {}", t.ticks, Ms(t.max_gap_us));
        if t.acl_empty > 0 {
            let avg = t.acl_empty_us / u64::from(t.acl_empty);
            let _ = write!(line, "; ACL reads {} empty (avg {}, max {})", t.acl_empty, Ms(avg), Ms(t.acl_empty_max_us));
        }
        if t.acl_data > 0 {
            let _ = write!(line, ", {} with data (max {}), {} notifications", t.acl_data, Ms(t.acl_data_max_us), t.notifications);
        }
        // What the host stack sent: GATT requests and their like. With the
        // data read above it tells a keyboard that stopped answering from a
        // host stack that stopped asking.
        if let Some(sent) = self.hci.try_borrow().ok().map(|hci| u64::from(hci.stats.acl_out)) {
            let _ = write!(line, "; {} ACL sent", sent.saturating_sub(self.acl_sent_logged));
            self.acl_sent_logged = sent;
        }
        // Reads that would have lost a packet before Nov 3 (lost key
        // releases): cumulative, and only when there are any.
        if let Some(pipe) = self.hci.try_borrow().ok().map(|hci| hci.acl_pipe_report()).filter(|r| !r.is_empty()) {
            let _ = write!(line, "; ACL pipe so far: {pipe}");
        }
        let _ = write!(line, "; {} events", t.events);
        if let Some(p) = self.hci.try_borrow().ok().and_then(|hci| hci.pipe_stats()) {
            let _ = write!(line, " (pipe: up to {} bytes waiting, {} overflows, {} errors)", p.max_buffered, p.overflows, p.errors);
        }
        let dropped = self.inbox.dropped();
        if dropped > 0 {
            let _ = write!(line, "; {dropped} packets dropped from the host stack's inbox");
        }
        let smp = self.smp_in.dropped + self.guard.smp_dropped();
        if smp > 0 {
            let _ = write!(line, "; {smp} pairing (SMP) packets dropped");
        }
        info!("{line}");
        // Keep measuring tick gaps across the line.
        self.timing.last_tick_us = t.last_tick_us;
    }

    fn shutdown(&mut self, recover: bool) {
        if self.handed_off {
            return;
        }
        self.log_timing("at hand-off");
        self.handed_off = true;
        self.dead = true;
        if let Some(timer) = &self.timer {
            let _ = boot::set_timer(timer, TimerTrigger::Cancel);
        }
        self.keyboard.release_all();
        // No encryption can be started with the bonded key after this.
        self.guard.wipe();
        let smp = self.smp_in.dropped + self.guard.smp_dropped();
        record::update(|r| {
            r.smp_dropped = smp;
            false
        });
        let Ok(mut hci) = self.hci.try_borrow_mut() else {
            error!("the controller is in use; not handing it back");
            return;
        };
        if let Some(handle) = self.tap.conn() {
            info!("disconnecting the keyboard (handle {handle:#06x})");
            let [lo, hi] = handle.to_le_bytes();
            // HCI_Disconnect, reason 0x15: remote device terminated (power off).
            let _ = hci.send_command(&[0x06, 0x04, 0x03, lo, hi, 0x15]);
            let _ = hci.drain(50, 500);
        }
        app::hand_off(&mut hci, recover);
        hci.stop_event_pipe();
        info!("controller handed back ({} key reports this session)", self.reports);
        #[cfg(feature = "pairing")]
        if self.pairing.paired {
            // The host stack made this boot's pairing keys, and the OS
            // gets boot services memory as it is: nothing of the stack
            // runs any more, so its memory is overwritten.
            drop(hci);
            self.future = None;
            for (start, len) in self.pairing.stack_memory {
                // SAFETY: the two leaked allocations of `start_driver`;
                // the only code that used them was the future just
                // dropped.
                unsafe { uefi_bt::bond::wipe_bytes(core::slice::from_raw_parts_mut(start, len)) };
            }
            info!("the host stack's memory was wiped (it held the pairing's keys)");
        }
    }
}

// ---------------------------------------------------------------------------
// Leaving: the OS starts, or the machine resets
// ---------------------------------------------------------------------------

fn watch_lifecycle() {
    // SAFETY: notify functions with the right signatures, no context.
    let before = unsafe {
        boot::create_event_ex(
            EventType::NOTIFY_SIGNAL,
            Tpl::CALLBACK,
            Some(before_exit_boot_services),
            None,
            Some(&BEFORE_EXIT_BOOT_SERVICES),
        )
    };
    if before.is_err() {
        warn!("no BeforeExitBootServices event group: the controller can't be handed back before an OS starts");
    }
    // Fallback if the firmware never signals the group: just stop running.
    // SAFETY: as above.
    let _ = unsafe { boot::create_event(EventType::SIGNAL_EXIT_BOOT_SERVICES, Tpl::NOTIFY, Some(exit_boot_services), None) };
    register_reset_notify();
    #[cfg(feature = "pairing")]
    if config().is_some_and(|c| c.pairing.is_some() && !c.from_shell) {
        // SAFETY: a notify function with the right signature, no context.
        let ready = unsafe { boot::create_event_ex(EventType::NOTIFY_SIGNAL, Tpl::CALLBACK, Some(ready_to_boot), None, Some(&READY_TO_BOOT)) };
        if ready.is_err() {
            warn!("no ReadyToBoot event group: the boot can't be made to wait for a pairing");
        }
    }
}

/// The boot waited for a pairing already (ReadyToBoot comes once per boot
/// option tried).
#[cfg(feature = "pairing")]
static HELD: AtomicBool = AtomicBool::new(false);

/// The boot manager is about to start a boot option. With pairing on
/// offer, this is where the boot waits: the screen is up, and whatever is
/// started next should find the keyboard working.
#[cfg(feature = "pairing")]
unsafe extern "efiapi" fn ready_to_boot(_event: Event, _context: Option<NonNull<c_void>>) {
    if EXITED.load(Ordering::Acquire) || HELD.swap(true, Ordering::AcqRel) {
        return;
    }
    hold_for_pairing();
    dlog::flush(false);
}

/// Wait for a pairing: up to the configured time for one to begin, and
/// then for as long as it is under way (it has limits of its own). The
/// driver's timer can't fire while this runs at its level, so the tick is
/// called from here.
#[cfg(feature = "pairing")]
fn hold_for_pairing() {
    use pair::Stage;
    let Some(cfg) = config() else { return };
    let Some(why) = cfg.pairing else { return };
    let Some(shared) = STATE.with(|state| state.as_ref().filter(|d| !d.dead).map(|d| d.shared)) else {
        info!("pairing: no controller was started, so there is nothing to wait for");
        return;
    };
    let p = &shared.pairing;
    if p.over.get() {
        return;
    }
    if !screen::available() {
        warn!("pairing: no console to show a passkey on: not offered at this boot");
        p.end();
        return;
    }
    // Keys typed before this screen was there (at the firmware's own
    // prompt, say) don't end the wait.
    for _ in 0..64 {
        if !screen::key_pressed() {
            break;
        }
    }
    let started = clock::now_ms();
    info!("pairing: the boot waits up to {} s for a keyboard in pairing mode", cfg.pair_wait_ms / 1000);
    p.go.set(true);
    let mut deadline = started + cfg.pair_wait_ms;
    let mut drawn: Option<Stage> = None;
    let mut shown_s = u64::MAX;
    let mut leave_at: Option<u64> = None;
    loop {
        let alive = STATE.with(|state| match state {
            Some(d) if !d.dead => {
                d.tick();
                !d.dead
            }
            _ => false,
        });
        dlog::flush(false);
        if !alive || POWER_OFF.load(Ordering::Acquire) {
            break;
        }
        let now = clock::now_ms();
        let stage = p.stage.borrow().clone();
        // A pairing under way is waited for.
        if p.busy.get() {
            deadline = deadline.max(now + 3000);
        }
        let left = deadline.saturating_sub(now).div_ceil(1000);
        let ending = matches!(stage, Stage::Paired { .. } | Stage::Over);
        if drawn.as_ref() != Some(&stage) {
            screen::draw(&stage, why, (!ending).then_some(left));
            drawn = Some(stage);
            shown_s = left;
        } else if left != shown_s && !ending {
            screen::countdown(left);
            shown_s = left;
        }
        if ending {
            // Long enough to be read.
            match leave_at {
                None => leave_at = Some(now + 2500),
                Some(at) if now >= at => break,
                Some(_) => {}
            }
        } else if now >= deadline {
            info!("pairing: no keyboard was paired in time");
            p.end();
        } else if screen::key_pressed() {
            info!("pairing: a key on another keyboard ended the wait");
            p.end();
        }
        boot::stall(Duration::from_millis(2));
    }
    info!("pairing: the boot goes on after {} ms", clock::now_ms() - started);
}

unsafe extern "efiapi" fn before_exit_boot_services(_event: Event, _context: Option<NonNull<c_void>>) {
    info!(
        "an OS is starting (ExitBootServices, {} ms after the CPU reset; {} USB interfaces appeared after loading)",
        clock::since_reset_ms(),
        USB_SEEN.load(Ordering::Relaxed)
    );
    STATE.with(|state| {
        if let Some(d) = state {
            d.shutdown(true);
        }
    });
    unregister_reset_notify();
    safety::clear();
    wipe_secrets();
    let now = clock::now_ms();
    record::update(|r| {
        r.os_started_ms = Some(now);
        true
    });
    record::write_now(now);
    dlog::flush(true);
}

/// Overwrite the driver's copy of the link key: the OS gets boot services
/// memory as it is. (The guard wipes its own copy at the hand-off.)
fn wipe_secrets() {
    let cfg = CONFIG.load(Ordering::Acquire);
    if !cfg.is_null() {
        // SAFETY: the leaked Config; nothing holds a reference into its
        // bond while this runs (the tick is at the same TPL, so not now).
        if let Some(bond) = unsafe { (*core::ptr::addr_of_mut!((*cfg).bond)).as_mut() } {
            bond.wipe();
        }
    }
}

unsafe extern "efiapi" fn exit_boot_services(_event: Event, _context: Option<NonNull<c_void>>) {
    // No memory or USB work allowed here; the timer can't fire any more.
    EXITED.store(true, Ordering::Release);
}

fn register_reset_notify() {
    let Ok(handle) = boot::get_handle_for_protocol::<uefi::proto::misc::ResetNotification>() else {
        warn!("no reset notification protocol: the controller isn't handed back before a reset");
        return;
    };
    let Ok(mut protocol) = open_get::<uefi::proto::misc::ResetNotification>(handle) else { return };
    let raw: *mut ResetNotificationProtocol = (&mut *protocol as *mut uefi::proto::misc::ResetNotification).cast();
    // Keep the protocol pointer for unregistering; the firmware's protocol
    // outlives us, so not closing the GET_PROTOCOL open is harmless.
    core::mem::forget(protocol);
    // SAFETY: a valid protocol; `on_reset` has the ResetSystem signature.
    let status = unsafe { ((*raw).register_reset_notify)(raw, on_reset) };
    if status.is_success() {
        RESET_NOTIFY.store(raw, Ordering::Release);
    } else {
        warn!("registering for reset notification failed: {status:?}");
    }
}

fn unregister_reset_notify() {
    let raw = RESET_NOTIFY.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !raw.is_null() {
        // SAFETY: the protocol we registered with.
        let _ = unsafe { ((*raw).unregister_reset_notify)(raw, on_reset) };
    }
}

unsafe extern "efiapi" fn on_reset(_reset: ResetType, _status: Status, _size: usize, _data: *const u8) {
    if EXITED.load(Ordering::Acquire) || current_tpl() > Tpl::CALLBACK {
        return;
    }
    info!("the machine is resetting");
    STATE.with(|state| {
        if let Some(d) = state {
            d.shutdown(true);
        }
    });
    // No variable writes here: with them, OVMF's power-off sometimes never
    // happened after this callback returned (Nov 1). The log variable is
    // volatile and would be lost anyway.
}
