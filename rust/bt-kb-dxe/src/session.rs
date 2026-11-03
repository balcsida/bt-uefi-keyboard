//! The host-stack side: TrouBLE runs in this future, polled by the driver's
//! timer. It keeps the keyboard connected and encrypted, discovers its HID
//! service (or checks the layout remembered from an earlier boot, see
//! `cache`), and writes LED changes. Key reports do not pass through
//! here: the driver reads them straight off the HCI link (`uefi_bt::link`),
//! which also catches the ones that arrive while this side is still busy.

use alloc::string::String;
use core::cell::Cell;
use core::convert::Infallible;

use bt_hci::controller::ExternalController;
use embassy_futures::select::{select, Either};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use trouble_host::prelude::*;
use uefi_bt::embassy::InboxTransport;
use uefi_bt::hid::{find_keyboard_report, KeyboardReport};

pub type Ctrl = ExternalController<InboxTransport<'static>, 10>;
pub type Pool = DefaultPacketPool;

const UUID_HID_SERVICE: u16 = 0x1812;
const UUID_REPORT_MAP: u16 = 0x2A4B;
const UUID_REPORT: u16 = 0x2A4D;
const REPORT_TYPE_INPUT: u8 = 1;
const REPORT_TYPE_OUTPUT: u8 = 2;

/// Where the keys are: found once per driver start, used by the tick.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Value handle of the keyboard input report.
    pub input: u16,
    pub report: KeyboardReport,
}

/// Shared between this future and the timer tick (both run at TPL_CALLBACK,
/// one after the other, so `Cell` is enough).
#[derive(Default)]
pub struct Shared {
    pub layout: Cell<Option<Layout>>,
    /// LED byte waiting to be written to the keyboard.
    pub leds: Cell<Option<u8>>,
    /// The connection the controller reported encrypted (the driver's tap
    /// sees every HCI event), whatever the host stack made of the report.
    pub encrypted: Cell<Option<u16>>,
}

/// How long the session trusts the host stack to register an encryption
/// the controller already reported, before going on without it.
const HOST_ENCRYPTION_GRACE: Duration = Duration::from_millis(500);

/// Attribute handles found by discovery (or remembered from an earlier
/// boot), reused on every reconnect.
#[derive(Clone, Copy)]
pub struct Found {
    /// The input report's notification switch (CCCD).
    pub cccd: u16,
    /// The LED output report, if the keyboard has one.
    pub output: Option<u16>,
    /// The input report's Report Reference descriptor.
    pub reference: u16,
    pub layout: Layout,
    /// Checked against the keyboard since the driver started.
    pub verified: bool,
}

/// `remembered`: the layout from an earlier boot, already in `shared`.
pub async fn run(stack: &'static Stack<'static, Ctrl, Pool>, shared: &'static Shared, keyboard: Address, remembered: Option<Found>) {
    let mut runner = stack.runner();
    let central = stack.central();
    match select(runner.run(), keep_connected(stack, central, shared, keyboard, remembered)).await {
        Either::First(result) => log::error!("host stack stopped: {result:?}"),
        Either::Second(never) => match never {},
    }
}

async fn keep_connected(
    stack: &'static Stack<'static, Ctrl, Pool>,
    mut central: Central<'static, Ctrl, Pool>,
    shared: &'static Shared,
    keyboard: Address,
    remembered: Option<Found>,
) -> Infallible {
    let accept = [keyboard];
    let config = ConnectConfig {
        scan_config: ScanConfig { filter_accept_list: &accept, ..ScanConfig::default() },
        connect_params: RequestedConnParams {
            min_connection_interval: Duration::from_millis(15),
            max_connection_interval: Duration::from_millis(30),
            max_latency: 0,
            min_event_length: Duration::from_secs(0),
            max_event_length: Duration::from_secs(0),
            supervision_timeout: Duration::from_secs(4),
        },
    };
    let mut found: Option<Found> = remembered;
    let mut failures: u64 = 0;
    loop {
        log::info!("waiting for the keyboard to connect (press a key on it)");
        let conn = match central.connect(&config).await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("connecting failed: {e:?}");
                Timer::after(Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut encrypted = false;
        let result = connected(stack, &conn, shared, &mut found, &mut encrypted).await;
        match &result {
            Ok(reason) => log::info!("keyboard disconnected: {reason}"),
            Err(e) => log::warn!("keyboard session ended: {e}"),
        }
        if conn.is_connected() {
            conn.disconnect();
            let _ = with_timeout(Duration::from_secs(3), async {
                loop {
                    if let ConnectionEvent::Disconnected { .. } = conn.next().await {
                        break;
                    }
                }
            })
            .await;
        }
        drop(conn);
        // A link that carried keys ends normally (the keyboard's idle
        // timeout, say): wait for the next key press at once, since the
        // keyboard keeps presses for the reconnection. Backing off is only
        // for links that never worked (on Nov 2 a 4-6 s pause here, after
        // every 10 s session, held keys back that long).
        let usable = encrypted && shared.layout.get().is_some();
        failures = if result.is_ok() || usable { 0 } else { failures + 1 };
        if failures > 0 {
            Timer::after(Duration::from_secs(1 << (failures - 1).min(3))).await;
        }
    }
}

/// How the session learned that the link is encrypted with the bonded key.
/// Always from the driver's tap; the host stack may or may not agree.
enum Encryption {
    /// The tap saw it, and the host stack registered it too.
    Host,
    /// Only the tap saw it: the host stack didn't register it.
    ControllerOnly,
}

/// Wait until the link is encrypted with the bonded key. Connection
/// parameter requests are kept in `params` and answered by the caller
/// afterwards: answering means waiting on HCI commands and an L2CAP reply,
/// and nothing may hold up this loop meanwhile.
///
/// Only the driver's tap decides: the controller reported this connection
/// encrypted, after LE Enable Encryption with the bonded key
/// (`uefi_bt::tap`). The host stack's word alone doesn't count, as TrouBLE
/// 0.8 reports a resumed bond the way it reports a fresh pairing: its
/// central pairing machine waits for the bonded encryption, ends in Success
/// and sends PairingComplete with the stored bond (then Encrypted). A fresh
/// pairing can't get past the tap: its SMP packets are dropped, and LE
/// Enable Encryption with a new key is refused. If the host stack reports
/// an encryption the tap doesn't confirm, the session ends.
async fn wait_encrypted(
    stack: &'static Stack<'static, Ctrl, Pool>,
    conn: &Connection<'static, Pool>,
    shared: &'static Shared,
    params: &mut Option<ConnectionParamsRequest>,
) -> Result<Encryption, String> {
    let handle = conn.handle().raw();
    let mut reported_at: Option<Instant> = None;
    let mut host_at: Option<Instant> = None;
    loop {
        if host_at.is_none() && conn.security_level().is_ok_and(|level| level != SecurityLevel::NoEncryption) {
            host_at = Some(Instant::now());
        }
        let tap = shared.encrypted.get() == Some(handle);
        match (host_at, tap) {
            (Some(_), true) => return Ok(Encryption::Host),
            (Some(at), false) if at.elapsed() >= HOST_ENCRYPTION_GRACE => {
                return Err(String::from(
                    "the host stack reports an encryption the driver didn't see with the bonded key",
                ));
            }
            (None, true) => {
                let at = *reported_at.get_or_insert_with(Instant::now);
                if at.elapsed() >= HOST_ENCRYPTION_GRACE {
                    return Ok(Encryption::ControllerOnly);
                }
            }
            _ => {}
        }
        match select(conn.next(), Timer::after(Duration::from_millis(20))).await {
            Either::First(event) => match event {
                // A resumed bond, as TrouBLE reports it; the tap decides.
                ConnectionEvent::Encrypted { .. } | ConnectionEvent::PairingComplete { .. } => {
                    host_at.get_or_insert_with(Instant::now);
                }
                ConnectionEvent::PairingFailed(e) => return Err(alloc::format!("encryption failed: {e:?}")),
                ConnectionEvent::BondLost => return Err(String::from("the keyboard rejected the stored key")),
                ConnectionEvent::Disconnected { reason } => return Err(alloc::format!("disconnected: {reason:?}")),
                ConnectionEvent::RequestConnectionParams(req) => {
                    if let Some(older) = params.replace(req) {
                        let _ = older.reject(stack).await;
                    }
                }
                _ => {}
            },
            Either::Second(()) => {}
        }
    }
}

/// Trouble with GATT on a link whose keys already work (they come through
/// the driver's tap, with the known layout): keep the link and answer its
/// connection events, rather than drop it and the keys typed meanwhile.
/// LED updates stay off until the next connection.
async fn keep_link(
    stack: &'static Stack<'static, Ctrl, Pool>,
    conn: &Connection<'static, Pool>,
    shared: &'static Shared,
    why: String,
) -> Result<String, String> {
    if shared.layout.get().is_none() {
        return Err(why);
    }
    log::warn!("{why}; keeping the link: keys still work, LED updates are off until it reconnects");
    Ok(watch(stack, conn).await)
}

/// One connection, from encryption to disconnection. `Ok` carries the
/// disconnect reason. `encrypted` is set once the link is encrypted.
async fn connected(
    stack: &'static Stack<'static, Ctrl, Pool>,
    conn: &Connection<'static, Pool>,
    shared: &'static Shared,
    found: &mut Option<Found>,
    encrypted: &mut bool,
) -> Result<String, String> {
    conn.request_security().map_err(|e| alloc::format!("requesting encryption failed: {e:?}"))?;
    let mut params = None;
    let how = match with_timeout(Duration::from_secs(10), wait_encrypted(stack, conn, shared, &mut params)).await {
        Ok(result) => result?,
        Err(_) => return Err(String::from("no encryption within 10 s")),
    };
    *encrypted = true;
    match how {
        Encryption::Host => log::info!("encryption confirmed by the host stack"),
        Encryption::ControllerOnly => log::warn!(
            "the host stack didn't register the encryption the controller reported; going on without it"
        ),
    }
    if let Some(req) = params.take() {
        let _ = req.accept(None, stack).await;
    }

    let client = match GattClient::<Ctrl, Pool, 8>::new(stack, conn).await {
        Ok(client) => client,
        Err(e) => return keep_link(stack, conn, shared, alloc::format!("starting the GATT client failed: {e:?}")).await,
    };
    // Layout check (or discovery) and the notification switch.
    let setup = async {
        if let Some(f) = found.as_mut().filter(|f| !f.verified) {
            if still_matches(&client, f).await? {
                log::info!("the remembered keyboard layout still matches");
                f.verified = true;
            } else {
                // Keys already decoded with it can't be taken back; the
                // tick stashes new ones until discovery is done.
                log::warn!("the keyboard's layout changed since it was remembered: discovering it again");
                shared.layout.set(None);
                *found = None;
                crate::cache::forget();
            }
        }
        let f = match *found {
            Some(f) => f,
            None => {
                let f = match with_timeout(Duration::from_secs(30), discover(&client)).await {
                    Ok(result) => result?,
                    Err(_) => return Err(String::from("discovery took longer than 30 s")),
                };
                log::info!("keyboard input report at {:#06x}: {:?}", f.layout.input, f.layout.report);
                shared.layout.set(Some(f.layout));
                *found = Some(f);
                crate::cache::store(&f);
                f
            }
        };
        notifications_on(&client, f.cccd).await?;
        Ok(f)
    };
    let session = async {
        match setup.await {
            Ok(f) => match select(watch(stack, conn), leds(&client, f.output, shared)).await {
                Either::First(reason) => Ok(reason),
                Either::Second(never) => match never {},
            },
            // The GATT client keeps running here, so ATT traffic still flows.
            Err(why) => keep_link(stack, conn, shared, why).await,
        }
    };
    match select(client.task(), session).await {
        Either::First(result) => match result {
            Err(BleHostError::BleHost(Error::Disconnected)) => Ok(String::from("link lost")),
            other => keep_link(stack, conn, shared, alloc::format!("GATT client stopped: {other:?}")).await,
        },
        Either::Second(result) => result,
    }
}

/// Is the remembered input report still where it was? Its Report Reference
/// must still say "input report, this ID". `Err` if the link failed.
async fn still_matches(client: &GattClient<'_, Ctrl, Pool, 8>, f: &Found) -> Result<bool, String> {
    let mut value = [0u8; 2];
    match client.read_handle(f.reference, &mut value).await {
        Ok(2) => Ok(value[1] == REPORT_TYPE_INPUT && f.layout.report.report_id.is_none_or(|id| id == value[0])),
        Ok(_) | Err(BleHostError::BleHost(Error::Att(_))) => Ok(false),
        Err(e) => Err(alloc::format!("checking the remembered layout failed: {e:?}")),
    }
}

/// Connection events until the link goes: accept parameter requests.
async fn watch(stack: &'static Stack<'static, Ctrl, Pool>, conn: &Connection<'static, Pool>) -> String {
    loop {
        match conn.next().await {
            ConnectionEvent::Disconnected { reason } => return alloc::format!("{reason:?}"),
            ConnectionEvent::RequestConnectionParams(req) => {
                let _ = req.accept(None, stack).await;
            }
            _ => {}
        }
    }
}

/// Write LED changes requested by the tick (Caps/Num/Scroll Lock).
async fn leds(client: &GattClient<'_, Ctrl, Pool, 8>, output: Option<u16>, shared: &'static Shared) -> Infallible {
    loop {
        Timer::after(Duration::from_millis(30)).await;
        if let (Some(bits), Some(output)) = (shared.leds.take(), output) {
            if let Err(e) = client.write_handle_without_response(output, &[bits]).await {
                log::warn!("writing the LED report failed: {e:?}");
            }
        }
    }
}

/// Make sure the keyboard notifies key reports to this host. The keyboard
/// stores this per bonded host (and Linux already turned it on), so it is
/// written only if it is off.
async fn notifications_on(client: &GattClient<'_, Ctrl, Pool, 8>, cccd: u16) -> Result<(), String> {
    let mut value = [0u8; 2];
    let on = matches!(client.read_handle(cccd, &mut value).await, Ok(2) if value[0] & 1 != 0);
    if !on {
        log::info!("turning keyboard report notifications on");
        client.write_handle(cccd, &[1, 0]).await.map_err(|e| alloc::format!("turning notifications on failed: {e:?}"))?;
    }
    Ok(())
}

/// HID service: Report Map layout, the keyboard input report and its LED
/// output report.
async fn discover(client: &GattClient<'_, Ctrl, Pool, 8>) -> Result<Found, String> {
    let services = client
        .services_by_uuid(&Uuid::new_short(UUID_HID_SERVICE))
        .await
        .map_err(|e| alloc::format!("HID service discovery failed: {e:?}"))?;
    let service = services.first().ok_or_else(|| String::from("the keyboard has no HID service"))?;
    let chars = client
        .characteristics::<32>(service)
        .await
        .map_err(|e| alloc::format!("characteristic discovery failed: {e:?}"))?;

    let map = chars
        .iter()
        .find(|c| c.uuid == Uuid::new_short(UUID_REPORT_MAP))
        .ok_or_else(|| String::from("no Report Map"))?;
    let mut buf = [0u8; 1024];
    let len = client.read_handle(map.handle, &mut buf).await.map_err(|e| alloc::format!("reading the Report Map failed: {e:?}"))?;
    let report: KeyboardReport =
        find_keyboard_report(&buf[..len]).ok_or_else(|| String::from("no keyboard input report in the Report Map"))?;

    let mut input: Option<(u16, u16, u16)> = None;
    let mut output = None;
    for c in chars.iter().filter(|c| c.uuid == Uuid::new_short(UUID_REPORT)) {
        // The Report Reference descriptor: first handle after the value
        // that isn't the CCCD. Value: [report ID][report type].
        let Some(reference) = (c.handle + 1..=c.end_handle).find(|&h| Some(h) != c.cccd_handle) else { continue };
        let mut value = [0u8; 2];
        if !matches!(client.read_handle(reference, &mut value).await, Ok(2)) {
            continue;
        }
        let same_id = report.report_id.is_none_or(|id| id == value[0]);
        match (value[1], c.cccd_handle) {
            (REPORT_TYPE_INPUT, Some(cccd)) if same_id && input.is_none() => input = Some((c.handle, cccd, reference)),
            (REPORT_TYPE_OUTPUT, _) if same_id && output.is_none() => output = Some(c.handle),
            _ => {}
        }
    }
    let (input, cccd, reference) =
        input.ok_or_else(|| String::from("no notifying Report characteristic for the keyboard input report"))?;
    Ok(Found { cccd, output, reference, layout: Layout { input, report }, verified: true })
}
