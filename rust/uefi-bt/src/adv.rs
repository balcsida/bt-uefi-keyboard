//! What a scan hears, for pairing in firmware: LE Advertising Report
//! events, and which advertiser is a keyboard in pairing mode.
//!
//! Everything here comes from the air, from whoever is in range: it is
//! parsed defensively, names are reduced to printable ASCII before they
//! can reach a screen, and "a keyboard in pairing mode" means no more
//! than "claims to be one". What the claim is worth is decided by the
//! pairing itself.

use alloc::string::String;
use alloc::vec::Vec;

/// Connectable undirected advertising.
pub const ADV_IND: u8 = 0x00;
pub const SCAN_RSP: u8 = 0x04;

const UUID_HID_SERVICE: u16 = 0x1812;
const APPEARANCE_HID: u16 = 0x03C0;
const APPEARANCE_KEYBOARD: u16 = 0x03C1;
const FLAG_LIMITED_DISCOVERABLE: u8 = 0x01;
const FLAG_GENERAL_DISCOVERABLE: u8 = 0x02;

/// One advertising report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<'a> {
    pub kind: u8,
    /// 0 public, 1 random; 2 and 3 are addresses the controller resolved.
    pub addr_type: u8,
    /// Least significant byte first.
    pub addr: [u8; 6],
    pub data: &'a [u8],
    pub rssi: i8,
}

/// The reports in one HCI event (header included); none if it isn't an LE
/// Advertising Report, and only those before the first malformed one.
pub fn reports(event: &[u8]) -> Reports<'_> {
    match event {
        [0x3E, len, 0x02, count, rest @ ..] if usize::from(*len) == rest.len() + 2 => Reports { left: *count, rest },
        _ => Reports { left: 0, rest: &[] },
    }
}

pub struct Reports<'a> {
    left: u8,
    rest: &'a [u8],
}

impl<'a> Iterator for Reports<'a> {
    type Item = Report<'a>;

    fn next(&mut self) -> Option<Report<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        // Event type, address type, address (6), data length, data, RSSI.
        let (head, rest) = self.rest.split_first_chunk::<9>().or_else(|| {
            self.left = 0;
            None
        })?;
        let len = usize::from(head[8]);
        if len > 31 || rest.len() < len + 1 {
            self.left = 0;
            return None;
        }
        self.rest = &rest[len + 1..];
        Some(Report { kind: head[0], addr_type: head[1], addr: head[2..8].try_into().unwrap(), data: &rest[..len], rssi: rest[len] as i8 })
    }
}

/// What advertising data says about its sender.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdInfo {
    pub flags: Option<u8>,
    pub name: Option<String>,
    pub appearance: Option<u16>,
    /// The HID service is among its 16-bit service UUIDs.
    pub hid: bool,
}

/// A device name for a screen and a log: printable ASCII, 32 characters
/// at most. Whatever else was sent becomes `?`.
pub fn printable_name(raw: &[u8]) -> String {
    raw.iter().take(32).map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '?' }).collect::<String>().trim().into()
}

/// Parse advertising or scan response data: length, type, value, repeated.
pub fn parse_ad(mut data: &[u8]) -> AdInfo {
    let mut info = AdInfo::default();
    while let [len, rest @ ..] = data {
        let len = usize::from(*len);
        if len == 0 || len > rest.len() {
            break;
        }
        let (kind, value) = (rest[0], &rest[1..len]);
        match kind {
            0x01 if !value.is_empty() => info.flags = Some(value[0]),
            0x02 | 0x03 => info.hid |= value.chunks_exact(2).any(|u| u16::from_le_bytes([u[0], u[1]]) == UUID_HID_SERVICE),
            0x08 | 0x09 if !value.is_empty() => info.name = Some(printable_name(value)),
            0x19 if value.len() >= 2 => info.appearance = Some(u16::from_le_bytes([value[0], value[1]])),
            _ => {}
        }
        data = &rest[len..];
    }
    info
}

/// Whether an address can be bonded with: a public one, or a random
/// static one. Private addresses change, and the driver doesn't resolve
/// them.
pub fn bondable_address(addr_type: u8, addr: &[u8; 6]) -> bool {
    match addr_type {
        0 => true,
        1 => addr[5] >> 6 == 0b11,
        _ => false,
    }
}

/// A report from a device that says it is a keyboard in pairing mode:
/// connectable, discoverable (the user pressed its pairing button), and
/// a HID device that is, or may be, a keyboard.
pub fn claims_pairable_keyboard(report: &Report<'_>, ad: &AdInfo) -> bool {
    let discoverable = ad.flags.is_some_and(|f| f & (FLAG_LIMITED_DISCOVERABLE | FLAG_GENERAL_DISCOVERABLE) != 0);
    let keyboard = match ad.appearance {
        Some(APPEARANCE_KEYBOARD) => true,
        Some(APPEARANCE_HID) | None => ad.hid,
        // A mouse, a gamepad, something else entirely.
        Some(_) => false,
    };
    report.kind == ADV_IND && discoverable && keyboard && bondable_address(report.addr_type, &report.addr)
}

/// Why an advertiser that looks like a keyboard isn't taken for one in
/// pairing mode. `None` if it is taken, or doesn't look like a keyboard.
/// For the log: a pairing that never starts shouldn't be a riddle.
pub fn why_not_pairable(report: &Report<'_>, ad: &AdInfo) -> Option<&'static str> {
    let looks_like_one = ad.hid || matches!(ad.appearance, Some(APPEARANCE_HID | APPEARANCE_KEYBOARD));
    if !looks_like_one || report.kind == SCAN_RSP || claims_pairable_keyboard(report, ad) {
        return None;
    }
    Some(if report.kind != ADV_IND {
        "it takes no connections"
    } else if !ad.flags.is_some_and(|f| f & (FLAG_LIMITED_DISCOVERABLE | FLAG_GENERAL_DISCOVERABLE) != 0) {
        "it is not in pairing mode (not discoverable)"
    } else if !bondable_address(report.addr_type, &report.addr) {
        "it uses a private address"
    } else {
        "it says it is another kind of device"
    })
}

/// A keyboard that could be paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub addr: [u8; 6],
    pub random: bool,
    pub rssi: i8,
    pub name: Option<String>,
    pub last_seen_ms: u64,
}

/// The candidates a scan has found so far.
#[derive(Debug, Default)]
pub struct Candidates {
    list: Vec<Candidate>,
}

impl Candidates {
    /// More advertisers than this aren't tracked: anyone can send as many
    /// addresses as they like.
    pub const LIMIT: usize = 8;

    /// Feed one HCI event. `true` if a candidate appeared, or one got its
    /// name.
    pub fn on_event(&mut self, event: &[u8], now_ms: u64) -> bool {
        let mut news = false;
        for report in reports(event) {
            let ad = parse_ad(report.data);
            let known = self.list.iter_mut().find(|c| c.addr == report.addr && u8::from(c.random) == report.addr_type);
            match known {
                Some(c) => {
                    // Its scan response, or more of its advertising.
                    if report.kind == ADV_IND || report.kind == SCAN_RSP {
                        c.rssi = report.rssi;
                        c.last_seen_ms = now_ms;
                    }
                    if c.name.is_none() && ad.name.is_some() {
                        c.name = ad.name;
                        news = true;
                    }
                }
                None if claims_pairable_keyboard(&report, &ad) => {
                    if self.list.len() >= Self::LIMIT {
                        // The one not heard from for longest makes room.
                        let Some(oldest) = self.list.iter().enumerate().min_by_key(|(_, c)| c.last_seen_ms).map(|(i, _)| i) else { continue };
                        self.list.swap_remove(oldest);
                    }
                    self.list.push(Candidate { addr: report.addr, random: report.addr_type == 1, rssi: report.rssi, name: ad.name, last_seen_ms: now_ms });
                    news = true;
                }
                None => {}
            }
        }
        news
    }

    /// The candidate to pair with: the strongest of those heard within the
    /// last `fresh_ms`. The nearest keyboard is usually the loudest; an
    /// attacker can be louder, which is why the choice decides nothing.
    pub fn best(&self, now_ms: u64, fresh_ms: u64) -> Option<&Candidate> {
        self.list.iter().filter(|c| now_ms.saturating_sub(c.last_seen_ms) <= fresh_ms).max_by_key(|c| c.rssi)
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn clear(&mut self) {
        self.list.clear();
    }

    /// Forget one (a pairing with it failed for good).
    pub fn remove(&mut self, addr: &[u8; 6], random: bool) {
        self.list.retain(|c| !(c.addr == *addr && c.random == random));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const KBD: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x00, 0xC0];
    /// Flags (limited discoverable), appearance keyboard, HID service.
    const PAIRING_AD: [u8; 11] = [2, 0x01, 0x05, 3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18];

    fn event(kind: u8, addr_type: u8, addr: [u8; 6], data: &[u8], rssi: i8) -> Vec<u8> {
        let mut e = vec![0x3E, 0, 0x02, 1, kind, addr_type];
        e.extend_from_slice(&addr);
        e.push(data.len() as u8);
        e.extend_from_slice(data);
        e.push(rssi as u8);
        e[1] = (e.len() - 2) as u8;
        e
    }

    fn name_ad(name: &[u8]) -> Vec<u8> {
        let mut ad = vec![name.len() as u8 + 1, 0x09];
        ad.extend_from_slice(name);
        ad
    }

    #[test]
    fn reports_are_parsed() {
        let e = event(ADV_IND, 1, KBD, &PAIRING_AD, -55);
        let all: Vec<Report> = reports(&e).collect();
        assert_eq!(all, [Report { kind: ADV_IND, addr_type: 1, addr: KBD, data: &PAIRING_AD, rssi: -55 }]);
        let ad = parse_ad(all[0].data);
        assert_eq!(ad, AdInfo { flags: Some(0x05), name: None, appearance: Some(0x03C1), hid: true });
        assert!(claims_pairable_keyboard(&all[0], &ad));
        // Two reports in one event.
        let mut two = e.clone();
        two.extend_from_slice(&event(SCAN_RSP, 1, KBD, &name_ad(b"Keys"), -60)[4..]);
        two[1] = (two.len() - 2) as u8;
        two[3] = 2;
        let all: Vec<Report> = reports(&two).collect();
        assert_eq!(all.len(), 2);
        assert_eq!(parse_ad(all[1].data).name.as_deref(), Some("Keys"));
        // Other events, and other LE events, have none.
        assert_eq!(reports(&[0x0E, 4, 1, 0x0C, 0x20, 0]).count(), 0);
        assert_eq!(reports(&[0x3E, 4, 0x01, 0, 0, 2]).count(), 0);
    }

    #[test]
    fn malformed_reports_end_the_event() {
        let good = event(ADV_IND, 1, KBD, &PAIRING_AD, -55);
        // Truncated anywhere: nothing, and no panic.
        for cut in 4..good.len() {
            let mut e = good[..cut].to_vec();
            e[1] = (e.len() - 2) as u8;
            assert_eq!(reports(&e).count(), 0, "cut at {cut}");
        }
        // A length byte that disagrees with the event.
        let mut e = good.clone();
        e[1] += 1;
        assert_eq!(reports(&e).count(), 0);
        // More reports claimed than there are.
        let mut e = good.clone();
        e[3] = 3;
        assert_eq!(reports(&e).count(), 1);
        // Data longer than advertising data can be.
        let mut e = event(ADV_IND, 1, KBD, &[0; 31], -55);
        e[12] = 32;
        assert_eq!(reports(&e).count(), 0);
        // Advertising data whose lengths run past its end.
        assert_eq!(parse_ad(&[5, 0x09, b'a']), AdInfo::default());
        assert_eq!(parse_ad(&[0, 0x09, b'a']), AdInfo::default());
        assert_eq!(parse_ad(&[2, 0x01, 0x06, 9]), AdInfo { flags: Some(6), ..AdInfo::default() });
    }

    #[test]
    fn names_are_made_printable() {
        assert_eq!(printable_name(b"  Ergonomic Keyboard "), "Ergonomic Keyboard");
        assert_eq!(printable_name(b"a\x1b[2Jb\r\n\x00\xff"), "a?[2Jb????");
        assert_eq!(printable_name(&[b'x'; 80]).len(), 32);
    }

    #[test]
    fn what_counts_as_a_keyboard_in_pairing_mode() {
        let check = |kind: u8, addr_type: u8, addr: [u8; 6], data: &[u8]| {
            let e = event(kind, addr_type, addr, data, -50);
            let r = reports(&e).next().unwrap();
            claims_pairable_keyboard(&r, &parse_ad(r.data))
        };
        assert!(check(ADV_IND, 1, KBD, &PAIRING_AD));
        // General discoverable; HID service without an appearance; a
        // public address.
        assert!(check(ADV_IND, 0, [1, 2, 3, 4, 5, 6], &[2, 0x01, 0x06, 3, 0x03, 0x12, 0x18]));
        // An appearance of "keyboard" without the service list.
        assert!(check(ADV_IND, 1, KBD, &[2, 0x01, 0x05, 3, 0x19, 0xC1, 0x03]));
        // Not discoverable: a bonded keyboard reconnecting, not one in
        // pairing mode.
        assert!(!check(ADV_IND, 1, KBD, &[2, 0x01, 0x04, 3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18]));
        assert!(!check(ADV_IND, 1, KBD, &[3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18]));
        // Directed, scannable, non-connectable advertising; a scan response.
        for kind in [1, 2, 3, SCAN_RSP] {
            assert!(!check(kind, 1, KBD, &PAIRING_AD));
        }
        // A mouse; a heart rate sensor.
        assert!(!check(ADV_IND, 1, KBD, &[2, 0x01, 0x05, 3, 0x19, 0xC2, 0x03, 3, 0x03, 0x12, 0x18]));
        assert!(!check(ADV_IND, 1, KBD, &[2, 0x01, 0x06, 3, 0x03, 0x0D, 0x18]));
        // Private addresses (resolvable, non-resolvable) and addresses the
        // controller resolved.
        assert!(!check(ADV_IND, 1, [1, 0, 0, 0, 0, 0x40], &PAIRING_AD));
        assert!(!check(ADV_IND, 1, [1, 0, 0, 0, 0, 0x00], &PAIRING_AD));
        assert!(!check(ADV_IND, 2, KBD, &PAIRING_AD));
    }

    #[test]
    fn why_a_keyboard_is_passed_over() {
        let why = |kind: u8, addr_type: u8, addr: [u8; 6], data: &[u8]| {
            let e = event(kind, addr_type, addr, data, -50);
            let r = reports(&e).next().unwrap();
            why_not_pairable(&r, &parse_ad(r.data))
        };
        // One in pairing mode is taken; a thermometer is nobody's business.
        assert_eq!(why(ADV_IND, 1, KBD, &PAIRING_AD), None);
        assert_eq!(why(ADV_IND, 1, KBD, &[2, 0x01, 0x06, 3, 0x03, 0x09, 0x18]), None);
        // A bonded keyboard reconnecting; one behind a private address;
        // a mouse; a keyboard's beacon; and its scan response says nothing.
        let bonded = [2, 0x01, 0x04, 3, 0x19, 0xC1, 0x03, 3, 0x03, 0x12, 0x18];
        assert_eq!(why(ADV_IND, 1, KBD, &bonded), Some("it is not in pairing mode (not discoverable)"));
        assert_eq!(why(ADV_IND, 1, [1, 0, 0, 0, 0, 0x40], &PAIRING_AD), Some("it uses a private address"));
        assert_eq!(why(ADV_IND, 1, KBD, &[2, 0x01, 0x05, 3, 0x19, 0xC2, 0x03, 3, 0x03, 0x12, 0x18]), Some("it says it is another kind of device"));
        assert_eq!(why(3, 1, KBD, &PAIRING_AD), Some("it takes no connections"));
        assert_eq!(why(SCAN_RSP, 1, KBD, &PAIRING_AD), None);
    }

    #[test]
    fn candidates_are_collected() {
        let mut c = Candidates::default();
        // A bonded keyboard waking up isn't one; a keyboard in pairing
        // mode is, and its scan response names it.
        assert!(!c.on_event(&event(1, 1, KBD, &[], -40), 0));
        assert!(c.on_event(&event(ADV_IND, 1, KBD, &PAIRING_AD, -55), 100));
        assert!(!c.on_event(&event(ADV_IND, 1, KBD, &PAIRING_AD, -57), 200));
        assert!(c.on_event(&event(SCAN_RSP, 1, KBD, &name_ad(b"Emulated Keyboard"), -56), 210));
        assert!(!c.on_event(&event(SCAN_RSP, 1, KBD, &name_ad(b"Another name"), -56), 220));
        let best = c.best(300, 1000).unwrap();
        assert_eq!((best.addr, best.random, best.rssi, best.name.as_deref()), (KBD, true, -56, Some("Emulated Keyboard")));
        // A second, nearer one wins while both are heard.
        let near = [0x02, 0, 0, 0, 0, 0xC0];
        assert!(c.on_event(&event(ADV_IND, 1, near, &PAIRING_AD, -30), 400));
        assert_eq!(c.best(500, 1000).unwrap().addr, near);
        // Not heard from lately: no longer the best, then none at all.
        c.on_event(&event(ADV_IND, 1, KBD, &PAIRING_AD, -55), 2000);
        assert_eq!(c.best(2100, 1000).unwrap().addr, KBD);
        assert!(c.best(9000, 1000).is_none());
        c.remove(&KBD, true);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn a_flood_of_addresses_is_bounded() {
        let mut c = Candidates::default();
        for i in 0..100u8 {
            c.on_event(&event(ADV_IND, 1, [i, 0, 0, 0, 0, 0xC0], &PAIRING_AD, -70), u64::from(i));
        }
        assert_eq!(c.len(), Candidates::LIMIT);
        // The latest are the ones kept.
        assert_eq!(c.best(100, 5).unwrap().addr[0], 99);
    }
}
