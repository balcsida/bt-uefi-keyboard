//! Diagnostics for the HCI link: counters, and a ring of the most recent
//! packets (WMT, HCI commands, events, ACL). Advertising reports are only
//! counted so they don't push everything else out. Printed when something
//! goes wrong, so a hang shows the last thing that was sent and received.


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Cmd,
    Event,
    AclIn,
    AclOut,
    WmtOut,
    WmtIn,
    Reg,
    /// An event dropped because the host stack couldn't parse it.
    Dropped,
}

impl Dir {
    fn tag(self) -> &'static str {
        match self {
            Self::Cmd => "hci>",
            Self::Event => "hci<",
            Self::AclIn => "acl<",
            Self::AclOut => "acl>",
            Self::WmtOut => "wmt>",
            Self::WmtIn => "wmt<",
            Self::Reg => "reg ",
            Self::Dropped => "BAD<",
        }
    }
}

const HEAD: usize = 20;
const ENTRIES: usize = 48;

#[derive(Clone, Copy)]
struct Entry {
    ms: u64,
    dir: Dir,
    len: u16,
    head: [u8; HEAD],
}

pub struct Trace {
    entries: [Option<Entry>; ENTRIES],
    next: usize,
    total: u32,
}

impl Default for Trace {
    fn default() -> Self {
        Self::new()
    }
}

impl Trace {
    pub const fn new() -> Self {
        Self { entries: [None; ENTRIES], next: 0, total: 0 }
    }

    pub fn record(&mut self, dir: Dir, data: &[u8]) {
        let mut head = [0u8; HEAD];
        let n = data.len().min(HEAD);
        head[..n].copy_from_slice(&data[..n]);
        self.entries[self.next] = Some(Entry { ms: crate::clock::now_ms(), dir, len: data.len().min(usize::from(u16::MAX)) as u16, head });
        self.next = (self.next + 1) % ENTRIES;
        self.total = self.total.wrapping_add(1);
    }

    /// Oldest first.
    pub fn print(&self) {
        let shown = (self.total as usize).min(ENTRIES);
        crate::say!("  Last {shown} of {} traced packets (ms since start, oldest first):", self.total);
        for i in 0..ENTRIES {
            let Some(e) = self.entries[(self.next + i) % ENTRIES] else { continue };
            let n = usize::from(e.len).min(HEAD);
            let mut line = alloc::string::String::new();
            for b in &e.head[..n] {
                let _ = core::fmt::Write::write_fmt(&mut line, format_args!(" {b:02x}"));
            }
            if usize::from(e.len) > HEAD {
                let _ = core::fmt::Write::write_fmt(&mut line, format_args!(" ... ({} bytes)", e.len));
            }
            crate::say!("    {:7} {}{line}", e.ms, e.dir.tag());
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HciStats {
    pub commands: u32,
    pub events: u32,
    pub adv_reports: u32,
    /// Events dropped because the host stack couldn't parse them.
    pub events_malformed: u32,
    pub acl_in: u32,
    /// ACL packets read and thrown away (draining, or no connections).
    pub acl_discarded: u32,
    pub acl_out: u32,
    /// Crash dump packets seen: the controller firmware has crashed.
    pub fw_dump_packets: u32,
    pub fw_dump_complete: bool,
    pub fw_diag_packets: u32,
    /// Opcode and time of the last HCI command sent.
    pub last_command: Option<(u16, u64)>,
    pub last_event_ms: Option<u64>,
}

impl HciStats {
    pub fn print(&self) {
        crate::say!(
            "  HCI: {} commands, {} events ({} advertising reports), {} ACL in ({} discarded), {} ACL out",
            self.commands, self.events, self.adv_reports, self.acl_in, self.acl_discarded, self.acl_out
        );
        if self.events_malformed > 0 {
            crate::say!("  {} malformed events dropped", self.events_malformed);
        }
        let now = crate::clock::now_ms();
        if let Some((opcode, at)) = self.last_command {
            crate::say!("  Last command {opcode:#06x}, {} ms ago", now.saturating_sub(at));
        }
        match self.last_event_ms {
            Some(at) => crate::say!("  Last event {} ms ago", now.saturating_sub(at)),
            None => crate::say!("  No HCI event received"),
        }
        if self.fw_dump_packets > 0 {
            crate::say!(
                "  CONTROLLER FIRMWARE CRASHED: {} crash dump packets{}",
                self.fw_dump_packets,
                if self.fw_dump_complete { " (dump complete)" } else { "" }
            );
        }
        if self.fw_diag_packets > 0 {
            crate::say!("  {} firmware debug packets", self.fw_diag_packets);
        }
    }
}
