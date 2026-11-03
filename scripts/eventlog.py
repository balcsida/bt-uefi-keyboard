#!/usr/bin/env python3
"""Read a TCG event log (crypto-agile format) and replay PCRs from it.

The log is what Linux shows as /sys/kernel/security/tpm0/binary_bios_measurements
(readable by root only), or what `btlog -eventlog FILE` writes in the UEFI
shell. Nothing here talks to a TPM.

    scripts/eventlog.py show FILE            every event: PCR, type, image path
    scripts/eventlog.py separators FILE      PCRs 0-7 with an EV_SEPARATOR
    scripts/eventlog.py replay FILE PCR [N]  a PCR's SHA-256 value from the log
                                             (from the events before event N)
    scripts/eventlog.py driver FILE [NAME]   where bt-kb-dxe.efi (or NAME) was
                                             loaded, and PCR 7 as it saw it
    scripts/eventlog.py predict FILE PCRS [--spare N] [--driver-hash HEX] [--name NAME]
                                             PCRS (e.g. 2,7) as the driver sees
                                             them, the spare PCR at zero, and
                                             the PolicyPCR digest over them
    scripts/eventlog.py pehash IMAGE         the SHA-256 firmware logs for an
                                             EFI image (its Authenticode hash)

Events are numbered as tpm2_eventlog numbers them: the Spec ID header is
event 0.

`driver` answers the AMI ordering question (does the driver load before the
separators?) and gives the PCR 7 value a TPM policy for the driver must
expect: the replay of every PCR 7 event logged before the driver's own load
event, plus the image authority event that follows it, if any (EDK2 logs
the db entry that verified an image once, next to the image's first load).
"""

import hashlib
import struct
import sys

EV_NO_ACTION = 0x00000003
EV_SEPARATOR = 0x00000004
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0
ALG_SHA256 = 0x000B

NAMES = {
    0x00000000: "EV_PREBOOT_CERT",
    0x00000001: "EV_POST_CODE",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION",
    0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
    0x0000000D: "EV_IPL",
    0x00000012: "EV_NONHOST_INFO",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION",
    0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES",
    0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2",
    0x80000010: "EV_EFI_HCRTM_EVENT",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
    0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
}


class Event:
    def __init__(self, index, pcr, kind, digests, data):
        self.index, self.pcr, self.kind, self.digests, self.data = index, pcr, kind, digests, data
        # As tpm2_eventlog numbers events: the header is event 0.
        self.number = index + 1

    def name(self):
        return NAMES.get(self.kind, f"0x{self.kind:08x}")

    def image_path(self):
        """The file path of an image load event's device path, if any."""
        if self.kind not in (EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_BOOT_SERVICES_APPLICATION) or len(self.data) < 32:
            return None
        (length,) = struct.unpack_from("<Q", self.data, 24)
        path, at, end = [], 32, min(32 + length, len(self.data))
        while at + 4 <= end:
            kind, sub, size = struct.unpack_from("<BBH", self.data, at)
            if size < 4:
                break
            if kind == 4 and sub == 4:  # media device path, file path
                path.append(self.data[at + 4 : at + size].decode("utf-16-le", "replace").rstrip("\0"))
            if kind == 0x7F:
                break
            at += size
        return "".join(path) or None


class Log:
    def __init__(self, data):
        self.events = []
        self.startup_locality = 0
        (size,) = struct.unpack_from("<I", data, 28)
        header = data[32 : 32 + size]
        kind = struct.unpack_from("<I", data, 4)[0]
        if kind != EV_NO_ACTION or header[:16] != b"Spec ID Event03\0":
            raise SystemExit("not a crypto-agile TCG event log (no Spec ID Event03 header)")
        (count,) = struct.unpack_from("<I", header, 24)
        self.sizes = dict(struct.unpack_from("<HH", header, 28 + 4 * i) for i in range(count))
        at = 32 + size
        while at + 12 <= len(data):
            pcr, kind, n = struct.unpack_from("<III", data, at)
            p = at + 12
            if n > 16:
                break
            digests = {}
            try:
                for _ in range(n):
                    (alg,) = struct.unpack_from("<H", data, p)
                    if alg not in self.sizes:
                        raise ValueError
                    digests[alg] = data[p + 2 : p + 2 + self.sizes[alg]]
                    p += 2 + self.sizes[alg]
                (dsize,) = struct.unpack_from("<I", data, p)
            except (ValueError, struct.error):
                break
            if p + 4 + dsize > len(data):
                break
            payload = data[p + 4 : p + 4 + dsize]
            if kind == EV_NO_ACTION and payload[:16] == b"StartupLocality\0" and len(payload) > 16:
                self.startup_locality = payload[16]
            self.events.append(Event(len(self.events), pcr, kind, digests, payload))
            at = p + 4 + dsize

    def replay(self, pcr, until=None):
        value = bytearray(32)
        if pcr == 0:
            value[31] = self.startup_locality
        for e in self.events[:until]:
            if e.pcr != pcr or e.kind == EV_NO_ACTION:
                continue
            if ALG_SHA256 not in e.digests:
                raise SystemExit(f"event {e.number} has no SHA-256 digest")
            value = hashlib.sha256(bytes(value) + e.digests[ALG_SHA256]).digest()
        return bytes(value)

    def separators(self, until=None):
        return sorted({e.pcr for e in self.events[:until] if e.kind == EV_SEPARATOR and e.pcr < 8})

    def driver(self, name):
        """The last load event of an image whose path ends with name."""
        hits = [e for e in self.events if (e.image_path() or "").lower().endswith(name.lower())]
        return hits[-1] if hits else None

    def pcr7_at(self, event):
        """PCR 7 once the image of a load event runs: every PCR 7 event
        before it, plus an authority event right after it."""
        until = event.index + 1
        if until < len(self.events):
            nxt = self.events[until]
            if nxt.pcr == 7 and nxt.kind == EV_EFI_VARIABLE_AUTHORITY:
                until += 1
        return self.replay(7, until)


def pe_hash(data):
    """The Authenticode SHA-256 of a PE image, as firmware measures one
    (EDK2's Tcg2MeasurePeImage): the headers without the checksum and the
    certificate table's directory entry, the sections in file order, then
    anything after them except the certificate table."""
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    coff = pe + 4
    # NumberOfSections, then (after the time stamp and the symbol table's
    # pointer and count) SizeOfOptionalHeader.
    (sections, opt_size) = struct.unpack_from("<H12xH", data, coff + 2)
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    dirs = opt + (112 if magic == 0x20B else 96)
    (ndirs,) = struct.unpack_from("<I", data, dirs - 4)
    (headers,) = struct.unpack_from("<I", data, opt + 60)
    checksum = opt + 64
    h = hashlib.sha256(data[:checksum])
    cert_size = 0
    if ndirs > 4:
        cert = dirs + 4 * 8
        (cert_size,) = struct.unpack_from("<I", data, cert + 4)
        h.update(data[checksum + 4 : cert])
        h.update(data[cert + 8 : headers])
    else:
        h.update(data[checksum + 4 : headers])
    hashed = headers
    raw = []
    for i in range(sections):
        size, ptr = struct.unpack_from("<II", data, opt + opt_size + 40 * i + 16)
        if size:
            raw.append((ptr, size))
    for ptr, size in sorted(raw):
        h.update(data[ptr : ptr + size])
        hashed += size
    if len(data) > hashed + cert_size:
        h.update(data[hashed : len(data) - cert_size])
    return h.digest()


def policy_pcr(pcrs, values):
    """The digest of a lone TPM2_PolicyPCR over PCRS (SHA-256 bank) with
    VALUES in PCR order."""
    bitmap = sum(1 << p for p in pcrs)
    selection = struct.pack(">IHB", 1, ALG_SHA256, 3) + bitmap.to_bytes(4, "little")[:3]
    pcr_digest = hashlib.sha256(b"".join(values)).digest()
    return hashlib.sha256(bytes(32) + struct.pack(">I", 0x17F) + selection + pcr_digest).digest()


def predict(log, pcrs, spare, name, driver_hash):
    """PCRS as the driver sees them while it unseals: every event before
    its load event and the load event itself (with DRIVER_HASH instead of
    the logged digest: the image the next boot runs), plus an authority
    event right after it (PCR 7). The spare PCR must have no events yet."""
    e = log.driver(name)
    if e is None:
        raise SystemExit(f"no load event for {name} in the log: the driver hasn't run this boot")
    until = e.index + 1
    nxt = log.events[until] if until < len(log.events) else None
    authority = nxt is not None and nxt.pcr == 7 and nxt.kind == EV_EFI_VARIABLE_AUTHORITY
    values = {}
    for p in sorted(set(pcrs) | ({spare} if spare is not None else set())):
        if p == spare:
            used = [ev for ev in log.events[:until] if ev.pcr == p and ev.kind != EV_NO_ACTION]
            if used:
                raise SystemExit(f"PCR {p} already has events before the driver (event {used[0].number}): pick another spare PCR")
            values[p] = bytes(32)
            continue
        value = bytearray(32)
        if p == 0:
            value[31] = log.startup_locality
        for ev in log.events[: until + (1 if p == 7 and authority else 0)]:
            if ev.pcr != p or ev.kind == EV_NO_ACTION:
                continue
            digest = driver_hash if (ev is e and driver_hash is not None) else ev.digests.get(ALG_SHA256)
            if digest is None:
                raise SystemExit(f"event {ev.number} has no SHA-256 digest")
            value = hashlib.sha256(bytes(value) + digest).digest()
        values[p] = bytes(value)
    return e, values


def pcr_ranges(pcrs):
    return ", ".join(str(p) for p in pcrs) or "none"


def main(argv):
    if len(argv) < 3 or argv[1] not in ("show", "separators", "replay", "driver", "predict", "pehash"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "pehash":
        with open(argv[2], "rb") as f:
            print(pe_hash(f.read()).hex())
        return 0
    with open(argv[2], "rb") as f:
        log = Log(f.read())
    cmd = argv[1]
    if cmd == "show":
        for e in log.events:
            d = e.digests.get(ALG_SHA256, b"").hex()[:16]
            extra = e.image_path() or ""
            print(f"{e.number:4} PCR {e.pcr:2} {e.name():34} {d} {extra}")
    elif cmd == "separators":
        print(pcr_ranges(log.separators()))
    elif cmd == "replay":
        until = max(int(argv[4]) - 1, 0) if len(argv) > 4 else None
        print(log.replay(int(argv[3]), until).hex())
    elif cmd == "driver":
        name = argv[3] if len(argv) > 3 else "bt-kb-dxe.efi"
        e = log.driver(name)
        if e is None:
            print(f"no load event for {name} in the log", file=sys.stderr)
            return 1
        before = log.separators(e.index)
        after = sorted(set(range(8)) - set(before))
        print(f"load event: {e.number} ({e.name()}, PCR {e.pcr}, {e.image_path()})")
        print(f"separators before the driver: PCRs {pcr_ranges(before)}")
        print(f"separators after the driver:  PCRs {pcr_ranges(after)}")
        print(f"pcr7_at_driver={log.pcr7_at(e).hex()}")
    elif cmd == "predict":
        if len(argv) < 4:
            print(__doc__, file=sys.stderr)
            return 2
        pcrs = [int(p) for p in argv[3].split(",") if p.strip()]
        opts = dict(zip(argv[4::2], argv[5::2]))
        spare = None if opts.get("--spare", "none") == "none" else int(opts["--spare"])
        driver_hash = bytes.fromhex(opts["--driver-hash"]) if "--driver-hash" in opts else None
        e, values = predict(log, pcrs, spare, opts.get("--name", "bt-kb-dxe.efi"), driver_hash)
        before = log.separators(e.index)
        for p in values:
            if p in before and p != spare:
                print(f"note: PCR {p}'s separator comes before the driver, so the OS may see this value too", file=sys.stderr)
        print(f"driver_event={e.number}")
        print(f"driver_logged={e.digests.get(ALG_SHA256, b'').hex()}")
        for p, v in values.items():
            print(f"pcr{p}={v.hex()}")
        print(f"pcrs={','.join(str(p) for p in values)}")
        print(f"pcr_digest={hashlib.sha256(b''.join(values.values())).hexdigest()}")
        print(f"policy={policy_pcr(list(values), list(values.values())).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
