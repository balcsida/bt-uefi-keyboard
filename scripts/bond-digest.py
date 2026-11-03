#!/usr/bin/env python3
"""The digest a bt-kb-dxe build pins for a bond (stage 3 of the security
hardening; README, Security).

    python3 -I scripts/bond-digest.py FILE.bond...

Prints one SHA-256 per bond file, the way the driver computes it
(ExportedBond::digest in rust/uefi-bt/src/bond.rs; the two must agree byte
for byte): SHA-256 of "bt-kb-dxe bond v1\\0" and the bond's 42-byte record:

    version 1, peer address (6 bytes, least significant first), peer is
    random (1), adapter address (6, least significant first), LTK (16, as
    BlueZ stores it), key type, key size, EDIV (2, little-endian),
    Rand (8, little-endian)

A digest reveals nothing about the key. scripts/build-rust.sh passes the
digests of qemu/keys/*.bond to the build in BT_KB_BOND_DIGESTS.
"""

import hashlib
import struct
import sys

DOMAIN = b"bt-kb-dxe bond v1\0"


def addr(text):
    parts = text.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        raise ValueError(f"not a Bluetooth address: {text!r}")
    return bytes(int(p, 16) for p in reversed(parts))


def record(fields):
    ltk = bytes.fromhex(fields["ltk"])
    if len(ltk) != 16:
        raise ValueError("ltk is not 16 bytes")
    return (
        bytes([1])
        + addr(fields["peer"])
        + bytes([0 if fields["peer_type"] == "public" else 1])
        + addr(fields["adapter"])
        + ltk
        + bytes([int(fields["ltk_type"]), int(fields["enc_size"])])
        + struct.pack("<HQ", int(fields["ediv"]), int(fields["rand"]))
    )


def parse(text):
    fields = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields.setdefault(key.strip(), value.strip())
    return fields


def main(paths):
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    for path in paths:
        with open(path, encoding="ascii") as f:
            print(hashlib.sha256(DOMAIN + record(parse(f.read()))).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
