#!/usr/bin/env python3
"""The OS side of pairing in firmware: take over the bond the driver made.

A driver built to pair in firmware (BT_KB_FEATURES=pairing) keeps the bond
it makes in a variable the OS can't read. The keyboard holds one key per
host, so the OS needs that very key, and must not pair again. The driver
therefore hands the bond over at every boot, encrypted to a public key it
was built with (BT_KB_HANDOFF_KEY), in the volatile variable BtKbHandOff.
Only the holder of the private key can open it: root, on the installed
system. efivarfs is readable by everyone, and so is the firmware's flash;
neither shows the key.

  bond-handoff.py keygen KEYFILE     make the private key (mode 600) and print
                                     the public one, for BT_KB_HANDOFF_KEY
  bond-handoff.py pubkey KEYFILE     print the public key of a private one
  bond-handoff.py open KEYFILE [--var FILE] --out FILE.bond
                                     decrypt BtKbHandOff into a bond file as
                                     export-bond.sh writes them (mode 600)
  bond-handoff.py import KEYFILE [--var FILE] [--bluez DIR] [--dry-run]
                                     give the bond to BlueZ: write the key into
                                     the keyboard's info file, if it isn't the
                                     one there already (run it before
                                     bluetooth.service starts, as root)
  bond-handoff.py selftest           the format against fixed values

The format (version 1), 147 bytes:
  "BTKBHO1\\0"  8 bytes
  the driver's ephemeral P-256 public key, uncompressed (65 bytes)
  the 42-byte bond record (rust/uefi-bt/src/bond.rs) XOR a key stream
  HMAC-SHA256 over all of the above (32 bytes)
with (key stream, MAC key) = HKDF-SHA256(ECDH x coordinate,
salt = ephemeral key || recipient key, info = "bt-kb-dxe hand-off v1").
ECIES, in other words, from standard parts. The elliptic curve work is
openssl's (the command line tool); the rest is Python's hashlib and hmac.
"""
import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
import tempfile

MAGIC = b"BTKBHO1\0"
INFO = b"bt-kb-dxe hand-off v1"
RECORD_LEN = 42
BLOB_LEN = len(MAGIC) + 65 + RECORD_LEN + 32
VENDOR = "5223227b-ac96-454e-9bca-f15199748a3c"
EFIVAR = f"/sys/firmware/efi/efivars/BtKbHandOff-{VENDOR}"
# SubjectPublicKeyInfo for a P-256 key, up to the point itself.
SPKI_P256 = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


class HandOffError(Exception):
    pass


def openssl(*args, data=None):
    try:
        done = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    except FileNotFoundError:
        raise HandOffError("openssl isn't installed") from None
    if done.returncode != 0:
        raise HandOffError(f"openssl {args[0]} failed: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def public_point(keyfile):
    """The public key of a private key file: 65 bytes, uncompressed."""
    der = openssl("ec", "-in", keyfile, "-pubout", "-outform", "DER")
    if not der.startswith(SPKI_P256) or len(der) != len(SPKI_P256) + 65:
        raise HandOffError(f"{keyfile} isn't a P-256 key")
    return der[len(SPKI_P256):]


def ecdh(keyfile, peer_point):
    """The x coordinate of our private key times the peer's public point.
    openssl refuses a point that isn't on the curve."""
    if len(peer_point) != 65 or peer_point[0] != 4:
        raise HandOffError("not an uncompressed P-256 point")
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(SPKI_P256 + peer_point) + b"-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as tmp:
        peer = os.path.join(tmp, "peer.pem")
        with open(peer, "wb") as f:
            f.write(pem)
        z = openssl("pkeyutl", "-derive", "-inkey", keyfile, "-peerkey", peer)
    if len(z) != 32:
        raise HandOffError("the key agreement gave no 32-byte secret")
    return z


def hkdf(ikm, salt, info, length):
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def keys(z, ephemeral, recipient):
    material = hkdf(z, ephemeral + recipient, INFO, RECORD_LEN + 32)
    return material[:RECORD_LEN], material[RECORD_LEN:]


def seal_with(z, ephemeral, recipient, record):
    """What the driver does, given the shared secret (for tests)."""
    stream, mac_key = keys(z, ephemeral, recipient)
    body = MAGIC + ephemeral + bytes(a ^ b for a, b in zip(record, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()


def open_blob(keyfile, blob):
    """The bond record in a hand-off blob."""
    if len(blob) != BLOB_LEN or not blob.startswith(MAGIC):
        raise HandOffError("not a hand-off (version 1) from bt-kb-dxe")
    ephemeral = blob[len(MAGIC):len(MAGIC) + 65]
    body, tag = blob[:-32], blob[-32:]
    stream, mac_key = keys(ecdh(keyfile, ephemeral), ephemeral, public_point(keyfile))
    if not hmac.compare_digest(tag, hmac.new(mac_key, body, hashlib.sha256).digest()):
        raise HandOffError("the hand-off isn't for this key, or it was changed")
    return bytes(a ^ b for a, b in zip(body[len(MAGIC) + 65:], stream))


def addr_text(raw):
    return ":".join(f"{b:02X}" for b in reversed(raw))


def parse_record(record):
    """A bond record (rust/uefi-bt/src/bond.rs) as export-bond.sh's fields."""
    if len(record) != RECORD_LEN or record[0] != 1:
        raise HandOffError("not a bond record (version 1)")
    return {
        "peer": addr_text(record[1:7]),
        "peer_type": "static" if record[7] else "public",
        "adapter": addr_text(record[8:14]),
        "ltk": record[14:30].hex().upper(),
        "ltk_type": str(record[30]),
        "enc_size": str(record[31]),
        "ediv": str(int.from_bytes(record[32:34], "little")),
        "rand": str(int.from_bytes(record[34:42], "little")),
    }


def bond_file_text(bond):
    order = ["peer", "peer_type", "adapter", "ltk", "ltk_type", "enc_size", "ediv", "rand"]
    return "".join(f"{k}={bond[k]}\n" for k in order) + "irk=\n"


def read_variable(path):
    """The hand-off in a file: the variable as efivarfs shows it (four
    attribute bytes first), as the UEFI shell's `dmpstore -s` saves it
    (inside a record), or by itself."""
    with open(path, "rb") as f:
        data = f.read()
    at = data.find(MAGIC)
    if at < 0:
        raise HandOffError(f"{path} holds no hand-off from bt-kb-dxe")
    return data[at:at + BLOB_LEN]


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


# ----- BlueZ ---------------------------------------------------------------

# Sections of a device's info file that belong to one pairing.
PAIRING_SECTIONS = {"LongTermKey", "PeripheralLongTermKey", "SlaveLongTermKey", "IdentityResolvingKey", "LocalSignatureKey", "RemoteSignatureKey"}
HID_UUID = "00001812-0000-1000-8000-00805f9b34fb"


def info_with_bond(old, bond):
    """A BlueZ info file with this bond as its pairing. Everything else the
    file had stays; a file that doesn't exist yet gets what BlueZ needs to
    know the device as an LE keyboard."""
    sections, order, current = {}, [], None
    for line in (old or "").splitlines():
        m = re.fullmatch(r"\[(.+)\]", line.strip())
        if m:
            current = m.group(1)
            if current not in sections:
                sections[current] = []
                order.append(current)
        elif current is not None and line.strip():
            sections[current].append(line)
    for name in PAIRING_SECTIONS:
        if name in sections:
            del sections[name]
            order.remove(name)
    if "General" not in sections:
        sections["General"] = [
            "Name=Bluetooth keyboard",
            "Appearance=0x03c1",
            f"AddressType={bond['peer_type']}",
            "SupportedTechnologies=LE;",
            "Trusted=false",
            "Blocked=false",
            "WakeAllowed=true",
            f"Services={HID_UUID};",
        ]
        order.insert(0, "General")
    sections["LongTermKey"] = [
        f"Key={bond['ltk']}",
        f"Authenticated={bond['ltk_type']}",
        f"EncSize={bond['enc_size']}",
        f"EDiv={bond['ediv']}",
        f"Rand={bond['rand']}",
    ]
    order.append("LongTermKey")
    return "".join(f"[{name}]\n" + "".join(l + "\n" for l in sections[name]) + "\n" for name in order)


def current_key(info):
    """(Key, EDiv, Rand) of the [LongTermKey] section, or None."""
    found, inside = {}, False
    for line in (info or "").splitlines():
        line = line.strip()
        if line.startswith("["):
            inside = line == "[LongTermKey]"
        elif inside and "=" in line:
            k, v = line.split("=", 1)
            found[k] = v
    if "Key" not in found:
        return None
    return (found["Key"].upper(), found.get("EDiv", "0"), found.get("Rand", "0"))


def import_bond(bond, bluez, dry_run):
    """Returns a line about what was done."""
    directory = os.path.join(bluez, bond["adapter"], bond["peer"])
    path = os.path.join(directory, "info")
    old = None
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            old = f.read()
    if current_key(old) == (bond["ltk"], bond["ediv"], bond["rand"]):
        return f"BlueZ already has this bond for {bond['peer']}: nothing to do"
    if not os.path.isdir(os.path.join(bluez, bond["adapter"])):
        raise HandOffError(f"BlueZ has no adapter {bond['adapter']} under {bluez}: the bond belongs to another controller")
    what = "replace the key BlueZ has" if current_key(old) else ("add the key to the device BlueZ knows" if old else "make the device known to BlueZ")
    if dry_run:
        return f"would {what} for {bond['peer']} ({path})"
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if old is not None:
        write_private(path + ".before-handoff", old)
    write_private(path + ".new", info_with_bond(old, bond))
    os.replace(path + ".new", path)
    return f"done: {what} for {bond['peer']} ({path}); bluetoothd reads it when it starts"


# ----- Commands ------------------------------------------------------------

def selftest():
    # RFC 5869, test case 1.
    okm = hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", okm.hex()
    # The same fixed values as the driver's test (rust/uefi-bt/src/handoff.rs).
    record = bytes(range(1, RECORD_LEN + 1))
    z = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698")
    ephemeral = bytes.fromhex(
        "0420b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6"
        "dc809c49652aeb6d63329abf5a52155c766345c28fed3024741c8ed01589d28b"
    )
    recipient = bytes.fromhex(
        "041ea1f0f01faf1d9609592284f19e4c0047b58afd8615a69f559077b22faaa190"
        "4c55f33e429dad377356703a9ab85160472d1130e28e36765f89aff915b1214a"
    )
    blob = seal_with(z, ephemeral, recipient, record)
    assert len(blob) == BLOB_LEN
    print("known answer: " + hashlib.sha256(blob).hexdigest())
    # A round trip through openssl, with a key made for it.
    with tempfile.TemporaryDirectory() as tmp:
        ours, theirs = os.path.join(tmp, "ours.pem"), os.path.join(tmp, "theirs.pem")
        for path in (ours, theirs):
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)
        z = ecdh(theirs, public_point(ours))
        bond = bytes([1]) + bytes(range(0x10, 0x10 + RECORD_LEN - 1))
        blob = seal_with(z, public_point(theirs), public_point(ours), bond)
        assert open_blob(ours, blob) == bond
        for i in (0, 8, 80, 120, BLOB_LEN - 1):
            bad = bytearray(blob)
            bad[i] ^= 1
            try:
                open_blob(ours, bytes(bad))
            except HandOffError:
                continue
            raise AssertionError(f"a changed byte {i} went unnoticed")
        try:
            open_blob(theirs, blob)
            raise AssertionError("another key opened it")
        except HandOffError:
            pass
        # As efivarfs and as dmpstore -s have it.
        for wrapped in (b"\x06\x00\x00\x00" + blob, b"\x18\x00\x00\x00\x93\x00\x00\x00B\x00t\x00" + blob + b"\x00" * 4):
            path = os.path.join(tmp, "var")
            with open(path, "wb") as f:
                f.write(wrapped)
            assert open_blob(ours, read_variable(path)) == bond
    # The BlueZ file.
    parsed = parse_record(bytes([1, 0x01, 0, 0, 0, 0, 0xC0, 1, 0x02, 0, 0, 0, 0, 0x02]) + bytes(range(16)) + bytes([1, 16, 0x34, 0x12]) + (1311768467463790320).to_bytes(8, "little"))
    assert parsed["peer"] == "C0:00:00:00:00:01" and parsed["adapter"] == "02:00:00:00:00:02" and parsed["ediv"] == "4660", parsed
    assert parsed["ltk"] == "000102030405060708090A0B0C0D0E0F" and parsed["rand"] == "1311768467463790320"
    old = "[General]\nName=Keys\nAddressType=static\n\n[LongTermKey]\nKey=FF\nEDiv=1\nRand=2\n\n[IdentityResolvingKey]\nKey=AA\n\n[DeviceID]\nSource=2\n"
    new = info_with_bond(old, parsed)
    assert "Name=Keys" in new and "[DeviceID]\nSource=2" in new and "IdentityResolvingKey" not in new and "Key=FF" not in new, new
    assert current_key(new) == (parsed["ltk"], "4660", "1311768467463790320")
    assert current_key(old) == ("FF", "1", "2")
    fresh = info_with_bond(None, parsed)
    assert f"Services={HID_UUID};" in fresh and "AddressType=static" in fresh and current_key(fresh) is not None
    with tempfile.TemporaryDirectory() as tmp:
        try:
            import_bond(parsed, tmp, False)
            raise AssertionError("imported for an adapter BlueZ doesn't have")
        except HandOffError:
            pass
        os.makedirs(os.path.join(tmp, parsed["adapter"]))
        assert import_bond(parsed, tmp, True).startswith("would make the device known")
        assert import_bond(parsed, tmp, False).startswith("done: make the device known")
        assert "nothing to do" in import_bond(parsed, tmp, False)
        path = os.path.join(tmp, parsed["adapter"], parsed["peer"], "info")
        assert os.stat(path).st_mode & 0o777 == 0o600
        changed = dict(parsed, ltk="AB" * 16)
        assert import_bond(changed, tmp, False).startswith("done: replace the key")
        assert current_key(open(path).read())[0] == "AB" * 16
        assert current_key(open(path + ".before-handoff").read())[0] == parsed["ltk"]
    print("selftest passed")


def main(argv):
    def option(name, default=None):
        if name in argv:
            i = argv.index(name)
            value = argv[i + 1]
            del argv[i:i + 2]
            return value
        return default

    def flag(name):
        if name in argv:
            argv.remove(name)
            return True
        return False

    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    try:
        if command == "selftest":
            selftest()
            return 0
        var = option("--var", EFIVAR)
        out = option("--out")
        bluez = option("--bluez", "/var/lib/bluetooth")
        dry_run = flag("--dry-run")
        if len(argv) != 3:
            print(__doc__, file=sys.stderr)
            return 2
        keyfile = argv[2]
        if command == "keygen":
            if os.path.exists(keyfile):
                raise HandOffError(f"{keyfile} exists already: a new key would lock out a driver built for the old one")
            os.makedirs(os.path.dirname(os.path.abspath(keyfile)), mode=0o700, exist_ok=True)
            old_mask = os.umask(0o077)
            try:
                openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyfile)
            finally:
                os.umask(old_mask)
            os.chmod(keyfile, 0o600)
            print(public_point(keyfile).hex())
        elif command == "pubkey":
            print(public_point(keyfile).hex())
        elif command in ("open", "import"):
            if not os.path.exists(var):
                print(f"no hand-off at {var}: the driver made none at this boot (no bond paired in firmware, or not built for a key)")
                return 0 if command == "import" else 1
            bond = parse_record(open_blob(keyfile, read_variable(var)))
            if command == "open":
                if not out:
                    raise HandOffError("open needs --out FILE.bond: the key doesn't go to the terminal")
                write_private(out, bond_file_text(bond))
                print(f"bond for {bond['peer']} on {bond['adapter']} written to {out} (mode 600)")
            else:
                print(import_bond(bond, bluez, dry_run))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except HandOffError as e:
        print(f"bond-handoff: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(list(sys.argv)))
