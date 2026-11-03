#!/usr/bin/env bash
# Milestone 5: install bt-kb-dxe on this PC's ESP as a UEFI driver that the
# board's firmware loads at every boot (a Driver#### entry), or remove it.
#   sudo scripts/board-install.sh             install, or update after a rebuild
#   sudo scripts/board-install.sh --remove    remove the driver, in two steps (see below)
#   sudo scripts/board-install.sh --remove --force   all at once
#   scripts/board-install.sh --dry-run [...]  print what would be done, change nothing
#
# Files go to \EFI\btkb\ on the ESP (mounted at /boot):
#   - bt-kb-dxe.efi (build it first, as yourself: scripts/build-rust.sh);
#   - the MT7922 firmware image, from linux-firmware: the driver only reads
#     it to ask the chip whether its firmware is loaded, and never uploads;
#   - the keyboard's bond from qemu/keys/ (sudo scripts/export-bond.sh). It
#     holds the keyboard's link key, so it only stays until the next boot:
#     the driver copies it into a variable the OS can't read (BtKbBond, no
#     RUNTIME_ACCESS) and deletes the file. The driver build must trust the
#     bond (scripts/build-rust.sh pins the digests of qemu/keys/*.bond).
#
# Removing takes two steps, since the OS can't delete a variable without
# RUNTIME_ACCESS: the first --remove deletes any bond file and leaves
# bt-kb-dxe.forget, which makes the driver delete its stored bond at the
# next boot; the second, after that boot, removes the entry, the files and
# the other variables (and the diagnostics of scripts/board-diag.sh).
# --force skips the first step; the stored bond then stays in NVRAM until a
# UEFI shell deletes it: dmpstore -d BtKbBond -guid 5223227b-ac96-454e-9bca-f15199748a3c
#
# Secure Boot (stage 2 of the security hardening; README, Security). The
# firmware verifies Driver#### images against db itself, so the driver and
# btlog.efi just need the same kind of signature as the boot loader:
#   - with sbctl's keys (scripts/secureboot-setup.sh), they are signed with
#     `sbctl sign -s`, which records them, so sbctl's pacman hook and
#     `sbctl sign-all` keep re-signing them;
#   - with a db key kept off this machine, set DB_CERT to its certificate
#     and DB_KEY to the key: a file (removable media, say) or a PKCS#11 URI
#     (`pkcs11:...`, a token through sbsign's engine). sbctl doesn't record
#     these files: it can't re-sign without the key;
#   - with Secure Boot on, the install stops unless both files verify
#     against a certificate that is in the firmware's db;
#   - with Secure Boot off, it installs, with a warning.
# The firmware image must be the one the driver build pinned (its SHA-256,
# in bt-kb-dxe.firmware.sha256 next to the build).
#
# If the driver misbehaves at boot:
#   - after 3 starts that neither reach an OS nor run 15 s, it stops loading
#     itself (the BtKbBoots variable; installing again re-enables it);
#   - with the files gone from the ESP, the firmware skips the entry;
#   - --remove undoes everything.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="Bluetooth keyboard (bt-kb-dxe)"
LOADER='\EFI\btkb\bt-kb-dxe.efi'
DEST=/boot/EFI/btkb
DRIVER="$ROOT/rust/target/x86_64-unknown-uefi/release/bt-kb-dxe.efi"
FW_NAME="BT_RAM_CODE_MT7922_1_1_hdr.bin"
FW_SRC="/usr/lib/firmware/mediatek/$FW_NAME.zst"
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
VENDOR=5223227b-ac96-454e-9bca-f15199748a3c
GLOBAL=8be4df61-93ca-11d2-aa0d-00e098032b8c
IMAGE_SECURITY=d719b2cb-3d3a-4596-a3bc-dad00e67656f
SBCTL_KEYS="${SBCTL_KEYS:-/var/lib/sbctl/keys}"

dry=""
mode=install
force=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    --remove) mode=remove ;;
    --force) force=1 ;;
    *) echo "usage: $0 [--dry-run] [--remove [--force]]" >&2; exit 2 ;;
  esac
done

run () {
  if [ -n "$dry" ]; then
    printf '  would run:'; printf ' %q' "$@"; echo
  else
    "$@"
  fi
}

if [ -z "$dry" ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo (or --dry-run to see what it would do)." >&2
  exit 1
fi

read -r esp_src esp_fs < <(findmnt -no SOURCE,FSTYPE /boot)
if [ "$esp_fs" != vfat ]; then
  echo "/boot is $esp_fs, not the FAT ESP; stopping." >&2
  exit 1
fi
esp_name="$(basename "$esp_src")"
disk="/dev/$(lsblk -no PKNAME "$esp_src" | head -1)"
part="$(cat "/sys/class/block/$esp_name/partition")"

# Driver#### entries with our label (efibootmgr prints "Driver0003* label...").
our_entries () {
  efibootmgr -r 2>/dev/null | grep -F "$LABEL" | sed -n 's/^Driver\([0-9A-Fa-f]\{4\}\).*/\1/p' || true
}

remove_entries () {
  local n
  for n in $(our_entries); do
    echo "Removing the Driver$n entry"
    run efibootmgr -q -r -b "$n" -B
  done
}

# A bond file on the ESP: overwritten, then deleted. rm alone leaves the
# key in the FAT's free clusters; vfat has no copy-on-write, so shred's
# overwrite lands in the file's own clusters.
delete_bond_file () {
  echo "Overwriting and deleting $1 (it holds the link key)"
  run shred -u -n 1 -z "$1"
}

# efivarfs marks variables immutable; deleting needs chattr -i first.
delete_variable () {
  local f="$EFIVARS/$1-$VENDOR"
  if [ -e "$f" ]; then
    echo "Deleting the $1 variable"
    run chattr -i "$f"
    run rm -f "$f"
  fi
}

if [ "$mode" = remove ]; then
  marker="$DEST/bt-kb-dxe.forget"
  record="$(tail -c +5 "$EFIVARS/BtKbLastBoot-$VENDOR" 2>/dev/null | tr -cd '[:print:]' || true)"
  installed=""
  if [ -f "$DEST/bt-kb-dxe.efi" ]; then
    installed=1
  elif [ -n "$dry" ] && ! ls /boot/EFI >/dev/null 2>&1; then
    echo "(dry run without sudo: the ESP isn't readable; assuming the driver is installed)"
    installed=1
  fi
  if [ -z "$force" ] && [ -n "$installed" ] && [[ "$record" != *"bond was forgotten"* ]]; then
    for f in "$DEST"/*.bond; do
      [ -e "$f" ] && delete_bond_file "$f"
    done
    if [ -e "$marker" ]; then
      echo "Waiting for the driver: $marker is still there, so it hasn't run since the first --remove."
      echo "Reboot once (with Fast Boot off), then run --remove again; or --remove --force (see the top of this script)."
      exit 1
    fi
    echo "Step 1 of 2: leaving $marker, which makes the driver delete its stored bond at the next boot."
    if [ -n "$dry" ]; then echo "  would run: touch $marker"; else : > "$marker"; fi
    echo "Reboot once, then run: sudo scripts/board-install.sh --remove"
    exit 0
  fi
  [ -n "$force" ] && echo "Removing at once (--force): a bond the driver stored stays in NVRAM until a UEFI shell deletes it."
  [ -e "$marker" ] && run rm -f "$marker"
  "$ROOT/scripts/board-diag.sh" --remove ${dry:+--dry-run}
  remove_entries
  for f in bt-kb-dxe.efi btlog.efi bt-kb-dxe.sealed "$FW_NAME"; do
    [ -e "$DEST/$f" ] && run rm -f "$DEST/$f"
  done
  for f in "$DEST"/*.bond; do
    [ -e "$f" ] && delete_bond_file "$f"
  done
  [ -d "$DEST" ] && run rmdir "$DEST"
  delete_variable BtKbBoots
  delete_variable BtKbGatt
  delete_variable BtKbPanic
  delete_variable BtKbLastBoot
  if [ -n "$dry" ]; then
    echo "(dry run: nothing changed)"
  else
    echo "Removed. The next boot runs without the driver."
  fi
  exit 0
fi

# --- install
sb_on=""
sb="$EFIVARS/SecureBoot-$GLOBAL"
if [ -r "$sb" ] && [ "$(tail -c 1 "$sb" | od -An -tu1 | tr -d ' ')" = 1 ]; then
  sb_on=1
fi

# How the files get signed: an off-machine db key, sbctl's, or not at all.
signer=none
if [ -n "${DB_KEY:-}" ] || [ -n "${DB_CERT:-}" ]; then
  if [ -z "${DB_KEY:-}" ] || [ -z "${DB_CERT:-}" ] || [ ! -r "$DB_CERT" ]; then
    echo "Set both DB_KEY (a key file or a pkcs11: URI) and DB_CERT (a readable certificate)." >&2
    exit 1
  fi
  command -v sbsign >/dev/null || { echo "Signing with DB_KEY needs sbsign (package sbsigntools)." >&2; exit 1; }
  signer=key
  cert="$DB_CERT"
elif command -v sbctl >/dev/null && { [ -f "$SBCTL_KEYS/db/db.key" ] || [ -n "$dry" ]; }; then
  signer=sbctl
  cert="$SBCTL_KEYS/db/db.pem"
fi
if [ -n "$sb_on" ] && [ "$signer" = none ]; then
  echo "Secure Boot is on, but there is no key to sign the driver with: the firmware would refuse it." >&2
  echo "Set up sbctl (scripts/secureboot-setup.sh), or set DB_KEY and DB_CERT. Stopping." >&2
  exit 1
fi

# sign_to SRC OUT: OUT is SRC signed with the chosen key.
sign_to () {
  case "$signer" in
    sbctl) run sbctl sign -o "$2" "$1" ;;
    key)
      if [[ "$DB_KEY" == pkcs11:* ]]; then
        run sbsign --engine pkcs11 --key "$DB_KEY" --cert "$DB_CERT" --output "$2" "$1"
      else
        run sbsign --key "$DB_KEY" --cert "$DB_CERT" --output "$2" "$1"
      fi
      ;;
    none) run cp "$1" "$2" ;;
  esac
}

# Whether a certificate is enrolled in the firmware's db (its DER bytes in
# the db variable's signature lists).
cert_in_db () {
  python3 -I - "$1" "$EFIVARS/db-$IMAGE_SECURITY" <<'PY'
import subprocess, sys
der = subprocess.run(["openssl", "x509", "-in", sys.argv[1], "-outform", "DER"], capture_output=True, check=True).stdout
try:
    db = open(sys.argv[2], "rb").read()
except OSError:
    sys.exit(1)
sys.exit(0 if der and der in db else 1)
PY
}

if [ ! -f "$DRIVER" ]; then
  echo "No driver build at $DRIVER. Build it first (as yourself): scripts/build-rust.sh" >&2
  exit 1
fi
bonds=("$ROOT"/qemu/keys/*.bond)
if [ ! -f "${bonds[0]}" ] || [ "${#bonds[@]}" -ne 1 ]; then
  echo "Need exactly one exported bond in qemu/keys/ (sudo scripts/export-bond.sh)." >&2
  exit 1
fi
if ! grep -qx "$(python3 -I "$ROOT/scripts/bond-digest.py" "${bonds[0]}")" "$(dirname "$DRIVER")/bt-kb-dxe.bonds" 2>/dev/null; then
  echo "The driver build doesn't trust ${bonds[0]##*/} (exported after the build?)." >&2
  echo "Rebuild first, as yourself: scripts/build-rust.sh" >&2
  exit 1
fi
if [ ! -f "$FW_SRC" ]; then
  echo "Firmware image $FW_SRC not found (linux-firmware-mediatek)." >&2
  exit 1
fi
pin="$(cat "$(dirname "$DRIVER")/bt-kb-dxe.firmware.sha256" 2>/dev/null || true)"
if [ "$(zstd -q -d -c "$FW_SRC" | sha256sum | cut -d' ' -f1)" != "$pin" ]; then
  echo "The driver build pins a different firmware image than $FW_SRC (a linux-firmware update?)." >&2
  echo "Rebuild first, as yourself: scripts/build-rust.sh" >&2
  exit 1
fi
if [ -n "$sb_on" ] && [ -z "$dry" ] && ! cert_in_db "$cert"; then
  echo "Secure Boot is on, but $cert isn't in the firmware's db: the firmware would refuse the driver. Stopping." >&2
  exit 1
fi

echo "ESP: $esp_src (disk $disk, partition $part), files in $DEST"
echo "Driver build: $(date -r "$DRIVER" '+%Y-%m-%d %H:%M'), $(stat -c %s "$DRIVER") bytes"
# Signed (and checked) in a staging directory first, so a failure leaves
# the installed files as they were.
stage="$DEST.new"
run rm -rf "$stage"
run mkdir -p "$stage"
LOG_APP="$(dirname "$DRIVER")/bt-kb-log.efi"
sign_to "$DRIVER" "$stage/bt-kb-dxe.efi"
sign_to "$LOG_APP" "$stage/btlog.efi"
if [ "$signer" != none ] && [ -z "$dry" ]; then
  for f in "$stage/bt-kb-dxe.efi" "$stage/btlog.efi"; do
    if ! sbverify --cert "$cert" "$f" >/dev/null 2>&1; then
      echo "$(basename "$f") doesn't verify against $cert after signing. Stopping; nothing installed." >&2
      rm -rf "$stage"
      exit 1
    fi
  done
fi
case "$signer" in
  sbctl) echo "Signed with sbctl's db key" ;;
  key) echo "Signed with the db key from DB_KEY ($DB_CERT)" ;;
  none) echo "WARNING: Secure Boot is off and the driver is unsigned: root can replace it, or the files next to it, and the firmware will run them. See scripts/secureboot-setup.sh." ;;
esac
run mkdir -p "$DEST"
run mv "$stage/bt-kb-dxe.efi" "$DEST/bt-kb-dxe.efi"
run mv "$stage/btlog.efi" "$DEST/btlog.efi"
run rmdir "$stage"
if [ "$signer" = sbctl ]; then
  # Recorded, so sbctl's pacman hook and `sbctl sign-all` re-sign them.
  run sbctl sign -s "$DEST/bt-kb-dxe.efi"
  run sbctl sign -s "$DEST/btlog.efi"
fi
if [ -n "$dry" ]; then
  echo "  would run: zstd -q -d -c $FW_SRC > $DEST/$FW_NAME"
else
  zstd -q -d -c "$FW_SRC" > "$DEST/$FW_NAME"
fi
# The driver uses the first *.bond in its directory: keep exactly one.
for f in "$DEST"/*.bond; do
  [ -e "$f" ] && delete_bond_file "$f"
done
# Sealed to the TPM (scripts/tpm-seal.sh) without a fallback copy: the
# bond file never goes on the ESP; the seal is renewed for the new driver.
sealed_only=""
grep -qx 'fallback=no' "$DEST/bt-kb-dxe.sealed" 2>/dev/null && sealed_only=1
if [ -n "$sealed_only" ]; then
  echo "The bond is sealed to the TPM without a fallback copy (fallback=no): not copying ${bonds[0]##*/}."
else
  run cp "${bonds[0]}" "$DEST/"
  echo "The driver imports the bond at the next boot, then overwrites and deletes ${bonds[0]##*/} on the ESP."
fi
if [ -f "$DEST/bt-kb-dxe.sealed" ]; then
  # The new driver measures differently: predict its PCR 2 now, so the
  # next boot unseals (the event log of this boot shows where it loads).
  echo "Renewing the TPM seal for the new driver:"
  if [ -n "$dry" ]; then
    run "$ROOT/scripts/tpm-seal.sh" --if-needed ${sealed_only:+--no-fallback} --driver "$DEST/bt-kb-dxe.efi"
  elif ! "$ROOT/scripts/tpm-seal.sh" --if-needed ${sealed_only:+--no-fallback} --driver "$DEST/bt-kb-dxe.efi"; then
    echo "WARNING: resealing failed; the next boot falls back to the boot-services copy, if any. Seal after it: sudo scripts/tpm-seal.sh"
  fi
fi
existing="$(our_entries | head -1)"
if [ -n "$existing" ]; then
  # Possibly the full-path entry from scripts/board-diag.sh: the files
  # stay where they were, so the entry still fits.
  echo "Keeping the existing Driver$existing entry"
else
  # A full device path: this board's firmware ignores driver entries with
  # efibootmgr's default short, partition-only path (Nov 2). The firmware's
  # own path, made by the UEFI shell, has the same nodes as Linux's view
  # (PCI 00:01.2/04:00.0, NVMe EUI-64 in sysfs byte order), so efibootmgr
  # should build the same one. If the driver still doesn't start, run
  # scripts/board-diag.sh once: it writes the firmware's own path.
  echo "Adding a Driver#### entry for $LOADER (full device path)"
  run efibootmgr -q -r -c --full-dev-path -d "$disk" -p "$part" -l "$LOADER" -L "$LABEL"
fi
# A driver that switched itself off (BtKbBoots at 3) runs again.
delete_variable BtKbBoots
if [ -z "$dry" ]; then
  echo
  efibootmgr -r
  echo
  echo "Installed. After the next boot into Linux: scripts/board-log.sh"
  [ -f "$DEST/bt-kb-dxe.sealed" ] || echo "To seal the bond to the TPM after that boot (stage 4): sudo scripts/tpm-seal.sh"
fi
