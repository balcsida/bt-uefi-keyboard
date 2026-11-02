#!/usr/bin/env bash
# Milestone 5: install bt-kb-dxe on this PC's ESP as a UEFI driver that the
# board's firmware loads at every boot (a Driver#### entry), or remove it.
#   sudo scripts/board-install.sh             install, or update after a rebuild
#   sudo scripts/board-install.sh --remove    remove the entry, the files and the driver's variables
#                                             (and the diagnostics of scripts/board-diag.sh)
#   scripts/board-install.sh --dry-run [...]  print what would be done, change nothing
#
# Files go to \EFI\btkb\ on the ESP (mounted at /boot):
#   - bt-kb-dxe.efi (build it first, as yourself: scripts/build-rust.sh);
#   - the MT7922 firmware image, from linux-firmware: the driver only reads
#     it to ask the chip whether its firmware is loaded, and never uploads;
#   - the keyboard's bond from qemu/keys/ (sudo scripts/export-bond.sh). It
#     holds the keyboard's link key; /boot is readable by root only.
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

dry=""
mode=install
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    --remove) mode=remove ;;
    *) echo "usage: $0 [--dry-run] [--remove]" >&2; exit 2 ;;
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
  "$ROOT/scripts/board-diag.sh" --remove ${dry:+--dry-run}
  remove_entries
  for f in bt-kb-dxe.efi "$FW_NAME"; do
    [ -e "$DEST/$f" ] && run rm -f "$DEST/$f"
  done
  for f in "$DEST"/*.bond; do
    [ -e "$f" ] && run rm -f "$f"
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
sb="$EFIVARS/SecureBoot-$GLOBAL"
if [ -r "$sb" ] && [ "$(tail -c 1 "$sb" | od -An -tu1 | tr -d ' ')" = 1 ]; then
  echo "Secure Boot is on: the firmware would refuse the unsigned driver. Stopping." >&2
  exit 1
fi
if [ ! -f "$DRIVER" ]; then
  echo "No driver build at $DRIVER. Build it first (as yourself): scripts/build-rust.sh" >&2
  exit 1
fi
bonds=("$ROOT"/qemu/keys/*.bond)
if [ ! -f "${bonds[0]}" ] || [ "${#bonds[@]}" -ne 1 ]; then
  echo "Need exactly one exported bond in qemu/keys/ (sudo scripts/export-bond.sh)." >&2
  exit 1
fi
if [ ! -f "$FW_SRC" ]; then
  echo "Firmware image $FW_SRC not found (linux-firmware-mediatek)." >&2
  exit 1
fi

echo "ESP: $esp_src (disk $disk, partition $part), files in $DEST"
echo "Driver build: $(date -r "$DRIVER" '+%Y-%m-%d %H:%M'), $(stat -c %s "$DRIVER") bytes"
run mkdir -p "$DEST"
run cp "$DRIVER" "$DEST/bt-kb-dxe.efi"
# The diagnostics shell's btlog, if scripts/board-diag.sh put it there:
# kept in step with the driver's log format.
LOG_APP="$(dirname "$DRIVER")/bt-kb-log.efi"
if [ -f "$LOG_APP" ] && { [ -f "$DEST/btlog.efi" ] || [ -n "$dry" ]; }; then
  run cp "$LOG_APP" "$DEST/btlog.efi"
fi
if [ -n "$dry" ]; then
  echo "  would run: zstd -q -d -c $FW_SRC > $DEST/$FW_NAME"
else
  zstd -q -d -c "$FW_SRC" > "$DEST/$FW_NAME"
fi
# The driver uses the first *.bond in its directory: keep exactly one.
for f in "$DEST"/*.bond; do
  [ -e "$f" ] && run rm -f "$f"
done
run cp "${bonds[0]}" "$DEST/"
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
fi
