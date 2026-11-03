#!/usr/bin/env bash
# Milestone 5 diagnostics: one boot into a UEFI shell on the board itself,
# to see why the firmware didn't start bt-kb-dxe from its Driver#### entry,
# and to try the driver on the board's own USB stack.
#
#   sudo scripts/board-diag.sh             prepare the next boot
#   sudo scripts/board-diag.sh --collect   afterwards, in Linux: results to board/diag-<time>/
#   sudo scripts/board-diag.sh --remove    remove the shell, its scripts, results and boot entry
#   scripts/board-diag.sh --dry-run [...]  show what would be done, change nothing
#
# Preparing copies the UEFI shell (built from edk2), btlog.efi and two
# scripts to \EFI\btkb\, refreshes bt-kb-dxe.efi there from the current
# build, and adds a boot entry for the shell that the firmware uses for the
# next boot only (BootNext; BootOrder stays as it is). In that boot:
#   1. the shell runs \EFI\btkb\startup.nsh by itself, no keyboard needed:
#      firmware information goes to \EFI\btkb\diag\ (UEFI version, the
#      driver entry, the loaded drivers: did the firmware start bt-kb-dxe?,
#      our variables). It replaces the driver entry with one the shell makes
#      from the firmware's own full device path: efibootmgr writes a short,
#      partition-only path, which this firmware resolves for boot entries
#      but apparently not for drivers (Nov 2). Then it loads bt-kb-dxe.efi
#      and saves more information (devices, USB I/O handles, mappings);
#   2. you press a key on the Bluetooth keyboard and type with it; `btlog`
#      shows the driver's log, from the moment it started;
#   3. you type `linux`: \EFI\btkb\linux.nsh saves the log to diag\ and
#      starts Limine. Starting Linux straight from the shell also keeps the
#      log variable readable in Linux; a reset would lose it.
# If the Bluetooth keyboard doesn't type: type `linux` on a wired USB
# keyboard, or leave the Bluetooth keyboard alone for 2 minutes (it
# disconnects when idle), then press the reset button. The next boot is a
# normal one, with the driver entry unchanged.
set -euo pipefail
. "$(dirname "$0")/common.sh"
DEST=/boot/EFI/btkb
LABEL="Bluetooth keyboard (bt-kb-dxe)"
DIAG_LABEL="bt-kb-dxe diagnostics (UEFI shell)"
DIAG_LOADER='\EFI\btkb\Shell.efi'
LOG_APP="$RUST_EFI_DIR/bt-kb-log.efi"
LIMINE_EFI="${LIMINE_EFI:-\\EFI\\limine\\limine_x64.efi}"
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
DRIVER="$RUST_EFI_DIR/bt-kb-dxe.efi"

dry=""
mode=prepare
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    --collect) mode=collect ;;
    --remove) mode=remove ;;
    *) echo "usage: $0 [--dry-run] [--collect | --remove]" >&2; exit 2 ;;
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

# A path on the ESP (\EFI\x) as a Linux path under /boot.
esp_file () { printf '/boot%s' "$(printf '%s' "$1" | tr '\\' '/')"; }

diag_entries () {
  efibootmgr 2>/dev/null | grep -F "$DIAG_LABEL" | sed -n 's/^Boot\([0-9A-Fa-f]\{4\}\).*/\1/p' || true
}

if [ "$mode" = remove ]; then
  next="$(efibootmgr 2>/dev/null | sed -n 's/^BootNext: //p')"
  for n in $(diag_entries); do
    if [ "$next" = "$n" ]; then
      echo "Deleting BootNext (it points to the diagnostics shell)"
      run efibootmgr -q -N
    fi
    echo "Removing the Boot$n entry ($DIAG_LABEL)"
    run efibootmgr -q -b "$n" -B
  done
  for f in Shell.efi btlog.efi startup.nsh linux.nsh; do
    [ -e "$DEST/$f" ] && run rm -f "$DEST/$f"
  done
  [ -d "$DEST/diag" ] && run rm -rf "$DEST/diag"
  echo "Diagnostics removed${dry:+ (dry run: nothing changed)}."
  exit 0
fi

if [ "$mode" = collect ]; then
  out="$ROOT/board/diag-$(date +%Y%m%d-%H%M%S)"
  if [ -n "$dry" ]; then
    echo "  would copy $DEST/diag/*.txt, the boot entries, our variables and Linux's Bluetooth log to $out"
    exit 0
  fi
  mkdir -p "$out"
  cp "$DEST"/diag/*.txt "$out/" 2>/dev/null || echo "No results in $DEST/diag: did the diagnostics boot run?"
  efibootmgr -v > "$out/boot-entries.txt" 2>&1 || true
  efibootmgr -v -r > "$out/driver-entries.txt" 2>&1 || true
  for v in BtKbLog BtKbBoots BtKbGatt BtKbPanic BtKbLastBoot; do
    f="$EFIVARS/$v-$DIAG_GUID"
    [ -f "$f" ] && tail -c +5 "$f" > "$out/var-$v.bin"
  done
  [ -f "$out/var-BtKbLog.bin" ] && tr -d '\000' < "$out/var-BtKbLog.bin" > "$out/driver-log.txt"
  # Saved by `linux` in the shell: the session's log as it was then.
  [ -f "$out/btlog.txt" ] && tr -d '\r' < "$out/btlog.txt" > "$out/session-log.txt"
  journalctl -k -b --no-pager 2>/dev/null | grep -E 'Bluetooth|usb 1-10' > "$out/linux-bluetooth.txt" || true
  chown -R "${SUDO_USER:-root}:" "$out"
  chmod -R go-rwx "$out"
  # Lines from the shell's files (ASCII with CRLF).
  pick () { [ -f "$out/$1" ] && tr -d '\r' < "$out/$1" | grep -m1 -E "$2" | sed 's/^[[:space:]]*//' || true; }
  echo "Results in $out"
  echo
  echo "Firmware:                  $(pick ver.txt 'UEFI v')"
  echo "In the diagnostics boot:"
  if [ -f "$out/drivers-before.txt" ]; then
    if grep -q 'Bluetooth LE keyboard' "$out/drivers-before.txt"; then
      echo "  firmware had loaded it:  yes (from its Driver#### entry, before the shell)"
    else
      echo "  firmware had loaded it:  no"
    fi
  fi
  echo "  driver entry at boot:    $(pick bcfg-driver-before.txt 'DevPath')"
  echo "  entry set by the shell:  $(pick bcfg-driver-after.txt 'DevPath')"
  echo "  shell's load:            $(pick load.txt 'Image')"
  echo "Driver entries now:        $(grep -c '^Driver[0-9A-F]' "$out/driver-entries.txt" || true)"
  echo "Linux's controller setup:  $(grep -m1 -oE 'Device setup in [0-9]+ usecs' "$out/linux-bluetooth.txt" || echo 'not found') (this boot)"
  # Linux started from the shell (`linux`): this boot's log is the session's.
  same_session=""
  if [ -f "$out/driver-log.txt" ] && grep -qE "loaded from a UEFI shell|registered for 'c' " "$out/driver-log.txt"; then
    same_session=1
  fi
  if [ -f "$out/driver-log.txt" ]; then
    echo
    if [ -n "$same_session" ]; then
      echo "--- driver log of the diagnostics session (this boot, BtKbLog)"
    else
      echo "--- driver log of this boot (BtKbLog), a later boot than the diagnostics session"
    fi
    cat "$out/driver-log.txt"
  fi
  if [ -z "$same_session" ]; then
    echo
    if [ -f "$out/session-log.txt" ]; then
      echo "--- driver log of the diagnostics session (saved by linux, diag\\btlog.txt)"
      cat "$out/session-log.txt"
    else
      echo "The diagnostics session's own log is lost: the session ended without typing linux (a reset clears it)."
    fi
  fi
  exit 0
fi

# --- prepare
sbvar="$EFIVARS/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -r "$sbvar" ] && [ "$(tail -c 1 "$sbvar" | od -An -tu1 | tr -d ' ')" = 1 ]; then
  echo "Secure Boot is on: the diagnostics shell and the files it runs are unsigned, so the firmware would" >&2
  echo "refuse them. Sign them first (sudo sbctl sign -s on each, after copying), or use scripts/board-log.sh." >&2
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
# /boot is readable by root only: a dry run without sudo can't look inside.
if ls /boot >/dev/null 2>&1; then
  if [ ! -f "$DEST/bt-kb-dxe.efi" ]; then
    echo "bt-kb-dxe isn't installed in $DEST. Run first: sudo scripts/board-install.sh" >&2
    exit 1
  fi
  if [ ! -f "$(esp_file "$LIMINE_EFI")" ]; then
    echo "Limine isn't at $LIMINE_EFI on the ESP; set LIMINE_EFI='\\EFI\\...' to its path." >&2
    exit 1
  fi
else
  echo "(dry run without sudo: can't check the files on the ESP)"
fi
for f in "$SHELL_EFI" "$DRIVER" "$LOG_APP"; do
  if [ ! -f "$f" ]; then
    echo "Missing $f. Build first (as yourself): scripts/build.sh and scripts/build-rust.sh" >&2
    exit 1
  fi
done
# linux.nsh removes the first driver entry: it has to be ours.
order="$(efibootmgr -r 2>/dev/null | sed -n 's/^DriverOrder: //p')"
first="${order%%,*}"
if [ -n "$first" ] && ! grep -q "^Driver$first\*\? $LABEL" < <(efibootmgr -r 2>/dev/null); then
  echo "The first driver entry (Driver$first) isn't bt-kb-dxe's; stopping, since the diagnostics replace it." >&2
  efibootmgr -r >&2
  exit 1
fi

echo "ESP: $esp_src (disk $disk, partition $part), files in $DEST"
echo "Driver build: $(date -r "$DRIVER" '+%Y-%m-%d %H:%M'), $(stat -c %s "$DRIVER") bytes (refreshed on the ESP)"
run cp "$DRIVER" "$DEST/bt-kb-dxe.efi"
run cp "$SHELL_EFI" "$DEST/Shell.efi"
run cp "$LOG_APP" "$DEST/btlog.efi"
tmp="$(mktemp -d)"
write_diag_scripts "$tmp" "$LIMINE_EFI"
run cp "$tmp/startup.nsh" "$tmp/linux.nsh" "$DEST/"
rm -rf "$tmp"
if [ -d "$DEST/diag" ] || [ -n "$dry" ]; then
  run rm -rf "$DEST/diag"
fi
run mkdir "$DEST/diag"
entry="$(diag_entries | head -1)"
if [ -z "$entry" ]; then
  echo "Adding a boot entry for the shell (not in BootOrder)"
  run efibootmgr -q -C -d "$disk" -p "$part" -l "$DIAG_LOADER" -L "$DIAG_LABEL"
  entry="$(diag_entries | head -1)"
fi
if [ -n "$dry" ] && [ -z "$entry" ]; then
  echo "  would run: efibootmgr -q -n <the new entry>"
else
  echo "Next boot only: Boot$entry ($DIAG_LABEL)"
  run efibootmgr -q -n "$entry"
fi
if [ -z "$dry" ]; then
  efibootmgr | grep -E '^(BootNext|BootOrder):'
  echo
  echo "Ready. Reboot; the shell starts by itself and shows what to do"
  echo "(btlog shows the driver's log; linux saves it and starts Linux)."
  echo "Back in Linux: sudo scripts/board-diag.sh --collect"
fi
