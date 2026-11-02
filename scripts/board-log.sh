#!/usr/bin/env bash
# After booting Linux with bt-kb-dxe installed (scripts/board-install.sh):
# what the driver logged during this boot, a timeline of the boot, its
# variables, and how Linux found the controller afterwards. Runs as
# yourself: the variables are readable by everyone (mode 644).
#
# BtKbLog is volatile: it holds the log of the current boot (the newest
# 3800 bytes) and is gone after a reset. To keep a setup session's log,
# leave setup through Boot Override into Linux rather than Save & Exit.
set -euo pipefail
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
VENDOR=5223227b-ac96-454e-9bca-f15199748a3c
LOADER=4a67b082-0a4c-41cf-b6c7-440b29bb8c4f

# efivarfs: 4 bytes of attributes, then the data.
data () { tail -c +5 "$EFIVARS/$1-$VENDOR"; }
have () { [ -f "$EFIVARS/$1-$VENDOR" ]; }
# A boot loader time variable (UTF-16 digits, microseconds since reset).
loader_us () { [ -f "$EFIVARS/$1-$LOADER" ] && tail -c +5 "$EFIVARS/$1-$LOADER" | tr -cd '0-9'; }

if have BtKbLog; then
  log="$(data BtKbLog | tr -d '\000')"
  echo "--- driver log of this boot (BtKbLog)"
  printf '%s\n\n' "$log"
  # Timeline: driver times plus the offset from a line that also carries
  # the time since the CPU reset (the start line, or the OS hand-off).
  printf '%s\n' "$log" | awk -v loader_init="$(loader_us LoaderTimeInitUSec || true)" '
    function at(ms) { return sprintf("%7.2f s", ms / 1000) }
    match($0, /[0-9]+ ms after the CPU reset/) {
      reset_ms = substr($0, RSTART, RLENGTH) + 0
      if (offset == "") offset = reset_ms - $1
    }
    { lines[++n] = $0 }
    END {
      if (offset == "") { print "(no timeline: this driver build does not log the time since the reset)"; exit }
      print "--- timeline of this boot (seconds since the CPU reset)"
      for (i = 1; i <= n; i++) {
        line = lines[i]
        if (line !~ /^ *[0-9]+ /) continue
        split(line, f, " "); t = f[1] + offset
        if (line ~ /starting from/) print at(t) "  driver loaded"
        else if (line ~ /controller ready/) print at(t) "  controller ready"
        else if (line ~ /keyboard connected \(handle/ && connected++ < 12) print at(t) "  keyboard connected"
        else if (match(line, /keyboard link encrypted \([^)]*\)/) && encrypted++ < 2) print at(t) "  " substr(line, RSTART + 9, RLENGTH - 9)
        else if (line ~ /first key report decoded/ && first_key++ < 12) print at(t) "  keys flowing"
        else if (line ~ /didn.t register the encryption/ && missed++ < 2) print at(t) "  the host stack missed the encryption; driver went on"
        else if (match(line, /keyboard disconnected \(reason 0x[0-9a-f]+\)/) && gone++ < 12) print at(t) "  " substr(line, RSTART, RLENGTH)
        else if (match(line, /key [A-Za-z0-9]+ delivered/) && hot++ < 5) print at(t) "  " substr(line, RSTART, RLENGTH)
        else if (line ~ /an OS is starting/) print at(t) "  an OS started (driver handed the controller back)"
        else if (line ~ /the machine is resetting/) print at(t) "  reset"
      }
      if (loader_init != "") print at(loader_init / 1000) "  the firmware started the boot loader (also in: systemd-analyze)"
    }' | sort -n
  echo
else
  echo "No BtKbLog: the driver didn't run during this boot, or couldn't write its log."
  init_us="$(loader_us LoaderTimeInitUSec || true)"
  if [ -n "$init_us" ]; then
    echo "The firmware started the boot loader $(awk -v us="$init_us" 'BEGIN { printf "%.2f", us / 1e6 }') s after the CPU reset."
  fi
  # AMI's Fast Boot module keeps its state in this vendor GUID. A fast boot
  # boots the stored option directly and skips Driver#### (Nov 2: 10.7 s to
  # the boot loader and no driver, against 14.3-15.1 s in full boots).
  if [ -f "$EFIVARS/FastBootOption-b540a530-6978-4da7-91cb-7207d764d262" ]; then
    echo "If the driver is installed, the likely cause is AMI's Fast Boot: a fast boot skips driver"
    echo "entries (and the setup key). Full boots on Nov 2 reached the boot loader after 14.3-15.1 s,"
    echo "the fast one after about 10.7 s. The setting is in firmware setup, Boot page (Fast Boot)."
  fi
fi
# The driver's one-line records (BtKbLastBoot, non-volatile): this boot's
# as last written, and the previous boot's as this boot found it.
if have BtKbLastBoot; then
  echo "This boot's record (BtKbLastBoot): $(data BtKbLastBoot | tr -cd '[:print:]')"
fi
if have BtKbLog; then
  prev="$(printf '%s\n' "$log" | sed -n 's/^ *[0-9]* I previous boot: //p' | head -1)"
  [ -z "$prev" ] || echo "Previous boot's record: $prev"
fi
if have BtKbBoots; then
  n="$(data BtKbBoots | od -An -tu1 | tr -d ' \n')"
  if [ "${n:-0}" -ge 3 ]; then
    echo "Boot-loop counter (BtKbBoots): $n: the driver has switched itself off (sudo scripts/board-install.sh re-enables it)"
  else
    echo "Boot-loop counter (BtKbBoots): $n of 3"
  fi
fi
if have BtKbPanic; then
  echo "--- last crash (BtKbPanic)"
  data BtKbPanic | tr -d '\000'
  echo
fi
if have BtKbGatt; then
  echo "Keyboard layout remembered (BtKbGatt): $(data BtKbGatt | wc -c) bytes"
fi
echo "--- Linux and the controller during this boot"
# The first setup after boot is the one that follows the driver's hand-off.
first="$(journalctl -k -b --no-pager 2>/dev/null | grep -m1 -E 'hci0: Device setup in' || true)"
echo "First controller setup: ${first:-none found}"
echo "(about 0.18 s: the firmware stayed loaded; about 20 s: Linux had to upload it again)"
errors="$(journalctl -k -b --no-pager 2>/dev/null | grep -E 'Bluetooth: hci0: .*([Ff]ail|[Ee]rror|[Tt]imeout)' | tail -4 || true)"
if [ -n "$errors" ]; then
  echo "Bluetooth errors during this boot:"
  echo "$errors"
fi
