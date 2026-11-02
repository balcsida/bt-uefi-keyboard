#!/usr/bin/env bash
# The driver loaded at boot, as on the real board: OVMF's boot manager loads
# bt-kb-dxe.efi from a Driver#### option before it connects the consoles,
# then counts down 20 s before booting, with F2 and Esc as hotkeys for the
# boot menu. On the real controller and keyboard, this tests:
#   - the boot hotkey: press F2 on the Bluetooth keyboard about once a
#     second, from the prompt on, until the boot menu shows;
#   - setup screens: pick "EFI Firmware Setup", move around (arrows, Enter,
#     Esc), and stay at least 15 s (the boot-loop counter clears then);
#   - the reset hand-off: "Reset" on setup's front page (QEMU then exits).
# Without the menu, the shell starts instead: `exit` there gives the boot
# menu, `ebs-test.efi` ends the session.
#
# The variable store stays in qemu/hw-boot/ between runs, so a second run
# uses the keyboard layout the first one remembered: compare the lines
# "first key report decoded N ms after the keyboard connected". FRESH=1
# starts over with a new store.
#
# Never quit QEMU with Ctrl-A x (see qemu-hw-driver.sh). The driver hands
# the controller back and powers off by itself after the time limit (first
# argument, default 240 s).
#
# The guest's screen opens in a QEMU window, and this terminal shows the
# driver's log as it is written. WINDOW= LIVE=1 uses the terminal instead
# (the serial console: no logo or countdown there).
set -euo pipefail
. "$(dirname "$0")/common.sh"
limit="${1:-240}"
dir="$ROOT/qemu/hw-boot"
mkdir -p "$dir"
vars="$dir/OVMF_VARS.4m.fd"
if ! ls "$ROOT"/qemu/keys/*.bond >/dev/null 2>&1; then
  echo "No exported bond in qemu/keys/. Run: sudo scripts/export-bond.sh" >&2
  exit 1
fi
if [ -n "${FRESH:-}" ] || [ ! -f "$vars" ]; then
  echo "Preparing a variable store with a Driver#### option for bt-kb-dxe.efi (no controller involved)..."
  cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$vars"
  add_driver_option "$vars" || { echo "Adding the driver option failed." >&2; rm -f "$vars"; exit 1; }
fi
echo "$limit" > "$dir/bt-kb-dxe.timelimit"
export VARS_FILE="$vars"
export WINDOW="${WINDOW-1}"
export EXTRA_QEMU_ARGS="-boot menu=on,splash-time=20000"
export ESP_INTERACTIVE=1
export EXTRA_ESP_FILES="$dir/bt-kb-dxe.timelimit"
export QEMU_TIMEOUT=$((limit + 120))
if [ -n "$WINDOW" ]; then
  export START_MESSAGE="In the QEMU window, a progress bar under the TianoCore logo counts down 20 s. Meanwhile press F2 on the Bluetooth keyboard about once a second until the boot menu appears."
else
  export START_MESSAGE="Now press F2 on the Bluetooth keyboard, about once a second, until the boot menu appears."
fi
"$ROOT/scripts/qemu-hw.sh" \
  "echo The shell instead of the boot menu: type exit for the menu, or ebs-test.efi to end. Power-off after $limit seconds anyway."
if grep -q 'not starting:' "$ROOT/qemu/hw/driver.log" 2>/dev/null; then
  echo
  echo "The driver's boot-loop guard stopped it (3 runs ended within 15 s of the driver starting)."
  echo "Run again with FRESH=1 for a new variable store."
fi
