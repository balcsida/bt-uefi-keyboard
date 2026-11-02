#!/usr/bin/env bash
# Milestone 4 on the real controller: the bt-kb-dxe driver in OVMF.
#
# The UEFI shell loads the driver and stays interactive. The driver checks
# the controller's firmware (no upload), turns Bluetooth on and waits for
# the keyboard: press a key on it, then type in the shell with it.
#
# The session ends, with the controller handed back each time, when:
#   - you type `ebs-test.efi` (tests the "OS is starting" hand-off), or
#   - you type `reset` or `reset -s` (tests the reset hand-off), or
#   - the driver's time limit runs out (first argument, default 180 s):
#     it hands the controller back and powers off.
# Don't quit QEMU with Ctrl-A x: that kills it while the driver holds the
# controller, the situation that wedged it on Nov 1.
#
# The shell opens in a QEMU window and this terminal shows the driver's log;
# WINDOW= LIVE=1 shows the shell in the terminal instead.
set -euo pipefail
limit="${1:-180}"
dir="$(cd "$(dirname "$0")/.." && pwd)/qemu/hw-driver-files"
mkdir -p "$dir"
echo "$limit" > "$dir/bt-kb-dxe.timelimit"
if ! ls "$(dirname "$0")"/../qemu/keys/*.bond >/dev/null 2>&1; then
  echo "No exported bond in qemu/keys/. Run: sudo scripts/export-bond.sh" >&2
  exit 1
fi
export WINDOW="${WINDOW-1}"
export ESP_INTERACTIVE=1
export EXTRA_ESP_FILES="$dir/bt-kb-dxe.timelimit"
export QEMU_TIMEOUT=$((limit + 120))
exec "$(dirname "$0")/qemu-hw.sh" \
  'load bt-kb-dxe.efi' \
  "echo Press a key on the Bluetooth keyboard, then type here. End with ebs-test.efi or reset. Power-off after $limit seconds anyway."
