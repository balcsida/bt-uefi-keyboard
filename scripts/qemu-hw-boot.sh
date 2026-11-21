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
#
# SB=1: Secure Boot on (throwaway test keys, signed images), with its own
# variable store (qemu/hw-boot/OVMF_VARS.sb.fd). TPM=1: a TPM 2.0 (swtpm),
# state kept in qemu/hw-boot/tpm. FRESH=1 starts both over.
#
# PAIR=1: pairing in firmware on the real keyboard (README, Pairing in
# firmware). THE KEYBOARD GETS A NEW KEY: Linux, and whatever else uses
# the old one (the driver installed on the board, Windows), has lost it
# until it is given the new one. Have another keyboard at hand.
#   - It needs a driver built to pair (BT_KB_FEATURES, scripts/build-rust.sh)
#     for a hand-off key whose private half is HANDOFF_KEY (default
#     qemu/keys/handoff.key; scripts/bond-handoff.py keygen makes one).
#   - No bond goes on the ESP, and the run has a variable store of its own
#     (OVMF_VARS.pair.*): the first run offers pairing, later ones use the
#     bond it made. FRESH=1 starts over.
#   - After the logo the pairing screen waits PAIR_WAIT seconds (default
#     180) for a keyboard in pairing mode, and shows a passkey to type on
#     it. Type it on the number pad: on the top row the digits go by key
#     position, where a Hungarian keyboard has its 0 elsewhere.
#   - The shell then saves the bond the driver hands to the OS, and the
#     script says how to give it to BlueZ. Default time limit: 600 s.
set -euo pipefail
. "$(dirname "$0")/common.sh"
pair="${PAIR:-}"
limit="${1:-${pair:+600}}"
limit="${limit:-240}"
dir="$ROOT/qemu/hw-boot"
mkdir -p "$dir"
vars="$dir/OVMF_VARS.4m.fd"
if [ -n "${SB:-}" ]; then
  vars="$dir/OVMF_VARS.sb.fd"
  sb_prepare
fi
if [ -n "$pair" ]; then
  vars="${vars/OVMF_VARS./OVMF_VARS.pair.}"
  key="${HANDOFF_KEY:-$ROOT/qemu/keys/handoff.key}"
  if ! grep -qxE 'pairing|insecure-legacy-pairing' "$RUST_EFI_DIR/bt-kb-dxe.features" 2>/dev/null; then
    echo "The driver build can't pair in firmware. Build one that can, for example:" >&2
    echo "  BT_KB_FEATURES=pairing scripts/build-rust.sh" >&2
    exit 1
  fi
  # Checked before the keyboard is touched: without the private half, the
  # new bond couldn't be given to Linux afterwards.
  built_for="$(cat "$RUST_EFI_DIR/bt-kb-dxe.handoff" 2>/dev/null || true)"
  if [ -z "$built_for" ] || [ "$(python3 -I "$ROOT/scripts/bond-handoff.py" pubkey "$key" 2>/dev/null)" != "$built_for" ]; then
    echo "The driver wasn't built for the hand-off key $key." >&2
    echo "  python3 -I scripts/bond-handoff.py keygen $key    (once)" >&2
    echo "  BT_KB_HANDOFF_KEY=\$(python3 -I scripts/bond-handoff.py pubkey $key) BT_KB_FEATURES=... scripts/build-rust.sh" >&2
    exit 1
  fi
fi
if [ -n "${FRESH:-}" ] && [ -d "$dir/tpm" ]; then
  tpm_stop "$dir/tpm"
  rm -rf "$dir/tpm"
fi
export TPM_DIR="$dir/tpm"
if [ -z "$pair" ] && ! ls "$ROOT"/qemu/keys/*.bond >/dev/null 2>&1; then
  echo "No exported bond in qemu/keys/. Run: sudo scripts/export-bond.sh" >&2
  exit 1
fi
if [ -n "${FRESH:-}" ] || [ ! -f "$vars" ]; then
  echo "Preparing a variable store with a Driver#### option for bt-kb-dxe.efi (no controller involved)..."
  fresh_vars "$vars"
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
command="echo The shell instead of the boot menu: type exit for the menu, or ebs-test.efi to end. Power-off after $limit seconds anyway."
if [ -n "$pair" ]; then
  echo "${PAIR_WAIT:-180}" > "$dir/bt-kb-dxe.pairwait"
  write_pair_nsh "$dir/pair.nsh"
  rm -f "$ROOT/qemu/hw/handoff.bin" "$ROOT/qemu/hw/paired.bond"
  export EXTRA_QEMU_ARGS="-boot menu=on,splash-time=5000"
  export EXTRA_ESP_FILES="$EXTRA_ESP_FILES $dir/bt-kb-dxe.pairwait $dir/pair.nsh"
  export NO_BOND=1 ESP_SAVE=handoff.bin
  export START_MESSAGE="Don't press anything yet. When the pairing screen shows (a few seconds after the logo): hold the keyboard's pairing button until its light blinks, wait for the passkey, type it on the keyboard's number pad, press Enter. (With a bond from an earlier PAIR=1 run there is no pairing screen: the shell starts, and the keyboard just works.)"
  command="pair.nsh"
fi
"$ROOT/scripts/qemu-hw.sh" "$command"
if [ -n "$pair" ]; then
  echo
  if [ -s "$ROOT/qemu/hw/handoff.bin" ] \
    && python3 -I "$ROOT/scripts/bond-handoff.py" open "$key" --var "$ROOT/qemu/hw/handoff.bin" --out "$ROOT/qemu/hw/paired.bond"; then
    echo "The keyboard has a new key, and Linux still has the old one. Give it the new one"
    echo "(the keyboard works in Linux again after the second command):"
    echo "  sudo python3 -I scripts/bond-handoff.py import $key --var $ROOT/qemu/hw/handoff.bin"
    echo "  sudo systemctl restart bluetooth"
    echo "If the keyboard has a new address too (some take one at every pairing; bluetoothctl devices"
    echo "lists the old one), add --like OLD:AD:DR:ES:S to the first command: BlueZ's name and settings"
    echo "for the keyboard then carry over."
  else
    echo "No bond was handed over: nothing was paired in this run (the driver's log above says why)."
  fi
fi
if grep -q 'not starting:' "$ROOT/qemu/hw/driver.log" 2>/dev/null; then
  echo
  echo "The driver's boot-loop guard stopped it (3 runs ended within 15 s of the driver starting)."
  echo "Run again with FRESH=1 for a new variable store."
fi
