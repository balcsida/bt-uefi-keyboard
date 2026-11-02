#!/usr/bin/env bash
# Run UEFI shell commands with the real MT7922 Bluetooth function (USB
# 0e8d:0616) passed through to OVMF in QEMU. Each argument is one shell
# command; the ESP holds every built app and the firmware image.
#   scripts/qemu-hw.sh "bt-hci-probe.efi -v"
#   LIVE=1 scripts/qemu-hw.sh ...   also shows the output as it happens
#   WINDOW=1 scripts/qemu-hw.sh ... shows the guest's screen in a QEMU window
#     (GTK); this terminal then shows the driver's log as it is written.
#     In the window, keys reach the guest only from the Bluetooth keyboard,
#     through the driver: no PS/2 keyboard, and the serial console only
#     writes the log. No menu bar and no working close button, since both
#     could end QEMU abruptly while the driver holds the controller.
# Other knobs: ESP_INTERACTIVE=1 (no `reset -s` at the end of the startup
# script), EXTRA_ESP_FILES="file ..." (more files for the ESP),
# QEMU_TIMEOUT=seconds (default 300), VARS_FILE=path (an OVMF variable
# store to use and keep, instead of a fresh one), EXTRA_QEMU_ARGS="...",
# START_MESSAGE="..." (shown once the host has let go of the controller).
# The bt-kb-dxe driver's log (QEMU debug console, port 0x402) ends up in
# qemu/hw/driver.log.
#
# Handover: BlueZ first powers the adapter off. That disconnects every
# device and Linux turns the Bluetooth function off, so no link is live when
# QEMU takes the controller. (On Nov 1 the keyboard was still connected when
# QEMU took over, and the controller wedged until a mains power cycle.)
# Afterwards the script waits for Linux to set the controller up again and
# powers BlueZ back on.
#
# While QEMU runs, the host has no Bluetooth, the keyboard included.
#
# The USB device node must be writable by you. One-off grant, gone after the
# device is re-enumerated (for example at reboot):
#   sudo setfacl -m u:$USER:rw /dev/bus/usb/BBB/DDD
set -euo pipefail
. "$(dirname "$0")/common.sh"
ensure_firmware

if [ $# -eq 0 ]; then
  echo "usage: $0 '<shell command>' ['<shell command>' ...]" >&2
  exit 2
fi

# Decided before anything touches BlueZ or the controller.
window=""
if [ -n "${WINDOW:-}" ]; then
  if ! "$QEMU" -display help 2>/dev/null | grep -qx gtk; then
    echo "This QEMU build has no GTK display; using the terminal instead." >&2
  elif [ -z "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]; then
    echo "No graphical session (WAYLAND_DISPLAY and DISPLAY are unset); using the terminal instead." >&2
  else
    window=1
  fi
fi

busdev="$(lsusb -d 0e8d:0616 | awk '{print $2 "/" $4}' | tr -d ':' | head -1)"
if [ -z "$busdev" ]; then
  echo "MediaTek Bluetooth device 0e8d:0616 not found" >&2
  exit 1
fi

node="/dev/bus/usb/$busdev"
if [ ! -w "$node" ]; then
  echo "No write access to $node. Grant it once with:" >&2
  echo "  sudo setfacl -m u:$USER:rw $node" >&2
  exit 1
fi

work="$ROOT/qemu/hw"
mkdir -p "$work"
started="$(date '+%Y-%m-%d %H:%M:%S')"

bt_powered () { timeout 5 bluetoothctl show 2>/dev/null | grep -q 'Powered: yes'; }
bt_present () { timeout 5 bluetoothctl list 2>/dev/null | grep -q '^Controller'; }

restore_bluetooth () {
  local i
  for i in $(seq 1 30); do
    lsusb -d 0e8d:0616 >/dev/null && break
    sleep 1
  done
  if ! lsusb -d 0e8d:0616 >/dev/null; then
    echo
    echo "WARNING: the Bluetooth controller did not come back on the USB bus."
    echo "On Nov 1 this state survived a USB port power cycle and a reboot; only a mains"
    echo "power cycle fixed it (shut down, switch the PSU off for ~30 s, boot)."
    journalctl -k --since "$started" --no-pager 2>/dev/null | grep -E 'usb 1-10' | tail -3 || true
    return 0
  fi
  # Linux's setup takes ~0.2 s, or ~20 s if it has to upload the firmware.
  for i in $(seq 1 60); do
    bt_present && break
    sleep 1
  done
  timeout 10 bluetoothctl power on >/dev/null 2>&1 || true
  sleep 1
  echo "Host Bluetooth: $(timeout 5 bluetoothctl show 2>/dev/null | grep -m1 'Powered' | xargs || echo 'controller not back yet')"
  journalctl -k --since "$started" --no-pager 2>/dev/null | grep -oE 'hci0: Device setup in [0-9]+ usecs' | tail -1 | sed 's/^hci0: /Linux /' || true
}

tail_pid=""
cleanup () {
  pkill -f "qemu-system-x86_64 .*${work}/" 2>/dev/null || true
  [ -z "$tail_pid" ] || kill "$tail_pid" 2>/dev/null || true
  # The exported bond only lives on the scratch ESP while QEMU runs.
  rm -f "$work/esp/"*.bond "$work/esp.img"
  restore_bluetooth
}

if bt_powered; then
  echo "Powering Bluetooth off in BlueZ first, so no connection is live when QEMU takes the controller..."
  timeout 10 bluetoothctl power off >/dev/null 2>&1 || true
  for i in $(seq 1 20); do
    bt_powered || break
    sleep 0.5
  done
  if bt_powered; then
    echo "WARNING: BlueZ did not power off; continuing (the apps drain and reset the controller themselves)."
  fi
fi
trap cleanup EXIT

make_esp "$work/esp" "$@"
for extra in ${EXTRA_ESP_FILES:-}; do
  cp "$extra" "$work/esp/"
done
# Keyboard bonds exported by scripts/export-bond.sh (bt-kb-probe, bt-kb-dxe).
for bond in "$ROOT"/qemu/keys/*.bond; do
  [ -f "$bond" ] && install -m 600 "$bond" "$work/esp/"
done
vars="${VARS_FILE:-$work/OVMF_VARS.4m.fd}"
[ -n "${VARS_FILE:-}" ] || cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$vars"
make_esp_image "$work/esp" "$work/esp.img"

echo "Passing $node through to QEMU; Bluetooth on the host is down until it exits."
machine="q35,accel=kvm"
display_args=(-nographic -serial mon:stdio)
if [ -n "$window" ]; then
  # The USB tablet (an absolute pointer) keeps a click in the window from
  # grabbing the mouse; it comes after the controller, which keeps its port.
  machine+=",i8042=off"
  display_args=(-display gtk,window-close=off,show-menubar=off -name "bt-kb-dxe: Bluetooth keyboard test"
    -device usb-tablet,bus=xhci.0 -serial file:"$work/serial.log" -monitor none -parallel none)
fi
qemu_args=(-machine "$machine" -cpu host -m 1G -no-reboot
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_DIR/OVMF_CODE.4m.fd"
  -drive if=pflash,format=raw,file="$vars"
  -drive if=none,id=esp,format=raw,file="$work/esp.img" -device virtio-blk-pci,drive=esp
  -device qemu-xhci,id=xhci
  -device usb-host,bus=xhci.0,vendorid=0x0e8d,productid=0x0616
  -chardev file,id=dbg,path="$work/driver.log" -device isa-debugcon,iobase=0x402,chardev=dbg
  ${EXTRA_QEMU_ARGS:-} -net none "${display_args[@]}")
: > "$work/driver.log"
# The serial log has whatever is typed: private from the start.
install -m 600 /dev/null "$work/serial.log"
[ -z "${START_MESSAGE:-}" ] || printf '\n>>> %s\n\n' "$START_MESSAGE"
if [ -n "$window" ]; then
  echo "The guest's screen is in the QEMU window. The driver's log follows here as it is written:"
  echo
  tail -n +1 -F "$work/driver.log" 2>/dev/null &
  tail_pid=$!
  # The terminal isn't in raw mode here, so Ctrl+C would end QEMU
  # abruptly with the controller in use. QEMU runs in its own session,
  # out of the terminal's reach, and Ctrl+C only prints a reminder.
  trap 'printf "\n>>> Not stopping QEMU: that would leave the controller in use. End the session in the window (setup: Reset; shell: reset or ebs-test.efi), or wait for the time limit.\n"' INT
  setsid timeout "${QEMU_TIMEOUT:-300}" "$QEMU" "${qemu_args[@]}" > "$work/qemu.out" 2>&1 &
  qemu_job=$!
  qemu_status=0
  while :; do
    if wait "$qemu_job"; then qemu_status=0; break; else qemu_status=$?; fi
    # A trapped signal interrupts wait while QEMU keeps running.
    kill -0 "$qemu_job" 2>/dev/null || break
  done
  trap - INT
  sleep 0.5
  kill "$tail_pid" 2>/dev/null || true
  wait "$tail_pid" 2>/dev/null || true
  tail_pid=""
  if [ "$qemu_status" -ne 0 ]; then
    echo "(QEMU exit status $qemu_status; its last messages:)"
    tail -5 "$work/qemu.out"
  fi
elif [ -n "${LIVE:-}" ]; then
  # Keys typed while the host still had the keyboard would reach the
  # guest's serial console (an F2 there opens the boot menu too): drop them.
  if [ -t 0 ]; then
    python3 -I -c 'import sys, termios; termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)' || true
  fi
  # Raw bytes, as they arrive: keys echo at once and full-screen UIs render.
  timeout --foreground "${QEMU_TIMEOUT:-300}" "$QEMU" "${qemu_args[@]}" 2>&1 | tee "$work/serial.log" \
    | python3 -I "$ROOT/scripts/live-filter.py" || true
  printf '\033[0m\n'
else
  timeout --foreground "${QEMU_TIMEOUT:-300}" "$QEMU" "${qemu_args[@]}" > "$work/serial.log" 2>&1 || true
  clean_log "$work/serial.log" | sed -n '/^=== /,$p'
fi
chmod 600 "$work/serial.log"
if [ -z "$window" ] && [ -s "$work/driver.log" ]; then
  echo
  echo "--- bt-kb-dxe driver log"
  cat "$work/driver.log"
fi
echo
echo "Full log: $work/serial.log"
[ -z "$window" ] || echo "Driver log: $work/driver.log"
