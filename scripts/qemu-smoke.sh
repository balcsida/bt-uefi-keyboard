#!/usr/bin/env bash
# Offline smoke test: boot OVMF + UEFI shell in QEMU with an emulated USB
# keyboard and tablet (no Bluetooth device) and run the probe's offline modes.
# Nothing touches the real controller.
set -euo pipefail
# Never leave a QEMU behind if this script is interrupted.
trap 'pkill -f "qemu-system-x86_64 .*${work:-/nonexistent}/" 2>/dev/null || true' EXIT
. "$(dirname "$0")/common.sh"
ensure_firmware

work="$ROOT/qemu/smoke"
mkdir -p "$work"
# Usage: scripts/qemu-smoke.sh [app.efi]   (default bt-hci-probe.efi, the Rust probe)
app="${1:-bt-hci-probe.efi}"
make_esp "$work/esp" \
  "$app -h" \
  "$app -parse" \
  "$app -list" \
  "$app"
cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$work/OVMF_VARS.4m.fd"
make_esp_image "$work/esp" "$work/esp.img"

timeout --foreground 180 "$QEMU" -machine q35,accel=kvm -cpu host -m 1G -nographic -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_DIR/OVMF_CODE.4m.fd" \
  -drive if=pflash,format=raw,file="$work/OVMF_VARS.4m.fd" \
  -drive if=none,id=esp,format=raw,file="$work/esp.img" -device virtio-blk-pci,drive=esp \
  -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0 \
  -net none -serial mon:stdio > "$work/serial.log" 2>&1

clean_log "$work/serial.log" | sed -n '/^=== /,$p'
