# Shared paths for the helper scripts. Source from bash.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QEMU="$ROOT/tools/local/bin/qemu-system-x86_64"
OVMF_DIR="$ROOT/tools/src/ovmf-pkg/extract/usr/share/edk2/x64"
SHELL_EFI="$ROOT/Build/Shell/RELEASE_GCC/X64/ShellPkg/Application/Shell/EA4BB293-2D7F-4456-A681-1F22F42CD0BC/OUTPUT/Shell.efi"
PROBE_EFI="$ROOT/Build/BtKbPkg/DEBUG_GCC/X64/BtHciProbe.efi"
RUST_EFI_DIR="$ROOT/rust/target/x86_64-unknown-uefi/release"
HOST_TEST="$ROOT/Build/BtKbPkg/HostTest/NOOPT_GCC/X64/MtkBtLibUnitTestHost"
FW_NAME="BT_RAM_CODE_MT7922_1_1_hdr.bin"
FW_SRC="/usr/lib/firmware/mediatek/$FW_NAME.zst"
FW_DIR="$ROOT/qemu/fw"
FW_BIN="$FW_DIR/$FW_NAME"

# Unpack the linux-firmware copy of the MT7922 image (never committed).
ensure_firmware () {
  if [ ! -f "$FW_BIN" ] || [ "$FW_SRC" -nt "$FW_BIN" ]; then
    mkdir -p "$FW_DIR"
    zstd -q -d -f "$FW_SRC" -o "$FW_BIN"
  fi
}

# Build an ESP directory: UEFI shell as the fallback boot loader, the probe,
# the firmware image and a startup.nsh made from the remaining arguments
# (one shell command per argument). With ESP_INTERACTIVE=1 the script ends
# without `reset -s`, leaving an interactive shell.
make_esp () {
  local esp="$1"; shift
  rm -rf "$esp"
  mkdir -p "$esp/EFI/BOOT"
  cp "$SHELL_EFI" "$esp/EFI/BOOT/BOOTX64.EFI"
  # Every app that has been built: C (EDK2) and Rust.
  for app in "$ROOT"/Build/BtKbPkg/DEBUG_GCC/X64/*.efi "$RUST_EFI_DIR"/*.efi; do
    [ -f "$app" ] && cp "$app" "$esp/"
  done
  cp "$FW_BIN" "$esp/"
  {
    printf '@echo -off\r\nfs0:\r\n'
    for cmd in "$@"; do
      printf 'echo "=== %s"\r\n%s\r\n' "$cmd" "$cmd"
    done
    if [ -z "${ESP_INTERACTIVE:-}" ]; then
      printf 'echo "=== done"\r\nreset -s\r\n'
    fi
  } > "$esp/startup.nsh"
}

# A FAT32 disk image with the contents of a directory, attached as
# virtio-blk. With the emulated SATA disk (fat:rw: or an image), OVMF hung
# at boot or timed out reading files now and then, Bluetooth driver or not.
make_esp_image () {
  local dir="$1" img="$2"
  rm -f "$img"
  truncate -s 64M "$img"
  mformat -i "$img" -F -v ESP ::
  mcopy -i "$img" -s -Q "$dir"/* ::/
}

# Strip terminal escapes and blank lines from a QEMU serial log.
clean_log () {
  sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\r//g' "$1" | grep -vE '^\s*$'
}

# Add a Driver#### option for bt-kb-dxe.efi (first in DriverOrder) to an
# OVMF variable store, so OVMF's boot manager loads the driver at every boot
# before it connects the consoles, as on the real board. Boots the shell
# once, without the Bluetooth controller. The PCI layout is the one of the
# other QEMU runs (ESP on virtio-blk at 00:02.0, xHCI at 00:03.0), so the
# option's device path, PciRoot(0x0)/Pci(0x2,0x0)/\bt-kb-dxe.efi, fits them.
add_driver_option () {
  local vars="$1" tmp ok=0
  tmp="$(mktemp -d "$ROOT/qemu/.driver-option.XXXXXX")"
  mkdir -p "$tmp/esp/EFI/BOOT"
  cp "$SHELL_EFI" "$tmp/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$RUST_EFI_DIR/bt-kb-dxe.efi" "$tmp/esp/"
  printf '%s\r\n' '@echo -off' 'fs0:' 'bcfg driver add 0 fs0:\bt-kb-dxe.efi "Bluetooth keyboard (bt-kb-dxe)"' \
    'echo "=== driver options"' 'bcfg driver dump' 'reset -s' > "$tmp/esp/startup.nsh"
  make_esp_image "$tmp/esp" "$tmp/esp.img"
  timeout --foreground 60 "$QEMU" -machine q35,accel=kvm -cpu host -m 1G -nographic -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_DIR/OVMF_CODE.4m.fd" \
    -drive if=pflash,format=raw,file="$vars" \
    -drive if=none,id=esp,format=raw,file="$tmp/esp.img" -device virtio-blk-pci,drive=esp \
    -device qemu-xhci,id=xhci -net none -serial mon:stdio > "$tmp/serial.log" 2>&1 || true
  clean_log "$tmp/serial.log" | sed -n '/=== driver options/,$p' | grep -E 'DevPath' | head -2
  clean_log "$tmp/serial.log" | grep -q 'DevPath.*bt-kb-dxe.efi' && ok=1
  rm -rf "$tmp"
  [ "$ok" = 1 ]
}
