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
