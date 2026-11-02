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

# The UEFI shell scripts for a diagnostics boot on the board, written into
# a directory that becomes \EFI\btkb\ on the ESP (CRLF line endings):
#   startup.nsh  run by the shell by itself: firmware information into
#                diag\ (did the firmware start bt-kb-dxe from Driver####?),
#                the driver entry replaced by one with the firmware's own
#                full device path, bt-kb-dxe.efi loaded, more information;
#   linux.nsh    typed as `linux` at the end: the driver's log saved
#                (btlog.efi), then Limine started.
# $2: Limine's path on the ESP, e.g. '\EFI\limine\limine_x64.efi'.
DIAG_GUID=5223227b-ac96-454e-9bca-f15199748a3c
write_diag_scripts () {
  local dir="$1" limine="$2"
  printf '%s\r\n' \
    '@echo -off' \
    '# bt-kb-dxe diagnostics on the board (scripts/board-diag.sh).' \
    '%homefilesystem%' \
    'cd \EFI\btkb' \
    'echo "=== bt-kb-dxe diagnostics: saving firmware information to \EFI\btkb\diag\"' \
    'ver >a diag\ver.txt' \
    'bcfg driver dump -v >a diag\bcfg-driver-before.txt' \
    'drivers >a diag\drivers-before.txt' \
    "dmpstore -guid $DIAG_GUID >a diag\\vars-before.txt" \
    'btlog >a diag\btlog-before.txt' \
    'echo "=== driver entry: replaced by one with the firmware'"'"'s own full device path"' \
    'bcfg driver rm 0 >a diag\bcfg-rm.txt' \
    'bcfg driver add 0 bt-kb-dxe.efi "Bluetooth keyboard (bt-kb-dxe)" >a diag\bcfg-add.txt' \
    'bcfg driver dump -v >a diag\bcfg-driver-after.txt' \
    'type diag\bcfg-driver-after.txt' \
    'echo "=== load bt-kb-dxe.efi"' \
    'load bt-kb-dxe.efi >a diag\load.txt' \
    'type diag\load.txt' \
    'echo ">>> Press a key on the Bluetooth keyboard now."' \
    'devices >a diag\devices.txt' \
    'dh -v -p USBIO >a diag\usbio.txt' \
    'map >a diag\map.txt' \
    'drivers >a diag\drivers-after.txt' \
    "dmpstore -guid $DIAG_GUID >a diag\\vars-after.txt" \
    'echo " "' \
    'echo "Type with the Bluetooth keyboard, e.g.  echo hello"' \
    'echo "Type  btlog  to see the driver'"'"'s log: when the keyboard connected, and how."' \
    'echo "When done, type  linux  to start Linux. It saves the log first: please"' \
    'echo "don'"'"'t reset from here, that loses it. In Linux:  sudo scripts/board-diag.sh --collect"' \
    'echo "No typing from the Bluetooth keyboard? Type linux on a wired USB keyboard, or leave"' \
    'echo "the Bluetooth keyboard alone for 2 minutes, then press the reset button."' \
    > "$dir/startup.nsh"
  printf '%s\r\n' \
    '@echo -off' \
    '# Typed at the end of the diagnostics (scripts/board-diag.sh).' \
    '%homefilesystem%' \
    'cd \EFI\btkb' \
    'echo "=== saving the driver'"'"'s log to \EFI\btkb\diag\btlog.txt"' \
    'btlog >a diag\btlog.txt' \
    "dmpstore -guid $DIAG_GUID >a diag\\vars-end.txt" \
    'echo "=== starting Limine"' \
    "%homefilesystem%$limine" \
    'echo "Limine returned. Type linux to try again."' \
    > "$dir/linux.nsh"
}

# A GPT disk image with one EFI system partition holding a directory's
# contents (attached as virtio-blk), so device paths end in HD(1,GPT,...)
# as on the board. The partition starts at 1 MiB.
make_gpt_esp_image () {
  local dir="$1" img="$2" part="$2.part"
  rm -f "$img" "$part"
  truncate -s 66M "$img"
  printf 'label: gpt\nstart=2048, size=131072, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI system partition"\n' \
    | sfdisk -q "$img"
  truncate -s 64M "$part"
  mformat -i "$part" -F -v ESP ::
  mcopy -i "$part" -s -Q "$dir"/* ::/
  dd if="$part" of="$img" bs=1M seek=1 conv=notrunc status=none
  rm -f "$part"
}
