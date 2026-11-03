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
  cp "$(img "$SHELL_EFI")" "$esp/EFI/BOOT/BOOTX64.EFI"
  # Every app that has been built: C (EDK2) and Rust. Under SB=1 the Rust
  # ones are the signed copies; the C ones stay unsigned and are refused.
  for app in "$ROOT"/Build/BtKbPkg/DEBUG_GCC/X64/*.efi; do
    [ -f "$app" ] && cp "$app" "$esp/"
  done
  for app in "$RUST_EFI_DIR"/*.efi; do
    [ -f "$app" ] && cp "$(img "$app")" "$esp/"
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
  cp "$(img "$SHELL_EFI")" "$tmp/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$(img "$RUST_EFI_DIR/bt-kb-dxe.efi")" "$tmp/esp/"
  printf '%s\r\n' '@echo -off' 'fs0:' 'bcfg driver add 0 fs0:\bt-kb-dxe.efi "Bluetooth keyboard (bt-kb-dxe)"' \
    'echo "=== driver options"' 'bcfg driver dump' 'reset -s' > "$tmp/esp/startup.nsh"
  make_esp_image "$tmp/esp" "$tmp/esp.img"
  # Without a TPM: this boot only writes the option.
  local TPM=""
  qemu_fw "$vars"
  timeout --foreground 60 "$QEMU" -machine "q35,$QEMU_MACHINE" -cpu host -m 1G -nographic -no-reboot "${QEMU_FW[@]}" \
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

# --- Secure Boot and a TPM for the QEMU runs (stage 0 of the security
# hardening; see README, Security) --------------------------------------
#
# SB=1: OVMF built with Secure Boot, SMM and TPM 2.0 support (Arch's
#   OVMF_CODE.secboot.4m.fd), on q35 with SMM and a secure flash, and a
#   variable store with throwaway test keys (PK, KEK, db; qemu/sb/keys,
#   git-ignored) enrolled and Secure Boot on. Every image the runs put on
#   an ESP comes from qemu/sb/signed/, signed with the test db key
#   (sbsign). Without sbsigntools, the images go there unsigned and their
#   Authenticode hashes are enrolled in db instead (SB_MODE=hash), which
#   tests the same enforcement.
# TPM=1: a TPM 2.0 emulated by swtpm, attached as tpm-crb.
SB_DIR="$ROOT/qemu/sb"
OVMF_SB_CODE="$OVMF_DIR/OVMF_CODE.secboot.4m.fd"
LIMINE_EFI_SRC="/usr/share/limine/BOOTX64.EFI"

# A virt-firmware tool: the packaged one, or from the venv in tools/venv-fw
# (python3 -m venv tools/venv-fw && tools/venv-fw/bin/pip install virt-firmware).
fw_tool () {
  if command -v "$1" >/dev/null 2>&1; then
    command -v "$1"
  elif [ -x "$ROOT/tools/venv-fw/bin/$1" ]; then
    echo "$ROOT/tools/venv-fw/bin/$1"
  else
    echo "$1 not found: install virt-firmware, or create tools/venv-fw (see scripts/common.sh)" >&2
    return 1
  fi
}

# sign: images are signed with sbsign; hash: their hashes go into db.
sb_mode () {
  if [ -n "${SB_MODE:-}" ]; then echo "$SB_MODE"; elif command -v sbsign >/dev/null 2>&1; then echo sign; else echo hash; fi
}

# Throwaway test keys: PK, KEK, db, and "other" (signs what db must refuse).
sb_keys () {
  local d="$SB_DIR/keys" k
  [ -f "$d/other.crt" ] && [ -f "$d/owner.guid" ] && return 0
  mkdir -p "$d"
  chmod 700 "$SB_DIR" "$d"
  for k in PK KEK db other; do
    openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=bt-kb-dxe throwaway test $k/" -keyout "$d/$k.key" -out "$d/$k.crt" 2>/dev/null
  done
  chmod 600 "$d"/*.key
  python3 -I -c 'import uuid; print(uuid.uuid4())' > "$d/owner.guid"
}

# The Authenticode SHA-256 of a PE image (what db hash entries hold).
authenticode_hash () {
  local t; t="$(mktemp)"
  hash-to-efi-sig-list "$1" "$t" | sed -n 's/^HASH IS \([0-9a-f]\{64\}\)$/\1/p'
  rm -f "$t"
}

# sb_sign IN OUT [KEY]: OUT is IN signed with a test key (default db).
sb_sign () {
  local d="$SB_DIR/keys" key="${3:-db}"
  sbsign --key "$d/$key.key" --cert "$d/$key.crt" --output "$2" "$1" >/dev/null 2>&1 \
    || { echo "sbsign failed for $1" >&2; return 1; }
}

# The signed (or hash-enrolled) copy of an image for SB=1 runs; the image
# itself otherwise. Use it wherever an image goes onto an ESP.
img () {
  if [ -n "${SB:-}" ]; then printf '%s\n' "$SB_DIR/signed/$(basename "$1")"; else printf '%s\n' "$1"; fi
}

# Sign the images the runs use (the UEFI shell, every Rust app, Limine)
# into qemu/sb/signed/, and make the variable template qemu/sb/OVMF_VARS.sb.fd.
# Cheap enough to redo before every run.
sb_prepare () {
  local mode fwvars guid f h
  mode="$(sb_mode)"
  fwvars="$(fw_tool virt-fw-vars)" || return 1
  sb_keys
  rm -rf "$SB_DIR/signed"
  mkdir -p "$SB_DIR/signed"
  guid="$(cat "$SB_DIR/keys/owner.guid")"
  local -a enroll=()
  for f in "$SHELL_EFI" "$RUST_EFI_DIR"/*.efi "$LIMINE_EFI_SRC"; do
    [ -f "$f" ] || continue
    if [ "$mode" = sign ]; then
      sb_sign "$f" "$SB_DIR/signed/$(basename "$f")" || return 1
    else
      cp "$f" "$SB_DIR/signed/"
      h="$(authenticode_hash "$f")"
      [ -n "$h" ] || { echo "no Authenticode hash for $f" >&2; return 1; }
      enroll+=(--add-db-hash "$guid" "$h")
    fi
  done
  "$fwvars" --input "$OVMF_DIR/OVMF_VARS.4m.fd" --output "$SB_DIR/OVMF_VARS.sb.fd" \
    --set-pk "$guid" "$SB_DIR/keys/PK.crt" --add-kek "$guid" "$SB_DIR/keys/KEK.crt" \
    --add-db "$guid" "$SB_DIR/keys/db.crt" "${enroll[@]}" --secure-boot >"$SB_DIR/virt-fw-vars.log" 2>&1 \
    || { echo "virt-fw-vars failed (see $SB_DIR/virt-fw-vars.log)" >&2; return 1; }
  if [ "$mode" = sign ]; then
    echo "Secure Boot: test keys enrolled; images signed with the test db key"
  else
    echo "Secure Boot: test keys enrolled; no sbsign, so the images' Authenticode hashes are enrolled in db instead"
  fi
}

# A fresh variable store for a run: Secure Boot template under SB=1.
fresh_vars () {
  if [ -n "${SB:-}" ]; then cp "$SB_DIR/OVMF_VARS.sb.fd" "$1"; else cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$1"; fi
}

# qemu_fw VARS: the firmware arguments for a run, in the array QEMU_FW, and
# the machine options in QEMU_MACHINE (q35 is added by the caller).
qemu_fw () {
  if [ -n "${SB:-}" ]; then
    QEMU_MACHINE="accel=kvm,smm=on"
    QEMU_FW=(-global driver=cfi.pflash01,property=secure,value=on -global ICH9-LPC.disable_s3=1
      -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_SB_CODE"
      -drive if=pflash,format=raw,unit=1,file="$1")
  else
    QEMU_MACHINE="accel=kvm"
    QEMU_FW=(-drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_DIR/OVMF_CODE.4m.fd"
      -drive if=pflash,format=raw,unit=1,file="$1")
  fi
  if [ -n "${TPM:-}" ]; then
    QEMU_FW+=("${QEMU_TPM[@]}")
  fi
}

# tpm_start DIR: swtpm for one QEMU run, state in DIR (kept, so a TPM
# survives reboots across runs); it exits when QEMU disconnects. Sets
# QEMU_TPM. A no-op without TPM=1.
QEMU_TPM=()
tpm_start () {
  [ -n "${TPM:-}" ] || return 0
  local dir="$1" i
  command -v swtpm >/dev/null || { echo "swtpm not found (package swtpm)" >&2; return 1; }
  mkdir -p "$dir"
  chmod 700 "$dir"
  tpm_stop "$dir"
  rm -f "$dir/swtpm.sock"
  swtpm socket --tpm2 --tpmstate dir="$dir" --ctrl type=unixio,path="$dir/swtpm.sock" \
    --terminate --daemon --pid file="$dir/swtpm.pid" --log file="$dir/swtpm.log",level="${TPM_LOG_LEVEL:-1}" \
    || { echo "swtpm didn't start (see $dir/swtpm.log)" >&2; return 1; }
  for i in $(seq 1 50); do [ -S "$dir/swtpm.sock" ] && break; sleep 0.1; done
  QEMU_TPM=(-chardev socket,id=chrtpm,path="$dir/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm
    -device "${TPM_DEVICE:-tpm-crb}",tpmdev=tpm0)
}

tpm_stop () {
  local pid
  pid="$(cat "$1/swtpm.pid" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 0.2
  fi
  rm -f "$1/swtpm.pid"
}

# tpm_host_start DIR [PORT]: the same TPM state for tpm2-tools on the host
# (provisioning): swtpm on 127.0.0.1, TCP PORT for commands and PORT+1 for
# control, with TPM2TOOLS_TCTI exported. Never while QEMU uses DIR.
tpm_host_start () {
  local dir="$1" port="${2:-2321}" i
  command -v swtpm >/dev/null || { echo "swtpm not found (package swtpm)" >&2; return 1; }
  command -v tpm2_startup >/dev/null || { echo "tpm2-tools not found (package tpm2-tools)" >&2; return 1; }
  mkdir -p "$dir"
  chmod 700 "$dir"
  tpm_stop "$dir"
  swtpm socket --tpm2 --tpmstate dir="$dir" --flags startup-clear \
    --server type=tcp,port="$port",bindaddr=127.0.0.1 --ctrl type=tcp,port=$((port + 1)),bindaddr=127.0.0.1 \
    --daemon --pid file="$dir/swtpm.pid" --log file="$dir/swtpm-host.log",level=1 \
    || { echo "swtpm didn't start (see $dir/swtpm-host.log)" >&2; return 1; }
  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$port"
  for i in $(seq 1 50); do tpm2_getcap properties-fixed >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "swtpm on port $port doesn't answer" >&2
  return 1
}

tpm_host_stop () {
  tpm_stop "$1"
  unset TPM2TOOLS_TCTI
}
