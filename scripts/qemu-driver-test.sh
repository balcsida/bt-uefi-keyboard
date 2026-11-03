#!/usr/bin/env bash
# Offline tests of the driver (bt-kb-dxe.efi) in OVMF, without the Bluetooth
# controller:
#   1. self-test: the driver types a shell command through its own console
#      path (keymap, key FIFO, Simple Text Input, ConSplitter); the shell
#      runs it, and the typed `reset -s` ends QEMU.
#   2. normal load with no MediaTek device: the driver installs its binding,
#      finds nothing, stays resident; a second load unloads itself again.
#   3. panic: message kept, notice shown, machine reset.
#   4. ExitBootServices: the hand-off handler runs.
#   5. loaded at boot (Driver####): the self-test presses F2 during OVMF's
#      boot countdown, and the boot manager's hotkey opens the boot menu.
#   6. loaded at boot, no controller: the driver watches USB, the boot goes
#      on to the shell, the OS hand-off runs and ends the boot record
#      (BtKbLastBoot); a second boot logs that record as the previous boot.
#   7. the board's diagnostics boot (scripts/board-diag.sh) on a GPT disk,
#      with a short-form Driver#### entry as efibootmgr writes it: the shell
#      in \EFI\btkb replaces it with a full device path, loads the driver;
#      `btlog` and `linux` are typed over QMP, the log is saved, and the
#      system's Limine chainloads ebs-test.efi in place of Linux.
#   8. measured boot (needs TPM=1): the driver, loaded at boot, logs PCR 7
#      and which separators were already measured; `btlog -eventlog` saves
#      the event log, and scripts/eventlog.py, replaying it, must arrive at
#      the PCR 7 value the driver read.
# The driver's log (QEMU debug console, port 0x402) is shown after each run.
# ONLY="1 3" runs just those cases.
#
# SB=1 runs every case with Secure Boot on (OVMF with SMM, throwaway test
# keys, signed images; see scripts/common.sh), TPM=1 with a TPM 2.0 (swtpm).
set -euo pipefail
. "$(dirname "$0")/common.sh"
ensure_firmware

DRIVER="$RUST_EFI_DIR/bt-kb-dxe.efi"
work="$ROOT/qemu/driver-test"
trap 'pkill -f "qemu-system-x86_64 .*${work}/" 2>/dev/null || true; for d in "$work"/*/tpm; do [ -d "$d" ] && tpm_stop "$d"; done' EXIT
if [ -n "${SB:-}" ]; then
  sb_prepare
fi

# KEEP_VARS=1: use the variable store already there; EXTRA_QEMU: more args.
# The TPM (TPM=1) keeps its state in $work/NAME/tpm.
#
# With a TPM, about one boot in ten hangs in the firmware: QEMU's TPM
# emulation stops answering for a while (a TPM command takes ~15 s) and
# the guest later stalls for good. It happens without the driver too, with
# tpm-crb and tpm-tis alike, and with swtpm's state on tmpfs (Nov 3). So a
# TPM boot that times out is retried from the same variable store and TPM
# state, twice at most; "TPM boot hung, retrying" lines count them.
run_qemu () {
  local name="$1" d="$work/$1" status=0 attempt tries=1 limit=120
  [ -n "${KEEP_VARS:-}" ] || fresh_vars "$d/OVMF_VARS.4m.fd"
  if [ -n "${TPM:-}" ]; then
    tries=3
    limit=60
    cp "$d/OVMF_VARS.4m.fd" "$d/.vars.before"
    rm -rf "$d/.tpm.before"
    [ -d "$d/tpm" ] && cp -a "$d/tpm" "$d/.tpm.before"
  fi
  for attempt in $(seq 1 "$tries"); do
    make_esp_image "$d/esp" "$d/esp.img"
    : > "$d/driver.log"
    tpm_start "$d/tpm"
    qemu_fw "$d/OVMF_VARS.4m.fd"
    status=0
    timeout --foreground "$limit" "$QEMU" -machine "q35,$QEMU_MACHINE" -cpu host -m 1G -nographic -no-reboot "${QEMU_FW[@]}" \
      -drive if=none,id=esp,format=raw,file="$d/esp.img" -device virtio-blk-pci,drive=esp \
      -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
      -chardev file,id=dbg,path="$d/driver.log" -device isa-debugcon,iobase=0x402,chardev=dbg \
      ${EXTRA_QEMU:-} -net none -serial mon:stdio > "$d/serial.log" 2>&1 || status=$?
    if [ -n "${TPM:-}" ]; then tpm_stop "$d/tpm"; fi
    if [ "$status" != 124 ] || [ "$attempt" = "$tries" ]; then
      break
    fi
    echo "(TPM boot hung, retrying: attempt $((attempt + 1)) of $tries)"
    cp "$d/.vars.before" "$d/OVMF_VARS.4m.fd"
    rm -rf "$d/tpm"
    [ -d "$d/.tpm.before" ] && cp -a "$d/.tpm.before" "$d/tpm"
  done
  rm -rf "$d/.vars.before" "$d/.tpm.before"
  [ "$status" = 0 ] || echo "(QEMU exit status $status)"
}

# A made-up bond (random key) for runs that never talk to a keyboard.
fake_bond () {
  printf 'peer=C0:00:00:00:00:01\npeer_type=static\nadapter=02:00:00:00:00:02\nltk=%s\nltk_type=1\nenc_size=16\nediv=4660\nrand=1311768467463790320\nirk=\n' \
    "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" > "$1/test.bond"
}

new_esp () {
  rm -rf "$work/$1"
  mkdir -p "$work/$1/esp/EFI/BOOT"
  cp "$(img "$SHELL_EFI")" "$work/$1/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$(img "$DRIVER")" "$work/$1/esp/"
}

want () { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }

if want 1; then
echo "##### 1. self-test: the driver types into the shell"
new_esp selftest
printf 'echo SELFTEST: typed by bt-kb-dxe, Shift+1 gives !\nreset -s\n' > "$work/selftest/esp/bt-kb-dxe.selftest"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load bt-kb-dxe.efi"' 'load bt-kb-dxe.efi' \
  'echo "=== the driver types a command in 3 s"' > "$work/selftest/esp/startup.nsh"
run_qemu selftest
clean_log "$work/selftest/serial.log" | sed -n '/^=== load/,$p' | head -20
echo "--- driver log"
cat "$work/selftest/driver.log"

fi

if want 2 || want 4; then
echo
echo "##### 2. normal load, no Bluetooth controller"
new_esp normal
cp "$FW_BIN" "$work/normal/esp/"
fake_bond "$work/normal/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load bt-kb-dxe.efi"' 'load bt-kb-dxe.efi' 'echo "=== drivers"' \
  'drivers' 'echo "=== load it again"' 'load bt-kb-dxe.efi' 'echo "=== the shell still works"' 'echo "=== done"' \
  'reset -s' > "$work/normal/esp/startup.nsh"
run_qemu normal
clean_log "$work/normal/serial.log" | sed -n '/^=== load/,$p' | grep -vE '^\s+[0-9A-F]+ [0-9A-F]+ [DB] ' | head -30
echo "--- driver log"
cat "$work/normal/driver.log"

fi

if want 3; then
echo
echo "##### 3. panic: message kept, notice shown, machine reset"
new_esp panic
printf 'panic\n' > "$work/panic/esp/bt-kb-dxe.selftest"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load bt-kb-dxe.efi"' 'load bt-kb-dxe.efi' > "$work/panic/esp/startup.nsh"
run_qemu panic
clean_log "$work/panic/serial.log" | sed -n '/^=== load/,$p' | head -6
echo "--- driver log"
cat "$work/panic/driver.log"
if grep -aq 'self-test: panic requested' "$work/panic/OVMF_VARS.4m.fd"; then
  echo "BtKbPanic variable: present in the NV variable store"
else
  echo "BtKbPanic variable: NOT FOUND in the NV variable store"
fi

fi

if want 4; then
echo
echo "##### 4. ExitBootServices: the driver's hand-off handler runs, then power-off"
new_esp ebs
cp "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$work/ebs/esp/"
fake_bond "$work/ebs/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load bt-kb-dxe.efi"' 'load bt-kb-dxe.efi' 'echo "=== ebs-test.efi"' 'ebs-test.efi' > "$work/ebs/esp/startup.nsh"
run_qemu ebs
clean_log "$work/ebs/serial.log" | sed -n '/^=== load/,$p' | head -6
echo "--- driver log"
cat "$work/ebs/driver.log"
fi

if want 5; then
echo
echo "##### 5. at boot (Driver####): the self-test presses F2 in the boot countdown"
new_esp hotkey
# F2 at 3 s, then pick the second entry of the boot menu (the ESP's shell).
printf '{f2}{wait:3000}{down}{enter}' > "$work/hotkey/esp/bt-kb-dxe.selftest"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== shell reached"' 'reset -s' > "$work/hotkey/esp/startup.nsh"
fresh_vars "$work/hotkey/OVMF_VARS.4m.fd"
add_driver_option "$work/hotkey/OVMF_VARS.4m.fd" || echo "adding the Driver#### option FAILED"
KEEP_VARS=1 EXTRA_QEMU="-boot menu=on,splash-time=8000" run_qemu hotkey
if clean_log "$work/hotkey/serial.log" | grep -q 'Please select boot device'; then
  echo "boot menu: opened by the hotkey"
else
  echo "boot menu: NOT SEEN (the hotkey didn't work)"
fi
clean_log "$work/hotkey/serial.log" | grep -m1 -o '=== shell reached' || echo "shell: NOT REACHED"
echo "--- driver log"
cat "$work/hotkey/driver.log"
fi

if want 6; then
echo
echo "##### 6. at boot (Driver####), no controller: USB watched, boot goes on, OS hand-off"
new_esp boot
cp "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$work/boot/esp/"
fake_bond "$work/boot/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== shell reached"' 'drivers -l en > fs0:\drivers.txt' \
  'echo "=== ebs-test.efi"' 'ebs-test.efi' > "$work/boot/esp/startup.nsh"
fresh_vars "$work/boot/OVMF_VARS.4m.fd"
add_driver_option "$work/boot/OVMF_VARS.4m.fd" || echo "adding the Driver#### option FAILED"
KEEP_VARS=1 run_qemu boot
clean_log "$work/boot/serial.log" | sed -n '/^=== shell reached/,$p' | head -4
echo "--- driver log"
cat "$work/boot/driver.log"
cp "$work/boot/driver.log" "$work/boot/driver-first.log"
echo "--- second boot with the same variable store"
KEEP_VARS=1 run_qemu boot
grep -m1 'previous boot:' "$work/boot/driver.log" | sed 's/^ *[0-9]* I /  /'
if grep -q 'previous boot: loaded .* OS started' "$work/boot/driver.log"; then
  echo "boot record: kept across the reboot"
else
  echo "boot record: NOT FOUND in the second boot's log"
fi
fi

if want 7; then
echo
echo "##### 7. board diagnostics boot: shell in \\EFI\\btkb, driver loaded, linux typed, Limine starts the OS"
d="$work/diag"
rm -rf "$d"
mkdir -p "$d/esp/EFI/BOOT" "$d/esp/EFI/btkb/diag" "$d/esp/EFI/limine"
# OVMF boots an outer shell that starts the one in \EFI\btkb (on the board,
# BootNext does that). First it adds a short-form driver entry, as
# efibootmgr wrote on the board; added after the firmware's driver pass, it
# isn't loaded in this boot, as on the board.
cp "$(img "$SHELL_EFI")" "$d/esp/EFI/BOOT/BOOTX64.EFI"
printf '%s\r\n' '@echo -off' \
  'bcfg driver addp 0 fs0:\EFI\btkb\bt-kb-dxe.efi "Bluetooth keyboard (bt-kb-dxe)"' \
  'fs0:\EFI\btkb\Shell.efi' > "$d/esp/startup.nsh"
cp "$(img "$SHELL_EFI")" "$d/esp/EFI/btkb/Shell.efi"
cp "$(img "$DRIVER")" "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$d/esp/EFI/btkb/"
cp "$(img "$RUST_EFI_DIR/bt-kb-log.efi")" "$d/esp/EFI/btkb/btlog.efi"
fake_bond "$d/esp/EFI/btkb"
write_diag_scripts "$d/esp/EFI/btkb" '\EFI\limine\limine_x64.efi'
# The system's Limine; its one entry chainloads ebs-test.efi in place of Linux.
cp "$(img "$LIMINE_EFI_SRC")" "$d/esp/EFI/limine/limine_x64.efi"
printf 'timeout: 1\n\n/ebs-test (stands in for Linux)\n    protocol: efi\n    path: boot():/EFI/btkb/ebs-test.efi\n' \
  > "$d/esp/EFI/limine/limine.conf"
make_gpt_esp_image "$d/esp" "$d/disk.img"
fresh_vars "$d/OVMF_VARS.4m.fd"
: > "$d/driver.log"
: > "$d/serial.log"
# Without a TPM even under TPM=1: this boot is typed into over QMP, so it
# can't be retried like run_qemu retries a hung TPM boot; case 8 covers
# the TPM.
saved_tpm="${TPM:-}"
TPM=""
qemu_fw "$d/OVMF_VARS.4m.fd"
TPM="$saved_tpm"
timeout 150 "$QEMU" -machine "q35,$QEMU_MACHINE" -cpu host -m 1G -no-reboot "${QEMU_FW[@]}" \
  -drive if=none,id=disk,format=raw,file="$d/disk.img" -device virtio-blk-pci,drive=disk \
  -device qemu-xhci,id=xhci \
  -chardev file,id=dbg,path="$d/driver.log" -device isa-debugcon,iobase=0x402,chardev=dbg \
  -display none -serial file:"$d/serial.log" -monitor none \
  -qmp unix:"$d/qmp.sock",server=on,wait=off -net none > "$d/qemu.out" 2>&1 &
qemu_pid=$!
python3 -I "$ROOT/scripts/qmp-type.py" "$d/qmp.sock" "$d/serial.log" 'board-diag.sh --collect' 'btlog\n' 100 || true
python3 -I "$ROOT/scripts/qmp-type.py" "$d/qmp.sock" "$d/serial.log" 'Keyboard layout remembered' 'linux\n' 60 || true
wait "$qemu_pid" || echo "(QEMU exit status $?)"
clean_log "$d/serial.log" | sed -n '/=== bt-kb-dxe diagnostics/,$p' | head -30
img="$d/disk.img@@1048576"
echo "--- diag files on the ESP:"
mdir -i "$img" -b ::/EFI/btkb/diag 2>/dev/null | sed 's|^::/EFI/btkb/diag/|  |'
show () { mtype -i "$img" "::/EFI/btkb/diag/$1" 2>/dev/null | tr -d '\r'; }
echo "--- load.txt: $(show load.txt | grep -v '^\s*$' | head -2)"
echo "--- driver loaded after the shell's load: $(show drivers-after.txt | grep -c 'Bluetooth LE keyboard')"
echo "--- our variables after load: $(show vars-after.txt | grep -oE 'BtKb[A-Za-z]+' | sort -u | tr '\n' ' ')"
echo "--- driver entry before: $(show bcfg-driver-before.txt | grep -m1 'DevPath' | sed 's/^[[:space:]]*//')"
echo "--- driver entry after:  $(show bcfg-driver-after.txt | grep -m1 'DevPath' | sed 's/^[[:space:]]*//')"
echo "--- driver entries after: $(show bcfg-driver-after.txt | grep -c '^Option')"
echo "--- started from Driver#### before the shell's load: $(show drivers-before.txt | grep -c 'Bluetooth LE keyboard')"
echo "--- btlog.txt: $(show btlog.txt | grep -c 'bt-kb-dxe 0.1.0 starting') start line(s), $(show btlog.txt | grep -c 'Boot-loop counter') counter line(s)"
echo "--- driver log"
cat "$d/driver.log"
fi

if want 8; then
echo
echo "##### 8. measured boot: PCR 7 and the separators at the driver, checked against the event log"
if [ -z "${TPM:-}" ]; then
  echo "skipped: needs TPM=1 (and swtpm)"
else
  new_esp measured
  cp "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$work/measured/esp/"
  cp "$(img "$RUST_EFI_DIR/bt-kb-log.efi")" "$work/measured/esp/btlog.efi"
  fake_bond "$work/measured/esp"
  printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== btlog"' 'btlog' 'btlog -eventlog fs0:\eventlog.bin' \
    'echo "=== ebs-test.efi"' 'ebs-test.efi' > "$work/measured/esp/startup.nsh"
  fresh_vars "$work/measured/OVMF_VARS.4m.fd"
  add_driver_option "$work/measured/OVMF_VARS.4m.fd" || echo "adding the Driver#### option FAILED"
  KEEP_VARS=1 run_qemu measured
  clean_log "$work/measured/serial.log" | sed -n '/^=== btlog/,$p' | grep -E 'TPM|Secure|=== ' | head -8
  echo "--- driver log (TPM lines)"
  grep -E 'TPM' "$work/measured/driver.log" | sed 's/^ *[0-9]* I /  /'
  mcopy -o -i "$work/measured/esp.img" ::/eventlog.bin "$work/measured/eventlog.bin" 2>/dev/null || true
  if [ -s "$work/measured/eventlog.bin" ]; then
    echo "--- scripts/eventlog.py driver"
    python3 -I "$ROOT/scripts/eventlog.py" driver "$work/measured/eventlog.bin" | sed 's/^/  /'
    predicted="$(python3 -I "$ROOT/scripts/eventlog.py" driver "$work/measured/eventlog.bin" | sed -n 's/^pcr7_at_driver=//p')"
    read_by_driver="$(sed -n 's/.*TPM: PCR 7 (SHA-256) = \([0-9a-f]\{64\}\).*/\1/p' "$work/measured/driver.log" | head -1)"
    if [ -n "$predicted" ] && [ "$predicted" = "$read_by_driver" ]; then
      echo "PCR 7 at the driver: the event log replay matches the value the driver read"
    else
      echo "PCR 7 at the driver: MISMATCH (replay ${predicted:-none}, driver ${read_by_driver:-none})"
    fi
  else
    echo "btlog wrote no event log"
  fi
fi
fi
