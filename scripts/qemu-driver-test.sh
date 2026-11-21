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
#   9. a changed firmware image: one byte of the MT7922 image differs, so it
#      no longer matches the SHA-256 the driver was built with (build.rs);
#      the driver refuses it and doesn't start.
#  10. Secure Boot (needs SB=1): Driver#### points at a tampered copy of the
#      driver, which the firmware refuses; the boot goes on to the shell. In
#      sign mode also the unsigned driver, and one signed with a key that
#      isn't in db.
#  11. bonds (stage 3), five boots on one variable store: a planted bond for
#      another device is refused; the trusted test bond is imported into a
#      boot-services-only variable and the file overwritten and deleted (the
#      key is nowhere in the ESP image, free space included); the next boot uses
#      the stored bond; a planted file next to it is ignored; the forget
#      marker deletes the stored bond.
#  12. the sealed bond (stage 4, needs TPM=1), eight boots on one variable
#      store and TPM: scripts/tpm-seal.sh seals the test bond from the first
#      boot's event log (swtpm over TCP on the same state); the driver
#      unseals it and extends PCR 8; `btlog -unseal-test` from the shell is
#      refused; a dbx entry changes PCR 7, so unsealing fails and the driver
#      uses its boot-services copy, until --if-needed reseals; a corrupted
#      seal fails cleanly; without a TPM the copy is used; with fallback=no
#      the copy is deleted, and a seal that then fails leaves no key.
#
# From here on the driver has a controller and a keyboard: the emulated ones
# of rust/bt-emu, which QEMU attaches as a usb-redir device. The driver is
# the same binary, and nothing touches a real radio.
#  13. a session: the keyboard is woken by typing, connects, is encrypted
#      with the test bond and discovered while more is typed; the shell runs
#      what was typed, in order. The keyboard's parameter request is
#      accepted, a media key ignored; it goes to sleep, and the next keys
#      bring it back.
#  14. at boot (Driver####), two boots: the layout is discovered and
#      remembered; at the second boot F2 from the keyboard opens OVMF's
#      boot menu, with the stored bond, the remembered layout and a
#      controller that reports encryption with version 1 of the event.
#  15. keys only from the bonded keyboard on an encrypted link (stage 1),
#      three boots: reports sent before the encryption and pairing packets
#      from the keyboard are dropped; a keyboard without the key, or with
#      another one, gets no encryption, no pairing, and types nothing.
#  16. the ACL reader against a real USB stack: two reports in one USB
#      transfer, and reports split across transfers (once inside the ACL
#      header), still arrive whole and in order.
#  17. held keys: Enter acts once; a key whose release never arrives repeats
#      until the next key press, and the driver says so.
#  18. bring-up refusals: firmware that isn't loaded on the chip; a bond
#      that belongs to another controller. The driver tries twice, then
#      leaves the controller alone for the rest of the boot.
#  19. how a session ends: ExitBootServices with a live link (the keyboard
#      is disconnected, the controller handed back); the controller
#      unplugged under the driver.
#  20. what a scan hears (bt-le-scan.efi): nothing from a sleeping
#      keyboard; a woken one directed at its bonded host, then undirected
#      with the HID service; one in pairing mode with its name in the scan
#      response.
# The driver's log (QEMU debug console, port 0x402) is shown after each run.
# ONLY="1 3" runs just those cases.
#
# SB=1 runs every case with Secure Boot on (OVMF with SMM, throwaway test
# keys, signed images; see scripts/common.sh), TPM=1 with a TPM 2.0 (swtpm).
set -euo pipefail
. "$(dirname "$0")/common.sh"
ensure_firmware

work="$ROOT/qemu/driver-test"
mkdir -p "$work"
# The driver under test is built to trust only the throwaway test bond
# (write_test_bond), into its own target directory: the production build
# in rust/target/ trusts the real bonds and nothing else.
write_test_bond "$work/test.bond"
export PATH="$HOME/.cargo/bin:$PATH"
test_digest="$(python3 -I "$ROOT/scripts/bond-digest.py" "$work/test.bond")"
# btlog gets -unseal-test here (case 12), and only here.
(cd "$ROOT/rust" && BT_KB_FIRMWARE="$FW_BIN" BT_KB_BOND_DIGESTS="$test_digest" \
  cargo build --quiet --release --target x86_64-unknown-uefi --target-dir "$ROOT/rust/target/offline-test" \
  -p bt-kb-dxe -p bt-kb-log -p ebs-test -p bt-le-scan --features bt-kb-log/unseal-test) || { echo "building the test driver failed" >&2; exit 1; }
RUST_EFI_DIR="$ROOT/rust/target/offline-test/x86_64-unknown-uefi/release"
# What scripts/tpm-seal.sh --build reads.
echo "$test_digest" > "$RUST_EFI_DIR/bt-kb-dxe.bonds"
echo "spare_pcr=8" > "$RUST_EFI_DIR/bt-kb-dxe.tpm"
DRIVER="$RUST_EFI_DIR/bt-kb-dxe.efi"
# The emulated controller and keyboard of cases 13 and up: a host program.
(cd "$ROOT/rust" && cargo build --quiet -p bt-emu) || { echo "building bt-emu failed" >&2; exit 1; }
EMU="$ROOT/rust/target/debug/bt-emu"
emu_pid=""
trap 'pkill -f "qemu-system-x86_64 .*${work}/" 2>/dev/null || true; [ -z "$emu_pid" ] || kill "$emu_pid" 2>/dev/null || true; for d in "$work"/*/tpm; do [ -d "$d" ] && tpm_stop "$d"; done' EXIT
if [ -n "${SB:-}" ]; then
  sb_prepare
fi

# emu_start DIR SCRIPT: the emulated controller and keyboard for one QEMU
# run, with the test bond as what the keyboard remembers. Its log is
# DIR/emu.log. Sets emu_sock (for QEMU's chardev) and emu_pid.
emu_start () {
  local i
  emu_sock="$1/emu.sock"
  # A Unix socket's path can't be much longer than 100 bytes.
  [ "${#emu_sock}" -lt 100 ] || emu_sock="$(mktemp -u /tmp/bt-emu.XXXXXX)"
  rm -f "$emu_sock"
  "$EMU" --socket "$emu_sock" --bond "$work/test.bond" --script "$2" --log "$1/emu.log" --quiet --timeout 170 &
  emu_pid=$!
  for i in $(seq 1 50); do
    [ -S "$emu_sock" ] && return 0
    sleep 0.1
  done
  echo "bt-emu didn't start (see $1/emu.log)" >&2
  return 1
}

# It ends by itself when QEMU closes the connection. Sets emu_status: 1 if
# a step of its script failed.
emu_stop () {
  local i
  emu_status=0
  [ -n "$emu_pid" ] || return 0
  for i in $(seq 1 30); do
    kill -0 "$emu_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill "$emu_pid" 2>/dev/null || true
  wait "$emu_pid" 2>/dev/null || emu_status=$?
  emu_pid=""
  rm -f "$emu_sock"
}

# KEEP_VARS=1: use the variable store already there; EXTRA_QEMU: more args.
# EMU_SCRIPT=FILE: with the emulated controller and keyboard, doing what
# FILE says (rust/bt-emu/src/script.rs).
# The TPM (TPM=1) keeps its state in $work/NAME/tpm.
#
# With a TPM, about one boot in ten hangs in the firmware: QEMU's TPM
# emulation stops answering for a while (a TPM command takes ~15 s) and
# the guest later stalls for good. It happens without the driver too, with
# tpm-crb and tpm-tis alike, and with swtpm's state on tmpfs (Nov 3). So a
# TPM boot that times out is retried from the same variable store and TPM
# state, twice at most; "TPM boot hung, retrying" lines count them.
run_qemu () {
  local name="$1" d="$work/$1" status=0 attempt tries=1 limit=120 emu=()
  emu_status=0
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
    if [ -n "${EMU_SCRIPT:-}" ]; then
      emu_start "$d" "$EMU_SCRIPT"
      emu=(-chardev "socket,id=emu,path=$emu_sock" -device usb-redir,chardev=emu,bus=xhci.0)
    fi
    status=0
    timeout --foreground "$limit" "$QEMU" -machine "q35,$QEMU_MACHINE" -cpu host -m 1G -nographic -no-reboot "${QEMU_FW[@]}" \
      -drive if=none,id=esp,format=raw,file="$d/esp.img" -device virtio-blk-pci,drive=esp \
      -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 "${emu[@]}" \
      -chardev file,id=dbg,path="$d/driver.log" -device isa-debugcon,iobase=0x402,chardev=dbg \
      ${EXTRA_QEMU:-} -net none -serial mon:stdio > "$d/serial.log" 2>&1 || status=$?
    if [ -n "${EMU_SCRIPT:-}" ]; then emu_stop; fi
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
  [ "$emu_status" = 0 ] || echo "(bt-emu exit status $emu_status)"
}

# check WHAT CONDITION: one line, "WHAT: yes" or "WHAT: NO".
check () { if eval "$2"; then echo "  $1: yes"; else echo "  $1: NO"; fi; }

# The test bond, for runs that never talk to a keyboard.
fake_bond () {
  cp "$work/test.bond" "$1/test.bond"
}

# A bond for a device the test build doesn't trust.
planted_bond () {
  printf 'peer=C0:00:00:00:00:66\npeer_type=static\nadapter=02:00:00:00:00:02\nltk=%s\nltk_type=1\nenc_size=16\nediv=4660\nrand=1311768467463790320\nirk=\n' \
    "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" > "$1/$2"
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
if grep -q 'Please select boot device' < <(clean_log "$work/hotkey/serial.log"); then
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
# can't be retried like run_qemu retries a hung TPM boot; cases 8 and 12
# cover the TPM.
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

if want 9; then
echo
echo "##### 9. a changed firmware image is refused (SHA-256 pinned at build time)"
new_esp fwpin
cp "$FW_BIN" "$work/fwpin/esp/"
fw="$work/fwpin/esp/$FW_NAME"
# One byte in the middle of section 1's data.
printf '\x5a' | dd of="$fw" bs=1 seek=$(( $(stat -c %s "$fw") / 2 )) conv=notrunc status=none
fake_bond "$work/fwpin/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load bt-kb-dxe.efi"' 'load bt-kb-dxe.efi' 'echo "=== drivers"' 'drivers' \
  'echo "=== done"' 'reset -s' > "$work/fwpin/esp/startup.nsh"
run_qemu fwpin
clean_log "$work/fwpin/serial.log" | sed -n '/^=== load/,/^=== drivers/p' | head -3
echo "--- driver log"
cat "$work/fwpin/driver.log"
if grep -q "isn't the image this driver was built for" "$work/fwpin/driver.log" \
  && ! grep -q 'Bluetooth LE keyboard' < <(clean_log "$work/fwpin/serial.log"); then
  echo "firmware pin: the changed image was refused, the driver didn't stay"
else
  echo "firmware pin: NOT REFUSED"
fi
fi

if want 10; then
echo
echo "##### 10. Secure Boot: a driver db doesn't allow is refused, and the boot goes on"
if [ -z "${SB:-}" ]; then
  echo "skipped: needs SB=1"
else
  variants="tampered"
  [ "$(sb_mode)" = sign ] && variants="tampered unsigned other-key"
  for variant in $variants; do
    new_esp "sb-$variant"
    drv="$work/sb-$variant/esp/bt-kb-dxe.efi"
    case "$variant" in
      tampered) printf '\x01' | dd of="$drv" bs=1 seek=$(( $(stat -c %s "$drv") - 64 )) conv=notrunc status=none ;;
      unsigned) cp "$DRIVER" "$drv" ;;
      other-key) sb_sign "$DRIVER" "$drv" other ;;
    esac
    cp "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$work/sb-$variant/esp/"
    fake_bond "$work/sb-$variant/esp"
    printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== shell reached"' 'drivers' 'echo "=== ebs-test.efi"' 'ebs-test.efi' \
      > "$work/sb-$variant/esp/startup.nsh"
    fresh_vars "$work/sb-$variant/OVMF_VARS.4m.fd"
    add_driver_option "$work/sb-$variant/OVMF_VARS.4m.fd" >/dev/null || echo "adding the Driver#### option FAILED"
    KEEP_VARS=1 run_qemu "sb-$variant"
    if [ ! -s "$work/sb-$variant/driver.log" ] && grep -q '^=== shell reached' < <(clean_log "$work/sb-$variant/serial.log") \
      && ! grep -q 'Bluetooth LE keyboard' < <(clean_log "$work/sb-$variant/serial.log"); then
      echo "Secure Boot, $variant driver: refused, boot went on to the shell"
    else
      echo "Secure Boot, $variant driver: NOT REFUSED (or the boot stopped)"
    fi
  done
fi
fi

if want 11; then
echo
echo "##### 11. bonds: planted ones refused, the trusted one imported and its file deleted, forgotten on request"
b="$work/bonds"
rm -rf "$b"
mkdir -p "$b/esp/EFI/BOOT"
cp "$(img "$SHELL_EFI")" "$b/esp/EFI/BOOT/BOOTX64.EFI"
cp "$(img "$DRIVER")" "$FW_BIN" "$b/esp/"
fresh_vars "$b/OVMF_VARS.4m.fd"
startup () {
  # These boots never reach an OS: reset the boot-loop counter each time.
  printf '%s\r\n' '@echo -off' 'fs0:' "dmpstore -d BtKbBoots -guid $DIAG_GUID" 'echo "=== load"' 'load bt-kb-dxe.efi' 'echo "=== stored bond"' \
    "dmpstore BtKbBond -guid $DIAG_GUID" 'echo "=== files"' 'ls fs0:\*.bond' 'echo "=== done"' 'reset -s' > "$b/esp/startup.nsh"
}
boot () { # boot N: one boot; its logs kept as N.*
  startup
  KEEP_VARS=1 run_qemu bonds
  cp "$b/driver.log" "$b/$1.driver.log"
  clean_log "$b/serial.log" > "$b/$1.serial.log"
  # The driver deletes imported files from the image; mirror that.
  mdir -i "$b/esp.img" -b ::/ 2>/dev/null | sed 's|^::/||' > "$b/$1.files"
}
planted_bond "$b/esp" other.bond
boot 1
check "1. a planted bond for another device is refused" "grep -q 'other.bond is a bond this driver wasn.t built for' $b/1.driver.log && grep -q 'no bond:' $b/1.driver.log"
fake_bond "$b/esp"
boot 2
check "2. the trusted bond is imported, its file deleted from the ESP" "grep -q 'bond imported into a variable the OS can.t read; test.bond overwritten and deleted' $b/2.driver.log && ! grep -qi '^test.bond' $b/2.files"
# A plain delete leaves a file's contents in the FAT's free clusters. The
# control: an image made with the file in it shows the key to the scan.
has_test_key () {
  python3 -I -c 'import sys; d = open(sys.argv[1], "rb").read(); k = "7E57B0ED7E57B0ED7E57B0ED7E57B0ED"
sys.exit(0 if any(x in d for x in (k.encode(), k.lower().encode(), bytes.fromhex(k))) else 1)' "$1"
}
make_esp_image "$b/esp" "$b/control.img"
check "   overwritten first: the key is nowhere in the ESP image, free space included" \
  "has_test_key $b/control.img && ! has_test_key $b/esp.img"
rm -f "$b/control.img"
check "   stored without runtime access (NV+BS only)" "grep -q \"Variable NV+BS '.*:BtKbBond'\" $b/2.serial.log"
rm -f "$b/esp/test.bond"
boot 3
check "3. the next boot uses the stored bond" "grep -q 'bond for C0:00:00:00:00:01 .*(stored)' $b/3.driver.log"
# Every variable the driver writes: only BtKbBond (no RUNTIME_ACCESS) may
# hold the link key; the others, and the log (BtKbLog), are world-readable
# in Linux's efivarfs.
"$(fw_tool virt-fw-vars)" --input "$b/OVMF_VARS.4m.fd" --output-json "$b/3.vars.json" >/dev/null 2>&1
check "   no variable the OS can read holds the link key; only BtKbBond (NV+BS) does" \
  "python3 -I - '$b/3.vars.json' '$b/3.driver.log' 7E57B0ED7E57B0ED7E57B0ED7E57B0ED <<'PY'
import json, sys
vars_json, log, ltk = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
ours = [v for v in json.load(open(vars_json))['variables'] if v['guid'].lower() == '$DIAG_GUID']
bad = [v['name'] for v in ours if v['attr'] & 0x4 and any(k in bytes.fromhex(v['data']) for k in (ltk, ltk[::-1]))]
bond = [v for v in ours if v['name'] == 'BtKbBond']
text = open(log, encoding='latin-1').read().lower()
leaked = any(k.hex() in text.replace(' ', '') for k in (ltk, ltk[::-1]))
ok = not bad and len(bond) == 1 and bond[0]['attr'] == 0x3 and ltk in bytes.fromhex(bond[0]['data']) and not leaked
print('   runtime variables:', sorted(v['name'] for v in ours if v['attr'] & 0x4), file=sys.stderr)
sys.exit(0 if ok else 1)
PY"
boot 4
check "4. a planted file next to the stored bond is ignored" "grep -q 'other.bond is a bond this driver wasn.t built for' $b/4.driver.log && grep -q '(stored)' $b/4.driver.log"
rm -f "$b/esp/other.bond"
: > "$b/esp/bt-kb-dxe.forget"
boot 5
check "5. the forget marker deletes the stored bond and itself" "grep -q 'stored bond deleted' $b/5.driver.log && ! grep -qi 'bt-kb-dxe.forget' $b/5.files && ! grep -q \"Variable .*:BtKbBond'\" $b/5.serial.log"
rm -f "$b/esp/bt-kb-dxe.forget"
boot 6
check "6. afterwards there is no bond" "grep -q 'no bond:' $b/6.driver.log"
fi

if want 12; then
echo
echo "##### 12. the sealed bond: unsealed by the driver only, resealed after a change, fallbacks"
if [ -z "${TPM:-}" ]; then
  echo "skipped: needs TPM=1 (swtpm and tpm2-tools)"
else
  t="$work/tpmseal"
  new_esp tpmseal
  cp "$FW_BIN" "$t/esp/"
  cp "$(img "$RUST_EFI_DIR/bt-kb-log.efi")" "$t/esp/btlog.efi"
  fake_bond "$t/esp"
  fresh_vars "$t/OVMF_VARS.4m.fd"
  add_driver_option "$t/OVMF_VARS.4m.fd" || echo "adding the Driver#### option FAILED"
  # These boots never reach an OS: each clears the boot-loop counter.
  printf '%s\r\n' '@echo -off' 'fs0:' "dmpstore -d BtKbBoots -guid $DIAG_GUID" 'echo "=== btlog"' \
    'btlog -eventlog fs0:\eventlog.bin' 'echo "=== unseal-test"' 'btlog -unseal-test' 'echo "=== stored bond"' \
    "dmpstore BtKbBond -guid $DIAG_GUID" 'echo "=== done"' 'reset -s' > "$t/esp/startup.nsh"
  boot12 () { # boot12 N: one boot; logs kept as N.*, the event log as N.eventlog
    KEEP_VARS=1 run_qemu tpmseal
    cp "$t/driver.log" "$t/$1.driver.log"
    clean_log "$t/serial.log" > "$t/$1.serial.log"
    rm -f "$t/$1.eventlog"
    mcopy -o -i "$t/esp.img" ::/eventlog.bin "$t/$1.eventlog" 2>/dev/null || true
    # The driver deletes imported bond files; mirror that.
    grep -qi 'test.bond' < <(mdir -i "$t/esp.img" -b ::/ 2>/dev/null) || rm -f "$t/esp/test.bond"
  }
  seal12 () { # seal12 ARGS...: scripts/tpm-seal.sh against the case's TPM
    tpm_host_start "$t/tpm" 2391 > /dev/null || return 1
    if [[ "${TPM2TOOLS_TCTI:-}" != swtpm:* ]]; then echo "TPM2TOOLS_TCTI isn't swtpm's: not sealing"; tpm_host_stop "$t/tpm"; return 1; fi
    EFIVARS="$t/no-efivars" "$ROOT/scripts/tpm-seal.sh" --bond "$work/test.bond" --build "$RUST_EFI_DIR" \
      --driver "$t/esp/bt-kb-dxe.efi" --out "$t/esp/bt-kb-dxe.sealed" "$@" 2>&1 | sed 's/^/    /'
    tpm_host_stop "$t/tpm"
  }
  mkdir -p "$t/no-efivars"

  boot12 1
  check "1. first boot: no seal yet, the bond imported, PCR 8 extended anyway" \
    "grep -q 'bond imported' $t/1.driver.log && grep -q 'TPM: PCR 8 extended' $t/1.driver.log"
  python3 -I "$ROOT/scripts/eventlog.py" predict "$t/1.eventlog" 2,7 --spare 8 > "$t/1.predict" 2>/dev/null || true
  python3 -I "$ROOT/scripts/eventlog.py" show "$t/1.eventlog" > "$t/1.events" 2>/dev/null || true
  check "   the event log logs the driver's image with the hash scripts/eventlog.py computes for it" \
    "grep -qx \"driver_logged=\$(python3 -I $ROOT/scripts/eventlog.py pehash $t/esp/bt-kb-dxe.efi)\" $t/1.predict"
  check "   and PCR 8's EV_EFI_ACTION after it" "grep -q 'PCR  8 EV_EFI_ACTION' $t/1.events"
  echo "  sealing from the first boot's event log:"
  seal12 --eventlog "$t/1.eventlog"
  check "   sealed" "[ -s $t/esp/bt-kb-dxe.sealed ] && grep -q '^fallback=yes' $t/esp/bt-kb-dxe.sealed"
  cp "$t/esp/bt-kb-dxe.sealed" "$t/sealed.good"

  boot12 2
  check "2. the driver unseals the bond" "grep -q 'TPM: bond unsealed' $t/2.driver.log && grep -q '(unsealed from the TPM)' $t/2.driver.log"
  check "   a shell app after the separators can't" \
    "grep -q 'unseal-test: refused with the expected values' $t/2.serial.log && grep -q 'unseal-test: refused without them: the TPM policy failed' $t/2.serial.log && ! grep -q 'UNSEALED' $t/2.serial.log"

  "$(fw_tool virt-fw-vars)" --input "$t/OVMF_VARS.4m.fd" --output "$t/OVMF_VARS.dbx.fd" \
    --add-dbx-hash 11111111-2222-3333-4444-555555555555 5c1d2e3f4a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5 > "$t/dbx.log" 2>&1
  mv "$t/OVMF_VARS.dbx.fd" "$t/OVMF_VARS.4m.fd"
  boot12 3
  check "3. after a dbx update unsealing fails (PCR 7 changed), the boot-services copy is used" \
    "grep -q 'unsealing failed: the PCRs changed since sealing' $t/3.driver.log && grep -q 'PCRs that changed since sealing: 7' $t/3.driver.log && grep -q '(stored)' $t/3.driver.log"
  echo "  resealing with --if-needed, twice:"
  seal12 --eventlog "$t/3.eventlog" --if-needed
  seal12 --eventlog "$t/3.eventlog" --if-needed
  check "   resealed once, then up to date" "! cmp -s $t/sealed.good $t/esp/bt-kb-dxe.sealed"
  cp "$t/esp/bt-kb-dxe.sealed" "$t/sealed.good"

  boot12 4
  check "4. the resealed bond unseals" "grep -q 'TPM: bond unsealed' $t/4.driver.log"

  python3 -I - "$t/sealed.good" "$t/esp/bt-kb-dxe.sealed" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
for i, l in enumerate(lines):
    if l.startswith("private="):
        b = bytearray.fromhex(l[8:]); b[len(b) // 2] ^= 0x01; lines[i] = "private=" + b.hex()
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
  boot12 5
  check "5. a corrupted seal fails cleanly, the copy is used" \
    "grep -q 'the TPM refused to load the sealed bond' $t/5.driver.log && grep -q '(stored)' $t/5.driver.log && grep -q '=== done' $t/5.serial.log"

  cp "$t/sealed.good" "$t/esp/bt-kb-dxe.sealed"
  saved_tpm="$TPM"
  TPM=""
  boot12 6
  TPM="$saved_tpm"
  check "6. without a TPM the boot-services copy is used" \
    "grep -q 'TPM: none' $t/6.driver.log && grep -q 'no TPM 2.0: using the boot-services copy' $t/6.driver.log && grep -q '(stored)' $t/6.driver.log"

  echo "  sealing again with --no-fallback:"
  seal12 --eventlog "$t/4.eventlog" --no-fallback
  boot12 7
  check "7. fallback=no: unsealed, and the boot-services copy deleted" \
    "grep -q 'TPM: bond unsealed' $t/7.driver.log && grep -q 'the boot-services copy of the bond was deleted' $t/7.driver.log && grep -q 'dmpstore: No matching variables' $t/7.serial.log"
  python3 -I - "$t/esp/bt-kb-dxe.sealed" "$t/esp/bt-kb-dxe.sealed" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
for i, l in enumerate(lines):
    if l.startswith("private="):
        b = bytearray.fromhex(l[8:]); b[len(b) // 2] ^= 0x01; lines[i] = "private=" + b.hex()
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
  boot12 8
  check "8. fallback=no and a failed unseal: no key anywhere, the driver doesn't start" \
    "grep -q 'the seal allows no other copy' $t/8.driver.log && ! grep -q 'bond for C0' $t/8.driver.log"
  for n in 1 2 3 4 5 6 7 8; do
    if grep -qE 'PANIC|panicked' "$t/$n.driver.log"; then echo "  boot $n: PANIC in the driver log"; fi
  done
fi
fi

# ----- With the emulated controller and keyboard (rust/bt-emu) -----------

# emu_esp NAME: an ESP whose shell loads the driver and stays at its prompt,
# for the keyboard to type at.
emu_esp () {
  new_esp "$1"
  cp "$FW_BIN" "$(img "$RUST_EFI_DIR/ebs-test.efi")" "$work/$1/esp/"
  fake_bond "$work/$1/esp"
  printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load"' 'load bt-kb-dxe.efi' 'echo "=== loaded"' > "$work/$1/esp/startup.nsh"
}

# What the shell showed once the driver was loaded, into NAME/shell.txt.
shell_after_load () {
  clean_log "$work/$1/serial.log" | sed -n '/^=== loaded/,$p' > "$work/$1/shell.txt"
}

# The emulator's verdict on its script: the steps that failed, and whether
# it ran to its end.
emu_verdict () {
  local log="$work/$1/emu.log"
  grep 'FAILED' "$log" | sed 's/^ *[0-9]* /  emulator: /' || true
  check "the emulator's script ran to its end, every expectation held" "grep -q 'summary: script: ran to its end, 0 failed' $log"
}

# Every key report the keyboard sent was counted by the driver. (The
# release of the Enter that resets the machine can come too late.)
key_counts () {
  local sent got
  sent="$(sed -n 's/.* \([0-9]*\) key reports sent.*/\1/p' "$work/$1/emu.log" | tail -1)"
  got="$(sed -n 's/.*controller handed back (\([0-9]*\) key reports this session).*/\1/p' "$work/$1/driver.log" | tail -1)"
  check "every key report arrived (${got:-?} of ${sent:-?})" "[ -n '$sent' ] && [ -n '$got' ] && { [ '$got' = '$sent' ] || [ '$got' = '$((${sent:-0} - 1))' ]; }"
}

# The driver's log without the lines every run has.
driver_log () {
  grep -vE 'key notify [0-9]+ registered|timing \(' "$work/$1/driver.log" || true
}

if want 13; then
echo
echo "##### 13. emulated keyboard: connect, encrypt, discover, type; sleep and come back"
emu_esp emu-session
s="$work/emu-session"
cat > "$s/emu.script" <<'EOF'
# A first connection: keys are typed while the driver discovers the keyboard.
set param-after 1500
set idle 4000
wait initiating 30000
sleep 200
type echo EMU-TYPED-1{enter}
wait encrypted 10000
wait sent 20000
wait att-quiet-ms >= 400 20000
expect connections = 1
expect encryptions = 1
expect smp-from-host = 0
expect unknown-commands = 0
expect keys-notifying = 1
wait param-accepted >= 1 10000
wait connection-updates >= 1 5000
media ea
wait sent 5000
# The keyboard goes to sleep. The next keys wake it, and arrive.
wait disconnected 15000
expect kbd-disconnects = 1
sleep 300
type echo SECOND Line 2!{enter}
wait connections >= 2 10000
wait sent 20000
sleep 600
expect encryptions = 2
type reset -s{enter}
wait sent 5000
EOF
EMU_SCRIPT="$s/emu.script" run_qemu emu-session
shell_after_load emu-session
sed -n '2,6p' "$s/shell.txt"
check "typed during discovery, and run in order" "grep -qx 'EMU-TYPED-1' $s/shell.txt"
check "typed after the keyboard slept and came back" "grep -qx 'SECOND Line 2!' $s/shell.txt"
check "encrypted with the bonded key twice, the host stack agreeing" \
  "[ \$(grep -c 'keyboard link encrypted with the bonded key' $s/driver.log) = 2 ] && [ \$(grep -c 'encryption confirmed by the host stack' $s/driver.log) = 2 ]"
check "the layout discovered and remembered" "grep -q 'keyboard layout remembered for the next boots' $s/driver.log"
check "the keyboard's parameter request accepted" \
  "grep -q 'asked for new connection parameters (interval 25 ms-45 ms, latency 4, timeout 2000 ms): accepted' $s/driver.log"
check "a media key ignored" "grep -q 'report on handle 0x0016 ignored (not the keyboard report): ea 00' $s/driver.log"
check "the keyboard's idle disconnect seen" "grep -q 'keyboard disconnected (reason 0x13)' $s/driver.log"
check "no report dropped, no command refused, no panic" "! grep -qE 'dropped|refused to send|PANIC' $s/driver.log"
key_counts emu-session
emu_verdict emu-session
echo "--- driver log"
driver_log emu-session
fi

if want 14; then
echo
echo "##### 14. emulated keyboard at boot (Driver####): F2 opens the boot menu; stored bond, remembered layout"
new_esp emu-hotkey
h="$work/emu-hotkey"
cp "$FW_BIN" "$h/esp/"
fake_bond "$h/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== shell reached"' 'reset -s' > "$h/esp/startup.nsh"
fresh_vars "$h/OVMF_VARS.4m.fd"
add_driver_option "$h/OVMF_VARS.4m.fd" || echo "adding the Driver#### option FAILED"
cat > "$h/emu.script" <<'EOF'
# First boot: the keyboard connects, and its layout is discovered.
wait initiating 30000
wake
wait encrypted 10000
wait att-quiet-ms >= 400 20000
expect keys-notifying = 1
EOF
KEEP_VARS=1 EMU_SCRIPT="$h/emu.script" run_qemu emu-hotkey
cp "$h/driver.log" "$h/1.driver.log"
cp "$h/emu.log" "$h/1.emu.log"
check "first boot: bond imported, layout discovered and remembered" \
  "grep -q 'bond imported into a variable' $h/1.driver.log && grep -q 'keyboard layout remembered for the next boots' $h/1.driver.log"
# The driver deleted the imported bond file from the image; mirror that.
rm -f "$h/esp/test.bond"
cat > "$h/emu.script" <<'EOF'
# Second boot: F2 in the boot countdown, on a controller that reports
# encryption the old way; then the second entry of the boot menu.
set encryption-change-v1 1
wait initiating 30000
type {f2}
wait encrypted 10000
wait sent 5000
sleep 3000
type {down}{enter}
wait sent 5000
EOF
KEEP_VARS=1 EXTRA_QEMU="-boot menu=on,splash-time=8000" EMU_SCRIPT="$h/emu.script" run_qemu emu-hotkey
clean_log "$h/serial.log" > "$h/serial.txt"
check "boot menu: opened by the keyboard's F2" "grep -q 'Please select boot device' $h/serial.txt"
check "the menu's second entry started the shell" "grep -q '^=== shell reached' $h/serial.txt"
check "the stored bond and the remembered layout were used" \
  "grep -q '(stored)' $h/driver.log && grep -q 'using the keyboard layout remembered from an earlier boot' $h/driver.log && grep -q 'the remembered keyboard layout still matches' $h/driver.log"
check "Encryption Change v1 understood" "grep -q 'keyboard link encrypted with the bonded key (Encryption Change v1)' $h/driver.log"
check "F2 ran the boot manager's hotkey" "grep -q 'key F2 delivered (1 key notify functions ran)' $h/driver.log"
emu_verdict emu-hotkey
echo "--- driver log of the second boot"
driver_log emu-hotkey
fi

if want 15; then
echo
echo "##### 15. emulated keyboard, stage 1: keys only from the bonded keyboard on an encrypted link"
# a. An attacker in radio range: key reports before the link is encrypted,
#    and pairing packets before and after.
emu_esp emu-attack
a="$work/emu-attack"
cat > "$a/emu.script" <<'EOF'
set encrypt-delay 1200
wait initiating 30000
wake
wait connected 10000
attack-type echo PWNED-A{enter}
# SMP Security Request, then (on the encrypted link) a Pairing Request.
l2cap 0006 0b 01
wait encrypted 10000
wait att-quiet-ms >= 400 20000
l2cap 0006 01 03 00 01 10 07 07
type echo OK-A{enter}
wait sent 10000
sleep 500
expect smp-from-host = 0
expect encryptions = 1
type reset -s{enter}
wait sent 5000
EOF
EMU_SCRIPT="$a/emu.script" run_qemu emu-attack
shell_after_load emu-attack
check "a. reports from before the encryption never reached the shell" "! grep -q PWNED $a/shell.txt && grep -q 'dropped 26 key reports that arrived before the link was encrypted' $a/driver.log"
check "   the keyboard's own typing did" "grep -qx 'OK-A' $a/shell.txt"
check "   pairing packets from the keyboard dropped, none answered" "grep -q 'dropped a pairing (SMP) packet' $a/driver.log && grep -q ' 0 pairing packets from the host' $a/emu.log"
emu_verdict emu-attack

# b. The keyboard has no key for this host (reset, or paired with another
#    computer), and what it sends is typed anyway by whoever holds it.
emu_esp emu-nokey
n="$work/emu-nokey"
printf '12' > "$n/esp/bt-kb-dxe.timelimit"
cat > "$n/emu.script" <<'EOF'
set bond none
wait initiating 30000
wake
wait connected 10000
wait refused >= 1 10000
attack-type echo PWNED-B{enter}
sleep 4000
expect smp-from-host = 0
expect encryptions = 0
EOF
EMU_SCRIPT="$n/emu.script" run_qemu emu-nokey
shell_after_load emu-nokey
check "b. a keyboard without the key: no encryption, nothing typed" \
  "! grep -q PWNED $n/shell.txt && grep -q 'keyboard session ended: the keyboard rejected the stored key' $n/driver.log && grep -q 'controller handed back (0 key reports this session)' $n/driver.log"
check "   the host stack wanted to pair afresh; no pairing packet left the driver" \
  "grep -q 'initiating fresh pairing' $n/driver.log && grep -q ' 0 pairing packets from the host' $n/emu.log"
check "   its reports dropped and counted" "grep -q 'key reports arrived on that connection before it was encrypted, and were dropped' $n/driver.log"
emu_verdict emu-nokey

# c. The keyboard's key differs from the driver's.
emu_esp emu-wrongkey
k="$work/emu-wrongkey"
printf '8' > "$k/esp/bt-kb-dxe.timelimit"
cat > "$k/emu.script" <<'EOF'
set bond wrong-key
wait initiating 30000
wake
wait mic-failures >= 1 10000
sleep 2500
expect encryptions = 0
expect smp-from-host = 0
EOF
EMU_SCRIPT="$k/emu.script" run_qemu emu-wrongkey
check "c. another key: the link is lost at the encryption, nothing typed" \
  "grep -q 'keyboard disconnected (reason 0x3d)' $k/driver.log && grep -q 'controller handed back (0 key reports this session)' $k/driver.log"
emu_verdict emu-wrongkey
echo "--- driver log of a."
driver_log emu-attack
echo "--- driver log of b. (first connection)"
driver_log emu-nokey | sed -n '/waiting for the keyboard/,/key reports arrived on that connection/p' | head -12
fi

if want 16; then
echo
echo "##### 16. emulated keyboard: reports merged into one USB transfer and split across transfers"
emu_esp emu-shaping
g="$work/emu-shaping"
cat > "$g/emu.script" <<'EOF'
wait initiating 30000
wake
wait encrypted 10000
wait att-quiet-ms >= 400 20000
type echo M
wait sent 5000
# A press and its release in one transfer.
set acl-merge 2
type e
wait sent 5000
# A report cut after the ACL header and three bytes; then inside the header.
set acl-split 7
type r
wait sent 5000
set acl-split 3
type g
wait sent 5000
set acl-merge 3
type ed{enter}
wait sent 5000
expect merged = 2
expect split = 2
sleep 500
type reset -s{enter}
wait sent 5000
EOF
EMU_SCRIPT="$g/emu.script" run_qemu emu-shaping
shell_after_load emu-shaping
check "every key arrived, in order" "grep -qx 'Merged' $g/shell.txt"
check "the driver saw both layouts" \
  "grep -q 'ACL pipe so far: 2 transfers held more than one packet, 2 packets spanned transfers' $g/driver.log && ! grep -q 'out of step' $g/driver.log"
key_counts emu-shaping
emu_verdict emu-shaping
grep -o 'summary: usb.*' "$g/emu.log" | sed 's/^/  emulator /'
fi

if want 17; then
echo
echo "##### 17. emulated keyboard: held keys, and a key whose release never arrives"
emu_esp emu-repeat
r="$work/emu-repeat"
cat > "$r/emu.script" <<'EOF'
wait initiating 30000
wake
wait encrypted 10000
wait att-quiet-ms >= 400 20000
# Enter held for 2 s.
type echo X
wait sent 5000
hold 28 2000
wait sent 5000
sleep 300
# 'a' goes down and its release is lost; 2 s later 'b' is pressed.
type echo{space}
wait sent 5000
report 00 04
wait sent 5000
sleep 2000
report 00 05
report 00
wait sent 5000
sleep 300
type {enter}
wait sent 5000
sleep 500
type reset -s{enter}
wait sent 5000
EOF
EMU_SCRIPT="$r/emu.script" run_qemu emu-repeat
shell_after_load emu-repeat
check "Enter held for 2 s ran the command once" "[ \$(grep -cx 'X' $r/shell.txt) = 1 ] && [ \$(grep -c '^FS0:.> *$' $r/shell.txt) -le 1 ]"
check "the key without a release repeated until the next key" "grep -qE '^a{40,}b$' $r/shell.txt"
check "the driver flagged the lost release" \
  "grep -q 'a key that had repeated for over 1.5 s stopped only when another key was pressed: its release report was probably lost (1 so far)' $r/driver.log"
emu_verdict emu-repeat
fi

if want 18; then
echo
echo "##### 18. emulated controller: bring-up refusals"
for which in nofw otheradapter; do
  new_esp "emu-$which"
  u="$work/emu-$which"
  cp "$FW_BIN" "$u/esp/"
  fake_bond "$u/esp"
  printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== load"' 'load bt-kb-dxe.efi' 'echo "=== loaded"' 'reset -s' > "$u/esp/startup.nsh"
  if [ "$which" = nofw ]; then
    printf '%s\n' '# As after a power cut: the chip has lost its firmware patch.' 'set firmware-loaded 0' 'wait wmt-commands >= 1 30000' > "$u/emu.script"
  else
    printf '%s\n' '# The bond was made on another controller.' 'set bd-addr 02:00:00:00:00:03' 'wait hci-resets >= 1 30000' > "$u/emu.script"
  fi
  EMU_SCRIPT="$u/emu.script" run_qemu "emu-$which"
done
u="$work/emu-nofw"
check "firmware not loaded: refused, nothing uploaded" \
  "grep -q 'firmware section 0 is not loaded on the chip' $u/driver.log && ! grep -q 'a firmware section was uploaded' $u/emu.log && ! grep -q 'waiting for the keyboard' $u/driver.log"
check "   tried twice, then left alone, with the controller handed back each time" \
  "[ \$(grep -c 'is not loaded on the chip' $u/driver.log) = 2 ] && grep -q 'leaving it alone until the next boot' $u/driver.log && [ \$(grep -c 'Handoff: HCI_Reset + function off: ok' $u/driver.log) = 2 ]"
emu_verdict emu-nofw
u="$work/emu-otheradapter"
check "a bond for another controller: refused" \
  "grep -q 'this controller is 02:00:00:00:00:03, but the bond belongs to 02:00:00:00:00:02' $u/driver.log && ! grep -q 'waiting for the keyboard' $u/driver.log"
emu_verdict emu-otheradapter
fi

if want 19; then
echo
echo "##### 19. emulated keyboard: how a session ends"
# a. An OS starts while the keyboard is connected.
emu_esp emu-ebs
e="$work/emu-ebs"
cat > "$e/emu.script" <<'EOF'
set idle off
wait initiating 30000
wake
wait encrypted 10000
wait att-quiet-ms >= 400 20000
type ebs-test.efi{enter}
wait sent 5000
# The hand-off: the keyboard disconnected, the controller reset and off.
wait function-on = 0 15000
expect host-disconnects = 1
expect connected = 0
EOF
EMU_SCRIPT="$e/emu.script" run_qemu emu-ebs
check "a. ExitBootServices: keyboard disconnected, controller handed back" \
  "grep -q 'an OS is starting (ExitBootServices' $e/driver.log && grep -q 'disconnecting the keyboard (handle 0x0200)' $e/driver.log && grep -q 'Handoff: HCI_Reset + function off: ok' $e/driver.log"
emu_verdict emu-ebs

# b. The controller disappears under the driver (unplugged), while the
#    shell is busy; the machine has to carry on.
emu_esp emu-unplug
p="$work/emu-unplug"
printf '%s\r\n' 'stall 8000000' 'echo "=== still alive"' 'reset -s' >> "$p/esp/startup.nsh"
cat > "$p/emu.script" <<'EOF'
wait initiating 30000
wake
wait encrypted 10000
wait att-quiet-ms >= 400 20000
sleep 500
quit
EOF
EMU_SCRIPT="$p/emu.script" run_qemu emu-unplug
shell_after_load emu-unplug
check "b. unplugged while connected: the driver stopped, the machine went on" \
  "grep -q 'stop (0 children)' $p/driver.log && grep -q '^=== still alive' $p/shell.txt && ! grep -qE 'PANIC|panicked' $p/driver.log"
emu_verdict emu-unplug
echo "--- driver log of b. (from the unplugging)"
driver_log emu-unplug | sed -n '/stop (/,$p'
fi

if want 20; then
echo
echo "##### 20. emulated keyboard: what a scan hears (bt-le-scan)"
new_esp emu-scan
c="$work/emu-scan"
cp "$FW_BIN" "$(img "$RUST_EFI_DIR/bt-le-scan.efi")" "$c/esp/"
fake_bond "$c/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== scan 1"' 'bt-le-scan.efi -t 4' 'echo "=== scan 2"' 'bt-le-scan.efi -t 3 -active -dups' \
  'echo "=== done"' 'reset -s' > "$c/esp/startup.nsh"
cat > "$c/emu.script" <<'EOF'
# A passive scan, one report per kind of advertising: nothing from a
# sleeping keyboard; woken, it advertises directed at its bonded host for
# 1.28 s, then undirected.
wait scanning 30000
sleep 500
expect adv-reports = 0
wake
wait adv-reports >= 2 5000
wait scanning = 0 10000
expect adv-reports = 2
# An active scan with duplicates, the keyboard in pairing mode.
wait scanning 30000
pairing-mode
wait scanning = 0 10000
expect adv-reports >= 20
expect connections = 0
expect unknown-commands = 0
EOF
EMU_SCRIPT="$c/emu.script" run_qemu emu-scan
clean_log "$c/serial.log" > "$c/serial.txt"
sed -n '/^=== scan 1/,/^=== scan 2/p' "$c/serial.txt" > "$c/scan1.txt"
sed -n '/^=== scan 2/,/^=== done/p' "$c/serial.txt" > "$c/scan2.txt"
grep -E '^  [*+] |Scan summary|^  C0:|Bonded keyboard' "$c/scan1.txt" "$c/scan2.txt" | sed 's/^.*scan\([12]\)\.txt:/  scan \1: /' | head -24
check "woken: directed at the bonded host first, then undirected with the HID service and the keyboard appearance" \
  "grep -q '\* C0:00:00:00:00:01 (random) .*ADV_DIRECT_IND   <== bonded keyboard' $c/scan1.txt && grep -q '\* C0:00:00:00:00:01 (random) .*ADV_IND  HID  appearance 0x03c1' $c/scan1.txt"
check "   one report of each, and the keyboard counted as seen" \
  "grep -q 'Scan summary: 2 reports from 1 devices' $c/scan1.txt && grep -q 'Bonded keyboard C0:00:00:00:00:01: SEEN' $c/scan1.txt"
check "pairing mode, active scan: its name from the scan response" \
  "grep -q ' 1 devices' $c/scan2.txt && grep -q 'ADV_IND SCAN_RSP  \"Emulated Keyboard\"  HID' $c/scan2.txt && ! grep -q 'ADV_DIRECT_IND' $c/scan2.txt"
check "both scans ended by themselves, the controller handed back" "grep -q '^=== done' $c/serial.txt && ! grep -qE 'Watchdog|PANIC|panicked' $c/serial.txt"
emu_verdict emu-scan
fi
