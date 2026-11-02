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
# The driver's log (QEMU debug console, port 0x402) is shown after each run.
# ONLY="1 3" runs just those cases.
set -euo pipefail
. "$(dirname "$0")/common.sh"
ensure_firmware

DRIVER="$RUST_EFI_DIR/bt-kb-dxe.efi"
work="$ROOT/qemu/driver-test"
trap 'pkill -f "qemu-system-x86_64 .*${work}/" 2>/dev/null || true' EXIT

# KEEP_VARS=1: use the variable store already there; EXTRA_QEMU: more args.
run_qemu () {
  local name="$1"
  [ -n "${KEEP_VARS:-}" ] || cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$work/$name/OVMF_VARS.4m.fd"
  make_esp_image "$work/$name/esp" "$work/$name/esp.img"
  : > "$work/$name/driver.log"
  timeout --foreground 120 "$QEMU" -machine q35,accel=kvm -cpu host -m 1G -nographic -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_DIR/OVMF_CODE.4m.fd" \
    -drive if=pflash,format=raw,file="$work/$name/OVMF_VARS.4m.fd" \
    -drive if=none,id=esp,format=raw,file="$work/$name/esp.img" -device virtio-blk-pci,drive=esp \
    -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
    -chardev file,id=dbg,path="$work/$name/driver.log" -device isa-debugcon,iobase=0x402,chardev=dbg \
    ${EXTRA_QEMU:-} -net none -serial mon:stdio > "$work/$name/serial.log" 2>&1 || echo "(QEMU exit status $?)"
}

# A made-up bond (random key) for runs that never talk to a keyboard.
fake_bond () {
  printf 'peer=C0:00:00:00:00:01\npeer_type=static\nadapter=02:00:00:00:00:02\nltk=%s\nltk_type=1\nenc_size=16\nediv=4660\nrand=1311768467463790320\nirk=\n' \
    "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" > "$1/test.bond"
}

new_esp () {
  rm -rf "$work/$1"
  mkdir -p "$work/$1/esp/EFI/BOOT"
  cp "$SHELL_EFI" "$work/$1/esp/EFI/BOOT/BOOTX64.EFI"
  cp "$DRIVER" "$work/$1/esp/"
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
cp "$FW_BIN" "$RUST_EFI_DIR/ebs-test.efi" "$work/ebs/esp/"
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
cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$work/hotkey/OVMF_VARS.4m.fd"
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
cp "$FW_BIN" "$RUST_EFI_DIR/ebs-test.efi" "$work/boot/esp/"
fake_bond "$work/boot/esp"
printf '%s\r\n' '@echo -off' 'fs0:' 'echo "=== shell reached"' 'drivers -l en > fs0:\drivers.txt' \
  'echo "=== ebs-test.efi"' 'ebs-test.efi' > "$work/boot/esp/startup.nsh"
cp "$OVMF_DIR/OVMF_VARS.4m.fd" "$work/boot/OVMF_VARS.4m.fd"
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
