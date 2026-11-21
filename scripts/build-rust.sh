#!/usr/bin/env bash
# Build the Rust UEFI apps (release) and run the host tests: of the two
# libraries, and of bt-emu, the emulated controller and keyboard that the
# offline tests (scripts/qemu-driver-test.sh) run the driver against.
#
# BT_KB_FEATURES: features of the driver, separated by spaces or commas:
#   pairing                  pair in firmware (LE Secure Connections only)
#   insecure-legacy-pairing  ... and with LE legacy pairing, for a keyboard
#                            that can't do Secure Connections (README:
#                            what that gives up)
# A driver built to pair needs no exported bond in qemu/keys/.
#
# BT_KB_HANDOFF_KEY: the public key a bond paired in firmware is handed to
# the OS under (`scripts/bond-handoff.py keygen` prints it), in hex; by
# default the contents of private/handoff.pub, if that file exists.
set -euo pipefail
. "$(dirname "$0")/common.sh"
export PATH="$HOME/.cargo/bin:$PATH"
ensure_firmware
cd "$ROOT/rust"
MTK_FW_PATH="$FW_BIN" cargo test -p mtk-bt -p uefi-bt -p bt-emu --lib --quiet 2>&1 | grep -E '^test result|FAILED|panicked' || true
cargo build --quiet -p bt-emu 2>&1 | grep -E '^(warning|error)' || true
# The driver pins the firmware image it accepts and the bonds it trusts
# (bt-kb-dxe/build.rs): the image the scripts use, and the bonds exported to
# qemu/keys/. Both are also written next to the build, for
# scripts/board-install.sh.
digests=""
for bond in "$ROOT"/qemu/keys/*.bond; do
  [ -r "$bond" ] && digests="$digests $(python3 -I "$ROOT/scripts/bond-digest.py" "$bond")"
done
features=()
for f in $(tr ',' ' ' <<<"${BT_KB_FEATURES:-}"); do
  case "$f" in
    pairing | insecure-legacy-pairing | insecure-replay-unencrypted) features+=("$f") ;;
    *) echo "BT_KB_FEATURES: bt-kb-dxe has no feature called $f" >&2; exit 2 ;;
  esac
done
feature_args=()
[ "${#features[@]}" -gt 0 ] && feature_args=(--features "$(printf 'bt-kb-dxe/%s,' "${features[@]}" | sed 's/,$//')")
handoff="${BT_KB_HANDOFF_KEY:-}"
if [ -z "$handoff" ] && [ -r "$ROOT/private/handoff.pub" ]; then
  handoff="$(tr -d ' \n' < "$ROOT/private/handoff.pub")"
fi
BT_KB_FIRMWARE="$FW_BIN" BT_KB_BOND_DIGESTS="$digests" BT_KB_HANDOFF_KEY="$handoff" cargo build --release --target x86_64-unknown-uefi \
  -p bt-hci-probe -p bt-le-scan -p bt-kb-probe -p bt-kb-dxe -p bt-kb-log -p ebs-test "${feature_args[@]}" 2>&1 | grep -E '^(warning|error)' || true
sha256sum "$FW_BIN" | cut -d' ' -f1 > "$RUST_EFI_DIR/bt-kb-dxe.firmware.sha256"
printf '%s\n' $digests > "$RUST_EFI_DIR/bt-kb-dxe.bonds"
# What the driver was built with, for scripts/board-install.sh.
printf '%s\n' "${features[@]}" | grep . > "$RUST_EFI_DIR/bt-kb-dxe.features" || true
printf '%s\n' "$handoff" | grep . > "$RUST_EFI_DIR/bt-kb-dxe.handoff" || true
# The spare PCR the driver extends (bt-kb-dxe/build.rs; BT_KB_SPARE_PCR),
# for scripts/tpm-seal.sh.
echo "spare_pcr=${BT_KB_SPARE_PCR:-8}" > "$RUST_EFI_DIR/bt-kb-dxe.tpm"
count="$(grep -c . "$RUST_EFI_DIR/bt-kb-dxe.bonds" || true)"
pairs=""
grep -qxE 'pairing|insecure-legacy-pairing' "$RUST_EFI_DIR/bt-kb-dxe.features" && pairs=1
if [ "$count" != 0 ]; then
  echo "bt-kb-dxe trusts $count bond(s), from qemu/keys/"
elif [ -z "$pairs" ]; then
  echo "bt-kb-dxe trusts no bond: export one first (sudo scripts/export-bond.sh), then build again"
fi
if grep -qx 'insecure-legacy-pairing' "$RUST_EFI_DIR/bt-kb-dxe.features"; then
  echo "bt-kb-dxe pairs in firmware, LE legacy pairing included (insecure-legacy-pairing: see README, Security)"
elif [ -n "$pairs" ]; then
  echo "bt-kb-dxe pairs in firmware, with LE Secure Connections only"
fi
if [ -n "$pairs" ] && [ -n "$handoff" ]; then
  echo "   and hands the bond to the OS under the key ${handoff:0:10}...${handoff: -8} (scripts/bond-handoff.py)"
elif [ -n "$pairs" ]; then
  echo "   WITHOUT a hand-off key (BT_KB_HANDOFF_KEY, or private/handoff.pub): the OS can't take its bond over"
fi
grep -qx 'insecure-replay-unencrypted' "$RUST_EFI_DIR/bt-kb-dxe.features" && echo "bt-kb-dxe: built with insecure-replay-unencrypted (experiments only)"
ls -l "$RUST_EFI_DIR"/*.efi
