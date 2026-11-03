#!/usr/bin/env bash
# Build the Rust UEFI apps (release) and run the host tests.
set -euo pipefail
. "$(dirname "$0")/common.sh"
export PATH="$HOME/.cargo/bin:$PATH"
ensure_firmware
cd "$ROOT/rust"
MTK_FW_PATH="$FW_BIN" cargo test -p mtk-bt -p uefi-bt --lib --quiet 2>&1 | grep -E '^test result|FAILED|panicked' || true
# The driver pins the firmware image it accepts and the bonds it trusts
# (bt-kb-dxe/build.rs): the image the scripts use, and the bonds exported to
# qemu/keys/. Both are also written next to the build, for
# scripts/board-install.sh.
digests=""
for bond in "$ROOT"/qemu/keys/*.bond; do
  [ -r "$bond" ] && digests="$digests $(python3 -I "$ROOT/scripts/bond-digest.py" "$bond")"
done
BT_KB_FIRMWARE="$FW_BIN" BT_KB_BOND_DIGESTS="$digests" cargo build --release --target x86_64-unknown-uefi \
  -p bt-hci-probe -p bt-le-scan -p bt-kb-probe -p bt-kb-dxe -p bt-kb-log -p ebs-test 2>&1 | grep -E '^(warning|error)' || true
sha256sum "$FW_BIN" | cut -d' ' -f1 > "$RUST_EFI_DIR/bt-kb-dxe.firmware.sha256"
printf '%s\n' $digests > "$RUST_EFI_DIR/bt-kb-dxe.bonds"
# The spare PCR the driver extends (bt-kb-dxe/build.rs; BT_KB_SPARE_PCR),
# for scripts/tpm-seal.sh.
echo "spare_pcr=${BT_KB_SPARE_PCR:-8}" > "$RUST_EFI_DIR/bt-kb-dxe.tpm"
count="$(grep -c . "$RUST_EFI_DIR/bt-kb-dxe.bonds" || true)"
if [ "$count" = 0 ]; then
  echo "bt-kb-dxe trusts no bond: export one first (sudo scripts/export-bond.sh), then build again"
else
  echo "bt-kb-dxe trusts $count bond(s), from qemu/keys/"
fi
ls -l "$RUST_EFI_DIR"/*.efi
