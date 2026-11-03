#!/usr/bin/env bash
# Build the Rust UEFI apps (release) and run the host tests.
set -euo pipefail
. "$(dirname "$0")/common.sh"
export PATH="$HOME/.cargo/bin:$PATH"
ensure_firmware
cd "$ROOT/rust"
MTK_FW_PATH="$FW_BIN" cargo test -p mtk-bt -p uefi-bt --lib --quiet 2>&1 | grep -E '^test result|FAILED|panicked' || true
# The driver pins the firmware image it accepts (bt-kb-dxe/build.rs); the
# pinned hash is also written next to it for scripts/board-install.sh.
BT_KB_FIRMWARE="$FW_BIN" cargo build --release --target x86_64-unknown-uefi -p bt-hci-probe -p bt-le-scan -p bt-kb-probe -p bt-kb-dxe -p bt-kb-log -p ebs-test 2>&1 | grep -E '^(warning|error)' || true
sha256sum "$FW_BIN" | cut -d' ' -f1 > "$RUST_EFI_DIR/bt-kb-dxe.firmware.sha256"
ls -l "$RUST_EFI_DIR"/*.efi
