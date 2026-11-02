#!/usr/bin/env bash
# Build the Rust UEFI apps (release) and run the host tests.
set -euo pipefail
. "$(dirname "$0")/common.sh"
export PATH="$HOME/.cargo/bin:$PATH"
ensure_firmware
cd "$ROOT/rust"
MTK_FW_PATH="$FW_BIN" cargo test -p mtk-bt -p uefi-bt --lib --quiet 2>&1 | grep -E '^test result|FAILED|panicked' || true
cargo build --release --target x86_64-unknown-uefi -p bt-hci-probe -p bt-le-scan -p bt-kb-probe -p bt-kb-dxe -p bt-kb-log 2>&1 | grep -E '^(warning|error)' || true
ls -l "$RUST_EFI_DIR"/*.efi
