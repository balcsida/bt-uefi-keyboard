#!/usr/bin/env bash
# Build BtKbPkg (DEBUG and RELEASE) and the host-based unit tests.
set -euo pipefail
. "$(dirname "$0")/common.sh"
cd "$ROOT"
set +u; . ./env.sh; set -u

for target in DEBUG RELEASE; do
  log="$ROOT/Build/build-$target.log"
  mkdir -p "$ROOT/Build"
  if ! build -p BtKbPkg/BtKbPkg.dsc -a X64 -t GCC -b "$target" -n "$(nproc)" > "$log" 2>&1; then
    "$ROOT/scripts/buildlog-summary.sh" "$log"
    exit 1
  fi
  echo "BtKbPkg $target: ok ($(stat -c %s "Build/BtKbPkg/${target}_GCC/X64/BtHciProbe.efi") bytes BtHciProbe.efi)"
done

log="$ROOT/Build/build-hosttest.log"
if ! build -p BtKbPkg/Test/BtKbPkgHostTest.dsc -a X64 -t GCC -b NOOPT -n "$(nproc)" > "$log" 2>&1; then
  "$ROOT/scripts/buildlog-summary.sh" "$log"
  exit 1
fi
echo "Host tests: built"
