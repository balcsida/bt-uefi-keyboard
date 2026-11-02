#!/usr/bin/env bash
# Run the host-based unit tests, including a full simulated upload of the
# real MT7922 image. Build first with scripts/build.sh.
set -uo pipefail
. "$(dirname "$0")/common.sh"
ensure_firmware

# EDK2's UnitTestLib leaks its per-test log buffers, so LeakSanitizer is off;
# AddressSanitizer's other checks stay on.
out="$(ASAN_OPTIONS=detect_leaks=0 "$HOST_TEST" "$FW_BIN" 2>&1)"
status=$?
grep -E '^\[|INFO\]' <<< "$out"
[ $status -eq 0 ] && echo "host tests: all passed" || echo "host tests: FAILED (exit $status)"
exit $status
