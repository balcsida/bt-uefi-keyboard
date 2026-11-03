#!/usr/bin/env bash
# Stage 4's TPM code against a real TPM implementation, without QEMU:
# swtpm on 127.0.0.1, scripts/tpm-seal.sh seals a throwaway test bond, and
# the driver's unseal code (rust/uefi-bt/tests/swtpm.rs) unseals it.
#
#   scripts/tpm-host-test.sh
#
# Never touches /dev/tpm*: everything goes to swtpm (TPM2TOOLS_TCTI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/common.sh"
export PATH="$HOME/.cargo/bin:$PATH"
TPM=1
work="$ROOT/qemu/tpm-host-test"
port=2371
rm -rf "$work"
mkdir -p "$work/build"
trap 'tpm_host_stop "$work/tpm" 2>/dev/null || true' EXIT

write_test_bond "$work/test.bond"
digest="$(python3 -I "$ROOT/scripts/bond-digest.py" "$work/test.bond")"
# A stand-in for a driver build that trusts the test bond.
echo "$digest" > "$work/build/bt-kb-dxe.bonds"
echo "spare_pcr=8" > "$work/build/bt-kb-dxe.tpm"
# swtpm right after TPM2_Startup: PCRs 2, 7 and 8 are zero, and the test
# seals to that (the driver's own policy would be predicted from a log).
printf 'pcr2=%064d\npcr7=%064d\npcr8=%064d\n' 0 0 0 > "$work/values.txt"

(cd "$ROOT/rust" && cargo test --offline --quiet -p uefi-bt --test swtpm --no-run 2>&1 | grep -E '^(warning|error)' || true)

start () { tpm_host_start "$work/tpm" "$port" > /dev/null; }
case_ () { # case_ NAME EXPECT [FILE]
  local name="$1" expect="$2" file="${3:-$work/sealed.txt}"
  if (cd "$ROOT/rust" && BTKB_SWTPM="127.0.0.1:$port" BTKB_SEALED="$file" BTKB_EXPECT="$expect" \
      cargo test --offline --quiet -p uefi-bt --test swtpm -- --nocapture 2>&1) > "$work/$name.out"; then
    echo "  $name: yes ($(grep -E '^(unsealed|refused)' "$work/$name.out"))"
  else
    echo "  $name: NO"
    sed 's/^/    /' "$work/$name.out" | tail -15
  fi
}

start
[[ "$TPM2TOOLS_TCTI" == swtpm:* ]] || { echo "TPM2TOOLS_TCTI isn't swtpm's: stopping" >&2; exit 1; }
echo "== seal (scripts/tpm-seal.sh, SRK created with systemd's template)"
"$ROOT/scripts/tpm-seal.sh" --values "$work/values.txt" --allow-current --bond "$work/test.bond" \
  --build "$work/build" --out "$work/sealed.txt" | sed 's/^/  /'
grep -q '^srk_name=000b' "$work/sealed.txt" && echo "  the SRK is persistent at 0x81000001: $(tpm2_getcap handles-persistent | tr -d '\n')"
echo "== refused without --allow-current (the running system has these PCR values)"
if "$ROOT/scripts/tpm-seal.sh" --values "$work/values.txt" --bond "$work/test.bond" --build "$work/build" \
    --out "$work/not-written.txt" > "$work/refusal.out" 2>&1; then
  echo "  refused: NO"
else
  echo "  refused: yes ($(tail -1 "$work/refusal.out"))"
fi

echo "== unseal with the driver's code"
case_ "1. the PCRs as sealed: unseals, the bond is the test bond" "ok:$digest"
tpm2_pcrextend 8:sha256=0000000000000000000000000000000000000000000000000000000000000001
case_ "2. PCR 8 extended (as the driver does after unsealing): refused" "fail:PCRs changed"
sed '/^pcr8=/d' "$work/sealed.txt" > "$work/no-expected.txt"
case_ "3. the same without the expected values: the policy check refuses" "fail:policy failed" "$work/no-expected.txt"
tpm_host_stop "$work/tpm"
start
case_ "4. after a TPM restart (PCRs back to zero): unseals again" "ok:$digest"
python3 -I - "$work/sealed.txt" "$work/corrupt.txt" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
for i, l in enumerate(lines):
    if l.startswith("private="):
        b = bytearray.fromhex(l[8:]); b[len(b) // 2] ^= 0x01; lines[i] = "private=" + b.hex()
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
case_ "5. a corrupted private part: refused by TPM2_Load" "fail:refused to load" "$work/corrupt.txt"
sed 's/^srk_name=000b./srk_name=000bf/' "$work/sealed.txt" > "$work/other-srk.txt"
case_ "6. sealed under another storage key: refused" "fail:storage key changed" "$work/other-srk.txt"
tpm_host_stop "$work/tpm"
