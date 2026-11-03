#!/usr/bin/env bash
# Seal the keyboard's bond to this machine's TPM for bt-kb-dxe (stage 4 of
# the security hardening; README, Security).
#
#   sudo scripts/tpm-seal.sh [--dry-run] [--no-fallback] [--if-needed]
#
# The driver then unseals the bond at every boot, and nothing else can:
# - **Policy:** TPM2_PolicyPCR over PCR 2, PCR 7 and the driver's spare PCR
#   (8 unless the build says otherwise), with the values they have while
#   the driver runs: replayed from this boot's event log up to the
#   driver's own load event. The OS never sees those values: the firmware
#   measures the separators after the driver (into PCR 2 and, on AMI, PCR
#   7), and the driver extends the spare PCR right after it unseals.
# - **Key:** the sealed object lives under the storage root key at
#   0x81000001 (created with systemd's template if missing). It's useless
#   on another machine, and after a TPM clear.
# - **Files:** only the sealed object's public and private parts and the
#   expected PCR values go on the ESP (bt-kb-dxe.sealed); the bond reaches
#   tpm2_create through a pipe.
#
# Run it after a boot in which the driver ran (the event log has to show
# where it loads). After changing the driver, Secure Boot keys, dbx, option
# ROMs or the firmware, the next boot can't unseal: the driver falls back to
# its boot-services copy and records why, and --if-needed (from a systemd
# unit, see scripts/systemd/) reseals.
#
# Options:
#   --dry-run          predict and print; no TPM commands, no files written
#   --if-needed        reseal only if the prediction or the bond differs from the
#                      seal on the ESP, or the driver's last boot record says
#                      unsealing failed
#   --no-fallback      the driver keeps no boot-services copy of the bond
#                      (fallback=no): the key is then only in the sealed object,
#                      and a boot after a PCR change has no Bluetooth keyboard
#                      until this reseals. Without it, a reseal keeps the
#                      existing seal's setting.
#   --bond FILE        default: the one bond in qemu/keys/
#   --eventlog FILE    default: /sys/kernel/security/tpm0/binary_bios_measurements
#   --driver FILE      the driver image the next boot runs (default: the one on
#                      the ESP); its hash stands in for the logged one
#   --build DIR        the driver build's directory (its bt-kb-dxe.bonds and
#                      bt-kb-dxe.tpm), default rust/target/x86_64-unknown-uefi/release
#   --out FILE         default: /boot/EFI/btkb/bt-kb-dxe.sealed
#   --pcrs LIST        PCRs besides the spare one, default 2,7
#   --values FILE      seal to the pcrN=HEX values in FILE instead of predicting
#   --allow-current    accept values the TPM has right now (tests only: the
#                      running OS could then unseal)
#
# The TPM is tpm2-tools' default: TPM2TOOLS_TCTI if set, else /dev/tpmrm0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/boot/EFI/btkb
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
VENDOR=5223227b-ac96-454e-9bca-f15199748a3c
SRK=0x81000001
MAGIC="bt-kb-dxe sealed bond v1"

dry="" if_needed="" fallback="" bond="" values_file="" allow_current=""
eventlog=/sys/kernel/security/tpm0/binary_bios_measurements
driver="$DEST/bt-kb-dxe.efi"
build="$ROOT/rust/target/x86_64-unknown-uefi/release"
out="$DEST/bt-kb-dxe.sealed"
pcrs=2,7
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1 ;;
    --if-needed) if_needed=1 ;;
    --no-fallback) fallback=no ;;
    --allow-current) allow_current=1 ;;
    --bond) bond="$2"; shift ;;
    --eventlog) eventlog="$2"; shift ;;
    --driver) driver="$2"; shift ;;
    --build) build="$2"; shift ;;
    --out) out="$2"; shift ;;
    --pcrs) pcrs="$2"; shift ;;
    --values) values_file="$2"; shift ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2 ;;
  esac
  shift
done

die () { echo "tpm-seal: $*" >&2; exit 1; }
if [ -z "$fallback" ]; then
  fallback="$(sed -n 's/^fallback=//p' "$out" 2>/dev/null || true)"
  [ "$fallback" = no ] || fallback=yes
fi
# Hex without xxd (vim's), which not every system has.
tohex () { python3 -I -c 'import sys; print(open(sys.argv[1], "rb").read().hex())' "$1"; }
fromhex () { python3 -I -c 'import sys; sys.stdout.buffer.write(bytes.fromhex("".join(sys.stdin.read().split())))'; }

# The bond, and whether the driver build trusts it.
if [ -z "$bond" ]; then
  bonds=("$ROOT"/qemu/keys/*.bond)
  [ -f "${bonds[0]}" ] && [ "${#bonds[@]}" = 1 ] || die "need exactly one bond in qemu/keys/ (sudo scripts/export-bond.sh), or --bond FILE"
  bond="${bonds[0]}"
fi
[ -r "$bond" ] || die "can't read $bond"
digest="$(python3 -I "$ROOT/scripts/bond-digest.py" "$bond")"
grep -qx "$digest" "$build/bt-kb-dxe.bonds" 2>/dev/null \
  || die "the driver build in $build doesn't trust ${bond##*/}: rebuild (scripts/build-rust.sh) and reinstall first"

# The spare PCR the build extends.
spare="$(sed -n 's/^spare_pcr=//p' "$build/bt-kb-dxe.tpm" 2>/dev/null || true)"
spare="${spare:-8}"

# The values to seal to.
prediction="$(mktemp)"
trap 'rm -f "$prediction"' EXIT
if [ -n "$values_file" ]; then
  python3 -I - "$values_file" "$pcrs" "$spare" > "$prediction" <<'PY'
import hashlib, struct, sys
path, pcrs, spare = sys.argv[1], sys.argv[2], sys.argv[3]
want = sorted({int(p) for p in pcrs.split(",") if p} | (set() if spare == "none" else {int(spare)}))
given = dict(l.strip().split("=", 1) for l in open(path) if l.strip().startswith("pcr"))
values = [bytes.fromhex(given[f"pcr{p}"]) for p in want]
bitmap = sum(1 << p for p in want)
selection = struct.pack(">IHB", 1, 0x000B, 3) + bitmap.to_bytes(4, "little")[:3]
pcr_digest = hashlib.sha256(b"".join(values)).digest()
print("driver_event=none")
for p, v in zip(want, values):
    print(f"pcr{p}={v.hex()}")
print("pcrs=" + ",".join(map(str, want)))
print(f"pcr_digest={pcr_digest.hex()}")
print("policy=" + hashlib.sha256(bytes(32) + struct.pack(">I", 0x17F) + selection + pcr_digest).hexdigest())
PY
else
  [ -r "$eventlog" ] || die "can't read the event log $eventlog (root only)"
  driver_hash=()
  if [ -f "$driver" ]; then
    driver_hash=(--driver-hash "$(python3 -I "$ROOT/scripts/eventlog.py" pehash "$driver")")
  elif [ -z "$dry" ]; then
    die "no driver image at $driver (--driver FILE)"
  fi
  python3 -I "$ROOT/scripts/eventlog.py" predict "$eventlog" "$pcrs" --spare "$spare" "${driver_hash[@]}" > "$prediction"
fi
field () { sed -n "s/^$1=//p" "$prediction"; }
policy="$(field policy)"
sealed_pcrs="$(field pcrs)"
echo "Policy: PolicyPCR over PCRs $sealed_pcrs (SHA-256), digest $policy"
grep '^pcr[0-9]' "$prediction" | sed 's/^/  /'
if [ "$(field driver_event)" != none ]; then
  echo "  (the driver's load is event $(field driver_event) of the log; the spare PCR is $spare)"
  [ "$(field driver_logged)" = "${driver_hash[1]:-}" ] || echo "  (with the hash of $driver in place of the logged image: the next boot runs that one)"
fi

if [ -n "$if_needed" ] && [ -f "$out" ]; then
  record="$(tail -c +5 "$EFIVARS/BtKbLastBoot-$VENDOR" 2>/dev/null | tr -cd '[:print:]' || true)"
  if grep -qx "policy=$policy" "$out" && grep -qx "fallback=$fallback" "$out" && grep -qx "bond=$digest" "$out" \
    && [[ "$record" != *"unseal failed"* ]]; then
    echo "The seal on the ESP is up to date."
    exit 0
  fi
fi
if [ -n "$dry" ]; then
  echo "Dry run: would seal ${bond##*/} under $SRK and write $out (fallback=$fallback)."
  exit 0
fi

command -v tpm2_create >/dev/null || die "tpm2-tools not found (package tpm2-tools)"
work="$(mktemp -d)"
trap 'rm -f "$prediction"; rm -rf "$work"' EXIT

# The storage root key: systemd's (systemd-tpm2-setup) if it's there, else
# made from the same template: ECC P-256, AES-128-CFB, no DA, at 0x81000001.
if ! tpm2_readpublic -Q -c "$SRK" -o "$work/srk.pub" -n "$work/srk.name" 2>/dev/null; then
  echo "No storage root key at $SRK: creating one (systemd's template)."
  tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb -c "$work/srk.ctx" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt'
  tpm2_evictcontrol -Q -C o -c "$work/srk.ctx" "$SRK"
  tpm2_readpublic -Q -c "$SRK" -o "$work/srk.pub" -n "$work/srk.name"
fi
# Without a resource manager (swtpm in tests, or /dev/tpm0) transient
# objects stay loaded, and a TPM has only a few slots; with /dev/tpmrm0
# this flushes nothing.
tpm2_flushcontext -t 2>/dev/null || true
# Not `| grep -q` under pipefail: grep's early exit can kill tpm2_readpublic
# with SIGPIPE and fail the check.
srk_text="$(tpm2_readpublic -c "$SRK")"
grep -q 'NIST p256' <<< "$srk_text" \
  || die "the key at $SRK isn't ECC P-256; the driver salts its session with ECDH and needs one"

# The policy digest as the TPM computes it, from the same values.
grep '^pcr[0-9]' "$prediction" | sed 's/^pcr[0-9]*=//' | fromhex > "$work/values.bin"
tpm2_startauthsession -Q -S "$work/trial.ctx"
tpm2_policypcr -Q -S "$work/trial.ctx" -l "sha256:$sealed_pcrs" -f "$work/values.bin" -L "$work/policy.bin"
tpm2_flushcontext -Q "$work/trial.ctx"
[ "$(tohex "$work/policy.bin")" = "$policy" ] || die "the TPM's policy digest differs from the prediction's"

# Values the TPM has right now would let the running OS unseal.
tpm2_pcrread -Q "sha256:$sealed_pcrs" -o "$work/current.bin"
if cmp -s "$work/current.bin" "$work/values.bin" && [ -z "$allow_current" ]; then
  die "the PCRs have these values right now, so the OS could unseal: refusing (is the driver's spare PCR in use?)"
fi

# Seal: the record goes through a pipe, never into a file.
python3 -I "$ROOT/scripts/bond-digest.py" --record "$bond" \
  | tpm2_create -Q -C "$SRK" -g sha256 -L "$work/policy.bin" -a 'fixedtpm|fixedparent|noda|adminwithpolicy' \
      -i - -u "$work/sealed.pub" -r "$work/sealed.priv"

{
  echo "$MAGIC"
  echo "# Made by scripts/tpm-seal.sh $(date -u +%Y-%m-%dT%H:%MZ). Nothing here is secret."
  echo "parent=$SRK"
  echo "srk_name=$(tohex "$work/srk.name")"
  echo "pcrs=$sealed_pcrs"
  grep '^pcr[0-9]' "$prediction"
  echo "fallback=$fallback"
  echo "policy=$policy"
  echo "bond=$digest"
  echo "public=$(tohex "$work/sealed.pub")"
  echo "private=$(tohex "$work/sealed.priv")"
} > "$work/sealed.txt"
mkdir -p "$(dirname "$out")"
cp "$work/sealed.txt" "$out.new"
mv "$out.new" "$out"
echo "Sealed ${bond##*/} under $SRK: $out (fallback=$fallback)."
