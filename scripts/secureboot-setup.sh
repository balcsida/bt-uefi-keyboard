#!/usr/bin/env bash
# Secure Boot with your own keys, CachyOS-style (sbctl), and bt-kb-dxe
# signed for it: a checklist. Stage 2 of the security hardening (README,
# Security).
#
#   scripts/secureboot-setup.sh            check each step, print what's left
#   sudo scripts/secureboot-setup.sh       the same, including the root-only checks
#   scripts/secureboot-setup.sh --dry-run  print the steps, check nothing
#
# It never changes anything, and above all never enrolls keys: every step
# that does is printed for you to run. The flow follows the CachyOS wiki:
# sbctl create-keys; sbctl enroll-keys --microsoft (plus --firmware-builtin,
# except on ASUS and Gigabyte boards); Limine with an enrolled config.
#
# Why bt-kb-dxe cares: the firmware verifies Driver#### images against db
# itself, so with Secure Boot on, only a driver signed with a db key runs.
# That ties what runs before the OS to whoever holds the db key, which is
# goal 1 only if that key isn't on this machine (see "Keys off the machine").
set -euo pipefail
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
GLOBAL=8be4df61-93ca-11d2-aa0d-00e098032b8c
IMAGE_SECURITY=d719b2cb-3d3a-4596-a3bc-dad00e67656f
SBCTL_KEYS="${SBCTL_KEYS:-/var/lib/sbctl/keys}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

dry=""
case "${1:-}" in
  --dry-run) dry=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac
is_root=""
[ "$(id -u)" -eq 0 ] && is_root=1

# The last byte of a global variable (SecureBoot, SetupMode), or "?".
var_byte () {
  local f="$EFIVARS/$1-$GLOBAL"
  if [ -r "$f" ]; then tail -c 1 "$f" | od -An -tu1 | tr -d ' '; else echo "?"; fi
}

step=0
# show STATE TITLE COMMAND...: STATE is done, todo, check (can't tell) or info.
show () {
  local state="$1" title="$2"
  shift 2
  step=$((step + 1))
  case "$state" in
    done) printf '%2d. [done]  %s\n' "$step" "$title" ;;
    todo) printf '%2d. [to do] %s\n' "$step" "$title" ;;
    check) printf '%2d. [?]     %s\n' "$step" "$title" ;;
    *) printf '%2d.         %s\n' "$step" "$title" ;;
  esac
  local line
  for line in "$@"; do
    [ -z "$line" ] || printf '              %s\n' "$line"
  done
}

# Whether a certificate is in the firmware's db (its DER in the variable).
cert_in_db () {
  [ -r "$1" ] || return 1
  python3 -I - "$1" "$EFIVARS/db-$IMAGE_SECURITY" <<'PY'
import subprocess, sys
der = subprocess.run(["openssl", "x509", "-in", sys.argv[1], "-outform", "DER"], capture_output=True).stdout
try:
    db = open(sys.argv[2], "rb").read()
except OSError:
    sys.exit(1)
sys.exit(0 if der and der in db else 1)
PY
}

state_of () { # state_of TEST-COMMAND...: done/todo, or info under --dry-run
  if [ -n "$dry" ]; then echo info; elif "$@"; then echo done; else echo todo; fi
}

sb="$(var_byte SecureBoot)"
setup="$(var_byte SetupMode)"
if [ -z "$dry" ]; then
  echo "Secure Boot: $([ "$sb" = 1 ] && echo on || echo off); Setup Mode: $([ "$setup" = 1 ] && echo yes || echo no)"
  echo
fi

echo "Before you start:"
echo "  - Keep a wired USB keyboard at hand for the first boot with Secure Boot on: if"
echo "    bt-kb-dxe isn't signed with your db key, the firmware refuses it, and the"
echo "    Bluetooth keyboard does nothing until Linux."
if [ -z "$dry" ] && grep -qi bitlocker < <(lsblk -no FSTYPE 2>/dev/null); then
  echo "  - A BitLocker volume is on this machine: new Secure Boot keys change PCR 7, and"
  echo "    Windows will ask for the recovery key. Have it ready, or suspend BitLocker in"
  echo "    Windows first (manage-bde -protectors -disable C: -RebootCount 2)."
else
  echo "  - With BitLocker in Windows: new Secure Boot keys change PCR 7, and Windows asks"
  echo "    for the recovery key. Have it ready, or suspend BitLocker first."
fi
echo

show "$(state_of command -v sbctl)" "Install sbctl" "sudo pacman -S sbctl"

if [ -n "$dry" ]; then keys=info
elif [ -n "$is_root" ]; then keys="$(state_of test -f "$SBCTL_KEYS/db/db.key")"
else keys=check
fi
show "$keys" "Create your keys (PK, KEK, db; kept in $SBCTL_KEYS)" "sudo sbctl create-keys" \
  "$([ "$keys" = check ] && echo '(run this script with sudo to check)')"

ours_enrolled=""
if [ -z "$dry" ] && [ "$setup" = 0 ] && [ -n "$is_root" ] && cert_in_db "$SBCTL_KEYS/db/db.pem"; then
  ours_enrolled=1
fi
if [ -n "$dry" ]; then mode=info
elif [ "$setup" = 1 ] || [ -n "$ours_enrolled" ]; then mode=done
elif [ -n "$is_root" ]; then mode=todo
else mode=check
fi
show "$mode" "Put the firmware into Setup Mode (only if your keys aren't enrolled yet)" \
  "In firmware setup (AMI: Security > Secure Boot > Key Management), choose" \
  "\"Reset to Setup Mode\" or \"Delete all Secure Boot variables\". Until your keys are" \
  "enrolled, the machine has no Secure Boot at all: enroll right after."

if [ -n "$dry" ]; then enrolled=info
elif [ -n "$ours_enrolled" ]; then enrolled=done
elif [ "$setup" = 1 ] || [ -n "$is_root" ]; then enrolled=todo
else enrolled=check
fi
show "$enrolled" "Enroll your keys, with Microsoft's (Windows, GPU option ROMs) and the board's own" \
  "sudo sbctl enroll-keys --microsoft --firmware-builtin" \
  "(drop --firmware-builtin on ASUS and Gigabyte boards; this board is an ASRock)" \
  "$(grep -aqs "Microsoft Corporation UEFI CA 2011" "$EFIVARS/db-$IMAGE_SECURITY" && echo "(db already has Microsoft's UEFI CA 2011)")"

limine_conf_ok () { grep -Eq '^\s*ENABLE_ENROLL_LIMINE_CONFIG=("?)yes\1\s*$' /etc/default/limine 2>/dev/null; }
show "$(state_of limine_conf_ok)" "Let limine-update enroll Limine's config into the signed Limine binary" \
  "In /etc/default/limine: ENABLE_ENROLL_LIMINE_CONFIG=yes"

if [ -n "$dry" ]; then splash=info
elif [ -n "$is_root" ] && [ -r /boot/limine.conf ]; then
  if grep -Eiq '^\s*(wallpaper|splash)[a-z_]*:\s*[^#]+$' /boot/limine.conf; then splash=todo; else splash=done; fi
else splash=check
fi
show "$splash" "Hash the splash image path, as the CachyOS wiki shows: an enrolled config makes Limine" \
  "check the files it loads, and a splash path without #b2sum fails" \
  "b2sum /boot/<splash image>   then append #<hash> to its path in the Limine config"

show info "Enroll the config and rebuild Limine's entries (again after every config change)" \
  "sudo limine-enroll-config" "sudo limine-update"

if [ -n "$dry" ]; then signed=info
elif [ -n "$is_root" ] && command -v sbctl >/dev/null; then
  if grep -q '✗' < <(sbctl verify 2>/dev/null); then signed=todo; else signed=done; fi
else signed=check
fi
show "$signed" "Every EFI binary on the ESP signed (sbctl's pacman hook keeps the kernel and Limine signed)" \
  "sudo sbctl verify        (lists them)" "sudo sbctl sign -s <file> (for any marked unsigned)"

if [ -n "$dry" ]; then drv=info
elif [ -n "$is_root" ] && [ -f /boot/EFI/btkb/bt-kb-dxe.efi ] && command -v sbverify >/dev/null; then
  if sbverify --cert "$SBCTL_KEYS/db/db.pem" /boot/EFI/btkb/bt-kb-dxe.efi >/dev/null 2>&1; then drv=done; else drv=todo; fi
else drv=check
fi
show "$drv" "Sign and install bt-kb-dxe with the same key (board-install.sh signs with sbctl when its keys exist)" \
  "sudo $ROOT/scripts/board-install.sh"

show "$(state_of test "$sb" = 1)" "Turn Secure Boot on in firmware setup (AMI: Secure Boot > Enabled, mode Custom)" \
  "First boot with a wired keyboard at hand. Then: scripts/board-log.sh (the driver ran)," \
  "and sbctl status (Secure Boot enabled)."

if [ -f /boot/EFI/btkb/bt-kb-dxe.sealed ] 2>/dev/null; then sealed=done; elif [ -e /dev/tpmrm0 ]; then sealed=todo; else sealed=check; fi
show "$sealed" "Optional, with a TPM: seal the bond to it (stage 4), after a boot with Secure Boot on" \
  "(turning it on changes PCR 7): sudo $ROOT/scripts/tpm-seal.sh, then a reseal unit:" \
  "scripts/systemd/bt-kb-reseal.service (it says how to install it)."

echo
echo "Keys off the machine (goal 1 against root):"
echo "  sbctl keeps PK, KEK and db unencrypted in $SBCTL_KEYS, so root can sign anything,"
echo "  and the firmware will run it. Against root, the private keys must not be on this"
echo "  machine. Once everything above is done:"
echo "    - move $SBCTL_KEYS to removable media (or keep db on a PKCS#11 token);"
echo "    - sign with it mounted: sbctl's keydir (/etc/sbctl/sbctl.conf) pointed at it, or"
echo "      DB_KEY=... DB_CERT=... sudo -E scripts/board-install.sh for the driver."
echo "  The price: sbctl's pacman hook can no longer re-sign the kernel and Limine after"
echo "  updates. Until you sign them with the key media, the next boot fails Secure Boot."
echo "  With --microsoft enrolled, anything Microsoft signs also runs (a signed shim, say),"
echo "  as Windows and GPU option ROMs need: goal 1 then also rests on a current dbx."
