#!/usr/bin/env bash
# Export the BlueZ bond of the Bluetooth keyboard for the UEFI test apps.
#
#   sudo scripts/export-bond.sh [ADDRESS]
#
# ADDRESS is the keyboard's Bluetooth address. It defaults to KEYBOARD_ADDR
# in private/local.env (not in git: see private/README.md); with neither,
# the script lists the LE bonds BlueZ has.
#
# BlueZ keeps bond keys in a root-only directory, hence sudo. The script
# writes qemu/keys/<address>.bond, owned by you and readable only by you
# (qemu/ is not in git), and prints the key type but never the key itself.
# The long-term key lets whoever holds it decrypt this keyboard's traffic to
# this PC. Delete it when you're done:  rm -r qemu/keys
set -euo pipefail

bluez="${BLUEZ_DIR:-/var/lib/bluetooth}"   # BLUEZ_DIR, KEYS_DIR: for testing only
root="$(cd "$(dirname "$0")/.." && pwd)"
owner="${SUDO_USER:-}"
# Read, not sourced: this runs as root.
local_addr="$(sed -n 's/^KEYBOARD_ADDR=\([0-9A-Fa-f:]*\)[[:space:]]*$/\1/p' "$root/private/local.env" 2>/dev/null | head -1 || true)"
peer="$(printf '%s' "${1:-$local_addr}" | tr 'a-f' 'A-F')"

if [ -z "${BLUEZ_DIR:-}" ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: BlueZ's key store is readable by root only." >&2
  exit 1
fi
if [ -z "$owner" ]; then
  echo "Run it through sudo from your own account, so the file can be given to you." >&2
  exit 1
fi

if [ -z "$peer" ]; then
  echo "usage: sudo $0 ADDRESS   (or set KEYBOARD_ADDR in private/local.env)" >&2
  echo "LE bonds BlueZ has:" >&2
  for f in "$bluez"/*/*/info; do
    [ -f "$f" ] && grep -q '^\[LongTermKey\]' "$f" || continue
    printf '  %s  %s\n' "$(basename "$(dirname "$f")")" "$(sed -n 's/^Name=//p' "$f" | head -1)" >&2
  done
  exit 2
fi
if ! [[ "$peer" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]]; then
  echo "Not a Bluetooth address: $peer" >&2
  exit 2
fi

info="$(ls -d "$bluez"/*/"$peer"/info 2>/dev/null | head -1 || true)"
if [ -z "$info" ]; then
  echo "No BlueZ bond for $peer under $bluez" >&2
  exit 1
fi
adapter="$(basename "$(dirname "$(dirname "$info")")")"

# Value of key $2 in section [$1] of the BlueZ info file.
ini () {
  awk -v section="[$1]" -v key="$2" '
    /^\[/ { in_section = ($0 == section); next }
    in_section && index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }
  ' "$info"
}

ltk="$(ini LongTermKey Key)"
if [ -z "$ltk" ]; then
  echo "$info has no [LongTermKey] section. Was the keyboard paired over LE?" >&2
  exit 1
fi
type="$(ini LongTermKey Authenticated)"
enc_size="$(ini LongTermKey EncSize)"
ediv="$(ini LongTermKey EDiv)"
rand="$(ini LongTermKey Rand)"
irk="$(ini IdentityResolvingKey Key)"
group="$(id -gn "$owner")"

dir="${KEYS_DIR:-$root/qemu/keys}"
install -d -m 700 -o "$owner" -g "$group" "$dir"
out="$dir/$(echo "$peer" | tr -d ':').bond"
umask 077
# Key bytes are in BlueZ's order: as on the air, least significant first.
cat > "$out" <<EOF
# BlueZ bond for $peer, exported $(date -Iseconds) from $info
peer=$peer
peer_type=$(ini General AddressType)
adapter=$adapter
ltk=$ltk
ltk_type=$type
enc_size=$enc_size
ediv=$ediv
rand=$rand
irk=$irk
EOF
chown "$owner:$group" "$out"
chmod 600 "$out"

case "$type" in
  0) kind="legacy pairing, unauthenticated" ;;
  1) kind="legacy pairing, authenticated" ;;
  2) kind="LE Secure Connections, unauthenticated" ;;
  3) kind="LE Secure Connections, authenticated" ;;
  4) kind="LE Secure Connections, debug key" ;;
  *) kind="unknown type '$type'" ;;
esac
if [ "$ediv" = 0 ] && [ "$rand" = 0 ]; then
  ediv_rand="both zero, as Secure Connections keys have"
else
  ediv_rand="set: a legacy-pairing key (TrouBLE needs its legacy-pairing feature)"
fi
echo "Exported the bond for $peer (adapter $adapter) to $out"
echo "  long-term key: ${#ltk} hex digits, $kind, encryption key size $enc_size"
echo "  EDIV/Rand: $ediv_rand"
echo "  identity resolving key: $([ -n "$irk" ] && echo present || echo none)"
echo "The key itself was not printed. Delete the file when you're done: rm -r $dir"
