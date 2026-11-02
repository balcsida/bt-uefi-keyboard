#!/usr/bin/env bash
# Milestone 3 on the real controller: bt-kb-probe connects to the bonded
# keyboard with the key from scripts/export-bond.sh, encrypts, switches it to
# boot protocol and shows its key reports (60 s by default), then restores
# report protocol, disconnects and hands the controller back.
# No firmware upload unless -upload is given; -recover allows the MT7922
# subsystem reset if the controller stops answering. Extra arguments go to
# bt-kb-probe, e.g. scripts/qemu-hw-kb.sh -t 90
if ! ls "$(dirname "$0")"/../qemu/keys/*.bond >/dev/null 2>&1; then
  echo "No exported bond in qemu/keys/. Run: sudo scripts/export-bond.sh" >&2
  exit 1
fi
exec "$(dirname "$0")/qemu-hw.sh" "bt-kb-probe.efi -recover $*"
