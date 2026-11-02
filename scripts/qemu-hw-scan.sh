#!/usr/bin/env bash
# Milestone 2 on the real controller: bt-le-scan (TrouBLE), 30 s by default.
# Passive scanning: nothing is transmitted except HCI to our own controller.
# No firmware upload unless -upload is given. -recover lets the app do the
# MT7922 subsystem reset if the controller stops answering. Extra arguments
# go to bt-le-scan, e.g. scripts/qemu-hw-scan.sh -t 60 -active
exec "$(dirname "$0")/qemu-hw.sh" "bt-le-scan.efi -recover $*"
