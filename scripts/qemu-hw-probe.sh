#!/usr/bin/env bash
# Milestone 1 on the real controller (Rust probe; APP=BtHciProbe.efi for the C one).
#
# What it sends to the controller (no -upload):
#   - chip register reads (ID, firmware version, flavor)
#   - one firmware status query per section; no firmware data is sent
#   - the endpoint reset option write and WMT FUNC_CTRL on
#   - HCI_Reset, Read_Local_Version, Read_BD_ADDR, LE_Read_Buffer_Size,
#     Read_Local_Name
#   - HCI_Reset and WMT FUNC_CTRL off (what Linux sends at shutdown)
# If the chip reports a section as not loaded, the probe stops there and
# uploads nothing. The Rust probe also gets -recover: if the controller stops
# answering, it does the MT7922 subsystem reset before exiting. Extra
# arguments go to the last probe run.
app="${APP:-bt-hci-probe.efi}"
recover=""
[ "$app" = "bt-hci-probe.efi" ] && recover=" -recover"
exec "$(dirname "$0")/qemu-hw.sh" "$app -list" "$app -chipid -v" "$app -v$recover $*"
