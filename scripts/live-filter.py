#!/usr/bin/env python3
"""Pass QEMU's serial console to the terminal as it arrives.

The UEFI shell echoes each key with a cursor-positioning sequence and no
newline, so a line-oriented filter (sed) showed nothing until Enter, and
stripping escape sequences broke Backspace and full-screen UIs. This one
works on raw bytes and only removes OVMF's "resize the terminal window"
requests (ESC [ 8 ; rows ; cols t).

Usage: ... | python3 -I scripts/live-filter.py
"""

import os
import re
import sys

RESIZE = re.compile(rb"\x1b\[8;\d+;\d+t")
COMPLETE_CSI = re.compile(rb"\x1b\[[0-9;?=]*[@-~]")


def main() -> None:
    fd_in, fd_out = sys.stdin.fileno(), sys.stdout.fileno()
    pending = b""
    while True:
        chunk = os.read(fd_in, 4096)
        if not chunk:
            break
        data = pending + chunk
        pending = b""
        # Keep an escape sequence cut off by the read for the next round.
        cut = data.rfind(b"\x1b")
        if cut != -1 and len(data) - cut < 32 and not COMPLETE_CSI.match(data, cut):
            data, pending = data[:cut], data[cut:]
        os.write(fd_out, RESIZE.sub(b"", data))
    if pending:
        os.write(fd_out, pending)


if __name__ == "__main__":
    main()
