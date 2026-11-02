#!/usr/bin/env python3
"""Type into a QEMU guest over QMP once a text shows up in its serial log.

Stands in for the person at the keyboard in offline tests. Keys go to the
guest's emulated keyboard (PS/2 on q35), not through bt-kb-dxe.

Usage: python3 -I scripts/qmp-type.py SOCKET LOG PATTERN TEXT [TIMEOUT_S]
TEXT may hold letters, digits, space, . - : \\ and \\n (Enter).
"""

import json
import socket
import sys
import time

SPECIAL = {
    " ": ["spc"],
    "\n": ["ret"],
    ".": ["dot"],
    "-": ["minus"],
    ":": ["shift", "semicolon"],
    "\\": ["backslash"],
}


def keys_for(ch: str) -> list[str]:
    if ch.isascii() and ch.isalpha():
        return [ch] if ch.islower() else ["shift", ch.lower()]
    if ch.isascii() and ch.isdigit():
        return [ch]
    return SPECIAL[ch]


def main() -> None:
    sock_path, log_path, pattern, text = sys.argv[1:5]
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 120.0
    text = text.replace("\\n", "\n")
    deadline = time.monotonic() + timeout

    while True:
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.connect(sock_path)
            break
        except OSError:
            if time.monotonic() > deadline:
                sys.exit("qmp-type: no QMP socket")
            time.sleep(0.2)
    stream = sock.makefile("rw")

    def command(name: str, **arguments: object) -> dict:
        request = {"execute": name, "arguments": arguments} if arguments else {"execute": name}
        stream.write(json.dumps(request) + "\n")
        stream.flush()
        while True:
            reply = json.loads(stream.readline())
            if "return" in reply or "error" in reply:
                return reply

    stream.readline()  # greeting
    command("qmp_capabilities")

    needle = pattern.encode()
    while True:
        try:
            with open(log_path, "rb") as log:
                if needle in log.read():
                    break
        except FileNotFoundError:
            pass
        if time.monotonic() > deadline:
            sys.exit(f"qmp-type: {pattern!r} never appeared in the log")
        time.sleep(0.3)

    time.sleep(1.0)
    for ch in text:
        keys = [{"type": "qcode", "data": k} for k in keys_for(ch)]
        reply = command("send-key", keys=keys)
        if "error" in reply:
            sys.exit(f"qmp-type: send-key failed: {reply['error']}")
        time.sleep(0.12)
    print(f"qmp-type: typed {text!r}")


if __name__ == "__main__":
    main()
