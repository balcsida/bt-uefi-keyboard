#!/usr/bin/env python3
"""Keep private identifiers out of the repository.

The real values (Bluetooth and network addresses, disk and partition IDs,
the host name, ...) live in private/scrub-map.tsv, which is not in git (see
private/README.md), each with the placeholder that stands in for it here.

    scripts/scrub.py check [PATH...]        files (default: all tracked files)
    scripts/scrub.py check --staged         what the next commit would contain
    scripts/scrub.py check --message FILE   a commit message
    scripts/scrub.py check --history [REV]  every file and commit message
                                            reachable from REV (default HEAD)
    scripts/scrub.py apply PATH...          replace real values in place
    scripts/scrub.py install-hooks          pre-commit and commit-msg hooks
                                            that run the check

Findings name the file, line and kind of value, never the value. Without a
map (a fresh clone, say), check passes and apply changes nothing.

Map format, one value per line, tab-separated (# starts a comment):
    kind  real  placeholder  label
  bytes  hex bytes split by ':' (an address). Found in either byte order and
         in any spelling: C0:00:00:00:00:01, c00000000001, "0x01, 0x00, ...",
         "\\x01\\x00...", hex dumps. Runs of 4 or more of its bytes count too
         (a truncated address), if they include a hex letter.
  guid   a GUID in canonical form. Found as text and in its in-memory byte
         order (as in device path dumps).
  text   literal text, any case.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MAP = os.path.join(ROOT, "private", "scrub-map.tsv")
MIN_RUN = 4
# Before a byte: an optional 0x or \x prefix. Between two bytes: any
# separators, then the prefix.
LEAD = r"(?P<p0>(?:0[xX]|\\x)?)"
GAP = r"(?P<p{i}>[\s:,.\-_]*(?:0[xX]|\\x)?)"


class Rule:
    """One spelling family of one value, with its replacement."""

    def __init__(self, label, regex, replace, partial=False):
        self.label = label
        self.regex = regex
        self.replace = replace
        self.partial = partial


def byte_rule(label, real, new, partial=False):
    parts = []
    for i, b in enumerate(real):
        parts.append(LEAD if i == 0 else GAP.format(i=i))
        parts.append(f"(?P<h{i}>{b:02x})")
    regex = re.compile("".join(parts), re.IGNORECASE)

    def replace(m):
        digits = "".join(m.group(f"h{i}") for i in range(len(real)))
        lower = any(c in "abcdef" for c in digits) and not any(c in "ABCDEF" for c in digits)
        fmt = "{:02x}" if lower else "{:02X}"
        return "".join(m.group(f"p{i}") + fmt.format(new[i]) for i in range(len(real)))

    return Rule(label, regex, replace, partial)


def text_rule(label, real, new):
    def replace(m):
        s = m.group(0)
        if s.isupper():
            return new.upper()
        if s[:1].isupper():
            return new[:1].upper() + new[1:]
        return new

    return Rule(label, re.compile(re.escape(real), re.IGNORECASE), replace)


def parse_bytes(s):
    parts = s.split(":")
    if not all(re.fullmatch(r"[0-9A-Fa-f]{2}", p) for p in parts):
        raise ValueError(f"not hex bytes split by ':': {s!r}")
    return [int(p, 16) for p in parts]


def guid_orders(s):
    h = s.replace("-", "")
    if not re.fullmatch(r"[0-9A-Fa-f]{32}", h):
        raise ValueError(f"not a GUID: {s!r}")
    canon = [int(h[i : i + 2], 16) for i in range(0, 32, 2)]
    memory = canon[3::-1] + canon[5:3:-1] + canon[7:5:-1] + canon[8:]
    return canon, memory


def load_rules(path):
    """(whole-value rules, partial-run rules); empty without a map."""
    full, partial = [], []
    if not os.path.exists(path):
        return full, partial
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 4:
                raise SystemExit(f"{path}:{n}: expected 4 tab-separated fields")
            kind, real, new, label = fields
            if kind == "bytes":
                r, p = parse_bytes(real), parse_bytes(new)
                if len(r) != len(p):
                    raise SystemExit(f"{path}:{n}: the placeholder has a different length")
                full += [byte_rule(label, r, p), byte_rule(label, r[::-1], p[::-1])]
                for length in range(len(r) - 1, MIN_RUN - 1, -1):
                    for start in range(len(r) - length + 1):
                        rr, pp = r[start : start + length], p[start : start + length]
                        if any(f"{b:02x}"[0] in "abcdef" or f"{b:02x}"[1] in "abcdef" for b in rr):
                            partial += [byte_rule(label, rr, pp, True), byte_rule(label, rr[::-1], pp[::-1], True)]
            elif kind == "guid":
                (rc, rm), (pc, pm) = guid_orders(real), guid_orders(new)
                full += [byte_rule(label, rc, pc), byte_rule(label, rm, pm)]
            elif kind == "text":
                full.append(text_rule(label, real, new))
            else:
                raise SystemExit(f"{path}:{n}: unknown kind {kind!r}")
    # Longest patterns first, so one value never eats part of another.
    full.sort(key=lambda r: -len(r.regex.pattern))
    partial.sort(key=lambda r: -len(r.regex.pattern))
    return full, partial


def scrub(text, rules):
    """Text with every real value replaced, and the number of replacements."""
    full, partial = rules
    count = 0
    for rule in full + partial:
        text, n = rule.regex.subn(rule.replace, text)
        count += n
    return text, count


def findings(text, rules):
    """(offset, label, partial) for each real value in text."""
    full, partial = rules
    spans, found = [], []
    for rule in full:
        for m in rule.regex.finditer(text):
            spans.append((m.start(), m.end()))
            found.append((m.start(), rule.label, False))
    for rule in partial:
        for m in rule.regex.finditer(text):
            if not any(s <= m.start() and m.end() <= e for s, e in spans):
                spans.append((m.start(), m.end()))
                found.append((m.start(), rule.label, True))
    return sorted(found)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout


def report(name, data, rules):
    """Print findings in data (bytes); returns how many."""
    text = data.decode("latin-1")
    found = findings(text, rules)
    for offset, label, partial in found:
        line = text.count("\n", 0, offset) + 1
        what = f"part of the {label}" if partial else label
        print(f"{name}:{line}: {what}")
    return len(found)


def check(args, rules):
    total = 0
    if args[:1] == ["--staged"]:
        paths = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR").decode().split("\0")
        for path in filter(None, paths):
            if git("ls-files", "-s", "--", path).decode().startswith("160000"):
                continue  # a submodule
            total += report(path, git("cat-file", "blob", f":{path}"), rules)
    elif args[:1] == ["--message"] and len(args) == 2:
        with open(args[1], "rb") as f:
            total += report("commit message", f.read(), rules)
    elif args[:1] == ["--history"] and len(args) <= 2:
        rev = args[1] if len(args) == 2 else "HEAD"
        seen = set()
        for commit in git("rev-list", rev).decode().split():
            short = commit[:7]
            total += report(f"message of {short}", git("log", "-1", "--format=%B", commit), rules)
            for entry in git("ls-tree", "-r", "-z", commit).decode().split("\0"):
                if not entry:
                    continue
                meta, path = entry.split("\t", 1)
                _mode, kind, sha = meta.split()
                if kind == "blob" and sha not in seen:
                    seen.add(sha)
                    total += report(f"{path} ({short})", git("cat-file", "blob", sha), rules)
    else:
        paths = args or [p for p in git("ls-files", "-z").decode().split("\0") if p]
        for path in paths:
            full = os.path.join(ROOT, path) if not os.path.isabs(path) else path
            if os.path.isfile(full):
                with open(full, "rb") as f:
                    total += report(path, f.read(), rules)
    if total:
        print(f"{total} private value(s) found; replace them with: scripts/scrub.py apply PATH...", file=sys.stderr)
        return 1
    return 0


def apply(paths, rules):
    for path in paths:
        with open(path, "rb") as f:
            text = f.read().decode("latin-1")
        new, n = scrub(text, rules)
        if n:
            with open(path, "wb") as f:
                f.write(new.encode("latin-1"))
            print(f"{path}: {n} replaced")
    return 0


HOOKS = {
    "pre-commit": 'exec python3 -I "$(git rev-parse --show-toplevel)/scripts/scrub.py" check --staged\n',
    "commit-msg": 'exec python3 -I "$(git rev-parse --show-toplevel)/scripts/scrub.py" check --message "$1"\n',
}
MARK = "# Installed by scripts/scrub.py install-hooks"


def install_hooks():
    hooks = os.path.join(ROOT, git("rev-parse", "--git-path", "hooks").decode().strip())
    os.makedirs(hooks, exist_ok=True)
    for name, body in HOOKS.items():
        path = os.path.join(hooks, name)
        if os.path.exists(path) and MARK not in open(path, encoding="utf-8", errors="replace").read():
            print(f"{path} exists and isn't ours; add this line to it yourself:\n  {body.strip()}")
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/sh\n{MARK}: keeps private identifiers out of commits.\n{body}")
        os.chmod(path, 0o755)
        print(f"installed {path}")
    return 0


def main():
    args = sys.argv[1:]
    if not args or args[0] not in ("check", "apply", "install-hooks"):
        print(__doc__, file=sys.stderr)
        return 2
    if args[0] == "install-hooks":
        return install_hooks()
    rules = load_rules(os.environ.get("SCRUB_MAP", DEFAULT_MAP))
    if args[0] == "check":
        return check(args[1:], rules)
    if len(args) < 2:
        print("apply needs at least one path", file=sys.stderr)
        return 2
    return apply(args[1:], rules)


if __name__ == "__main__":
    sys.exit(main())
