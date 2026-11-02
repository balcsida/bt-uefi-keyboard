#!/usr/bin/env bash
# Print only the interesting lines of an EDK2 build log: compiler/linker diagnostics and build.py errors.
log="${1:-/dev/stdin}"
grep -nE '(: (fatal )?error:|: warning:|: note:|error [0-9A-F]{4}:|undefined reference|^build\.py\.\.\.|^\s+(Library|File|\S+\.(inf|dsc|dec)).*not found|- (Done|Failed) -)' "$log" \
  | grep -v 'does not support LIBRARY_CLASS' | head -${2:-40}
