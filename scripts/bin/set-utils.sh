#!/bin/sh

set -eu
export LC_ALL=C

# Escape strings in sed
# See: https://stackoverflow.com/a/29613573
quoteRe() { printf -- '%s' "${1-}" | sed -e 's/[^^]/[&]/g; s/\^/\\^/g; $!a'\\''"$(printf '\n')"'\\n' | tr -d '\n'; }
quoteSubst() { printf -- '%s' "${1-}" | sed -e ':a' -e '$!{N;ba' -e '}' -e 's/[&/\]/\\&/g; s/\n/\\&/g'; }

# Check if a string matches a pattern
matches() { printf -- '%s' "${1:?}" | grep -q "${2:?}"; }

# Print log messages
logInfo() { printf -- '[INFO] %s\n' "$@"; }
logWarn() { >&2 printf -- '[WARN] %s\n' "$@"; }
logFail() { >&2 printf -- '[FAIL] %s\n' "$@"; }
