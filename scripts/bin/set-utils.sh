#!/bin/sh

set -eu
export LC_ALL=C

# Set default umask
export UMASK=0002
umask "${UMASK:?}"

# Clean up temp directory on exit
# shellcheck disable=SC2154
trap 'ret="$?"; find "${TMPDIR:-/tmp}" -mindepth 1 -writable -delete ||:; trap - EXIT; exit "${ret:?}"' EXIT TERM INT HUP

# Some regex patterns
export PATTERN_EXT_RUN="\.\(sh\|run\)$"
export PATTERN_EXT_TAR="\.\(tar\|tar\.gz\|tgz\|tar\.bz2\|tbz2\|tar\.xz\|txz\)$"
export PATTERN_EXT_ZIP="\.\(zip\|kar\)$"
export PATTERN_EXT_JAR="\.\(jar\)$"
export PATTERN_EXT_ERB="\.\(erb\)$"

# Get a variable value from multiple sources
getVar() {
	name=${1:?}
	default=${2-}

	# If "$VARNAME" is defined, print it
	eval var="\${${name:?}-}"
	if [ -n "${var-}" ]; then
		printf -- '%s' "${var:?}"
		return
	fi

	# If "$VARNAME_B64" is defined, decode and print it
	eval varB64="\${${name:?}_B64-}"
	if [ -n "${varB64-}" ]; then
		printf -- '%s' "${varB64:?}" | base64 -d
		return
	fi

	# If "$VARNAME_FILE" file exists, print its content
	eval varFile="\${${name:?}_FILE-}"
	if [ -n "${varFile-}" ] && [ -e "${varFile-}" ]; then
		cat -- "${varFile:?}"
		return
	fi

	# If a Docker secret exists, print its content
	varSecret="${SECRETS_DIR-/run/secrets}/${name:?}"
	if [ -e "${varSecret:?}" ]; then
		cat -- "${varSecret:?}"
		return
	fi

	printf -- '%s' "${default-}"
}

# Get or generate a random password
getPasswordVar() {
	name=${1:?}
	default=${2-}

	password=$(getVar "${name:?}" "${default-}")

	if [ -z "${password-}" ]; then
		password=$(pwgen 24 1)
		logWarn "Empty \"${name:?}\" variable, generated password: ${password:?}"
	fi

	printf -- '%s' "${password:?}"
}

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

# Enables a service
runitEnSv() {
	svdir=/usr/share/biserver/service
	if [ ! -e "${svdir:?}"/enabled/"${1:?}" ]; then
		ln -rs "${svdir:?}"/available/"${1:?}" "${svdir:?}"/enabled/"${1:?}"
	fi
}

# Disables a service
runitDisSv() {
	svdir=/usr/share/biserver/service
	if [ -e "${svdir:?}"/enabled/"${1:?}" ]; then
		unlink "${svdir:?}"/enabled/"${1:?}"
	fi
}

# Runs a command redirecting its output to stdout and a file while keeping its exit code
runAndLog() {
	runCmd=${1:?}
	logFile=${2:?}

	logPipe=$(mktemp -u)
	mkfifo -m 600 "${logPipe:?}"

	tee "${logFile:?}" < "${logPipe:?}" & teePid=$!
	${runCmd:?} > "${logPipe:?}" 2>&1; exitCode=$?
	rm -f "${logPipe:?}"; wait "${teePid:?}"

	return "${exitCode:?}"
}

# Merges a source directory with a target directory
mergeDirs() {
	source=${1:?}
	target=${2:?}

	rsync -rl --remove-source-files "${source:?}"/ "${target:?}"/

	rm -rf "${source:?}"
}

# Executes an ERB template
execErb() {
	in=${1:?}
	out=${2:-${in%.erb}}

	if [ "${out:?}" = '-' ]; then
		erb -T - -- "${in:?}"
	else
		rm -f -- "${out:?}"
		erb -T - -- "${in:?}" > "${out:?}"
		chmod --reference="${in:?}" -- "${out:?}"
	fi
}
