#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

ROOT_DIR="${BISERVER_HOME}"
PLUGINS_DIR="${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system

for file in "${BISERVER_INITD}"/*; do
	[ -e "${file}" ] || continue
	case "${file}" in
		# Execute shell scripts
		*.sh|*.run)
			logInfo "Executing script \"${file}\""
			cd "${BISERVER_HOME}" && "${file}"
			;;
		# Extract zip files
		*.zip|*.kar)
			case "${file}" in
				*.root.*)
					logInfo "Uncompressing archive \"${file}\""
					unzip -qod "${ROOT_DIR}" "${file}"
					;;
				*)
					logInfo "Installing plugin \"${file}\""
					unzip -qod "${PLUGINS_DIR}" "${file}"
					;;
			esac
			;;
		# Extract tar files
		*.tar\
		|*.tar.gz|*.tgz|*.taz\
		|*.tar.bz2|*.tbz|*.tbz2|*.tz2\
		|*.tar.lz\
		|*.tar.lzma|*.tlz\
		|*.tar.lzo\
		|*.tar.xz|*.txz)
			case "${file}" in
				*.root.*)
					logInfo "Uncompressing archive \"${file}\""
					tar -C "${ROOT_DIR}" -xf "${file}"
					;;
				*)
					logInfo "Installing plugin \"${file}\""
					tar -C "${PLUGINS_DIR}" -xf "${file}"
					;;
			esac
			;;
		*)
			logWarn "Ignoring file \"${file}\""
			;;
	esac
done
