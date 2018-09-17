#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

PLUGINS_DIR="${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system

initdFromDir() {
	directory="${1:?}"
	for file in "${directory}"/*; do
		[ -f "${file}" ] || continue
		case "${file}" in
			# Execute shell scripts
			*.sh|*.run)
				logInfo "Executing script \"${file}\""
				cd "${BISERVER_HOME}" && "${file}"
				;;
			# Extract zip files
			*.zip|*.kar)
				logInfo "Installing plugin \"${file}\""
				unzip -qod "${PLUGINS_DIR}" "${file}"
				;;
			# Extract tar files
			*.tar\
			|*.tar.gz|*.tgz|*.taz\
			|*.tar.bz2|*.tbz|*.tbz2|*.tz2\
			|*.tar.lz\
			|*.tar.lzma|*.tlz\
			|*.tar.lzo\
			|*.tar.xz|*.txz)
				logInfo "Installing plugin \"${file}\""
				tar -C "${PLUGINS_DIR}" -xf "${file}"
				;;
			*)
				logWarn "Ignoring file \"${file}\""
				;;
		esac
	done
}

if [ -d "${BISERVER_INITD}" ]; then
	initdFromDir "${BISERVER_INITD}"
fi

if [ -d "${BISERVER_INITD}"/"${WEBAPP_PENTAHO_DIRNAME}" ]; then
	initdFromDir "${BISERVER_INITD}"/"${WEBAPP_PENTAHO_DIRNAME}"
fi
