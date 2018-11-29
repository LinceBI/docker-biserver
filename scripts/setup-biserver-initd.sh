#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

extractArchive() {
	source="${1:?}"
	target="${2:?}"
	case "${source}" in
		*.tar|*.tar.gz|*.tar.bz2|*.tar.xz)
			tar -C "${target}" -xf "${source}"
			;;
		*.zip|*.kar)
			unzip -qod "${target}" "${source}"
			;;
	esac
}

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
			# Extract archives
			*.tar|*.tar.gz|*.tar.bz2|*.tar.xz|*.zip|*.kar)
				case "${file}" in
					*.__webapp__.*)
						logInfo "Extracting file \"${file}\" to Pentaho webapp directory ..."
						extractArchive "${file}" "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"
						;;
					*.__style_webapp__.*)
						logInfo "Extracting file \"${file}\" to Pentaho Style webapp directory ..."
						extractArchive "${file}" "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}"
						;;
					*.__solutions__.*)
						logInfo "Extracting file \"${file}\" to solutions directory ..."
						extractArchive "${file}" "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"
						;;
					*.__data__.*)
						logInfo "Extracting file \"${file}\" to data directory ..."
						extractArchive "${file}" "${BISERVER_HOME}"/"${DATA_DIRNAME}"
						;;
					*)
						logInfo "Installing plugin \"${file}\"..."
						extractArchive "${file}" "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system
						;;
				esac
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