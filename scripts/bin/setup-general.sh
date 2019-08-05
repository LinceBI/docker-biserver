#!/bin/sh

set -eu
export LC_ALL=C

. /usr/share/biserver/bin/set-utils.sh

########

# Execute ERB files
recursiveExecuteErbs() {
	for path in "${1:?}"/*; do
		if [ -d "${path}" ] && [ ! -L "${path}" ]; then
			recursiveExecuteErbs "${path}"
		elif [ "${path}" != "${path%.erb}" ]; then
			logInfo "Executing ERB file: ${path}"
			dirname=${path%/*}; basename=$(basename "${path}" .erb)
			output=${dirname}/${basename}
			erb -T - -- "${output}.erb" > "${output}"
			chmod --reference="${output}.erb" -- "${output}"
		fi
	done
}
recursiveExecuteErbs "${BISERVER_HOME}"

# Compress directories ending in .zip, .pfm or .pgus
recursiveZipDirs() {
	for path in "${1:?}"/*; do
		if [ -d "${path}" ] && [ ! -L "${path}" ]; then
			# This method must be called in a subshell to avoid
			# overwriting variables in the current scope
			(recursiveZipDirs "${path}")
			if
				[ "${path}" != "${path%.zip}" ] ||
				# Pentaho File Metadata plugin
				[ "${path}" != "${path%.pfm}" ] ||
				# Pentaho Global User Settings plugin
				[ "${path}" != "${path%.pgus}" ]
			then
				logInfo "Compressing directory: ${path}"
				dirname=${path%/*}; basename=${path##*/}
				output=${dirname}/${basename}; tmpOutput=$(mktemp -u)
				cd -- "${output}" || exit; zip -qmyr "${tmpOutput}" ./
				cd -- "${OLDPWD}" || exit; rmdir -- "${output}"
				[ -f "${tmpOutput}" ] && mv -- "${tmpOutput}" "${output}"
			fi
		fi
	done
}
recursiveZipDirs "${BISERVER_HOME}"