#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck disable=SC1091
. /usr/share/biserver/bin/set-utils.sh

########

# Create Kettle directory if it does not exist
if [ ! -e "${KETTLE_HOME:?}"/.kettle/ ]; then
	mkdir "${KETTLE_HOME:?}"/.kettle/
	chmod 775 "${KETTLE_HOME:?}"/.kettle/
fi

# Create Kettle properties file if it does not exist
if [ ! -e "${KETTLE_HOME:?}"/.kettle/kettle.properties ]; then
	touch "${KETTLE_HOME:?}"/.kettle/kettle.properties
	chmod 664 "${KETTLE_HOME:?}"/.kettle/kettle.properties
fi

########

# Execute ERB files
recursiveExecuteErbs() {
	for path in "${1:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			recursiveExecuteErbs "${path:?}"
		elif [ "${path:?}" != "${path%.erb}" ]; then
			logInfo "Executing ERB file: ${path:?}"
			dirname=${path%/*}; basename=$(basename "${path:?}" .erb)
			output=${dirname:?}/${basename:?}
			rm -f "${output:?}"
			erb -T - -- "${output:?}.erb" > "${output:?}"
			chmod --reference="${output:?}.erb" -- "${output:?}"
		fi
	done
}
recursiveExecuteErbs "${BISERVER_HOME:?}"

# Compress directories ending in .zip, .pfm or .pgus
recursiveZipDirs() {
	for path in "${1:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			# This method must be called in a subshell to avoid
			# overwriting variables in the current scope
			(recursiveZipDirs "${path:?}")
			if
				[ "${path:?}" != "${path%.zip}" ] ||
				# Pentaho File Metadata plugin
				[ "${path:?}" != "${path%.pfm}" ] ||
				# Pentaho Global User Settings plugin
				[ "${path:?}" != "${path%.pgus}" ]
			then
				logInfo "Compressing directory: ${path:?}"
				dirname=${path%/*}; basename=${path##*/}
				output=${dirname:?}/${basename:?}; tmpOutput=$(mktemp -u)
				cd -- "${output:?}" || exit; zip -qmyr "${tmpOutput:?}" ./
				cd -- "${OLDPWD:?}" || exit; rmdir -- "${output:?}"
				[ -f "${tmpOutput:?}" ] && mv -- "${tmpOutput:?}" "${output:?}"
			fi
		fi
	done
}
recursiveZipDirs "${BISERVER_HOME:?}"
