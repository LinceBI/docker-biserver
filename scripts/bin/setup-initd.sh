#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# Execute ERB files
recursiveExecuteErbs() {
	for path in "${1:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			recursiveExecuteErbs "${path:?}"
		elif [ "${path:?}" != "${path%.erb}" ]; then
			logInfo "Executing ERB file: ${path:?}"
			in=${path:?}; out=${path%.erb}
			rm -f "${out:?}"
			erb -T - -- "${in:?}" > "${out:?}"
			chmod --reference="${in:?}" -- "${out:?}"
		fi
	done
}

# Extract files ending in .zip
recursiveUnzipFiles() {
	for path in "${1:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			recursiveUnzipFiles "${path:?}"
		elif [ "${path:?}" != "${path%.zip}" ]; then
			logInfo "Extracting ZIP file: ${path:?}"
			in=${path:?}; out=${path%/*}
			unzip -qod "${out:?}" "${in:?}"
			rm -f "${in:?}"
		fi
	done
}

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
				in=${path:?}; out=${in:?}; tmpOut=$(mktemp -u)
				cd -- "${in:?}"     || exit; zip -qmyr "${tmpOut:?}" ./
				cd -- "${OLDPWD:?}" || exit; rmdir -- "${in:?}"
				[ -f "${tmpOut:?}" ] && mv -- "${tmpOut:?}" "${out:?}"
			fi
		fi
	done
}

# Remove ".__keep__" suffix from files and directories
recursiveRemoveSuffix() {
	for path in "${1:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			# This method must be called in a subshell to avoid
			# overwriting variables in the current scope
			(recursiveRemoveSuffix "${path:?}")
		fi
		if [ "${path:?}" != "${path%.__keep__}" ]; then
			logInfo "Removing suffix from: ${path:?}"
			in=${path:?}; out=${path%.__keep__}
			if [ -e "${out:?}" ]; then exit 1; fi
			mv -- "${in:?}" "${out:?}"
		fi
	done
}

# Extract archive and execute initialisation steps
extractArchive() {
	source=${1:?}
	target=${2:?}
	tmpdir=$(mktemp -d)

	if matches "${source:?}" "${PATTERN_EXT_TAR:?}"; then
		tar -C "${tmpdir:?}" -xf "${source:?}"
	elif matches "${source:?}" "${PATTERN_EXT_ZIP:?}"; then
		unzip -qod "${tmpdir:?}" "${source:?}"
	fi

	cd "${tmpdir:?}"
	recursiveUnzipFiles "${tmpdir:?}"
	recursiveExecuteErbs "${tmpdir:?}"
	recursiveZipDirs "${tmpdir:?}"
	recursiveRemoveSuffix "${tmpdir:?}"
	cd "${OLDPWD:?}"

	rsync -aAX --remove-source-files "${tmpdir:?}"/ "${target:?}"/ \
		|| case "$?" in 0|23) exit 0 ;; *) exit "$?"; esac

	rm -rf "${tmpdir:?}"
}

# Copy directory and execute initialisation steps
copyDirectory() {
	source=${1:?}
	target=${2:?}
	tmpdir=$(mktemp -d)

	rsync -aAX "${source:?}"/ "${tmpdir:?}"/

	cd "${tmpdir:?}"
	recursiveUnzipFiles "${tmpdir:?}"
	recursiveExecuteErbs "${tmpdir:?}"
	recursiveZipDirs "${tmpdir:?}"
	recursiveRemoveSuffix "${tmpdir:?}"
	cd "${OLDPWD:?}"

	rsync -aAX --remove-source-files "${tmpdir:?}"/ "${target:?}"/ \
		|| case "$?" in 0|23) exit 0 ;; *) exit "$?"; esac

	rm -rf "${tmpdir:?}"
}

# Check if it is a Pentaho plugin by detecting if a "plugin.xml" file is present
isPentahoPlugin() {
	source="${1:?}"
	if [ -d "${source:?}" ]; then
		if [ -f "${source:?}"/plugin.xml ]; then
			return 0
		fi
	elif [ -f "${entry:?}" ]; then
		if matches "${source:?}" "${PATTERN_EXT_TAR:?}"; then
			if tar -tf "${source:?}" | grep -q '^.*/plugin\.xml$'; then
				return 0
			fi
		elif matches "${source:?}" "${PATTERN_EXT_ZIP:?}"; then
			if unzip -Z1 "${source:?}" | grep -q '^.*/plugin\.xml$'; then
				return 0
			fi
		fi
	fi
	return 1
}

initdFromDir() {
	directory="${1:?}"
	_LC_COLLATE=${LC_COLLATE-}; LC_COLLATE=C
	for entry in "${directory:?}"/*; do
		if [ -d "${entry:?}" ]; then
			# Copy directories
			case "${entry:?}" in
				*.__root__)
					logInfo "Copying directory \"${entry:?}\" to root directory..."
					copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"
					;;
				*.__webapp_pentaho__)
					logInfo "Copying directory \"${entry:?}\" to Pentaho webapp directory..."
					copyDirectory "${entry:?}"/. "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
					;;
				*.__webapp_pentaho_style__)
					logInfo "Copying directory \"${entry:?}\" to Pentaho Style webapp directory..."
					copyDirectory "${entry:?}"/. "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
					;;
				*.__pentaho_solutions__)
					logInfo "Copying directory \"${entry:?}\" to solutions directory..."
					copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
					;;
				*.__data__)
					logInfo "Copying directory \"${entry:?}\" to data directory..."
					copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
					;;
				*.__plugin__)
					logInfo "Installing plugin \"${entry:?}\"..."
					copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
					;;
				*)
					# Determine if it is a Pentaho plugin
					if isPentahoPlugin "${entry:?}"; then
						logInfo "Installing plugin \"${entry:?}\"..."
						copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
					else
						logInfo "Copying directory \"${entry:?}\" to root directory..."
						copyDirectory "${entry:?}"/. "${BISERVER_HOME:?}"
					fi
					;;
			esac
		elif [ -f "${entry:?}" ]; then
			# Execute shell scripts
			if matches "${entry:?}" "${PATTERN_EXT_RUN:?}"; then
				logInfo "Executing script \"${entry:?}\""
				(cd "${BISERVER_HOME:?}" && "${entry:?}")
			# Extract archives
			elif matches "${entry:?}" "\(${PATTERN_EXT_TAR:?}\|${PATTERN_EXT_ZIP:?}\)"; then
				case "${entry:?}" in
					*.__root__.*)
						logInfo "Extracting file \"${entry:?}\" to root directory..."
						extractArchive "${entry:?}" "${BISERVER_HOME:?}"
						;;
					*.__webapp_pentaho__.*)
						logInfo "Extracting file \"${entry:?}\" to Pentaho webapp directory..."
						extractArchive "${entry:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
						;;
					*.__webapp_pentaho_style__.*)
						logInfo "Extracting file \"${entry:?}\" to Pentaho Style webapp directory..."
						extractArchive "${entry:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
						;;
					*.__pentaho_solutions__.*)
						logInfo "Extracting file \"${entry:?}\" to solutions directory..."
						extractArchive "${entry:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
						;;
					*.__data__.*)
						logInfo "Extracting file \"${entry:?}\" to data directory..."
						extractArchive "${entry:?}" "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
						;;
					*.__plugin__.*)
						logInfo "Installing plugin \"${entry:?}\"..."
						extractArchive "${entry:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
						;;
					*)
						# Determine if it is a Pentaho plugin
						if isPentahoPlugin "${entry:?}"; then
							logInfo "Installing plugin \"${entry:?}\"..."
							extractArchive "${entry:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
						else
							logInfo "Extracting file \"${entry:?}\" to root directory..."
							extractArchive "${entry:?}" "${BISERVER_HOME:?}"
						fi
						;;
				esac
			# Copy jar files
			elif matches "${entry:?}" "${PATTERN_EXT_JAR:?}"; then
				logInfo "Copying jar \"${entry:?}\"..."
				cp -f "${entry:?}" "${CATALINA_BASE:?}"/lib/
			# Ignore the rest of files
			else
				logWarn "Ignoring file \"${entry:?}\""
			fi
		elif [ -e "${entry:?}" ]; then
			logWarn "Ignoring entry \"${entry:?}\""
		fi
	done
	LC_COLLATE=$_LC_COLLATE
}

initdFromDir "${@}"
