#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# Rename root directories
renameRootDirs() {
	source=${1:?}

	# Rename solutions directory
	if [ -e "${source:?}"/pentaho-solutions/ ] && [ ! -e "${source:?}"/"${SOLUTIONS_DIRNAME:?}" ]; then
		mv -f "${source:?}"/pentaho-solutions/ "${source:?}"/"${SOLUTIONS_DIRNAME:?}"
	fi

	# Rename data directory
	if [ -e "${source:?}"/data/ ] && [ ! -e "${source:?}"/"${DATA_DIRNAME:?}" ]; then
		mv -f "${source:?}"/data/ "${source:?}"/"${DATA_DIRNAME:?}"
	fi

	# Rename Pentaho webapp directory
	if [ -e "${source:?}"/tomcat/webapps/pentaho/ ] && [ ! -e "${source:?}"/tomcat/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" ]; then
		mv -f "${source:?}"/tomcat/webapps/pentaho/ "${source:?}"/tomcat/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
	fi

	# Rename Pentaho style webapp directory
	if [ -e "${source:?}"/tomcat/webapps/pentaho-style/ ] && [ ! -e "${source:?}"/tomcat/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" ]; then
		mv -f "${source:?}"/tomcat/webapps/pentaho-style/ "${source:?}"/tomcat/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
	fi
}

# Execute ERB files
recursiveExecuteErbs() {
	source=${1:?}

	for path in "${source:?}"/*; do
		if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
			recursiveExecuteErbs "${path:?}"
		elif [ "${path:?}" != "${path%.erb}" ]; then
			logInfo "Executing ERB file: ${path:?}"
			in=${path:?}; out=${path%.erb}
			execErb "${in:?}" "${out:?}"
		fi
	done
}

# Extract files ending in .zip
recursiveUnzipFiles() {
	source=${1:?}

	for path in "${source:?}"/*; do
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
	source=${1:?}

	for path in "${source:?}"/*; do
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
	source=${1:?}

	for path in "${source:?}"/*; do
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
	type=${1:?}
	source=${2:?}
	target=${3:?}
	tmpdir=$(mktemp -d)

	if matches "${source:?}" "${PATTERN_EXT_TAR:?}"; then
		tar -C "${tmpdir:?}" -xf "${source:?}"
	elif matches "${source:?}" "${PATTERN_EXT_ZIP:?}"; then
		unzip -qod "${tmpdir:?}" "${source:?}"
	fi

	cd "${tmpdir:?}"
	if [ "${type:?}" = 'root' ]; then
		renameRootDirs "${tmpdir:?}"
	fi
	recursiveExecuteErbs "${tmpdir:?}"
	cd "${OLDPWD:?}"

	mergeDirs "${tmpdir:?}"/ "${target:?}"/
}

# Copy directory and execute initialisation steps
copyDirectory() {
	type=${1:?}
	source=${2:?}
	target=${3:?}
	tmpdir=$(mktemp -du)

	cp -a "${source:?}"/ "${tmpdir:?}"/

	cd "${tmpdir:?}"
	if [ "${type:?}" = 'root' ]; then
		renameRootDirs "${tmpdir:?}"
	fi
	recursiveUnzipFiles "${tmpdir:?}"
	recursiveExecuteErbs "${tmpdir:?}"
	recursiveZipDirs "${tmpdir:?}"
	recursiveRemoveSuffix "${tmpdir:?}"
	cd "${OLDPWD:?}"

	mergeDirs "${tmpdir:?}"/ "${target:?}"/
}

# Check if it is a Pentaho plugin by detecting if a "plugin.xml" file is present
isPentahoPlugin() {
	source=${1:?}

	if [ -d "${source:?}" ]; then
		if [ -f "${source:?}"/plugin.xml ]; then
			return 0
		fi
	elif [ -f "${source:?}" ]; then
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
	source=${1:?}

	_LC_COLLATE=${LC_COLLATE-}; LC_COLLATE=C
	for path in "${source:?}"/*; do
		if [ -d "${path:?}" ]; then
			# Copy directories
			case "${path:?}" in
				*.__root__)
					logInfo "Copying directory \"${path:?}\" to root directory..."
					copyDirectory 'root' "${path:?}" "${BISERVER_HOME:?}"
					;;
				*.__webapp_pentaho__)
					logInfo "Copying directory \"${path:?}\" to Pentaho webapp directory..."
					copyDirectory 'webapp-pentaho' "${path:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
					;;
				*.__webapp_pentaho_style__)
					logInfo "Copying directory \"${path:?}\" to Pentaho Style webapp directory..."
					copyDirectory 'webapp-pentaho-style' "${path:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
					;;
				*.__pentaho_solutions__)
					logInfo "Copying directory \"${path:?}\" to solutions directory..."
					copyDirectory 'solutions' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
					;;
				*.__data__)
					logInfo "Copying directory \"${path:?}\" to data directory..."
					copyDirectory 'data' "${path:?}" "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
					;;
				*.__plugin__)
					logInfo "Installing plugin \"${path:?}\"..."
					copyDirectory 'root' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
					;;
				*)
					# Determine if it is a Pentaho plugin
					if isPentahoPlugin "${path:?}"; then
						logInfo "Installing plugin \"${path:?}\"..."
						copyDirectory 'plugin' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
					else
						logInfo "Copying directory \"${path:?}\" to root directory..."
						copyDirectory 'root' "${path:?}" "${BISERVER_HOME:?}"
					fi
					;;
			esac
		elif [ -f "${path:?}" ]; then
			# Execute shell scripts
			if matches "${path:?}" "${PATTERN_EXT_RUN:?}"; then
				logInfo "Executing script \"${path:?}\""
				(cd "${BISERVER_HOME:?}" && "${path:?}")
			# Extract archives
			elif matches "${path:?}" "\(${PATTERN_EXT_TAR:?}\|${PATTERN_EXT_ZIP:?}\)"; then
				case "${path:?}" in
					*.__root__.*)
						logInfo "Extracting file \"${path:?}\" to root directory..."
						extractArchive 'root' "${path:?}" "${BISERVER_HOME:?}"
						;;
					*.__webapp_pentaho__.*)
						logInfo "Extracting file \"${path:?}\" to Pentaho webapp directory..."
						extractArchive 'webapp-pentaho' "${path:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
						;;
					*.__webapp_pentaho_style__.*)
						logInfo "Extracting file \"${path:?}\" to Pentaho Style webapp directory..."
						extractArchive 'webapp-pentaho-style' "${path:?}" "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
						;;
					*.__pentaho_solutions__.*)
						logInfo "Extracting file \"${path:?}\" to solutions directory..."
						extractArchive 'solutions' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
						;;
					*.__data__.*)
						logInfo "Extracting file \"${path:?}\" to data directory..."
						extractArchive 'data' "${path:?}" "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
						;;
					*.__plugin__.*)
						logInfo "Installing plugin \"${path:?}\"..."
						extractArchive 'plugin' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
						;;
					*)
						# Determine if it is a Pentaho plugin
						if isPentahoPlugin "${path:?}"; then
							logInfo "Installing plugin \"${path:?}\"..."
							extractArchive 'plugin' "${path:?}" "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system
						else
							logInfo "Extracting file \"${path:?}\" to root directory..."
							extractArchive 'root' "${path:?}" "${BISERVER_HOME:?}"
						fi
						;;
				esac
			# Copy jar files
			elif matches "${path:?}" "${PATTERN_EXT_JAR:?}"; then
				logInfo "Copying jar \"${path:?}\"..."
				cp -f "${path:?}" "${CATALINA_BASE:?}"/lib/
			# Ignore the rest of files
			else
				logWarn "Ignoring file \"${path:?}\""
			fi
		elif [ -e "${path:?}" ]; then
			logWarn "Ignoring entry \"${path:?}\""
		fi
	done
	LC_COLLATE=$_LC_COLLATE
}

initdFromDir "${@}"
