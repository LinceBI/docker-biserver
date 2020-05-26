#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

extractArchive() {
	source="${1:?}"
	target="${2:?}"
	if matches "${source:?}" "${PATTERN_EXT_TAR:?}"; then
		tar -C "${target:?}" -xf "${source:?}"
	elif matches "${source:?}" "${PATTERN_EXT_ZIP:?}"; then
		unzip -qod "${target:?}" "${source:?}"
	fi
}

copyDirectory() {
	source="${1:?}"
	target="${2:?}"
	rsync -aAX "${source:?}"/ "${target:?}"/

	# Execute ERB files
	recursiveExecuteErbs() {
		for path in "${1:?}"/*; do
			if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
				recursiveExecuteErbs "${path:?}"
			elif [ "${path:?}" != "${path%.erb}" ]; then
				logInfo "Executing ERB file: ${path:?}"
				dirname=${path%/*}; basename=$(basename "${path:?}" .erb)
				# Substitute source dirname with target dirname
				dirname=${target:?}${dirname##${source:?}}
				output=${dirname:?}/${basename:?}
				rm -f "${output:?}"
				erb -T - -- "${output:?}.erb" > "${output:?}"
				chmod --reference="${output:?}.erb" -- "${output:?}"
			fi
		done
	}
	recursiveExecuteErbs "${source:?}"

	# Extract files ending in .zip
	recursiveUnzipFiles() {
		for path in "${1:?}"/*; do
			if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
				recursiveUnzipFiles "${path:?}"
			elif [ "${path:?}" != "${path%.zip}" ]; then
				logInfo "Extracting ZIP file: ${path:?}"
				dirname=${path%/*}; basename=${path##*/}
				# Substitute source dirname with target dirname
				dirname=${target:?}${dirname##${source:?}}
				input=${dirname:?}/${basename:?}
				unzip -qd "${dirname:?}" "${input:?}"
				rm -f "${input:?}"
			fi
		done
	}
	recursiveUnzipFiles "${source:?}"

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
					# Substitute source dirname with target dirname
					dirname=${target:?}${dirname##${source:?}}
					output=${dirname:?}/${basename:?}; tmpOutput=$(mktemp -u)
					cd -- "${output:?}" || exit; zip -qmyr "${tmpOutput:?}" ./
					cd -- "${OLDPWD:?}" || exit; rmdir -- "${output:?}"
					[ -f "${tmpOutput:?}" ] && mv -- "${tmpOutput:?}" "${output:?}"
				fi
			fi
		done
	}
	recursiveZipDirs "${source:?}"

	# Remove ".__preserve__" suffix from files and directories
	recursiveRemoveSuffix() {
		for path in "${1:?}"/*; do
			if [ -d "${path:?}" ] && [ ! -L "${path:?}" ]; then
				# This method must be called in a subshell to avoid
				# overwriting variables in the current scope
				(recursiveRemoveSuffix "${path:?}")
			fi
			if [ "${path:?}" != "${path%.__preserve__}" ]; then
				logInfo "Removing suffix from: ${path:?}"
				dirname=${path%/*}; basename=${path##*/}
				# Substitute source dirname with target dirname
				dirname=${target:?}${dirname##${source:?}}
				output=${dirname:?}/${basename%.__preserve__}
				mv -- "${output:?}.__preserve__" "${output:?}"
			fi
		done
	}
	recursiveRemoveSuffix "${source:?}"
}

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
