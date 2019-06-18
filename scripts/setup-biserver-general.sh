#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

# Execute ERB files
find "${BISERVER_HOME}" \
	-type f \
	-name '*.erb' \
	-exec sh -c 'set -eu;
		for erb in "$@"; do
			printf "%s\n" "[INFO] Executing ERB file: ${erb}";
			dirname=${erb%/*}; basename=$(basename "${erb}" .erb);
			erb -T - "${erb}" > "${dirname}"/"${basename}";
		done
	' _ '{}' '+'

# Compress directories ending in .zip, .pfm or .pgus
find "${BISERVER_HOME}" \
	-type d \
	-regex '.*\.\(zip\|pfm\|pgus\)' \
	-exec sh -c 'set -eu;
		for dir in "$@"; do
			printf "%s\n" "[INFO] Compressing directory: ${dir}";
			dirname=${dir%/*}; basename=${dir##*/};
			(cd "${dir}"; zip -qmr "../.${basename}" ./);
			rmdir "${dir}"; mv "${dirname}/.${basename}" "${dir}";
		done
	' _ '{}' '+'

# Update Kettle directory location
sed -ri "s|^(DI_HOME)=.*$|\1=\"\$DIR/${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.sh
sed -ri "s|^(SET DI_HOME)=.*$|\1=\"%~dp0${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.bat
