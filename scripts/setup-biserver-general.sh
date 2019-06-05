#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

# shellcheck disable=SC2016
find "${BISERVER_HOME}" -type f -name '*.erb' \
	-exec printf 'Replacing ERB file: %s\n' '{}' ';' \
	-exec sh -c 'erb -T - "$1" > "$(dirname "$1")"/"$(basename "$1" .erb)"' _ '{}' ';'

########

sed -ri "s|^(DI_HOME)=.*$|\1=\"\$DIR/${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.sh
sed -ri "s|^(SET DI_HOME)=.*$|\1=\"%~dp0${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.bat
