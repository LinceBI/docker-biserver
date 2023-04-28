#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

BISERVER_SETUP_LCK_FILE="${BISERVER_HOME:?}"/setup.lock
BISERVER_SETUP_LOG_FILE="${CATALINA_BASE:?}"/logs/setup.log
if [ ! -e "${BISERVER_SETUP_LCK_FILE:?}" ]; then
	runAndLog /usr/share/biserver/bin/setup.sh "${BISERVER_SETUP_LOG_FILE}"
	touch "${BISERVER_SETUP_LCK_FILE:?}"
fi

########

update-ca-certificates

########

exec runsvdir -P "${SVDIR:?}"
