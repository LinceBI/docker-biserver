#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck disable=SC1091
. /usr/share/biserver/bin/set-utils.sh

########

if [ "${SERVICE_BISERVER_ENABLED:?}" = 'true' ]; then
	runitEnSv biserver

	BISERVER_SETUP_LCK_FILE="${BISERVER_HOME:?}"/setup.lock
	BISERVER_SETUP_LOG_FILE="${CATALINA_BASE:?}"/logs/setup.log
	if [ ! -f "${BISERVER_SETUP_LCK_FILE:?}" ]; then
		runAndLog /usr/share/biserver/bin/setup.sh "${BISERVER_SETUP_LOG_FILE}"
		touch "${BISERVER_SETUP_LCK_FILE:?}"
	fi
fi

if [ "${SERVICE_SUPERCRONIC_ENABLED:?}" = 'true' ] && [ -e "${BIUSER_HOME:?}"/crontab ]; then
	runitEnSv supercronic
fi

########

exec runsvdir -P /usr/share/biserver/service/enabled/
