#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck disable=SC1091
. /usr/share/biserver/bin/set-utils.sh

########

if [ "${SERVICE_BISERVER_ENABLED:?}" = 'true' ]; then
	runitEnSv biserver
fi

if [ "${SERVICE_SUPERCRONIC_ENABLED:?}" = 'true' ] && [ -e "${BIUSER_HOME:?}"/crontab ]; then
	runitEnSv supercronic
fi

########

exec runsvdir -P /usr/share/biserver/service/enabled/
