#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

WEBINFDIR="${CATALINA_BASE:?}/webapps/${WEBAPP_PENTAHO_DIRNAME:?}/WEB-INF"
CLASSPATH=$(find "${WEBINFDIR:?}/lib" -type d -printf '%p:%p/*:')

TMPCLASSPATH=$(mktemp -d)
# shellcheck disable=SC2154
trap 'ret="$?"; rm -rf "${TMPCLASSPATH:?}"; trap - EXIT; exit "${ret:?}"' EXIT TERM INT HUP

if [ -e "${WEBINFDIR:?}"/classes/kettle-password-encoder-plugins.xml ]; then
	cp "${WEBINFDIR:?}"/classes/kettle-password-encoder-plugins.xml "${TMPCLASSPATH:?}"
fi

cd "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/
exec java \
		-classpath "${CLASSPATH:?}:${TMPCLASSPATH:?}" \
		-Dlog4j2.configurationFile=file:"${WEBINFDIR:?}/classes/log4j2.xml" \
		-Dlog4j2.formatMsgNoLookups=true \
		org.pentaho.di.core.encryption.Encr "$@" | tr -d '\n'
