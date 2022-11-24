#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

WEBINFDIR="${CATALINA_BASE:?}/webapps/${WEBAPP_PENTAHO_DIRNAME:?}/WEB-INF"

CLASSPATH=$(find \
	"${WEBINFDIR:?}/lib" \
	-type f -name '*.jar' \
	-not -name 'classic-core-platform-plugin-*.jar' \
	-not -name 'classic-extensions-cda-*.jar' \
	-printf '%p:')

cd "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/
exec java \
		-classpath "${CLASSPATH:?}" \
		-Dlog4j2.configurationFile=file:"${WEBINFDIR:?}/classes/log4j2.xml" \
		-Dlog4j2.formatMsgNoLookups=true \
		org.pentaho.di.core.encryption.Encr "$@" | tr -d '\n'
