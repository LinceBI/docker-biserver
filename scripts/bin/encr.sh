#!/bin/sh

set -eu
export LC_ALL=C

WEBINFDIR="${CATALINA_BASE:?}/webapps/${WEBAPP_PENTAHO_DIRNAME:?}/WEB-INF"
CLASSPATH=$(printf -- '%s:' \
	"${WEBINFDIR:?}/lib"/kettle-core-*.jar \
	"${WEBINFDIR:?}/lib"/commons-*.jar \
	"${WEBINFDIR:?}/lib"/slf4j-api-*.jar \
)

exec java \
		-classpath "${CLASSPATH:?}" \
		org.pentaho.di.core.encryption.Encr \
		"$@" 2>/dev/null | tr -d '\n'
