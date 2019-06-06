#!/bin/sh

set -eu
export LC_ALL=C

LIBDIR="${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_DIRNAME}/WEB-INF/lib"

java \
	-classpath "$(printf -- '%s:' \
		"${LIBDIR}"/kettle-core-*.jar \
		"${LIBDIR}"/slf4j-api-*.jar \
		"${LIBDIR}"/commons-*.jar\
	)" \
	org.pentaho.di.core.encryption.Encr \
	"$@" 2>/dev/null
