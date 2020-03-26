#!/bin/sh

set -eu
export LC_ALL=C

WEBINFDIR="${CATALINA_BASE:?}/webapps/${WEBAPP_PENTAHO_DIRNAME:?}/WEB-INF"
CLASSPATH=$(find "${WEBINFDIR:?}/lib" "${CATALINA_BASE:?}/lib" -type d -printf '%p/*:')

cd "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/
exec java \
		-classpath "${CLASSPATH:?}" \
		-Dlog4j.configuration=file:"${WEBINFDIR:?}/classes/log4j.xml" \
		org.pentaho.di.pan.Pan -initialDir "${BISERVER_HOME:?}" "$@"
