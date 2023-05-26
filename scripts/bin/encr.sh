#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

DI_HOME="${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle
WEBINF_DIR="${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF

cd "${CATALINA_BASE:?}"/bin/
exec java \
		-classpath "${WEBINF_DIR:?}/lib/*:${WEBINF_DIR:?}/classes" \
		-Xms16m -Xmx32m \
		-Dfile.encoding=utf8 \
		-Djava.locale.providers=COMPAT,SPI \
		-Dpentaho.disable.karaf=true \
		-Dlog4j2.configurationFile=file:"${WEBINF_DIR:?}/classes/log4j2.xml" \
		-Dlog4j2.formatMsgNoLookups=true \
		-DDI_HOME="${DI_HOME:?}" \
		org.pentaho.di.core.encryption.Encr "$@" | tr -d '\n'
