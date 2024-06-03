#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

DI_HOME="${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle
WEBINF_DIR="${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF

CLASSPATH=$(find \
	"${WEBINF_DIR:?}/lib" \
	"${CATALINA_BASE:?}/lib" \
	-type f -name '*.jar' \
	-not -name 'classic-core-platform-plugin-*.jar' \
	-not -name 'classic-extensions-cda-*.jar' \
	-printf '%p:')

TMPCLASSPATH=$(mktemp -d)
# shellcheck disable=SC2154
trap 'ret="$?"; rm -rf "${TMPCLASSPATH:?}"; trap - EXIT; exit "${ret:?}"' EXIT TERM INT HUP

if [ -e "${WEBINF_DIR:?}"/classes/kettle-password-encoder-plugins.xml ]; then
	cp "${WEBINF_DIR:?}"/classes/kettle-password-encoder-plugins.xml "${TMPCLASSPATH:?}"
fi

cd "${DI_HOME:?}"
exec java \
		-classpath "${CLASSPATH:?}:${TMPCLASSPATH:?}" \
		-Xms"${JAVA_XMS:?}" -Xmx"${JAVA_XMX:?}" \
		-Dfile.encoding=utf8 \
		-Djava.locale.providers=COMPAT,SPI \
		-Dpentaho.disable.karaf=true \
		-Dlog4j2.configurationFile=file:"${WEBINF_DIR:?}/classes/log4j2.xml" \
		-Dlog4j2.formatMsgNoLookups=true \
		-DSTRING_ONLY_USED_DB_TO_XML=N \
		-DDI_HOME="${DI_HOME:?}" \
		-Dorg.osjava.sj.root="${BIUSER_HOME:?}/.simple-jndi" \
		org.pentaho.di.pan.Pan -initialDir "${BISERVER_HOME:?}" "$@"
