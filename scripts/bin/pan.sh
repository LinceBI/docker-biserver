#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

WEBINFDIR="${CATALINA_BASE:?}/webapps/${WEBAPP_PENTAHO_DIRNAME:?}/WEB-INF"

CLASSPATH=$(find \
	"${WEBINFDIR:?}/lib" \
	"${CATALINA_BASE:?}/lib" \
	-type f -name '*.jar' \
	-not -name 'classic-core-platform-plugin-*.jar' \
	-not -name 'classic-extensions-cda-*.jar' \
	-printf '%p:')

TMPCLASSPATH=$(mktemp -d)
# shellcheck disable=SC2154
trap 'ret="$?"; rm -rf "${TMPCLASSPATH:?}"; trap - EXIT; exit "${ret:?}"' EXIT TERM INT HUP

if [ -e "${WEBINFDIR:?}"/classes/kettle-password-encoder-plugins.xml ]; then
	cp "${WEBINFDIR:?}"/classes/kettle-password-encoder-plugins.xml "${TMPCLASSPATH:?}"
fi

cd "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/
exec java \
		-classpath "${CLASSPATH:?}:${TMPCLASSPATH:?}" \
		-Xms"${JAVA_XMS:?}" -Xmx"${JAVA_XMX:?}" \
		-Dorg.osjava.sj.root="${BIUSER_HOME:?}/.simple-jndi" \
		-Dlog4j2.configurationFile=file:"${WEBINFDIR:?}/classes/log4j2.xml" \
		-Dlog4j2.formatMsgNoLookups=true \
		org.pentaho.di.pan.Pan -initialDir "${BISERVER_HOME:?}" "$@"
