#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

export LD_LIBRARY_PATH="${CATALINA_HOME:?}"/lib:/lib/x86_64-linux-gnu:"${LD_LIBRARY_PATH-}"
export CATALINA_OPTS="\
	-Xms${JAVA_XMS:?} -Xmx${JAVA_XMX:?} \
	-Dfile.encoding=utf8 \
	-Dsun.rmi.dgc.client.gcInterval=3600000 \
	-Dsun.rmi.dgc.server.gcInterval=3600000 \
	-Dlog4j2.formatMsgNoLookups=true \
	-DDI_HOME='${BISERVER_HOME:?}/${SOLUTIONS_DIRNAME:?}/system/kettle/' \
	${CATALINA_OPTS_EXTRA?}"

logInfo "Starting Pentaho BI Server..."
cd "${CATALINA_HOME:?}"/bin
exec ./catalina.sh run
