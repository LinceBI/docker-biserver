#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH-}:${CATALINA_HOME:?}/lib
export CATALINA_OPTS="\
	-Dfile.encoding=utf8 -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000 -XX:MaxPermSize=256m \
	-Xms${CATALINA_OPTS_JAVA_XMS:?} -Xmx${CATALINA_OPTS_JAVA_XMX:?} ${CATALINA_OPTS_EXTRA?} \
	-DDI_HOME='${BISERVER_HOME:?}/${SOLUTIONS_DIRNAME:?}/system/kettle/'"

logInfo "Starting Pentaho BI Server..."
cd "${CATALINA_HOME:?}"/bin
exec ./catalina.sh run
