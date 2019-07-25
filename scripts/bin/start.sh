#!/bin/sh

set -eu
export LC_ALL=C

. /usr/share/biserver/bin/set-utils.sh

########

if [ ! -f "${HOME}"/.biserver.firstrun.lock ]; then
	touch "${HOME}"/.biserver.firstrun.lock
	/usr/share/biserver/bin/setup.sh
fi

########

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}:${CATALINA_HOME}/lib"
# shellcheck disable=SC2155
export CATALINA_OPTS="$(cat <<-EOF
	-DDI_HOME="${BISERVER_HOME}"/"${KETTLE_DIRNAME}"
	-Dsun.rmi.dgc.client.gcInterval=3600000
	-Dsun.rmi.dgc.server.gcInterval=3600000
	-Dfile.encoding=utf8
	-Xms${JAVA_XMS-1024m}
	-Xmx${JAVA_XMX-4096m}
	${CATALINA_OPTS_EXTRA-}
EOF
)"

########

logInfo "Starting Pentaho BI Server..."
cd "${CATALINA_HOME}"/bin
exec ./catalina.sh run
