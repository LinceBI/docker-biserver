#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

if [ ! -f "${HOME}"/.biserver.firstrun.lock ]; then
	touch "${HOME}"/.biserver.firstrun.lock
	/opt/scripts/setup.sh
fi

########

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}:${CATALINA_HOME}/lib"
export CATALINA_OPTS="$(cat <<-EOF
	-Dsun.rmi.dgc.client.gcInterval=3600000
	-Dsun.rmi.dgc.server.gcInterval=3600000
	-Dfile.encoding=utf8
	-DDI_HOME="${BISERVER_HOME}"/"${BISERVER_KETTLE_DIRNAME}"
	${CATALINA_OPTS_EXTRA-
		-Xms1024m
		-Xmx4096m
	}
EOF
)"

########

logInfo "Starting Pentaho BI Server..."
cd "${CATALINA_HOME}"/bin
exec sh catalina.sh run
