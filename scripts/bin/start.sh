#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck disable=SC1091
. /usr/share/biserver/bin/set-utils.sh

########

if [ ! -f "${HOME:?}"/biserver.setup.lock ]; then
	runAndLog /usr/share/biserver/bin/setup.sh "${HOME:?}"/biserver.setup.log
	touch "${HOME:?}"/biserver.setup.lock
fi

########

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}:${CATALINA_HOME:?}/lib"
# shellcheck disable=SC2155
export CATALINA_OPTS="$(cat <<-EOF
	-DDI_HOME="${BISERVER_HOME:?}"/"${KETTLE_DIRNAME:?}" \
	-Dsun.rmi.dgc.client.gcInterval=3600000 \
	-Dsun.rmi.dgc.server.gcInterval=3600000 \
	-Dfile.encoding=utf8 \
	-Xms${CATALINA_OPTS_JAVA_XMS:?} \
	-Xmx${CATALINA_OPTS_JAVA_XMX:?} \
	${CATALINA_OPTS_EXTRA?}
EOF
)"

########

logInfo "Starting Pentaho BI Server..."
cd "${CATALINA_HOME:?}"/bin
exec ./catalina.sh run
