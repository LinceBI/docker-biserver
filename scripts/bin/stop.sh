#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

logInfo "Stopping Pentaho BI Server..."
cd "${CATALINA_HOME:?}"/bin
exec ./catalina.sh stop
