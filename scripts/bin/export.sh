#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# Execute setup scripts
export IS_EXPORTING='true'
/usr/share/biserver/bin/setup.sh 1>&2

# Print zip to stdout
cd "${BISERVER_HOME:?}"
exec zip -rq1 -x '*.erb' -x '.placeholder' - ./
