#!/bin/sh

set -eu
export LC_ALL=C

# Execute setup scripts
export EXPORT_ENABLED='true'
/usr/share/biserver/bin/setup.sh 1>&2

# Print zip to stdout
cd "${BISERVER_HOME:?}"
exec zip -rq1 -x '*.erb' -x '.placeholder' - ./
