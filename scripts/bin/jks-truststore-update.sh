#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

mkdir -p "$(dirname "${JAVA_TRUSTSTORE_FILE:?}")"
trust extract --overwrite --format=java-cacerts --filter=ca-anchors --purpose=server-auth "${JAVA_TRUSTSTORE_FILE:?}"
chmod 0664 "${JAVA_TRUSTSTORE_FILE:?}"
