#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.1.0.0-365

docker run --rm \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
