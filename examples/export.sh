#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/biserver:8.2.0.0-342

docker run --rm \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
