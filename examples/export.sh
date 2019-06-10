#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/biserver:latest

docker run --rm \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
