#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=repo.stratebi.com/stratebi/biserver:8.3.0.0-371

docker run --rm \
	"${DOCKER_BISERVER_IMAGE}" /usr/share/biserver/bin/export.sh
