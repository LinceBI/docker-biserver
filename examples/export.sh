#!/bin/sh

set -eu
export LC_ALL=C

DOCKER=$(command -v docker 2>/dev/null)

IMAGE_REGISTRY=repo.stratebi.com
IMAGE_NAMESPACE=lincebi
IMAGE_PROJECT=biserver
IMAGE_TAG=9.5.2.0-272-2
IMAGE_NAME=${IMAGE_REGISTRY:?}/${IMAGE_NAMESPACE:?}/${IMAGE_PROJECT:?}:${IMAGE_TAG:?}

exec "${DOCKER:?}" run --rm --log-driver none --attach STDOUT --attach STDERR \
	--env DEFAULT_ADMIN_PASSWORD='password' \
	"${IMAGE_NAME:?}" /usr/share/biserver/bin/export.sh
