#!/bin/sh

set -eu
export LC_ALL=C

DOCKER=$(command -v docker 2>/dev/null)

IMAGE_REGISTRY=repo.stratebi.com
IMAGE_NAMESPACE=stratebi
IMAGE_PROJECT=biserver
IMAGE_TAG=9.0.0.0-423
IMAGE_NAME=${IMAGE_REGISTRY:?}/${IMAGE_NAMESPACE:?}/${IMAGE_PROJECT:?}:${IMAGE_TAG:?}
CONTAINER_NAME=${IMAGE_PROJECT:?}-export

"${DOCKER:?}" run --rm \
	--name "${CONTAINER_NAME:?}" \
	--hostname "${CONTAINER_NAME:?}" \
	"${IMAGE_NAME:?}" /usr/share/biserver/bin/export.sh
