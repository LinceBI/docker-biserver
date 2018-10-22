#!/bin/sh

set -eu
export LC_ALL=C

imageExists() { [ -n "$(docker images -q "$1")" ]; }
containerExists() { docker ps -aqf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }
containerIsRunning() { docker ps -qf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.1.0.0-365
DOCKER_BISERVER_CONTAINER=pentaho-biserver

# Pentaho BI Server container
#############################

if ! imageExists "${DOCKER_BISERVER_IMAGE}"; then
	>&2 printf -- '%s\n' "${DOCKER_BISERVER_IMAGE} image doesn't exist!"
	exit 1
fi

if containerIsRunning "${DOCKER_BISERVER_CONTAINER}"; then
	printf -- '%s\n' "Stopping \"${DOCKER_BISERVER_CONTAINER}\" container..."
	docker stop "${DOCKER_BISERVER_CONTAINER}" >/dev/null
fi

if containerExists "${DOCKER_BISERVER_CONTAINER}"; then
	printf -- '%s\n' "Removing \"${DOCKER_BISERVER_CONTAINER}\" container..."
	docker rm "${DOCKER_BISERVER_CONTAINER}" >/dev/null
fi

printf -- '%s\n' "Creating \"${DOCKER_BISERVER_CONTAINER}\" container..."
docker run --detach \
	--name "${DOCKER_BISERVER_CONTAINER}" \
	--hostname "${DOCKER_BISERVER_CONTAINER}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '8080:8080/tcp' \
	--publish '8009:8009/tcp' \
	"${DOCKER_BISERVER_IMAGE}" "$@"
