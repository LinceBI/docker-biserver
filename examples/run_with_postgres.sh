#!/bin/sh

set -eu
export LC_ALL=C

DOCKER=$(command -v docker 2>/dev/null)

BISERVER_IMAGE_REGISTRY=repo.stratebi.com
BISERVER_IMAGE_NAMESPACE=lincebi
BISERVER_IMAGE_PROJECT=biserver
BISERVER_IMAGE_TAG=9.0.0.0-423
BISERVER_IMAGE_NAME=${BISERVER_IMAGE_REGISTRY:?}/${BISERVER_IMAGE_NAMESPACE:?}/${BISERVER_IMAGE_PROJECT:?}:${BISERVER_IMAGE_TAG:?}
BISERVER_CONTAINER_NAME=${BISERVER_IMAGE_PROJECT:?}

POSTGRES_IMAGE_REGISTRY=docker.io
#POSTGRES_IMAGE_NAMESPACE=
POSTGRES_IMAGE_PROJECT=postgres
POSTGRES_IMAGE_TAG=12
POSTGRES_IMAGE_NAME=${POSTGRES_IMAGE_REGISTRY:?}/${POSTGRES_IMAGE_PROJECT:?}:${POSTGRES_IMAGE_TAG:?}
POSTGRES_CONTAINER_NAME=${BISERVER_IMAGE_PROJECT:?}-${POSTGRES_IMAGE_PROJECT:?}
POSTGRES_CONTAINER_PASSWORD='H4!b5at+kWls-8yh4Guq'

CONTAINERS_NETWORK=${BISERVER_IMAGE_PROJECT:?}

imageExists() { [ -n "$("${DOCKER:?}" images -q "${1:?}")" ]; }
containerExists() { "${DOCKER:?}" ps -af name="${1:?}" --format '{{.Names}}' | grep -Fxq "${1:?}"; }
containerIsRunning() { "${DOCKER:?}" ps -f name="${1:?}" --format '{{.Names}}' | grep -Fxq "${1:?}"; }
networkExists() { "${DOCKER:?}" network ls -f name="$1" --format '{{.Name}}' | grep -Fxq "${1:?}"; }

# Network
#########

if ! networkExists "${CONTAINERS_NETWORK:?}"; then
	printf -- '%s\n' "Creating \"${CONTAINERS_NETWORK:?}\" network..."
	"${DOCKER:?}" network create "${CONTAINERS_NETWORK:?}"
fi

# PostgreSQL container
######################

if ! imageExists "${POSTGRES_IMAGE_NAME:?}" && ! imageExists "${POSTGRES_IMAGE_NAME#docker.io/}"; then
	"${DOCKER:?}" pull "${POSTGRES_IMAGE_NAME:?}"
fi

if containerIsRunning "${POSTGRES_CONTAINER_NAME:?}"; then
	printf -- '%s\n' "Stopping \"${POSTGRES_CONTAINER_NAME:?}\" container..."
	"${DOCKER:?}" stop "${POSTGRES_CONTAINER_NAME:?}" >/dev/null
fi

if containerExists "${POSTGRES_CONTAINER_NAME:?}"; then
	printf -- '%s\n' "Removing \"${POSTGRES_CONTAINER_NAME:?}\" container..."
	"${DOCKER:?}" rm "${POSTGRES_CONTAINER_NAME:?}" >/dev/null
fi

printf -- '%s\n' "Creating \"${POSTGRES_CONTAINER_NAME:?}\" container..."
"${DOCKER:?}" run --detach \
	--name "${POSTGRES_CONTAINER_NAME:?}" \
	--hostname "${POSTGRES_CONTAINER_NAME:?}" \
	--network "${CONTAINERS_NETWORK:?}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '127.0.0.1:5432:5432/tcp' \
	--env POSTGRES_PASSWORD="${POSTGRES_CONTAINER_PASSWORD:?}" \
	"${POSTGRES_IMAGE_NAME:?}"

printf -- '%s\n' 'Waiting for database server...'
until nc -zv 127.0.0.1 5432; do sleep 1; done && sleep 10

# Pentaho BI Server container
#############################

if ! imageExists "${BISERVER_IMAGE_NAME:?}" && ! imageExists "${BISERVER_IMAGE_NAME#docker.io/}"; then
	>&2 printf -- '%s\n' "\"${BISERVER_IMAGE_NAME:?}\" image doesn't exist!"
	exit 1
fi

if containerIsRunning "${BISERVER_CONTAINER_NAME:?}"; then
	printf -- '%s\n' "Stopping \"${BISERVER_CONTAINER_NAME:?}\" container..."
	"${DOCKER:?}" stop "${BISERVER_CONTAINER_NAME:?}" >/dev/null
fi

if containerExists "${BISERVER_CONTAINER_NAME:?}"; then
	printf -- '%s\n' "Removing \"${BISERVER_CONTAINER_NAME:?}\" container..."
	"${DOCKER:?}" rm "${BISERVER_CONTAINER_NAME:?}" >/dev/null
fi

printf -- '%s\n' "Creating \"${BISERVER_CONTAINER_NAME:?}\" container..."
"${DOCKER:?}" run --detach \
	--name "${BISERVER_CONTAINER_NAME:?}" \
	--hostname "${BISERVER_CONTAINER_NAME:?}" \
	--network "${CONTAINERS_NETWORK:?}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '8080:8080/tcp' \
	--env STORAGE_TYPE='postgres' \
	--env POSTGRES_HOST="${POSTGRES_CONTAINER_NAME:?}" \
	--env POSTGRES_PASSWORD="${POSTGRES_CONTAINER_PASSWORD:?}" \
	"${BISERVER_IMAGE_NAME:?}" "$@"
