#!/bin/sh

set -eu
export LC_ALL=C

imageExists() { [ -n "$(docker images -q "$1")" ]; }
containerExists() { docker ps -aqf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }
containerIsRunning() { docker ps -qf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }
networkExists() { docker network ls -qf name="$1" --format '{{.Name}}' | grep -Fxq "$1"; }

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.2.0.0-342
DOCKER_BISERVER_CONTAINER=pentaho-biserver

DOCKER_POSTGRES_IMAGE=postgres:10
DOCKER_POSTGRES_CONTAINER="${DOCKER_BISERVER_CONTAINER}-postgres"
DOCKER_POSTGRES_PASSWORD='H4!b5at+kWls-8yh4Guq' # CHANGE ME!

DOCKER_NETWORK=${DOCKER_BISERVER_CONTAINER}

# Network
#########

if ! networkExists "${DOCKER_NETWORK}"; then
	printf -- '%s\n' "Creating \"${DOCKER_NETWORK}\" network..."
	docker network create "${DOCKER_NETWORK}"
fi

# PostgreSQL container
######################

if ! imageExists "${DOCKER_POSTGRES_IMAGE}"; then
	>&2 printf -- '%s\n' "${DOCKER_POSTGRES_IMAGE} image doesn't exist!"
	exit 1
fi

if containerIsRunning "${DOCKER_POSTGRES_CONTAINER}"; then
	printf -- '%s\n' "Stopping \"${DOCKER_POSTGRES_CONTAINER}\" container..."
	docker stop "${DOCKER_POSTGRES_CONTAINER}" >/dev/null
fi

if containerExists "${DOCKER_POSTGRES_CONTAINER}"; then
	printf -- '%s\n' "Removing \"${DOCKER_POSTGRES_CONTAINER}\" container..."
	docker rm "${DOCKER_POSTGRES_CONTAINER}" >/dev/null
fi

printf -- '%s\n' "Creating \"${DOCKER_POSTGRES_CONTAINER}\" container..."

docker run --detach \
	--name "${DOCKER_POSTGRES_CONTAINER}" \
	--hostname "${DOCKER_POSTGRES_CONTAINER}" \
	--network "${DOCKER_NETWORK}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '127.0.0.1:5432:5432/tcp' --publish '[::1]:5432:5432/tcp' \
	--env PGDATA='/var/lib/postgresql/data/pgdata' \
	--env POSTGRES_PASSWORD="${DOCKER_POSTGRES_PASSWORD}" \
	"${DOCKER_POSTGRES_IMAGE}"

printf -- '%s\n' 'Waiting for database server...'
until nc -zv 127.0.0.1 5432; do sleep 1; done && sleep 10

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
	--network "${DOCKER_NETWORK}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '8080:8080/tcp' \
	--publish '8009:8009/tcp' \
	--env STORAGE_TYPE='postgres' \
	--env POSTGRES_HOST="${DOCKER_POSTGRES_CONTAINER}" \
	--env POSTGRES_PASSWORD="${DOCKER_POSTGRES_PASSWORD}" \
	"${DOCKER_BISERVER_IMAGE}" "$@"
