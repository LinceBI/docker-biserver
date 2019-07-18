#!/bin/sh

set -eu
export LC_ALL=C

imageExists() { [ -n "$(docker images -q "$1")" ]; }
containerExists() { docker ps -aqf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }
containerIsRunning() { docker ps -qf name="$1" --format '{{.Names}}' | grep -Fxq "$1"; }
networkExists() { docker network ls -qf name="$1" --format '{{.Name}}' | grep -Fxq "$1"; }

DOCKER_BISERVER_IMAGE=repo.stratebi.com/stratebi/biserver:8.3.0.0-371
DOCKER_BISERVER_CONTAINER=biserver

DOCKER_MYSQL_IMAGE=mysql:5.7
DOCKER_MYSQL_CONTAINER="${DOCKER_BISERVER_CONTAINER}-mysql"
DOCKER_MYSQL_MAINTENANCE_PASSWORD='root'

DOCKER_NETWORK=${DOCKER_BISERVER_CONTAINER}

# Network
#########

if ! networkExists "${DOCKER_NETWORK}"; then
	printf -- '%s\n' "Creating \"${DOCKER_NETWORK}\" network..."
	docker network create "${DOCKER_NETWORK}"
fi

# MySQL container
######################

if ! imageExists "${DOCKER_MYSQL_IMAGE}"; then
	>&2 printf -- '%s\n' "${DOCKER_MYSQL_IMAGE} image doesn't exist!"
	exit 1
fi

if containerIsRunning "${DOCKER_MYSQL_CONTAINER}"; then
	printf -- '%s\n' "Stopping \"${DOCKER_MYSQL_CONTAINER}\" container..."
	docker stop "${DOCKER_MYSQL_CONTAINER}" >/dev/null
fi

if containerExists "${DOCKER_MYSQL_CONTAINER}"; then
	printf -- '%s\n' "Removing \"${DOCKER_MYSQL_CONTAINER}\" container..."
	docker rm "${DOCKER_MYSQL_CONTAINER}" >/dev/null
fi

printf -- '%s\n' "Creating \"${DOCKER_MYSQL_CONTAINER}\" container..."

docker run --detach \
	--name "${DOCKER_MYSQL_CONTAINER}" \
	--hostname "${DOCKER_MYSQL_CONTAINER}" \
	--network "${DOCKER_NETWORK}" \
	--restart on-failure:3 \
	--log-opt max-size=32m \
	--publish '127.0.0.1:3306:3306/tcp' \
	--env MYSQL_ROOT_PASSWORD="${DOCKER_MYSQL_MAINTENANCE_PASSWORD}" \
	"${DOCKER_MYSQL_IMAGE}"

printf -- '%s\n' 'Waiting for database server...'
until nc -zv 127.0.0.1 3306; do sleep 1; done && sleep 20

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
	--env STORAGE_TYPE='mysql' \
	--env MYSQL_HOST="${DOCKER_MYSQL_CONTAINER}" \
	--env MYSQL_MAINTENANCE_PASSWORD="${DOCKER_MYSQL_MAINTENANCE_PASSWORD}" \
	"${DOCKER_BISERVER_IMAGE}" "$@"
