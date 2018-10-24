#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.1.0.0-365

docker run --rm \
	--env STORAGE_TYPE='postgres' \
	--env POSTGRES_HOST='localhost' \
	--env POSTGRES_PORT='5432' \
	--env POSTGRES_USER='postgres' \
	--env POSTGRES_PASSWORD='postgres' \
	--env POSTGRES_DATABASE='postgres' \
	--env POSTGRES_JACKRABBIT_USER='jcr_user' \
	--env POSTGRES_JACKRABBIT_PASSWORD='jackrabbit' \
	--env POSTGRES_JACKRABBIT_DATABASE='jackrabbit' \
	--env POSTGRES_HIBERNATE_USER='hibuser' \
	--env POSTGRES_HIBERNATE_PASSWORD='hibernate' \
	--env POSTGRES_HIBERNATE_DATABASE='hibernate' \
	--env POSTGRES_QUARTZ_USER='pentaho_user' \
	--env POSTGRES_QUARTZ_PASSWORD='quartz' \
	--env POSTGRES_QUARTZ_DATABASE='quartz' \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
