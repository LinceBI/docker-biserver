#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.2.0.0-342

docker run --rm \
	--env STORAGE_TYPE='mysql' \
	--env MYSQL_HOST='localhost' \
	--env MYSQL_PORT='3306' \
	--env MYSQL_USER='root' \
	--env MYSQL_PASSWORD='root' \
	--env MYSQL_JACKRABBIT_USER='jcr_user' \
	--env MYSQL_JACKRABBIT_PASSWORD='jcr_user' \
	--env MYSQL_JACKRABBIT_DATABASE='jackrabbit' \
	--env MYSQL_HIBERNATE_USER='hibuser' \
	--env MYSQL_HIBERNATE_PASSWORD='hibuser' \
	--env MYSQL_HIBERNATE_DATABASE='hibernate' \
	--env MYSQL_QUARTZ_USER='pentaho_user' \
	--env MYSQL_QUARTZ_PASSWORD='pentaho_user' \
	--env MYSQL_QUARTZ_DATABASE='quartz' \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
