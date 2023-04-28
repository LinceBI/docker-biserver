#!/bin/sh

set -eu
export LC_ALL=C

DOCKER=$(command -v docker 2>/dev/null)

IMAGE_REGISTRY=repo.stratebi.com
IMAGE_NAMESPACE=lincebi
IMAGE_PROJECT=biserver
IMAGE_TAG=9.3.0.3-702-1
IMAGE_NAME=${IMAGE_REGISTRY:?}/${IMAGE_NAMESPACE:?}/${IMAGE_PROJECT:?}:${IMAGE_TAG:?}

exec "${DOCKER:?}" run --rm --log-driver none --attach STDOUT --attach STDERR \
	--env DEFAULT_ADMIN_PASSWORD='password' \
	--env STORAGE_TYPE='mysql' \
	--env MYSQL_HOST='localhost' \
	--env MYSQL_PORT='3306' \
	--env MYSQL_USER='root' \
	--env MYSQL_PASSWORD='root' \
	--env MYSQL_DATABASE='mysql' \
	--env MYSQL_JACKRABBIT_USER='jcr_user' \
	--env MYSQL_JACKRABBIT_PASSWORD='jcr_password' \
	--env MYSQL_JACKRABBIT_DATABASE='jackrabbit' \
	--env MYSQL_HIBERNATE_USER='hibuser' \
	--env MYSQL_HIBERNATE_PASSWORD='hibpassword' \
	--env MYSQL_HIBERNATE_DATABASE='hibernate' \
	--env MYSQL_QUARTZ_USER='pentaho_user' \
	--env MYSQL_QUARTZ_PASSWORD='pentaho_password' \
	--env MYSQL_QUARTZ_DATABASE='quartz' \
	"${IMAGE_NAME:?}" /usr/share/biserver/bin/export.sh
