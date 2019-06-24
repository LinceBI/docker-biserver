#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh
. /opt/scripts/set-utils-mysql.sh

########

if [ "${EXPORT_ENABLED}" = 'false' ]; then
	mysqlWaitUntilAvailable

	mysqlCreateDatabaseIfNotExists \
		"${MYSQL_JACKRABBIT_DATABASE}" "${MYSQL_JACKRABBIT_USER}" "${MYSQL_JACKRABBIT_PASSWORD}" \
		"${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_jcr_mysql.sql

	mysqlCreateDatabaseIfNotExists \
		"${MYSQL_HIBERNATE_DATABASE}" "${MYSQL_HIBERNATE_USER}" "${MYSQL_HIBERNATE_PASSWORD}" \
		"${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_repository_mysql.sql

	mysqlCreateDatabaseIfNotExists \
		"${MYSQL_QUARTZ_DATABASE}" "${MYSQL_QUARTZ_USER}" "${MYSQL_QUARTZ_PASSWORD}" \
		"${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_quartz_mysql.sql
fi
