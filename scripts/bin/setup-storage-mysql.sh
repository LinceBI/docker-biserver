#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh
# shellcheck source=./set-utils-storage-mysql.sh
. /usr/share/biserver/bin/set-utils-storage-mysql.sh

########

mysqlWaitUntilAvailable

mysqlCreateDatabaseIfNotExists \
	"${MYSQL_JACKRABBIT_DATABASE:?}" "${MYSQL_JACKRABBIT_USER:?}" "${MYSQL_JACKRABBIT_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/create_jcr_mysql.sql

mysqlCreateDatabaseIfNotExists \
	"${MYSQL_HIBERNATE_DATABASE:?}" "${MYSQL_HIBERNATE_USER:?}" "${MYSQL_HIBERNATE_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/create_repository_mysql.sql

mysqlCreateDatabaseIfNotExists \
	"${MYSQL_QUARTZ_DATABASE:?}" "${MYSQL_QUARTZ_USER:?}" "${MYSQL_QUARTZ_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/create_quartz_mysql.sql

if [ "${AUDIT_ENTRY:?}" = 'sql' ]; then
	mysqlCreateDatabaseIfNotExists \
		"${MYSQL_AUDIT_DATABASE:?}" "${MYSQL_AUDIT_USER:?}" "${MYSQL_AUDIT_PASSWORD:?}" \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/create_audit_mysql.sql
fi
