#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh
# shellcheck source=./set-utils-storage-tidb.sh
. /usr/share/biserver/bin/set-utils-storage-tidb.sh

########

mysqlWaitUntilAvailable

mysqlCreateDatabaseIfNotExists \
	"${TIDB_JACKRABBIT_DATABASE:?}" "${TIDB_JACKRABBIT_USER:?}" "${TIDB_JACKRABBIT_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/tidb/create_jcr_tidb.sql

mysqlCreateDatabaseIfNotExists \
	"${TIDB_HIBERNATE_DATABASE:?}" "${TIDB_HIBERNATE_USER:?}" "${TIDB_HIBERNATE_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/tidb/create_repository_tidb.sql

mysqlCreateDatabaseIfNotExists \
	"${TIDB_QUARTZ_DATABASE:?}" "${TIDB_QUARTZ_USER:?}" "${TIDB_QUARTZ_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/tidb/create_quartz_tidb.sql
