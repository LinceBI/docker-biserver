#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh
# shellcheck source=./set-utils-storage-postgres.sh
. /usr/share/biserver/bin/set-utils-storage-postgres.sh

########

psqlWaitUntilAvailable

psqlCreateDatabaseIfNotExists \
	"${POSTGRES_JACKRABBIT_DATABASE:?}" "${POSTGRES_JACKRABBIT_USER:?}" "${POSTGRES_JACKRABBIT_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/create_jcr_postgresql.sql

psqlCreateDatabaseIfNotExists \
	"${POSTGRES_HIBERNATE_DATABASE:?}" "${POSTGRES_HIBERNATE_USER:?}" "${POSTGRES_HIBERNATE_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/create_repository_postgresql.sql

psqlCreateDatabaseIfNotExists \
	"${POSTGRES_QUARTZ_DATABASE:?}" "${POSTGRES_QUARTZ_USER:?}" "${POSTGRES_QUARTZ_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/create_quartz_postgresql.sql

if [ "${AUDIT_ENTRY:?}" = 'sql' ]; then
	psqlCreateDatabaseIfNotExists \
		"${POSTGRES_AUDIT_DATABASE:?}" "${POSTGRES_AUDIT_USER:?}" "${POSTGRES_AUDIT_PASSWORD:?}" \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/create_audit_postgresql.sql
fi
