#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh
# shellcheck source=./set-utils-storage-cockroach.sh
. /usr/share/biserver/bin/set-utils-storage-cockroach.sh

########

psqlWaitUntilAvailable

psqlCreateDatabaseIfNotExists \
	"${COCKROACH_JACKRABBIT_DATABASE:?}" "${COCKROACH_JACKRABBIT_USER:?}" "${COCKROACH_JACKRABBIT_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/cockroach/create_jcr_cockroach.sql

psqlCreateDatabaseIfNotExists \
	"${COCKROACH_HIBERNATE_DATABASE:?}" "${COCKROACH_HIBERNATE_USER:?}" "${COCKROACH_HIBERNATE_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/cockroach/create_repository_cockroach.sql

psqlCreateDatabaseIfNotExists \
	"${COCKROACH_QUARTZ_DATABASE:?}" "${COCKROACH_QUARTZ_USER:?}" "${COCKROACH_QUARTZ_PASSWORD:?}" \
	"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/cockroach/create_quartz_cockroach.sql

if [ "${AUDIT_ENTRY:?}" = 'sql' ]; then
	psqlCreateDatabaseIfNotExists \
		"${COCKROACH_AUDIT_DATABASE:?}" "${COCKROACH_AUDIT_USER:?}" "${COCKROACH_AUDIT_PASSWORD:?}" \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/cockroach/create_audit_cockroach.sql
fi
