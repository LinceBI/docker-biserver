#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

psqlRun() {
	PGPASSWORD="${POSTGRES_PASSWORD}" psql \
		--host="${POSTGRES_HOST}" \
		--port="${POSTGRES_PORT}" \
		--username="${POSTGRES_USER}" \
		--dbname="${POSTGRES_MAINTENANCE_DATABASE}" \
		"$@"
}

psqlDbExists() {
	psqlRun -lqt | cut -d'|' -f1 | grep -qwi -- "$1"
}

########

if [ "${EXPORT_ENABLED}" = 'false' ]; then
	logInfo 'Checking PostgreSQL connection...'
	if ! psqlRun -c '\conninfo'; then
		logFail 'PostgreSQL connection failed'
		exit 1
	fi

	logInfo "Checking \"${POSTGRES_JACKRABBIT_DATABASE}\" database..."
	if ! psqlDbExists "${POSTGRES_JACKRABBIT_DATABASE}"; then
		logInfo "Creating \"${POSTGRES_JACKRABBIT_DATABASE}\" database..."
		psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_jcr_postgresql.sql
	fi

	logInfo "Checking \"${POSTGRES_HIBERNATE_DATABASE}\" database..."
	if ! psqlDbExists "${POSTGRES_HIBERNATE_DATABASE}"; then
		logInfo "Creating \"${POSTGRES_HIBERNATE_DATABASE}\" database..."
		psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_repository_postgresql.sql
	fi

	logInfo "Checking \"${POSTGRES_QUARTZ_DATABASE}\" database..."
	if ! psqlDbExists "${POSTGRES_QUARTZ_DATABASE}"; then
		logInfo "Creating \"${POSTGRES_QUARTZ_DATABASE}\" database..."
		psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_quartz_postgresql.sql
	fi
fi
