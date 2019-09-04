#!/bin/sh

set -eu
export LC_ALL=C

psqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	PGPASSWORD="${password:?}" psql \
		--host="${POSTGRES_HOST:?}" \
		--port="${POSTGRES_PORT:?}" \
		--username="${username:?}" \
		--dbname="${database:?}" \
		"$@"
}

psqlConnect() {
	psqlRun "${1:?}" "${2:?}" "${3:?}" -c '\conninfo' >/dev/null 2>&1
}

psqlWaitUntilAvailable() {
	logInfo 'Checking PostgreSQL connection...'
	connectionRetries=0; maxConnectionRetries=60
	until
		psqlConnect "${POSTGRES_MAINTENANCE_DATABASE:?}" "${POSTGRES_MAINTENANCE_USER:?}" "${POSTGRES_MAINTENANCE_PASSWORD:?}" ||
		psqlConnect "${POSTGRES_JACKRABBIT_DATABASE:?}" "${POSTGRES_JACKRABBIT_USER:?}" "${POSTGRES_JACKRABBIT_PASSWORD:?}" ||
		psqlConnect "${POSTGRES_HIBERNATE_DATABASE:?}" "${POSTGRES_HIBERNATE_USER:?}" "${POSTGRES_HIBERNATE_PASSWORD:?}" ||
		psqlConnect "${POSTGRES_QUARTZ_DATABASE:?}" "${POSTGRES_QUARTZ_USER:?}" "${POSTGRES_QUARTZ_PASSWORD:?}"
	do
		if [ "${connectionRetries:?}" -gt "${maxConnectionRetries:?}" ]; then
			logFail 'PostgreSQL connection failed'
			exit 1
		fi
		connectionRetries=$((connectionRetries + 1))
		sleep 1
	done
}

psqlCreateDatabaseIfNotExists() {
	database=${1:?}; username=${2:?}; password=${3:?}; script=${4:?}; shift 3
	logInfo "Checking \"${database:?}\" database..."
	if ! psqlConnect "${database:?}" "${username:?}" "${password:?}"; then
		logInfo "Creating \"${database:?}\" database..."
		psqlRun "${POSTGRES_MAINTENANCE_DATABASE:?}" "${POSTGRES_MAINTENANCE_USER:?}" "${POSTGRES_MAINTENANCE_PASSWORD:?}" < "${script:?}"
	fi
}
