#!/bin/sh

set -eu
export LC_ALL=C

psqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	PGPASSWORD="${password:?}" psql \
		--host="${COCKROACH_HOST:?}" \
		--port="${COCKROACH_PORT:?}" \
		--username="${username:?}" \
		--dbname="${database:?}" \
		"$@"
}

psqlConnect() {
	psqlRun "${1:?}" "${2:?}" "${3:?}" -c '\conninfo' >/dev/null 2>&1
}

psqlWaitUntilAvailable() {
	logInfo 'Checking CockroachDB connection...'
	connectionRetries=0; maxConnectionRetries=60
	until
		psqlConnect "${COCKROACH_MAINTENANCE_DATABASE:?}" "${COCKROACH_MAINTENANCE_USER:?}" "${COCKROACH_MAINTENANCE_PASSWORD:?}" ||
		psqlConnect "${COCKROACH_JACKRABBIT_DATABASE:?}" "${COCKROACH_JACKRABBIT_USER:?}" "${COCKROACH_JACKRABBIT_PASSWORD:?}" ||
		psqlConnect "${COCKROACH_HIBERNATE_DATABASE:?}" "${COCKROACH_HIBERNATE_USER:?}" "${COCKROACH_HIBERNATE_PASSWORD:?}" ||
		psqlConnect "${COCKROACH_QUARTZ_DATABASE:?}" "${COCKROACH_QUARTZ_USER:?}" "${COCKROACH_QUARTZ_PASSWORD:?}"
	do
		if [ "${connectionRetries:?}" -gt "${maxConnectionRetries:?}" ]; then
			logFail 'CockroachDB connection failed'
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
		psqlRun "${COCKROACH_MAINTENANCE_DATABASE:?}" "${COCKROACH_MAINTENANCE_USER:?}" "${COCKROACH_MAINTENANCE_PASSWORD:?}" < "${script:?}"
	fi
}
