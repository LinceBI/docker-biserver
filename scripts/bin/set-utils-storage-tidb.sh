#!/bin/sh

set -eu
export LC_ALL=C

mysqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	TIDB_PWD="${password:?}" mysql \
		--host="${TIDB_HOST:?}" \
		--port="${TIDB_PORT:?}" \
		--user="${username:?}" \
		"${database:?}" "$@"
}

mysqlConnect() {
	mysqlRun "${1:?}" "${2:?}" "${3:?}" -e '\q' >/dev/null 2>&1
}

mysqlWaitUntilAvailable() {
	logInfo 'Checking MySQL connection...'
	connectionRetries=0; maxConnectionRetries=60
	until
		mysqlConnect "${TIDB_DATABASE:?}" "${TIDB_USER:?}" "${TIDB_PASSWORD:?}" ||
		mysqlConnect "${TIDB_JACKRABBIT_DATABASE:?}" "${TIDB_JACKRABBIT_USER:?}" "${TIDB_JACKRABBIT_PASSWORD:?}" ||
		mysqlConnect "${TIDB_HIBERNATE_DATABASE:?}" "${TIDB_HIBERNATE_USER:?}" "${TIDB_HIBERNATE_PASSWORD:?}" ||
		mysqlConnect "${TIDB_QUARTZ_DATABASE:?}" "${TIDB_QUARTZ_USER:?}" "${TIDB_QUARTZ_PASSWORD:?}"
	do
		if [ "${connectionRetries:?}" -gt "${maxConnectionRetries:?}" ]; then
			logFail 'MySQL connection failed'
			exit 1
		fi
		connectionRetries=$((connectionRetries + 1))
		sleep 1
	done
}

mysqlCreateDatabaseIfNotExists() {
	database=${1:?}; username=${2:?}; password=${3:?}; script=${4:?}
	logInfo "Checking \"${database:?}\" database..."
	if ! mysqlConnect "${database:?}" "${username:?}" "${password:?}"; then
		logInfo "Creating \"${database:?}\" database..."
		mysqlRun "${TIDB_DATABASE:?}" "${TIDB_USER:?}" "${TIDB_PASSWORD:?}" < "${script:?}"
	fi
}
