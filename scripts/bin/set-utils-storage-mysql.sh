#!/bin/sh

set -eu
export LC_ALL=C

mysqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	MYSQL_PWD="${password:?}" mysql \
		--host="${MYSQL_HOST:?}" \
		--port="${MYSQL_PORT:?}" \
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
		mysqlConnect "${MYSQL_DATABASE:?}" "${MYSQL_USER:?}" "${MYSQL_PASSWORD:?}" ||
		mysqlConnect "${MYSQL_JACKRABBIT_DATABASE:?}" "${MYSQL_JACKRABBIT_USER:?}" "${MYSQL_JACKRABBIT_PASSWORD:?}" ||
		mysqlConnect "${MYSQL_HIBERNATE_DATABASE:?}" "${MYSQL_HIBERNATE_USER:?}" "${MYSQL_HIBERNATE_PASSWORD:?}" ||
		mysqlConnect "${MYSQL_QUARTZ_DATABASE:?}" "${MYSQL_QUARTZ_USER:?}" "${MYSQL_QUARTZ_PASSWORD:?}"
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
	database=${1:?}; username=${2:?}; password=${3:?}; script=${4:?}; shift 3
	logInfo "Checking \"${database:?}\" database..."
	if ! mysqlConnect "${database:?}" "${username:?}" "${password:?}"; then
		logInfo "Creating \"${database:?}\" database..."
		mysqlRun "${MYSQL_DATABASE:?}" "${MYSQL_USER:?}" "${MYSQL_PASSWORD:?}" < "${script:?}"
	fi
}
