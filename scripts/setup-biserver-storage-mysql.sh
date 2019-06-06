#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

mysqlRun() {
	MYSQL_PWD="${MYSQL_PASSWORD}" mysql \
		--host="${MYSQL_HOST}" \
		--port="${MYSQL_PORT}" \
		--user="${MYSQL_USER}" \
		"$@"
}

mysqlDbExists() {
	mysqlRun -NBe 'SHOW DATABASES' | grep -qwi -- "$1"
}

########

if [ "${EXPORT_ENABLED}" = 'false' ]; then
	logInfo 'Checking MySQL connection...'
	if ! mysqlRun -e '\q'; then
		logFail 'MySQL connection failed'
		exit 1
	fi

	logInfo "Checking \"${MYSQL_JACKRABBIT_DATABASE}\" database..."
	if ! mysqlDbExists "${MYSQL_JACKRABBIT_DATABASE}"; then
		logInfo "Creating \"${MYSQL_JACKRABBIT_DATABASE}\" database..."
		mysqlRun < "${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_jcr_mysql.sql
	fi

	logInfo "Checking \"${MYSQL_HIBERNATE_DATABASE}\" database..."
	if ! mysqlDbExists "${MYSQL_HIBERNATE_DATABASE}"; then
		logInfo "Creating \"${MYSQL_HIBERNATE_DATABASE}\" database..."
		mysqlRun < "${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_repository_mysql.sql
	fi

	logInfo "Checking \"${MYSQL_QUARTZ_DATABASE}\" database..."
	if ! mysqlDbExists "${MYSQL_QUARTZ_DATABASE}"; then
		logInfo "Creating \"${MYSQL_QUARTZ_DATABASE}\" database..."
		mysqlRun < "${BISERVER_HOME}"/"${DATA_DIRNAME}"/mysql5/create_quartz_mysql.sql
	fi
fi
