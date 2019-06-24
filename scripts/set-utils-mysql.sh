#!/bin/sh

set -eu
export LC_ALL=C

mysqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	MYSQL_PWD="${password}" mysql \
		--host="${MYSQL_HOST}" \
		--port="${MYSQL_PORT}" \
		--user="${username}" \
		"${database}" "$@"
}

mysqlConnect() {
	mysqlRun "${1:?}" "${2:?}" "${3:?}" -e '\q' >/dev/null 2>&1
}
