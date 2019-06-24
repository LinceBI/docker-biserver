#!/bin/sh

set -eu
export LC_ALL=C

psqlRun() {
	database=${1:?}; username=${2:?}; password=${3:?}; shift 3
	PGPASSWORD="${password}" psql \
		--host="${POSTGRES_HOST}" \
		--port="${POSTGRES_PORT}" \
		--username="${username}" \
		--dbname="${database}" \
		"$@"
}

psqlConnect() {
	psqlRun "${1:?}" "${2:?}" "${3:?}" -c '\conninfo' >/dev/null 2>&1
}
