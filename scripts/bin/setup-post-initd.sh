#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

if [ "${IS_EXPORTING:?}" != 'true' ]; then
	# PostgreSQL setup
	if [ "${STORAGE_TYPE:?}" = 'postgres' ]; then
		/usr/share/biserver/bin/setup-storage-postgres.sh
	fi

	# CockroachDB setup
	if [ "${STORAGE_TYPE:?}" = 'cockroach' ]; then
		/usr/share/biserver/bin/setup-storage-cockroach.sh
	fi

	# MySQL setup
	if [ "${STORAGE_TYPE:?}" = 'mysql' ]; then
		/usr/share/biserver/bin/setup-storage-mysql.sh
	fi
fi
