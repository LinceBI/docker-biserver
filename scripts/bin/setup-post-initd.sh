#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# During export no connection to any database is attempted
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

	# TiDB setup
	if [ "${STORAGE_TYPE:?}" = 'tidb' ]; then
		/usr/share/biserver/bin/setup-storage-tidb.sh
	fi

	# Oracle setup (not implemented)
	# if [ "${STORAGE_TYPE:?}" = 'oracle' ]; then
	# fi
fi

########

# If not true samples will not be loaded
if [ "${LOAD_SAMPLES:?}" != 'true' ]; then
	# Remove HSQLDB databases
	rm -f \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/hsqldb/sampledata.* \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/hsqldb/foodmart.*

	# Remove sample files
	rm -f \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/default-content/samples.zip \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/default-content/*-samples.zip

	# Re-run template to update "hsqldb-databases" value
	if [ -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/web.xml.erb ]; then
		execErb "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/web.xml.erb
	fi
fi
