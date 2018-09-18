#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

psqlRun() { PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DATABASE}" "$@"; }
psqlDbExists() { psqlRun -lqt | cut -d'|' -f1 | grep -qw -- "$1"; }

########

logInfo 'Checking PostgreSQL connection...'
if ! nc -zv "${POSTGRES_HOST}" "${POSTGRES_PORT}" || ! psqlRun -c '\conninfo'; then
	logFail 'PostgreSQL connection failed'
	exit 1
fi

########

sed -r \
	-e "s|%POSTGRES_USER%|${POSTGRES_USER_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_USER%|${POSTGRES_JACKRABBIT_USER_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_PASSWORD%|${POSTGRES_JACKRABBIT_PASSWORD_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_DATABASE%|${POSTGRES_JACKRABBIT_DATABASE_SUBST}|g" \
	"${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_jcr_postgresql.sql.tmpl \
	> "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_jcr_postgresql.sql

logInfo "Checking \"${POSTGRES_JACKRABBIT_DATABASE}\" database..."
if ! psqlDbExists "${POSTGRES_JACKRABBIT_DATABASE}"; then
	logInfo "Creating \"${POSTGRES_JACKRABBIT_DATABASE}\" database..."
	psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_jcr_postgresql.sql
fi

########

sed -r \
	-e "s|%POSTGRES_USER%|${POSTGRES_USER_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_USER%|${POSTGRES_HIBERNATE_USER_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_PASSWORD%|${POSTGRES_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_DATABASE%|${POSTGRES_HIBERNATE_DATABASE_SUBST}|g" \
	"${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_repository_postgresql.sql.tmpl \
	> "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_repository_postgresql.sql

logInfo "Checking \"${POSTGRES_HIBERNATE_DATABASE}\" database..."
if ! psqlDbExists "${POSTGRES_HIBERNATE_DATABASE}"; then
	logInfo "Creating \"${POSTGRES_HIBERNATE_DATABASE}\" database..."
	psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_repository_postgresql.sql
fi

########

sed -r \
	-e "s|%POSTGRES_USER%|${POSTGRES_USER_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_USER%|${POSTGRES_QUARTZ_USER_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_PASSWORD%|${POSTGRES_QUARTZ_PASSWORD_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_DATABASE%|${POSTGRES_QUARTZ_DATABASE_SUBST}|g" \
	"${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_quartz_postgresql.sql.tmpl \
	> "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_quartz_postgresql.sql

logInfo "Checking \"${POSTGRES_QUARTZ_DATABASE}\" database..."
if ! psqlDbExists "${POSTGRES_QUARTZ_DATABASE}"; then
	logInfo "Creating \"${POSTGRES_QUARTZ_DATABASE}\" database..."
	psqlRun -f "${BISERVER_HOME}"/"${DATA_DIRNAME}"/postgresql/create_quartz_postgresql.sql
fi

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_URL%|${POSTGRES_JACKRABBIT_URL_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_USER%|${POSTGRES_JACKRABBIT_USER_SUBST}|g" \
	-e "s|%POSTGRES_JACKRABBIT_PASSWORD%|${POSTGRES_JACKRABBIT_PASSWORD_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml.postgres.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml

########

sed -r \
	-e "s|%POSTGRES_HIBERNATE_URL%|${POSTGRES_HIBERNATE_URL_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_USER%|${POSTGRES_HIBERNATE_USER_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_PASSWORD%|${POSTGRES_HIBERNATE_PASSWORD_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/postgresql.hibernate.cfg.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/postgresql.hibernate.cfg.xml

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties.postgres.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties

########

sed -r \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_URL%|${POSTGRES_HIBERNATE_URL_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_USER%|${POSTGRES_HIBERNATE_USER_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_PASSWORD%|${POSTGRES_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_URL%|${POSTGRES_QUARTZ_URL_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_USER%|${POSTGRES_QUARTZ_USER_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_PASSWORD%|${POSTGRES_QUARTZ_PASSWORD_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties.postgres.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties

########

sed -r \
	-e "s|%SOLUTIONS_DIRNAME%|${SOLUTIONS_DIRNAME_SUBST}|g" \
	-e "s|%DATA_DIRNAME%|${DATA_DIRNAME_SUBST}|g" \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml.postgres.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_URL%|${POSTGRES_HIBERNATE_URL_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_USER%|${POSTGRES_HIBERNATE_USER_SUBST}|g" \
	-e "s|%POSTGRES_HIBERNATE_PASSWORD%|${POSTGRES_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_URL%|${POSTGRES_QUARTZ_URL_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_USER%|${POSTGRES_QUARTZ_USER_SUBST}|g" \
	-e "s|%POSTGRES_QUARTZ_PASSWORD%|${POSTGRES_QUARTZ_PASSWORD_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml.postgres.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml
