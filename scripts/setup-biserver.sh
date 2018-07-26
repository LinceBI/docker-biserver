#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

[ -z "${INSTANCE_ID:-}" ] && export INSTANCE_ID="$(tr -dc 'a-z0-9' < /dev/urandom | head -c12)"

[ -z "${FQSU_PROTOCOL:-}" ] && export FQSU_PROTOCOL='http'
[ -z "${FQSU_DOMAIN:-}" ]   && export FQSU_DOMAIN='localhost'
[ -z "${FQSU_PORT:-}" ]     && export FQSU_PORT='8080'
[ -z "${FQSU:-}" ]          && export FQSU="${FQSU_PROTOCOL}://${FQSU_DOMAIN}:${FQSU_PORT}/${BISERVER_WEBAPP_PENTAHO_DIRNAME}/"

[ -z "${BISERVER_MULTI_SETUP_ENABLED:-}" ] && export BISERVER_MULTI_SETUP_ENABLED='false'

if [ "${BISERVER_STORAGE}" = 'local' ]; then

	[ -z "${DBCON_HOST:-}" ]     && export DBCON_HOST=
	[ -z "${DBCON_PORT:-}" ]     && export DBCON_PORT=
	[ -z "${DBCON_USER:-}" ]     && export DBCON_USER=
	[ -z "${DBCON_PASSWORD:-}" ] && export DBCON_PASSWORD='password'
	[ -z "${DBCON_DATABASE:-}" ] && export DBCON_DATABASE=

	[ -z "${DBCON_DATABASE_TYPE:-}" ]            && export DBCON_DATABASE_TYPE='hsqldb'
	[ -z "${DBCON_DRIVER_CLASS:-}" ]             && export DBCON_DRIVER_CLASS='org.hsqldb.jdbcDriver'
	[ -z "${DBCON_DIALECT_CLASS:-}" ]            && export DBCON_DIALECT_CLASS='org.hibernate.dialect.HSQLDialect'
	[ -z "${DBCON_FILESYSTEM_CLASS:-}" ]         && export DBCON_FILESYSTEM_CLASS='org.apache.jackrabbit.core.fs.local.LocalFileSystem'
	[ -z "${DBCON_DATASTORE_CLASS:-}" ]          && export DBCON_DATASTORE_CLASS='org.apache.jackrabbit.core.data.FileDataStore'
	[ -z "${DBCON_PERSISTENCEMANAGER_CLASS:-}" ] && export DBCON_PERSISTENCEMANAGER_CLASS='org.apache.jackrabbit.core.persistence.pool.H2PersistenceManager'
	[ -z "${DBCON_DRIVERDELEGATE_CLASS:-}" ]     && export DBCON_DRIVERDELEGATE_CLASS='org.quartz.impl.jdbcjobstore.PostgreSQLDelegate'
	[ -z "${DBCON_VALIDATIONQUERY:-}" ]          && export DBCON_VALIDATIONQUERY='select count(*) from INFORMATION_SCHEMA.SYSTEM_SEQUENCES'

	[ -z "${DBCON_JACKRABBIT_USER:-}" ]     && export DBCON_JACKRABBIT_USER='jcr_user'
	[ -z "${DBCON_JACKRABBIT_PASSWORD:-}" ] && export DBCON_JACKRABBIT_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_JACKRABBIT_DATABASE:-}" ] && export DBCON_JACKRABBIT_DATABASE='jackrabbit'
	[ -z "${DBCON_JACKRABBIT_URL:-}" ]      && export DBCON_JACKRABBIT_URL='jdbc:h2:${rep.home}/version/db'

	[ -z "${DBCON_HIBERNATE_USER:-}" ]        && export DBCON_HIBERNATE_USER='hibuser'
	[ -z "${DBCON_HIBERNATE_PASSWORD:-}" ]    && export DBCON_HIBERNATE_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_HIBERNATE_DATABASE:-}" ]    && export DBCON_HIBERNATE_DATABASE='hibernate'
	[ -z "${DBCON_HIBERNATE_URL:-}" ]         && export DBCON_HIBERNATE_URL="jdbc:hsqldb:hsql://localhost/${DBCON_HIBERNATE_DATABASE}"
	[ -z "${DBCON_HIBERNATE_CONFIG_FILE:-}" ] && export DBCON_HIBERNATE_CONFIG_FILE='system/hibernate/hsql.hibernate.cfg.xml'

	[ -z "${DBCON_QUARTZ_USER:-}" ]     && export DBCON_QUARTZ_USER='pentaho_user'
	[ -z "${DBCON_QUARTZ_PASSWORD:-}" ] && export DBCON_QUARTZ_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_QUARTZ_DATABASE:-}" ] && export DBCON_QUARTZ_DATABASE='quartz'
	[ -z "${DBCON_QUARTZ_URL:-}" ]      && export DBCON_QUARTZ_URL="jdbc:hsqldb:hsql://localhost/${DBCON_QUARTZ_DATABASE}"

elif [ "${BISERVER_STORAGE}" = 'postgres' ]; then

	[ -z "${DBCON_HOST:-}" ]     && export DBCON_HOST='localhost'
	[ -z "${DBCON_PORT:-}" ]     && export DBCON_PORT='5432'
	[ -z "${DBCON_USER:-}" ]     && export DBCON_USER='postgres'
	[ -z "${DBCON_PASSWORD:-}" ] && export DBCON_PASSWORD="${DBCON_USER}"
	[ -z "${DBCON_DATABASE:-}" ] && export DBCON_DATABASE="${DBCON_USER}"

	[ -z "${DBCON_DATABASE_TYPE:-}" ]            && export DBCON_DATABASE_TYPE='postgresql'
	[ -z "${DBCON_DRIVER_CLASS:-}" ]             && export DBCON_DRIVER_CLASS='org.postgresql.Driver'
	[ -z "${DBCON_DIALECT_CLASS:-}" ]            && export DBCON_DIALECT_CLASS='org.hibernate.dialect.PostgreSQLDialect'
	[ -z "${DBCON_FILESYSTEM_CLASS:-}" ]         && export DBCON_FILESYSTEM_CLASS='org.apache.jackrabbit.core.fs.db.DbFileSystem'
	[ -z "${DBCON_DATASTORE_CLASS:-}" ]          && export DBCON_DATASTORE_CLASS='org.apache.jackrabbit.core.data.db.DbDataStore'
	[ -z "${DBCON_PERSISTENCEMANAGER_CLASS:-}" ] && export DBCON_PERSISTENCEMANAGER_CLASS='org.apache.jackrabbit.core.persistence.bundle.PostgreSQLPersistenceManager'
	[ -z "${DBCON_DRIVERDELEGATE_CLASS:-}" ]     && export DBCON_DRIVERDELEGATE_CLASS='org.quartz.impl.jdbcjobstore.PostgreSQLDelegate'
	[ -z "${DBCON_VALIDATIONQUERY:-}" ]          && export DBCON_VALIDATIONQUERY='select 1'

	[ -z "${DBCON_JACKRABBIT_USER:-}" ]     && export DBCON_JACKRABBIT_USER='jcr_user'
	[ -z "${DBCON_JACKRABBIT_PASSWORD:-}" ] && export DBCON_JACKRABBIT_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_JACKRABBIT_DATABASE:-}" ] && export DBCON_JACKRABBIT_DATABASE='jackrabbit'
	[ -z "${DBCON_JACKRABBIT_URL:-}" ]      && export DBCON_JACKRABBIT_URL="jdbc:postgresql://${DBCON_HOST}:${DBCON_PORT}/${DBCON_JACKRABBIT_DATABASE}"

	[ -z "${DBCON_HIBERNATE_USER:-}" ]        && export DBCON_HIBERNATE_USER='hibuser'
	[ -z "${DBCON_HIBERNATE_PASSWORD:-}" ]    && export DBCON_HIBERNATE_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_HIBERNATE_DATABASE:-}" ]    && export DBCON_HIBERNATE_DATABASE='hibernate'
	[ -z "${DBCON_HIBERNATE_URL:-}" ]         && export DBCON_HIBERNATE_URL="jdbc:postgresql://${DBCON_HOST}:${DBCON_PORT}/${DBCON_HIBERNATE_DATABASE}"
	[ -z "${DBCON_HIBERNATE_CONFIG_FILE:-}" ] && export DBCON_HIBERNATE_CONFIG_FILE='system/hibernate/postgresql.hibernate.cfg.xml'

	[ -z "${DBCON_QUARTZ_USER:-}" ]     && export DBCON_QUARTZ_USER='pentaho_user'
	[ -z "${DBCON_QUARTZ_PASSWORD:-}" ] && export DBCON_QUARTZ_PASSWORD="${DBCON_PASSWORD}"
	[ -z "${DBCON_QUARTZ_DATABASE:-}" ] && export DBCON_QUARTZ_DATABASE='quartz'
	[ -z "${DBCON_QUARTZ_URL:-}" ]      && export DBCON_QUARTZ_URL="jdbc:postgresql://${DBCON_HOST}:${DBCON_PORT}/${DBCON_QUARTZ_DATABASE}"

else
	logFail "Unknown storage type: ${BISERVER_STORAGE}"
	exit 1
fi

########

# Export all environment variables escaped so they can be used as a replacement in sed

ENVIRON="$(awk 'BEGIN {
  for (v in ENVIRON) {
    if (v !~ /^(HOME|PWD|SHELL|USER|GROUP|UID|GID)$/) {
      gsub(/[^0-9A-Za-z]/, "_", v)
      gsub(/\n/, " ", ENVIRON[v])
      print v "\t" ENVIRON[v]
    }
  }
}')"

_IFS=$IFS; IFS="$(printf '\nx')"; IFS="${IFS%x}"
for env in ${ENVIRON}; do
	env_key="$(printf -- '%s' "${env}" | cut -f1)"
	env_value="$(printf -- '%s' "${env}" | cut -f2)"
	export "${env_key}_RE=$(quoteRe "${env_value}")"
	export "${env_key}_SUBST=$(quoteSubst "${env_value}")"
done
IFS=$_IFS

########

# Directory rename setup
/opt/scripts/setup-biserver-rename.sh

# General setup
/opt/scripts/setup-biserver-general.sh

# PostgreSQL setup
if [ "${BISERVER_STORAGE}" = 'postgres' ]; then
	/opt/scripts/setup-biserver-postgres.sh
fi

# biserver.init.d setup
/opt/scripts/setup-biserver-initd.sh
