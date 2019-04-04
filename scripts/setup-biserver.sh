#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

[ -z "${EXPORT_ENABLED-}" ]      && export EXPORT_ENABLED='false'
[ -z "${MULTI_SETUP_ENABLED-}" ] && export MULTI_SETUP_ENABLED='false'

if [ -z "${INSTANCE_ID-}" ]; then
	# Each instance has a random 12 characters alphanumeric string
	INSTANCE_ID="$(tr -dc 'a-z0-9' < /dev/urandom | head -c12)"
	export INSTANCE_ID
fi

[ -z "${FQSU_PROTOCOL-}" ] && export FQSU_PROTOCOL='http'
[ -z "${FQSU_DOMAIN-}" ]   && export FQSU_DOMAIN='localhost'
[ -z "${FQSU_PORT-}" ]     && export FQSU_PORT='8080'
[ -z "${FQSU-}" ]          && export FQSU="${FQSU_PROTOCOL}://${FQSU_DOMAIN}:${FQSU_PORT}/${WEBAPP_PENTAHO_DIRNAME}/"

[ -z "${HSQLDB_PORT-}" ]            && export HSQLDB_PORT='9001'
[ -z "${KARAF_STARTPORT-}" ]        && export KARAF_STARTPORT='8801'
[ -z "${KARAF_ENDPORT-}" ]          && export KARAF_ENDPORT='8899'
[ -z "${OSGI_SERVICE_STARTPORT-}" ] && export OSGI_SERVICE_STARTPORT='9050'
[ -z "${OSGI_SERVICE_ENDPORT-}" ]   && export OSGI_SERVICE_ENDPORT='9149'
[ -z "${RMI_SERVER_STARTPORT-}" ]   && export RMI_SERVER_STARTPORT='44444'
[ -z "${RMI_SERVER_ENDPORT-}" ]     && export RMI_SERVER_ENDPORT='44499'
[ -z "${RMI_REGISTRY_STARTPORT-}" ] && export RMI_REGISTRY_STARTPORT='11098'
[ -z "${RMI_REGISTRY_ENDPORT-}" ]   && export RMI_REGISTRY_ENDPORT='11190'

[ -z "${STORAGE_TYPE-}" ] && export STORAGE_TYPE='local'

if [ "${STORAGE_TYPE}" = 'local' ]; then

	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/hsql.hibernate.cfg.xml'

elif [ "${STORAGE_TYPE}" = 'postgres' ]; then

	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/postgresql.hibernate.cfg.xml'

	[ -z "${POSTGRES_HOST-}" ]     && export POSTGRES_HOST='localhost'
	[ -z "${POSTGRES_PORT-}" ]     && export POSTGRES_PORT='5432'
	[ -z "${POSTGRES_USER-}" ]     && export POSTGRES_USER='postgres'
	[ -z "${POSTGRES_PASSWORD-}" ] && export POSTGRES_PASSWORD="${POSTGRES_USER}"
	[ -z "${POSTGRES_DATABASE-}" ] && export POSTGRES_DATABASE="${POSTGRES_USER}"

	[ -z "${POSTGRES_JACKRABBIT_USER-}" ]     && export POSTGRES_JACKRABBIT_USER='jcr_user'
	[ -z "${POSTGRES_JACKRABBIT_PASSWORD-}" ] && export POSTGRES_JACKRABBIT_PASSWORD="${POSTGRES_PASSWORD}"
	[ -z "${POSTGRES_JACKRABBIT_DATABASE-}" ] && export POSTGRES_JACKRABBIT_DATABASE='jackrabbit'
	[ -z "${POSTGRES_JACKRABBIT_URL-}" ]      && export POSTGRES_JACKRABBIT_URL="jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_JACKRABBIT_DATABASE}"

	[ -z "${POSTGRES_HIBERNATE_USER-}" ]     && export POSTGRES_HIBERNATE_USER='hibuser'
	[ -z "${POSTGRES_HIBERNATE_PASSWORD-}" ] && export POSTGRES_HIBERNATE_PASSWORD="${POSTGRES_PASSWORD}"
	[ -z "${POSTGRES_HIBERNATE_DATABASE-}" ] && export POSTGRES_HIBERNATE_DATABASE='hibernate'
	[ -z "${POSTGRES_HIBERNATE_URL-}" ]      && export POSTGRES_HIBERNATE_URL="jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_HIBERNATE_DATABASE}"

	[ -z "${POSTGRES_QUARTZ_USER-}" ]     && export POSTGRES_QUARTZ_USER='pentaho_user'
	[ -z "${POSTGRES_QUARTZ_PASSWORD-}" ] && export POSTGRES_QUARTZ_PASSWORD="${POSTGRES_PASSWORD}"
	[ -z "${POSTGRES_QUARTZ_DATABASE-}" ] && export POSTGRES_QUARTZ_DATABASE='quartz'
	[ -z "${POSTGRES_QUARTZ_URL-}" ]      && export POSTGRES_QUARTZ_URL="jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_QUARTZ_DATABASE}"

else
	logFail "Unknown storage type: ${STORAGE_TYPE}"
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
if [ "${STORAGE_TYPE}" = 'postgres' ]; then
	/opt/scripts/setup-biserver-storage-postgres.sh
else
	/opt/scripts/setup-biserver-storage-local.sh
fi

# biserver.init.d setup
/opt/scripts/setup-biserver-initd.sh
